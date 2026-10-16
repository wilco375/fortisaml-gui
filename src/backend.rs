//! Connection orchestration (all native Rust, no external interpreter).
//!
//! GUI side (unprivileged):  SAML login in-process (browser via xdg-open, local callback listener).
//! Privileged side:          `pkexec <this binary> --backend` - a private strongSwan charon does IKEv2 and the XFRM
//!                           SAs; we add the xfrm interface, routes and DNS, then drop to the user + CAP_NET_ADMIN.
//!   * the request (settings + PSK + one-time token) is sent as one JSON line on stdin, never on argv;
//!   * afterwards stdin is a control channel: "disconnect" or EOF (GUI closed/crashed) => teardown;
//!   * progress is reported as `@@{json}` lines on stdout, other lines are log output.

use crate::charon::{self, ConnParams};
use crate::config::{Config, Profile, RouteMode, UserAuth};
use crate::net::{Ipv4Net, Secret};
use crate::protocol::{BackendEvent, BackendRequest, ClientAuth, EapIdentity, Routes};
use crate::tunnel::{Tunnel, TunnelOpts};
use crate::vici::EventName;
use crate::{netlink, privdrop};
use std::io::{BufRead, BufReader, Write};
use std::process::{ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use vec1::Vec1;

// ═════════════════════════════ GUI side ═════════════════════════════
pub enum Event {
    Log(String),
    /// progress, from SAML or from the privileged backend
    Backend(BackendEvent),
    Elevating,
    Error(String),
    Finished,
}

#[derive(Default)]
struct Shared {
    backend_stdin: Option<ChildStdin>,
}

pub struct Session {
    shared: Arc<Mutex<Shared>>,
    cancel: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Session {
    pub fn start(cfg: &Config, profile: &Profile, tx: Sender<Event>, ctx: eframe::egui::Context) -> Session {
        let shared = Arc::new(Mutex::new(Shared::default()));
        let cancel = Arc::new(AtomicBool::new(false));
        let (cfg, profile) = (cfg.clone(), profile.clone());
        let (sh, cn) = (shared.clone(), cancel.clone());
        let thread = std::thread::spawn(move || {
            let tx2 = tx.clone();
            let ctx2 = ctx.clone();
            let send: Arc<dyn Fn(Event) + Send + Sync> = Arc::new(move |e: Event| {
                let _ = tx2.send(e);
                ctx2.request_repaint();
            });
            if let Err(e) = run(&cfg, &profile, &sh, &cn, send.clone()) {
                send(Event::Error(e));
            }
            send(Event::Finished);
        });
        Session { shared, cancel, thread: Some(thread) }
    }

    pub fn disconnect(&self) {
        self.cancel.store(true, Ordering::SeqCst);
        if let Some(stdin) = self.shared.lock().unwrap().backend_stdin.as_mut() {
            let _ = stdin.write_all(b"disconnect\n");
            let _ = stdin.flush();
        }
    }

    pub fn is_finished(&self) -> bool {
        self.thread.as_ref().is_none_or(|t| t.is_finished())
    }

    pub fn shutdown(mut self, timeout: Duration) {
        self.disconnect();
        let t0 = Instant::now();
        while !self.is_finished() && t0.elapsed() < timeout {
            std::thread::sleep(Duration::from_millis(50));
        }
        self.shared.lock().unwrap().backend_stdin.take(); // EOF => backend tears down regardless
        if let Some(t) = self.thread.take()
            && t.is_finished() {
                let _ = t.join();
            }
    }
}

/// "error: can't connect without {what}", with why it's needed and where to enter it (see `diag`).
fn missing(what: &str, why: &str, help: &str) -> String {
    crate::diag("error", &format!("can't connect without {what}"), why, help)
}

fn no_token() -> String {
    crate::diag("error", "the SSO login gave no token", "the login page finished without handing one over", "connect again and sign in once more")
}

/// How profile `p` authenticates: SSO -> (UID, SAML token), EAP login -> (username, password), else PSK only.
pub fn client_auth(cfg: &Config, p: &Profile, sso_token: Option<Secret>) -> Result<ClientAuth, String> {
    let missing = || missing("a username and password", "with SSO off, this connection signs in with them", "enter them under Sign-in, or turn on SSO");
    match (p.sso.enabled, p.auth.mode) {
        (true, _) => Ok(ClientAuth::Eap { identity: EapIdentity::Uid(cfg.uid), secret: sso_token.ok_or_else(no_token)? }),
        (false, UserAuth::Eap) => {
            let identity = EapIdentity::User(p.auth.username.clone().ok_or_else(missing)?);
            let secret = Secret::new(p.auth.password.clone()).map_err(|_| missing())?;
            Ok(ClientAuth::Eap { identity, secret })
        }
        (false, UserAuth::None) => Ok(ClientAuth::PskOnly),
    }
}

/// The backend request for profile `p`. The profile's types already guarantee valid values; this refuses what's
/// missing.
pub fn build_request(cfg: &Config, p: &Profile, auth: ClientAuth) -> Result<BackendRequest, String> {
    let proposals = |v: &[crate::net::Proposal], phase: &str| {
        Vec1::try_from_vec(v.to_vec()).map_err(|_| missing(&format!("a {phase} proposal"), "it says which encryption the gateway may choose", &format!("select one under Advanced → {phase}")))
    };
    let routes = match p.network.route_mode {
        RouteMode::Gateway => Routes::Gateway,
        RouteMode::Full => Routes::Full,
        RouteMode::Custom => Routes::Custom(Vec1::try_from_vec(p.network.custom_routes.clone()).map_err(|_| {
            missing("a network to route", "routing is set to only listed networks, and the list is empty", "enter one under Advanced → Network, or choose another routing option")
        })?),
    };
    Ok(BackendRequest {
        gateway: p.gateway.clone().ok_or_else(|| missing("a remote gateway", "it's the FortiGate's address", "enter it under Connection → Remote gateway"))?,
        ike_port: p.ike.port,
        psk: Secret::new(p.psk.clone())
            .map_err(|_| missing("a pre-shared key", "the FortiGate proves who it is with it, also when you sign in with SSO", "enter it under Connection → Pre-shared key"))?,
        auth,
        local_id: p.ike.local_id.clone(),
        dh_groups: Vec1::try_from_vec(p.ike.dh_groups.clone())
            .map_err(|_| missing("a DH group", "Phase 1 needs one for the key exchange", "select one under Advanced → Phase 1"))?,
        ike_proposals: proposals(&p.ike.proposals, "Phase 1")?,
        esp_proposals: proposals(&p.esp.proposals, "Phase 2")?,
        natt_keepalive: p.ike.natt_keepalive,
        ifname: p.network.ifname.clone(),
        mtu: p.network.mtu,
        routes,
        block_ipv6: p.network.block_ipv6,
        set_dns: p.network.set_dns,
        verbose: cfg.verbose,
    })
}

/// Everything that would make the connection fail after the SSO login and the password prompt: all settings, the
/// PSK, and username + password without SSO. Only the SSO token can't be checked yet.
fn preflight(cfg: &Config, p: &Profile) -> Result<(), String> {
    build_request(cfg, p, ClientAuth::PskOnly)?;
    if !p.sso.enabled {
        client_auth(cfg, p, None)?;
    }
    Ok(())
}

fn run(cfg: &Config, p: &Profile, shared: &Arc<Mutex<Shared>>, cancel: &Arc<AtomicBool>, send: Arc<dyn Fn(Event) + Send + Sync>) -> Result<(), String> {
    if charon::charon_binary().is_none() {
        return Err(charon::install_hint());
    }
    preflight(cfg, p)?;

    // ---- 1. SAML, unprivileged, in-process (SSO profiles only) ----
    let sso_token = if p.sso.enabled { Some(sso_login(cfg, p, cancel, send.clone())?) } else { None };
    if cancel.load(Ordering::SeqCst) {
        return Ok(());
    }
    let sso_token = sso_token.map(|t| Secret::new(t).map_err(|_| no_token())).transpose()?;
    let req = build_request(cfg, p, client_auth(cfg, p, sso_token)?)?;

    // ---- 2. IKE + tunnel as root: pkexec <self> --backend ----
    run_backend(&req, shared, cancel, send)
}

/// SAML login; Err("") on user cancel.
fn sso_login(cfg: &Config, p: &Profile, cancel: &Arc<AtomicBool>, send: Arc<dyn Fn(Event) + Send + Sync>) -> Result<String, String> {
    send(Event::Backend(BackendEvent::SamlStart));
    let s2 = send.clone();
    let log: Arc<dyn Fn(String) + Send + Sync> = Arc::new(move |m| s2(Event::Log(m)));
    let s3 = send.clone();
    let res = crate::saml::login(
        &crate::saml::SamlParams {
            gateway: p.gateway.clone().ok_or_else(|| missing("a remote gateway", "it's the FortiGate's address", "enter it under Connection → Remote gateway"))?,
            port: p.sso.port,
            uid: cfg.uid,
            verify_cert: p.sso.verify_cert,
            open_browser: p.sso.open_browser,
            timeout: Duration::from_secs(p.sso.timeout.get().into()),
        },
        cancel,
        log,
        &move |url| s3(Event::Backend(BackendEvent::SamlUrl { url: url.to_string() })),
    );
    let saml = match res {
        Err(e) if cancel.load(Ordering::SeqCst) => {
            send(Event::Log(format!("SAML: {e}")));
            return Ok(String::new());
        }
        r => r?,
    };
    send(Event::Backend(BackendEvent::SamlOk { username: saml.username }));
    Ok(saml.token)
}

fn run_backend(req: &BackendRequest, shared: &Arc<Mutex<Shared>>, cancel: &Arc<AtomicBool>, send: Arc<dyn Fn(Event) + Send + Sync>) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot locate own executable: {e}"))?;
    send(Event::Elevating);
    send(Event::Log("requesting root privileges (pkexec) to set up the tunnel".into()));
    let mut child = Command::new("pkexec")
        .arg(&exe)
        .arg("--backend")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot start pkexec: {e}"))?;
    let mut stdin = child.stdin.take().unwrap();
    let line = serde_json::to_string(req).map_err(|e| e.to_string())? + "\n";
    stdin.write_all(line.as_bytes()).map_err(|e| format!("backend stdin: {e}"))?;
    stdin.flush().ok();
    shared.lock().unwrap().backend_stdin = Some(stdin);
    if cancel.load(Ordering::SeqCst)
        && let Some(s) = shared.lock().unwrap().backend_stdin.as_mut() {
            let _ = s.write_all(b"disconnect\n");
        }
    let stderr = child.stderr.take().unwrap();
    let s4 = send.clone();
    let eth = std::thread::spawn(move || {
        for l in BufReader::new(stderr).lines().map_while(Result::ok) {
            if !l.trim().is_empty() {
                s4(Event::Log(l));
            }
        }
    });
    for line in BufReader::new(child.stdout.take().unwrap()).lines().map_while(Result::ok) {
        send(stdout_event(line));
    }
    let _ = eth.join();
    shared.lock().unwrap().backend_stdin.take();
    let st = child.wait().map_err(|e| e.to_string())?;
    match st.code() {
        Some(0) => Ok(()),
        Some(126) => Err("root authorization was cancelled".into()),
        Some(127) => Err("not authorized to run the VPN backend as root (pkexec)".into()),
        Some(1) => Ok(()), // backend already reported the error via a status event
        c => Err(format!("backend exited with status {c:?} (see log)")),
    }
}

/// What a backend stdout line means for the GUI: a status event, or a log line. An `@@` line that doesn't parse is
/// logged as an error, so a backend/GUI mismatch shows up instead of being ignored.
fn stdout_event(line: String) -> Event {
    match BackendEvent::from_line(&line) {
        Some(Ok(ev)) => Event::Backend(ev),
        Some(Err(e)) => Event::Log(format!("ERROR: {e}")),
        None => Event::Log(line),
    }
}

/// Networks for log lines: "10.0.0.0/8, 10.1.0.0/16".
fn nets(v: &[Ipv4Net]) -> String {
    v.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
}

// ═════════════════════════════ privileged side ═════════════════════════════
static STOP: AtomicBool = AtomicBool::new(false);
static VERBOSE: AtomicBool = AtomicBool::new(false);

fn out(line: String) {
    let mut o = std::io::stdout().lock();
    let _ = writeln!(o, "{line}"); // never panic on a closed pipe
    let _ = o.flush();
}
fn status(ev: BackendEvent) {
    out(ev.to_line());
}
fn blog(m: String) {
    out(format!("[*] {m}"));
}
fn bdbg(m: String) {
    if VERBOSE.load(Ordering::Relaxed) {
        out(format!("[d] {m}"));
    }
}

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

/// Entry point for `archway-vpn --backend` (run via pkexec).
pub fn privileged_main() -> i32 {
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGHUP, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    if unsafe { libc::geteuid() } != 0 {
        status(BackendEvent::Error { message: "backend must run as root".into() });
        return 1;
    }
    let mut first = String::new();
    if std::io::stdin().read_line(&mut first).unwrap_or(0) == 0 {
        return 1;
    }
    let req: BackendRequest = match serde_json::from_str(&first) {
        Ok(r) => r,
        Err(e) => {
            status(BackendEvent::Error { message: format!("bad backend request: {e}") });
            return 1;
        }
    };
    VERBOSE.store(req.verbose, Ordering::Relaxed);
    std::thread::spawn(|| {
        for line in std::io::stdin().lock().lines() {
            match line {
                Ok(l) if ["disconnect", "quit", "stop"].contains(&l.trim()) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        STOP.store(true, Ordering::SeqCst); // also on EOF: front-end went away
    });
    match run_privileged(&req) {
        Ok(()) => 0,
        Err(e) => {
            blog(format!("ERROR: {e}"));
            status(BackendEvent::Error { message: e });
            status(BackendEvent::Disconnected);
            1
        }
    }
}

fn run_privileged(r: &BackendRequest) -> Result<(), String> {
    let binary = charon::charon_binary().ok_or_else(charon::install_hint)?;
    // held until this process exits, also across the privilege drop
    let _lock = charon::lock()?;
    if charon::kill_stale() > 0 {
        blog("stopped a charon left behind by a previous run".into());
    }
    let n = netlink::purge(&r.ifname)?;
    if n > 0 {
        blog(format!("purged {n} stale item(s) from a previous run"));
    }
    let dns_name = r.set_dns.then(|| charon::resolvconf_name(&r.ifname, charon::resolvconf_target().as_deref()));
    let conf = charon::write_config(&charon::config(u32::from(r.natt_keepalive.get()), r.verbose, dns_name.as_deref()))?;
    status(BackendEvent::IkeStart { gateway: r.gateway.clone() });
    // charon must be started from this (the main) thread: it gets SIGTERM when this thread ends
    let mut child = charon::spawn(binary, &conf)?;
    let stderr = child.stderr.take().expect("piped stderr");
    std::thread::spawn(move || {
        // always shown: startup and plugin errors are only explained here (verbose raises charon's log level)
        for l in BufReader::new(stderr).lines().map_while(Result::ok) {
            blog(format!("charon: {l}"));
        }
    });
    let result = session(r, &mut child);
    // SIGTERM so charon removes its SAs and policies; the kept CAP_KILL allows this after the privilege drop too
    charon::stop(&mut child, Duration::from_secs(5));
    result
}

/// One VPN session with charon running: connect, set up the tunnel, drop privileges, wait, tear down.
fn session(r: &BackendRequest, child: &mut std::process::Child) -> Result<(), String> {
    let mut v = charon::wait_for_socket(child, Duration::from_secs(5))?;
    charon::check_plugins(&mut v, r.set_dns)?;
    let params = ConnParams {
        gateway: r.gateway.clone(),
        ike_port: r.ike_port,
        ike_proposals: r.ike_proposals.clone(),
        dh_groups: r.dh_groups.clone(),
        esp_proposals: r.esp_proposals.clone(),
        local_id: r.local_id.clone(),
        auth: r.auth.clone(),
        psk: r.psk.clone(),
    };
    // the interface exists before IKE, so charon can hand the VPN's DNS servers to resolvconf for it
    let opts = TunnelOpts { ifname: r.ifname.clone(), mtu: r.mtu, routes: r.routes.overrides(), block_ipv6: r.block_ipv6, set_dns: r.set_dns };
    let mut tun = Tunnel::create(&opts, &bdbg)?;
    let result = tunnel_session(&mut v, &mut tun, &params, &opts);
    // the SA first: charon then removes the VPN's DNS servers while the interface still exists
    charon::terminate(&mut v);
    tun.down(&bdbg);
    if result.is_ok() {
        blog("disconnected".into());
        status(BackendEvent::Disconnected);
    }
    result
}

/// Connect, configure the interface, drop privileges and wait until the session ends. The caller tears down.
fn tunnel_session(v: &mut crate::vici::Vici, tun: &mut Tunnel, params: &ConnParams, opts: &TunnelOpts) -> Result<(), String> {
    let est = charon::connect(v, params, &blog)?;
    blog(format!("IKE SA + child SA established: ip {} routes [{}]", est.vip, nets(&est.remote_ts)));
    status(BackendEvent::Established { ip: est.vip });
    if STOP.load(Ordering::SeqCst) {
        return Ok(());
    }
    tun.configure(&est, opts, &bdbg)?;
    status(BackendEvent::TunnelUp { ifname: opts.ifname.clone(), ip: est.vip, routes: tun.routes.clone(), full_tunnel: tun.full });
    blog(format!("tunnel up: {} ip={} routes [{}]", opts.ifname, est.vip, nets(&tun.routes)));

    // charon reports the SA going down (gateway delete, DPD timeout) as ike-updown
    v.register(EventName::IkeUpdown)?;
    privdrop::drop_to(privdrop::pkexec_uid()?)?;
    blog("running as your user now, keeping only the network-admin and kill capabilities".into());
    status(BackendEvent::Connected);

    let mut reason = "disconnect requested";
    while !STOP.load(Ordering::SeqCst) {
        match v.next_event(Duration::from_secs(1)) {
            Ok(Some((EventName::IkeUpdown, body))) if charon::is_down(&body) => {
                reason = "the gateway ended the connection";
                break;
            }
            Ok(_) => {}
            Err(e) => {
                blog(format!("charon stopped: {e}"));
                reason = "strongSwan stopped";
                break;
            }
        }
    }
    blog(format!("disconnecting: {reason}"));
    status(BackendEvent::Disconnecting);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use vec1::vec1;

    fn profile() -> (Config, Profile) {
        let cfg = Config::default();
        let mut p = cfg.profiles[0].clone();
        p.gateway = Some("vpn.example.com".parse().unwrap());
        p.psk = "k".into();
        (cfg, p)
    }

    fn token() -> Secret {
        Secret::new("tok".into()).unwrap()
    }

    #[test]
    fn request_from_a_normal_profile() {
        let (cfg, p) = profile();
        let r = build_request(&cfg, &p, client_auth(&cfg, &p, Some(token())).unwrap()).unwrap();
        assert_eq!(r.auth, ClientAuth::Eap { identity: EapIdentity::Uid(cfg.uid), secret: token() }, "SSO: the FortiClient UID is the EAP identity");
        assert_eq!(crate::net::ike_proposals(&r.ike_proposals, &r.dh_groups), ["aes128-sha1-ecp384", "aes256-sha256-ecp384"]);
        assert_eq!(r.routes, Routes::Gateway);
    }

    #[test]
    fn username_login_and_psk_only() {
        let (cfg, mut p) = profile();
        p.sso.enabled = false;
        assert!(client_auth(&cfg, &p, None).unwrap_err().starts_with("error: can't connect without a username and password\n"));
        p.auth.username = Some("jane".parse().unwrap());
        assert!(client_auth(&cfg, &p, None).unwrap_err().starts_with("error: can't connect without a username and password\n"), "no password");
        p.auth.password = "pw".into();
        assert_eq!(
            client_auth(&cfg, &p, None).unwrap(),
            ClientAuth::Eap { identity: EapIdentity::User("jane".parse().unwrap()), secret: Secret::new("pw".into()).unwrap() }
        );
        p.auth.mode = UserAuth::None;
        assert_eq!(client_auth(&cfg, &p, None).unwrap(), ClientAuth::PskOnly);
    }

    #[test]
    fn incomplete_profiles_are_refused_before_pkexec() {
        let (cfg, p) = profile();
        let bad = |f: &dyn Fn(&mut Profile)| {
            let mut q = p.clone();
            f(&mut q);
            build_request(&cfg, &q, ClientAuth::PskOnly).unwrap_err()
        };
        // like the app's other errors: a headline, then what's wrong and what to do (see `diag`)
        let refused = |e: String, headline: &str| assert!(e.starts_with(&format!("error: {headline}\n  note: ")) && e.contains("\n  help: "), "{e}");
        refused(bad(&|q| q.gateway = None), "can't connect without a remote gateway");
        refused(bad(&|q| q.psk.clear()), "can't connect without a pre-shared key");
        refused(bad(&|q| q.ike.proposals.clear()), "can't connect without a Phase 1 proposal");
        refused(bad(&|q| q.ike.dh_groups.clear()), "can't connect without a DH group");
        refused(bad(&|q| q.esp.proposals.clear()), "can't connect without a Phase 2 proposal");
        let e = bad(&|q| {
            q.network.route_mode = RouteMode::Custom;
            q.network.custom_routes.clear();
        });
        refused(e, "can't connect without a network to route");
    }

    #[test]
    fn preflight_refuses_what_would_fail_after_the_sso_login() {
        let (cfg, mut p) = profile();
        assert_eq!(preflight(&cfg, &p), Ok(()));
        p.psk.clear();
        assert!(preflight(&cfg, &p).unwrap_err().starts_with("error: can't connect without a pre-shared key\n"));
        let (cfg, mut p) = profile();
        p.sso.enabled = false;
        assert!(preflight(&cfg, &p).unwrap_err().starts_with("error: can't connect without a username and password\n"));
    }

    #[test]
    fn routes_follow_the_routing_choice() {
        let (cfg, mut p) = profile();
        p.network.route_mode = RouteMode::Full;
        assert_eq!(build_request(&cfg, &p, ClientAuth::PskOnly).unwrap().routes, Routes::Full);
        p.network.route_mode = RouteMode::Custom;
        p.network.custom_routes = vec!["10.0.0.0/8".parse().unwrap()];
        assert_eq!(build_request(&cfg, &p, ClientAuth::PskOnly).unwrap().routes, Routes::Custom(vec1!["10.0.0.0/8".parse().unwrap()]));
    }

    #[test]
    fn unreadable_status_lines_are_logged_as_errors() {
        assert!(matches!(stdout_event("@@{\"event\":\"connected\"}".into()), Event::Backend(BackendEvent::Connected)));
        assert!(matches!(stdout_event("[*] hello".into()), Event::Log(l) if l == "[*] hello"));
        assert!(matches!(stdout_event("@@{\"event\":\"tunnel_up\",\"dns\":[]}".into()), Event::Log(l) if l.starts_with("ERROR: unreadable status line")));
    }
}
