//! Connection orchestration (all native Rust, no external interpreter).
//!
//! GUI side (unprivileged):  SAML login in-process (browser via xdg-open, local callback listener).
//! Privileged side:          `pkexec <this binary> --backend` - IKEv2 + kernel XFRM tunnel.
//!   * the request (settings + PSK + one-time token) is sent as one JSON line on stdin, never on argv;
//!   * afterwards stdin is a control channel: "disconnect" or EOF (GUI closed/crashed) => teardown;
//!   * progress is reported as `@@{json}` lines on stdout, other lines are log output.

use crate::config::{Config, Profile, RouteMode, UserAuth};
use crate::ike::{parse_proposals, Ike, IkeParams};
use crate::tunnel::{purge_stale, set_udp_encap, Tunnel, TunnelOpts};
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

#[derive(Serialize, Deserialize, Clone)]
pub struct BackendRequest {
    pub gateway: String,
    pub ike_port: u16,
    pub uid: String,
    pub psk: String,
    /// EAP identity (UID for SSO, username otherwise); None = PSK-only authentication
    pub eap_identity: Option<String>,
    /// EAP secret: SAML tokenid or password
    pub token: String,
    pub local_id: Option<String>,
    pub dh_groups: Vec<u16>,
    pub ike_proposals: String,
    pub esp_proposals: String,
    pub natt_keepalive: u32,
    pub ifname: String,
    pub mtu: u16,
    pub routes: Option<Vec<String>>,
    pub block_ipv6: bool,
    pub set_dns: bool,
    pub verbose: bool,
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

fn build_request(cfg: &Config, p: &Profile, sso_token: Option<String>) -> BackendRequest {
    let (eap_identity, token) = credentials(cfg, p, sso_token);
    let props = |v: &Vec<crate::config::Proposal>| v.iter().map(|x| x.spec()).collect::<Vec<_>>().join(",");
    // first group is used in the KE payload: prefer the strongest selected ECP group
    let mut groups: Vec<u16> = [20, 21, 19, 14].into_iter().filter(|g| p.ike.dh_groups.contains(g)).collect();
    if groups.is_empty() {
        groups.push(20);
    }
    BackendRequest {
        gateway: p.gateway.trim().to_string(),
        ike_port: p.ike.port,
        uid: cfg.uid.clone(),
        psk: p.psk.clone(),
        eap_identity,
        token,
        local_id: Some(p.ike.local_id.trim().to_string()).filter(|s| !s.is_empty()),
        dh_groups: groups,
        ike_proposals: props(&p.ike.proposals),
        esp_proposals: props(&p.esp.proposals),
        natt_keepalive: p.ike.natt_keepalive,
        ifname: p.network.ifname.clone(),
        mtu: p.network.mtu,
        routes: match p.network.route_mode {
            RouteMode::Gateway => None,
            RouteMode::Full => Some(vec!["0.0.0.0/0".into()]),
            RouteMode::Custom => Some(
                p.network.custom_routes
                    .split(|c: char| c == ',' || c.is_whitespace())
                    .filter(|r| !r.is_empty())
                    .map(String::from)
                    .collect(),
            ),
        },
        block_ipv6: p.network.block_ipv6,
        set_dns: p.network.set_dns,
        verbose: cfg.verbose,
    }
}

fn run(cfg: &Config, p: &Profile, shared: &Arc<Mutex<Shared>>, cancel: &Arc<AtomicBool>, send: Arc<dyn Fn(Event) + Send + Sync>) -> Result<(), String> {
    if p.gateway.trim().is_empty() {
        return Err("no remote gateway configured".into());
    }
    parse_proposals(&p.ike.proposals.iter().map(|x| x.spec()).collect::<Vec<_>>().join(","))?;
    parse_proposals(&p.esp.proposals.iter().map(|x| x.spec()).collect::<Vec<_>>().join(","))?;
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
    let req = serde_json::to_string(&build_request(cfg, p, sso_token)).unwrap() + "\n";
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
    status(json!({"event": "ike_start", "gateway": r.gateway}));
    let mut ike = Ike::new(
        IkeParams {
            gateway: r.gateway.clone(),
            port: r.ike_port,
            psk: Some(r.psk.clone()),
            uid: r.uid.clone(),
            eap_identity: r.eap_identity.clone(),
            token: r.token.clone(),
            local_id: r.local_id.clone(),
            groups: r.dh_groups.clone(),
            ike_props: parse_proposals(&r.ike_proposals)?,
            esp_props: parse_proposals(&r.esp_proposals)?,
            fake_nat: true,
        },
        Box::new(blog),
        Box::new(bdbg),
    )?;
    ike.sa_init()?;
    let child = ike.auth()?;
    blog("IKE SA + child SA established".into());
    status(json!({"event": "established", "config": child.cfg}));
    if let Some(b) = &child.cfg.banner {
        blog(format!("banner: {b}"));
    }
    if STOP.load(Ordering::SeqCst) {
        ike.delete();
        status(json!({"event": "disconnected"}));
        return Ok(());
    }

    let n = purge_stale(&r.ifname);
    if n > 0 {
        blog(format!("purged {n} stale item(s) from a previous run"));
    }
    let opts = TunnelOpts { ifname: r.ifname.clone(), mtu: r.mtu, routes: r.routes.clone(), block_ipv6: r.block_ipv6, set_dns: r.set_dns };
    let mut tun = Tunnel::up(&ike, &child, &opts, &bdbg)?;
    status(json!({"event": "tunnel_up", "ifname": r.ifname, "ip": child.cfg.ip, "routes": tun.routes,
                  "dns": child.cfg.dns, "domain": child.cfg.domain, "full_tunnel": tun.full}));
    blog(format!("tunnel up: {} ip={:?} routes={:?}", r.ifname, child.cfg.ip, tun.routes));
    status(json!({"event": "connected"}));

    // keepalive / DPD loop
    ike.sock.set_read_timeout(Some(Duration::from_secs(1))).ok();
    let mut last_ka = Instant::now() - Duration::from_secs(3600);
    let mut reason = "disconnect requested";
    while !STOP.load(Ordering::SeqCst) {
        if last_ka.elapsed() >= Duration::from_secs(r.natt_keepalive.max(5) as u64) {
            ike.send_keepalive();
            last_ka = Instant::now();
        }
        match ike.recv_msg() {
            Ok(msg) if msg[19] & 0x20 == 0 => match ike.handle_peer_request(&msg) {
                Ok(true) => {
                    reason = "gateway deleted the SA";
                    break;
                }
                Ok(false) => {}
                Err(e) => bdbg(format!("ignored bad message: {e}")),
            },
            Ok(_) => {}
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => {}
            Err(e) => {
                bdbg(format!("socket: {e}"));
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }
    blog(format!("disconnecting: {reason}"));
    status(json!({"event": "disconnecting"}));
    tun.down(&bdbg);
    let _ = set_udp_encap(&ike, false);
    if reason != "gateway deleted the SA" {
        ike.delete();
    }
    blog("disconnected".into());
    status(json!({"event": "disconnected"}));
    Ok(())
}

/// `fortisaml-gui --down [ifname]`: remove leftovers (needs root).
pub fn down_main(ifname: &str) -> i32 {
    let n = purge_stale(ifname);
    println!("removed {n} stale item(s)");
    0
}

/// `fortisaml-gui --probe [--gateway H] [--saml-port P] [--ike-port P] [--psk K] [--no-verify] [--no-browser]
///                        [--token T] [--no-sso --username U --password P | --no-eap] [-v]`
/// Unprivileged end-to-end test: SAML + IKEv2/EAP negotiation with the selected profile (overridable),
/// prints the result and deletes the SA again. Nothing is installed in the kernel.
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
        let req = build_request(&cfg, &p, token);
        let mut ike = Ike::new(
            IkeParams {
                gateway: req.gateway.clone(),
                port: req.ike_port,
                psk: Some(req.psk.clone()),
                uid: req.uid.clone(),
                eap_identity: req.eap_identity.clone(),
                token: req.token.clone(),
                local_id: req.local_id.clone(),
                groups: req.dh_groups.clone(),
                ike_props: parse_proposals(&req.ike_proposals)?,
                esp_props: parse_proposals(&req.esp_proposals)?,
                fake_nat: true,
            },
            Box::new(blog),
            Box::new(bdbg),
        )?;
        ike.sa_init()?;
        let c = ike.auth()?;
        blog(format!("PROBE OK: IKE SA + child SA established; config {}", serde_json::to_string(&c.cfg).unwrap()));
        blog(format!("TSr {:?}, ESP integ {}, SPI out {} in {}", c.tsr, c.integ, crate::ike::hex(&c.spi_out), crate::ike::hex(&c.spi_in)));
        ike.delete();
        blog("SA deleted".into());
        Ok(())
    })();
    match result {
        Ok(()) => 0,
        Err(e) => {
            blog(format!("PROBE FAILED: {e}"));
            1
        }
    }
}
