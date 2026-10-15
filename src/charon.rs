//! A private strongSwan charon for one session: our own config and VICI socket under /run/fortisaml-gui, random
//! IKE ports, no routes or addresses of its own (we do those on our xfrm interface), and a plugin allowlist.
//! Secrets never go into the config file; they're loaded over VICI.

use crate::net::{Host, IfName, Ipv4Net, Secret};
use crate::netlink::IF_ID;
use crate::vici::{Empty, Status, Vici};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::Ipv4Addr;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub const RUN_DIR: &str = "/run/fortisaml-gui";
/// Where distros install charon-systemd (Fedora/Arch, Debian/Ubuntu).
pub const CHARON_PATHS: [&str; 2] = ["/usr/bin/charon-systemd", "/usr/sbin/charon-systemd"];
/// Plugins we load (plus `resolve` when VPN DNS is wanted); `stats` confirms they loaded.
pub const PLUGINS: [&str; 10] =
    ["random", "nonce", "openssl", "kernel-netlink", "socket-default", "vici", "eap-identity", "eap-mschapv2", "eap-gtc", "eap-md5"];
/// Plugins without which a FortiGate SSO connection can't work.
const REQUIRED: [&str; 5] = ["openssl", "kernel-netlink", "socket-default", "vici", "eap-mschapv2"];
pub const CONN: &str = "fortisaml";

pub fn charon_binary() -> Option<&'static str> {
    CHARON_PATHS.into_iter().find(|p| Path::new(p).is_file())
}

/// What to tell the user when charon-systemd isn't installed.
pub fn install_hint() -> &'static str {
    "strongSwan is needed for the IPsec connection; install it: Fedora `sudo dnf install strongswan`, \
     Debian/Ubuntu `sudo apt install charon-systemd strongswan-swanctl libstrongswan-standard-plugins libcharon-extra-plugins libcharon-extauth-plugins`, Arch `sudo pacman -S strongswan`"
}

pub fn socket_path() -> PathBuf {
    Path::new(RUN_DIR).join("charon.vici")
}
fn conf_path() -> PathBuf {
    Path::new(RUN_DIR).join("strongswan.conf")
}

/// Create /run/fortisaml-gui (0700, root only).
fn make_run_dir() -> Result<(), String> {
    std::fs::DirBuilder::new().recursive(true).mode(0o700).create(RUN_DIR).map_err(|e| format!("{RUN_DIR}: {e}"))
}

/// One VPN session at a time: an exclusive lock held for the backend's lifetime (released by the kernel when it
/// exits, also on a crash).
pub fn lock() -> Result<std::fs::File, String> {
    make_run_dir()?;
    lock_at(&Path::new(RUN_DIR).join("lock"))
}

fn lock_at(path: &Path) -> Result<std::fs::File, String> {
    use std::os::fd::AsRawFd;
    let f = std::fs::OpenOptions::new().create(true).truncate(false).write(true).mode(0o600).open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    // SAFETY: flock(2) on a file descriptor we own
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("a VPN session is already running; disconnect it first".into());
    }
    Ok(f)
}

/// The name under which the VPN's DNS servers are given to resolvconf(8). systemd-resolved's resolvconf needs the
/// real interface. openresolv and Debian's resolvconf take any record name and order records by it: a `lo.` name
/// sorts first, so the VPN's servers are asked before the LAN's.
pub fn resolvconf_name(ifname: &IfName, resolvconf_target: Option<&Path>) -> String {
    match resolvconf_target.and_then(|t| t.file_name()).and_then(|n| n.to_str()) {
        Some("resolvectl") => ifname.to_string(),
        _ => format!("lo.{ifname}"),
    }
}

/// What the system's resolvconf links to (`/usr/bin/resolvectl` for systemd-resolved).
pub fn resolvconf_target() -> Option<PathBuf> {
    ["/sbin/resolvconf", "/usr/sbin/resolvconf", "/usr/bin/resolvconf"].iter().find_map(|p| std::fs::canonicalize(p).ok())
}

/// The private strongswan.conf. No secrets: those go over VICI.
/// With `dns_name` (see `resolvconf_name`), the resolve plugin asks the gateway for DNS servers and hands them to the
/// system's resolvconf(8) under that name; it removes them again when the SA goes down. `iface` is the setting since
/// strongSwan 5.9.9, older versions use `iface_prefix` plus the server address. Without a resolvconf the plugin would
/// write `file` instead, so that points into our run directory, never at /etc/resolv.conf.
pub fn config(keepalive_s: u32, verbose: bool, dns_name: Option<&str>) -> String {
    let run = RUN_DIR;
    let level = if verbose { 2 } else { 1 };
    let mut plugins = PLUGINS.join(" ");
    let mut resolve = String::new();
    if let Some(n) = dns_name {
        plugins.push_str(" resolve ");
        resolve = format!(
            "        resolve {{\n            file = {run}/resolv.conf\n            resolvconf {{\n                iface = {n}\n                iface_prefix = {n}.\n            }}\n        }}\n"
        );
    }
    format!(
        "charon-systemd {{
    load = {plugins}
    port = 0
    port_nat_t = 0
    install_routes = no
    install_virtual_ip = no
    keep_alive = {keepalive_s}s
    retransmit_tries = 3
    filelog {{
        stderr {{
            default = {level}
            ike_name = yes
        }}
    }}
    journal {{
        default = -1
    }}
    plugins {{
        vici {{
            socket = unix://{run}/charon.vici
        }}
{resolve}    }}
}}
"
    )
}

/// Create /run/fortisaml-gui (0700) and write the config (0600). Returns its path.
pub fn write_config(contents: &str) -> Result<PathBuf, String> {
    make_run_dir()?;
    let path = conf_path();
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(contents.as_bytes()).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(path)
}

/// Start charon with `conf`. It gets SIGTERM when this thread exits (PR_SET_PDEATHSIG), so call this from the main
/// thread. stderr (its log) is piped for the caller to forward.
pub fn spawn(binary: &str, conf: &Path) -> Result<Child, String> {
    let mut cmd = Command::new(binary);
    cmd.env_clear()
        .env("STRONGSWAN_CONF", conf)
        .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // SAFETY: only async-signal-safe calls between fork and exec
    unsafe {
        cmd.pre_exec(|| {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.spawn().map_err(|e| format!("cannot start {binary}: {e}"))
}

/// Stop charon cleanly: SIGTERM (it then removes its SAs and policies), wait up to `grace`, SIGKILL as a last
/// resort. Returns its exit status if it could be collected.
pub fn stop(child: &mut Child, grace: Duration) -> Option<std::process::ExitStatus> {
    // SAFETY: kill(2) on our own child's pid
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    let t0 = Instant::now();
    while t0.elapsed() < grace {
        if let Ok(Some(st)) = child.try_wait() {
            return Some(st);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    child.wait().ok()
}

/// Wait until charon's VICI socket accepts connections.
pub fn wait_for_socket(child: &mut Child, timeout: Duration) -> Result<Vici, String> {
    let t0 = Instant::now();
    loop {
        if let Ok(v) = Vici::connect(&socket_path()) {
            return Ok(v);
        }
        if let Ok(Some(st)) = child.try_wait() {
            return Err(format!("charon exited during startup ({st}); see the log above"));
        }
        if t0.elapsed() > timeout {
            return Err(format!("charon didn't open its control socket within {}s; see the log above", timeout.as_secs()));
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[derive(Deserialize, Default)]
struct Stats {
    #[serde(default)]
    plugins: Vec<String>,
}

/// Check that the plugins we need are loaded (`resolve` too when VPN DNS is wanted).
pub fn check_plugins(v: &mut Vici, dns: bool) -> Result<(), String> {
    let s: Stats = v.request("stats", &Empty {}, Duration::from_secs(5), &mut |_, _| {})?;
    let needed = REQUIRED.into_iter().chain(dns.then_some("resolve"));
    let missing: Vec<&str> = needed.filter(|p| !s.plugins.iter().any(|l| l == p)).collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "strongSwan is missing plugin(s) {}; install the extra plugins (Debian/Ubuntu: `sudo apt install charon-systemd strongswan-swanctl libstrongswan-standard-plugins libcharon-extra-plugins libcharon-extauth-plugins`)",
            missing.join(", ")
        ))
    }
}

/// How the client authenticates.
#[derive(Clone, Debug)]
pub enum ClientAuth {
    /// EAP with this identity and secret (SSO: FortiClient UID + SAML token; otherwise username + password)
    Eap { identity: String, secret: Secret },
    /// pre-shared key only, no user authentication
    PskOnly,
}

#[derive(Clone, Debug)]
pub struct ConnParams {
    pub gateway: Host,
    pub ike_port: u16,
    /// strongSwan proposal strings, e.g. "aes128-sha1-ecp384"
    pub ike_proposals: Vec<String>,
    pub esp_proposals: Vec<String>,
    pub local_id: Option<String>,
    pub auth: ClientAuth,
    pub psk: Secret,
}

#[derive(Serialize)]
struct AuthSection {
    auth: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    eap_id: Option<String>,
}

#[derive(Serialize)]
struct ChildSection {
    remote_ts: Vec<String>,
    esp_proposals: Vec<String>,
    if_id_in: String,
    if_id_out: String,
}

#[derive(Serialize)]
struct ConnSection {
    version: String,
    remote_addrs: Vec<String>,
    remote_port: String,
    encap: String,
    vips: Vec<String>,
    proposals: Vec<String>,
    keyingtries: String,
    dpd_delay: String,
    local: AuthSection,
    remote: AuthSection,
    children: BTreeMap<String, ChildSection>,
}

/// The `load-conn` message for `p`.
pub fn conn_message(p: &ConnParams) -> BTreeMap<String, impl Serialize> {
    let local = match &p.auth {
        ClientAuth::Eap { identity, .. } => AuthSection { auth: "eap".into(), id: p.local_id.clone(), eap_id: Some(identity.clone()) },
        ClientAuth::PskOnly => AuthSection { auth: "psk".into(), id: p.local_id.clone(), eap_id: None },
    };
    let child = ChildSection {
        remote_ts: vec!["0.0.0.0/0".into()],
        esp_proposals: p.esp_proposals.clone(),
        if_id_in: format!("{IF_ID:#x}"),
        if_id_out: format!("{IF_ID:#x}"),
    };
    let conn = ConnSection {
        version: "2".into(),
        remote_addrs: vec![p.gateway.to_string()],
        remote_port: p.ike_port.to_string(),
        encap: "yes".into(),
        vips: vec!["0.0.0.0".into()],
        proposals: p.ike_proposals.clone(),
        keyingtries: "1".into(),
        dpd_delay: "30s".into(),
        local,
        remote: AuthSection { auth: "psk".into(), id: None, eap_id: None },
        children: BTreeMap::from([(CONN.to_string(), child)]),
    };
    BTreeMap::from([(CONN.to_string(), conn)])
}

#[derive(Serialize)]
struct Shared<'a> {
    id: &'a str,
    #[serde(rename = "type")]
    kind: &'a str,
    data: &'a str,
    owners: Vec<String>,
}

#[derive(Serialize)]
struct Initiate<'a> {
    ike: &'a str,
    child: &'a str,
    timeout: String,
    loglevel: String,
}

#[derive(Serialize)]
struct Terminate<'a> {
    ike: &'a str,
    timeout: String,
}

#[derive(Serialize)]
struct ListSas<'a> {
    ike: &'a str,
}

#[derive(Deserialize, Default, Debug)]
struct ChildInfo {
    #[serde(rename = "remote-ts", default)]
    remote_ts: Vec<String>,
}

#[derive(Deserialize, Default, Debug)]
struct IkeInfo {
    #[serde(rename = "remote-host", default)]
    remote_host: String,
    #[serde(rename = "local-vips", default)]
    local_vips: Vec<String>,
    #[serde(rename = "child-sas", default)]
    child_sas: BTreeMap<String, ChildInfo>,
}

#[derive(Deserialize, Default)]
struct LogLine {
    #[serde(default)]
    msg: String,
}

/// What the gateway gave us once the tunnel is up.
#[derive(Debug, Clone, PartialEq)]
pub struct Established {
    /// the gateway's IPv4 address as charon resolved it
    pub gateway: Ipv4Addr,
    pub vip: Ipv4Addr,
    /// remote traffic selectors (what the FortiGate routes through the tunnel)
    pub remote_ts: Vec<Ipv4Net>,
}

/// Turn charon's log of a failed `initiate` into a message the user can act on.
pub fn explain(log: &[String]) -> String {
    let has = |s: &str| log.iter().any(|l| l.contains(s));
    if has("AUTHENTICATION_FAILED") || has("EAP-MS-CHAPv2 failed") || (has("authentication of") && has("failed")) {
        "authentication failed: the SSO token was rejected or the pre-shared key is wrong".into()
    } else if has("NO_PROPOSAL_CHOSEN") {
        "the gateway accepts none of the Phase 1/Phase 2 proposals or DH groups in this profile".into()
    } else if has("giving up after") || has("retransmit") {
        "no answer from the gateway on the IKE port (check the gateway and IKE port)".into()
    } else {
        "the IPsec connection failed; see the log for charon's reason".into()
    }
}

/// Load the connection and secrets, initiate, and return what the gateway assigned. Log lines go to `log`.
pub fn connect(v: &mut Vici, p: &ConnParams, log: &dyn Fn(String)) -> Result<Established, String> {
    let st: Status = v.request("load-conn", &conn_message(p), Duration::from_secs(5), &mut |_, _| {})?;
    st.check("loading the connection")?;
    let mut shared = vec![Shared { id: "fortisaml-psk", kind: "IKE", data: &p.psk.0, owners: vec![] }];
    if let ClientAuth::Eap { identity, secret } = &p.auth {
        shared.push(Shared { id: "fortisaml-eap", kind: "EAP", data: &secret.0, owners: vec![identity.clone()] });
    }
    for s in &shared {
        let st: Status = v.request("load-shared", s, Duration::from_secs(5), &mut |_, _| {})?;
        st.check("loading the secrets")?;
    }
    v.register("control-log")?;
    let mut lines = Vec::new();
    let req = Initiate { ike: CONN, child: CONN, timeout: "30000".into(), loglevel: "1".into() };
    let st: Status = v.request("initiate", &req, Duration::from_secs(40), &mut |_, body| {
        if let Ok(l) = serde_vici::from_slice::<LogLine>(body) {
            log(format!("charon: {}", l.msg));
            lines.push(l.msg);
        }
    })?;
    if st.success != "yes" {
        return Err(explain(&lines));
    }
    // an SA we can't use (no virtual IP, IPv6 gateway) must not stay up at the gateway
    established(v).inspect_err(|_| terminate(v))
}

/// The virtual IP and remote traffic selectors of our SA (`list-sas`).
pub fn established(v: &mut Vici) -> Result<Established, String> {
    // charon streams list-sas results as list-sa events, only to clients registered for them
    v.register("list-sa")?;
    let mut found: Option<IkeInfo> = None;
    let _: Empty = v.request("list-sas", &ListSas { ike: CONN }, Duration::from_secs(5), &mut |name, body| {
        if name == "list-sa"
            && let Ok(mut m) = serde_vici::from_slice::<BTreeMap<String, IkeInfo>>(body)
        {
            found = m.remove(CONN);
        }
    })?;
    let ike = found.ok_or("the IKE SA vanished right after it came up")?;
    let vip = ike
        .local_vips
        .iter()
        .find_map(|a| a.parse::<Ipv4Addr>().ok())
        .ok_or("the gateway assigned no IPv4 address (Mode Config)")?;
    let gateway = ike.remote_host.parse::<Ipv4Addr>().map_err(|_| format!("gateway address {:?} isn't IPv4", ike.remote_host))?;
    let remote_ts = ike.child_sas.values().flat_map(|c| c.remote_ts.iter()).filter_map(|t| t.parse::<Ipv4Net>().ok()).collect();
    Ok(Established { gateway, vip, remote_ts })
}

#[derive(Deserialize, Default)]
struct UpDown {
    #[serde(default)]
    up: String,
}

/// An `ike-updown` event body that reports the SA going down (the `up` key is only present when it comes up).
pub fn is_down(body: &[u8]) -> bool {
    serde_vici::from_slice::<UpDown>(body).map(|u| u.up != "yes").unwrap_or(false)
}

/// End the SA (best effort; also fine if it's already gone).
pub fn terminate(v: &mut Vici) {
    let _: Result<Status, String> = v.request("terminate", &Terminate { ike: CONN, timeout: "5000".into() }, Duration::from_secs(8), &mut |_, _| {});
}

/// Stop a charon left behind by a crashed session. Ours are recognised by the environment we start them with, which
/// no other process (such as the system's strongSwan) has. Waits until they're gone, so a new instance doesn't race
/// them for the control socket. Returns how many were stopped.
pub fn kill_stale() -> usize {
    let mark = format!("STRONGSWAN_CONF={}", conf_path().display());
    pids_with_env(&mark).into_iter().filter(|&pid| sigterm_and_wait(pid, Duration::from_secs(5))).count()
}

/// Processes whose environment contains the exact entry `entry` ("KEY=value").
fn pids_with_env(entry: &str) -> Vec<i32> {
    let Ok(dir) = std::fs::read_dir("/proc") else { return vec![] };
    dir.flatten()
        .filter_map(|e| e.file_name().to_str()?.parse::<i32>().ok())
        .filter(|pid| {
            std::fs::read(format!("/proc/{pid}/environ")).is_ok_and(|env| env.split(|&b| b == 0).any(|kv| kv == entry.as_bytes()))
        })
        .collect()
}

/// SIGTERM `pid` and wait until it has exited (a zombie counts as exited). False if it couldn't be signalled.
fn sigterm_and_wait(pid: i32, grace: Duration) -> bool {
    // SAFETY: plain kill(2)
    if unsafe { libc::kill(pid, libc::SIGTERM) } != 0 {
        return false;
    }
    let gone = || std::fs::read_to_string(format!("/proc/{pid}/stat")).map_or(true, |s| s.rsplit(") ").next().is_some_and(|r| r.starts_with('Z')));
    let t0 = Instant::now();
    while !gone() && t0.elapsed() < grace {
        std::thread::sleep(Duration::from_millis(50));
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params() -> ConnParams {
        ConnParams {
            gateway: "vpn.example.com".parse().unwrap(),
            ike_port: 500,
            ike_proposals: vec!["aes128-sha1-ecp384".into()],
            esp_proposals: vec!["aes128-sha1".into()],
            local_id: None,
            auth: ClientAuth::Eap { identity: "0123456789ABCDEF0123456789ABCDEF".into(), secret: Secret("token-secret".into()) },
            psk: Secret("psk-secret".into()),
        }
    }

    #[test]
    fn config_has_no_secrets_and_the_right_settings() {
        let c = config(20, false, None);
        for want in ["port = 0", "port_nat_t = 0", "install_routes = no", "install_virtual_ip = no", "keep_alive = 20s",
                     "socket = unix:///run/fortisaml-gui/charon.vici", "eap-mschapv2"] {
            assert!(c.contains(want), "missing {want:?} in\n{c}");
        }
        assert!(!c.contains("secret"));
        assert!(!c.contains("resolve"), "no VPN DNS wanted: no resolve plugin, so charon doesn't even ask for it");
    }

    #[test]
    fn resolvconf_name_suits_the_implementation() {
        let ifn: IfName = "fsaml0".parse().unwrap();
        // systemd-resolved's resolvconf needs the real interface
        assert_eq!(resolvconf_name(&ifn, Some(Path::new("/usr/bin/resolvectl"))), "fsaml0");
        // openresolv / Debian resolvconf: a lo.* record sorts before the LAN's, so VPN servers are asked first
        assert_eq!(resolvconf_name(&ifn, Some(Path::new("/usr/sbin/resolvconf.openresolv"))), "lo.fsaml0");
        assert_eq!(resolvconf_name(&ifn, None), "lo.fsaml0");
    }

    #[test]
    fn config_hands_dns_to_resolvconf_for_our_interface() {
        let c = config(20, false, Some("lo.fsaml0"));
        // iface for strongSwan >= 5.9.9, iface_prefix (prefix + server address) for older versions
        assert!(c.contains(" resolve ") && c.contains("iface = lo.fsaml0") && c.contains("iface_prefix = lo.fsaml0."), "{c}");
        // without any resolvconf, the resolve plugin would rewrite this file instead: never /etc/resolv.conf
        assert!(c.contains("file = /run/fortisaml-gui/resolv.conf"), "{c}");
    }

    #[test]
    fn conn_message_shape() {
        let m = serde_vici::to_vec(&conn_message(&params())).unwrap();
        let s = String::from_utf8_lossy(&m);
        for want in ["remote_addrs", "vpn.example.com", "encap", "if_id_in", "0x5a17", "eap_id", "0123456789ABCDEF0123456789ABCDEF", "aes128-sha1-ecp384"] {
            assert!(s.contains(want), "missing {want:?}");
        }
        assert!(!s.contains("token-secret") && !s.contains("psk-secret"), "secrets only go over load-shared");
    }

    /// Fake charon answering one `list-sas` with a `list-sa` event for `remote_host`.
    fn list_sas_with(remote_host: &'static str) -> Result<Established, String> {
        use std::io::{Read, Write};
        #[derive(Serialize)]
        struct I {
            #[serde(rename = "remote-host")]
            remote_host: &'static str,
            #[serde(rename = "local-vips")]
            local_vips: Vec<&'static str>,
        }
        let (a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            fn next(b: &mut std::os::unix::net::UnixStream) -> crate::vici::Packet {
                let mut len = [0u8; 4];
                b.read_exact(&mut len).unwrap();
                let mut req = vec![0u8; u32::from_be_bytes(len) as usize];
                b.read_exact(&mut req).unwrap();
                crate::vici::decode(&req).unwrap()
            }
            // like charon: list-sa events only reach clients registered for them
            let reg = next(&mut b);
            assert_eq!((reg.kind, reg.name.as_deref()), (3, Some("list-sa")), "register for list-sa first");
            b.write_all(&crate::vici::encode(5, None, &[])).unwrap();
            assert_eq!(next(&mut b).name.as_deref(), Some("list-sas"));
            let ev = serde_vici::to_vec(&BTreeMap::from([(CONN, I { remote_host, local_vips: vec!["10.98.10.1"] })])).unwrap();
            b.write_all(&crate::vici::encode(7, Some("list-sa"), &ev)).unwrap();
            b.write_all(&crate::vici::encode(1, None, &[])).unwrap();
        });
        let r = established(&mut Vici::from_stream(a));
        server.join().unwrap();
        r
    }

    #[test]
    fn established_reads_gateway_and_address() {
        let e = list_sas_with("192.0.2.1").unwrap();
        assert_eq!((e.gateway, e.vip), (Ipv4Addr::new(192, 0, 2, 1), Ipv4Addr::new(10, 98, 10, 1)));
        assert!(e.remote_ts.is_empty());
    }

    #[test]
    fn ipv6_gateway_is_a_clear_error() {
        assert_eq!(list_sas_with("2001:db8::1").unwrap_err(), "gateway address \"2001:db8::1\" isn't IPv4");
    }

    #[test]
    fn debian_hint_names_every_package_with_a_needed_plugin() {
        // Debian splits strongSwan: vici, openssl, eap-mschapv2 and eap-identity/gtc/md5 live in separate packages
        for pkg in ["charon-systemd", "strongswan-swanctl", "libstrongswan-standard-plugins", "libcharon-extauth-plugins", "libcharon-extra-plugins"] {
            assert!(install_hint().contains(pkg), "{pkg}");
        }
    }

    #[test]
    fn one_session_at_a_time() {
        let path = std::env::temp_dir().join(format!("fortisaml-lock-test-{}", std::process::id()));
        let first = lock_at(&path).unwrap();
        assert_eq!(lock_at(&path).unwrap_err(), "a VPN session is already running; disconnect it first");
        drop(first);
        assert!(lock_at(&path).is_ok(), "free again once the holder is gone");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn finds_our_processes_by_their_environment() {
        let mark = format!("FORTISAML_TEST_MARK={}", std::process::id());
        let (k, v) = mark.split_once('=').unwrap();
        let mut c = Command::new("sleep").arg("30").env(k, v).spawn().unwrap();
        assert_eq!(pids_with_env(&mark), [c.id() as i32]);
        let _ = c.kill();
        let _ = c.wait();
        assert!(pids_with_env(&mark).is_empty());
    }

    #[test]
    fn sigterm_and_wait_returns_once_the_process_is_gone() {
        let mut c = Command::new("sleep").arg("30").spawn().unwrap();
        assert!(sigterm_and_wait(c.id() as i32, Duration::from_secs(3)));
        let _ = c.wait();
        assert!(!sigterm_and_wait(c.id() as i32, Duration::from_secs(1)), "nothing left to signal");
    }

    #[test]
    fn stop_sends_sigterm_and_waits() {
        use std::os::unix::process::ExitStatusExt;
        let mut c = Command::new("sleep").arg("30").spawn().unwrap();
        let t0 = Instant::now();
        let st = stop(&mut c, Duration::from_secs(3));
        assert_eq!(st.and_then(|s| s.signal()), Some(libc::SIGTERM));
        assert!(t0.elapsed() < Duration::from_secs(3));
    }

    /// Fake charon: answers each command in order, records the command names.
    fn fake_charon(script: Vec<(&'static str, Vec<Vec<u8>>)>) -> (Vici, std::thread::JoinHandle<Vec<String>>) {
        use std::io::{Read, Write};
        let (a, mut b) = std::os::unix::net::UnixStream::pair().unwrap();
        let h = std::thread::spawn(move || {
            let mut seen = vec![];
            for (_, replies) in script {
                let mut len = [0u8; 4];
                if b.read_exact(&mut len).is_err() {
                    break;
                }
                let mut req = vec![0u8; u32::from_be_bytes(len) as usize];
                b.read_exact(&mut req).unwrap();
                seen.push(crate::vici::decode(&req).unwrap().name.unwrap_or_default());
                for r in replies {
                    b.write_all(&r).unwrap();
                }
            }
            seen
        });
        (Vici::from_stream(a), h)
    }

    #[test]
    fn connect_terminates_an_sa_it_can_not_use() {
        let ok = || crate::vici::encode(1, None, &serde_vici::to_vec(&BTreeMap::from([("success", "yes")])).unwrap());
        #[derive(Serialize)]
        struct I {
            #[serde(rename = "remote-host")]
            remote_host: &'static str,
        }
        let ipv6 = serde_vici::to_vec(&BTreeMap::from([(CONN, I { remote_host: "2001:db8::1" })])).unwrap();
        let (mut v, h) = fake_charon(vec![
            ("load-conn", vec![ok()]),
            ("load-shared", vec![ok()]),
            ("load-shared", vec![ok()]),
            ("control-log", vec![crate::vici::encode(5, None, &[])]),
            ("initiate", vec![ok()]),
            ("list-sa", vec![crate::vici::encode(5, None, &[])]),
            ("list-sas", vec![crate::vici::encode(7, Some("list-sa"), &ipv6), crate::vici::encode(1, None, &[])]),
            ("terminate", vec![ok()]),
        ]);
        assert!(connect(&mut v, &params(), &|_| {}).is_err(), "no virtual IP, IPv6 gateway: unusable");
        drop(v);
        assert_eq!(h.join().unwrap().last().map(String::as_str), Some("terminate"), "the SA is ended, not left half up");
    }

    #[test]
    fn updown_events() {
        #[derive(Serialize)]
        struct Sa {
            state: &'static str,
        }
        #[derive(Serialize)]
        struct Up {
            up: &'static str,
            fortisaml: Sa,
        }
        #[derive(Serialize)]
        struct Down {
            fortisaml: Sa,
        }
        assert!(!is_down(&serde_vici::to_vec(&Up { up: "yes", fortisaml: Sa { state: "ESTABLISHED" } }).unwrap()));
        assert!(is_down(&serde_vici::to_vec(&Down { fortisaml: Sa { state: "DELETING" } }).unwrap()));
    }

    #[test]
    fn errors_are_explained() {
        assert!(explain(&["received AUTHENTICATION_FAILED notify error".into()]).starts_with("authentication failed"));
        assert!(explain(&["received NO_PROPOSAL_CHOSEN notify error".into()]).contains("proposals"));
        assert!(explain(&["giving up after 3 retransmits".into()]).contains("no answer"));
        assert!(explain(&[]).contains("see the log"));
    }

    #[test]
    fn list_sa_event_decodes() {
        // what charon sends: { fortisaml: { local-vips: [10.98.10.1], child-sas: { fortisaml-1: { remote-ts: [0.0.0.0/0] } } } }
        #[derive(Serialize)]
        struct C {
            #[serde(rename = "remote-ts")]
            remote_ts: Vec<&'static str>,
        }
        #[derive(Serialize)]
        struct I {
            state: &'static str,
            #[serde(rename = "remote-host")]
            remote_host: &'static str,
            #[serde(rename = "local-vips")]
            local_vips: Vec<&'static str>,
            #[serde(rename = "child-sas")]
            child_sas: BTreeMap<&'static str, C>,
        }
        let body = serde_vici::to_vec(&BTreeMap::from([(
            CONN,
            I { state: "ESTABLISHED", remote_host: "192.0.2.1", local_vips: vec!["10.98.10.1"], child_sas: BTreeMap::from([("fortisaml-1", C { remote_ts: vec!["10.10.0.0/16", "10.20.0.0/16"] })]) },
        )]))
        .unwrap();
        let m: BTreeMap<String, IkeInfo> = serde_vici::from_slice(&body).unwrap();
        let i = &m[CONN];
        assert_eq!(i.local_vips, ["10.98.10.1"]);
        assert_eq!(i.remote_host, "192.0.2.1");
        assert_eq!(i.child_sas["fortisaml-1"].remote_ts, ["10.10.0.0/16", "10.20.0.0/16"]);
    }
}
