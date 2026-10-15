//! SAML SSO for FortiGate IKE (external-browser flow of FortiAuth.dll `GetIpsecSamlDataExternalBrowser`):
//!   POST https://<gw>:<ike_saml_port>/saml_login?   UID=<uid>&REDIRECT_PORT=<p>
//!   -> window.location="<IdP URL>"  -> user logs in in the browser
//!   -> FortiGate redirects the browser to http://127.0.0.1:<p>/?...tokenid=<T>&...&username=<U>

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const DONE_PAGE: &str = "<html><head><title>FortiSAML</title></head><body style=\"font-family:sans-serif\">\
<h3>✔ Signed in</h3><p>You can close this tab. FortiSAML VPN continues setting up the connection.</p></body></html>";

pub struct SamlResult {
    pub username: String,
    pub token: String,
}

pub fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'+' => out.push(b' '),
            b'%' if i + 2 < b.len() => {
                if let Ok(v) = u8::from_str_radix(&s[i + 1..i + 3], 16) {
                    out.push(v);
                    i += 3;
                    continue;
                }
                out.push(b'%');
            }
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into()
}

fn query_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        (k == key).then(|| url_decode(v))
    })
}

pub struct SamlParams<'a> {
    pub gateway: &'a str,
    pub port: u16,
    pub uid: &'a str,
    pub verify_cert: bool,
    pub open_browser: bool,
    pub timeout: Duration,
}

fn port_error(p: &SamlParams, cause: &str) -> String {
    crate::diag(
        "error",
        &format!("no SSO login page at {}:{}", p.gateway, p.port),
        cause,
        "check the SSO port (FortiGate `auth-ike-saml-port`)",
    )
}

/// `on_url` is called with the IdP start URL (for display / manual opening).
pub fn login(
    p: &SamlParams,
    cancel: &AtomicBool,
    log: Arc<dyn Fn(String) + Send + Sync>,
    on_url: &dyn Fn(&str),
) -> Result<SamlResult, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("callback listener: {e}"))?;
    listener.set_nonblocking(true).ok();
    let rport = listener.local_addr().map_err(|e| e.to_string())?.port();

    log(format!("SAML: POST https://{}:{}/saml_login? (UID={}, REDIRECT_PORT={rport})", p.gateway, p.port, p.uid));
    let body = format!("UID={}&REDIRECT_PORT={rport}", p.uid);
    // in the background, so Cancel works while the gateway is slow or silent; an abandoned request ends at
    // its own connect/read timeout
    let (tx, rx) = std::sync::mpsc::channel();
    {
        let (gateway, port, verify, log) = (p.gateway.to_string(), p.port, p.verify_cert, log.clone());
        std::thread::spawn(move || {
            let headers = [("Content-Type", "application/x-www-form-urlencoded"), ("User-Agent", "FortiClient Windows")];
            let _ = tx.send(crate::tls::https_post(&gateway, port, "/saml_login?", &headers, body.as_bytes(), verify, log));
        });
    }
    let (head, html) = loop {
        if cancel.load(Ordering::SeqCst) {
            return Err("cancelled".into());
        }
        match rx.recv_timeout(Duration::from_millis(150)) {
            Ok(r) => break r.map_err(|e| port_error(p, &e))?,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Err(port_error(p, "the request ended without an answer")),
        }
    };
    let html = String::from_utf8_lossy(&html);
    let start = html
        .split_once("window.location=\"")
        .and_then(|(_, r)| r.split_once('"'))
        .map(|(u, _)| u.to_string())
        .ok_or_else(|| {
            port_error(p, &format!("the answer isn't a FortiGate SSO page ({})", head.lines().next().unwrap_or("empty response")))
        })?;
    let start = if start.starts_with('/') { format!("https://{}:{}{start}", p.gateway, p.port) } else { start };
    log(format!("SAML: identity provider login URL: {start}"));
    on_url(&start);
    if p.open_browser {
        // FORTISAML_BROWSER overrides the opener (e.g. a specific browser, or a test harness)
        let opener = std::env::var("FORTISAML_BROWSER").unwrap_or_else(|_| "xdg-open".into());
        match std::process::Command::new(&opener).arg(&start).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn() {
            Ok(_) => {}
            Err(e) => log(format!("could not run {opener} ({e}); open the URL manually")),
        }
    }
    log(format!("SAML: waiting up to {}s for the browser to return to http://127.0.0.1:{rport}/", p.timeout.as_secs()));

    let deadline = Instant::now() + p.timeout;
    while Instant::now() < deadline {
        if cancel.load(Ordering::SeqCst) {
            return Err("cancelled".into());
        }
        let (mut s, _) = match listener.accept() {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(150));
                continue;
            }
            Err(e) => return Err(format!("callback listener: {e}")),
        };
        s.set_nonblocking(false).ok();
        s.set_read_timeout(Some(Duration::from_secs(5))).ok();
        let mut req = Vec::new();
        let mut buf = [0u8; 4096];
        while !req.windows(4).any(|w| w == b"\r\n\r\n") && req.len() < 65536 {
            match s.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => req.extend_from_slice(&buf[..n]),
            }
        }
        let text = String::from_utf8_lossy(&req);
        let target = text.lines().next().and_then(|l| l.split_whitespace().nth(1)).unwrap_or("");
        let query = target.split_once('?').map(|(_, q)| q).unwrap_or("");
        let token = query_param(query, "tokenid");
        let resp = if token.is_some() {
            format!("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{DONE_PAGE}", DONE_PAGE.len())
        } else {
            "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
        };
        let _ = s.write_all(resp.as_bytes());
        if let Some(token) = token.filter(|t| !t.is_empty()) {
            let username = query_param(query, "username").unwrap_or_default();
            log(format!("SAML: success, username={username}, tokenid=<{} chars>", token.len()));
            return Ok(SamlResult { username, token });
        }
    }
    Err("SSO login timed out".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn decode() {
        assert_eq!(url_decode("user%40example.com"), "user@example.com");
        assert_eq!(query_param("tokenid=ab%2Fc&realm=&username=a%40b", "username").unwrap(), "a@b");
        assert_eq!(query_param("tokenid=ab%2Fc&realm=", "tokenid").unwrap(), "ab/c");
    }

    fn params(port: u16) -> SamlParams<'static> {
        SamlParams { gateway: "127.0.0.1", port, uid: "X", verify_cert: false, open_browser: false, timeout: Duration::from_secs(5) }
    }

    fn quiet() -> Arc<dyn Fn(String) + Send + Sync> {
        Arc::new(|_| {})
    }

    fn assert_port_error(e: &str, port: u16) {
        assert!(e.starts_with(&format!("error: no SSO login page at 127.0.0.1:{port}\n  note: ")), "{e}");
        assert!(e.contains("\n  help: check the SSO port (FortiGate `auth-ike-saml-port`)"), "{e}");
    }

    #[test]
    fn refused_port_explains_itself() {
        let port = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port(); // closed again
        let e = login(&params(port), &AtomicBool::new(false), quiet(), &|_| {}).err().unwrap();
        assert_port_error(&e, port);
    }

    #[test]
    fn non_tls_answer_explains_itself() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut s, _)) = l.accept() {
                let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
            }
        });
        let e = login(&params(port), &AtomicBool::new(false), quiet(), &|_| {}).err().unwrap();
        assert_port_error(&e, port);
    }

    #[test]
    fn cancel_returns_while_gateway_hangs() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap(); // connects, but never answers the TLS handshake
        let port = l.local_addr().unwrap().port();
        let cancel = Arc::new(AtomicBool::new(false));
        let c = cancel.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            c.store(true, Ordering::SeqCst);
        });
        let t0 = Instant::now();
        let r = login(&params(port), &cancel, quiet(), &|_| {});
        assert_eq!(r.err().as_deref(), Some("cancelled"));
        assert!(t0.elapsed() < Duration::from_secs(2), "took {:?}", t0.elapsed());
        drop(l);
    }
}
