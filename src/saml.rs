//! SAML SSO for FortiGate IKE (external-browser flow of FortiAuth.dll `GetIpsecSamlDataExternalBrowser`):
//!   POST https://<gw>:<ike_saml_port>/saml_login?   UID=<uid>&REDIRECT_PORT=<p>
//!   -> window.location="<IdP URL>"  -> user logs in in the browser
//!   -> FortiGate redirects the browser to http://127.0.0.1:<p>/?...tokenid=<T>&...&username=<U>

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const DONE_PAGE: &str = "<html><head><title>Archway</title></head><body style=\"font-family:sans-serif\">\
<h3>✔ Signed in</h3><p>You can close this tab. Archway continues setting up the connection.</p></body></html>";

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

pub struct SamlParams {
    pub gateway: crate::net::Host,
    pub port: crate::net::Port,
    /// 32 hex digits, so it goes into the form body as is
    pub uid: crate::net::ClientUid,
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

/// Why waiting for a background request ended without its answer.
enum Waited {
    Cancelled,
    /// the thread ended without sending (it panicked)
    Gone,
}

/// Run `f` on another thread and wait for it, so Cancel works while the gateway is slow or silent. An abandoned request
/// ends at its own connect/read timeout.
fn in_background<T: Send + 'static>(cancel: &AtomicBool, f: impl FnOnce() -> T + Send + 'static) -> Result<T, Waited> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    loop {
        if cancel.load(Ordering::SeqCst) {
            return Err(Waited::Cancelled);
        }
        match rx.recv_timeout(Duration::from_millis(150)) {
            Ok(r) => return Ok(r),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Err(Waited::Gone),
        }
    }
}

/// The target of the page's `window.location="…"` script redirect.
fn js_redirect(html: &str) -> Option<String> {
    html.split_once("window.location=\"").and_then(|(_, r)| r.split_once('"')).map(|(u, _)| u.to_string())
}

/// Given the FortiGate's SSO start page: the identity provider URL it only redirects to by script, when the browser can
/// go there directly. Not when the page sets a cookie (the FortiGate would need it back when the IdP posts the answer)
/// or the target isn't https.
fn idp_from_start_page(head: &str, body: &str) -> Option<String> {
    let ok = head.lines().next().is_some_and(|l| l.split_whitespace().nth(1) == Some("200"));
    let cookie = head.lines().any(|l| l.to_ascii_lowercase().starts_with("set-cookie:"));
    js_redirect(body).filter(|u| ok && !cookie && u.starts_with("https://"))
}

/// The start page only sends the browser on to the identity provider. Fetch it here and open the IdP directly: one
/// page fewer flashing by in the browser. None: open the start page as before.
fn skip_start_page(p: &SamlParams, start: &str, cancel: &AtomicBool, log: Arc<dyn Fn(String) + Send + Sync>) -> Result<Option<String>, Waited> {
    let Some(path) = start.strip_prefix(&format!("https://{}:{}", p.gateway, p.port)).map(str::to_owned) else { return Ok(None) };
    let (gateway, port, verify, l) = (p.gateway.to_string(), p.port.get(), p.verify_cert, log.clone());
    let page = in_background(cancel, move || crate::tls::https_get(&gateway, port, &path, &[("User-Agent", "FortiClient Windows")], verify, l))?;
    Ok(match page {
        Ok((head, body)) => {
            let idp = idp_from_start_page(&head, &String::from_utf8_lossy(&body));
            if idp.is_none() {
                log("SAML: opening the FortiGate start page in the browser (it can't be skipped)".into());
            }
            idp
        }
        Err(e) => {
            log(format!("SAML: start page not fetched ({e}); opening it in the browser"));
            None
        }
    })
}

/// `url` if the browser may open it: https only, so an answer like `file:///…` never reaches xdg-open.
fn browser_url(url: &str) -> Result<String, String> {
    if url.starts_with("https://") { Ok(url.into()) } else { Err(format!("the login page address isn't https ({})", url.chars().take(40).collect::<String>())) }
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
    let (gateway, port, verify, l) = (p.gateway.to_string(), p.port.get(), p.verify_cert, log.clone());
    let answer = in_background(cancel, move || {
        let headers = [("Content-Type", "application/x-www-form-urlencoded"), ("User-Agent", "FortiClient Windows")];
        crate::tls::https_post(&gateway, port, "/saml_login?", &headers, body.as_bytes(), verify, l)
    });
    let (head, html) = match answer {
        Err(Waited::Cancelled) => return Err("cancelled".into()),
        Err(Waited::Gone) => return Err(port_error(p, "the request ended without an answer")),
        Ok(r) => r.map_err(|e| port_error(p, &e))?,
    };
    let html = String::from_utf8_lossy(&html);
    let start = js_redirect(&html).ok_or_else(|| {
        port_error(p, &format!("the answer isn't a FortiGate SSO page ({})", head.lines().next().unwrap_or("empty response")))
    })?;
    let start = if start.starts_with('/') { format!("https://{}:{}{start}", p.gateway, p.port) } else { start };
    let url = match skip_start_page(p, &start, cancel, log.clone()) {
        Err(Waited::Cancelled) => return Err("cancelled".into()),
        Ok(Some(idp)) => idp,
        Ok(None) | Err(Waited::Gone) => start,
    };
    let url = browser_url(&url).map_err(|e| port_error(p, &e))?;
    log(format!("SAML: identity provider login URL: {url}"));
    on_url(&url);
    if p.open_browser {
        // ARCHWAY_BROWSER overrides the opener (e.g. a specific browser, or a test harness)
        let opener = std::env::var("ARCHWAY_BROWSER").unwrap_or_else(|_| "xdg-open".into());
        match std::process::Command::new(&opener).arg(&url).stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).spawn() {
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

    fn params(port: u16) -> SamlParams {
        SamlParams {
            gateway: "127.0.0.1".parse().unwrap(),
            port: crate::net::Port::new(port).unwrap(),
            uid: "0123456789ABCDEF0123456789ABCDEF".parse().unwrap(),
            verify_cert: false,
            open_browser: false,
            timeout: Duration::from_secs(5),
        }
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

    #[test]
    fn script_redirects_are_found() {
        assert_eq!(js_redirect("<script>window.location=\"/saml?x=1\";</script>").as_deref(), Some("/saml?x=1"));
        assert_eq!(js_redirect("<html>nothing</html>"), None);
    }

    #[test]
    fn the_start_page_is_skipped_only_when_it_is_a_plain_redirect_to_https() {
        let page = "<html><script>window.location=\"https://login.example/saml2?SAMLRequest=abc%3D\";</script></html>";
        let ok = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nCache-Control: no-cache";
        assert_eq!(idp_from_start_page(ok, page).as_deref(), Some("https://login.example/saml2?SAMLRequest=abc%3D"));
        // a cookie set here would be needed again when the IdP posts back: then the browser must load this page itself
        assert_eq!(idp_from_start_page("HTTP/1.1 200 OK\r\nSet-Cookie: s=1; Path=/", page), None);
        assert_eq!(idp_from_start_page("HTTP/1.1 200 OK\r\nset-cookie: s=1", page), None);
        assert_eq!(idp_from_start_page("HTTP/1.1 302 Found\r\nLocation: /x", page), None);
        assert_eq!(idp_from_start_page(ok, "<script>window.location=\"file:///etc/passwd\"</script>"), None);
        assert_eq!(idp_from_start_page(ok, "<html>no script</html>"), None);
    }

    #[test]
    fn only_https_pages_are_opened_in_the_browser() {
        assert!(browser_url("https://vpn.example.com:10443/saml?x=1").is_ok());
        for bad in ["file:///etc/passwd", "javascript:alert(1)", "http://vpn.example.com/saml", "-x", ""] {
            assert!(browser_url(bad).is_err(), "{bad:?}");
        }
    }
}
