//! Minimal HTTPS client (rustls + system CA store) with browser-like AIA chasing.
//!
//! Some FortiGates send only their leaf certificate. Browsers then download the missing issuer from the
//! certificate's AIA "CA Issuers" URL. We do the same, but the downloaded certificates are only offered to
//! webpki as *untrusted intermediates*: trust still comes exclusively from the system CA store.

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

type Log = Arc<dyn Fn(String) + Send + Sync>;

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Plain-HTTP GET (AIA URLs are http:// by design), following no redirects.
fn http_get(url: &str) -> Result<Vec<u8>, String> {
    let rest = url.strip_prefix("http://").ok_or("AIA URL is not http://")?;
    let (hostport, path) = rest.split_once('/').map(|(h, p)| (h, format!("/{p}"))).unwrap_or((rest, "/".into()));
    let addr = if hostport.contains(':') { hostport.to_string() } else { format!("{hostport}:80") };
    let host = hostport.split(':').next().unwrap_or(hostport);
    let mut s = TcpStream::connect(&addr).map_err(|e| format!("{addr}: {e}"))?;
    s.set_read_timeout(Some(Duration::from_secs(10))).ok();
    write!(s, "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: fortisaml\r\n\r\n").map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    let (head, body) = split_http(&buf)?;
    if !head.starts_with("HTTP/1.1 200") && !head.starts_with("HTTP/1.0 200") {
        return Err(format!("AIA fetch {url}: {}", head.lines().next().unwrap_or("")));
    }
    Ok(body)
}

pub fn split_http(buf: &[u8]) -> Result<(String, Vec<u8>), String> {
    let pos = buf.windows(4).position(|w| w == b"\r\n\r\n").ok_or("malformed HTTP response")?;
    let head = String::from_utf8_lossy(&buf[..pos]).to_string();
    let mut body = buf[pos + 4..].to_vec();
    if head.to_ascii_lowercase().contains("transfer-encoding: chunked") {
        body = dechunk(&body);
    }
    Ok((head, body))
}

fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(p) = b.windows(2).position(|w| w == b"\r\n") {
        let n = usize::from_str_radix(String::from_utf8_lossy(&b[..p]).split(';').next().unwrap_or("0").trim(), 16).unwrap_or(0);
        if n == 0 || p + 2 + n > b.len() {
            break;
        }
        out.extend_from_slice(&b[p + 2..p + 2 + n]);
        b = &b[(p + 4 + n).min(b.len())..];
    }
    out
}

/// Extract certificates from DER, PEM or a PKCS#7 bundle (.p7c) by scanning for embedded X.509 SEQUENCEs.
fn certs_from_blob(data: &[u8]) -> Vec<CertificateDer<'static>> {
    if data.starts_with(b"-----BEGIN") {
        let text = String::from_utf8_lossy(data);
        return x509_parser::pem::Pem::iter_from_buffer(text.as_bytes())
            .filter_map(Result::ok)
            .filter(|p| p.label == "CERTIFICATE")
            .map(|p| CertificateDer::from(p.contents))
            .collect();
    }
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if data[i] == 0x30
            && let Ok((rest, _)) = x509_parser::parse_x509_certificate(&data[i..]) {
                let used = data.len() - i - rest.len();
                out.push(CertificateDer::from(data[i..i + used].to_vec()));
                i += used;
                continue;
            }
        i += 1;
    }
    out
}

fn aia_issuer_urls(der: &[u8]) -> Vec<String> {
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(der) else { return vec![] };
    let mut urls = vec![];
    for ext in cert.extensions() {
        if let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() {
            for d in &aia.accessdescs {
                if d.access_method == x509_parser::oid_registry::OID_PKIX_ACCESS_DESCRIPTOR_CA_ISSUERS
                    && let GeneralName::URI(u) = d.access_location
                        && u.starts_with("http://") {
                            urls.push(u.to_string());
                        }
            }
        }
    }
    urls
}

#[derive(Debug)]
struct AiaVerifier {
    inner: Arc<WebPkiServerVerifier>,
    #[allow(dead_code)]
    log: LogDbg,
}

struct LogDbg(Log);
impl std::fmt::Debug for LogDbg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("log")
    }
}

impl ServerCertVerifier for AiaVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        match self.inner.verify_server_cert(end_entity, intermediates, server_name, ocsp, now) {
            Err(TlsError::InvalidCertificate(CertificateError::UnknownIssuer)) => {
                // walk AIA (max 3 levels) collecting candidate intermediates
                let mut extra: Vec<CertificateDer<'static>> = vec![];
                let mut cur = end_entity.as_ref().to_vec();
                for _ in 0..3 {
                    let Some(url) = aia_issuer_urls(&cur).into_iter().next() else { break };
                    let Ok(blob) = http_get(&url) else { break };
                    let certs = certs_from_blob(&blob);
                    let Some(first) = certs.first().cloned() else { break };
                    extra.extend(certs);
                    cur = first.as_ref().to_vec();
                }
                let mut all: Vec<CertificateDer<'_>> = intermediates.to_vec();
                all.extend(extra.iter().cloned());
                let r = self.inner.verify_server_cert(end_entity, &all, server_name, ocsp, now);
                if r.is_ok() {
                    (self.log.0)("TLS: server omitted its certificate chain; verified it with the issuer fetched via AIA".into());
                }
                r
            }
            r => r,
        }
    }
    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls12_signature(m, c, d)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, TlsError> {
        self.inner.verify_tls13_signature(m, c, d)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Accepts any certificate (FortiClient's default behaviour on the SAML port). Signatures are still checked.
#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);
impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, TlsError> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, TlsError> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn client_config(verify: bool, log: Log) -> Result<Arc<rustls::ClientConfig>, String> {
    let prov = provider();
    let builder = rustls::ClientConfig::builder_with_provider(prov.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?;
    let verifier: Arc<dyn ServerCertVerifier> = if verify {
        let mut roots = rustls::RootCertStore::empty();
        let native = rustls_native_certs::load_native_certs();
        roots.add_parsable_certificates(native.certs);
        if roots.is_empty() {
            return Err("no system CA certificates found".into());
        }
        let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), prov.clone())
            .build()
            .map_err(|e| e.to_string())?;
        Arc::new(AiaVerifier { inner, log: LogDbg(log) })
    } else {
        Arc::new(NoVerify(prov))
    };
    Ok(Arc::new(builder.dangerous().with_custom_certificate_verifier(verifier).with_no_client_auth()))
}

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// TCP connect that gives up after `CONNECT_TIMEOUT` instead of the OS default (minutes).
fn connect(host: &str, port: u16) -> Result<TcpStream, String> {
    let mut last = format!("can't resolve {host}");
    for addr in (host, port).to_socket_addrs().map_err(|e| format!("can't resolve {host}: {e}"))? {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(s) => return Ok(s),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                last = format!("connection timed out after {}s", CONNECT_TIMEOUT.as_secs())
            }
            Err(e) => last = e.to_string(),
        }
    }
    Err(last)
}

/// HTTPS POST; returns (status line + headers, body).
pub fn https_post(host: &str, port: u16, path: &str, headers: &[(&str, &str)], body: &[u8], verify: bool, log: Log) -> Result<(String, Vec<u8>), String> {
    https_request("POST", host, port, path, headers, body, verify, log)
}

/// HTTPS GET; returns (status line + headers, body). Redirects aren't followed.
pub fn https_get(host: &str, port: u16, path: &str, headers: &[(&str, &str)], verify: bool, log: Log) -> Result<(String, Vec<u8>), String> {
    https_request("GET", host, port, path, headers, &[], verify, log)
}

#[allow(clippy::too_many_arguments)]
fn https_request(method: &str, host: &str, port: u16, path: &str, headers: &[(&str, &str)], body: &[u8], verify: bool, log: Log) -> Result<(String, Vec<u8>), String> {
    let cfg = client_config(verify, log)?;
    let name = ServerName::try_from(host.to_string()).map_err(|e| format!("bad server name {host}: {e}"))?;
    let mut conn = rustls::ClientConnection::new(cfg, name).map_err(|e| e.to_string())?;
    let mut sock = connect(host, port)?;
    sock.set_read_timeout(Some(Duration::from_secs(15))).ok();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Length: {}\r\nConnection: close\r\n", body.len());
    for (k, v) in headers {
        req += &format!("{k}: {v}\r\n");
    }
    req += "\r\n";
    tls.write_all(req.as_bytes()).map_err(|e| format!("TLS: {e}"))?;
    tls.write_all(body).map_err(|e| format!("TLS: {e}"))?;
    let mut buf = Vec::new();
    match tls.read_to_end(&mut buf) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof && !buf.is_empty() => {} // no close_notify
        Err(e) => return Err(format!("TLS: {e}")),
    }
    split_http(&buf)
}

