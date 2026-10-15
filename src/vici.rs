//! Minimal synchronous client for strongSwan's VICI protocol (the API `swanctl` uses) over a Unix socket.
//! Wire format: u32 big-endian length, then a packet type byte, a length-prefixed name for named types, and a
//! message body encoded with `serde_vici`. See https://docs.strongswan.org/docs/latest/plugins/vici.html

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

const CMD_REQUEST: u8 = 0;
const CMD_RESPONSE: u8 = 1;
const CMD_UNKNOWN: u8 = 2;
const EVENT_REGISTER: u8 = 3;
const EVENT_UNREGISTER: u8 = 4;
const EVENT_CONFIRM: u8 = 5;
const EVENT_UNKNOWN: u8 = 6;
const EVENT: u8 = 7;
/// charon refuses bigger messages; also bounds what a broken peer can make us allocate
const MAX_PACKET: usize = 512 * 1024;

#[derive(Debug, PartialEq)]
pub struct Packet {
    pub kind: u8,
    pub name: Option<String>,
    pub body: Vec<u8>,
}

fn named(kind: u8) -> bool {
    matches!(kind, CMD_REQUEST | EVENT_REGISTER | EVENT_UNREGISTER | EVENT)
}

pub fn encode(kind: u8, name: Option<&str>, body: &[u8]) -> Vec<u8> {
    let mut p = vec![kind];
    if let Some(n) = name {
        p.push(n.len() as u8);
        p.extend_from_slice(n.as_bytes());
    }
    p.extend_from_slice(body);
    let mut out = (p.len() as u32).to_be_bytes().to_vec();
    out.extend(p);
    out
}

pub fn decode(payload: &[u8]) -> Result<Packet, String> {
    let (&kind, rest) = payload.split_first().ok_or("empty VICI packet")?;
    if !named(kind) {
        return Ok(Packet { kind, name: None, body: rest.to_vec() });
    }
    let (&len, rest) = rest.split_first().ok_or("truncated VICI packet")?;
    let len = len as usize;
    if rest.len() < len {
        return Err("truncated VICI packet name".into());
    }
    let name = String::from_utf8(rest[..len].to_vec()).map_err(|_| "VICI packet name isn't UTF-8")?;
    Ok(Packet { kind, name: Some(name), body: rest[len..].to_vec() })
}

/// The usual command result: `success = yes|no`, `errmsg` on failure.
#[derive(Deserialize, Debug, Default)]
pub struct Status {
    #[serde(default)]
    pub success: String,
    #[serde(default)]
    pub errmsg: String,
}

impl Status {
    pub fn check(self, what: &str) -> Result<(), String> {
        if self.success == "yes" { Ok(()) } else { Err(format!("{what} failed: {}", if self.errmsg.is_empty() { "no reason given" } else { &self.errmsg })) }
    }
}

/// An empty request or response body.
#[derive(Serialize, Deserialize, Default)]
pub struct Empty {}

pub struct Vici {
    stream: UnixStream,
}

impl Vici {
    pub fn connect(path: &Path) -> Result<Self, String> {
        let stream = UnixStream::connect(path).map_err(|e| format!("cannot connect to charon at {}: {e}", path.display()))?;
        Ok(Self { stream })
    }

    #[cfg(test)]
    pub fn from_stream(stream: UnixStream) -> Self {
        Self { stream }
    }

    fn send(&mut self, kind: u8, name: Option<&str>, body: &[u8]) -> Result<(), String> {
        self.stream.write_all(&encode(kind, name, body)).map_err(|e| format!("VICI write: {e}"))
    }

    /// Next packet; `Ok(None)` when `timeout` passes without one.
    pub fn recv(&mut self, timeout: Option<Duration>) -> Result<Option<Packet>, String> {
        self.stream.set_read_timeout(timeout).map_err(|e| e.to_string())?;
        let mut len = [0u8; 4];
        match self.stream.read_exact(&mut len) {
            Ok(()) => {}
            Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut) => return Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err("charon closed the VICI connection".into()),
            Err(e) => return Err(format!("VICI read: {e}")),
        }
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 || len > MAX_PACKET {
            return Err(format!("bad VICI packet length {len}"));
        }
        let mut payload = vec![0u8; len];
        self.stream.set_read_timeout(Some(Duration::from_secs(5))).map_err(|e| e.to_string())?;
        self.stream.read_exact(&mut payload).map_err(|e| format!("VICI read: {e}"))?;
        decode(&payload).map(Some)
    }

    /// Subscribe to event `name` (e.g. "ike-updown", "child-updown", "control-log").
    pub fn register(&mut self, name: &str) -> Result<(), String> {
        self.send(EVENT_REGISTER, Some(name), &[])?;
        loop {
            match self.recv(Some(Duration::from_secs(5)))? {
                Some(p) if p.kind == EVENT_CONFIRM => return Ok(()),
                Some(p) if p.kind == EVENT_UNKNOWN => return Err(format!("charon doesn't know event {name}")),
                Some(p) if p.kind == EVENT => continue, // an earlier subscription
                Some(p) => return Err(format!("unexpected VICI packet type {} while registering {name}", p.kind)),
                None => return Err(format!("no answer from charon registering {name}")),
            }
        }
    }

    /// Run command `cmd`; events that arrive meanwhile go to `on_event(name, body)`.
    pub fn request<Q: Serialize, A: DeserializeOwned>(
        &mut self,
        cmd: &str,
        req: &Q,
        timeout: Duration,
        on_event: &mut dyn FnMut(&str, &[u8]),
    ) -> Result<A, String> {
        let body = serde_vici::to_vec(req).map_err(|e| format!("VICI encode {cmd}: {e}"))?;
        self.send(CMD_REQUEST, Some(cmd), &body)?;
        loop {
            match self.recv(Some(timeout))? {
                Some(Packet { kind: CMD_RESPONSE, body, .. }) => {
                    return serde_vici::from_slice(&body).map_err(|e| format!("VICI decode {cmd}: {e}"));
                }
                Some(Packet { kind: CMD_UNKNOWN, .. }) => return Err(format!("charon doesn't know command {cmd}")),
                Some(Packet { kind: EVENT, name: Some(n), body }) => on_event(&n, &body),
                Some(p) => return Err(format!("unexpected VICI packet type {} for {cmd}", p.kind)),
                None => return Err(format!("no answer from charon for {cmd} within {}s", timeout.as_secs())),
            }
        }
    }

    /// Next event within `timeout`: (name, body).
    pub fn next_event(&mut self, timeout: Duration) -> Result<Option<(String, Vec<u8>)>, String> {
        match self.recv(Some(timeout))? {
            Some(Packet { kind: EVENT, name: Some(n), body }) => Ok(Some((n, body))),
            Some(p) => Err(format!("unexpected VICI packet type {} between events", p.kind)),
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn packets_encode_and_decode() {
        let p = encode(CMD_REQUEST, Some("version"), &[]);
        assert_eq!(p, [0, 0, 0, 9, 0, 7, b'v', b'e', b'r', b's', b'i', b'o', b'n']);
        assert_eq!(decode(&p[4..]).unwrap(), Packet { kind: CMD_REQUEST, name: Some("version".into()), body: vec![] });
        let r = encode(CMD_RESPONSE, None, &[3, 1, b'k', 0, 1, b'v']);
        assert_eq!(decode(&r[4..]).unwrap(), Packet { kind: CMD_RESPONSE, name: None, body: vec![3, 1, b'k', 0, 1, b'v'] });
        assert!(decode(&[EVENT, 9, b'x']).is_err(), "name longer than the packet");
        assert!(decode(&[]).is_err());
    }

    #[test]
    fn serde_vici_body_matches_the_protocol_example() {
        // key1 = value1 (type 3 = KEY_VALUE)
        let mut m = BTreeMap::new();
        m.insert("key1", "value1");
        assert_eq!(serde_vici::to_vec(&m).unwrap(), [3, 4, b'k', b'e', b'y', b'1', 0, 6, b'v', b'a', b'l', b'u', b'e', b'1']);
    }

    /// A fake charon on the other end of a socket pair: answers `version`, forwards one event first.
    #[test]
    fn request_collects_events_then_returns_the_response() {
        let (a, mut b) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            let mut len = [0u8; 4];
            b.read_exact(&mut len).unwrap();
            let mut req = vec![0u8; u32::from_be_bytes(len) as usize];
            b.read_exact(&mut req).unwrap();
            assert_eq!(decode(&req).unwrap().name.as_deref(), Some("initiate"));
            let mut log = BTreeMap::new();
            log.insert("msg", "establishing CHILD_SA");
            b.write_all(&encode(EVENT, Some("control-log"), &serde_vici::to_vec(&log).unwrap())).unwrap();
            let mut ok = BTreeMap::new();
            ok.insert("success", "yes");
            b.write_all(&encode(CMD_RESPONSE, None, &serde_vici::to_vec(&ok).unwrap())).unwrap();
        });
        let mut v = Vici::from_stream(a);
        let mut seen = vec![];
        let st: Status = v
            .request("initiate", &Empty {}, Duration::from_secs(5), &mut |n, body| {
                let m: BTreeMap<String, String> = serde_vici::from_slice(body).unwrap();
                seen.push(format!("{n}: {}", m["msg"]));
            })
            .unwrap();
        server.join().unwrap();
        assert!(st.check("initiate").is_ok());
        assert_eq!(seen, ["control-log: establishing CHILD_SA"]);
    }

    #[test]
    fn closed_socket_is_an_error_and_silence_is_none() {
        let (a, b) = UnixStream::pair().unwrap();
        let mut v = Vici::from_stream(a);
        assert_eq!(v.next_event(Duration::from_millis(50)).unwrap(), None);
        drop(b);
        assert_eq!(v.next_event(Duration::from_millis(50)).unwrap_err(), "charon closed the VICI connection");
    }

    #[test]
    fn failed_status_has_a_reason() {
        let s = Status { success: "no".into(), errmsg: "unknown peer".into() };
        assert_eq!(s.check("load-conn").unwrap_err(), "load-conn failed: unknown peer");
    }
}
