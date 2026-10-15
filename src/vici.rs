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

/// Commands we send.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cmd {
    Version,
    Stats,
    LoadConn,
    LoadShared,
    Initiate,
    Terminate,
    ListSas,
}

impl Cmd {
    const ALL: [Cmd; 7] = [Cmd::Version, Cmd::Stats, Cmd::LoadConn, Cmd::LoadShared, Cmd::Initiate, Cmd::Terminate, Cmd::ListSas];
    pub fn as_str(self) -> &'static str {
        match self {
            Cmd::Version => "version",
            Cmd::Stats => "stats",
            Cmd::LoadConn => "load-conn",
            Cmd::LoadShared => "load-shared",
            Cmd::Initiate => "initiate",
            Cmd::Terminate => "terminate",
            Cmd::ListSas => "list-sas",
        }
    }
}

impl std::str::FromStr for Cmd {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        Self::ALL.into_iter().find(|c| c.as_str() == s).ok_or_else(|| format!("unknown VICI command {s:?}"))
    }
}

/// Events we subscribe to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventName {
    ControlLog,
    ListSa,
    IkeUpdown,
}

impl EventName {
    const ALL: [EventName; 3] = [EventName::ControlLog, EventName::ListSa, EventName::IkeUpdown];
    pub fn as_str(self) -> &'static str {
        match self {
            EventName::ControlLog => "control-log",
            EventName::ListSa => "list-sa",
            EventName::IkeUpdown => "ike-updown",
        }
    }
}

impl std::str::FromStr for EventName {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        Self::ALL.into_iter().find(|e| e.as_str() == s).ok_or_else(|| format!("unknown VICI event {s:?}"))
    }
}

/// One VICI packet. Named types carry a `Cmd`/`EventName`, unnamed ones can't have a name.
#[derive(Debug, PartialEq)]
pub enum Packet {
    CmdRequest { cmd: Cmd, body: Vec<u8> },
    CmdResponse(Vec<u8>),
    CmdUnknown,
    EventRegister(EventName),
    EventUnregister(EventName),
    EventConfirm,
    EventUnknown,
    Event { name: EventName, body: Vec<u8> },
}

impl Packet {
    /// The command or event name of a named packet type.
    pub fn name(&self) -> Option<&'static str> {
        match self {
            Packet::CmdRequest { cmd, .. } => Some(cmd.as_str()),
            Packet::EventRegister(e) | Packet::EventUnregister(e) | Packet::Event { name: e, .. } => Some(e.as_str()),
            _ => None,
        }
    }
}

pub fn encode(p: &Packet) -> Vec<u8> {
    let (kind, body): (u8, &[u8]) = match p {
        Packet::CmdRequest { body, .. } => (CMD_REQUEST, body),
        Packet::CmdResponse(body) => (CMD_RESPONSE, body),
        Packet::CmdUnknown => (CMD_UNKNOWN, &[]),
        Packet::EventRegister(_) => (EVENT_REGISTER, &[]),
        Packet::EventUnregister(_) => (EVENT_UNREGISTER, &[]),
        Packet::EventConfirm => (EVENT_CONFIRM, &[]),
        Packet::EventUnknown => (EVENT_UNKNOWN, &[]),
        Packet::Event { body, .. } => (EVENT, body),
    };
    let mut payload = vec![kind];
    if let Some(n) = p.name() {
        // one of the short names above, so its length fits the byte
        payload.push(n.len() as u8);
        payload.extend_from_slice(n.as_bytes());
    }
    payload.extend_from_slice(body);
    let mut out = (payload.len() as u32).to_be_bytes().to_vec();
    out.extend(payload);
    out
}

/// The packet in `payload` (without the length prefix). `Ok(None)`: an event whose name we don't know.
pub fn decode(payload: &[u8]) -> Result<Option<Packet>, String> {
    let (&kind, rest) = payload.split_first().ok_or("empty VICI packet")?;
    let named = |rest: &[u8]| -> Result<(String, Vec<u8>), String> {
        let (&len, rest) = rest.split_first().ok_or("truncated VICI packet")?;
        let len = len as usize;
        if rest.len() < len {
            return Err("truncated VICI packet name".into());
        }
        let name = String::from_utf8(rest[..len].to_vec()).map_err(|_| "VICI packet name isn't UTF-8")?;
        Ok((name, rest[len..].to_vec()))
    };
    Ok(Some(match kind {
        CMD_REQUEST => {
            let (n, body) = named(rest)?;
            Packet::CmdRequest { cmd: n.parse()?, body }
        }
        CMD_RESPONSE => Packet::CmdResponse(rest.to_vec()),
        CMD_UNKNOWN => Packet::CmdUnknown,
        EVENT_REGISTER => Packet::EventRegister(named(rest)?.0.parse()?),
        EVENT_UNREGISTER => Packet::EventUnregister(named(rest)?.0.parse()?),
        EVENT_CONFIRM => Packet::EventConfirm,
        EVENT_UNKNOWN => Packet::EventUnknown,
        EVENT => {
            let (n, body) = named(rest)?;
            match n.parse() {
                Ok(name) => Packet::Event { name, body },
                Err(_) => return Ok(None),
            }
        }
        k => return Err(format!("unknown VICI packet type {k}")),
    }))
}

/// The usual command result: `success = yes|no`, `errmsg` on failure.
#[derive(Deserialize, Debug, Default)]
pub struct Status {
    #[serde(default)]
    pub success: bool,
    #[serde(default)]
    pub errmsg: String,
}

impl Status {
    pub fn check(self, what: &str) -> Result<(), String> {
        if self.success { Ok(()) } else { Err(format!("{what} failed: {}", if self.errmsg.is_empty() { "no reason given" } else { &self.errmsg })) }
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

    fn send(&mut self, p: &Packet) -> Result<(), String> {
        self.stream.write_all(&encode(p)).map_err(|e| format!("VICI write: {e}"))
    }

    /// Next packet; `Ok(None)` when `timeout` passes without one. Events we don't know are skipped.
    pub fn recv(&mut self, timeout: Option<Duration>) -> Result<Option<Packet>, String> {
        loop {
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
            if let Some(p) = decode(&payload)? {
                return Ok(Some(p));
            }
        }
    }

    /// Subscribe to event `ev`.
    pub fn register(&mut self, ev: EventName) -> Result<(), String> {
        self.send(&Packet::EventRegister(ev))?;
        loop {
            match self.recv(Some(Duration::from_secs(5)))? {
                Some(Packet::EventConfirm) => return Ok(()),
                Some(Packet::EventUnknown) => return Err(format!("charon doesn't know event {}", ev.as_str())),
                Some(Packet::Event { .. }) => continue, // an earlier subscription
                Some(_) => return Err(format!("unexpected VICI packet while registering {}", ev.as_str())),
                None => return Err(format!("no answer from charon registering {}", ev.as_str())),
            }
        }
    }

    /// Run command `cmd`; events that arrive meanwhile go to `on_event(name, body)`.
    pub fn request<Q: Serialize, A: DeserializeOwned>(
        &mut self,
        cmd: Cmd,
        req: &Q,
        timeout: Duration,
        on_event: &mut dyn FnMut(EventName, &[u8]),
    ) -> Result<A, String> {
        let name = cmd.as_str();
        let body = serde_vici::to_vec(req).map_err(|e| format!("VICI encode {name}: {e}"))?;
        self.send(&Packet::CmdRequest { cmd, body })?;
        loop {
            match self.recv(Some(timeout))? {
                Some(Packet::CmdResponse(body)) => return serde_vici::from_slice(&body).map_err(|e| format!("VICI decode {name}: {e}")),
                Some(Packet::CmdUnknown) => return Err(format!("charon doesn't know command {name}")),
                Some(Packet::Event { name: ev, body }) => on_event(ev, &body),
                Some(_) => return Err(format!("unexpected VICI packet for {name}")),
                None => return Err(format!("no answer from charon for {name} within {}s", timeout.as_secs())),
            }
        }
    }

    /// Next event within `timeout`.
    pub fn next_event(&mut self, timeout: Duration) -> Result<Option<(EventName, Vec<u8>)>, String> {
        match self.recv(Some(timeout))? {
            Some(Packet::Event { name, body }) => Ok(Some((name, body))),
            Some(_) => Err("unexpected VICI packet between events".into()),
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
        let p = encode(&Packet::CmdRequest { cmd: Cmd::Version, body: vec![] });
        assert_eq!(p, [0, 0, 0, 9, 0, 7, b'v', b'e', b'r', b's', b'i', b'o', b'n']);
        assert_eq!(decode(&p[4..]).unwrap(), Some(Packet::CmdRequest { cmd: Cmd::Version, body: vec![] }));
        let r = encode(&Packet::CmdResponse(vec![3, 1, b'k', 0, 1, b'v']));
        assert_eq!(decode(&r[4..]).unwrap(), Some(Packet::CmdResponse(vec![3, 1, b'k', 0, 1, b'v'])));
        assert!(decode(&[EVENT, 9, b'x']).is_err(), "name longer than the packet");
        assert!(decode(&[]).is_err());
        assert!(decode(&[42]).is_err(), "unknown packet type");
        assert_eq!(decode(&[EVENT, 3, b'f', b'o', b'o']).unwrap(), None, "events we don't know are skipped");
        assert!(decode(&[CMD_REQUEST, 3, b'f', b'o', b'o']).is_err(), "commands we don't know aren't");
    }

    #[test]
    fn every_packet_round_trips() {
        for p in [
            Packet::CmdRequest { cmd: Cmd::Initiate, body: vec![1, 2] },
            Packet::CmdResponse(vec![3]),
            Packet::CmdUnknown,
            Packet::EventRegister(EventName::IkeUpdown),
            Packet::EventUnregister(EventName::ControlLog),
            Packet::EventConfirm,
            Packet::EventUnknown,
            Packet::Event { name: EventName::ListSa, body: vec![4] },
        ] {
            let bytes = encode(&p);
            assert_eq!(u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize, bytes.len() - 4);
            assert_eq!(decode(&bytes[4..]).unwrap(), Some(p));
        }
    }

    #[test]
    fn serde_vici_body_matches_the_protocol_example() {
        // key1 = value1 (type 3 = KEY_VALUE)
        let mut m = BTreeMap::new();
        m.insert("key1", "value1");
        assert_eq!(serde_vici::to_vec(&m).unwrap(), [3, 4, b'k', b'e', b'y', b'1', 0, 6, b'v', b'a', b'l', b'u', b'e', b'1']);
    }

    /// A fake charon on the other end of a socket pair: answers `initiate`, forwards one event first.
    #[test]
    fn request_collects_events_then_returns_the_response() {
        let (a, mut b) = UnixStream::pair().unwrap();
        let server = std::thread::spawn(move || {
            let mut len = [0u8; 4];
            b.read_exact(&mut len).unwrap();
            let mut req = vec![0u8; u32::from_be_bytes(len) as usize];
            b.read_exact(&mut req).unwrap();
            assert_eq!(decode(&req).unwrap().unwrap().name(), Some("initiate"));
            let log = BTreeMap::from([("msg", "establishing CHILD_SA")]);
            b.write_all(&encode(&Packet::Event { name: EventName::ControlLog, body: serde_vici::to_vec(&log).unwrap() })).unwrap();
            let ok = BTreeMap::from([("success", "yes")]);
            b.write_all(&encode(&Packet::CmdResponse(serde_vici::to_vec(&ok).unwrap()))).unwrap();
        });
        let mut v = Vici::from_stream(a);
        let mut seen = vec![];
        let st: Status = v
            .request(Cmd::Initiate, &Empty {}, Duration::from_secs(5), &mut |n, body| {
                let m: BTreeMap<String, String> = serde_vici::from_slice(body).unwrap();
                seen.push(format!("{}: {}", n.as_str(), m["msg"]));
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
    fn status_reads_yes_no_and_a_missing_value() {
        let body = |m: BTreeMap<&str, &str>| serde_vici::to_vec(&m).unwrap();
        let s: Status = serde_vici::from_slice(&body(BTreeMap::from([("success", "yes")]))).unwrap();
        assert!(s.success);
        let s: Status = serde_vici::from_slice(&body(BTreeMap::from([("success", "no"), ("errmsg", "unknown peer")]))).unwrap();
        assert_eq!(s.check("load-conn").unwrap_err(), "load-conn failed: unknown peer");
        let s: Status = serde_vici::from_slice(&body(BTreeMap::from([("errmsg", "x")]))).unwrap();
        assert!(!s.success, "no success key counts as failed");
    }
}
