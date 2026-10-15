//! Typed values that reach the kernel, charon or systemd-resolved. Each type can only be built by parsing, so a
//! value of the type is valid by construction; the privileged backend parses its whole request into these.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

/// Network interface name: 1-15 bytes of `[A-Za-z0-9_-]`, starting with a letter (stricter than the kernel, so it
/// can never look like an option or contain a path separator).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct IfName(String);

impl FromStr for IfName {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let ok = (1..=15).contains(&s.len())
            && s.starts_with(|c: char| c.is_ascii_alphabetic())
            && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        if ok { Ok(Self(s.into())) } else { Err(format!("invalid interface name {s:?}: use 1-15 letters, digits, _ or -, starting with a letter")) }
    }
}

/// IPv4 network: address + prefix 0-32 with the host bits zero, e.g. `10.0.0.0/8`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Ipv4Net {
    addr: Ipv4Addr,
    prefix: u8,
}

impl Ipv4Net {
    pub fn new(addr: Ipv4Addr, prefix: u8) -> Result<Self, String> {
        if prefix > 32 {
            return Err(format!("invalid prefix /{prefix}"));
        }
        let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
        if u32::from(addr) & !mask != 0 {
            return Err(format!("{addr}/{prefix} has host bits set (did you mean {}/{prefix}?)", Ipv4Addr::from(u32::from(addr) & mask)));
        }
        Ok(Self { addr, prefix })
    }
    pub fn addr(&self) -> Ipv4Addr {
        self.addr
    }
    pub fn prefix(&self) -> u8 {
        self.prefix
    }
}

impl FromStr for Ipv4Net {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let (a, p) = s.split_once('/').unwrap_or((s, "32"));
        let addr = a.parse::<Ipv4Addr>().map_err(|_| format!("invalid network {s:?}: expected e.g. 10.0.0.0/8"))?;
        let prefix = p.parse::<u8>().map_err(|_| format!("invalid network {s:?}: expected e.g. 10.0.0.0/8"))?;
        Self::new(addr, prefix)
    }
}

/// DNS name (RFC 1123): at most 253 characters, dot-separated labels of 1-63 `[A-Za-z0-9-]` that don't start or end
/// with `-`. A trailing dot is accepted and dropped.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct DnsName(String);

impl FromStr for DnsName {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let name = s.strip_suffix('.').unwrap_or(s);
        let label_ok = |l: &str| {
            (1..=63).contains(&l.len())
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        };
        if !name.is_empty() && name.len() <= 253 && name.split('.').all(label_ok) {
            Ok(Self(name.to_ascii_lowercase()))
        } else {
            Err(format!("invalid DNS name {s:?}"))
        }
    }
}

/// Gateway: an IPv4 address or a DNS name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum Host {
    Ip(Ipv4Addr),
    Name(DnsName),
}

impl FromStr for Host {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.trim();
        match s.parse::<Ipv4Addr>() {
            Ok(ip) => Ok(Host::Ip(ip)),
            Err(_) => s.parse::<DnsName>().map(Host::Name).map_err(|_| format!("invalid gateway {s:?}: expected a host name or IPv4 address")),
        }
    }
}

/// Interface MTU, 576-1500.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct Mtu(u16);

impl TryFrom<u16> for Mtu {
    type Error = String;
    fn try_from(v: u16) -> Result<Self, String> {
        if (576..=1500).contains(&v) { Ok(Self(v)) } else { Err(format!("invalid MTU {v}: use 576 to 1500")) }
    }
}

impl From<Mtu> for u16 {
    fn from(m: Mtu) -> u16 {
        m.0
    }
}

/// A PSK, token or password: printed as `<redacted>` by `Debug`, so it never ends up in a log or panic message.
#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(pub String);

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(if self.0.is_empty() { "\"\"" } else { "<redacted>" })
    }
}

/// Phase 1/2 encryption (AES-CBC key size).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Encryption {
    #[serde(rename = "AES128")]
    Aes128,
    #[serde(rename = "AES192")]
    Aes192,
    #[serde(rename = "AES256")]
    Aes256,
}

/// Phase 1/2 integrity / PRF hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Hash {
    #[serde(rename = "SHA1")]
    Sha1,
    #[serde(rename = "SHA256")]
    Sha256,
    #[serde(rename = "SHA384")]
    Sha384,
    #[serde(rename = "SHA512")]
    Sha512,
}

/// Diffie-Hellman groups we offer (MODP2048, ECP256/384/521).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub enum DhGroup {
    Modp2048,
    Ecp256,
    Ecp384,
    Ecp521,
}

impl TryFrom<u16> for DhGroup {
    type Error = String;
    fn try_from(g: u16) -> Result<Self, String> {
        match g {
            14 => Ok(Self::Modp2048),
            19 => Ok(Self::Ecp256),
            20 => Ok(Self::Ecp384),
            21 => Ok(Self::Ecp521),
            _ => Err(format!("DH group {g} is not supported (use 14, 19, 20 or 21)")),
        }
    }
}

impl From<DhGroup> for u16 {
    fn from(g: DhGroup) -> u16 {
        match g {
            DhGroup::Modp2048 => 14,
            DhGroup::Ecp256 => 19,
            DhGroup::Ecp384 => 20,
            DhGroup::Ecp521 => 21,
        }
    }
}

impl Encryption {
    pub fn parse(s: &str) -> Result<Self, String> {
        serde_json::from_value(serde_json::Value::String(s.to_ascii_uppercase())).map_err(|_| format!("unsupported encryption {s:?}"))
    }
    fn swan(self) -> &'static str {
        match self {
            Self::Aes128 => "aes128",
            Self::Aes192 => "aes192",
            Self::Aes256 => "aes256",
        }
    }
}

impl Hash {
    pub fn parse(s: &str) -> Result<Self, String> {
        serde_json::from_value(serde_json::Value::String(s.to_ascii_uppercase())).map_err(|_| format!("unsupported hash {s:?}"))
    }
    fn swan(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
        }
    }
}

impl DhGroup {
    fn swan(self) -> &'static str {
        match self {
            Self::Modp2048 => "modp2048",
            Self::Ecp256 => "ecp256",
            Self::Ecp384 => "ecp384",
            Self::Ecp521 => "ecp521",
        }
    }
}

/// strongSwan IKE proposals: one per (encryption, hash), each with all DH groups, strongest first (the first one
/// goes in the KE payload). No groups means ECP384, FortiClient's default.
pub fn ike_proposals(props: &[(Encryption, Hash)], groups: &[DhGroup]) -> Vec<String> {
    let order = [DhGroup::Ecp384, DhGroup::Ecp521, DhGroup::Ecp256, DhGroup::Modp2048];
    let mut g: Vec<&str> = order.iter().filter(|x| groups.contains(x)).map(|x| x.swan()).collect();
    if g.is_empty() {
        g.push(DhGroup::Ecp384.swan());
    }
    props.iter().map(|(e, h)| format!("{}-{}-{}", e.swan(), h.swan(), g.join("-"))).collect()
}

/// strongSwan ESP proposals: one per (encryption, hash).
pub fn esp_proposals(props: &[(Encryption, Hash)]) -> Vec<String> {
    props.iter().map(|(e, h)| format!("{}-{}", e.swan(), h.swan())).collect()
}

macro_rules! string_type {
    ($t:ty) => {
        impl TryFrom<String> for $t {
            type Error = String;
            fn try_from(s: String) -> Result<Self, String> {
                s.parse()
            }
        }
        impl From<$t> for String {
            fn from(v: $t) -> String {
                v.to_string()
            }
        }
    };
}
string_type!(IfName);
string_type!(Ipv4Net);
string_type!(DnsName);
string_type!(Host);

impl fmt::Display for IfName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl fmt::Display for Ipv4Net {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}
impl fmt::Display for DnsName {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Host::Ip(ip) => write!(f, "{ip}"),
            Host::Name(n) => write!(f, "{n}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifname_accepts_normal_names_only() {
        for ok in ["fsaml0", "vpn_1", "a", "wg-office", "abcdefghijklmno"] {
            assert!(ok.parse::<IfName>().is_ok(), "{ok}");
        }
        for bad in ["", "-x", "0abc", "x; rm -rf /", "a b", "a/b", "a:b", "abcdefghijklmnop", "fsaml0\n", "é"] {
            assert!(bad.parse::<IfName>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn ipv4net_parses_and_rejects_host_bits() {
        assert_eq!("10.0.0.0/8".parse::<Ipv4Net>().unwrap().to_string(), "10.0.0.0/8");
        assert_eq!("192.0.2.7".parse::<Ipv4Net>().unwrap().to_string(), "192.0.2.7/32");
        assert_eq!("0.0.0.0/0".parse::<Ipv4Net>().unwrap().prefix(), 0);
        let e = "10.1.2.3/8".parse::<Ipv4Net>().unwrap_err();
        assert!(e.contains("did you mean 10.0.0.0/8"), "{e}");
        for bad in ["10.0.0.0/33", "default", "-1/8", "10.0.0.0/8; reboot", "10.0.0/8", ""] {
            assert!(bad.parse::<Ipv4Net>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn dnsname_follows_rfc1123() {
        assert_eq!("Corp.Example.COM.".parse::<DnsName>().unwrap().to_string(), "corp.example.com");
        for bad in ["", "~.", "~corp", "-x.com", "a-.com", "a..b", "a b", "a;b", "x\n", &"a".repeat(64), &format!("{}.com", "a.".repeat(130))] {
            assert!(bad.parse::<DnsName>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn host_is_ip_or_name() {
        assert_eq!("192.0.2.1".parse::<Host>().unwrap(), Host::Ip(Ipv4Addr::new(192, 0, 2, 1)));
        assert!(matches!(" vpn.example.com ".parse::<Host>().unwrap(), Host::Name(_)));
        assert!("vpn.example.com; id".parse::<Host>().is_err());
    }

    #[test]
    fn mtu_range() {
        assert!(Mtu::try_from(1400).is_ok());
        assert!(Mtu::try_from(575).is_err() && Mtu::try_from(1501).is_err());
    }

    #[test]
    fn serde_rejects_bad_values() {
        assert!(serde_json::from_str::<IfName>("\"x;y\"").is_err());
        assert_eq!(serde_json::from_str::<Ipv4Net>("\"10.0.0.0/8\"").unwrap().to_string(), "10.0.0.0/8");
        assert_eq!(serde_json::to_string(&"fsaml0".parse::<IfName>().unwrap()).unwrap(), "\"fsaml0\"");
    }

    #[test]
    fn proposals_for_strongswan() {
        let p = [(Encryption::Aes128, Hash::Sha1), (Encryption::Aes256, Hash::Sha256)];
        let g = [DhGroup::Modp2048, DhGroup::Ecp384];
        assert_eq!(ike_proposals(&p, &g), ["aes128-sha1-ecp384-modp2048", "aes256-sha256-ecp384-modp2048"]);
        assert_eq!(ike_proposals(&p[..1], &[]), ["aes128-sha1-ecp384"]);
        assert_eq!(esp_proposals(&p), ["aes128-sha1", "aes256-sha256"]);
        assert_eq!(Encryption::parse("aes192").unwrap(), Encryption::Aes192);
        assert!(Hash::parse("MD5").is_err());
        assert!(DhGroup::try_from(5).is_err());
        assert_eq!(serde_json::to_string(&DhGroup::Ecp521).unwrap(), "21");
    }

    #[test]
    fn secret_debug_is_redacted() {
        assert_eq!(format!("{:?}", Secret("hunter2".into())), "<redacted>");
    }
}
