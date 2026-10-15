//! Typed values that reach the kernel, charon, systemd-resolved, the FortiGate or a settings file. Each type can only
//! be built by parsing, so a value of the type is valid by construction. Parse errors are capitalised, context-free
//! sentences: the UI shows them under a field, the loader and the backend put the field name in front.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::Ipv4Addr;
use std::num::NonZeroU16;
use std::str::FromStr;
use vec1::Vec1;

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
        if ok { Ok(Self(s.into())) } else { Err("Use 1 to 15 letters, digits, _ or -, starting with a letter.".into()) }
    }
}

/// IPv4 network with the host bits zero, e.g. `10.0.0.0/8`. A bare address means `/32`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Ipv4Net(ipnet::Ipv4Net);

impl Ipv4Net {
    /// 0.0.0.0/0: everything.
    pub const ALL: Ipv4Net = Ipv4Net(ipnet::Ipv4Net::new_assert(Ipv4Addr::UNSPECIFIED, 0));
    /// 0.0.0.0/1 and 128.0.0.0/1: together everything, each more specific than any default route.
    pub const HALVES: [Ipv4Net; 2] = [
        Ipv4Net(ipnet::Ipv4Net::new_assert(Ipv4Addr::new(0, 0, 0, 0), 1)),
        Ipv4Net(ipnet::Ipv4Net::new_assert(Ipv4Addr::new(128, 0, 0, 0), 1)),
    ];

    pub fn new(addr: Ipv4Addr, prefix: u8) -> Result<Self, String> {
        let n = ipnet::Ipv4Net::new(addr, prefix).map_err(|_| format!("The prefix /{prefix} is too long. Use 0 to 32."))?;
        if n.trunc() != n {
            return Err(format!("{n} has host bits set. Did you mean {}?", n.trunc()));
        }
        Ok(Self(n))
    }
    pub fn addr(&self) -> Ipv4Addr {
        self.0.addr()
    }
    pub fn prefix(&self) -> u8 {
        self.0.prefix_len()
    }

    /// Networks separated by commas, spaces or line breaks. An error names its line (1-based).
    pub fn parse_list(text: &str) -> Result<Vec<Ipv4Net>, String> {
        let mut out = Vec::new();
        for (i, line) in text.lines().enumerate() {
            for item in line.split(|c: char| c == ',' || c.is_whitespace()).filter(|r| !r.is_empty()) {
                out.push(item.parse().map_err(|e| format!("Line {}: {e}", i + 1))?);
            }
        }
        Ok(out)
    }
}

impl FromStr for Ipv4Net {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let bad = || format!("Expected a network such as 10.0.0.0/8, not {}.", quoted(s));
        let (a, p) = s.split_once('/').unwrap_or((s, "32"));
        let addr = a.parse::<Ipv4Addr>().map_err(|_| bad())?;
        let prefix = p.parse::<u8>().map_err(|_| bad())?;
        Self::new(addr, prefix)
    }
}

/// `s` quoted for an error message, cut at 40 characters: a pasted wall of text mustn't become a wall of warning.
fn quoted(s: &str) -> String {
    const MAX: usize = 40;
    if s.chars().count() <= MAX { format!("{s:?}") } else { format!("{:?}…", s.chars().take(MAX).collect::<String>()) }
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
        // an all-numeric last label is a mistyped IPv4 address, not a name (RFC 3696 §2)
        let numeric_tld = name.rsplit('.').next().is_some_and(|l| l.chars().all(|c| c.is_ascii_digit()));
        if !name.is_empty() && name.len() <= 253 && name.split('.').all(label_ok) && !numeric_tld {
            Ok(Self(name.to_ascii_lowercase()))
        } else {
            Err(format!("{} is not a valid host name.", quoted(s)))
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
            Err(_) => s.parse::<DnsName>().map(Host::Name).map_err(|_| format!("Expected a host name or IPv4 address, not {}.", quoted(s))),
        }
    }
}

/// TCP/UDP port, 1-65535.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u16", into = "u16")]
pub struct Port(NonZeroU16);

impl Port {
    pub fn new(n: u16) -> Option<Port> {
        NonZeroU16::new(n).map(Port)
    }
    pub fn get(self) -> u16 {
        self.0.get()
    }
}

const PORT_RANGE: &str = "Port must be 1 to 65535.";

impl TryFrom<u16> for Port {
    type Error = String;
    fn try_from(n: u16) -> Result<Self, String> {
        Port::new(n).ok_or_else(|| PORT_RANGE.into())
    }
}

impl From<Port> for u16 {
    fn from(p: Port) -> u16 {
        p.get()
    }
}

impl FromStr for Port {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        s.trim().parse::<u16>().ok().and_then(Port::new).ok_or_else(|| PORT_RANGE.into())
    }
}

/// A `u16` limited to `$min..=$max`; `$what` starts the error sentence.
macro_rules! ranged_u16 {
    ($(#[$doc:meta])* $t:ident, $min:literal, $max:literal, $what:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(try_from = "u16", into = "u16")]
        pub struct $t(u16);

        impl $t {
            pub const RANGE: std::ops::RangeInclusive<u16> = $min..=$max;
            pub fn get(self) -> u16 {
                self.0
            }
        }

        impl TryFrom<u16> for $t {
            type Error = String;
            fn try_from(v: u16) -> Result<Self, String> {
                if Self::RANGE.contains(&v) { Ok(Self(v)) } else { Err(format!("{} must be {} to {}.", $what, $min, $max)) }
            }
        }

        impl From<$t> for u16 {
            fn from(v: $t) -> u16 {
                v.0
            }
        }
    };
}

ranged_u16!(
    /// Interface MTU, 576-1500.
    Mtu, 576, 1500, "MTU"
);
ranged_u16!(
    /// NAT-T keepalive interval in seconds, 5-300.
    Keepalive, 5, 300, "The NAT-T keepalive"
);
ranged_u16!(
    /// How long the SSO login may take, in seconds, 30-3600.
    LoginTimeout, 30, 3600, "The login timeout"
);

/// A PSK, token or password: never empty, printed as `<redacted>` by `Debug`, and wiped from memory when dropped.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct Secret(String);

impl Secret {
    pub fn new(s: String) -> Result<Self, String> {
        if s.is_empty() { Err("The secret is empty.".into()) } else { Ok(Self(s)) }
    }
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Secret {
    type Error = String;
    fn try_from(s: String) -> Result<Self, String> {
        Secret::new(s)
    }
}

impl Serialize for Secret {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.0.zeroize();
    }
}

/// Phase 1/2 encryption (AES-CBC key size).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Encryption {
    Aes128,
    Aes192,
    Aes256,
}

/// Phase 1/2 integrity / PRF hash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hash {
    Sha1,
    Sha256,
    Sha384,
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
        DhGroup::ALL.into_iter().find(|d| u16::from(*d) == g).ok_or_else(|| format!("DH group {g} is not supported. Use 14, 19, 20 or 21."))
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
    pub const ALL: [Encryption; 3] = [Self::Aes128, Self::Aes192, Self::Aes256];
    fn swan(self) -> &'static str {
        match self {
            Self::Aes128 => "aes128",
            Self::Aes192 => "aes192",
            Self::Aes256 => "aes256",
        }
    }
}

impl Hash {
    pub const ALL: [Hash; 4] = [Self::Sha1, Self::Sha256, Self::Sha384, Self::Sha512];
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
    /// In group-number order, as the UI shows them.
    pub const ALL: [DhGroup; 4] = [Self::Modp2048, Self::Ecp256, Self::Ecp384, Self::Ecp521];
    fn swan(self) -> &'static str {
        match self {
            Self::Modp2048 => "modp2048",
            Self::Ecp256 => "ecp256",
            Self::Ecp384 => "ecp384",
            Self::Ecp521 => "ecp521",
        }
    }
}

impl FromStr for Encryption {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        Self::ALL.into_iter().find(|e| e.swan().eq_ignore_ascii_case(s)).ok_or_else(|| format!("Unsupported encryption {}.", quoted(s)))
    }
}

impl FromStr for Hash {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        Self::ALL.into_iter().find(|h| h.swan().eq_ignore_ascii_case(s)).ok_or_else(|| format!("Unsupported hash {}.", quoted(s)))
    }
}

impl fmt::Display for Encryption {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.swan().to_ascii_uppercase())
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(&self.swan().to_ascii_uppercase())
    }
}

impl fmt::Display for DhGroup {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", u16::from(*self))
    }
}

/// A Phase 1/2 proposal. In profile files and requests it's written `aes128-sha1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proposal {
    pub enc: Encryption,
    pub hash: Hash,
}

impl FromStr for Proposal {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let parsed = s.split_once('-').and_then(|(e, h)| Some(Proposal { enc: e.parse().ok()?, hash: h.parse().ok()? }));
        parsed.ok_or_else(|| {
            let names = |v: &[&str]| v.join(", ");
            format!(
                "Invalid proposal {}: expected encryption-hash such as \"aes128-sha1\" (encryption: {}; hash: {}).",
                quoted(s),
                names(&Encryption::ALL.map(Encryption::swan)),
                names(&Hash::ALL.map(Hash::swan))
            )
        })
    }
}

impl fmt::Display for Proposal {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}-{}", self.enc.swan(), self.hash.swan())
    }
}

/// strongSwan IKE proposals: one per Phase 1 proposal, each with all DH groups, strongest first (the first one goes
/// in the KE payload).
pub fn ike_proposals(props: &Vec1<Proposal>, groups: &Vec1<DhGroup>) -> Vec<String> {
    let order = [DhGroup::Ecp384, DhGroup::Ecp521, DhGroup::Ecp256, DhGroup::Modp2048];
    let g: Vec<&str> = order.iter().filter(|x| groups.contains(x)).map(|x| x.swan()).collect();
    props.iter().map(|p| format!("{p}-{}", g.join("-"))).collect()
}

/// strongSwan ESP proposals: one per Phase 2 proposal.
pub fn esp_proposals(props: &Vec1<Proposal>) -> Vec<String> {
    props.iter().map(ToString::to_string).collect()
}

/// The FortiClient installation UID: 32 hex characters, sent with the SSO login and used as the EAP identity, so it
/// never contains anything but hex digits. Kept exactly as written: the FortiGate may compare it case-sensitively, so
/// a hand-edited lowercase UID must reach it unchanged. New ones are uppercase, like FortiClient's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ClientUid([u8; 32]);

impl ClientUid {
    pub fn generate() -> Result<Self, String> {
        let mut b = [0u8; 16];
        getrandom::fill(&mut b).map_err(|e| format!("Couldn't generate a client UID: {e}."))?;
        Ok(b.iter().map(|x| format!("{x:02X}")).collect::<String>().parse().expect("32 hex digits"))
    }
}

impl FromStr for ClientUid {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        let s = s.trim();
        let hex: [u8; 32] = s.as_bytes().try_into().map_err(|_| "The client UID must be 32 hexadecimal characters.".to_string())?;
        if hex.iter().all(u8::is_ascii_hexdigit) { Ok(Self(hex)) } else { Err("The client UID must be 32 hexadecimal characters.".into()) }
    }
}

impl fmt::Display for ClientUid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(std::str::from_utf8(&self.0).expect("hex digits are ASCII"))
    }
}

/// `s` if it's 1 to `max` printable ASCII characters (0x20-0x7E) without a space at either end. `what` starts the
/// error sentence, `why` ends the character-set one.
fn printable_ascii(s: &str, what: &str, max: usize, why: &str) -> Result<String, String> {
    if s.is_empty() {
        Err(format!("{what} cannot be empty."))
    } else if !s.chars().all(|c| (' '..='~').contains(&c)) {
        Err(format!("{what} can only contain ASCII letters, digits, spaces and punctuation{why}."))
    } else if s.trim() != s {
        Err(format!("{what} cannot start or end with a space."))
    } else if s.len() > max {
        Err(format!("{what} can be at most {max} characters."))
    } else {
        Ok(s.into())
    }
}

/// EAP user name. EAP-MSCHAPv2 carries it as ASCII (RFC 2759 §4) and RADIUS User-Name is at most 253 octets
/// (RFC 2865 §5.1), so: printable ASCII, 1-253 characters, no space at either end. `DOMAIN\user` and `user@domain`
/// are fine.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Username(String);

impl FromStr for Username {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        printable_ascii(s, "The username", 253, ", because EAP-MSCHAPv2 requires it").map(Self)
    }
}

/// IKE local ID: printable ASCII, 1-63 characters (FortiGate's limit for the phase 1 local/peer ID).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct LocalId(String);

impl FromStr for LocalId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        printable_ascii(s, "The local ID", 63, "").map(Self)
    }
}

/// Profile description: one line, no control characters, at most 200 characters. Only shown locally, so any script.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Description(String);

impl FromStr for Description {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        if s.chars().any(char::is_control) {
            Err("The description must be one line without control characters.".into())
        } else if s.chars().count() > 200 {
            Err("The description can be at most 200 characters.".into())
        } else {
            Ok(Self(s.into()))
        }
    }
}

/// A connection's name, which is also its file name (`profiles/<name>.toml`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProfileName(String);

impl ProfileName {
    /// Longest name in bytes.
    pub const MAX: usize = 100;
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// This name plus `suffix` (e.g. " (copy)", " 2"), shortened first if the result would be too long.
    pub fn with_suffix(&self, suffix: &str) -> ProfileName {
        let room = Self::MAX - suffix.len();
        let mut len = 0;
        let stem: String = self.0.chars().take_while(|c| {
            len += c.len_utf8();
            len <= room
        }).collect();
        format!("{}{suffix}", stem.trim_end()).parse().expect("a shortened valid name plus a suffix stays valid")
    }
}

impl Default for ProfileName {
    fn default() -> Self {
        Self("New connection".into())
    }
}

impl FromStr for ProfileName {
    type Err = String;
    fn from_str(name: &str) -> Result<Self, String> {
        if name.trim().is_empty() {
            Err("Name cannot be empty.".into())
        } else if name.contains(['/', '\0']) {
            Err("Name cannot contain a '/'.".into())
        } else if name.chars().any(|c| c.is_control() || matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')) {
            // also the file name the Share button shows: nothing hidden, nothing that reorders the text around it
            Err("Name cannot contain control or text-direction characters.".into())
        } else if name.starts_with('.') {
            Err("Name cannot start with a '.'.".into())
        } else if name.len() > Self::MAX {
            Err("Name is too long.".into())
        } else {
            Ok(Self(name.into()))
        }
    }
}

/// Tests set names and descriptions a lot (`p.name = "Home".into()`); a bad literal panics.
#[cfg(test)]
impl From<&str> for ProfileName {
    fn from(s: &str) -> Self {
        s.parse().expect("a valid test profile name")
    }
}

#[cfg(test)]
impl From<&str> for Description {
    fn from(s: &str) -> Self {
        s.parse().expect("a valid test description")
    }
}

/// serde through `String` for the types above that parse from text.
macro_rules! string_type {
    ($($t:ty),*) => {$(
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
    )*};
}
string_type!(IfName, Ipv4Net, DnsName, Host, Proposal, ClientUid, Description, ProfileName);

/// serde for `Username` and `LocalId`: older versions wrote what was typed, spaces around it included, and trimmed it
/// when connecting; reading drops them so those files still load. The editor stays strict.
macro_rules! trimmed_string_type {
    ($($t:ty),*) => {$(
        impl TryFrom<String> for $t {
            type Error = String;
            fn try_from(s: String) -> Result<Self, String> {
                s.trim().parse()
            }
        }
        impl From<$t> for String {
            fn from(v: $t) -> String {
                v.0
            }
        }
    )*};
}
trimmed_string_type!(Username, LocalId);

impl Serialize for Proposal {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Proposal {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?.parse().map_err(serde::de::Error::custom)
    }
}

/// `Display` for the newtypes over a `String`.
macro_rules! display_inner {
    ($($t:ty),*) => {$(
        impl fmt::Display for $t {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    )*};
}
display_inner!(IfName, DnsName, Username, LocalId, Description, ProfileName);

impl fmt::Display for Ipv4Net {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.0.fmt(f)
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

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.get().fmt(f)
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
        assert_eq!("-x".parse::<IfName>().unwrap_err(), "Use 1 to 15 letters, digits, _ or -, starting with a letter.");
    }

    #[test]
    fn ipv4net_parses_and_rejects_host_bits() {
        assert_eq!("10.0.0.0/8".parse::<Ipv4Net>().unwrap().to_string(), "10.0.0.0/8");
        assert_eq!("192.0.2.7".parse::<Ipv4Net>().unwrap().to_string(), "192.0.2.7/32");
        assert_eq!("0.0.0.0/0".parse::<Ipv4Net>().unwrap(), Ipv4Net::ALL);
        assert_eq!(Ipv4Net::HALVES.map(|n| n.to_string()), ["0.0.0.0/1", "128.0.0.0/1"]);
        assert_eq!("10.1.2.3/8".parse::<Ipv4Net>().unwrap_err(), "10.1.2.3/8 has host bits set. Did you mean 10.0.0.0/8?");
        assert_eq!("10.0.0.0/33".parse::<Ipv4Net>().unwrap_err(), "The prefix /33 is too long. Use 0 to 32.");
        for bad in ["default", "-1/8", "10.0.0.0/8; reboot", "10.0.0/8", ""] {
            assert!(bad.parse::<Ipv4Net>().unwrap_err().starts_with("Expected a network such as 10.0.0.0/8"), "{bad:?}");
        }
    }

    #[test]
    fn network_lists_split_on_commas_spaces_and_lines_and_name_the_line() {
        let v = Ipv4Net::parse_list("10.0.0.0/8, 192.168.10.0/24\n\n172.16.0.0/12").unwrap();
        assert_eq!(v.iter().map(|n| n.to_string()).collect::<Vec<_>>(), ["10.0.0.0/8", "192.168.10.0/24", "172.16.0.0/12"]);
        assert_eq!(Ipv4Net::parse_list("").unwrap(), []);
        assert_eq!(
            Ipv4Net::parse_list("10.0.0.0/8\n10.1.2.3/16").unwrap_err(),
            "Line 2: 10.1.2.3/16 has host bits set. Did you mean 10.1.0.0/16?"
        );
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
        assert_eq!("vpn.example.com; id".parse::<Host>().unwrap_err(), "Expected a host name or IPv4 address, not \"vpn.example.com; id\".");
    }

    #[test]
    fn ranges() {
        assert!(Mtu::try_from(1400).is_ok());
        assert_eq!(Mtu::try_from(1501).unwrap_err(), "MTU must be 576 to 1500.");
        assert!(Mtu::try_from(575).is_err());
        assert_eq!(Keepalive::try_from(4).unwrap_err(), "The NAT-T keepalive must be 5 to 300.");
        assert_eq!(LoginTimeout::try_from(3601).unwrap_err(), "The login timeout must be 30 to 3600.");
        assert_eq!(u16::from(Keepalive::try_from(20).unwrap()), 20);
        assert_eq!(serde_json::from_str::<Mtu>("9000").unwrap_err().to_string(), "MTU must be 576 to 1500.");
    }

    #[test]
    fn ports() {
        assert_eq!("8443".parse::<Port>().unwrap().get(), 8443);
        assert_eq!(" 443 ".parse::<Port>().unwrap().get(), 443);
        for bad in ["0", "65536", "", "x", "4438443"] {
            assert_eq!(bad.parse::<Port>().unwrap_err(), "Port must be 1 to 65535.", "{bad:?}");
        }
        assert!(serde_json::from_str::<Port>("0").is_err());
        assert_eq!(serde_json::to_string(&Port::new(500).unwrap()).unwrap(), "500");
    }

    #[test]
    fn serde_rejects_bad_values() {
        assert!(serde_json::from_str::<IfName>("\"x;y\"").is_err());
        assert_eq!(serde_json::from_str::<Ipv4Net>("\"10.0.0.0/8\"").unwrap().to_string(), "10.0.0.0/8");
        assert_eq!(serde_json::to_string(&"fsaml0".parse::<IfName>().unwrap()).unwrap(), "\"fsaml0\"");
    }

    #[test]
    fn proposals() {
        let p: Proposal = "AES256-Sha384".parse().unwrap();
        assert_eq!(p, Proposal { enc: Encryption::Aes256, hash: Hash::Sha384 });
        assert_eq!(p.to_string(), "aes256-sha384");
        let e = "foo-bar".parse::<Proposal>().unwrap_err();
        assert!(e.contains("\"foo-bar\"") && e.contains("aes128, aes192, aes256") && e.contains("sha1, sha256, sha384, sha512"), "{e}");
        assert!("aes128sha1".parse::<Proposal>().is_err() && "-sha1".parse::<Proposal>().is_err());
        assert_eq!(serde_json::to_string(&p).unwrap(), "\"aes256-sha384\"");
        assert_eq!("aes192".parse::<Encryption>().unwrap(), Encryption::Aes192);
        assert_eq!(Encryption::Aes128.to_string(), "AES128");
        assert_eq!(Hash::Sha512.to_string(), "SHA512");
        assert_eq!("MD5".parse::<Hash>().unwrap_err(), "Unsupported hash \"MD5\".");
        assert_eq!(DhGroup::ALL.map(u16::from), [14, 19, 20, 21]);
        assert_eq!(DhGroup::Ecp521.to_string(), "21");
    }

    #[test]
    fn usernames_are_what_eap_mschapv2_can_carry() {
        for ok in ["jane", "CORP\\jane", "jane@corp.example", "Jane Doe", &"a".repeat(253)] {
            assert!(ok.parse::<Username>().is_ok(), "{ok:?}");
        }
        assert_eq!("".parse::<Username>().unwrap_err(), "The username cannot be empty.");
        assert_eq!(
            "jané".parse::<Username>().unwrap_err(),
            "The username can only contain ASCII letters, digits, spaces and punctuation, because EAP-MSCHAPv2 requires it."
        );
        assert!("ja\tne".parse::<Username>().is_err());
        assert_eq!(" jane".parse::<Username>().unwrap_err(), "The username cannot start or end with a space.");
        assert_eq!("a".repeat(254).parse::<Username>().unwrap_err(), "The username can be at most 253 characters.");
    }

    #[test]
    fn local_id_fits_the_fortigate_peer_id_field() {
        assert!("client.example.com".parse::<LocalId>().is_ok());
        assert!("a".repeat(63).parse::<LocalId>().is_ok());
        assert_eq!("a".repeat(64).parse::<LocalId>().unwrap_err(), "The local ID can be at most 63 characters.");
        assert_eq!("ïd".parse::<LocalId>().unwrap_err(), "The local ID can only contain ASCII letters, digits, spaces and punctuation.");
    }

    #[test]
    fn descriptions_are_one_line() {
        assert_eq!("Büro Utrecht".parse::<Description>().unwrap().to_string(), "Büro Utrecht");
        assert_eq!("".parse::<Description>().unwrap(), Description::default());
        assert_eq!("a\nb".parse::<Description>().unwrap_err(), "The description must be one line without control characters.");
        assert_eq!("é".repeat(201).parse::<Description>().unwrap_err(), "The description can be at most 200 characters.");
    }

    #[test]
    fn profile_names_keep_todays_rules() {
        assert_eq!(ProfileName::default().as_str(), "New connection");
        assert_eq!("".parse::<ProfileName>().unwrap_err(), "Name cannot be empty.");
        assert_eq!("  ".parse::<ProfileName>().unwrap_err(), "Name cannot be empty.");
        assert_eq!("a/b".parse::<ProfileName>().unwrap_err(), "Name cannot contain a '/'.");
        assert_eq!(".hidden".parse::<ProfileName>().unwrap_err(), "Name cannot start with a '.'.");
        assert_eq!("x".repeat(101).parse::<ProfileName>().unwrap_err(), "Name is too long.");
        let long: ProfileName = "x".repeat(100).parse().unwrap();
        let copy = long.with_suffix(" (copy)");
        assert!(copy.as_str().ends_with("x (copy)") && copy.as_str().len() <= 100, "{copy}");
        assert_eq!(ProfileName::default().with_suffix(" 2").as_str(), "New connection 2");
    }

    #[test]
    fn proposals_for_strongswan() {
        use vec1::vec1;
        let p = vec1![Proposal { enc: Encryption::Aes128, hash: Hash::Sha1 }, Proposal { enc: Encryption::Aes256, hash: Hash::Sha256 }];
        let g = vec1![DhGroup::Modp2048, DhGroup::Ecp384];
        assert_eq!(ike_proposals(&p, &g), ["aes128-sha1-ecp384-modp2048", "aes256-sha256-ecp384-modp2048"]);
        assert_eq!(esp_proposals(&p), ["aes128-sha1", "aes256-sha256"]);
        assert!(DhGroup::try_from(5).is_err());
        assert_eq!(serde_json::to_string(&DhGroup::Ecp521).unwrap(), "21");
    }

    #[test]
    fn secrets_are_never_empty_and_never_printed() {
        let s = Secret::new("hunter2".into()).unwrap();
        assert_eq!(format!("{s:?}"), "<redacted>");
        assert_eq!(s.expose(), "hunter2");
        assert!(Secret::new(String::new()).is_err());
        assert!(serde_json::from_str::<Secret>("\"\"").is_err());
        assert_eq!(serde_json::to_string(&s).unwrap(), "\"hunter2\"");
    }

    #[test]
    fn client_uid_keeps_the_case_it_was_written_in() {
        // the FortiGate has seen it written this way; sending it differently could make it a new device
        let u: ClientUid = "0123456789abcdef0123456789ABCDEF".parse().unwrap();
        assert_eq!(u.to_string(), "0123456789abcdef0123456789ABCDEF");
        assert_eq!(serde_json::to_string(&u).unwrap(), "\"0123456789abcdef0123456789ABCDEF\"");
        let g = ClientUid::generate().unwrap().to_string();
        assert_eq!(g, g.to_ascii_uppercase(), "new UIDs are uppercase, like FortiClient's");
        for bad in ["", "0123456789ABCDEF0123456789ABCDE", "0123456789ABCDEF0123456789ABCDEG", "x&REDIRECT_PORT=1"] {
            assert_eq!(bad.parse::<ClientUid>().unwrap_err(), "The client UID must be 32 hexadecimal characters.", "{bad:?}");
        }
        let a = ClientUid::generate().unwrap();
        assert_ne!(a, ClientUid::generate().unwrap());
        assert_eq!(a.to_string().parse::<ClientUid>().unwrap(), a);
    }

    #[test]
    fn all_numeric_names_are_not_host_names() {
        // a mistyped IP must not slip through as a DNS name (resolvers read "10.0.0" as 10.0.0.0)
        for bad in ["1.2.3", "256.1.1.1", "192.168.192.168.", "10.0.0", "example.123", "1"] {
            assert!(bad.parse::<Host>().is_err(), "{bad:?}");
        }
        for ok in ["g", "host1", "123abc.example", "vpn.example.com", "1a"] {
            assert!(matches!(ok.parse::<Host>(), Ok(Host::Name(_))), "{ok:?}");
        }
        assert_eq!("192.168.1.1".parse::<Host>().unwrap(), Host::Ip(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn long_input_is_not_repeated_in_full_in_errors() {
        let long = "a b".repeat(5000);
        for e in [
            long.parse::<Host>().unwrap_err(),
            long.parse::<DnsName>().unwrap_err(),
            long.parse::<Ipv4Net>().unwrap_err(),
            long.parse::<Proposal>().unwrap_err(),
            long.parse::<Encryption>().unwrap_err(),
            long.parse::<Hash>().unwrap_err(),
        ] {
            assert!(e.chars().count() < 250, "{} chars: {}", e.len(), &e[..80]);
        }
        assert_eq!("a;b".parse::<Host>().unwrap_err(), "Expected a host name or IPv4 address, not \"a;b\".", "short input is quoted as is");
    }

    #[test]
    fn profile_names_have_no_control_or_direction_characters() {
        // the name is also the file name the Share button shows: no hidden or reordering characters
        for bad in ["a\tb", "a\u{1}b", "a\u{7f}", "rtl\u{202e}lmot.exe", "\u{2066}x", "x\u{200f}"] {
            assert_eq!(bad.parse::<ProfileName>().unwrap_err(), "Name cannot contain control or text-direction characters.", "{bad:?}");
        }
        assert!("Büro Utrecht 😀".parse::<ProfileName>().is_ok());
    }

}
