//! The GUI ↔ privileged backend contract. The GUI sends one `BackendRequest` as a JSON line on the backend's stdin;
//! the backend reports progress as `@@{json}` `BackendEvent` lines on stdout. Every field is a checked type and the
//! lists that must not be empty are `Vec1`s, so a malformed or hand-crafted request is rejected while it's parsed,
//! before anything runs as root.

use crate::net::{ClientUid, DhGroup, Host, IfName, Ipv4Net, Keepalive, LocalId, Mtu, Port, Proposal, Secret, Username};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::Ipv4Addr;
use vec1::Vec1;

/// The EAP identity: the FortiClient UID with SSO, the username otherwise.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum EapIdentity {
    Uid(ClientUid),
    User(Username),
}

impl fmt::Display for EapIdentity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EapIdentity::Uid(u) => u.fmt(f),
            EapIdentity::User(u) => u.fmt(f),
        }
    }
}

/// How the client authenticates besides the PSK.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum ClientAuth {
    /// EAP with this identity and secret (SSO: UID + SAML token; otherwise username + password)
    Eap { identity: EapIdentity, secret: Secret },
    /// pre-shared key only, no user authentication
    PskOnly,
}

/// Which networks go through the tunnel.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Routes {
    /// the traffic selectors the FortiGate narrows to
    Gateway,
    /// everything
    Full,
    /// only these
    Custom(Vec1<Ipv4Net>),
}

impl Routes {
    /// The networks to route instead of the gateway's traffic selectors; None: use the traffic selectors.
    pub fn overrides(&self) -> Option<Vec<Ipv4Net>> {
        match self {
            Routes::Gateway => None,
            Routes::Full => Some(vec![Ipv4Net::ALL]),
            Routes::Custom(v) => Some(v.to_vec()),
        }
    }
}

/// What the GUI asks the privileged backend to do.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BackendRequest {
    pub gateway: Host,
    pub ike_port: Port,
    pub psk: Secret,
    pub auth: ClientAuth,
    pub local_id: Option<LocalId>,
    pub dh_groups: Vec1<DhGroup>,
    pub ike_proposals: Vec1<Proposal>,
    pub esp_proposals: Vec1<Proposal>,
    pub natt_keepalive: Keepalive,
    pub ifname: IfName,
    pub mtu: Mtu,
    pub routes: Routes,
    pub block_ipv6: bool,
    pub set_dns: bool,
    pub verbose: bool,
}

/// Progress, from the in-process SAML login or from the privileged backend.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum BackendEvent {
    SamlStart,
    SamlUrl { url: String },
    SamlOk { username: String },
    IkeStart { gateway: Host },
    Established { ip: Ipv4Addr },
    TunnelUp { ifname: IfName, ip: Ipv4Addr, routes: Vec<Ipv4Net>, full_tunnel: bool },
    Connected,
    Disconnecting,
    Disconnected,
    Error { message: String },
}

impl BackendEvent {
    /// The stdout line for this event.
    pub fn to_line(&self) -> String {
        format!("@@{}", serde_json::to_string(self).expect("events serialize"))
    }

    /// The event on an `@@` line; None for any other (log) line.
    pub fn from_line(line: &str) -> Option<Result<BackendEvent, String>> {
        line.strip_prefix("@@").map(|j| serde_json::from_str(j).map_err(|e| format!("unreadable status line from the backend: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use vec1::vec1;

    fn request() -> BackendRequest {
        BackendRequest {
            gateway: "vpn.example.com".parse().unwrap(),
            ike_port: Port::new(500).unwrap(),
            psk: Secret::new("psk-secret".into()).unwrap(),
            auth: ClientAuth::Eap {
                identity: EapIdentity::Uid("0123456789ABCDEF0123456789ABCDEF".parse().unwrap()),
                secret: Secret::new("token-secret".into()).unwrap(),
            },
            local_id: None,
            dh_groups: vec1![DhGroup::Ecp384],
            ike_proposals: vec1!["aes128-sha1".parse().unwrap()],
            esp_proposals: vec1!["aes128-sha1".parse().unwrap()],
            natt_keepalive: Keepalive::try_from(20).unwrap(),
            ifname: "fsaml0".parse().unwrap(),
            mtu: Mtu::try_from(1400).unwrap(),
            routes: Routes::Custom(vec1!["10.0.0.0/8".parse().unwrap()]),
            block_ipv6: true,
            set_dns: true,
            verbose: false,
        }
    }

    #[test]
    fn requests_round_trip() {
        let r = request();
        let back: BackendRequest = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn malformed_requests_are_rejected_while_parsing() {
        let good = serde_json::to_value(request()).unwrap();
        let rejected = |f: &dyn Fn(&mut serde_json::Value)| {
            let mut v = good.clone();
            f(&mut v);
            serde_json::from_value::<BackendRequest>(v).is_err()
        };
        assert!(!rejected(&|_| {}));
        assert!(rejected(&|v| v["ike_proposals"] = json!([])));
        assert!(rejected(&|v| v["esp_proposals"] = json!([])));
        assert!(rejected(&|v| v["dh_groups"] = json!([])));
        assert!(rejected(&|v| v["routes"] = json!({"Custom": []})));
        assert!(rejected(&|v| v["auth"] = json!({"Eap": {"secret": "tok"}})), "a secret without an identity");
        assert!(rejected(&|v| v["auth"] = json!({"Eap": {"identity": {"Uid": "0123456789ABCDEF0123456789ABCDEF"}, "secret": ""}})), "empty secret");
        assert!(rejected(&|v| v["psk"] = json!("")));
        assert!(rejected(&|v| v["ifname"] = json!("-x")));
    }

    #[test]
    fn secrets_stay_out_of_debug_output() {
        let s = format!("{:?}", request());
        assert!(!s.contains("psk-secret") && !s.contains("token-secret"), "{s}");
    }

    #[test]
    fn routes_overrides() {
        assert_eq!(Routes::Gateway.overrides(), None);
        assert_eq!(Routes::Full.overrides(), Some(vec![Ipv4Net::ALL]));
        assert_eq!(Routes::Custom(vec1!["10.0.0.0/8".parse().unwrap()]).overrides(), Some(vec!["10.0.0.0/8".parse().unwrap()]));
    }

    #[test]
    fn events_round_trip_as_lines() {
        let all = [
            BackendEvent::SamlStart,
            BackendEvent::SamlUrl { url: "https://idp.example/login".into() },
            BackendEvent::SamlOk { username: "jane".into() },
            BackendEvent::IkeStart { gateway: "vpn.example.com".parse().unwrap() },
            BackendEvent::Established { ip: Ipv4Addr::new(10, 98, 0, 2) },
            BackendEvent::TunnelUp { ifname: "fsaml0".parse().unwrap(), ip: Ipv4Addr::new(10, 98, 0, 2), routes: vec![Ipv4Net::ALL], full_tunnel: true },
            BackendEvent::Connected,
            BackendEvent::Disconnecting,
            BackendEvent::Disconnected,
            BackendEvent::Error { message: "no answer".into() },
        ];
        for ev in all {
            assert_eq!(BackendEvent::from_line(&ev.to_line()), Some(Ok(ev.clone())));
        }
        assert_eq!(BackendEvent::Connected.to_line(), "@@{\"event\":\"connected\"}");
        assert!(BackendEvent::from_line("[*] a log line").is_none());
        assert!(BackendEvent::from_line("@@{\"event\":\"dns\"}").unwrap().unwrap_err().starts_with("unreadable status line from the backend"));
    }
}
