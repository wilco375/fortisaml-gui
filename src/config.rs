//! Persistent settings in ~/.config/fortisaml-gui/config.json (mode 0600), written when the user clicks Save.
//! The PSK and password are not in this file: they live in the Secret Service (see keyring.rs).

use serde::{Deserialize, Serialize};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

pub const ENCRYPTIONS: [&str; 3] = ["AES128", "AES192", "AES256"];
pub const HASHES: [&str; 4] = ["SHA1", "SHA256", "SHA384", "SHA512"];
/// DH groups the backend implements (MODP2048, ECP256/384/521).
pub const DH_SUPPORTED: [u16; 4] = [14, 19, 20, 21];
/// Groups shown by the official client but not implemented here (rendered disabled).
pub const DH_UNSUPPORTED: [u16; 8] = [1, 2, 5, 15, 16, 17, 18, 31];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Proposal {
    pub enc: String,
    pub hash: String,
}

impl Proposal {
    pub fn new(enc: &str, hash: &str) -> Self {
        Self { enc: enc.into(), hash: hash.into() }
    }
    pub fn spec(&self) -> String {
        format!("{}-{}", self.enc.to_lowercase(), self.hash.to_lowercase())
    }
}

/// User authentication when SSO is disabled.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub enum UserAuth {
    /// EAP (MSCHAPv2/GTC) with username + password - FortiClient's IKEv2 default
    Eap,
    /// No user authentication: the client authenticates with the pre-shared key only
    None,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub enum RouteMode {
    /// Use split networks / traffic selectors pushed by the FortiGate (full tunnel if it pushes 0.0.0.0/0)
    Gateway,
    /// Force everything through the VPN
    Full,
    /// Only the networks listed in `custom_routes`
    Custom,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Profile {
    /// stable key for this profile's keyring items (see keyring.rs)
    pub id: String,
    pub name: String,
    pub description: String,
    pub gateway: String,
    // Single Sign On
    pub sso_enabled: bool,
    pub saml_port: u16,
    pub open_browser: bool,
    pub verify_cert: bool,
    pub saml_timeout: u32,
    // Authentication
    /// stored in the Secret Service, never in this file (see keyring.rs)
    #[serde(skip)]
    pub psk: String,
    // user authentication when SSO is off
    pub user_auth: UserAuth,
    pub username: String,
    /// stored in the Secret Service only if `save_password`, never in this file
    #[serde(skip)]
    pub password: String,
    pub save_password: bool,
    // VPN settings
    pub ike_port: u16,
    // Phase 1
    pub ike_proposals: Vec<Proposal>,
    pub dh_groups: Vec<u16>,
    pub local_id: String,
    pub natt_keepalive: u32,
    // Phase 2
    pub esp_proposals: Vec<Proposal>,
    // Network
    pub route_mode: RouteMode,
    pub custom_routes: String,
    pub block_ipv6: bool,
    pub set_dns: bool,
    pub ifname: String,
    pub mtu: u16,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            id: new_uid(),
            name: "New connection".into(),
            description: String::new(),
            gateway: String::new(),
            sso_enabled: true,
            saml_port: 443,
            open_browser: true,
            verify_cert: false,
            saml_timeout: 300,
            psk: String::new(),
            user_auth: UserAuth::Eap,
            username: String::new(),
            password: String::new(),
            save_password: false,
            ike_port: 500,
            // FortiClient GUI defaults
            ike_proposals: vec![Proposal::new("AES128", "SHA1"), Proposal::new("AES256", "SHA256")],
            dh_groups: vec![20],
            local_id: String::new(),
            natt_keepalive: 20,
            esp_proposals: vec![Proposal::new("AES128", "SHA1"), Proposal::new("AES256", "SHA256")],
            route_mode: RouteMode::Gateway,
            custom_routes: String::new(),
            block_ipv6: true,
            set_dns: true,
            ifname: "fsaml0".into(),
            mtu: 1400,
        }
    }
}

impl Profile {
    /// Copy under a new id, so it doesn't share keyring items with the original.
    pub fn duplicate(&self) -> Self {
        Self { id: new_uid(), name: format!("{} (copy)", self.name), ..self.clone() }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Config {
    pub profiles: Vec<Profile>,
    pub selected: usize,
    /// FortiClient installation UID presented to the FortiGate (SAML UID + EAP identity)
    pub uid: String,
    pub verbose: bool,
    pub log_file: String,
    pub show_log: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            profiles: vec![Profile::default()],
            selected: 0,
            uid: new_uid(),
            verbose: false,
            log_file: String::new(),
            show_log: true,
        }
    }
}

pub fn new_uid() -> String {
    let mut b = [0u8; 16];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        use std::io::Read;
        let _ = f.read_exact(&mut b);
    }
    b.iter().map(|x| format!("{x:02X}")).collect()
}

pub fn config_path() -> PathBuf {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".config"));
    base.join("fortisaml-gui").join("config.json")
}

impl Config {
    pub fn load() -> Self {
        let mut c: Config = std::fs::read_to_string(config_path())
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        if c.profiles.is_empty() {
            c.profiles.push(Profile::default());
        }
        if c.uid.len() != 32 {
            c.uid = new_uid();
        }
        c.selected = c.selected.min(c.profiles.len() - 1);
        c
    }

    /// Give profiles with an empty or already used id (hand-edited config) a fresh one,
    /// so no two profiles share keyring items.
    pub fn dedupe_ids(&mut self) {
        let mut seen = std::collections::HashSet::new();
        for p in &mut self.profiles {
            if p.id.is_empty() || !seen.insert(p.id.clone()) {
                p.id = new_uid();
                seen.insert(p.id.clone());
            }
        }
    }

    /// Same settings, ignoring view state (`selected`, `show_log`) and passwords that aren't saved.
    pub fn settings_eq(&self, other: &Config) -> bool {
        fn norm(c: &Config) -> Config {
            let mut c = c.clone();
            c.selected = 0;
            c.show_log = false;
            for p in c.profiles.iter_mut().filter(|p| !p.save_password) {
                p.password.clear();
            }
            c
        }
        norm(self) == norm(other)
    }

    /// Atomic write with 0600 permissions.
    pub fn save(&self) -> std::io::Result<()> {
        let path = config_path();
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        let tmp = path.with_extension("json.tmp");
        {
            let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
            f.write_all(serde_json::to_string_pretty(self).unwrap().as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(tmp, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secrets_never_serialized() {
        let mut c = Config::default();
        c.profiles[0].psk = "topsecret".into();
        c.profiles[0].password = "hunter2".into();
        c.profiles[0].save_password = true;
        let json = serde_json::to_string(&c).unwrap();
        assert!(!json.contains("topsecret") && !json.contains("hunter2"));
        assert!(!json.contains("\"psk\"") && !json.contains("\"password\""));
    }

    #[test]
    fn old_config_loads_without_secrets_and_gets_ids() {
        let json = r#"{"profiles":[{"name":"a","psk":"enc:v1:00ff","password":"enc:v1:00ff","save_password":true},{"name":"b"}]}"#;
        let c: Config = serde_json::from_str(json).unwrap();
        assert_eq!(c.profiles[0].psk, "");
        assert_eq!(c.profiles[0].password, "");
        assert_eq!(c.profiles[0].id.len(), 32);
        assert_ne!(c.profiles[0].id, c.profiles[1].id);
    }

    #[test]
    fn duplicate_gets_new_id() {
        let mut p = Profile::default();
        p.name = "Office".into();
        p.psk = "k".into();
        let d = p.duplicate();
        assert_ne!(d.id, p.id);
        assert_eq!(d.name, "Office (copy)");
        assert_eq!(d.psk, "k");
    }

    #[test]
    fn settings_eq_ignores_view_state_and_unsaved_password() {
        let mut a = Config::default();
        a.profiles.push(Profile::default());
        let mut b = a.clone();
        b.selected = 1;
        b.show_log = !a.show_log;
        b.profiles[0].password = "typed".into(); // save_password is off
        assert!(a.settings_eq(&b));

        let mut saved = a.clone();
        saved.profiles[0].save_password = true;
        let mut typed = saved.clone();
        typed.profiles[0].password = "typed".into();
        assert!(!saved.settings_eq(&typed));

        let mut c = a.clone();
        c.profiles[1].gateway = "vpn.example.com".into();
        assert!(!a.settings_eq(&c));
    }

    #[test]
    fn dedupe_ids_gives_duplicates_and_empty_ids_a_fresh_id() {
        let mut c = Config::default();
        c.profiles.push(c.profiles[0].clone());
        c.profiles.push(Profile { id: String::new(), ..Profile::default() });
        let first = c.profiles[0].id.clone();
        c.dedupe_ids();
        assert_eq!(c.profiles[0].id, first, "first owner keeps its id");
        assert_ne!(c.profiles[1].id, first);
        assert_eq!(c.profiles[2].id.len(), 32);
        assert_ne!(c.profiles[1].id, c.profiles[2].id);
    }
}
