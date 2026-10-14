//! Settings, written when the user clicks Save (paths in `Paths`):
//! - config.toml: app settings; profiles/<name>.toml: one per connection, shareable by copying the file.
//!   Both only hold values that differ from the default.
//! - state.json in the XDG state dir: profile ids (the keyring key), selection, log panel. App-only.
//! The PSK and password are not in these files: they live in the Secret Service (see keyring.rs).

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const ENCRYPTIONS: [&str; 3] = ["AES128", "AES192", "AES256"];
pub const HASHES: [&str; 4] = ["SHA1", "SHA256", "SHA384", "SHA512"];
/// DH groups the backend implements (MODP2048, ECP256/384/521).
pub const DH_SUPPORTED: [u16; 4] = [14, 19, 20, 21];
/// Groups shown by the official client but not implemented here (rendered disabled).
pub const DH_UNSUPPORTED: [u16; 8] = [1, 2, 5, 15, 16, 17, 18, 31];

#[derive(Clone, Debug, PartialEq)]
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

/// In profile files a proposal is its `spec()`: "aes128-sha1".
impl Serialize for Proposal {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.spec())
    }
}

impl<'de> Deserialize<'de> for Proposal {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let (enc, hash) = s.split_once('-').unwrap_or((&s, ""));
        let (enc, hash) = (enc.to_uppercase(), hash.to_uppercase());
        if ENCRYPTIONS.contains(&enc.as_str()) && HASHES.contains(&hash.as_str()) {
            return Ok(Proposal::new(&enc, &hash));
        }
        let lower = |v: &[&str]| v.iter().map(|x| x.to_lowercase()).collect::<Vec<_>>().join(", ");
        Err(serde::de::Error::custom(format!(
            "invalid proposal \"{s}\", expected encryption-hash like \"aes128-sha1\" (encryption: {}; hash: {})",
            lower(&ENCRYPTIONS),
            lower(&HASHES)
        )))
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

/// A connection: profiles/<name>.toml holds everything except id, name and secrets, in the same sections.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Profile {
    /// stable key for this profile's keyring items (see keyring.rs); stored in state.json, not in the profile file
    #[serde(skip)]
    pub id: String,
    /// the profile file's name without `.toml`
    #[serde(skip)]
    pub name: String,
    pub description: String,
    pub gateway: String,
    /// stored in the Secret Service, never in the profile file (see keyring.rs)
    #[serde(skip)]
    pub psk: String,
    /// Single Sign On
    pub sso: Sso,
    /// user authentication when SSO is off
    pub auth: Auth,
    /// VPN settings, phase 1
    pub ike: Ike,
    /// phase 2
    pub esp: Esp,
    pub network: Network,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Sso {
    pub enabled: bool,
    pub port: u16,
    pub open_browser: bool,
    pub verify_cert: bool,
    pub timeout: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Auth {
    pub mode: UserAuth,
    pub username: String,
    /// stored in the Secret Service only if `save_password`, never in the profile file
    #[serde(skip)]
    pub password: String,
    pub save_password: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Ike {
    pub port: u16,
    pub proposals: Vec<Proposal>,
    pub dh_groups: Vec<u16>,
    pub local_id: String,
    pub natt_keepalive: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Esp {
    pub proposals: Vec<Proposal>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct Network {
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
            psk: String::new(),
            sso: Sso::default(),
            auth: Auth::default(),
            ike: Ike::default(),
            esp: Esp::default(),
            network: Network::default(),
        }
    }
}

impl Default for Sso {
    fn default() -> Self {
        Self { enabled: true, port: 443, open_browser: true, verify_cert: false, timeout: 300 }
    }
}

impl Default for Auth {
    fn default() -> Self {
        Self { mode: UserAuth::Eap, username: String::new(), password: String::new(), save_password: false }
    }
}

impl Default for Ike {
    fn default() -> Self {
        Self {
            port: 500,
            // FortiClient GUI defaults
            proposals: vec![Proposal::new("AES128", "SHA1"), Proposal::new("AES256", "SHA256")],
            dh_groups: vec![20],
            local_id: String::new(),
            natt_keepalive: 20,
        }
    }
}

impl Default for Esp {
    fn default() -> Self {
        Self { proposals: vec![Proposal::new("AES128", "SHA1"), Proposal::new("AES256", "SHA256")] }
    }
}

impl Default for Network {
    fn default() -> Self {
        Self { route_mode: RouteMode::Gateway, custom_routes: String::new(), block_ipv6: true, set_dns: true, ifname: "fsaml0".into(), mtu: 1400 }
    }
}

impl Profile {
    /// Copy under a new id, so it doesn't share keyring items with the original.
    pub fn duplicate(&self) -> Self {
        Self { id: new_uid(), name: format!("{} (copy)", self.name), ..self.clone() }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Config {
    pub profiles: Vec<Profile>,
    pub selected: usize,
    /// FortiClient installation UID presented to the FortiGate (SAML UID + EAP identity)
    pub uid: String,
    pub verbose: bool,
    pub log_file: String,
    pub show_log: bool,
    /// profile files that couldn't be parsed: name -> id; Save leaves them alone
    pub unreadable: BTreeMap<String, String>,
    /// keyring ids whose profile file is gone; Save deletes their keyring items
    pub orphans: Vec<String>,
    /// problems `load` found, shown at startup
    pub load_errors: Vec<String>,
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
            unreadable: BTreeMap::new(),
            orphans: Vec::new(),
            load_errors: Vec::new(),
        }
    }
}

/// config.toml
#[derive(Default, Serialize, Deserialize)]
#[serde(default)]
struct AppFile {
    uid: String,
    verbose: bool,
    log_file: String,
}

/// state.json
#[derive(Serialize, Deserialize)]
#[serde(default)]
struct StateFile {
    /// profile name -> id
    ids: BTreeMap<String, String>,
    orphans: Vec<String>,
    /// name of the selected profile
    selected: String,
    show_log: bool,
}

impl Default for StateFile {
    fn default() -> Self {
        Self { ids: BTreeMap::new(), orphans: Vec::new(), selected: String::new(), show_log: true }
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

/// Where the files live: the XDG dirs in the app, temp dirs in tests.
#[derive(Clone, Debug)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
}

/// An XDG base dir: `value` if it's an absolute path (the spec says to ignore anything else), else `$HOME/fallback`.
fn xdg_dir(value: Option<std::ffi::OsString>, home: Option<std::ffi::OsString>, fallback: &str) -> PathBuf {
    value.map(PathBuf::from).filter(|p| p.is_absolute()).unwrap_or_else(|| PathBuf::from(home.unwrap_or_default()).join(fallback))
}

impl Paths {
    pub fn from_env() -> Self {
        let xdg = |var: &str, fallback: &str| xdg_dir(std::env::var_os(var), std::env::var_os("HOME"), fallback);
        Self {
            config_dir: xdg("XDG_CONFIG_HOME", ".config").join("fortisaml-gui"),
            state_dir: xdg("XDG_STATE_HOME", ".local/state").join("fortisaml-gui"),
        }
    }
    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }
    pub fn profiles_dir(&self) -> PathBuf {
        self.config_dir.join("profiles")
    }
    pub fn profile_file(&self, name: &str) -> PathBuf {
        self.profiles_dir().join(format!("{name}.toml"))
    }
    pub fn state_file(&self) -> PathBuf {
        self.state_dir.join("state.json")
    }
}

pub fn config_path() -> PathBuf {
    Paths::from_env().config_file()
}

/// TOML of `v` without the keys whose value equals the default, at any depth, and without tables left empty.
fn sparse<T: Serialize + Default>(v: &T) -> String {
    fn prune(t: &mut toml::Table, d: &toml::Table) {
        t.retain(|k, v| match (v, d.get(k)) {
            (toml::Value::Table(t), Some(toml::Value::Table(d))) => {
                prune(t, d);
                !t.is_empty()
            }
            (v, d) => d != Some(v),
        });
    }
    let mut t = toml::Table::try_from(v).expect("settings serialize to a TOML table");
    prune(&mut t, &toml::Table::try_from(T::default()).expect("settings serialize to a TOML table"));
    toml::to_string(&t).expect("a TOML table serializes")
}

/// A profile file's settings; id and name are left for the caller.
fn parse_profile(s: &str) -> Result<Profile, String> {
    toml::from_str(s).map_err(|e| e.to_string())
}

/// Parse the file at `path`. Missing: None. Unreadable or invalid: None plus a message with `help`.
fn read<T>(path: &Path, parse: impl FnOnce(&str) -> Result<T, String>, help: &str, errors: &mut Vec<String>) -> Option<T> {
    let parsed = match std::fs::read_to_string(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return None,
        r => r.map_err(|e| e.to_string()).and_then(|s| parse(&s)),
    };
    parsed.map_err(|e| errors.push(crate::diag("error", &format!("{} couldn't be read", path.display()), e.trim_end(), help))).ok()
}

/// Atomic write with 0600 permissions, in a 0700 directory.
fn write_private(path: &Path, data: &[u8]) -> Result<(), String> {
    let run = || -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
        }
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        {
            let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&tmp)?;
            f.write_all(data)?;
            f.sync_all()?;
        }
        std::fs::rename(tmp, path)
    };
    run().map_err(|e| format!("{}: {e}", path.display()))
}

/// Why `name` can't be a profile file name, if it can't.
fn name_problem(name: &str) -> Option<&'static str> {
    if name.trim().is_empty() {
        Some("is empty")
    } else if name.contains(['/', '\0']) {
        Some("contains a / or NUL character")
    } else if name.starts_with('.') {
        Some("starts with a dot")
    } else if name.len() > 100 {
        Some("is longer than 100 bytes")
    } else {
        None
    }
}

impl Config {
    /// One message per profile whose name can't be saved as a file; Save refuses while there are any.
    pub fn name_errors(&self) -> Vec<String> {
        let mut seen = HashSet::new();
        self.profiles
            .iter()
            .filter_map(|p| {
                let why = name_problem(&p.name)
                    .or_else(|| (!seen.insert(p.name.as_str())).then_some("is used by another connection"))
                    .or_else(|| self.unreadable.contains_key(&p.name).then_some("belongs to a connection file that couldn't be read"));
                why.map(|why| {
                    crate::diag("error", &format!("connection \"{}\" can't be saved", p.name), &format!("its name {why}"), "choose another name and click Save")
                })
            })
            .collect()
    }

    /// `base`, or `base 2`, `base 3`, ...: the first name no profile (or unreadable file) uses.
    pub fn unique_name(&self, base: &str) -> String {
        let taken = |n: &str| self.profiles.iter().any(|p| p.name == n) || self.unreadable.contains_key(n);
        if !taken(base) {
            return base.into();
        }
        (2..).map(|i| format!("{base} {i}")).find(|n| !taken(n)).expect("a free name")
    }

    pub fn load() -> Self {
        Self::load_from(&Paths::from_env())
    }

    pub fn load_from(paths: &Paths) -> Self {
        let mut errors = Vec::new();
        let app: AppFile = read(
            &paths.config_file(),
            |s| toml::from_str(s).map_err(|e| e.to_string()),
            "fix the file, or click Save to replace it with the settings shown",
            &mut errors,
        )
        .unwrap_or_default();
        let state: StateFile = read(
            &paths.state_file(),
            |s| serde_json::from_str(s).map_err(|e| e.to_string()),
            "it's rewritten on the next Save; saved PSKs and passwords must be entered again",
            &mut errors,
        )
        .unwrap_or_default();

        // a dir that can't be listed (missing included) says nothing about which profiles are gone
        let listing = std::fs::read_dir(paths.profiles_dir());
        let listed = listing.is_ok();
        match &listing {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                let dir = paths.profiles_dir().display().to_string();
                errors.push(crate::diag("error", &format!("{dir} couldn't be read"), &e.to_string(), "fix its permissions and restart"));
            }
            _ => {}
        }
        let mut files: Vec<PathBuf> =
            listing.into_iter().flatten().flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "toml")).collect();
        files.sort();
        let mut profiles = Vec::new();
        let mut unreadable = BTreeMap::new();
        for path in files {
            let Some(name) = path.file_stem().and_then(|s| s.to_str()).map(str::to_owned) else { continue };
            let id = state.ids.get(&name).cloned().unwrap_or_else(new_uid);
            let help = "fix the file; until then Save leaves it alone";
            match read(&path, parse_profile, help, &mut errors) {
                Some(p) => profiles.push(Profile { id, name, ..p }),
                None => {
                    unreadable.insert(name, id);
                }
            }
        }
        profiles.sort_by(|a, b| a.name.cmp(&b.name));

        // ids whose file is gone (deleted or renamed by hand): Save removes their keyring items
        let in_use: HashSet<&String> = profiles.iter().map(|p| &p.id).chain(unreadable.values()).collect();
        let gone = state.ids.iter().filter(|_| listed).filter(|(n, _)| !profiles.iter().any(|p| &p.name == *n) && !unreadable.contains_key(*n)).map(|(_, id)| id);
        let mut orphans: Vec<String> = state.orphans.iter().chain(gone).filter(|id| !in_use.contains(id)).cloned().collect();
        orphans.sort();
        orphans.dedup();

        if profiles.is_empty() {
            profiles.push(Profile::default());
        }
        let selected = profiles.iter().position(|p| p.name == state.selected).unwrap_or(0);
        Config {
            profiles,
            selected,
            uid: if app.uid.len() == 32 { app.uid } else { new_uid() },
            verbose: app.verbose,
            log_file: app.log_file,
            show_log: state.show_log,
            unreadable,
            orphans,
            load_errors: errors,
        }
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

    /// Same settings, ignoring view state (`selected`, `show_log`), load bookkeeping and passwords that aren't saved.
    pub fn settings_eq(&self, other: &Config) -> bool {
        fn norm(c: &Config) -> Config {
            let mut c = c.clone();
            c.selected = 0;
            c.show_log = false;
            c.unreadable.clear();
            c.orphans.clear();
            c.load_errors.clear();
            for p in c.profiles.iter_mut().filter(|p| !p.auth.save_password) {
                p.auth.password.clear();
            }
            c
        }
        norm(self) == norm(other)
    }

    pub fn save(&self, saved: &Config) -> Result<(), String> {
        self.save_to(&Paths::from_env(), saved)
    }

    /// Write the profile files, state.json and config.toml, then delete the files of names in `saved` (the last saved
    /// state) that no profile uses any more (renamed or removed). A profile unchanged since `saved` whose file exists
    /// isn't rewritten, so hand edits to it are kept. In this order an interrupted Save leaves at worst an extra
    /// profile file, never state.json mapping an id to a name whose file is gone. Errors name the failing path.
    pub fn save_to(&self, paths: &Paths, saved: &Config) -> Result<(), String> {
        for p in &self.profiles {
            let path = paths.profile_file(&p.name);
            if !(saved.profiles.contains(p) && path.exists()) {
                write_private(&path, sparse(p).as_bytes())?;
            }
        }
        let state = StateFile {
            ids: self.profiles.iter().map(|p| (p.name.clone(), p.id.clone())).chain(self.unreadable.clone()).collect(),
            orphans: self.orphans.clone(),
            selected: self.profiles.get(self.selected).map(|p| p.name.clone()).unwrap_or_default(),
            show_log: self.show_log,
        };
        write_private(&paths.state_file(), serde_json::to_string_pretty(&state).expect("state serializes").as_bytes())?;
        let app = AppFile { uid: self.uid.clone(), verbose: self.verbose, log_file: self.log_file.clone() };
        write_private(&paths.config_file(), sparse(&app).as_bytes())?;
        for o in saved.profiles.iter().filter(|o| !self.profiles.iter().any(|p| p.name == o.name)) {
            let path = paths.profile_file(&o.name);
            match std::fs::remove_file(&path) {
                Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(format!("{}: {e}", path.display())),
                _ => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Temp config + state dirs, removed on drop.
    struct Tmp {
        dir: PathBuf,
        paths: Paths,
    }

    impl Tmp {
        fn new() -> Self {
            static N: AtomicUsize = AtomicUsize::new(0);
            let dir = std::env::temp_dir().join(format!("fortisaml-gui-cfg-{}-{}", std::process::id(), N.fetch_add(1, Ordering::SeqCst)));
            let _ = std::fs::remove_dir_all(&dir);
            Self { paths: Paths { config_dir: dir.join("config"), state_dir: dir.join("state") }, dir }
        }

        fn files(&self) -> Vec<String> {
            let mut v: Vec<String> =
                std::fs::read_dir(self.paths.profiles_dir()).unwrap().map(|e| e.unwrap().file_name().into_string().unwrap()).collect();
            v.sort();
            v
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn profile(name: &str) -> Profile {
        Profile { name: name.into(), ..Profile::default() }
    }

    #[test]
    fn defaults_write_empty_files() {
        assert_eq!(sparse(&Profile::default()), "");
        assert_eq!(sparse(&AppFile::default()), "");
    }

    #[test]
    fn changed_profile_fields_round_trip() {
        let mut p = profile("Office");
        p.gateway = "vpn.example.com".into();
        p.sso.port = 10443;
        p.auth.mode = UserAuth::None;
        p.ike.proposals = vec![Proposal::new("AES256", "SHA512")];
        p.ike.dh_groups = vec![20, 21];
        p.esp.proposals = vec![Proposal::new("AES192", "SHA384"), Proposal::new("AES128", "SHA1")];
        p.network.route_mode = RouteMode::Custom;
        p.network.mtu = 1300;
        let s = sparse(&p);
        assert!(s.contains("gateway = \"vpn.example.com\"") && s.contains("proposals = [\"aes256-sha512\"]"), "{s}");
        assert!(s.contains("[network]\nroute_mode = \"Custom\"\nmtu = 1300\n"), "keys in Profile order: {s}");
        assert!(!s.contains("port = 500") && !s.contains("ifname"), "defaults are left out: {s}");
        let back = parse_profile(&s).unwrap();
        assert_eq!(Profile { id: p.id.clone(), name: p.name.clone(), ..back }, p);
    }

    #[test]
    fn only_changed_keys_and_their_sections_are_written() {
        let mut p = profile("Office");
        p.sso.port = 10443;
        assert_eq!(sparse(&p), "[sso]\nport = 10443\n");
        p.gateway = "vpn.example.com".into();
        assert_eq!(sparse(&p), "gateway = \"vpn.example.com\"\n\n[sso]\nport = 10443\n");
        p.auth.username = "jane".into();
        p.description = "Office".into();
        assert_eq!(sparse(&p), "description = \"Office\"\ngateway = \"vpn.example.com\"\n\n[sso]\nport = 10443\n\n[auth]\nusername = \"jane\"\n", "struct order");
    }

    #[test]
    fn documented_example_parses() {
        let s = "description = \"Office\"\ngateway = \"vpn.example.com\"\n\n[sso]\nport = 10443\nverify_cert = false\n\n\
                 [auth]\nmode = \"Eap\"\nusername = \"jane\"\n\n[ike]\nproposals = [\"aes128-sha1\", \"aes256-sha256\"]\ndh_groups = [20]\n\n\
                 [network]\nroute_mode = \"Custom\"\ncustom_routes = \"10.0.0.0/8\"\nmtu = 1400\n";
        let p = parse_profile(s).unwrap();
        let want = Profile {
            description: "Office".into(),
            gateway: "vpn.example.com".into(),
            sso: Sso { port: 10443, ..Sso::default() },
            auth: Auth { username: "jane".into(), ..Auth::default() },
            network: Network { route_mode: RouteMode::Custom, custom_routes: "10.0.0.0/8".into(), ..Network::default() },
            ..Profile::default()
        };
        assert_eq!(Profile { id: want.id.clone(), name: want.name.clone(), ..p }, want);
    }

    #[test]
    fn bad_proposal_is_a_parse_error_naming_it() {
        let err = parse_profile("[esp]\nproposals = [\"aes128-sha1\", \"aes128sha1\"]\n").unwrap_err();
        assert!(err.contains("\"aes128sha1\""), "{err}");
        assert!(parse_profile("[ike]\nproposals = [\"-sha1\"]\n").is_err());
        let err = parse_profile("[ike]\nproposals = [\"foo-bar\"]\n").unwrap_err();
        assert!(err.contains("\"foo-bar\"") && err.contains("aes128, aes192, aes256") && err.contains("sha1, sha256, sha384, sha512"), "{err}");
        assert_eq!(parse_profile("[esp]\nproposals = [\"AES256-Sha384\"]\n").unwrap().esp.proposals, [Proposal::new("AES256", "SHA384")]);
    }

    #[test]
    fn profile_file_has_no_secrets_id_or_name() {
        let mut p = profile("Office");
        p.psk = "topsecret".into();
        p.auth.password = "hunter2".into();
        p.auth.save_password = true;
        assert_eq!(sparse(&p), "[auth]\nsave_password = true\n");
    }

    #[test]
    fn unknown_keys_are_ignored() {
        let p = parse_profile("gateway = \"g\"\nfuture_option = 1\n[sso]\nport = 8443\nfuture_option = 2\n[future_section]\nx = 1\n").unwrap();
        assert_eq!((p.gateway.as_str(), p.sso.port), ("g", 8443));
    }

    #[test]
    fn empty_dirs_load_one_default_profile() {
        let t = Tmp::new();
        let c = Config::load_from(&t.paths);
        assert_eq!(c.profiles.len(), 1);
        assert_eq!(c.uid.len(), 32);
        assert!(c.load_errors.is_empty() && c.orphans.is_empty() && c.unreadable.is_empty());
    }

    #[test]
    fn save_then_load_keeps_settings_ids_and_selection() {
        let t = Tmp::new();
        let mut c = Config::default();
        c.profiles = vec![profile("B"), profile("A")];
        c.profiles[0].gateway = "b.example".into();
        c.selected = 0; // "B"
        c.show_log = false;
        c.verbose = true;
        c.save_to(&t.paths, &Config::default()).unwrap();
        let l = Config::load_from(&t.paths);
        assert_eq!(l.profiles.iter().map(|p| p.name.as_str()).collect::<Vec<_>>(), ["A", "B"], "sorted by name");
        assert_eq!(l.selected, 1, "selection follows the name");
        assert_eq!(l.profiles[1], c.profiles[0]);
        assert_eq!(l.profiles[0], c.profiles[1]);
        assert_eq!((l.uid.as_str(), l.verbose, l.show_log), (c.uid.as_str(), true, false));
    }

    #[test]
    fn files_are_private() {
        let t = Tmp::new();
        let c = Config::default();
        c.save_to(&t.paths, &c).unwrap();
        for f in [t.paths.config_file(), t.paths.profile_file("New connection"), t.paths.state_file()] {
            assert_eq!(std::fs::metadata(&f).unwrap().permissions().mode() & 0o777, 0o600, "{}", f.display());
        }
        assert_eq!(std::fs::metadata(t.paths.profiles_dir()).unwrap().permissions().mode() & 0o777, 0o700);
    }

    #[test]
    fn rename_and_remove_delete_old_files_but_a_swap_deletes_nothing() {
        let t = Tmp::new();
        let mut saved = Config::default();
        saved.profiles = vec![profile("A"), profile("B"), profile("C")];
        saved.save_to(&t.paths, &saved).unwrap();
        let mut c = saved.clone();
        c.profiles[0].name = "B".into();
        c.profiles[1].name = "A".into(); // swap A and B
        c.profiles[2].name = "D".into(); // rename C
        c.save_to(&t.paths, &saved).unwrap();
        assert_eq!(t.files(), ["A.toml", "B.toml", "D.toml"]);
        let mut gone = c.clone();
        gone.profiles.remove(0);
        gone.save_to(&t.paths, &c).unwrap();
        assert_eq!(t.files(), ["A.toml", "D.toml"]);
        let l = Config::load_from(&t.paths);
        assert_eq!(l.profiles.iter().find(|p| p.name == "A").unwrap().id, saved.profiles[1].id, "id follows the profile, not the name");
    }

    #[test]
    fn unreadable_profile_file_is_reported_and_kept() {
        let t = Tmp::new();
        let c = Config::default();
        c.save_to(&t.paths, &c).unwrap();
        std::fs::write(t.paths.profile_file("Broken"), "gateway = [").unwrap();
        let l = Config::load_from(&t.paths);
        assert_eq!(l.profiles.len(), 1);
        assert!(l.unreadable.contains_key("Broken"));
        assert_eq!(l.load_errors.len(), 1);
        assert!(l.load_errors[0].contains("Broken.toml couldn't be read"), "{}", l.load_errors[0]);
        l.save_to(&t.paths, &l).unwrap();
        assert_eq!(std::fs::read_to_string(t.paths.profile_file("Broken")).unwrap(), "gateway = [");
        assert_eq!(Config::load_from(&t.paths).unreadable["Broken"], l.unreadable["Broken"], "its id is kept");
    }

    #[test]
    fn bad_config_toml_gives_defaults_and_a_message() {
        let t = Tmp::new();
        std::fs::create_dir_all(&t.paths.config_dir).unwrap();
        std::fs::write(t.paths.config_file(), "uid = ").unwrap();
        let l = Config::load_from(&t.paths);
        assert_eq!(l.uid.len(), 32);
        assert_eq!(l.load_errors.len(), 1);
        assert!(l.load_errors[0].contains("config.toml couldn't be read"), "{}", l.load_errors[0]);
    }

    #[test]
    fn vanished_and_renamed_files_leave_orphan_ids() {
        let t = Tmp::new();
        let mut c = Config::default();
        c.profiles = vec![profile("A"), profile("B"), profile("C")];
        c.save_to(&t.paths, &c).unwrap();
        std::fs::remove_file(t.paths.profile_file("A")).unwrap();
        std::fs::rename(t.paths.profile_file("B"), t.paths.profile_file("B2")).unwrap();
        let l = Config::load_from(&t.paths);
        let mut want = vec![c.profiles[0].id.clone(), c.profiles[1].id.clone()];
        want.sort();
        assert_eq!(l.orphans, want);
        let b2 = l.profiles.iter().find(|p| p.name == "B2").unwrap();
        assert_ne!(b2.id, c.profiles[1].id, "a hand-renamed file gets a fresh id");
        l.save_to(&t.paths, &l).unwrap();
        assert_eq!(Config::load_from(&t.paths).orphans, want, "orphans persist until the keyring is cleaned");
    }

    #[test]
    fn missing_profiles_dir_leaves_no_orphans_from_state_ids() {
        let t = Tmp::new();
        let (id, orphan) = (new_uid(), new_uid());
        std::fs::create_dir_all(&t.paths.state_dir).unwrap();
        std::fs::write(t.paths.state_file(), format!(r#"{{"ids":{{"Office":"{id}"}},"orphans":["{orphan}"]}}"#)).unwrap();
        let l = Config::load_from(&t.paths);
        assert_eq!(l.orphans, [orphan.clone()], "only the recorded orphans");
        assert!(l.load_errors.is_empty(), "{:?}", l.load_errors);
        std::fs::create_dir_all(&t.paths.config_dir).unwrap();
        std::fs::write(t.paths.profiles_dir(), "").unwrap(); // a file: listing fails with something other than NotFound
        let l = Config::load_from(&t.paths);
        assert_eq!(l.orphans, [orphan]);
        assert_eq!(l.load_errors.len(), 1);
        assert!(l.load_errors[0].contains("profiles couldn't be read"), "{}", l.load_errors[0]);
    }

    #[test]
    fn failed_save_during_rename_keeps_the_old_file() {
        let t = Tmp::new();
        let saved = Config { profiles: vec![profile("A")], ..Config::default() };
        saved.save_to(&t.paths, &saved).unwrap();
        let mut c = saved.clone();
        c.profiles[0].name = "B".into();
        let mut tmp = t.paths.state_file().into_os_string();
        tmp.push(".tmp");
        std::fs::create_dir(tmp).unwrap(); // blocks the state.json write
        let err = c.save_to(&t.paths, &saved).unwrap_err();
        assert!(err.contains("state.json"), "{err}");
        assert!(t.paths.profile_file("A").exists(), "the old file stays until state.json maps the id to the new name");
    }

    #[test]
    fn save_leaves_unchanged_profile_files_alone() {
        let t = Tmp::new();
        let saved = Config { profiles: vec![profile("A"), profile("B")], ..Config::default() };
        saved.save_to(&t.paths, &saved).unwrap();
        std::fs::write(t.paths.profile_file("A"), "# hand-written\n").unwrap();
        let mut c = saved.clone();
        c.profiles[1].gateway = "b.example".into();
        c.save_to(&t.paths, &saved).unwrap();
        assert_eq!(std::fs::read_to_string(t.paths.profile_file("A")).unwrap(), "# hand-written\n");
        assert_eq!(std::fs::read_to_string(t.paths.profile_file("B")).unwrap(), "gateway = \"b.example\"\n");
    }

    #[test]
    fn xdg_dir_ignores_empty_and_relative_values() {
        let home = Some(std::ffi::OsString::from("/home/u"));
        let dir = |v: Option<&str>| xdg_dir(v.map(Into::into), home.clone(), ".config");
        assert_eq!(dir(Some("/x")), PathBuf::from("/x"));
        assert_eq!(dir(None), PathBuf::from("/home/u/.config"));
        assert_eq!(dir(Some("")), PathBuf::from("/home/u/.config"));
        assert_eq!(dir(Some("rel")), PathBuf::from("/home/u/.config"));
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
        b.orphans = vec![new_uid()];
        b.profiles[0].auth.password = "typed".into(); // save_password is off
        assert!(a.settings_eq(&b));

        let mut saved = a.clone();
        saved.profiles[0].auth.save_password = true;
        let mut typed = saved.clone();
        typed.profiles[0].auth.password = "typed".into();
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

    #[test]
    fn name_errors_reject_unusable_names() {
        let long = "x".repeat(101);
        let mut c = Config::default();
        c.profiles = ["", "  ", "a/b", ".hidden", long.as_str(), "Office", "Office", "Broken", "fine"].map(profile).to_vec();
        c.unreadable.insert("Broken".into(), new_uid());
        let errors = c.name_errors();
        assert_eq!(errors.len(), 7, "{errors:#?}");
        assert_eq!(errors[2], "error: connection \"a/b\" can't be saved\n  note: its name contains a / or NUL character\n  help: choose another name and click Save");
        assert!(errors[5].contains("its name is used by another connection"));
        assert!(errors[6].contains("its name belongs to a connection file that couldn't be read"));
    }

    #[test]
    fn unique_name_appends_the_first_free_number() {
        let mut c = Config::default(); // "New connection"
        c.unreadable.insert("Broken".into(), new_uid());
        assert_eq!(c.unique_name("Office"), "Office");
        assert_eq!(c.unique_name("New connection"), "New connection 2");
        assert_eq!(c.unique_name("Broken"), "Broken 2");
        c.profiles.push(profile("New connection 2"));
        assert_eq!(c.unique_name("New connection"), "New connection 3");
    }
}
