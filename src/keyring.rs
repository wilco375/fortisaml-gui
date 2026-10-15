//! PSK and password storage in the desktop keyring (freedesktop Secret Service).
//! The settings files never hold secrets; without a Secret Service they only live in memory.

use crate::config::{Config, Profile};
use crate::diag;
use secret_service::blocking::{Collection, SecretService};
use secret_service::{EncryptionType, Error};
use std::collections::HashMap;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Kind {
    Psk,
    Password,
}

impl Kind {
    /// value of the `kind` item attribute
    fn attr(self) -> &'static str {
        match self {
            Kind::Psk => "psk",
            Kind::Password => "password",
        }
    }
    fn name(self) -> &'static str {
        match self {
            Kind::Psk => "PSK",
            Kind::Password => "password",
        }
    }
}

pub trait SecretStore {
    fn get(&self, profile_id: &str, kind: Kind) -> Result<Option<String>, String>;
    /// An empty `secret` deletes the item.
    fn set(&self, profile_id: &str, kind: Kind, label: &str, secret: &str) -> Result<(), String>;
    fn delete_profile(&self, profile_id: &str) -> Result<(), String>;
}

/// Item label shown in Seahorse / KWallet / KeePassXC.
pub fn item_label(profile_name: &str, kind: Kind) -> String {
    format!("FortiSAML VPN: {profile_name} ({})", kind.name())
}

#[derive(PartialEq)]
pub enum Op {
    Set { profile_id: String, kind: Kind, label: String, secret: String },
    DeleteProfile { profile_id: String },
}

/// Hand-written so the secret never ends up in a log or panic message.
impl std::fmt::Debug for Op {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Op::Set { profile_id, kind, label, secret } => f
                .debug_struct("Set")
                .field("profile_id", profile_id)
                .field("kind", kind)
                .field("label", label)
                .field("secret", &if secret.is_empty() { "" } else { "<redacted>" })
                .finish(),
            Op::DeleteProfile { profile_id } => f.debug_struct("DeleteProfile").field("profile_id", profile_id).finish(),
        }
    }
}

/// The secret as it belongs in the keyring: the password only when `save_password`.
fn stored(p: &Profile, kind: Kind) -> &str {
    match kind {
        Kind::Psk => &p.psk,
        Kind::Password if p.auth.save_password => &p.auth.password,
        Kind::Password => "",
    }
}

fn field_ref(p: &Profile, kind: Kind) -> &String {
    match kind {
        Kind::Psk => &p.psk,
        Kind::Password => &p.auth.password,
    }
}

fn field(p: &mut Profile, kind: Kind) -> &mut String {
    match kind {
        Kind::Psk => &mut p.psk,
        Kind::Password => &mut p.auth.password,
    }
}

/// Keyring operations that bring the store from `saved` to `cfg`; profiles are matched by id, `cfg.orphans` are deleted.
pub fn plan(saved: &Config, cfg: &Config) -> Vec<Op> {
    let mut ops = Vec::new();
    for p in &cfg.profiles {
        let old = saved.profiles.iter().find(|o| o.id == p.id);
        for kind in [Kind::Psk, Kind::Password] {
            let new = stored(p, kind);
            let changed = match old {
                // a rename re-sets existing secrets so the label follows
                Some(o) => stored(o, kind) != new || (o.name != p.name && !new.is_empty()),
                None => !new.is_empty(),
            };
            if changed {
                ops.push(Op::Set { profile_id: p.id.clone(), kind, label: item_label(p.name.as_str(), kind), secret: new.into() });
            }
        }
    }
    for o in saved.profiles.iter().filter(|o| !cfg.profiles.iter().any(|p| p.id == o.id)) {
        ops.push(Op::DeleteProfile { profile_id: o.id.clone() });
    }
    // profiles whose file vanished outside the app
    for id in &cfg.orphans {
        ops.push(Op::DeleteProfile { profile_id: id.clone() });
    }
    ops
}

/// Run `ops`. Returns the new saved state - `cfg`, except that a secret whose keyring write failed keeps its
/// saved value (and its profile the saved name), so it still counts as unsaved and the next Save retries it,
/// an orphan whose delete failed stays in `orphans`,
/// and one message per failure.
pub fn apply(store: &dyn SecretStore, ops: &[Op], saved: &Config, cfg: &Config) -> (Config, Vec<String>) {
    let mut next = Config { orphans: Vec::new(), ..cfg.clone() };
    let mut errors = Vec::new();
    for op in ops {
        match op {
            Op::Set { profile_id, kind, label, secret } => {
                if let Err(e) = store.set(profile_id, *kind, label, secret) {
                    errors.push(diag(
                        "error",
                        &format!("the {} couldn't be saved to the keyring", kind.name()),
                        &e,
                        "your other settings were saved; click Save to try again",
                    ));
                    match saved.profiles.iter().find(|o| &o.id == profile_id) {
                        Some(o) => {
                            if let Some(n) = next.profiles.iter_mut().find(|n| &n.id == profile_id) {
                                n.name = o.name.clone(); // a failed relabel is retried too
                                *field(n, *kind) = field_ref(o, *kind).clone();
                                if *kind == Kind::Password {
                                    n.auth.save_password = o.auth.save_password;
                                }
                            }
                        }
                        None => next.profiles.retain(|n| &n.id != profile_id),
                    }
                }
            }
            Op::DeleteProfile { profile_id } => {
                if let Err(e) = store.delete_profile(profile_id) {
                    errors.push(diag(
                        "error",
                        "a deleted connection's secrets couldn't be removed from the keyring",
                        &e,
                        "your other settings were saved; click Save to try again",
                    ));
                    match saved.profiles.iter().find(|o| &o.id == profile_id) {
                        Some(o) => next.profiles.push(o.clone()),
                        None => next.orphans.push(profile_id.clone()),
                    }
                }
            }
        }
    }
    (next, errors)
}

/// Fill every profile's PSK, and its password if `save_password`, from the store. One message per failed read.
pub fn fill(store: &dyn SecretStore, cfg: &mut Config) -> Vec<String> {
    cfg.profiles.iter_mut().flat_map(|p| fill_profile(store, p)).collect()
}

/// `fill` for a single profile.
pub fn fill_profile(store: &dyn SecretStore, p: &mut Profile) -> Vec<String> {
    let mut errors = Vec::new();
    let kinds: &[Kind] = if p.auth.save_password { &[Kind::Psk, Kind::Password] } else { &[Kind::Psk] };
    for &kind in kinds {
        match store.get(&p.id, kind) {
            Ok(Some(s)) => *field(p, kind) = s,
            Ok(None) => {}
            Err(e) => errors.push(diag(
                "error",
                &format!("the {} of \"{}\" couldn't be read from the keyring", kind.name(), p.name),
                &e,
                "enter it again and click Save",
            )),
        }
    }
    errors
}

/// Why secrets can't be stored this session.
pub enum Unavailable {
    NoService(String),
    /// the service runs but has no default collection (e.g. no login keyring)
    NoDefault,
    /// the default collection is locked and the unlock prompt was dismissed
    Locked,
}

impl Unavailable {
    pub fn message(&self) -> String {
        let headline = "the PSK and password can't be saved";
        match self {
            Unavailable::NoService(e) => diag(
                "warning",
                headline,
                &format!("no keyring service found: {e} (is GNOME Keyring, KWallet or KeePassXC running?)"),
                "they're kept in memory until you close the app",
            ),
            Unavailable::NoDefault => diag(
                "warning",
                headline,
                "the keyring service has no default keyring",
                "create one (e.g. in Seahorse or KeePassXC) and restart; until then they're kept in memory",
            ),
            Unavailable::Locked => diag(
                "warning",
                headline,
                "the keyring is locked, the unlock prompt was cancelled",
                "they're kept in memory until you close the app; restart to try again",
            ),
        }
    }
}

/// The session's Secret Service (GNOME Keyring, KWallet, KeePassXC), default collection.
pub struct SecretServiceStore {
    ss: SecretService<'static>,
}

fn attrs(profile_id: &str, kind: Option<Kind>) -> HashMap<&str, &str> {
    let mut a = HashMap::from([("application", "fortisaml-gui"), ("profile", profile_id)]);
    if let Some(k) = kind {
        a.insert("kind", k.attr());
    }
    a
}

impl SecretServiceStore {
    /// Connect and unlock the default collection; this may show the system unlock prompt.
    pub fn connect() -> Result<Self, Unavailable> {
        let ss = SecretService::connect(EncryptionType::Dh).map_err(|e| Unavailable::NoService(e.to_string()))?;
        let store = Self { ss };
        store.collection().map_err(|e| match e {
            Error::Prompt | Error::PromptDisconnected | Error::Locked => Unavailable::Locked,
            Error::NoResult => Unavailable::NoDefault,
            e => Unavailable::NoService(e.to_string()),
        })?;
        Ok(store)
    }

    /// The default collection, unlocked (prompts if it was locked again since connect).
    fn collection(&self) -> Result<Collection<'_>, Error> {
        let c = self.ss.get_default_collection()?;
        if c.is_locked()? {
            c.unlock()?;
        }
        Ok(c)
    }
}

impl SecretStore for SecretServiceStore {
    fn get(&self, profile_id: &str, kind: Kind) -> Result<Option<String>, String> {
        let run = || -> Result<Option<String>, Error> {
            let c = self.collection()?;
            let Some(item) = c.search_items(attrs(profile_id, Some(kind)))?.into_iter().next() else {
                return Ok(None);
            };
            Ok(Some(String::from_utf8_lossy(&item.get_secret()?).into_owned()))
        };
        run().map_err(|e| e.to_string())
    }

    fn set(&self, profile_id: &str, kind: Kind, label: &str, secret: &str) -> Result<(), String> {
        let run = || -> Result<(), Error> {
            let c = self.collection()?;
            if secret.is_empty() {
                for item in c.search_items(attrs(profile_id, Some(kind)))? {
                    item.delete()?;
                }
            } else {
                let items = c.search_items(attrs(profile_id, Some(kind)))?;
                match items.split_first() {
                    // update in place: KWallet keeps the old label when create_item replaces an item
                    Some((item, extra)) => {
                        item.set_label(label)?;
                        item.set_secret(secret.as_bytes(), "text/plain")?;
                        for e in extra {
                            e.delete()?;
                        }
                    }
                    None => {
                        c.create_item(label, attrs(profile_id, Some(kind)), secret.as_bytes(), false, "text/plain")?;
                    }
                }
            }
            Ok(())
        };
        run().map_err(|e| e.to_string())
    }

    fn delete_profile(&self, profile_id: &str) -> Result<(), String> {
        let run = || -> Result<(), Error> {
            let c = self.collection()?;
            for item in c.search_items(attrs(profile_id, None))? {
                item.delete()?;
            }
            Ok(())
        };
        run().map_err(|e| e.to_string())
    }
}

/// In-memory keyring for tests.
#[cfg(test)]
pub mod testing {
    use super::{Kind, SecretStore};
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::rc::Rc;

    /// (profile id, kind attribute) -> (label, secret)
    type Items = HashMap<(String, &'static str), (String, String)>;

    /// Items shared between clones; `fail` makes every write of that kind fail.
    #[derive(Clone, Default)]
    pub struct MemoryStore {
        pub items: Rc<RefCell<Items>>,
        pub fail: Option<Kind>,
        pub fail_delete: bool,
    }

    impl SecretStore for MemoryStore {
        fn get(&self, profile_id: &str, kind: Kind) -> Result<Option<String>, String> {
            Ok(self.items.borrow().get(&(profile_id.to_string(), kind.attr())).map(|(_, s)| s.clone()))
        }
        fn set(&self, profile_id: &str, kind: Kind, label: &str, secret: &str) -> Result<(), String> {
            if self.fail == Some(kind) {
                return Err("simulated failure".into());
            }
            let key = (profile_id.to_string(), kind.attr());
            if secret.is_empty() {
                self.items.borrow_mut().remove(&key);
            } else {
                self.items.borrow_mut().insert(key, (label.to_string(), secret.to_string()));
            }
            Ok(())
        }
        fn delete_profile(&self, profile_id: &str) -> Result<(), String> {
            if self.fail_delete {
                return Err("simulated failure".into());
            }
            self.items.borrow_mut().retain(|(id, _), _| id != profile_id);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::MemoryStore;
    use super::*;

    fn cfg_with(name: &str) -> Config {
        let mut c = Config::default();
        c.profiles[0].name = name.into();
        c
    }

    fn set_op(p: &Profile, kind: Kind, secret: &str) -> Op {
        Op::Set { profile_id: p.id.clone(), kind, label: item_label(p.name.as_str(), kind), secret: secret.into() }
    }

    #[test]
    fn no_changes_no_ops() {
        let c = cfg_with("Office");
        assert_eq!(plan(&c, &c.clone()), vec![]);
    }

    #[test]
    fn psk_changed_and_cleared() {
        let saved = cfg_with("Office");
        let mut cfg = saved.clone();
        cfg.profiles[0].psk = "k1".into();
        assert_eq!(plan(&saved, &cfg), vec![set_op(&cfg.profiles[0], Kind::Psk, "k1")]);
        let mut cleared = cfg.clone();
        cleared.profiles[0].psk.clear();
        assert_eq!(plan(&cfg, &cleared), vec![set_op(&cfg.profiles[0], Kind::Psk, "")]);
    }

    #[test]
    fn password_only_stored_when_saved() {
        let saved = cfg_with("Office");
        let mut cfg = saved.clone();
        cfg.profiles[0].auth.password = "pw".into();
        assert_eq!(plan(&saved, &cfg), vec![], "save_password off: nothing to store");
        cfg.profiles[0].auth.save_password = true;
        assert_eq!(plan(&saved, &cfg), vec![set_op(&cfg.profiles[0], Kind::Password, "pw")]);
    }

    #[test]
    fn untick_save_password_deletes() {
        let mut saved = cfg_with("Office");
        saved.profiles[0].auth.password = "pw".into();
        saved.profiles[0].auth.save_password = true;
        let mut cfg = saved.clone();
        cfg.profiles[0].auth.save_password = false;
        assert_eq!(plan(&saved, &cfg), vec![set_op(&cfg.profiles[0], Kind::Password, "")]);
    }

    #[test]
    fn rename_relabels_existing_secrets() {
        let mut saved = cfg_with("Office");
        saved.profiles[0].psk = "k".into();
        let mut cfg = saved.clone();
        cfg.profiles[0].name = "Home".into();
        assert_eq!(plan(&saved, &cfg), vec![set_op(&cfg.profiles[0], Kind::Psk, "k")]);
    }

    #[test]
    fn rename_without_secrets_is_noop() {
        let saved = cfg_with("Office");
        let mut cfg = saved.clone();
        cfg.profiles[0].name = "Home".into();
        assert_eq!(plan(&saved, &cfg), vec![]);
    }

    #[test]
    fn deleted_profile_and_copy() {
        let mut saved = cfg_with("Office");
        saved.profiles[0].psk = "k".into();
        let mut cfg = saved.clone();
        let copy = cfg.profiles[0].duplicate();
        cfg.profiles.push(copy.clone());
        assert_eq!(plan(&saved, &cfg), vec![set_op(&copy, Kind::Psk, "k")], "copy stores under its own id");
        let mut removed = cfg.clone();
        removed.profiles.remove(0);
        assert_eq!(plan(&cfg, &removed), vec![Op::DeleteProfile { profile_id: cfg.profiles[0].id.clone() }]);
    }

    #[test]
    fn fill_reads_psk_and_saved_password_only() {
        let store = MemoryStore::default();
        let mut cfg = cfg_with("Office");
        cfg.profiles.push(Profile::default());
        cfg.profiles[1].auth.save_password = true;
        for p in &cfg.profiles {
            store.set(&p.id, Kind::Psk, "l", "k").unwrap();
            store.set(&p.id, Kind::Password, "l", "pw").unwrap();
        }
        assert!(fill(&store, &mut cfg).is_empty());
        assert_eq!((cfg.profiles[0].psk.as_str(), cfg.profiles[0].auth.password.as_str()), ("k", ""));
        assert_eq!((cfg.profiles[1].psk.as_str(), cfg.profiles[1].auth.password.as_str()), ("k", "pw"));
    }

    #[test]
    fn apply_writes_and_returns_cfg() {
        let store = MemoryStore::default();
        let saved = cfg_with("Office");
        let mut cfg = saved.clone();
        cfg.profiles[0].psk = "k".into();
        let (next, errors) = apply(&store, &plan(&saved, &cfg), &saved, &cfg);
        assert!(errors.is_empty());
        assert!(next.settings_eq(&cfg));
        assert_eq!(store.get(&cfg.profiles[0].id, Kind::Psk).unwrap().as_deref(), Some("k"));
        let (label, _) = store.items.borrow()[&(cfg.profiles[0].id.clone(), "psk")].clone();
        assert_eq!(label, "FortiSAML VPN: Office (PSK)");
    }

    #[test]
    fn failed_set_keeps_profile_unsaved() {
        let store = MemoryStore { fail: Some(Kind::Psk), ..Default::default() };
        let saved = cfg_with("Office");
        let mut cfg = saved.clone();
        cfg.profiles[0].psk = "k".into();
        let (next, errors) = apply(&store, &plan(&saved, &cfg), &saved, &cfg);
        assert_eq!(errors, vec![
            "error: the PSK couldn't be saved to the keyring\n  note: simulated failure\n  help: your other settings were saved; click Save to try again"
        ]);
        assert!(!next.settings_eq(&cfg), "still unsaved");
        assert_eq!(plan(&next, &cfg), vec![set_op(&cfg.profiles[0], Kind::Psk, "k")], "retried on next Save");
    }

    #[test]
    fn failed_delete_keeps_profile_pending() {
        let store = MemoryStore { fail_delete: true, ..Default::default() };
        let mut saved = cfg_with("Office");
        saved.profiles.push(Profile::default());
        let mut cfg = saved.clone();
        let gone = cfg.profiles.remove(1);
        let (next, errors) = apply(&store, &plan(&saved, &cfg), &saved, &cfg);
        assert_eq!(errors.len(), 1);
        assert_eq!(plan(&next, &cfg), vec![Op::DeleteProfile { profile_id: gone.id }], "retried on next Save");
    }

    #[test]
    fn orphans_are_deleted_and_failures_retried() {
        let saved = cfg_with("Office");
        let mut cfg = saved.clone();
        cfg.orphans = vec!["B".repeat(32)];
        assert_eq!(plan(&saved, &cfg), vec![Op::DeleteProfile { profile_id: "B".repeat(32) }]);

        let store = MemoryStore::default();
        store.set(&"B".repeat(32), Kind::Psk, "l", "k").unwrap();
        let (next, errors) = apply(&store, &plan(&saved, &cfg), &saved, &cfg);
        assert!(errors.is_empty() && next.orphans.is_empty());
        assert_eq!(store.get(&"B".repeat(32), Kind::Psk).unwrap(), None);

        let failing = MemoryStore { fail_delete: true, ..Default::default() };
        let (next, errors) = apply(&failing, &plan(&saved, &cfg), &saved, &cfg);
        assert_eq!(errors.len(), 1);
        assert_eq!(next.orphans, cfg.orphans, "retried on next Save");
        assert_eq!(next.profiles, cfg.profiles, "an orphan never comes back as a profile");
    }

    #[test]
    fn unavailable_messages() {
        assert_eq!(
            Unavailable::Locked.message(),
            "warning: the PSK and password can't be saved\n  \
             note: the keyring is locked, the unlock prompt was cancelled\n  \
             help: they're kept in memory until you close the app; restart to try again"
        );
        assert_eq!(
            Unavailable::NoService("no secret service provider or dbus session found".into()).message(),
            "warning: the PSK and password can't be saved\n  \
             note: no keyring service found: no secret service provider or dbus session found \
             (is GNOME Keyring, KWallet or KeePassXC running?)\n  \
             help: they're kept in memory until you close the app"
        );
    }

    /// Talks to the real session keyring; may show an unlock prompt.
    #[test]
    #[ignore = "needs a running Secret Service: cargo test -- --ignored"]
    fn secret_service_roundtrip() {
        let s = SecretServiceStore::connect().unwrap_or_else(|u| panic!("{}", u.message()));
        let id = "fortisaml-gui-test-0000";
        let label = item_label("test", Kind::Psk);
        s.set(id, Kind::Psk, &label, "s3cret").unwrap();
        assert_eq!(s.get(id, Kind::Psk).unwrap().as_deref(), Some("s3cret"));
        s.set(id, Kind::Psk, &item_label("renamed", Kind::Psk), "changed").unwrap();
        assert_eq!(s.get(id, Kind::Psk).unwrap().as_deref(), Some("changed"));
        let c = s.collection().unwrap();
        let items = c.search_items(attrs(id, Some(Kind::Psk))).unwrap();
        assert_eq!(items.len(), 1, "replaced, not duplicated");
        assert_eq!(items[0].get_label().unwrap(), "FortiSAML VPN: renamed (PSK)", "label follows a rename");
        s.set(id, Kind::Password, &item_label("test", Kind::Password), "pw").unwrap();
        s.set(id, Kind::Password, "", "").unwrap();
        assert_eq!(s.get(id, Kind::Password).unwrap(), None, "empty secret deletes");
        s.delete_profile(id).unwrap();
        assert_eq!(s.get(id, Kind::Psk).unwrap(), None);
    }

    #[test]
    fn no_default_collection_message() {
        assert_eq!(
            Unavailable::NoDefault.message(),
            "warning: the PSK and password can't be saved\n  \
             note: the keyring service has no default keyring\n  \
             help: create one (e.g. in Seahorse or KeePassXC) and restart; until then they're kept in memory"
        );
    }

    #[test]
    fn deduped_profile_stores_secrets_under_its_new_id() {
        let mut cfg = cfg_with("A");
        cfg.profiles[0].psk = "shared".into();
        cfg.profiles.push(cfg.profiles[0].clone());
        let saved = cfg.clone();
        cfg.dedupe_ids();
        assert_eq!(plan(&saved, &cfg), vec![set_op(&cfg.profiles[1], Kind::Psk, "shared")]);
    }

    #[test]
    fn failed_set_reverts_only_that_secret() {
        let store = MemoryStore { fail: Some(Kind::Psk), ..Default::default() };
        let saved = cfg_with("Office");
        let mut cfg = saved.clone();
        cfg.profiles[0].psk = "k".into();
        cfg.profiles[0].auth.password = "pw".into();
        cfg.profiles[0].auth.save_password = true;
        let (next, _) = apply(&store, &plan(&saved, &cfg), &saved, &cfg);
        assert_eq!(next.profiles[0].auth.password, "pw", "password write succeeded, so it counts as saved");
        assert_eq!(plan(&next, &cfg), vec![set_op(&cfg.profiles[0], Kind::Psk, "k")], "only the PSK is retried");
    }

    #[test]
    fn failed_untick_save_password_is_retried() {
        let store = MemoryStore { fail: Some(Kind::Password), ..Default::default() };
        let mut saved = cfg_with("Office");
        saved.profiles[0].auth.password = "pw".into();
        saved.profiles[0].auth.save_password = true;
        let mut cfg = saved.clone();
        cfg.profiles[0].auth.save_password = false;
        let (next, _) = apply(&store, &plan(&saved, &cfg), &saved, &cfg);
        assert!(!next.settings_eq(&cfg), "still unsaved");
        assert_eq!(plan(&next, &cfg), vec![set_op(&cfg.profiles[0], Kind::Password, "")]);
    }

    #[test]
    fn op_debug_redacts_secret() {
        let op = Op::Set { profile_id: "id".into(), kind: Kind::Psk, label: "l".into(), secret: "hunter2".into() };
        let s = format!("{op:?}");
        assert!(!s.contains("hunter2") && s.contains("<redacted>"), "{s}");
    }
}
