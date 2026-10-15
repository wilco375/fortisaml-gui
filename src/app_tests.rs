//! App tests without a window: Save, unsaved tracking, startup and the close dialog.
//! They use an in-memory keyring and temp config/state dirs, one test at a time (Paths::from_env() reads XDG_*).

use super::*;
use crate::keyring::testing::MemoryStore;
use crate::keyring::{Kind, SecretStore, Unavailable};
use egui::accesskit::{Action, ActionRequest, Role};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

static ENV: Mutex<()> = Mutex::new(());

/// Fresh XDG_CONFIG_HOME for one test; holds the lock until dropped.
struct TempConfig {
    dir: std::path::PathBuf,
    _lock: MutexGuard<'static, ()>,
}

impl TempConfig {
    fn new() -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let lock = ENV.lock().unwrap_or_else(|e| e.into_inner());
        let n = N.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("fortisaml-gui-test-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // SAFETY: tests touching the environment hold ENV
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", &dir);
            std::env::set_var("XDG_STATE_HOME", dir.join("state"));
        }
        Self { dir, _lock: lock }
    }
}

impl Drop for TempConfig {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn app_with(store: &MemoryStore) -> App {
    App::with_keyring(Config::load(), Ok(Box::new(store.clone())))
}

/// config.toml plus every profile file.
fn file() -> String {
    let paths = Paths::from_env();
    let mut s = std::fs::read_to_string(paths.config_file()).unwrap_or_default();
    for e in std::fs::read_dir(paths.profiles_dir()).into_iter().flatten().flatten() {
        s += &std::fs::read_to_string(e.path()).unwrap_or_default();
    }
    s
}

#[test]
fn first_start_writes_config_and_is_clean() {
    let _t = TempConfig::new();
    let app = app_with(&MemoryStore::default());
    let paths = Paths::from_env();
    assert!(paths.config_file().exists() && paths.profile_file("New connection").exists() && paths.state_file().exists());
    assert!(!app.unsaved());
    assert!(app.save_error.is_none() && app.keyring_warning.is_none());
}

#[test]
fn save_puts_psk_in_keyring_not_in_file() {
    let _t = TempConfig::new();
    let store = MemoryStore::default();
    let mut app = app_with(&store);
    app.cfg.profiles[0].psk = "s3cret".into();
    assert!(app.unsaved());
    app.save();
    assert!(!app.unsaved() && app.save_error.is_none());
    assert_eq!(store.get(&app.cfg.profiles[0].id, Kind::Psk).unwrap().as_deref(), Some("s3cret"));
    assert!(!file().contains("s3cret"));
}

#[test]
fn restart_fills_secrets() {
    let _t = TempConfig::new();
    let store = MemoryStore::default();
    let mut app = app_with(&store);
    app.cfg.profiles[0].psk = "s3cret".into();
    app.save();
    let app = app_with(&store);
    assert_eq!(app.cfg.profiles[0].psk, "s3cret");
    assert!(!app.unsaved());
}

#[test]
fn rename_moves_the_file_and_keeps_the_secrets() {
    let _t = TempConfig::new();
    let store = MemoryStore::default();
    let mut app = app_with(&store);
    app.cfg.profiles[0].psk = "k".into();
    app.save();
    app.cfg.profiles[0].name = "Home".into();
    app.save();
    let paths = Paths::from_env();
    assert!(!paths.profile_file("New connection").exists() && paths.profile_file("Home").exists());
    let app = app_with(&store);
    assert_eq!((app.cfg.profiles[0].name.as_str(), app.cfg.profiles[0].psk.as_str()), ("Home", "k"));
    assert!(!app.unsaved());
}

#[test]
fn duplicate_name_blocks_save() {
    let _t = TempConfig::new();
    let store = MemoryStore::default();
    let mut app = app_with(&store);
    app.cfg.profiles.push(Profile::default()); // same name as the first
    app.cfg.profiles[1].psk = "k".into();
    app.save();
    let err = app.save_error.as_deref().unwrap();
    assert!(err.starts_with("error: connection \"New connection\" can't be saved\n  note: Another connection already has this name."), "{err}");
    assert!(app.unsaved());
    assert_eq!(store.get(&app.cfg.profiles[1].id, Kind::Psk).unwrap(), None, "nothing saved");
}

#[test]
fn secrets_of_a_vanished_profile_file_are_deleted_on_save() {
    let _t = TempConfig::new();
    let store = MemoryStore::default();
    let mut app = app_with(&store);
    app.cfg.profiles.push(Profile { name: "Gone".into(), psk: "k".into(), ..Profile::default() });
    app.save();
    let gone = app.cfg.profiles[1].id.clone();
    assert_eq!(store.get(&gone, Kind::Psk).unwrap().as_deref(), Some("k"));
    std::fs::remove_file(Paths::from_env().profile_file("Gone")).unwrap();
    let mut app = app_with(&store);
    assert!(!app.unsaved(), "an orphan alone isn't an unsaved change");
    app.cfg.profiles[0].description = "x".into();
    app.save();
    assert_eq!(store.get(&gone, Kind::Psk).unwrap(), None);
    assert!(app.cfg.orphans.is_empty());
}

#[test]
fn first_start_without_config_dir_keeps_secrets_named_in_state() {
    let _t = TempConfig::new();
    let store = MemoryStore::default();
    let id = "A".repeat(32);
    store.set(&id, Kind::Psk, "l", "k").unwrap();
    let paths = Paths::from_env();
    std::fs::create_dir_all(&paths.state_dir).unwrap();
    std::fs::write(paths.state_file(), format!(r#"{{"ids":{{"Office":"{id}"}}}}"#)).unwrap();
    let app = app_with(&store); // first start: also saves
    assert!(app.save_error.is_none(), "{:?}", app.save_error);
    assert_eq!(store.get(&id, Kind::Psk).unwrap().as_deref(), Some("k"));
}

#[test]
fn bad_profile_file_is_reported_at_startup_and_left_alone() {
    let _t = TempConfig::new();
    let paths = Paths::from_env();
    std::fs::create_dir_all(paths.profiles_dir()).unwrap();
    std::fs::write(paths.profile_file("Broken"), "gateway = [").unwrap();
    let mut app = app_with(&MemoryStore::default()); // first start: also saves
    let err = app.save_error.clone().unwrap_or_default();
    assert!(err.starts_with("error: ") && err.contains("Broken.toml couldn't be read"), "{err}");
    app.cfg.profiles[0].description = "x".into();
    app.save();
    assert_eq!(std::fs::read_to_string(paths.profile_file("Broken")).unwrap(), "gateway = [");
}

#[test]
fn view_state_and_unsaved_password_are_not_changes() {
    let _t = TempConfig::new();
    let mut app = app_with(&MemoryStore::default());
    app.cfg.profiles.push(Profile { name: "Second".into(), ..Profile::default() });
    app.save();
    app.cfg.selected = 1;
    app.cfg.show_log = !app.cfg.show_log;
    app.cfg.profiles[0].auth.password = "typed".into(); // "Save password" is off
    assert!(!app.unsaved());
}

#[test]
fn duplicate_ids_in_state_are_fixed_and_saved_separately() {
    let _t = TempConfig::new();
    let store = MemoryStore::default();
    let id = "A".repeat(32);
    store.set(&id, Kind::Psk, "l", "k").unwrap();
    let paths = Paths::from_env();
    std::fs::create_dir_all(paths.profiles_dir()).unwrap();
    std::fs::create_dir_all(&paths.state_dir).unwrap();
    std::fs::write(paths.config_file(), "").unwrap(); // not a first start
    std::fs::write(paths.profile_file("A"), "").unwrap();
    std::fs::write(paths.profile_file("B"), "").unwrap();
    std::fs::write(paths.state_file(), format!(r#"{{"ids":{{"A":"{id}","B":"{id}"}}}}"#)).unwrap();
    let mut app = app_with(&store);
    let new_id = app.cfg.profiles[1].id.clone();
    assert_ne!(new_id, id);
    assert!(app.unsaved());
    app.save();
    assert_eq!(store.get(&new_id, Kind::Psk).unwrap().as_deref(), Some("k"));
}

#[test]
fn unwritable_config_shows_error_and_leaves_keyring_alone() {
    let _t = TempConfig::new();
    let store = MemoryStore::default();
    let mut app = app_with(&store);
    let mut tmp = Paths::from_env().profile_file("New connection").into_os_string();
    tmp.push(".tmp");
    std::fs::create_dir(tmp).unwrap(); // blocks the atomic write
    app.cfg.profiles[0].psk = "k".into();
    app.save();
    assert!(app.save_error.as_deref().unwrap().starts_with("error: the settings couldn't be saved\n  note: "));
    assert!(app.unsaved());
    assert_eq!(store.get(&app.cfg.profiles[0].id, Kind::Psk).unwrap(), None);
}

#[test]
fn keyring_failure_shows_error_but_saves_the_file() {
    let _t = TempConfig::new();
    let store = MemoryStore { fail: Some(Kind::Psk), ..Default::default() };
    let mut app = app_with(&store);
    app.cfg.profiles[0].psk = "k".into();
    app.cfg.profiles[0].description = "kept".into();
    app.save();
    assert!(app.save_error.as_deref().unwrap().starts_with("error: the PSK couldn't be saved to the keyring"));
    assert!(app.unsaved());
    assert!(file().contains("kept"));
}

#[test]
fn without_keyring_warns_and_saves_file_only() {
    let _t = TempConfig::new();
    let mut app = App::with_keyring(Config::load(), Err(Unavailable::NoService("test".into())));
    assert!(app.keyring_warning.as_deref().unwrap().starts_with("warning: the PSK and password can't be saved"));
    app.cfg.profiles[0].psk = "memonly".into();
    app.save();
    assert!(app.save_error.is_none() && !app.unsaved());
    assert!(!file().contains("memonly"));
}

// ---- close dialog, driven through egui's AccessKit tree ----

/// Headless egui frames running only `close_guard`.
struct Frames {
    ctx: egui::Context,
    tree: Vec<(egui::accesskit::NodeId, egui::accesskit::Node)>,
    tree_id: egui::accesskit::TreeId,
}

impl Frames {
    fn new() -> Self {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        Self { ctx, tree: vec![], tree_id: egui::accesskit::TreeId::ROOT }
    }

    /// One frame; returns the viewport commands it sent.
    fn run(&mut self, app: &mut App, close: bool, events: Vec<egui::Event>) -> Vec<egui::ViewportCommand> {
        let mut input = egui::RawInput { events, ..Default::default() };
        if close {
            input.viewports.entry(egui::ViewportId::ROOT).or_default().events.push(egui::ViewportEvent::Close);
        }
        let mut out = self.ctx.run_ui(input, |ui| app.close_guard(&ui.ctx().clone()));
        if let Some(u) = out.platform_output.accesskit_update.take() {
            self.tree = u.nodes;
            self.tree_id = u.tree_id;
        }
        let cmds = out.viewport_output.get(&egui::ViewportId::ROOT).map(|o| o.commands.clone()).unwrap_or_default();
        out.drop_without_applying_deltas();
        cmds
    }

    /// Visible texts: button/window labels and label values.
    fn texts(&self) -> impl Iterator<Item = &str> {
        self.tree.iter().filter_map(|(_, n)| n.label().or(n.value()))
    }

    fn has(&self, text: &str) -> bool {
        self.texts().any(|t| t == text)
    }

    /// Click the button `label`; returns the commands of that frame.
    fn click(&mut self, app: &mut App, label: &str) -> Vec<egui::ViewportCommand> {
        let (id, _) = self.tree.iter().find(|(_, n)| n.role() == Role::Button && n.label() == Some(label)).expect(label);
        let req = ActionRequest { action: Action::Click, target_tree: self.tree_id, target_node: *id, data: None };
        self.run(app, false, vec![egui::Event::AccessKitActionRequest(req)])
    }
}

const DIALOG: &str = "Save your changes before closing?";

#[test]
fn close_without_changes_goes_through() {
    let _t = TempConfig::new();
    let mut app = app_with(&MemoryStore::default());
    let mut f = Frames::new();
    assert!(!f.run(&mut app, true, vec![]).contains(&egui::ViewportCommand::CancelClose));
    assert!(!app.confirm_close);
}

#[test]
fn close_with_changes_asks_and_cancel_keeps_them() {
    let _t = TempConfig::new();
    let mut app = app_with(&MemoryStore::default());
    app.cfg.profiles[0].description = "dirty".into();
    let mut f = Frames::new();
    assert!(f.run(&mut app, true, vec![]).contains(&egui::ViewportCommand::CancelClose));
    f.run(&mut app, false, vec![]);
    assert!(f.has(DIALOG));
    f.click(&mut app, "Cancel");
    f.run(&mut app, false, vec![]);
    assert!(!f.has(DIALOG) && app.unsaved());
}

#[test]
fn close_dialog_discard_closes_without_saving() {
    let _t = TempConfig::new();
    let mut app = app_with(&MemoryStore::default());
    app.cfg.profiles[0].description = "dirty".into();
    let mut f = Frames::new();
    f.run(&mut app, true, vec![]);
    f.run(&mut app, false, vec![]);
    assert!(f.click(&mut app, "Discard").contains(&egui::ViewportCommand::Close));
    assert!(!file().contains("dirty"));
    assert!(!f.run(&mut app, true, vec![]).contains(&egui::ViewportCommand::CancelClose), "next close goes through");
}

#[test]
fn close_dialog_save_saves_and_closes() {
    let _t = TempConfig::new();
    let store = MemoryStore::default();
    let mut app = app_with(&store);
    app.cfg.profiles[0].psk = "k".into();
    let mut f = Frames::new();
    f.run(&mut app, true, vec![]);
    f.run(&mut app, false, vec![]);
    assert!(f.click(&mut app, "Save").contains(&egui::ViewportCommand::Close));
    assert_eq!(store.get(&app.cfg.profiles[0].id, Kind::Psk).unwrap().as_deref(), Some("k"));
}

#[test]
fn close_dialog_save_failure_keeps_dialog_open_with_error() {
    let _t = TempConfig::new();
    let store = MemoryStore { fail: Some(Kind::Psk), ..Default::default() };
    let mut app = app_with(&store);
    app.cfg.profiles[0].psk = "k".into();
    let mut f = Frames::new();
    f.run(&mut app, true, vec![]);
    f.run(&mut app, false, vec![]);
    assert!(!f.click(&mut app, "Save").contains(&egui::ViewportCommand::Close));
    f.run(&mut app, false, vec![]);
    assert!(f.has(DIALOG));
    assert!(f.texts().any(|t| t.starts_with("error: the PSK couldn't be saved")));
}

// ---- whole window ----

/// One frame of the full app; returns the texts and what was copied to the clipboard.
fn app_frame(ctx: &egui::Context, app: &mut App, events: Vec<egui::Event>) -> (Vec<(egui::accesskit::NodeId, egui::accesskit::Node)>, Vec<String>) {
    let mut ef = eframe::Frame::_new_kittest();
    let mut out = ctx.run_ui(egui::RawInput { events, ..Default::default() }, |ui| eframe::App::ui(app, ui, &mut ef));
    let nodes = out.platform_output.accesskit_update.take().map(|u| u.nodes).unwrap_or_default();
    let copied = out.platform_output.commands.iter().filter_map(|c| match c {
        egui::OutputCommand::CopyText(t) => Some(t.clone()),
        _ => None,
    }).collect();
    out.drop_without_applying_deltas();
    (nodes, copied)
}

fn button<'a>(nodes: &'a [(egui::accesskit::NodeId, egui::accesskit::Node)], label: &str) -> Option<&'a egui::accesskit::Node> {
    nodes.iter().map(|(_, n)| n).find(|n| n.role() == Role::Button && n.label() == Some(label))
}

fn click_event(nodes: &[(egui::accesskit::NodeId, egui::accesskit::Node)], label: &str) -> egui::Event {
    let (id, _) = nodes.iter().find(|(_, n)| n.role() == Role::Button && n.label() == Some(label)).expect(label);
    egui::Event::AccessKitActionRequest(ActionRequest { action: Action::Click, target_tree: egui::accesskit::TreeId::ROOT, target_node: *id, data: None })
}

#[test]
fn save_button_says_what_state_you_are_in() {
    let _t = TempConfig::new();
    let mut app = app_with(&MemoryStore::default());
    let ctx = egui::Context::default();
    ctx.enable_accesskit();
    app_frame(&ctx, &mut app, vec![]);
    let (nodes, _) = app_frame(&ctx, &mut app, vec![]);
    assert!(button(&nodes, "✔ Saved").is_some());
    app.cfg.profiles[0].description = "dirty".into();
    let (nodes, _) = app_frame(&ctx, &mut app, vec![]);
    assert!(button(&nodes, "💾 Save changes").is_some());
}

#[test]
fn ctrl_s_saves() {
    let _t = TempConfig::new();
    let mut app = app_with(&MemoryStore::default());
    app.cfg.profiles[0].description = "dirty".into();
    let ctx = egui::Context::default();
    let ctrl_s = egui::Event::Key { key: egui::Key::S, physical_key: None, pressed: true, repeat: false, modifiers: egui::Modifiers::COMMAND };
    app_frame(&ctx, &mut app, vec![ctrl_s]);
    assert!(!app.unsaved());
    assert!(file().contains("dirty"));
}

#[test]
fn login_link_can_be_copied() {
    let _t = TempConfig::new();
    let mut app = app_with(&MemoryStore::default());
    app.state = State::Authenticating;
    app.info.saml_url = "https://idp.example/login".into();
    let ctx = egui::Context::default();
    ctx.enable_accesskit();
    app_frame(&ctx, &mut app, vec![]);
    let (nodes, _) = app_frame(&ctx, &mut app, vec![]);
    assert!(button(&nodes, "🌐 Open login page").is_some());
    let (_, copied) = app_frame(&ctx, &mut app, vec![click_event(&nodes, "📋 Copy link")]);
    assert_eq!(copied, ["https://idp.example/login"]);
    let (nodes, _) = app_frame(&ctx, &mut app, vec![]);
    assert!(button(&nodes, "✔ Copied").is_some());
}

#[test]
fn password_prompt_is_explained_while_elevating() {
    let _t = TempConfig::new();
    let mut app = app_with(&MemoryStore::default());
    let ctx = egui::Context::default();
    ctx.enable_accesskit();
    let explained = |nodes: &[(egui::accesskit::NodeId, egui::accesskit::Node)]| {
        nodes.iter().filter_map(|(_, n)| n.value()).any(|t| t.contains("needs administrator rights"))
    };
    app_frame(&ctx, &mut app, vec![]);
    assert!(!explained(&app_frame(&ctx, &mut app, vec![]).0));
    app.state = State::Elevating;
    assert!(explained(&app_frame(&ctx, &mut app, vec![]).0));
}

#[test]
fn finished_sso_login_asks_for_attention() {
    let _t = TempConfig::new();
    let mut app = app_with(&MemoryStore::default());
    app.state = State::Authenticating;
    let ctx = egui::Context::default();
    let frame = |app: &mut App| {
        let mut ef = eframe::Frame::_new_kittest();
        let out = ctx.run_ui(Default::default(), |ui| eframe::App::ui(app, ui, &mut ef));
        let cmds = out.viewport_output.get(&egui::ViewportId::ROOT).map(|o| o.commands.clone()).unwrap_or_default();
        out.drop_without_applying_deltas();
        cmds
    };
    let attention = egui::ViewportCommand::RequestUserAttention(egui::UserAttentionType::Informational);
    assert!(!frame(&mut app).contains(&attention));
    app.tx.send(backend::Event::Backend(BackendEvent::SamlOk { username: "u".into() })).unwrap();
    assert!(frame(&mut app).contains(&attention));
    assert!(!frame(&mut app).contains(&attention), "only once");
}

// ---- settings window and sharing ----

#[test]
fn regenerate_uid_asks_first() {
    let _t = TempConfig::new();
    let mut app = app_with(&MemoryStore::default());
    let uid = app.cfg.uid;
    app.ask_regenerate_uid();
    assert!(app.confirm_regen);
    assert_eq!(app.cfg.uid, uid);
    app.regenerate_uid(false);
    assert!(!app.confirm_regen);
    assert_eq!(app.cfg.uid, uid);
    assert!(!app.unsaved());
    app.ask_regenerate_uid();
    app.regenerate_uid(true);
    assert!(!app.confirm_regen);
    assert_ne!(app.cfg.uid, uid);
    assert!(app.unsaved());
}

/// Fonts::has_glyphs can't be used: it reports every NotoEmoji char as missing, because that face also holds the
/// replacement glyph. Look the chars up in the fonts' character maps instead.
#[test]
fn new_button_glyphs_exist_in_default_fonts() {
    let ctx = egui::Context::default();
    ctx.run_ui(Default::default(), |_| {}).drop_without_applying_deltas();
    let has = |c: char| ctx.fonts_mut(|f| f.fonts.font(&egui::FontFamily::Proportional).characters().contains_key(&c));
    assert!(!has('●') && !has('⧉'), "the check must catch the glyphs f21fbf3 replaced");
    for label in ["📂 Open folder", "🔗 Share", "Regenerate", "Cancel"] {
        assert!(label.chars().all(has), "{label}");
    }
}

// ---- drafts and problems ----

/// Type an invalid gateway into profile `i` (what the editor does when the text doesn't parse).
fn type_bad_gateway(app: &mut App, i: usize) {
    let key = (DraftOwner::Profile(app.cfg.profiles[i].id.clone()), Field::Gateway);
    app.drafts.edit_opt(key, "vpn example".into(), &mut app.cfg.profiles[i].gateway);
}

fn label_shown(nodes: &[(egui::accesskit::NodeId, egui::accesskit::Node)], text: &str) -> bool {
    nodes.iter().any(|(_, n)| n.label() == Some(text) || n.value() == Some(text))
}

#[test]
fn invalid_draft_blocks_save_and_ctrl_s() {
    let _t = TempConfig::new();
    let mut app = app_with(&MemoryStore::default());
    app.cfg.profiles[0].description = "dirty".into();
    type_bad_gateway(&mut app, 0);
    assert!(app.unsaved());
    let ctx = egui::Context::default();
    ctx.enable_accesskit();
    let ctrl_s = egui::Event::Key { key: egui::Key::S, physical_key: None, pressed: true, repeat: false, modifiers: egui::Modifiers::COMMAND };
    app_frame(&ctx, &mut app, vec![ctrl_s]);
    assert!(!file().contains("dirty"), "nothing saved");
    let (nodes, _) = app_frame(&ctx, &mut app, vec![]);
    assert!(button(&nodes, "💾 Save changes").unwrap().is_disabled());
    assert!(button(&nodes, "Connect").unwrap().is_disabled(), "the selected profile has the problem");
    assert!(label_shown(&nodes, "⚠ Expected a host name or IPv4 address, not \"vpn example\"."));
    let key = (DraftOwner::Profile(app.cfg.profiles[0].id.clone()), Field::Gateway);
    assert_eq!(app.drafts.text(&key), Some("vpn example"), "what was typed is kept");
    app.save();
    assert!(app.save_error.as_deref().unwrap().contains("Remote gateway: Expected a host name"), "{:?}", app.save_error);
}

#[test]
fn invalid_draft_on_another_profile_is_marked() {
    let _t = TempConfig::new();
    let mut app = app_with(&MemoryStore::default());
    app.cfg.profiles.push(Profile { name: "Second".into(), ..Profile::default() });
    type_bad_gateway(&mut app, 0);
    app.cfg.selected = 1;
    let ctx = egui::Context::default();
    ctx.enable_accesskit();
    app_frame(&ctx, &mut app, vec![]);
    let (nodes, _) = app_frame(&ctx, &mut app, vec![]);
    assert!(label_shown(&nodes, "⚠ New connection"), "the profile with the problem is marked");
    assert!(label_shown(&nodes, "Second"));
    assert!(button(&nodes, "💾 Save changes").unwrap().is_disabled());
    assert!(!button(&nodes, "Connect").unwrap().is_disabled(), "the selected profile is fine");
}

#[test]
fn deleting_a_profile_drops_its_drafts() {
    let _t = TempConfig::new();
    let mut app = app_with(&MemoryStore::default());
    app.cfg.profiles.push(Profile { name: "Second".into(), ..Profile::default() });
    type_bad_gateway(&mut app, 1);
    app.cfg.selected = 1;
    let ctx = egui::Context::default();
    ctx.enable_accesskit();
    app_frame(&ctx, &mut app, vec![]);
    let (nodes, _) = app_frame(&ctx, &mut app, vec![]);
    app_frame(&ctx, &mut app, vec![click_event(&nodes, "🗑 Delete")]); // arms it; the next frame shows "Confirm delete"
    let (nodes, _) = app_frame(&ctx, &mut app, vec![]);
    app_frame(&ctx, &mut app, vec![click_event(&nodes, "Confirm delete")]);
    assert_eq!(app.cfg.profiles.len(), 1);
    assert!(!app.drafts.has_errors() && app.problems().is_empty());
}

#[test]
fn empty_custom_routes_block_save() {
    let _t = TempConfig::new();
    let mut app = app_with(&MemoryStore::default());
    app.cfg.profiles[0].network.route_mode = RouteMode::Custom;
    assert_eq!(app.problems().iter().map(|p| p.message.as_str()).collect::<Vec<_>>(), [config::NO_ROUTES]);
    app.save();
    assert!(app.save_error.as_deref().unwrap().contains(config::NO_ROUTES), "{:?}", app.save_error);
    assert!(!file().contains("Custom"));
}

#[test]
fn close_dialog_cannot_save_with_problems() {
    let _t = TempConfig::new();
    let mut app = app_with(&MemoryStore::default());
    type_bad_gateway(&mut app, 0);
    let mut f = Frames::new();
    assert!(f.run(&mut app, true, vec![]).contains(&egui::ViewportCommand::CancelClose), "invalid text counts as a change");
    f.run(&mut app, false, vec![]);
    assert!(f.has(DIALOG));
    let save = f.tree.iter().find(|(_, n)| n.role() == Role::Button && n.label() == Some("Save")).unwrap();
    assert!(save.1.is_disabled());
    assert!(f.click(&mut app, "Discard").contains(&egui::ViewportCommand::Close));
}

#[test]
fn backend_events_drive_the_status() {
    let _t = TempConfig::new();
    let mut app = app_with(&MemoryStore::default());
    app.state = State::Elevating;
    app.on_backend(BackendEvent::IkeStart { gateway: "vpn.example.com".parse().unwrap() });
    assert_eq!(app.state, State::Negotiating);
    let ip = Ipv4Addr::new(10, 98, 0, 2);
    app.on_backend(BackendEvent::TunnelUp { ifname: "fsaml0".parse().unwrap(), ip, routes: vec!["10.10.0.0/16".parse().unwrap()], full_tunnel: false });
    assert_eq!((app.info.ip, app.info.routes.len(), app.info.full_tunnel), (Some(ip), 1, false));
    app.on_backend(BackendEvent::Connected);
    assert_eq!(app.state, State::Connected);
    app.on_backend(BackendEvent::Error { message: "no answer".into() });
    assert_eq!(app.error.as_deref(), Some("no answer"));
}

#[test]
fn problems_in_hidden_fields_are_listed_on_screen() {
    let _t = TempConfig::new();
    let mut app = app_with(&MemoryStore::default());
    // the Settings window is closed: the UID field and its warning aren't visible
    app.drafts.edit((DraftOwner::App, Field::Uid), "x".into(), &mut app.cfg.uid);
    let ctx = egui::Context::default();
    ctx.enable_accesskit();
    app_frame(&ctx, &mut app, vec![]);
    let (nodes, _) = app_frame(&ctx, &mut app, vec![]);
    assert!(label_shown(&nodes, "⚠ Settings: Client UID: The client UID must be 32 hexadecimal characters."));
    assert!(button(&nodes, "Connect").unwrap().is_disabled());
}

#[test]
fn a_field_the_mode_does_not_use_does_not_block() {
    let _t = TempConfig::new();
    let mut app = app_with(&MemoryStore::default());
    let key = (DraftOwner::Profile(app.cfg.profiles[0].id.clone()), Field::Username);
    app.drafts.edit_opt(key.clone(), "jané".into(), &mut app.cfg.profiles[0].auth.username);
    assert!(app.cfg.profiles[0].sso.enabled);
    assert!(app.problems().is_empty(), "SSO doesn't use the username");
    app.cfg.profiles[0].sso.enabled = false;
    assert_eq!(app.problems().len(), 1, "it counts again once the username is used");
    assert_eq!(app.drafts.text(&key), Some("jané"), "what was typed is kept");
}

// ---- typing character by character ----

/// One frame; returns the nodes and the focused node.
fn frame_focus(ctx: &egui::Context, app: &mut App, events: Vec<egui::Event>) -> (Vec<(egui::accesskit::NodeId, egui::accesskit::Node)>, Option<egui::accesskit::NodeId>) {
    let mut ef = eframe::Frame::_new_kittest();
    let mut out = ctx.run_ui(egui::RawInput { events, ..Default::default() }, |ui| eframe::App::ui(app, ui, &mut ef));
    let u = out.platform_output.accesskit_update.take().unwrap();
    out.drop_without_applying_deltas();
    (u.nodes, Some(u.focus))
}

fn field_node(nodes: &[(egui::accesskit::NodeId, egui::accesskit::Node)], f: Field) -> (egui::accesskit::NodeId, egui::accesskit::Node) {
    nodes.iter().find(|(_, n)| matches!(n.role(), Role::TextInput | Role::MultilineTextInput) && n.label() == Some(f.label())).cloned().unwrap_or_else(|| panic!("no field {}", f.label()))
}

/// Focus field `f` and type `text` one character per frame; after each frame the field must still have the focus.
fn type_slowly(ctx: &egui::Context, app: &mut App, f: Field, text: &str) -> Vec<(egui::accesskit::NodeId, egui::accesskit::Node)> {
    let (nodes, _) = frame_focus(ctx, app, vec![]);
    let (id, _) = field_node(&nodes, f);
    let focus = egui::Event::AccessKitActionRequest(ActionRequest { action: Action::Focus, target_tree: egui::accesskit::TreeId::ROOT, target_node: id, data: None });
    frame_focus(ctx, app, vec![focus]);
    let mut nodes = vec![];
    let mut typed = String::new();
    for c in text.chars() {
        typed.push(c);
        let (n, focused) = frame_focus(ctx, app, vec![egui::Event::Text(c.to_string())]);
        let (now, _) = field_node(&n, f);
        assert_eq!(focused, Some(now), "{} lost the focus after typing {typed:?}", f.label());
        nodes = n;
    }
    nodes
}

#[test]
fn typing_an_invalid_gateway_keeps_focus_and_the_label_level() {
    let _t = TempConfig::new();
    let mut app = app_with(&MemoryStore::default());
    let ctx = egui::Context::default();
    ctx.enable_accesskit();
    frame_focus(&ctx, &mut app, vec![]);
    type_slowly(&ctx, &mut app, Field::Gateway, "vpn example");
    let (nodes, _) = frame_focus(&ctx, &mut app, vec![]);
    let (_, field) = field_node(&nodes, Field::Gateway);
    assert_eq!(field.value(), Some("vpn example"));
    let label = nodes.iter().find(|(_, n)| n.role() == Role::Label && n.value() == Some("Remote gateway")).unwrap().1.clone();
    let lb = label.bounds().unwrap();
    let fb = field.bounds().unwrap();
    let cy = (lb.y0 + lb.y1) / 2.0;
    assert!(fb.y0 <= cy && cy <= fb.y1, "label at {lb:?} isn't level with the field at {fb:?}");
}

#[test]
fn typing_a_custom_route_is_not_reformatted_halfway() {
    let _t = TempConfig::new();
    let mut app = app_with(&MemoryStore::default());
    app.cfg.profiles[0].network.route_mode = RouteMode::Custom;
    let ctx = egui::Context::default();
    ctx.enable_accesskit();
    frame_focus(&ctx, &mut app, vec![]);
    let (nodes, _) = frame_focus(&ctx, &mut app, vec![]);
    let net = nodes.iter().find(|(_, n)| n.role() == Role::Button && n.label() == Some("Network")).unwrap().0;
    frame_focus(&ctx, &mut app, vec![egui::Event::AccessKitActionRequest(ActionRequest { action: Action::Click, target_tree: egui::accesskit::TreeId::ROOT, target_node: net, data: None })]);
    type_slowly(&ctx, &mut app, Field::CustomRoutes, "10.0.0.0/8");
    assert_eq!(app.cfg.profiles[0].network.custom_routes, ["10.0.0.0/8".parse::<net::Ipv4Net>().unwrap()]);
}

#[test]
fn an_older_file_format_counts_as_a_change_until_saved() {
    let _t = TempConfig::new();
    let paths = Paths::from_env();
    std::fs::create_dir_all(paths.profiles_dir()).unwrap();
    std::fs::write(paths.profile_file("Old"), "[network]\ncustom_routes = \"\"\n").unwrap();
    // not a first start (that saves straight away)
    std::fs::write(paths.config_file(), "uid = \"0123456789ABCDEF0123456789ABCDEF\"\n").unwrap();
    let mut app = app_with(&MemoryStore::default());
    assert!(app.unsaved(), "Save is offered for the old file");
    app.save();
    assert_eq!(app.save_error, None);
    assert!(!app.unsaved());
    assert_eq!(std::fs::read_to_string(paths.profile_file("Old")).unwrap(), "");
}
