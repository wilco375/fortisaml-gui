//! App tests without a window: Save, unsaved tracking, startup and the close dialog.
//! They use an in-memory keyring and a temp config dir, one test at a time (config_path() reads XDG_CONFIG_HOME).

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
        unsafe { std::env::set_var("XDG_CONFIG_HOME", &dir) };
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

fn file() -> String {
    std::fs::read_to_string(config_path()).unwrap_or_default()
}

#[test]
fn first_start_writes_config_and_is_clean() {
    let _t = TempConfig::new();
    let app = app_with(&MemoryStore::default());
    assert!(config_path().exists());
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
fn view_state_and_unsaved_password_are_not_changes() {
    let _t = TempConfig::new();
    let mut app = app_with(&MemoryStore::default());
    app.cfg.profiles.push(Profile::default());
    app.save();
    app.cfg.selected = 1;
    app.cfg.show_log = !app.cfg.show_log;
    app.cfg.profiles[0].password = "typed".into(); // "Save password" is off
    assert!(!app.unsaved());
}

#[test]
fn duplicate_ids_in_file_are_fixed_and_saved_separately() {
    let _t = TempConfig::new();
    let store = MemoryStore::default();
    let id = "A".repeat(32);
    store.set(&id, Kind::Psk, "l", "k").unwrap();
    std::fs::create_dir_all(config_path().parent().unwrap()).unwrap();
    std::fs::write(config_path(), format!(r#"{{"profiles":[{{"id":"{id}"}},{{"id":"{id}"}}]}}"#)).unwrap();
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
    std::fs::create_dir(config_path().with_extension("json.tmp")).unwrap(); // blocks the atomic write
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

// ---- port field ----

/// Focus the port field, send `events`, then move focus away. Returns the port and the visible texts.
fn edit_port(start: u16, events: Vec<egui::Event>) -> (u16, Vec<String>) {
    let ctx = egui::Context::default();
    ctx.enable_accesskit();
    let mut port = start;
    let mut texts = vec![];
    let mut run = |port: &mut u16, events: Vec<egui::Event>, focus: bool| {
        let mut out = ctx.run_ui(egui::RawInput { events, ..Default::default() }, |ui| {
            let r = port_field(ui, "p", port);
            if focus {
                r.request_focus();
            } else {
                r.surrender_focus();
            }
        });
        if let Some(u) = out.platform_output.accesskit_update.take() {
            texts = u.nodes.iter().filter_map(|(_, n)| n.label().or(n.value()).map(str::to_owned)).collect();
        }
        out.drop_without_applying_deltas();
    };
    run(&mut port, vec![], true);
    run(&mut port, events, true);
    run(&mut port, vec![], false);
    run(&mut port, vec![], false);
    (port, texts)
}

fn typed(s: &str) -> Vec<egui::Event> {
    vec![egui::Event::Text(s.into())]
}

fn select_all() -> egui::Event {
    egui::Event::Key { key: egui::Key::A, physical_key: None, pressed: true, repeat: false, modifiers: egui::Modifiers::COMMAND }
}

#[test]
fn port_field_takes_a_typed_port() {
    let (port, _) = edit_port(443, vec![select_all(), egui::Event::Text("8443".into())]);
    assert_eq!(port, 8443);
}

#[test]
fn port_field_rejects_too_big_instead_of_clamping() {
    let (port, texts) = edit_port(443, typed("8443")); // appended: 4438443
    assert_eq!(port, 443);
    assert!(texts.iter().any(|t| t.contains("1 to 65535")), "{texts:?}");
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
