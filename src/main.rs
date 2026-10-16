//! archway-vpn - FortiGate IPsec (IKEv2) + SAML SSO client for Linux, egui front-end.
//! SAML is native Rust (saml.rs/tls.rs); IKEv2 and the XFRM SAs are done by a private strongSwan charon (charon.rs,
//! vici.rs); the xfrm interface, routes and DNS are set up over netlink and D-Bus (tunnel.rs, netlink.rs, resolved.rs).
//! The same binary is the privileged backend: `pkexec archway-vpn --backend` (see backend.rs).

mod backend;
mod charon;
mod config;
mod form;
mod keyring;
mod net;
mod netlink;
mod privdrop;
mod protocol;
mod resolved;
mod saml;
mod theme;
mod tls;
mod tunnel;
mod vici;
mod view;

#[cfg(test)]
mod app_tests;

use backend::{Event, Session};
use config::*;
use eframe::egui::{self, RichText};
use form::{DraftOwner, Field};
use net::{ClientUid, Ipv4Net};
use protocol::BackendEvent;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Instant;

/// rustc-style message: "<level>: <headline>" plus a `note` (the cause) and a `help` (what now) line.
pub fn diag(level: &str, headline: &str, note: &str, help: &str) -> String {
    format!("{level}: {headline}\n  note: {note}\n  help: {help}")
}

const UID_HELP: &str = "Identifies this installation to the FortiGate, like the UID FortiClient generates at install. The app sends it with the SSO login and uses it as the EAP identity. The FortiGate may track devices by it, so only regenerate it if this setup was copied from another machine. Shared connection files don't include it.";
const SHARE_HELP: &str = "Shows this connection's file in your file manager. Send the file to a colleague, who puts it in their profiles folder and restarts the app. The PSK and password aren't in the file.";

const FIX_FIRST: &str = "Fix the fields marked ⚠ first.";

/// Something the user must fix before Save (and, when it's the selected profile's or the app settings', Connect).
struct Problem {
    owner: DraftOwner,
    message: String,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum State {
    Idle,
    Authenticating,
    Elevating,
    Negotiating,
    Connected,
    Disconnecting,
}

impl State {
    fn label(self) -> &'static str {
        match self {
            State::Idle => "Disconnected",
            State::Authenticating => "Waiting for SSO login in your browser…",
            State::Elevating => "Waiting for root authorization…",
            State::Negotiating => "Negotiating IKEv2…",
            State::Connected => "Connected",
            State::Disconnecting => "Disconnecting…",
        }
    }
}

#[derive(Default, Clone)]
struct TunnelInfo {
    username: String,
    ip: Option<Ipv4Addr>,
    routes: Vec<Ipv4Net>,
    full_tunnel: bool,
    saml_url: String,
}

struct App {
    cfg: Config,
    saved: Config,
    /// text typed into fields that differs from the typed value (see form.rs)
    drafts: form::Drafts,
    save_error: Option<String>,
    /// None: no Secret Service this session, secrets stay in memory (see `keyring_warning`)
    keyring: Option<Box<dyn keyring::SecretStore>>,
    keyring_warning: Option<String>,
    /// "Unsaved changes" dialog is open
    confirm_close: bool,
    /// the user chose Save or Discard; let the next close request through
    allow_close: bool,
    state: State,
    session: Option<Session>,
    profile_connected: usize,
    tx: Sender<Event>,
    rx: Receiver<Event>,
    log: Vec<String>,
    error: Option<String>,
    info: TunnelInfo,
    since: Option<Instant>,
    /// when Connect was clicked; drives the "no answer yet" notice
    connect_started: Option<Instant>,
    /// when the login link was copied; shows "✔ Copied" for a moment
    copied_at: Option<Instant>,
    /// SSO login finished in the browser: flash the taskbar entry once (Wayland won't let us raise the window)
    want_attention: bool,
    show_settings: bool,
    /// "Regenerate client UID?" dialog is open
    confirm_regen: bool,
    /// Open folder failed; shown on the settings page until the next success
    settings_error: Option<String>,
    share_error: Option<String>,
    confirm_delete: bool,
    stats: (u64, u64),
    stats_at: Option<Instant>,
}

impl App {
    fn new() -> Self {
        let keyring = keyring::SecretServiceStore::connect().map(|s| Box::new(s) as Box<dyn keyring::SecretStore>);
        Self::with_keyring(Config::load(), keyring)
    }

    fn with_keyring(mut cfg: Config, keyring: Result<Box<dyn keyring::SecretStore>, keyring::Unavailable>) -> Self {
        let (keyring, keyring_warning) = match keyring {
            Ok(s) => (Some(s), None),
            Err(u) => (None, Some(u.message())),
        };
        let mut startup_errors = std::mem::take(&mut cfg.load_errors);
        startup_errors.extend(keyring.as_deref().map(|s| keyring::fill(s, &mut cfg)).unwrap_or_default());
        let saved = cfg.clone();
        cfg.dedupe_ids(); // after `saved`: a profile that got a new id is unsaved, Save stores its secrets under it
        let (tx, rx) = channel();
        let mut app = App {
            saved,
            cfg,
            drafts: form::Drafts::default(),
            save_error: None,
            keyring,
            keyring_warning,
            confirm_close: false,
            allow_close: false,
            state: State::Idle,
            session: None,
            profile_connected: 0,
            tx,
            rx,
            log: Vec::new(),
            error: None,
            info: TunnelInfo::default(),
            since: None,
            connect_started: None,
            copied_at: None,
            want_attention: false,
            show_settings: false,
            confirm_regen: false,
            settings_error: None,
            share_error: None,
            confirm_delete: false,
            stats: (0, 0),
            stats_at: None,
        };
        if !config_path().exists() {
            app.save(); // writes the generated UID on first start
        }
        // after the first-start save, which would clear them
        startup_errors.extend(app.save_error.take());
        app.save_error = (!startup_errors.is_empty()).then(|| startup_errors.join("\n"));
        app
    }

    /// Changed settings, text in a field that doesn't parse (valid text is already in `cfg`), or a profile file in an
    /// older format.
    fn unsaved(&self) -> bool {
        !self.cfg.settings_eq(&self.saved) || !self.draft_problems().is_empty() || !self.cfg.outdated.is_empty()
    }

    /// Text that doesn't parse, in fields that are in use (see `Field::in_use`).
    fn draft_problems(&self) -> Vec<Problem> {
        self.drafts
            .errors()
            .filter(|((owner, field), _)| match owner {
                DraftOwner::Profile(id) => self.cfg.profiles.iter().find(|p| &p.id == id).is_none_or(|p| field.in_use(p)),
                DraftOwner::App => true,
            })
            .map(|((owner, field), e)| Problem { owner: owner.clone(), message: format!("{}: {e}", field.label()) })
            .collect()
    }

    /// Everything that blocks Save: text that doesn't parse, profile problems, clashing names.
    fn problems(&self) -> Vec<Problem> {
        let mut v = self.draft_problems();
        for (p, why) in self.cfg.profiles.iter().zip(self.cfg.name_problems()) {
            let owner = DraftOwner::Profile(p.id.clone());
            v.extend(why.map(|w| Problem { owner: owner.clone(), message: format!("{}: {w}", Field::Name.label()) }));
            v.extend(p.problems().into_iter().map(|m| Problem { owner: owner.clone(), message: m.into() }));
        }
        v
    }

    /// Connect needs the selected profile and the app settings to be fine; other profiles don't matter.
    fn blocks_connect(&self, problems: &[Problem]) -> bool {
        let selected = DraftOwner::Profile(self.cfg.profiles[self.cfg.selected].id.clone());
        problems.iter().any(|p| p.owner == selected || p.owner == DraftOwner::App)
    }

    /// Save button: write the settings files, then bring the keyring in line with them.
    fn save(&mut self) {
        let name_errors = self.cfg.name_errors();
        if !name_errors.is_empty() {
            self.save_error = Some(name_errors.join("\n"));
            return;
        }
        let problems = self.problems();
        if !problems.is_empty() {
            let list = problems.iter().map(|p| p.message.as_str()).collect::<Vec<_>>().join(" ");
            self.save_error = Some(diag("error", "the settings can't be saved", &list, "fix the fields marked ⚠ and click Save"));
            return;
        }
        if let Err(e) = self.cfg.save(&self.saved) {
            self.save_error = Some(diag(
                "error",
                "the settings couldn't be saved",
                &e,
                &format!("check that {} is writable and click Save to try again", Paths::from_env().config_dir.display()),
            ));
            return;
        }
        self.save_error = None;
        self.share_error = None; // the file it was about may have changed
        self.cfg.outdated.clear(); // rewritten
        match self.keyring.as_deref() {
            Some(store) => {
                let ops = keyring::plan(&self.saved, &self.cfg);
                let (next, errors) = keyring::apply(store, &ops, &self.saved, &self.cfg);
                self.saved = next;
                self.cfg.orphans = self.saved.orphans.clone();
                if !errors.is_empty() {
                    self.save_error = Some(errors.join("\n"));
                }
            }
            None => self.saved = self.cfg.clone(),
        }
    }

    /// Ask before closing with unsaved changes.
    fn close_guard(&mut self, ctx: &egui::Context) {
        if ctx.input(|i| i.viewport().close_requested()) && !self.allow_close && self.unsaved() {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.confirm_close = true;
        }
        if !self.confirm_close {
            return;
        }
        egui::Window::new("Unsaved changes")
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label("Save your changes before closing?");
                if let Some(e) = &self.save_error {
                    ui.label(RichText::new(e).monospace().color(ui.visuals().error_fg_color));
                }
                ui.horizontal(|ui| {
                    if ui.add_enabled(self.problems().is_empty(), egui::Button::new("Save")).on_disabled_hover_text(FIX_FIRST).clicked() {
                        self.save();
                        // on failure the dialog stays open with the error; Discard still closes
                        if !self.unsaved() {
                            self.confirm_close = false;
                            self.allow_close = true;
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    }
                    if ui.button("Discard").clicked() {
                        self.confirm_close = false;
                        self.allow_close = true;
                        ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    }
                    if ui.button("Cancel").clicked() {
                        self.confirm_close = false;
                    }
                });
            });
    }

    /// Regenerate button: ask first, the FortiGate will see a new device.
    fn ask_regenerate_uid(&mut self) {
        self.confirm_regen = true;
    }

    /// Answer to "Regenerate client UID?". The new UID is stored on Save, like any other change.
    fn regenerate_uid(&mut self, confirmed: bool) {
        if confirmed {
            match ClientUid::generate() {
                Ok(u) => {
                    self.cfg.uid = u;
                    self.drafts.remove(&(DraftOwner::App, Field::Uid));
                }
                Err(e) => self.settings_error = Some(diag("error", "a new client UID couldn't be generated", &e, "try again")),
            }
        }
        self.confirm_regen = false;
    }

    /// Open folder button.
    fn open_from_settings(&mut self, path: &Path, headline: &str) {
        self.settings_error = opener::open(path).err().map(|e| diag("error", headline, &e.to_string(), &format!("open it yourself: {}", path.display())));
    }

    /// Share button: show the selected profile's file in the file manager.
    fn share_profile(&mut self) {
        let file = Paths::from_env().profile_file(self.cfg.profiles[self.cfg.selected].name.as_str());
        self.share_error = opener::reveal(&file).err().map(|e| diag("error", "the connection file couldn't be shown", &e.to_string(),
            &format!("open it yourself: {}", file.display())));
    }

    fn push_log(&mut self, line: String) {
        // one row per line: the log panel draws only the rows in view, which needs them all the same height
        self.log.extend(line.lines().map(str::to_owned));
        if self.log.len() > 5000 {
            self.log.drain(..1000);
        }
    }

    /// Add `p` under a name no other connection has, and select it.
    fn add_profile(&mut self, mut p: Profile) {
        p.name = self.cfg.unique_name(&p.name);
        self.cfg.profiles.push(p);
        self.cfg.selected = self.cfg.profiles.len() - 1;
    }

    fn busy(&self) -> bool {
        self.state != State::Idle
    }

    fn connect(&mut self, ctx: &egui::Context) {
        self.error = None;
        self.info = TunnelInfo::default();
        self.since = None;
        self.connect_started = Some(Instant::now());
        self.profile_connected = self.cfg.selected;
        let p = self.cfg.profiles[self.cfg.selected].clone();
        self.push_log(format!("=== connecting \"{}\" ({}) ===", p.name, gateway_text(&p)));
        // without SSO there is no browser step: go straight to the root prompt
        self.state = if p.sso.enabled { State::Authenticating } else { State::Elevating };
        self.session = Some(Session::start(&self.cfg, &p, self.tx.clone(), ctx.clone()));
    }

    fn disconnect(&mut self) {
        if let Some(s) = &self.session {
            s.disconnect();
            self.state = State::Disconnecting;
        }
    }

    fn handle_events(&mut self) {
        while let Ok(ev) = self.rx.try_recv() {
            match ev {
                Event::Log(l) => self.push_log(l),
                Event::Elevating => self.state = State::Elevating,
                Event::Error(e) => {
                    self.push_log(format!("ERROR: {e}"));
                    if self.error.is_none() {
                        self.error = Some(connect_error(e));
                    }
                }
                Event::Finished => {
                    self.state = State::Idle;
                    self.session = None;
                    self.since = None;
                    self.push_log("=== disconnected ===".into());
                }
                Event::Backend(ev) => self.on_backend(ev),
            }
        }
    }

    fn on_backend(&mut self, ev: BackendEvent) {
        match ev {
            BackendEvent::SamlUrl { url } => self.info.saml_url = url,
            BackendEvent::SamlOk { username } => {
                self.info.username = username;
                self.want_attention = true;
            }
            BackendEvent::IkeStart { .. } => self.state = State::Negotiating,
            BackendEvent::TunnelUp { ip, routes, full_tunnel, .. } => {
                self.info.ip = Some(ip);
                self.info.routes = routes;
                self.info.full_tunnel = full_tunnel;
            }
            BackendEvent::Connected => {
                self.state = State::Connected;
                self.since = Some(Instant::now());
            }
            BackendEvent::Disconnecting => self.state = State::Disconnecting,
            // the backend logged it already
            BackendEvent::Error { message } => self.error = Some(connect_error(message)),
            // nothing to show: the state already says it, or Finished follows
            BackendEvent::SamlStart | BackendEvent::Established { .. } | BackendEvent::Disconnected => {}
        }
    }

    fn read_stats(&mut self) {
        if self.state != State::Connected {
            return;
        }
        if self.stats_at.is_none_or(|t| t.elapsed().as_millis() > 900) {
            let ifn = &self.cfg.profiles[self.profile_connected].network.ifname;
            let rd = |f: &str| {
                std::fs::read_to_string(format!("/sys/class/net/{ifn}/statistics/{f}"))
                    .ok()
                    .and_then(|s| s.trim().parse().ok())
                    .unwrap_or(0)
            };
            self.stats = (rd("rx_bytes"), rd("tx_bytes"));
            self.stats_at = Some(Instant::now());
        }
    }
}

/// A connect error as the app shows errors (see `diag`): messages that aren't in that form yet become its note.
fn connect_error(message: String) -> String {
    if message.starts_with("error: ") { message } else { diag("error", "couldn't connect", &message, "the log has the details") }
}

/// The profile's gateway for messages, empty if it has none.
fn gateway_text(p: &Profile) -> String {
    p.gateway.as_ref().map_or_else(String::new, ToString::to_string)
}

impl eframe::App for App {
    fn ui(&mut self, root: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = root.ctx().clone();
        self.handle_events();
        let problems = self.problems();
        if std::mem::take(&mut self.want_attention) {
            ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(egui::UserAttentionType::Informational));
        }
        self.read_stats();
        if self.busy() {
            ctx.request_repaint_after(std::time::Duration::from_secs(1));
        }
        let save_key = egui::KeyboardShortcut::new(egui::Modifiers::COMMAND, egui::Key::S);
        if ctx.input_mut(|i| i.consume_shortcut(&save_key)) && self.unsaved() && problems.is_empty() {
            self.save();
        }

        theme::install(&ctx);
        self.top_bar(root, &problems, &save_key);
        self.connection_list(root, &problems);
        self.log_drawer(root);
        self.main_view(root, &problems);
        self.dialogs(&ctx);
        self.close_guard(&ctx);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        if let Some(s) = self.session.take() {
            s.shutdown(std::time::Duration::from_secs(8));
        }
    }
}

fn main() -> eframe::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("--version" | "-V") => {
            println!("archway-vpn {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Some("--backend") => std::process::exit(backend::privileged_main()),
        _ => {}
    }
    // RUST_LOG=info/debug shows renderer / windowing backend diagnostics (eframe, egui_glow, winit, glutin)
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Archway")
            .with_app_id("archway-vpn")
            // X11 shows this; Wayland takes the icon from the installed archway-vpn.desktop (matched by app id)
            .with_icon(eframe::icon_data::from_png_bytes(include_bytes!("../assets/archway-vpn-256.png")).expect("valid icon png"))
            .with_inner_size([1000.0, 760.0])
            .with_min_inner_size([760.0, 520.0]),
        ..Default::default()
    };
    eframe::run_native("Archway", opts, Box::new(|cc| {
        theme::install(&cc.egui_ctx);
        Ok(Box::new(App::new()))
    }))
}
