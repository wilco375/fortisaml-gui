//! fortisaml-gui - FortiGate IPsec (IKEv2) + SAML SSO client for Linux, egui front-end.
//! SAML is native Rust (saml.rs/tls.rs); IKEv2 and the XFRM SAs are done by a private strongSwan charon (charon.rs,
//! vici.rs); the xfrm interface, routes and DNS are set up over netlink and D-Bus (tunnel.rs, netlink.rs, resolved.rs).
//! The same binary is the privileged backend: `pkexec fortisaml-gui --backend` (see backend.rs).

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
mod tls;
mod tunnel;
mod vici;

#[cfg(test)]
mod app_tests;

use backend::{Event, Session};
use config::*;
use form::{DraftOwner, Field, Look};
use protocol::BackendEvent;
use net::{ClientUid, DhGroup, Encryption, Hash, Ipv4Net, Keepalive, LoginTimeout, Mtu, Proposal};
use eframe::egui::{self, Color32, RichText};
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
    /// Open folder failed; shown in the settings window until the next success
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

    /// Text that doesn't parse, in fields that are in use (see `field_in_use`).
    fn draft_problems(&self) -> Vec<Problem> {
        self.drafts
            .errors()
            .filter(|((owner, field), _)| match owner {
                DraftOwner::Profile(id) => self.cfg.profiles.iter().find(|p| &p.id == id).is_none_or(|p| field_in_use(p, *field)),
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
        self.log.push(line);
        if self.log.len() > 5000 {
            self.log.drain(..1000);
        }
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
                        self.error = Some(e);
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
            BackendEvent::Error { message } => {
                self.push_log(format!("ERROR: {message}"));
                self.error = Some(message);
            }
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

fn human(b: u64) -> String {
    let u = ["B", "KB", "MB", "GB", "TB"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < u.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", u[i])
}

fn proposal_rows(ui: &mut egui::Ui, id: &str, props: &mut Vec<Proposal>) {
    let mut remove = None;
    egui::Grid::new(id).num_columns(3).spacing([12.0, 6.0]).show(ui, |ui| {
        ui.label(RichText::new("Encryption").weak());
        ui.label(RichText::new("Authentication").weak());
        ui.end_row();
        for (i, p) in props.iter_mut().enumerate() {
            egui::ComboBox::from_id_salt((id, i, "enc")).selected_text(p.enc.to_string()).show_ui(ui, |ui| {
                for e in Encryption::ALL {
                    ui.selectable_value(&mut p.enc, e, e.to_string());
                }
            });
            egui::ComboBox::from_id_salt((id, i, "hash")).selected_text(p.hash.to_string()).show_ui(ui, |ui| {
                for h in Hash::ALL {
                    ui.selectable_value(&mut p.hash, h, h.to_string());
                }
            });
            if ui.small_button("✖").on_hover_text("remove proposal").clicked() {
                remove = Some(i);
            }
            ui.end_row();
        }
    });
    if let Some(i) = remove {
        props.remove(i);
    }
    if props.len() < 4 && ui.small_button("➕ Add proposal").clicked() {
        props.push(Proposal { enc: Encryption::Aes256, hash: Hash::Sha256 });
    }
}

/// DragValue for a range-limited setting: the widget's range keeps the value valid.
fn ranged<T: Copy + Into<u16> + TryFrom<u16>>(ui: &mut egui::Ui, value: &mut T, range: std::ops::RangeInclusive<u16>) -> egui::Response {
    let mut v: u16 = (*value).into();
    let r = ui.add(egui::DragValue::new(&mut v).range(range));
    if let Ok(t) = T::try_from(v) {
        *value = t;
    }
    r
}

/// Whether profile `p` uses field `f` in its current mode. Text that doesn't parse in a field it doesn't use (the
/// username while SSO is on, custom routes outside Custom routing) blocks nothing; it's kept, and counts again once
/// the mode uses the field.
fn field_in_use(p: &Profile, f: Field) -> bool {
    match f {
        Field::Username => !p.sso.enabled && p.auth.mode == UserAuth::Eap,
        Field::SsoPort => p.sso.enabled,
        Field::CustomRoutes => p.network.route_mode == RouteMode::Custom,
        _ => true,
    }
}

/// The profile's gateway for messages, empty if it has none.
fn gateway_text(p: &Profile) -> String {
    p.gateway.as_ref().map_or_else(String::new, ToString::to_string)
}

fn section(ui: &mut egui::Ui, title: &str, open: bool, body: impl FnOnce(&mut egui::Ui)) {
    egui::CollapsingHeader::new(RichText::new(title).strong()).default_open(open).show(ui, body);
}

fn form_row(ui: &mut egui::Ui, label: &str, body: impl FnOnce(&mut egui::Ui)) {
    ui.label(label);
    body(ui);
    ui.end_row();
}

impl App {
    fn profile_editor(&mut self, ui: &mut egui::Ui) {
        let keyring_warning = self.keyring_warning.clone();
        let name_problem = self.cfg.name_problems()[self.cfg.selected];
        let drafts = &mut self.drafts;
        let p = &mut self.cfg.profiles[self.cfg.selected];
        let owner = DraftOwner::Profile(p.id.clone());
        let key = |f: Field| (owner.clone(), f);

        section(ui, "Connection", true, |ui| {
            egui::Grid::new("general").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
                form::row(ui, "Connection name", |ui| {
                    form::parsed(ui, drafts, key(Field::Name), &mut p.name, Look { warning_elsewhere: true, ..Look::default() });
                    // a clash with another profile isn't a parse error; shown the same way
                    drafts.error(&key(Field::Name)).or(name_problem).map(str::to_owned)
                });
                form::row(ui, "Description", |ui| {
                    form::parsed(ui, drafts, key(Field::Description), &mut p.description, Look { warning_elsewhere: true, ..Look::default() });
                    drafts.error(&key(Field::Description)).map(str::to_owned)
                });
                form::row(ui, "Remote gateway", |ui| {
                    form::parsed_opt(ui, drafts, key(Field::Gateway), &mut p.gateway, Look { hint: "vpn.example.com", warning_elsewhere: true, ..Look::default() });
                    drafts.error(&key(Field::Gateway)).map(str::to_owned)
                });
                form_row(ui, "Pre-shared key", |ui| {
                    ui.add(egui::TextEdit::singleline(&mut p.psk).password(true));
                });
            });
            if let Some(w) = &keyring_warning {
                ui.label(RichText::new(w).monospace().color(ui.visuals().warn_fg_color));
            }
        });

        section(ui, "Authentication", true, |ui| {
            ui.checkbox(&mut p.sso.enabled, "Enable Single Sign On (SSO) for VPN Tunnel");
            ui.add_space(4.0);
            if p.sso.enabled {
                egui::Grid::new("sso").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
                    form::row(ui, "Customize port", |ui| {
                        form::parsed(ui, drafts, key(Field::SsoPort), &mut p.sso.port, Look { warning_elsewhere: true, ..Look::PORT }).on_hover_text("FortiGate 'auth-ike-saml-port'");
                        drafts.error(&key(Field::SsoPort)).map(str::to_owned)
                    });
                    form_row(ui, "", |ui| {
                        ui.checkbox(&mut p.sso.open_browser, "Open the login page in the browser automatically");
                    });
                    form_row(ui, "", |ui| {
                        ui.checkbox(&mut p.sso.verify_cert, "Verify the server certificate on the SSO port");
                    });
                    form_row(ui, "Login timeout (s)", |ui| {
                        ranged(ui, &mut p.sso.timeout, LoginTimeout::RANGE);
                    });
                });
            } else {
                egui::Grid::new("userauth").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
                    form_row(ui, "User authentication", |ui| {
                        ui.vertical(|ui| {
                            ui.radio_value(&mut p.auth.mode, UserAuth::Eap, "Username and password (EAP)");
                            ui.radio_value(&mut p.auth.mode, UserAuth::None, "None (pre-shared key only)");
                        });
                    });
                    if p.auth.mode == UserAuth::Eap {
                        form::row(ui, "Username", |ui| {
                            form::parsed_opt(ui, drafts, key(Field::Username), &mut p.auth.username, Look { warning_elsewhere: true, ..Look::default() });
                            drafts.error(&key(Field::Username)).map(str::to_owned)
                        });
                        form_row(ui, "Password", |ui| {
                            ui.add(egui::TextEdit::singleline(&mut p.auth.password).password(true));
                        });
                        form_row(ui, "", |ui| {
                            ui.checkbox(&mut p.auth.save_password, "Save password")
                                .on_hover_text("Unchecked: the password is only kept in memory until the app is closed");
                        });
                    }
                });
            }
        });

        section(ui, "VPN settings", false, |ui| {
            egui::Grid::new("vpn").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
                form_row(ui, "IKE", |ui| {
                    ui.label("Version 2");
                });
                form_row(ui, "Address assignment", |ui| {
                    ui.label("Mode Config");
                });
                form::row(ui, "Encapsulation", |ui| {
                    ui.horizontal(|ui| {
                        ui.label("IKE UDP port");
                        form::parsed(ui, drafts, key(Field::IkePort), &mut p.ike.port, Look { warning_elsewhere: true, ..Look::PORT });
                    });
                    drafts.error(&key(Field::IkePort)).map(str::to_owned)
                });
            });
        });

        section(ui, "Phase 1", false, |ui| {
            proposal_rows(ui, "p1", &mut p.ike.proposals);
            if p.ike.proposals.is_empty() {
                form::warning(ui, config::NO_P1_PROPOSAL);
            }
            ui.add_space(6.0);
            ui.label("DH group");
            ui.horizontal_wrapped(|ui| {
                for g in DH_UNSUPPORTED.iter().take(3) {
                    ui.add_enabled(false, egui::Checkbox::new(&mut false, g.to_string()))
                        .on_disabled_hover_text("not supported by this client");
                }
                for g in DhGroup::ALL {
                    let mut on = p.ike.dh_groups.contains(&g);
                    if ui.checkbox(&mut on, g.to_string()).changed() {
                        if on {
                            p.ike.dh_groups.push(g);
                            p.ike.dh_groups.sort_by_key(|g| u16::from(*g));
                        } else {
                            p.ike.dh_groups.retain(|x| *x != g);
                        }
                    }
                }
            });
            if p.ike.dh_groups.is_empty() {
                form::warning(ui, config::NO_DH_GROUP);
            }
            egui::Grid::new("p1b").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
                form::row(ui, "Local ID", |ui| {
                    form::parsed_opt(ui, drafts, key(Field::LocalId), &mut p.ike.local_id, Look { hint: "Optional (default: local IP)", warning_elsewhere: true, ..Look::default() });
                    drafts.error(&key(Field::LocalId)).map(str::to_owned)
                });
                form_row(ui, "NAT-T keepalive (s)", |ui| {
                    ranged(ui, &mut p.ike.natt_keepalive, Keepalive::RANGE);
                });
            });
        });

        section(ui, "Phase 2", false, |ui| {
            proposal_rows(ui, "p2", &mut p.esp.proposals);
            if p.esp.proposals.is_empty() {
                form::warning(ui, config::NO_P2_PROPOSAL);
            }
        });

        section(ui, "Network", false, |ui| {
            egui::Grid::new("net").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
                form_row(ui, "Routing", |ui| {
                    ui.vertical(|ui| {
                        ui.radio_value(&mut p.network.route_mode, RouteMode::Gateway, "As pushed by the FortiGate");
                        ui.radio_value(&mut p.network.route_mode, RouteMode::Full, "All traffic through the VPN");
                        ui.radio_value(&mut p.network.route_mode, RouteMode::Custom, "Only these networks:");
                        if p.network.route_mode == RouteMode::Custom {
                            form::text_field(
                                ui,
                                drafts,
                                key(Field::CustomRoutes),
                                &mut p.network.custom_routes,
                                Look { hint: "10.0.0.0/8\n192.168.10.0/24", multiline: true, ..Look::default() },
                                |v| v.iter().map(ToString::to_string).collect::<Vec<_>>().join("\n"),
                                Ipv4Net::parse_list,
                            );
                            if p.network.custom_routes.is_empty() && drafts.error(&key(Field::CustomRoutes)).is_none() {
                                form::warning(ui, config::NO_ROUTES);
                            }
                        }
                    });
                });
                form_row(ui, "", |ui| {
                    ui.checkbox(&mut p.network.set_dns, "Use DNS servers from the VPN (systemd-resolved)");
                });
                form_row(ui, "", |ui| {
                    ui.checkbox(&mut p.network.block_ipv6, "Block IPv6 while all traffic goes through the VPN");
                });
                form::row(ui, "Interface name", |ui| {
                    form::parsed(ui, drafts, key(Field::IfName), &mut p.network.ifname, Look { warning_elsewhere: true, ..Look::default() });
                    drafts.error(&key(Field::IfName)).map(str::to_owned)
                });
                form_row(ui, "MTU", |ui| {
                    ranged(ui, &mut p.network.mtu, Mtu::RANGE);
                });
            });
        });
    }

    fn settings_window(&mut self, ctx: &egui::Context) {
        let mut open = self.show_settings;
        let hint = |ui: &mut egui::Ui, text: &str| {
            ui.label(RichText::new(text).weak().small());
        };
        egui::Window::new("Settings").open(&mut open).resizable(true).show(ctx, |ui| {
            egui::Grid::new("settings").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
                // form_row by hand: the label gets the explanation too
                ui.label("Client UID").on_hover_text(UID_HELP);
                ui.vertical(|ui| {
                    ui.horizontal(|ui| {
                        form::parsed(ui, &mut self.drafts, (DraftOwner::App, Field::Uid), &mut self.cfg.uid, Look { width: Some(290.0), monospace: true, ..Look::default() })
                            .on_hover_text(UID_HELP);
                        if ui.button("Regenerate").clicked() {
                            self.ask_regenerate_uid();
                        }
                    });
                    hint(ui, "Identifies this installation to the FortiGate.");
                });
                ui.end_row();
                form_row(ui, "", |ui| {
                    ui.vertical(|ui| {
                        ui.checkbox(&mut self.cfg.verbose, "Verbose backend logging (keys are always redacted)");
                        hint(ui, "Adds IKE protocol detail to the log, for troubleshooting.");
                    });
                });
                form_row(ui, "Settings folder", |ui| {
                    ui.horizontal(|ui| {
                        let dir = Paths::from_env().config_dir;
                        ui.add(egui::Label::new(RichText::new(dir.display().to_string()).monospace()).selectable(true));
                        if ui.button("📂 Open folder").clicked() {
                            match std::fs::create_dir_all(&dir) {
                                Ok(()) => self.open_from_settings(&dir, "the settings folder couldn't be opened"),
                                Err(e) => self.settings_error = Some(diag("error", "the settings folder couldn't be opened", &e.to_string(),
                                    &format!("open it yourself: {}", dir.display()))),
                            }
                        }
                    });
                });
            });
            if let Some(e) = &self.settings_error {
                ui.label(RichText::new(e).monospace().color(ui.visuals().error_fg_color));
            }
        });
        if !open {
            self.settings_error = None;
        }
        self.show_settings = open;

        if self.confirm_regen {
            let modal = egui::Modal::new(egui::Id::new("regenerate_uid")).show(ctx, |ui| {
                ui.heading("Regenerate client UID?");
                ui.label("The FortiGate will see this installation as a new device. The new UID is used after you click Save.");
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Regenerate").clicked() {
                        self.regenerate_uid(true);
                    }
                    if ui.button("Cancel").clicked() {
                        self.regenerate_uid(false);
                    }
                });
            });
            // Escape or a click outside counts as Cancel
            if self.confirm_regen && modal.should_close() {
                self.regenerate_uid(false);
            }
        }
    }
}

impl eframe::App for App {
    fn ui(&mut self, root: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = &root.ctx().clone();
        self.handle_events();
        let problems = self.problems();
        if std::mem::take(&mut self.want_attention) {
            ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(egui::UserAttentionType::Informational));
        }
        self.read_stats();
        if self.state == State::Connected || self.busy() {
            ctx.request_repaint_after(std::time::Duration::from_secs(1));
        }
        let save_key = egui::KeyboardShortcut::new(egui::Modifiers::COMMAND, egui::Key::S);
        if ctx.input_mut(|i| i.consume_shortcut(&save_key)) && self.unsaved() && problems.is_empty() {
            self.save();
        }

        egui::Panel::top("top").show(root, |ui| {
            ui.horizontal(|ui| {
                ui.heading("FortiSAML VPN");
                ui.label(RichText::new("IPsec IKEv2 + SAML SSO").weak());
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("⚙ Settings").clicked() {
                        self.show_settings = !self.show_settings;
                    }
                    ui.toggle_value(&mut self.cfg.show_log, "📜 Log");
                    let shortcut = ctx.format_shortcut(&save_key);
                    if self.unsaved() && problems.is_empty() {
                        let b = egui::Button::new(RichText::new("💾 Save changes").strong().color(Color32::WHITE))
                            .fill(ui.visuals().selection.bg_fill);
                        if ui.add(b).on_hover_text(format!("Save the settings ({shortcut})")).clicked() {
                            self.save();
                        }
                    } else if self.unsaved() {
                        ui.add_enabled(false, egui::Button::new("💾 Save changes")).on_disabled_hover_text(FIX_FIRST);
                    } else {
                        ui.add_enabled(false, egui::Button::new("✔ Saved")).on_disabled_hover_text("No unsaved changes");
                    }
                });
            });
        });

        // ---- connection list ----
        egui::Panel::left("profiles").resizable(true).default_size(200.0).show(root, |ui| {
            ui.add_space(4.0);
            ui.label(RichText::new("VPN connections").strong());
            ui.separator();
            let busy = self.busy();
            // the buttons wrap in a narrow panel; the list above them scrolls, so they stay reachable with many profiles
            egui::Panel::bottom("profile_buttons").frame(egui::Frame::NONE).show_separator_line(false).show(ui, |ui| {
                ui.add_space(8.0);
                ui.horizontal_wrapped(|ui| {
                    if ui.add_enabled(!busy, egui::Button::new("➕ New")).clicked() {
                        let mut p = Profile::default();
                        p.name = self.cfg.unique_name(&p.name);
                        self.cfg.profiles.push(p);
                        self.cfg.selected = self.cfg.profiles.len() - 1;
                    }
                    if ui.add_enabled(!busy, egui::Button::new("🗐 Copy")).clicked() {
                        let mut p = self.cfg.profiles[self.cfg.selected].duplicate();
                        p.name = self.cfg.unique_name(&p.name);
                        self.cfg.profiles.push(p);
                        self.cfg.selected = self.cfg.profiles.len() - 1;
                    }
                    // also while connected: it only shows the saved file
                    let unsaved = self.unsaved();
                    let share = ui.add_enabled(!unsaved, egui::Button::new("🔗 Share"))
                        .on_disabled_hover_text("Save first, so the file matches what you see.")
                        .on_hover_text(SHARE_HELP);
                    if share.clicked() {
                        self.share_profile();
                    }
                    if self.cfg.profiles.len() > 1 {
                        if !self.confirm_delete {
                            if ui.add_enabled(!busy, egui::Button::new("🗑 Delete")).clicked() {
                                self.confirm_delete = true;
                            }
                        } else if ui.add_enabled(!busy, egui::Button::new(RichText::new("Confirm delete").color(Color32::RED))).clicked() {
                            let gone = self.cfg.profiles.remove(self.cfg.selected);
                            self.drafts.remove_owner(&DraftOwner::Profile(gone.id));
                            self.cfg.selected = self.cfg.selected.min(self.cfg.profiles.len() - 1);
                            self.confirm_delete = false;
                        }
                    }
                });
            });
            egui::ScrollArea::vertical().show(ui, |ui| {
                for i in 0..self.cfg.profiles.len() {
                    let p = &self.cfg.profiles[i];
                    let marked = problems.iter().any(|x| x.owner == DraftOwner::Profile(p.id.clone()));
                    let mut text = RichText::new(if marked { format!("⚠ {}", p.name) } else { p.name.to_string() });
                    if busy && i == self.profile_connected {
                        text = text.color(if self.state == State::Connected { Color32::from_rgb(60, 170, 90) } else { Color32::from_rgb(220, 160, 40) });
                    }
                    if ui.add_enabled(!busy, egui::Button::selectable(i == self.cfg.selected, text)).clicked() {
                        self.cfg.selected = i;
                        self.confirm_delete = false;
                    }
                }
            });
        });

        // ---- log ----
        if self.cfg.show_log {
            egui::Panel::bottom("log").resizable(true).default_size(170.0).show(root, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("Log").strong());
                    if ui.small_button("Copy").clicked() {
                        ctx.copy_text(self.log.join("\n"));
                    }
                    if ui.small_button("Clear").clicked() {
                        self.log.clear();
                    }
                });
                egui::ScrollArea::vertical().stick_to_bottom(true).auto_shrink([false, false]).show(ui, |ui| {
                    for l in &self.log {
                        let c = if l.starts_with("ERROR") { Color32::LIGHT_RED } else { ui.visuals().text_color() };
                        ui.label(RichText::new(l).monospace().size(11.5).color(c));
                    }
                });
            });
        }

        // ---- main ----
        egui::CentralPanel::default().show(root, |ui| {
            // status / connect bar
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                let col = match self.state {
                    State::Connected => Color32::from_rgb(60, 170, 90),
                    State::Idle => Color32::GRAY,
                    _ => Color32::from_rgb(220, 160, 40),
                };
                // painted, not a "●" label: the proportional fonts have no glyph for it
                let (rect, _) = ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::hover());
                ui.painter().circle_filled(rect.center(), 6.0, col);
                ui.label(RichText::new(self.state.label()).size(16.0));
                if self.busy() && self.state != State::Connected {
                    ui.spinner();
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let big = |t: &str| egui::Button::new(RichText::new(t).size(16.0)).min_size(egui::vec2(130.0, 32.0));
                    match self.state {
                        State::Idle => {
                            let blocked = self.blocks_connect(&problems);
                            if ui.add_enabled(!blocked, big("Connect")).on_disabled_hover_text(FIX_FIRST).clicked() {
                                self.connect(ctx);
                            }
                        }
                        State::Disconnecting => {
                            ui.add_enabled(false, big("Disconnect"));
                        }
                        State::Connected => {
                            if ui.add(big("Disconnect")).clicked() {
                                self.disconnect();
                            }
                        }
                        _ => {
                            if ui.add(big("Cancel")).clicked() {
                                self.disconnect();
                            }
                        }
                    }
                });
            });
            if let Some(e) = &self.error {
                if e.starts_with("error:") {
                    ui.label(RichText::new(e).monospace().color(ui.visuals().error_fg_color));
                } else {
                    ui.colored_label(Color32::LIGHT_RED, format!("⚠ {e}"));
                }
            }
            if let Some(e) = &self.save_error {
                ui.label(RichText::new(e).monospace().color(ui.visuals().error_fg_color));
            }
            if let Some(e) = &self.share_error {
                ui.label(RichText::new(e).monospace().color(ui.visuals().error_fg_color));
            }
            // also the ones in a collapsed section, another mode's field or the closed Settings window
            for p in &problems {
                let whose = match &p.owner {
                    DraftOwner::App => "Settings".to_string(),
                    DraftOwner::Profile(id) => self.cfg.profiles.iter().find(|x| &x.id == id).map_or_else(String::new, |x| x.name.to_string()),
                };
                form::warning(ui, &format!("{whose}: {}", p.message));
            }
            if self.state == State::Authenticating && !self.info.saml_url.is_empty() {
                ui.add_space(4.0);
                ui.label(RichText::new("Finish signing in in your browser.").strong());
                ui.horizontal(|ui| {
                    if ui.button("🌐 Open login page").on_hover_text(&self.info.saml_url).clicked() {
                        ctx.open_url(egui::OpenUrl::new_tab(&self.info.saml_url));
                    }
                    let copied = self.copied_at.is_some_and(|t| t.elapsed().as_secs() < 2);
                    if ui.button(if copied { "✔ Copied" } else { "📋 Copy link" })
                        .on_hover_text("Paste it into the browser where you're signed in")
                        .clicked()
                    {
                        ctx.copy_text(self.info.saml_url.clone());
                        self.copied_at = Some(Instant::now());
                    }
                    if copied {
                        ctx.request_repaint_after(std::time::Duration::from_millis(500));
                    }
                });
            } else if self.state == State::Elevating {
                ui.add_space(4.0);
                ui.label(RichText::new("🔒 Enter your password in the system prompt.").strong());
                ui.label("Setting up the VPN tunnel needs administrator rights.");
            } else if self.state == State::Authenticating && self.connect_started.is_some_and(|t| t.elapsed().as_secs() >= 5) {
                let p = &self.cfg.profiles[self.profile_connected];
                ui.label(
                    RichText::new(format!("⏳ No answer from {}:{} yet. The SSO port may be wrong.", gateway_text(p), p.sso.port))
                        .color(ui.visuals().warn_fg_color),
                );
            }
            ui.separator();

            if self.busy() {
                let p = &self.cfg.profiles[self.profile_connected];
                egui::Grid::new("status").num_columns(2).spacing([20.0, 8.0]).show(ui, |ui| {
                    form_row(ui, "Connection", |ui| {
                        ui.label(RichText::new(p.name.as_str()).strong());
                    });
                    form_row(ui, "Gateway", |ui| {
                        ui.label(gateway_text(p));
                    });
                    if !self.info.username.is_empty() {
                        form_row(ui, "Username", |ui| {
                            ui.label(&self.info.username);
                        });
                    }
                    if let Some(ip) = self.info.ip {
                        form_row(ui, "IP address", |ui| {
                            ui.label(RichText::new(ip.to_string()).monospace());
                        });
                    }
                    if !self.info.routes.is_empty() {
                        form_row(ui, "Routes", |ui| {
                            ui.label(if self.info.full_tunnel {
                                "all traffic".to_string()
                            } else {
                                self.info.routes.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
                            });
                        });
                    }
                    if let Some(t) = self.since {
                        let s = t.elapsed().as_secs();
                        form_row(ui, "Duration", |ui| {
                            ui.label(format!("{:02}:{:02}:{:02}", s / 3600, s / 60 % 60, s % 60));
                        });
                        form_row(ui, "Bytes received", |ui| {
                            ui.label(human(self.stats.0));
                        });
                        form_row(ui, "Bytes sent", |ui| {
                            ui.label(human(self.stats.1));
                        });
                    }
                });
            } else {
                egui::ScrollArea::vertical().auto_shrink([false, false]).show(ui, |ui| {
                    self.profile_editor(ui);
                });
            }
        });

        self.settings_window(ctx);
        self.close_guard(ctx);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        if let Some(s) = self.session.take() {
            s.shutdown(std::time::Duration::from_secs(8));
        }
    }
}

fn main() -> eframe::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--backend") {
        std::process::exit(backend::privileged_main());
    }
    // RUST_LOG=info/debug shows renderer / windowing backend diagnostics (eframe, egui_glow, winit, glutin)
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();
    let opts = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("FortiSAML VPN")
            .with_app_id("fortisaml-gui")
            .with_inner_size([860.0, 680.0])
            .with_min_inner_size([640.0, 460.0]),
        ..Default::default()
    };
    eframe::run_native("FortiSAML VPN", opts, Box::new(|_cc| Ok(Box::new(App::new()))))
}
