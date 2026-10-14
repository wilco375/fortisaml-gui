//! fortisaml-gui - FortiGate IPsec (IKEv2) + SAML SSO client for Linux, egui front-end.
//! Everything is native Rust: SAML (saml.rs/tls.rs), IKEv2 (ike.rs/crypto.rs), kernel XFRM (tunnel.rs).
//! The same binary is the privileged backend: `pkexec fortisaml-gui --backend` (see backend.rs).

mod backend;
mod config;
mod crypto;
mod ike;
mod keyring;
mod saml;
mod tls;
mod tunnel;

#[cfg(test)]
mod app_tests;

use backend::{Event, Session};
use config::*;
use eframe::egui::{self, Color32, RichText};
use serde_json::Value;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Instant;

/// rustc-style message: "<level>: <headline>" plus a `note` (the cause) and a `help` (what now) line.
pub fn diag(level: &str, headline: &str, note: &str, help: &str) -> String {
    format!("{level}: {headline}\n  note: {note}\n  help: {help}")
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
    ip: String,
    dns: Vec<String>,
    routes: Vec<String>,
    domain: String,
    full_tunnel: bool,
    saml_url: String,
}

struct App {
    cfg: Config,
    saved: Config,
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
    show_settings: bool,
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
        let read_errors = keyring.as_deref().map(|s| keyring::fill(s, &mut cfg)).unwrap_or_default();
        let saved = cfg.clone();
        cfg.dedupe_ids(); // after `saved`: a profile that got a new id is unsaved, Save stores its secrets under it
        let (tx, rx) = channel();
        let mut app = App {
            saved,
            cfg,
            save_error: (!read_errors.is_empty()).then(|| read_errors.join("\n")),
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
            show_settings: false,
            confirm_delete: false,
            stats: (0, 0),
            stats_at: None,
        };
        if !config_path().exists() {
            app.save(); // writes the generated UID on first start
        }
        app
    }

    fn unsaved(&self) -> bool {
        !self.cfg.settings_eq(&self.saved)
    }

    /// Save button: write the config file, then bring the keyring in line with it.
    fn save(&mut self) {
        if let Err(e) = self.cfg.save() {
            self.save_error = Some(diag(
                "error",
                "the settings couldn't be saved",
                &e.to_string(),
                &format!("check that {} is writable and click Save to try again", config_path().display()),
            ));
            return;
        }
        self.save_error = None;
        match self.keyring.as_deref() {
            Some(store) => {
                let ops = keyring::plan(&self.saved, &self.cfg);
                let (next, errors) = keyring::apply(store, &ops, &self.saved, &self.cfg);
                self.saved = next;
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
                    if ui.button("Save").clicked() {
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

    fn push_log(&mut self, line: String) {
        if !self.cfg.log_file.trim().is_empty() {
            use std::io::Write;
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(self.cfg.log_file.trim()) {
                let _ = writeln!(f, "{line}");
            }
        }
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
        self.profile_connected = self.cfg.selected;
        let p = self.cfg.profiles[self.cfg.selected].clone();
        self.push_log(format!("=== connecting \"{}\" ({}) ===", p.name, p.gateway));
        // without SSO there is no browser step: go straight to the root prompt
        self.state = if p.sso_enabled { State::Authenticating } else { State::Elevating };
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
                Event::Status(v) => self.on_status(v),
            }
        }
    }

    fn on_status(&mut self, v: Value) {
        let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
        let list = |x: Option<&Value>| -> Vec<String> {
            x.and_then(|x| x.as_array())
                .map(|a| a.iter().filter_map(|i| i.as_str().map(String::from)).collect())
                .unwrap_or_default()
        };
        match v.get("event").and_then(|e| e.as_str()).unwrap_or("") {
            "saml_url" => self.info.saml_url = s("url"),
            "saml_ok" => self.info.username = s("username"),
            "ike_start" => self.state = State::Negotiating,
            "established" => {
                if let Some(c) = v.get("config") {
                    self.info.dns = list(c.get("dns"));
                    self.info.domain = c.get("domain").and_then(|d| d.as_str()).unwrap_or("").into();
                }
            }
            "tunnel_up" => {
                self.info.ip = s("ip");
                self.info.routes = list(v.get("routes"));
                self.info.dns = list(v.get("dns"));
                self.info.full_tunnel = v.get("full_tunnel").and_then(|b| b.as_bool()).unwrap_or(false);
            }
            "connected" => {
                self.state = State::Connected;
                self.since = Some(Instant::now());
            }
            "disconnecting" => self.state = State::Disconnecting,
            "error" => {
                let m = s("message");
                self.push_log(format!("ERROR: {m}"));
                self.error = Some(m);
            }
            _ => {}
        }
    }

    fn read_stats(&mut self) {
        if self.state != State::Connected {
            return;
        }
        if self.stats_at.map_or(true, |t| t.elapsed().as_millis() > 900) {
            let ifn = &self.cfg.profiles[self.profile_connected].ifname;
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
            egui::ComboBox::from_id_salt((id, i, "enc")).selected_text(p.enc.clone()).show_ui(ui, |ui| {
                for e in ENCRYPTIONS {
                    ui.selectable_value(&mut p.enc, e.to_string(), e);
                }
            });
            egui::ComboBox::from_id_salt((id, i, "hash")).selected_text(p.hash.clone()).show_ui(ui, |ui| {
                for h in HASHES {
                    ui.selectable_value(&mut p.hash, h.to_string(), h);
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
        props.push(Proposal::new("AES256", "SHA256"));
    }
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
        let p = &mut self.cfg.profiles[self.cfg.selected];

        section(ui, "Connection", true, |ui| {
            egui::Grid::new("general").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
                form_row(ui, "Connection name", |ui| {
                    ui.text_edit_singleline(&mut p.name);
                });
                form_row(ui, "Description", |ui| {
                    ui.text_edit_singleline(&mut p.description);
                });
                form_row(ui, "Remote gateway", |ui| {
                    ui.add(egui::TextEdit::singleline(&mut p.gateway).hint_text("vpn.example.com"));
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
            ui.checkbox(&mut p.sso_enabled, "Enable Single Sign On (SSO) for VPN Tunnel");
            ui.add_space(4.0);
            if p.sso_enabled {
                egui::Grid::new("sso").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
                    form_row(ui, "Customize port", |ui| {
                        ui.add(egui::DragValue::new(&mut p.saml_port).range(1..=65535))
                            .on_hover_text("FortiGate 'auth-ike-saml-port'");
                    });
                    form_row(ui, "", |ui| {
                        ui.checkbox(&mut p.open_browser, "Open the login page in the browser automatically");
                    });
                    form_row(ui, "", |ui| {
                        ui.checkbox(&mut p.verify_cert, "Verify the server certificate on the SSO port");
                    });
                    form_row(ui, "Login timeout (s)", |ui| {
                        ui.add(egui::DragValue::new(&mut p.saml_timeout).range(30..=3600));
                    });
                });
            } else {
                egui::Grid::new("userauth").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
                    form_row(ui, "User authentication", |ui| {
                        ui.vertical(|ui| {
                            ui.radio_value(&mut p.user_auth, UserAuth::Eap, "Username and password (EAP)");
                            ui.radio_value(&mut p.user_auth, UserAuth::None, "None (pre-shared key only)");
                        });
                    });
                    if p.user_auth == UserAuth::Eap {
                        form_row(ui, "Username", |ui| {
                            ui.text_edit_singleline(&mut p.username);
                        });
                        form_row(ui, "Password", |ui| {
                            ui.add(egui::TextEdit::singleline(&mut p.password).password(true));
                        });
                        form_row(ui, "", |ui| {
                            ui.checkbox(&mut p.save_password, "Save password")
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
                form_row(ui, "Encapsulation", |ui| {
                    ui.horizontal(|ui| {
                        ui.label("IKE UDP port");
                        ui.add(egui::DragValue::new(&mut p.ike_port).range(1..=65535));
                    });
                });
            });
        });

        section(ui, "Phase 1", false, |ui| {
            proposal_rows(ui, "p1", &mut p.ike_proposals);
            ui.add_space(6.0);
            ui.label("DH group");
            ui.horizontal_wrapped(|ui| {
                for g in DH_UNSUPPORTED.iter().take(3) {
                    ui.add_enabled(false, egui::Checkbox::new(&mut false, g.to_string()))
                        .on_disabled_hover_text("not supported by this client");
                }
                for g in DH_SUPPORTED {
                    let mut on = p.dh_groups.contains(&g);
                    if ui.checkbox(&mut on, g.to_string()).changed() {
                        if on {
                            p.dh_groups.push(g);
                            p.dh_groups.sort();
                        } else {
                            p.dh_groups.retain(|x| *x != g);
                        }
                    }
                }
            });
            egui::Grid::new("p1b").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
                form_row(ui, "Local ID", |ui| {
                    ui.add(egui::TextEdit::singleline(&mut p.local_id).hint_text("Optional (default: local IP)"));
                });
                form_row(ui, "NAT-T keepalive (s)", |ui| {
                    ui.add(egui::DragValue::new(&mut p.natt_keepalive).range(5..=300));
                });
            });
        });

        section(ui, "Phase 2", false, |ui| {
            proposal_rows(ui, "p2", &mut p.esp_proposals);
        });

        section(ui, "Network", false, |ui| {
            egui::Grid::new("net").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
                form_row(ui, "Routing", |ui| {
                    ui.vertical(|ui| {
                        ui.radio_value(&mut p.route_mode, RouteMode::Gateway, "As pushed by the FortiGate");
                        ui.radio_value(&mut p.route_mode, RouteMode::Full, "All traffic through the VPN");
                        ui.radio_value(&mut p.route_mode, RouteMode::Custom, "Only these networks:");
                        if p.route_mode == RouteMode::Custom {
                            ui.add(egui::TextEdit::multiline(&mut p.custom_routes)
                                .hint_text("10.0.0.0/8\n192.168.10.0/24").desired_rows(3));
                        }
                    });
                });
                form_row(ui, "", |ui| {
                    ui.checkbox(&mut p.set_dns, "Use DNS servers from the VPN (systemd-resolved)");
                });
                form_row(ui, "", |ui| {
                    ui.checkbox(&mut p.block_ipv6, "Block IPv6 while all traffic goes through the VPN");
                });
                form_row(ui, "Interface name", |ui| {
                    ui.text_edit_singleline(&mut p.ifname);
                });
                form_row(ui, "MTU", |ui| {
                    ui.add(egui::DragValue::new(&mut p.mtu).range(576..=1500));
                });
            });
        });
    }

    fn settings_window(&mut self, ctx: &egui::Context) {
        let mut open = self.show_settings;
        egui::Window::new("Settings").open(&mut open).resizable(true).show(ctx, |ui| {
            egui::Grid::new("settings").num_columns(2).spacing([16.0, 8.0]).show(ui, |ui| {
                form_row(ui, "Client UID", |ui| {
                    ui.horizontal(|ui| {
                        ui.add(egui::TextEdit::singleline(&mut self.cfg.uid).desired_width(290.0).font(egui::TextStyle::Monospace))
                            .on_hover_text("FortiClient installation UID: sent to the FortiGate during SSO and used as EAP identity");
                        if ui.button("Regenerate").clicked() {
                            self.cfg.uid = new_uid();
                        }
                    });
                });
                form_row(ui, "Log file", |ui| {
                    ui.add(egui::TextEdit::singleline(&mut self.cfg.log_file).hint_text("optional, e.g. ~/fortisaml.log"));
                });
                form_row(ui, "", |ui| {
                    ui.checkbox(&mut self.cfg.verbose, "Verbose backend logging (keys are always redacted)");
                });
            });
            ui.separator();
            ui.label(RichText::new(format!("Settings file: {}", config_path().display())).weak());
        });
        self.show_settings = open;
    }
}

impl eframe::App for App {
    fn ui(&mut self, root: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = &root.ctx().clone();
        self.handle_events();
        self.read_stats();
        if self.state == State::Connected || self.busy() {
            ctx.request_repaint_after(std::time::Duration::from_secs(1));
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
                    let unsaved = self.unsaved();
                    if ui.add_enabled(unsaved, egui::Button::new("💾 Save")).clicked() {
                        self.save();
                    }
                    if unsaved {
                        ui.label(RichText::new("Unsaved changes").weak());
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
            for i in 0..self.cfg.profiles.len() {
                let p = &self.cfg.profiles[i];
                let mut text = RichText::new(&p.name);
                if busy && i == self.profile_connected {
                    text = text.color(if self.state == State::Connected { Color32::from_rgb(60, 170, 90) } else { Color32::from_rgb(220, 160, 40) });
                }
                if ui.add_enabled(!busy, egui::Button::selectable(i == self.cfg.selected, text)).clicked() {
                    self.cfg.selected = i;
                    self.confirm_delete = false;
                }
            }
            ui.add_space(8.0);
            ui.add_enabled_ui(!busy, |ui| {
                ui.horizontal(|ui| {
                    if ui.button("➕ New").clicked() {
                        self.cfg.profiles.push(Profile::default());
                        self.cfg.selected = self.cfg.profiles.len() - 1;
                    }
                    if ui.button("⧉ Copy").clicked() {
                        let p = self.cfg.profiles[self.cfg.selected].duplicate();
                        self.cfg.profiles.push(p);
                        self.cfg.selected = self.cfg.profiles.len() - 1;
                    }
                    if self.cfg.profiles.len() > 1 {
                        if !self.confirm_delete {
                            if ui.button("🗑 Delete").clicked() {
                                self.confirm_delete = true;
                            }
                        } else if ui.button(RichText::new("Confirm delete").color(Color32::RED)).clicked() {
                            self.cfg.profiles.remove(self.cfg.selected);
                            self.cfg.selected = self.cfg.selected.min(self.cfg.profiles.len() - 1);
                            self.confirm_delete = false;
                        }
                    }
                });
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
                let (dot, col) = match self.state {
                    State::Connected => ("●", Color32::from_rgb(60, 170, 90)),
                    State::Idle => ("●", Color32::GRAY),
                    _ => ("●", Color32::from_rgb(220, 160, 40)),
                };
                ui.label(RichText::new(dot).color(col).size(20.0));
                ui.label(RichText::new(self.state.label()).size(16.0));
                if self.busy() && self.state != State::Connected {
                    ui.spinner();
                }
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let big = |t: &str| egui::Button::new(RichText::new(t).size(16.0)).min_size(egui::vec2(130.0, 32.0));
                    match self.state {
                        State::Idle => {
                            if ui.add(big("Connect")).clicked() {
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
                ui.colored_label(Color32::LIGHT_RED, format!("⚠ {e}"));
            }
            if let Some(e) = &self.save_error {
                ui.label(RichText::new(e).monospace().color(ui.visuals().error_fg_color));
            }
            if self.state == State::Authenticating && !self.info.saml_url.is_empty() {
                ui.horizontal(|ui| {
                    ui.label("Login page:");
                    ui.hyperlink_to("open in browser", &self.info.saml_url);
                    if ui.small_button("copy URL").clicked() {
                        ctx.copy_text(self.info.saml_url.clone());
                    }
                });
            }
            ui.separator();

            if self.busy() {
                let p = &self.cfg.profiles[self.profile_connected];
                egui::Grid::new("status").num_columns(2).spacing([20.0, 8.0]).show(ui, |ui| {
                    form_row(ui, "Connection", |ui| {
                        ui.label(RichText::new(&p.name).strong());
                    });
                    form_row(ui, "Gateway", |ui| {
                        ui.label(&p.gateway);
                    });
                    if !self.info.username.is_empty() {
                        form_row(ui, "Username", |ui| {
                            ui.label(&self.info.username);
                        });
                    }
                    if !self.info.ip.is_empty() {
                        form_row(ui, "IP address", |ui| {
                            ui.label(RichText::new(&self.info.ip).monospace());
                        });
                    }
                    if !self.info.routes.is_empty() {
                        form_row(ui, "Routes", |ui| {
                            ui.label(if self.info.full_tunnel { "all traffic".to_string() } else { self.info.routes.join(", ") });
                        });
                    }
                    if !self.info.dns.is_empty() {
                        form_row(ui, "DNS", |ui| {
                            ui.label(format!("{}{}", self.info.dns.join(", "),
                                if self.info.domain.is_empty() { String::new() } else { format!("  ({})", self.info.domain) }));
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
    if args.iter().any(|a| a == "--probe") {
        std::process::exit(backend::probe_main(&args));
    }
    if let Some(i) = args.iter().position(|a| a == "--down") {
        std::process::exit(backend::down_main(args.get(i + 1).map_or("fsaml0", |s| s.as_str())));
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
