//! Editing typed settings as text. The value in `Profile`/`Config` is always valid. While the text the user typed for
//! a field differs from it, the text lives in `Drafts`. A draft that doesn't parse shows its error under the field,
//! keeps the last valid value, and makes the app refuse Save and Connect until it's fixed.

use crate::config::{Profile, RouteMode, UserAuth};
use eframe::egui::{self, RichText};
use std::collections::BTreeMap;
use std::fmt::Display;
use std::str::FromStr;

/// Whose field a draft belongs to.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DraftOwner {
    /// a profile, by its id
    Profile(String),
    /// the app settings (the client UID)
    App,
}

/// The text fields that hold typed values.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Field {
    Name,
    Description,
    Gateway,
    Username,
    SsoPort,
    IkePort,
    LocalId,
    CustomRoutes,
    IfName,
    Uid,
}

impl Field {
    /// The field's label in the editor, for messages that name it.
    pub fn label(self) -> &'static str {
        match self {
            Field::Name => "Connection name",
            Field::Description => "Description",
            Field::Gateway => "Remote gateway",
            Field::Username => "Username",
            Field::SsoPort => "SSO port",
            Field::IkePort => "IKE UDP port",
            Field::LocalId => "Local ID",
            Field::CustomRoutes => "Custom routes",
            Field::IfName => "Interface name",
            Field::Uid => "Client UID",
        }
    }

    /// Whether profile `p` uses this field in its current mode. Text that doesn't parse in a field it doesn't use (the
    /// username while SSO is on, custom routes outside Custom routing) blocks nothing; it's kept, and counts again once
    /// the mode uses the field.
    pub fn in_use(self, p: &Profile) -> bool {
        match self {
            Field::Username => !p.sso.enabled && p.auth.mode == UserAuth::Eap,
            Field::SsoPort => p.sso.enabled,
            Field::CustomRoutes => p.network.route_mode == RouteMode::Custom,
            _ => true,
        }
    }
}

pub type DraftKey = (DraftOwner, Field);

#[derive(Clone, Debug, PartialEq)]
struct Draft {
    text: String,
    /// why `text` doesn't parse; None: it parsed and the value was updated
    error: Option<String>,
}

#[derive(Debug, Default)]
pub struct Drafts {
    map: BTreeMap<DraftKey, Draft>,
}

impl Drafts {
    /// The user changed the field's text to `text`: update `value` if it parses, remember the text either way.
    pub fn edit_with<V>(&mut self, key: DraftKey, text: String, value: &mut V, parse: impl FnOnce(&str) -> Result<V, String>) {
        let error = parse(&text).map(|v| *value = v).err();
        self.map.insert(key, Draft { text, error });
    }

    /// `edit_with` for a type that parses from text. The editor goes through `text_field`; tests type with this.
    #[cfg(test)]
    pub fn edit<V: FromStr<Err = String>>(&mut self, key: DraftKey, text: String, value: &mut V) {
        self.edit_with(key, text, value, |s| s.parse())
    }

    /// Like `edit`; empty (or blank) text means None.
    #[cfg(test)]
    pub fn edit_opt<V: FromStr<Err = String>>(&mut self, key: DraftKey, text: String, value: &mut Option<V>) {
        self.edit_with(key, text, value, parse_opt)
    }

    /// Focus left the field: a draft that parsed has done its job (the value holds it), so the field shows the value
    /// again. An invalid draft stays.
    pub fn settle(&mut self, key: &DraftKey) {
        if self.map.get(key).is_some_and(|d| d.error.is_none()) {
            self.map.remove(key);
        }
    }

    pub fn text(&self, key: &DraftKey) -> Option<&str> {
        self.map.get(key).map(|d| d.text.as_str())
    }

    pub fn error(&self, key: &DraftKey) -> Option<&str> {
        self.map.get(key)?.error.as_deref()
    }

    /// Every draft that doesn't parse, with its error.
    pub fn errors(&self) -> impl Iterator<Item = (&DraftKey, &str)> {
        self.map.iter().filter_map(|(k, d)| Some((k, d.error.as_deref()?)))
    }

    #[cfg(test)]
    pub fn has_errors(&self) -> bool {
        self.errors().next().is_some()
    }

    /// The value was set another way (Browse…, Regenerate): forget the typed text.
    pub fn remove(&mut self, key: &DraftKey) {
        self.map.remove(key);
    }

    /// The profile was deleted.
    pub fn remove_owner(&mut self, owner: &DraftOwner) {
        self.map.retain(|(o, _), _| o != owner);
    }
}

fn parse_opt<V: FromStr<Err = String>>(s: &str) -> Result<Option<V>, String> {
    if s.trim().is_empty() { Ok(None) } else { s.parse().map(Some) }
}

/// How a text field looks.
#[derive(Clone, Copy, Default)]
pub struct Look {
    pub hint: &'static str,
    pub width: Option<f32>,
    pub multiline: bool,
    pub monospace: bool,
}

impl Look {
    pub const PORT: Look = Look { hint: "", width: Some(110.0), multiline: false, monospace: false };

    pub const fn hint(hint: &'static str) -> Look {
        Look { hint, width: None, multiline: false, monospace: false }
    }
}

/// A column as wide as there is room for.
pub const WIDE: f32 = f32::INFINITY;

/// A column of a fixed `width` (so a field next to it doesn't move): `label` above, what `add` draws, and the
/// warning `add` returns in the slot below.
pub fn column<R>(ui: &mut egui::Ui, width: f32, label: &str, add: impl FnOnce(&mut egui::Ui) -> (R, Option<String>)) -> R {
    ui.vertical(|ui| {
        ui.set_width(width.min(ui.available_width()));
        ui.spacing_mut().item_spacing.y = 5.0;
        ui.label(crate::theme::caption(ui, label));
        let (r, warning) = add(ui);
        warning_slot(ui, warning.as_deref());
        r
    })
    .inner
}

/// One line that is always there, so a warning appearing doesn't move what's below it: "⚠ {msg}" in the warning
/// colour, cut to the line if it's longer (all of it on hover), or nothing. The real ⚠ character, not an icon-font
/// glyph, so screen readers say it.
pub fn warning_slot(ui: &mut egui::Ui, msg: Option<&str>) {
    let size = egui::vec2(ui.available_width(), 18.0);
    ui.allocate_ui_with_layout(size, egui::Layout::left_to_right(egui::Align::Center), |ui| {
        ui.set_min_size(size);
        if let Some(m) = msg {
            let text = format!("⚠ {m}");
            ui.add(egui::Label::new(RichText::new(&text).size(crate::theme::SMALL).color(ui.visuals().warn_fg_color)).truncate()).on_hover_text(text);
        }
    });
}

/// A text field for `value`: shows the draft for `key` if there is one, else `show(value)`. Edits go through `parse`;
/// while the text doesn't parse the field has a warning outline (the message is the caller's to show).
pub fn text_field<V>(
    ui: &mut egui::Ui,
    drafts: &mut Drafts,
    key: DraftKey,
    value: &mut V,
    look: Look,
    show: impl FnOnce(&V) -> String,
    parse: impl FnOnce(&str) -> Result<V, String>,
) -> egui::Response {
    let mut text = drafts.text(&key).map_or_else(|| show(value), str::to_owned);
    let edit = if look.multiline { egui::TextEdit::multiline(&mut text).desired_rows(3) } else { egui::TextEdit::singleline(&mut text) };
    // an id from the field, not from the layout: a warning or problem line appearing elsewhere mustn't make this a
    // new widget, which would take the focus away mid-typing
    let mut edit = edit.id(egui::Id::new(("form-field", &key))).hint_text(look.hint).margin(egui::Margin::symmetric(10, 8));
    if let Some(w) = look.width {
        edit = edit.desired_width(w);
    }
    if look.monospace {
        edit = edit.font(egui::TextStyle::Monospace);
    }
    let r = crate::theme::labelled(ui.add(edit), key.1.label());
    if drafts.error(&key).is_some() {
        let warn = ui.visuals().warn_fg_color;
        ui.painter().rect_stroke(r.rect, ui.visuals().widgets.inactive.corner_radius, egui::Stroke::new(1.0, warn), egui::StrokeKind::Inside);
    }
    if r.changed() {
        drafts.edit_with(key.clone(), text, value, parse);
    }
    if !r.has_focus() {
        drafts.settle(&key);
    }
    r
}

/// `text_field` for a type that parses from its own `Display` text.
pub fn parsed<V: FromStr<Err = String> + Display>(ui: &mut egui::Ui, drafts: &mut Drafts, key: DraftKey, value: &mut V, look: Look) -> egui::Response {
    text_field(ui, drafts, key, value, look, |v| v.to_string(), |s| s.parse())
}

/// `parsed` for an optional value: an empty field is None.
pub fn parsed_opt<V: FromStr<Err = String> + Display>(ui: &mut egui::Ui, drafts: &mut Drafts, key: DraftKey, value: &mut Option<V>, look: Look) -> egui::Response {
    text_field(ui, drafts, key, value, look, |v| v.as_ref().map(ToString::to_string).unwrap_or_default(), parse_opt)
}

/// `parsed` in a `column` captioned with the field's label, its error in the slot below.
pub fn parsed_field<V: FromStr<Err = String> + Display>(ui: &mut egui::Ui, width: f32, drafts: &mut Drafts, key: DraftKey, value: &mut V, look: Look) -> egui::Response {
    column(ui, width, key.1.label(), |ui| (parsed(ui, drafts, key.clone(), value, look), drafts.error(&key).map(str::to_owned)))
}

/// `parsed_opt` in a `column`, like `parsed_field`.
pub fn parsed_opt_field<V: FromStr<Err = String> + Display>(ui: &mut egui::Ui, width: f32, drafts: &mut Drafts, key: DraftKey, value: &mut Option<V>, look: Look) -> egui::Response {
    column(ui, width, key.1.label(), |ui| (parsed_opt(ui, drafts, key.clone(), value, look), drafts.error(&key).map(str::to_owned)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::Port;

    fn key(f: Field) -> DraftKey {
        (DraftOwner::Profile("p1".into()), f)
    }

    #[test]
    fn invalid_text_keeps_the_value_and_reports_why() {
        let mut d = Drafts::default();
        let mut port = Port::new(443).unwrap();
        d.edit(key(Field::IkePort), "0".into(), &mut port);
        assert_eq!(port.get(), 443);
        assert_eq!(d.error(&key(Field::IkePort)), Some("Port must be 1 to 65535."));
        assert_eq!(d.text(&key(Field::IkePort)), Some("0"));
        assert!(d.has_errors());
        d.settle(&key(Field::IkePort));
        assert_eq!(d.text(&key(Field::IkePort)), Some("0"), "an invalid draft stays after focus leaves");
    }

    #[test]
    fn valid_text_updates_the_value_and_settles_away() {
        let mut d = Drafts::default();
        let mut port = Port::new(443).unwrap();
        d.edit(key(Field::IkePort), " 8443".into(), &mut port);
        assert_eq!(port.get(), 8443);
        assert_eq!(d.text(&key(Field::IkePort)), Some(" 8443"), "kept while the field has focus");
        assert!(!d.has_errors());
        d.settle(&key(Field::IkePort));
        assert_eq!(d.text(&key(Field::IkePort)), None);
    }

    #[test]
    fn empty_optional_text_is_none() {
        let mut d = Drafts::default();
        let mut gw: Option<crate::net::Host> = Some("vpn.example.com".parse().unwrap());
        d.edit_opt(key(Field::Gateway), "  ".into(), &mut gw);
        assert_eq!(gw, None);
        assert!(!d.has_errors());
        d.edit_opt(key(Field::Gateway), "a b".into(), &mut gw);
        assert_eq!(gw, None, "still the last valid value");
        assert!(d.error(&key(Field::Gateway)).unwrap().starts_with("Expected a host name"));
    }

    #[test]
    fn errors_list_every_invalid_draft_and_owners_can_be_dropped() {
        let mut d = Drafts::default();
        let (mut a, mut b) = (Port::new(1).unwrap(), Port::new(1).unwrap());
        d.edit(key(Field::IkePort), "x".into(), &mut a);
        d.edit((DraftOwner::App, Field::SsoPort), "y".into(), &mut b);
        assert_eq!(d.errors().count(), 2);
        d.remove_owner(&DraftOwner::Profile("p1".into()));
        assert_eq!(d.errors().map(|(k, _)| k.clone()).collect::<Vec<_>>(), [(DraftOwner::App, Field::SsoPort)]);
        d.remove(&(DraftOwner::App, Field::SsoPort));
        assert!(!d.has_errors());
    }

    // ---- the egui widget ----

    /// Focus the port field, send `events`, then move focus away. Returns the port, the drafts and the visible texts.
    fn edit_port(start: u16, events: Vec<egui::Event>) -> (u16, Drafts, Vec<String>) {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        let mut port = Port::new(start).unwrap();
        let mut drafts = Drafts::default();
        let mut texts = vec![];
        let mut run = |port: &mut Port, drafts: &mut Drafts, events: Vec<egui::Event>, focus: bool| {
            let mut out = ctx.run_ui(egui::RawInput { events, ..Default::default() }, |ui| {
                let r = parsed_field(ui, WIDE, drafts, key(Field::IkePort), port, Look::PORT);
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
        run(&mut port, &mut drafts, vec![], true);
        run(&mut port, &mut drafts, events, true);
        run(&mut port, &mut drafts, vec![], false);
        run(&mut port, &mut drafts, vec![], false);
        (port.get(), drafts, texts)
    }

    fn select_all() -> egui::Event {
        egui::Event::Key { key: egui::Key::A, physical_key: None, pressed: true, repeat: false, modifiers: egui::Modifiers::COMMAND }
    }

    #[test]
    fn port_field_takes_a_typed_port() {
        let (port, drafts, _) = edit_port(443, vec![select_all(), egui::Event::Text("8443".into())]);
        assert_eq!(port, 8443);
        assert!(drafts.text(&key(Field::IkePort)).is_none(), "settled once focus left");
    }

    #[test]
    fn port_field_rejects_too_big_instead_of_clamping() {
        let (port, drafts, texts) = edit_port(443, vec![egui::Event::Text("8443".into())]); // appended: 4438443
        assert_eq!(port, 443);
        assert_eq!(drafts.text(&key(Field::IkePort)), Some("4438443"), "what the user typed is kept");
        assert!(texts.iter().any(|t| t == "⚠ Port must be 1 to 65535."), "{texts:?}");
    }

    #[test]
    fn fields_are_labelled_for_screen_readers() {
        let ctx = egui::Context::default();
        ctx.enable_accesskit();
        let mut port = Port::new(443).unwrap();
        let mut drafts = Drafts::default();
        let mut out = ctx.run_ui(Default::default(), |ui| {
            parsed(ui, &mut drafts, key(Field::IkePort), &mut port, Look::PORT);
        });
        let nodes = out.platform_output.accesskit_update.take().unwrap().nodes;
        out.drop_without_applying_deltas();
        assert!(nodes.iter().any(|(_, n)| n.role() == egui::accesskit::Role::TextInput && n.label() == Some("IKE UDP port")));
    }
}
