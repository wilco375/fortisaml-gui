//! The look: colours for dark and light, fonts (Inter, Phosphor icons), sizes, and the widgets egui doesn't have
//! (cards, buttons that don't change size on hover, status pill, toggle, the logo).

use eframe::egui::{self, Align, Color32, CornerRadius, FontFamily, FontId, Frame, Margin, RichText, Sense, Stroke, StrokeKind, TextStyle, Ui, Vec2, vec2};
pub use egui_phosphor::regular as icon;
use std::sync::LazyLock;

/// Colours egui's `Visuals` has no slot for, plus the ones the widgets here use directly.
#[derive(Clone, Copy)]
pub struct Tokens {
    pub bg: Color32,
    pub side: Color32,
    pub card: Color32,
    pub field: Color32,
    pub border: Color32,
    pub border_strong: Color32,
    pub text: Color32,
    pub weak: Color32,
    pub accent: Color32,
    /// text on an accent fill
    pub accent_ink: Color32,
    pub success: Color32,
    pub warning: Color32,
    pub danger: Color32,
    pub hover: Color32,
}

const fn hex(s: u32) -> Color32 {
    Color32::from_rgb((s >> 16) as u8, (s >> 8) as u8, s as u8)
}

pub fn tint(c: Color32, alpha: u8) -> Color32 {
    Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), alpha)
}

const DARK: Tokens = Tokens {
    bg: hex(0x14161b),
    side: hex(0x0f1115),
    card: hex(0x1b1e24),
    field: hex(0x111318),
    border: hex(0x2b2f38),
    border_strong: hex(0x3d4350),
    text: hex(0xe8eaef),
    weak: hex(0x9aa0ab),
    accent: hex(0x6b8cff),
    accent_ink: hex(0x0b1020),
    success: hex(0x3ecf8e),
    warning: hex(0xe0a43f),
    danger: hex(0xef5c68),
    hover: hex(0x22262e),
};

const LIGHT: Tokens = Tokens {
    bg: hex(0xf5f6f8),
    side: hex(0xebedf1),
    card: hex(0xffffff),
    field: hex(0xffffff),
    border: hex(0xdcdfe5),
    border_strong: hex(0xb9bec8),
    text: hex(0x1b1f26),
    weak: hex(0x5f6672),
    accent: hex(0x3d63e0),
    accent_ink: hex(0xffffff),
    success: hex(0x1f9d63),
    warning: hex(0xb7791f),
    danger: hex(0xd23c4a),
    hover: hex(0xe1e4ea),
};

/// The colours for the theme `ui` is drawn in (follows the desktop's light/dark setting).
pub fn tokens(ui: &Ui) -> Tokens {
    if ui.visuals().dark_mode { DARK } else { LIGHT }
}

// ---- sizes ----

/// Field captions and secondary lines.
pub const CAPTION: f32 = 13.5;
/// Help text and warnings under fields.
pub const SMALL: f32 = 13.0;
pub const CARD_RADIUS: u8 = 12;
pub const CARD_PADDING: i8 = 18;
/// The big button in the status card.
pub const ACTION_SIZE: Vec2 = vec2(160.0, 44.0);

// ---- fonts ----

static STRONG: LazyLock<FontFamily> = LazyLock::new(|| FontFamily::Name("strong".into()));
static ICONS: LazyLock<FontFamily> = LazyLock::new(|| FontFamily::Name("icons".into()));

/// `family` once the fonts are loaded (they apply from the frame after `install`), else None.
fn loaded(ctx: &egui::Context, family: &FontFamily) -> Option<FontFamily> {
    ctx.fonts(|f| f.definitions().families.contains_key(family)).then(|| family.clone())
}

fn strong_family(ctx: &egui::Context) -> FontFamily {
    loaded(ctx, &STRONG).unwrap_or(FontFamily::Proportional)
}

/// Load the fonts, and from the next call on (fonts apply from the next frame on) the sizes and colours. Call it
/// every frame, and before the first one; it does nothing once both are done. It must not ask egui which fonts are
/// loaded: before the first frame that panics.
pub fn install(ctx: &egui::Context) {
    #[derive(Clone, Copy, Default, PartialEq)]
    enum Step {
        #[default]
        Fonts,
        Style,
        Done,
    }
    let id = egui::Id::new("theme-install");
    let step = ctx.data(|d| d.get_temp::<Step>(id)).unwrap_or_default();
    match step {
        Step::Fonts => {
            ctx.set_fonts(fonts());
            ctx.data_mut(|d| d.insert_temp(id, Step::Style));
        }
        Step::Style => {
            for (theme, t) in [(egui::Theme::Dark, DARK), (egui::Theme::Light, LIGHT)] {
                ctx.style_mut_of(theme, |s| style(s, t, theme));
            }
            ctx.data_mut(|d| d.insert_temp(id, Step::Done));
        }
        Step::Done => {}
    }
    // without input nothing else repaints: the next step would wait for the first mouse move
    if step != Step::Done {
        ctx.request_repaint();
    }
}

fn fonts() -> egui::FontDefinitions {
    let mut fonts = egui::FontDefinitions::default();
    let mut add = |name: &str, bytes: &'static [u8]| {
        fonts.font_data.insert(name.into(), egui::FontData::from_static(bytes).into());
    };
    add("inter", include_bytes!("../assets/fonts/Inter-Regular.ttf"));
    add("inter-semibold", include_bytes!("../assets/fonts/Inter-SemiBold.ttf"));
    add("phosphor", egui_phosphor::Variant::Regular.font_bytes());
    let proportional = fonts.families.get_mut(&FontFamily::Proportional).expect("egui has a proportional family");
    proportional.insert(0, "inter".into());
    // egui's own fonts stay as fallbacks, for ⚠ and other symbols Inter lacks
    let fallbacks: Vec<String> = proportional.iter().skip(1).cloned().collect();
    fonts.families.insert(STRONG.clone(), std::iter::once("inter-semibold".to_string()).chain(fallbacks).collect());
    // a family of its own: Inter has glyphs of its own in the private use area Phosphor uses, and Phosphor maps a-z
    // to blank ligature parts, so neither can be a fallback of the other. Inter after it only for egui's
    // replacement glyph (◻), which Phosphor lacks.
    fonts.families.insert(ICONS.clone(), vec!["phosphor".into(), "inter".into()]);
    fonts
}

fn style(s: &mut egui::Style, t: Tokens, theme: egui::Theme) {
    s.text_styles.insert(TextStyle::Body, FontId::proportional(15.0));
    s.text_styles.insert(TextStyle::Button, FontId::proportional(15.0));
    s.text_styles.insert(TextStyle::Small, FontId::proportional(12.5));
    s.text_styles.insert(TextStyle::Monospace, FontId::monospace(CAPTION));
    s.text_styles.insert(TextStyle::Heading, FontId::new(22.0, STRONG.clone()));
    s.spacing.interact_size.y = 34.0;
    s.spacing.button_padding = vec2(14.0, 7.0);
    s.spacing.item_spacing = vec2(10.0, 10.0);
    s.spacing.window_margin = Margin::same(16);
    s.spacing.menu_margin = Margin::same(6);
    s.spacing.icon_width = 18.0;
    s.spacing.icon_width_inner = 10.0;
    s.spacing.text_edit_width = 440.0;

    let v = &mut s.visuals;
    *v = theme.default_visuals();
    v.panel_fill = t.bg;
    v.window_fill = t.card;
    v.extreme_bg_color = t.field;
    v.faint_bg_color = t.card;
    v.hyperlink_color = t.accent;
    v.selection.bg_fill = tint(t.accent, 90);
    v.selection.stroke = Stroke::new(1.5, t.accent);
    v.warn_fg_color = t.warning;
    v.error_fg_color = t.danger;
    v.window_corner_radius = CornerRadius::same(CARD_RADIUS);
    v.menu_corner_radius = CornerRadius::same(10);
    v.window_stroke = Stroke::new(1.0, t.border);
    let r = CornerRadius::same(8);
    v.widgets.noninteractive.bg_fill = t.card;
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, t.border);
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, t.text);
    v.widgets.noninteractive.corner_radius = r;
    for (w, fill, stroke) in [
        (&mut v.widgets.inactive, t.card, t.border),
        (&mut v.widgets.hovered, t.hover, t.border_strong),
        (&mut v.widgets.active, t.hover, t.accent),
        (&mut v.widgets.open, t.hover, t.border_strong),
    ] {
        w.bg_fill = fill;
        w.weak_bg_fill = fill;
        w.bg_stroke = Stroke::new(1.0, stroke);
        w.fg_stroke = Stroke::new(1.5, t.text);
        w.corner_radius = r;
        w.expansion = 0.0;
    }
}

// ---- text ----

/// Semibold text (regular until the fonts are loaded).
pub fn strong(ui: &Ui, text: impl Into<String>, size: f32) -> RichText {
    RichText::new(text.into()).family(strong_family(ui.ctx())).size(size)
}

/// Semibold text in the main text colour: titles and values.
pub fn title(ui: &Ui, text: impl Into<String>, size: f32) -> RichText {
    strong(ui, text, size).color(tokens(ui).text)
}

/// A field's caption, or a secondary line.
pub fn caption(ui: &Ui, text: impl Into<String>) -> RichText {
    RichText::new(text.into()).size(CAPTION).color(tokens(ui).weak)
}

/// Help text.
pub fn weak(ui: &Ui, text: impl Into<String>) -> RichText {
    RichText::new(text.into()).size(SMALL).color(tokens(ui).weak)
}

/// Uppercase section caption.
pub fn eyebrow(ui: &mut Ui, text: &str) {
    let t = tokens(ui);
    ui.label(RichText::new(text.to_uppercase()).size(11.5).extra_letter_spacing(0.8).color(t.weak));
}

/// `glyph` in the icon font (nothing until the fonts are loaded).
pub fn glyph(ui: &Ui, glyph: &str, size: f32, color: Color32) -> RichText {
    match loaded(ui.ctx(), &ICONS) {
        Some(f) => RichText::new(glyph).family(f).size(size).color(color),
        None => RichText::new(""),
    }
}

/// An icon, then `text`. `color` PLACEHOLDER takes the widget's text colour.
pub fn with_icon(ui: &Ui, glyph: &str, text: &str, size: f32, color: Color32, bold: bool) -> egui::text::LayoutJob {
    let mut job = egui::text::LayoutJob::default();
    let format = |font_id| egui::TextFormat { font_id, color, valign: Align::Center, ..Default::default() };
    if let Some(icons) = loaded(ui.ctx(), &ICONS) {
        job.append(glyph, 0.0, format(FontId::new(size * 1.15, icons)));
        job.append("  ", 0.0, format(FontId::proportional(size)));
    }
    let family = if bold { strong_family(ui.ctx()) } else { FontFamily::Proportional };
    job.append(text, 0.0, format(FontId::new(size, family)));
    job
}

/// Screen readers get `label`: the visible text starts with an icon from the private use area, or the widget's
/// caption is a separate label.
pub fn labelled(r: egui::Response, label: &str) -> egui::Response {
    r.ctx.accesskit_node_builder(r.id, |n| n.set_label(label));
    r
}

// ---- buttons ----

/// What a filled button is for.
#[derive(Clone, Copy)]
pub enum Tone {
    /// the main action: accent fill
    Accent,
    /// stopping or removing something: red outline
    Danger,
    /// anything else: the normal button look
    Plain,
}

/// The big button in the status card (Connect, Disconnect, Cancel).
pub fn action(ui: &mut Ui, enabled: bool, tone: Tone, icon: &str, text: &str) -> egui::Response {
    filled(ui, enabled, tone, icon, text, 16.0, ACTION_SIZE)
}

/// A button with an icon in `tone`, at the normal height.
pub fn solid(ui: &mut Ui, enabled: bool, tone: Tone, icon: &str, text: &str) -> egui::Response {
    filled(ui, enabled, tone, icon, text, 15.0, vec2(0.0, 36.0))
}

/// A plain button with an icon.
pub fn button(ui: &mut Ui, enabled: bool, icon: &str, text: &str) -> egui::Response {
    solid(ui, enabled, Tone::Plain, icon, text)
}

fn filled(ui: &mut Ui, enabled: bool, tone: Tone, icon: &str, text: &str, size: f32, min: Vec2) -> egui::Response {
    let t = tokens(ui);
    let (ink, fill, stroke, bold) = match tone {
        Tone::Accent => (t.accent_ink, t.accent, Stroke::NONE, true),
        Tone::Danger => (t.danger, tint(t.danger, 18), Stroke::new(1.0, t.danger), true),
        Tone::Plain => (t.text, t.card, Stroke::new(1.0, t.border), false),
    };
    let radius = if min.y >= ACTION_SIZE.y { 10 } else { 8 };
    let b = egui::Button::new(with_icon(ui, icon, text, size, ink, bold)).fill(fill).stroke(stroke).corner_radius(radius).min_size(min);
    labelled(ui.add_enabled(enabled, b), text)
}

/// A frameless button with an icon, for secondary actions.
pub fn quiet(ui: &mut Ui, icon: &str, text: &str) -> egui::Response {
    let job = with_icon(ui, icon, text, 14.5, Color32::PLACEHOLDER, false);
    ghost(ui, true, job.into(), vec2(0.0, 34.0), vec2(10.0, 6.0), 8, false, text)
}

/// A square icon-only button; `on` draws it highlighted (a toggle that's on).
pub fn icon_button(ui: &mut Ui, icon: &str, label: &str, on: bool) -> egui::Response {
    let text = glyph(ui, icon, 19.0, Color32::PLACEHOLDER).into();
    ghost(ui, true, text, vec2(36.0, 36.0), Vec2::ZERO, 8, on, label).on_hover_text(label)
}

/// Side of `small_icon_button`.
pub const SMALL_BUTTON: f32 = 28.0;

/// A small square icon-only button, for actions inside a list row.
pub fn small_icon_button(ui: &mut Ui, enabled: bool, icon: &str, label: &str) -> egui::Response {
    let text = glyph(ui, icon, 16.0, Color32::PLACEHOLDER).into();
    ghost(ui, enabled, text, Vec2::splat(SMALL_BUTTON), Vec2::ZERO, 7, false, label).on_hover_text(label)
}

/// A button without a frame until it's hovered. Painted here because egui's frameless buttons change size when the
/// frame appears, which moves everything next to them. `on` keeps it highlighted (a toggle that's on).
#[allow(clippy::too_many_arguments)]
fn ghost(ui: &mut Ui, enabled: bool, text: egui::WidgetText, min: Vec2, padding: Vec2, radius: u8, on: bool, label: &str) -> egui::Response {
    let t = tokens(ui);
    ui.add_enabled_ui(enabled, |ui| {
        let galley = text.into_galley(ui, Some(egui::TextWrapMode::Extend), f32::INFINITY, TextStyle::Button);
        let (rect, r) = ui.allocate_exact_size((galley.size() + 2.0 * padding).max(min), Sense::click());
        r.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Button, enabled, label));
        let p = ui.painter();
        let radius = CornerRadius::same(radius);
        if on {
            p.rect_filled(rect, radius, tint(t.accent, 40));
            p.rect_stroke(rect, radius, Stroke::new(1.0, t.accent), StrokeKind::Inside);
        } else if enabled && (r.hovered() || r.has_focus()) {
            p.rect_filled(rect, radius, t.hover);
            p.rect_stroke(rect, radius, Stroke::new(1.0, t.border_strong), StrokeKind::Inside);
        }
        p.galley(rect.center() - galley.size() / 2.0, galley, if enabled { t.text } else { tint(t.weak, 120) });
        r
    })
    .inner
}

/// A full-width outlined button at the end of a list ("New connection").
pub fn list_button(ui: &mut Ui, enabled: bool, icon: &str, text: &str) -> egui::Response {
    let t = tokens(ui);
    let b = egui::Button::new(with_icon(ui, icon, text, 14.5, t.weak, false))
        .fill(Color32::TRANSPARENT)
        .min_size(vec2(ui.available_width(), 42.0))
        .corner_radius(10);
    labelled(ui.add_enabled(enabled, b), text)
}

// ---- containers ----

/// The box behind a card, without its margin.
pub fn card_frame(t: Tokens) -> Frame {
    Frame::new().fill(t.card).stroke(Stroke::new(1.0, t.border)).corner_radius(CARD_RADIUS)
}

/// A rounded, bordered box for one group of things.
pub fn card(ui: &mut Ui, add: impl FnOnce(&mut Ui)) {
    card_frame(tokens(ui)).inner_margin(Margin::same(CARD_PADDING)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        add(ui);
    });
}

/// Icon, title and an optional one-line explanation at the top of a card.
pub fn card_title(ui: &mut Ui, icon: &str, title_text: &str, sub: Option<&str>) {
    let t = tokens(ui);
    ui.horizontal(|ui| {
        ui.spacing_mut().interact_size.y = 0.0;
        ui.label(glyph(ui, icon, 21.0, t.accent));
        match sub {
            // next to the icon, not at the top of a taller column
            None => {
                ui.label(title(ui, title_text, 16.0));
            }
            Some(sub) => {
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 2.0;
                    ui.label(title(ui, title_text, 16.0));
                    ui.label(weak(ui, sub));
                });
            }
        }
    });
    ui.add_space(2.0);
}

/// A tinted, full-width box in `color` with an icon: messages that need attention.
pub fn banner(ui: &mut Ui, color: Color32, icon: &str, add: impl FnOnce(&mut Ui)) {
    Frame::new()
        .fill(tint(color, 22))
        .stroke(Stroke::new(1.0, tint(color, 120)))
        .corner_radius(CARD_RADIUS)
        .inner_margin(Margin::same(16))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_top(|ui| {
                ui.label(glyph(ui, icon, 24.0, color));
                ui.vertical(|ui| {
                    ui.spacing_mut().item_spacing.y = 6.0;
                    add(ui);
                });
            });
        });
}

/// A red banner with a monospace error (the rustc-style `diag` text).
pub fn error_banner(ui: &mut Ui, text: &str) {
    let t = tokens(ui);
    banner(ui, t.danger, icon::WARNING_CIRCLE, |ui| {
        ui.add(egui::Label::new(RichText::new(text).monospace().color(t.text)).wrap());
    });
}

/// A card that folds open: icon, title, a one-line summary of what's inside, and a caret. Starts closed. Whether
/// it's open is kept per title, so it stays open when another connection is selected.
pub fn fold_card(ui: &mut Ui, icon: &str, title_text: &str, summary: &str, body: impl FnOnce(&mut Ui)) {
    let t = tokens(ui);
    let id = ui.make_persistent_id(("fold", title_text));
    let mut open = ui.data_mut(|d| d.get_persisted::<bool>(id)).unwrap_or(false);
    card_frame(t).inner_margin(Margin::symmetric(CARD_PADDING, 14)).show(ui, |ui| {
        ui.set_width(ui.available_width());
        let (rect, r) = ui.allocate_exact_size(vec2(ui.available_width(), 26.0), Sense::click());
        if r.clicked() {
            open = !open;
            ui.data_mut(|d| d.insert_persisted(id, open));
        }
        r.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::CollapsingHeader, true, title_text));
        ui.ctx().accesskit_node_builder(r.id, |n| n.set_expanded(open));
        let p = ui.painter();
        if r.has_focus() {
            p.rect_stroke(rect.expand(4.0), CornerRadius::same(8), Stroke::new(1.5, t.accent), StrokeKind::Outside);
        }
        let mut x = rect.left();
        let caret_room = if let Some(icons) = loaded(ui.ctx(), &ICONS) {
            p.text(egui::pos2(x, rect.center().y), egui::Align2::LEFT_CENTER, icon, FontId::new(20.0, icons.clone()), t.weak);
            let caret = if open { icon::CARET_DOWN } else { icon::CARET_RIGHT };
            p.text(rect.right_center(), egui::Align2::RIGHT_CENTER, caret, FontId::new(17.0, icons), t.weak);
            x += 30.0;
            24.0
        } else {
            0.0
        };
        let tr = p.text(egui::pos2(x, rect.center().y), egui::Align2::LEFT_CENTER, title_text, FontId::new(15.5, strong_family(ui.ctx())), if r.hovered() { t.accent } else { t.text });
        // the summary gets what's left before the caret
        let room = rect.right() - caret_room - tr.right() - 12.0;
        let summary = egui::WidgetText::from(RichText::new(summary).size(CAPTION).color(t.weak)).into_galley(ui, Some(egui::TextWrapMode::Truncate), room.max(0.0), TextStyle::Body);
        ui.painter().galley(egui::pos2(tr.right() + 12.0, rect.center().y - summary.size().y / 2.0), summary, t.weak);
        if open {
            ui.add_space(8.0);
            body(ui);
        }
    });
}

// ---- small widgets ----

/// Rounded label with a dot: the connection state.
pub fn pill(ui: &mut Ui, color: Color32, text: &str) -> egui::Response {
    let galley = ui.painter().layout_no_wrap(text.to_string(), FontId::new(CAPTION, strong_family(ui.ctx())), color);
    let (rect, r) = ui.allocate_exact_size(vec2(galley.size().x + 34.0, 28.0), Sense::hover());
    r.widget_info(|| egui::WidgetInfo::labeled(egui::WidgetType::Label, true, text));
    let p = ui.painter();
    p.rect_filled(rect, CornerRadius::same(14), tint(color, 36));
    p.circle_filled(rect.left_center() + vec2(14.0, 0.0), 4.5, color);
    p.galley(rect.left_center() + vec2(24.0, -galley.size().y / 2.0), galley, color);
    r
}

/// An on/off switch with its label (one widget: both toggle it) and an optional explanation under it.
pub fn toggle(ui: &mut Ui, on: &mut bool, label: &str, help: Option<&str>) -> egui::Response {
    const SWITCH: Vec2 = vec2(42.0, 24.0);
    const GAP: f32 = 10.0;
    let t = tokens(ui);
    ui.vertical(|ui| {
        ui.spacing_mut().item_spacing.y = 2.0;
        let text = egui::WidgetText::from(RichText::new(label).color(t.text)).into_galley(ui, Some(egui::TextWrapMode::Extend), f32::INFINITY, TextStyle::Body);
        let (rect, mut r) = ui.allocate_exact_size(vec2(SWITCH.x + GAP + text.size().x, SWITCH.y.max(text.size().y)), Sense::click());
        if r.clicked() {
            *on = !*on;
            r.mark_changed();
        }
        r.widget_info(|| egui::WidgetInfo::selected(egui::WidgetType::Checkbox, true, *on, label));
        let switch = egui::Rect::from_min_size(egui::pos2(rect.left(), rect.center().y - SWITCH.y / 2.0), SWITCH);
        let k = ui.ctx().animate_bool_responsive(r.id, *on);
        let off = if r.hovered() { t.border_strong } else { t.border };
        let p = ui.painter();
        p.rect_filled(switch, CornerRadius::same(12), off.lerp_to_gamma(t.accent, k));
        if r.has_focus() {
            p.rect_stroke(switch.expand(2.0), CornerRadius::same(14), Stroke::new(1.5, t.accent), StrokeKind::Outside);
        }
        p.circle_filled(egui::pos2(egui::lerp((switch.left() + 12.0)..=(switch.right() - 12.0), k), switch.center().y), 9.0, Color32::WHITE);
        p.galley(egui::pos2(switch.right() + GAP, rect.center().y - text.size().y / 2.0), text, t.text);
        if let Some(help) = help {
            ui.horizontal(|ui| {
                ui.add_space(SWITCH.x + GAP - ui.spacing().item_spacing.x);
                ui.label(weak(ui, help));
            });
        }
        r
    })
    .inner
}

/// The app icon (two arches on an accent square), drawn so it follows the theme's accent. The installed icon,
/// assets/archway-vpn.svg, has a gradient; this one is flat.
pub fn logo(ui: &mut Ui, size: f32) -> egui::Response {
    // assets/archway-vpn.svg: a 512 box with the square at 32..480
    const SQUARE_AT: f32 = 32.0;
    const SQUARE: f32 = 448.0;
    let t = tokens(ui);
    let (rect, response) = ui.allocate_exact_size(vec2(size, size), Sense::hover());
    let p = ui.painter();
    let s = size / SQUARE;
    let at = |x: f32, y: f32| rect.min + vec2((x - SQUARE_AT) * s, (y - SQUARE_AT) * s);
    p.rect_filled(rect, CornerRadius::same((104.0 * s) as u8), t.accent);
    // `white` is how much white is mixed into the accent: opaque, so the caps don't blend twice with the line
    let arch = |left: f32, right: f32, top: f32, white: f32, width: f32| {
        let (cx, radius) = ((left + right) / 2.0, (right - left) / 2.0);
        let color = t.accent.lerp_to_gamma(Color32::WHITE, white);
        let mut pts = vec![at(left, 404.0)];
        for i in 0..=24 {
            let a = std::f32::consts::PI * (1.0 + i as f32 / 24.0);
            pts.push(at(cx + radius * a.cos(), top + radius * a.sin()));
        }
        pts.push(at(right, 404.0));
        // round caps, as in the svg
        for end in [pts[0], pts[pts.len() - 1]] {
            p.circle_filled(end, width * s / 2.0, color);
        }
        p.add(egui::Shape::line(pts, Stroke::new(width * s, color)));
    };
    arch(132.0, 380.0, 268.0, 1.0, 38.0);
    arch(204.0, 308.0, 276.0, 0.55, 28.0);
    response
}
