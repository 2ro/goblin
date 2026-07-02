// Copyright 2023 The Grim Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[macro_use]
extern crate rust_i18n;
rust_i18n::i18n!("locales");

use eframe::NativeOptions;
use egui::{Context, Stroke, Theme};
use lazy_static::lazy_static;
use parking_lot::RwLock;
use std::sync::Arc;

#[cfg(target_os = "android")]
use winit::platform::android::activity::AndroidApp;

pub use settings::AppConfig;
pub use settings::Settings;

use crate::gui::platform::PlatformCallbacks;
use crate::gui::views::View;
use crate::gui::{App, Colors};
use crate::node::Node;

pub mod gui;
mod http;
pub mod logger;
mod node;
pub mod nostr;
pub mod nym;
mod settings;
mod wallet;

/// Upstream GRIM version the fork is based on (third-party credit).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Goblin build number: commits on top of the GRIM base (see build.rs).
pub const BUILD: &str = env!("GOBLIN_BUILD");

/// Android platform entry point.
#[allow(dead_code)]
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
fn android_main(app: AndroidApp) {
	// Setup logger.
	logger::init_logger();

	use gui::platform::Android;
	let platform = Android::new(app.clone());
	use winit::platform::android::EventLoopBuilderExtAndroid;

	// Setup system theme if not set.
	if let None = AppConfig::dark_theme() {
		let use_dark = use_dark_theme(&platform);
		AppConfig::set_dark_theme(use_dark);
	}

	let width = app.config().screen_width_dp().unwrap() as f32;
	let height = app.config().screen_height_dp().unwrap() as f32;
	let size = egui::emath::vec2(width, height);
	let mut options = NativeOptions {
		android_app: Some(app.clone()),
		viewport: egui::ViewportBuilder::default().with_inner_size(size),
		..Default::default()
	};
	options.event_loop_builder = Some(Box::new(move |builder| {
		builder.with_android_app(app);
	}));

	let app = App::new(platform);
	start(options, app_creator(app)).unwrap();
}

/// Check if system is using dark theme.
#[allow(dead_code)]
#[cfg(target_os = "android")]
fn use_dark_theme(platform: &gui::platform::Android) -> bool {
	let res = platform
		.call_java_method("useDarkTheme", "()Z", &[])
		.unwrap();
	unsafe { res.z != 0 }
}

/// [`App`] setup for [`eframe`].
pub fn app_creator<T: 'static>(app: App<T>) -> eframe::AppCreator<'static>
where
	App<T>: eframe::App,
	T: PlatformCallbacks,
{
	Box::new(|cc| {
		// Setup images support.
		egui_extras::install_image_loaders(&cc.egui_ctx);
		// Bind fonts before the first frame: set_fonts inside a frame only
		// applies on the next pass, and the first-run onboarding references
		// named weight families (Geist) on frame one.
		setup_fonts(&cc.egui_ctx);
		Ok(Box::new(app))
	})
}

/// Entry point to start ui with [`eframe`].
pub fn start(options: NativeOptions, app_creator: eframe::AppCreator) -> eframe::Result<()> {
	// Pin rustls to the ring provider process-wide. Linking nym-sdk brings
	// aws-lc-rs into the graph alongside our ring; with two providers present
	// rustls 0.23 won't auto-select a default, and tokio-tungstenite/reqwest
	// would panic on the first TLS handshake. nym uses its own explicit provider,
	// so this only steers our relay/HTTP TLS. Idempotent (Err if already set).
	let _ = rustls::crypto::ring::default_provider().install_default();
	// Setup translations.
	setup_i18n();
	// Start integrated node if needed.
	if AppConfig::autostart_node() {
		Node::start();
	}
	// Pre-warm the in-process Nym mixnet tunnel so price/NIP-05/nostr are ready at
	// first use. All of Goblin's outbound traffic egresses through it; nothing
	// clearnet.
	nym::warm_up();
	// Launch graphical interface.
	eframe::run_native("Goblin", options, app_creator)
}

/// Setup application [`egui::Style`] and [`egui::Visuals`].
pub fn setup_visuals(ctx: &Context) {
	let use_dark = AppConfig::dark_theme().unwrap_or_else(|| {
		let use_dark = ctx.system_theme().unwrap_or(Theme::Dark) == Theme::Dark;
		AppConfig::set_dark_theme(use_dark);
		use_dark
	});

	let mut style = (*ctx.style()).clone();
	// Setup selection.
	style.interaction.selectable_labels = false;
	style.interaction.multi_widget_text_select = false;
	// Setup spacing for buttons.
	if View::is_desktop() {
		style.spacing.button_padding = egui::vec2(12.0, 8.0);
	} else {
		style.spacing.button_padding = egui::vec2(14.0, 10.0);
	}
	// Make scroll-bar thinner and lighter.
	style.spacing.scroll.bar_width = 4.0;
	style.spacing.scroll.bar_outer_margin = -2.0;
	style.spacing.scroll.foreground_color = false;
	// Disable spacing between items.
	style.spacing.item_spacing = egui::vec2(0.0, 0.0);
	style.spacing.text_edit_width = 500.0;
	// Setup radio button/checkbox size and spacing.
	style.spacing.icon_width = 24.0;
	style.spacing.icon_width_inner = 14.0;
	style.spacing.icon_spacing = 10.0;
	// Setup style
	ctx.set_style(style);

	// Setup visuals based on the Goblin theme tokens.
	let _ = use_dark;
	let t = gui::theme::tokens();
	let mut visuals = if t.dark_base {
		egui::Visuals::dark()
	} else {
		egui::Visuals::light()
	};
	// Base surfaces.
	visuals.panel_fill = t.bg;
	visuals.window_fill = t.surface;
	visuals.extreme_bg_color = t.surface2;
	visuals.faint_bg_color = t.surface2;
	// Default text inks.
	visuals.widgets.noninteractive.fg_stroke.color = t.text_dim;
	visuals.widgets.hovered.fg_stroke.color = t.text;
	visuals.widgets.active.fg_stroke.color = t.text;
	// Setup selection color.
	visuals.selection.stroke = Stroke {
		width: 1.0,
		color: t.accent_ink,
	};
	visuals.selection.bg_fill = t.accent;
	// Disable stroke around panels by default.
	visuals.widgets.noninteractive.bg_stroke = Stroke::NONE;
	// Setup stroke around inactive widgets.
	visuals.widgets.inactive.bg_stroke = View::default_stroke();
	// Setup background and foreground stroke color for widgets like pull-to-refresher.
	visuals.widgets.inactive.bg_fill = if t.dark_base { t.bg } else { t.accent };
	visuals.widgets.inactive.fg_stroke.color = Colors::item_button_text();
	// Hover/active fills.
	visuals.widgets.hovered.bg_fill = t.hover;
	visuals.widgets.active.bg_fill = t.hover;
	// Setup visuals.
	ctx.set_visuals(visuals);
}

/// Setup application fonts: Geist (+ weight families), Geist Mono,
/// Phosphor icons and Noto SC as CJK/ツ fallback.
pub fn setup_fonts(ctx: &Context) {
	use egui::FontFamily::{Monospace, Proportional};

	let mut fonts = egui::FontDefinitions::default();

	let plain = |bytes: &'static [u8]| Arc::new(egui::FontData::from_static(bytes));
	fonts.font_data.insert(
		"geist".to_owned(),
		plain(include_bytes!("../fonts/Geist-Regular.ttf")),
	);
	fonts.font_data.insert(
		"geist-medium".to_owned(),
		plain(include_bytes!("../fonts/Geist-Medium.ttf")),
	);
	fonts.font_data.insert(
		"geist-semibold".to_owned(),
		plain(include_bytes!("../fonts/Geist-SemiBold.ttf")),
	);
	fonts.font_data.insert(
		"geist-bold".to_owned(),
		plain(include_bytes!("../fonts/Geist-Bold.ttf")),
	);
	fonts.font_data.insert(
		"geist-mono".to_owned(),
		plain(include_bytes!("../fonts/GeistMono-Regular.ttf")),
	);
	fonts.font_data.insert(
		"geist-mono-sb".to_owned(),
		plain(include_bytes!("../fonts/GeistMono-SemiBold.ttf")),
	);
	fonts.font_data.insert(
		"phosphor".to_owned(),
		Arc::new(
			egui::FontData::from_static(include_bytes!("../fonts/phosphor.ttf")).tweak(
				egui::FontTweak {
					scale: 1.0,
					y_offset_factor: -0.04,
					y_offset: 0.0,
				},
			),
		),
	);
	fonts.font_data.insert(
		"noto".to_owned(),
		Arc::new(
			egui::FontData::from_static(include_bytes!("../fonts/noto_sc_reg.otf")).tweak(
				egui::FontTweak {
					scale: 1.0,
					y_offset_factor: -0.08,
					y_offset: 0.0,
				},
			),
		),
	);
	// Noto Sans JP subset — ONLY the ツ glyph (~1.7 KB), the mark on the center
	// Pay puck. A clean, geometric katakana tsu; referenced solely at that widget.
	fonts.font_data.insert(
		"noto-tsu".to_owned(),
		plain(include_bytes!("../fonts/NotoSansJpTsu.otf")),
	);

	// Default proportional stack: Geist first, icons and CJK/ツ as fallback.
	{
		let prop = fonts.families.entry(Proportional).or_default();
		prop.insert(0, "geist".to_owned());
		prop.insert(1, "phosphor".to_owned());
		prop.insert(2, "noto".to_owned());
	}
	// Monospace stack for amounts (tabular digits).
	{
		let mono = fonts.families.entry(Monospace).or_default();
		mono.insert(0, "geist-mono".to_owned());
		mono.insert(1, "phosphor".to_owned());
		mono.insert(2, "noto".to_owned());
	}
	// Named weight families, each with icon + CJK fallback.
	for name in [
		"geist-medium",
		"geist-semibold",
		"geist-bold",
		"geist-mono-sb",
	] {
		fonts.families.insert(
			egui::FontFamily::Name(name.into()),
			vec![name.to_owned(), "phosphor".to_owned(), "noto".to_owned()],
		);
	}
	// Puck ツ family: the subset first, then the normal fallbacks so anything
	// other than ツ still renders (the puck only ever draws ツ with it).
	fonts.families.insert(
		egui::FontFamily::Name("noto-tsu".into()),
		vec![
			"noto-tsu".to_owned(),
			"geist-bold".to_owned(),
			"noto".to_owned(),
		],
	);

	ctx.set_fonts(fonts);

	use egui::FontId;
	use egui::TextStyle;

	// NOTE: text_styles must only reference Proportional/Monospace families.
	// set_fonts() applies on the next pass while set_style() is immediate; a
	// default text style referencing a custom Name family would panic on the
	// first frame before the fonts swap in. Goblin weights are applied at the
	// widget call sites via RichText::font(), which render after the swap.
	let mut style = (*ctx.style()).clone();
	style.text_styles = [
		(TextStyle::Heading, FontId::new(19.0, Proportional)),
		(TextStyle::Body, FontId::new(16.0, Proportional)),
		(TextStyle::Button, FontId::new(17.0, Proportional)),
		(TextStyle::Small, FontId::new(15.0, Proportional)),
		(
			TextStyle::Monospace,
			FontId::new(16.0, egui::FontFamily::Monospace),
		),
	]
	.into();

	ctx.set_style(style);
}

/// Setup translations.
fn setup_i18n() {
	// Set saved locale or get from system.
	if let Some(lang) = AppConfig::locale() {
		if rust_i18n::available_locales!().contains(&lang.as_str()) {
			rust_i18n::set_locale(lang.as_str());
		}
	} else {
		let locale = sys_locale::get_locale().unwrap_or(String::from(AppConfig::DEFAULT_LOCALE));
		// sys_locale may hand back either `zh-CN` or `zh_CN`; normalize the
		// separator so a region-specific locale can match its file name.
		let normalized = locale.replace('_', "-");
		let available = rust_i18n::available_locales!();
		// Prefer an exact region match (e.g. `zh-CN`, the only CJK locale and one
		// the bare-subtag fallback could never reach), then the language subtag
		// (e.g. `de` from `de-DE`), else the default.
		let primary = normalized
			.split('-')
			.next()
			.unwrap_or(AppConfig::DEFAULT_LOCALE);
		if available.contains(&normalized.as_str()) {
			rust_i18n::set_locale(normalized.as_str());
		} else if available.contains(&primary) {
			rust_i18n::set_locale(primary);
		} else {
			rust_i18n::set_locale(AppConfig::DEFAULT_LOCALE);
		}
	}
}

/// Get data from deeplink or opened file.
pub fn consume_incoming_data() -> Option<String> {
	let has_data = {
		let r_data = INCOMING_DATA.read();
		r_data.is_some()
	};
	if has_data {
		// Clear data.
		let mut w_data = INCOMING_DATA.write();
		let data = w_data.clone();
		*w_data = None;
		return data;
	}
	None
}

/// Provide data from deeplink or opened file.
pub fn on_data(data: String) {
	let mut w_data = INCOMING_DATA.write();
	*w_data = Some(data);
}

/// Unix-seconds timestamp of the most recent GUI frame. Background workers read
/// it to tell whether the app is actually on-screen: while the app is
/// backgrounded, eframe stops calling the per-frame draw and this stops
/// advancing. Crate-root so both `gui` and `nostr` can reach it without coupling.
static LAST_FRAME_AT: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

/// A frame older than this many seconds means the app isn't drawing — i.e. it's
/// backgrounded/occluded. The GUI keeps a ~2s repaint heartbeat while visible, so
/// this leaves a couple of frames of margin before declaring "not foreground".
const FOREGROUND_STALE_SECS: i64 = 5;

fn now_unix_secs() -> i64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs() as i64)
		.unwrap_or(0)
}

/// Stamp that the GUI just drew a frame. Called once per frame from the app loop.
pub fn mark_frame() {
	LAST_FRAME_AT.store(now_unix_secs(), std::sync::atomic::Ordering::Relaxed);
}

/// True when the GUI drew a frame within the last few seconds — i.e. the app is
/// foreground and visible. While backgrounded (no frames), returns false, so
/// periodic background work (the @name re-verify sweep) can pause and catch up
/// on resume instead of burning mixnet round-trips while nobody's looking.
pub fn app_foreground() -> bool {
	let last = LAST_FRAME_AT.load(std::sync::atomic::Ordering::Relaxed);
	last != 0 && now_unix_secs() - last <= FOREGROUND_STALE_SECS
}

/// Fire the platform "payment received" notification with the payer's display
/// name and human-readable amount. Android shows a one-shot system
/// notification (`BackgroundService.notifyPaymentReceived`, id=2, separate
/// from the persistent sync notification); other platforms are a no-op.
/// Crate-root so the nostr service can reach it without holding a platform
/// reference.
pub fn notify_payment_received(name: &str, amount: &str) {
	#[cfg(target_os = "android")]
	gui::platform::notify_payment_received(name, amount);
	#[cfg(not(target_os = "android"))]
	{
		let _ = (name, amount);
	}
}

lazy_static! {
	/// Data provided from deeplink or opened file.
	pub static ref INCOMING_DATA: Arc<RwLock<Option<String>>> = Arc::new(RwLock::new(None));
}

/// Callback from Java code with passed data.
#[allow(dead_code)]
#[allow(non_snake_case)]
#[cfg(target_os = "android")]
#[unsafe(no_mangle)]
pub extern "C" fn Java_mw_gri_android_MainActivity_onData(
	_env: jni::JNIEnv,
	_class: jni::objects::JObject,
	char: jni::sys::jstring,
) {
	unsafe {
		let j_obj = jni::objects::JString::from_raw(char);
		if let Ok(j_str) = _env.get_string_unchecked(j_obj.as_ref()) {
			match j_str.to_str() {
				Ok(str) => {
					let mut w_path = INCOMING_DATA.write();
					*w_path = Some(str.to_string());
				}
				Err(_) => {}
			}
		};
	}
}
