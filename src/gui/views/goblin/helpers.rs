// Copyright 2026 The Goblin Developers
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

//! Shared row / button / style helpers.

use super::*;

/// Draw the small Goblin mascot mark.
pub fn widgets_logo(ui: &mut egui::Ui) {
	widgets_logo_sized(ui, 24.0);
}

/// Tinted goblin mark at a given size.
pub fn widgets_logo_sized(ui: &mut egui::Ui, size: f32) {
	let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
	// Chip-sized marks use a pre-rendered 48px raster: cleaner antialiasing
	// at ~24px than runtime svg rasterization, with 2x headroom for hidpi.
	let img = egui::Image::new(if size <= 32.0 {
		egui::include_image!("../../../../img/goblin-logo2-48.png")
	} else {
		egui::include_image!("../../../../img/goblin-logo2.svg")
	})
	.tint(theme::tokens().text)
	.fit_to_exact_size(Vec2::splat(size));
	img.paint_at(ui, rect);
}

pub(super) fn empty_state(ui: &mut egui::Ui, title: &str, subtitle: &str) {
	let t = theme::tokens();
	ui.add_space(40.0);
	ui.vertical_centered(|ui| {
		ui.label(
			RichText::new(title)
				.font(FontId::new(17.0, fonts::semibold()))
				.color(t.text),
		);
		ui.add_space(4.0);
		ui.label(
			RichText::new(subtitle)
				.font(FontId::new(14.0, fonts::regular()))
				.color(t.text_dim),
		);
	});
}

pub(super) fn settings_group(ui: &mut egui::Ui, title: &str, add: impl FnOnce(&mut egui::Ui)) {
	w::kicker(ui, title);
	ui.add_space(8.0);
	w::card(ui, |ui| add(ui));
}

/// Title row for an Advanced-page action card.
pub(super) fn advanced_head(ui: &mut egui::Ui, label: &str, color: Color32) {
	ui.label(
		RichText::new(label)
			.font(FontId::new(15.0, fonts::semibold()))
			.color(color),
	);
	ui.add_space(4.0);
}

/// Wrapped description line under an Advanced-page action title.
pub(super) fn advanced_desc(ui: &mut egui::Ui, text: &str) {
	let t = theme::tokens();
	ui.label(
		RichText::new(text)
			.font(FontId::new(13.0, fonts::regular()))
			.color(t.surface_text_dim),
	);
}

/// A settings row: label + subtitle on the left, an on/off switch on the right.
/// Returns `Some(new_value)` on the frame it is toggled.
pub(super) fn settings_row_toggle(
	ui: &mut egui::Ui,
	label: &str,
	sub: &str,
	on: bool,
) -> Option<bool> {
	let t = theme::tokens();
	let mut toggled = None;
	ui.horizontal(|ui| {
		// Reserve room for the switch and bound the text column, so a long
		// label/subtitle WRAPS onto another line instead of running under the
		// switch and clipping (longer locales clipped worst). 46px switch + gap.
		let toggle_w = 58.0;
		let text_w = (ui.available_width() - toggle_w).max(0.0);
		ui.vertical(|ui| {
			ui.set_width(text_w);
			ui.label(
				RichText::new(label)
					.font(FontId::new(15.0, fonts::medium()))
					.color(t.surface_text),
			);
			ui.label(
				RichText::new(sub)
					.font(FontId::new(13.0, fonts::regular()))
					.color(t.surface_text_dim),
			);
		});
		ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
			if w::toggle(ui, on).clicked() {
				toggled = Some(!on);
			}
		});
	});
	ui.add_space(10.0);
	toggled
}

pub(super) fn settings_row(ui: &mut egui::Ui, label: &str, value: &str) {
	settings_row_ink(ui, label, value, theme::tokens().surface_text_dim);
}

/// Like [`settings_row`] but the value is drawn in an explicit ink — used to flag
/// the always-on Tor routing in the privacy color.
pub(super) fn settings_row_ink(ui: &mut egui::Ui, label: &str, value: &str, value_ink: Color32) {
	let t = theme::tokens();
	ui.horizontal(|ui| {
		ui.label(
			RichText::new(label)
				.font(FontId::new(15.0, fonts::medium()))
				.color(t.surface_text),
		);
		ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
			ui.label(
				RichText::new(value)
					.font(FontId::new(13.0, fonts::regular()))
					.color(value_ink),
			);
		});
	});
	ui.add_space(10.0);
}

pub(super) fn settings_row_btn(ui: &mut egui::Ui, label: &str, icon: &str) -> bool {
	let t = theme::tokens();
	let mut clicked = false;
	let row = ui.horizontal(|ui| {
		ui.label(
			RichText::new(label)
				.font(FontId::new(15.0, fonts::medium()))
				.color(t.surface_text),
		);
		ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
			let resp = ui.label(
				RichText::new(icon)
					.font(FontId::new(18.0, fonts::regular()))
					.color(t.surface_text_dim),
			);
			if resp.interact(Sense::click()).clicked() {
				clicked = true;
			}
		});
	});
	ui.add_space(10.0);
	// The whole row is tappable, not just the trailing value/icon.
	clicked || row.response.interact(Sense::click()).clicked()
}

/// A danger-styled settings row button (whole row taps).
pub(super) fn settings_row_danger(ui: &mut egui::Ui, label: &str, icon: &str) -> bool {
	let t = theme::tokens();
	let row = ui.horizontal(|ui| {
		ui.label(
			RichText::new(label)
				.font(FontId::new(15.0, fonts::medium()))
				.color(t.neg),
		);
		ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
			ui.label(
				RichText::new(icon)
					.font(FontId::new(18.0, fonts::regular()))
					.color(t.neg),
			);
		});
	});
	ui.add_space(10.0);
	row.response.interact(Sense::click()).clicked()
}

/// A settings row whose value cycles in place on tap (no navigation): the
/// value is drawn in the same small/dim style as [`settings_row_nav`] so it
/// sits consistently next to chevroned siblings, just without the chevron.
pub(super) fn settings_row_cycle(ui: &mut egui::Ui, label: &str, value: &str) -> bool {
	let t = theme::tokens();
	let row = ui.horizontal(|ui| {
		ui.label(
			RichText::new(label)
				.font(FontId::new(15.0, fonts::medium()))
				.color(t.surface_text),
		);
		ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
			ui.label(
				RichText::new(value)
					.font(FontId::new(13.0, fonts::regular()))
					.color(t.surface_text_dim),
			);
		});
	});
	ui.add_space(10.0);
	row.response.interact(Sense::click()).clicked()
}

/// A settings row that navigates somewhere: value + chevron, whole row taps.
pub(super) fn settings_row_nav(ui: &mut egui::Ui, label: &str, value: &str) -> bool {
	let t = theme::tokens();
	let row = ui.horizontal(|ui| {
		ui.label(
			RichText::new(label)
				.font(FontId::new(15.0, fonts::medium()))
				.color(t.surface_text),
		);
		ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
			ui.label(
				RichText::new(crate::gui::icons::CARET_RIGHT)
					.font(FontId::new(13.0, fonts::regular()))
					.color(t.surface_text_mute),
			);
			ui.add_space(4.0);
			ui.label(
				RichText::new(value)
					.font(FontId::new(13.0, fonts::regular()))
					.color(t.surface_text_dim),
			);
		});
	});
	ui.add_space(10.0);
	row.response.interact(Sense::click()).clicked()
}

/// Open a URL in the system browser.
pub(super) fn open_url(ui: &egui::Ui, url: &str) {
	ui.ctx().open_url(egui::OpenUrl::new_tab(url));
}

/// Linear blend between two colors (`p` 0→`a`, 1→`b`). Used by the Pay-screen
/// over-balance flash to ease the digits from red back to normal ink.
pub(super) fn lerp_color(a: Color32, b: Color32, p: f32) -> Color32 {
	let p = p.clamp(0.0, 1.0);
	let mix = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * p).round() as u8;
	Color32::from_rgb(mix(a.r(), b.r()), mix(a.g(), b.g()), mix(a.b(), b.b()))
}

pub(super) fn approve_button(ui: &mut egui::Ui) -> bool {
	w::big_action(ui, &t!("goblin.request.approve"), false).clicked()
}

pub(super) fn decline_button(ui: &mut egui::Ui) -> bool {
	w::big_action(ui, &t!("goblin.request.decline"), true).clicked()
}

pub(super) fn accept_policy_label(wallet: &Wallet) -> String {
	use crate::nostr::config::AcceptPolicy;
	wallet
		.nostr_service()
		.map(|s| match s.config.read().accept_from() {
			AcceptPolicy::Everyone => t!("goblin.settings.accept_anyone").to_string(),
			AcceptPolicy::Contacts => t!("goblin.settings.accept_contacts").to_string(),
			AcceptPolicy::Ask => t!("goblin.settings.accept_ask").to_string(),
		})
		.unwrap_or_else(|| t!("goblin.settings.accept_anyone").to_string())
}

/// Cycle the color theme Dark ↔ Light and re-apply visuals. Yellow is kept
/// defined (gui/theme.rs) but out of the picker for now — it's still in beta;
/// `Yellow => Dark` is an escape hatch for anyone whose config already has it.
pub(super) fn cycle_theme(ctx: &egui::Context) {
	use crate::gui::theme::ThemeKind;
	let next = match crate::AppConfig::theme() {
		ThemeKind::Dark => ThemeKind::Light,
		ThemeKind::Light => ThemeKind::Dark,
		ThemeKind::Yellow => ThemeKind::Dark,
	};
	crate::AppConfig::set_theme(next);
	crate::setup_visuals(ctx);
}

/// Cycle the density Comfy → Regular → Compact → Comfy.
/// Cycle the incoming-payment accept policy Anyone → Contacts → Ask → Anyone.
pub(super) fn cycle_accept_policy(wallet: &Wallet) {
	use crate::nostr::config::AcceptPolicy;
	if let Some(s) = wallet.nostr_service() {
		let next = match s.config.read().accept_from() {
			AcceptPolicy::Everyone => AcceptPolicy::Contacts,
			AcceptPolicy::Contacts => AcceptPolicy::Ask,
			AcceptPolicy::Ask => AcceptPolicy::Everyone,
		};
		s.config.write().set_accept_from(next);
	}
}

impl GoblinWalletView {
	/// Round back button + title for full-surface overlays. Returns true on tap.
	pub(super) fn overlay_back_header(ui: &mut egui::Ui, title: &str) -> bool {
		let t = theme::tokens();
		let mut back = false;
		ui.horizontal(|ui| {
			let (rect, resp) = ui.allocate_exact_size(Vec2::splat(36.0), Sense::click());
			ui.painter().circle_filled(rect.center(), 18.0, t.surface2);
			ui.painter().text(
				rect.center(),
				egui::Align2::CENTER_CENTER,
				ARROW_LEFT,
				FontId::new(16.0, fonts::regular()),
				t.text,
			);
			back = resp
				.on_hover_cursor(egui::CursorIcon::PointingHand)
				.clicked();
			ui.add_space(12.0);
			ui.label(
				RichText::new(title)
					.font(FontId::new(18.0, fonts::bold()))
					.color(t.text),
			);
		});
		ui.add_space(12.0);
		back
	}
}
