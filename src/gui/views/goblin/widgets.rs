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

//! Reusable Goblin design widgets: avatars, amounts, buttons, rows, chips.

use eframe::epaint::{CornerRadius, FontId, Stroke};
use egui::{Align, Color32, Layout, Response, RichText, Sense, Ui, Vec2};

use crate::gui::theme::{self, fonts};

/// Currency mark for grin amounts.
pub const TSU: &str = "ツ";

/// Format atomic grin units to a trimmed human string (no unit).
pub fn amount_str(atomic: u64) -> String {
	grin_core::core::amount_to_hr_string(atomic, true)
}

/// Draw a colored avatar puck with the contact initial.
pub fn avatar(ui: &mut Ui, name: &str, size: f32, hue: usize) -> Response {
	let (rect, resp) = ui.allocate_exact_size(Vec2::splat(size), Sense::click());
	let (bg, ink) = theme::avatar_pair(hue);
	ui.painter().circle_filled(rect.center(), size / 2.0, bg);
	// First letter of the name — never the @ prefix or other decoration.
	let initial = name
		.chars()
		.find(|c| c.is_alphanumeric())
		.map(|c| c.to_uppercase().to_string())
		.unwrap_or_else(|| "?".to_string());
	ui.painter().text(
		rect.center(),
		egui::Align2::CENTER_CENTER,
		initial,
		FontId::new(size * 0.42, fonts::bold()),
		ink,
	);
	resp
}

/// A custom-picture avatar: the texture drawn in a circle.
pub fn avatar_tex(ui: &mut Ui, tex: &egui::TextureHandle, size: f32) -> Response {
	let (rect, resp) = ui.allocate_exact_size(Vec2::splat(size), Sense::click());
	let rounding = eframe::epaint::CornerRadius::same((size / 2.0) as u8);
	egui::Image::new(tex)
		.corner_radius(rounding)
		.fit_to_exact_size(Vec2::splat(size))
		.paint_at(ui, rect);
	resp
}

/// Picture avatar when a texture exists, letter avatar otherwise.
pub fn avatar_any(
	ui: &mut Ui,
	name: &str,
	size: f32,
	hue: usize,
	tex: Option<&egui::TextureHandle>,
) -> Response {
	match tex {
		Some(t) => avatar_tex(ui, t, size),
		None => avatar(ui, name, size, hue),
	}
}

/// Draw a balance/amount: big bold number + smaller ツ mark, tight.
/// Geist (sans) per the design; mono is reserved for kernel/block ids.
pub fn amount_text(ui: &mut Ui, value: &str, size: f32) {
	let t = theme::tokens();
	ui.horizontal(|ui| {
		ui.spacing_mut().item_spacing.x = 0.0;
		ui.label(
			RichText::new(value)
				.font(FontId::new(size, fonts::bold()))
				.color(t.text),
		);
		ui.add_space(1.0);
		ui.label(
			RichText::new(TSU)
				.font(FontId::new(size * 0.4, fonts::medium()))
				.color(t.text_dim),
		);
	});
}

/// Like [`amount_text`] but centered in the available width.
pub fn amount_text_centered(ui: &mut Ui, value: &str, size: f32) {
	let t = theme::tokens();
	amount_text_centered_ink(ui, value, size, t.text, t.text_dim);
}

/// Centered amount with explicit inks, for drawing on card surfaces.
pub fn amount_text_centered_ink(
	ui: &mut Ui,
	value: &str,
	size: f32,
	num_ink: Color32,
	mark_ink: Color32,
) {
	let num =
		ui.painter()
			.layout_no_wrap(value.to_string(), FontId::new(size, fonts::bold()), num_ink);
	let mark = ui.painter().layout_no_wrap(
		TSU.to_string(),
		FontId::new(size * 0.4, fonts::medium()),
		mark_ink,
	);
	let total = num.size().x + 1.0 + mark.size().x;
	ui.horizontal(|ui| {
		ui.spacing_mut().item_spacing.x = 0.0;
		ui.add_space(((ui.available_width() - total) / 2.0).max(0.0));
		ui.label(
			RichText::new(value)
				.font(FontId::new(size, fonts::bold()))
				.color(num_ink),
		);
		ui.add_space(1.0);
		ui.label(
			RichText::new(TSU)
				.font(FontId::new(size * 0.4, fonts::medium()))
				.color(mark_ink),
		);
	});
}

/// An uppercase letterspaced kicker label.
pub fn kicker(ui: &mut Ui, text: &str) {
	let t = theme::tokens();
	ui.label(
		RichText::new(text.to_uppercase())
			.font(fonts::kicker())
			.color(t.text_mute),
	);
}

/// Big primary/secondary action button (56px, radius 14).
pub fn big_action(ui: &mut Ui, label: &str, secondary: bool) -> Response {
	let t = theme::tokens();
	let desired = Vec2::new(ui.available_width(), 56.0);
	let (rect, resp) = ui.allocate_exact_size(desired, Sense::click());
	let (fill, ink, stroke) = if secondary {
		(Color32::TRANSPARENT, t.text, Stroke::new(1.5, t.line))
	} else {
		(t.accent, t.accent_ink, Stroke::NONE)
	};
	let visual_fill = if resp.hovered() && !secondary {
		t.accent_dark
	} else {
		fill
	};
	ui.painter().rect(
		rect,
		CornerRadius::same(14),
		visual_fill,
		stroke,
		egui::StrokeKind::Inside,
	);
	ui.painter().text(
		rect.center(),
		egui::Align2::CENTER_CENTER,
		label,
		FontId::new(17.0, fonts::semibold()),
		ink,
	);
	resp
}

/// Secondary big action drawn on a card surface: same shape as
/// [`big_action`], but the label uses on-surface text so it stays readable
/// on the yellow theme's dark cards.
pub fn big_action_on_card(ui: &mut Ui, label: &str) -> Response {
	let t = theme::tokens();
	let desired = Vec2::new(ui.available_width(), 56.0);
	let (rect, resp) = ui.allocate_exact_size(desired, Sense::click());
	ui.painter().rect(
		rect,
		CornerRadius::same(14),
		Color32::TRANSPARENT,
		Stroke::new(1.5, t.line),
		egui::StrokeKind::Inside,
	);
	ui.painter().text(
		rect.center(),
		egui::Align2::CENTER_CENTER,
		label,
		FontId::new(17.0, fonts::semibold()),
		t.surface_text,
	);
	resp
}

/// Like [`big_action_on_card`] with an explicit label ink (danger actions).
pub fn big_action_on_card_ink(ui: &mut Ui, label: &str, ink: Color32) -> Response {
	let t = theme::tokens();
	let desired = Vec2::new(ui.available_width(), 44.0);
	let (rect, resp) = ui.allocate_exact_size(desired, Sense::click());
	ui.painter().rect(
		rect,
		CornerRadius::same(14),
		Color32::TRANSPARENT,
		Stroke::new(1.5, t.line),
		egui::StrokeKind::Inside,
	);
	ui.painter().text(
		rect.center(),
		egui::Align2::CENTER_CENTER,
		label,
		FontId::new(15.0, fonts::semibold()),
		ink,
	);
	resp
}

/// A pill/chip; returns the click response. `active` paints it inverted.
pub fn chip(ui: &mut Ui, label: &str, active: bool) -> Response {
	let t = theme::tokens();
	let galley = ui.painter().layout_no_wrap(
		label.to_string(),
		FontId::new(13.0, fonts::semibold()),
		if active { t.bg } else { t.surface_text },
	);
	let pad = Vec2::new(14.0, 8.0);
	let size = galley.size() + pad * 2.0;
	let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
	let fill = if active { t.text } else { t.surface2 };
	ui.painter().rect(
		rect,
		CornerRadius::same(255),
		fill,
		Stroke::NONE,
		egui::StrokeKind::Inside,
	);
	ui.painter().galley(
		rect.center() - galley.size() / 2.0,
		galley,
		if active { t.bg } else { t.surface_text },
	);
	resp
}

/// An outline pill chip (transparent fill, line border) per the design's
/// amount quick-select row.
pub fn chip_outline(ui: &mut Ui, label: &str) -> Response {
	let t = theme::tokens();
	let galley = ui.painter().layout_no_wrap(
		label.to_string(),
		FontId::new(13.0, fonts::semibold()),
		t.text,
	);
	let pad = Vec2::new(14.0, 8.0);
	let size = galley.size() + pad * 2.0;
	let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
	ui.painter().rect(
		rect,
		CornerRadius::same(255),
		Color32::TRANSPARENT,
		Stroke::new(1.0, t.line),
		egui::StrokeKind::Inside,
	);
	ui.painter()
		.galley(rect.center() - galley.size() / 2.0, galley, t.text);
	resp
}

/// Paint a QR code for `text` with the goblin mark centered, per the
/// design's receive card. Always dark modules on a white plate, whatever the
/// theme: inverted (light-on-dark) codes fail to decode in a number of
/// scanner apps. Encoding a short URI is microseconds, so this is done
/// synchronously each frame; modules are plain painter rects.
pub fn qr_code(ui: &mut Ui, text: &str, size: f32) {
	let plate = Color32::WHITE;
	let ink = Color32::from_rgb(0x0E, 0x0E, 0x0C);
	// High error correction tolerates the center mark covering modules.
	let Ok(qr) = qrcodegen::QrCode::encode_text(text, qrcodegen::QrCodeEcc::High) else {
		return;
	};
	let pad = (size * 0.05).max(8.0);
	let (outer, _) = ui.allocate_exact_size(Vec2::splat(size + pad * 2.0), Sense::hover());
	ui.painter()
		.rect_filled(outer, CornerRadius::same(16), plate);
	let rect = outer.shrink(pad);
	let n = qr.size();
	let cell = size / n as f32;
	// Full cells with no inter-module gap: at receive-card density (~4.5px
	// cells) even a 0.5px gap fragments the finder patterns and scanners
	// fail to detect the code at all (probed with rqrr). Corner rounding
	// only when cells are big enough that the notching can't matter.
	let radius = if cell >= 6.0 { (cell * 0.3) as u8 } else { 0 };
	for y in 0..n {
		for x in 0..n {
			if qr.get_module(x, y) {
				let min = rect.min + Vec2::new(x as f32 * cell, y as f32 * cell);
				ui.painter().rect_filled(
					egui::Rect::from_min_size(min, Vec2::splat(cell)),
					CornerRadius::same(radius),
					ink,
				);
			}
		}
	}
	// Goblin mark on a plate-colored backing square in the center. 19% of
	// the code: at 26%, zbar-class scanners fail on the glyph (rqrr and
	// ZXing-class tolerate it); 19% passes everything probed.
	let backing = size * 0.19;
	let b_rect = egui::Rect::from_center_size(rect.center(), Vec2::splat(backing));
	ui.painter()
		.rect_filled(b_rect, CornerRadius::same((backing * 0.18) as u8), plate);
	let m_rect = egui::Rect::from_center_size(rect.center(), Vec2::splat(backing * 0.72));
	egui::Image::new(egui::include_image!("../../../../img/goblin-logo2.svg"))
		.tint(ink)
		.fit_to_exact_size(m_rect.size())
		.paint_at(ui, m_rect);
}

/// A filled input well for a text field sitting on a card, so the field
/// reads as a field: frameless edits on the card fill are invisible.
pub fn field_well(ui: &mut Ui, content: impl FnOnce(&mut Ui)) {
	let t = theme::tokens();
	egui::Frame {
		fill: t.surface2,
		stroke: Stroke::new(1.0, t.line),
		corner_radius: CornerRadius::same(10),
		inner_margin: egui::Margin::symmetric(12, 10),
		..Default::default()
	}
	.show(ui, |ui| {
		ui.set_min_width(ui.available_width());
		content(ui);
	});
}

/// A balance hero block: kicker, big number + ツ, optional fiat line.
pub fn balance_hero(ui: &mut Ui, atomic: u64, fiat: Option<&str>, size: f32) {
	let t = theme::tokens();
	// Centered to match the Pay amount and the empty-state below it.
	ui.vertical_centered(|ui| kicker(ui, "Balance"));
	ui.add_space(6.0);
	amount_text_centered(ui, &amount_str(atomic), size);
	if let Some(fiat) = fiat {
		ui.add_space(4.0);
		ui.vertical_centered(|ui| {
			ui.label(
				RichText::new(fiat)
					.font(FontId::new(13.0, fonts::regular()))
					.color(t.text_dim),
			);
		});
	}
}

/// An activity row: avatar, title, subtitle, signed amount.
/// Returns the row click response.
pub fn activity_row(
	ui: &mut Ui,
	title: &str,
	subtitle: &str,
	hue: usize,
	amount: &str,
	incoming: bool,
	system: bool,
	tex: Option<&egui::TextureHandle>,
) -> Response {
	let t = theme::tokens();
	let row_h = 60.0;
	let (rect, resp) =
		ui.allocate_exact_size(Vec2::new(ui.available_width(), row_h), Sense::click());
	let mut content = ui.new_child(
		egui::UiBuilder::new()
			.max_rect(rect.shrink2(Vec2::new(0.0, 8.0)))
			.layout(Layout::left_to_right(Align::Center)),
	);
	content.horizontal(|ui| {
		if system {
			let (r, _) = ui.allocate_exact_size(Vec2::splat(40.0), Sense::hover());
			ui.painter().rect(
				r,
				CornerRadius::same(10),
				t.surface2,
				Stroke::NONE,
				egui::StrokeKind::Inside,
			);
			ui.painter().text(
				r.center(),
				egui::Align2::CENTER_CENTER,
				crate::gui::icons::CUBE,
				FontId::new(20.0, fonts::regular()),
				t.text,
			);
		} else {
			avatar_any(ui, title, 40.0, hue, tex);
		}
		ui.add_space(12.0);
		ui.vertical(|ui| {
			ui.add_space(2.0);
			ui.label(
				RichText::new(title)
					.font(FontId::new(15.0, fonts::semibold()))
					.color(t.text),
			);
			ui.label(
				RichText::new(subtitle)
					.font(FontId::new(13.0, fonts::regular()))
					.color(t.text_dim),
			);
		});
		ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
			ui.label(
				RichText::new(amount)
					.font(FontId::new(15.0, fonts::mono_semibold()))
					.color(if incoming { t.pos } else { t.text }),
			);
		});
	});
	// Divider.
	let line_y = rect.bottom();
	ui.painter()
		.hline(rect.left()..=rect.right(), line_y, Stroke::new(1.0, t.line));
	resp
}

/// Section header used above grouped lists.
pub fn section_header(ui: &mut Ui, text: &str) {
	ui.add_space(8.0);
	kicker(ui, text);
	ui.add_space(6.0);
}

/// Draw a rounded surface card and run a closure inside it.
pub fn card<R>(ui: &mut Ui, add_contents: impl FnOnce(&mut Ui) -> R) -> R {
	let t = theme::tokens();
	egui::Frame::new()
		.fill(t.surface)
		.stroke(Stroke::new(1.0, t.line))
		.corner_radius(CornerRadius::same(18))
		.inner_margin(16.0)
		.show(ui, add_contents)
		.inner
}

/// A bordered rect helper for non-interactive value rows.
pub fn info_row(ui: &mut Ui, label: &str, value: &str) {
	let t = theme::tokens();
	ui.horizontal(|ui| {
		ui.label(
			RichText::new(label)
				.font(FontId::new(14.0, fonts::regular()))
				.color(t.text_dim),
		);
		ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
			ui.label(
				RichText::new(value)
					.font(FontId::new(15.0, fonts::semibold()))
					.color(t.text),
			);
		});
	});
	ui.add_space(8.0);
	ui.painter().hline(
		ui.min_rect().left()..=ui.min_rect().right(),
		ui.cursor().top(),
		Stroke::new(1.0, t.line),
	);
	ui.add_space(8.0);
}

/// Draw a centered Send / Receive split. Returns (send, receive) clicks.
pub fn send_receive(ui: &mut Ui) -> (bool, bool) {
	let t = theme::tokens();
	let mut send = false;
	let mut receive = false;
	let h = 60.0;
	ui.horizontal(|ui| {
		let w = (ui.available_width() - 10.0) / 2.0;
		let (rs, resp_s) = ui.allocate_exact_size(Vec2::new(w, h), Sense::click());
		ui.painter().rect(
			rs,
			CornerRadius::same(14),
			if resp_s.hovered() {
				t.accent_dark
			} else {
				t.accent
			},
			Stroke::NONE,
			egui::StrokeKind::Inside,
		);
		ui.painter().text(
			rs.center(),
			egui::Align2::CENTER_CENTER,
			format!("{}  Send", crate::gui::icons::ARROW_UP),
			FontId::new(16.0, fonts::semibold()),
			t.accent_ink,
		);
		send = resp_s.clicked();
		ui.add_space(10.0);
		let (rr, resp_r) = ui.allocate_exact_size(Vec2::new(w, h), Sense::click());
		let r_fill = if resp_r.hovered() {
			t.hover
		} else {
			t.surface2
		};
		ui.painter().rect(
			rr,
			CornerRadius::same(14),
			r_fill,
			Stroke::NONE,
			egui::StrokeKind::Inside,
		);
		ui.painter().text(
			rr.center(),
			egui::Align2::CENTER_CENTER,
			format!("{}  Receive", crate::gui::icons::ARROW_DOWN),
			FontId::new(16.0, fonts::semibold()),
			theme::ink_for(r_fill),
		);
		receive = resp_r.clicked();
	});
	(send, receive)
}

/// A simple numeric keypad. Mutates `amount` string. Returns true if changed.
pub fn numpad(ui: &mut Ui, amount: &mut String) -> bool {
	let t = theme::tokens();
	let mut changed = false;
	let keys = [
		["1", "2", "3"],
		["4", "5", "6"],
		["7", "8", "9"],
		[".", "0", "<"],
	];
	let key_h = 58.0;
	let gap = 14.0;
	// Center a fixed-width pad so the three columns line up directly under
	// the centered amount above, on any width. Wider than before to give the
	// columns more breathing room (Cash App-style).
	let pad_w = ui.available_width().min(332.0);
	let key_w = (pad_w - 2.0 * gap) / 3.0;
	let side = ((ui.available_width() - pad_w) / 2.0).max(0.0);
	// Spread the four rows toward the bottom when there's room (the Pay tab,
	// which otherwise leaves a big empty gap), staying compact on dense
	// screens (the send flow). Reserve space below for the action buttons and
	// the floating tab bar. Clamped so it never stretches absurdly or overflows.
	let reserve_below = 170.0;
	let avail = (ui.available_height() - reserve_below).max(0.0);
	let row_gap = ((avail - key_h * 4.0) / 3.0).clamp(6.0, 30.0);
	for (ri, row) in keys.iter().enumerate() {
		if ri > 0 {
			ui.add_space(row_gap);
		}
		ui.horizontal(|ui| {
			ui.add_space(side);
			for (i, &k) in row.iter().enumerate() {
				if i > 0 {
					ui.add_space(gap);
				}
				let (rect, resp) = ui.allocate_exact_size(Vec2::new(key_w, key_h), Sense::click());
				let label = if k == "<" {
					crate::gui::icons::BACKSPACE.to_string()
				} else {
					k.to_string()
				};
				let col = if resp.hovered() { t.accent } else { t.text };
				ui.painter().text(
					rect.center(),
					egui::Align2::CENTER_CENTER,
					label,
					FontId::new(30.0, fonts::medium()),
					col,
				);
				if resp.clicked() {
					apply_key(amount, k);
					changed = true;
				}
			}
		});
	}
	changed
}

/// Apply a numpad key to the amount string with validation.
/// Apply typed keyboard events (digits, '.', backspace) to an amount string,
/// for desktop where the on-screen numpad is hidden.
pub fn amount_typed_input(ui: &Ui, amount: &mut String) {
	ui.input(|i| {
		for ev in &i.events {
			if let egui::Event::Text(txt) = ev {
				for ch in txt.chars() {
					if ch.is_ascii_digit() {
						apply_key(amount, &ch.to_string());
					} else if ch == '.' {
						apply_key(amount, ".");
					}
				}
			}
			if let egui::Event::Key {
				key: egui::Key::Backspace,
				pressed: true,
				..
			} = ev
			{
				apply_key(amount, "<");
			}
		}
	});
}

pub fn apply_key(amount: &mut String, key: &str) {
	match key {
		"<" => {
			amount.pop();
		}
		"." => {
			if !amount.contains('.') {
				if amount.is_empty() {
					amount.push('0');
				}
				amount.push('.');
			}
		}
		d => {
			// Limit to 9 decimals (grin precision).
			if let Some(dot) = amount.find('.') {
				if amount.len() - dot - 1 >= 9 {
					return;
				}
			}
			// Avoid leading zeros like "00".
			if amount == "0" {
				amount.clear();
			}
			amount.push_str(d);
		}
	}
}

/// Paint a full-rect background fill on the current panel.
pub fn fill_bg(ui: &Ui, color: Color32) {
	let rect = ui.ctx().screen_rect();
	ui.painter().rect_filled(rect, CornerRadius::ZERO, color);
}

/// Center a fixed-width column for narrow content on wide screens.
/// Hands the child the full remaining height: wrapping in `horizontal()`
/// would start the row a single line tall, so a `ScrollArea` inside would
/// clip everything below the first widget.
pub fn centered_column<R>(ui: &mut Ui, width: f32, add: impl FnOnce(&mut Ui) -> R) -> R {
	// Always keep a side gutter so content never runs flush to the screen
	// edge on phones (where `width` exceeds the available width).
	const MIN_SIDE_PAD: f32 = 18.0;
	let avail = ui.available_width();
	let w = width.min(avail - MIN_SIDE_PAD * 2.0).max(0.0);
	let margin = ((avail - w) / 2.0).max(MIN_SIDE_PAD);
	let mut rect = ui.available_rect_before_wrap();
	rect.min.x += margin;
	rect.max.x = rect.min.x + w;
	let mut child = ui.new_child(
		egui::UiBuilder::new()
			.max_rect(rect)
			.layout(Layout::top_down(Align::Min)),
	);
	let result = add(&mut child);
	ui.allocate_rect(child.min_rect(), Sense::hover());
	result
}

/// Hold-to-send button: fills over `hold_secs`; returns true once on completion.
pub struct HoldToSend {
	progress: f32,
}

impl Default for HoldToSend {
	fn default() -> Self {
		Self { progress: 0.0 }
	}
}

impl HoldToSend {
	pub fn ui(&mut self, ui: &mut Ui, label: &str) -> bool {
		let t = theme::tokens();
		let (rect, resp) = ui.allocate_exact_size(
			Vec2::new(ui.available_width(), 56.0),
			Sense::click_and_drag(),
		);
		// Background.
		ui.painter().rect(
			rect,
			CornerRadius::same(14),
			t.surface2,
			Stroke::NONE,
			egui::StrokeKind::Inside,
		);
		let held = resp.is_pointer_button_down_on() || resp.dragged();
		let dt = ui.input(|i| i.stable_dt).min(0.1);
		if held {
			self.progress = (self.progress + dt / 0.7).min(1.0);
			ui.ctx().request_repaint();
		} else {
			self.progress = (self.progress - dt / 0.3).max(0.0);
			if self.progress > 0.0 {
				ui.ctx().request_repaint();
			}
		}
		// Progress fill.
		if self.progress > 0.0 {
			let mut fill_rect = rect;
			fill_rect.set_width(rect.width() * self.progress);
			ui.painter().rect(
				fill_rect,
				CornerRadius::same(14),
				t.accent,
				Stroke::NONE,
				egui::StrokeKind::Inside,
			);
		}
		ui.painter().text(
			rect.center(),
			egui::Align2::CENTER_CENTER,
			label,
			FontId::new(17.0, fonts::semibold()),
			if self.progress > 0.5 {
				t.accent_ink
			} else {
				theme::ink_for(t.surface2)
			},
		);
		if self.progress >= 1.0 {
			self.progress = 0.0;
			return true;
		}
		false
	}
}

/// Shorten a long key/address for display (8…6).
pub fn short_key(key: &str) -> String {
	if key.len() <= 16 {
		return key.to_string();
	}
	format!("{}…{}", &key[..8], &key[key.len() - 6..])
}
