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

/// A custom-picture avatar: the texture drawn to fill the circle. Names never
/// affect the avatar — claimed and anonymous identities render identically.
pub fn avatar_tex(ui: &mut Ui, tex: &egui::TextureHandle, _name: &str, size: f32) -> Response {
	let (rect, resp) = ui.allocate_exact_size(Vec2::splat(size), Sense::click());
	let rounding = eframe::epaint::CornerRadius::same((rect.width() / 2.0) as u8);
	egui::Image::new(tex)
		.corner_radius(rounding)
		.fit_to_exact_size(rect.size())
		.paint_at(ui, rect);
	resp
}

/// Deterministic gradient avatar (a pubkey-seeded two-tone tile with the Grin
/// mark on top) — the fallback for anonymous nostr users. `id` is the npub or
/// hex pubkey; the image is a pure function of it, so the same key always draws
/// the same avatar (see [`super::identicon`]). Cached per-pubkey by egui.
pub fn gradient_avatar(ui: &mut Ui, id: &str, size: f32) -> Response {
	let (rect, resp) = ui.allocate_exact_size(Vec2::splat(size), Sense::click());
	paint_gradient(ui, id, rect);
	resp
}

/// Paint the pubkey-seeded grinmark gradient into `rect` (rasterized at 2x,
/// cached by egui via the `uri`).
fn paint_gradient(ui: &mut Ui, id: &str, rect: egui::Rect) {
	let hex = super::identicon::to_hex_seed(id);
	let px = (rect.width() * 2.0) as u32;
	let svg = super::identicon::gradient_avatar_svg(&hex, px, "");
	let uri = format!("bytes://gobavatar-{}-{}.svg", hex, rect.width() as u32);
	egui::Image::new(egui::ImageSource::Bytes {
		uri: uri.into(),
		bytes: svg.into_bytes().into(),
	})
	.corner_radius(CornerRadius::same((rect.width() / 2.0) as u8))
	.fit_to_exact_size(rect.size())
	.paint_at(ui, rect);
}

/// Picture avatar when a texture exists; otherwise the deterministic
/// pubkey-seeded grinmark gradient for everyone, named or anonymous — names
/// never affect the avatar. When no pubkey is known (last resort) the name
/// seeds the gradient instead, so the tile is still deterministic. `id` is
/// the npub/hex used to seed the gradient.
pub fn avatar_any(
	ui: &mut Ui,
	name: &str,
	id: &str,
	size: f32,
	tex: Option<&egui::TextureHandle>,
) -> Response {
	match tex {
		Some(t) => avatar_tex(ui, t, name, size),
		None if !id.is_empty() => gradient_avatar(ui, id, size),
		None => gradient_avatar(ui, name, size),
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
	amount_text_centered_shifted(ui, value, size, num_ink, mark_ink, 0.0);
}

/// Like [`amount_text_centered_ink`] but nudged horizontally by `dx` pixels — the
/// hook for the "can't pay that" shake on the Pay screen.
pub fn amount_text_centered_shifted(
	ui: &mut Ui,
	value: &str,
	size: f32,
	num_ink: Color32,
	mark_ink: Color32,
	dx: f32,
) {
	let avail = ui.available_width();
	let measure = |ui: &Ui, sz: f32| -> f32 {
		let num =
			ui.painter()
				.layout_no_wrap(value.to_string(), FontId::new(sz, fonts::bold()), num_ink);
		let mark = ui.painter().layout_no_wrap(
			TSU.to_string(),
			FontId::new(sz * 0.46, fonts::semibold()),
			mark_ink,
		);
		num.size().x + 1.0 + mark.size().x
	};
	// Shrink to fit: a long balance (e.g. 0.46520721ツ) must not run off the
	// edge. Glyph width is ~linear in font size, so scale down to the available
	// width with a small margin and a sane floor.
	let mut size = size;
	let total0 = measure(ui, size);
	if total0 > avail && total0 > 1.0 {
		size = (size * (avail / total0) * 0.97).clamp(14.0, size);
	}
	let total = measure(ui, size);
	ui.horizontal(|ui| {
		ui.spacing_mut().item_spacing.x = 0.0;
		ui.add_space(((ui.available_width() - total) / 2.0 + dx).max(0.0));
		ui.label(
			RichText::new(value)
				.font(FontId::new(size, fonts::bold()))
				.color(num_ink),
		);
		ui.add_space(1.0);
		ui.label(
			RichText::new(TSU)
				.font(FontId::new(size * 0.46, fonts::semibold()))
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

/// A Cash-App-style on/off switch. Yellow (brand accent) when on, neutral track
/// when off. Returns the response — the caller flips the bound state on click.
pub fn toggle(ui: &mut Ui, on: bool) -> Response {
	let t = theme::tokens();
	let (rect, resp) = ui.allocate_exact_size(Vec2::new(46.0, 28.0), Sense::click());
	let track = if on { t.accent } else { t.surface2 };
	ui.painter()
		.rect_filled(rect, CornerRadius::same(14), track);
	let knob_r = 11.0;
	let knob_x = if on {
		rect.right() - knob_r - 3.0
	} else {
		rect.left() + knob_r + 3.0
	};
	let knob = if on {
		t.accent_ink
	} else {
		t.surface_text_mute
	};
	ui.painter()
		.circle_filled(egui::pos2(knob_x, rect.center().y), knob_r, knob);
	resp.on_hover_cursor(egui::CursorIcon::PointingHand)
}

/// A segmented control (e.g. `["Scan", "My Code"]`). Highlights `selected`;
/// returns `Some(i)` when a different segment is tapped.
pub fn segmented(ui: &mut Ui, labels: &[&str], selected: usize) -> Option<usize> {
	let t = theme::tokens();
	let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 44.0), Sense::hover());
	ui.painter()
		.rect_filled(rect, CornerRadius::same(22), t.surface2);
	let inner = rect.shrink(4.0);
	let seg_w = inner.width() / labels.len().max(1) as f32;
	let mut clicked = None;
	for (i, label) in labels.iter().enumerate() {
		let seg = egui::Rect::from_min_size(
			inner.min + Vec2::new(i as f32 * seg_w, 0.0),
			Vec2::new(seg_w, inner.height()),
		);
		let resp = ui.interact(seg, ui.id().with(("seg", i)), Sense::click());
		let on = i == selected;
		if on {
			ui.painter()
				.rect_filled(seg, CornerRadius::same(18), t.accent);
		}
		ui.painter().text(
			seg.center(),
			egui::Align2::CENTER_CENTER,
			*label,
			FontId::new(
				15.0,
				if on {
					fonts::semibold()
				} else {
					fonts::regular()
				},
			),
			if on { t.accent_ink } else { t.surface_text_dim },
		);
		if resp.clicked() && !on {
			clicked = Some(i);
		}
		resp.on_hover_cursor(egui::CursorIcon::PointingHand);
	}
	clicked
}

/// Big primary/secondary action button (56px, radius 14).
pub fn big_action(ui: &mut Ui, label: &str, secondary: bool) -> Response {
	let t = theme::tokens();
	let desired = Vec2::new(ui.available_width(), 56.0);
	let (rect, resp) = ui.allocate_exact_size(desired, Sense::click());
	let (mut fill, mut ink, mut stroke) = if secondary {
		(Color32::TRANSPARENT, t.text, Stroke::new(1.5, t.line))
	} else {
		(t.accent, t.accent_ink, Stroke::NONE)
	};
	// Inside `add_enabled_ui(false)` the button must LOOK disabled too, so a
	// blocked action (e.g. Review while over balance) never reads as a live CTA.
	let enabled = ui.is_enabled();
	if !enabled {
		fill = fill.gamma_multiply(0.35);
		ink = ink.gamma_multiply(0.45);
		stroke.color = stroke.color.gamma_multiply(0.45);
	}
	let visual_fill = if enabled && resp.hovered() && !secondary {
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

/// A full-width outlined action with an icon to the left of its label, bordered
/// in a tint of `ink` (so it reads "around the same color" as the text). Used
/// for the wallet-management cluster at the foot of Settings — switch / lock /
/// advanced — where each action stands on its own rather than in a card.
pub fn outlined_icon_action(ui: &mut Ui, icon: &str, label: &str, ink: Color32) -> Response {
	let desired = Vec2::new(ui.available_width(), 50.0);
	let (rect, resp) = ui.allocate_exact_size(desired, Sense::click());
	let border = ink.gamma_multiply(if resp.hovered() { 0.9 } else { 0.55 });
	let fill = if resp.hovered() {
		ink.gamma_multiply(0.10)
	} else {
		Color32::TRANSPARENT
	};
	ui.painter().rect(
		rect,
		CornerRadius::same(14),
		fill,
		Stroke::new(1.5, border),
		egui::StrokeKind::Inside,
	);
	ui.painter().text(
		rect.left_center() + Vec2::new(18.0, 0.0),
		egui::Align2::LEFT_CENTER,
		icon,
		FontId::new(18.0, fonts::regular()),
		ink,
	);
	ui.painter().text(
		rect.left_center() + Vec2::new(46.0, 0.0),
		egui::Align2::LEFT_CENTER,
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

/// Paint a QR code for `text` with the goblin mark centered. Always dark modules
/// on a white plate, whatever the theme — inverted codes fail to decode in many
/// scanners. Encoded synchronously each frame; modules are plain painter rects.
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
	// Full cells, no inter-module gap: at receive-card density (~4.5px cells) even
	// a 0.5px gap fragments the finder patterns and scanners fail. Round corners
	// only when cells are large enough that the notching can't matter.
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
	// Goblin mark on a yellow backing square in the center, 19% footprint (larger
	// obscures too many modules for a reliable decode). Yellow reads as "light" to
	// a scanner like white, so the covered center is recovered by the High ECC.
	let t = theme::tokens();
	let backing = size * 0.19;
	let b_rect = egui::Rect::from_center_size(rect.center(), Vec2::splat(backing));
	ui.painter()
		.rect_filled(b_rect, CornerRadius::same((backing * 0.18) as u8), t.accent);
	let m_rect = egui::Rect::from_center_size(rect.center(), Vec2::splat(backing * 0.72));
	egui::Image::new(egui::include_image!("../../../../img/goblin-logo2.svg"))
		.tint(t.accent_ink)
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
/// `updating` marks a zero balance that is only zero because funds are in
/// flight or the first sync is still running.
/// Honest subline shown under the balance figure. A wallet that can't reach a
/// node must never present a bare `0` (or a silently-stale number) as if it were
/// a live, confirmed balance.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BalanceSubline {
	/// Nothing to add: the shown balance is live and non-zero.
	None,
	/// Balance reads 0 while a sync/first-scan is in progress or funds are in
	/// flight — say "updating", not "empty".
	Updating,
	/// Balance reads 0 and the node is unreachable with nothing cached — say
	/// "can't reach node", never a bare 0.
	Unreachable,
	/// A cached (last-known) balance is shown but the node is currently
	/// unreachable — flag it as possibly stale.
	Stale,
}

/// Pure decision for the balance subline. `updating` means a sync is in progress
/// (or funds are in flight); `error` means the wallet currently can't reach a
/// node. Priority: updating > unreachable > stale.
pub fn balance_subline(total: u64, updating: bool, error: bool) -> BalanceSubline {
	if total == 0 && updating {
		BalanceSubline::Updating
	} else if total == 0 && error {
		BalanceSubline::Unreachable
	} else if error {
		BalanceSubline::Stale
	} else {
		BalanceSubline::None
	}
}

/// What the fiat subline should render under the balance. `None` (pairing off)
/// draws no line at all; otherwise the line is honest about its state and never
/// paints a stale rate as if current.
pub enum FiatLine {
	/// A ready "≈ … · 1ツ = …" line built from a fresh rate.
	Text(String),
	/// A live fetch is in flight; show a subtle placeholder, not a number.
	Loading,
	/// The rate could not be fetched; say so rather than show an old value.
	Unavailable,
}

pub fn balance_hero(
	ui: &mut Ui,
	total: u64,
	spendable: u64,
	updating: bool,
	error: bool,
	sync_pct: u8,
	fiat: Option<FiatLine>,
	size: f32,
) {
	let t = theme::tokens();
	// Headline is the TOTAL the wallet holds — same number GRIM shows — so a
	// wallet mid-confirmation doesn't look empty.
	ui.vertical_centered(|ui| kicker(ui, "Balance"));
	ui.add_space(6.0);
	amount_text_centered(ui, &amount_str(total), size);
	// When some of it can't be spent yet (a payment still confirming, ~10 blocks),
	// say how much is available vs confirming so a failed send explains itself.
	if total > spendable {
		let confirming = total - spendable;
		ui.add_space(4.0);
		ui.vertical_centered(|ui| {
			ui.label(
				RichText::new(format!(
					"{}{} available · {}{} confirming",
					amount_str(spendable),
					TSU,
					amount_str(confirming),
					TSU
				))
				.font(FontId::new(12.5, fonts::medium()))
				.color(t.text_dim),
			);
		});
	}
	// A stark 0 (or a stale number) reads as "funds vanished". Pick the honest
	// subline: still-updating, node-unreachable, or last-known-balance. See
	// [`balance_subline`] for the pure state machine.
	match balance_subline(total, updating, error) {
		BalanceSubline::Updating => {
			let label = if (1..100).contains(&sync_pct) {
				format!("{} {sync_pct}%", t!("goblin.home.balance_updating"))
			} else {
				t!("goblin.home.balance_updating").to_string()
			};
			ui.add_space(4.0);
			ui.vertical_centered(|ui| {
				ui.label(
					RichText::new(label)
						.font(FontId::new(12.5, fonts::medium()))
						.color(t.text_dim),
				);
			});
		}
		BalanceSubline::Unreachable => {
			// Node unreachable and nothing cached yet: a bare 0 would claim the
			// wallet is empty. Say the truth so the user switches nodes instead
			// of assuming funds vanished.
			ui.add_space(4.0);
			ui.vertical_centered(|ui| {
				ui.label(
					RichText::new(t!("goblin.home.cant_reach_node"))
						.font(FontId::new(12.5, fonts::medium()))
						.color(t.neg),
				);
			});
		}
		BalanceSubline::Stale => {
			// A cached balance is shown but we can't currently reach a node:
			// flag it as possibly stale rather than presenting it as live.
			ui.add_space(4.0);
			ui.vertical_centered(|ui| {
				ui.label(
					RichText::new(t!("goblin.home.balance_stale"))
						.font(FontId::new(12.5, fonts::medium()))
						.color(t.text_dim),
				);
			});
		}
		BalanceSubline::None => {}
	}
	if let Some(fiat) = fiat {
		// Loading and Unavailable both render a subtle dim line — never a stale
		// number. While loading, nudge egui to re-poll so the rate pops in once the
		// live fetch lands even if the view is otherwise idle (bounded to the time
		// the balance is actually on screen — not a background timer).
		let text = match fiat {
			FiatLine::Text(s) => s,
			FiatLine::Loading => {
				ui.ctx()
					.request_repaint_after(std::time::Duration::from_millis(300));
				"≈ …".to_string()
			}
			FiatLine::Unavailable => t!("goblin.home.fiat_unavailable").to_string(),
		};
		ui.add_space(4.0);
		ui.vertical_centered(|ui| {
			ui.label(
				RichText::new(text)
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
	note: &str,
	tail: &str,
	id: &str,
	amount: &str,
	incoming: bool,
	canceled: bool,
	system: bool,
	tex: Option<&egui::TextureHandle>,
) -> Response {
	let t = theme::tokens();
	// A touch taller than a single-line row so the amount can sit centered
	// against the two-line title/subtitle stack with clear breathing room
	// above and below instead of colliding with the title baseline.
	let row_h = 64.0;
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
			avatar_any(ui, title, id, 40.0, tex);
		}
		ui.add_space(12.0);
		// Reserve the amount as its own right-hand column FIRST. Placing it
		// before the text means the title/subtitle column is bounded to the
		// remaining width and truncates cleanly, instead of stretching under
		// the amount and colliding with it. Centered against the whole stack,
		// the amount lands between the title and subtitle lines.
		ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
			if !amount.is_empty() {
				// A canceled tx delivered no funds: mute the amount so it never
				// reads as a completed green credit (or a real debit).
				ui.label(
					RichText::new(amount)
						.font(FontId::new(15.0, fonts::mono_semibold()))
						.color(if canceled {
							t.text_dim
						} else if incoming {
							t.pos
						} else {
							t.text
						}),
				);
				ui.add_space(10.0);
			}
			// Remaining width to the left holds the title + subtitle stack.
			ui.vertical(|ui| {
				ui.add_space(2.0);
				ui.add(
					egui::Label::new(
						RichText::new(title)
							.font(FontId::new(15.0, fonts::semibold()))
							.color(t.text),
					)
					.truncate(),
				);
				activity_subtitle(ui, note, tail, t.text_dim);
			});
		});
	});
	// Divider.
	let line_y = rect.bottom();
	ui.painter()
		.hline(rect.left()..=rect.right(), line_y, Stroke::new(1.0, t.line));
	resp
}

/// Single-line subtitle for an activity row.
///
/// The `tail` (date/time, or a short status word) is pinned to the right and
/// never clipped; the `note` takes whatever width is left and gets the
/// ellipsis when it runs out of room. When only one part is present it is
/// left-aligned under the title, truncating on its own (e.g. a long npub in
/// the contact picker).
fn activity_subtitle(ui: &mut Ui, note: &str, tail: &str, color: Color32) {
	let dim = |s: &str| {
		RichText::new(s.to_string())
			.font(FontId::new(13.0, fonts::regular()))
			.color(color)
	};
	match (note.is_empty(), tail.is_empty()) {
		(true, true) => {}
		(false, true) => {
			ui.add(egui::Label::new(dim(note)).truncate());
		}
		(true, false) => {
			ui.add(egui::Label::new(dim(tail)).truncate());
		}
		(false, false) => {
			ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
				ui.spacing_mut().item_spacing.x = 4.0;
				// Rightmost, full: the date/time (with seconds) is never clipped.
				ui.add(egui::Label::new(dim(tail)));
				ui.add(egui::Label::new(dim("·")));
				// Leftmost, fills the gap: the note truncates with an ellipsis.
				ui.add(egui::Label::new(dim(note)).truncate());
			});
		}
	}
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
			// Truncate so a long value (e.g. "Encrypted nostr DM over Nym") never
			// runs past the edge or collides with the label on a narrow screen.
			ui.add(
				egui::Label::new(
					RichText::new(value)
						.font(FontId::new(15.0, fonts::semibold()))
						.color(t.text),
				)
				.truncate(),
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
pub fn numpad(
	ui: &mut Ui,
	amount: &mut String,
	cb: &dyn crate::gui::platform::PlatformCallbacks,
) -> bool {
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
	// columns more breathing room (payment-app-style).
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
					let before = amount.clone();
					apply_key(amount, k);
					if *amount == before {
						// A no-op key — a second '.', a '0' on a leading zero, the
						// 9-decimal cap, or backspace on empty. Nudge with a short
						// error haptic instead of silently doing nothing.
						cb.vibrate_error();
					} else {
						changed = true;
					}
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

/// Center a fixed-width column for narrow content on wide screens.
/// Hands the child the full remaining height: wrapping in `horizontal()`
/// would start the row a single line tall, so a `ScrollArea` inside would
/// clip everything below the first widget.
pub fn centered_column<R>(ui: &mut Ui, width: f32, add: impl FnOnce(&mut Ui) -> R) -> R {
	// Keep a small side gutter so content sits close to the screen edges on
	// phones (where `width` exceeds the available width) without running flush.
	const MIN_SIDE_PAD: f32 = 8.0;
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

#[cfg(test)]
mod tests {
	use super::{BalanceSubline, balance_subline};

	// A live, non-zero balance needs no subline.
	#[test]
	fn live_balance_has_no_subline() {
		assert_eq!(balance_subline(1_000, false, false), BalanceSubline::None);
	}

	// Zero while syncing / funds in flight is "updating", not "empty".
	#[test]
	fn zero_while_updating_says_updating() {
		assert_eq!(balance_subline(0, true, false), BalanceSubline::Updating);
	}

	// Zero with an unreachable node and nothing cached must say so, never a
	// bare 0 that reads as "wallet empty" (the silent-zero incident).
	#[test]
	fn zero_with_node_error_says_unreachable() {
		assert_eq!(balance_subline(0, false, true), BalanceSubline::Unreachable);
	}

	// A cached balance shown during a node outage is flagged stale, not passed
	// off as a live figure.
	#[test]
	fn cached_balance_with_error_is_stale() {
		assert_eq!(balance_subline(500, false, true), BalanceSubline::Stale);
	}

	// Updating wins over error while the balance is still zero: a fresh switch
	// to a new node shows progress, not a scary red banner, until it errors.
	#[test]
	fn updating_takes_priority_over_error_at_zero() {
		assert_eq!(balance_subline(0, true, true), BalanceSubline::Updating);
	}
}
