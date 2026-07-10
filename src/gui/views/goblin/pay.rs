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

//! Pay tab: amount entry and send launch.

use super::*;

impl GoblinWalletView {
	/// Pay tab: amount-first combined pay/request surface.
	pub(super) fn pay_ui(
		&mut self,
		ui: &mut egui::Ui,
		wallet: &Wallet,
		cb: &dyn PlatformCallbacks,
	) {
		let t = theme::tokens();
		ui.add_space(8.0);
		ui.horizontal(|ui| {
			// Goblin mark (left), sized to match the right-side controls.
			ui.add(
				egui::Image::new(egui::include_image!("../../../../img/goblin-logo2.svg"))
					.tint(t.text)
					.fit_to_exact_size(Vec2::splat(40.0)),
			);
			// Right cluster: scan-QR glyph (black, no background). The
			// tap-to-Settings profile avatar that used to sit at the far right
			// was removed per owner request; Settings stays on the nav bar.
			ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
				ui.add_space(12.0);
				let (rect, resp) = ui.allocate_exact_size(Vec2::splat(44.0), Sense::click());
				ui.painter().text(
					rect.center(),
					egui::Align2::CENTER_CENTER,
					QR_CODE,
					FontId::new(38.0, fonts::regular()),
					t.text,
				);
				if resp
					.on_hover_cursor(egui::CursorIcon::PointingHand)
					.on_hover_text(t!("goblin.home.scan_to_pay").to_string())
					.clicked()
				{
					let mut f = SendFlow::default();
					f.prefill_amount(self.pay_amount.clone());
					f.request_scan();
					self.pay_amount.clear();
					self.send = Some(f);
				}
			});
		});

		// Big centered amount.
		let display = if self.pay_amount.is_empty() {
			"0".to_string()
		} else {
			self.pay_amount.clone()
		};
		let tall = ui.available_height() > 560.0;
		// Over-balance is NOT shown while typing — requesting more than you hold is
		// valid, and reddening digits mid-entry reads as an error when it isn't.
		// The only feedback is on the Pay press: a brief red flash + shake + buzz
		// (see the Pay button below). `spendable` is read there too.
		let spendable = wallet
			.get_data()
			.map(|d| d.info.amount_currently_spendable)
			.unwrap_or(0);
		// Drive the "can't pay that" animation if it's running.
		let now = ui.input(|i| i.time);
		const SHAKE_DUR: f64 = 0.45;
		if self.pay_shake.is_some_and(|s| now - s >= SHAKE_DUR) {
			self.pay_shake = None;
		}
		ui.add_space(if tall { 56.0 } else { 24.0 });
		if let Some(start) = self.pay_shake {
			ui.ctx().request_repaint(); // keep the animation ticking
			let p = ((now - start) / SHAKE_DUR).clamp(0.0, 1.0) as f32;
			// Damped horizontal oscillation, amplitude decaying to zero.
			let dx = 14.0 * (1.0 - p) * (p * std::f32::consts::PI * 9.0).sin();
			// Red flash that eases back to the normal ink over the shake.
			let num = lerp_color(t.neg, t.text, p);
			let mark = lerp_color(t.neg, t.text_dim, p);
			w::amount_text_centered_shifted(ui, &display, 76.0, num, mark, dx);
		} else {
			w::amount_text_centered(ui, &display, 76.0);
		}
		if let Ok(grin) = display.parse::<f64>() {
			if let Some(preview) = pairing_preview(grin, ui.ctx()) {
				ui.add_space(6.0);
				ui.vertical_centered(|ui| {
					ui.label(
						RichText::new(preview)
							.font(FontId::new(14.0, fonts::regular()))
							.color(t.text_dim),
					);
				});
			}
		}
		// Drop the keypad toward the bottom on phone layouts (thumb reach) so it
		// isn't stranded in the middle with a big empty gap below it.
		let narrow = ui.available_width() < 700.0;
		let drop = if narrow {
			((ui.available_height() - 430.0) * 0.6).max(0.0)
		} else {
			0.0
		};
		ui.add_space(if tall { 32.0 } else { 16.0 } + drop);

		// The pay column is capped at 480 by `centered_column`, so the old
		// `< 700` width gate was always narrow: the numpad always showed and
		// the typed-input branch was dead — a physical keyboard did nothing.
		// Show the pad and accept typed digits alongside it.
		w::numpad(ui, &mut self.pay_amount, cb);
		w::amount_typed_input(ui, &mut self.pay_amount);
		ui.add_space(20.0);

		// Request | Pay actions, half width each.
		let valid = grin_core::core::amount_from_hr_string(&self.pay_amount)
			.map(|a| a > 0)
			.unwrap_or(false);
		ui.horizontal(|ui| {
			let half = (ui.available_width() - 10.0) / 2.0;
			ui.scope_builder(
				egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
					ui.cursor().min,
					Vec2::new(half, 56.0),
				)),
				|ui| {
					if w::big_action(ui, &t!("goblin.home.request"), true).clicked() && valid {
						// Open the request flow: pick a contact, then DM them a
						// grin Invoice1 they can approve to pay.
						let f = SendFlow::new_request(self.pay_amount.clone());
						self.pay_amount.clear();
						self.send = Some(f);
					}
				},
			);
			ui.add_space(10.0);
			ui.scope_builder(
				egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
					ui.cursor().min,
					Vec2::new(half, 56.0),
				)),
				|ui| {
					if w::big_action(ui, &t!("goblin.home.pay"), false).clicked() && valid {
						let over = grin_core::core::amount_from_hr_string(&self.pay_amount)
							.map(|a| a > spendable)
							.unwrap_or(false);
						if over {
							// "No, you can't pay that": shake + flash the amount red
							// and buzz the phone. Nothing is reddened while typing.
							self.pay_shake = Some(now);
							cb.vibrate_error();
						} else {
							let mut f = SendFlow::default();
							f.prefill_amount(self.pay_amount.clone());
							self.pay_amount.clear();
							self.send = Some(f);
						}
					}
				},
			);
		});
		if !valid {
			ui.add_space(8.0);
			ui.vertical_centered(|ui| {
				ui.label(
					RichText::new(t!("goblin.home.enter_amount"))
						.font(FontId::new(12.0, fonts::regular()))
						.color(t.text_mute),
				);
			});
		}
	}
}
