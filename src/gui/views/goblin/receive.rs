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

//! Receive screen: npub / grin-address copy flow.

use super::*;

impl GoblinWalletView {
	pub(super) fn receive_ui(
		&mut self,
		ui: &mut egui::Ui,
		wallet: &Wallet,
		cb: &dyn PlatformCallbacks,
	) {
		let t = theme::tokens();
		ui.add_space(8.0);
		ui.label(
			RichText::new(t!("goblin.receive.title"))
				.font(FontId::new(28.0, fonts::bold()))
				.color(t.text),
		);
		ui.add_space(16.0);

		// `has_name`: a claimed nip05 name exists — gates the "handle"/"username"
		// wording, which would mislead when only the raw npub is shown.
		let (handle, has_name) = wallet
			.nostr_service()
			.map(|s| {
				let identity = s.identity.read();
				match identity.nip05.clone() {
					Some(n) => (n.split('@').next().unwrap_or("").to_string(), true),
					None => (data::short_npub(&hex_of(&identity.npub)), false),
				}
			})
			.unwrap_or_else(|| ("—".to_string(), false));
		let npub = wallet.nostr_service().map(|s| s.npub()).unwrap_or_default();
		let nprofile = wallet
			.nostr_service()
			.map(|s| s.nprofile())
			.unwrap_or_else(|| npub.clone());

		w::card(ui, |ui| {
			ui.vertical_centered(|ui| {
				// QR of the nostr handle (nostr: URI).
				ui.add_space(12.0);
				let uri = format!("nostr:{}", nprofile);
				w::qr_code(ui, &uri, 220.0);
				ui.add_space(14.0);
				ui.label(
					RichText::new(&handle)
						.font(FontId::new(18.0, fonts::bold()))
						.color(t.surface_text),
				);
				match &self.request_amount {
					Some(amt) => {
						ui.label(
							RichText::new(t!(
								"goblin.receive.requesting",
								amt => amt,
								tsu => w::TSU
							))
							.font(FontId::new(13.0, fonts::semibold()))
							.color(t.surface_text),
						);
						ui.add_space(6.0);
						if w::chip(ui, &t!("goblin.receive.clear_request"), false).clicked() {
							self.request_amount = None;
						}
					}
					None => {
						let caption = if has_name {
							t!("goblin.receive.share_handle")
						} else {
							t!("goblin.receive.share_npub")
						};
						ui.label(
							RichText::new(caption)
								.font(FontId::new(13.0, fonts::regular()))
								.color(t.surface_text_dim),
						);
					}
				}
			});
		});

		ui.add_space(12.0);
		// Transient "Copied" feedback on the copy button; a silent copy reads as
		// a dead button.
		let fresh = |at: std::time::Instant| at.elapsed().as_millis() < 1500;
		let copied = matches!(self.receive_copied, Some((1, at)) if fresh(at));
		if self.receive_copied.is_some() {
			ui.ctx()
				.request_repaint_after(std::time::Duration::from_millis(200));
		}
		ui.horizontal(|ui| {
			let half = (ui.available_width() - 10.0) / 2.0;
			// Share the nprofile: the payer learns which relays to reach you on
			// (the bare npub still shows in-app as who-is-paid; the shareable
			// handle carries relay hints so per-identity relays interoperate).
			ui.scope_builder(
				egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
					ui.cursor().min,
					Vec2::new(half, 56.0),
				)),
				|ui| {
					let label = t!("goblin.send.share_btn", "icon" => SHARE);
					if w::big_action(ui, &label, true).clicked() && !nprofile.is_empty() {
						cb.share_text(
							t!("goblin.receive.share_message", "npub" => nprofile.clone())
								.to_string(),
						);
					}
				},
			);
			ui.add_space(10.0);
			// Copy the nprofile (the QR encodes the same); the human-copy now
			// matches what the QR scans.
			ui.scope_builder(
				egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
					ui.cursor().min,
					Vec2::new(half, 56.0),
				)),
				|ui| {
					let label = if copied {
						format!("{} {}", CHECK, t!("goblin.receive.copied"))
					} else {
						format!("{} {}", COPY, t!("goblin.receive.copy"))
					};
					if w::big_action(ui, &label, false).clicked() && !nprofile.is_empty() {
						cb.copy_string_to_buffer(nprofile.clone());
						cb.vibrate_copy();
						self.receive_copied = Some((1, std::time::Instant::now()));
					}
				},
			);
		});

		ui.add_space(16.0);
		let privacy_note = if has_name {
			t!("goblin.receive.privacy_note")
		} else {
			t!("goblin.receive.privacy_note_npub")
		};
		ui.label(
			RichText::new(privacy_note)
				.font(FontId::new(12.0, fonts::regular()))
				.color(t.text_mute),
		);
	}
}
