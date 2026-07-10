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

//! Contact-profile full-surface overlay.

use super::*;

impl GoblinWalletView {
	/// Full-surface contact profile: who they are, history between us, and a
	/// block toggle (a nostr-level mute).
	pub(super) fn profile_ui(
		&mut self,
		ui: &mut egui::Ui,
		wallet: &Wallet,
		_cb: &dyn PlatformCallbacks,
		npub: &str,
	) -> bool {
		let t = theme::tokens();
		let name = wallet
			.nostr_service()
			.map(|s| data::contact_title(&s.store, npub))
			.unwrap_or_else(|| data::short_npub(npub));
		let contact = wallet.nostr_service().and_then(|s| s.store.contact(npub));
		let blocked = contact.as_ref().map(|c| c.blocked).unwrap_or(false);
		let nip05 = contact.as_ref().and_then(|c| c.nip05.clone());
		let history = data::history_with(wallet, npub);
		let tex = self.handle_tex(ui.ctx(), wallet, &name);
		let htexs: Vec<Option<egui::TextureHandle>> = history
			.iter()
			.map(|i| self.handle_tex(ui.ctx(), wallet, &i.title))
			.collect();
		let mut close = false;
		let mut do_pay = false;
		let mut do_block = false;
		let mut open_receipt: Option<u32> = None;
		egui::CentralPanel::default()
			.frame(egui::Frame {
				fill: t.bg,
				inner_margin: Margin {
					left: (View::far_left_inset_margin(ui) + 20.0) as i8,
					right: (View::get_right_inset() + 20.0) as i8,
					top: (View::get_top_inset() + 12.0) as i8,
					bottom: (View::get_bottom_inset() + 12.0) as i8,
				},
				..Default::default()
			})
			.show_inside(ui, |ui| {
				w::centered_column(ui, Content::SIDE_PANEL_WIDTH * 1.2, |ui| {
					if Self::overlay_back_header(ui, &t!("goblin.profile.title")) {
						close = true;
					}
					ScrollArea::vertical()
						.id_salt("goblin_profile_scroll")
						.auto_shrink([false; 2])
						.show(ui, |ui| {
							ui.add_space(8.0);
							ui.vertical_centered(|ui| {
								w::avatar_any(ui, &name, npub, 72.0, tex.as_ref());
								ui.add_space(12.0);
								ui.label(
									RichText::new(&name)
										.font(FontId::new(22.0, fonts::bold()))
										.color(t.text),
								);
								ui.add_space(2.0);
								let sub = nip05
									.clone()
									.map(|n| format!("✓ {}", n))
									.unwrap_or_else(|| data::short_npub(npub));
								ui.label(
									RichText::new(sub)
										.font(FontId::new(13.0, fonts::regular()))
										.color(t.text_dim),
								);
							});
							ui.add_space(18.0);
							if !blocked
								&& w::big_action(ui, &t!("goblin.home.pay"), false).clicked()
							{
								do_pay = true;
							}
							ui.add_space(18.0);
							w::kicker(ui, &t!("goblin.profile.activity"));
							ui.add_space(10.0);
							if history.is_empty() {
								ui.label(
									RichText::new(t!("goblin.profile.no_activity"))
										.font(FontId::new(13.0, fonts::regular()))
										.color(t.text_dim),
								);
							} else {
								for (item, htex) in history.iter().zip(htexs.iter()) {
									// No +/- for canceled: nothing moved.
									let sign = if item.canceled {
										""
									} else if item.incoming {
										"+ "
									} else {
										"− "
									};
									let amount =
										format!("{}{}{}", sign, w::amount_str(item.amount), w::TSU);
									let (note, time) = Self::activity_note_time(item);
									if w::activity_row(
										ui,
										&item.title,
										&note,
										&time,
										item.npub.as_deref().unwrap_or(""),
										&amount,
										item.incoming,
										item.canceled,
										item.system,
										htex.as_ref(),
										false,
									)
									.clicked()
									{
										open_receipt = Some(item.tx_id);
									}
								}
							}
							ui.add_space(24.0);
							let label = if blocked {
								t!("goblin.profile.unblock").to_string()
							} else {
								format!("{}  {}", PROHIBIT, t!("goblin.profile.block"))
							};
							if w::big_action_on_card_ink(ui, &label, t.neg).clicked() {
								do_block = true;
							}
							ui.add_space(8.0);
							ui.vertical_centered(|ui| {
								ui.label(
									RichText::new(if blocked {
										t!("goblin.profile.blocked_blurb")
									} else {
										t!("goblin.profile.block_blurb")
									})
									.font(FontId::new(12.0, fonts::regular()))
									.color(t.text_mute),
								);
							});
							ui.add_space(20.0);
						});
				});
			});
		if let Some(id) = open_receipt {
			self.receipt = Some(id);
			close = true;
		}
		if do_pay {
			let mut f = SendFlow::default();
			f.prefill_contact(name.clone(), npub.to_string());
			self.send = Some(f);
			close = true;
		}
		if do_block {
			if let Some(s) = wallet.nostr_service() {
				let mut c = s.store.contact(npub).unwrap_or(crate::nostr::Contact {
					ver: 1,
					npub: npub.to_string(),
					petname: None,
					nip05: nip05.clone(),
					nip05_verified_at: None,
					relays: vec![],
					nip44_v3: false,
					hue: data::hue_of(npub) as u8,
					unknown: true,
					added_at: crate::nostr::unix_time(),
					last_paid_at: None,
					blocked: false,
				});
				c.blocked = !c.blocked;
				s.store.save_contact(&c);
			}
		}
		close
	}
}
