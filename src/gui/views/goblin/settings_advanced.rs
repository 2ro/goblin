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

//! Advanced settings page (recovery / repair / delete).

use super::*;

impl GoblinWalletView {
	/// Advanced (wallet-recovery) page — GRIM's low-level tools surfaced in the
	/// goblin style: repair, restore-from-seed, reveal the recovery phrase, and
	/// delete. The two destructive actions arm a tap-twice confirm.
	pub(super) fn advanced_ui(
		&mut self,
		ui: &mut egui::Ui,
		wallet: &Wallet,
		cb: &dyn PlatformCallbacks,
	) {
		use crate::wallet::types::ConnectionMethod;
		let t = theme::tokens();
		if self.sub_header(ui, &t!("goblin.advanced.title")) {
			self.advanced = AdvancedState::default();
			// Don't leave a half-entered backup password sitting in memory.
			self.backup = None;
			self.settings_page = SettingsPage::Main;
			return;
		}
		// Repair needs a synced node; mirror GRIM's availability check.
		let integrated = wallet.get_current_connection() == ConnectionMethod::Integrated;
		let integrated_ready =
			crate::node::Node::get_sync_status() == Some(grin_chain::SyncStatus::NoSync);
		let repair_unavailable = wallet.sync_error() || (integrated && !integrated_ready);
		let repairing = wallet.is_repairing();
		let progress = wallet.repairing_progress();
		let mut leave = false;
		let mut open_node = false;
		let mut open_integrated = false;
		{
			ScrollArea::vertical()
				.id_salt("goblin_advanced_scroll")
				.auto_shrink([false; 2])
				.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
				.show(ui, |ui| {
					// Borrow ends (NLL) at the last `adv.` use in the Nostr-key card;
					// the .backup + Danger Zone sections below then use `self`.
					let adv = &mut self.advanced;
					ui.label(
						RichText::new(t!("goblin.advanced.intro"))
							.font(FontId::new(14.0, fonts::regular()))
							.color(t.text_dim),
					);
					ui.add_space(16.0);

					// Run your own node (the internal node). Opens the node-connection
					// page, where you pick the integrated node or an external one.
					w::card(ui, |ui| {
						ui.set_min_width(ui.available_width());
						advanced_head(ui, &t!("goblin.node.integrated"), t.surface_text);
						advanced_desc(ui, &t!("goblin.advanced.own_node_desc"));
						ui.add_space(10.0);
						if wallet.get_current_connection() == ConnectionMethod::Integrated {
							ui.label(
								RichText::new(format!(
									"{} {}",
									crate::gui::icons::CHECK,
									t!("goblin.advanced.own_node_active")
								))
								.font(FontId::new(13.0, fonts::medium()))
								.color(t.pos),
							);
							ui.add_space(10.0);
						}
						if w::big_action_on_card(ui, &t!("goblin.advanced.manage_node")).clicked() {
							open_node = true;
						}
						ui.add_space(10.0);
						// GRIM's integrated-node tabs (info, metrics, mining with
						// stratum, node settings) in Goblin chrome. Their ONE home
						// (single-home rule): Goblin is the lighter client, so they
						// live here under Advanced, not in main Settings.
						let node_label = if crate::node::Node::is_running() {
							format!(
								"{} · {}",
								t!("goblin.settings.integrated_node"),
								crate::node::Node::get_sync_status_text()
							)
						} else {
							t!("goblin.settings.integrated_node").to_string()
						};
						if w::big_action_on_card(ui, &node_label).clicked() {
							open_integrated = true;
						}
					});
					ui.add_space(12.0);

					// Repair.
					w::card(ui, |ui| {
						ui.set_min_width(ui.available_width());
						advanced_head(ui, &t!("goblin.advanced.repair"), t.surface_text);
						advanced_desc(ui, &t!("goblin.advanced.repair_desc"));
						ui.add_space(10.0);
						if repairing {
							ui.label(
								RichText::new(
									t!("goblin.advanced.repairing", pct => progress.to_string()),
								)
								.font(FontId::new(13.0, fonts::medium()))
								.color(t.accent),
							);
						} else if repair_unavailable {
							ui.label(
								RichText::new(t!("goblin.advanced.repair_unavailable"))
									.font(FontId::new(13.0, fonts::medium()))
									.color(t.neg),
							);
						} else if adv.confirm_repair {
							// Repair re-scans the chain — it can take a few minutes.
							// Warn + confirm in the accent (yellow) before starting.
							ui.label(
								RichText::new(t!("goblin.advanced.repair_confirm_note"))
									.font(FontId::new(13.0, fonts::regular()))
									.color(t.text_dim),
							);
							ui.add_space(10.0);
							if w::big_action_on_card_ink(
								ui,
								&t!("goblin.advanced.repair_confirm"),
								t.accent,
							)
							.clicked()
							{
								adv.confirm_repair = false;
								wallet.repair();
							}
						} else if w::big_action_on_card(ui, &t!("goblin.advanced.repair")).clicked()
						{
							adv.confirm_repair = true;
						}
					});
					ui.add_space(12.0);

					// Restore (rebuild local data from the seed).
					w::card(ui, |ui| {
						ui.set_min_width(ui.available_width());
						advanced_head(ui, &t!("goblin.advanced.restore"), t.surface_text);
						advanced_desc(ui, &t!("goblin.advanced.restore_desc"));
						ui.add_space(10.0);
						if adv.confirm_restore {
							ui.label(
								RichText::new(t!("goblin.advanced.restore_confirm_note"))
									.font(FontId::new(13.0, fonts::regular()))
									.color(t.text_dim),
							);
							ui.add_space(10.0);
							if w::big_action_on_card_ink(
								ui,
								&t!("goblin.advanced.restore_confirm"),
								t.neg,
							)
							.clicked()
							{
								wallet.delete_db();
								leave = true;
							}
						} else if w::big_action_on_card(ui, &t!("goblin.advanced.restore"))
							.clicked()
						{
							adv.confirm_restore = true;
						}
					});
					ui.add_space(12.0);

					// Recovery phrase (the grin seed words).
					w::card(ui, |ui| {
						ui.set_min_width(ui.available_width());
						advanced_head(ui, &t!("goblin.advanced.show_phrase"), t.surface_text);
						advanced_desc(ui, &t!("goblin.advanced.phrase_desc"));
						ui.add_space(10.0);
						if let Some(words) = adv.revealed.clone() {
							w::field_well(ui, |ui| {
								ui.label(
									RichText::new(words)
										.font(FontId::new(15.0, fonts::medium()))
										.color(t.surface_text),
								);
							});
							ui.add_space(10.0);
							if w::big_action_on_card(ui, &t!("goblin.advanced.hide")).clicked() {
								adv.revealed = None;
								adv.reveal_pass.clear();
							}
						} else {
							w::field_well(ui, |ui| {
								TextEdit::new(egui::Id::from("advanced_reveal_pass"))
									.focus(false)
									.hint_text(t!("goblin.advanced.password"))
									.password()
									.text_color(t.surface_text)
									.body()
									.ui(ui, &mut adv.reveal_pass, cb);
							});
							if adv.wrong_pass {
								ui.add_space(6.0);
								ui.label(
									RichText::new(t!("goblin.advanced.wrong_password"))
										.font(FontId::new(13.0, fonts::medium()))
										.color(t.neg),
								);
							}
							ui.add_space(10.0);
							ui.add_enabled_ui(!adv.reveal_pass.is_empty(), |ui| {
								if w::big_action_on_card(ui, &t!("goblin.advanced.reveal"))
									.clicked()
								{
									match wallet.get_recovery(adv.reveal_pass.clone()) {
										Ok(phrase) => {
											adv.revealed = Some(phrase.to_string());
											adv.wrong_pass = false;
											adv.reveal_pass.clear();
										}
										Err(_) => {
											adv.wrong_pass = true;
										}
									}
								}
							});
						}
					});
					ui.add_space(12.0);

					// ── ADVANCED NOSTR SETTINGS ──────────────────────────────
					// The Nostr key, and directly below it the .backup download.
					w::kicker(ui, &t!("goblin.advanced.nostr_section"));
					ui.add_space(8.0);
					// Nostr key (nsec). Password-gated reveal, then Copy + a QR
					// so it can be carried into a nostr app's private-key login
					// (e.g. magick.market) without retyping. Same gate as the
					// recovery phrase above.
					w::card(ui, |ui| {
						ui.set_min_width(ui.available_width());
						advanced_head(ui, &t!("goblin.advanced.nostr_key"), t.surface_text);
						advanced_desc(ui, &t!("goblin.advanced.nostr_key_desc"));
						ui.add_space(10.0);
						if let Some(nsec) = adv.nsec_revealed.clone() {
							w::field_well(ui, |ui| {
								ui.label(
									RichText::new(&nsec)
										.font(FontId::new(14.0, fonts::medium()))
										.color(t.surface_text),
								);
							});
							ui.add_space(10.0);
							if w::big_action_on_card(ui, &t!("goblin.advanced.copy_nsec")).clicked()
							{
								// Secret: auto-clears from the clipboard after a delay
								// (compare-then-clear) so it does not linger there.
								cb.copy_secret_to_buffer(nsec.clone());
							}
							ui.add_space(8.0);
							let qr_label = if adv.nsec_qr {
								t!("goblin.advanced.hide_qr")
							} else {
								t!("goblin.advanced.show_qr")
							};
							if w::big_action_on_card(ui, &qr_label).clicked() {
								adv.nsec_qr = !adv.nsec_qr;
							}
							if adv.nsec_qr {
								ui.add_space(10.0);
								ui.vertical_centered(|ui| {
									w::qr_code(ui, &nsec, 220.0);
								});
							}
							ui.add_space(10.0);
							if w::big_action_on_card(ui, &t!("goblin.advanced.hide")).clicked() {
								adv.nsec_revealed = None;
								adv.nsec_qr = false;
								adv.nsec_pass.clear();
							}
						} else {
							w::field_well(ui, |ui| {
								TextEdit::new(egui::Id::from("advanced_nsec_pass"))
									.focus(false)
									.hint_text(t!("goblin.advanced.password"))
									.password()
									.text_color(t.surface_text)
									.body()
									.ui(ui, &mut adv.nsec_pass, cb);
							});
							if adv.nsec_wrong {
								ui.add_space(6.0);
								ui.label(
									RichText::new(t!("goblin.advanced.wrong_password"))
										.font(FontId::new(13.0, fonts::medium()))
										.color(t.neg),
								);
							}
							ui.add_space(10.0);
							ui.add_enabled_ui(!adv.nsec_pass.is_empty(), |ui| {
								if w::big_action_on_card(ui, &t!("goblin.advanced.reveal_nsec"))
									.clicked()
								{
									match wallet.get_nostr_nsec(adv.nsec_pass.clone()) {
										Ok(nsec) => {
											adv.nsec_revealed = Some(nsec);
											adv.nsec_wrong = false;
											adv.nsec_pass.clear();
										}
										Err(_) => {
											adv.nsec_wrong = true;
										}
									}
								}
							});
						}
					});
					ui.add_space(12.0);

					// .backup download — directly under the Nostr key, the second
					// half of the ADVANCED NOSTR SETTINGS group. One button, no
					// checklist: it seals your CURRENT identity (key + username)
					// into an encrypted .backup file. (`adv` is no longer used past
					// here, so `self` is free again.)
					w::card(ui, |ui| {
						ui.set_min_width(ui.available_width());
						advanced_head(ui, &t!("goblin.settings.backup_file_title"), t.surface_text);
						advanced_desc(ui, &t!("goblin.advanced.backup_caption"));
						ui.add_space(10.0);
						if w::big_action_on_card(ui, &t!("goblin.settings.backup_file")).clicked()
							&& self.backup.is_none()
						{
							self.backup = Some(BackupState::default());
						}
					});
					// The password/seal form, anchored here unless it was opened from
					// the Danger Zone delete flow below.
					if self.backup.as_ref().is_some_and(|b| !b.anchor_delete) {
						ui.add_space(8.0);
						self.backup_ui(ui, wallet, cb);
					}
					ui.add_space(16.0);

					// ── DANGER ZONE ──────────────────────────────────────────
					// Delete the wallet — password-gated, with a back-up prompt.
					w::kicker_danger(ui, &t!("goblin.advanced.danger_zone"));
					ui.add_space(8.0);
					w::card(ui, |ui| {
						ui.set_min_width(ui.available_width());
						advanced_head(ui, &t!("goblin.advanced.delete"), t.neg);
						advanced_desc(ui, &t!("goblin.advanced.delete_desc"));
						ui.add_space(10.0);
						if self.advanced.confirm_delete {
							ui.label(
								RichText::new(t!("goblin.advanced.delete_warning"))
									.font(FontId::new(13.0, fonts::regular()))
									.color(t.neg),
							);
							ui.add_space(10.0);
							// Back up BEFORE the password field (spec) — the same seal
							// action, but anchored to this flow so its form renders
							// here, not up in the nostr section.
							if w::big_action_on_card(ui, &t!("goblin.advanced.download_backup"))
								.clicked() && self.backup.is_none()
							{
								self.backup = Some(BackupState {
									anchor_delete: true,
									..Default::default()
								});
							}
							if self.backup.as_ref().is_some_and(|b| b.anchor_delete) {
								self.backup_ui(ui, wallet, cb);
								ui.add_space(10.0);
							}
							w::field_well(ui, |ui| {
								TextEdit::new(egui::Id::from("advanced_delete_pass"))
									.focus(false)
									.hint_text(t!("goblin.advanced.password"))
									.password()
									.text_color(t.surface_text)
									.body()
									.ui(ui, &mut self.advanced.delete_pass, cb);
							});
							if self.advanced.delete_wrong {
								ui.add_space(6.0);
								ui.label(
									RichText::new(t!("goblin.advanced.wrong_password"))
										.font(FontId::new(13.0, fonts::medium()))
										.color(t.neg),
								);
							}
							ui.add_space(10.0);
							let adv = &mut self.advanced;
							ui.add_enabled_ui(!adv.delete_pass.is_empty(), |ui| {
								if w::big_action_on_card_ink(
									ui,
									&t!("goblin.advanced.delete_final"),
									t.neg,
								)
								.clicked()
								{
									// Wallet-password gate: get_recovery only returns Ok
									// when the password decrypts the seed.
									if wallet.get_recovery(adv.delete_pass.clone()).is_ok() {
										wallet.delete_wallet();
										leave = true;
									} else {
										adv.delete_wrong = true;
									}
								}
							});
						} else if w::big_action_on_card_ink(
							ui,
							&t!("goblin.advanced.delete"),
							t.neg,
						)
						.clicked()
						{
							self.advanced.confirm_delete = true;
						}
					});
					ui.add_space(20.0);
				});
		}
		if leave {
			self.advanced = AdvancedState::default();
			self.backup = None;
			self.settings_page = SettingsPage::Main;
		}
		if open_node {
			// Advanced → "Manage node connection" opens Goblin's own Node screen.
			self.node_url_input.clear();
			self.node_secret_input.clear();
			self.settings_page = SettingsPage::Node;
		}
		if open_integrated {
			// Advanced is the one home of the integrated-node tabs; back
			// returns here.
			self.node_tab = Box::new(crate::gui::views::network::NetworkNode);
			self.node_tab_back = SettingsPage::Advanced;
			self.settings_page = SettingsPage::IntegratedNode;
		}
	}
}
