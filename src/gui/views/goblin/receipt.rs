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

//! Transaction-receipt full-surface overlay.

use super::*;

impl GoblinWalletView {
	/// Full-surface transaction receipt: GRIM metadata joined with the nostr
	/// counterparty + note. Tapping the counterparty opens their profile.
	pub(super) fn receipt_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet, tx_id: u32) -> bool {
		let t = theme::tokens();
		let d = data::receipt_detail(wallet, tx_id);
		// Only resolve a real avatar when the tx has an npub association; a wiped
		// or non-nostr tx (no npub) must never resolve a profile picture.
		let tex = d
			.as_ref()
			.filter(|d| d.npub.is_some())
			.and_then(|d| self.handle_tex(ui.ctx(), wallet, &d.title));
		let mut close = false;
		let mut open_profile: Option<String> = None;
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
					if Self::overlay_back_header(ui, &t!("goblin.receipt.title")) {
						close = true;
					}
					let Some(d) = d else {
						ui.add_space(40.0);
						ui.vertical_centered(|ui| {
							ui.label(
								RichText::new(t!("goblin.receipt.not_found"))
									.font(FontId::new(15.0, fonts::regular()))
									.color(t.text_dim),
							);
						});
						return;
					};
					ScrollArea::vertical()
						.id_salt("goblin_receipt_scroll")
						.auto_shrink([false; 2])
						.show(ui, |ui| {
							ui.add_space(8.0);
							ui.vertical_centered(|ui| {
								let resp = if d.npub.is_some() {
									w::avatar_any(
										ui,
										&d.title,
										d.npub.as_deref().unwrap_or(""),
										64.0,
										tex.as_ref(),
									)
								} else {
									// No npub association (wiped or non-nostr tx):
									// the anonymous yellow-goblin tile, never a real
									// profile picture.
									w::avatar_censored(ui, 64.0)
								};
								ui.add_space(10.0);
								ui.label(
									RichText::new(&d.title)
										.font(FontId::new(22.0, fonts::bold()))
										.color(t.text),
								);
								ui.add_space(2.0);
								ui.label(
									RichText::new(View::format_time(d.time))
										.font(FontId::new(13.0, fonts::regular()))
										.color(t.text_dim),
								);
								if let Some(note) = &d.note {
									ui.add_space(2.0);
									ui.label(
										RichText::new(t!("goblin.receipt.for_note", note => note))
											.font(FontId::new(13.0, fonts::regular()))
											.color(t.text_dim),
									);
								}
								ui.add_space(14.0);
								w::amount_text_centered(ui, &w::amount_str(d.amount), 56.0);
								if resp.clicked() {
									if let Some(npub) = &d.npub {
										open_profile = Some(npub.clone());
									}
								}
							});
							ui.add_space(20.0);
							w::kicker(ui, &t!("goblin.receipt.details"));
							ui.add_space(10.0);
							w::card(ui, |ui| {
								let (status, sub): (String, String) = if d.canceled {
									(
										t!("goblin.receipt.canceled").to_string(),
										if d.incoming {
											t!("goblin.receipt.expired").to_string()
										} else {
											t!("goblin.receipt.funds_returned").to_string()
										},
									)
								} else if let Some((c, r)) = d.confs {
									// On-chain but still maturing toward the spendable
									// threshold — show the live X/N count (grin marks a
									// tx confirmed at one block; spendable takes N).
									if c == 0 && !d.incoming && d.npub.is_some() {
										// Sent but not yet picked up / mined.
										(
											t!("goblin.receipt.pending").to_string(),
											t!("goblin.receipt.waiting_to_receive", name => d.title)
												.to_string(),
										)
									} else {
										(
											t!("goblin.receipt.pending").to_string(),
											t!("goblin.receipt.confs", c => c, r => r).to_string(),
										)
									}
								} else if d.confirmed {
									(
										t!("goblin.receipt.complete").to_string(),
										if d.incoming {
											t!("goblin.receipt.payment_received").to_string()
										} else {
											t!("goblin.receipt.payment_sent").to_string()
										},
									)
								} else {
									(
										t!("goblin.receipt.pending").to_string(),
										t!("goblin.receipt.waiting_to_confirm").to_string(),
									)
								};
								w::info_row(ui, &status, &sub);
								if d.has_identity {
									let (to, from) = if d.incoming {
										(t!("goblin.receipt.you").to_string(), d.title.clone())
									} else {
										(d.title.clone(), t!("goblin.receipt.you").to_string())
									};
									w::info_row(ui, &t!("goblin.receipt.to"), &to);
									w::info_row(ui, &t!("goblin.receipt.from"), &from);
									// Which of the wallet's held nostr identities was active
									// when this payment was received/sent — the "front door"
									// it used. Uses the identity recorded on the tx
									// (recipient_pubkey), falling back to the primary for
									// pre-feature rows. NIP-05 name when claimed, else a
									// truncated npub.
									let owning_hex = d
										.slate_id
										.as_deref()
										.and_then(|sid| {
											wallet
												.nostr_service()
												.and_then(|s| s.store.tx_meta(sid))
										})
										.map(|m| m.recipient_pubkey)
										.filter(|h| !h.is_empty());
									let ids = wallet.nostr_identities();
									// The identity this tx used: the one recorded on it,
									// else the primary for pre-feature rows.
									let owner = match &owning_hex {
										Some(hex) => ids.iter().find(|i| &i.pubkey_hex == hex),
										None => ids.first(),
									};
									let seed = owner
										.map(|i| i.pubkey_hex.clone())
										.or_else(|| owning_hex.clone());
									// The claimed name (no leading @, no domain — the project
									// convention), else the truncated npub. Never a
									// placeholder word.
									let id_label = owner
										.map(|i| i.display())
										.or_else(|| owning_hex.as_deref().map(data::short_npub))
										.unwrap_or_default();
									if !id_label.is_empty() {
										match &seed {
											Some(seed) => w::info_row_dot(
												ui,
												&t!("goblin.receipt.identity"),
												&id_label,
												seed,
											),
											None => w::info_row(
												ui,
												&t!("goblin.receipt.identity"),
												&id_label,
											),
										}
									}
								}
								if let Some(npub) = &d.npub {
									w::info_row(
										ui,
										&t!("goblin.receipt.nostr"),
										&data::short_npub(npub),
									);
								}
								// Only the SENDER pays a network fee, so the row only makes
								// sense on outgoing payments. A received payment has no fee
								// (data sets it to None) — hide the row entirely instead of
								// showing a confusing "—".
								if let Some(fee_amount) = d.fee {
									let fee = if fee_amount == 0 {
										t!("goblin.receipt.fee_none").to_string()
									} else {
										format!("{}{}", w::amount_str(fee_amount), w::TSU)
									};
									w::info_row(ui, &t!("goblin.receipt.network_fee"), &fee);
								}
								w::info_row(
									ui,
									&t!("goblin.receipt.privacy"),
									&t!("goblin.receipt.privacy_value"),
								);
								if let Some(sid) = &d.slate_id {
									let short = if sid.len() > 13 {
										format!("{}…{}", &sid[..8], &sid[sid.len() - 4..])
									} else {
										sid.clone()
									};
									w::info_row(ui, &t!("goblin.receipt.transaction"), &short);
								}
							});
							// Withdraw a request we sent that hasn't been paid yet:
							// cancel the local invoice and tell the payer (a void
							// message). Requests are messages; payments are final.
							let cancelable_request = d
								.slate_id
								.as_ref()
								.and_then(|sid| {
									wallet.nostr_service().and_then(|s| s.store.tx_meta(sid))
								})
								.map(|m| {
									m.direction == crate::nostr::NostrTxDirection::RequestedByUs
										&& matches!(
											m.status,
											crate::nostr::NostrSendStatus::Created
												| crate::nostr::NostrSendStatus::AwaitingI2
										)
								})
								.unwrap_or(false) && !d.canceled
								&& !d.confirmed;
							if cancelable_request {
								ui.add_space(16.0);
								if w::big_action(ui, &t!("goblin.receipt.cancel_request"), true)
									.clicked()
								{
									if let Some(sid) = &d.slate_id {
										wallet.task(
											crate::wallet::types::WalletTask::NostrCancelOutgoing(
												sid.clone(),
											),
										);
									}
									close = true;
								}
							}
							// Reclaim a payment WE sent that the recipient never
							// completed: cancel the grin tx to unlock our funds, mark
							// it cancelled, best-effort void. Appears after the grace
							// window (or immediately if it never reached a relay).
							let send_meta = d.slate_id.as_ref().and_then(|sid| {
								wallet.nostr_service().and_then(|s| s.store.tx_meta(sid))
							});
							let grace = wallet
								.nostr_service()
								.map(|s| s.config.read().cancel_grace_secs())
								.unwrap_or(600);
							let cancelable_send = send_meta
								.as_ref()
								.map(|m| {
									m.direction == crate::nostr::NostrTxDirection::Sent
										&& matches!(
											m.status,
											crate::nostr::NostrSendStatus::Created
												| crate::nostr::NostrSendStatus::AwaitingS2
												| crate::nostr::NostrSendStatus::SendFailed
										) && (matches!(
										m.status,
										crate::nostr::NostrSendStatus::SendFailed
									) || crate::nostr::unix_time() - m.created_at > grace)
								})
								.unwrap_or(false) && !d.canceled
								&& !d.confirmed;
							// A manual Cancel is ALWAYS available for a stuck pending. The
							// nostr-aware path above (after the grace window) also voids
							// the counterparty's DM; this fallback covers every other
							// cancellable pending it missed — e.g. a tx orphaned by an
							// identity switch (its meta lives in another identity's
							// store) or one left by an older build. Both run the plain
							// libwallet cancel that unlocks our reserved inputs; nothing
							// auto-fires on a timer.
							let fallback_cancel =
								!cancelable_request && !cancelable_send && d.can_cancel;
							if cancelable_send || fallback_cancel {
								// Soft nudge that this pending has been waiting a long
								// time (a hint; the Cancel button sits right below).
								if d.stale {
									ui.add_space(12.0);
									ui.vertical_centered(|ui| {
										ui.label(
											RichText::new(t!("goblin.receipt.stale_note"))
												.font(FontId::new(13.0, fonts::regular()))
												.color(t.accent),
										);
									});
								}
								ui.add_space(16.0);
								let confirming = self.cancel_confirm == Some(d.tx_id);
								let label = if confirming {
									t!("goblin.receipt.cancel_send_confirm")
								} else {
									t!("goblin.receipt.cancel_send")
								};
								if w::big_action(ui, &label, true).clicked() {
									if confirming {
										if cancelable_send {
											if let Some(sid) = &d.slate_id {
												wallet.task(
													crate::wallet::types::WalletTask::NostrCancelSend(
														sid.clone(),
													),
												);
											}
										} else {
											wallet.task(crate::wallet::types::WalletTask::Cancel(
												d.tx_id,
											));
										}
										self.cancel_confirm = None;
									} else {
										self.cancel_confirm = Some(d.tx_id);
									}
								}
							} else {
								self.cancel_confirm = None;
							}
							// Transient outcome notice, set async by the task handler.
							if let Some(outcome) =
								wallet.nostr_service().and_then(|s| s.take_cancel_notice())
							{
								self.cancel_msg = Some((outcome, std::time::Instant::now()));
							}
							if let Some((outcome, at)) = self.cancel_msg {
								if at.elapsed().as_secs() < 5 {
									ui.add_space(10.0);
									let (msg, col) = match outcome {
										crate::nostr::CancelOutcome::Cancelled => {
											(t!("goblin.receipt.cancel_send_done"), t.pos)
										}
										crate::nostr::CancelOutcome::AlreadyCompleted => {
											(t!("goblin.receipt.cancel_send_too_late"), t.text_dim)
										}
									};
									ui.vertical_centered(|ui| {
										ui.label(
											RichText::new(msg)
												.font(FontId::new(13.0, fonts::regular()))
												.color(col),
										);
									});
									ui.ctx().request_repaint_after(
										std::time::Duration::from_millis(300),
									);
								} else {
									self.cancel_msg = None;
								}
							}
							ui.add_space(20.0);
						});
				});
			});
		if let Some(npub) = open_profile {
			self.profile = Some(npub);
			close = true;
		}
		close
	}
}
