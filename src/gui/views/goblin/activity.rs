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

//! Activity tab: history rows, incoming requests and request review.

use super::*;

impl GoblinWalletView {
	/// List-row timestamp: date + HH:MM, no seconds. The tap-in detail view keeps
	/// the full timestamp to the second (see [`View::format_time`]).
	pub(super) fn list_time(ts: i64) -> String {
		let utc_offset = chrono::Local::now().offset().local_minus_utc();
		chrono::DateTime::from_timestamp(ts + utc_offset as i64, 0)
			.map(|t| t.format("%d/%m/%Y %H:%M").to_string())
			.unwrap_or_default()
	}

	/// The (left message, right timestamp) an [`ActivityItem`] shows in a row. The
	/// timestamp (no seconds) is only set for a confirmed tx; otherwise the status
	/// word (canceled/pending) folds into the message so a row with no time still
	/// reads its state without an empty right-side time slot.
	pub(super) fn activity_note_time(item: &ActivityItem) -> (String, String) {
		let status_word = if item.canceled {
			t!("goblin.activity.canceled").to_string()
		} else {
			t!("goblin.activity.pending").to_string()
		};
		let time = if item.confirmed {
			Self::list_time(item.time)
		} else {
			String::new()
		};
		let note = match (item.note.as_deref(), item.confirmed) {
			(Some(n), false) => format!("{n} · {status_word}"),
			(None, false) => status_word,
			(Some(n), true) => n.to_string(),
			(None, true) => String::new(),
		};
		(note, time)
	}

	/// Friendly day-grouping label for the activity feed.
	pub(super) fn day_label(ts: i64) -> String {
		use chrono::{TimeZone, Utc};
		let Some(dt) = Utc.timestamp_opt(ts, 0).single() else {
			return t!("goblin.activity.earlier").to_string();
		};
		let today = Utc::now().date_naive();
		let day = dt.date_naive();
		if day == today {
			t!("goblin.activity.today").to_string()
		} else if (today - day).num_days() == 1 {
			t!("goblin.activity.yesterday").to_string()
		} else {
			dt.format("%b %-d, %Y").to_string()
		}
	}

	pub(super) fn activity_ui(
		&mut self,
		ui: &mut egui::Ui,
		wallet: &Wallet,
		cb: &dyn PlatformCallbacks,
	) {
		ui.add_space(8.0);
		ui.label(
			RichText::new(t!("goblin.activity.title"))
				.font(FontId::new(28.0, fonts::bold()))
				.color(theme::tokens().text),
		);
		ui.add_space(12.0);

		// Recent contacts strip (payment-app-style row above the feed).
		self.peers_strip_ui(ui, wallet, "goblin_peers_activity");

		// Pending payment requests pinned on top.
		if let Some(service) = wallet.nostr_service() {
			// An approve that failed (e.g. funds still confirming) flips the send
			// phase to FAILED — un-grey the buttons so the user can retry, and
			// surface why instead of leaving the card stuck.
			if service.send_phase() == crate::nostr::send_phase::FAILED
				&& !self.approving.is_empty()
			{
				self.approving.clear();
				self.request_error = service.last_send_error();
			}
			let requests = service.store.pending_requests();
			if !requests.is_empty() {
				w::section_header(ui, &t!("goblin.activity.requests"));
				if let Some(err) = &self.request_error {
					ui.add_space(4.0);
					ui.label(
						RichText::new(err)
							.font(FontId::new(13.0, fonts::regular()))
							.color(theme::tokens().neg),
					);
					ui.add_space(4.0);
				}
				for req in requests {
					self.request_row_ui(ui, &req, wallet);
				}
				ui.add_space(8.0);
			}
		}

		ScrollArea::vertical()
			.id_salt("goblin_activity_scroll")
			.auto_shrink([false; 2])
			.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
			.show(ui, |ui| {
				let items = activity_items(wallet);
				let id_cue = IdentityCueCtx::compute(wallet);
				if items.is_empty() {
					empty_state(
						ui,
						&t!("goblin.activity.empty_title"),
						&t!("goblin.activity.empty_sub"),
					);
				} else {
					// Unconfirmed (< min confirmations) pinned on top as Pending.
					// Canceled txs are not pending — they group with history below.
					let pending: Vec<&_> = items
						.iter()
						.filter(|i| !i.confirmed && !i.system && !i.canceled)
						.collect();
					if !pending.is_empty() {
						w::section_header(ui, &t!("goblin.activity.pending_header"));
						for item in pending {
							self.activity_item_ui(ui, item, wallet, cb, &id_cue);
						}
						ui.add_space(8.0);
					}
					// Confirmed (and canceled), grouped by day (newest first).
					let mut last: Option<String> = None;
					for item in items
						.iter()
						.filter(|i| i.confirmed || i.system || i.canceled)
					{
						let label = Self::day_label(item.time);
						if last.as_deref() != Some(label.as_str()) {
							w::section_header(ui, &label);
							last = Some(label);
						}
						self.activity_item_ui(ui, item, wallet, cb, &id_cue);
					}
				}
				ui.add_space(16.0);
			});
	}

	pub(super) fn activity_item_ui(
		&mut self,
		ui: &mut egui::Ui,
		item: &ActivityItem,
		wallet: &Wallet,
		_cb: &dyn PlatformCallbacks,
		id_cue: &IdentityCueCtx,
	) {
		// No +/- for canceled: nothing moved.
		let sign = if item.canceled {
			""
		} else if item.incoming {
			"+ "
		} else {
			"− "
		};
		// Anonymous mode dots the name and amount and replaces the avatar with the
		// uniform censored tile (drawn inside `activity_row` from the `anon` flag)
		// and drops the memo, so nothing leaks; the row still taps through to the
		// full detail, which is the "reveal" the spec calls for.
		let anon = crate::AppConfig::anonymous_mode();
		let amount = if anon {
			// Fixed dot count, never digit-matched, so a censored row can't leak
			// the amount's magnitude.
			censored_amount_dots(item.amount, false)
		} else {
			format!("{}{}{}", sign, w::amount_str(item.amount), w::TSU)
		};
		let (note, time) = Self::activity_note_time(item);
		// No npub association (a non-nostr tx, or metadata cleared by a payment
		// history wipe) => never resolve a real avatar for this row; render the
		// anonymous yellow-goblin tile so the picture can't leak who it was with.
		let anon_avatar = data::tx_row_anonymous(item.npub.as_deref(), item.system);
		let tex = if anon || item.npub.is_none() {
			None
		} else {
			self.handle_tex(ui.ctx(), wallet, &item.title)
		};
		let (title, note_ref, id_ref): (&str, &str, &str) = if anon {
			(CENSOR_NAME_DOTS, "", "")
		} else {
			(&item.title, &note, item.npub.as_deref().unwrap_or(""))
		};
		let resp = w::activity_row(
			ui,
			title,
			note_ref,
			&time,
			id_ref,
			&amount,
			item.incoming,
			item.canceled,
			item.system,
			tex.as_ref(),
			anon,
			anon_avatar,
		);
		// Per-identity cue (owner-approved): only when the wallet holds MORE THAN
		// ONE identity, and never on system (mining) rows. A small corner badge on
		// the counterparty avatar, filled with the identity THIS tx used (its own
		// gradient; falls back to the primary for pre-feature rows). The row avatar
		// is 40px, flush to the row's left and vertically centred, so its
		// bottom-right corner is at (left+40, mid+20); the badge overhangs that
		// corner by ~4px (matching the mock's right:-4/bottom:-4, 14px badge).
		if !anon && SHOW_ROW_IDENTITY_CUE && id_cue.multi && !item.system {
			let seed = item.owner_pubkey.clone().or_else(|| id_cue.primary.clone());
			if let Some(seed) = seed {
				let r = resp.rect;
				let badge = egui::pos2(r.left() + 37.0, r.center().y + 17.0);
				w::identity_dot(ui.painter(), badge, 6.0, &seed);
			}
		}
		if resp.clicked() {
			self.receipt = Some(item.tx_id);
		}
	}

	pub(super) fn request_row_ui(
		&mut self,
		ui: &mut egui::Ui,
		req: &crate::nostr::PaymentRequest,
		wallet: &Wallet,
	) {
		let t = theme::tokens();
		// While an approved request is being paid, the whole card becomes one
		// centered spinner labelled with the action, sitting exactly where the card
		// was: no Decline, no amount, no buttons. It vanishes once the send
		// completes and the request clears from the pending list.
		if self.approving.contains(&req.rumor_id) {
			let working = wallet
				.nostr_service()
				.map(|s| s.send_phase() == crate::nostr::send_phase::WORKING)
				.unwrap_or(false);
			w::card(ui, |ui| {
				ui.vertical_centered(|ui| {
					ui.add_space(6.0);
					View::small_loading_spinner(ui);
					ui.add_space(2.0);
					ui.label(
						RichText::new(t!("goblin.receipt.paying"))
							.font(FontId::new(12.0, fonts::regular()))
							.color(t.text_dim),
					);
					ui.add_space(6.0);
				});
			});
			if working {
				ui.ctx().request_repaint();
			}
			ui.add_space(10.0);
			return;
		}
		let name = wallet
			.nostr_service()
			.map(|s| data::contact_title(&s.store, &req.npub))
			.unwrap_or_else(|| data::short_npub(&req.npub));
		let tex = self.handle_tex(ui.ctx(), wallet, &name);
		w::card(ui, |ui| {
			ui.horizontal(|ui| {
				w::avatar_any(ui, &name, &req.npub, 40.0, tex.as_ref());
				ui.add_space(12.0);
				ui.vertical(|ui| {
					ui.label(
						RichText::new(t!("goblin.request.title", name => name))
							.font(FontId::new(15.0, fonts::semibold()))
							.color(t.surface_text),
					);
					ui.horizontal(|ui| {
						ui.spacing_mut().item_spacing.x = 0.0;
						ui.label(
							RichText::new(w::amount_str(req.amount))
								.font(FontId::new(15.0, fonts::mono_semibold()))
								.color(t.surface_text),
						);
						ui.label(
							RichText::new(w::TSU)
								.font(FontId::new(13.0, fonts::medium()))
								.color(t.surface_text_dim),
						);
					});
				});
			});
			if let Some(note) = &req.note {
				ui.add_space(6.0);
				ui.label(
					RichText::new(format!("\u{201C}{}\u{201D}", note))
						.font(FontId::new(13.0, fonts::regular()))
						.color(t.text_dim),
				);
			}
			ui.add_space(10.0);
			ui.horizontal(|ui| {
				let half = (ui.available_width() - 10.0) / 2.0;
				ui.scope_builder(
					egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
						ui.cursor().min,
						Vec2::new(half, 44.0),
					)),
					|ui| {
						if decline_button(ui) {
							// Optimistically clear the card, then send the decline as
							// a void control message so the requester's side clears
							// too. Requests are messages; payments are final.
							let mut r = req.clone();
							r.status = crate::nostr::RequestStatus::Declined;
							if let Some(s) = wallet.nostr_service() {
								s.store.save_request(&r);
							}
							wallet.task(crate::wallet::types::WalletTask::NostrDeclineRequest(
								req.rumor_id.clone(),
							));
						}
					},
				);
				ui.add_space(10.0);
				ui.scope_builder(
					egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
						ui.cursor().min,
						Vec2::new(half, 44.0),
					)),
					|ui| {
						if approve_button(ui) {
							// Don't pay on the tap — open the review screen and make
							// the user hold-to-accept there, like a send. The actual
							// NostrPayRequest is dispatched from approve_review_ui. Once
							// approved, the in-flight branch above takes over this card.
							self.request_error = None;
							self.approve_hold = w::HoldToSend::default();
							self.approve_fee_for = None;
							self.approve_review = Some(req.clone());
						}
					},
				);
			});
		});
		ui.add_space(10.0);
	}

	/// Full-surface review for an incoming payment request: who's asking, how
	/// much, the network fee — then hold-to-accept. Paying a request is a spend,
	/// so this mirrors the send review's confirm gesture instead of a one-tap
	/// accept. Returns true when the screen should close (back, or after the
	/// payment is enqueued by the hold).
	pub(super) fn approve_review_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet) -> bool {
		let t = theme::tokens();
		let Some(req) = self.approve_review.clone() else {
			return true;
		};
		let name = wallet
			.nostr_service()
			.map(|s| data::contact_title(&s.store, &req.npub))
			.unwrap_or_else(|| data::short_npub(&req.npub));
		let tex = self.handle_tex(ui.ctx(), wallet, &name);
		// Paying a request spends our balance, so guard against over-balance and
		// disable the accept gesture (re-checked each frame).
		let spendable = wallet
			.get_data()
			.map(|d| d.info.amount_currently_spendable)
			.unwrap_or(0);
		let over = req.amount > spendable;
		let mut close = false;
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
					if Self::overlay_back_header(ui, &t!("goblin.request.review_title")) {
						close = true;
					}
					ScrollArea::vertical()
						.id_salt("goblin_approve_scroll")
						.auto_shrink([false; 2])
						.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
						.show(ui, |ui| {
							ui.add_space(8.0);
							w::card(ui, |ui| {
								ui.set_min_width(ui.available_width());
								ui.add_space(8.0);
								ui.vertical_centered(|ui| {
									w::avatar_any(ui, &name, &req.npub, 40.0, tex.as_ref());
									ui.add_space(6.0);
									ui.label(
										RichText::new(t!("goblin.request.title", name => &name))
											.font(FontId::new(14.0, fonts::regular()))
											.color(t.surface_text_dim),
									);
								});
								ui.add_space(8.0);
								let amt = w::amount_str(req.amount);
								w::amount_text_centered_ink(
									ui,
									&amt,
									48.0,
									t.surface_text,
									t.surface_text_dim,
								);
								ui.add_space(8.0);
							});
							ui.add_space(16.0);

							w::info_row(ui, &t!("goblin.send.row_from"), &name);
							if let Some(note) = &req.note {
								if !note.trim().is_empty() {
									w::info_row(
										ui,
										&t!("goblin.send.row_note"),
										&format!("\u{201C}{}\u{201D}", note.trim()),
									);
								}
							}
							// Live network fee for paying this request (a spend),
							// priced like the send review — one CalculateFee per amount.
							if req.amount > 0 && self.approve_fee_for != Some(req.amount) {
								self.approve_fee_for = Some(req.amount);
								wallet.task(crate::wallet::types::WalletTask::CalculateFee(
									req.amount, 0,
								));
							}
							let fee_val = match wallet.calculated_fee(req.amount) {
								Some(fee) => format!("{}{}", w::amount_str(fee), w::TSU),
								None => {
									ui.ctx().request_repaint_after(
										std::time::Duration::from_millis(120),
									);
									"…".to_string()
								}
							};
							w::info_row(ui, &t!("goblin.send.row_network_fee"), &fee_val);
							w::info_row(
								ui,
								&t!("goblin.send.row_privacy"),
								&t!("goblin.send.row_privacy_val"),
							);
							w::info_row(
								ui,
								&t!("goblin.send.row_delivery"),
								&t!("goblin.send.row_delivery_val"),
							);
							ui.add_space(16.0);

							if over {
								ui.vertical_centered(|ui| {
									ui.label(
										RichText::new(t!("goblin.send.not_enough"))
											.font(FontId::new(14.0, fonts::regular()))
											.color(t.neg),
									);
								});
								ui.add_space(8.0);
							}
							ui.add_enabled_ui(!over, |ui| {
								if self
									.approve_hold
									.ui(ui, &t!("goblin.request.hold_to_accept"))
									&& !over
								{
									// Guard double-pay + show the spinner back on the
									// request card; dispatch the actual payment.
									self.approving.insert(req.rumor_id.clone());
									self.request_error = None;
									wallet.task(crate::wallet::types::WalletTask::NostrPayRequest(
										req.rumor_id.clone(),
									));
									close = true;
								}
							});
							ui.add_space(6.0);
							ui.vertical_centered(|ui| {
								ui.label(
									RichText::new(if over {
										t!("goblin.send.lower_amount")
									} else {
										t!("goblin.request.hold_accept_hint")
									})
									.font(FontId::new(12.0, fonts::regular()))
									.color(t.text_mute),
								);
							});
							ui.add_space(16.0);
						});
				});
			});
		close
	}
}
