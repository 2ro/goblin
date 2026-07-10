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

//! Small modals (min-conf, batch invoice, trusted sites) and the login toast.

use super::*;

impl GoblinWalletView {
	/// Content of the minimum-confirmations edit modal — a direct port of GRIM's
	/// min_conf_modal_ui (numeric input, invalid-value error, Cancel/Save). The
	/// saved value persists in WalletConfig::min_confirmations and feeds the
	/// wallet's spendable/send logic on the next balance refresh.
	pub(super) fn min_conf_modal_content(
		&mut self,
		ui: &mut egui::Ui,
		wallet: &Wallet,
		modal: &Modal,
		cb: &dyn PlatformCallbacks,
	) {
		let on_save = |s: &mut GoblinWalletView| {
			if let Ok(min_conf) = s.min_conf_edit.parse::<u64>() {
				wallet.update_min_confirmations(min_conf);
				Modal::close();
			}
		};
		ui.add_space(6.0);
		ui.vertical_centered(|ui| {
			ui.label(
				RichText::new(t!("wallets.min_tx_conf_count"))
					.size(17.0)
					.color(Colors::gray()),
			);
			ui.add_space(8.0);
			let mut edit = TextEdit::new(egui::Id::from(modal.id)).h_center().numeric();
			edit.ui(ui, &mut self.min_conf_edit, cb);
			if edit.enter_pressed {
				on_save(self);
			}
			if self.min_conf_edit.parse::<u64>().is_err() {
				ui.add_space(12.0);
				ui.label(
					RichText::new(t!("network_settings.not_valid_value"))
						.size(17.0)
						.color(Colors::red()),
				);
			}
			ui.add_space(12.0);
		});
		ui.scope(|ui| {
			ui.spacing_mut().item_spacing = egui::Vec2::new(8.0, 0.0);
			ui.columns(2, |columns| {
				columns[0].vertical_centered_justified(|ui| {
					View::button(
						ui,
						t!("modal.cancel"),
						Colors::white_or_black(false),
						|| {
							Modal::close();
						},
					);
				});
				columns[1].vertical_centered_justified(|ui| {
					View::button(ui, t!("modal.save"), Colors::white_or_black(false), || {
						on_save(self);
					});
				});
			});
			ui.add_space(6.0);
		});
	}

	/// Content of the batch-invoice approval modal: ONE approval for N payment
	/// requests to the same payer, each request minted its own fresh per-sale
	/// proof address so no two sales share an address. Approve fires the same
	/// request task the single flow uses, N times; the requests then appear in
	/// activity as they dispatch, exactly like single requests.
	pub(super) fn batch_invoice_modal_content(&mut self, ui: &mut egui::Ui, wallet: &Wallet) {
		let Some(b) = &self.batch_invoice else {
			Modal::close();
			return;
		};
		let name = wallet
			.nostr_service()
			.map(|s| data::contact_title(&s.store, &b.hex))
			.unwrap_or_else(|| data::short_npub(&b.hex));
		let each = grin_core::core::amount_from_hr_string(&b.amount).unwrap_or(0);
		let total = each.saturating_mul(b.count as u64);
		ui.vertical_centered(|ui| {
			ui.add_space(6.0);
			ui.label(
				RichText::new(t!(
					"goblin.batch.blurb",
					n => b.count.to_string(),
					name => name,
					amount => format!("{}{}", w::amount_str(each), w::TSU),
					total => format!("{}{}", w::amount_str(total), w::TSU)
				))
				.size(16.0)
				.color(Colors::gray()),
			);
			if let Some(memo) = &b.memo {
				ui.add_space(6.0);
				ui.label(
					RichText::new(format!("\u{201C}{}\u{201D}", memo))
						.size(15.0)
						.color(Colors::gray()),
				);
			}
			ui.add_space(12.0);
		});
		let mut cancel = false;
		let mut approve = false;
		ui.scope(|ui| {
			ui.spacing_mut().item_spacing = egui::Vec2::new(8.0, 0.0);
			ui.columns(2, |columns| {
				columns[0].vertical_centered_justified(|ui| {
					View::button(
						ui,
						t!("modal.cancel"),
						Colors::white_or_black(false),
						|| {
							cancel = true;
						},
					);
				});
				columns[1].vertical_centered_justified(|ui| {
					View::button(
						ui,
						t!("goblin.batch.approve"),
						Colors::white_or_black(false),
						|| {
							approve = true;
						},
					);
				});
			});
			ui.add_space(6.0);
		});
		if cancel {
			self.batch_invoice = None;
			Modal::close();
		}
		if approve {
			if let Some(b) = self.batch_invoice.take() {
				if let Some(service) = wallet.nostr_service() {
					service.set_send_phase(crate::nostr::send_phase::WORKING);
				}
				let w = wallet.clone();
				std::thread::spawn(move || {
					for _ in 0..b.count {
						// Each request gets its OWN fresh proof address; a mint
						// failure stops the batch (already-issued requests stand).
						match w.mint_proof_address() {
							Ok((_index, addr)) => {
								w.task(crate::wallet::types::WalletTask::NostrRequest(
									each,
									b.hex.clone(),
									b.memo.clone(),
									b.relay_hints.clone(),
									Some(addr),
								));
							}
							Err(e) => {
								log::error!("batch invoice: mint failed: {e}");
								break;
							}
						}
					}
				});
			}
			Modal::close();
		}
	}

	/// Trusted Sites: the active Authorize Sessions, what each can sign silently,
	/// time remaining, and a one-tap end (immediate, unilateral revocation).
	pub(super) fn trusted_sites_ui(
		&mut self,
		ui: &mut egui::Ui,
		wallet: &Wallet,
		_cb: &dyn PlatformCallbacks,
	) {
		let t = theme::tokens();
		if self.sub_header(ui, &t!("goblin.trusted_sites.title")) {
			self.settings_page = SettingsPage::Main;
			return;
		}
		let summaries = wallet
			.nostr_service()
			.map(|s| s.session_summaries())
			.unwrap_or_default();
		ScrollArea::vertical()
			.id_salt("goblin_trusted_sites_scroll")
			.auto_shrink([false; 2])
			.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
			.show(ui, |ui| {
				ui.label(
					RichText::new(t!("goblin.trusted_sites.intro"))
						.font(FontId::new(13.0, fonts::regular()))
						.color(t.text_dim),
				);
				ui.add_space(12.0);
				if summaries.is_empty() {
					ui.label(
						RichText::new(t!("goblin.trusted_sites.empty"))
							.font(FontId::new(13.0, fonts::regular()))
							.color(t.text_dim),
					);
					return;
				}
				let mut to_end: Option<String> = None;
				let mut to_resume: Option<String> = None;
				for s in &summaries {
					settings_group(ui, &s.domain, |ui| {
						// The low-tier categories this session signs silently.
						let cats: Vec<String> = s
							.categories
							.iter()
							.map(|c| t!(c.key()).to_string())
							.collect();
						let cats = if cats.is_empty() {
							t!("goblin.trusted_sites.none").to_string()
						} else {
							cats.join(", ")
						};
						ui.label(
							RichText::new(t!("goblin.trusted_sites.can_sign", cats => cats))
								.font(FontId::new(12.5, fonts::regular()))
								.color(t.text_dim),
						);
						ui.add_space(4.0);
						let mins = s.ttl_remaining_secs / 60;
						ui.label(
							RichText::new(
								t!("goblin.trusted_sites.time_left", mins => mins.to_string()),
							)
							.font(FontId::new(12.5, fonts::regular()))
							.color(t.text_dim),
						);
						if s.paused {
							ui.add_space(4.0);
							ui.label(
								RichText::new(t!("goblin.trusted_sites.paused"))
									.font(FontId::new(12.5, fonts::regular()))
									.color(Colors::red()),
							);
							if settings_row_btn(
								ui,
								&t!("goblin.trusted_sites.resume"),
								crate::gui::icons::PLAY,
							) {
								to_resume = Some(s.domain.clone());
							}
						}
						if settings_row_btn(
							ui,
							&t!("goblin.trusted_sites.end"),
							crate::gui::icons::X_CIRCLE,
						) {
							to_end = Some(s.domain.clone());
						}
					});
					ui.add_space(8.0);
				}
				if let Some(svc) = wallet.nostr_service() {
					if let Some(d) = to_end {
						svc.end_session(&d);
					}
					if let Some(d) = to_resume {
						svc.resume_session(&d);
					}
				}
			});
	}

	/// Draw the transient login-outcome toast: the same quiet pill as the back
	/// hint (solid soft pill, no border, small dim text), bottom-anchored,
	/// non-blocking, fading out.
	pub(super) fn login_toast_ui(&mut self, ctx: &egui::Context) {
		const SHOW_SECS: f32 = 3.5;
		let Some((text, at)) = &self.login_toast else {
			return;
		};
		let elapsed = at.elapsed().as_secs_f32();
		if elapsed >= SHOW_SECS {
			self.login_toast = None;
			return;
		}
		let text = text.clone();
		let t = theme::tokens();
		// Fade over the final 0.5s.
		let alpha = ((SHOW_SECS - elapsed) / 0.5).clamp(0.0, 1.0);
		let font = FontId::new(13.0, fonts::regular());
		egui::Area::new(egui::Id::new("goblin_login_toast"))
			.order(egui::Order::Foreground)
			.anchor(
				egui::Align2::CENTER_BOTTOM,
				Vec2::new(0.0, -(View::get_bottom_inset() + 92.0)),
			)
			.interactable(false)
			.show(ctx, |ui| {
				let galley = ui
					.painter()
					.layout_no_wrap(text, font.clone(), t.surface_text_dim);
				let pad = Vec2::new(16.0, 10.0);
				let size = galley.size() + pad * 2.0;
				let (rect, _) = ui.allocate_exact_size(size, Sense::hover());
				ui.painter().rect(
					rect,
					CornerRadius::same((size.y / 2.0) as u8),
					t.surface2.gamma_multiply(alpha),
					Stroke::NONE,
					egui::StrokeKind::Inside,
				);
				ui.painter().galley(
					rect.min + pad,
					galley,
					t.surface_text_dim.gamma_multiply(alpha),
				);
			});
		ctx.request_repaint_after(std::time::Duration::from_millis(50));
	}
}
