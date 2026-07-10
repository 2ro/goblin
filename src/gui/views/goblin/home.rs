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

//! Home tab: balance hero, node card, news and peers strip.

use super::*;

impl GoblinWalletView {
	/// Compact node status card: sync state dot, block height, connection.
	pub(super) fn node_card_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet) {
		let t = theme::tokens();
		let height = wallet
			.get_data()
			.map(|d| d.info.last_confirmed_height)
			.unwrap_or(0);
		// Distinguish "scanning" from "can't reach the node": a flaky
		// external node otherwise reads as syncing forever.
		let error = wallet.sync_error();
		let synced = height > 0 && !wallet.syncing() && !error;
		w::card(ui, |ui| {
			ui.set_min_width(ui.available_width());
			ui.horizontal(|ui| {
				let (dot, _) = ui.allocate_exact_size(Vec2::splat(10.0), Sense::hover());
				ui.painter().circle_filled(
					dot.center(),
					4.0,
					if error {
						t.neg
					} else if synced {
						t.pos
					} else {
						t.accent
					},
				);
				ui.add_space(8.0);
				ui.vertical(|ui| {
					ui.label(
						RichText::new(if error {
							t!("goblin.home.cant_reach_node")
						} else if synced {
							t!("goblin.home.node_synced")
						} else {
							t!("goblin.home.syncing")
						})
						.font(FontId::new(14.0, fonts::semibold()))
						.color(t.surface_text),
					);
					// Three lines: status, block height, then the node host
					// on its own line so it never truncates the height.
					let height = wallet
						.get_data()
						.map(|d| d.info.last_confirmed_height)
						.unwrap_or(0);
					ui.label(
						RichText::new(if height > 0 {
							t!("goblin.home.block", height => fmt_thousands(height)).to_string()
						} else {
							t!("goblin.home.waiting_for_chain").to_string()
						})
						.font(FontId::new(12.0, fonts::regular()))
						.color(t.surface_text_dim),
					);
					ui.add(
						egui::Label::new(
							RichText::new(node_host(wallet))
								.font(FontId::new(12.0, fonts::regular()))
								.color(t.surface_text_mute),
						)
						.truncate(),
					);
				});
				// Low-opacity gear so the card reads as a tappable settings
				// shortcut; on-surface ink keeps it theme-aware.
				ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
					ui.label(
						RichText::new(crate::gui::icons::GEAR)
							.font(FontId::new(16.0, fonts::regular()))
							.color(t.surface_text.gamma_multiply(0.35)),
					);
				});
			});
		});
	}

	pub(super) fn home_ui(
		&mut self,
		ui: &mut egui::Ui,
		wallet: &Wallet,
		cb: &dyn PlatformCallbacks,
		wide: bool,
	) {
		let data = wallet.get_data();
		ScrollArea::vertical()
			.id_salt("goblin_home_scroll")
			.auto_shrink([false; 2])
			.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
			.show(ui, |ui| {
				// Mobile header: wordmark left, avatar (opens settings) right.
				if !wide {
					ui.add_space(10.0);
					ui.horizontal(|ui| {
						// Owner-sized: +50% over the original 24px mark so the lockup
						// carries the same visual weight as the 40-44px right cluster.
						widgets_logo_sized(ui, 36.0);
						ui.add_space(9.0);
						ui.label(
							RichText::new("goblin")
								.font(FontId::new(26.0, fonts::bold()))
								.color(theme::tokens().text),
						);
						ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
							// The user's own avatar (opens settings). Mode-aware: the
							// flat yellow + Grin mark tile only in anonymous mode,
							// otherwise this identity's normal gradient/picture.
							if self.avatar_self(ui, wallet, 40.0).clicked() {
								self.tab = Tab::Me;
							}
							// Scan-to-pay, left of the avatar. No frame: a bold white QR
							// glyph sized and centered to mirror the Pay-page header
							// treatment next to the avatar (was a tacky filled circle).
							ui.add_space(12.0);
							let (rect, resp) =
								ui.allocate_exact_size(Vec2::splat(44.0), Sense::click());
							ui.painter().text(
								rect.center(),
								egui::Align2::CENTER_CENTER,
								QR_CODE,
								FontId::new(38.0, fonts::regular()),
								theme::tokens().text,
							);
							let resp = resp.on_hover_cursor(egui::CursorIcon::PointingHand);
							if resp.clicked() {
								let mut flow = SendFlow::default();
								flow.request_scan();
								self.send = Some(flow);
							}
						});
					});
					ui.add_space(28.0);
				} else {
					ui.add_space(48.0);
				}
				let (total, spendable) = data
					.as_ref()
					.map(|d| (d.info.total, d.info.amount_currently_spendable))
					.unwrap_or((0, 0));
				// Zero can just mean "in transit" (locked change / awaiting
				// finalization) or a first sync still running.
				let in_flight = data
					.as_ref()
					.map(|d| d.info.amount_locked + d.info.amount_awaiting_finalization)
					.unwrap_or(0);
				let updating = total == 0 && (in_flight > 0 || wallet.syncing());
				// Distinguish "still updating" from "can't reach the node" so a
				// node outage never renders as a silent zero (see balance_hero).
				let error = wallet.sync_error();
				// Anonymous mode: the balance is a row of dots until tapped. The
				// fiat lookup is skipped entirely while censored (fiat_line is what
				// kicks the rate fetch) and only fires once revealed.
				if crate::AppConfig::anonymous_mode() && !self.balance_revealed {
					if censored_balance_hero(ui, total) {
						self.balance_revealed = true;
					}
				} else {
					w::balance_hero(
						ui,
						total,
						spendable,
						updating,
						error,
						wallet.info_sync_progress(),
						fiat_line(&data),
						56.0,
					);
				}
				ui.add_space(20.0);
				let (send, receive) = w::send_receive(ui);
				if send {
					self.send = Some(SendFlow::default());
				}
				if receive {
					self.tab = Tab::Receive;
				}
				ui.add_space(24.0);

				// Latest news post (hidden entirely when none seen yet).
				self.news_panel_ui(ui, wallet);

				// Recent peers strip.
				self.peers_strip_ui(ui, wallet, "goblin_peers_home");

				// Recent activity.
				w::kicker(ui, &t!("goblin.home.activity"));
				ui.add_space(6.0);
				let items = activity_items(wallet);
				let id_cue = IdentityCueCtx::compute(wallet);
				if items.is_empty() {
					empty_state(
						ui,
						&t!("goblin.home.empty_title"),
						&t!("goblin.home.empty_sub"),
					);
				} else {
					for item in items.iter().take(6) {
						self.activity_item_ui(ui, item, wallet, cb, &id_cue);
					}
				}
				ui.add_space(16.0);
			});
	}

	/// Latest news post from the Goblin news key. Title + summary in a card, with
	/// any http(s) URL in the summary rendered as a tappable link. Renders nothing
	/// (early return) when no post has been cached yet — no empty state.
	pub(super) fn news_panel_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet) {
		let Some(news) = news_latest(wallet) else {
			return;
		};
		let t = theme::tokens();
		w::kicker(ui, &t!("goblin.home.news"));
		ui.add_space(8.0);
		w::card(ui, |ui| {
			// Span the full content width like the balance/activity rows so the
			// panel reads as a band, not a content-hugging chip.
			ui.set_min_width(ui.available_width());
			// Date first, ISO 8601 (YYYY-MM-DD, UTC). Dated by the article's
			// published_at tag when present, else the event's created_at.
			let stamp = news.published_at.unwrap_or(news.created_at);
			ui.label(
				RichText::new(data::news_date_iso(stamp))
					.font(FontId::new(12.0, fonts::medium()))
					.color(t.surface_text_dim),
			);
			if !news.title.is_empty() {
				ui.add_space(2.0);
				// Title guardrail: hard-cap the length (predictable ellipsis past
				// NEWS_TITLE_MAX_CHARS) then shrink the font to fit the card width on
				// one line down to a 12pt floor, so a title never clips. `.truncate()`
				// backs the floor for the pathological narrow case.
				let title = data::news_title_clamped(&news.title);
				let pt = fit_news_title_pt(ui, &title, ui.available_width());
				ui.add(
					egui::Label::new(
						RichText::new(&title)
							.font(FontId::new(pt, fonts::semibold()))
							.color(t.surface_text),
					)
					.truncate(),
				);
			}
			if !news.summary.is_empty() {
				ui.add_space(4.0);
				ui.horizontal_wrapped(|ui| {
					ui.spacing_mut().item_spacing.x = 0.0;
					for (seg, is_url) in split_urls(&news.summary) {
						if is_url {
							// hyperlink opens via ctx.open_url, same as open_url().
							ui.hyperlink(seg);
						} else {
							ui.label(
								RichText::new(seg)
									.font(FontId::new(13.0, fonts::regular()))
									.color(t.surface_text_dim),
							);
						}
					}
				});
			}
		});
		ui.add_space(24.0);
	}

	/// Horizontal recent-contacts strip; tapping one starts a prefilled send.
	pub(super) fn peers_strip_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet, salt: &str) {
		let peers = recent_peers(wallet, 8);
		if peers.is_empty() {
			return;
		}
		// Anonymous mode censors the Recent strip exactly like the rest of the
		// surface: the uniform yellow tile for every avatar and dotted names, so a
		// recent recipient is no more identifiable here than in the activity feed.
		let anon = crate::AppConfig::anonymous_mode();
		let texs: Vec<Option<egui::TextureHandle>> = if anon {
			peers.iter().map(|_| None).collect()
		} else {
			peers
				.iter()
				.map(|(name, _)| self.handle_tex(ui.ctx(), wallet, name))
				.collect()
		};
		w::kicker(ui, &t!("goblin.home.recent"));
		ui.add_space(12.0);
		ScrollArea::horizontal()
			.id_salt(salt.to_string())
			.auto_shrink([false, true])
			.show(ui, |ui| {
				ui.horizontal(|ui| {
					for ((name, npub), tex) in peers.iter().zip(texs.iter()) {
						// Fixed-width centered cell so the name sits centered under the
						// avatar (not left-aligned to a wider label).
						ui.allocate_ui_with_layout(
							Vec2::new(72.0, 78.0),
							Layout::top_down(Align::Center),
							|ui| {
								let resp = if anon {
									w::avatar_censored(ui, 48.0)
								} else {
									w::avatar_any(ui, name, npub, 48.0, tex.as_ref())
								};
								ui.add_space(6.0);
								let short: String = if anon {
									CENSOR_NAME_DOTS.to_string()
								} else {
									let chars: Vec<char> = name.chars().collect();
									if chars.len() > 8 {
										format!("{}…", chars[..8].iter().collect::<String>())
									} else {
										name.to_string()
									}
								};
								ui.label(
									RichText::new(short).font(FontId::new(12.0, fonts::medium())),
								);
								// Tapping still opens the profile (tap-to-reveal); the strip
								// itself stays censored.
								if resp.clicked() {
									self.profile = Some(npub.clone());
								}
							},
						);
						ui.add_space(12.0);
					}
				});
			});
		ui.add_space(20.0);
	}
}
