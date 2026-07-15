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

//! "Me" account-header screen.

use super::*;

impl GoblinWalletView {
	pub(super) fn me_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet, cb: &dyn PlatformCallbacks) {
		let t = theme::tokens();
		match self.settings_page {
			SettingsPage::Node => return self.node_settings_ui(ui, wallet, cb),
			SettingsPage::IntegratedNode => return self.integrated_node_ui(ui, cb),
			SettingsPage::Relays => return self.relays_ui(ui, wallet, cb),
			SettingsPage::Nips => return self.nips_ui(ui),
			SettingsPage::Pairing => return self.pairing_settings_ui(ui),
			SettingsPage::Language => return self.language_settings_ui(ui),
			SettingsPage::Slatepack => return self.slatepack_ui(ui, wallet, cb),
			SettingsPage::Privacy => return self.privacy_ui(ui, wallet),
			SettingsPage::Username => return self.username_ui(ui, wallet, cb),
			SettingsPage::AdvancedPrivacy => return self.advanced_privacy_ui(ui, wallet, cb),
			SettingsPage::Advanced => return self.advanced_ui(ui, wallet, cb),
			SettingsPage::Identities => return self.identities_ui(ui, wallet, cb),
			SettingsPage::TrustedSites => return self.trusted_sites_ui(ui, wallet, cb),
			SettingsPage::Main => {}
		}
		// Minimum-confirmations edit modal (GRIM parity), opened from the
		// wallet group below.
		if Modal::opened() == Some(MIN_CONF_MODAL) {
			Modal::ui(ui.ctx(), cb, |ui, modal, cb| {
				self.min_conf_modal_content(ui, wallet, modal, cb);
			});
		}
		ui.add_space(8.0);
		ui.label(
			RichText::new(t!("goblin.settings.title"))
				.font(FontId::new(28.0, fonts::bold()))
				.color(t.text),
		);
		ui.add_space(16.0);

		// Profile card.
		let (handle, npub, connected, bare_name, npub_hex) = wallet
			.nostr_service()
			.map(|s| {
				let identity = s.identity.read();
				let bare = identity
					.nip05
					.clone()
					.map(|n| n.split('@').next().unwrap_or("").to_string());
				let handle = bare
					.clone()
					.map(|n| n.to_string())
					.unwrap_or_else(|| data::short_npub(&hex_of(&identity.npub)));
				(
					handle,
					s.npub(),
					s.is_connected(),
					bare,
					hex_of(&identity.npub),
				)
			})
			.unwrap_or_else(|| {
				(
					t!("goblin.home.anonymous").to_string(),
					String::new(),
					false,
					None,
					String::new(),
				)
			});

		let own_tex = bare_name
			.as_deref()
			.and_then(|_| self.handle_tex(ui.ctx(), wallet, &handle));

		// Set inside the (deeply nested) card closure when the identity-switcher
		// glyph is tapped; applied after the card so the closures don't need a
		// mutable borrow of `self`.
		let mut open_identities = false;
		w::card(ui, |ui| {
			ui.set_min_width(ui.available_width());
			ui.horizontal(|ui| {
				// Custom picture when one is set; otherwise the deterministic
				// pubkey-seeded gradient identicon.
				w::avatar_any(ui, &handle, &npub_hex, 56.0, own_tex.as_ref());
				ui.add_space(14.0);
				ui.vertical(|ui| {
					ui.horizontal(|ui| {
						ui.spacing_mut().item_spacing.x = 5.0;
						ui.label(
							RichText::new(&handle)
								.font(FontId::new(17.0, fonts::bold()))
								.color(t.surface_text),
						);
						// A claimed/verified name gets the little check.
						if bare_name.is_some() {
							ui.label(
								RichText::new(crate::gui::icons::SEAL_CHECK)
									.font(FontId::new(15.0, fonts::regular()))
									.color(t.pos),
							);
						}
					});
					// Transport status in place of the redundant second npub line.
					// Transport-aware: Tor states are relay-gated (a warm tunnel is
					// not enough — a relay must carry our traffic), while a clearnet
					// wallet reads "Connected (direct)" rather than forever
					// "connecting over Tor".
					let transport = transport_status_label(
						wallet
							.nostr_service()
							.map(|s| s.transport_status())
							.unwrap_or(crate::nostr::TransportStatus::ConnectingTor),
					);
					ui.label(
						RichText::new(transport)
							.font(FontId::new(13.0, fonts::regular()))
							.color(t.surface_text_dim),
					);
					// nostr relay status — the slower step (a relay reached over Tor).
					let nostr = if connected {
						t!("goblin.settings.connected_nostr")
					} else {
						t!("goblin.settings.connecting_relays")
					};
					ui.label(
						RichText::new(nostr)
							.font(FontId::new(12.0, fonts::regular()))
							.color(t.surface_text_mute),
					);
					// Keep repainting until a relay is live. Gating on the Tor-only
					// transport_ready would spin forever on a clearnet wallet, so
					// use the transport-neutral relay-connected flag.
					if !connected {
						ui.ctx()
							.request_repaint_after(std::time::Duration::from_millis(600));
					}
				});
				// Trailing (top-right) controls of the identity row: the identity
				// SWITCHER (one wallet, many nostr identities) and, when present,
				// the update-available badge. Right-aligned into the space to the
				// right of the name/avatar; the switcher sits in the far corner.
				ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
					let (rect, resp) = ui.allocate_exact_size(Vec2::splat(36.0), Sense::click());
					ui.painter().circle_filled(rect.center(), 18.0, t.surface2);
					ui.painter().text(
						rect.center(),
						egui::Align2::CENTER_CENTER,
						crate::gui::icons::ARROWS_LEFT_RIGHT,
						FontId::new(17.0, fonts::regular()),
						theme::ink_for(t.surface2),
					);
					if resp
						.on_hover_cursor(egui::CursorIcon::PointingHand)
						.on_hover_text(t!("goblin.identities.switch_hint").to_string())
						.clicked()
					{
						open_identities = true;
					}
					// Update-available badge to the LEFT of the switcher. Shown only
					// when the release check found a newer build; tapping it opens
					// the release download page.
					if let Some(update) = crate::AppConfig::app_update() {
						ui.add_space(6.0);
						let (rect, resp) =
							ui.allocate_exact_size(Vec2::splat(36.0), Sense::click());
						ui.painter().circle_filled(rect.center(), 18.0, t.accent);
						ui.painter().text(
							rect.center(),
							egui::Align2::CENTER_CENTER,
							crate::gui::icons::CLOUD_ARROW_DOWN,
							FontId::new(18.0, fonts::regular()),
							t.accent_ink,
						);
						if resp
							.on_hover_cursor(egui::CursorIcon::PointingHand)
							.on_hover_text(t!("goblin.settings.update_available").to_string())
							.clicked()
						{
							open_url(ui, &update.url);
						}
					}
				});
			});
		});
		if open_identities {
			self.settings_page = SettingsPage::Identities;
			self.identity_switch = IdentitySwitchState::default();
		}

		ui.add_space(16.0);
		// Mark the scroll boundary: rows clipping under the pinned profile
		// card otherwise read as sliced glyphs on an invisible edge.
		let line_y = ui.cursor().min.y;
		ui.painter().hline(
			ui.max_rect().x_range(),
			line_y,
			eframe::epaint::Stroke::new(1.0, t.line),
		);
		ui.add_space(6.0);
		ScrollArea::vertical()
			.id_salt("goblin_settings_scroll")
			.auto_shrink([false; 2])
			.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
			.show(ui, |ui| {
				// Identity: username, picture, keys — first because it is the
				// face of the wallet.
				w::kicker(ui, &t!("goblin.settings.identity"));
				ui.add_space(8.0);
				// Hoisted above the identity card: the Nostr Relays row now lives
				// inside that card (relays are a nostr concern, like the keys), but
				// its open handler runs further down — so the flag is declared here.
				let mut open_relays = false;
				// Username has its own home (claim/release + name authority); the
				// row shows the current name (or "Not set") and opens that page.
				let mut open_username = false;
				// Trusted Sites (the active Authorize Sessions) lives with the
				// nostr rows — it is nostr-identity signing, not a wallet setting
				// — but its open handler runs further down, so the flag is here.
				let mut open_trusted = false;
				w::card(ui, |ui| {
					if !npub.is_empty() {
						let username = wallet
							.nostr_service()
							.and_then(|s| s.identity.read().nip05.clone())
							.map(|n| n.split('@').next().unwrap_or("").to_string());
						let uname_val = username
							.unwrap_or_else(|| t!("goblin.settings.username_none").to_string());
						if settings_row_nav(ui, &t!("goblin.settings.username"), &uname_val) {
							open_username = true;
						}
						if settings_row_btn(ui, &t!("goblin.settings.copy_npub"), COPY) {
							cb.copy_string_to_buffer(npub.clone());
							cb.vibrate_copy();
							self.copy_flash = Some(std::time::Instant::now());
						}
						// The encrypted .backup file now lives on the Advanced page,
						// under ADVANCED NOSTR SETTINGS (single home — no duplicate
						// exposure here).
						// Nostr relays the wallet publishes/reads gift wraps on.
						// Sits with the identity rows because relays are a nostr
						// concern; opens the relay editor (handled below).
						if settings_row_nav(
							ui,
							&t!("goblin.settings.nostr_relays"),
							&relay_summary(wallet),
						) {
							open_relays = true;
						}
						// Trusted Sites: the active Authorize Sessions, with a
						// one-tap end; the row value is the live session count.
						// Nostr-identity signing, so it sits with the keys/relays.
						let session_count = wallet
							.nostr_service()
							.map(|s| s.session_summaries().len())
							.unwrap_or(0);
						if settings_row_nav(
							ui,
							&t!("goblin.settings.trusted_sites"),
							&session_count.to_string(),
						) {
							open_trusted = true;
						}
					}
				});
				if open_username {
					self.claim = Some(ClaimState::default());
					// Seed the free-type authority field with the current server so
					// the Username page opens showing where names resolve today.
					let cur = wallet
						.nostr_service()
						.map(|s| s.config.read().nip05_server())
						.unwrap_or_default();
					self.name_authority = Some(NameAuthorityState {
						input: cur,
						error: None,
					});
					self.settings_page = SettingsPage::Username;
				}
				// Transient confirmation that the copy landed — pairs with the
				// haptic tick so the tap feels acknowledged.
				if let Some(at) = self.copy_flash {
					if at.elapsed().as_secs_f32() < 1.5 {
						ui.add_space(6.0);
						ui.vertical_centered(|ui| {
							ui.label(
								RichText::new(format!(
									"{} {}",
									crate::gui::icons::CHECK,
									t!("goblin.receive.copied")
								))
								.font(FontId::new(13.0, fonts::medium()))
								.color(t.pos),
							);
						});
						ui.ctx()
							.request_repaint_after(std::time::Duration::from_millis(120));
					} else {
						self.copy_flash = None;
					}
				}
				ui.add_space(16.0);
				let mut open_node = false;
				let mut open_slatepack = false;
				settings_group(ui, &t!("goblin.settings.wallet"), |ui| {
					if settings_row_nav(ui, &t!("goblin.settings.node"), &node_summary(wallet)) {
						open_node = true;
					}
					// Minimum confirmations before received funds are spendable
					// (GRIM parity, default 10). Prominent, just below the node
					// row; tapping opens the numeric edit modal. The value feeds
					// the wallet's spendable/send logic via
					// WalletConfig::min_confirmations.
					if settings_row_nav(
						ui,
						&t!("goblin.settings.min_conf"),
						&wallet.get_config().min_confirmations.to_string(),
					) {
						self.min_conf_edit = wallet.get_config().min_confirmations.to_string();
						Modal::new(MIN_CONF_MODAL)
							.position(ModalPosition::CenterTop)
							.title(t!("goblin.settings.min_conf"))
							.show();
					}
					// GRIM's native by-hand slatepack exchange, for when a payment
					// can't go through a username.
					if settings_row_nav(
						ui,
						&t!("goblin.settings.slatepacks"),
						&t!("goblin.settings.slatepacks_value"),
					) {
						open_slatepack = true;
					}
				});
				if open_slatepack {
					self.slatepack = SlatepackManual::default();
					self.settings_page = SettingsPage::Slatepack;
				}
				if open_trusted {
					self.settings_page = SettingsPage::TrustedSites;
				}
				if open_relays {
					// The ACTIVE set (override or per-identity advertised set),
					// so the editor shows what is really in use.
					self.relay_edit = wallet
						.nostr_service()
						.map(|s| s.relays())
						.unwrap_or_default();
					self.relay_input.clear();
					self.settings_page = SettingsPage::Relays;
				}
				if open_node {
					self.node_url_input.clear();
					self.node_secret_input.clear();
					self.settings_page = SettingsPage::Node;
				}

				ui.add_space(16.0);
				let mut open_pairing = false;
				let mut open_privacy = false;
				let mut open_adv_privacy = false;
				settings_group(ui, &t!("goblin.settings.privacy"), |ui| {
					// Value shows the wallet's current Tor state (On/Off) in the
					// same dim font; the row opens the Network-privacy screen where
					// the big switch flips it.
					let tor_on = wallet
						.nostr_service()
						.map(|s| s.tor_routing())
						.unwrap_or(true);
					if settings_row_nav(
						ui,
						&t!("goblin.settings.tor_routing"),
						&if tor_on {
							t!("goblin.settings.tor_on")
						} else {
							t!("goblin.settings.tor_off")
						},
					) {
						open_privacy = true;
					}
					// Tap to cycle the incoming-payment accept policy. Value styled
					// like the sibling rows' values (small/dim), not like an icon.
					if settings_row_cycle(
						ui,
						&t!("goblin.settings.auto_accept"),
						&accept_policy_label(wallet),
					) {
						cycle_accept_policy(wallet);
					}
					// Amount pairing: what the ≈ preview is shown against.
					if settings_row_nav(
						ui,
						&t!("goblin.settings.pairing"),
						crate::AppConfig::pairing().label(),
					) {
						open_pairing = true;
					}
					// Notification hiding (amounts/names/details) and anonymous mode
					// now live together on their own page. Replaces the lone
					// hide-amounts toggle that used to sit here.
					if settings_row_nav(ui, &t!("goblin.settings.advanced_privacy"), "") {
						open_adv_privacy = true;
					}
				});
				if open_pairing {
					self.settings_page = SettingsPage::Pairing;
				}
				if open_privacy {
					self.settings_page = SettingsPage::Privacy;
				}
				if open_adv_privacy {
					self.settings_page = SettingsPage::AdvancedPrivacy;
				}

				ui.add_space(16.0);
				settings_group(ui, &t!("goblin.settings.requests"), |ui| {
					let allow = wallet
						.nostr_service()
						.map(|s| s.config.read().allow_incoming_requests())
						.unwrap_or(true);
					if let Some(v) = settings_row_toggle(
						ui,
						&t!("goblin.settings.incoming_requests"),
						&t!("goblin.settings.incoming_requests_sub"),
						allow,
					) {
						if let Some(s) = wallet.nostr_service() {
							s.config.write().set_allow_incoming_requests(v);
						}
						// Advertise the change so requesters see it before asking.
						wallet.task(crate::wallet::types::WalletTask::NostrRepublishProfile);
					}
				});

				ui.add_space(16.0);
				w::kicker(ui, &t!("goblin.settings.appearance"));
				ui.add_space(8.0);
				let mut open_language = false;
				w::card(ui, |ui| {
					let theme_label = match crate::AppConfig::theme() {
						crate::gui::theme::ThemeKind::Light => t!("goblin.settings.theme_light"),
						crate::gui::theme::ThemeKind::Dark => t!("goblin.settings.theme_dark"),
						crate::gui::theme::ThemeKind::Yellow => t!("goblin.settings.theme_yellow"),
					};
					// Cycle-in-place (not a nav/icon row) so the value ("Dark") is
					// drawn in the same small/dim style as the Language value beside
					// it, instead of the larger icon size settings_row_btn uses.
					if settings_row_cycle(ui, &t!("goblin.settings.theme"), &theme_label) {
						cycle_theme(ui.ctx());
					}
					// Language sits beside theme under Appearance; the value is the
					// active language in its own name (e.g. "Deutsch").
					let current = crate::AppConfig::locale()
						.unwrap_or_else(|| rust_i18n::locale().to_string());
					if settings_row_nav(
						ui,
						&t!("goblin.settings.language"),
						&t!("lang_name", locale = current.as_str()),
					) {
						open_language = true;
					}
				});
				if open_language {
					self.settings_page = SettingsPage::Language;
				}

				ui.add_space(16.0);
				settings_group(ui, &t!("goblin.settings.about"), |ui| {
					if settings_row_nav(
						ui,
						&t!("goblin.settings.goblin"),
						&t!("goblin.settings.build", build => crate::BUILD),
					) {
						open_url(ui, "https://github.com/2ro/goblin/releases");
					}
					settings_row(
						ui,
						&t!("goblin.settings.network"),
						&t!("goblin.settings.network_value"),
					);
				});

				ui.add_space(16.0);
				let mut open_nips = false;
				settings_group(ui, &t!("goblin.settings.third_party"), |ui| {
					if settings_row_nav(ui, &t!("goblin.settings.grim"), crate::VERSION) {
						// Live upstream GRIM (GitHub mirror of code.gri.mw/GUI/grim).
						// Was github.com/ardocrat/grim — a stale personal fork.
						open_url(ui, "https://github.com/GetGrin/grim");
					}
					if settings_row_nav(ui, &t!("goblin.settings.grin_node"), "5.4.0") {
						open_url(ui, "https://github.com/mimblewimble/grin");
					}
					if settings_row_nav(ui, "nostr-sdk", "0.44") {
						open_url(ui, "https://github.com/rust-nostr/nostr");
					}
					if settings_row_nav(ui, "Tor (arti)", "0.43") {
						open_url(ui, "https://gitlab.torproject.org/tpo/core/arti");
					}
					if settings_row_nav(ui, "egui", "0.33") {
						open_url(ui, "https://github.com/emilk/egui");
					}
					if settings_row_nav(ui, "NIPs", "05 · 17 · 44 · 49 · 59 · 98") {
						open_nips = true;
					}
				});
				if open_nips {
					self.settings_page = SettingsPage::Nips;
				}

				// Wallet management lives at the foot of Settings: a neutral
				// switch, the red lock, then the advanced (recovery) tools —
				// each its own outlined action, so the destructive lock reads
				// apart from the rest.
				ui.add_space(24.0);
				let dim = theme::tokens().surface_text_dim;
				if w::outlined_icon_action(
					ui,
					crate::gui::icons::USER_SWITCH,
					&t!("goblin.settings.switch_wallet"),
					dim,
				)
				.clicked()
				{
					self.settings_page = SettingsPage::Main;
					self.switch_requested = true;
				}
				ui.add_space(10.0);
				if w::outlined_icon_action(
					ui,
					crate::gui::icons::LOCK,
					&t!("goblin.settings.lock_wallet"),
					theme::tokens().neg,
				)
				.clicked()
				{
					// Lock — NOT close. The wallet stays open and its nostr relays
					// stay connected (payments keep arriving and queue up), but the
					// whole surface is replaced by the unlock screen and the money
					// seed is sealed until the password is re-entered.
					wallet.lock();
				}
				ui.add_space(10.0);
				if w::outlined_icon_action(
					ui,
					crate::gui::icons::WRENCH,
					&t!("goblin.settings.advanced"),
					dim,
				)
				.clicked()
				{
					self.advanced = AdvancedState::default();
					self.settings_page = SettingsPage::Advanced;
				}
				ui.add_space(20.0);
			});
	}

	/// The money-path unlock screen, shown full-surface whenever the wallet is
	/// locked (`wallet.is_locked()`). It is drawn as an early return from
	/// [`GoblinWalletView::ui`], so it covers every tab, header, overlay and
	/// pending deep link — no money action is reachable behind it. It offers
	/// exactly two ways out: unlock in place (the relays stayed connected, so any
	/// payments that queued while locked drain right after), or fully close the
	/// wallet (the old lock-button behavior: stops the nostr service and seals
	/// the seed to disk).
	pub(super) fn lock_screen_ui(
		&mut self,
		ui: &mut egui::Ui,
		wallet: &Wallet,
		cb: &dyn PlatformCallbacks,
	) {
		let t = theme::tokens();
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
					ScrollArea::vertical()
						.id_salt("goblin_lock_scroll")
						.auto_shrink([false; 2])
						.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
						.show(ui, |ui| {
							ui.add_space(48.0);
							ui.vertical_centered(|ui| {
								ui.label(
									RichText::new(crate::gui::icons::LOCK_KEY)
										.font(FontId::new(56.0, fonts::regular()))
										.color(t.surface_text),
								);
								ui.add_space(16.0);
								ui.label(
									RichText::new(t!("goblin.lock.title"))
										.size(22.0)
										.color(Colors::title(false)),
								);
								ui.add_space(8.0);
								ui.label(
									RichText::new(t!("goblin.lock.subtitle"))
										.size(14.0)
										.color(Colors::gray()),
								);
							});
							ui.add_space(24.0);

							let mut field =
								TextEdit::new(egui::Id::new("goblin_lock_pass")).password();
							field.ui(ui, &mut self.lock_pass, cb);
							// Wrong-password line, cleared the moment the field empties.
							if self.lock_pass.is_empty() {
								self.lock_wrong = false;
							} else if self.lock_wrong {
								ui.add_space(10.0);
								ui.vertical_centered(|ui| {
									ui.label(
										RichText::new(t!("goblin.advanced.wrong_password"))
											.size(15.0)
											.color(Colors::red()),
									);
								});
							}
							ui.add_space(18.0);

							// Enter submits, matching the wallet-open password modal.
							let mut unlock = ui.input(|i| i.key_pressed(egui::Key::Enter))
								&& !self.lock_pass.is_empty();
							ui.vertical_centered_justified(|ui| {
								View::colored_text_button(
									ui,
									t!("goblin.lock.unlock").to_string(),
									t.accent_ink,
									t.accent,
									|| {
										unlock = true;
									},
								);
							});
							ui.add_space(10.0);
							ui.vertical_centered_justified(|ui| {
								View::button(
									ui,
									t!("goblin.lock.close_wallet"),
									Colors::white_or_black(false),
									|| {
										self.lock_pass.clear();
										self.lock_wrong = false;
										wallet.close();
									},
								);
							});
							ui.add_space(24.0);

							if unlock {
								if self.lock_pass.is_empty()
									|| !wallet.verify_nostr_password(&self.lock_pass)
								{
									self.lock_wrong = true;
								} else {
									// Verified WITHOUT re-opening — the wallet is still
									// open, only the money path was sealed. Clearing the
									// flag lets the service loop drain queued payments and
									// the sync loop restart the Foreign API listener.
									wallet.unlock();
									self.lock_pass.clear();
									self.lock_wrong = false;
								}
							}
						});
				});
			});
	}
}
