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

//! The Goblin Cash App-style wallet surface for an open wallet.

pub mod avatars;
pub mod data;
pub mod onboarding;
pub mod send;
pub mod widgets;

use eframe::epaint::{CornerRadius, FontId, Stroke};
use egui::{Align, Color32, Layout, Margin, RichText, ScrollArea, Sense, Vec2};

use crate::gui::icons::{
	ARROW_DOWN, ARROW_LEFT, CHECK, CLOCK, COPY, PROHIBIT, QR_CODE, USER_CIRCLE, WALLET,
};
use crate::gui::platform::PlatformCallbacks;
use crate::gui::theme::{self, fonts};
use crate::gui::views::{Content, TextEdit, View};
use crate::wallet::Wallet;
use crate::wallet::types::WalletData;

use self::data::{ActivityItem, activity_items, recent_peers};
use self::send::SendFlow;
use self::widgets as w;

/// Goblin navigation tabs. The mobile bar shows Home / Pay / Activity;
/// Receive and Me stay reachable (Pay's Request action, header avatar,
/// desktop sidebar).
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tab {
	Home,
	Pay,
	Activity,
	Receive,
	Me,
}

/// Goblin wallet content view.
pub struct GoblinWalletView {
	tab: Tab,
	send: Option<SendFlow>,
	/// Open transaction receipt by tx id (full-surface overlay).
	receipt: Option<u32>,
	/// Open contact profile by npub hex (full-surface overlay).
	profile: Option<String>,
	/// Request ids already approved this session (double-tap guard).
	approving: std::collections::HashSet<String>,
	/// Identifier of the wallet this view is bound to (reset on change).
	wallet_id: Option<String>,
	/// Inline username-claim state for the Me tab.
	claim: Option<ClaimState>,
	/// Inline key-rotation state for the Me tab.
	rotate: Option<RotateState>,
	/// Inline nsec-import state for the Me tab.
	import_nsec: Option<ImportState>,
	/// Amount being entered on the Pay tab.
	pay_amount: String,
	/// Amount being requested, shown on the Receive screen.
	request_amount: Option<String>,
	/// Sub-page open inside the Settings tab.
	settings_page: SettingsPage,
	/// Inputs for adding an external node connection.
	node_url_input: String,
	node_secret_input: String,
	/// Relay list being edited and the add-relay input.
	relay_edit: Vec<String>,
	relay_input: String,
	/// Transient "Copied" feedback on the Receive buttons: which one
	/// (0 = npub, 1 = grin address) and when it was clicked.
	receive_copied: Option<(u8, std::time::Instant)>,
	/// Avatar texture layer (disk cache + background fetches).
	avatars: avatars::AvatarTextures,
	/// Profile-picture upload in flight.
	avatar_busy: bool,
	/// Upload worker result: (server hash, processed png) or error.
	avatar_slot: std::sync::Arc<std::sync::Mutex<Option<Result<(String, Vec<u8>), String>>>>,
	/// Last upload outcome message (cleared on the next attempt).
	avatar_msg: Option<String>,
}

/// Sub-pages of the Settings tab.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SettingsPage {
	Main,
	Node,
	Relays,
	Nips,
	Pairing,
}

impl Default for GoblinWalletView {
	fn default() -> Self {
		Self {
			tab: Tab::Home,
			send: None,
			receipt: None,
			profile: None,
			approving: std::collections::HashSet::new(),
			wallet_id: None,
			claim: None,
			rotate: None,
			import_nsec: None,
			pay_amount: String::new(),
			request_amount: None,
			settings_page: SettingsPage::Main,
			node_url_input: String::new(),
			node_secret_input: String::new(),
			relay_edit: Vec::new(),
			relay_input: String::new(),
			receive_copied: None,
			avatars: avatars::AvatarTextures::default(),
			avatar_busy: false,
			avatar_slot: std::sync::Arc::new(std::sync::Mutex::new(None)),
			avatar_msg: None,
		}
	}
}

/// Inline key-rotation flow state (two warnings + typed confirmation).
struct RotateState {
	/// 1 = warning, 2 = confirm (RESET + password), 3 = working,
	/// 4 = done (new npub), 5 = error (message).
	stage: u8,
	reset_input: String,
	password: String,
	new_npub: String,
	error: String,
	result: std::sync::Arc<std::sync::Mutex<Option<Result<String, String>>>>,
}

impl Default for RotateState {
	fn default() -> Self {
		Self {
			stage: 1,
			reset_input: String::new(),
			password: String::new(),
			new_npub: String::new(),
			error: String::new(),
			result: std::sync::Arc::new(std::sync::Mutex::new(None)),
		}
	}
}

/// Inline nsec-import flow state (restore path for the random-key model).
struct ImportState {
	/// 1 = form, 3 = working, 4 = done, 5 = error.
	stage: u8,
	nsec: String,
	password: String,
	backup_password: String,
	new_npub: String,
	error: String,
	result: std::sync::Arc<std::sync::Mutex<Option<Result<String, String>>>>,
}

impl Default for ImportState {
	fn default() -> Self {
		Self {
			stage: 1,
			nsec: String::new(),
			password: String::new(),
			backup_password: String::new(),
			new_npub: String::new(),
			error: String::new(),
			result: std::sync::Arc::new(std::sync::Mutex::new(None)),
		}
	}
}

/// Inline username-claim widget state.
struct ClaimState {
	input: String,
	checking: bool,
	available: Option<bool>,
	result: std::sync::Arc<std::sync::Mutex<Option<ClaimMsg>>>,
	message: Option<String>,
	/// The are-you-sure gate before releasing a username.
	confirm_release: bool,
}

enum ClaimMsg {
	Availability(crate::nostr::nip05::Availability),
	Registered(String),
	Released,
	Error(String),
}

/// Map an availability probe to user-facing state: `None` availability
/// means the check itself failed — never present that as "Taken".
fn availability_feedback(avail: crate::nostr::nip05::Availability) -> (Option<bool>, &'static str) {
	use crate::nostr::nip05::Availability::*;
	match avail {
		Available => (Some(true), "Available!"),
		Taken => (Some(false), "Taken"),
		Reserved => (Some(false), "Reserved"),
		Invalid => (Some(false), "Names are 3–30 chars: a–z, 0–9, _ or -"),
		Quarantined => (Some(false), "Not available"),
		Unknown => (None, "Couldn't check — connection hiccup. Try again."),
	}
}

impl Default for ClaimState {
	fn default() -> Self {
		Self {
			input: String::new(),
			checking: false,
			available: None,
			result: std::sync::Arc::new(std::sync::Mutex::new(None)),
			message: None,
			confirm_release: false,
		}
	}
}

impl GoblinWalletView {
	/// Whether an overlay flow (send) is active.
	pub fn overlay_active(&self) -> bool {
		self.send.is_some()
	}

	/// Handle a back navigation; returns true if not consumed.
	pub fn on_back(&mut self) -> bool {
		if self.receipt.is_some() {
			self.receipt = None;
			return false;
		}
		if self.profile.is_some() {
			self.profile = None;
			return false;
		}
		if self.send.is_some() {
			self.send = None;
			return false;
		}
		if self.tab == Tab::Me && self.settings_page != SettingsPage::Main {
			self.settings_page = SettingsPage::Main;
			return false;
		}
		if self.tab != Tab::Home {
			self.tab = Tab::Home;
			return false;
		}
		true
	}

	/// Render the full Goblin surface for an open wallet.
	pub fn ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet, cb: &dyn PlatformCallbacks) {
		let t = theme::tokens();

		// Reset transient UI state when the bound wallet changes, so a
		// half-filled send or claim never leaks across a wallet switch.
		let id = wallet.identifier();
		if self.wallet_id.as_deref() != Some(id.as_str()) {
			self.wallet_id = Some(id);
			self.tab = Tab::Home;
			self.send = None;
			self.receipt = None;
			self.profile = None;
			self.claim = None;
			self.rotate = None;
			self.import_nsec = None;
			self.approving.clear();
			self.pay_amount.clear();
			self.request_amount = None;
			self.settings_page = SettingsPage::Main;
		}

		// Send flow takes the full surface when active.
		if let Some(send) = &mut self.send {
			let done = send.ui(ui, wallet, cb, &mut self.avatars);
			if done {
				let receipt_npub = send.receipt_npub.clone();
				self.send = None;
				// "Receipt" on the success screen opens the latest tx with them.
				if let Some(npub) = receipt_npub {
					if let Some(item) = data::history_with(wallet, &npub).into_iter().next() {
						self.receipt = Some(item.tx_id);
					}
				}
			}
			return;
		}
		// Receipt + contact profile are full-surface overlays as well.
		if let Some(tx_id) = self.receipt {
			if self.receipt_ui(ui, wallet, tx_id) {
				self.receipt = None;
			}
			return;
		}
		if let Some(npub) = self.profile.clone() {
			if self.profile_ui(ui, wallet, cb, &npub) {
				self.profile = None;
			}
			return;
		}

		// Desktop (wide) shows a left sidebar (shell B); narrow/mobile shows a
		// bottom tab bar (shell A). Both drive the same Tab state and screens.
		let wide_desktop = View::is_desktop() && ui.available_width() >= 720.0;
		if wide_desktop {
			egui::SidePanel::left("goblin_sidebar")
				.resizable(false)
				.exact_width(244.0)
				.frame(egui::Frame {
					fill: t.bg,
					stroke: Stroke::new(1.0, t.line),
					inner_margin: Margin {
						left: (View::far_left_inset_margin(ui) + 16.0) as i8,
						right: 16,
						top: (View::get_top_inset() + 28.0) as i8,
						bottom: 20,
					},
					..Default::default()
				})
				.show_inside(ui, |ui| {
					self.sidebar_ui(ui, wallet);
				});
		} else {
			let bottom_inset = View::get_bottom_inset();
			egui::TopBottomPanel::bottom("goblin_tabs")
				.frame(egui::Frame {
					fill: t.bg,
					inner_margin: Margin {
						left: 16,
						right: 16,
						top: 10,
						bottom: (12.0 + bottom_inset) as i8,
					},
					..Default::default()
				})
				.show_inside(ui, |ui| {
					self.tab_bar_ui(ui, wallet);
				});
		}

		// Central content.
		egui::CentralPanel::default()
			.frame(egui::Frame {
				fill: t.bg,
				inner_margin: Margin {
					left: (View::far_left_inset_margin(ui) + 20.0) as i8,
					right: (View::get_right_inset() + 20.0) as i8,
					top: (View::get_top_inset() + 8.0) as i8,
					bottom: 0,
				},
				..Default::default()
			})
			.show_inside(ui, |ui| {
				w::centered_column(ui, Content::SIDE_PANEL_WIDTH * 1.2, |ui| match self.tab {
					Tab::Home => self.home_ui(ui, wallet, cb, wide_desktop),
					Tab::Pay => self.pay_ui(ui, wallet, cb),
					Tab::Activity => self.activity_ui(ui, wallet, cb),
					Tab::Receive => self.receive_ui(ui, wallet, cb),
					Tab::Me => self.me_ui(ui, wallet, cb),
				});
			});
	}

	/// Floating 3-item pill bar: Wallet · Pay (center ツ puck) · Activity.
	fn tab_bar_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet) {
		let t = theme::tokens();
		let has_requests = wallet
			.nostr_service()
			.map(|s| !s.store.pending_requests().is_empty())
			.unwrap_or(false);

		let bar_h = 64.0;
		let bar_w = ui.available_width().min(340.0);
		let margin = ((ui.available_width() - bar_w) / 2.0).max(0.0);
		ui.horizontal(|ui| {
			ui.add_space(margin);
			let (bar_rect, _) = ui.allocate_exact_size(Vec2::new(bar_w, bar_h), Sense::hover());
			// Soft shadow + floating pill.
			let shadow = bar_rect.translate(Vec2::new(0.0, 3.0)).expand(2.0);
			ui.painter().rect_filled(
				shadow,
				CornerRadius::same(34),
				Color32::from_black_alpha(70),
			);
			ui.painter().rect(
				bar_rect,
				CornerRadius::same(32),
				t.surface,
				Stroke::new(1.0, t.line),
				egui::StrokeKind::Inside,
			);

			let cell = bar_w / 3.0;
			let tabs = [
				(Tab::Home, Some(WALLET), false),
				(Tab::Pay, None, false),
				(Tab::Activity, Some(CLOCK), has_requests),
			];
			for (i, (tab, icon, badge)) in tabs.into_iter().enumerate() {
				let rect = egui::Rect::from_min_size(
					bar_rect.min + Vec2::new(i as f32 * cell, 0.0),
					Vec2::new(cell, bar_h),
				);
				let resp = ui.interact(rect, ui.id().with(("goblin_tab", i)), Sense::click());
				let active = self.tab == tab;
				match icon {
					Some(icon) => {
						// Icon-only; the active tab gets a circular highlight.
						if active {
							ui.painter().circle_filled(rect.center(), 22.0, t.surface2);
						}
						let color = if active {
							t.surface_text
						} else {
							t.surface_text_mute
						};
						ui.painter().text(
							rect.center(),
							egui::Align2::CENTER_CENTER,
							icon,
							FontId::new(23.0, fonts::regular()),
							color,
						);
					}
					None => {
						// Center Pay action: accent ツ puck.
						let grow = if active || resp.hovered() { 1.0 } else { 0.0 };
						ui.painter().circle_filled(
							rect.center(),
							24.0 + grow,
							if resp.hovered() {
								t.accent_dark
							} else {
								t.accent
							},
						);
						ui.painter().text(
							rect.center(),
							egui::Align2::CENTER_CENTER,
							w::TSU,
							// Gamja Flower's ツ — the cute smiley shape — only here.
							FontId::new(31.0, egui::FontFamily::Name("gamja-tsu".into())),
							t.accent_ink,
						);
					}
				}
				if badge {
					ui.painter()
						.circle_filled(rect.center() + Vec2::new(13.0, -13.0), 4.5, t.neg);
				}
				if resp.clicked() {
					self.tab = tab;
				}
			}
		});
	}

	/// Desktop left sidebar: wordmark, nav items, profile card.
	fn sidebar_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet) {
		let t = theme::tokens();
		// Wordmark.
		ui.horizontal(|ui| {
			widgets_logo(ui);
			ui.add_space(8.0);
			ui.label(
				RichText::new("goblin")
					.font(FontId::new(20.0, fonts::bold()))
					.color(t.text),
			);
		});
		ui.add_space(28.0);

		let has_requests = wallet
			.nostr_service()
			.map(|s| !s.store.pending_requests().is_empty())
			.unwrap_or(false);
		// (tab, icon, label, badge)
		let items = [
			(Tab::Home, WALLET, "Wallet", false),
			(Tab::Pay, crate::gui::icons::ARROW_UP, "Pay", false),
			(Tab::Activity, CLOCK, "Activity", has_requests),
			(Tab::Receive, ARROW_DOWN, "Receive", false),
			(Tab::Me, USER_CIRCLE, "Settings", false),
		];
		for (tab, icon, label, badge) in items {
			let active = tab == self.tab;
			let (rect, resp) =
				ui.allocate_exact_size(Vec2::new(ui.available_width(), 44.0), Sense::click());
			if active || resp.hovered() {
				ui.painter().rect_filled(
					rect,
					eframe::epaint::CornerRadius::same(12),
					if active { t.surface2 } else { t.hover },
				);
			}
			// The active pill is a surface; on-surface ink keeps it readable
			// in the yellow theme (dark pill on bright bg).
			let color = if active { t.surface_text } else { t.text_dim };
			ui.painter().text(
				rect.left_center() + Vec2::new(14.0, 0.0),
				egui::Align2::LEFT_CENTER,
				icon,
				FontId::new(20.0, fonts::regular()),
				color,
			);
			ui.painter().text(
				rect.left_center() + Vec2::new(44.0, 0.0),
				egui::Align2::LEFT_CENTER,
				label,
				FontId::new(
					15.0,
					if active {
						fonts::semibold()
					} else {
						fonts::medium()
					},
				),
				color,
			);
			if badge {
				ui.painter()
					.circle_filled(rect.right_center() - Vec2::new(14.0, 0.0), 4.0, t.neg);
			}
			if resp.clicked() {
				self.tab = tab;
			}
			ui.add_space(4.0);
		}

		// Node status + profile cards pinned to the bottom (node info lives
		// here so the surface needs no separate network column). Each card is
		// its own shortcut: the node card opens the Node menu, the identity
		// chip opens identity settings.
		ui.with_layout(Layout::bottom_up(Align::Min), |ui| {
			let width = ui.available_width();
			ui.allocate_ui_with_layout(
				Vec2::new(width, 196.0),
				Layout::top_down(Align::Min),
				|ui| {
					// Node status card → Settings → Node menu.
					let node = ui
						.scope(|ui| self.node_card_ui(ui, wallet))
						.response
						.interact(Sense::click())
						.on_hover_cursor(egui::CursorIcon::PointingHand);
					if node.clicked() {
						self.tab = Tab::Me;
						self.settings_page = SettingsPage::Node;
					}
					ui.add_space(8.0);
					let (handle, connected, npub_hex) = wallet
						.nostr_service()
						.map(|s| {
							let id = s.identity.read();
							let h = id
								.nip05
								.clone()
								.map(|n| format!("@{}", n.split('@').next().unwrap_or("")))
								.unwrap_or_else(|| data::short_npub(&hex_of(&id.npub)));
							(h, s.is_connected(), hex_of(&id.npub))
						})
						.unwrap_or_else(|| ("Anonymous".to_string(), false, String::new()));
					let hue = data::hue_of(&npub_hex);
					let tex = self.handle_tex(ui.ctx(), wallet, &handle);
					// Identity chip → identity settings.
					let id_resp = ui
						.scope(|ui| {
							w::card(ui, |ui| {
								ui.set_min_width(ui.available_width());
								ui.horizontal(|ui| {
									w::avatar_any(ui, &handle, 36.0, hue, tex.as_ref());
									ui.add_space(10.0);
									ui.vertical(|ui| {
										ui.label(
											RichText::new(&handle)
												.font(FontId::new(14.0, fonts::semibold()))
												.color(t.surface_text),
										);
										ui.label(
											RichText::new(if connected {
												"synced · Nym"
											} else {
												"connecting…"
											})
											.font(FontId::new(12.0, fonts::regular()))
											.color(t.surface_text_mute),
										);
									});
								});
							});
						})
						.response
						.interact(Sense::click())
						.on_hover_cursor(egui::CursorIcon::PointingHand);
					if id_resp.clicked() {
						self.tab = Tab::Me;
						self.settings_page = SettingsPage::Main;
					}
				},
			);
		});
	}

	/// Avatar texture for a display handle ("@name"); None for non-handles
	/// (anonymous identities keep their letter puck).
	fn handle_tex(
		&mut self,
		ctx: &egui::Context,
		wallet: &Wallet,
		handle: &str,
	) -> Option<egui::TextureHandle> {
		if !handle.starts_with('@') {
			return None;
		}
		let server = wallet
			.nostr_service()
			.map(|s| s.config.read().nip05_server())?;
		self.avatars.texture_for(ctx, &server, handle)
	}

	/// Compact node status card: sync state dot, block height, connection.
	fn node_card_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet) {
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
							"Can't reach node"
						} else if synced {
							"Node synced"
						} else {
							"Syncing…"
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
							format!("Block {}", fmt_thousands(height))
						} else {
							"Waiting for chain…".to_string()
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
			});
		});
	}

	fn home_ui(
		&mut self,
		ui: &mut egui::Ui,
		wallet: &Wallet,
		cb: &dyn PlatformCallbacks,
		wide: bool,
	) {
		let data = wallet.get_data();
		ScrollArea::vertical()
			.auto_shrink([false; 2])
			.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
			.show(ui, |ui| {
				// Mobile header: wordmark left, avatar (opens settings) right.
				if !wide {
					ui.add_space(10.0);
					let (header_handle, header_hex) = wallet
						.nostr_service()
						.map(|s| {
							let id = s.identity.read();
							let h = id
								.nip05
								.clone()
								.map(|n| format!("@{}", n.split('@').next().unwrap_or("")))
								.unwrap_or_else(|| "N".to_string());
							(h, hex_of(&id.npub))
						})
						.unwrap_or_else(|| ("N".to_string(), String::new()));
					let header_hue = data::hue_of(&header_hex);
					let header_tex = self.handle_tex(ui.ctx(), wallet, &header_handle);
					ui.horizontal(|ui| {
						widgets_logo(ui);
						ui.add_space(8.0);
						ui.label(
							RichText::new("goblin")
								.font(FontId::new(18.0, fonts::bold()))
								.color(theme::tokens().text),
						);
						ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
							if w::avatar_any(
								ui,
								&header_handle,
								36.0,
								header_hue,
								header_tex.as_ref(),
							)
							.clicked()
							{
								self.tab = Tab::Me;
							}
							// Scan-to-pay, left of the avatar per the refs.
							ui.add_space(10.0);
							let (rect, resp) =
								ui.allocate_exact_size(Vec2::splat(36.0), Sense::click());
							ui.painter().circle_filled(
								rect.center(),
								18.0,
								theme::tokens().surface2,
							);
							ui.painter().text(
								rect.center(),
								egui::Align2::CENTER_CENTER,
								QR_CODE,
								FontId::new(17.0, fonts::regular()),
								theme::tokens().surface_text,
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
				let spendable = data
					.as_ref()
					.map(|d| d.info.amount_currently_spendable)
					.unwrap_or(0);
				w::balance_hero(ui, spendable, fiat_line(&data).as_deref(), 56.0);
				ui.add_space(20.0);
				let (send, receive) = w::send_receive(ui);
				if send {
					self.send = Some(SendFlow::default());
				}
				if receive {
					self.tab = Tab::Receive;
				}
				ui.add_space(24.0);

				// Recent peers strip.
				self.peers_strip_ui(ui, wallet, "goblin_peers_home");

				// Recent activity.
				w::kicker(ui, "Activity");
				ui.add_space(6.0);
				let items = activity_items(wallet);
				if items.is_empty() {
					empty_state(
						ui,
						"No activity yet",
						"Send or receive grin to get started.",
					);
				} else {
					for item in items.iter().take(6) {
						self.activity_item_ui(ui, item, wallet, cb);
					}
				}
				ui.add_space(16.0);
			});
	}

	/// Horizontal recent-contacts strip; tapping one starts a prefilled send.
	fn peers_strip_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet, salt: &str) {
		let peers = recent_peers(wallet, 8);
		if peers.is_empty() {
			return;
		}
		let texs: Vec<Option<egui::TextureHandle>> = peers
			.iter()
			.map(|(name, _, _)| self.handle_tex(ui.ctx(), wallet, name))
			.collect();
		w::kicker(ui, "Recent");
		ui.add_space(12.0);
		ScrollArea::horizontal()
			.id_salt(salt.to_string())
			.auto_shrink([false, true])
			.show(ui, |ui| {
				ui.horizontal(|ui| {
					for ((name, hue, npub), tex) in peers.iter().zip(texs.iter()) {
						ui.vertical(|ui| {
							let resp = w::avatar_any(ui, name, 48.0, *hue, tex.as_ref());
							ui.add_space(6.0);
							let short: String = name.chars().take(6).collect();
							ui.label(RichText::new(short).font(FontId::new(12.0, fonts::medium())));
							if resp.clicked() {
								self.profile = Some(npub.clone());
							}
						});
						ui.add_space(12.0);
					}
				});
			});
		ui.add_space(20.0);
	}

	/// Pay tab: amount-first combined pay/request surface.
	fn pay_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet, cb: &dyn PlatformCallbacks) {
		let t = theme::tokens();
		ui.add_space(8.0);
		ui.horizontal(|ui| {
			ui.label(
				RichText::new("Pay")
					.font(FontId::new(28.0, fonts::bold()))
					.color(t.text),
			);
			// Scan-to-pay QR, top-right (mirrors the Home header scan puck):
			// open the scanner with the typed amount preserved.
			ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
				let (rect, resp) = ui.allocate_exact_size(Vec2::splat(36.0), Sense::click());
				ui.painter().circle_filled(rect.center(), 18.0, t.surface2);
				ui.painter().text(
					rect.center(),
					egui::Align2::CENTER_CENTER,
					QR_CODE,
					FontId::new(17.0, fonts::regular()),
					t.surface_text,
				);
				if resp
					.on_hover_cursor(egui::CursorIcon::PointingHand)
					.on_hover_text("Scan to pay")
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
		// Block paying more than the spendable balance: red amount + a message
		// + an error buzz on tap (Request is unguarded — you can request more
		// than you hold).
		let spendable = wallet
			.get_data()
			.map(|d| d.info.amount_currently_spendable)
			.unwrap_or(0);
		let over = grin_core::core::amount_from_hr_string(&self.pay_amount)
			.map(|a| a > spendable)
			.unwrap_or(false);
		ui.add_space(if tall { 56.0 } else { 24.0 });
		if over {
			w::amount_text_centered_ink(ui, &display, 76.0, t.neg, t.neg);
		} else {
			w::amount_text_centered(ui, &display, 76.0);
		}
		if let Ok(grin) = display.parse::<f64>() {
			if let Some(preview) = pairing_preview(grin) {
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
		if over {
			ui.add_space(6.0);
			ui.vertical_centered(|ui| {
				ui.label(
					RichText::new("You don't have enough grin")
						.font(FontId::new(14.0, fonts::regular()))
						.color(t.neg),
				);
			});
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

		// Numpad at narrow (mobile-shell) widths, typed input on the wide
		// desktop layout — gate by width like the shell itself, or narrow
		// desktop windows get neither input.
		let typed_hint = !narrow && self.pay_amount.is_empty();
		if narrow {
			w::numpad(ui, &mut self.pay_amount);
		} else {
			w::amount_typed_input(ui, &mut self.pay_amount);
			if typed_hint {
				ui.vertical_centered(|ui| {
					ui.label(
						RichText::new("Type an amount")
							.font(FontId::new(13.0, fonts::regular()))
							.color(t.text_mute),
					);
				});
			}
		}
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
					if w::big_action(ui, "Request", true).clicked() && valid {
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
					if w::big_action(ui, "Pay", false).clicked() && valid {
						if over {
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
		// Skip when the "Type an amount" hint is already showing above.
		if !valid && !typed_hint {
			ui.add_space(8.0);
			ui.vertical_centered(|ui| {
				ui.label(
					RichText::new("Enter an amount to pay or request")
						.font(FontId::new(12.0, fonts::regular()))
						.color(t.text_mute),
				);
			});
		}
	}

	/// Round back button + title for full-surface overlays. Returns true on tap.
	fn overlay_back_header(ui: &mut egui::Ui, title: &str) -> bool {
		let t = theme::tokens();
		let mut back = false;
		ui.horizontal(|ui| {
			let (rect, resp) = ui.allocate_exact_size(Vec2::splat(36.0), Sense::click());
			ui.painter().circle_filled(rect.center(), 18.0, t.surface2);
			ui.painter().text(
				rect.center(),
				egui::Align2::CENTER_CENTER,
				ARROW_LEFT,
				FontId::new(16.0, fonts::regular()),
				t.text,
			);
			back = resp
				.on_hover_cursor(egui::CursorIcon::PointingHand)
				.clicked();
			ui.add_space(12.0);
			ui.label(
				RichText::new(title)
					.font(FontId::new(18.0, fonts::bold()))
					.color(t.text),
			);
		});
		ui.add_space(12.0);
		back
	}

	/// Full-surface transaction receipt: GRIM metadata joined with the nostr
	/// counterparty + note. Tapping the counterparty opens their profile.
	fn receipt_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet, tx_id: u32) -> bool {
		let t = theme::tokens();
		let d = data::receipt_detail(wallet, tx_id);
		let tex = d
			.as_ref()
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
					if Self::overlay_back_header(ui, "Receipt") {
						close = true;
					}
					let Some(d) = d else {
						ui.add_space(40.0);
						ui.vertical_centered(|ui| {
							ui.label(
								RichText::new("Transaction not found")
									.font(FontId::new(15.0, fonts::regular()))
									.color(t.text_dim),
							);
						});
						return;
					};
					ScrollArea::vertical()
						.auto_shrink([false; 2])
						.show(ui, |ui| {
							ui.add_space(8.0);
							ui.vertical_centered(|ui| {
								let resp = w::avatar_any(ui, &d.title, 64.0, d.hue, tex.as_ref());
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
										RichText::new(format!("For {}", note))
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
							w::kicker(ui, "Transaction details");
							ui.add_space(10.0);
							w::card(ui, |ui| {
								let (status, sub) = if d.canceled {
									(
										"Canceled",
										if d.incoming {
											"Expired".to_string()
										} else {
											"Funds returned".to_string()
										},
									)
								} else if d.confirmed {
									(
										"Complete",
										if d.incoming {
											"Payment received".to_string()
										} else {
											"Payment sent successfully".to_string()
										},
									)
								} else {
									(
										"Pending",
										match d.confs {
											Some((c, r)) => format!("{}/{} confirmations", c, r),
											None => "Waiting to confirm".to_string(),
										},
									)
								};
								w::info_row(ui, status, &sub);
								if d.has_identity {
									let (to, from) = if d.incoming {
										("You".to_string(), d.title.clone())
									} else {
										(d.title.clone(), "You".to_string())
									};
									w::info_row(ui, "To", &to);
									w::info_row(ui, "From", &from);
								}
								if let Some(npub) = &d.npub {
									w::info_row(ui, "nostr", &data::short_npub(npub));
								}
								let fee = match d.fee {
									Some(0) => "None".to_string(),
									Some(f) => format!("{}{}", w::amount_str(f), w::TSU),
									None => "—".to_string(),
								};
								w::info_row(ui, "Network fee", &fee);
								w::info_row(ui, "Privacy", "Mimblewimble + Nym");
								if let Some(sid) = &d.slate_id {
									let short = if sid.len() > 13 {
										format!("{}…{}", &sid[..8], &sid[sid.len() - 4..])
									} else {
										sid.clone()
									};
									w::info_row(ui, "Transaction", &short);
								}
							});
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

	/// Full-surface contact profile: who they are, history between us, and a
	/// block toggle (a nostr-level mute).
	fn profile_ui(
		&mut self,
		ui: &mut egui::Ui,
		wallet: &Wallet,
		_cb: &dyn PlatformCallbacks,
		npub: &str,
	) -> bool {
		let t = theme::tokens();
		let (name, hue) = wallet
			.nostr_service()
			.map(|s| data::contact_title(&s.store, npub))
			.unwrap_or_else(|| (data::short_npub(npub), 0));
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
					if Self::overlay_back_header(ui, "Profile") {
						close = true;
					}
					ScrollArea::vertical()
						.auto_shrink([false; 2])
						.show(ui, |ui| {
							ui.add_space(8.0);
							ui.vertical_centered(|ui| {
								w::avatar_any(ui, &name, 72.0, hue, tex.as_ref());
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
							if !blocked && w::big_action(ui, "Pay", false).clicked() {
								do_pay = true;
							}
							ui.add_space(18.0);
							w::kicker(ui, "Activity");
							ui.add_space(10.0);
							if history.is_empty() {
								ui.label(
									RichText::new("No activity with them yet.")
										.font(FontId::new(13.0, fonts::regular()))
										.color(t.text_dim),
								);
							} else {
								for (item, htex) in history.iter().zip(htexs.iter()) {
									let sign = if item.incoming { "+ " } else { "− " };
									let amount =
										format!("{}{}{}", sign, w::amount_str(item.amount), w::TSU);
									let status_word =
										if item.canceled { "canceled" } else { "pending" };
									let subtitle = match (&item.note, item.confirmed) {
										(Some(n), true) => {
											format!("{} · {}", n, View::format_time(item.time))
										}
										(Some(n), false) => format!("{} · {}", n, status_word),
										(None, true) => View::format_time(item.time),
										(None, false) => status_word.to_string(),
									};
									if w::activity_row(
										ui,
										&item.title,
										&subtitle,
										item.hue,
										&amount,
										item.incoming,
										item.system,
										htex.as_ref(),
									)
									.clicked()
									{
										open_receipt = Some(item.tx_id);
									}
								}
							}
							ui.add_space(24.0);
							let label = if blocked {
								"Unblock".to_string()
							} else {
								format!("{}  Block", PROHIBIT)
							};
							if w::big_action_on_card_ink(ui, &label, t.neg).clicked() {
								do_block = true;
							}
							ui.add_space(8.0);
							ui.vertical_centered(|ui| {
								ui.label(
									RichText::new(if blocked {
										"Blocked — their payments and requests are dropped."
									} else {
										"Blocking drops their incoming payments and requests."
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
					hue: hue as u8,
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

	/// Friendly day-grouping label for the activity feed.
	fn day_label(ts: i64) -> String {
		use chrono::{TimeZone, Utc};
		let Some(dt) = Utc.timestamp_opt(ts, 0).single() else {
			return "Earlier".to_string();
		};
		let today = Utc::now().date_naive();
		let day = dt.date_naive();
		if day == today {
			"Today".to_string()
		} else if (today - day).num_days() == 1 {
			"Yesterday".to_string()
		} else {
			dt.format("%b %-d, %Y").to_string()
		}
	}

	fn activity_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet, cb: &dyn PlatformCallbacks) {
		ui.add_space(8.0);
		ui.label(
			RichText::new("Activity")
				.font(FontId::new(28.0, fonts::bold()))
				.color(theme::tokens().text),
		);
		ui.add_space(12.0);

		// Recent contacts strip (Cash App-style row above the feed).
		self.peers_strip_ui(ui, wallet, "goblin_peers_activity");

		// Pending payment requests pinned on top.
		if let Some(service) = wallet.nostr_service() {
			let requests = service.store.pending_requests();
			if !requests.is_empty() {
				w::section_header(ui, "Requests");
				for req in requests {
					self.request_row_ui(ui, &req, wallet);
				}
				ui.add_space(8.0);
			}
		}

		ScrollArea::vertical()
			.auto_shrink([false; 2])
			.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
			.show(ui, |ui| {
				let items = activity_items(wallet);
				if items.is_empty() {
					empty_state(ui, "No activity yet", "Your payments will appear here.");
				} else {
					// Unconfirmed (< min confirmations) pinned on top as Pending.
					let pending: Vec<&_> =
						items.iter().filter(|i| !i.confirmed && !i.system).collect();
					if !pending.is_empty() {
						w::section_header(ui, "Pending");
						for item in pending {
							self.activity_item_ui(ui, item, wallet, cb);
						}
						ui.add_space(8.0);
					}
					// Confirmed, grouped by day (newest first).
					let mut last: Option<String> = None;
					for item in items.iter().filter(|i| i.confirmed || i.system) {
						let label = Self::day_label(item.time);
						if last.as_deref() != Some(label.as_str()) {
							w::section_header(ui, &label);
							last = Some(label);
						}
						self.activity_item_ui(ui, item, wallet, cb);
					}
				}
				ui.add_space(16.0);
			});
	}

	fn activity_item_ui(
		&mut self,
		ui: &mut egui::Ui,
		item: &ActivityItem,
		wallet: &Wallet,
		_cb: &dyn PlatformCallbacks,
	) {
		let sign = if item.incoming { "+ " } else { "− " };
		let amount = format!("{}{}{}", sign, w::amount_str(item.amount), w::TSU);
		let status_word = if item.canceled { "canceled" } else { "pending" };
		let subtitle = match (&item.note, item.confirmed) {
			(Some(note), true) => format!("{} · {}", note, View::format_time(item.time)),
			(Some(note), false) => format!("{} · {}", note, status_word),
			(None, true) => View::format_time(item.time),
			(None, false) => status_word.to_string(),
		};
		let tex = self.handle_tex(ui.ctx(), wallet, &item.title);
		if w::activity_row(
			ui,
			&item.title,
			&subtitle,
			item.hue,
			&amount,
			item.incoming,
			item.system,
			tex.as_ref(),
		)
		.clicked()
		{
			self.receipt = Some(item.tx_id);
		}
	}

	fn request_row_ui(
		&mut self,
		ui: &mut egui::Ui,
		req: &crate::nostr::PaymentRequest,
		wallet: &Wallet,
	) {
		let t = theme::tokens();
		let (name, hue) = wallet
			.nostr_service()
			.map(|s| data::contact_title(&s.store, &req.npub))
			.unwrap_or_else(|| (data::short_npub(&req.npub), 0));
		let tex = self.handle_tex(ui.ctx(), wallet, &name);
		w::card(ui, |ui| {
			ui.horizontal(|ui| {
				w::avatar_any(ui, &name, 40.0, hue, tex.as_ref());
				ui.add_space(12.0);
				ui.vertical(|ui| {
					ui.label(
						RichText::new(format!("{} requests", name))
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
							let mut r = req.clone();
							r.status = crate::nostr::RequestStatus::Declined;
							if let Some(s) = wallet.nostr_service() {
								s.store.save_request(&r);
							}
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
						let already = self.approving.contains(&req.rumor_id);
						ui.add_enabled_ui(!already, |ui| {
							if approve_button(ui) {
								// Guard against double-tap: only enqueue the
								// payment once per request id this session.
								self.approving.insert(req.rumor_id.clone());
								wallet.task(crate::wallet::types::WalletTask::NostrPayRequest(
									req.rumor_id.clone(),
								));
							}
						});
					},
				);
			});
		});
		ui.add_space(10.0);
	}

	fn receive_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet, cb: &dyn PlatformCallbacks) {
		let t = theme::tokens();
		ui.add_space(8.0);
		ui.label(
			RichText::new("Receive")
				.font(FontId::new(28.0, fonts::bold()))
				.color(t.text),
		);
		ui.add_space(16.0);

		let handle = wallet
			.nostr_service()
			.map(|s| {
				let identity = s.identity.read();
				identity
					.nip05
					.clone()
					.map(|n| format!("@{}", n.split('@').next().unwrap_or("")))
					.unwrap_or_else(|| data::short_npub(&hex_of(&identity.npub)))
			})
			.unwrap_or_else(|| "—".to_string());
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
							RichText::new(format!(
								"Requesting {}{} — share to get paid",
								amt,
								w::TSU
							))
							.font(FontId::new(13.0, fonts::semibold()))
							.color(t.surface_text),
						);
						ui.add_space(6.0);
						if w::chip(ui, "Clear request", false).clicked() {
							self.request_amount = None;
						}
					}
					None => {
						ui.label(
							RichText::new("Share your handle to get paid")
								.font(FontId::new(13.0, fonts::regular()))
								.color(t.surface_text_dim),
						);
					}
				}
			});
		});

		ui.add_space(12.0);
		// Transient per-button "Copied" feedback; silent copies read as dead
		// buttons.
		let fresh = |at: std::time::Instant| at.elapsed().as_millis() < 1500;
		let copied0 = matches!(self.receive_copied, Some((0, at)) if fresh(at));
		let copied1 = matches!(self.receive_copied, Some((1, at)) if fresh(at));
		if self.receive_copied.is_some() {
			ui.ctx()
				.request_repaint_after(std::time::Duration::from_millis(200));
		}
		ui.horizontal(|ui| {
			let half = (ui.available_width() - 10.0) / 2.0;
			ui.scope_builder(
				egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
					ui.cursor().min,
					Vec2::new(half, 56.0),
				)),
				|ui| {
					let label = if copied0 {
						format!("{} Copied", CHECK)
					} else {
						format!("{} Copy nostr ID", COPY)
					};
					if w::big_action(ui, &label, true).clicked() {
						let copy = if nprofile.is_empty() {
							handle.clone()
						} else {
							nprofile.clone()
						};
						cb.copy_string_to_buffer(copy);
						self.receive_copied = Some((0, std::time::Instant::now()));
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
					// Copy the grin1 slatepack address for manual/Tor exchange.
					let label = if copied1 {
						format!("{} Copied", CHECK)
					} else {
						"Copy address".to_string()
					};
					if w::big_action(ui, &label, false).clicked() {
						if let Some(addr) = wallet.slatepack_address() {
							cb.copy_string_to_buffer(addr);
							self.receive_copied = Some((1, std::time::Instant::now()));
						}
					}
				},
			);
		});

		ui.add_space(16.0);
		ui.label(
			RichText::new(
				"Your username is public. Payment contents stay encrypted over the network.",
			)
			.font(FontId::new(12.0, fonts::regular()))
			.color(t.text_mute),
		);
	}

	fn me_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet, cb: &dyn PlatformCallbacks) {
		let t = theme::tokens();
		match self.settings_page {
			SettingsPage::Node => return self.node_settings_ui(ui, wallet, cb),
			SettingsPage::Relays => return self.relays_ui(ui, wallet, cb),
			SettingsPage::Nips => return self.nips_ui(ui),
			SettingsPage::Pairing => return self.pairing_settings_ui(ui),
			SettingsPage::Main => {}
		}
		ui.add_space(8.0);
		ui.label(
			RichText::new("Settings")
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
					.map(|n| format!("@{n}"))
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
					"Anonymous".to_string(),
					String::new(),
					false,
					None,
					String::new(),
				)
			});

		// Poll a finished avatar upload.
		if let Some(res) = self.avatar_slot.lock().unwrap().take() {
			self.avatar_busy = false;
			match res {
				Ok((hash, png)) => {
					if let Some(b) = bare_name.as_deref() {
						self.avatars.set_own(ui.ctx(), b, &hash, &png);
					}
					self.avatar_msg = Some("Profile picture updated".to_string());
				}
				Err(e) => self.avatar_msg = Some(e),
			}
		}
		let hue = data::hue_of(&npub_hex);
		let own_tex = bare_name
			.as_deref()
			.and_then(|_| self.handle_tex(ui.ctx(), wallet, &handle));
		let mut pick_picture = false;
		let avatar_busy = self.avatar_busy;
		let avatar_msg = self.avatar_msg.clone();

		w::card(ui, |ui| {
			ui.set_min_width(ui.available_width());
			ui.horizontal(|ui| {
				// Avatar is display-only for now: tapping does nothing (no custom
				// picture upload). Letter/identicon pucks only.
				w::avatar_any(ui, &handle, 56.0, hue, own_tex.as_ref());
				let _ = (avatar_busy, &mut pick_picture);
				ui.add_space(14.0);
				ui.vertical(|ui| {
					ui.label(
						RichText::new(&handle)
							.font(FontId::new(17.0, fonts::bold()))
							.color(t.surface_text),
					);
					if !npub.is_empty() {
						// Full npub when it fits on one line, else head…tail.
						let full = ui.painter().layout_no_wrap(
							npub.clone(),
							FontId::new(11.0, fonts::mono()),
							t.surface_text_mute,
						);
						let text = if full.size().x <= ui.available_width() {
							npub.clone()
						} else {
							format!("{}…{}", &npub[..12], &npub[npub.len() - 6..])
						};
						ui.label(
							RichText::new(text)
								.font(FontId::new(11.0, fonts::mono()))
								.color(t.surface_text_mute),
						);
					}
					let status = if connected {
						"Connected over Nym"
					} else {
						"Connecting…"
					};
					ui.label(
						RichText::new(status)
							.font(FontId::new(13.0, fonts::regular()))
							.color(t.surface_text_dim),
					);
				});
			});
			if avatar_busy {
				ui.add_space(6.0);
				ui.horizontal(|ui| {
					View::small_loading_spinner(ui);
					ui.add_space(8.0);
					ui.label(
						RichText::new("Uploading picture…")
							.font(FontId::new(12.5, fonts::regular()))
							.color(t.surface_text_dim),
					);
				});
				ui.ctx().request_repaint();
			} else if let Some(msg) = &avatar_msg {
				ui.add_space(6.0);
				let good = msg.starts_with("Profile picture");
				ui.label(
					RichText::new(msg)
						.font(FontId::new(12.5, fonts::regular()))
						.color(if good { t.pos } else { t.neg }),
				);
			}
		});
		if pick_picture {
			match bare_name.clone() {
				Some(name) => {
					if let Some(path) = cb.pick_image_file() {
						self.avatar_busy = true;
						self.avatar_msg = None;
						start_avatar_upload(self.avatar_slot.clone(), path, name, wallet);
					}
				}
				None => {
					self.avatar_msg =
						Some("Claim a username first — pictures ride on it".to_string());
				}
			}
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
			.auto_shrink([false; 2])
			.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
			.show(ui, |ui| {
				// Identity: username, picture, keys — first because it is the
				// face of the wallet.
				w::kicker(ui, "Identity");
				ui.add_space(8.0);
				if self.claim.is_none() {
					self.claim = Some(ClaimState::default());
				}
				self.claim_ui(ui, wallet, cb);
				ui.add_space(8.0);
				w::card(ui, |ui| {
					if !npub.is_empty() {
						if settings_row_btn(ui, "Copy npub (public)", COPY) {
							cb.copy_string_to_buffer(npub.clone());
						}
						// A real backup is the SECRET key (nsec), not the npub.
						if settings_row_btn(ui, "Back up secret key (nsec)", COPY) {
							if let Some(nsec) = wallet.nostr_service().and_then(|s| s.nsec()) {
								cb.copy_string_to_buffer(nsec);
							}
						}
						// Encrypted backup file: the identity JSON as stored
						// (NIP-49 ncryptsec inside), incl. username + history.
						if settings_row_btn(
							ui,
							"Export identity backup (encrypted)",
							crate::gui::icons::DOWNLOAD_SIMPLE,
						) {
							if let Some(s) = wallet.nostr_service() {
								let json = serde_json::to_string_pretty(&*s.identity.read())
									.unwrap_or_default();
								cb.copy_string_to_buffer(json);
							}
						}
						if settings_row_danger(
							ui,
							"Rotate nostr key",
							crate::gui::icons::ARROWS_CLOCKWISE,
						) && self.rotate.is_none()
						{
							self.rotate = Some(RotateState::default());
						}
						if settings_row_btn(
							ui,
							"Import identity (nsec / backup)",
							crate::gui::icons::KEY,
						) && self.import_nsec.is_none()
						{
							self.import_nsec = Some(ImportState::default());
						}
					}
				});
				ui.add_space(6.0);
				ui.label(
					RichText::new(
						"Moving devices? Back up BOTH: your seed phrase (funds) \
						 and an identity backup (name + key).",
					)
					.font(FontId::new(12.0, fonts::regular()))
					.color(t.text_mute),
				);
				if self.rotate.is_some() {
					ui.add_space(8.0);
					self.rotate_ui(ui, wallet, cb);
				}
				if self.import_nsec.is_some() {
					ui.add_space(8.0);
					self.import_nsec_ui(ui, wallet, cb);
				}

				ui.add_space(16.0);
				let mut open_relays = false;
				let mut open_node = false;
				settings_group(ui, "Wallet", |ui| {
					settings_row(ui, "Display unit", "ツ (grin)");
					if settings_row_nav(ui, "Relays", &relay_summary(wallet)) {
						open_relays = true;
					}
					if settings_row_nav(ui, "Node", &node_summary(wallet)) {
						open_node = true;
					}
					if settings_row_btn(ui, "Lock wallet", crate::gui::icons::LOCK) {
						wallet.close();
					}
				});
				if open_relays {
					self.relay_edit = wallet
						.nostr_service()
						.map(|s| s.config.read().relays())
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
				settings_group(ui, "Privacy", |ui| {
					settings_row(
						ui,
						"Mixnet routing",
						"All traffic routed over the Nym mixnet",
					);
					// Tap to cycle the incoming-payment accept policy.
					if settings_row_btn(ui, "Auto-accept", accept_policy_label(wallet)) {
						cycle_accept_policy(wallet);
					}
					// Amount pairing: what the ≈ preview is shown against.
					if settings_row_nav(ui, "Pairing", crate::AppConfig::pairing().label()) {
						open_pairing = true;
					}
				});
				if open_pairing {
					self.settings_page = SettingsPage::Pairing;
				}

				ui.add_space(16.0);
				settings_group(ui, "Requests", |ui| {
					let allow = wallet
						.nostr_service()
						.map(|s| s.config.read().allow_incoming_requests())
						.unwrap_or(true);
					if let Some(v) = settings_row_toggle(
						ui,
						"Incoming requests",
						"Let others request money from you",
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
				w::kicker(ui, "Appearance");
				ui.add_space(8.0);
				w::card(ui, |ui| {
					let theme_label = match crate::AppConfig::theme() {
						crate::gui::theme::ThemeKind::Light => "Light",
						crate::gui::theme::ThemeKind::Dark => "Dark",
						crate::gui::theme::ThemeKind::Yellow => "Yellow",
					};
					if settings_row_btn(ui, "Theme", theme_label) {
						cycle_theme(ui.ctx());
					}
				});

				ui.add_space(16.0);
				w::kicker(ui, "Archive");
				ui.add_space(8.0);
				w::card(ui, |ui| {
					if settings_row_btn(ui, "Export archive", COPY) {
						if let Some(s) = wallet.nostr_service() {
							let json = s.store.export_json(&s.npub());
							cb.copy_string_to_buffer(json);
						}
					}
					if settings_row_btn(ui, "Wipe payment history", crate::gui::icons::X) {
						if let Some(s) = wallet.nostr_service() {
							s.store.wipe_archive();
						}
					}
				});

				ui.add_space(16.0);
				settings_group(ui, "About", |ui| {
					settings_row(ui, "Goblin", &format!("Build {}", crate::BUILD));
					settings_row(ui, "Network", "Mimblewimble · no address on chain");
				});

				ui.add_space(16.0);
				let mut open_nips = false;
				settings_group(ui, "Third party", |ui| {
					if settings_row_nav(ui, "GRIM (upstream wallet)", crate::VERSION) {
						open_url(ui, "https://github.com/ardocrat/grim");
					}
					if settings_row_nav(ui, "Grin node", "5.4.0") {
						open_url(ui, "https://github.com/mimblewimble/grin");
					}
					if settings_row_nav(ui, "nostr-sdk", "0.44") {
						open_url(ui, "https://github.com/rust-nostr/nostr");
					}
					if settings_row_nav(ui, "Nym mixnet", "socks5") {
						open_url(ui, "https://nym.com");
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
				ui.add_space(16.0);
			});
	}

	/// Back header for Settings sub-pages; returns true when back is tapped.
	fn sub_header(&mut self, ui: &mut egui::Ui, title: &str) -> bool {
		let t = theme::tokens();
		let mut back = false;
		ui.add_space(8.0);
		ui.horizontal(|ui| {
			let (rect, resp) = ui.allocate_exact_size(Vec2::splat(36.0), Sense::click());
			ui.painter().circle_filled(rect.center(), 18.0, t.surface2);
			ui.painter().text(
				rect.center(),
				egui::Align2::CENTER_CENTER,
				crate::gui::icons::ARROW_LEFT,
				FontId::new(16.0, fonts::regular()),
				theme::ink_for(t.surface2),
			);
			back = resp.clicked();
			ui.add_space(12.0);
			ui.label(
				RichText::new(title)
					.font(FontId::new(24.0, fonts::bold()))
					.color(t.text),
			);
		});
		ui.add_space(16.0);
		back
	}

	/// Node connection editor: pick integrated/external, add or remove nodes.
	fn pairing_settings_ui(&mut self, ui: &mut egui::Ui) {
		let t = theme::tokens();
		if self.sub_header(ui, "Pairing") {
			self.settings_page = SettingsPage::Main;
			return;
		}
		ScrollArea::vertical()
			.auto_shrink([false; 2])
			.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
			.show(ui, |ui| {
				ui.label(
					RichText::new("What your balance and amounts are shown against.")
						.font(FontId::new(13.0, fonts::regular()))
						.color(t.text_dim),
				);
				ui.add_space(12.0);
				let current = crate::AppConfig::pairing();
				settings_group(ui, "Pair with", |ui| {
					for p in crate::settings::Pairing::ALL {
						let active = p == current;
						let row = ui.horizontal(|ui| {
							ui.label(
								RichText::new(p.label())
									.font(FontId::new(15.0, fonts::medium()))
									.color(t.surface_text),
							);
							ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
								if active {
									ui.label(
										RichText::new(crate::gui::icons::CHECK)
											.font(FontId::new(16.0, fonts::regular()))
											.color(t.pos),
									);
								}
							});
						});
						ui.add_space(10.0);
						if !active && row.response.interact(Sense::click()).clicked() {
							crate::AppConfig::set_pairing(p);
						}
					}
				});
				ui.add_space(16.0);
			});
	}

	fn node_settings_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet, cb: &dyn PlatformCallbacks) {
		use crate::wallet::types::ConnectionMethod;
		use crate::wallet::{ConnectionsConfig, ExternalConnection};
		let t = theme::tokens();
		if self.sub_header(ui, "Node") {
			self.settings_page = SettingsPage::Main;
			return;
		}
		ScrollArea::vertical()
			.auto_shrink([false; 2])
			.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
			.show(ui, |ui| {
				let live = wallet.get_current_connection();
				let saved = wallet.get_config().connection();
				settings_group(ui, "Connection", |ui| {
					let integrated = matches!(saved, ConnectionMethod::Integrated);
					let row = ui.horizontal(|ui| {
						ui.label(
							RichText::new("Integrated node")
								.font(FontId::new(15.0, fonts::medium()))
								.color(t.surface_text),
						);
						ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
							if integrated {
								ui.label(
									RichText::new(crate::gui::icons::CHECK)
										.font(FontId::new(16.0, fonts::regular()))
										.color(t.pos),
								);
							}
						});
					});
					ui.add_space(10.0);
					if !integrated && row.response.interact(Sense::click()).clicked() {
						wallet.update_connection(&ConnectionMethod::Integrated);
					}
					for conn in ConnectionsConfig::ext_conn_list() {
						let active =
							matches!(&saved, ConnectionMethod::External(id, _) if *id == conn.id);
						let label = conn.url.replace("https://", "").replace("http://", "");
						let mut removed = false;
						let row = ui.horizontal(|ui| {
							ui.label(
								RichText::new(&label)
									.font(FontId::new(15.0, fonts::medium()))
									.color(t.surface_text),
							);
							ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
								if active {
									ui.label(
										RichText::new(crate::gui::icons::CHECK)
											.font(FontId::new(16.0, fonts::regular()))
											.color(t.pos),
									);
								} else {
									let x = ui.label(
										RichText::new(crate::gui::icons::X)
											.font(FontId::new(15.0, fonts::regular()))
											.color(t.surface_text_mute),
									);
									if x.interact(Sense::click()).clicked() {
										ConnectionsConfig::remove_ext_conn(conn.id);
										removed = true;
									}
								}
							});
						});
						ui.add_space(10.0);
						if !removed && !active && row.response.interact(Sense::click()).clicked() {
							wallet.update_connection(&ConnectionMethod::External(
								conn.id,
								conn.url.clone(),
							));
						}
					}
				});
				if saved != live {
					ui.add_space(8.0);
					ui.label(
						RichText::new("Applies after the wallet is locked and unlocked again.")
							.font(FontId::new(13.0, fonts::regular()))
							.color(t.text_dim),
					);
				}

				ui.add_space(16.0);
				settings_group(ui, "Add external node", |ui| {
					TextEdit::new(egui::Id::from("set_node_url"))
						.focus(false)
						.hint_text("https://node.example.com:3413")
						.text_color(t.surface_text)
						.body()
						.ui(ui, &mut self.node_url_input, cb);
					ui.add_space(8.0);
					TextEdit::new(egui::Id::from("set_node_secret"))
						.focus(false)
						.hint_text("API secret (optional)")
						.text_color(t.surface_text)
						.body()
						.ui(ui, &mut self.node_secret_input, cb);
				});
				ui.add_space(10.0);
				let url = self.node_url_input.trim().to_string();
				let valid = url.starts_with("http://") || url.starts_with("https://");
				if w::big_action(ui, "Add node", false).clicked() && valid {
					let secret = {
						let s = self.node_secret_input.trim();
						if s.is_empty() {
							None
						} else {
							Some(s.to_string())
						}
					};
					let conn = ExternalConnection::new(url, None, secret);
					wallet
						.update_connection(&ConnectionMethod::External(conn.id, conn.url.clone()));
					ConnectionsConfig::add_ext_conn(conn);
					self.node_url_input.clear();
					self.node_secret_input.clear();
				}
				ui.add_space(16.0);
			});
	}

	/// Relay list editor; saving restarts the nostr service live.
	fn relays_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet, cb: &dyn PlatformCallbacks) {
		let t = theme::tokens();
		if self.sub_header(ui, "Relays") {
			self.settings_page = SettingsPage::Main;
			return;
		}
		ScrollArea::vertical()
			.auto_shrink([false; 2])
			.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
			.show(ui, |ui| {
				ui.label(
					RichText::new(
						"Payment messages are mirrored to every relay below; \
						 one reachable relay is enough to receive.",
					)
					.font(FontId::new(13.0, fonts::regular()))
					.color(t.text_dim),
				);
				ui.add_space(14.0);
				settings_group(ui, "Your relays", |ui| {
					let mut remove: Option<usize> = None;
					let many = self.relay_edit.len() > 1;
					for (i, relay) in self.relay_edit.iter().enumerate() {
						ui.horizontal(|ui| {
							ui.label(
								RichText::new(relay)
									.font(FontId::new(14.0, fonts::medium()))
									.color(t.surface_text),
							);
							ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
								if many {
									let x = ui.label(
										RichText::new(crate::gui::icons::X)
											.font(FontId::new(15.0, fonts::regular()))
											.color(t.surface_text_mute),
									);
									if x.interact(Sense::click()).clicked() {
										remove = Some(i);
									}
								}
							});
						});
						ui.add_space(10.0);
					}
					if let Some(i) = remove {
						self.relay_edit.remove(i);
					}
				});

				ui.add_space(16.0);
				settings_group(ui, "Add relay", |ui| {
					TextEdit::new(egui::Id::from("set_relay"))
						.focus(false)
						.hint_text("wss://relay.example.com")
						.text_color(t.surface_text)
						.body()
						.ui(ui, &mut self.relay_input, cb);
				});
				ui.add_space(10.0);
				let relay = self.relay_input.trim().to_string();
				let valid = relay.starts_with("wss://") || relay.starts_with("ws://");
				if w::big_action_on_card(ui, "Add relay").clicked()
					&& valid && !self.relay_edit.contains(&relay)
				{
					self.relay_edit.push(relay);
					self.relay_input.clear();
				}
				ui.add_space(10.0);
				if w::big_action(ui, "Save & reconnect", false).clicked() {
					if let Some(s) = wallet.nostr_service() {
						{
							let mut c = s.config.write();
							c.set_relays(self.relay_edit.clone());
							c.save();
						}
						s.restart(wallet.clone());
					}
					self.settings_page = SettingsPage::Main;
				}
				ui.add_space(16.0);
			});
	}

	/// What-is-nostr explainer and tappable NIP reference list.
	fn nips_ui(&mut self, ui: &mut egui::Ui) {
		let t = theme::tokens();
		if self.sub_header(ui, "nostr & NIPs") {
			self.settings_page = SettingsPage::Main;
			return;
		}
		ScrollArea::vertical()
			.auto_shrink([false; 2])
			.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
			.show(ui, |ui| {
				ui.label(
					RichText::new(
						"Goblin speaks nostr — an open protocol of signed messages \
						 passed through simple relay servers. Your wallet carries \
						 its own nostr identity: a standalone random key, kept \
						 deliberately independent of your funds and seed. Every \
						 payment travels as an end-to-end encrypted direct message \
						 between identities, with the slatepack riding inside.",
					)
					.font(FontId::new(14.0, fonts::regular()))
					.color(t.text_dim),
				);
				ui.add_space(10.0);
				ui.label(
					RichText::new(
						"goblin.st is Goblin's name service: claiming a username \
						 publishes a name → key mapping there (NIP-05), so people \
						 can pay @you instead of a long npub. The username is \
						 public; payment contents never are. NIPs are the \
						 protocol's building blocks — tap one to read the spec.",
					)
					.font(FontId::new(14.0, fonts::regular()))
					.color(t.text_dim),
				);
				ui.add_space(16.0);
				let nips = [
					(
						"05",
						"Names",
						"Maps @username@goblin.st to your key, so handles work like addresses.",
					),
					(
						"17",
						"Private messages",
						"The encrypted DM envelope every payment travels in.",
					),
					(
						"44",
						"Encryption",
						"The authenticated cipher used inside those messages.",
					),
					(
						"49",
						"Key encryption",
						"How the secret key is stored at rest, locked by your password.",
					),
					(
						"59",
						"Gift wrap",
						"Wraps messages so relays can't see who is talking to whom.",
					),
					(
						"98",
						"HTTP auth",
						"Signs the username registration request to goblin.st.",
					),
				];
				for (num, title, blurb) in nips {
					let resp = ui.scope(|ui| {
						w::card(ui, |ui| {
							ui.set_min_width(ui.available_width());
							ui.label(
								RichText::new(format!("NIP-{} · {}", num, title))
									.font(FontId::new(14.0, fonts::semibold()))
									.color(t.surface_text),
							);
							ui.add_space(2.0);
							ui.label(
								RichText::new(blurb)
									.font(FontId::new(12.0, fonts::regular()))
									.color(t.surface_text_dim),
							);
						});
					});
					if resp.response.interact(Sense::click()).clicked() {
						open_url(
							ui,
							&format!(
								"https://github.com/nostr-protocol/nips/blob/master/{}.md",
								num
							),
						);
					}
					ui.add_space(8.0);
				}
				ui.add_space(16.0);
			});
	}

	/// Inline key-rotation flow: warning → typed RESET + password → result.
	fn rotate_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet, cb: &dyn PlatformCallbacks) {
		let t = theme::tokens();
		let rotate = self.rotate.as_mut().unwrap();
		// Poll the worker result.
		if rotate.stage == 3 {
			if let Some(res) = rotate.result.lock().unwrap().take() {
				match res {
					Ok(npub) => {
						rotate.new_npub = npub;
						rotate.stage = 4;
					}
					Err(e) => {
						rotate.error = e;
						rotate.stage = 5;
					}
				}
			}
		}
		let mut close = false;
		w::card(ui, |ui| {
			ui.set_min_width(ui.available_width());
			match rotate.stage {
				1 => {
					ui.label(
						RichText::new("Rotate nostr key")
							.font(FontId::new(15.0, fonts::semibold()))
							.color(t.neg),
					);
					ui.add_space(6.0);
					for line in [
						"• You get a brand-new RANDOM key; the old npub stops \
						 receiving. There is no derivation chain between them.",
						"• The new key is NOT recoverable from your seed — back \
						 up the new nsec right after rotating.",
						"• Your @username is RELEASED and your profile picture \
					 deleted — claim the same or a new name right after \
					 (anyone else can grab it too once it's free).",
						"• Payments still in flight to the old key WILL be \
						 disrupted — wait for pending payments to finish first.",
						"• Contacts who saved your npub directly must re-find \
					 you — share your new npub or re-claimed @username.",
					] {
						ui.label(
							RichText::new(line)
								.font(FontId::new(13.0, fonts::regular()))
								.color(t.surface_text_dim),
						);
						ui.add_space(4.0);
					}
					ui.add_space(8.0);
					ui.horizontal(|ui| {
						let half = (ui.available_width() - 10.0) / 2.0;
						ui.scope_builder(
							egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
								ui.cursor().min,
								Vec2::new(half, 44.0),
							)),
							|ui| {
								if w::big_action_on_card(ui, "Cancel").clicked() {
									close = true;
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
								if w::big_action(ui, "Continue", false).clicked() {
									rotate.stage = 2;
								}
							},
						);
					});
				}
				2 => {
					ui.label(
						RichText::new("Final confirmation")
							.font(FontId::new(15.0, fonts::semibold()))
							.color(t.neg),
					);
					ui.add_space(6.0);
					ui.label(
						RichText::new(
							"This cannot be undone from the app. Type RESET and \
							 enter your wallet password to rotate.",
						)
						.font(FontId::new(13.0, fonts::regular()))
						.color(t.surface_text_dim),
					);
					ui.add_space(10.0);
					w::field_well(ui, |ui| {
						TextEdit::new(egui::Id::from("rotate_reset"))
							.focus(false)
							.hint_text("Type RESET")
							.text_color(t.surface_text)
							.body()
							.ui(ui, &mut rotate.reset_input, cb);
					});
					ui.add_space(8.0);
					w::field_well(ui, |ui| {
						TextEdit::new(egui::Id::from("rotate_pass"))
							.focus(false)
							.hint_text("Wallet password")
							.password()
							.text_color(t.surface_text)
							.body()
							.ui(ui, &mut rotate.password, cb);
					});
					ui.add_space(10.0);
					let armed = rotate.reset_input.trim() == "RESET" && !rotate.password.is_empty();
					ui.horizontal(|ui| {
						let half = (ui.available_width() - 10.0) / 2.0;
						ui.scope_builder(
							egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
								ui.cursor().min,
								Vec2::new(half, 44.0),
							)),
							|ui| {
								if w::big_action_on_card(ui, "Cancel").clicked() {
									close = true;
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
								ui.add_enabled_ui(armed, |ui| {
									if w::big_action(ui, "Rotate key", false).clicked() {
										rotate.stage = 3;
										let slot = rotate.result.clone();
										let password = std::mem::take(&mut rotate.password);
										rotate.reset_input.clear();
										let wallet = wallet.clone();
										std::thread::spawn(move || {
											let res = wallet.rotate_nostr_identity(password);
											*slot.lock().unwrap() = Some(res);
										});
									}
								});
							},
						);
					});
				}
				3 => {
					ui.horizontal(|ui| {
						View::small_loading_spinner(ui);
						ui.add_space(8.0);
						ui.label(
							RichText::new("Rotating key…")
								.font(FontId::new(13.0, fonts::regular()))
								.color(t.surface_text_dim),
						);
					});
					ui.ctx().request_repaint();
				}
				4 => {
					ui.label(
						RichText::new("Key rotated")
							.font(FontId::new(15.0, fonts::semibold()))
							.color(t.pos),
					);
					ui.add_space(4.0);
					let npub = &rotate.new_npub;
					let short = if npub.len() > 18 {
						format!("{}…{}", &npub[..12], &npub[npub.len() - 6..])
					} else {
						npub.clone()
					};
					ui.label(
						RichText::new(format!("New npub: {}", short))
							.font(FontId::new(13.0, fonts::mono()))
							.color(t.surface_text_dim),
					);
					ui.add_space(6.0);
					ui.label(
						RichText::new(
							"Back up the NEW secret key now — your seed cannot \
							 recover it.",
						)
						.font(FontId::new(13.0, fonts::semibold()))
						.color(t.neg),
					);
					ui.add_space(10.0);
					if w::big_action_on_card(ui, "Copy new nsec backup").clicked() {
						if let Some(nsec) = wallet.nostr_service().and_then(|s| s.nsec()) {
							cb.copy_string_to_buffer(nsec);
						}
					}
					ui.add_space(8.0);
					if w::big_action(ui, "Done", false).clicked() {
						close = true;
					}
				}
				_ => {
					ui.label(
						RichText::new("Rotation failed")
							.font(FontId::new(15.0, fonts::semibold()))
							.color(t.neg),
					);
					ui.add_space(4.0);
					ui.label(
						RichText::new(&rotate.error)
							.font(FontId::new(13.0, fonts::regular()))
							.color(t.surface_text_dim),
					);
					ui.add_space(10.0);
					if w::big_action_on_card(ui, "Close").clicked() {
						close = true;
					}
				}
			}
		});
		if close {
			self.rotate = None;
		}
	}

	/// Inline nsec-import flow: replaces the identity with an imported key.
	fn import_nsec_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet, cb: &dyn PlatformCallbacks) {
		let t = theme::tokens();
		let import = self.import_nsec.as_mut().unwrap();
		if import.stage == 3 {
			if let Some(res) = import.result.lock().unwrap().take() {
				match res {
					Ok(npub) => {
						import.new_npub = npub;
						import.stage = 4;
					}
					Err(e) => {
						import.error = e;
						import.stage = 5;
					}
				}
			}
		}
		let mut close = false;
		w::card(ui, |ui| {
			ui.set_min_width(ui.available_width());
			match import.stage {
				1 => {
					ui.label(
						RichText::new("Import identity")
							.font(FontId::new(15.0, fonts::semibold()))
							.color(t.surface_text),
					);
					ui.add_space(6.0);
					ui.label(
						RichText::new(
							"Replaces this wallet's nostr identity — paste a \
							 bare nsec or an exported identity backup (the \
							 backup also restores your username and history). \
							 Back up the current key first if you still need it.",
						)
						.font(FontId::new(13.0, fonts::regular()))
						.color(t.surface_text_dim),
					);
					ui.add_space(10.0);
					w::field_well(ui, |ui| {
						TextEdit::new(egui::Id::from("import_nsec"))
							.focus(false)
							.hint_text("nsec1… or identity backup JSON")
							.password()
							.text_color(t.surface_text)
							.body()
							.ui(ui, &mut import.nsec, cb);
					});
					ui.add_space(8.0);
					w::field_well(ui, |ui| {
						TextEdit::new(egui::Id::from("import_pass"))
							.focus(false)
							.hint_text("Wallet password")
							.password()
							.text_color(t.surface_text)
							.body()
							.ui(ui, &mut import.password, cb);
					});
					ui.add_space(8.0);
					w::field_well(ui, |ui| {
						TextEdit::new(egui::Id::from("import_backup_pass"))
							.focus(false)
							.hint_text("Backup password (only if exported elsewhere)")
							.password()
							.text_color(t.surface_text)
							.body()
							.ui(ui, &mut import.backup_password, cb);
					});
					ui.add_space(10.0);
					let pasted = import.nsec.trim();
					let armed = (pasted.starts_with("nsec1") || pasted.starts_with('{'))
						&& !import.password.is_empty();
					ui.horizontal(|ui| {
						let half = (ui.available_width() - 10.0) / 2.0;
						ui.scope_builder(
							egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
								ui.cursor().min,
								Vec2::new(half, 44.0),
							)),
							|ui| {
								if w::big_action_on_card(ui, "Cancel").clicked() {
									close = true;
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
								ui.add_enabled_ui(armed, |ui| {
									if w::big_action(ui, "Import", false).clicked() {
										import.stage = 3;
										let slot = import.result.clone();
										let nsec = std::mem::take(&mut import.nsec);
										let password = std::mem::take(&mut import.password);
										let bpw = std::mem::take(&mut import.backup_password);
										let bpw = if bpw.is_empty() { None } else { Some(bpw) };
										let wallet = wallet.clone();
										std::thread::spawn(move || {
											let res =
												wallet.import_nostr_identity(nsec, password, bpw);
											*slot.lock().unwrap() = Some(res);
										});
									}
								});
							},
						);
					});
				}
				3 => {
					ui.horizontal(|ui| {
						View::small_loading_spinner(ui);
						ui.add_space(8.0);
						ui.label(
							RichText::new("Importing…")
								.font(FontId::new(13.0, fonts::regular()))
								.color(t.surface_text_dim),
						);
					});
					ui.ctx().request_repaint();
				}
				4 => {
					ui.label(
						RichText::new("Identity replaced")
							.font(FontId::new(15.0, fonts::semibold()))
							.color(t.pos),
					);
					ui.add_space(4.0);
					let npub = &import.new_npub;
					let short = if npub.len() > 18 {
						format!("{}…{}", &npub[..12], &npub[npub.len() - 6..])
					} else {
						npub.clone()
					};
					ui.label(
						RichText::new(format!("Now using: {}", short))
							.font(FontId::new(13.0, fonts::mono()))
							.color(t.surface_text_dim),
					);
					ui.add_space(10.0);
					if w::big_action(ui, "Done", false).clicked() {
						close = true;
					}
				}
				_ => {
					ui.label(
						RichText::new("Import failed")
							.font(FontId::new(15.0, fonts::semibold()))
							.color(t.neg),
					);
					ui.add_space(4.0);
					ui.label(
						RichText::new(&import.error)
							.font(FontId::new(13.0, fonts::regular()))
							.color(t.surface_text_dim),
					);
					ui.add_space(10.0);
					if w::big_action_on_card(ui, "Close").clicked() {
						close = true;
					}
				}
			}
		});
		if close {
			self.import_nsec = None;
		}
	}

	/// Inline username-claim widget (availability check + register over Tor).
	fn claim_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet, cb: &dyn PlatformCallbacks) {
		let t = theme::tokens();
		// Poll the worker result; avatar invalidation happens after the
		// claim borrow is released.
		let mut invalidate_avatar: Option<String> = None;
		{
			let claim = self.claim.as_mut().unwrap();
			if let Some(msg) = claim.result.lock().unwrap().take() {
				claim.checking = false;
				match msg {
					ClaimMsg::Availability(avail) => {
						let (available, msg) = availability_feedback(avail);
						claim.available = available;
						claim.message = Some(msg.to_string());
					}
					ClaimMsg::Registered(nip05) => {
						let name = nip05.split('@').next().unwrap_or("").to_string();
						claim.message = Some(format!("Registered {name}"));
						claim.available = Some(true);
						claim.input.clear();
						// Persist nip05 on the identity and republish.
						if let Some(s) = wallet.nostr_service() {
							{
								let mut id = s.identity.write();
								id.nip05 = Some(nip05.clone());
								id.anonymous = false;
							}
							s.save_identity();
						}
					}
					ClaimMsg::Released => {
						claim.message = Some("Released — the name is up for grabs".to_string());
						claim.available = None;
						claim.confirm_release = false;
						if let Some(s) = wallet.nostr_service() {
							let name = {
								let mut id = s.identity.write();
								let n = id.nip05.take();
								id.anonymous = true;
								n
							};
							s.save_identity();
							invalidate_avatar =
								name.map(|n| n.split('@').next().unwrap_or("").to_string());
						}
					}
					ClaimMsg::Error(e) => {
						claim.available = Some(false);
						claim.message = Some(e);
					}
				}
			}
		}
		if let Some(name) = invalidate_avatar {
			self.avatars.invalidate(&name);
		}
		let claim = self.claim.as_mut().unwrap();

		let registered: Option<String> = wallet
			.nostr_service()
			.and_then(|s| s.identity.read().nip05.clone())
			.map(|n| n.split('@').next().unwrap_or("").to_string());

		w::card(ui, |ui| {
			ui.set_min_width(ui.available_width());
			if let Some(name) = registered {
				if claim.confirm_release {
					// The are-you-sure gate.
					ui.label(
						RichText::new(format!("Release @{name}?"))
							.font(FontId::new(15.0, fonts::semibold()))
							.color(t.surface_text),
					);
					ui.add_space(4.0);
					ui.label(
						RichText::new(
							"It's up for grabs the moment it's free — anyone can \
							 claim it, including the next key you rotate to. Your \
							 profile picture is deleted with it.",
						)
						.font(FontId::new(12.5, fonts::regular()))
						.color(t.surface_text_dim),
					);
					ui.add_space(10.0);
					if claim.checking {
						ui.horizontal(|ui| {
							View::small_loading_spinner(ui);
							ui.add_space(8.0);
							ui.label(RichText::new("Releasing…").color(t.surface_text_dim));
						});
						ui.ctx().request_repaint();
					} else {
						ui.horizontal(|ui| {
							let half = (ui.available_width() - 10.0) / 2.0;
							ui.scope_builder(
								egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
									ui.cursor().min,
									Vec2::new(half, 44.0),
								)),
								|ui| {
									if w::big_action_on_card_ink(ui, "Keep it", t.surface_text)
										.clicked()
									{
										claim.confirm_release = false;
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
									if w::big_action_on_card_ink(ui, "Release it", t.neg).clicked()
									{
										start_release(claim, &name, wallet);
									}
								},
							);
						});
					}
				} else {
					ui.label(
						RichText::new("Username")
							.font(FontId::new(15.0, fonts::semibold()))
							.color(t.surface_text),
					);
					ui.add_space(4.0);
					ui.label(
						RichText::new(format!("@{name}"))
							.font(FontId::new(20.0, fonts::bold()))
							.color(t.surface_text),
					);
					ui.add_space(4.0);
					ui.label(
						RichText::new(
							"Shown as @you. Public on goblin.st. Payments stay encrypted.",
						)
						.font(FontId::new(12.0, fonts::regular()))
						.color(t.surface_text_mute),
					);
					if let Some(msg) = &claim.message {
						ui.add_space(6.0);
						ui.label(
							RichText::new(msg)
								.font(FontId::new(13.0, fonts::regular()))
								.color(match claim.available {
									Some(false) => t.neg,
									Some(true) => t.pos,
									None => t.surface_text_dim,
								}),
						);
					}
					ui.add_space(10.0);
					if w::big_action_on_card_ink(ui, "Release username", t.neg).clicked() {
						claim.confirm_release = true;
						claim.message = None;
					}
				}
			} else {
				ui.label(
					RichText::new("Pick a username — optional")
						.font(FontId::new(15.0, fonts::semibold()))
						.color(t.surface_text),
				);
				ui.add_space(8.0);
				ui.horizontal(|ui| {
					ui.label(
						RichText::new("@")
							.font(FontId::new(16.0, fonts::semibold()))
							.color(t.surface_text),
					);
					let before = claim.input.clone();
					TextEdit::new(egui::Id::from("settings_claim"))
						.focus(false)
						.hint_text("yourname")
						.text_color(t.surface_text)
						.body()
						.ui(ui, &mut claim.input, cb);
					if claim.input != before {
						claim.available = None;
						claim.message = None;
					}
				});
				ui.add_space(4.0);
				ui.label(
					RichText::new("Shown as @you. Public on goblin.st. Payments stay encrypted.")
						.font(FontId::new(12.0, fonts::regular()))
						.color(t.surface_text_mute),
				);
				if let Some(msg) = &claim.message {
					ui.add_space(6.0);
					ui.label(
						RichText::new(msg)
							.font(FontId::new(13.0, fonts::regular()))
							.color(match claim.available {
								Some(false) => t.neg,
								Some(true) => t.pos,
								None => t.surface_text_dim,
							}),
					);
				}
				ui.add_space(10.0);
				let name = claim.input.trim().to_lowercase();
				let valid = name.len() >= 3 && name.len() <= 30;
				if claim.checking {
					ui.horizontal(|ui| {
						View::small_loading_spinner(ui);
						ui.add_space(8.0);
						ui.label(RichText::new("Working…").color(t.surface_text_dim));
					});
					ui.ctx().request_repaint();
				} else {
					ui.add_enabled_ui(valid, |ui| {
						if w::big_action(ui, "Claim", false).clicked() {
							start_claim_flow(claim, &name, wallet);
						}
					});
				}
			}
		});
	}
}

/// Spawn the combined claim: availability check first, then registration
/// in the same worker — one button, no separate Check step.
fn start_claim_flow(claim: &mut ClaimState, name: &str, wallet: &Wallet) {
	let Some(service) = wallet.nostr_service() else {
		return;
	};
	let server = service.config.read().nip05_server();
	// Reuse the service's keys directly — never round-trip the secret through a
	// plaintext nsec String to rebuild keys the service already holds.
	let keys = service.keys();
	claim.checking = true;
	claim.message = None;
	claim.available = None;
	let slot = claim.result.clone();
	let name = name.to_string();
	std::thread::spawn(move || {
		let rt = match tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
		{
			Ok(rt) => rt,
			Err(_) => return,
		};
		let msg = rt.block_on(async {
			use crate::nostr::nip05::{Availability, RegisterResult, check_availability, register};
			match check_availability(&server, &name).await {
				Availability::Available => match register(&server, &name, &keys).await {
					RegisterResult::Ok(nip05) => ClaimMsg::Registered(nip05),
					RegisterResult::Conflict(_) => {
						ClaimMsg::Error("That username was just taken".into())
					}
					RegisterResult::Rejected(e) if e == "name_change_cooldown" => ClaimMsg::Error(
						"Easy there — one username change every 10 minutes. \
							 Try again shortly."
							.into(),
					),
					RegisterResult::Rejected(e) => ClaimMsg::Error(e),
					RegisterResult::Network => ClaimMsg::Error(
						"Couldn't reach goblin.st — connection hiccup. Try again.".into(),
					),
				},
				other => ClaimMsg::Availability(other),
			}
		});
		*slot.lock().unwrap() = Some(msg);
	});
}

/// Spawn the username release; the server deletes its avatar with it.
fn start_release(claim: &mut ClaimState, name: &str, wallet: &Wallet) {
	let Some(service) = wallet.nostr_service() else {
		return;
	};
	let server = service.config.read().nip05_server();
	// Reuse the service's keys directly — never round-trip the secret through a
	// plaintext nsec String to rebuild keys the service already holds.
	let keys = service.keys();
	claim.checking = true;
	claim.message = None;
	let slot = claim.result.clone();
	let name = name.to_string();
	std::thread::spawn(move || {
		let rt = match tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
		{
			Ok(rt) => rt,
			Err(_) => return,
		};
		let msg = match rt.block_on(crate::nostr::nip05::unregister(&server, &name, &keys)) {
			Ok(()) => ClaimMsg::Released,
			Err(e) if e.contains("name_change_cooldown") => ClaimMsg::Error(
				"Easy there — one username change every 10 minutes. Try again shortly.".into(),
			),
			Err(e) => ClaimMsg::Error(format!("Couldn't release: {e}")),
		};
		*slot.lock().unwrap() = Some(msg);
	});
}

/// Process a picked picture and upload it as the avatar for an owned name.
fn start_avatar_upload(
	slot: std::sync::Arc<std::sync::Mutex<Option<Result<(String, Vec<u8>), String>>>>,
	path: String,
	name: String,
	wallet: &Wallet,
) {
	let Some(service) = wallet.nostr_service() else {
		return;
	};
	let server = service.config.read().nip05_server();
	// Reuse the service's keys directly — never round-trip the secret through a
	// plaintext nsec String to rebuild keys the service already holds.
	let keys = service.keys();
	std::thread::spawn(move || {
		let res = (|| {
			let png = crate::nostr::avatar::process_avatar_file(&path)?;
			let rt = tokio::runtime::Builder::new_current_thread()
				.enable_all()
				.build()
				.map_err(|e| e.to_string())?;
			let hash = rt.block_on(crate::nostr::nip05::upload_avatar(
				&server,
				&name,
				&keys,
				png.clone(),
			))?;
			Ok((hash, png))
		})();
		*slot.lock().unwrap() = Some(res);
	});
}

/// Draw the small Goblin mascot mark.
pub fn widgets_logo(ui: &mut egui::Ui) {
	widgets_logo_sized(ui, 24.0);
}

/// Tinted goblin mark at a given size.
pub fn widgets_logo_sized(ui: &mut egui::Ui, size: f32) {
	let (rect, _) = ui.allocate_exact_size(Vec2::splat(size), Sense::hover());
	// Chip-sized marks use a pre-rendered 48px raster: cleaner antialiasing
	// at ~24px than runtime svg rasterization, with 2x headroom for hidpi.
	let img = egui::Image::new(if size <= 32.0 {
		egui::include_image!("../../../../img/goblin-logo2-48.png")
	} else {
		egui::include_image!("../../../../img/goblin-logo2.svg")
	})
	.tint(theme::tokens().text)
	.fit_to_exact_size(Vec2::splat(size));
	img.paint_at(ui, rect);
}

fn empty_state(ui: &mut egui::Ui, title: &str, subtitle: &str) {
	let t = theme::tokens();
	ui.add_space(40.0);
	ui.vertical_centered(|ui| {
		ui.label(
			RichText::new(title)
				.font(FontId::new(17.0, fonts::semibold()))
				.color(t.text),
		);
		ui.add_space(4.0);
		ui.label(
			RichText::new(subtitle)
				.font(FontId::new(14.0, fonts::regular()))
				.color(t.text_dim),
		);
	});
}

fn settings_group(ui: &mut egui::Ui, title: &str, add: impl FnOnce(&mut egui::Ui)) {
	w::kicker(ui, title);
	ui.add_space(8.0);
	w::card(ui, |ui| add(ui));
}

/// A settings row: label + subtitle on the left, an on/off switch on the right.
/// Returns `Some(new_value)` on the frame it is toggled.
fn settings_row_toggle(ui: &mut egui::Ui, label: &str, sub: &str, on: bool) -> Option<bool> {
	let t = theme::tokens();
	let mut toggled = None;
	ui.horizontal(|ui| {
		ui.vertical(|ui| {
			ui.label(
				RichText::new(label)
					.font(FontId::new(15.0, fonts::medium()))
					.color(t.surface_text),
			);
			ui.label(
				RichText::new(sub)
					.font(FontId::new(13.0, fonts::regular()))
					.color(t.surface_text_dim),
			);
		});
		ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
			if w::toggle(ui, on).clicked() {
				toggled = Some(!on);
			}
		});
	});
	ui.add_space(10.0);
	toggled
}

fn settings_row(ui: &mut egui::Ui, label: &str, value: &str) {
	let t = theme::tokens();
	ui.horizontal(|ui| {
		ui.label(
			RichText::new(label)
				.font(FontId::new(15.0, fonts::medium()))
				.color(t.surface_text),
		);
		ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
			ui.label(
				RichText::new(value)
					.font(FontId::new(13.0, fonts::regular()))
					.color(t.surface_text_dim),
			);
		});
	});
	ui.add_space(10.0);
}

fn settings_row_btn(ui: &mut egui::Ui, label: &str, icon: &str) -> bool {
	let t = theme::tokens();
	let mut clicked = false;
	let row = ui.horizontal(|ui| {
		ui.label(
			RichText::new(label)
				.font(FontId::new(15.0, fonts::medium()))
				.color(t.surface_text),
		);
		ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
			let resp = ui.label(
				RichText::new(icon)
					.font(FontId::new(18.0, fonts::regular()))
					.color(t.surface_text_dim),
			);
			if resp.interact(Sense::click()).clicked() {
				clicked = true;
			}
		});
	});
	ui.add_space(10.0);
	// The whole row is tappable, not just the trailing value/icon.
	clicked || row.response.interact(Sense::click()).clicked()
}

/// A danger-styled settings row button (whole row taps).
fn settings_row_danger(ui: &mut egui::Ui, label: &str, icon: &str) -> bool {
	let t = theme::tokens();
	let row = ui.horizontal(|ui| {
		ui.label(
			RichText::new(label)
				.font(FontId::new(15.0, fonts::medium()))
				.color(t.neg),
		);
		ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
			ui.label(
				RichText::new(icon)
					.font(FontId::new(18.0, fonts::regular()))
					.color(t.neg),
			);
		});
	});
	ui.add_space(10.0);
	row.response.interact(Sense::click()).clicked()
}

/// A settings row that navigates somewhere: value + chevron, whole row taps.
fn settings_row_nav(ui: &mut egui::Ui, label: &str, value: &str) -> bool {
	let t = theme::tokens();
	let row = ui.horizontal(|ui| {
		ui.label(
			RichText::new(label)
				.font(FontId::new(15.0, fonts::medium()))
				.color(t.surface_text),
		);
		ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
			ui.label(
				RichText::new(crate::gui::icons::CARET_RIGHT)
					.font(FontId::new(13.0, fonts::regular()))
					.color(t.surface_text_mute),
			);
			ui.add_space(4.0);
			ui.label(
				RichText::new(value)
					.font(FontId::new(13.0, fonts::regular()))
					.color(t.surface_text_dim),
			);
		});
	});
	ui.add_space(10.0);
	row.response.interact(Sense::click()).clicked()
}

/// Open a URL in the system browser.
fn open_url(ui: &egui::Ui, url: &str) {
	ui.ctx().open_url(egui::OpenUrl::new_tab(url));
}

fn approve_button(ui: &mut egui::Ui) -> bool {
	w::big_action(ui, "Approve", false).clicked()
}

fn decline_button(ui: &mut egui::Ui) -> bool {
	w::big_action(ui, "Decline", true).clicked()
}

fn accept_policy_label(wallet: &Wallet) -> &'static str {
	use crate::nostr::config::AcceptPolicy;
	wallet
		.nostr_service()
		.map(|s| match s.config.read().accept_from() {
			AcceptPolicy::Everyone => "Anyone",
			AcceptPolicy::Contacts => "Contacts only",
			AcceptPolicy::Ask => "Always ask",
		})
		.unwrap_or("Anyone")
}

/// Cycle the color theme Dark ↔ Light and re-apply visuals. Yellow is kept
/// defined (gui/theme.rs) but out of the picker for now — it's still in beta;
/// `Yellow => Dark` is an escape hatch for anyone whose config already has it.
fn cycle_theme(ctx: &egui::Context) {
	use crate::gui::theme::ThemeKind;
	let next = match crate::AppConfig::theme() {
		ThemeKind::Dark => ThemeKind::Light,
		ThemeKind::Light => ThemeKind::Dark,
		ThemeKind::Yellow => ThemeKind::Dark,
	};
	crate::AppConfig::set_theme(next);
	crate::setup_visuals(ctx);
}

/// Cycle the density Comfy → Regular → Compact → Comfy.
/// Cycle the incoming-payment accept policy Anyone → Contacts → Ask → Anyone.
fn cycle_accept_policy(wallet: &Wallet) {
	use crate::nostr::config::AcceptPolicy;
	if let Some(s) = wallet.nostr_service() {
		let next = match s.config.read().accept_from() {
			AcceptPolicy::Everyone => AcceptPolicy::Contacts,
			AcceptPolicy::Contacts => AcceptPolicy::Ask,
			AcceptPolicy::Ask => AcceptPolicy::Everyone,
		};
		s.config.write().set_accept_from(next);
	}
}

fn relay_summary(wallet: &Wallet) -> String {
	wallet
		.nostr_service()
		.map(|s| {
			let relays = s.relays();
			match relays.len() {
				0 => "none".to_string(),
				1 => relays[0].replace("wss://", ""),
				n => format!("{} relays", n),
			}
		})
		.unwrap_or_else(|| "—".to_string())
}

/// Compute a fiat preview line for the balance, when a rate is available.
/// One-line node summary: "Block 1,847,221 · main.gri.mw".
/// Bare node host (or "integrated node") for the sidebar card's third line.
fn node_host(wallet: &Wallet) -> String {
	match wallet.get_current_connection() {
		crate::wallet::types::ConnectionMethod::Integrated => "integrated node".to_string(),
		crate::wallet::types::ConnectionMethod::External(_, url) => url
			.replace("https://", "")
			.replace("http://", "")
			.trim_end_matches('/')
			.to_string(),
	}
}

fn node_summary(wallet: &Wallet) -> String {
	let height = wallet
		.get_data()
		.map(|d| d.info.last_confirmed_height)
		.unwrap_or(0);
	let conn = match wallet.get_current_connection() {
		crate::wallet::types::ConnectionMethod::Integrated => "integrated node".to_string(),
		crate::wallet::types::ConnectionMethod::External(_, url) => url
			.replace("https://", "")
			.replace("http://", "")
			.trim_end_matches('/')
			.to_string(),
	};
	if height == 0 {
		format!("{} · syncing", conn)
	} else {
		format!("Block {} · {}", fmt_thousands(height), conn)
	}
}

/// Format a number with thousands separators.
fn fmt_thousands(n: u64) -> String {
	let s = n.to_string();
	let mut out = String::with_capacity(s.len() + s.len() / 3);
	for (i, c) in s.chars().enumerate() {
		if i > 0 && (s.len() - i) % 3 == 0 {
			out.push(',');
		}
		out.push(c);
	}
	out
}

fn fiat_line(data: &Option<WalletData>) -> Option<String> {
	let p = crate::AppConfig::pairing();
	let vs = p.vs_currency()?;
	let rate = crate::http::grin_rate(vs)?;
	let spendable = data
		.as_ref()
		.map(|d| d.info.amount_currently_spendable)
		.unwrap_or(0);
	let grin = spendable as f64 / 1_000_000_000.0;
	Some(format!(
		"≈ {}  ·  1ツ = {}",
		fmt_pairing(grin * rate, p),
		fmt_pairing(rate, p)
	))
}

/// Format a value already in the pairing's unit (dollars, BTC, …) with the
/// right symbol/precision. Sats scales the BTC value by 1e8.
fn fmt_pairing(value: f64, p: crate::settings::Pairing) -> String {
	use crate::settings::Pairing;
	match p {
		Pairing::Usd => format!("${:.2}", value),
		Pairing::Eur => format!("€{:.2}", value),
		Pairing::Gbp => format!("£{:.2}", value),
		Pairing::Jpy => format!("¥{:.0}", value),
		Pairing::Cny => format!("CN¥{:.2}", value),
		Pairing::Btc => {
			let s = format!("{:.8}", value);
			let s = s.trim_end_matches('0').trim_end_matches('.');
			format!("₿{}", if s.is_empty() { "0" } else { s })
		}
		Pairing::Sats => format!("{} sats", fmt_thousands((value * 1e8).round() as u64)),
		Pairing::Off => String::new(),
	}
}

/// The "≈ …" amount preview for the current pairing, or `None` when off / no
/// rate yet. Shared by the Pay screen, the send flow, and the balance hero.
fn pairing_preview(grin: f64) -> Option<String> {
	let p = crate::AppConfig::pairing();
	let vs = p.vs_currency()?;
	let rate = crate::http::grin_rate(vs)?;
	Some(format!("≈ {}", fmt_pairing(grin * rate, p)))
}

/// Convert a bech32 npub to hex for short display fallbacks.
fn hex_of(npub: &str) -> String {
	use nostr_sdk::{FromBech32, PublicKey};
	PublicKey::from_bech32(npub)
		.map(|pk| pk.to_hex())
		.unwrap_or_else(|_| npub.to_string())
}
