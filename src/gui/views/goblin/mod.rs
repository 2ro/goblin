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

//! The Goblin payment-app-style wallet surface for an open wallet.

pub mod avatars;
pub mod data;
pub mod identicon;
pub mod onboarding;
pub mod send;
pub mod widgets;

use eframe::epaint::{CornerRadius, FontId, Stroke};
use egui::{Align, Color32, Layout, Margin, RichText, ScrollArea, Sense, Vec2};

use crate::gui::icons::{
	ARROW_DOWN, ARROW_LEFT, CHECK, CLOCK, COPY, PROHIBIT, QR_CODE, SHARE, USER_CIRCLE, WALLET,
};
use crate::gui::platform::PlatformCallbacks;
use crate::gui::theme::{self, fonts};
use crate::gui::views::{Content, TextEdit, View};
use crate::wallet::Wallet;
use crate::wallet::types::WalletData;

use self::data::{ActivityItem, activity_items, news_latest, recent_peers, split_urls};
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
	/// Request being reviewed before payment (full-surface hold-to-accept
	/// overlay); approving a request goes through this, not a one-tap pay.
	approve_review: Option<crate::nostr::PaymentRequest>,
	/// Hold-to-accept gesture state for the request-review screen.
	approve_hold: w::HoldToSend,
	/// Amount the last CalculateFee was requested for on the review screen.
	approve_fee_for: Option<u64>,
	/// Request ids already approved this session (double-tap guard).
	approving: std::collections::HashSet<String>,
	/// Why the last approve failed (e.g. funds confirming), shown above the
	/// request list; cleared when a new approve is attempted.
	request_error: Option<String>,
	/// Identifier of the wallet this view is bound to (reset on change).
	wallet_id: Option<String>,
	/// Inline username-claim state for the Me tab.
	claim: Option<ClaimState>,
	/// Inline key-rotation state for the Me tab.
	rotate: Option<RotateState>,
	/// Inline nsec-import state for the Me tab.
	import_nsec: Option<ImportState>,
	/// Inline "back up identity to a file" flow state.
	backup: Option<BackupState>,
	/// Inline "change name authority" editor state.
	name_authority: Option<NameAuthorityState>,
	/// Amount being entered on the Pay tab.
	pay_amount: String,
	/// When set, the over-balance "no" animation is playing: the start time (egui
	/// input seconds) the user pressed Pay without enough funds. Drives a brief
	/// red flash + horizontal shake of the amount, then clears itself.
	pay_shake: Option<f64>,
	/// Amount being requested, shown on the Receive screen.
	request_amount: Option<String>,
	/// Sub-page open inside the Settings tab.
	settings_page: SettingsPage,
	/// Active GRIM integrated-node tab (Info/Metrics/Mining/Settings), hosted
	/// inside Goblin chrome — GRIM's dual-panel shell is never rendered.
	node_tab: Box<dyn crate::gui::views::network::types::NodeTab>,
	/// Where the integrated-node page returns to (it has two entry points:
	/// the Settings screen and the Node screen).
	node_tab_back: SettingsPage,
	/// Inline state for the Advanced settings page (recovery/repair/delete).
	advanced: AdvancedState,
	/// One-shot signal to the wallet host: deselect this wallet (return to the
	/// chooser) without locking it, so another can be picked. Consumed by
	/// [`WalletContent::take_switch_request`].
	switch_requested: bool,
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
	/// Manual slatepack page state (GRIM-native send/receive fallback).
	slatepack: SlatepackManual,
	/// Receipt "Cancel payment" tap-twice confirm: the tx_id awaiting a second
	/// confirming tap (cleared when another receipt opens or it's fired).
	cancel_confirm: Option<u32>,
	/// Outcome of the last manual cancel, shown transiently on the receipt.
	cancel_msg: Option<(crate::nostr::CancelOutcome, std::time::Instant)>,
	/// Transient "Copied" flash for the settings backup card (npub/keys).
	copy_flash: Option<std::time::Instant>,
	/// "Wipe payment history" tap-twice confirm: armed after the first tap,
	/// wipes on the second (cleared once fired).
	wipe_confirm: bool,
}

/// Sub-pages of the Settings tab.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SettingsPage {
	Main,
	Node,
	/// GRIM's integrated-node tabs, embedded in Goblin chrome.
	IntegratedNode,
	Relays,
	Nips,
	Pairing,
	Slatepack,
	Privacy,
	Advanced,
}

/// Inline state for the Advanced (wallet-recovery) settings page: the
/// recovery-phrase reveal and the two-step confirms for destructive actions.
#[derive(Default)]
struct AdvancedState {
	/// Password typed to reveal the grin recovery phrase.
	reveal_pass: String,
	/// The revealed seed words, held only while shown (cleared on hide/back).
	revealed: Option<String>,
	/// Set when the entered password didn't decrypt the seed.
	wrong_pass: bool,
	/// Password typed to reveal the nostr secret key (nsec).
	nsec_pass: String,
	/// The revealed nsec, held only while shown (cleared on hide/back).
	nsec_revealed: Option<String>,
	/// Set when the entered password didn't unlock the nostr identity.
	nsec_wrong: bool,
	/// Whether the nsec QR is expanded (so it can be scanned to log in
	/// elsewhere, e.g. magick.market's private-key login).
	nsec_qr: bool,
	/// Armed "really restore?" confirm.
	confirm_restore: bool,
	/// Armed "really repair?" confirm (repair takes a few minutes).
	confirm_repair: bool,
	/// Armed "really delete?" confirm.
	confirm_delete: bool,
}

/// Inputs and last result for the manual slatepack page (GRIM's native flow,
/// surfaced as an advanced fallback under Settings → Wallet).
#[derive(Default)]
struct SlatepackManual {
	/// Pasted incoming slatepack to receive/finalize.
	paste: String,
	/// Outgoing amount (human grin) for a manually-created payment.
	amount: String,
	/// Optional recipient slatepack address for the outgoing payment.
	address: String,
	/// Produced slatepack text to copy and hand over (send, or a receive reply).
	result: String,
	/// Transient status line (e.g. "Finalizing…") under the actions.
	status: Option<String>,
	/// Last error to show in the danger color.
	error: Option<String>,
}

impl Default for GoblinWalletView {
	fn default() -> Self {
		Self {
			tab: Tab::Home,
			send: None,
			receipt: None,
			profile: None,
			approve_review: None,
			approve_hold: w::HoldToSend::default(),
			approve_fee_for: None,
			approving: std::collections::HashSet::new(),
			request_error: None,
			wallet_id: None,
			claim: None,
			rotate: None,
			import_nsec: None,
			backup: None,
			name_authority: None,
			pay_amount: String::new(),
			pay_shake: None,
			request_amount: None,
			settings_page: SettingsPage::Main,
			node_tab: Box::new(crate::gui::views::network::NetworkNode),
			node_tab_back: SettingsPage::Main,
			advanced: AdvancedState::default(),
			switch_requested: false,
			node_url_input: String::new(),
			node_secret_input: String::new(),
			relay_edit: Vec::new(),
			relay_input: String::new(),
			receive_copied: None,
			slatepack: SlatepackManual::default(),
			avatars: avatars::AvatarTextures::default(),
			cancel_confirm: None,
			cancel_msg: None,
			copy_flash: None,
			wipe_confirm: false,
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
	/// A native file pick is in flight (Android returns the path asynchronously).
	picking: bool,
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
			picking: false,
			result: std::sync::Arc::new(std::sync::Mutex::new(None)),
		}
	}
}

/// Inline "change name authority" (federation) editor state.
#[derive(Default)]
struct NameAuthorityState {
	/// Server URL being typed (e.g. https://other.example).
	input: String,
	/// Validation error to show.
	error: Option<String>,
}

/// Inline "back up identity to a file" flow state.
#[derive(Default)]
struct BackupState {
	/// Wallet password to unseal the identity for the backup.
	password: String,
	/// Error to show (wrong password / write failed).
	error: Option<String>,
	/// The backup file was created.
	done: bool,
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
fn availability_feedback(avail: crate::nostr::nip05::Availability) -> (Option<bool>, String) {
	use crate::nostr::nip05::Availability::*;
	match avail {
		Available => (
			Some(true),
			t!("goblin.settings.avail_available").to_string(),
		),
		Taken => (Some(false), t!("goblin.settings.avail_taken").to_string()),
		Reserved => (
			Some(false),
			t!("goblin.settings.avail_reserved").to_string(),
		),
		Invalid => (Some(false), t!("goblin.settings.avail_invalid").to_string()),
		Quarantined => (
			Some(false),
			t!("goblin.settings.avail_quarantined").to_string(),
		),
		Unknown => (None, t!("goblin.settings.avail_unknown").to_string()),
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

	/// Take the pending "switch wallet" request (set by the Settings button),
	/// resetting it. The host deselects the wallet when this returns true.
	pub fn take_switch_request(&mut self) -> bool {
		std::mem::take(&mut self.switch_requested)
	}

	/// Whether back navigation has anything left to consume: an overlay, a
	/// settings sub-page, or a non-Home tab (back routes to Home). Mirrors
	/// [`Self::on_back`], so the host never falls back to the wallet chooser.
	pub fn can_back(&self) -> bool {
		self.receipt.is_some()
			|| self.profile.is_some()
			|| self.send.is_some()
			|| (self.tab == Tab::Me && self.settings_page != SettingsPage::Main)
			|| self.tab != Tab::Home
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
			self.approve_review = None;
			self.approve_hold = w::HoldToSend::default();
			self.approve_fee_for = None;
			self.approving.clear();
			self.request_error = None;
			self.pay_amount.clear();
			self.request_amount = None;
			self.settings_page = SettingsPage::Main;
			self.advanced = AdvancedState::default();
		}

		// A pending payment deep link (`goblin:` / `nostr:` pay URI, routed here
		// from an OS launch/open) opens a prefilled send-review flow — the exact
		// destination a scanned checkout QR lands on.
		if let Some(uri) = crate::take_pending_pay_uri() {
			let now = ui.input(|i| i.time);
			self.send = Some(SendFlow::from_deeplink(&uri, wallet, now));
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
		// Approving a request opens a full-surface review with hold-to-accept.
		if self.approve_review.is_some() {
			if self.approve_review_ui(ui, wallet) {
				self.approve_review = None;
				self.approve_fee_for = None;
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
					// Bottom strip goes yellow on the Pay surface, like the body.
					fill: if self.tab == Tab::Pay {
						theme::YELLOW.bg
					} else {
						t.bg
					},
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

		// Central content. The Pay tab is painted in the yellow theme (Cash
		// App-style brand surface) regardless of the user's chosen theme: a
		// scoped override held across the whole panel so its fill AND every
		// widget inside pick up the yellow tokens together.
		let pay = self.tab == Tab::Pay;
		let _pay_theme = pay.then(|| theme::scoped(theme::ThemeKind::Yellow));
		// Bright yellow top → dark status-bar icons (see status_bar_white_icons).
		theme::set_status_surface_yellow(pay);
		let panel_fill = if pay { theme::YELLOW.bg } else { t.bg };
		egui::CentralPanel::default()
			.frame(egui::Frame {
				fill: panel_fill,
				inner_margin: Margin {
					left: (View::far_left_inset_margin(ui) + 20.0) as i8,
					right: (View::get_right_inset() + 20.0) as i8,
					top: (View::get_top_inset() + 8.0) as i8,
					bottom: 0,
				},
				..Default::default()
			})
			.show_inside(ui, |ui| {
				// Desktop Home fills the window (up to a readable max) instead of
				// sitting in the narrow 1.2x column with dead space around it — the news
				// panel and the rest of home then use the available width. Every other
				// tab, and all of mobile, keeps the original narrow column.
				let col_width = if wide_desktop && self.tab == Tab::Home {
					Content::SIDE_PANEL_WIDTH * 2.4
				} else {
					Content::SIDE_PANEL_WIDTH * 1.2
				};
				w::centered_column(ui, col_width, |ui| match self.tab {
					Tab::Home => self.home_ui(ui, wallet, cb, wide_desktop),
					Tab::Pay => self.pay_ui(ui, wallet, cb),
					Tab::Activity => self.activity_ui(ui, wallet, cb),
					Tab::Receive => self.receive_ui(ui, wallet, cb),
					Tab::Me => self.me_ui(ui, wallet, cb),
				});
			});
	}

	/// 3-item bar: Wallet · Pay (center ツ) · Activity. A floating pill on most
	/// surfaces; chromeless (no pill/shadow, dark items on yellow) on the Pay tab.
	fn tab_bar_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet) {
		let t = theme::tokens();
		let pay = self.tab == Tab::Pay;
		let yt = &theme::YELLOW;
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
			// Soft shadow + floating pill — omitted on the Pay surface.
			if !pay {
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
			}

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
						// Icon-only; the active tab gets a circular highlight (only
						// where there's a pill — not on the chromeless Pay surface).
						if active && !pay {
							ui.painter().circle_filled(rect.center(), 22.0, t.surface2);
						}
						let color = if pay {
							if active { yt.text } else { yt.text_dim }
						} else if active {
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
						// Center Pay action: accent ツ puck off the Pay surface; a
						// chromeless dark ツ on it (payment-app style).
						if !pay {
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
						}
						ui.painter().text(
							rect.center(),
							egui::Align2::CENTER_CENTER,
							w::TSU,
							// Noto Sans JP's clean ツ — the Pay puck mark, only here.
							FontId::new(31.0, egui::FontFamily::Name("noto-tsu".into())),
							if pay { yt.text } else { t.accent_ink },
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
			(Tab::Home, WALLET, t!("goblin.home.nav_wallet"), false),
			(
				Tab::Pay,
				crate::gui::icons::ARROW_UP,
				t!("goblin.home.nav_pay"),
				false,
			),
			(
				Tab::Activity,
				CLOCK,
				t!("goblin.home.nav_activity"),
				has_requests,
			),
			(
				Tab::Receive,
				ARROW_DOWN,
				t!("goblin.home.nav_receive"),
				false,
			),
			(Tab::Me, USER_CIRCLE, t!("goblin.home.nav_settings"), false),
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
					let (handle, npub_hex) = wallet
						.nostr_service()
						.map(|s| {
							let id = s.identity.read();
							let h = id
								.nip05
								.clone()
								.map(|n| n.split('@').next().unwrap_or("").to_string())
								.unwrap_or_else(|| data::short_npub(&hex_of(&id.npub)));
							(h, hex_of(&id.npub))
						})
						.unwrap_or_else(|| {
							(t!("goblin.home.anonymous").to_string(), String::new())
						});
					let tex = self.handle_tex(ui.ctx(), wallet, &handle);
					// Identity chip → identity settings.
					let id_resp = ui
						.scope(|ui| {
							w::card(ui, |ui| {
								ui.set_min_width(ui.available_width());
								ui.horizontal(|ui| {
									w::avatar_any(ui, &handle, &npub_hex, 28.0, tex.as_ref());
									ui.add_space(10.0);
									ui.vertical(|ui| {
										// Scale the handle to its length: short @names get a
										// big, legible size; a long npub shrinks to stay on
										// one line.
										let len = handle.chars().count() as f32;
										let handle_font =
											(20.0 - (len - 6.0).max(0.0) * 0.7).clamp(11.0, 16.0);
										ui.label(
											RichText::new(&handle)
												.font(FontId::new(handle_font, fonts::semibold()))
												.color(t.surface_text),
										);
										ui.label(
											// Relay-gated: "Connected over Nym" only once a
											// relay is live on the current tunnel generation.
											RichText::new(if crate::tor::transport_ready() {
												t!("goblin.home.connected_nym")
											} else if crate::tor::is_ready() {
												t!("goblin.home.nym_ready")
											} else {
												t!("goblin.home.connecting_nym")
											})
											.font(FontId::new(11.0, fonts::regular()))
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
		// Avatars live on the nip05 server, keyed by handle. Handles no longer
		// carry an '@'; skip bare-npub and empty display names (no avatar there).
		if handle.is_empty() || handle.starts_with("npub1") {
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
							let hex = hex_of(&id.npub);
							// With a verified handle show "@name"; otherwise fall back to
							// the short npub (avatar_any then draws the deterministic
							// pubkey-seeded gradient).
							let h = id
								.nip05
								.clone()
								.map(|n| n.split('@').next().unwrap_or("").to_string())
								.unwrap_or_else(|| data::short_npub(&hex));
							(h, hex)
						})
						.unwrap_or_else(|| ("N".to_string(), String::new()));
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
								&header_hex,
								36.0,
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
				w::balance_hero(
					ui,
					total,
					spendable,
					updating,
					error,
					wallet.info_sync_progress(),
					fiat_line(&data).as_deref(),
					56.0,
				);
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
				if items.is_empty() {
					empty_state(
						ui,
						&t!("goblin.home.empty_title"),
						&t!("goblin.home.empty_sub"),
					);
				} else {
					for item in items.iter().take(6) {
						self.activity_item_ui(ui, item, wallet, cb);
					}
				}
				ui.add_space(16.0);
			});
	}

	/// Latest news post from the Goblin news key. Title + summary in a card, with
	/// any http(s) URL in the summary rendered as a tappable link. Renders nothing
	/// (early return) when no post has been cached yet — no empty state.
	fn news_panel_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet) {
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
			if !news.title.is_empty() {
				ui.add(
					egui::Label::new(
						RichText::new(&news.title)
							.font(FontId::new(16.0, fonts::semibold()))
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
	fn peers_strip_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet, salt: &str) {
		let peers = recent_peers(wallet, 8);
		if peers.is_empty() {
			return;
		}
		let texs: Vec<Option<egui::TextureHandle>> = peers
			.iter()
			.map(|(name, _)| self.handle_tex(ui.ctx(), wallet, name))
			.collect();
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
								let resp = w::avatar_any(ui, name, npub, 48.0, tex.as_ref());
								ui.add_space(6.0);
								let chars: Vec<char> = name.chars().collect();
								let short: String = if chars.len() > 8 {
									format!("{}…", chars[..8].iter().collect::<String>())
								} else {
									name.to_string()
								};
								ui.label(
									RichText::new(short).font(FontId::new(12.0, fonts::medium())),
								);
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

	/// Pay tab: amount-first combined pay/request surface.
	fn pay_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet, cb: &dyn PlatformCallbacks) {
		let t = theme::tokens();
		ui.add_space(8.0);
		// Header identity for the avatar (→ settings), mirroring the Home header.
		let (header_handle, header_hex) = wallet
			.nostr_service()
			.map(|s| {
				let id = s.identity.read();
				let hex = hex_of(&id.npub);
				let h = id
					.nip05
					.clone()
					.map(|n| n.split('@').next().unwrap_or("").to_string())
					.unwrap_or_else(|| data::short_npub(&hex));
				(h, hex)
			})
			.unwrap_or_else(|| ("N".to_string(), String::new()));
		let header_tex = self.handle_tex(ui.ctx(), wallet, &header_handle);
		ui.horizontal(|ui| {
			// Goblin mark (left), sized to match the right-side controls.
			ui.add(
				egui::Image::new(egui::include_image!("../../../../img/goblin-logo2.svg"))
					.tint(t.text)
					.fit_to_exact_size(Vec2::splat(40.0)),
			);
			// Right cluster: scan QR (black, no background) then the profile
			// picture at the far right; all three controls about the same size.
			ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
				if w::avatar_any(ui, &header_handle, &header_hex, 40.0, header_tex.as_ref())
					.on_hover_cursor(egui::CursorIcon::PointingHand)
					.clicked()
				{
					self.tab = Tab::Me;
				}
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
						.auto_shrink([false; 2])
						.show(ui, |ui| {
							ui.add_space(8.0);
							ui.vertical_centered(|ui| {
								let resp = w::avatar_any(
									ui,
									&d.title,
									d.npub.as_deref().unwrap_or(""),
									64.0,
									tex.as_ref(),
								);
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
							if cancelable_send {
								ui.add_space(16.0);
								let confirming = self.cancel_confirm == Some(d.tx_id);
								let label = if confirming {
									t!("goblin.receipt.cancel_send_confirm")
								} else {
									t!("goblin.receipt.cancel_send")
								};
								if w::big_action(ui, &label, true).clicked() {
									if confirming {
										if let Some(sid) = &d.slate_id {
											wallet.task(
												crate::wallet::types::WalletTask::NostrCancelSend(
													sid.clone(),
												),
											);
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
									let status_word = if item.canceled {
										t!("goblin.activity.canceled").to_string()
									} else {
										t!("goblin.activity.pending").to_string()
									};
									let subtitle = match (&item.note, item.confirmed) {
										(Some(n), true) => {
											format!("{} · {}", n, View::format_time(item.time))
										}
										(Some(n), false) => format!("{} · {}", n, status_word),
										(None, true) => View::format_time(item.time),
										(None, false) => status_word.clone(),
									};
									if w::activity_row(
										ui,
										&item.title,
										&subtitle,
										item.npub.as_deref().unwrap_or(""),
										&amount,
										item.incoming,
										item.canceled,
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

	/// Friendly day-grouping label for the activity feed.
	fn day_label(ts: i64) -> String {
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

	fn activity_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet, cb: &dyn PlatformCallbacks) {
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
			.auto_shrink([false; 2])
			.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
			.show(ui, |ui| {
				let items = activity_items(wallet);
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
							self.activity_item_ui(ui, item, wallet, cb);
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
		// No +/- for canceled: nothing moved.
		let sign = if item.canceled {
			""
		} else if item.incoming {
			"+ "
		} else {
			"− "
		};
		let amount = format!("{}{}{}", sign, w::amount_str(item.amount), w::TSU);
		let status_word = if item.canceled {
			t!("goblin.activity.canceled").to_string()
		} else {
			t!("goblin.activity.pending").to_string()
		};
		let subtitle = match (&item.note, item.confirmed) {
			(Some(note), true) => format!("{} · {}", note, View::format_time(item.time)),
			(Some(note), false) => format!("{} · {}", note, status_word),
			(None, true) => View::format_time(item.time),
			(None, false) => status_word.clone(),
		};
		let tex = self.handle_tex(ui.ctx(), wallet, &item.title);
		if w::activity_row(
			ui,
			&item.title,
			&subtitle,
			item.npub.as_deref().unwrap_or(""),
			&amount,
			item.incoming,
			item.canceled,
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
						let already = self.approving.contains(&req.rumor_id);
						let working = already
							&& wallet
								.nostr_service()
								.map(|s| s.send_phase() == crate::nostr::send_phase::WORKING)
								.unwrap_or(false);
						if already {
							// Paying: show a centered spinner so the tap clearly
							// registered (the card clears itself once it's sent).
							ui.vertical_centered(|ui| {
								ui.add_space(6.0);
								View::small_loading_spinner(ui);
								ui.add_space(2.0);
								ui.label(
									RichText::new(t!("goblin.receipt.paying"))
										.font(FontId::new(12.0, fonts::regular()))
										.color(t.text_dim),
								);
							});
							if working {
								ui.ctx().request_repaint();
							}
						} else if approve_button(ui) {
							// Don't pay on the tap — open the review screen and make
							// the user hold-to-accept there, like a send. The actual
							// NostrPayRequest is dispatched from approve_review_ui.
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
	fn approve_review_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet) -> bool {
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

	fn receive_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet, cb: &dyn PlatformCallbacks) {
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
			// Share a friendly "pay me" message carrying the bare npub — the
			// public key people pay you on. Never the nprofile or a grin address.
			ui.scope_builder(
				egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
					ui.cursor().min,
					Vec2::new(half, 56.0),
				)),
				|ui| {
					let label = t!("goblin.send.share_btn", "icon" => SHARE);
					if w::big_action(ui, &label, true).clicked() && !npub.is_empty() {
						cb.share_text(
							t!("goblin.receive.share_message", "npub" => npub.clone()).to_string(),
						);
					}
				},
			);
			ui.add_space(10.0);
			// Copy the bare npub itself.
			ui.scope_builder(
				egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
					ui.cursor().min,
					Vec2::new(half, 56.0),
				)),
				|ui| {
					let label = if copied {
						format!("{} {}", CHECK, t!("goblin.receive.copied"))
					} else {
						format!("{} {}", COPY, t!("goblin.receive.copy_npub"))
					};
					if w::big_action(ui, &label, false).clicked() && !npub.is_empty() {
						cb.copy_string_to_buffer(npub.clone());
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

	fn me_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet, cb: &dyn PlatformCallbacks) {
		let t = theme::tokens();
		match self.settings_page {
			SettingsPage::Node => return self.node_settings_ui(ui, wallet, cb),
			SettingsPage::IntegratedNode => return self.integrated_node_ui(ui, cb),
			SettingsPage::Relays => return self.relays_ui(ui, wallet, cb),
			SettingsPage::Nips => return self.nips_ui(ui),
			SettingsPage::Pairing => return self.pairing_settings_ui(ui),
			SettingsPage::Slatepack => return self.slatepack_ui(ui, wallet, cb),
			SettingsPage::Privacy => return self.privacy_ui(ui),
			SettingsPage::Advanced => return self.advanced_ui(ui, wallet, cb),
			SettingsPage::Main => {}
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
					// "Connected over Nym" is RELAY-GATED (transport_ready): the
					// tunnel being warm is not enough — a relay must actually carry
					// our traffic on the current exit. Otherwise show the tunnel is
					// up but relays are still connecting/reconnecting.
					let mixnet = if crate::tor::transport_ready() {
						t!("goblin.home.connected_nym")
					} else if crate::tor::is_ready() {
						t!("goblin.home.nym_ready")
					} else {
						t!("goblin.home.connecting_nym")
					};
					ui.label(
						RichText::new(mixnet)
							.font(FontId::new(13.0, fonts::regular()))
							.color(t.surface_text_dim),
					);
					// nostr relay status — the slower step (a relay reached over Nym).
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
					if !crate::tor::transport_ready() || !connected {
						ui.ctx()
							.request_repaint_after(std::time::Duration::from_millis(600));
					}
				});
			});
		});

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
				w::kicker(ui, &t!("goblin.settings.identity"));
				ui.add_space(8.0);
				if self.claim.is_none() {
					self.claim = Some(ClaimState::default());
				}
				self.claim_ui(ui, wallet, cb);
				ui.add_space(8.0);
				// Hoisted above the identity card: the Nostr Relays row now lives
				// inside that card (relays are a nostr concern, like the keys), but
				// its open handler runs further down — so the flag is declared here.
				let mut open_relays = false;
				w::card(ui, |ui| {
					if !npub.is_empty() {
						if settings_row_btn(ui, &t!("goblin.settings.copy_npub"), COPY) {
							cb.copy_string_to_buffer(npub.clone());
							cb.vibrate_copy();
							self.copy_flash = Some(std::time::Instant::now());
						}
						// One encrypted backup FILE (key + username + history sealed
						// together) — replaces the old copy-nsec / copy-JSON split.
						if settings_row_btn(
							ui,
							&t!("goblin.settings.backup_file"),
							crate::gui::icons::DOWNLOAD_SIMPLE,
						) && self.backup.is_none()
						{
							self.backup = Some(BackupState::default());
						}
						if settings_row_danger(
							ui,
							&t!("goblin.settings.rotate_key"),
							crate::gui::icons::ARROWS_CLOCKWISE,
						) && self.rotate.is_none()
						{
							self.rotate = Some(RotateState::default());
						}
						if settings_row_btn(
							ui,
							&t!("goblin.settings.import_identity"),
							crate::gui::icons::KEY,
						) && self.import_nsec.is_none()
						{
							self.import_nsec = Some(ImportState::default());
						}
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
						// Federation: which name authority (server) registers and
						// verifies names. Shows the current host on the right.
						let authority = wallet
							.nostr_service()
							.map(|s| s.config.read().home_domain())
							.unwrap_or_default();
						if settings_row_nav(ui, &t!("goblin.settings.name_authority"), &authority)
							&& self.name_authority.is_none()
						{
							let cur = wallet
								.nostr_service()
								.map(|s| s.config.read().nip05_server())
								.unwrap_or_default();
							self.name_authority = Some(NameAuthorityState {
								input: cur,
								error: None,
							});
						}
					}
				});
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
									t!("goblin.receipt.copied")
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
				ui.add_space(6.0);
				ui.label(
					RichText::new(t!("goblin.settings.backup_note"))
						.font(FontId::new(12.0, fonts::regular()))
						.color(t.text_mute),
				);
				if self.backup.is_some() {
					ui.add_space(8.0);
					self.backup_ui(ui, wallet, cb);
				}
				if self.name_authority.is_some() {
					ui.add_space(8.0);
					self.name_authority_ui(ui, wallet, cb);
				}
				if self.rotate.is_some() {
					ui.add_space(8.0);
					self.rotate_ui(ui, wallet, cb);
				}
				if self.import_nsec.is_some() {
					ui.add_space(8.0);
					self.import_nsec_ui(ui, wallet, cb);
				}

				ui.add_space(16.0);
				let mut open_node = false;
				let mut open_integrated = false;
				let mut open_slatepack = false;
				settings_group(ui, &t!("goblin.settings.wallet"), |ui| {
					if settings_row_nav(ui, &t!("goblin.settings.node"), &node_summary(wallet)) {
						open_node = true;
					}
					// GRIM's integrated-node tabs (info, metrics, mining, node
					// settings), shown in Goblin chrome. Live sync status when
					// the node runs, like the Node row above.
					let node_value = if crate::node::Node::is_running() {
						crate::node::Node::get_sync_status_text()
					} else {
						String::new()
					};
					if settings_row_nav(ui, &t!("goblin.settings.integrated_node"), &node_value) {
						open_integrated = true;
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
				if open_integrated {
					self.node_tab = Box::new(crate::gui::views::network::NetworkNode);
					self.node_tab_back = SettingsPage::Main;
					self.settings_page = SettingsPage::IntegratedNode;
				}

				ui.add_space(16.0);
				let mut open_pairing = false;
				let mut open_privacy = false;
				settings_group(ui, &t!("goblin.settings.privacy"), |ui| {
					// Messages, names, price and avatars ride the mixnet; the grin
					// node connects directly. Normal dim value ink: the salmon
					// privacy color doubled as the destructive-action color on
					// this page, making a plain navigable row read as a warning.
					if settings_row_nav(
						ui,
						&t!("goblin.settings.mixnet_routing"),
						&t!("goblin.settings.messages_lookups"),
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
				});
				if open_pairing {
					self.settings_page = SettingsPage::Pairing;
				}
				if open_privacy {
					self.settings_page = SettingsPage::Privacy;
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
				w::card(ui, |ui| {
					let theme_label = match crate::AppConfig::theme() {
						crate::gui::theme::ThemeKind::Light => t!("goblin.settings.theme_light"),
						crate::gui::theme::ThemeKind::Dark => t!("goblin.settings.theme_dark"),
						crate::gui::theme::ThemeKind::Yellow => t!("goblin.settings.theme_yellow"),
					};
					if settings_row_btn(ui, &t!("goblin.settings.theme"), &theme_label) {
						cycle_theme(ui.ctx());
					}
				});

				ui.add_space(16.0);
				w::kicker(ui, &t!("goblin.settings.archive"));
				ui.add_space(8.0);
				w::card(ui, |ui| {
					if settings_row_btn(ui, &t!("goblin.settings.export_archive"), COPY) {
						if let Some(s) = wallet.nostr_service() {
							let json = s.store.export_json(&s.npub());
							cb.copy_string_to_buffer(json);
							cb.vibrate_copy();
						}
					}
					// Destructive: danger styling + tap-twice confirm (like the
					// receipt's "Cancel payment") before the archive is wiped.
					let wipe_label = if self.wipe_confirm {
						t!("goblin.settings.wipe_history_confirm")
					} else {
						t!("goblin.settings.wipe_history")
					};
					if settings_row_danger(ui, &wipe_label, crate::gui::icons::X) {
						if self.wipe_confirm {
							if let Some(s) = wallet.nostr_service() {
								s.store.wipe_archive();
							}
							self.wipe_confirm = false;
						} else {
							self.wipe_confirm = true;
						}
					}
				});

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
					wallet.close();
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
		if self.sub_header(ui, &t!("goblin.pairing.title")) {
			self.settings_page = SettingsPage::Main;
			return;
		}
		ScrollArea::vertical()
			.auto_shrink([false; 2])
			.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
			.show(ui, |ui| {
				ui.label(
					RichText::new(t!("goblin.pairing.intro"))
						.font(FontId::new(13.0, fonts::regular()))
						.color(t.text_dim),
				);
				ui.add_space(12.0);
				let current = crate::AppConfig::pairing();
				settings_group(ui, &t!("goblin.pairing.pair_with"), |ui| {
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
				ui.add_space(10.0);
				ui.label(
					RichText::new(t!("goblin.pairing.rates_note"))
						.font(FontId::new(12.0, fonts::regular()))
						.color(t.text_dim),
				);
				ui.add_space(16.0);
			});
	}

	/// Network-privacy breakdown: what rides the Nym mixnet versus what connects
	/// directly. Honest by design — no claim that node traffic is mixed, and no
	/// toggle to route it (chain sync is heavy and not tied to your identity).
	fn privacy_ui(&mut self, ui: &mut egui::Ui) {
		let t = theme::tokens();
		if self.sub_header(ui, &t!("goblin.privacy.title")) {
			self.settings_page = SettingsPage::Main;
			return;
		}
		ScrollArea::vertical()
			.auto_shrink([false; 2])
			.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
			.show(ui, |ui| {
				ui.label(
					RichText::new(t!("goblin.privacy.intro"))
						.font(FontId::new(14.0, fonts::regular()))
						.color(t.text_dim),
				);
				ui.add_space(16.0);
				let mixnet = [
					(
						t!("goblin.privacy.payments"),
						t!("goblin.privacy.payments_blurb"),
					),
					(
						t!("goblin.privacy.usernames"),
						t!("goblin.privacy.usernames_blurb"),
					),
					(
						t!("goblin.privacy.price_avatars"),
						t!("goblin.privacy.price_avatars_blurb"),
					),
				];
				settings_group(ui, &t!("goblin.privacy.over_mixnet"), |ui| {
					for (title, blurb) in &mixnet {
						privacy_line(ui, t.neg, title, blurb);
					}
				});
				ui.add_space(16.0);
				settings_group(ui, &t!("goblin.privacy.direct_connection"), |ui| {
					privacy_line(
						ui,
						t.surface_text_mute,
						&t!("goblin.privacy.grin_node"),
						&t!("goblin.privacy.grin_node_blurb"),
					);
				});
				ui.add_space(16.0);
			});
	}

	/// Advanced (wallet-recovery) page — GRIM's low-level tools surfaced in the
	/// goblin style: repair, restore-from-seed, reveal the recovery phrase, and
	/// delete. The two destructive actions arm a tap-twice confirm.
	fn advanced_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet, cb: &dyn PlatformCallbacks) {
		use crate::wallet::types::ConnectionMethod;
		let t = theme::tokens();
		if self.sub_header(ui, &t!("goblin.advanced.title")) {
			self.advanced = AdvancedState::default();
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
		{
			let adv = &mut self.advanced;
			ScrollArea::vertical()
				.auto_shrink([false; 2])
				.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
				.show(ui, |ui| {
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
								cb.copy_string_to_buffer(nsec.clone());
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

					// Delete.
					w::card(ui, |ui| {
						ui.set_min_width(ui.available_width());
						advanced_head(ui, &t!("goblin.advanced.delete"), t.neg);
						advanced_desc(ui, &t!("goblin.advanced.delete_desc"));
						ui.add_space(10.0);
						if adv.confirm_delete {
							if w::big_action_on_card_ink(
								ui,
								&t!("goblin.advanced.delete_confirm"),
								t.neg,
							)
							.clicked()
							{
								wallet.delete_wallet();
								leave = true;
							}
						} else if w::big_action_on_card_ink(
							ui,
							&t!("goblin.advanced.delete"),
							t.neg,
						)
						.clicked()
						{
							adv.confirm_delete = true;
						}
					});
					ui.add_space(20.0);
				});
		}
		if leave {
			self.advanced = AdvancedState::default();
			self.settings_page = SettingsPage::Main;
		}
		if open_node {
			// Advanced → "Manage node connection" opens Goblin's own Node screen
			// (its Advanced button reaches the integrated-node tabs from there).
			self.node_url_input.clear();
			self.node_secret_input.clear();
			self.settings_page = SettingsPage::Node;
		}
	}

	/// GRIM's four integrated-node tabs (Info / Metrics / Mining / Settings)
	/// hosted under a Goblin back header and segmented control — GRIM's
	/// dual-panel and floating-navbar chrome are never rendered. The header
	/// title follows the active tab, like GRIM's own title panel.
	fn integrated_node_ui(&mut self, ui: &mut egui::Ui, cb: &dyn PlatformCallbacks) {
		use crate::gui::icons::{DATABASE, FACTORY, FADERS, GAUGE};
		use crate::gui::views::network::types::NodeTabType;
		use crate::gui::views::network::{
			NetworkContent, NetworkMetrics, NetworkMining, NetworkNode, NetworkSettings,
			disabled_node_ui, node_error_ui,
		};
		use crate::node::Node;
		let title = self.node_tab.get_type().title();
		if self.sub_header(ui, &title) {
			self.settings_page = self.node_tab_back;
			return;
		}
		let selected = match self.node_tab.get_type() {
			NodeTabType::Info => 0,
			NodeTabType::Metrics => 1,
			NodeTabType::Mining => 2,
			NodeTabType::Settings => 3,
		};
		if let Some(i) = w::segmented(ui, &[DATABASE, GAUGE, FACTORY, FADERS], selected) {
			self.node_tab = match i {
				0 => Box::new(NetworkNode),
				1 => Box::new(NetworkMetrics),
				2 => Box::new(NetworkMining::default()),
				_ => Box::new(NetworkSettings::default()),
			};
		}
		ui.add_space(12.0);
		// Same availability gate as GRIM's NetworkContent: the Settings tab is
		// editable with the node off; the live tabs need a running node with
		// stats before their content can draw.
		if self.node_tab.get_type() != NodeTabType::Settings {
			if let Some(err) = Node::get_error() {
				node_error_ui(ui, err);
			} else if !Node::is_running() {
				disabled_node_ui(ui);
			} else if Node::get_stats().is_none() || Node::is_restarting() || Node::is_stopping() {
				NetworkContent::loading_ui(ui, None::<String>);
			} else {
				self.node_tab.tab_ui(ui, cb);
			}
		} else {
			self.node_tab.tab_ui(ui, cb);
		}
		// Keep the stats fresh while the node runs.
		if Node::is_running() {
			ui.ctx().request_repaint_after(Node::STATS_UPDATE_DELAY);
		}
	}

	fn node_settings_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet, cb: &dyn PlatformCallbacks) {
		use crate::wallet::types::ConnectionMethod;
		use crate::wallet::{ConnectionsConfig, ExternalConnection};
		let t = theme::tokens();
		if self.sub_header(ui, &t!("goblin.node.title")) {
			self.settings_page = SettingsPage::Main;
			return;
		}
		ScrollArea::vertical()
			.auto_shrink([false; 2])
			.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
			.show(ui, |ui| {
				let live = wallet.get_current_connection();
				let saved = wallet.get_config().connection();
				settings_group(ui, &t!("goblin.node.connection"), |ui| {
					// Integrated node (run your own) sits at the top of the picker.
					{
						let active = matches!(&saved, ConnectionMethod::Integrated);
						let row = ui.horizontal(|ui| {
							ui.label(
								RichText::new(t!("goblin.node.integrated"))
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
							wallet.update_connection(&ConnectionMethod::Integrated);
							// Apply to the running session now, not on next unlock.
							wallet.reconnect_node();
						}
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
									// Trash, not an X: a grey × next to the active row's
									// green check read as a failed-status icon, not the
									// remove action it actually is.
									let x = ui.label(
										RichText::new(crate::gui::icons::TRASH_SIMPLE)
											.font(FontId::new(15.0, fonts::regular()))
											.color(t.surface_text_dim),
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
							// Apply to the running session now, not on next unlock.
							wallet.reconnect_node();
						}
					}
				});
				if saved != live {
					ui.add_space(8.0);
					ui.label(
						RichText::new(t!("goblin.node.applies_after"))
							.font(FontId::new(13.0, fonts::regular()))
							.color(t.text_dim),
					);
				}

				ui.add_space(16.0);
				settings_group(ui, &t!("goblin.node.add_external"), |ui| {
					TextEdit::new(egui::Id::from("set_node_url"))
						.focus(false)
						.hint_text("https://node.example.com:3413")
						.text_color(t.surface_text)
						.body()
						.ui(ui, &mut self.node_url_input, cb);
					ui.add_space(8.0);
					TextEdit::new(egui::Id::from("set_node_secret"))
						.focus(false)
						.hint_text(t!("goblin.node.api_secret_hint"))
						.text_color(t.surface_text)
						.body()
						.ui(ui, &mut self.node_secret_input, cb);
				});
				ui.add_space(10.0);
				let url = self.node_url_input.trim().to_string();
				let valid = url.starts_with("http://") || url.starts_with("https://");
				if w::big_action(ui, &t!("goblin.node.add_node"), false).clicked() && valid {
					let secret = {
						let s = self.node_secret_input.trim();
						if s.is_empty() {
							None
						} else {
							Some(s.to_string())
						}
					};
					let conn = ExternalConnection::new(url, None, secret);
					ConnectionsConfig::add_ext_conn(conn.clone());
					wallet
						.update_connection(&ConnectionMethod::External(conn.id, conn.url.clone()));
					// Apply to the running session now, not on next unlock.
					wallet.reconnect_node();
					self.node_url_input.clear();
					self.node_secret_input.clear();
				}
				ui.add_space(10.0);
				// Advanced: GRIM's integrated-node tabs (info, metrics, mining
				// with stratum, node settings) inside Goblin chrome.
				if w::big_action(ui, &t!("goblin.settings.node_advanced"), true).clicked() {
					self.node_tab = Box::new(crate::gui::views::network::NetworkNode);
					self.node_tab_back = SettingsPage::Node;
					self.settings_page = SettingsPage::IntegratedNode;
				}
				ui.add_space(16.0);
			});
	}

	/// Relay list editor; saving restarts the nostr service live.
	fn relays_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet, cb: &dyn PlatformCallbacks) {
		let t = theme::tokens();
		if self.sub_header(ui, &t!("goblin.relays.title")) {
			self.settings_page = SettingsPage::Main;
			return;
		}
		ScrollArea::vertical()
			.auto_shrink([false; 2])
			.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
			.show(ui, |ui| {
				ui.label(
					RichText::new(t!("goblin.relays.intro"))
						.font(FontId::new(13.0, fonts::regular()))
						.color(t.text_dim),
				);
				ui.add_space(14.0);
				settings_group(ui, &t!("goblin.relays.your_relays"), |ui| {
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
				settings_group(ui, &t!("goblin.relays.add_relay"), |ui| {
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
				if w::big_action_on_card(ui, &t!("goblin.relays.add_relay_btn")).clicked()
					&& valid && !self.relay_edit.contains(&relay)
				{
					self.relay_edit.push(relay);
					self.relay_input.clear();
				}
				ui.add_space(10.0);
				if w::big_action(ui, &t!("goblin.relays.save_reconnect"), false).clicked() {
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

	/// Manual slatepack exchange — GRIM's native by-hand flow, exposed as an
	/// advanced fallback for when a payment can't ride a @username.
	fn slatepack_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet, cb: &dyn PlatformCallbacks) {
		let t = theme::tokens();
		if self.sub_header(ui, &t!("goblin.settings.slatepacks")) {
			self.settings_page = SettingsPage::Main;
			return;
		}
		ScrollArea::vertical()
			.auto_shrink([false; 2])
			.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
			.show(ui, |ui| {
				ui.label(
					RichText::new(t!("goblin.settings.sp_intro"))
						.font(FontId::new(13.0, fonts::regular()))
						.color(t.text_dim),
				);
				ui.add_space(14.0);

				// Receive / continue: paste a slatepack, let the wallet route it.
				let mut do_process = false;
				settings_group(ui, &t!("goblin.settings.sp_receive_group"), |ui| {
					ui.label(
						RichText::new(t!("goblin.settings.sp_receive_blurb"))
							.font(FontId::new(12.5, fonts::regular()))
							.color(t.surface_text_dim),
					);
					ui.add_space(8.0);
					TextEdit::new(egui::Id::from("sp_paste"))
						.focus(false)
						.paste()
						.hint_text("BEGINSLATEPACK. … ENDSLATEPACK.")
						.text_color(t.surface_text)
						.body()
						.ui(ui, &mut self.slatepack.paste, cb);
				});
				ui.add_space(10.0);
				if w::big_action(ui, &t!("goblin.settings.sp_process"), false).clicked() {
					do_process = true;
				}
				if do_process {
					let text = self.slatepack.paste.trim().to_string();
					if text.is_empty() {
						self.slatepack.error =
							Some(t!("goblin.settings.sp_paste_first").to_string());
						self.slatepack.status = None;
					} else {
						use crate::wallet::types::ManualSlatepackOutcome as Out;
						match wallet.manual_process_slatepack(&text) {
							Ok(Out::Response(reply)) => {
								self.slatepack.result = reply;
								self.slatepack.status =
									Some(t!("goblin.settings.sp_reply_ready").to_string());
								self.slatepack.error = None;
								self.slatepack.paste.clear();
							}
							Ok(Out::Finalizing) => {
								self.slatepack.result.clear();
								self.slatepack.status =
									Some(t!("goblin.settings.sp_finalizing").to_string());
								self.slatepack.error = None;
								self.slatepack.paste.clear();
							}
							Err(e) => {
								self.slatepack.error = Some(e.to_string());
								self.slatepack.status = None;
							}
						}
					}
				}

				// Send: create a slatepack to hand over out-of-band.
				ui.add_space(16.0);
				let mut do_send = false;
				settings_group(ui, &t!("goblin.settings.sp_create_group"), |ui| {
					ui.label(
						RichText::new(t!("goblin.settings.sp_create_blurb"))
							.font(FontId::new(12.5, fonts::regular()))
							.color(t.surface_text_dim),
					);
					ui.add_space(8.0);
					TextEdit::new(egui::Id::from("sp_amount"))
						.focus(false)
						.numeric()
						.hint_text(t!("goblin.settings.sp_amount_hint"))
						.text_color(t.surface_text)
						.body()
						.ui(ui, &mut self.slatepack.amount, cb);
					ui.add_space(8.0);
					TextEdit::new(egui::Id::from("sp_addr"))
						.focus(false)
						.hint_text(t!("goblin.settings.sp_addr_hint"))
						.text_color(t.surface_text)
						.body()
						.ui(ui, &mut self.slatepack.address, cb);
				});
				ui.add_space(10.0);
				if w::big_action(ui, &t!("goblin.settings.sp_create"), false).clicked() {
					do_send = true;
				}
				if do_send {
					match grin_core::core::amount_from_hr_string(self.slatepack.amount.trim()) {
						Ok(a) if a > 0 => {
							let s = self.slatepack.address.trim();
							let dest = if s.is_empty() {
								None
							} else {
								Some(s.to_string())
							};
							match wallet.manual_send_slatepack(a, dest) {
								Ok(text) => {
									self.slatepack.result = text;
									self.slatepack.status =
										Some(t!("goblin.settings.sp_ready").to_string());
									self.slatepack.error = None;
								}
								Err(e) => {
									self.slatepack.error = Some(e.to_string());
									self.slatepack.status = None;
								}
							}
						}
						_ => {
							self.slatepack.error =
								Some(t!("goblin.settings.sp_amount_gt_zero").to_string());
							self.slatepack.status = None;
						}
					}
				}

				// Status, error, and the produced slatepack (copyable).
				if let Some(err) = self.slatepack.error.clone() {
					ui.add_space(10.0);
					ui.label(
						RichText::new(err)
							.font(FontId::new(13.0, fonts::regular()))
							.color(t.neg),
					);
				}
				if let Some(status) = self.slatepack.status.clone() {
					ui.add_space(10.0);
					ui.label(
						RichText::new(status)
							.font(FontId::new(13.0, fonts::regular()))
							.color(t.text_dim),
					);
				}
				let result = self.slatepack.result.clone();
				if !result.is_empty() {
					ui.add_space(14.0);
					settings_group(ui, &t!("goblin.settings.sp_to_send"), |ui| {
						let preview: String = result.chars().take(120).collect();
						let preview = if result.chars().count() > 120 {
							format!("{preview}…")
						} else {
							preview
						};
						ui.label(
							RichText::new(preview)
								.font(FontId::new(12.0, fonts::mono()))
								.color(t.surface_text_dim),
						);
					});
					ui.add_space(10.0);
					if w::big_action(ui, &t!("goblin.settings.sp_copy"), false).clicked() {
						cb.copy_string_to_buffer(result);
						cb.vibrate_copy();
					}
				}
				ui.add_space(16.0);
			});
	}

	/// What-is-nostr explainer and tappable NIP reference list.
	fn nips_ui(&mut self, ui: &mut egui::Ui) {
		let t = theme::tokens();
		if self.sub_header(ui, &t!("goblin.nips.title")) {
			self.settings_page = SettingsPage::Main;
			return;
		}
		ScrollArea::vertical()
			.auto_shrink([false; 2])
			.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
			.show(ui, |ui| {
				ui.label(
					RichText::new(t!("goblin.nips.intro1"))
						.font(FontId::new(14.0, fonts::regular()))
						.color(t.text_dim),
				);
				ui.add_space(10.0);
				ui.label(
					RichText::new(t!("goblin.nips.intro2"))
						.font(FontId::new(14.0, fonts::regular()))
						.color(t.text_dim),
				);
				ui.add_space(16.0);
				let nips = [
					(
						"05",
						t!("goblin.nips.n05_title"),
						t!("goblin.nips.n05_blurb"),
					),
					(
						"17",
						t!("goblin.nips.n17_title"),
						t!("goblin.nips.n17_blurb"),
					),
					(
						"44",
						t!("goblin.nips.n44_title"),
						t!("goblin.nips.n44_blurb"),
					),
					(
						"49",
						t!("goblin.nips.n49_title"),
						t!("goblin.nips.n49_blurb"),
					),
					(
						"59",
						t!("goblin.nips.n59_title"),
						t!("goblin.nips.n59_blurb"),
					),
					(
						"98",
						t!("goblin.nips.n98_title"),
						t!("goblin.nips.n98_blurb"),
					),
				];
				for (num, title, blurb) in &nips {
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
								RichText::new(blurb.as_ref())
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
						RichText::new(t!("goblin.settings.rotate_key"))
							.font(FontId::new(15.0, fonts::semibold()))
							.color(t.neg),
					);
					ui.add_space(6.0);
					for line in [
						t!("goblin.settings.rotate_line1"),
						t!("goblin.settings.rotate_line2"),
						t!("goblin.settings.rotate_line3"),
						t!("goblin.settings.rotate_line4"),
						t!("goblin.settings.rotate_line5"),
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
								if w::big_action_on_card(ui, &t!("goblin.settings.cancel"))
									.clicked()
								{
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
								if w::big_action(ui, &t!("goblin.settings.continue"), false)
									.clicked()
								{
									rotate.stage = 2;
								}
							},
						);
					});
				}
				2 => {
					ui.label(
						RichText::new(t!("goblin.settings.final_confirmation"))
							.font(FontId::new(15.0, fonts::semibold()))
							.color(t.neg),
					);
					ui.add_space(6.0);
					ui.label(
						RichText::new(t!("goblin.settings.rotate_confirm_blurb"))
							.font(FontId::new(13.0, fonts::regular()))
							.color(t.surface_text_dim),
					);
					ui.add_space(10.0);
					w::field_well(ui, |ui| {
						TextEdit::new(egui::Id::from("rotate_reset"))
							.focus(false)
							.hint_text(t!("goblin.settings.type_reset"))
							.text_color(t.surface_text)
							.body()
							.ui(ui, &mut rotate.reset_input, cb);
					});
					ui.add_space(8.0);
					w::field_well(ui, |ui| {
						TextEdit::new(egui::Id::from("rotate_pass"))
							.focus(false)
							.hint_text(t!("goblin.settings.wallet_password"))
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
								if w::big_action_on_card(ui, &t!("goblin.settings.cancel"))
									.clicked()
								{
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
									if w::big_action(
										ui,
										&t!("goblin.settings.rotate_key_btn"),
										false,
									)
									.clicked()
									{
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
							RichText::new(t!("goblin.settings.rotating_key"))
								.font(FontId::new(13.0, fonts::regular()))
								.color(t.surface_text_dim),
						);
					});
					ui.ctx().request_repaint();
				}
				4 => {
					ui.label(
						RichText::new(t!("goblin.settings.key_rotated"))
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
						RichText::new(t!("goblin.settings.new_npub", npub => short))
							.font(FontId::new(13.0, fonts::mono()))
							.color(t.surface_text_dim),
					);
					ui.add_space(6.0);
					ui.label(
						RichText::new(t!("goblin.settings.backup_new_key"))
							.font(FontId::new(13.0, fonts::semibold()))
							.color(t.neg),
					);
					ui.add_space(10.0);
					if w::big_action_on_card(ui, &t!("goblin.settings.copy_new_nsec")).clicked() {
						if let Some(nsec) = wallet.nostr_service().and_then(|s| s.nsec()) {
							cb.copy_string_to_buffer(nsec);
							cb.vibrate_copy();
						}
					}
					ui.add_space(8.0);
					if w::big_action(ui, &t!("goblin.settings.done"), false).clicked() {
						close = true;
					}
				}
				_ => {
					ui.label(
						RichText::new(t!("goblin.settings.rotation_failed"))
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
					if w::big_action_on_card(ui, &t!("goblin.settings.close")).clicked() {
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
	/// Inline "change name authority" editor: set the NIP-05 server that registers
	/// and verifies names. Lets a user on one instance pay names on another.
	fn name_authority_ui(
		&mut self,
		ui: &mut egui::Ui,
		wallet: &Wallet,
		cb: &dyn PlatformCallbacks,
	) {
		let t = theme::tokens();
		let na = self.name_authority.as_mut().unwrap();
		let mut close = false;
		w::card(ui, |ui| {
			ui.set_min_width(ui.available_width());
			ui.label(
				RichText::new(t!("goblin.settings.name_authority_title"))
					.font(FontId::new(15.0, fonts::semibold()))
					.color(t.surface_text),
			);
			ui.add_space(6.0);
			ui.label(
				RichText::new(t!("goblin.settings.name_authority_blurb"))
					.font(FontId::new(13.0, fonts::regular()))
					.color(t.surface_text_dim),
			);
			ui.add_space(10.0);
			w::field_well(ui, |ui| {
				TextEdit::new(egui::Id::from("name_authority_input"))
					.focus(false)
					.hint_text("https://goblin.st")
					.text_color(t.surface_text)
					.body()
					.ui(ui, &mut na.input, cb);
			});
			if let Some(err) = &na.error {
				ui.add_space(6.0);
				ui.label(
					RichText::new(err)
						.font(FontId::new(12.5, fonts::regular()))
						.color(t.neg),
				);
			}
			ui.add_space(10.0);
			ui.horizontal(|ui| {
				let third = (ui.available_width() - 20.0) / 3.0;
				ui.scope_builder(
					egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
						ui.cursor().min,
						Vec2::new(third, 44.0),
					)),
					|ui| {
						if w::big_action_on_card(ui, &t!("goblin.settings.cancel")).clicked() {
							close = true;
						}
					},
				);
				ui.add_space(10.0);
				ui.scope_builder(
					egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
						ui.cursor().min,
						Vec2::new(third, 44.0),
					)),
					|ui| {
						if w::big_action_on_card(ui, &t!("goblin.settings.reset")).clicked() {
							if let Some(s) = wallet.nostr_service() {
								s.config.write().set_nip05_server(None);
								crate::nostr::nip05::set_home_domain(
									&s.config.read().home_domain(),
								);
							}
							close = true;
						}
					},
				);
				ui.add_space(10.0);
				ui.scope_builder(
					egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
						ui.cursor().min,
						Vec2::new(third, 44.0),
					)),
					|ui| {
						if w::big_action(ui, &t!("goblin.settings.save"), false).clicked() {
							let url = na.input.trim().to_string();
							if !url.starts_with("https://") && !url.starts_with("http://") {
								na.error =
									Some(t!("goblin.settings.name_authority_invalid").to_string());
							} else if let Some(s) = wallet.nostr_service() {
								s.config.write().set_nip05_server(Some(url));
								crate::nostr::nip05::set_home_domain(
									&s.config.read().home_domain(),
								);
								close = true;
							}
						}
					},
				);
			});
		});
		if close {
			self.name_authority = None;
		}
	}

	/// Inline "back up identity to a file" flow: ask for the wallet password,
	/// seal the identity, and write a GOBLIN-*.backup file via the native picker.
	fn backup_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet, cb: &dyn PlatformCallbacks) {
		let t = theme::tokens();
		let bk = self.backup.as_mut().unwrap();
		let mut close = false;
		w::card(ui, |ui| {
			ui.set_min_width(ui.available_width());
			if bk.done {
				ui.label(
					RichText::new(t!("goblin.settings.backup_saved"))
						.font(FontId::new(15.0, fonts::semibold()))
						.color(t.pos),
				);
				ui.add_space(4.0);
				ui.label(
					RichText::new(t!("goblin.settings.backup_saved_sub"))
						.font(FontId::new(13.0, fonts::regular()))
						.color(t.surface_text_dim),
				);
				ui.add_space(10.0);
				if w::big_action(ui, &t!("goblin.settings.done"), false).clicked() {
					close = true;
				}
				return;
			}
			ui.label(
				RichText::new(t!("goblin.settings.backup_file_title"))
					.font(FontId::new(15.0, fonts::semibold()))
					.color(t.surface_text),
			);
			ui.add_space(6.0);
			ui.label(
				RichText::new(t!("goblin.settings.backup_file_blurb"))
					.font(FontId::new(13.0, fonts::regular()))
					.color(t.surface_text_dim),
			);
			ui.add_space(10.0);
			w::field_well(ui, |ui| {
				TextEdit::new(egui::Id::from("backup_pass"))
					.focus(false)
					.hint_text(t!("goblin.settings.wallet_password"))
					.password()
					.text_color(t.surface_text)
					.body()
					.ui(ui, &mut bk.password, cb);
			});
			if let Some(err) = &bk.error {
				ui.add_space(6.0);
				ui.label(
					RichText::new(err)
						.font(FontId::new(12.5, fonts::regular()))
						.color(t.neg),
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
						if w::big_action_on_card(ui, &t!("goblin.settings.cancel")).clicked() {
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
						ui.add_enabled_ui(!bk.password.is_empty(), |ui| {
							if w::big_action(ui, &t!("goblin.settings.create_backup"), false)
								.clicked()
							{
								match wallet.create_nostr_backup(&bk.password) {
									Ok(envelope) => {
										let stamp = chrono::Local::now().format("%Y-%m-%d-%H%M");
										let fname = format!("GOBLIN-{stamp}.backup");
										match cb.save_file(fname, envelope.into_bytes()) {
											Ok(()) => {
												bk.done = true;
												bk.error = None;
												bk.password.clear();
											}
											Err(_) => {
												bk.error = Some(
													t!("goblin.settings.backup_write_failed")
														.to_string(),
												);
											}
										}
									}
									Err(e) => bk.error = Some(e),
								}
							}
						});
					},
				);
			});
		});
		if close {
			self.backup = None;
		}
	}

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
						RichText::new(t!("goblin.settings.import_identity_title"))
							.font(FontId::new(15.0, fonts::semibold()))
							.color(t.surface_text),
					);
					ui.add_space(6.0);
					ui.label(
						RichText::new(t!("goblin.settings.import_blurb"))
							.font(FontId::new(13.0, fonts::regular()))
							.color(t.surface_text_dim),
					);
					ui.add_space(10.0);
					// Native ".backup file" picker. Desktop returns the path now;
					// Android returns it asynchronously (poll picked_file()).
					if import.picking {
						if let Some(path) = cb.picked_file() {
							import.picking = false;
							if !path.is_empty() {
								match std::fs::read_to_string(&path) {
									Ok(contents) => import.nsec = contents.trim().to_string(),
									Err(_) => {
										import.error =
											t!("goblin.settings.backup_read_failed").to_string();
									}
								}
							}
						} else {
							ui.ctx().request_repaint();
						}
					}
					if w::big_action_on_card(ui, &t!("goblin.settings.choose_backup_file"))
						.clicked()
					{
						import.error.clear();
						match cb.pick_file() {
							Some(path) if !path.is_empty() => {
								match std::fs::read_to_string(&path) {
									Ok(contents) => import.nsec = contents.trim().to_string(),
									Err(_) => {
										import.error =
											t!("goblin.settings.backup_read_failed").to_string();
									}
								}
							}
							// Empty string = Android async pick in flight.
							Some(_) => import.picking = true,
							None => {}
						}
					}
					if !import.error.is_empty() && import.stage == 1 {
						ui.add_space(6.0);
						ui.label(
							RichText::new(&import.error)
								.font(FontId::new(12.5, fonts::regular()))
								.color(t.neg),
						);
					}
					ui.add_space(8.0);
					w::field_well(ui, |ui| {
						TextEdit::new(egui::Id::from("import_nsec"))
							.focus(false)
							.hint_text(t!("goblin.settings.import_nsec_hint"))
							.password()
							.text_color(t.surface_text)
							.body()
							.ui(ui, &mut import.nsec, cb);
					});
					ui.add_space(8.0);
					w::field_well(ui, |ui| {
						TextEdit::new(egui::Id::from("import_pass"))
							.focus(false)
							.hint_text(t!("goblin.settings.wallet_password"))
							.password()
							.text_color(t.surface_text)
							.body()
							.ui(ui, &mut import.password, cb);
					});
					ui.add_space(8.0);
					w::field_well(ui, |ui| {
						TextEdit::new(egui::Id::from("import_backup_pass"))
							.focus(false)
							.hint_text(t!("goblin.settings.backup_password_hint"))
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
								if w::big_action_on_card(ui, &t!("goblin.settings.cancel"))
									.clicked()
								{
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
									if w::big_action(ui, &t!("goblin.settings.import_btn"), false)
										.clicked()
									{
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
							RichText::new(t!("goblin.settings.importing"))
								.font(FontId::new(13.0, fonts::regular()))
								.color(t.surface_text_dim),
						);
					});
					ui.ctx().request_repaint();
				}
				4 => {
					ui.label(
						RichText::new(t!("goblin.settings.identity_replaced"))
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
						RichText::new(t!("goblin.settings.now_using", npub => short))
							.font(FontId::new(13.0, fonts::mono()))
							.color(t.surface_text_dim),
					);
					ui.add_space(10.0);
					if w::big_action(ui, &t!("goblin.settings.done"), false).clicked() {
						close = true;
					}
				}
				_ => {
					ui.label(
						RichText::new(t!("goblin.settings.import_failed"))
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
					if w::big_action_on_card(ui, &t!("goblin.settings.close")).clicked() {
						close = true;
					}
				}
			}
		});
		if close {
			self.import_nsec = None;
		}
	}

	/// Inline username-claim widget (availability check + registration).
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
						claim.message =
							Some(t!("goblin.settings.registered", name => name).to_string());
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
						// Publish kind 0 NOW so others can resolve our @name without
						// waiting for the next app start — otherwise a just-claimed
						// name is invisible over the relays (no kind-0 event exists).
						wallet.task(crate::wallet::types::WalletTask::NostrRepublishProfile);
					}
					ClaimMsg::Released => {
						claim.message = Some(t!("goblin.settings.released_msg").to_string());
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
						RichText::new(t!("goblin.settings.release_confirm", name => name))
							.font(FontId::new(15.0, fonts::semibold()))
							.color(t.surface_text),
					);
					ui.add_space(4.0);
					ui.label(
						RichText::new(t!("goblin.settings.release_blurb"))
							.font(FontId::new(12.5, fonts::regular()))
							.color(t.surface_text_dim),
					);
					ui.add_space(10.0);
					if claim.checking {
						ui.horizontal(|ui| {
							View::small_loading_spinner(ui);
							ui.add_space(8.0);
							ui.label(
								RichText::new(t!("goblin.settings.releasing"))
									.color(t.surface_text_dim),
							);
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
									if w::big_action_on_card_ink(
										ui,
										&t!("goblin.settings.keep_it"),
										t.surface_text,
									)
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
									if w::big_action_on_card_ink(
										ui,
										&t!("goblin.settings.release_it"),
										t.neg,
									)
									.clicked()
									{
										start_release(claim, &name, wallet);
									}
								},
							);
						});
					}
				} else {
					ui.label(
						RichText::new(t!("goblin.settings.username"))
							.font(FontId::new(15.0, fonts::semibold()))
							.color(t.surface_text),
					);
					ui.add_space(4.0);
					ui.label(
						RichText::new(name.to_string())
							.font(FontId::new(20.0, fonts::bold()))
							.color(t.surface_text),
					);
					ui.add_space(4.0);
					ui.label(
						RichText::new(t!("goblin.settings.username_note"))
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
					if w::big_action_on_card_ink(ui, &t!("goblin.settings.release_username"), t.neg)
						.clicked()
					{
						claim.confirm_release = true;
						claim.message = None;
					}
				}
			} else {
				ui.label(
					RichText::new(t!("goblin.settings.pick_username"))
						.font(FontId::new(15.0, fonts::semibold()))
						.color(t.surface_text),
				);
				ui.add_space(8.0);
				// Placeholder shows the bare handle ("yourname") — we never display
				// the "@" to users. A leading "@" the user happens to type is still
				// stripped when the name is read below.
				let before = claim.input.clone();
				TextEdit::new(egui::Id::from("settings_claim"))
					.focus(false)
					.hint_text(t!("goblin.onboarding.identity.username_field_hint"))
					.text_color(t.surface_text)
					.body()
					.ui(ui, &mut claim.input, cb);
				if claim.input != before {
					claim.available = None;
					claim.message = None;
				}
				ui.add_space(4.0);
				ui.label(
					RichText::new(t!("goblin.settings.username_note"))
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
				let name = claim.input.trim().trim_start_matches('@').to_lowercase();
				let valid = name.len() >= 3 && name.len() <= 20;
				if claim.checking {
					ui.horizontal(|ui| {
						View::small_loading_spinner(ui);
						ui.add_space(8.0);
						ui.label(
							RichText::new(t!("goblin.settings.working")).color(t.surface_text_dim),
						);
					});
					ui.ctx().request_repaint();
				} else {
					ui.add_enabled_ui(valid, |ui| {
						if w::big_action(ui, &t!("goblin.settings.claim"), false).clicked() {
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
						ClaimMsg::Error(t!("goblin.settings.err_just_taken").to_string())
					}
					RegisterResult::Rejected(e) if e == "name_change_cooldown" => {
						ClaimMsg::Error(t!("goblin.settings.err_cooldown").to_string())
					}
					RegisterResult::Rejected(e) => ClaimMsg::Error(e),
					RegisterResult::Network => {
						ClaimMsg::Error(t!("goblin.settings.err_unreachable").to_string())
					}
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
		// Release is always allowed server-side (it's what arms the cooldown),
		// so there's no cooldown rejection to handle here.
		let msg = match rt.block_on(crate::nostr::nip05::unregister(&server, &name, &keys)) {
			Ok(()) => ClaimMsg::Released,
			Err(e) => ClaimMsg::Error(t!("goblin.settings.err_release", err => e).to_string()),
		};
		*slot.lock().unwrap() = Some(msg);
	});
}

/// Process a picked picture and upload it as the avatar for an owned name.

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

/// Title row for an Advanced-page action card.
fn advanced_head(ui: &mut egui::Ui, label: &str, color: Color32) {
	ui.label(
		RichText::new(label)
			.font(FontId::new(15.0, fonts::semibold()))
			.color(color),
	);
	ui.add_space(4.0);
}

/// Wrapped description line under an Advanced-page action title.
fn advanced_desc(ui: &mut egui::Ui, text: &str) {
	let t = theme::tokens();
	ui.label(
		RichText::new(text)
			.font(FontId::new(13.0, fonts::regular()))
			.color(t.surface_text_dim),
	);
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
	settings_row_ink(ui, label, value, theme::tokens().surface_text_dim);
}

/// Like [`settings_row`] but the value is drawn in an explicit ink — used to flag
/// the always-on mixnet routing in the privacy color.
fn settings_row_ink(ui: &mut egui::Ui, label: &str, value: &str, value_ink: Color32) {
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
					.color(value_ink),
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

/// A settings row whose value cycles in place on tap (no navigation): the
/// value is drawn in the same small/dim style as [`settings_row_nav`] so it
/// sits consistently next to chevroned siblings, just without the chevron.
fn settings_row_cycle(ui: &mut egui::Ui, label: &str, value: &str) -> bool {
	let t = theme::tokens();
	let row = ui.horizontal(|ui| {
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

/// One channel row on the Network-privacy page: a status dot, a title and a
/// wrapped blurb explaining where that traffic goes.
fn privacy_line(ui: &mut egui::Ui, dot: Color32, title: &str, blurb: &str) {
	let t = theme::tokens();
	ui.horizontal_top(|ui| {
		let (rect, _) = ui.allocate_exact_size(Vec2::new(14.0, 20.0), Sense::hover());
		ui.painter()
			.circle_filled(rect.center() + Vec2::new(0.0, -2.0), 4.0, dot);
		ui.vertical(|ui| {
			ui.label(
				RichText::new(title)
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
	ui.add_space(10.0);
}

/// Open a URL in the system browser.
fn open_url(ui: &egui::Ui, url: &str) {
	ui.ctx().open_url(egui::OpenUrl::new_tab(url));
}

/// Linear blend between two colors (`p` 0→`a`, 1→`b`). Used by the Pay-screen
/// over-balance flash to ease the digits from red back to normal ink.
fn lerp_color(a: Color32, b: Color32, p: f32) -> Color32 {
	let p = p.clamp(0.0, 1.0);
	let mix = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * p).round() as u8;
	Color32::from_rgb(mix(a.r(), b.r()), mix(a.g(), b.g()), mix(a.b(), b.b()))
}

fn approve_button(ui: &mut egui::Ui) -> bool {
	w::big_action(ui, &t!("goblin.request.approve"), false).clicked()
}

fn decline_button(ui: &mut egui::Ui) -> bool {
	w::big_action(ui, &t!("goblin.request.decline"), true).clicked()
}

fn accept_policy_label(wallet: &Wallet) -> String {
	use crate::nostr::config::AcceptPolicy;
	wallet
		.nostr_service()
		.map(|s| match s.config.read().accept_from() {
			AcceptPolicy::Everyone => t!("goblin.settings.accept_anyone").to_string(),
			AcceptPolicy::Contacts => t!("goblin.settings.accept_contacts").to_string(),
			AcceptPolicy::Ask => t!("goblin.settings.accept_ask").to_string(),
		})
		.unwrap_or_else(|| t!("goblin.settings.accept_anyone").to_string())
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
				0 => t!("goblin.relays.none").to_string(),
				1 => relays[0].replace("wss://", ""),
				n => t!("goblin.relays.count", n => n).to_string(),
			}
		})
		.unwrap_or_else(|| "—".to_string())
}

/// Compute a fiat preview line for the balance, when a rate is available.
/// One-line node summary: "Block 1,847,221 · main.gri.mw".
/// Bare node host (or "integrated node") for the sidebar card's third line.
fn node_host(wallet: &Wallet) -> String {
	match wallet.get_current_connection() {
		crate::wallet::types::ConnectionMethod::Integrated => {
			t!("goblin.node.integrated_host").to_string()
		}
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
		crate::wallet::types::ConnectionMethod::Integrated => {
			t!("goblin.node.integrated_host").to_string()
		}
		crate::wallet::types::ConnectionMethod::External(_, url) => url
			.replace("https://", "")
			.replace("http://", "")
			.trim_end_matches('/')
			.to_string(),
	};
	if height == 0 {
		t!("goblin.node.summary_syncing", conn => conn).to_string()
	} else {
		t!("goblin.node.summary_block", height => fmt_thousands(height), conn => conn).to_string()
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
