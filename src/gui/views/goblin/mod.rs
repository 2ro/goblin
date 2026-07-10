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

mod activity;
pub mod avatars;
pub mod data;
mod format;
mod helpers;
mod home;
pub mod identicon;
mod identities;
mod me;
mod modals;
pub mod onboarding;
mod pay;
mod privacy;
mod profile;
mod prompts;
mod receipt;
mod receive;
pub mod send;
mod settings;
mod settings_advanced;
mod settings_node;
mod username;
pub mod widgets;

use eframe::epaint::{CornerRadius, FontId, Stroke};
use egui::{Align, Color32, Layout, Margin, RichText, ScrollArea, Sense, Vec2};

use crate::gui::Colors;
use crate::gui::icons::{
	ARROW_DOWN, ARROW_LEFT, CHECK, CLOCK, COPY, PROHIBIT, QR_CODE, SHARE, USER_CIRCLE, WALLET,
};
use crate::gui::platform::PlatformCallbacks;
use crate::gui::theme::{self, fonts};
use crate::gui::views::types::ModalPosition;
use crate::gui::views::{Content, Modal, TextEdit, View};
use crate::wallet::Wallet;
use crate::wallet::types::WalletData;

use self::data::{ActivityItem, activity_items, news_latest, recent_peers, split_urls};
use self::send::SendFlow;
use self::widgets as w;

use self::format::*;
use self::helpers::*;
use self::privacy::*;
use self::username::{availability_feedback, start_claim_flow};

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
	/// Inline "back up identity to a file" flow state.
	backup: Option<BackupState>,
	/// Identity switcher (one wallet, many nostr identities) page state.
	identity_switch: IdentitySwitchState,
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
	/// Minimum-confirmations value being edited in its modal (GRIM parity).
	min_conf_edit: String,
	/// When the first back of the double-back was pressed at Home, for the
	/// brief "press back again for the wallet switcher" hint. Display only.
	back_hint: Option<std::time::Instant>,
	/// A batch invoice request awaiting approval (count=N deep link).
	batch_invoice: Option<BatchInvoiceState>,
	/// A "Sign in with Goblin" login request awaiting approval (deep link or
	/// scanned QR), including the callback POST once approved. While this is
	/// `Some`, every new incoming login URI is ignored (one at a time).
	login: Option<LoginState>,
	/// An "Authorize with Goblin" request awaiting approval (deep link or scanned
	/// QR): the wallet signs one arbitrary event and hands it to the site. While
	/// this OR `login` is `Some`, every new incoming authorize/login URI is
	/// ignored (one approval at a time).
	authorize: Option<AuthorizeState>,
	/// Quiet toast for the login outcome: text and when it appeared. Reused for
	/// the authorize outcome (same quiet pill, different strings).
	login_toast: Option<(String, std::time::Instant)>,
	/// A "Trust with Goblin" (Authorize Sessions) grant awaiting approval. While
	/// this OR `login`/`authorize`/`money` is `Some`, new incoming requests are
	/// ignored (one approval at a time).
	trust: Option<TrustState>,
	/// A granted trust whose `session-open` announce is still unconfirmed: the
	/// toast and any return-to-caller wait here until the service loop confirms
	/// the publish reached a relay (or the deadline passes).
	trust_wait: Option<TrustWait>,
	/// The hold-to-confirm gesture for the single high-value trust decision.
	trust_hold: w::HoldToSend,
	/// A money-tier sign or encrypt arriving mid-session that must be
	/// password-approved per action (the v1-style prompt raised over the channel).
	money: Option<MoneyState>,
	/// The hold-to-confirm gesture for a money-tier approval.
	money_hold: w::HoldToSend,
	/// Anonymous mode: whether the home balance has been tapped to reveal this
	/// visit. Presentation-only and transient — reset whenever the user leaves
	/// the Home tab so a later glance is censored again.
	balance_revealed: bool,
}

/// Whether the per-identity cue is drawn on activity rows (owner-approved). The
/// row's main avatar stays the COUNTERPARTY; the cue is a SMALL corner badge on
/// that avatar, filled with the USER's OWN identity gradient for the tx (from
/// `ActivityItem.owner_pubkey`), so a glance clusters which of your identities
/// each payment used. Only shown when the wallet holds more than one identity.
const SHOW_ROW_IDENTITY_CUE: bool = true;

/// Known name authorities offered on the Username page as a tappable list, on top
/// of the free-typed custom entry. Kept to servers we actually run; anything else
/// goes through the custom field. `(display, base URL)`.
const KNOWN_AUTHORITIES: &[(&str, &str)] = &[("goblin.st", "https://goblin.st")];

/// Per-frame identity context for the activity rows: whether the wallet holds
/// more than one identity (the cue only shows then) and the primary identity's
/// pubkey hex (the seed for pre-feature rows that carry no owner tag). Computed
/// once per activity list, not per row.
struct IdentityCueCtx {
	multi: bool,
	primary: Option<String>,
}

impl IdentityCueCtx {
	fn compute(wallet: &Wallet) -> Self {
		let ids = wallet.nostr_identities();
		IdentityCueCtx {
			multi: ids.len() > 1,
			primary: ids.first().map(|i| i.pubkey_hex.clone()),
		}
	}
}

/// The settings sub-page for the coming frame: reset to the root once the user
/// is off the Settings (Me) tab, otherwise keep the current page. Pure so the
/// leave/enter boundary rule is unit-testable without an egui context. Deep
/// links open a sub-page while setting the tab to Me in the same frame, so they
/// are preserved.
fn settings_page_after(tab: Tab, page: SettingsPage) -> SettingsPage {
	if tab == Tab::Me {
		page
	} else {
		SettingsPage::Main
	}
}

/// Sub-pages of the Settings tab.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SettingsPage {
	Main,
	Node,
	/// GRIM's integrated-node tabs, embedded in Goblin chrome.
	IntegratedNode,
	Relays,
	Nips,
	Pairing,
	Language,
	Slatepack,
	Privacy,
	/// Everything username: claim, release, and the name authority (known list
	/// plus a free-typed custom one). The single home for names.
	Username,
	/// Notification privacy (hide amounts / names / all details) plus the
	/// anonymous-mode toggle that dots the home balance and activity list.
	AdvancedPrivacy,
	Advanced,
	/// The identity switcher: one wallet, one balance, many nostr identities.
	Identities,
	/// Trusted Sites: the active Authorize Sessions, what each can sign, and a
	/// one-tap end (revocation).
	TrustedSites,
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
	/// Wallet password typed into the Danger Zone delete gate.
	delete_pass: String,
	/// The delete password didn't decrypt the seed — show the wrong-password line.
	delete_wrong: bool,
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
			backup: None,
			identity_switch: IdentitySwitchState::default(),
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
			min_conf_edit: String::new(),
			back_hint: None,
			batch_invoice: None,
			login: None,
			authorize: None,
			login_toast: None,
			trust: None,
			trust_wait: None,
			trust_hold: w::HoldToSend::default(),
			money: None,
			money_hold: w::HoldToSend::default(),
			balance_revealed: false,
		}
	}
}

/// Id of the wallet-password modal used to unlock a switch or encrypt an add,
/// mirroring the wallet-open password modal.
const IDENTITY_PASS_MODAL: &str = "goblin_identity_pass_modal";

/// Id of the per-identity management modal (rename / delete). A true modal —
/// the GRIM Modal system dims and locks the list behind it, so no switching or
/// row taps while it is open.
const IDENTITY_MANAGE_MODAL: &str = "goblin_identity_manage_modal";

/// Id of the step-1 delete-confirmation modal (danger text before the
/// wallet-password modal executes the delete). Also background-locking.
const IDENTITY_DELETE_MODAL: &str = "goblin_identity_delete_modal";

/// Id of the minimum-confirmations edit modal (GRIM parity: numeric input,
/// Cancel/Save), opened from the Settings wallet group.
const MIN_CONF_MODAL: &str = "goblin_min_conf_modal";

/// Id of the batch-invoice approval modal (a `count=N` invoice-request URI):
/// one approval for N payment requests, each on its own fresh proof address.
const BATCH_INVOICE_MODAL: &str = "goblin_batch_invoice_modal";

/// Id of the "Sign in with Goblin" approval modal: the user reviews the
/// requesting domain, picks the signing identity, and confirms with the
/// wallet password before the one-time challenge is signed.
const LOGIN_MODAL: &str = "goblin_login_modal";

/// Id of the "Authorize with Goblin" approval modal: the user reviews the
/// requesting domain and the exact event to be signed, picks the signing
/// identity, and confirms with the wallet password before the one event is
/// signed and handed to the site. Shares the login expiry and POST timeout.
const AUTHORIZE_MODAL: &str = "goblin_authorize_modal";

/// A pending, untouched login approval expires after this many seconds (the
/// modal closes and the request is dropped).
const LOGIN_EXPIRY_SECS: u64 = 120;

/// The login callback POST gives up after this many seconds.
const LOGIN_POST_TIMEOUT_SECS: u64 = 15;

/// How long the trust flow waits for the `session-open` announce to be
/// confirmed accepted by the site's relay before giving up with an honest
/// toast. The service loop ticks every 2s and re-publishes until a hint relay
/// confirms, so this covers a cold Tor circuit to a relay we weren't already
/// connected to (which can take well over 15s on the first reach).
const TRUST_ANNOUNCE_TIMEOUT_SECS: u64 = 30;

/// A granted trust waiting on its `session-open` announce confirmation. The
/// success toast and the return-to-caller decision (same-device flows) are
/// deferred until [`crate::nostr::NostrService::session_announced`] turns true
/// for `channel_pk`, or `deadline` passes. Keeping the app foreground for this
/// window is what fixes the Build 153 QR-trust bug: backgrounding stops the
/// frame pump and strands the announce in the paused service.
struct TrustWait {
	/// The wallet channel pubkey (hex) identifying the announced session.
	channel_pk: String,
	/// The granted domain, for the toast.
	domain: String,
	/// Give-up time for the confirmation wait.
	deadline: std::time::Instant,
	/// The parsed `rt` flag: whether a completed flow may hand focus back.
	want_return: bool,
}

/// One pending "Sign in with Goblin" approval. Single-use by construction:
/// once the event is signed (`posting`), or on cancel/expiry, the state is
/// dropped and only a fresh URI can start another.
struct LoginState {
	/// The validated request (challenge, domain, callback).
	uri: crate::nostr::loginuri::LoginUri,
	/// The CHOSEN signing identity (pubkey hex); defaults to the active one.
	selected: String,
	/// When the request arrived, for the [`LOGIN_EXPIRY_SECS`] deadline.
	created: std::time::Instant,
	/// Wallet password typed into the modal; cleared as soon as consumed.
	pass: String,
	/// The typed password did not verify: show the wrong-password line. The
	/// request itself stays pending (a typo never consumes it).
	wrong_pass: bool,
	/// The event is signed and the callback POST is in flight; the request is
	/// consumed either way once the worker reports back.
	posting: bool,
	/// Result slot the POST worker thread fills.
	result: std::sync::Arc<std::sync::Mutex<Option<Result<(), String>>>>,
}

/// One pending "Authorize with Goblin" approval. Mirrors [`LoginState`]
/// field-for-field, plus a `show_full` toggle for the complete-content view.
/// Single-use by construction: once the event is signed (`posting`), or on
/// cancel/expiry, the state is dropped and only a fresh URI can start another.
struct AuthorizeState {
	/// The validated request (challenge, domain, callback, event template).
	uri: crate::nostr::authuri::AuthorizeUri,
	/// The CHOSEN signing identity (pubkey hex); defaults to the active one.
	selected: String,
	/// When the request arrived, for the [`LOGIN_EXPIRY_SECS`] deadline.
	created: std::time::Instant,
	/// Wallet password typed into the modal; cleared as soon as consumed.
	pass: String,
	/// The typed password did not verify: show the wrong-password line. The
	/// request itself stays pending (a typo never consumes it).
	wrong_pass: bool,
	/// The event is signed and the callback POST is in flight; the request is
	/// consumed either way once the worker reports back.
	posting: bool,
	/// Whether the complete (escaped) content is expanded in a scrollable view.
	/// Approval is never blocked on it; it only reveals what truncation hid.
	show_full: bool,
	/// Result slot the POST worker thread fills.
	result: std::sync::Arc<std::sync::Mutex<Option<Result<(), String>>>>,
}

/// The "Trust with Goblin" (Authorize Sessions) grant modal id. Its verb is
/// "Trust", kept distinct from login's "Sign in" and authorize's "Authorize" so
/// the user always knows which decision they are making.
const TRUST_MODAL: &str = "goblin_trust_modal";
/// The money-tier per-action approval modal id (a channel request the wallet
/// classified as money, raised mid-session with the same shape as v1 authorize).
const MONEY_MODAL: &str = "goblin_money_modal";

/// One pending "Trust with Goblin" grant. Mirrors [`LoginState`] (it folds login
/// in as its identity step, then establishes the session), plus the freshly
/// generated wallet channel keypair carried into session creation on success.
struct TrustState {
	/// The validated request (nonce, domain, callback, channel key, relay, kinds).
	uri: crate::nostr::trusturi::TrustUri,
	/// The CHOSEN signing identity (pubkey hex); defaults to the active one.
	selected: String,
	/// When the request arrived, for the [`LOGIN_EXPIRY_SECS`] deadline.
	created: std::time::Instant,
	/// Wallet password typed into the modal; cleared as soon as consumed.
	pass: String,
	/// The typed password did not verify; the request stays pending.
	wrong_pass: bool,
	/// The login event is signed and its callback POST is in flight; on success
	/// the session is created, on failure the whole grant fails (spec 4.3).
	posting: bool,
	/// The wallet's ephemeral channel keypair for this session, generated at
	/// approval and carried into [`crate::nostr::session::Session::new`].
	channel: nostr_sdk::Keys,
	/// A friendly label for the identity (for the Trusted Sites list).
	label: String,
	/// Whether the collapsed permission detail (categories, money line,
	/// duration) is expanded. The modal leads with the one-line gist.
	show_full: bool,
	/// Result slot the login-POST worker fills.
	result: std::sync::Arc<std::sync::Mutex<Option<Result<(), String>>>>,
}

/// One pending money-tier approval arriving over a live session channel. The
/// user sees exactly what they are committing to and gates it with the wallet
/// password, hold-to-confirm, every time.
struct MoneyState {
	/// The request awaiting the user's decision (sign or pay-committing encrypt).
	pending: crate::nostr::session::PendingMoney,
	/// When it arrived, for the [`LOGIN_EXPIRY_SECS`] deadline.
	created: std::time::Instant,
	/// Wallet password typed into the modal; cleared as soon as consumed.
	pass: String,
	/// The typed password did not verify; the request stays pending.
	wrong_pass: bool,
}

/// A password-gated identity action the modal executes. Switching no longer uses
/// the modal (it is instant and local); only these need the wallet password.
#[derive(Clone)]
enum PendingPassAction {
	/// Add a held identity: generate a fresh key (`None`) or import an nsec / a
	/// sealed .backup blob (`Some`).
	Add(Option<String>),
	/// Permanently delete this held identity (pubkey hex).
	Delete(String),
}

/// Identity switcher page state: the add-identity sub-form and the wallet-password
/// modal buffer (the encrypt step for ADDING an identity — switching is instant
/// and needs no password), plus the last add result. Holds no secret key material
/// at rest.
#[derive(Default)]
struct IdentitySwitchState {
	/// Add-identity sub-form is open.
	adding: bool,
	/// Add mode is import (else generate a fresh one). Import offers a .backup
	/// file picker AND a paste-an-nsec field.
	import: bool,
	/// Pasted nsec when importing.
	nsec: String,
	/// Contents of a selected .backup file (import path); wins over `nsec`.
	backup_input: String,
	/// A native .backup file pick is in flight (Android returns it asynchronously).
	picking: bool,
	/// A held identity whose management sheet (rename / delete) is open (hex).
	manage: Option<String>,
	/// Private-tag text being edited in the management sheet.
	tag_input: String,
	/// A held identity awaiting the step-1 delete confirmation (pubkey hex).
	confirm_delete: Option<String>,
	/// The password-gated action the modal is currently gating.
	pending: Option<PendingPassAction>,
	/// Password typed into the modal; cleared as soon as it is consumed.
	pass: String,
	/// The modal password didn't unlock — show the wrong-password line.
	wrong_pass: bool,
	/// A background add is running.
	busy: bool,
	/// Transient error to show (invalid nsec, already held, at capacity).
	error: String,
	/// Result slot for the background add worker: Ok(npub) or Err(message).
	result: std::sync::Arc<std::sync::Mutex<Option<Result<String, String>>>>,
}

/// A batch invoice request (`count=N` URI) awaiting its one approval.
struct BatchInvoiceState {
	/// Receiver public key, hex (URI recipient must be a direct npub/nprofile).
	hex: String,
	/// Relay hints from the nprofile, if any.
	relay_hints: Vec<String>,
	/// Amount PER invoice, raw decimal-GRIN string from the URI.
	amount: String,
	/// Optional memo threaded onto every request.
	memo: Option<String>,
	/// How many requests to issue (2..=MAX_BATCH_COUNT).
	count: u32,
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
	/// The form was opened from the Danger Zone delete flow, so it renders
	/// inline there instead of under the Advanced nostr section.
	anchor_delete: bool,
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

	/// Show the brief "press back again for the wallet switcher" hint. Called
	/// by the host when the first back of the double-back lands at the wallet
	/// Home (the second deselects to the switcher, wallet left unlocked).
	pub fn show_back_hint(&mut self) {
		self.back_hint = Some(std::time::Instant::now());
	}

	/// Draw the transient back hint as a small bottom-anchored pill above the
	/// tab bar, non-blocking, fading out with the double-back window.
	fn back_hint_ui(&mut self, ctx: &egui::Context) {
		const SHOW_SECS: f32 = 2.0;
		let Some(at) = self.back_hint else {
			return;
		};
		let elapsed = at.elapsed().as_secs_f32();
		if elapsed >= SHOW_SECS {
			self.back_hint = None;
			return;
		}
		let t = theme::tokens();
		// Fade over the final 0.5s.
		let alpha = ((SHOW_SECS - elapsed) / 0.5).clamp(0.0, 1.0);
		let text = t!("goblin.home.back_again");
		// Native quiet-toast look: a solid soft pill, no border, small regular
		// dim text — no accent, nothing loud.
		let font = FontId::new(13.0, fonts::regular());
		egui::Area::new(egui::Id::new("goblin_back_hint"))
			.order(egui::Order::Foreground)
			.anchor(
				egui::Align2::CENTER_BOTTOM,
				Vec2::new(0.0, -(View::get_bottom_inset() + 92.0)),
			)
			.interactable(false)
			.show(ctx, |ui| {
				let galley =
					ui.painter()
						.layout_no_wrap(text.to_string(), font.clone(), t.surface_text_dim);
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
			// Don't leave the wallet password sitting in memory after leaving the
			// identity switcher.
			if self.settings_page == SettingsPage::Identities {
				self.identity_switch = IdentitySwitchState::default();
			}
			// TODO(audit L4): reset AdvancedState on back navigation too, so a
			// revealed nsec/password does not survive leaving the Advanced page.
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
			self.approve_review = None;
			self.approve_hold = w::HoldToSend::default();
			self.approve_fee_for = None;
			self.approving.clear();
			self.request_error = None;
			self.pay_amount.clear();
			self.request_amount = None;
			self.settings_page = SettingsPage::Main;
			self.advanced = AdvancedState::default();
			self.identity_switch = IdentitySwitchState::default();
			self.login = None;
			self.authorize = None;
			self.login_toast = None;
		}

		// Settings navigation resets to its ROOT whenever the user is not on the
		// Settings (Me) tab, so leaving Settings and coming back always lands on
		// the top-level page instead of the last sub-page. One reset at the
		// leave/enter boundary — deep links that open a sub-page set the tab to Me
		// in the same frame, so they are unaffected (the tab is Me by next frame).
		self.settings_page = settings_page_after(self.tab, self.settings_page);

		// Transient login-outcome toast (drawn as a Foreground area, so it rides
		// above whatever surface or overlay is showing).
		self.login_toast_ui(ui.ctx());

		// A pending payment deep link (`goblin:` / `nostr:` pay URI, routed here
		// from an OS launch/open) opens a prefilled send-review flow — the exact
		// destination a scanned checkout QR lands on. A BATCH invoice-request
		// (`count=N`, N >= 2, direct key + amount) opens the one batch-approval
		// modal instead; anything else (including count on a name that needs
		// discovery) degrades to the single flow, count ignored.
		if let Some(uri) = crate::take_pending_pay_uri() {
			let pay = crate::nostr::payuri::parse(&uri);
			let batch = if pay.count >= 2 {
				match (
					send::decode_recipient_key(&pay.recipient),
					pay.amount.clone(),
				) {
					(Some((hex, relay_hints)), Some(amount)) => Some(BatchInvoiceState {
						hex,
						relay_hints,
						amount,
						memo: pay.memo.clone(),
						count: pay.count,
					}),
					_ => None,
				}
			} else {
				None
			};
			match batch {
				Some(b) => {
					let n = b.count;
					self.batch_invoice = Some(b);
					Modal::new(BATCH_INVOICE_MODAL)
						.position(ModalPosition::CenterTop)
						.title(t!("goblin.batch.title", n => n.to_string()))
						.show();
				}
				None => {
					let now = ui.input(|i| i.time);
					self.send = Some(SendFlow::from_deeplink(&uri, wallet, now));
				}
			}
		}
		// Batch-invoice approval modal (locks the surface behind it).
		if Modal::opened() == Some(BATCH_INVOICE_MODAL) {
			Modal::ui(ui.ctx(), cb, |ui, _modal, _cb| {
				self.batch_invoice_modal_content(ui, wallet);
			});
		}

		// A pending "Sign in with Goblin" request (deep link or scanned QR,
		// already fully validated at the dispatch site). One approval at a
		// time: while one is pending (modal open or POST in flight), any new
		// incoming login request is dropped; re-triggering needs a fresh URI.
		if let Some(login) = crate::take_pending_login() {
			if self.login.is_none() && self.authorize.is_none() {
				if let Some(active) = wallet.active_nostr_pubkey() {
					// The approval takes over from any open scan/send flow.
					self.send = None;
					self.login = Some(LoginState {
						uri: login,
						selected: active,
						created: std::time::Instant::now(),
						pass: String::new(),
						wrong_pass: false,
						posting: false,
						result: std::sync::Arc::new(std::sync::Mutex::new(None)),
					});
					Modal::new(LOGIN_MODAL)
						.position(ModalPosition::CenterTop)
						.title(t!("goblin.login.title"))
						.show();
				}
			}
		}
		// An untouched approval dies after 2 minutes: modal closed, request
		// dropped. The signed-and-posting phase is governed by the POST
		// timeout instead, so it is exempt here.
		let login_expired = matches!(&self.login, Some(st)
			if !st.posting && st.created.elapsed().as_secs() >= LOGIN_EXPIRY_SECS);
		if login_expired {
			self.login = None;
			if Modal::opened() == Some(LOGIN_MODAL) {
				Modal::close();
			}
		}
		// Poll the callback POST; the request is consumed either way and the
		// outcome shows as a quiet toast (distinct success/failure strings).
		let mut login_outcome = None;
		if let Some(st) = &self.login {
			if st.posting {
				// The return decision only counts as FRESH within the posting
				// window: if the user backgrounded the wallet themselves and the
				// result is consumed on a much-later resume, bouncing them back
				// out again would be a surprise, not a completion.
				let fresh =
					st.created.elapsed().as_secs() <= LOGIN_EXPIRY_SECS + LOGIN_POST_TIMEOUT_SECS;
				login_outcome = st
					.result
					.lock()
					.unwrap()
					.take()
					.map(|res| (res, st.uri.domain.clone(), st.uri.return_to_caller && fresh));
				if login_outcome.is_none() {
					ui.ctx().request_repaint();
				}
			}
		}
		if let Some((res, domain, want_return)) = login_outcome {
			let posted_ok = res.is_ok();
			let text = match res {
				Ok(()) => t!("goblin.login.sent", domain => domain).to_string(),
				Err(e) => {
					log::warn!("sign-in callback failed: {e}");
					t!("goblin.login.failed", domain => domain).to_string()
				}
			};
			self.login_toast = Some((text, std::time::Instant::now()));
			self.login = None;
			// The flow is fully complete only NOW (POST result in hand); a
			// failed POST keeps the user in the wallet with the honest toast.
			if crate::nostr::authuri::should_return_to_caller(want_return, Some(posted_ok), true) {
				cb.return_to_caller();
			}
		}
		// The sign-in approval modal itself.
		if Modal::opened() == Some(LOGIN_MODAL) {
			Modal::ui(ui.ctx(), cb, |ui, modal, cb| {
				self.login_modal_content(ui, modal, wallet, cb);
			});
		}

		// A pending "Authorize with Goblin" request (deep link or scanned QR,
		// already fully validated at the dispatch site: kind on the allowlist,
		// template shape and domain binding checked). One approval at a time:
		// while a login OR an authorize is pending, any new incoming request is
		// dropped; re-triggering needs a fresh URI.
		if let Some(authorize) = crate::take_pending_authorize() {
			if self.login.is_none() && self.authorize.is_none() {
				if let Some(active) = wallet.active_nostr_pubkey() {
					// The approval takes over from any open scan/send flow.
					self.send = None;
					self.authorize = Some(AuthorizeState {
						uri: authorize,
						selected: active,
						created: std::time::Instant::now(),
						pass: String::new(),
						wrong_pass: false,
						posting: false,
						show_full: false,
						result: std::sync::Arc::new(std::sync::Mutex::new(None)),
					});
					Modal::new(AUTHORIZE_MODAL)
						.position(ModalPosition::CenterTop)
						.title(t!("goblin.authorize.title"))
						.show();
				}
			}
		}
		// An untouched approval dies after 2 minutes: modal closed, request
		// dropped. The signed-and-posting phase is governed by the POST timeout
		// instead, so it is exempt here.
		let authorize_expired = matches!(&self.authorize, Some(st)
			if !st.posting && st.created.elapsed().as_secs() >= LOGIN_EXPIRY_SECS);
		if authorize_expired {
			self.authorize = None;
			if Modal::opened() == Some(AUTHORIZE_MODAL) {
				Modal::close();
			}
		}
		// Poll the callback POST; the request is consumed either way and the
		// outcome shows as the same quiet toast (distinct success/failure
		// strings).
		let mut authorize_outcome = None;
		if let Some(st) = &self.authorize {
			if st.posting {
				// Same freshness rule as login: a result consumed on a late
				// resume must not bounce the user back out.
				let fresh =
					st.created.elapsed().as_secs() <= LOGIN_EXPIRY_SECS + LOGIN_POST_TIMEOUT_SECS;
				authorize_outcome = st
					.result
					.lock()
					.unwrap()
					.take()
					.map(|res| (res, st.uri.domain.clone(), st.uri.return_to_caller && fresh));
				if authorize_outcome.is_none() {
					ui.ctx().request_repaint();
				}
			}
		}
		if let Some((res, domain, want_return)) = authorize_outcome {
			let posted_ok = res.is_ok();
			let text = match res {
				Ok(()) => t!("goblin.authorize.sent", domain => domain).to_string(),
				Err(e) => {
					log::warn!("authorize callback failed: {e}");
					t!("goblin.authorize.failed", domain => domain).to_string()
				}
			};
			self.login_toast = Some((text, std::time::Instant::now()));
			self.authorize = None;
			// Fully complete only NOW (POST result in hand); a failed POST keeps
			// the user in the wallet with the honest toast.
			if crate::nostr::authuri::should_return_to_caller(want_return, Some(posted_ok), true) {
				cb.return_to_caller();
			}
		}
		// The authorize approval modal itself.
		if Modal::opened() == Some(AUTHORIZE_MODAL) {
			Modal::ui(ui.ctx(), cb, |ui, modal, cb| {
				self.authorize_modal_content(ui, modal, wallet, cb);
			});
		}

		// A pending "Trust with Goblin" (Authorize Sessions) grant. One approval
		// at a time: while login/authorize/trust/money is pending, drop new URIs.
		if let Some(trust) = crate::take_pending_trust() {
			if self.login.is_none()
				&& self.authorize.is_none()
				&& self.trust.is_none()
				&& self.money.is_none()
			{
				if let Some(active) = wallet.active_nostr_pubkey() {
					self.send = None;
					let label = wallet
						.nostr_identities()
						.into_iter()
						.find(|i| i.pubkey_hex == active)
						.map(|i| i.display())
						.unwrap_or_else(|| data::short_npub(&active));
					self.trust = Some(TrustState {
						uri: trust,
						selected: active,
						created: std::time::Instant::now(),
						pass: String::new(),
						wrong_pass: false,
						posting: false,
						channel: nostr_sdk::Keys::generate(),
						label,
						show_full: false,
						result: std::sync::Arc::new(std::sync::Mutex::new(None)),
					});
					self.trust_hold = w::HoldToSend::default();
					Modal::new(TRUST_MODAL)
						.position(ModalPosition::CenterTop)
						.title(t!("goblin.trust.title"))
						.show();
				}
			}
		}
		// An untouched grant dies after 2 minutes (posting is governed by the POST
		// timeout, so it is exempt here).
		let trust_expired = matches!(&self.trust, Some(st)
			if !st.posting && st.created.elapsed().as_secs() >= LOGIN_EXPIRY_SECS);
		if trust_expired {
			self.trust = None;
			if Modal::opened() == Some(TRUST_MODAL) {
				Modal::close();
			}
		}
		// Poll the login-callback POST. On success the session is created together
		// with the identity; on failure the whole grant fails (spec 4.3).
		let mut trust_outcome = None;
		if let Some(st) = &self.trust {
			if st.posting {
				trust_outcome = st
					.result
					.lock()
					.unwrap()
					.take()
					.map(|res| (res, st.uri.domain.clone()));
				if trust_outcome.is_none() {
					ui.ctx().request_repaint();
				}
			}
		}
		if let Some((res, domain)) = trust_outcome {
			let st = self.trust.take();
			let text = match (res, st) {
				(Ok(()), Some(st)) => {
					let mut session_added = false;
					if let Some(svc) = wallet.nostr_service() {
						if let (Ok(site_pk), Ok(id_pk)) = (
							nostr_sdk::PublicKey::from_hex(&st.uri.site_session_pubkey),
							nostr_sdk::PublicKey::from_hex(&st.selected),
						) {
							let now = std::time::SystemTime::now()
								.duration_since(std::time::UNIX_EPOCH)
								.map(|d| d.as_secs())
								.unwrap_or(0);
							let session = crate::nostr::session::Session::new(
								st.uri.domain.clone(),
								id_pk,
								st.label.clone(),
								&st.uri.requested_kinds,
								&st.channel,
								site_pk,
								vec![st.uri.relay.clone()],
								now,
							);
							svc.add_session(session);
							session_added = true;
						}
					}
					if session_added {
						// The grant is NOT complete yet: the session-open channel
						// event still has to reach the relay (the service loop
						// publishes it on its next tick). Hold the success toast
						// AND the return-to-caller decision until the announce is
						// confirmed, or the site never learns the session exists
						// (the Build 153 QR-trust bug).
						self.trust_wait = Some(TrustWait {
							channel_pk: st.channel.public_key().to_hex(),
							domain,
							deadline: std::time::Instant::now()
								+ std::time::Duration::from_secs(TRUST_ANNOUNCE_TIMEOUT_SECS),
							want_return: st.uri.return_to_caller,
						});
						ui.ctx().request_repaint();
						None
					} else {
						// No service / bad keys: no session, no announce. Show the
						// login-sent toast (the 22242 POST did succeed) but never
						// return-to-caller on an incomplete grant.
						Some(t!("goblin.trust.sent", domain => domain).to_string())
					}
				}
				(Err(e), _) => {
					log::warn!("trust login callback failed: {e}");
					Some(t!("goblin.trust.failed", domain => domain).to_string())
				}
				(Ok(()), None) => Some(t!("goblin.trust.sent", domain => domain).to_string()),
			};
			if let Some(text) = text {
				self.login_toast = Some((text, std::time::Instant::now()));
			}
		}
		// Wait out the session-open announce: the service loop confirms the
		// publish reached a relay, then (and only then) the grant is complete,
		// the toast shows, and a same-device flow may hand focus back. The
		// repaint keeps frames pumping so the app stays foreground while waiting.
		let mut trust_wait_done = None;
		if let Some(wt) = &self.trust_wait {
			let announced = wallet
				.nostr_service()
				.map(|s| s.session_announced(&wt.channel_pk))
				.unwrap_or(false);
			if announced {
				// Fresh only within the wait window: an announce observed on a
				// late resume (the user backgrounded the wallet themselves) shows
				// the toast but must not bounce them back out.
				let fresh = std::time::Instant::now() < wt.deadline;
				trust_wait_done = Some((true, wt.domain.clone(), wt.want_return && fresh));
			} else if std::time::Instant::now() >= wt.deadline {
				trust_wait_done = Some((false, wt.domain.clone(), wt.want_return));
			} else {
				ui.ctx().request_repaint();
			}
		}
		if let Some((announced, domain, want_return)) = trust_wait_done {
			self.trust_wait = None;
			let text = if announced {
				t!("goblin.trust.sent", domain => domain).to_string()
			} else {
				// Honest: the login went through and the session exists in the
				// wallet, but the site has not confirmably received it.
				log::warn!("trust session-open announce unconfirmed for {domain}");
				t!("goblin.trust.announce_failed", domain => domain).to_string()
			};
			self.login_toast = Some((text, std::time::Instant::now()));
			if crate::nostr::authuri::should_return_to_caller(want_return, Some(true), announced) {
				cb.return_to_caller();
			}
		}

		// A money-tier request arriving over a live session channel raises the
		// per-action approval, every time (never silent). One at a time.
		if self.money.is_none()
			&& self.login.is_none()
			&& self.authorize.is_none()
			&& self.trust.is_none()
		{
			if let Some(pending) = wallet.nostr_service().and_then(|s| s.peek_money_prompt()) {
				self.money = Some(MoneyState {
					pending,
					created: std::time::Instant::now(),
					pass: String::new(),
					wrong_pass: false,
				});
				self.money_hold = w::HoldToSend::default();
				Modal::new(MONEY_MODAL)
					.position(ModalPosition::CenterTop)
					.title(t!("goblin.money.title"))
					.show();
			}
		}
		// An unanswered money prompt times out and declines the action.
		let money_expired = matches!(&self.money, Some(st)
			if st.created.elapsed().as_secs() >= LOGIN_EXPIRY_SECS);
		if money_expired {
			if let (Some(st), Some(svc)) = (self.money.as_ref(), wallet.nostr_service()) {
				svc.answer_money_prompt(st.pending.id(), false);
			}
			self.money = None;
			if Modal::opened() == Some(MONEY_MODAL) {
				Modal::close();
			}
		}
		// A session volume notice surfaces as the quiet toast, with honest wording
		// per capability: heavy DM reading is called out as reading, not signing.
		if let Some(kind) = wallet.nostr_service().and_then(|s| s.take_session_notice()) {
			let text = if kind == "reading" {
				t!("goblin.trust.notice_decrypt").to_string()
			} else {
				t!("goblin.trust.notice_volume").to_string()
			};
			self.login_toast = Some((text, std::time::Instant::now()));
		}
		// Draw the trust and money modals.
		if Modal::opened() == Some(TRUST_MODAL) {
			Modal::ui(ui.ctx(), cb, |ui, modal, cb| {
				self.trust_modal_content(ui, modal, wallet, cb);
			});
		}
		if Modal::opened() == Some(MONEY_MODAL) {
			Modal::ui(ui.ctx(), cb, |ui, modal, cb| {
				self.money_modal_content(ui, modal, wallet, cb);
			});
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
				// Leaving Home re-censors the balance (anonymous mode): the reveal
				// is a per-visit tap, never sticky.
				if self.tab != Tab::Home {
					self.balance_revealed = false;
				}
				w::centered_column(ui, col_width, |ui| match self.tab {
					Tab::Home => self.home_ui(ui, wallet, cb, wide_desktop),
					Tab::Pay => self.pay_ui(ui, wallet, cb),
					Tab::Activity => self.activity_ui(ui, wallet, cb),
					Tab::Receive => self.receive_ui(ui, wallet, cb),
					Tab::Me => self.me_ui(ui, wallet, cb),
				});
			});
		// Transient "press back again" hint (first back at Home; the second
		// goes to the wallet switcher, wallet left unlocked).
		self.back_hint_ui(ui.ctx());
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
											// Transport-aware: Tor states are relay-gated,
											// while a clearnet wallet reads "Connected
											// (direct)" instead of forever "connecting over
											// Tor" (which never flips off-Tor).
											RichText::new(transport_status_label(
												wallet
													.nostr_service()
													.map(|s| s.transport_status())
													.unwrap_or(
														crate::nostr::TransportStatus::ConnectingTor,
													),
											))
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

	/// The user's OWN avatar as shown top-right on the front surfaces (home,
	/// pay). Mode-aware: anonymous mode is the ONLY thing that makes it yellow.
	/// Anon ON → the flat Goblin-yellow censored tile ([`w::avatar_censored`]);
	/// anon OFF → the exact same picture-or-gradient identicon this identity
	/// renders everywhere else ([`w::avatar_any`]). Returns the tap Response so
	/// the caller can route to settings.
	fn avatar_self(&mut self, ui: &mut egui::Ui, wallet: &Wallet, size: f32) -> egui::Response {
		if crate::AppConfig::anonymous_mode() {
			return w::avatar_censored(ui, size);
		}
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
			.unwrap_or_else(|| (t!("goblin.home.anonymous").to_string(), String::new()));
		let tex = self.handle_tex(ui.ctx(), wallet, &handle);
		w::avatar_any(ui, &handle, &npub_hex, size, tex.as_ref())
	}
}

/// Process a picked picture and upload it as the avatar for an owned name.

#[cfg(test)]
mod anon_censor_tests {
	use super::{SettingsPage, Tab, settings_page_after};

	/// Leaving the Settings tab resets the sub-page to the root, so re-entering
	/// always lands on the top-level Settings page. Staying on the Settings tab
	/// preserves the current sub-page (so deep links into a sub-page survive).
	#[test]
	fn settings_nav_resets_to_root_off_settings_tab() {
		// Off the Settings tab: any sub-page collapses to the root.
		for tab in [Tab::Home, Tab::Pay, Tab::Activity, Tab::Receive] {
			assert_eq!(
				settings_page_after(tab, SettingsPage::AdvancedPrivacy),
				SettingsPage::Main
			);
			assert_eq!(
				settings_page_after(tab, SettingsPage::Username),
				SettingsPage::Main
			);
		}
		// On the Settings tab: the current sub-page is preserved.
		assert_eq!(
			settings_page_after(Tab::Me, SettingsPage::Username),
			SettingsPage::Username
		);
		assert_eq!(
			settings_page_after(Tab::Me, SettingsPage::AdvancedPrivacy),
			SettingsPage::AdvancedPrivacy
		);
		assert_eq!(
			settings_page_after(Tab::Me, SettingsPage::Main),
			SettingsPage::Main
		);
	}
}
