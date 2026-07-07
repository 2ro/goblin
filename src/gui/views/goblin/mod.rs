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
}

/// Whether the per-identity cue is drawn on activity rows (owner-approved). The
/// row's main avatar stays the COUNTERPARTY; the cue is a SMALL corner badge on
/// that avatar, filled with the USER's OWN identity gradient for the tx (from
/// `ActivityItem.owner_pubkey`), so a glance clusters which of your identities
/// each payment used. Only shown when the wallet holds more than one identity.
const SHOW_ROW_IDENTITY_CUE: bool = true;

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
	Language,
	Slatepack,
	Privacy,
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
/// confirmed handed to a relay before giving up with an honest toast. The
/// service loop ticks every 2s and the publish itself is bounded by its own
/// send timeout, so this comfortably covers the normal path.
const TRUST_ANNOUNCE_TIMEOUT_SECS: u64 = 15;

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
			self.identity_switch = IdentitySwitchState::default();
			self.login = None;
			self.authorize = None;
			self.login_toast = None;
		}

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
			.id_salt("goblin_home_scroll")
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
							if w::avatar_any(
								ui,
								&header_handle,
								&header_hex,
								40.0,
								header_tex.as_ref(),
							)
							.clicked()
							{
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
			// Official GoblinPay lockup (left): the black Apple-Pay-style badge on
			// light surfaces, the white wordmark on dark. Owner-specified brand mark.
			if t.dark_base {
				ui.add(
					egui::Image::new(egui::include_image!(
						"../../../../img/goblinpay-wordmark.svg"
					))
					.fit_to_exact_size(Vec2::new(84.0, 33.0)),
				);
			} else {
				ui.add(
					egui::Image::new(egui::include_image!(
						"../../../../img/goblinpay-badge-black.svg"
					))
					.fit_to_exact_size(Vec2::new(98.0, 40.0)),
				);
			}
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
			if let Some(preview) = pairing_preview(grin, ui.ctx()) {
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
						.id_salt("goblin_receipt_scroll")
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

	/// List-row timestamp: date + HH:MM, no seconds. The tap-in detail view keeps
	/// the full timestamp to the second (see [`View::format_time`]).
	fn list_time(ts: i64) -> String {
		let utc_offset = chrono::Local::now().offset().local_minus_utc();
		chrono::DateTime::from_timestamp(ts + utc_offset as i64, 0)
			.map(|t| t.format("%d/%m/%Y %H:%M").to_string())
			.unwrap_or_default()
	}

	/// The (left message, right timestamp) an [`ActivityItem`] shows in a row. The
	/// timestamp (no seconds) is only set for a confirmed tx; otherwise the status
	/// word (canceled/pending) folds into the message so a row with no time still
	/// reads its state without an empty right-side time slot.
	fn activity_note_time(item: &ActivityItem) -> (String, String) {
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

	fn activity_item_ui(
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
		let amount = format!("{}{}{}", sign, w::amount_str(item.amount), w::TSU);
		let (note, time) = Self::activity_note_time(item);
		let tex = self.handle_tex(ui.ctx(), wallet, &item.title);
		let resp = w::activity_row(
			ui,
			&item.title,
			&note,
			&time,
			item.npub.as_deref().unwrap_or(""),
			&amount,
			item.incoming,
			item.canceled,
			item.system,
			tex.as_ref(),
		);
		// Per-identity cue (owner-approved): only when the wallet holds MORE THAN
		// ONE identity, and never on system (mining) rows. A small corner badge on
		// the counterparty avatar, filled with the identity THIS tx used (its own
		// gradient; falls back to the primary for pre-feature rows). The row avatar
		// is 40px, flush to the row's left and vertically centred, so its
		// bottom-right corner is at (left+40, mid+20); the badge overhangs that
		// corner by ~4px (matching the mock's right:-4/bottom:-4, 14px badge).
		if SHOW_ROW_IDENTITY_CUE && id_cue.multi && !item.system {
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

	fn request_row_ui(
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
			SettingsPage::Language => return self.language_settings_ui(ui),
			SettingsPage::Slatepack => return self.slatepack_ui(ui, wallet, cb),
			SettingsPage::Privacy => return self.privacy_ui(ui),
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
				let mut open_slatepack = false;
				let mut open_trusted = false;
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
					// Trusted Sites: the active Authorize Sessions, with a one-tap
					// end. Shows the live count as the row value.
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
					// Hide received amounts in payment notifications/alerts. Same
					// switch widget as the incoming-requests toggle below.
					if let Some(v) = settings_row_toggle(
						ui,
						&t!("goblin.settings.hide_amounts"),
						&t!("goblin.settings.hide_amounts_sub"),
						crate::AppConfig::hide_amounts(),
					) {
						crate::AppConfig::set_hide_amounts(v);
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
			.id_salt("goblin_pairing_scroll")
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

	/// Language picker: the six shipped locales, each in its own name. Tapping one
	/// switches the active locale and persists it (mirrors the GRIM interface
	/// settings, but in Goblin's row style like the pairing picker).
	fn language_settings_ui(&mut self, ui: &mut egui::Ui) {
		let t = theme::tokens();
		if self.sub_header(ui, &t!("goblin.settings.language")) {
			self.settings_page = SettingsPage::Main;
			return;
		}
		let current = crate::AppConfig::locale().unwrap_or_else(|| rust_i18n::locale().to_string());
		ScrollArea::vertical()
			.id_salt("goblin_language_scroll")
			.auto_shrink([false; 2])
			.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
			.show(ui, |ui| {
				settings_group(ui, &t!("goblin.settings.language"), |ui| {
					for locale in rust_i18n::available_locales!() {
						let active = current == locale;
						let row = ui.horizontal(|ui| {
							ui.label(
								RichText::new(t!("lang_name", locale = locale))
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
							rust_i18n::set_locale(locale);
							crate::AppConfig::save_locale(locale);
						}
					}
				});
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
			.id_salt("goblin_privacy_scroll")
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
		let mut open_integrated = false;
		{
			let adv = &mut self.advanced;
			ScrollArea::vertical()
				.id_salt("goblin_advanced_scroll")
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
			.id_salt("goblin_node_scroll")
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
				// (The integrated-node tabs' single home is Settings → Advanced;
				// no duplicate entry here.)
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
			.id_salt("goblin_relays_scroll")
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
			.id_salt("goblin_slatepack_scroll")
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
			.id_salt("goblin_nips_scroll")
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
							// Secret: auto-clears from the clipboard after a delay
							// (compare-then-clear) so it does not linger there.
							cb.copy_secret_to_buffer(nsec);
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

	/// The identity switcher page: one wallet, one grin balance, many nostr
	/// identities. Lists the held identities (tap to make one active), and adds a
	/// new one (generate a fresh nsec or import an existing one). Switching runs a
	/// catch-up so payments that arrived while an identity was dormant land in the
	/// single shared balance; the syncing / "you were paid while away" state shows
	/// here. The wallet password (entered once on this page) unlocks a target on
	/// switch and encrypts a new identity on add — every held nsec is stored the
	/// same way: its own NIP-49 ncryptsec under the wallet password.
	fn identities_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet, cb: &dyn PlatformCallbacks) {
		let t = theme::tokens();
		if self.sub_header(ui, &t!("goblin.identities.title")) {
			self.settings_page = SettingsPage::Main;
			self.identity_switch = IdentitySwitchState::default();
			return;
		}
		// Poll the background switch/add worker.
		if self.identity_switch.busy
			&& let Some(res) = self.identity_switch.result.lock().unwrap().take()
		{
			self.identity_switch.busy = false;
			match res {
				Ok(_) => {
					self.identity_switch.error.clear();
					self.identity_switch.adding = false;
					self.identity_switch.import = false;
					self.identity_switch.nsec.clear();
					self.identity_switch.backup_input.clear();
					self.identity_switch.confirm_delete = None;
				}
				Err(e) => {
					self.identity_switch.error = e;
				}
			}
		}

		// Wallet-password modal — the unlock step for ADDING an identity only
		// (switching is instant and local, no password), mirroring the wallet-open
		// password modal (dimmed backdrop, same buttons).
		if Modal::opened() == Some(IDENTITY_PASS_MODAL) {
			Modal::ui(ui.ctx(), cb, |ui, modal, cb| {
				self.identity_pass_modal_content(ui, modal, wallet, cb);
			});
		}
		// Per-identity management modal (rename / delete): dims and locks the
		// list, disabling switching and row taps until it closes.
		if Modal::opened() == Some(IDENTITY_MANAGE_MODAL) {
			Modal::ui(ui.ctx(), cb, |ui, _modal, cb| {
				self.identity_manage_modal_content(ui, wallet, cb);
			});
		}
		// Step-1 delete confirmation modal (danger text), also background-locking.
		if Modal::opened() == Some(IDENTITY_DELETE_MODAL) {
			Modal::ui(ui.ctx(), cb, |ui, _modal, _cb| {
				self.identity_delete_modal_content(ui, wallet);
			});
		}

		let identities = wallet.nostr_identities();

		ScrollArea::vertical()
			.id_salt("goblin_identities_scroll")
			.auto_shrink([false; 2])
			.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
			.show(ui, |ui| {
				ui.label(
					RichText::new(t!("goblin.identities.blurb"))
						.font(FontId::new(13.5, fonts::regular()))
						.color(t.text_dim),
				);
				ui.add_space(8.0);
				ui.label(
					RichText::new(t!("goblin.identities.privacy_note"))
						.font(FontId::new(12.0, fonts::regular()))
						.color(t.text_mute),
				);
				ui.add_space(14.0);

				// Held identities. Tap a non-active one to switch to it INSTANTLY —
				// all identities are already unlocked and listening, so a switch is a
				// local change of which one is presented and used for sending.
				w::kicker(ui, &t!("goblin.identities.held"));
				ui.add_space(8.0);
				let busy = self.identity_switch.busy;
				let mut switch_to: Option<String> = None;
				let mut manage_target: Option<String> = None;
				for id in &identities {
					// Display precedence: private tag, else claimed name (bare, no
					// leading @), else truncated npub. Never a placeholder word.
					let short = data::short_npub(&id.pubkey_hex);
					let title = id.display();
					let mut pencil_hit = false;
					let row = w::card(ui, |ui| {
						ui.set_min_width(ui.available_width());
						ui.horizontal(|ui| {
							w::avatar_any(ui, &title, &id.pubkey_hex, 40.0, None);
							ui.add_space(12.0);
							ui.vertical(|ui| {
								ui.label(
									RichText::new(&title)
										.font(FontId::new(15.0, fonts::semibold()))
										.color(t.surface_text),
								);
								// The npub underneath, unless the title already IS the
								// npub (unnamed, untagged identity).
								if title != short {
									ui.label(
										RichText::new(&short)
											.font(FontId::new(12.0, fonts::regular()))
											.color(t.surface_text_mute),
									);
								}
							});
							ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
								if id.active {
									ui.label(
										RichText::new(crate::gui::icons::CHECK_CIRCLE)
											.font(FontId::new(18.0, fonts::regular()))
											.color(t.pos),
									);
								} else {
									ui.label(
										RichText::new(crate::gui::icons::ARROWS_LEFT_RIGHT)
											.font(FontId::new(16.0, fonts::regular()))
											.color(t.surface_text_dim),
									);
								}
								// Edit (pencil) affordance: opens the per-identity
								// management sheet (rename / delete). Its own tap target
								// so it never triggers the row switch.
								if !busy {
									ui.add_space(8.0);
									let (r, resp) =
										ui.allocate_exact_size(Vec2::splat(28.0), Sense::click());
									ui.painter().text(
										r.center(),
										egui::Align2::CENTER_CENTER,
										crate::gui::icons::PENCIL_SIMPLE,
										FontId::new(16.0, fonts::regular()),
										t.surface_text_dim,
									);
									if resp
										.on_hover_cursor(egui::CursorIcon::PointingHand)
										.clicked()
									{
										pencil_hit = true;
									}
								}
							});
						})
						.response
						.rect
					});
					// Tap anywhere else on a non-active row = INSTANT switch (skip
					// when the pencil was tapped, whose rect overlaps the row).
					if !id.active && !busy {
						let hit = ui.interact(
							row,
							egui::Id::new(("id_switch", id.pubkey_hex.as_str())),
							Sense::click(),
						);
						if !pencil_hit
							&& hit
								.on_hover_cursor(egui::CursorIcon::PointingHand)
								.clicked()
						{
							switch_to = Some(id.pubkey_hex.clone());
						}
					}
					if pencil_hit {
						manage_target = Some(id.pubkey_hex.clone());
					}
					ui.add_space(6.0);
				}

				// Tapping a held identity switches to it INSTANTLY — no password, no
				// sync (it was already unlocked and listening). Purely local.
				if let Some(target) = switch_to {
					self.identity_switch.error.clear();
					if let Err(e) = wallet.switch_nostr_identity(target) {
						self.identity_switch.error = e;
					}
				}
				// The pencil opens the management MODAL, pre-filled with the tag and
				// titled with the identity it manages. The GRIM Modal dims and locks
				// the list behind it, so no switching or row taps while it is open.
				if let Some(target) = manage_target {
					self.identity_switch.error.clear();
					self.identity_switch.confirm_delete = None;
					let display = identities
						.iter()
						.find(|i| i.pubkey_hex == target)
						.map(|i| i.display())
						.unwrap_or_else(|| data::short_npub(&target));
					self.identity_switch.tag_input = identities
						.iter()
						.find(|i| i.pubkey_hex == target)
						.and_then(|i| i.tag.clone())
						.unwrap_or_default();
					self.identity_switch.manage = Some(target);
					Modal::new(IDENTITY_MANAGE_MODAL)
						.position(ModalPosition::CenterTop)
						.title(display)
						.show();
				}

				ui.add_space(8.0);

				// Add-identity section.
				if !self.identity_switch.adding {
					if w::big_action(ui, &t!("goblin.identities.add"), false).clicked() {
						self.identity_switch.adding = true;
						self.identity_switch.error.clear();
					}
				} else {
					w::card(ui, |ui| {
						ui.set_min_width(ui.available_width());
						ui.label(
							RichText::new(t!("goblin.identities.add_title"))
								.font(FontId::new(15.0, fonts::semibold()))
								.color(t.surface_text),
						);
						ui.add_space(8.0);
						// The sheet defaults to GENERATE (a fresh anonymous key). What
						// generating means, in one line, so the default mode isn't blank.
						if !self.identity_switch.import {
							ui.label(
								RichText::new(t!("goblin.identities.generate_note"))
									.font(FontId::new(12.5, fonts::regular()))
									.color(t.surface_text_dim),
							);
						}
						if self.identity_switch.import {
							ui.add_space(8.0);
							// (a) Select a .backup file. Desktop returns the path now;
							// Android returns it asynchronously (poll picked_file()).
							if self.identity_switch.picking {
								if let Some(path) = cb.picked_file() {
									self.identity_switch.picking = false;
									if !path.is_empty() {
										match std::fs::read_to_string(&path) {
											Ok(c) => {
												self.identity_switch.backup_input =
													c.trim().to_string()
											}
											Err(_) => {
												self.identity_switch.error =
													t!("goblin.settings.backup_read_failed")
														.to_string()
											}
										}
									}
								} else {
									ui.ctx().request_repaint();
								}
							}
							let file_label = if self.identity_switch.backup_input.is_empty() {
								t!("goblin.identities.choose_backup").to_string()
							} else {
								t!("goblin.identities.backup_selected").to_string()
							};
							if w::big_action_on_card(ui, &file_label).clicked() {
								self.identity_switch.error.clear();
								match cb.pick_file() {
									Some(path) if !path.is_empty() => {
										match std::fs::read_to_string(&path) {
											Ok(c) => {
												self.identity_switch.backup_input =
													c.trim().to_string()
											}
											Err(_) => {
												self.identity_switch.error =
													t!("goblin.settings.backup_read_failed")
														.to_string()
											}
										}
									}
									Some(_) => self.identity_switch.picking = true,
									None => {}
								}
							}
							ui.add_space(8.0);
							// (b) Or paste an nsec.
							w::field_well(ui, |ui| {
								TextEdit::new(egui::Id::from("identity_add_nsec"))
									.focus(false)
									.hint_text(t!("goblin.identities.nsec_hint"))
									.password()
									.text_color(t.surface_text)
									.body()
									.ui(ui, &mut self.identity_switch.nsec, cb);
							});
						}
						ui.add_space(10.0);
						let import = self.identity_switch.import;
						let busy = self.identity_switch.busy;
						// Two real actions instead of a mode toggle: Generate is always
						// ready; Import first reveals the .backup/nsec inputs, then
						// confirms once one of them is filled. The password is entered
						// in the modal.
						let has_import = !self.identity_switch.backup_input.trim().is_empty()
							|| self.identity_switch.nsec.trim().starts_with("nsec1");
						let import_armed = (!import || has_import) && !busy;
						// The password-gated add to launch this frame: `Some(None)` for
						// a fresh key, `Some(Some(blob))` for an import.
						let mut open_add: Option<Option<String>> = None;
						ui.horizontal(|ui| {
							let half = (ui.available_width() - 10.0) / 2.0;
							// Generate on the LEFT, the positive (green) action: a
							// fresh anonymous key via the existing password step.
							ui.scope_builder(
								egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
									ui.cursor().min,
									Vec2::new(half, 44.0),
								)),
								|ui| {
									ui.add_enabled_ui(!busy, |ui| {
										if w::big_action_on_card_ink(
											ui,
											&t!("goblin.identities.generate"),
											if busy { t.surface_text_mute } else { t.pos },
										)
										.clicked()
										{
											open_add = Some(None);
										}
									});
								},
							);
							ui.add_space(10.0);
							// Import on the RIGHT, neutral: reveal-then-confirm.
							ui.scope_builder(
								egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
									ui.cursor().min,
									Vec2::new(half, 44.0),
								)),
								|ui| {
									ui.add_enabled_ui(import_armed, |ui| {
										if w::big_action_on_card_ink(
											ui,
											&t!("goblin.identities.import"),
											if import_armed {
												t.surface_text
											} else {
												t.surface_text_mute
											},
										)
										.clicked()
										{
											if !import {
												// First tap: reveal the import inputs.
												self.identity_switch.import = true;
												self.identity_switch.error.clear();
											} else {
												// Confirm: the selected .backup wins over
												// a pasted nsec.
												let b = self.identity_switch.backup_input.trim();
												let blob = if b.is_empty() {
													self.identity_switch.nsec.trim().to_string()
												} else {
													b.to_string()
												};
												open_add = Some(Some(blob));
											}
										}
									});
								},
							);
						});
						// Cancel centered BENEATH the pair: red, same uniform size.
						ui.add_space(10.0);
						ui.horizontal(|ui| {
							let half = (ui.available_width() - 10.0) / 2.0;
							ui.add_space((ui.available_width() - half) / 2.0);
							ui.scope_builder(
								egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
									ui.cursor().min,
									Vec2::new(half, 44.0),
								)),
								|ui| {
									if w::big_action_on_card_ink(
										ui,
										&t!("goblin.settings.cancel"),
										t.neg,
									)
									.clicked()
									{
										self.identity_switch.adding = false;
										self.identity_switch.import = false;
										self.identity_switch.nsec.clear();
										self.identity_switch.backup_input.clear();
										self.identity_switch.error.clear();
									}
								},
							);
						});
						if let Some(import_blob) = open_add {
							// Open the password modal to encrypt+store the new
							// identity. It is added WITHOUT switching; the user
							// activates it later by tapping it.
							self.identity_switch.error.clear();
							self.identity_switch.pass.clear();
							self.identity_switch.wrong_pass = false;
							self.identity_switch.pending =
								Some(PendingPassAction::Add(import_blob));
							Modal::new(IDENTITY_PASS_MODAL)
								.position(ModalPosition::CenterTop)
								.title(t!("goblin.identities.add_title"))
								.show();
						}
					});
				}

				if self.identity_switch.busy {
					ui.add_space(10.0);
					ui.horizontal(|ui| {
						View::small_loading_spinner(ui);
						ui.add_space(8.0);
						ui.label(
							RichText::new(t!("goblin.identities.working"))
								.font(FontId::new(13.0, fonts::regular()))
								.color(t.surface_text_dim),
						);
					});
					ui.ctx().request_repaint();
				}
				if !self.identity_switch.error.is_empty() {
					ui.add_space(8.0);
					ui.label(
						RichText::new(&self.identity_switch.error)
							.font(FontId::new(12.5, fonts::regular()))
							.color(t.neg),
					);
				}
				ui.add_space(24.0);
			});
	}

	/// Content of the wallet-password modal that gates ADDING an identity (encrypt
	/// + store its new nsec). Switching no longer uses this — it is instant and
	/// local. Mirrors the wallet-open password modal (open.rs): explanation, masked
	/// field, wrong-password line, Cancel/Continue. A correct password is verified
	/// synchronously before the add worker is spawned, so a wrong password stays in
	/// the modal instead of failing later.
	fn identity_pass_modal_content(
		&mut self,
		ui: &mut egui::Ui,
		modal: &Modal,
		wallet: &Wallet,
		cb: &dyn PlatformCallbacks,
	) {
		let mut go = false;
		let mut cancel = false;
		ui.vertical_centered(|ui| {
			ui.add_space(6.0);
			ui.label(
				RichText::new(t!("goblin.identities.pass_prompt"))
					.size(16.0)
					.color(Colors::gray()),
			);
			ui.add_space(10.0);
			let mut field = TextEdit::new(egui::Id::from(modal.id).with("id_pass")).password();
			field.ui(ui, &mut self.identity_switch.pass, cb);
			if field.enter_pressed {
				go = true;
			}
			if self.identity_switch.pass.is_empty() {
				self.identity_switch.wrong_pass = false;
			} else if self.identity_switch.wrong_pass {
				ui.add_space(10.0);
				ui.label(
					RichText::new(t!("goblin.advanced.wrong_password"))
						.size(16.0)
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
							cancel = true;
						},
					);
				});
				columns[1].vertical_centered_justified(|ui| {
					View::button(ui, t!("continue"), Colors::white_or_black(false), || {
						go = true;
					});
				});
			});
			ui.add_space(6.0);
		});
		if cancel {
			self.identity_switch.pass.clear();
			self.identity_switch.pending = None;
			self.identity_switch.wrong_pass = false;
			Modal::close();
		}
		if go && !self.identity_switch.pass.is_empty() {
			if !wallet.verify_nostr_password(&self.identity_switch.pass) {
				self.identity_switch.wrong_pass = true;
			} else if let Some(action) = self.identity_switch.pending.take() {
				let password = std::mem::take(&mut self.identity_switch.pass);
				self.identity_switch.wrong_pass = false;
				self.identity_switch.error.clear();
				self.identity_switch.busy = true;
				let slot = self.identity_switch.result.clone();
				let w = wallet.clone();
				std::thread::spawn(move || {
					let r = match action {
						// Add only — never auto-switch into the new identity.
						PendingPassAction::Add(import) => w.add_nostr_identity(import, password),
						// Delete returns the surviving active npub for the result slot.
						PendingPassAction::Delete(hex) => w
							.delete_nostr_identity(hex, password)
							.map(|_| String::new()),
					};
					*slot.lock().unwrap() = Some(r);
				});
				Modal::close();
			}
		}
	}

	/// Content of the per-identity management MODAL (title = the identity's
	/// display name). Rename (the private, app-only tag — never published) on
	/// top with uniform paired Cancel/Save buttons; Delete at the bottom,
	/// separated and red, feeding the delete-confirmation modal. Being a GRIM
	/// Modal, the identity list behind it is dimmed and locked.
	fn identity_manage_modal_content(
		&mut self,
		ui: &mut egui::Ui,
		wallet: &Wallet,
		cb: &dyn PlatformCallbacks,
	) {
		let Some(target) = self.identity_switch.manage.clone() else {
			Modal::close();
			return;
		};
		ui.vertical_centered(|ui| {
			ui.add_space(6.0);
			ui.label(
				RichText::new(t!("goblin.identities.tag_note"))
					.size(16.0)
					.color(Colors::gray()),
			);
			ui.add_space(10.0);
			let mut field = TextEdit::new(egui::Id::from(IDENTITY_MANAGE_MODAL).with("tag"))
				.hint_text(t!("goblin.identities.tag_hint"));
			field.ui(ui, &mut self.identity_switch.tag_input, cb);
			ui.add_space(12.0);
		});
		let mut save = false;
		let mut cancel = false;
		let mut delete = false;
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
						t!("goblin.identities.tag_save"),
						Colors::white_or_black(false),
						|| {
							save = true;
						},
					);
				});
			});
			// Delete lives at the bottom, clearly apart from rename, red, same
			// button shape. Only while more than one identity is held.
			if wallet.nostr_identities().len() > 1 {
				ui.add_space(10.0);
				ui.vertical_centered_justified(|ui| {
					View::colored_text_button(
						ui,
						t!("goblin.identities.delete_short").to_string(),
						Colors::red(),
						Colors::white_or_black(false),
						|| {
							delete = true;
						},
					);
				});
			}
			ui.add_space(6.0);
		});
		if cancel {
			self.identity_switch.manage = None;
			self.identity_switch.tag_input.clear();
			Modal::close();
		}
		if save {
			let tag = std::mem::take(&mut self.identity_switch.tag_input);
			if let Err(e) = wallet.rename_nostr_identity(target.clone(), tag) {
				self.identity_switch.error = e;
			}
			self.identity_switch.manage = None;
			Modal::close();
		}
		if delete {
			// Step 1 of the delete gate: the danger-confirmation modal.
			self.identity_switch.manage = None;
			self.identity_switch.confirm_delete = Some(target.clone());
			let display = wallet
				.nostr_identities()
				.iter()
				.find(|i| i.pubkey_hex == target)
				.map(|i| i.display())
				.unwrap_or_else(|| data::short_npub(&target));
			Modal::close();
			Modal::new(IDENTITY_DELETE_MODAL)
				.position(ModalPosition::CenterTop)
				.title(display)
				.show();
		}
	}

	/// Content of the step-1 delete-confirmation MODAL (title = the identity's
	/// display name): states the removal is PERMANENT with a prominent back-up
	/// reminder, then uniform paired Cancel/Delete buttons — Delete red, same
	/// size and shape. Confirming opens the wallet-password modal (step 2).
	fn identity_delete_modal_content(&mut self, ui: &mut egui::Ui, wallet: &Wallet) {
		let Some(target) = self.identity_switch.confirm_delete.clone() else {
			Modal::close();
			return;
		};
		let display = wallet
			.nostr_identities()
			.iter()
			.find(|i| i.pubkey_hex == target)
			.map(|i| i.display())
			.unwrap_or_else(|| data::short_npub(&target));
		ui.vertical_centered(|ui| {
			ui.add_space(6.0);
			ui.label(
				RichText::new(t!("goblin.identities.delete_title", name => display))
					.size(17.0)
					.color(Colors::red()),
			);
			ui.add_space(8.0);
			ui.label(
				RichText::new(t!("goblin.identities.delete_blurb"))
					.size(15.0)
					.color(Colors::gray()),
			);
			ui.add_space(8.0);
			ui.label(
				RichText::new(t!("goblin.identities.delete_backup_note"))
					.size(15.0)
					.color(Colors::red()),
			);
			ui.add_space(12.0);
		});
		let mut cancel = false;
		let mut confirm = false;
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
					View::colored_text_button(
						ui,
						t!("goblin.identities.delete_confirm").to_string(),
						Colors::red(),
						Colors::white_or_black(false),
						|| {
							confirm = true;
						},
					);
				});
			});
			ui.add_space(6.0);
		});
		if cancel {
			self.identity_switch.confirm_delete = None;
			Modal::close();
		}
		if confirm {
			// Step 2: the wallet-password modal executes the delete.
			self.identity_switch.pass.clear();
			self.identity_switch.wrong_pass = false;
			self.identity_switch.pending = Some(PendingPassAction::Delete(target));
			Modal::close();
			Modal::new(IDENTITY_PASS_MODAL)
				.position(ModalPosition::CenterTop)
				.title(t!("goblin.identities.delete_short"))
				.show();
		}
	}

	/// Content of the minimum-confirmations edit modal — a direct port of GRIM's
	/// min_conf_modal_ui (numeric input, invalid-value error, Cancel/Save). The
	/// saved value persists in WalletConfig::min_confirmations and feeds the
	/// wallet's spendable/send logic on the next balance refresh.
	fn min_conf_modal_content(
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
	fn batch_invoice_modal_content(&mut self, ui: &mut egui::Ui, wallet: &Wallet) {
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

	/// Content of the "Sign in with Goblin" approval modal: the requesting
	/// domain up top, the signing identity (a picker when several are held;
	/// the truncated npub is always visible as the anchor), a one-line plain
	/// explanation, the wallet password, and uniform paired Cancel / Sign in
	/// buttons. Approving signs the one-time kind-22242 challenge with the
	/// CHOSEN identity's key and POSTs it to the callback off the UI thread;
	/// a wrong password stays in the modal without consuming the request.
	fn login_modal_content(
		&mut self,
		ui: &mut egui::Ui,
		modal: &Modal,
		wallet: &Wallet,
		cb: &dyn PlatformCallbacks,
	) {
		let Some(st) = self.login.as_mut() else {
			Modal::close();
			return;
		};
		if st.posting {
			// Already signed and in flight; nothing left to gate here.
			Modal::close();
			return;
		}
		let domain = st.uri.domain.clone();
		let identities = wallet.nostr_identities();
		let mut go = false;
		let mut cancel = false;
		ui.vertical_centered(|ui| {
			ui.add_space(6.0);
			// Headline with the requesting domain prominent.
			ui.label(
				RichText::new(t!("goblin.login.headline", domain => domain.clone()))
					.size(17.0)
					.color(Colors::title(false)),
			);
			ui.add_space(10.0);
			// The signing identity. Display precedence is the switcher's:
			// private tag, else bare claimed name, else truncated npub — and
			// the truncated npub is ALWAYS shown as the anchor.
			ui.label(
				RichText::new(t!("goblin.login.identity"))
					.size(13.0)
					.color(Colors::gray()),
			);
			ui.add_space(6.0);
			if identities.len() > 1 {
				// Identity picker: the held-identities list, tap to choose
				// which one signs. Defaults to the active identity.
				for id in &identities {
					let selected = st.selected == id.pubkey_hex;
					let title = id.display();
					let short = data::short_npub(&id.pubkey_hex);
					let row = ui
						.scope(|ui| {
							ui.horizontal(|ui| {
								ui.add_space(4.0);
								ui.label(
									RichText::new(if selected {
										crate::gui::icons::CHECK_CIRCLE
									} else {
										crate::gui::icons::CIRCLE
									})
									.size(18.0)
									.color(if selected {
										Colors::green()
									} else {
										Colors::gray()
									}),
								);
								ui.add_space(8.0);
								ui.vertical(|ui| {
									if title != short {
										ui.label(
											RichText::new(&title)
												.size(15.0)
												.color(Colors::text(false)),
										);
									}
									ui.label(
										RichText::new(&short).size(12.5).color(Colors::gray()),
									);
								});
							});
						})
						.response
						.rect;
					let hit = ui.interact(
						row,
						egui::Id::from(modal.id).with(("login_id", id.pubkey_hex.as_str())),
						Sense::click(),
					);
					if hit
						.on_hover_cursor(egui::CursorIcon::PointingHand)
						.clicked()
					{
						st.selected = id.pubkey_hex.clone();
					}
					ui.add_space(4.0);
				}
			} else if let Some(id) = identities.first() {
				let title = id.display();
				let short = data::short_npub(&id.pubkey_hex);
				if title != short {
					ui.label(RichText::new(&title).size(15.0).color(Colors::text(false)));
				}
				ui.label(RichText::new(&short).size(12.5).color(Colors::gray()));
			}
			ui.add_space(10.0);
			// One plain line on what approving does (and does not do).
			ui.label(
				RichText::new(t!("goblin.login.explain"))
					.size(13.0)
					.color(Colors::gray()),
			);
			ui.add_space(10.0);
			// The wallet password gates the signature, mirroring the identity
			// password modal (masked field, same wrong-password line).
			ui.label(
				RichText::new(t!("goblin.login.pass_prompt"))
					.size(16.0)
					.color(Colors::gray()),
			);
			ui.add_space(10.0);
			let mut field = TextEdit::new(egui::Id::from(modal.id).with("login_pass")).password();
			field.ui(ui, &mut st.pass, cb);
			if field.enter_pressed {
				go = true;
			}
			if st.pass.is_empty() {
				st.wrong_pass = false;
			} else if st.wrong_pass {
				ui.add_space(10.0);
				ui.label(
					RichText::new(t!("goblin.advanced.wrong_password"))
						.size(16.0)
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
							cancel = true;
						},
					);
				});
				columns[1].vertical_centered_justified(|ui| {
					View::button(
						ui,
						t!("goblin.login.confirm"),
						Colors::white_or_black(false),
						|| {
							go = true;
						},
					);
				});
			});
			ui.add_space(6.0);
		});
		if cancel {
			// Cancel drops the request: it is single-use, no retry.
			self.login = None;
			Modal::close();
			return;
		}
		if go {
			let (pass, selected) = match self.login.as_ref() {
				Some(st) => (st.pass.clone(), st.selected.clone()),
				None => return,
			};
			if pass.is_empty() {
				return;
			}
			if !wallet.verify_nostr_password(&pass) {
				// Wrong password: stay in the modal, request NOT consumed.
				if let Some(st) = self.login.as_mut() {
					st.wrong_pass = true;
				}
				return;
			}
			// The chosen identity's unlocked in-memory keys, from the running
			// service (the Build-145 model: every held identity is unlocked).
			let keys = wallet.nostr_service().and_then(|s| {
				s.recv_snapshot()
					.into_iter()
					.find(|h| h.keys.public_key().to_hex() == selected)
					.map(|h| h.keys)
			});
			let Some(keys) = keys else {
				// No running service / identity gone: drop the request.
				self.login = None;
				Modal::close();
				return;
			};
			let st = self.login.as_mut().unwrap();
			st.pass.clear();
			st.wrong_pass = false;
			match crate::nostr::loginuri::build_login_event(
				&keys,
				&st.uri.challenge,
				&st.uri.domain,
			) {
				Ok(event) => {
					// Signed: the request is consumed from here on, whatever
					// the POST outcome. Deliver off the UI thread with the
					// shared HTTP client and a hard timeout.
					st.posting = true;
					let callback = st.uri.callback.clone();
					let slot = st.result.clone();
					std::thread::spawn(move || {
						let res = match tokio::runtime::Builder::new_current_thread()
							.enable_all()
							.build()
						{
							Ok(rt) => rt.block_on(async {
								let post =
									crate::nostr::loginuri::post_login_event(&callback, &event);
								match tokio::time::timeout(
									std::time::Duration::from_secs(LOGIN_POST_TIMEOUT_SECS),
									post,
								)
								.await
								{
									Ok(r) => r,
									Err(_) => Err("timeout".to_string()),
								}
							}),
							Err(e) => Err(e.to_string()),
						};
						*slot.lock().unwrap() = Some(res);
					});
					Modal::close();
					// The return-to-caller decision is DEFERRED to the outcome
					// poll: returning now would background the app with the POST
					// still in flight, stop the frame pump, and strand the
					// completion work (the Build 153 QR-trust bug). The app stays
					// foreground (frames pumping) until the POST result lands.
				}
				Err(e) => {
					// Signing failed (never expected): consume the request and
					// surface the quiet failure toast.
					log::error!("login event signing failed: {e}");
					self.login_toast = Some((
						t!("goblin.login.failed", domain => domain).to_string(),
						std::time::Instant::now(),
					));
					self.login = None;
					Modal::close();
				}
			}
		}
	}

	/// The "Authorize with Goblin" approval modal: headline, the rendered event
	/// (kind label, escaped content preview with an optional show-full view, and
	/// per-kind key-tag summary), the identity picker, the password gate, and the
	/// Cancel/Authorize buttons. Mirrors [`Self::login_modal_content`]; on
	/// confirm it signs one event with the chosen identity and POSTs it off the
	/// UI thread. Signed = consumed, whatever the POST outcome.
	fn authorize_modal_content(
		&mut self,
		ui: &mut egui::Ui,
		modal: &Modal,
		wallet: &Wallet,
		cb: &dyn PlatformCallbacks,
	) {
		use crate::nostr::authuri;
		let Some(st) = self.authorize.as_mut() else {
			Modal::close();
			return;
		};
		if st.posting {
			// Already signed and in flight; nothing left to gate here.
			Modal::close();
			return;
		}
		let domain = st.uri.domain.clone();
		// Clone the small template once so the read-only render borrows nothing
		// from `st` while its password/show-full fields are mutated below.
		let template = st.uri.template.clone();
		let kind = template.kind;
		let label = authuri::kind_label(kind);
		let (preview, remaining) = authuri::content_preview(&template.content);
		let preview_esc = authuri::escape_for_display(&preview);
		let full_esc = authuri::escape_for_display(&template.content);
		// Key tags, all escaped before display.
		let e_tag = template
			.first_tag_value("e")
			.map(|v| authuri::escape_for_display(&authuri::truncate_id(v)));
		let p_tag = template
			.first_tag_value("p")
			.map(|v| authuri::escape_for_display(&authuri::truncate_id(v)));
		let title = template
			.first_tag_value("title")
			.map(authuri::escape_for_display);
		let identities = wallet.nostr_identities();
		let mut go = false;
		let mut cancel = false;
		ui.vertical_centered(|ui| {
			ui.add_space(6.0);
			// Headline with the requesting domain prominent.
			ui.label(
				RichText::new(t!("goblin.authorize.headline", domain => domain.clone()))
					.size(17.0)
					.color(Colors::title(false)),
			);
			ui.add_space(10.0);
			// The plain-language kind label (and, for an off-allowlist kind that
			// v1 cannot actually reach, a caution line).
			let kind_text = match label {
				authuri::KindLabel::Post => t!("goblin.authorize.kind_post"),
				authuri::KindLabel::Repost => t!("goblin.authorize.kind_repost"),
				authuri::KindLabel::Reaction => t!("goblin.authorize.kind_reaction"),
				authuri::KindLabel::Article => t!("goblin.authorize.kind_article"),
				authuri::KindLabel::Unknown => {
					t!("goblin.authorize.kind_unknown", n => kind.to_string())
				}
			};
			ui.label(
				RichText::new(kind_text)
					.size(15.0)
					.color(Colors::text(false)),
			);
			if label == authuri::KindLabel::Unknown {
				ui.add_space(4.0);
				ui.label(
					RichText::new(t!("goblin.authorize.unknown_caution", domain => domain.clone()))
						.size(12.5)
						.color(Colors::red()),
				);
			}
			ui.add_space(8.0);
			// Per-kind rendering of the event body and its key tags. All
			// requester-controlled text is escaped before it hits a label.
			let show_preview = |ui: &mut egui::Ui| {
				if !preview_esc.is_empty() {
					ui.label(RichText::new(&preview_esc).size(13.5).color(Colors::gray()));
				}
			};
			match kind {
				7 => {
					// Reaction: the reaction glyph (emoji or "+"), then target.
					let reaction = if full_esc.is_empty() {
						"+".to_string()
					} else {
						full_esc.clone()
					};
					ui.label(
						RichText::new(reaction)
							.size(20.0)
							.color(Colors::text(false)),
					);
					ui.add_space(4.0);
					if let Some(id) = &e_tag {
						ui.label(
							RichText::new(t!("goblin.authorize.reacts_to", id => id.clone()))
								.size(12.5)
								.color(Colors::gray()),
						);
					}
					if let Some(id) = &p_tag {
						ui.label(
							RichText::new(t!("goblin.authorize.by_author", id => id.clone()))
								.size(12.5)
								.color(Colors::gray()),
						);
					}
				}
				6 => {
					// Repost: reposted event id and author.
					if let Some(id) = &e_tag {
						ui.label(
							RichText::new(t!("goblin.authorize.repost_of", id => id.clone()))
								.size(12.5)
								.color(Colors::gray()),
						);
					}
					if let Some(id) = &p_tag {
						ui.label(
							RichText::new(t!("goblin.authorize.by_author", id => id.clone()))
								.size(12.5)
								.color(Colors::gray()),
						);
					}
				}
				30023 => {
					// Article: title tag if present, then the content preview.
					if let Some(t) = &title {
						ui.label(
							RichText::new(t!("goblin.authorize.article_title", title => t.clone()))
								.size(14.0)
								.color(Colors::text(false)),
						);
						ui.add_space(4.0);
					}
					show_preview(ui);
				}
				_ => {
					// Kind 1 (and the unreachable fallback): content preview, then
					// the reply/mention tags.
					show_preview(ui);
					if let Some(id) = &e_tag {
						ui.add_space(4.0);
						ui.label(
							RichText::new(t!("goblin.authorize.replying_to", id => id.clone()))
								.size(12.5)
								.color(Colors::gray()),
						);
					}
					if let Some(id) = &p_tag {
						ui.label(
							RichText::new(t!("goblin.authorize.mentions", id => id.clone()))
								.size(12.5)
								.color(Colors::gray()),
						);
					}
				}
			}
			// Truncation marker plus the mandatory show-full affordance. Approval
			// is never blocked on opening it.
			if remaining > 0 {
				ui.add_space(6.0);
				ui.label(
					RichText::new(t!("goblin.authorize.truncated", n => remaining.to_string()))
						.size(12.0)
						.color(Colors::gray()),
				);
				let toggle = if st.show_full {
					t!("goblin.authorize.show_less")
				} else {
					t!("goblin.authorize.show_full")
				};
				let rect = ui
					.label(RichText::new(toggle).size(13.0).color(Colors::green()))
					.rect;
				let hit = ui.interact(
					rect,
					egui::Id::from(modal.id).with("auth_showfull"),
					Sense::click(),
				);
				if hit
					.on_hover_cursor(egui::CursorIcon::PointingHand)
					.clicked()
				{
					st.show_full = !st.show_full;
				}
				if st.show_full {
					ui.add_space(6.0);
					ScrollArea::vertical()
						.max_height(160.0)
						.auto_shrink([false, true])
						.show(ui, |ui| {
							ui.label(RichText::new(&full_esc).size(13.0).color(Colors::gray()));
						});
				}
			}
			ui.add_space(10.0);
			// The signing identity. Display precedence is the switcher's: private
			// tag, else bare claimed name, else truncated npub, and the truncated
			// npub is ALWAYS shown as the anchor. Defaults to the active identity.
			ui.label(
				RichText::new(t!("goblin.authorize.identity"))
					.size(13.0)
					.color(Colors::gray()),
			);
			ui.add_space(6.0);
			if identities.len() > 1 {
				for id in &identities {
					let selected = st.selected == id.pubkey_hex;
					let name = id.display();
					let short = data::short_npub(&id.pubkey_hex);
					let row = ui
						.scope(|ui| {
							ui.horizontal(|ui| {
								ui.add_space(4.0);
								ui.label(
									RichText::new(if selected {
										crate::gui::icons::CHECK_CIRCLE
									} else {
										crate::gui::icons::CIRCLE
									})
									.size(18.0)
									.color(if selected {
										Colors::green()
									} else {
										Colors::gray()
									}),
								);
								ui.add_space(8.0);
								ui.vertical(|ui| {
									if name != short {
										ui.label(
											RichText::new(&name)
												.size(15.0)
												.color(Colors::text(false)),
										);
									}
									ui.label(
										RichText::new(&short).size(12.5).color(Colors::gray()),
									);
								});
							});
						})
						.response
						.rect;
					let hit = ui.interact(
						row,
						egui::Id::from(modal.id).with(("auth_id", id.pubkey_hex.as_str())),
						Sense::click(),
					);
					if hit
						.on_hover_cursor(egui::CursorIcon::PointingHand)
						.clicked()
					{
						st.selected = id.pubkey_hex.clone();
					}
					ui.add_space(4.0);
				}
			} else if let Some(id) = identities.first() {
				let name = id.display();
				let short = data::short_npub(&id.pubkey_hex);
				if name != short {
					ui.label(RichText::new(&name).size(15.0).color(Colors::text(false)));
				}
				ui.label(RichText::new(&short).size(12.5).color(Colors::gray()));
			}
			ui.add_space(10.0);
			// One plain line on what approving does (and does not do).
			ui.label(
				RichText::new(t!("goblin.authorize.explain", domain => domain.clone()))
					.size(13.0)
					.color(Colors::gray()),
			);
			ui.add_space(10.0);
			// The wallet password gates the signature, mirroring the identity
			// password modal (masked field, same wrong-password line).
			ui.label(
				RichText::new(t!("goblin.authorize.pass_prompt"))
					.size(16.0)
					.color(Colors::gray()),
			);
			ui.add_space(10.0);
			let mut field = TextEdit::new(egui::Id::from(modal.id).with("auth_pass")).password();
			field.ui(ui, &mut st.pass, cb);
			if field.enter_pressed {
				go = true;
			}
			if st.pass.is_empty() {
				st.wrong_pass = false;
			} else if st.wrong_pass {
				ui.add_space(10.0);
				ui.label(
					RichText::new(t!("goblin.advanced.wrong_password"))
						.size(16.0)
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
							cancel = true;
						},
					);
				});
				columns[1].vertical_centered_justified(|ui| {
					View::button(
						ui,
						t!("goblin.authorize.confirm"),
						Colors::white_or_black(false),
						|| {
							go = true;
						},
					);
				});
			});
			ui.add_space(6.0);
		});
		if cancel {
			// Cancel drops the request: it is single-use, no retry.
			self.authorize = None;
			Modal::close();
			return;
		}
		if go {
			let (pass, selected) = match self.authorize.as_ref() {
				Some(st) => (st.pass.clone(), st.selected.clone()),
				None => return,
			};
			if pass.is_empty() {
				return;
			}
			if !wallet.verify_nostr_password(&pass) {
				// Wrong password: stay in the modal, request NOT consumed.
				if let Some(st) = self.authorize.as_mut() {
					st.wrong_pass = true;
				}
				return;
			}
			// The chosen identity's unlocked in-memory keys, from the running
			// service (the Build-145 model: every held identity is unlocked).
			let keys = wallet.nostr_service().and_then(|s| {
				s.recv_snapshot()
					.into_iter()
					.find(|h| h.keys.public_key().to_hex() == selected)
					.map(|h| h.keys)
			});
			let Some(keys) = keys else {
				// No running service / identity gone: drop the request.
				self.authorize = None;
				Modal::close();
				return;
			};
			let st = self.authorize.as_mut().unwrap();
			st.pass.clear();
			st.wrong_pass = false;
			match crate::nostr::authuri::build_authorize_event(&keys, &st.uri.template) {
				Ok(event) => {
					// Signed: the request is consumed from here on, whatever the
					// POST outcome. Deliver off the UI thread with the shared HTTP
					// client and a hard timeout.
					st.posting = true;
					let callback = st.uri.callback.clone();
					let challenge = st.uri.challenge.clone();
					let domain = st.uri.domain.clone();
					let slot = st.result.clone();
					std::thread::spawn(move || {
						let res = match tokio::runtime::Builder::new_current_thread()
							.enable_all()
							.build()
						{
							Ok(rt) => rt.block_on(async {
								let post = crate::nostr::authuri::post_authorize_event(
									&callback, &challenge, &domain, &event,
								);
								match tokio::time::timeout(
									std::time::Duration::from_secs(LOGIN_POST_TIMEOUT_SECS),
									post,
								)
								.await
								{
									Ok(r) => r,
									Err(_) => Err("timeout".to_string()),
								}
							}),
							Err(e) => Err(e.to_string()),
						};
						*slot.lock().unwrap() = Some(res);
					});
					Modal::close();
					// Return-to-caller is DEFERRED to the outcome poll (see the
					// login flow): the app must stay foreground until the POST
					// result lands, or the completion work freezes backgrounded.
				}
				Err(e) => {
					// Signing failed (never expected): consume the request and
					// surface the quiet failure toast.
					log::error!("authorize event signing failed: {e}");
					self.login_toast = Some((
						t!("goblin.authorize.failed", domain => domain).to_string(),
						std::time::Instant::now(),
					));
					self.authorize = None;
					Modal::close();
				}
			}
		}
	}

	/// The "Trust with Goblin" (Authorize Sessions) grant modal: proves identity
	/// (folds login in) AND establishes the session in one password-gated,
	/// hold-to-confirm decision. Shows the identity, the low-tier categories being
	/// granted for silent signing, and the fixed line that money always asks.
	fn trust_modal_content(
		&mut self,
		ui: &mut egui::Ui,
		modal: &Modal,
		wallet: &Wallet,
		cb: &dyn PlatformCallbacks,
	) {
		let Some(st) = self.trust.as_mut() else {
			Modal::close();
			return;
		};
		if st.posting {
			Modal::close();
			return;
		}
		let domain = st.uri.domain.clone();
		let identities = wallet.nostr_identities();
		let display = crate::nostr::session::render_grant(&st.uri.requested_kinds);
		let mut go = false;
		let mut cancel = false;
		ui.vertical_centered(|ui| {
			ui.add_space(6.0);
			ui.label(
				RichText::new(t!("goblin.trust.headline", domain => domain.clone()))
					.size(17.0)
					.color(Colors::title(false)),
			);
			ui.add_space(10.0);
			ui.label(
				RichText::new(t!("goblin.trust.identity"))
					.size(13.0)
					.color(Colors::gray()),
			);
			ui.add_space(6.0);
			// Identity picker (defaults to the active identity), the truncated
			// npub always shown as the anchor.
			if identities.len() > 1 {
				for id in &identities {
					let selected = st.selected == id.pubkey_hex;
					let title = id.display();
					let short = data::short_npub(&id.pubkey_hex);
					let row = ui
						.scope(|ui| {
							ui.horizontal(|ui| {
								ui.add_space(4.0);
								ui.label(
									RichText::new(if selected {
										crate::gui::icons::CHECK_CIRCLE
									} else {
										crate::gui::icons::CIRCLE
									})
									.size(18.0)
									.color(if selected {
										Colors::green()
									} else {
										Colors::gray()
									}),
								);
								ui.add_space(8.0);
								ui.vertical(|ui| {
									if title != short {
										ui.label(
											RichText::new(&title)
												.size(15.0)
												.color(Colors::text(false)),
										);
									}
									ui.label(
										RichText::new(&short).size(12.5).color(Colors::gray()),
									);
								});
							});
						})
						.response
						.rect;
					let hit = ui.interact(
						row,
						egui::Id::from(modal.id).with(("trust_id", id.pubkey_hex.as_str())),
						Sense::click(),
					);
					if hit
						.on_hover_cursor(egui::CursorIcon::PointingHand)
						.clicked()
					{
						st.selected = id.pubkey_hex.clone();
					}
					ui.add_space(4.0);
				}
			} else if let Some(id) = identities.first() {
				let title = id.display();
				let short = data::short_npub(&id.pubkey_hex);
				if title != short {
					ui.label(RichText::new(&title).size(15.0).color(Colors::text(false)));
				}
				ui.label(RichText::new(&short).size(12.5).color(Colors::gray()));
			}
			ui.add_space(12.0);
			// The gist in one short line (grant + the money rule), with the full
			// permission detail behind a small disclosure for anyone who wants it.
			ui.label(
				RichText::new(t!("goblin.trust.lead", domain => domain.clone()))
					.size(13.5)
					.color(Colors::text(false)),
			);
			// Caution lines are safety-relevant and stay visible even collapsed.
			for kind in &display.unknown_kinds {
				ui.label(
					RichText::new(format!(
						"• {}",
						t!("goblin.trust.cat_unknown", n => kind.to_string())
					))
					.size(13.5)
					.color(Colors::red()),
				);
			}
			if display.stripped_login {
				ui.label(
					RichText::new(t!("goblin.trust.login_excluded"))
						.size(12.5)
						.color(Colors::red()),
				);
			}
			ui.add_space(8.0);
			// The disclosure toggle, same idiom as the authorize full-content view.
			let toggle = if st.show_full {
				t!("goblin.authorize.show_less")
			} else {
				t!("goblin.authorize.show_full")
			};
			let rect = ui
				.label(RichText::new(toggle).size(13.0).color(Colors::green()))
				.rect;
			let hit = ui.interact(
				rect,
				egui::Id::from(modal.id).with("trust_showfull"),
				Sense::click(),
			);
			if hit
				.on_hover_cursor(egui::CursorIcon::PointingHand)
				.clicked()
			{
				st.show_full = !st.show_full;
			}
			if st.show_full {
				ui.add_space(6.0);
				// What the silent grant covers, as human categories.
				ui.label(
					RichText::new(t!("goblin.trust.grant_intro"))
						.size(13.0)
						.color(Colors::gray()),
				);
				ui.add_space(4.0);
				for cat in &display.categories {
					ui.label(
						RichText::new(format!("• {}", t!(cat.key())))
							.size(13.5)
							.color(Colors::text(false)),
					);
				}
				ui.add_space(6.0);
				// The fixed money line: the low-tier grant is not a money grant.
				ui.label(
					RichText::new(t!("goblin.trust.money_line"))
						.size(13.0)
						.color(Colors::title(false)),
				);
				ui.add_space(4.0);
				ui.label(
					RichText::new(t!("goblin.trust.duration"))
						.size(12.5)
						.color(Colors::gray()),
				);
			}
			ui.add_space(12.0);
			ui.label(
				RichText::new(t!("goblin.trust.pass_prompt"))
					.size(16.0)
					.color(Colors::gray()),
			);
			ui.add_space(10.0);
			let mut field = TextEdit::new(egui::Id::from(modal.id).with("trust_pass")).password();
			field.ui(ui, &mut st.pass, cb);
			if st.pass.is_empty() {
				st.wrong_pass = false;
			} else if st.wrong_pass {
				ui.add_space(10.0);
				ui.label(
					RichText::new(t!("goblin.advanced.wrong_password"))
						.size(16.0)
						.color(Colors::red()),
				);
			}
			ui.add_space(12.0);
		});
		// Hold-to-confirm: the single high-value decision cannot be a stray tap.
		if self.trust_hold.ui(ui, &t!("goblin.trust.confirm_hold")) {
			go = true;
		}
		ui.add_space(6.0);
		ui.scope(|ui| {
			ui.spacing_mut().item_spacing = egui::Vec2::new(8.0, 0.0);
			ui.vertical_centered_justified(|ui| {
				View::button(
					ui,
					t!("modal.cancel"),
					Colors::white_or_black(false),
					|| {
						cancel = true;
					},
				);
			});
			ui.add_space(6.0);
		});
		if cancel {
			self.trust = None;
			Modal::close();
			return;
		}
		if go {
			let (pass, selected) = match self.trust.as_ref() {
				Some(st) => (st.pass.clone(), st.selected.clone()),
				None => return,
			};
			if pass.is_empty() {
				self.trust_hold = w::HoldToSend::default();
				return;
			}
			if !wallet.verify_nostr_password(&pass) {
				if let Some(st) = self.trust.as_mut() {
					st.wrong_pass = true;
				}
				self.trust_hold = w::HoldToSend::default();
				return;
			}
			let keys = wallet.nostr_service().and_then(|s| {
				s.recv_snapshot()
					.into_iter()
					.find(|h| h.keys.public_key().to_hex() == selected)
					.map(|h| h.keys)
			});
			let Some(keys) = keys else {
				self.trust = None;
				Modal::close();
				return;
			};
			let st = self.trust.as_mut().unwrap();
			st.pass.clear();
			st.wrong_pass = false;
			// Sign and POST the kind-22242 login event exactly as Build 150 does;
			// the session is created by the router once this POST succeeds.
			match crate::nostr::loginuri::build_login_event(
				&keys,
				&st.uri.challenge,
				&st.uri.domain,
			) {
				Ok(event) => {
					st.posting = true;
					let callback = st.uri.callback.clone();
					let slot = st.result.clone();
					std::thread::spawn(move || {
						let res = match tokio::runtime::Builder::new_current_thread()
							.enable_all()
							.build()
						{
							Ok(rt) => rt.block_on(async {
								let post =
									crate::nostr::loginuri::post_login_event(&callback, &event);
								match tokio::time::timeout(
									std::time::Duration::from_secs(LOGIN_POST_TIMEOUT_SECS),
									post,
								)
								.await
								{
									Ok(r) => r,
									Err(_) => Err("timeout".to_string()),
								}
							}),
							Err(e) => Err(e.to_string()),
						};
						*slot.lock().unwrap() = Some(res);
					});
					Modal::close();
					// Return-to-caller is DEFERRED even further than login: past
					// the POST outcome AND past the session-open announce
					// confirmation (the trust_wait poll). Returning here was the
					// Build 153 QR-trust bug: the app backgrounded with the POST
					// in flight and the session-open never published.
				}
				Err(e) => {
					log::error!("trust login event signing failed: {e}");
					self.login_toast = Some((
						t!("goblin.trust.failed", domain => domain).to_string(),
						std::time::Instant::now(),
					));
					self.trust = None;
					Modal::close();
				}
			}
		}
	}

	/// The money-tier per-action approval modal: a value-moving sign (or a
	/// pay-committing encrypt) arriving over a live session channel. Identical
	/// gravity to a v1 authorize — what is being done, which identity, a masked
	/// password, hold-to-confirm — raised every time, never silent.
	fn money_modal_content(
		&mut self,
		ui: &mut egui::Ui,
		modal: &Modal,
		wallet: &Wallet,
		cb: &dyn PlatformCallbacks,
	) {
		use crate::nostr::session::ChannelOp;
		let Some(st) = self.money.as_mut() else {
			Modal::close();
			return;
		};
		let domain = st.pending.domain.clone();
		let req_id = st.pending.id().to_string();
		let short_id = data::short_npub(&st.pending.identity_pubkey.to_hex());
		// A one-line description of exactly what is being committed to.
		let what = match &st.pending.op {
			ChannelOp::Sign(req) => {
				let label = crate::nostr::authuri::kind_label(req.event.kind);
				let (preview, _) = crate::nostr::authuri::content_preview(&req.event.content);
				let preview = crate::nostr::authuri::escape_for_display(&preview);
				if preview.trim().is_empty() {
					t!(label.key(), n => req.event.kind.to_string()).to_string()
				} else {
					format!(
						"{}: {}",
						t!(label.key(), n => req.event.kind.to_string()),
						preview
					)
				}
			}
			ChannelOp::Encrypt(e) => {
				// Order DMs are where payment agreements live: show the inspected
				// plaintext (escaped + truncated exactly like the sign path), so
				// the user sees WHAT they are agreeing to pay, not a blind label.
				let (preview, _) = crate::nostr::authuri::content_preview(&e.plaintext);
				let preview = crate::nostr::authuri::escape_for_display(&preview);
				if preview.trim().is_empty() {
					t!("goblin.money.encrypt_desc").to_string()
				} else {
					format!("{}: {}", t!("goblin.money.encrypt_desc"), preview)
				}
			}
		};
		let mut approve = false;
		let mut decline = false;
		ui.vertical_centered(|ui| {
			ui.add_space(6.0);
			ui.label(
				RichText::new(t!("goblin.money.headline", domain => domain.clone()))
					.size(17.0)
					.color(Colors::title(false)),
			);
			ui.add_space(8.0);
			ui.label(RichText::new(&what).size(14.0).color(Colors::text(false)));
			ui.add_space(8.0);
			ui.label(
				RichText::new(t!("goblin.money.identity", id => short_id.clone()))
					.size(12.5)
					.color(Colors::gray()),
			);
			ui.add_space(8.0);
			ui.label(
				RichText::new(t!("goblin.money.explain"))
					.size(13.0)
					.color(Colors::gray()),
			);
			ui.add_space(10.0);
			ui.label(
				RichText::new(t!("goblin.money.pass_prompt"))
					.size(16.0)
					.color(Colors::gray()),
			);
			ui.add_space(10.0);
			let mut field = TextEdit::new(egui::Id::from(modal.id).with("money_pass")).password();
			field.ui(ui, &mut st.pass, cb);
			if st.pass.is_empty() {
				st.wrong_pass = false;
			} else if st.wrong_pass {
				ui.add_space(10.0);
				ui.label(
					RichText::new(t!("goblin.advanced.wrong_password"))
						.size(16.0)
						.color(Colors::red()),
				);
			}
			ui.add_space(12.0);
		});
		if self.money_hold.ui(ui, &t!("goblin.money.confirm_hold")) {
			approve = true;
		}
		ui.add_space(6.0);
		ui.vertical_centered_justified(|ui| {
			View::button(
				ui,
				t!("modal.cancel"),
				Colors::white_or_black(false),
				|| {
					decline = true;
				},
			);
		});
		ui.add_space(6.0);
		if decline {
			if let Some(svc) = wallet.nostr_service() {
				svc.answer_money_prompt(&req_id, false);
			}
			self.money = None;
			Modal::close();
			return;
		}
		if approve {
			let pass = self
				.money
				.as_ref()
				.map(|s| s.pass.clone())
				.unwrap_or_default();
			if pass.is_empty() || !wallet.verify_nostr_password(&pass) {
				if let Some(st) = self.money.as_mut() {
					st.wrong_pass = true;
				}
				self.money_hold = w::HoldToSend::default();
				return;
			}
			if let Some(svc) = wallet.nostr_service() {
				svc.answer_money_prompt(&req_id, true);
			}
			self.money = None;
			Modal::close();
		}
	}

	/// Trusted Sites: the active Authorize Sessions, what each can sign silently,
	/// time remaining, and a one-tap end (immediate, unilateral revocation).
	fn trusted_sites_ui(
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
	fn login_toast_ui(&mut self, ctx: &egui::Context) {
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

fn fiat_line(data: &Option<WalletData>) -> Option<w::FiatLine> {
	use crate::http::RateState;
	let p = crate::AppConfig::pairing();
	let vs = p.vs_currency()?;
	// Asking for the rate here (while the balance is on screen) is what kicks a
	// live refetch when the in-session rate has aged out; an idle wallet never
	// reaches this path.
	Some(match crate::http::grin_rate(vs) {
		RateState::Fresh(rate) => {
			let spendable = data
				.as_ref()
				.map(|d| d.info.amount_currently_spendable)
				.unwrap_or(0);
			let grin = spendable as f64 / 1_000_000_000.0;
			w::FiatLine::Text(format!(
				"≈ {}  ·  1ツ = {}",
				fmt_pairing(grin * rate, p),
				fmt_pairing(rate, p)
			))
		}
		RateState::Loading => w::FiatLine::Loading,
		RateState::Unavailable => w::FiatLine::Unavailable,
	})
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
fn pairing_preview(grin: f64, ctx: &egui::Context) -> Option<String> {
	use crate::http::RateState;
	let p = crate::AppConfig::pairing();
	let vs = p.vs_currency()?;
	match crate::http::grin_rate(vs) {
		RateState::Fresh(rate) => Some(format!("≈ {}", fmt_pairing(grin * rate, p))),
		// No stale fallback: show nothing until a fresh rate lands. Nudge a repaint
		// while loading so the preview appears once the live fetch returns.
		RateState::Loading => {
			ctx.request_repaint_after(std::time::Duration::from_millis(300));
			None
		}
		RateState::Unavailable => None,
	}
}

/// Convert a bech32 npub to hex for short display fallbacks.
fn hex_of(npub: &str) -> String {
	use nostr_sdk::{FromBech32, PublicKey};
	PublicKey::from_bech32(npub)
		.map(|pk| pk.to_hex())
		.unwrap_or_else(|_| npub.to_string())
}

/// Largest point size in `[12.0, 16.0]` at which the semibold news title fits on
/// one line within `avail` px, measured against the live font atlas and stepping
/// down by 0.5. Returns the 12pt floor when even that overflows (the caller pairs
/// it with `.truncate()`). This is the shrink-to-fit safety net that keeps a
/// title readable on a 390px screen; the hard char cap (`news_title_clamped`) is
/// the predictable ceiling.
fn fit_news_title_pt(ui: &egui::Ui, text: &str, avail: f32) -> f32 {
	const CEIL: f32 = 16.0;
	const FLOOR: f32 = 12.0;
	let mut pt = CEIL;
	while pt > FLOOR {
		let w = ui
			.painter()
			.layout_no_wrap(
				text.to_owned(),
				FontId::new(pt, fonts::semibold()),
				egui::Color32::WHITE,
			)
			.size()
			.x;
		if w <= avail {
			return pt;
		}
		pt -= 0.5;
	}
	FLOOR
}
