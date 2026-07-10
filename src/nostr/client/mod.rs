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

//! Per-wallet nostr service: relay connections over Tor,
//! identity event publishing, the guarded ingest loop and the DM send path.

use grin_core::core::amount_to_hr_string;
use log::{error, info, warn};
use nostr_sdk::{
	Client, ClientOptions, Event, EventBuilder, Filter, FromBech32, Keys, Kind, Metadata,
	PublicKey, RelayPoolNotification, RelayStatus, RelayUrl, SubscriptionId, Tag, TagKind,
	Timestamp, ToBech32,
};
use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crate::nostr::ingest::{IngestContext, IngestDecision, decide};
use crate::nostr::protocol;
use crate::nostr::relays::MAX_DM_RELAYS;
use crate::nostr::types::*;
use crate::nostr::wrapv3;
use crate::nostr::{NostrConfig, NostrIdentity, NostrStore};
use crate::tor::{ClearnetWebSocketTransport, TorWebSocketTransport};
use crate::wallet::Wallet;
use crate::wallet::types::WalletTask;

mod identity;
mod send;
mod service;
mod sessions;

use service::run_service;

/// A peer's published nostr profile (kind-0 metadata), used to confirm a
/// pasted key belongs to a live identity before paying it.
pub struct NostrProfile {
	pub name: Option<String>,
	pub nip05: Option<String>,
}

/// Stable subscription id for our kind:1059 gift-wrap inbox. Reusing ONE id
/// (rather than a fresh random id per (re)subscribe) means re-establishing the
/// subscription after a tunnel reselect REPLACES it instead of piling up
/// duplicate REQs on the relays.
const GIFTWRAP_SUB: &str = "goblin-giftwrap";

/// Stable subscription id for the Authorize Sessions encrypted channel (kind
/// 24140), re-subscribed (replace-not-duplicate) whenever the session set
/// changes so newly granted sessions start receiving immediately.
const CHANNEL_SUB: &str = "goblin-session-channel";

/// The Goblin news publisher (kind 30023 long-form). The Home news panel shows
/// this key's latest post, fetched from our own relay set.
const NEWS_NPUB: &str = "npub15gsytqvs5c78u83yv2agl4twjkk6qgem7gtwe2agu7s90tkelxys0xxely";
/// Stable subscription id for the news feed (same replace-not-duplicate reason
/// as [`GIFTWRAP_SUB`]).
const NEWS_SUB: &str = "goblin-news";

/// Subscription look-back window beyond the last connection time: gift wrap
/// timestamps are randomized up to 2 days into the past (NIP-59), use 3 days.
const LOOKBACK_SECS: i64 = 3 * 86_400;
/// Catch-up fetch timeout.
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);
/// Send dispatch timeout.
const SEND_TIMEOUT: Duration = Duration::from_secs(40);
/// Money-path safety: total budget to read-back-confirm a dispatched wrap on a
/// relay the recipient reads (a positive delivery proof — a transport-write
/// success alone is not). The confirm retries across transient transport drops
/// within this budget; on exhaustion the send is treated as sent-PENDING (the tx
/// waits for S2 / expiry), NOT a hard failure — see the confirm loop in
/// `dispatch_dm` for why a hard failure here would trigger duplicate re-dispatch.
const CONFIRM_TIMEOUT: Duration = Duration::from_secs(30);
/// Per-attempt read-back timeout while confirming (short, so one dead relay
/// doesn't consume the whole confirm budget in a single poll).
const CONFIRM_POLL: Duration = Duration::from_secs(8);
/// Gap between confirmation polls — the wrap may still be egressing right after
/// the transport returns "sent".
const CONFIRM_GAP: Duration = Duration::from_secs(3);
/// Rate limit for incoming messages per known contact (events/hour).
const RATE_CONTACT_PER_HOUR: usize = 30;
/// Rate limit for incoming messages per unknown sender (events/hour).
const RATE_UNKNOWN_PER_HOUR: usize = 10;
/// Auto-resend window for pending outgoing messages (days).
const RESEND_WINDOW_SECS: i64 = 7 * 86_400;
/// How often a cached @username is re-validated against the identity server, so
/// a released or reassigned name stops being shown. Doubles as the freshness
/// gate in `resolve_contact_identity`. Tuned for release/name-change detection
/// freshness, not liveness — a name rarely changes, so 6h is ample and keeps the
/// Tor re-verify traffic off the interactive path.
const NAME_REVERIFY_INTERVAL_SECS: i64 = 6 * 3600;
/// Cap on contacts re-verified per sweep, so a large contact list rolls through
/// instead of bursting dozens of simultaneous Tor lookups at once.
const NAME_REVERIFY_MAX_PER_TICK: usize = 8;

/// One held identity live in memory: its decrypted keys (for unwrapping incoming
/// gift wraps addressed to it, and for signing when it is the active identity)
/// and its file state (for publishing its DM-relay list and, if named, its
/// profile). Every held identity of the open wallet is kept here so the wallet
/// LISTENS for ALL of them at once; switching is then a purely local change of
/// which one is presented and used for sending.
#[derive(Clone)]
pub struct HeldIdentityKeys {
	pub keys: Keys,
	pub identity: NostrIdentity,
}

/// Per-wallet nostr service.
pub struct NostrService {
	/// The ACTIVE identity's keys — used for sending, signing, and display. A
	/// switch swaps this in place (the target is already unlocked in `recv`).
	keys: RwLock<Keys>,
	/// Active identity file state (display, username claim, etc.).
	pub identity: RwLock<NostrIdentity>,
	/// EVERY held identity of the open wallet, decrypted for the session. The
	/// wallet subscribes to gift wraps for all of their pubkeys at once and
	/// unwraps each incoming wrap with whichever of these keys opens it, redeeming
	/// into the one shared balance. Rebuilt on add/import/rotate; a plain switch
	/// leaves it untouched and only re-points `keys`/`identity`.
	recv: RwLock<Vec<HeldIdentityKeys>>,
	/// Per-wallet configuration.
	pub config: RwLock<NostrConfig>,
	/// Metadata archive.
	pub store: Arc<NostrStore>,
	/// Directory holding identity.json.
	nostr_dir: PathBuf,

	/// SDK client, present while the service loop runs.
	client: RwLock<Option<Client>>,
	/// Handle to the service's tokio runtime. One-shot fetches (e.g. profile
	/// lookups) from worker threads MUST run here, not on a throwaway runtime:
	/// the relay connections (all driven over Tor) are driven
	/// by this runtime, and a foreign runtime can't reach them.
	rt_handle: RwLock<Option<tokio::runtime::Handle>>,
	/// Service thread started flag.
	started: AtomicBool,
	/// Shutdown request flag.
	shutdown: AtomicBool,
	/// At least one relay is connected.
	connected: AtomicBool,
	/// New payment requests arrived (UI badge hint).
	pub has_new_requests: AtomicBool,
	/// Per-sender rate limiting state (unix seconds of accepted events).
	rate: Mutex<HashMap<String, Vec<i64>>>,
	/// Current outgoing-send phase for the UI (see [`SendPhase`]).
	send_phase: std::sync::atomic::AtomicU8,
	/// Human-readable reason the last send/request/approve failed, surfaced on
	/// the failure screen so the user (and we) can see WHY, not just "couldn't
	/// send". Cleared when a new attempt starts.
	last_send_error: RwLock<Option<String>>,
	/// Result of the most recent manual payment-cancel, taken once by the receipt
	/// UI to show "cancelled" vs "already went through".
	cancel_notice: RwLock<Option<CancelOutcome>>,
	/// Serializes a manual payment-cancel against a concurrent S2 finalize+post
	/// so the two can't both succeed (cancel the outputs AND post on-chain).
	cancel_finalize_lock: Mutex<()>,
	/// Active Authorize Sessions (v2). In memory only: quitting the wallet ends
	/// every session. The service loop subscribes each session's encrypted
	/// channel, serves silent low-tier signs, and routes money-tier requests to
	/// the GUI money prompt.
	sessions: RwLock<Vec<crate::nostr::session::Session>>,
	/// Set whenever the session set changes so the loop re-subscribes the channel
	/// filter and publishes `session-open` for any new session.
	sessions_dirty: AtomicBool,
	/// Money-tier requests awaiting the GUI's per-action password prompt (FIFO).
	money_pending: Mutex<Vec<crate::nostr::session::PendingMoney>>,
	/// The GUI's answers to money prompts (the answered request plus approve/decline),
	/// drained by the loop which then signs (or declines) and publishes on the channel.
	money_answers: Mutex<Vec<(crate::nostr::session::PendingMoney, bool)>>,
	/// A single non-blocking "signing a lot" notice for the GUI toast, set when a
	/// session trips the soft rate cap.
	session_notice: RwLock<Option<String>>,
	/// Wallet channel pubkeys (hex) whose `session-open` announce was CONFIRMED
	/// handed to at least one relay connection. The trust GUI waits on this
	/// before it may background the app (return-to-caller): backgrounding stops
	/// the frame pump, and an announce still queued behind `sessions_dirty`
	/// would freeze in the paused service (the Build 153 QR-trust bug).
	/// Transient and tiny (one entry per grant this run).
	announced_ok: RwLock<std::collections::HashSet<String>>,
}

/// Transport-aware connection state for the UI status lines. Tor and clearnet
/// are distinct so a Tor-off wallet never reads as "connecting over Tor". See
/// [`NostrService::transport_status`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TransportStatus {
	/// Tor wallet: embedded Tor still bootstrapping / dialing.
	ConnectingTor,
	/// Tor wallet: tunnel up, but no relay live on the current generation yet.
	TorReady,
	/// Tor wallet: a relay is connected+subscribed over Tor.
	ConnectedTor,
	/// Clearnet wallet: dialing relays directly, none connected yet.
	ConnectingDirect,
	/// Clearnet wallet: a relay is connected directly ("Connected (direct)").
	ConnectedDirect,
}

/// Phase of the most recent outgoing send, polled by the send UI.
pub mod send_phase {
	pub const IDLE: u8 = 0;
	pub const WORKING: u8 = 1;
	pub const SENT: u8 = 2;
	pub const FAILED: u8 = 3;
	/// A request was refused up front because the recipient advertises that
	/// they are not accepting incoming requests ("Could not request").
	pub const REQUEST_BLOCKED: u8 = 4;
}

impl NostrService {
	/// Create the service holding EVERY held identity of the open wallet (all
	/// unlocked at wallet-open), with `active_hex` marking which one is presented
	/// and used for sending. The wallet listens for all of them at once.
	pub fn new(
		recv: Vec<HeldIdentityKeys>,
		active_hex: &str,
		config: NostrConfig,
		store: NostrStore,
		nostr_dir: PathBuf,
	) -> Arc<Self> {
		// Pick the active identity (fall back to the first if the pointer doesn't
		// resolve — the service must always have a running identity).
		let active = recv
			.iter()
			.find(|h| h.keys.public_key().to_hex() == active_hex)
			.or_else(|| recv.first())
			.cloned()
			.expect("nostr service created with no identities");
		Arc::new(Self {
			keys: RwLock::new(active.keys),
			identity: RwLock::new(active.identity),
			recv: RwLock::new(recv),
			config: RwLock::new(config),
			store: Arc::new(store),
			nostr_dir,
			client: RwLock::new(None),
			rt_handle: RwLock::new(None),
			started: AtomicBool::new(false),
			shutdown: AtomicBool::new(false),
			connected: AtomicBool::new(false),
			has_new_requests: AtomicBool::new(false),
			rate: Mutex::new(HashMap::new()),
			send_phase: std::sync::atomic::AtomicU8::new(send_phase::IDLE),
			last_send_error: RwLock::new(None),
			cancel_notice: RwLock::new(None),
			cancel_finalize_lock: Mutex::new(()),
			sessions: RwLock::new(Vec::new()),
			sessions_dirty: AtomicBool::new(false),
			money_pending: Mutex::new(Vec::new()),
			money_answers: Mutex::new(Vec::new()),
			session_notice: RwLock::new(None),
			announced_ok: RwLock::new(std::collections::HashSet::new()),
		})
	}

	/// Own (active) public key.
	pub fn public_key(&self) -> PublicKey {
		self.keys.read().public_key()
	}

	/// Own npub bech32.
	pub fn npub(&self) -> String {
		self.identity.read().npub.clone()
	}

	/// Shareable NIP-19 nprofile: our pubkey plus up to two of our relays as
	/// routing hints, so a sender can reach us without any registry or
	/// indexer lookup. Falls back to the bare npub when encoding fails.
	pub fn nprofile(&self) -> String {
		use nostr_sdk::nips::nip19::Nip19Profile;
		let relays: Vec<RelayUrl> = self
			.relays()
			.iter()
			.filter_map(|r| RelayUrl::parse(r).ok())
			.take(2)
			.collect();
		Nip19Profile::new(self.keys.read().public_key(), relays)
			.to_bech32()
			.ok()
			.unwrap_or_else(|| self.npub())
	}

	/// Own (active) nsec (secret key) bech32 — for explicit user backup only.
	pub fn nsec(&self) -> Option<String> {
		self.keys.read().secret_key().to_bech32().ok()
	}

	/// The active identity's signing keys, for in-process signing (e.g. NIP-98
	/// auth) without ever serializing the secret to a plaintext `String`.
	pub fn keys(&self) -> Keys {
		self.keys.read().clone()
	}

	/// Read the current outgoing-send phase (see [`send_phase`]).
	pub fn send_phase(&self) -> u8 {
		self.send_phase.load(Ordering::Relaxed)
	}

	/// Set the outgoing-send phase (called by the send task + UI). Starting a new
	/// attempt (WORKING) clears any prior failure reason.
	pub fn set_send_phase(&self, phase: u8) {
		if phase == send_phase::WORKING {
			*self.last_send_error.write() = None;
		}
		self.send_phase.store(phase, Ordering::Relaxed);
	}

	/// Record why the current send/request/approve failed (shown on the failure
	/// screen) and flip the phase to FAILED.
	pub fn fail_send(&self, reason: impl Into<String>) {
		*self.last_send_error.write() = Some(reason.into());
		self.send_phase.store(send_phase::FAILED, Ordering::Relaxed);
	}

	/// The reason the last send failed, if any.
	pub fn last_send_error(&self) -> Option<String> {
		self.last_send_error.read().clone()
	}

	/// Record the outcome of a manual payment-cancel for the UI to surface.
	pub fn set_cancel_notice(&self, outcome: CancelOutcome) {
		*self.cancel_notice.write() = Some(outcome);
	}

	/// Take (consume) the pending payment-cancel outcome, if any.
	pub fn take_cancel_notice(&self) -> Option<CancelOutcome> {
		self.cancel_notice.write().take()
	}

	/// Acquire the cancel/finalize serialization lock. Held by both the manual
	/// payment-cancel and `nostr_finalize_post` so a cancel and a concurrent S2
	/// finalize can't both commit (one would reclaim outputs the other posts).
	pub fn lock_finalize(&self) -> parking_lot::MutexGuard<'_, ()> {
		self.cancel_finalize_lock.lock()
	}

	/// Whether at least one relay is connected.
	pub fn is_connected(&self) -> bool {
		self.connected.load(Ordering::Relaxed)
	}

	/// Whether this wallet routes over Tor (resolved; `None`/legacy = ON).
	pub fn tor_routing(&self) -> bool {
		self.config.read().tor_enabled()
	}

	/// Transport-aware connection status for the UI status lines, so a Tor-off
	/// wallet reads "Connected (direct)" instead of forever "connecting over Tor"
	/// (the Tor-only [`crate::tor::transport_ready`] never flips on clearnet).
	/// The three status-line call sites are rewired to this in a later slice; the
	/// state is exposed cleanly here now.
	pub fn transport_status(&self) -> TransportStatus {
		if self.tor_routing() {
			if crate::tor::transport_ready() {
				TransportStatus::ConnectedTor
			} else if crate::tor::is_ready() {
				TransportStatus::TorReady
			} else {
				TransportStatus::ConnectingTor
			}
		} else if self.connected.load(Ordering::Relaxed) {
			TransportStatus::ConnectedDirect
		} else {
			TransportStatus::ConnectingDirect
		}
	}

	/// Whether the service loop is running.
	pub fn is_running(&self) -> bool {
		self.started.load(Ordering::Relaxed) && !self.shutdown.load(Ordering::Relaxed)
	}

	/// Save the identity file after mutation (e.g. NIP-05 registration).
	pub fn save_identity(&self) {
		let identity = self.identity.read().clone();
		if let Err(e) = identity.save(&self.nostr_dir) {
			error!("nostr: identity save failed: {e}");
		}
	}

	/// Start the service thread (idempotent).
	pub fn start(self: &Arc<Self>, wallet: Wallet) {
		if self.started.swap(true, Ordering::SeqCst) {
			return;
		}
		let svc = self.clone();
		thread::spawn(move || {
			let rt = tokio::runtime::Builder::new_multi_thread()
				.worker_threads(2)
				.enable_all()
				.build()
				.unwrap();
			let svc_run = svc.clone();
			rt.block_on(async move {
				run_service(svc_run, wallet).await;
			});
			svc.started.store(false, Ordering::SeqCst);
			svc.connected.store(false, Ordering::Relaxed);
			info!("nostr: service stopped");
		});
	}

	/// Request the service loop to stop.
	pub fn stop(&self) {
		self.shutdown.store(true, Ordering::SeqCst);
	}

	/// Restart with current config (relay list changes).
	pub fn restart(self: &Arc<Self>, wallet: Wallet) {
		self.stop();
		let svc = self.clone();
		thread::spawn(move || {
			// Wait for the loop to exit, then start again.
			while svc.started.load(Ordering::SeqCst) {
				thread::sleep(Duration::from_millis(300));
			}
			svc.shutdown.store(false, Ordering::SeqCst);
			svc.start(wallet);
		});
	}

	/// Current relay list, resolved for the wallet's ACTIVE transport
	/// (per-user-tor §4). A user `nostr.toml` override wins in both regimes.
	/// Otherwise: on Tor the FIXED pinned `TOR_RELAYS` set (same for every
	/// identity); on clearnet this identity's persisted random healthy subset
	/// (`dm_relays`), falling back to the built-in defaults until selection has
	/// run. `relay.floonet.dev` is pinned first in every case. Because this reads
	/// `tor_routing()` live, a Tor toggle (which calls `restart()`) recomputes the
	/// set for the new transport at the next `run_service` without touching the
	/// persisted clearnet subset.
	pub fn relays(&self) -> Vec<String> {
		crate::nostr::relays::effective_relays(
			self.tor_routing(),
			self.config.read().relays_override(),
			self.identity.read().dm_relays.clone(),
			self.config.read().relays(),
		)
	}
}
