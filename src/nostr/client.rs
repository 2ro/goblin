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

//! Per-wallet nostr service: relay connections over the Nym mixnet,
//! identity event publishing, the guarded ingest loop and the DM send path.

use log::{error, info, warn};
use nostr_sdk::{
	Client, Event, EventBuilder, Filter, Keys, Kind, Metadata, PublicKey, RelayPoolNotification,
	RelayStatus, Tag, TagKind, Timestamp, ToBech32,
};
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crate::nostr::ingest::{IngestContext, IngestDecision, decide};
use crate::nostr::protocol;
use crate::nostr::relays::MAX_DM_RELAYS;
use crate::nostr::types::*;
use crate::nostr::{NostrConfig, NostrIdentity, NostrStore};
use crate::nym::NymWebSocketTransport;
use crate::wallet::Wallet;
use crate::wallet::types::WalletTask;

/// A peer's published nostr profile (kind-0 metadata), used to confirm a
/// pasted key belongs to a live identity before paying it.
pub struct NostrProfile {
	pub name: Option<String>,
	pub nip05: Option<String>,
}

/// Subscription look-back window beyond the last connection time: gift wrap
/// timestamps are randomized up to 2 days into the past (NIP-59), use 3 days.
const LOOKBACK_SECS: i64 = 3 * 86_400;
/// Catch-up fetch timeout.
const FETCH_TIMEOUT: Duration = Duration::from_secs(30);
/// Send dispatch timeout.
const SEND_TIMEOUT: Duration = Duration::from_secs(40);
/// Rate limit for incoming messages per known contact (events/hour).
const RATE_CONTACT_PER_HOUR: usize = 30;
/// Rate limit for incoming messages per unknown sender (events/hour).
const RATE_UNKNOWN_PER_HOUR: usize = 10;
/// Auto-resend window for pending outgoing messages (days).
const RESEND_WINDOW_SECS: i64 = 7 * 86_400;
/// How often a cached @username is re-validated against the identity server, so
/// a released or reassigned name stops being shown. Doubles as the freshness
/// gate in `resolve_contact_identity`.
const NAME_REVERIFY_INTERVAL_SECS: i64 = 78;
/// Cap on contacts re-verified per sweep, so a large contact list rolls through
/// instead of bursting dozens of simultaneous mixnet lookups at once.
const NAME_REVERIFY_MAX_PER_TICK: usize = 8;

/// Per-wallet nostr service.
pub struct NostrService {
	/// Identity keys (decrypted for the session).
	keys: Keys,
	/// Identity file state.
	pub identity: RwLock<NostrIdentity>,
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
	/// the relay connections (incl. the custom Nym mixnet transport) are driven
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
	/// Create the service for an unlocked identity.
	pub fn new(
		keys: Keys,
		identity: NostrIdentity,
		config: NostrConfig,
		store: NostrStore,
		nostr_dir: PathBuf,
	) -> Arc<Self> {
		Arc::new(Self {
			keys,
			identity: RwLock::new(identity),
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
		})
	}

	/// Own public key.
	pub fn public_key(&self) -> PublicKey {
		self.keys.public_key()
	}

	/// Own npub bech32.
	pub fn npub(&self) -> String {
		self.identity.read().npub.clone()
	}

	/// Shareable NIP-19 nprofile: our pubkey plus up to two of our relays as
	/// routing hints, so a sender can reach us without any registry or
	/// indexer lookup. Falls back to the bare npub when encoding fails.
	pub fn nprofile(&self) -> String {
		use nostr_sdk::RelayUrl;
		use nostr_sdk::nips::nip19::Nip19Profile;
		let relays: Vec<RelayUrl> = self
			.relays()
			.iter()
			.filter_map(|r| RelayUrl::parse(r).ok())
			.take(2)
			.collect();
		Nip19Profile::new(self.keys.public_key(), relays)
			.to_bech32()
			.ok()
			.unwrap_or_else(|| self.npub())
	}

	/// Own nsec (secret key) bech32 — for explicit user backup only.
	pub fn nsec(&self) -> Option<String> {
		self.keys.secret_key().to_bech32().ok()
	}

	/// The service's signing keys, for in-process signing (e.g. NIP-98 auth)
	/// without ever serializing the secret to a plaintext `String`.
	pub fn keys(&self) -> Keys {
		self.keys.clone()
	}

	/// Fetch a pubkey's published kind-0 profile (one shot, short timeout).
	/// `Some` means the key is a live nostr identity; `None` means no profile is
	/// published (new/anonymous key) or the relays were unreachable. `hints` are
	/// extra relays to dial first — the profile may live only on the target's own
	/// relays (NIP-65/gossip), which we won't otherwise be connected to. Blocking;
	/// call from a worker thread.
	pub fn fetch_profile_blocking(&self, hex: &str, hints: &[String]) -> Option<NostrProfile> {
		let client = self.client.read().clone()?;
		let pk = PublicKey::from_hex(hex).ok()?;
		let hints: Vec<String> = hints.to_vec();
		// Run on the SERVICE runtime — the relay connections (and the custom Nym
		// mixnet transport) live there. A throwaway current-thread runtime can't
		// drive them, which is why bare-npub profile lookups silently returned
		// nothing even though the relay serves the kind-0 fine.
		let handle = self.rt_handle.read().clone()?;
		let own_relays = self.relays();
		handle.block_on(async {
			// Dial the target's own relays (hints) AND our own relay set so the
			// kind-0 is reachable whether it lives on their relays or ours (most
			// Goblin users share relay.goblin.st). Without this, a bare-npub scan
			// only queried whatever happened to be connected and often saw nothing.
			let mut dial: Vec<String> = hints.clone();
			for r in &own_relays {
				if !dial.contains(r) {
					dial.push(r.clone());
				}
			}
			if !dial.is_empty() {
				connect_relays(&client, &dial).await;
			}
			let filter = Filter::new().kind(Kind::Metadata).author(pk).limit(1);
			let events = client
				.fetch_events(filter, Duration::from_secs(10))
				.await
				.ok()?;
			let md: Metadata = serde_json::from_str(&events.first()?.content).ok()?;
			Some(NostrProfile {
				name: md.name.filter(|s| !s.is_empty()),
				nip05: md.nip05.filter(|s| !s.is_empty()),
			})
		})
	}

	/// Best-effort read of a pubkey's published "accepts requests" preference.
	/// `Some(false)` = explicitly not accepting; `Some(true)`/`None` (no profile,
	/// field absent, or relays unreachable) = treat as accepting. Async — safe to
	/// call from the service runtime. Fail-open: only `Some(false)` blocks.
	pub async fn accepts_requests(&self, hex: &str) -> Option<bool> {
		let client = self.client.read().clone()?;
		let pk = PublicKey::from_hex(hex).ok()?;
		let filter = Filter::new().kind(Kind::Metadata).author(pk).limit(1);
		let events = client
			.fetch_events(filter, Duration::from_secs(8))
			.await
			.ok()?;
		let md: Metadata = serde_json::from_str(&events.first()?.content).ok()?;
		md.custom
			.get("goblin_accepts_requests")
			.and_then(|v| v.as_bool())
	}

	/// Republish our kind-0 profile + kind-10050 DM relays (e.g. after toggling
	/// the incoming-requests preference) so the change propagates immediately.
	pub async fn republish_identity(self: &Arc<Self>) {
		let client = { self.client.read().clone() };
		if let Some(client) = client {
			publish_identity(self, &client).await;
		}
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

	/// Current relay list.
	pub fn relays(&self) -> Vec<String> {
		self.config.read().relays()
	}

	/// Auto-expire stale pending transactions after the configured window
	/// (`NostrConfig::expiry_secs`, default 24h). A transaction that never
	/// completed is canceled/expired:
	/// - Outgoing sends and invoices we paid LOCK our outputs, so they are
	///   cancelled at the wallet level (reusing GRIM's `cancel_tx` via
	///   `WalletTask::Cancel`) to release those funds.
	/// - Incoming payments and invoices we issued lock nothing of ours, so we
	///   only annotate the metadata `Cancelled`; if a payment posts late,
	///   on-chain confirmation still wins (the UI only shows "canceled" while
	///   unconfirmed).
	/// - Pending incoming requests become `Expired`.
	///
	/// Runs from the wallet sync loop, so a lowered `expiry_secs` (set in
	/// `nostr.toml` for testing) takes effect within a sync cycle.
	pub fn expire_stale(&self, wallet: &Wallet) {
		let now = unix_time();
		let window = self.config.read().expiry_secs();
		if window <= 0 {
			return;
		}

		let stale: Vec<TxNostrMeta> = self
			.store
			.all_tx_meta()
			.into_iter()
			.filter(|m| !expiry_terminal(m.status))
			.filter(|m| now - m.created_at > window)
			.collect();

		if !stale.is_empty() {
			// Map slate uuid → wallet tx id once (public wallet data), so we can
			// cancel the underlying GRIM tx for the funds-locking cases.
			let tx_ids: HashMap<String, u32> = wallet
				.get_data()
				.and_then(|d| d.txs)
				.map(|txs| {
					txs.iter()
						.filter_map(|t| t.data.tx_slate_id.map(|u| (u.to_string(), t.data.id)))
						.collect()
				})
				.unwrap_or_default();

			for meta in stale {
				// Only outgoing sends + invoices we paid lock our outputs.
				if expiry_locks_outputs(meta.direction, meta.status) {
					if let Some(&tx_id) = tx_ids.get(&meta.slate_id) {
						info!(
							"nostr: expiring stale send {} → cancel wallet tx {}",
							meta.slate_id, tx_id
						);
						wallet.task(WalletTask::Cancel(tx_id));
					}
				} else {
					info!(
						"nostr: expiring stale {} ({:?})",
						meta.slate_id, meta.direction
					);
				}
				self.store
					.update_tx_status(&meta.slate_id, NostrSendStatus::Cancelled);
			}
		}

		// Incoming payment requests we never approved.
		for req in self.store.pending_requests() {
			if now - req.received_at > window {
				info!("nostr: expiring stale incoming request {}", req.rumor_id);
				self.store
					.update_request_status(&req.rumor_id, RequestStatus::Expired);
			}
		}
	}

	/// Sliding-window rate limiter, true when the event is allowed.
	fn allow_sender(&self, sender: &str, is_contact: bool) -> bool {
		let max = if is_contact {
			RATE_CONTACT_PER_HOUR
		} else {
			RATE_UNKNOWN_PER_HOUR
		};
		let now = unix_time();
		let mut rate = self.rate.lock();
		let hits = rate.entry(sender.to_string()).or_default();
		hits.retain(|t| now - *t < 3600);
		if hits.len() >= max {
			return false;
		}
		hits.push(now);
		if rate.len() > 10_000 {
			rate.retain(|_, v| v.iter().any(|t| now - *t < 3600));
		}
		true
	}

	/// Global ceiling on gift-wrap decrypt attempts across ALL senders. The
	/// per-sender limit only kicks in after the (expensive) NIP-44 decrypt
	/// reveals the sender, so an attacker minting unlimited fresh keypairs
	/// would otherwise force unbounded decrypts. Bounds total decrypt work to
	/// ~2/sec — far above any legitimate inbound rate.
	fn allow_global_unwrap(&self) -> bool {
		const GLOBAL_PER_MIN: usize = 120;
		let now = unix_time();
		let mut rate = self.rate.lock();
		let hits = rate.entry("\0global".to_string()).or_default();
		hits.retain(|t| now - *t < 60);
		if hits.len() >= GLOBAL_PER_MIN {
			return false;
		}
		hits.push(now);
		true
	}

	/// Dispatch a payment DM (slatepack + optional note) to a recipient,
	/// publishing to their DM relays plus our own relay set. `relay_hints`
	/// are extra recipient relays carried by an nprofile the sender pasted
	/// or scanned — the only routing info we have for a fresh recipient
	/// whose kind 10050 isn't discoverable from our relays.
	pub async fn send_payment_dm(
		&self,
		receiver_hex: &str,
		slatepack: &str,
		note: Option<&str>,
		relay_hints: &[String],
	) -> Result<String, String> {
		let client = {
			let r_client = self.client.read();
			r_client.clone().ok_or("nostr client is not running")?
		};
		let receiver =
			PublicKey::from_hex(receiver_hex).map_err(|e| format!("invalid receiver: {e}"))?;
		let content = protocol::build_payment_content(slatepack);
		let tags = protocol::build_rumor_tags(note);

		// Resolve receiver DM relays (kind 10050) with our relays as fallback.
		let mut urls = self.fetch_dm_relays(&client, &receiver).await;
		for r in relay_hints {
			if !urls.contains(r) {
				urls.push(r.clone());
			}
		}
		for r in self.relays() {
			if !urls.contains(&r) {
				urls.push(r);
			}
		}

		// NIP-17 delivers to the RECIPIENT's relays, which may differ from ours;
		// dial any we don't already hold so the gift wrap actually reaches their
		// inbox (otherwise `send_*_to` errors "relay not found" / never arrives).
		connect_relays(&client, &urls).await;

		let res = tokio::time::timeout(
			SEND_TIMEOUT,
			client.send_private_msg_to(urls, receiver, content, tags),
		)
		.await
		.map_err(|_| "send timeout".to_string())?
		.map_err(|e| format!("send failed: {e}"))?;
		Ok(res.val.to_hex())
	}

	/// Dispatch a control DM that voids a pending request (a decline by the payer
	/// or a cancel by the requester) to `receiver_hex`, referencing `slate_id`.
	/// Same routing as a payment DM, but the message carries no slatepack.
	pub async fn send_control_dm(
		&self,
		receiver_hex: &str,
		slate_id: &str,
		relay_hints: &[String],
	) -> Result<String, String> {
		let client = {
			let r_client = self.client.read();
			r_client.clone().ok_or("nostr client is not running")?
		};
		let receiver =
			PublicKey::from_hex(receiver_hex).map_err(|e| format!("invalid receiver: {e}"))?;
		let content = protocol::build_control_content();
		let tags = protocol::build_control_tags(slate_id);

		let mut urls = self.fetch_dm_relays(&client, &receiver).await;
		for r in relay_hints {
			if !urls.contains(r) {
				urls.push(r.clone());
			}
		}
		for r in self.relays() {
			if !urls.contains(&r) {
				urls.push(r);
			}
		}

		connect_relays(&client, &urls).await;

		let res = tokio::time::timeout(
			SEND_TIMEOUT,
			client.send_private_msg_to(urls, receiver, content, tags),
		)
		.await
		.map_err(|_| "send timeout".to_string())?
		.map_err(|e| format!("send failed: {e}"))?;
		Ok(res.val.to_hex())
	}

	/// Fetch a contact's kind 10050 DM relay list from our relays.
	async fn fetch_dm_relays(&self, client: &Client, pk: &PublicKey) -> Vec<String> {
		// Use cached relays first.
		if let Some(contact) = self.store.contact(&pk.to_hex()) {
			if !contact.relays.is_empty() {
				return contact.relays.into_iter().take(MAX_DM_RELAYS).collect();
			}
		}
		let filter = Filter::new().kind(Kind::InboxRelays).author(*pk).limit(1);
		let mut out = vec![];
		if let Ok(events) = client.fetch_events(filter, FETCH_TIMEOUT).await {
			if let Some(event) = events.first() {
				for tag in event.tags.iter() {
					let parts = tag.as_slice();
					if parts.first().map(|s| s.as_str()) == Some("relay") {
						if let Some(url) = parts.get(1) {
							if out.len() < MAX_DM_RELAYS {
								out.push(url.trim_end_matches('/').to_string());
							}
						}
					}
				}
			}
		}
		// Cache discovered relays on the contact when present.
		if !out.is_empty() {
			if let Some(mut contact) = self.store.contact(&pk.to_hex()) {
				contact.relays = out.clone();
				self.store.save_contact(&contact);
			}
		}
		out
	}

	/// Ensure a contact entry exists for a sender (auto-added as unknown).
	fn ensure_contact(&self, sender_hex: &str) {
		if self.store.contact(sender_hex).is_none() {
			// Guard the byte slice: callers pass 64-char hex today, but this is a
			// general helper and a short/non-ASCII key must not panic.
			let hue = sender_hex
				.get(..2)
				.and_then(|s| u8::from_str_radix(s, 16).ok())
				.unwrap_or(0)
				% 7;
			self.store.save_contact(&Contact {
				ver: 1,
				npub: sender_hex.to_string(),
				petname: None,
				nip05: None,
				nip05_verified_at: None,
				relays: vec![],
				hue,
				unknown: true,
				added_at: unix_time(),
				last_paid_at: None,
				blocked: false,
			});
		}
	}

	/// Best-effort: resolve and KEEP FRESH a contact's published `@username`.
	/// Incoming messages only carry the sender's key, so a fresh contact shows as
	/// a bare npub; this fetches their kind-0, and if it advertises a NIP-05 that
	/// maps back to their key, records it so the UI shows `@username`. It also
	/// re-validates an already-known name (older than the freshness window): if
	/// the server says the name was released or reassigned, it CLEARS it so the
	/// stale name stops showing; a transient network miss leaves it untouched.
	/// Spawns a worker; fail-open. A user-set petname is never touched.
	pub fn resolve_contact_identity(self: &Arc<Self>, sender_hex: &str) {
		let existing = self.store.contact(sender_hex);
		// Freshness gate: skip only if a name was verified recently. Older (or
		// never-verified) contacts are (re-)checked so releases get caught.
		if let Some(c) = &existing {
			if let (Some(_), Some(at)) = (&c.nip05, c.nip05_verified_at) {
				if unix_time() - at < NAME_REVERIFY_INTERVAL_SECS {
					return;
				}
			}
		}
		// Any DM relays we've already learned for them are the best hint for where
		// their profile lives (their messages came from there).
		let hints = existing
			.as_ref()
			.map(|c| c.relays.clone())
			.unwrap_or_default();
		let cached_nip05 = existing.and_then(|c| c.nip05);
		let svc = self.clone();
		let hex = sender_hex.to_string();
		thread::spawn(move || {
			let Ok(pk) = PublicKey::from_hex(&hex) else {
				return;
			};
			let Ok(rt) = tokio::runtime::Builder::new_current_thread()
				.enable_all()
				.build()
			else {
				return;
			};
			// Primary: ask the home authority directly what @name this key holds.
			// One HTTP round-trip, authoritative, and independent of whether we can
			// fetch their kind-0 off a relay (the fragile leg) — this is what
			// makes a contact's name show on the FIRST interaction.
			let home = crate::nostr::nip05::home_domain();
			if let Some(name) = rt.block_on(crate::nostr::nip05::name_by_pubkey(&home, &hex)) {
				let nip05 = format!("{}@{}", name, home);
				if let Some(mut c) = svc.store.contact(&hex) {
					if apply_nip05_check(&mut c, &nip05, crate::nostr::nip05::Nip05Check::Verified)
					{
						svc.store.save_contact(&c);
					}
				}
				return;
			}
			// Fallback: the handle they advertise in their kind-0 (covers FOREIGN
			// authorities the home reverse-lookup can't speak for); if the kind-0 can't
			// be fetched, fall back to the cached handle so a release is still caught.
			// This path can also CLEAR a released/reassigned name.
			let advertised = svc
				.fetch_profile_blocking(&hex, &hints)
				.and_then(|p| p.nip05);
			let Some(nip05) = advertised.or(cached_nip05) else {
				return; // anonymous and nothing cached — nothing to check
			};
			let Some((name, domain)) = nip05.split_once('@') else {
				return;
			};
			let check = rt.block_on(crate::nostr::nip05::check(&pk, name, domain));
			if let Some(mut c) = svc.store.contact(&hex) {
				if apply_nip05_check(&mut c, &nip05, check) {
					svc.store.save_contact(&c);
				}
			}
		});
	}
}

/// Apply a name re-check outcome to a contact in place; returns true if it
/// changed and should be saved. `Verified` records/refreshes the handle;
/// `Mismatch` (released or reassigned) clears it so the npub takes over;
/// `Unreachable` leaves it alone. A user-set petname is never touched.
fn apply_nip05_check(c: &mut Contact, nip05: &str, check: crate::nostr::nip05::Nip05Check) -> bool {
	use crate::nostr::nip05::Nip05Check;
	match check {
		Nip05Check::Verified => {
			c.nip05 = Some(nip05.to_string());
			c.nip05_verified_at = Some(unix_time());
			true
		}
		Nip05Check::Mismatch => {
			let had = c.nip05.is_some() || c.nip05_verified_at.is_some();
			c.nip05 = None;
			c.nip05_verified_at = None;
			had
		}
		Nip05Check::Unreachable => false,
	}
}

/// Main service loop: connect, publish identity, catch up, listen.
async fn run_service(svc: Arc<NostrService>, wallet: Wallet) {
	// Publish the service runtime handle so worker-thread one-shots (profile
	// lookups) can run their fetches here, where the relay I/O actually lives.
	*svc.rt_handle.write() = Some(tokio::runtime::Handle::current());
	// Mirror the configured name authority so resolution + display follow it.
	crate::nostr::nip05::set_home_domain(&svc.config.read().home_domain());
	let relays = svc.relays();
	info!(
		"nostr: starting service for {} with relays {:?}",
		svc.npub(),
		relays
	);

	let client = Client::builder()
		.signer(svc.keys.clone())
		.websocket_transport(NymWebSocketTransport)
		.build();
	for relay in &relays {
		if let Err(e) = client.add_relay(relay.clone()).await {
			warn!("nostr: add relay {relay} failed: {e}");
		}
	}
	// Wait for the in-process Nym SOCKS5 proxy (:1080) before dialing relays.
	// `warm_up()` starts it at launch, but a fast wallet-open can beat the cold
	// mixnet bootstrap — and dialing before it's up drops every relay into
	// nostr-sdk's backing-off reconnect, leaving the wallet on "Connecting…" long
	// after the mixnet is actually ready. Once it's warm this returns immediately.
	for i in 0..60u32 {
		if nym_socks_ready().await {
			if i > 0 {
				info!(
					"nostr: Nym proxy ready after ~{}ms, dialing relays",
					i * 500
				);
			}
			break;
		}
		tokio::time::sleep(Duration::from_millis(500)).await;
	}
	let connect_started = std::time::Instant::now();
	client.connect().await;
	{
		let mut w_client = svc.client.write();
		*w_client = Some(client.clone());
	}

	// Log when the first relay reaches Connected over the mixnet, measured from
	// the connect() call. Non-blocking; exits on first success.
	{
		let client_probe = client.clone();
		let svc_probe = svc.clone();
		tokio::spawn(async move {
			loop {
				tokio::time::sleep(Duration::from_millis(250)).await;
				if relays_connected(&client_probe).await {
					info!(
						"nostr: first relay Connected ~{}ms after connect()",
						connect_started.elapsed().as_millis()
					);
					return;
				}
				if svc_probe.shutdown.load(Ordering::SeqCst)
					|| connect_started.elapsed() > Duration::from_secs(150)
				{
					warn!(
						"nostr: no relay Connected within {}ms of connect()",
						connect_started.elapsed().as_millis()
					);
					return;
				}
			}
		});
	}

	// Publish identity events (kind 10050 DM relays; kind 0 only when named).
	publish_identity(&svc, &client).await;

	// Catch-up + live subscription for our gift wraps.
	let since = svc
		.store
		.last_connected_at()
		.map(|t| t - LOOKBACK_SECS)
		.unwrap_or_else(|| unix_time() - LOOKBACK_SECS)
		.max(0) as u64;
	let filter = Filter::new()
		.kind(Kind::GiftWrap)
		.pubkey(svc.public_key())
		.since(Timestamp::from_secs(since));

	if let Ok(events) = client.fetch_events(filter.clone(), FETCH_TIMEOUT).await {
		info!("nostr: catch-up fetched {} wraps", events.len());
		for event in events.into_iter() {
			handle_wrap(&svc, &wallet, &client, event).await;
		}
	}
	if let Err(e) = client.subscribe(filter, None).await {
		error!("nostr: subscribe failed: {e}");
	}

	// Re-dispatch pending outgoing messages after restart.
	reconcile(&svc, &wallet).await;

	// Backfill @usernames for contacts we only know by npub (e.g. from before
	// this resolved on every interaction), so activity shows names not keys.
	for contact in svc.store.all_contacts() {
		if contact.nip05.is_none() || contact.nip05_verified_at.is_none() {
			svc.resolve_contact_identity(&contact.npub);
		}
	}

	svc.store.set_last_connected_at(unix_time());
	svc.store.prune_processed();

	// Reflect the connection the moment we reach the loop instead of leaving the
	// UI on "Connecting…" until the first heartbeat — by now catch-up has run, so
	// a relay is typically already up.
	svc.connected
		.store(relays_connected(&client).await, Ordering::Relaxed);

	let mut notifications = client.notifications();
	// Poll connection state on a SHORT, INDEPENDENT interval. This used to live in
	// the `select!` behind a `sleep(30s)` that restarted on every notification, so
	// the flag could lag the real relay state by 30s+ (or, under steady event
	// flow, never update) — that's the "stuck on Connecting…" the mixnet gets
	// blamed for, even though a relay handshake over Nym takes ~2s. An `interval`
	// fires on its own schedule regardless of notifications; the heavier heartbeat
	// work (persisting last-seen, TTL pruning) stays on a ~30s cadence.
	let mut status_tick = tokio::time::interval(Duration::from_secs(2));
	status_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
	let mut last_heartbeat = unix_time();
	let mut last_prune = unix_time();
	// Seed from the persisted sweep time, NOT now: a fresh launch should re-check
	// names right away (so you see refreshed info from app open), unless one ran
	// within the last interval.
	let mut last_name_sweep = svc.store.last_name_sweep_at().unwrap_or(0);
	loop {
		if svc.shutdown.load(Ordering::SeqCst) || !wallet.is_open() {
			break;
		}
		tokio::select! {
			notification = notifications.recv() => {
				match notification {
					Ok(RelayPoolNotification::Event { event, .. }) => {
						handle_wrap(&svc, &wallet, &client, *event).await;
					}
					Ok(_) => {}
					Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
						warn!("nostr: notifications lagged by {n}");
					}
					Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
				}
			}
			_ = status_tick.tick() => {
				svc.connected
					.store(relays_connected(&client).await, Ordering::Relaxed);
				let now = unix_time();
				if now - last_heartbeat >= 30 {
					last_heartbeat = now;
					svc.store.set_last_connected_at(now);
					if now - last_prune >= 3600 {
						svc.store.prune_processed();
						last_prune = now;
					}
				}
				// Re-validate cached @usernames so a released/reassigned name
				// stops showing. Only the stalest few per sweep (capped) to bound
				// mixnet lookups; each worker re-checks against the identity server.
				// Skipped while the app is backgrounded — no point spending mixnet
				// round-trips when nobody's looking. We DON'T advance last_name_sweep
				// in that case, so the very next foreground tick runs the sweep
				// immediately to catch up on resume.
				if now - last_name_sweep >= NAME_REVERIFY_INTERVAL_SECS && crate::app_foreground() {
					last_name_sweep = now;
					svc.store.set_last_name_sweep_at(now);
					let mut due: Vec<_> = svc
						.store
						.all_contacts()
						.into_iter()
						.filter(|c| {
							c.nip05.is_some()
								&& c.nip05_verified_at
									.map(|at| now - at >= NAME_REVERIFY_INTERVAL_SECS)
									.unwrap_or(true)
						})
						.collect();
					// Stalest first (oldest verification), so a big list rolls through.
					due.sort_by_key(|c| c.nip05_verified_at.unwrap_or(0));
					for c in due.into_iter().take(NAME_REVERIFY_MAX_PER_TICK) {
						svc.resolve_contact_identity(&c.npub);
					}
				}
			}
		}
	}

	{
		let mut w_client = svc.client.write();
		*w_client = None;
	}
	client.disconnect().await;
}

/// Quick, non-blocking check that the Nym SOCKS5 proxy is accepting
/// connections on its loopback port (i.e. the mixnet is ready to carry traffic).
async fn nym_socks_ready() -> bool {
	matches!(
		tokio::time::timeout(
			Duration::from_millis(500),
			tokio::net::TcpStream::connect(crate::nym::socks5_addr()),
		)
		.await,
		Ok(Ok(_))
	)
}

/// Add + dial every relay in `urls` so a targeted send reaches relays we don't
/// already hold (NIP-65/gossip: the recipient's relays may differ from ours).
/// `add_relay` is idempotent and `try_connect_relay` returns once connected or
/// the timeout lapses; dialed concurrently so a slow relay doesn't stall the rest.
async fn connect_relays(client: &Client, urls: &[String]) {
	let dials = urls.iter().map(|url| {
		let url = url.clone();
		async move {
			let _ = client.add_relay(&url).await;
			// Short cap: a reachable relay connects in ~2-4s over the mixnet; we
			// don't want one dead relay in the list to stall the whole send. Once
			// connected it stays connected, so only the first send pays this.
			let _ = client.try_connect_relay(&url, Duration::from_secs(6)).await;
		}
	});
	futures::future::join_all(dials).await;
}

/// True when at least one relay has completed its handshake.
async fn relays_connected(client: &Client) -> bool {
	client
		.relays()
		.await
		.values()
		.any(|r| r.status() == RelayStatus::Connected)
}

/// Publish kind 10050 DM relay list and, for named identities, kind 0 metadata.
async fn publish_identity(svc: &Arc<NostrService>, client: &Client) {
	let relays = svc.relays();
	let dm_tags: Vec<Tag> = relays
		.iter()
		.take(MAX_DM_RELAYS)
		.map(|r| Tag::custom(TagKind::custom("relay"), [r.clone()]))
		.collect();
	let builder = EventBuilder::new(Kind::InboxRelays, "").tags(dm_tags);
	if let Err(e) = client.send_event_builder(builder).await {
		warn!("nostr: publish 10050 failed: {e}");
	}

	let (anonymous, nip05) = {
		let identity = svc.identity.read();
		(identity.anonymous, identity.nip05.clone())
	};
	if !anonymous {
		if let Some(nip05) = nip05 {
			let name = nip05.split('@').next().unwrap_or_default().to_string();
			// Advertise the request opt-out so requesters see it before sending.
			let allow_requests = svc.config.read().allow_incoming_requests();
			let metadata = Metadata::new()
				.name(name)
				.nip05(nip05)
				.custom_field("goblin_accepts_requests", allow_requests);
			let builder = EventBuilder::metadata(&metadata);
			if let Err(e) = client.send_event_builder(builder).await {
				warn!("nostr: publish kind 0 failed: {e}");
			}
		}
	}
}

/// A transaction in a terminal state never expires (already done or canceled).
fn expiry_terminal(status: NostrSendStatus) -> bool {
	matches!(
		status,
		NostrSendStatus::Finalized | NostrSendStatus::Cancelled
	)
}

/// Whether an expired transaction with this (direction, status) locked OUR
/// outputs and therefore needs a wallet-level `cancel_tx` to release them
/// (outgoing sends and invoices we paid). Incoming payments and invoices we
/// issued lock nothing of ours, so those are only annotated as canceled.
fn expiry_locks_outputs(direction: NostrTxDirection, status: NostrSendStatus) -> bool {
	matches!(
		(direction, status),
		(NostrTxDirection::Sent, NostrSendStatus::Created)
			| (NostrTxDirection::Sent, NostrSendStatus::AwaitingS2)
			| (NostrTxDirection::Sent, NostrSendStatus::SendFailed)
			| (
				NostrTxDirection::RequestedOfUs,
				NostrSendStatus::PaidAwaitingFinalize
			)
	)
}

/// Re-dispatch our pending outgoing messages (crash/offline recovery).
async fn reconcile(svc: &Arc<NostrService>, wallet: &Wallet) {
	let now = unix_time();
	for meta in svc.store.all_tx_meta() {
		if now - meta.created_at > RESEND_WINDOW_SECS {
			continue;
		}
		let resend_state = match (meta.direction, meta.status) {
			// S1 never dispatched or failed.
			(NostrTxDirection::Sent, NostrSendStatus::Created)
			| (NostrTxDirection::Sent, NostrSendStatus::SendFailed) => {
				Some(grin_wallet_libwallet::SlateState::Standard1)
			}
			// I1 request never dispatched or failed.
			(NostrTxDirection::RequestedByUs, NostrSendStatus::Created)
			| (NostrTxDirection::RequestedByUs, NostrSendStatus::SendFailed) => {
				Some(grin_wallet_libwallet::SlateState::Invoice1)
			}
			// We received and processed S1 but the S2 reply may not have left.
			(NostrTxDirection::Received, NostrSendStatus::ReceivedNoReply) => {
				Some(grin_wallet_libwallet::SlateState::Standard2)
			}
			// We paid a request (I2) but the reply may not have left.
			(NostrTxDirection::RequestedOfUs, NostrSendStatus::ReceivedNoReply) => {
				Some(grin_wallet_libwallet::SlateState::Invoice2)
			}
			_ => None,
		};
		let Some(state) = resend_state else { continue };
		let Ok(slate_id) = uuid::Uuid::parse_str(&meta.slate_id) else {
			continue;
		};
		let Some(text) = wallet.read_slatepack_text(slate_id, &state) else {
			continue;
		};
		info!(
			"nostr: reconcile re-dispatch {} ({:?})",
			meta.slate_id, state
		);
		match svc
			.send_payment_dm(&meta.npub, &text, meta.note.as_deref(), &[])
			.await
		{
			Ok(event_id) => {
				let mut updated = meta.clone();
				updated.sent_event_id = Some(event_id);
				updated.status = match state {
					grin_wallet_libwallet::SlateState::Standard1 => NostrSendStatus::AwaitingS2,
					grin_wallet_libwallet::SlateState::Invoice1 => NostrSendStatus::AwaitingI2,
					grin_wallet_libwallet::SlateState::Standard2 => NostrSendStatus::RepliedS2,
					_ => NostrSendStatus::PaidAwaitingFinalize,
				};
				updated.updated_at = unix_time();
				svc.store.save_tx_meta(&updated);
			}
			Err(e) => warn!(
				"nostr: reconcile dispatch failed for {}: {e}",
				meta.slate_id
			),
		}
	}
}

/// Full guarded pipeline for one incoming gift wrap event.
/// Apply a request-void control message. Two roles, distinguished by what we
/// hold for `slate_id`; in both the `sender` must match the stored counterparty,
/// so an attacker can't void a request they're not party to.
fn handle_request_void(svc: &Arc<NostrService>, wallet: &Wallet, slate_id: &str, sender: &str) {
	// Role A — we are the payer and the requester withdrew. Drop the pending card.
	let mut voided = false;
	for req in svc.store.pending_requests() {
		if req.slate_id == slate_id && req.npub == sender {
			info!(
				"nostr: incoming request {} withdrawn by requester",
				req.rumor_id
			);
			svc.store
				.update_request_status(&req.rumor_id, RequestStatus::Cancelled);
			svc.has_new_requests.store(true, Ordering::Relaxed);
			voided = true;
		}
	}
	if voided {
		return;
	}
	// The `sender` must match the stored counterparty (binding checked below) so
	// a stranger can't void someone else's tx.
	let Some(meta) = svc.store.tx_meta(slate_id) else {
		return;
	};
	if meta.npub != sender {
		return;
	}
	match (meta.direction, meta.status) {
		// Role B — we are the requester and the payer declined our invoice. An
		// issued invoice locks no outputs of ours, so cancelling the grin tx is
		// safe and keeps the ledger tidy.
		(NostrTxDirection::RequestedByUs, NostrSendStatus::Created)
		| (NostrTxDirection::RequestedByUs, NostrSendStatus::AwaitingI2) => {
			info!("nostr: outgoing request {slate_id} declined by payer");
			if let Some(tx_id) = wallet.get_data().and_then(|d| d.txs).and_then(|txs| {
				txs.iter()
					.find(|t| {
						t.data.tx_slate_id.map(|u| u.to_string()).as_deref() == Some(slate_id)
					})
					.map(|t| t.data.id)
			}) {
				wallet.task(WalletTask::Cancel(tx_id));
			}
			svc.store
				.update_tx_status(slate_id, NostrSendStatus::Cancelled);
		}
		// Role C — we received a payment the SENDER now says is void. Only mark
		// the meta cancelled for display; do NOT cancel the grin tx. Cancelling a
		// received tx DELETES our incoming output from wallet tracking, and a
		// malicious sender could void-then-still-finalize (they hold our S2 once
		// we replied), confirming funds our wallet would no longer see. Leaving
		// the output tracked means it still confirms if they post; if they don't,
		// it simply never confirms (and shows Cancelled while unconfirmed).
		(NostrTxDirection::Received, NostrSendStatus::ReceivedNoReply)
		| (NostrTxDirection::Received, NostrSendStatus::RepliedS2) => {
			info!("nostr: incoming payment {slate_id} voided by sender");
			svc.store
				.update_tx_status(slate_id, NostrSendStatus::Cancelled);
		}
		_ => {}
	}
}

async fn handle_wrap(svc: &Arc<NostrService>, wallet: &Wallet, client: &Client, event: Event) {
	// 0. Only gift wraps.
	if event.kind != Kind::GiftWrap {
		return;
	}
	let wrap_id = event.id.to_hex();
	// 1. Cheap size cap before any crypto.
	if event.content.len() > protocol::MAX_WRAP_CONTENT {
		svc.store.mark_processed(&wrap_id);
		return;
	}
	// 2. Wrap-level dedupe.
	if svc.store.is_processed(&wrap_id) {
		return;
	}
	// 2.5 Global decrypt ceiling: bound total NIP-44 unwrap work regardless of
	// sender, so fresh-keypair spam can't burn unbounded CPU/battery. Not marked
	// processed — a genuine backlog re-attempts once the window reopens.
	if !svc.allow_global_unwrap() {
		return;
	}
	// 3. Unwrap (NIP-59: seal signature is verified, rumor must not be signed).
	let unwrapped = match client.unwrap_gift_wrap(&event).await {
		Ok(u) => u,
		Err(_) => {
			svc.store.mark_processed(&wrap_id);
			return;
		}
	};
	let sender = unwrapped.sender;
	let mut rumor = unwrapped.rumor;
	// 4. The rumor author must be the seal signer (NIP-17 requirement).
	if rumor.pubkey != sender {
		warn!("nostr: rumor author differs from seal signer, dropping");
		svc.store.mark_processed(&wrap_id);
		return;
	}
	// Ignore our own messages (e.g. wrap-to-self copies).
	if sender == svc.public_key() {
		svc.store.mark_processed(&wrap_id);
		return;
	}
	// 5. Only kind 14 with bounded content.
	if rumor.kind != Kind::PrivateDirectMessage || rumor.content.len() > protocol::MAX_RUMOR_CONTENT
	{
		svc.store.mark_processed(&wrap_id);
		return;
	}
	let sender_hex = sender.to_hex();
	// Blocked sender: drop silently, a nostr-level mute. Mark processed so we
	// don't reconsider it on every catch-up.
	if svc
		.store
		.contact(&sender_hex)
		.map(|c| c.blocked)
		.unwrap_or(false)
	{
		svc.store.mark_processed(&wrap_id);
		return;
	}
	let is_contact = svc
		.store
		.contact(&sender_hex)
		.map(|c| !c.unknown)
		.unwrap_or(false);
	// 6. Rate limit per sender.
	if !svc.allow_sender(&sender_hex, is_contact) {
		// Deliberately NOT marked processed: legitimate bursts can retry later.
		return;
	}
	// 7. Rumor-level dedupe (the same rumor can arrive in different wraps).
	let rumor_id = rumor.id().to_hex();
	if svc.store.is_processed(&rumor_id) {
		svc.store.mark_processed(&wrap_id);
		return;
	}
	// 8. Request-void control message (a decline by the payer or a cancel by the
	// requester): it carries no slatepack, just an action tag naming a slate id.
	// Handle it before slatepack extraction; the sender is bound to the stored
	// counterparty inside, so a stranger can't void someone else's request.
	if let Some(void_slate_id) = protocol::extract_control(&rumor.tags) {
		handle_request_void(svc, wallet, &void_slate_id, &sender_hex);
		// A decline/cancel is still an interaction with a known counterparty —
		// (re)resolve their @name so it never drops to a bare npub just because the
		// request didn't go through. Cheap, authoritative (reverse lookup), and a
		// no-op for anonymous keys.
		svc.resolve_contact_identity(&sender_hex);
		// Record the void keyed by (slate, sender) so a payment S1 that arrives
		// AFTER its void (relays reorder; NIP-59 randomizes timestamps) is dropped.
		// Binding to the sender stops a stranger pre-voiding someone else's slate.
		// A slate id is a UUID (36 chars); ignore anything longer so an attacker
		// can't bloat the processed-key store with an oversized tag value.
		if void_slate_id.len() <= 64 {
			svc.store
				.mark_processed(&format!("void:{}:{}", void_slate_id, sender_hex));
		}
		svc.store.mark_processed(&wrap_id);
		svc.store.mark_processed(&rumor_id);
		return;
	}
	// 8b. Extract the slatepack; non-payment DMs are ignored entirely.
	let Some(armor) = protocol::extract_slatepack(&rumor.content) else {
		svc.store.mark_processed(&wrap_id);
		svc.store.mark_processed(&rumor_id);
		return;
	};
	let note = protocol::extract_subject(&rumor.tags);
	// 9. Parse and validate the slate itself.
	let Ok((slate, _)) = wallet.parse_slatepack(&armor) else {
		svc.store.mark_processed(&wrap_id);
		svc.store.mark_processed(&rumor_id);
		return;
	};
	// 10. Slate-level dedupe.
	let slate_marker = format!("slate:{}:{}", slate.id, slate.state);
	if svc.store.is_processed(&slate_marker) {
		svc.store.mark_processed(&wrap_id);
		svc.store.mark_processed(&rumor_id);
		return;
	}
	// 10b. Void-before-payment: the sender cancelled this payment and the void
	// reached us before the S1. Drop the dead slate rather than auto-receiving it.
	if matches!(slate.state, grin_wallet_libwallet::SlateState::Standard1)
		&& svc
			.store
			.is_processed(&format!("void:{}:{}", slate.id, sender_hex))
	{
		info!(
			"nostr: dropping S1 for slate {} already voided by sender",
			slate.id
		);
		svc.store.mark_processed(&wrap_id);
		svc.store.mark_processed(&rumor_id);
		svc.store.mark_processed(&slate_marker);
		return;
	}
	// 11. Policy decision.
	let meta = svc.store.tx_meta(&slate.id.to_string());
	let tx_exists = wallet.has_tx_for_slate(&slate.id);
	let accept = svc.config.read().accept_from();
	let allow_requests = svc.config.read().allow_incoming_requests();
	let decision = decide(&IngestContext {
		state: slate.state.clone(),
		amount: slate.amount,
		sender: &sender_hex,
		meta: meta.as_ref(),
		tx_exists,
		is_contact,
		accept,
		allow_requests,
	});
	info!(
		"nostr: wrap {} slate {} state {} from {}…: {:?}",
		&wrap_id[..8],
		slate.id,
		slate.state,
		&sender_hex[..8],
		decision
	);

	match decision {
		IngestDecision::AutoReceive => {
			svc.ensure_contact(&sender_hex);
			// Resolve the sender's @username so the receive shows their name in
			// activity, not a bare npub.
			svc.resolve_contact_identity(&sender_hex);
			match wallet.nostr_receive(&slate) {
				Ok((_, reply_text)) => {
					// Record BEFORE dispatching the reply: crash here is
					// recovered by reconcile() re-sending the S2 from disk.
					let now = unix_time();
					svc.store.save_tx_meta(&TxNostrMeta {
						ver: 1,
						slate_id: slate.id.to_string(),
						npub: sender_hex.clone(),
						direction: NostrTxDirection::Received,
						note: note.clone(),
						status: NostrSendStatus::ReceivedNoReply,
						sent_event_id: None,
						received_rumor_id: Some(rumor_id.clone()),
						created_at: now,
						updated_at: now,
					});
					// Commit dedup markers now the receive is durable, BEFORE
					// the reply + sync tail. A crash there must not let this
					// wrap re-trigger a second receive on catch-up (decide()
					// and grin's TransactionAlreadyReceived also backstop it).
					svc.store.mark_processed(&wrap_id);
					svc.store.mark_processed(&rumor_id);
					svc.store.mark_processed(&slate_marker);
					match svc
						.send_payment_dm(&sender_hex, &reply_text, None, &[])
						.await
					{
						Ok(event_id) => {
							if let Some(mut meta) = svc.store.tx_meta(&slate.id.to_string()) {
								meta.status = NostrSendStatus::RepliedS2;
								meta.sent_event_id = Some(event_id);
								meta.updated_at = unix_time();
								svc.store.save_tx_meta(&meta);
							}
						}
						Err(e) => warn!("nostr: S2 reply dispatch failed: {e}"),
					}
					wallet.sync();
				}
				Err(e) => {
					error!("nostr: receive failed for slate {}: {:?}", slate.id, e);
				}
			}
		}
		IngestDecision::SurfaceIncoming | IngestDecision::SurfaceRequest => {
			svc.ensure_contact(&sender_hex);
			// Resolve the requester's @username so the card isn't a bare npub.
			svc.resolve_contact_identity(&sender_hex);
			svc.store.save_request(&PaymentRequest {
				ver: 1,
				rumor_id: rumor_id.clone(),
				slate_id: slate.id.to_string(),
				slatepack: armor.clone(),
				npub: sender_hex.clone(),
				amount: slate.amount,
				note: note.clone(),
				received_at: unix_time(),
				status: RequestStatus::Pending,
			});
			svc.has_new_requests.store(true, Ordering::Relaxed);
			// The request is durably saved — safe to mark this wrap processed.
			svc.store.mark_processed(&wrap_id);
			svc.store.mark_processed(&rumor_id);
			svc.store.mark_processed(&slate_marker);
		}
		IngestDecision::FinalizePost => {
			// The payer's reply is our first contact with their key on this side of
			// a request we sent — make sure they're a known contact and resolve their
			// @username so the completed request shows their name, not a bare npub.
			svc.ensure_contact(&sender_hex);
			svc.resolve_contact_identity(&sender_hex);
			match wallet.nostr_finalize_post(&slate) {
				Ok(true) => {
					svc.store
						.update_tx_status(&slate.id.to_string(), NostrSendStatus::Finalized);
					// Finalize+post committed; mark dedup before the sync tail so a
					// crash can't re-finalize on catch-up (grin rejects a second
					// finalize and the meta is now Finalized, which decide() drops —
					// this just avoids the redundant attempt).
					svc.store.mark_processed(&wrap_id);
					svc.store.mark_processed(&rumor_id);
					svc.store.mark_processed(&slate_marker);
					if let Some(mut contact) = svc.store.contact(&sender_hex) {
						contact.last_paid_at = Some(unix_time());
						svc.store.save_contact(&contact);
					}
					wallet.sync();
				}
				Ok(false) => {
					// The send was cancelled out-of-band (the meta usually already
					// reflects this and decide() drops the S2 before we get here; this
					// covers a tx-list cancel that left the meta untouched). Reconcile
					// the status and treat the reply as handled — never retry/re-post.
					svc.store
						.update_tx_status(&slate.id.to_string(), NostrSendStatus::Cancelled);
					svc.store.mark_processed(&wrap_id);
					svc.store.mark_processed(&rumor_id);
					svc.store.mark_processed(&slate_marker);
					info!("nostr: skipped finalize of cancelled slate {}", slate.id);
				}
				Err(e) => {
					error!("nostr: finalize failed for slate {}: {:?}", slate.id, e);
				}
			}
		}
		IngestDecision::Drop(reason) => {
			info!("nostr: dropped slate {}: {}", slate.id, reason);
			// A dropped slate is a permanent decision — don't re-evaluate it.
			svc.store.mark_processed(&wrap_id);
			svc.store.mark_processed(&rumor_id);
			svc.store.mark_processed(&slate_marker);
		}
	}
	// NOTE: AutoReceive and FinalizePost mark the wrap processed only inside their
	// success arms. On a transient failure they deliberately leave it UNMARKED so
	// the next catch-up fetch retries — otherwise an incoming payment could be
	// silently lost on a momentary wallet/node hiccup. decide() + grin's
	// already-received / re-post guards keep a retried success idempotent.
}

#[cfg(test)]
mod tests {
	use super::*;

	fn sample_contact() -> Contact {
		Contact {
			ver: 1,
			npub: "abc".to_string(),
			petname: Some("Mom".to_string()),
			nip05: Some("ada@goblin.st".to_string()),
			nip05_verified_at: Some(1000),
			relays: vec![],
			hue: 0,
			unknown: false,
			added_at: 1,
			last_paid_at: None,
			blocked: false,
		}
	}

	#[test]
	fn name_recheck_clears_on_mismatch_keeps_petname() {
		use crate::nostr::nip05::Nip05Check;
		// Released/reassigned → clear the handle, but never the user's petname.
		let mut c = sample_contact();
		assert!(apply_nip05_check(
			&mut c,
			"ada@goblin.st",
			Nip05Check::Mismatch
		));
		assert_eq!(c.nip05, None);
		assert_eq!(c.nip05_verified_at, None);
		assert_eq!(c.petname.as_deref(), Some("Mom"));

		// Unreachable → no change at all (don't drop a good name on a blip).
		let mut c = sample_contact();
		assert!(!apply_nip05_check(
			&mut c,
			"ada@goblin.st",
			Nip05Check::Unreachable
		));
		assert_eq!(c.nip05.as_deref(), Some("ada@goblin.st"));
		assert_eq!(c.nip05_verified_at, Some(1000));

		// Verified → record the handle and refresh the timestamp.
		let mut c = sample_contact();
		c.nip05 = None;
		c.nip05_verified_at = None;
		assert!(apply_nip05_check(
			&mut c,
			"bob@goblin.st",
			Nip05Check::Verified
		));
		assert_eq!(c.nip05.as_deref(), Some("bob@goblin.st"));
		assert!(c.nip05_verified_at.is_some());

		// Mismatch on an already-nameless contact → nothing to do.
		let mut c = sample_contact();
		c.nip05 = None;
		c.nip05_verified_at = None;
		assert!(!apply_nip05_check(
			&mut c,
			"ada@goblin.st",
			Nip05Check::Mismatch
		));
	}

	#[test]
	fn terminal_states_do_not_expire() {
		assert!(expiry_terminal(NostrSendStatus::Finalized));
		assert!(expiry_terminal(NostrSendStatus::Cancelled));
		// Everything in flight is eligible to expire.
		for s in [
			NostrSendStatus::Created,
			NostrSendStatus::AwaitingS2,
			NostrSendStatus::ReceivedNoReply,
			NostrSendStatus::RepliedS2,
			NostrSendStatus::AwaitingI2,
			NostrSendStatus::PaidAwaitingFinalize,
			NostrSendStatus::SendFailed,
		] {
			assert!(!expiry_terminal(s), "{s:?} should be expirable");
		}
	}

	#[test]
	fn only_our_committed_outputs_get_cancelled() {
		use NostrSendStatus::*;
		use NostrTxDirection::*;
		// Our sends (we locked outputs) and invoices we paid → cancel to unlock.
		assert!(expiry_locks_outputs(Sent, Created));
		assert!(expiry_locks_outputs(Sent, AwaitingS2));
		assert!(expiry_locks_outputs(Sent, SendFailed));
		assert!(expiry_locks_outputs(RequestedOfUs, PaidAwaitingFinalize));
		// Incoming payments and invoices we issued lock nothing of ours →
		// annotate only, never cancel a tx that could still settle/pay.
		assert!(!expiry_locks_outputs(Received, ReceivedNoReply));
		assert!(!expiry_locks_outputs(Received, RepliedS2));
		assert!(!expiry_locks_outputs(RequestedByUs, AwaitingI2));
		assert!(!expiry_locks_outputs(RequestedByUs, Created));
		assert!(!expiry_locks_outputs(RequestedOfUs, ReceivedNoReply));
	}
}
