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

//! Per-wallet nostr service: relay connections over the embedded Tor client,
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
use crate::tor::transport::ArtiWebSocketTransport;
use crate::wallet::Wallet;

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
			started: AtomicBool::new(false),
			shutdown: AtomicBool::new(false),
			connected: AtomicBool::new(false),
			has_new_requests: AtomicBool::new(false),
			rate: Mutex::new(HashMap::new()),
			send_phase: std::sync::atomic::AtomicU8::new(send_phase::IDLE),
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

	/// Fetch a pubkey's published kind-0 profile over the connected relay
	/// pool (one shot, short timeout). `Some` means the key is a live nostr
	/// identity; `None` means no profile is published (new/anonymous key) or
	/// the relays were unreachable. Blocking — call from a worker thread.
	pub fn fetch_profile_blocking(&self, hex: &str) -> Option<NostrProfile> {
		let client = self.client.read().clone()?;
		let pk = PublicKey::from_hex(hex).ok()?;
		let rt = tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
			.ok()?;
		rt.block_on(async {
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

	/// Set the outgoing-send phase (called by the send task + UI).
	pub fn set_send_phase(&self, phase: u8) {
		self.send_phase.store(phase, Ordering::Relaxed);
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
			let hue = u8::from_str_radix(&sender_hex[..2], 16).unwrap_or(0) % 7;
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
}

/// Main service loop: connect, publish identity, catch up, listen.
async fn run_service(svc: Arc<NostrService>, wallet: Wallet) {
	let relays = svc.relays();
	info!(
		"nostr: starting service for {} with relays {:?}",
		svc.npub(),
		relays
	);

	let client = Client::builder()
		.signer(svc.keys.clone())
		.websocket_transport(ArtiWebSocketTransport)
		.build();
	for relay in &relays {
		if let Err(e) = client.add_relay(relay.clone()).await {
			warn!("nostr: add relay {relay} failed: {e}");
		}
	}
	client.connect().await;
	{
		let mut w_client = svc.client.write();
		*w_client = Some(client.clone());
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

	svc.store.set_last_connected_at(unix_time());
	svc.store.prune_processed();

	let mut notifications = client.notifications();
	// Re-run TTL pruning periodically, not just at startup: a session that
	// never restarts would otherwise let the processed-dedup store grow
	// unbounded under fresh-keypair spam (the 30-day TTL never applied).
	let mut last_prune = unix_time();
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
			_ = tokio::time::sleep(Duration::from_secs(30)) => {
				// Heartbeat: persist last seen time, update connection state.
				svc.store.set_last_connected_at(unix_time());
				let connected = client.relays().await.values()
					.any(|r| r.status() == RelayStatus::Connected);
				svc.connected.store(connected, Ordering::Relaxed);
				if unix_time() - last_prune >= 3600 {
					svc.store.prune_processed();
					last_prune = unix_time();
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
	// 8. Extract the slatepack; non-payment DMs are ignored entirely.
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
		}
		IngestDecision::FinalizePost => match wallet.nostr_finalize_post(&slate) {
			Ok(()) => {
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
			Err(e) => {
				error!("nostr: finalize failed for slate {}: {:?}", slate.id, e);
			}
		},
		IngestDecision::Drop(reason) => {
			info!("nostr: dropped slate {}: {}", slate.id, reason);
		}
	}

	svc.store.mark_processed(&wrap_id);
	svc.store.mark_processed(&rumor_id);
	svc.store.mark_processed(&slate_marker);
}
