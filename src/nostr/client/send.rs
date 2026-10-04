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

//! DM send path: payment and control DMs, receipt/proof delivery wraps,
//! relay-target selection and the send allow-list gates.

use super::service::connect_relays;
use super::*;

impl NostrService {
	/// Sliding-window rate limiter, true when the event is allowed.
	pub(super) fn allow_sender(&self, sender: &str, is_contact: bool) -> bool {
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
	pub(super) fn allow_global_unwrap(&self) -> bool {
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

	/// The keys our identity `from_hex` seals and signs a wallet message with.
	/// Every outgoing message names its identity: the active one for a payment
	/// or request the user starts, the one recorded for the tx for a reply, a
	/// void, a re-send, a receipt or a proof. An identity that is no longer held
	/// (deleted since) is an error, never another identity: the counterparty
	/// would drop the message and learn that both identities are one wallet.
	pub fn sender_keys(&self, from_hex: &str) -> Result<Keys, String> {
		// A tx row written before identities were recorded on it names none.
		// Such a row uses the active identity, as every earlier build did.
		if from_hex.is_empty() {
			return Ok(self.keys());
		}
		held_keys_for(&self.recv.read(), from_hex)
	}

	/// The keys a receipt or proof of a payment is signed with: the identity
	/// that paid, or the active one when that identity is no longer held
	/// (deleted, or replaced by an import). Unlike a reply, nobody checks their
	/// sender (the merchant matches the order handle), and without them the
	/// order is never credited, so they never fail for want of the paying
	/// identity. The fallback is logged once per identity and order.
	fn payment_proof_keys(&self, from_hex: &str, order: &str) -> Keys {
		static LOGGED: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
		match self.sender_keys(from_hex) {
			Ok(keys) => keys,
			Err(e) => {
				let key = format!("{from_hex}:{order}");
				let first = LOGGED
					.lock()
					.map(|mut seen| {
						let first = !seen.contains(&key);
						if first && seen.len() < 256 {
							seen.push(key);
						}
						first
					})
					.unwrap_or(true);
				if first {
					warn!(
						"nostr: {e}; the receipt and proof for order {order} go out as the \
						 active identity"
					);
				}
				self.keys()
			}
		}
	}

	/// Our identity (pubkey hex) for an incoming request or surfaced payment:
	/// the one its wrap was addressed to. A request stored before Build 170
	/// has no record of it and uses the active identity, as before.
	pub fn request_identity(&self, request: &PaymentRequest) -> String {
		request
			.recipient_pubkey
			.clone()
			.unwrap_or_else(|| self.public_key().to_hex())
	}

	/// Move a tx row on after its message went out (Created to AwaitingS2 or
	/// AwaitingI2, ReceivedNoReply to RepliedS2 or PaidAwaitingFinalize), only
	/// while it is still in `left_at`, the status the sending task left it in.
	/// The publish can take a while: a fast reply may have finalized the row
	/// meanwhile, or the user cancelled it, and that must stand (a Finalized row
	/// still owes its proof; a Cancelled one must not reopen). Re-read under the
	/// finalize lock, as reconcile does. True when the row moved on.
	pub fn advance_after_dispatch(
		&self,
		slate_id: &str,
		left_at: NostrSendStatus,
		next: NostrSendStatus,
		event_id: String,
	) -> bool {
		let _lock = self.lock_finalize();
		let Some(mut meta) = self.store.tx_meta(slate_id) else {
			return false;
		};
		if meta.status != left_at {
			info!(
				"nostr: {slate_id} is {:?} now, not moved to {:?}",
				meta.status, next
			);
			return false;
		}
		meta.status = next;
		meta.sent_event_id = Some(event_id);
		meta.updated_at = unix_time();
		self.store.save_tx_meta(&meta);
		true
	}

	/// Record that the plain receipt of a send landed. Re-read under the
	/// finalize lock and only that flag changes, so a status written meanwhile
	/// (a fast reply finalized it, the user cancelled it) is kept.
	pub fn mark_receipt_sent(&self, slate_id: &str) {
		let _lock = self.lock_finalize();
		if let Some(mut meta) = self.store.tx_meta(slate_id) {
			meta.receipt_sent = true;
			meta.updated_at = unix_time();
			self.store.save_tx_meta(&meta);
		}
	}

	/// Dispatch a payment DM (slatepack + optional note) to a recipient,
	/// publishing to their DM relays plus our own relay set. `relay_hints`
	/// are extra recipient relays carried by an nprofile the sender pasted
	/// or scanned — the only routing info we have for a fresh recipient
	/// whose kind 10050 isn't discoverable from our relays. Sealed and signed
	/// by our identity `from_hex` (see [`Self::sender_keys`]).
	///
	/// One attempt, as Build 169 timed it: for the messages nobody waits for on
	/// screen (the auto-receive reply, a recovery re-send), which their own
	/// retry at the next service start covers.
	pub async fn send_payment_dm(
		&self,
		from_hex: &str,
		receiver_hex: &str,
		slatepack: &str,
		note: Option<&str>,
		relay_hints: &[String],
	) -> Result<String, String> {
		self.send_payment(
			Push::Short,
			from_hex,
			receiver_hex,
			slatepack,
			note,
			relay_hints,
		)
		.await
	}

	/// [`Self::send_payment_dm`] for a message the user starts and waits for on
	/// screen (a payment, a request, the reply of an approval): it is pushed
	/// until a relay accepts it or the budget is used, then read back before it
	/// may fail, because that failure cancels the payment.
	pub async fn send_payment_dm_on_screen(
		&self,
		from_hex: &str,
		receiver_hex: &str,
		slatepack: &str,
		note: Option<&str>,
		relay_hints: &[String],
	) -> Result<String, String> {
		self.send_payment(
			Push::Long,
			from_hex,
			receiver_hex,
			slatepack,
			note,
			relay_hints,
		)
		.await
	}

	async fn send_payment(
		&self,
		push: Push,
		from_hex: &str,
		receiver_hex: &str,
		slatepack: &str,
		note: Option<&str>,
		relay_hints: &[String],
	) -> Result<String, String> {
		let from = self.sender_keys(from_hex)?;
		let client = {
			let r_client = self.client.read();
			r_client.clone().ok_or("nostr client is not running")?
		};
		let receiver =
			PublicKey::from_hex(receiver_hex).map_err(|e| format!("invalid receiver: {e}"))?;
		let content = protocol::build_payment_content(slatepack);
		let tags = protocol::build_rumor_tags(note);

		let (urls, v3) = self.send_targets(&client, &receiver, relay_hints).await;

		// NIP-17 delivers to the RECIPIENT's relays, which may differ from ours;
		// dial any we don't already hold so the gift wrap actually reaches their
		// inbox (otherwise `send_*_to` errors "relay not found" / never arrives).
		connect_relays(&client, &urls).await;

		let wrap = build_dm_wrap(&from, &receiver, v3, content, tags).await?;
		self.dispatch_dm(&client, urls, &wrap, receiver, push).await
	}

	/// Dispatch a control DM that voids a pending request (a decline by the payer
	/// or a cancel by the requester) from our identity `from_hex` to
	/// `receiver_hex`, referencing `slate_id`.
	/// Same routing as a payment DM, but the message carries no slatepack.
	pub async fn send_control_dm(
		&self,
		from_hex: &str,
		receiver_hex: &str,
		slate_id: &str,
		relay_hints: &[String],
	) -> Result<String, String> {
		let from = self.sender_keys(from_hex)?;
		let client = {
			let r_client = self.client.read();
			r_client.clone().ok_or("nostr client is not running")?
		};
		let receiver =
			PublicKey::from_hex(receiver_hex).map_err(|e| format!("invalid receiver: {e}"))?;
		let content = protocol::build_control_content();
		let tags = protocol::build_control_tags(slate_id);

		let (urls, v3) = self.send_targets(&client, &receiver, relay_hints).await;

		connect_relays(&client, &urls).await;

		let wrap = build_dm_wrap(&from, &receiver, v3, content, tags).await?;
		self.dispatch_dm(&client, urls, &wrap, receiver, Push::Short)
			.await
	}

	/// Publish the plain "payment sent" receipt (frozen contract 4.3.1): a
	/// buyer-signed, UNENCRYPTED kind-17 to our app relays that flips the order
	/// page to "payment detected, confirming". It is buyer-signed and unverified,
	/// so the market NEVER treats it as "paid" (only the watcher's 4.4 event
	/// does). The proof and kernel excess are DELIBERATELY omitted here: a Grin
	/// payment proof carries the buyer's own slatepack address, and publishing it
	/// in the clear would leak the buyer's wallet address to the world. Signed
	/// by our identity `from_hex`, the one that paid (see
	/// [`Self::payment_proof_keys`]).
	pub async fn publish_receipt_sent(
		&self,
		from_hex: &str,
		order: &str,
		amount: u64,
	) -> Result<(), String> {
		let from = self.payment_proof_keys(from_hex, order);
		let client = {
			let r_client = self.client.read();
			r_client.clone().ok_or("nostr client is not running")?
		};
		let event = receipt_sent_event(&from, order, amount)?;
		let urls: Vec<String> = self.relays();
		publish(&client, &urls, &event, Push::Short)
			.await
			.map_err(|e| format!("receipt publish failed: {e}"))
	}

	/// Gift-wrap the full proof delivery (frozen contract 4.3.2) to the watcher's
	/// npub: a kind-17 rumor whose content is the Grin payment proof JSON verbatim,
	/// tagged with the invoice number, the amount, and the kernel excess. Encrypted
	/// end to end, so the proof (which contains the buyer's sender address) never
	/// goes out in the clear; only the addressed watcher can read it. Sealed and
	/// signed by our identity `from_hex`, the one that paid (see
	/// [`Self::payment_proof_keys`]).
	pub async fn deliver_proof_wrap(
		&self,
		from_hex: &str,
		notify_npub: &str,
		order: &str,
		amount: u64,
		kernel_hex: &str,
		proof_json: &str,
	) -> Result<(), String> {
		let from = self.payment_proof_keys(from_hex, order);
		let client = {
			let r_client = self.client.read();
			r_client.clone().ok_or("nostr client is not running")?
		};
		let receiver =
			PublicKey::from_bech32(notify_npub).map_err(|e| format!("invalid notify npub: {e}"))?;
		let tags = vec![
			Tag::custom(TagKind::custom("payment-request"), [order.to_string()]),
			Tag::custom(TagKind::custom("amount"), [amount.to_string()]),
			Tag::custom(TagKind::custom("kernel"), [kernel_hex.to_string()]),
			Tag::custom(TagKind::custom("status"), ["proof".to_string()]),
			Tag::custom(
				TagKind::custom(protocol::GOBLIN_TAG),
				[protocol::PROTOCOL_VERSION.to_string()],
			),
		];
		let wrap = wrapv3::wrap_kind(
			&from,
			&receiver,
			Kind::Custom(17),
			proof_json.to_string(),
			tags,
		)?;
		let urls: Vec<String> = self.relays();
		connect_relays(&client, &urls).await;
		publish(&client, &urls, &wrap, Push::Short)
			.await
			.map_err(|e| format!("proof delivery failed: {e}"))
	}

	/// Dispatch one gift-wrapped DM built by [`build_dm_wrap`] to `urls`.
	async fn dispatch_dm(
		&self,
		client: &Client,
		urls: Vec<String>,
		wrap: &Event,
		receiver: PublicKey,
		push: Push,
	) -> Result<String, String> {
		publish(client, &urls, wrap, push)
			.await
			.map_err(|e| format!("send failed: {e}"))?;
		let event_id = wrap.id;

		// The write already succeeded (a relay accepted the wrap for delivery),
		// which IS the send-level evidence the UI waits on — so return Sent NOW at
		// write-ack. The read-back delivery-confirm below is ADVISORY only (it
		// never changes the returned id and never marks the tx failed), so it runs
		// detached in the background: it keeps its logging/retry behavior without
		// pinning the spinner for up to CONFIRM_TIMEOUT after the wrap has landed.
		{
			let client = client.clone();
			let urls = urls.clone();
			tokio::spawn(async move {
				Self::confirm_delivery(&client, urls, receiver, event_id).await;
			});
		}
		Ok(event_id.to_hex())
	}

	/// Advisory delivery-confirm (money-path safety), reconnect-resilient, run in
	/// the background AFTER the send returns. `send_*_to` returned success the
	/// moment the wrap was accepted for delivery to the relays — that IS
	/// write-level evidence, but not proof a relay the RECIPIENT reads has stored
	/// it. Confirm the way the recipient's inbox retrieves it: query
	/// {kinds:[1059], "#p":[receiver]} pinned to THIS wrap's id, over the SAME
	/// target set — which always includes our own advertised relays (the
	/// shared-relay floor the recipient also reads; see `send_targets`). The loop
	/// retries across transient transport drops within the budget (arti rebuilds
	/// circuits during the CONFIRM_GAP sleeps), so a flapping onion doesn't defeat
	/// a wrap that actually landed. It NEVER fails the tx — an unconfirmed wrap
	/// simply waits for S2 / expiry (a hard failure would re-dispatch DUPLICATE
	/// wraps); this is purely a logged observation now that the UI no longer waits.
	async fn confirm_delivery(
		client: &Client,
		urls: Vec<String>,
		receiver: PublicKey,
		event_id: nostr_sdk::EventId,
	) {
		use futures::StreamExt;
		let confirm_filter = Filter::new()
			.kind(Kind::GiftWrap)
			.pubkey(receiver)
			.id(event_id)
			.limit(1);
		let confirm_deadline = tokio::time::Instant::now() + CONFIRM_TIMEOUT;
		loop {
			if let Ok(mut stream) = client
				.stream_events_from(urls.clone(), confirm_filter.clone(), CONFIRM_POLL)
				.await && stream.next().await.is_some()
			{
				return;
			}
			if tokio::time::Instant::now() >= confirm_deadline {
				warn!(
					"nostr: wrap {} dispatched but not read-back-confirmed within {}s \
					 (likely a transient transport drop); treating as sent-pending — \
					 tx waits for S2 / expiry, NOT re-dispatched",
					event_id.to_hex(),
					CONFIRM_TIMEOUT.as_secs()
				);
				return;
			}
			tokio::time::sleep(CONFIRM_GAP).await;
		}
	}

	/// Publish targets for one DM plus the negotiated NIP-44 v3 capability:
	/// the recipient's advertised 10050 inbox (capped at 3) when they publish
	/// one, PLUS the nprofile relay hints, ALWAYS unioned with our OWN advertised
	/// set. `true` means the recipient's 10050 `encryption` tag advertises
	/// `nip44_v3`; no tag (or no 10050 at all) = v2 only.
	///
	/// MONEY-PATH SAFETY: we must NEVER return a target set that excludes our own
	/// relays. By default our advertised set begins with the shared rendezvous
	/// (`relay.floonet.dev`, `DEFAULT_RELAYS[0]`, placed first by
	/// `ensure_advertised_set`; a user relay edit may drop it), and every Goblin
	/// peer's inbox subscription
	/// (`{kinds:[1059], "#p":[them]}`, see the service loop) likewise reads that
	/// same shared relay. The prior code early-returned ONLY the recipient's
	/// cached 10050 set: if that cache was stale or hint-seeded and missed the
	/// shared relay, the wrap was published solely to relays the recipient never
	/// reads — delivered nowhere while the sender saw success. Unioning our own
	/// set guarantees the wrap always lands on a relay both parties read, even
	/// when the recipient's cached relays are wrong.
	async fn send_targets(
		&self,
		client: &Client,
		receiver: &PublicKey,
		relay_hints: &[String],
	) -> (Vec<String>, bool) {
		let (recipient_relays, v3) = self.fetch_dm_relays(client, receiver).await;
		let mut urls: Vec<String> = vec![];
		// The recipient's own advertised inbox first (best delivery target when
		// fresh), then any nprofile relay hints...
		for r in recipient_relays
			.into_iter()
			.chain(relay_hints.iter().cloned())
		{
			if !urls.contains(&r) {
				urls.push(r);
			}
		}
		// ...and ALWAYS our own advertised set (the shared-relay floor). This is
		// the load-bearing union: it never lets a stale recipient cache exclude
		// the relay both parties actually read.
		for r in self.relays() {
			if !urls.contains(&r) {
				urls.push(r);
			}
		}
		(urls, v3)
	}

	/// Fetch a contact's kind 10050 DM relay list plus their advertised
	/// NIP-44 v3 capability (the `encryption` tag of the same event). Queries
	/// our own relays AND the pool's discovery indexers — the recipient's
	/// 10050 lives on their relays and the indexers, not necessarily on
	/// anything we share. Both facts are cached on the contact together.
	async fn fetch_dm_relays(&self, client: &Client, pk: &PublicKey) -> (Vec<String>, bool) {
		// Use cached relays (and the capability learned with them) first.
		if let Some(contact) = self.store.contact(&pk.to_hex())
			&& !contact.relays.is_empty()
		{
			return (
				contact.relays.into_iter().take(MAX_DM_RELAYS).collect(),
				contact.nip44_v3,
			);
		}
		let mut from = self.relays();
		for url in crate::nostr::pool::usable_discovery_relays(self.tor_routing().into()).await {
			if !from.contains(&url) {
				from.push(url);
			}
		}
		connect_relays(client, &from).await;
		let filter = Filter::new().kind(Kind::InboxRelays).author(*pk).limit(1);
		let mut out = vec![];
		let mut v3 = false;
		// Cap at 10s (not the 30s catch-up FETCH_TIMEOUT): this is on the
		// interactive send path, so a slow/dead discovery relay must fail fast and
		// fall back to relay hints + our own set rather than stall the send.
		if let Ok(events) = client
			.fetch_events_from(&from, filter, Duration::from_secs(10))
			.await && let Some(event) = events.first()
		{
			for tag in event.tags.iter() {
				let parts = tag.as_slice();
				match parts.first().map(|s| s.as_str()) {
					Some("relay") => {
						if let Some(url) = parts.get(1)
							&& out.len() < MAX_DM_RELAYS
						{
							out.push(url.trim_end_matches('/').to_string());
						}
					}
					Some("encryption") => {
						v3 = wrapv3::peer_supports_v3(parts.get(1).map(|s| s.as_str()));
					}
					_ => {}
				}
			}
		}
		// Cache discovered relays + capability on the contact when present.
		if !out.is_empty()
			&& let Some(mut contact) = self.store.contact(&pk.to_hex())
		{
			contact.relays = out.clone();
			contact.nip44_v3 = v3;
			self.store.save_contact(&contact);
		}
		(out, v3)
	}
}

/// The keys of held identity `hex`, or an error when it is no longer held.
fn held_keys_for(held: &[HeldIdentityKeys], hex: &str) -> Result<Keys, String> {
	held.iter()
		.find(|h| h.keys.public_key().to_hex() == hex)
		.map(|h| h.keys.clone())
		.ok_or_else(|| {
			let short: String = hex.chars().take(8).collect();
			format!("identity {short}... is no longer held")
		})
}

/// Build one gift-wrapped wallet DM from our identity `from` to `receiver`, no
/// network. NIP-44 v3 when the recipient advertises it ([`wrapv3::wrap`]),
/// otherwise the library's own NIP-17 builder, the same one
/// `Client::send_private_msg_to` runs with the client signer: same kinds (1059
/// wrap, 13 seal, 14 rumor), same tags, same randomized created_at on seal and
/// wrap, same NIP-44 v2. Only the signer differs: the named identity instead of
/// the one the client was built with at service start.
pub(super) async fn build_dm_wrap(
	from: &Keys,
	receiver: &PublicKey,
	v3: bool,
	content: String,
	tags: Vec<Tag>,
) -> Result<Event, String> {
	if v3 {
		wrapv3::wrap(from, receiver, content, tags)
	} else {
		EventBuilder::private_msg(from, *receiver, content, tags)
			.await
			.map_err(|e| format!("gift wrap failed: {e}"))
	}
}

/// The plain "payment sent" receipt event (frozen contract 4.3.1), signed by
/// our identity `from`.
fn receipt_sent_event(from: &Keys, order: &str, amount: u64) -> Result<Event, String> {
	let tags = vec![
		Tag::custom(TagKind::custom("payment-request"), [order.to_string()]),
		Tag::custom(
			TagKind::custom("payment"),
			["grin".to_string(), order.to_string(), String::new()],
		),
		Tag::custom(TagKind::custom("amount"), [amount.to_string()]),
		Tag::custom(TagKind::custom("status"), ["sent".to_string()]),
		Tag::custom(
			TagKind::custom(protocol::GOBLIN_TAG),
			[protocol::PROTOCOL_VERSION.to_string()],
		),
	];
	EventBuilder::new(Kind::Custom(17), "Payment sent")
		.tags(tags)
		.sign_with_keys(from)
		.map_err(|e| format!("receipt sign failed: {e}"))
}

/// How hard a wallet message is pushed out before it counts as not sent.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Push {
	/// A message the user starts and waits for on screen: attempts again while
	/// a whole attempt fits in SEND_TIMEOUT, then a read-back by id before any
	/// failure verdict (that verdict cancels the payment).
	Long,
	/// Any other message: one attempt within SEND_TIMEOUT, as Build 169 timed
	/// it. Its own retry (next service start, receipt and proof retries) covers
	/// a miss.
	Short,
}

/// Least time between the starts of two publish attempts. An attempt that
/// comes back at once (no relay could even take the event yet) waits out the
/// rest of it, so a dead network does not spin.
const RETRY_GAP: Duration = Duration::from_secs(2);

/// Least time a whole attempt needs: the pool's own OK wait per relay (relay
/// constants WAIT_FOR_OK_TIMEOUT). Another attempt starts only while this much,
/// or as much as the last attempt took if that was longer, is left of the
/// budget, so an attempt is never cut by the budget.
const ATTEMPT_WINDOW: Duration = Duration::from_secs(10);

/// Hang guard for one attempt, above the longest the pool takes for one (its
/// OK wait, a NIP-42 auth wait, and a second OK wait: 27 s). Reaching it is
/// not a verdict: the read-back decides.
const ATTEMPT_CAP: Duration = Duration::from_secs(30);

/// How long the read-back by id waits for the relays.
const READBACK_WAIT: Duration = Duration::from_secs(5);

/// What one publish attempt came back with.
enum Attempt {
	/// The pool answered: the relays that accepted, and the others with why.
	Answered(HashSet<RelayUrl>, HashMap<RelayUrl, String>),
	/// The pool refused the send outright (no relays, a relay not added).
	Refused(String),
	/// No answer within the time given to the attempt.
	TimedOut,
}

/// Publish a finished wallet event (a DM wrap, a receipt, a proof wrap) to
/// `urls` in the given [`Push`] mode. Ok means a relay accepted it (or, for
/// [`Push::Long`], that a relay holds it).
async fn publish(
	client: &Client,
	urls: &[String],
	event: &Event,
	push: Push,
) -> Result<(), String> {
	let send = |cap: Duration| async move {
		match tokio::time::timeout(cap, client.send_event_to(urls, event)).await {
			Ok(Ok(out)) => Attempt::Answered(out.success, out.failed),
			Ok(Err(e)) => Attempt::Refused(e.to_string()),
			Err(_) => Attempt::TimedOut,
		}
	};
	match push {
		Push::Short => publish_once(send(SEND_TIMEOUT).await),
		Push::Long => {
			let start = tokio::time::Instant::now();
			publish_until_accepted(
				SEND_TIMEOUT,
				|| start.elapsed(),
				|| send(ATTEMPT_CAP),
				tokio::time::sleep,
				|| async move {
					let filter = Filter::new().id(event.id).limit(1);
					match client.fetch_events_from(urls, filter, READBACK_WAIT).await {
						Ok(found) => holds_event(found.iter(), &event.id),
						Err(_) => false,
					}
				},
			)
			.await
		}
	}
}

/// The [`Push::Short`] verdict on its single attempt: no acceptance is an
/// error (the message is not marked delivered and its own retry applies).
fn publish_once(attempt: Attempt) -> Result<(), String> {
	match attempt {
		Attempt::Answered(success, failed) => relay_accepted(&success, &failed),
		Attempt::Refused(e) => Err(e),
		Attempt::TimedOut => Err("timeout".to_string()),
	}
}

/// The [`Push::Long`] rule, apart from the network and the clock so a test
/// can drive it. `elapsed` is the time since the publish began, `attempt`
/// sends once (the pool bounds it), `pause` waits, `read_back` asks the relays
/// whether one holds the event.
///
/// A relay that is not connected yet (cold start, a slow Tor circuit) gets the
/// event queued by the pool, which waits 10 s for its OK and then reports the
/// relay as failed; the queued copy still goes out once the relay connects. So
/// an attempt that no relay accepted is sent again, the same event with the
/// same id: a relay that already holds it answers OK (duplicate), which also
/// collects the acknowledgement of a queued copy that landed meanwhile. The
/// pool answers an attempt only when its slowest relay is done, so an attempt
/// in flight is never cut: another one starts only while an attempt as long as
/// the last one fits in the budget. Before any failure verdict the event is
/// read back by id; a relay that returns that exact event makes it a send. Only the pool refusing the very first
/// attempt outright (no relays, a relay not added) fails at once, as before.
async fn publish_until_accepted<C, A, AF, P, PF, R, RF>(
	budget: Duration,
	elapsed: C,
	mut attempt: A,
	mut pause: P,
	mut read_back: R,
) -> Result<(), String>
where
	C: Fn() -> Duration,
	A: FnMut() -> AF,
	AF: std::future::Future<Output = Attempt>,
	P: FnMut(Duration) -> PF,
	PF: std::future::Future<Output = ()>,
	R: FnMut() -> RF,
	RF: std::future::Future<Output = bool>,
{
	// Why the last attempt did not count, for the error.
	let mut why: String;
	let mut first = true;
	loop {
		let began = elapsed();
		match attempt().await {
			Attempt::Refused(e) if first => return Err(e),
			Attempt::Refused(e) => why = e,
			// The pool did not answer within the hang guard: retrying a stuck
			// pool is pointless, the read-back decides.
			Attempt::TimedOut => {
				why = "no answer from the relays".to_string();
				break;
			}
			Attempt::Answered(success, failed) => match relay_accepted(&success, &failed) {
				Ok(()) => return Ok(()),
				Err(e) => why = e,
			},
		}
		first = false;
		let took = elapsed().saturating_sub(began);
		let wait = RETRY_GAP.saturating_sub(took);
		// The next attempt may last as long as this one did (up to 27 s when a
		// relay asks for NIP-42 auth), never less than the pool's OK wait.
		if elapsed() + wait + took.max(ATTEMPT_WINDOW) > budget {
			break;
		}
		if !wait.is_zero() {
			pause(wait).await;
		}
	}
	if read_back().await {
		return Ok(());
	}
	Err(why)
}

/// Whether a read-back found the event that was sent. Only that exact id
/// counts: the pool does not match what a relay returns against the filter
/// (subscription checks are off by default), so a relay answering with any
/// other event must not turn a send nobody accepted into "Sent".
fn holds_event<'a>(found: impl IntoIterator<Item = &'a Event>, id: &nostr_sdk::EventId) -> bool {
	found.into_iter().any(|e| e.id == *id)
}

/// Whether a relay publish counts as sent: at least one relay accepted the
/// event. The relay pool answers Ok even when no relay took it (a timeout, a
/// relay that is not connected or a refusal is only listed among the failed
/// relays), so an empty accepted set is not a send. One accepting relay is
/// enough, as before.
///
/// A relay that already holds the event answers OK true with a "duplicate:"
/// message (NIP-01), which the pool counts as accepted. A relay that answers
/// it with false still holds the event, so that counts as accepted too.
fn relay_accepted(
	success: &HashSet<RelayUrl>,
	failed: &HashMap<RelayUrl, String>,
) -> Result<(), String> {
	if !success.is_empty() || failed.values().any(|e| e.starts_with("duplicate:")) {
		return Ok(());
	}
	if failed.is_empty() {
		return Err("no relay accepted it".to_string());
	}
	// Sorted so the log line is stable.
	let mut reasons: Vec<String> = failed.iter().map(|(u, e)| format!("{u}: {e}")).collect();
	reasons.sort();
	Err(format!("no relay accepted it ({})", reasons.join("; ")))
}

#[cfg(test)]
mod tests {
	use super::*;

	fn url(s: &str) -> RelayUrl {
		RelayUrl::parse(s).unwrap()
	}

	/// H2: the pool's Ok with an empty accepted set (every relay timed out, was
	/// not connected, or refused) is a failed send; one accepting relay among
	/// failures is still a send.
	#[test]
	fn a_publish_no_relay_accepted_is_a_failed_send() {
		let a = url("wss://relay.floonet.dev");
		let b = url("wss://relay.nostr.net");

		// No relay connected or every relay timed out.
		let mut failed = HashMap::new();
		failed.insert(a.clone(), "timeout".to_string());
		failed.insert(b.clone(), "relay not connected".to_string());
		let err = relay_accepted(&HashSet::new(), &failed).unwrap_err();
		assert!(
			err.contains("timeout") && err.contains("not connected"),
			"{err}"
		);

		// Nothing tried and nothing accepted.
		assert!(relay_accepted(&HashSet::new(), &HashMap::new()).is_err());

		// One relay accepted, the other failed: a send.
		let mut success = HashSet::new();
		success.insert(a.clone());
		let mut failed = HashMap::new();
		failed.insert(b.clone(), "timeout".to_string());
		assert!(relay_accepted(&success, &failed).is_ok());

		// Every relay accepted.
		success.insert(b);
		assert!(relay_accepted(&success, &HashMap::new()).is_ok());

		// A relay that answers a copy it already holds with OK false and a
		// "duplicate:" message still holds it: accepted.
		let mut failed = HashMap::new();
		failed.insert(a, "duplicate: have this event".to_string());
		assert!(relay_accepted(&HashSet::new(), &failed).is_ok());
	}

	// --- Retry of a publish no relay accepted yet (fake clock, no network) ---

	use std::cell::Cell;
	use std::rc::Rc;

	const BUDGET: Duration = Duration::from_secs(40);
	/// The pool's own OK wait per relay (relay/constants.rs WAIT_FOR_OK_TIMEOUT).
	const OK_WAIT: Duration = Duration::from_secs(10);
	const OURS: &str = "wss://relay.floonet.dev";

	fn accepted_by(relay: &str) -> Attempt {
		let mut success = HashSet::new();
		success.insert(url(relay));
		Attempt::Answered(success, HashMap::new())
	}

	fn none_accepted(why: &str) -> Attempt {
		let mut failed = HashMap::new();
		failed.insert(url(OURS), why.to_string());
		Attempt::Answered(HashSet::new(), failed)
	}

	/// What the fake run did.
	struct Run {
		result: Result<(), String>,
		/// The fake clock when the verdict was given.
		at: Duration,
		attempts: usize,
		read_backs: usize,
	}

	/// Run the [`Push::Long`] rule on a fake clock. `step` gets the attempt's
	/// start time and returns how long the pool took to answer and what it
	/// answered (the pool answers when its slowest relay is done). `held`
	/// answers the read-back. Pauses and a read-back only move the clock.
	async fn drive(step: impl Fn(Duration) -> (Duration, Attempt), held: bool) -> Run {
		let clock = Rc::new(Cell::new(Duration::ZERO));
		let attempts = Rc::new(Cell::new(0usize));
		let read_backs = Rc::new(Cell::new(0usize));
		let result = publish_until_accepted(
			BUDGET,
			|| clock.get(),
			|| {
				attempts.set(attempts.get() + 1);
				let (took, outcome) = step(clock.get());
				let clock = clock.clone();
				async move {
					clock.set(clock.get() + took);
					outcome
				}
			},
			|d| {
				let clock = clock.clone();
				async move { clock.set(clock.get() + d) }
			},
			|| {
				read_backs.set(read_backs.get() + 1);
				let clock = clock.clone();
				async move {
					clock.set(clock.get() + READBACK_WAIT);
					held
				}
			},
		)
		.await;
		Run {
			result,
			at: clock.get(),
			attempts: attempts.get(),
			read_backs: read_backs.get(),
		}
	}

	/// Two relays, as the pool joins them: ours connects at `up` (a copy queued
	/// before is acknowledged then), the other never connects and holds every
	/// attempt for the full OK wait. The attempt answers at its start + 10 s.
	fn ours_up_at(up: Duration) -> impl Fn(Duration) -> (Duration, Attempt) {
		move |start| {
			let mut failed = HashMap::new();
			failed.insert(url("wss://dead.example"), "timeout".to_string());
			let mut success = HashSet::new();
			if up < start + OK_WAIT {
				success.insert(url(OURS));
			} else {
				failed.insert(url(OURS), "timeout".to_string());
			}
			(OK_WAIT, Attempt::Answered(success, failed))
		}
	}

	/// Nothing accepted on the first attempt (the relay was still connecting),
	/// accepted on the second: a send, no read-back.
	#[tokio::test]
	async fn a_publish_accepted_on_a_later_attempt_is_a_send() {
		let run = drive(
			|start| {
				if start.is_zero() {
					(OK_WAIT, none_accepted("timeout"))
				} else {
					(Duration::from_millis(300), accepted_by(OURS))
				}
			},
			false,
		)
		.await;
		assert!(run.result.is_ok());
		assert_eq!(run.attempts, 2);
		assert_eq!(run.read_backs, 0);
		assert_eq!(run.at, OK_WAIT + Duration::from_millis(300));
	}

	/// The re-sent copy is answered as a duplicate (the queued first copy has
	/// landed): a send, whether the relay says OK true (the pool lists it as
	/// accepted) or OK false with "duplicate:".
	#[tokio::test]
	async fn a_duplicate_acknowledgement_is_a_send() {
		let run = drive(
			|start| {
				if start.is_zero() {
					(OK_WAIT, none_accepted("timeout"))
				} else {
					(
						Duration::from_millis(300),
						none_accepted("duplicate: have this event"),
					)
				}
			},
			false,
		)
		.await;
		assert!(run.result.is_ok());
		assert_eq!(run.attempts, 2);
	}

	/// Truly offline: every attempt waits out the pool's OK wait, or comes
	/// back at once and is paced. Attempts start only while a whole one fits
	/// in the budget, the read-back finds nothing, and only then is it a
	/// failed send; a dead network does not spin.
	#[tokio::test]
	async fn no_acceptance_within_the_budget_is_a_failed_send() {
		let run = drive(|_| (OK_WAIT, none_accepted("timeout")), false).await;
		let err = run.result.unwrap_err();
		assert!(err.contains("no relay accepted it"), "{err}");
		assert_eq!(run.attempts, 4);
		assert_eq!(run.read_backs, 1);
		assert_eq!(run.at, BUDGET + READBACK_WAIT);

		let run = drive(
			|_| (Duration::ZERO, none_accepted("relay not connected")),
			false,
		)
		.await;
		assert!(run.result.is_err());
		assert_eq!(run.read_backs, 1);
		// Attempts at 0, 2, ..., 30 s: the last one that still has a whole
		// attempt's time before the budget ends.
		assert_eq!(run.attempts, 16);
		assert_eq!(run.at, Duration::from_secs(30) + READBACK_WAIT);
	}

	/// The pool refusing the first attempt outright (no relays, a relay not
	/// added) is an error at once, as before: no retry, no read-back.
	#[tokio::test]
	async fn a_refused_publish_fails_at_once() {
		let run = drive(
			|_| (Duration::ZERO, Attempt::Refused("relay not found".into())),
			true,
		)
		.await;
		assert_eq!(run.result.unwrap_err(), "relay not found");
		assert_eq!(run.at, Duration::ZERO);
		assert_eq!(run.attempts, 1);
		assert_eq!(run.read_backs, 0);
	}

	/// The join model: ours connects late while a dead second relay holds every
	/// attempt for its full OK wait. An acceptance inside the last attempt
	/// (ours up at 33 s, that attempt ends at 40 s) is kept: no attempt is
	/// cut. The send is reported when the attempt ends.
	#[tokio::test]
	async fn a_relay_that_connects_late_still_gets_the_send() {
		for (up, sent_at) in [(5u64, 10u64), (15, 20), (33, 40)] {
			let run = drive(ours_up_at(Duration::from_secs(up)), false).await;
			assert!(run.result.is_ok(), "ours up at {up} s");
			assert_eq!(run.at, Duration::from_secs(sent_at), "ours up at {up} s");
			assert_eq!(run.read_backs, 0);
		}
		// Up only after the last attempt: the read-back decides.
		let run = drive(ours_up_at(Duration::from_secs(41)), false).await;
		assert!(run.result.is_err());
		assert_eq!(run.at, BUDGET + READBACK_WAIT);
	}

	/// No relay acknowledged it, but one holds it (an OK that came after the
	/// pool stopped waiting): the read-back makes it a send, so the payment is
	/// not cancelled while it is out.
	#[tokio::test]
	async fn a_read_back_hit_turns_no_acknowledgement_into_a_send() {
		let run = drive(|_| (OK_WAIT, none_accepted("timeout")), true).await;
		assert!(run.result.is_ok());
		assert_eq!(run.read_backs, 1);
		// An attempt that got no answer at all goes to the read-back too.
		let run = drive(|_| (ATTEMPT_CAP, Attempt::TimedOut), true).await;
		assert!(run.result.is_ok());
		assert_eq!(run.attempts, 1);
	}

	/// An attempt that took long (a relay asking for NIP-42 auth) gates the
	/// next one by its own length: no second attempt that would run past the
	/// budget, so the verdict comes by the budget plus the read-back.
	#[tokio::test]
	async fn a_long_attempt_keeps_the_verdict_inside_the_budget() {
		let run = drive(
			|_| (Duration::from_secs(29), none_accepted("timeout")),
			false,
		)
		.await;
		assert!(run.result.is_err());
		assert_eq!(run.attempts, 1);
		assert!(run.at <= BUDGET + READBACK_WAIT, "verdict at {:?}", run.at);
	}

	/// A read-back hit is only the event that was sent: a relay answering the
	/// id filter with another event is not one.
	#[test]
	fn only_the_sent_event_is_a_read_back_hit() {
		let keys = Keys::generate();
		let sent = EventBuilder::new(Kind::GiftWrap, "a")
			.sign_with_keys(&keys)
			.unwrap();
		let other = EventBuilder::new(Kind::GiftWrap, "b")
			.sign_with_keys(&keys)
			.unwrap();
		assert!(!holds_event([&other], &sent.id));
		assert!(!holds_event(std::iter::empty::<&Event>(), &sent.id));
		assert!(holds_event([&other, &sent], &sent.id));
	}

	/// The single attempt of a message nobody waits for on screen: no
	/// acceptance is an error (not marked delivered), as in Build 169's timing.
	#[test]
	fn a_short_publish_is_one_attempt() {
		assert!(publish_once(accepted_by(OURS)).is_ok());
		assert!(publish_once(none_accepted("timeout")).is_err());
		assert!(publish_once(none_accepted("duplicate: have this event")).is_ok());
		assert!(publish_once(Attempt::TimedOut).is_err());
		assert!(publish_once(Attempt::Refused("relay not found".into())).is_err());
	}

	// --- H3: every message is sealed and signed by the identity it belongs to ---

	use super::super::service::open_with_held;
	use crate::nostr::AcceptPolicy;
	use base64::Engine;
	use grin_wallet_libwallet::SlateState;
	use nostr_sdk::{JsonUtil, UnsignedEvent};

	const SLATEPACK: &str = "BEGINSLATEPACK. 4H1qx1wHe668tFW yC2gfL8PPd8kSgv \
		pcXQhyRkHbyKHZg GN75o7uWoT3dkib R2tj1fFGN2FoRLY oeBPyKizupksgRT. \
		ENDSLATEPACK.";

	/// A service holding `held` with `active` presented, on a throwaway store.
	/// No client: nothing here touches a relay.
	fn service_with(
		held: &[(NostrIdentity, Keys)],
		active: &Keys,
	) -> (Arc<NostrService>, std::path::PathBuf) {
		static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
		let dir = std::env::temp_dir().join(format!(
			"goblin-send-test-{}-{}-{}",
			std::process::id(),
			unix_time(),
			SEQ.fetch_add(1, Ordering::Relaxed)
		));
		let recv = held
			.iter()
			.map(|(identity, keys)| HeldIdentityKeys {
				keys: keys.clone(),
				identity: identity.clone(),
			})
			.collect();
		let svc = NostrService::new(
			recv,
			&active.public_key().to_hex(),
			NostrConfig::default(),
			NostrStore::new(dir.join("db")),
			dir.clone(),
		);
		(svc, dir)
	}

	/// The payer's side of a send: its row for a payment made to `counterparty`.
	fn payer_meta(counterparty: &str) -> TxNostrMeta {
		TxNostrMeta {
			ver: 1,
			slate_id: "s".to_string(),
			npub: counterparty.to_string(),
			direction: NostrTxDirection::Sent,
			note: None,
			status: NostrSendStatus::AwaitingS2,
			sent_event_id: None,
			received_rumor_id: None,
			created_at: unix_time(),
			updated_at: unix_time(),
			proof_mode: false,
			proof_order: None,
			proof_notify: None,
			proof_amount: None,
			proof_delivered: false,
			receipt_sent: false,
			recipient_pubkey: String::new(),
			proof_address: None,
		}
	}

	/// What the payer's ingest decides about an S2 from `sender`.
	fn payer_decides(sender: &PublicKey, meta: &TxNostrMeta) -> IngestDecision {
		let sender = sender.to_hex();
		decide(&IngestContext {
			state: SlateState::Standard2,
			amount: 100,
			sender: &sender,
			meta: Some(meta),
			tx_exists: true,
			is_contact: false,
			accept: AcceptPolicy::Everyone,
			allow_requests: true,
		})
	}

	fn version_byte(wrap: &Event) -> u8 {
		base64::engine::general_purpose::STANDARD
			.decode(&wrap.content)
			.unwrap()[0]
	}

	/// Two held identities, A active. A payment addressed to B is opened by B,
	/// and its S2 reply is sealed and signed by B on both encryption versions,
	/// so the payer finalizes it. The reply Build 169 sent (as the active A) is
	/// dropped by the payer.
	#[tokio::test]
	async fn reply_is_sealed_by_the_identity_the_payment_was_addressed_to() {
		let (id_a, a) = NostrIdentity::create_random("pw").unwrap();
		let (id_b, b) = NostrIdentity::create_random("pw").unwrap();
		let payer = Keys::generate();
		let (svc, dir) = service_with(&[(id_a, a.clone()), (id_b, b.clone())], &a);
		assert_eq!(svc.public_key(), a.public_key());

		for v3 in [false, true] {
			let s1 = build_dm_wrap(
				&payer,
				&b.public_key(),
				v3,
				protocol::build_payment_content(SLATEPACK),
				protocol::build_rumor_tags(None),
			)
			.await
			.unwrap();
			// Ingest: B's key opens it, so B is what the row records.
			let (recipient, s1_open) = open_with_held(&svc.recv_snapshot(), &s1).await.unwrap();
			assert_eq!(recipient, b.public_key());
			assert_eq!(s1_open.sender, payer.public_key());

			// The S2 reply, sent as the recorded identity.
			let from = svc.sender_keys(&recipient.to_hex()).unwrap();
			let s2 = build_dm_wrap(
				&from,
				&s1_open.sender,
				v3,
				protocol::build_payment_content(SLATEPACK),
				protocol::build_rumor_tags(None),
			)
			.await
			.unwrap();
			assert_eq!(version_byte(&s2), if v3 { 3 } else { 2 });
			let got = wrapv3::unwrap(&payer, &s2).await.unwrap();
			assert_eq!(got.sender, b.public_key(), "seal signer, v3={v3}");
			assert_eq!(got.rumor.pubkey, b.public_key(), "rumor author, v3={v3}");
			let meta = payer_meta(&b.public_key().to_hex());
			assert_eq!(
				payer_decides(&got.sender, &meta),
				IngestDecision::FinalizePost
			);

			// Build 169 replied as the active identity A: the payer drops it.
			let old = build_dm_wrap(
				&svc.keys(),
				&s1_open.sender,
				v3,
				protocol::build_payment_content(SLATEPACK),
				protocol::build_rumor_tags(None),
			)
			.await
			.unwrap();
			let got = wrapv3::unwrap(&payer, &old).await.unwrap();
			assert!(matches!(
				payer_decides(&got.sender, &meta),
				IngestDecision::Drop(_)
			));
		}
		let _ = std::fs::remove_dir_all(dir);
	}

	/// After an instant switch to B, a new payment (which reads the active
	/// identity once) is a v2 wrap sealed by B. Build 169 built v2 wraps with
	/// the client signer fixed at service start, which was still A.
	#[tokio::test]
	async fn a_new_v2_send_after_a_switch_is_signed_by_the_new_identity() {
		let (id_a, a) = NostrIdentity::create_random("pw").unwrap();
		let (id_b, b) = NostrIdentity::create_random("pw").unwrap();
		let peer = Keys::generate();
		let (svc, dir) = service_with(&[(id_a, a.clone()), (id_b, b.clone())], &a);
		let start_client = Client::builder().signer(svc.keys()).build();

		assert!(svc.set_active_by_pubkey(&b.public_key().to_hex()));
		let from_hex = svc.public_key().to_hex();
		let from = svc.sender_keys(&from_hex).unwrap();
		let content = protocol::build_payment_content(SLATEPACK);
		let tags = protocol::build_rumor_tags(None);
		let wrap = build_dm_wrap(
			&from,
			&peer.public_key(),
			false,
			content.clone(),
			tags.clone(),
		)
		.await
		.unwrap();
		assert_eq!(version_byte(&wrap), 2);
		let got = wrapv3::unwrap(&peer, &wrap).await.unwrap();
		assert_eq!(got.sender, b.public_key());
		assert_eq!(got.rumor.pubkey, b.public_key());

		// The Build 169 v2 path: `send_private_msg_to` with the client signer.
		let signer = start_client.signer().await.unwrap();
		let old = EventBuilder::private_msg(&signer, peer.public_key(), content, tags)
			.await
			.unwrap();
		let got = wrapv3::unwrap(&peer, &old).await.unwrap();
		assert_eq!(got.sender, a.public_key());
		let _ = std::fs::remove_dir_all(dir);
	}

	/// A message for an identity that is no longer held fails before any
	/// network work, for every message type; it never goes out as another
	/// identity. A row with no recorded identity (written before identities
	/// were recorded) and a request stored before Build 170 use the active one.
	#[tokio::test]
	async fn a_message_for_an_identity_no_longer_held_fails() {
		let (id_a, a) = NostrIdentity::create_random("pw").unwrap();
		let (id_b, b) = NostrIdentity::create_random("pw").unwrap();
		let (svc, dir) = service_with(&[(id_a, a.clone()), (id_b, b.clone())], &a);
		let gone = Keys::generate().public_key().to_hex();
		let peer = Keys::generate().public_key();

		assert!(
			svc.sender_keys(&gone)
				.unwrap_err()
				.contains("no longer held")
		);
		let err = svc
			.send_payment_dm(&gone, &peer.to_hex(), SLATEPACK, None, &[])
			.await
			.unwrap_err();
		assert!(err.contains("no longer held"), "{err}");
		let err = svc
			.send_control_dm(&gone, &peer.to_hex(), "slate", &[])
			.await
			.unwrap_err();
		assert!(err.contains("no longer held"), "{err}");
		// A receipt and a proof are the exception: nobody checks their sender
		// and the order is credited only with them, so they go out as the
		// active identity (here they get as far as the missing client).
		let err = svc
			.publish_receipt_sent(&gone, "MM-ab", 1)
			.await
			.unwrap_err();
		assert!(err.contains("not running"), "{err}");
		let err = svc
			.deliver_proof_wrap(&gone, &peer.to_bech32().unwrap(), "MM-ab", 1, "00", "{}")
			.await
			.unwrap_err();
		assert!(err.contains("not running"), "{err}");
		assert_eq!(
			svc.payment_proof_keys(&gone, "MM-ab").public_key(),
			a.public_key()
		);
		assert_eq!(
			svc.payment_proof_keys(&b.public_key().to_hex(), "MM-ab")
				.public_key(),
			b.public_key()
		);

		// Held identities resolve to themselves, whichever is active.
		let b_hex = b.public_key().to_hex();
		assert_eq!(
			svc.sender_keys(&b_hex).unwrap().public_key(),
			b.public_key()
		);
		assert_eq!(
			svc.sender_keys(&a.public_key().to_hex())
				.unwrap()
				.public_key(),
			a.public_key()
		);
		// No recorded identity: the active one, as before.
		assert_eq!(svc.sender_keys("").unwrap().public_key(), a.public_key());

		// Requests: the addressed identity, or the active one for an old row.
		let mut req: PaymentRequest = serde_json::from_str(
			r#"{"ver":1,"rumor_id":"r","slate_id":"s","slatepack":"x","npub":"ab","amount":5,"note":null,"received_at":7,"status":"Pending"}"#,
		)
		.unwrap();
		assert_eq!(svc.request_identity(&req), a.public_key().to_hex());
		req.recipient_pubkey = Some(b_hex.clone());
		assert_eq!(svc.request_identity(&req), b_hex);
		let _ = std::fs::remove_dir_all(dir);
	}

	/// The v2 wrap built with the named identity's keys is the library's own
	/// NIP-17 private message, the one `send_private_msg_to` built: same kinds,
	/// tags, payload version and timestamp window, and it opens through the
	/// unchanged unwrap with the same rumor.
	#[tokio::test]
	async fn v2_wrap_matches_the_library_private_message() {
		let sender = Keys::generate();
		let receiver = Keys::generate();
		let content = protocol::build_payment_content(SLATEPACK);
		let tags = protocol::build_rumor_tags(Some("lunch"));

		let new = build_dm_wrap(
			&sender,
			&receiver.public_key(),
			false,
			content.clone(),
			tags.clone(),
		)
		.await
		.unwrap();
		let client = Client::builder().signer(sender.clone()).build();
		let signer = client.signer().await.unwrap();
		let old = EventBuilder::private_msg(&signer, receiver.public_key(), content.clone(), tags)
			.await
			.unwrap();

		let now = Timestamp::now().as_secs();
		let two_days = 2 * 86_400;
		let mut rumors = vec![];
		for wrap in [&new, &old] {
			assert_eq!(wrap.kind, Kind::GiftWrap);
			assert!(wrap.verify().is_ok());
			assert_ne!(wrap.pubkey, sender.public_key(), "one-time wrap key");
			let wrap_tags: Vec<Vec<String>> =
				wrap.tags.iter().map(|t| t.as_slice().to_vec()).collect();
			assert_eq!(
				wrap_tags,
				vec![vec!["p".to_string(), receiver.public_key().to_hex()]]
			);
			assert_eq!(version_byte(wrap), 2);
			let at = wrap.created_at.as_secs();
			assert!(at <= now && now - at <= two_days);

			// The seal: kind 13, signed by the sender, no tags, same window.
			let seal_json =
				nostr_sdk::nips::nip44::decrypt(receiver.secret_key(), &wrap.pubkey, &wrap.content)
					.unwrap();
			let seal = Event::from_json(seal_json).unwrap();
			assert_eq!(seal.kind, Kind::Seal);
			assert_eq!(seal.pubkey, sender.public_key());
			assert!(seal.verify().is_ok());
			assert!(seal.tags.is_empty());
			let at = seal.created_at.as_secs();
			assert!(at <= now && now - at <= two_days);

			let got = wrapv3::unwrap(&receiver, wrap).await.unwrap();
			assert_eq!(got.sender, sender.public_key());
			assert_eq!(got.rumor.kind, Kind::PrivateDirectMessage);
			assert_eq!(got.rumor.content, content);
			rumors.push(got.rumor);
		}
		// Same rumor tags in the same order: receiver p tag first, then ours.
		let tags_of = |r: &UnsignedEvent| -> Vec<Vec<String>> {
			r.tags.iter().map(|t| t.as_slice().to_vec()).collect()
		};
		assert_eq!(tags_of(&rumors[0]), tags_of(&rumors[1]));
		assert_eq!(
			tags_of(&rumors[0])[0],
			vec!["p".to_string(), receiver.public_key().to_hex()]
		);
	}

	/// A dispatch result moves a row on only from the status its task left it
	/// in: a row a fast reply finalized, or the user cancelled, during the
	/// publish stays as it is.
	#[tokio::test]
	async fn a_dispatch_result_never_overwrites_a_newer_status() {
		let (id_a, a) = NostrIdentity::create_random("pw").unwrap();
		let (svc, dir) = service_with(&[(id_a, a.clone())], &a);
		let row = |slate: &str, direction, status| {
			let mut m = payer_meta("cd");
			m.slate_id = slate.to_string();
			m.direction = direction;
			m.status = status;
			m
		};
		use NostrSendStatus::*;
		use NostrTxDirection::*;

		svc.store.save_tx_meta(&row("finalized", Sent, Finalized));
		assert!(!svc.advance_after_dispatch("finalized", Created, AwaitingS2, "e1".into()));
		let m = svc.store.tx_meta("finalized").unwrap();
		assert_eq!(m.status, Finalized);
		assert_eq!(m.sent_event_id, None);

		svc.store
			.save_tx_meta(&row("cancelled", RequestedByUs, Cancelled));
		assert!(!svc.advance_after_dispatch("cancelled", Created, AwaitingI2, "e2".into()));
		assert_eq!(svc.store.tx_meta("cancelled").unwrap().status, Cancelled);

		svc.store
			.save_tx_meta(&row("paid", RequestedOfUs, Cancelled));
		assert!(!svc.advance_after_dispatch(
			"paid",
			ReceivedNoReply,
			PaidAwaitingFinalize,
			"e3".into()
		));
		assert_eq!(svc.store.tx_meta("paid").unwrap().status, Cancelled);

		// Still where the task left it: moved on, with the event id.
		svc.store.save_tx_meta(&row("fresh", Sent, Created));
		assert!(svc.advance_after_dispatch("fresh", Created, AwaitingS2, "e4".into()));
		let m = svc.store.tx_meta("fresh").unwrap();
		assert_eq!(m.status, AwaitingS2);
		assert_eq!(m.sent_event_id.as_deref(), Some("e4"));

		// The receipt flag alone changes; the status written meanwhile stays.
		svc.mark_receipt_sent("finalized");
		let m = svc.store.tx_meta("finalized").unwrap();
		assert!(m.receipt_sent);
		assert_eq!(m.status, Finalized);
		let _ = std::fs::remove_dir_all(dir);
	}

	/// A result belongs to the dispatch that produced it. Send #1 spins, the
	/// user goes back and starts send #2: #1's late verdict (FAILED, or a late
	/// SENT) never reaches #2's screen; only the task holding the current turn
	/// changes the phase.
	#[tokio::test]
	async fn only_the_current_send_turn_changes_the_screen() {
		use crate::nostr::send_phase::{FAILED, SENT, WORKING};
		let (id_a, a) = NostrIdentity::create_random("pw").unwrap();
		let (svc, dir) = service_with(&[(id_a, a.clone())], &a);

		// Send #1: the screen begins a turn, the task takes it first thing.
		let one = svc.begin_send();
		let task_one = svc.send_turn();
		assert_eq!(task_one, one);
		assert!(svc.set_send_phase_for(task_one, WORKING));

		// Back, then send #2.
		let two = svc.begin_send();
		let task_two = svc.send_turn();
		assert_eq!(task_two, two);
		assert_ne!(task_one, task_two);
		assert_eq!(svc.send_phase(), WORKING);

		// #1 reaches its failure verdict: its money work is its own, the
		// screen is not.
		assert!(!svc.fail_send_for(task_one, "no relay accepted it"));
		assert!(!svc.set_send_phase_for(task_one, FAILED));
		assert_eq!(svc.send_phase(), WORKING);
		assert_eq!(svc.last_send_error(), None);

		// #2 completes: shown.
		assert!(svc.set_send_phase_for(task_two, SENT));
		assert_eq!(svc.send_phase(), SENT);

		// The reverse: a stale SENT never shows over a later send.
		let three = svc.begin_send();
		assert!(!svc.set_send_phase_for(task_two, SENT));
		assert_eq!(svc.send_phase(), WORKING);
		assert!(svc.fail_send_for(three, "why"));
		assert_eq!(svc.send_phase(), FAILED);
		assert_eq!(svc.last_send_error().as_deref(), Some("why"));

		// A new turn clears the reason.
		svc.begin_send();
		assert_eq!(svc.last_send_error(), None);
		let _ = std::fs::remove_dir_all(dir);
	}

	/// The plain receipt is signed by the identity that paid, with the frozen
	/// contract shape unchanged.
	#[test]
	fn receipt_is_signed_by_the_paying_identity() {
		let paid_as = Keys::generate();
		let ev = receipt_sent_event(&paid_as, "MM-ab", 1_000).unwrap();
		assert!(ev.verify().is_ok());
		assert_eq!(ev.pubkey, paid_as.public_key());
		assert_eq!(ev.kind, Kind::Custom(17));
		assert_eq!(ev.content, "Payment sent");
		let tags: Vec<Vec<String>> = ev.tags.iter().map(|t| t.as_slice().to_vec()).collect();
		let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect::<Vec<String>>();
		assert_eq!(
			tags,
			vec![
				s(&["payment-request", "MM-ab"]),
				s(&["payment", "grin", "MM-ab", ""]),
				s(&["amount", "1000"]),
				s(&["status", "sent"]),
				s(&[protocol::GOBLIN_TAG, protocol::PROTOCOL_VERSION]),
			]
		);
	}
}
