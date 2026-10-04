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

	/// Our identity (pubkey hex) for an incoming request or surfaced payment:
	/// the one its wrap was addressed to. A request stored before Build 170
	/// has no record of it and uses the active identity, as before.
	pub fn request_identity(&self, request: &PaymentRequest) -> String {
		request
			.recipient_pubkey
			.clone()
			.unwrap_or_else(|| self.public_key().to_hex())
	}

	/// Dispatch a payment DM (slatepack + optional note) to a recipient,
	/// publishing to their DM relays plus our own relay set. `relay_hints`
	/// are extra recipient relays carried by an nprofile the sender pasted
	/// or scanned — the only routing info we have for a fresh recipient
	/// whose kind 10050 isn't discoverable from our relays. Sealed and signed
	/// by our identity `from_hex` (see [`Self::sender_keys`]).
	pub async fn send_payment_dm(
		&self,
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
		self.dispatch_dm(&client, urls, &wrap, receiver).await
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
		self.dispatch_dm(&client, urls, &wrap, receiver).await
	}

	/// Publish the plain "payment sent" receipt (frozen contract 4.3.1): a
	/// buyer-signed, UNENCRYPTED kind-17 to our app relays that flips the order
	/// page to "payment detected, confirming". It is buyer-signed and unverified,
	/// so the market NEVER treats it as "paid" (only the watcher's 4.4 event
	/// does). The proof and kernel excess are DELIBERATELY omitted here: a Grin
	/// payment proof carries the buyer's own slatepack address, and publishing it
	/// in the clear would leak the buyer's wallet address to the world. Signed
	/// by our identity `from_hex`, the one that paid.
	pub async fn publish_receipt_sent(
		&self,
		from_hex: &str,
		order: &str,
		amount: u64,
	) -> Result<(), String> {
		let from = self.sender_keys(from_hex)?;
		let client = {
			let r_client = self.client.read();
			r_client.clone().ok_or("nostr client is not running")?
		};
		let event = receipt_sent_event(&from, order, amount)?;
		let urls: Vec<String> = self.relays();
		match tokio::time::timeout(SEND_TIMEOUT, client.send_event_to(&urls, &event)).await {
			Ok(Ok(out)) => relay_accepted(&out.success, &out.failed)
				.map_err(|e| format!("receipt publish failed: {e}")),
			Ok(Err(e)) => Err(format!("receipt publish failed: {e}")),
			Err(_) => Err("receipt publish timeout".to_string()),
		}
	}

	/// Gift-wrap the full proof delivery (frozen contract 4.3.2) to the watcher's
	/// npub: a kind-17 rumor whose content is the Grin payment proof JSON verbatim,
	/// tagged with the invoice number, the amount, and the kernel excess. Encrypted
	/// end to end, so the proof (which contains the buyer's sender address) never
	/// goes out in the clear; only the addressed watcher can read it. Sealed and
	/// signed by our identity `from_hex`, the one that paid.
	pub async fn deliver_proof_wrap(
		&self,
		from_hex: &str,
		notify_npub: &str,
		order: &str,
		amount: u64,
		kernel_hex: &str,
		proof_json: &str,
	) -> Result<(), String> {
		let from = self.sender_keys(from_hex)?;
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
		match tokio::time::timeout(SEND_TIMEOUT, client.send_event_to(&urls, &wrap)).await {
			Ok(Ok(out)) => relay_accepted(&out.success, &out.failed)
				.map_err(|e| format!("proof delivery failed: {e}")),
			Ok(Err(e)) => Err(format!("proof delivery failed: {e}")),
			Err(_) => Err("proof delivery timeout".to_string()),
		}
	}

	/// Dispatch one gift-wrapped DM built by [`build_dm_wrap`] to `urls`.
	async fn dispatch_dm(
		&self,
		client: &Client,
		urls: Vec<String>,
		wrap: &Event,
		receiver: PublicKey,
	) -> Result<String, String> {
		let res = tokio::time::timeout(SEND_TIMEOUT, client.send_event_to(urls.clone(), wrap))
			.await
			.map_err(|_| "send timeout".to_string())?
			.map_err(|e| format!("send failed: {e}"))?;
		relay_accepted(&res.success, &res.failed).map_err(|e| format!("send failed: {e}"))?;
		let event_id = res.val;

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

/// Whether a relay publish counts as sent: at least one relay accepted the
/// event. The relay pool answers Ok even when no relay took it (a timeout, a
/// relay that is not connected or a refusal is only listed among the failed
/// relays), so an empty accepted set is a failed send, never "Sent". One
/// accepting relay is enough, as before.
fn relay_accepted(
	success: &HashSet<RelayUrl>,
	failed: &HashMap<RelayUrl, String>,
) -> Result<(), String> {
	if !success.is_empty() {
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
		let err = svc
			.publish_receipt_sent(&gone, "MM-ab", 1)
			.await
			.unwrap_err();
		assert!(err.contains("no longer held"), "{err}");
		let err = svc
			.deliver_proof_wrap(&gone, &peer.to_bech32().unwrap(), "MM-ab", 1, "00", "{}")
			.await
			.unwrap_err();
		assert!(err.contains("no longer held"), "{err}");

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
