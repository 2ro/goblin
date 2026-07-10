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

		let (urls, v3) = self.send_targets(&client, &receiver, relay_hints).await;

		// NIP-17 delivers to the RECIPIENT's relays, which may differ from ours;
		// dial any we don't already hold so the gift wrap actually reaches their
		// inbox (otherwise `send_*_to` errors "relay not found" / never arrives).
		connect_relays(&client, &urls).await;

		self.dispatch_dm(&client, urls, v3, receiver, content, tags)
			.await
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

		let (urls, v3) = self.send_targets(&client, &receiver, relay_hints).await;

		connect_relays(&client, &urls).await;

		self.dispatch_dm(&client, urls, v3, receiver, content, tags)
			.await
	}

	/// Publish the plain "payment sent" receipt (frozen contract 4.3.1): a
	/// buyer-signed, UNENCRYPTED kind-17 to our app relays that flips the order
	/// page to "payment detected, confirming". It is buyer-signed and unverified,
	/// so the market NEVER treats it as "paid" (only the watcher's 4.4 event
	/// does). The proof and kernel excess are DELIBERATELY omitted here: a Grin
	/// payment proof carries the buyer's own slatepack address, and publishing it
	/// in the clear would leak the buyer's wallet address to the world.
	pub async fn publish_receipt_sent(&self, order: &str, amount: u64) -> Result<(), String> {
		let client = {
			let r_client = self.client.read();
			r_client.clone().ok_or("nostr client is not running")?
		};
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
		let builder = EventBuilder::new(Kind::Custom(17), "Payment sent").tags(tags);
		let event = client
			.sign_event_builder(builder)
			.await
			.map_err(|e| format!("receipt sign failed: {e}"))?;
		let urls: Vec<String> = self.relays();
		match tokio::time::timeout(SEND_TIMEOUT, client.send_event_to(&urls, &event)).await {
			Ok(Ok(_)) => Ok(()),
			Ok(Err(e)) => Err(format!("receipt publish failed: {e}")),
			Err(_) => Err("receipt publish timeout".to_string()),
		}
	}

	/// Gift-wrap the full proof delivery (frozen contract 4.3.2) to the watcher's
	/// npub: a kind-17 rumor whose content is the Grin payment proof JSON verbatim,
	/// tagged with the invoice number, the amount, and the kernel excess. Encrypted
	/// end to end, so the proof (which contains the buyer's sender address) never
	/// goes out in the clear; only the addressed watcher can read it.
	pub async fn deliver_proof_wrap(
		&self,
		notify_npub: &str,
		order: &str,
		amount: u64,
		kernel_hex: &str,
		proof_json: &str,
	) -> Result<(), String> {
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
			&self.keys.read().clone(),
			&receiver,
			Kind::Custom(17),
			proof_json.to_string(),
			tags,
		)?;
		let urls: Vec<String> = self.relays();
		connect_relays(&client, &urls).await;
		match tokio::time::timeout(SEND_TIMEOUT, client.send_event_to(&urls, &wrap)).await {
			Ok(Ok(_)) => Ok(()),
			Ok(Err(e)) => Err(format!("proof delivery failed: {e}")),
			Err(_) => Err("proof delivery timeout".to_string()),
		}
	}

	/// Dispatch one gift-wrapped DM over the negotiated encryption: when the
	/// recipient advertises `nip44_v3` the wrap is built by [`wrapv3::wrap`],
	/// otherwise it goes through the unchanged nostr-sdk v2 path (best mutual
	/// wins; absent capability = v2, so v2-only peers see no change).
	async fn dispatch_dm(
		&self,
		client: &Client,
		urls: Vec<String>,
		v3: bool,
		receiver: PublicKey,
		content: String,
		tags: Vec<Tag>,
	) -> Result<String, String> {
		let sent = if v3 {
			let wrap = wrapv3::wrap(&self.keys.read().clone(), &receiver, content, tags)?;
			tokio::time::timeout(SEND_TIMEOUT, client.send_event_to(urls.clone(), &wrap)).await
		} else {
			tokio::time::timeout(
				SEND_TIMEOUT,
				client.send_private_msg_to(urls.clone(), receiver, content, tags),
			)
			.await
		};
		let res = sent
			.map_err(|_| "send timeout".to_string())?
			.map_err(|e| format!("send failed: {e}"))?;
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
		for url in crate::nostr::pool::usable_discovery_relays().await {
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
