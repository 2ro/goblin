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

//! Shared types of the nostr payment-messaging subsystem.

use serde_derive::{Deserialize, Serialize};

/// Direction of a nostr-transported transaction relative to this wallet.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum NostrTxDirection {
	/// We sent funds (Standard flow, we created S1).
	Sent,
	/// We received funds (Standard flow, we replied S2).
	Received,
	/// We issued an invoice / requested funds (Invoice flow, we created I1).
	RequestedByUs,
	/// Someone requested funds of us (Invoice flow, we may pay I1).
	RequestedOfUs,
}

/// Lifecycle status of a nostr-transported transaction.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum NostrSendStatus {
	/// Slate created locally, DM not dispatched yet.
	Created,
	/// S1 DM dispatched, waiting for the S2 reply.
	AwaitingS2,
	/// Incoming S1 processed, S2 reply not yet dispatched (crash recovery).
	ReceivedNoReply,
	/// S2 reply dispatched for a received payment.
	RepliedS2,
	/// I1 request dispatched, waiting for the I2 reply.
	AwaitingI2,
	/// We paid an invoice (I2 reply sent), their side finalizes.
	PaidAwaitingFinalize,
	/// Transaction finalized and posted.
	Finalized,
	/// DM dispatch failed, retry possible.
	SendFailed,
	/// Cancelled locally.
	Cancelled,
}

/// Outcome of a manual payment-cancel, surfaced transiently on the receipt so
/// the user knows whether their funds came back or the payment had already
/// completed in the race window.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CancelOutcome {
	/// The pending payment was cancelled and the locked funds released.
	Cancelled,
	/// The payment had already gone through; nothing was cancelled.
	AlreadyCompleted,
}

/// Per-transaction nostr metadata, joined to wallet txs by slate id.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TxNostrMeta {
	pub ver: u8,
	/// Slate UUID string.
	pub slate_id: String,
	/// Counterparty public key, hex.
	pub npub: String,
	pub direction: NostrTxDirection,
	/// Sanitized user note (subject line).
	pub note: Option<String>,
	pub status: NostrSendStatus,
	/// Gift wrap event id of our outgoing message, hex.
	pub sent_event_id: Option<String>,
	/// Rumor id of the counterparty message we processed, hex.
	pub received_rumor_id: Option<String>,
	pub created_at: i64,
	pub updated_at: i64,
	/// Proof-on-request (frozen contract section 4.3): a proof address was
	/// threaded into this send, so on finalize the wallet must produce and
	/// deliver a real Grin payment proof. `false` for every ordinary send, so a
	/// person-to-person payment carries and delivers nothing extra.
	#[serde(default)]
	pub proof_mode: bool,
	/// The opaque order handle (the `order=` URI param, magick's `MM-<hex>`
	/// invoice number). Echoed verbatim into the delivery events'
	/// `payment-request` tag. The wallet never learns magick's internal orderId.
	#[serde(default)]
	pub proof_order: Option<String>,
	/// The watcher's npub (the `notify=` URI param): the gift-wrap target for the
	/// full proof delivery. `None` = no encrypted delivery target (plain receipt
	/// still publishes).
	#[serde(default)]
	pub proof_notify: Option<String>,
	/// The payment amount in integer nanogrin, persisted so the crash-safe
	/// reconcile pass can rebuild the delivery-event `amount` tag without the
	/// slate.
	#[serde(default)]
	pub proof_amount: Option<u64>,
	/// Set once the encrypted proof delivery (frozen contract 4.3.2) has been
	/// accepted by a relay. The plain receipt is tracked separately by
	/// `receipt_sent`, since the two now publish at different lifecycle points
	/// (receipt at dispatch, proof at finalize). Until then the reconcile pass
	/// retries the proof delivery.
	#[serde(default)]
	pub proof_delivered: bool,
	/// Set once the plain "payment sent" receipt (frozen contract 4.3.1) has been
	/// accepted by a relay. Published at S1 DISPATCH, the moment the payment
	/// envelope is accepted and the wallet UI flips to "sent", NOT at finalize,
	/// so the buyer's order page loses its scannable QR the instant they pay and
	/// the double-send window closes. One receipt per tx: this flag is the guard
	/// against a duplicate at finalize. `false` for every ordinary (non-order)
	/// send, which publishes no receipt at all.
	#[serde(default)]
	pub receipt_sent: bool,
	/// The wallet's OWN nostr identity (pubkey hex) that was ACTIVE when this row
	/// was created — the "front door" the payment came in / went out on. One
	/// wallet can hold several identities that all redeem into the single shared
	/// grin balance; this tags which one so activity can be shown per identity and
	/// a later per-identity accounting split has the data. Serde-default empty on
	/// pre-feature rows, which are treated as identity #1 (the primary).
	#[serde(default)]
	pub recipient_pubkey: String,
}

/// A contact: another nostr user we can pay.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Contact {
	pub ver: u8,
	/// Public key, hex.
	pub npub: String,
	/// Local petname, overrides any resolved name.
	pub petname: Option<String>,
	/// NIP-05 identifier (user@domain).
	pub nip05: Option<String>,
	/// Unix time of last successful NIP-05 verification.
	pub nip05_verified_at: Option<i64>,
	/// Known DM relays (kind 10050) of the contact.
	pub relays: Vec<String>,
	/// The contact advertises NIP-44 v3 in the `encryption` tag of the same
	/// kind 10050 the relays come from (NIP-17 backward-compat extension).
	/// Absent tag = v2 only, hence the conservative default.
	#[serde(default)]
	pub nip44_v3: bool,
	/// Avatar palette index.
	pub hue: u8,
	/// Auto-added from an incoming payment, not yet confirmed by the user.
	pub unknown: bool,
	pub added_at: i64,
	pub last_paid_at: Option<i64>,
	/// Blocked at the nostr level: their incoming messages are dropped on
	/// ingest, as if muted on nostr (which is what this is).
	#[serde(default)]
	pub blocked: bool,
}

/// Status of an incoming payment request (Invoice1).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum RequestStatus {
	Pending,
	Approved,
	Declined,
	Expired,
	/// Withdrawn by the requester (we received their cancel control message).
	Cancelled,
}

/// An incoming Invoice1 payment request awaiting explicit user approval.
/// NEVER paid automatically.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PaymentRequest {
	pub ver: u8,
	/// Rumor event id, hex (storage key).
	pub rumor_id: String,
	/// Slate UUID string.
	pub slate_id: String,
	/// Raw slatepack armor to pay on approval.
	pub slatepack: String,
	/// Requester public key, hex.
	pub npub: String,
	/// Requested amount in atomic units.
	pub amount: u64,
	/// Sanitized note.
	pub note: Option<String>,
	pub received_at: i64,
	pub status: RequestStatus,
}

/// A cached news post (kind 30023 long-form) from the Goblin news key, shown
/// in the Home news panel. Only the fields the panel needs are persisted.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct NewsItem {
	/// The addressable `d` tag (replaceable-event identifier); dedupe key.
	pub d: String,
	/// Event `created_at` (seconds); newest per `d` wins, newest overall shows.
	pub created_at: i64,
	/// The post `title` tag. May carry a trailing `[xx]` language marker, which
	/// the Home panel strips for display (see `data::news_display_title`).
	pub title: String,
	/// Plain-text summary (the `summary` tag, or a stripped content fallback).
	pub summary: String,
	/// Article language as a lower-case ISO 639-1 code, taken from an event
	/// language tag (`l` / `lang`) when present. `None` falls back to the
	/// title-suffix marker, then to English. `#[serde(default)]` so posts cached
	/// before this field existed still deserialize.
	#[serde(default)]
	pub lang: Option<String>,
	/// Optional NIP-23 `published_at` tag (unix seconds). When present the Home
	/// panel dates the article by this rather than `created_at` (which tracks the
	/// event's last edit). `#[serde(default)]` so posts cached before this field
	/// existed still deserialize.
	#[serde(default)]
	pub published_at: Option<i64>,
}

/// Whether the plain "payment sent" receipt (frozen contract 4.3.1) is due at
/// S1 dispatch for this send. True only for an order-carrying send in proof
/// mode: a person-to-person send (no `order=` context) publishes no receipt at
/// all, at any lifecycle point. The receipt is the buyer's routing key back to
/// the market (the `payment-request` tag echoes the order handle), so without an
/// order handle there is nothing the market could match and nothing to publish.
pub fn receipt_due_at_dispatch(proof_mode: bool, order: Option<&str>) -> bool {
	proof_mode && order.is_some_and(|o| !o.trim().is_empty())
}

/// Current unix time in seconds.
pub fn unix_time() -> i64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs() as i64)
		.unwrap_or(0)
}
