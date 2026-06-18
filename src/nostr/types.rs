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

/// Current unix time in seconds.
pub fn unix_time() -> i64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs() as i64)
		.unwrap_or(0)
}
