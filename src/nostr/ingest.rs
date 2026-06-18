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

//! The guarded ingest policy: what to do with a validated incoming slate.
//!
//! Security invariants (do not weaken):
//! - Invoice1 (a request for US to PAY) is NEVER paid automatically.
//! - Standard2/Invoice2 replies only finalize when they match a pending
//!   transaction we initiated AND the sender matches the stored counterparty.
//! - Everything else is dropped.

use grin_wallet_libwallet::SlateState;

use crate::nostr::config::AcceptPolicy;
use crate::nostr::types::{NostrSendStatus, NostrTxDirection, TxNostrMeta};

/// What the ingest pipeline should do with a validated slate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IngestDecision {
	/// Standard1: receive the payment and reply S2 automatically.
	AutoReceive,
	/// Standard1 under a stricter accept policy: surface for approval.
	SurfaceIncoming,
	/// Standard2/Invoice2 reply matching our pending tx: finalize and post.
	FinalizePost,
	/// Invoice1: surface a payment request for explicit user approval.
	SurfaceRequest,
	/// Drop silently (reason for logging only).
	Drop(&'static str),
}

/// Inputs for the policy decision.
pub struct IngestContext<'a> {
	/// Parsed slate state.
	pub state: SlateState,
	/// Parsed slate amount in atomic units.
	pub amount: u64,
	/// Seal-verified sender public key, hex.
	pub sender: &'a str,
	/// Stored nostr metadata for this slate id, when present.
	pub meta: Option<&'a TxNostrMeta>,
	/// Whether the wallet has a transaction with this slate id.
	pub tx_exists: bool,
	/// Whether the sender is a known (non-unknown) contact.
	pub is_contact: bool,
	/// Accept policy from wallet config.
	pub accept: AcceptPolicy,
	/// Whether incoming payment requests (Invoice1) are accepted (opt-out).
	pub allow_requests: bool,
}

/// Pure policy function — unit tested, no side effects.
pub fn decide(ctx: &IngestContext) -> IngestDecision {
	match ctx.state {
		SlateState::Standard1 => {
			if ctx.amount == 0 {
				return IngestDecision::Drop("zero amount");
			}
			if ctx.tx_exists || ctx.meta.is_some() {
				return IngestDecision::Drop("slate already known");
			}
			match ctx.accept {
				AcceptPolicy::Everyone => IngestDecision::AutoReceive,
				AcceptPolicy::Contacts => {
					if ctx.is_contact {
						IngestDecision::AutoReceive
					} else {
						IngestDecision::SurfaceIncoming
					}
				}
				AcceptPolicy::Ask => IngestDecision::SurfaceIncoming,
			}
		}
		// Standard2 is the counterparty's reply to a send WE initiated. The
		// status allow-set below includes Created/SendFailed (not just
		// AwaitingS2) on purpose: our send records intent as Created BEFORE
		// dispatch and only flips to AwaitingS2 after a relay accepts S1, so
		// a crash in that gap leaves a legitimate pending send marked
		// Created/SendFailed even though the counterparty did receive S1.
		// This is NOT a forgery vector: a finalizing S2 must carry our S1
		// partial signature over our locked outputs, which the counterparty
		// can only have if we actually sent it. Sender + tx_exists are still
		// required, and grin rejects finalizing an already-finalized tx.
		SlateState::Standard2 => match ctx.meta {
			Some(meta)
				if meta.direction == NostrTxDirection::Sent
					&& matches!(
						meta.status,
						NostrSendStatus::AwaitingS2
							| NostrSendStatus::Created
							| NostrSendStatus::SendFailed
					) && meta.npub == ctx.sender
					&& ctx.tx_exists =>
			{
				IngestDecision::FinalizePost
			}
			Some(meta) if meta.npub != ctx.sender => {
				IngestDecision::Drop("S2 sender does not match stored counterparty")
			}
			_ => IngestDecision::Drop("S2 without matching pending send"),
		},
		SlateState::Invoice1 => {
			if ctx.amount == 0 {
				return IngestDecision::Drop("zero amount");
			}
			if ctx.tx_exists || ctx.meta.is_some() {
				return IngestDecision::Drop("slate already known");
			}
			// Honour the opt-out: when incoming requests are off, drop them.
			// (Requesters also see this advertised in our profile beforehand.)
			if !ctx.allow_requests {
				return IngestDecision::Drop("incoming requests disabled");
			}
			// NEVER pay automatically.
			IngestDecision::SurfaceRequest
		}
		SlateState::Invoice2 => match ctx.meta {
			Some(meta)
				if meta.direction == NostrTxDirection::RequestedByUs
					&& matches!(
						meta.status,
						NostrSendStatus::AwaitingI2
							| NostrSendStatus::Created
							| NostrSendStatus::SendFailed
					) && meta.npub == ctx.sender
					&& ctx.tx_exists =>
			{
				IngestDecision::FinalizePost
			}
			Some(meta) if meta.npub != ctx.sender => {
				IngestDecision::Drop("I2 sender does not match stored counterparty")
			}
			_ => IngestDecision::Drop("I2 without matching pending request"),
		},
		_ => IngestDecision::Drop("unsupported slate state"),
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::nostr::types::unix_time;

	const ALICE: &str = "91cf9dbbea5e6511fd2bbb190b112055ee4131c5d2bbb9faedf3ee8cbeac0d05";
	const MALLORY: &str = "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

	fn meta(direction: NostrTxDirection, status: NostrSendStatus, npub: &str) -> TxNostrMeta {
		TxNostrMeta {
			ver: 1,
			slate_id: "s".into(),
			npub: npub.into(),
			direction,
			note: None,
			status,
			sent_event_id: None,
			received_rumor_id: None,
			created_at: unix_time(),
			updated_at: unix_time(),
		}
	}

	fn ctx<'a>(
		state: SlateState,
		amount: u64,
		sender: &'a str,
		meta: Option<&'a TxNostrMeta>,
		tx_exists: bool,
	) -> IngestContext<'a> {
		IngestContext {
			state,
			amount,
			sender,
			meta,
			tx_exists,
			is_contact: false,
			accept: AcceptPolicy::Everyone,
			allow_requests: true,
		}
	}

	#[test]
	fn s1_auto_receives_from_anyone_by_default() {
		let c = ctx(SlateState::Standard1, 100, ALICE, None, false);
		assert_eq!(decide(&c), IngestDecision::AutoReceive);
	}

	#[test]
	fn s1_zero_amount_drops() {
		let c = ctx(SlateState::Standard1, 0, ALICE, None, false);
		assert!(matches!(decide(&c), IngestDecision::Drop(_)));
	}

	#[test]
	fn s1_duplicate_drops() {
		let m = meta(
			NostrTxDirection::Received,
			NostrSendStatus::RepliedS2,
			ALICE,
		);
		let c = ctx(SlateState::Standard1, 100, ALICE, Some(&m), false);
		assert!(matches!(decide(&c), IngestDecision::Drop(_)));
		let c2 = ctx(SlateState::Standard1, 100, ALICE, None, true);
		assert!(matches!(decide(&c2), IngestDecision::Drop(_)));
	}

	#[test]
	fn s1_contacts_policy_surfaces_unknown() {
		let mut c = ctx(SlateState::Standard1, 100, ALICE, None, false);
		c.accept = AcceptPolicy::Contacts;
		assert_eq!(decide(&c), IngestDecision::SurfaceIncoming);
		c.is_contact = true;
		assert_eq!(decide(&c), IngestDecision::AutoReceive);
	}

	#[test]
	fn s1_ask_policy_always_surfaces() {
		let mut c = ctx(SlateState::Standard1, 100, ALICE, None, false);
		c.accept = AcceptPolicy::Ask;
		c.is_contact = true;
		assert_eq!(decide(&c), IngestDecision::SurfaceIncoming);
	}

	#[test]
	fn s2_finalizes_only_matching_pending_send() {
		let m = meta(NostrTxDirection::Sent, NostrSendStatus::AwaitingS2, ALICE);
		let c = ctx(SlateState::Standard2, 100, ALICE, Some(&m), true);
		assert_eq!(decide(&c), IngestDecision::FinalizePost);
	}

	#[test]
	fn s2_from_wrong_sender_drops() {
		let m = meta(NostrTxDirection::Sent, NostrSendStatus::AwaitingS2, ALICE);
		let c = ctx(SlateState::Standard2, 100, MALLORY, Some(&m), true);
		assert!(matches!(decide(&c), IngestDecision::Drop(_)));
	}

	#[test]
	fn s2_without_meta_drops() {
		let c = ctx(SlateState::Standard2, 100, ALICE, None, true);
		assert!(matches!(decide(&c), IngestDecision::Drop(_)));
	}

	#[test]
	fn s2_without_wallet_tx_drops() {
		let m = meta(NostrTxDirection::Sent, NostrSendStatus::AwaitingS2, ALICE);
		let c = ctx(SlateState::Standard2, 100, ALICE, Some(&m), false);
		assert!(matches!(decide(&c), IngestDecision::Drop(_)));
	}

	#[test]
	fn s2_wrong_direction_drops() {
		let m = meta(
			NostrTxDirection::Received,
			NostrSendStatus::RepliedS2,
			ALICE,
		);
		let c = ctx(SlateState::Standard2, 100, ALICE, Some(&m), true);
		assert!(matches!(decide(&c), IngestDecision::Drop(_)));
	}

	#[test]
	fn s2_on_cancelled_send_drops() {
		// Safety backstop for the cancel/reclaim race: once a manual "Cancel
		// payment" (or 24h expiry) marks the meta Cancelled, a late S2 from a
		// recipient who finally came online must be DROPPED — never re-finalized
		// onto outputs the sender already reclaimed.
		let m = meta(NostrTxDirection::Sent, NostrSendStatus::Cancelled, ALICE);
		let c = ctx(SlateState::Standard2, 100, ALICE, Some(&m), true);
		assert!(matches!(decide(&c), IngestDecision::Drop(_)));
	}

	#[test]
	fn s2_on_finalized_send_drops() {
		// Idempotency: a duplicate S2 after we already finalized is dropped.
		let m = meta(NostrTxDirection::Sent, NostrSendStatus::Finalized, ALICE);
		let c = ctx(SlateState::Standard2, 100, ALICE, Some(&m), true);
		assert!(matches!(decide(&c), IngestDecision::Drop(_)));
	}

	#[test]
	fn s2_finalizes_from_pre_dispatch_states() {
		// Created/SendFailed are deliberately accepted: a crash between
		// relay-accept and the AwaitingS2 write must not strand a real send.
		for status in [NostrSendStatus::Created, NostrSendStatus::SendFailed] {
			let m = meta(NostrTxDirection::Sent, status, ALICE);
			let c = ctx(SlateState::Standard2, 100, ALICE, Some(&m), true);
			assert_eq!(decide(&c), IngestDecision::FinalizePost);
			// Still bound to the counterparty: a stranger's S2 drops.
			let c2 = ctx(SlateState::Standard2, 100, MALLORY, Some(&m), true);
			assert!(matches!(decide(&c2), IngestDecision::Drop(_)));
		}
	}

	#[test]
	fn i1_never_pays_automatically() {
		// Even from a contact under the most permissive policy.
		let mut c = ctx(SlateState::Invoice1, 100, ALICE, None, false);
		c.is_contact = true;
		c.accept = AcceptPolicy::Everyone;
		assert_eq!(decide(&c), IngestDecision::SurfaceRequest);
	}

	#[test]
	fn i1_dropped_when_requests_disabled() {
		let mut c = ctx(SlateState::Invoice1, 100, ALICE, None, false);
		c.allow_requests = false;
		assert!(matches!(decide(&c), IngestDecision::Drop(_)));
	}

	#[test]
	fn i2_finalizes_only_matching_request() {
		let m = meta(
			NostrTxDirection::RequestedByUs,
			NostrSendStatus::AwaitingI2,
			ALICE,
		);
		let c = ctx(SlateState::Invoice2, 100, ALICE, Some(&m), true);
		assert_eq!(decide(&c), IngestDecision::FinalizePost);
		let c2 = ctx(SlateState::Invoice2, 100, MALLORY, Some(&m), true);
		assert!(matches!(decide(&c2), IngestDecision::Drop(_)));
	}

	#[test]
	fn terminal_states_drop() {
		for state in [
			SlateState::Standard3,
			SlateState::Invoice3,
			SlateState::Unknown,
		] {
			let c = ctx(state, 100, ALICE, None, false);
			assert!(matches!(decide(&c), IngestDecision::Drop(_)));
		}
	}
}
