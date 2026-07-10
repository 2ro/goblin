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

//! Identity and key surface: pubkey/npub/profile lookups, private-tag
//! and re-encryption, active-identity switching, contact resolution and
//! the NIP-05 re-check helper.

use super::service::{connect_relays, publish_identity};
use super::*;

impl NostrService {
	/// Every held identity's pubkey — the recipients the gift-wrap subscription
	/// filter names, so the wallet receives for all identities at once.
	pub fn recv_pubkeys(&self) -> Vec<PublicKey> {
		self.recv
			.read()
			.iter()
			.map(|h| h.keys.public_key())
			.collect()
	}

	/// Snapshot of every held identity live in memory (for unwrapping a wrap with
	/// whichever key opens it, and for publishing each identity's relay list).
	pub fn recv_snapshot(&self) -> Vec<HeldIdentityKeys> {
		self.recv.read().clone()
	}

	/// Whether `pk` is one of THIS wallet's own held identities (used to ignore
	/// our own wrap-to-self copies across any identity).
	pub fn is_own_pubkey(&self, pk: &PublicKey) -> bool {
		self.recv.read().iter().any(|h| &h.keys.public_key() == pk)
	}

	// --- Authorize Sessions (v2) -------------------------------------------

	/// Publish an event on the service runtime without blocking the caller
	/// (used for the best-effort `session-end` courtesy). No-op if the loop is
	/// not running.
	pub(super) fn publish_event_best_effort(&self, event: nostr_sdk::Event) {
		let (Some(client), Some(handle)) =
			(self.client.read().clone(), self.rt_handle.read().clone())
		else {
			return;
		};
		let urls: Vec<String> = self.relays();
		handle.spawn(async move {
			let _ = tokio::time::timeout(
				std::time::Duration::from_secs(10),
				client.send_event_to(&urls, &event),
			)
			.await;
		});
	}

	/// Update a held identity's PRIVATE tag in the in-memory set (and the active
	/// copy when it is the same identity), so the switcher re-renders immediately
	/// after a rename without a service rebuild. The caller persists the file.
	pub fn set_private_tag(&self, hex: &str, tag: Option<String>) {
		for h in self.recv.write().iter_mut() {
			if h.keys.public_key().to_hex() == hex {
				h.identity.private_tag = tag.clone();
			}
		}
		if self.public_key().to_hex() == hex {
			self.identity.write().private_tag = tag;
		}
	}

	/// Re-encrypt every in-memory held identity's ncryptsec from `old` to `new`,
	/// keeping the running service in sync with a wallet-password change without a
	/// teardown. A password change does not alter the decrypted keys, so sending
	/// and listening keep working untouched; this only refreshes the encrypted
	/// blobs the in-memory copies carry, so a same-session gated op (which
	/// re-unlocks the stored identity with the NEW password) and any later
	/// identity-file save both use the new password rather than the stale old one.
	/// Best-effort per copy: a copy that fails to re-encrypt is left as is (a
	/// gated op on it may then need the app reopened), never a hard error.
	pub fn reencrypt_in_memory(&self, old: &str, new: &str) {
		for h in self.recv.write().iter_mut() {
			let _ = h.identity.reencrypt(old, new);
		}
		let _ = self.identity.write().reencrypt(old, new);
	}

	/// Instant, purely-local identity switch: re-point the active keys/identity to
	/// a held identity already unlocked and already listening. No password, no
	/// teardown, no catch-up. `false` if `hex` is not held.
	pub fn set_active_by_pubkey(&self, hex: &str) -> bool {
		let held = self
			.recv
			.read()
			.iter()
			.find(|h| h.keys.public_key().to_hex() == hex)
			.cloned();
		match held {
			Some(h) => {
				*self.keys.write() = h.keys;
				*self.identity.write() = h.identity;
				true
			}
			None => false,
		}
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
		// Run on the SERVICE runtime — the relay connections (all driven over Tor)
		// live there. A throwaway current-thread runtime can't
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
			// First-event-wins, scoped to the relays we just dialed: stream from
			// exactly that set and return on the FIRST kind-0 that parses as
			// Metadata (capped at 10s by the stream's own auto-close). The old
			// `fetch_events` waited for EVERY relay (or the full 10s), so a single
			// dead hint relay in the set always cost the whole 10s.
			use futures::StreamExt;
			let mut stream = client
				.stream_events_from(dial, filter, Duration::from_secs(10))
				.await
				.ok()?;
			while let Some(event) = stream.next().await {
				if let Ok(md) = serde_json::from_str::<Metadata>(&event.content) {
					return Some(NostrProfile {
						name: md.name.filter(|s| !s.is_empty()),
						nip05: md.nip05.filter(|s| !s.is_empty()),
					});
				}
			}
			None
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
		// First-event-wins, scoped to our own connected relays (cap 8s): return on
		// the first kind-0 that parses as Metadata rather than waiting on every
		// relay / the full timeout, so one dead relay can't stall the request gate.
		use futures::StreamExt;
		let mut stream = client
			.stream_events_from(self.relays(), filter, Duration::from_secs(8))
			.await
			.ok()?;
		while let Some(event) = stream.next().await {
			if let Ok(md) = serde_json::from_str::<Metadata>(&event.content) {
				return md
					.custom
					.get("goblin_accepts_requests")
					.and_then(|v| v.as_bool());
			}
		}
		None
	}

	/// Republish our kind-0 profile + kind-10050 DM relays (e.g. after toggling
	/// the incoming-requests preference) so the change propagates immediately.
	pub async fn republish_identity(self: &Arc<Self>) {
		let client = { self.client.read().clone() };
		if let Some(client) = client {
			publish_identity(self, &client).await;
		}
	}

	/// Ensure a contact entry exists for a sender (auto-added as unknown).
	pub(super) fn ensure_contact(&self, sender_hex: &str) {
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
				nip44_v3: false,
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
			nip44_v3: false,
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
}
