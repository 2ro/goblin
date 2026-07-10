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

//! Default relay set and relay list helpers.

/// Default DM relays: the Floonet relay (the pinned shared floor) plus
/// Tor-reachable public relays for redundancy.
///
/// TRANSPORT CONSTRAINT: Goblin dials every relay over Tor, so the defaults MUST
/// be relays that accept Tor-exit connections. `relay.damus.io` and `nos.lol`
/// throttle/block Tor exits — a wallet left on the raw defaults (e.g. when pool
/// selection hasn't run or found nothing) then had NO working fallback whenever
/// the Floonet onion flapped, so its payments stopped flowing. `relay.0xchat.com`
/// and `offchain.pub` are Tor-friendly (and are also probe-vetted pool `dm`
/// candidates), giving a real fallback that survives an onion drop.
/// The shared Floonet rendezvous relay. Pinned FIRST in every resolved relay
/// list and never removable by the user, so any two Goblin wallets always share
/// a guaranteed rendezvous regardless of transport or per-wallet edits.
pub const FLOONET_RELAY: &str = "wss://relay.floonet.dev";

pub const DEFAULT_RELAYS: &[&str] = &[
	FLOONET_RELAY,
	"wss://relay.0xchat.com",
	"wss://offchain.pub",
];

/// FIXED pinned relay set used by EVERY identity when the wallet routes over Tor.
///
/// Per the owner's ruling (per-user-tor plan §4): on Tor there is NO per-identity
/// variation — all identities share this one set so switching identity on Tor
/// never changes relays (and keeps the instant in-process switch). `relay.floonet.dev`
/// is pinned FIRST here (as it is in [`DEFAULT_RELAYS`]) so any two Goblin users
/// always share a guaranteed rendezvous. All three are reached over a Tor exit to
/// their clearnet host (no onion). The clearnet regime instead draws a per-identity
/// random healthy subset from the pool (see [`effective_relays`]).
pub const TOR_RELAYS: &[&str] = &[FLOONET_RELAY, "wss://relay.nostr.net", "wss://offchain.pub"];

/// Default NIP-05 identity server.
pub const DEFAULT_NIP05_SERVER: &str = "https://goblin.st";

/// Domain whose NIP-05 names display as plain @user.
pub const HOME_NIP05_DOMAIN: &str = "goblin.st";

/// Maximum relays published in the kind 10050 DM relay list (NIP-17 guidance).
pub const MAX_DM_RELAYS: usize = 3;

/// Resolve the effective relay list for the CURRENT transport (per-user-tor §4).
///
/// Precedence, in order:
/// 1. A user `nostr.toml` relay override wins in BOTH regimes (explicit user intent).
/// 2. Tor ON -> the FIXED [`TOR_RELAYS`] set, identical for every identity.
/// 3. Clearnet -> this identity's persisted random healthy subset (`clearnet_sticky`,
///    i.e. `NostrIdentity.dm_relays`), which pins `relay.floonet.dev` first.
/// 4. Clearnet with no subset yet selected -> the built-in `clearnet_defaults`
///    ([`DEFAULT_RELAYS`], floonet pinned first) until selection runs.
///
/// `relay.floonet.dev` is therefore pinned first in every branch, so any two users
/// share a rendezvous regardless of transport or per-identity subset. On Tor the
/// persisted clearnet subset is IGNORED (not read, not mutated) so it survives a
/// round-trip back to clearnet unchanged.
pub fn effective_relays(
	over_tor: bool,
	override_set: Option<Vec<String>>,
	clearnet_sticky: Vec<String>,
	clearnet_defaults: Vec<String>,
) -> Vec<String> {
	if let Some(over) = override_set {
		return pin_floonet(over);
	}
	if over_tor {
		return TOR_RELAYS.iter().map(|s| s.to_string()).collect();
	}
	if !clearnet_sticky.is_empty() {
		return clearnet_sticky;
	}
	clearnet_defaults
}

/// Ensure [`FLOONET_RELAY`] is present and pinned FIRST, preserving the order of
/// the remaining entries and dropping any duplicate floonet occurrences. Applied
/// to every user relay override so the shared rendezvous can never be edited out.
pub fn pin_floonet(relays: Vec<String>) -> Vec<String> {
	let mut out = vec![FLOONET_RELAY.to_string()];
	for r in relays {
		if r != FLOONET_RELAY && !out.contains(&r) {
			out.push(r);
		}
	}
	out
}

/// Normalize a user-entered relay url (adds wss:// when missing).
pub fn normalize_relay_url(input: &str) -> Option<String> {
	let trimmed = input.trim().trim_end_matches('/');
	if trimmed.is_empty() {
		return None;
	}
	let url = if trimmed.starts_with("ws://") || trimmed.starts_with("wss://") {
		trimmed.to_string()
	} else {
		format!("wss://{}", trimmed)
	};
	// Basic shape validation.
	match nostr_sdk::Url::parse(&url) {
		Ok(u) if u.host_str().is_some() => Some(url),
		_ => None,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn normalizes_relay_urls() {
		assert_eq!(
			normalize_relay_url("relay.goblin.st"),
			Some("wss://relay.goblin.st".to_string())
		);
		assert_eq!(
			normalize_relay_url("wss://relay.damus.io/"),
			Some("wss://relay.damus.io".to_string())
		);
		assert_eq!(
			normalize_relay_url("ws://127.0.0.1:8088"),
			Some("ws://127.0.0.1:8088".to_string())
		);
		assert_eq!(normalize_relay_url(""), None);
		assert_eq!(normalize_relay_url("   "), None);
	}

	fn defaults() -> Vec<String> {
		DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect()
	}

	const FLOONET: &str = "wss://relay.floonet.dev";

	#[test]
	fn floonet_is_pinned_first_in_both_regimes() {
		// The shared rendezvous is the first entry of every base set.
		assert_eq!(DEFAULT_RELAYS[0], FLOONET);
		assert_eq!(TOR_RELAYS[0], FLOONET);
		// Tor set stays within the DM-relay size cap.
		assert!(TOR_RELAYS.len() <= MAX_DM_RELAYS);
	}

	#[test]
	fn tor_yields_the_fixed_pinned_set_with_floonet() {
		// On Tor the fixed set is used regardless of any persisted clearnet subset,
		// and it is identical for every identity.
		let stale_clearnet = vec!["wss://someones.clearnet.example".to_string()];
		let r = effective_relays(true, None, stale_clearnet, defaults());
		assert_eq!(
			r,
			TOR_RELAYS.iter().map(|s| s.to_string()).collect::<Vec<_>>()
		);
		assert_eq!(r[0], FLOONET);
		assert!(r.iter().any(|u| u == FLOONET));
	}

	#[test]
	fn clearnet_uses_the_persisted_per_identity_subset_with_floonet() {
		let sticky = vec![FLOONET.to_string(), "wss://a.example".to_string()];
		let r = effective_relays(false, None, sticky.clone(), defaults());
		assert_eq!(r, sticky);
		assert_eq!(r[0], FLOONET);
	}

	#[test]
	fn clearnet_without_a_subset_falls_back_to_defaults_floonet_pinned() {
		let r = effective_relays(false, None, vec![], defaults());
		assert_eq!(r, defaults());
		assert_eq!(r[0], FLOONET);
	}

	#[test]
	fn a_user_override_wins_in_both_regimes_with_floonet_pinned() {
		let ov = vec!["wss://only.example".to_string()];
		let expected = vec![FLOONET.to_string(), "wss://only.example".to_string()];
		// The override wins over both the Tor set and the clearnet subset, and
		// floonet is pinned first in each regime even when the user omitted it.
		assert_eq!(
			effective_relays(true, Some(ov.clone()), vec![], vec![]),
			expected
		);
		assert_eq!(
			effective_relays(false, Some(ov.clone()), vec![], vec![]),
			expected
		);
	}

	#[test]
	fn pin_floonet_prepends_and_dedups() {
		// Missing floonet gets prepended.
		assert_eq!(
			pin_floonet(vec!["wss://a.example".to_string()]),
			vec![FLOONET.to_string(), "wss://a.example".to_string()]
		);
		// A floonet already in the middle is moved to the front (deduped).
		assert_eq!(
			pin_floonet(vec![
				"wss://a.example".to_string(),
				FLOONET.to_string(),
				"wss://a.example".to_string(),
			]),
			vec![FLOONET.to_string(), "wss://a.example".to_string()]
		);
		// Floonet can never be edited out entirely.
		assert_eq!(pin_floonet(vec![]), vec![FLOONET.to_string()]);
	}
}
