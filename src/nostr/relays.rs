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
pub const DEFAULT_RELAYS: &[&str] = &[
	"wss://relay.floonet.dev",
	"wss://relay.0xchat.com",
	"wss://offchain.pub",
];

/// Default NIP-05 identity server.
pub const DEFAULT_NIP05_SERVER: &str = "https://goblin.st";

/// Domain whose NIP-05 names display as plain @user.
pub const HOME_NIP05_DOMAIN: &str = "goblin.st";

/// Maximum relays published in the kind 10050 DM relay list (NIP-17 guidance).
pub const MAX_DM_RELAYS: usize = 3;

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
}
