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

//! Per-wallet nostr configuration, stored as `nostr.toml` in the wallet dir.

use serde_derive::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::Settings;
use crate::nostr::relays::{DEFAULT_NIP05_SERVER, DEFAULT_RELAYS};

/// Policy for accepting incoming payments (Standard1 slates).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum AcceptPolicy {
	/// Accept payments from anyone automatically (default, instant-pay feel).
	Everyone,
	/// Auto-accept contacts, surface unknown senders for approval.
	Contacts,
	/// Surface every incoming payment for approval.
	Ask,
}

/// Per-wallet nostr configuration.
#[derive(Serialize, Deserialize, Clone, Default)]
pub struct NostrConfig {
	/// Whether the nostr subsystem runs for this wallet.
	enabled: Option<bool>,
	/// Relay list override.
	relays: Option<Vec<String>>,
	/// Accept policy for incoming payments.
	accept_from: Option<AcceptPolicy>,
	/// NIP-05 identity server base URL.
	nip05_server: Option<String>,
	/// Seconds after which a still-pending transaction is auto-canceled/expired.
	/// Default 24h; lower it (e.g. 60) in nostr.toml to test the expiry flow.
	expiry_secs: Option<i64>,
	/// Seconds before the manual "Cancel payment" button appears on a still-
	/// pending send (one that never reached a relay shows it immediately).
	/// Default 10 min; lower it in nostr.toml to test the cancel flow.
	cancel_grace_secs: Option<i64>,
	/// Whether incoming payment requests (Invoice1) are accepted. Opt-out: on
	/// by default. When off, incoming requests are dropped and the preference is
	/// advertised in our kind-0 profile so requesters see it before sending.
	allow_incoming_requests: Option<bool>,

	/// Whether this wallet routes its nostr relay traffic and every sensitive
	/// HTTP call (NIP-05, price, relay pool) over Tor. Tri-state on purpose:
	/// `Some(true)` = Tor on, `Some(false)` = clearnet, `None` (unset) resolves
	/// to ON. `None` is what every pre-existing `nostr.toml` deserializes to, so
	/// upgrading wallets keep Tor with no migration; new wallets write an explicit
	/// value at onboarding (a later slice).
	tor_enabled: Option<bool>,

	/// Path of the config file, not serialized.
	#[serde(skip)]
	path: Option<PathBuf>,
}

impl NostrConfig {
	/// Nostr configuration file name inside the wallet directory.
	pub const FILE_NAME: &'static str = "nostr.toml";

	/// Load the config from the wallet directory, falling back to defaults.
	pub fn load(wallet_dir: PathBuf) -> Self {
		let mut path = wallet_dir;
		path.push(Self::FILE_NAME);
		let mut config: Self = Settings::read_from_file(path.clone()).unwrap_or_default();
		config.path = Some(path);
		config
	}

	/// Save the config to disk.
	pub fn save(&self) {
		if let Some(path) = &self.path {
			Settings::write_to_file(self, path.clone());
		}
	}

	pub fn enabled(&self) -> bool {
		self.enabled.unwrap_or(true)
	}

	pub fn set_enabled(&mut self, enabled: bool) {
		self.enabled = Some(enabled);
		self.save();
	}

	pub fn relays(&self) -> Vec<String> {
		self.relays_override()
			.unwrap_or_else(|| DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect())
	}

	/// The relay list explicitly set by the user in nostr.toml, if any. An
	/// override disables the per-identity advertised-set selection entirely.
	pub fn relays_override(&self) -> Option<Vec<String>> {
		self.relays.clone().filter(|r| !r.is_empty())
	}

	pub fn set_relays(&mut self, relays: Vec<String>) {
		self.relays = Some(relays);
		self.save();
	}

	pub fn accept_from(&self) -> AcceptPolicy {
		self.accept_from.unwrap_or(AcceptPolicy::Everyone)
	}

	pub fn set_accept_from(&mut self, policy: AcceptPolicy) {
		self.accept_from = Some(policy);
		self.save();
	}

	pub fn nip05_server(&self) -> String {
		self.nip05_server
			.clone()
			.unwrap_or_else(|| DEFAULT_NIP05_SERVER.to_string())
	}

	/// The name-authority HOST derived from the configured server URL (e.g.
	/// `goblin.st`). This is "home": bare names (`alice`) resolve here and own/
	/// home-domain names display without their domain. Federation: a different
	/// authority makes `alice` mean `alice@thatdomain`, while a full
	/// `bob@goblin.st` always resolves against goblin.st.
	pub fn home_domain(&self) -> String {
		let server = self.nip05_server();
		server
			.trim_start_matches("https://")
			.trim_start_matches("http://")
			.split('/')
			.next()
			.unwrap_or("")
			.split(':')
			.next()
			.unwrap_or("")
			.to_string()
	}

	/// Set the name-authority server (e.g. `https://other.example`). Pass an
	/// empty string to reset to the default (goblin.st).
	pub fn set_nip05_server(&mut self, server: Option<String>) {
		self.nip05_server = server.filter(|s| !s.trim().is_empty());
		self.save();
	}

	/// Seconds after which a still-pending transaction is auto-canceled/expired.
	pub fn expiry_secs(&self) -> i64 {
		self.expiry_secs.unwrap_or(24 * 60 * 60)
	}

	/// Seconds before the manual cancel button appears on a pending send.
	pub fn cancel_grace_secs(&self) -> i64 {
		self.cancel_grace_secs.unwrap_or(600)
	}

	pub fn allow_incoming_requests(&self) -> bool {
		self.allow_incoming_requests.unwrap_or(true)
	}

	pub fn set_allow_incoming_requests(&mut self, allow: bool) {
		self.allow_incoming_requests = Some(allow);
		self.save();
	}

	/// Resolved Tor routing for this wallet: `None` (unset, i.e. every legacy
	/// `nostr.toml`) resolves to ON so upgraders keep Tor with no migration.
	/// New wallets write an explicit value at onboarding (a later slice).
	pub fn tor_enabled(&self) -> bool {
		self.tor_enabled.unwrap_or(true)
	}

	/// Whether the wallet has an EXPLICIT Tor choice on disk (vs the `None`
	/// upgrade default). Onboarding uses this to know it must still write one.
	pub fn tor_enabled_is_set(&self) -> bool {
		self.tor_enabled.is_some()
	}

	/// Persist an explicit Tor routing choice. Toggling this at runtime must be
	/// followed by `NostrService::restart()` so the relay pool is rebuilt on the
	/// newly-selected transport (see `src/nostr/client.rs::run_service`).
	pub fn set_tor_enabled(&mut self, enabled: bool) {
		self.tor_enabled = Some(enabled);
		self.save();
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn tor_enabled_tri_state_resolves_and_is_back_compat() {
		// A brand-new/default config has no explicit choice and resolves to ON,
		// so nothing about the default flips a wallet off Tor.
		let cfg = NostrConfig::default();
		assert!(!cfg.tor_enabled_is_set());
		assert!(cfg.tor_enabled(), "unset must resolve to Tor ON");

		// The load-bearing upgrade guarantee: an OLD nostr.toml written before
		// this field existed deserializes with tor_enabled = None -> ON. Include
		// an unrelated field so we exercise a realistic legacy file.
		let legacy: NostrConfig =
			toml::from_str("accept_from = \"Everyone\"\n").expect("legacy nostr.toml parses");
		assert!(!legacy.tor_enabled_is_set());
		assert!(legacy.tor_enabled(), "legacy file must keep Tor ON");

		// Explicit values round-trip both ways (save() is a no-op with no path).
		let mut cfg = NostrConfig::default();
		cfg.set_tor_enabled(false);
		assert!(cfg.tor_enabled_is_set());
		assert!(!cfg.tor_enabled());
		cfg.set_tor_enabled(true);
		assert!(cfg.tor_enabled());

		// An explicit false on disk parses back as clearnet.
		let off: NostrConfig =
			toml::from_str("tor_enabled = false\n").expect("explicit-off nostr.toml parses");
		assert!(off.tor_enabled_is_set());
		assert!(!off.tor_enabled());
	}
}
