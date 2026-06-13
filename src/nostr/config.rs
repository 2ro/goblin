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
	/// Accept payments from anyone automatically (default, Cash App feel).
	Everyone,
	/// Auto-accept contacts, surface unknown senders for approval.
	Contacts,
	/// Surface every incoming payment for approval.
	Ask,
}

/// Per-wallet nostr configuration.
#[derive(Serialize, Deserialize, Clone)]
pub struct NostrConfig {
	/// Whether the nostr subsystem runs for this wallet.
	enabled: Option<bool>,
	/// Relay list override.
	relays: Option<Vec<String>>,
	/// Accept policy for incoming payments.
	accept_from: Option<AcceptPolicy>,
	/// NIP-05 identity server base URL.
	nip05_server: Option<String>,
	/// Days after which a pending outgoing payment is shown as expired.
	request_expiry_days: Option<u64>,

	/// Path of the config file, not serialized.
	#[serde(skip)]
	path: Option<PathBuf>,
}

impl Default for NostrConfig {
	fn default() -> Self {
		Self {
			enabled: None,
			relays: None,
			accept_from: None,
			nip05_server: None,
			request_expiry_days: None,
			path: None,
		}
	}
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
		self.relays
			.clone()
			.filter(|r| !r.is_empty())
			.unwrap_or_else(|| DEFAULT_RELAYS.iter().map(|s| s.to_string()).collect())
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

	pub fn request_expiry_days(&self) -> u64 {
		self.request_expiry_days.unwrap_or(7)
	}
}
