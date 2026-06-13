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

//! Per-wallet nostr metadata archive: tx metadata, contacts, payment requests
//! and processed-event markers. rkv (SafeMode) storage under the wallet data
//! directory — the user-controlled local archive.

use rkv::backend::{SafeMode, SafeModeDatabase, SafeModeEnvironment};
use rkv::{Manager, Rkv, SingleStore, StoreOptions, Value};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};

use crate::nostr::types::*;

/// Keys are processed-event markers older than this get pruned (30 days).
const PROCESSED_TTL_SECS: i64 = 30 * 86_400;

/// Nostr metadata archive for a wallet.
pub struct NostrStore {
	env: Arc<RwLock<Rkv<SafeModeEnvironment>>>,
	/// Tx metadata by slate uuid.
	tx_meta: SingleStore<SafeModeDatabase>,
	/// Contacts by pubkey hex.
	contacts: SingleStore<SafeModeDatabase>,
	/// Payment requests by rumor id hex.
	requests: SingleStore<SafeModeDatabase>,
	/// Processed markers (event/rumor ids and slate states) to timestamps.
	processed: SingleStore<SafeModeDatabase>,
	/// Service settings (last connected time etc).
	settings: SingleStore<SafeModeDatabase>,
}

impl NostrStore {
	/// Open or create the archive in the provided directory.
	pub fn new(dir: PathBuf) -> Self {
		let _ = fs::create_dir_all(&dir);
		let mut manager = Manager::<SafeModeEnvironment>::singleton().write().unwrap();
		// Open with headroom above the 5 stores below: rkv's SafeMode checks
		// capacity before existence, so reopening an env that already holds
		// `DEFAULT_MAX_DBS` (5) named dbs fails with DbsFull.
		let created_arc = manager
			.get_or_create(dir.as_path(), |p: &std::path::Path| {
				Rkv::with_capacity::<SafeMode>(p, 16)
			})
			.unwrap();
		let env = created_arc.clone();
		let k = created_arc.read().unwrap();

		let tx_meta = k
			.open_single("nostr_tx_meta", StoreOptions::create())
			.unwrap();
		let contacts = k
			.open_single("nostr_contacts", StoreOptions::create())
			.unwrap();
		let requests = k
			.open_single("nostr_requests", StoreOptions::create())
			.unwrap();
		let processed = k
			.open_single("nostr_processed", StoreOptions::create())
			.unwrap();
		let settings = k
			.open_single("nostr_settings", StoreOptions::create())
			.unwrap();
		Self {
			env,
			tx_meta,
			contacts,
			requests,
			processed,
			settings,
		}
	}

	fn get_json<T: DeserializeOwned>(
		&self,
		store: &SingleStore<SafeModeDatabase>,
		key: &str,
	) -> Option<T> {
		let env = self.env.read().unwrap_or_else(|e| e.into_inner());
		let reader = env.read().unwrap();
		if let Ok(Some(Value::Json(raw))) = store.get(&reader, key) {
			return serde_json::from_str(raw).ok();
		}
		None
	}

	fn put_json<T: Serialize>(&self, store: &SingleStore<SafeModeDatabase>, key: &str, value: &T) {
		if let Ok(raw) = serde_json::to_string(value) {
			let env = self.env.read().unwrap_or_else(|e| e.into_inner());
			let mut writer = env.write().unwrap();
			let _ = store.put(&mut writer, key, &Value::Json(&raw));
			let _ = writer.commit();
		}
	}

	fn delete(&self, store: &SingleStore<SafeModeDatabase>, key: &str) {
		let env = self.env.read().unwrap_or_else(|e| e.into_inner());
		let mut writer = env.write().unwrap();
		let _ = store.delete(&mut writer, key);
		let _ = writer.commit();
	}

	fn all_json<T: DeserializeOwned>(&self, store: &SingleStore<SafeModeDatabase>) -> Vec<T> {
		let env = self.env.read().unwrap_or_else(|e| e.into_inner());
		let reader = env.read().unwrap();
		let mut out = vec![];
		if let Ok(iter) = store.iter_start(&reader) {
			for item in iter.flatten() {
				if let (_, Value::Json(raw)) = item {
					if let Ok(v) = serde_json::from_str(raw) {
						out.push(v);
					}
				}
			}
		}
		out
	}

	fn clear(&self, store: &SingleStore<SafeModeDatabase>) {
		let env = self.env.read().unwrap_or_else(|e| e.into_inner());
		let mut writer = env.write().unwrap();
		let _ = store.clear(&mut writer);
		let _ = writer.commit();
	}

	// ── tx metadata ─────────────────────────────────────────────────────────

	pub fn tx_meta(&self, slate_id: &str) -> Option<TxNostrMeta> {
		self.get_json(&self.tx_meta, slate_id)
	}

	pub fn save_tx_meta(&self, meta: &TxNostrMeta) {
		self.put_json(&self.tx_meta, &meta.slate_id, meta);
	}

	pub fn all_tx_meta(&self) -> Vec<TxNostrMeta> {
		self.all_json(&self.tx_meta)
	}

	/// Update status of existing tx metadata.
	pub fn update_tx_status(&self, slate_id: &str, status: NostrSendStatus) {
		if let Some(mut meta) = self.tx_meta(slate_id) {
			meta.status = status;
			meta.updated_at = unix_time();
			self.save_tx_meta(&meta);
		}
	}

	// ── contacts ────────────────────────────────────────────────────────────

	pub fn contact(&self, npub_hex: &str) -> Option<Contact> {
		self.get_json(&self.contacts, npub_hex)
	}

	pub fn save_contact(&self, contact: &Contact) {
		self.put_json(&self.contacts, &contact.npub, contact);
	}

	pub fn delete_contact(&self, npub_hex: &str) {
		self.delete(&self.contacts, npub_hex);
	}

	pub fn all_contacts(&self) -> Vec<Contact> {
		self.all_json(&self.contacts)
	}

	// ── payment requests ────────────────────────────────────────────────────

	pub fn request(&self, rumor_id: &str) -> Option<PaymentRequest> {
		self.get_json(&self.requests, rumor_id)
	}

	pub fn save_request(&self, request: &PaymentRequest) {
		self.put_json(&self.requests, &request.rumor_id, request);
	}

	pub fn all_requests(&self) -> Vec<PaymentRequest> {
		self.all_json(&self.requests)
	}

	pub fn pending_requests(&self) -> Vec<PaymentRequest> {
		let mut reqs: Vec<PaymentRequest> = self
			.all_requests()
			.into_iter()
			.filter(|r| r.status == RequestStatus::Pending)
			.collect();
		reqs.sort_by_key(|r| std::cmp::Reverse(r.received_at));
		reqs
	}

	// ── processed markers ───────────────────────────────────────────────────

	pub fn is_processed(&self, key: &str) -> bool {
		let env = self.env.read().unwrap_or_else(|e| e.into_inner());
		let reader = env.read().unwrap();
		matches!(self.processed.get(&reader, key), Ok(Some(_)))
	}

	pub fn mark_processed(&self, key: &str) {
		let env = self.env.read().unwrap_or_else(|e| e.into_inner());
		let mut writer = env.write().unwrap();
		let _ = self
			.processed
			.put(&mut writer, key, &Value::I64(unix_time()));
		let _ = writer.commit();
	}

	/// Remove processed markers older than the TTL.
	pub fn prune_processed(&self) {
		let cutoff = unix_time() - PROCESSED_TTL_SECS;
		let stale: Vec<String> = {
			let env = self.env.read().unwrap_or_else(|e| e.into_inner());
			let reader = env.read().unwrap();
			let mut stale = vec![];
			if let Ok(iter) = self.processed.iter_start(&reader) {
				for item in iter.flatten() {
					if let (key, Value::I64(ts)) = item {
						if ts < cutoff {
							if let Ok(k) = std::str::from_utf8(key) {
								stale.push(k.to_string());
							}
						}
					}
				}
			}
			stale
		};
		for key in stale {
			self.delete(&self.processed, &key);
		}
	}

	// ── settings ────────────────────────────────────────────────────────────

	pub fn last_connected_at(&self) -> Option<i64> {
		let env = self.env.read().unwrap_or_else(|e| e.into_inner());
		let reader = env.read().unwrap();
		if let Ok(Some(Value::I64(v))) = self.settings.get(&reader, "last_connected_at") {
			return Some(v);
		}
		None
	}

	pub fn set_last_connected_at(&self, ts: i64) {
		let env = self.env.read().unwrap_or_else(|e| e.into_inner());
		let mut writer = env.write().unwrap();
		let _ = self
			.settings
			.put(&mut writer, "last_connected_at", &Value::I64(ts));
		let _ = writer.commit();
	}

	// ── archive control (user-facing) ───────────────────────────────────────

	/// Export the whole archive as a JSON document.
	pub fn export_json(&self, npub: &str) -> String {
		let doc = serde_json::json!({
			"exported_at": unix_time(),
			"npub": npub,
			"contacts": self.all_contacts(),
			"tx_meta": self.all_tx_meta(),
			"requests": self.all_requests(),
		});
		serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string())
	}

	/// Wipe payment history metadata (keeps contacts).
	pub fn wipe_archive(&self) {
		self.clear(&self.tx_meta);
		self.clear(&self.requests);
		self.clear(&self.processed);
	}

	/// Wipe everything including contacts.
	pub fn wipe_all(&self) {
		self.wipe_archive();
		self.clear(&self.contacts);
		self.clear(&self.settings);
	}
}
