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

/// Cap on stored news posts (newest kept, older pruned) — the panel only ever
/// shows the latest, so this is just a small archive bound. Sized for two full
/// nine-language posts so the oldest-`created_at` variant (English is published
/// first) is not evicted before its readers see it.
const NEWS_CAP: usize = 18;

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
	/// Cached news posts by `d` tag.
	news: SingleStore<SafeModeDatabase>,
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
		let news = k.open_single("nostr_news", StoreOptions::create()).unwrap();
		Self {
			env,
			tx_meta,
			contacts,
			requests,
			processed,
			settings,
			news,
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

	/// Update the status of an existing payment request.
	pub fn update_request_status(&self, rumor_id: &str, status: RequestStatus) {
		if let Some(mut req) = self.request(rumor_id) {
			req.status = status;
			self.save_request(&req);
		}
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

	/// Unix time this identity (by pubkey hex) was last the ACTIVE, live-listening
	/// identity. Held per identity in the one shared settings store so that a
	/// switch back to a dormant identity can catch up "since it last listened"
	/// rather than "since the wallet last connected". `None` for an identity that
	/// has never been active (fresh/imported), which the catch-up handles by
	/// falling back to the wallet-wide last connection.
	pub fn last_active_at(&self, pubkey_hex: &str) -> Option<i64> {
		let env = self.env.read().unwrap_or_else(|e| e.into_inner());
		let reader = env.read().unwrap();
		let key = format!("last_active_at:{pubkey_hex}");
		if let Ok(Some(Value::I64(v))) = self.settings.get(&reader, &key) {
			return Some(v);
		}
		None
	}

	pub fn set_last_active_at(&self, pubkey_hex: &str, ts: i64) {
		let env = self.env.read().unwrap_or_else(|e| e.into_inner());
		let mut writer = env.write().unwrap();
		let key = format!("last_active_at:{pubkey_hex}");
		let _ = self.settings.put(&mut writer, &key, &Value::I64(ts));
		let _ = writer.commit();
	}

	/// Unix time of the last contact-name re-verify sweep (persisted across
	/// restarts so a fresh launch only re-sweeps if it's been a while).
	pub fn last_name_sweep_at(&self) -> Option<i64> {
		let env = self.env.read().unwrap_or_else(|e| e.into_inner());
		let reader = env.read().unwrap();
		if let Ok(Some(Value::I64(v))) = self.settings.get(&reader, "last_name_sweep_at") {
			return Some(v);
		}
		None
	}

	pub fn set_last_name_sweep_at(&self, ts: i64) {
		let env = self.env.read().unwrap_or_else(|e| e.into_inner());
		let mut writer = env.write().unwrap();
		let _ = self
			.settings
			.put(&mut writer, "last_name_sweep_at", &Value::I64(ts));
		let _ = writer.commit();
	}

	// ── news ────────────────────────────────────────────────────────────────

	pub fn all_news(&self) -> Vec<NewsItem> {
		self.all_json(&self.news)
	}

	/// The latest news post overall (newest `created_at`).
	pub fn latest_news(&self) -> Option<NewsItem> {
		self.all_news().into_iter().max_by_key(|n| n.created_at)
	}

	/// Store a news post: newest-`created_at`-per-`d` wins, capped to the newest
	/// `NEWS_CAP` entries (older pruned). Keyed by `d`, so the store holds one
	/// row per addressable post.
	pub fn save_news(&self, item: NewsItem) {
		let merged = reconcile_news(self.all_news(), item, NEWS_CAP);
		self.clear(&self.news);
		for n in &merged {
			self.put_json(&self.news, &n.d, n);
		}
	}

	// ── full-backup snapshot / merge (activity history) ─────────────────────

	/// Collect the activity metadata a full `.backup` seals: every tx meta,
	/// contact and payment request across ALL held identities. Processed markers,
	/// service settings and cached news are intentionally excluded — they are
	/// operational or relay-reproducible, not user activity a chain rescan loses.
	pub fn snapshot_archive(&self) -> ArchiveSnapshot {
		ArchiveSnapshot {
			ver: 1,
			tx_meta: self.all_tx_meta(),
			contacts: self.all_contacts(),
			requests: self.all_requests(),
		}
	}

	/// Merge a backup's activity metadata into this store WITHOUT clobbering
	/// newer local data. A tx meta is written only when the store has no row for
	/// its slate, or the backup row is newer (`updated_at`). A contact or request
	/// is written only when the store has no row for it yet, so a locally-edited
	/// petname or an already-answered request is never regressed by an older
	/// backup. Returns the number of rows written.
	pub fn merge_archive(&self, snap: &ArchiveSnapshot) -> usize {
		let mut written = 0usize;
		for meta in &snap.tx_meta {
			let keep_local = self
				.tx_meta(&meta.slate_id)
				.map(|cur| cur.updated_at >= meta.updated_at)
				.unwrap_or(false);
			if !keep_local {
				self.save_tx_meta(meta);
				written += 1;
			}
		}
		for contact in &snap.contacts {
			if self.contact(&contact.npub).is_none() {
				self.save_contact(contact);
				written += 1;
			}
		}
		for request in &snap.requests {
			if self.request(&request.rumor_id).is_none() {
				self.save_request(request);
				written += 1;
			}
		}
		written
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
}

/// Merge an incoming news post into the stored set: newest `created_at` wins
/// per `d`, then keep only the newest `cap` overall. Pure so it's unit-testable
/// without the rkv env.
fn reconcile_news(mut all: Vec<NewsItem>, incoming: NewsItem, cap: usize) -> Vec<NewsItem> {
	if let Some(existing) = all.iter_mut().find(|n| n.d == incoming.d) {
		if incoming.created_at >= existing.created_at {
			*existing = incoming;
		}
	} else {
		all.push(incoming);
	}
	all.sort_by_key(|n| std::cmp::Reverse(n.created_at));
	all.truncate(cap);
	all
}

#[cfg(test)]
mod tests {
	use super::*;

	fn item(d: &str, created_at: i64) -> NewsItem {
		item_lang(d, created_at, None)
	}

	fn item_lang(d: &str, created_at: i64, lang: Option<&str>) -> NewsItem {
		NewsItem {
			d: d.to_string(),
			created_at,
			title: format!("t{created_at}"),
			summary: String::new(),
			lang: lang.map(str::to_string),
			published_at: None,
		}
	}

	fn temp_store() -> (NostrStore, PathBuf) {
		let dir = std::env::temp_dir().join(format!(
			"goblin-store-test-{}-{}",
			std::process::id(),
			unix_time_nanos()
		));
		(NostrStore::new(dir.clone()), dir)
	}

	fn unix_time_nanos() -> u128 {
		std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_nanos())
			.unwrap_or(0)
	}

	fn tx(slate: &str, note: &str, updated_at: i64) -> TxNostrMeta {
		TxNostrMeta {
			ver: 1,
			slate_id: slate.to_string(),
			npub: "np".to_string(),
			direction: NostrTxDirection::Sent,
			note: Some(note.to_string()),
			status: NostrSendStatus::Finalized,
			sent_event_id: None,
			received_rumor_id: None,
			created_at: 0,
			updated_at,
			proof_mode: false,
			proof_order: None,
			proof_notify: None,
			proof_amount: None,
			proof_delivered: false,
			receipt_sent: false,
			recipient_pubkey: String::new(),
			proof_address: None,
		}
	}

	fn contact(npub: &str, petname: &str) -> Contact {
		Contact {
			ver: 1,
			npub: npub.to_string(),
			petname: Some(petname.to_string()),
			nip05: None,
			nip05_verified_at: None,
			relays: vec![],
			nip44_v3: false,
			hue: 0,
			unknown: false,
			added_at: 0,
			last_paid_at: None,
			blocked: false,
		}
	}

	fn request(rumor: &str) -> PaymentRequest {
		PaymentRequest {
			ver: 1,
			rumor_id: rumor.to_string(),
			slate_id: "s".to_string(),
			slatepack: "sp".to_string(),
			npub: "np".to_string(),
			amount: 42,
			note: None,
			received_at: 0,
			status: RequestStatus::Pending,
		}
	}

	#[test]
	fn snapshot_then_merge_into_empty_store_restores_activity() {
		// Seed a source store, snapshot it, then merge into a fresh empty store:
		// every tx meta, contact and request must reappear.
		let (src, src_dir) = temp_store();
		src.save_tx_meta(&tx("slate-1", "coffee", 100));
		src.save_tx_meta(&tx("slate-2", "rent", 100));
		src.save_contact(&contact("aa", "Alice"));
		src.save_request(&request("rum-1"));
		let snap = src.snapshot_archive();
		assert_eq!(snap.tx_meta.len(), 2);
		assert_eq!(snap.contacts.len(), 1);
		assert_eq!(snap.requests.len(), 1);

		let (dst, dst_dir) = temp_store();
		let written = dst.merge_archive(&snap);
		assert_eq!(written, 4);
		assert_eq!(
			dst.tx_meta("slate-1").unwrap().note.as_deref(),
			Some("coffee")
		);
		assert_eq!(
			dst.tx_meta("slate-2").unwrap().note.as_deref(),
			Some("rent")
		);
		assert_eq!(dst.contact("aa").unwrap().petname.as_deref(), Some("Alice"));
		assert!(dst.request("rum-1").is_some());

		let _ = std::fs::remove_dir_all(&src_dir);
		let _ = std::fs::remove_dir_all(&dst_dir);
	}

	#[test]
	fn merge_does_not_clobber_newer_local_rows() {
		// Local edits must win over an older backup: a newer local tx meta, a
		// locally-renamed contact, and an already-answered request are all kept.
		let (dst, dst_dir) = temp_store();
		dst.save_tx_meta(&tx("slate-1", "local-newer", 200));
		dst.save_contact(&contact("aa", "LocalName"));
		let mut answered = request("rum-1");
		answered.status = RequestStatus::Approved;
		dst.save_request(&answered);

		// Backup snapshot carries OLDER / different versions of the same rows,
		// plus a brand-new tx the local store hasn't seen.
		let snap = ArchiveSnapshot {
			ver: 1,
			tx_meta: vec![
				tx("slate-1", "backup-older", 100),
				tx("slate-2", "new-tx", 50),
			],
			contacts: vec![contact("aa", "BackupName")],
			requests: vec![request("rum-1")],
		};
		let written = dst.merge_archive(&snap);
		// Only the genuinely-new tx is written; the three colliding rows are kept.
		assert_eq!(written, 1);
		assert_eq!(
			dst.tx_meta("slate-1").unwrap().note.as_deref(),
			Some("local-newer"),
			"newer local tx meta must not be clobbered by an older backup"
		);
		assert_eq!(
			dst.contact("aa").unwrap().petname.as_deref(),
			Some("LocalName")
		);
		assert_eq!(
			dst.request("rum-1").unwrap().status,
			RequestStatus::Approved
		);
		// The new-to-us tx did land.
		assert_eq!(
			dst.tx_meta("slate-2").unwrap().note.as_deref(),
			Some("new-tx")
		);

		let _ = std::fs::remove_dir_all(&dst_dir);
	}

	#[test]
	fn newest_per_d_wins_and_cap_prunes() {
		// Same d, newer created_at replaces (and carries the newer title).
		let start = vec![item("a", 100)];
		let merged = reconcile_news(start, item("a", 200), 8);
		assert_eq!(merged.len(), 1);
		assert_eq!(merged[0].created_at, 200);
		assert_eq!(merged[0].title, "t200");

		// Same d, OLDER created_at is ignored.
		let merged = reconcile_news(merged, item("a", 150), 8);
		assert_eq!(merged.len(), 1);
		assert_eq!(merged[0].created_at, 200);

		// Distinct d accumulate, newest first, capped to `cap`.
		let mut all = vec![];
		for i in 0..10 {
			all = reconcile_news(all, item(&format!("d{i}"), i as i64), 3);
		}
		assert_eq!(all.len(), 3);
		assert_eq!(all[0].created_at, 9);
		assert_eq!(all[2].created_at, 7);
	}

	#[test]
	fn nine_language_batch_retains_english_under_news_cap() {
		// A single post now ships as nine per-`d` language variants. The
		// publisher emits English FIRST, so the untagged (lang == None) English
		// event carries the OLDEST `created_at` in the batch. Under the real
		// `NEWS_CAP` the whole batch must survive so English readers see it.
		let langs = ["es", "fr", "de", "it", "pt", "ja", "zh", "ko"];
		let mut all = vec![];
		// English published first → oldest created_at, no lang tag.
		all = reconcile_news(all, item_lang("post-en", 100, None), NEWS_CAP);
		for (i, code) in langs.iter().enumerate() {
			all = reconcile_news(
				all,
				item_lang(&format!("post-{code}"), 101 + i as i64, Some(code)),
				NEWS_CAP,
			);
		}
		assert_eq!(all.len(), 9);
		assert!(
			all.iter().any(|n| n.d == "post-en" && n.lang.is_none()),
			"untagged English variant must survive the cap"
		);
	}
}
