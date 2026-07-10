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
	/// Cap on total stored incoming payment requests — a disk-exhaustion-DoS
	/// bound. An attacker can stream valid Invoice1 requests from fresh ephemeral
	/// keys (bypassing the per-sender limit); without a cap each ~30 KB slatepack
	/// armor row accretes until the device disk fills. A few thousand rows is
	/// already far beyond any real backlog a human will act on. When the store is
	/// full the bound is enforced by deleting TERMINAL rows (Expired/Cancelled/
	/// Declined — they will never transition again) oldest-first, and only if none
	/// can be freed does it REFUSE the new request (backpressure). A live PENDING
	/// or user-Approved request is NEVER evicted.
	pub const REQUEST_CAP: usize = 2000;

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

	/// Delete a stored payment request by rumor id.
	pub fn delete_request(&self, rumor_id: &str) {
		self.delete(&self.requests, rumor_id);
	}

	/// Delete every TERMINAL (Expired/Cancelled/Declined) request row, reclaiming
	/// the disk their ~30 KB armor holds. A terminal request will never transition
	/// again, so this never removes a live PENDING or user-Approved request.
	/// Returns the count removed. Called from the expiry sweep so freshly-expired
	/// requests are actually deleted rather than left flipped-to-`Expired` forever.
	pub fn prune_terminal_requests(&self) -> usize {
		let terminal: Vec<String> = self
			.all_requests()
			.into_iter()
			.filter(|r| request_is_terminal(r.status))
			.map(|r| r.rumor_id)
			.collect();
		let n = terminal.len();
		for id in &terminal {
			self.delete(&self.requests, id);
		}
		n
	}

	/// Store a freshly-received INCOMING payment request under the disk-DoS cap
	/// (`REQUEST_CAP`). Returns `true` if stored, `false` if refused (backpressure).
	///
	/// Never drops a legitimate PENDING request: when the store is at the cap it
	/// first deletes terminal rows (Expired/Cancelled/Declined) oldest-first to
	/// make room; only if none can be freed does it REFUSE the new request rather
	/// than evict a live one. A refused request is simply not persisted (and the
	/// caller does not mark it processed), so a later catch-up re-surfaces it once
	/// capacity frees. Used only for the ingest path — `save_request` (backup
	/// restore, status updates) stays unbounded so a user's own data is never
	/// refused.
	pub fn save_incoming_request(&self, request: &PaymentRequest) -> bool {
		let existing: Vec<(String, RequestStatus, i64)> = self
			.all_requests()
			.into_iter()
			.map(|r| (r.rumor_id, r.status, r.received_at))
			.collect();
		match plan_incoming_admission(&existing, Self::REQUEST_CAP) {
			Admission::Refuse => false,
			Admission::Store(evict) => {
				for id in &evict {
					self.delete(&self.requests, id);
				}
				self.save_request(request);
				true
			}
		}
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

/// A request in a terminal state (Expired/Cancelled/Declined) will never
/// transition again, so its row is safe to delete to reclaim disk. Pure so the
/// bounds policy is unit-testable without the rkv env.
fn request_is_terminal(status: RequestStatus) -> bool {
	matches!(
		status,
		RequestStatus::Expired | RequestStatus::Cancelled | RequestStatus::Declined
	)
}

/// Outcome of admitting a NEW incoming request under the request-store cap.
#[derive(Debug, PartialEq, Eq)]
enum Admission {
	/// Store the newcomer after deleting these terminal rows (by rumor id) to
	/// stay within the cap. Empty when there is already room.
	Store(Vec<String>),
	/// Refuse the newcomer: the store is full of live PENDING/Approved rows and
	/// no terminal row can be evicted to make space (backpressure).
	Refuse,
}

/// Pure admission policy for the request-store disk bound. `existing` is every
/// currently-stored request as `(rumor_id, status, received_at)`. Never selects a
/// Pending or Approved row for eviction — it evicts terminal rows OLDEST-first
/// (smallest `received_at`), and REFUSES the newcomer rather than dropping a live
/// one. This is the load-bearing guarantee: a legitimate pending invoice is never
/// discarded.
fn plan_incoming_admission(existing: &[(String, RequestStatus, i64)], cap: usize) -> Admission {
	if existing.len() < cap {
		return Admission::Store(Vec::new());
	}
	// Free enough terminal rows for the newcomer to fit at/under the cap.
	let need = existing.len() + 1 - cap;
	let mut evictable: Vec<(&str, i64)> = existing
		.iter()
		.filter(|(_, status, _)| request_is_terminal(*status))
		.map(|(id, _, ts)| (id.as_str(), *ts))
		.collect();
	if evictable.len() < need {
		return Admission::Refuse;
	}
	evictable.sort_by_key(|(_, ts)| *ts); // oldest received_at first
	Admission::Store(
		evictable
			.into_iter()
			.take(need)
			.map(|(id, _)| id.to_string())
			.collect(),
	)
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

	fn temp_store_tagged(tag: &str) -> NostrStore {
		let dir = std::env::temp_dir().join(format!(
			"goblin-store-test-{}-{}-{:?}",
			std::process::id(),
			tag,
			std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.map(|d| d.as_nanos())
				.unwrap_or(0)
		));
		let _ = fs::remove_dir_all(&dir);
		NostrStore::new(dir)
	}

	fn sample_meta(slate_id: &str, npub: &str) -> TxNostrMeta {
		TxNostrMeta {
			ver: 1,
			slate_id: slate_id.to_string(),
			npub: npub.to_string(),
			direction: NostrTxDirection::Sent,
			note: Some("lunch".to_string()),
			status: NostrSendStatus::Finalized,
			sent_event_id: None,
			received_rumor_id: None,
			created_at: 100,
			updated_at: 100,
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

	fn sample_contact(npub: &str) -> Contact {
		Contact {
			ver: 1,
			npub: npub.to_string(),
			petname: Some("Alice".to_string()),
			nip05: Some("alice@goblin.st".to_string()),
			nip05_verified_at: Some(100),
			relays: vec![],
			nip44_v3: false,
			hue: 0,
			unknown: false,
			added_at: 100,
			last_paid_at: Some(100),
			blocked: false,
		}
	}

	fn sample_request(rumor_id: &str, npub: &str) -> PaymentRequest {
		PaymentRequest {
			ver: 1,
			rumor_id: rumor_id.to_string(),
			slate_id: "slate-req".to_string(),
			slatepack: "BEGINSLATEPACK.END".to_string(),
			npub: npub.to_string(),
			amount: 42,
			note: None,
			received_at: 100,
			status: RequestStatus::Pending,
		}
	}

	/// After a payment-history wipe, none of the queries the activity UI reads
	/// (tx metadata, payment requests, processed markers) can resolve a
	/// counterparty for a wiped tx anymore — so no leftover name/npub is left to
	/// resolve a profile picture. Contacts are intentionally kept (the address
	/// book), which is asserted here so a future change to that is deliberate.
	#[test]
	fn wipe_archive_clears_tx_association_but_keeps_contacts() {
		let store = temp_store_tagged("wipe");
		let npub = "abc123def456";
		store.save_tx_meta(&sample_meta("slate-1", npub));
		store.save_contact(&sample_contact(npub));
		store.save_request(&sample_request("rumor-1", npub));
		store.mark_processed("slate-1:S1");

		// Pre-wipe: the tx resolves its counterparty.
		assert_eq!(store.all_tx_meta().len(), 1);
		assert!(store.tx_meta("slate-1").is_some());
		assert_eq!(store.pending_requests().len(), 1);
		assert!(store.is_processed("slate-1:S1"));

		store.wipe_archive();

		// Post-wipe: nothing the activity feed / receipt reads can join a
		// surviving grin tx row back to an npub, name, or avatar.
		assert!(store.all_tx_meta().is_empty());
		assert!(store.tx_meta("slate-1").is_none());
		assert!(store.all_requests().is_empty());
		assert!(store.pending_requests().is_empty());
		assert!(!store.is_processed("slate-1:S1"));

		// Contacts survive by design (the address book, not payment history).
		assert_eq!(store.all_contacts().len(), 1);
		assert!(store.contact(npub).is_some());
	}

	fn req_status(rumor: &str, status: RequestStatus, received_at: i64) -> PaymentRequest {
		PaymentRequest {
			ver: 1,
			rumor_id: rumor.to_string(),
			slate_id: "s".to_string(),
			slatepack: "sp".to_string(),
			npub: "np".to_string(),
			amount: 42,
			note: None,
			received_at,
			status,
		}
	}

	/// Load-bearing disk-DoS bound proof (pure policy). Filling PAST the cap with a
	/// mix of terminal and pending rows must: evict terminal rows OLDEST-first, and
	/// NEVER select a pending (or approved) row — refusing the newcomer instead.
	#[test]
	fn admission_evicts_terminal_oldest_first_and_never_drops_pending() {
		// Under cap → store with nothing evicted.
		let some = vec![
			("p1".to_string(), RequestStatus::Pending, 10),
			("e1".to_string(), RequestStatus::Expired, 5),
		];
		assert_eq!(
			plan_incoming_admission(&some, 5),
			Admission::Store(vec![]),
			"below the cap, admit without evicting anything"
		);

		// At cap with terminal rows present → evict the OLDEST terminal first.
		// received_at: e-old=1 (Expired), c-mid=2 (Cancelled), p=3/4/5 (Pending).
		let full = vec![
			("p3".to_string(), RequestStatus::Pending, 3),
			("e-old".to_string(), RequestStatus::Expired, 1),
			("p4".to_string(), RequestStatus::Pending, 4),
			("c-mid".to_string(), RequestStatus::Cancelled, 2),
			("p5".to_string(), RequestStatus::Pending, 5),
		];
		// cap 5, len 5 → need 1 freed. Oldest terminal is e-old (received_at 1).
		assert_eq!(
			plan_incoming_admission(&full, 5),
			Admission::Store(vec!["e-old".to_string()]),
			"evict the oldest terminal row, not either newer terminal nor any pending"
		);

		// Two terminal rows, need two freed → both terminal, oldest first order.
		// cap 4, len 5 → need 2. Terminals are e-old(1) then c-mid(2).
		let plan = plan_incoming_admission(&full, 4);
		assert_eq!(
			plan,
			Admission::Store(vec!["e-old".to_string(), "c-mid".to_string()]),
			"free exactly `need` terminal rows, oldest-first, never a pending"
		);

		// At cap with ONLY pending/approved rows → REFUSE (backpressure); a live
		// pending request is never dropped to admit a newcomer.
		let all_live = vec![
			("p1".to_string(), RequestStatus::Pending, 1),
			("p2".to_string(), RequestStatus::Pending, 2),
			("a1".to_string(), RequestStatus::Approved, 3),
		];
		assert_eq!(
			plan_incoming_admission(&all_live, 3),
			Admission::Refuse,
			"with no terminal rows to evict, refuse rather than drop a pending/approved"
		);

		// Enough pending but not enough terminal to cover `need` → still refuse.
		// cap 3, len 5 → need 3, but only 2 terminal exist.
		let mostly_pending = vec![
			("p1".to_string(), RequestStatus::Pending, 1),
			("p2".to_string(), RequestStatus::Pending, 2),
			("p3".to_string(), RequestStatus::Pending, 3),
			("e1".to_string(), RequestStatus::Expired, 4),
			("d1".to_string(), RequestStatus::Declined, 5),
		];
		assert_eq!(
			plan_incoming_admission(&mostly_pending, 3),
			Admission::Refuse,
			"cannot free enough terminal rows without touching a pending → refuse"
		);
	}

	/// End-to-end on the real store: terminal rows are actually DELETED (disk
	/// reclaimed) while pending rows survive, and the bounded ingest path stores
	/// under the cap.
	#[test]
	fn prune_terminal_deletes_terminal_keeps_pending() {
		let store = temp_store_tagged("prune-terminal");
		store.save_request(&req_status("pend", RequestStatus::Pending, 1));
		store.save_request(&req_status("appr", RequestStatus::Approved, 2));
		store.save_request(&req_status("exp", RequestStatus::Expired, 3));
		store.save_request(&req_status("canc", RequestStatus::Cancelled, 4));
		store.save_request(&req_status("decl", RequestStatus::Declined, 5));
		assert_eq!(store.all_requests().len(), 5);

		let removed = store.prune_terminal_requests();
		assert_eq!(removed, 3, "Expired + Cancelled + Declined are deleted");

		let remaining: Vec<RequestStatus> =
			store.all_requests().into_iter().map(|r| r.status).collect();
		assert_eq!(remaining.len(), 2, "only the two live rows survive");
		assert!(
			store.request("pend").is_some(),
			"pending must never be deleted"
		);
		assert!(store.request("appr").is_some(), "approved must be kept");
		assert!(store.request("exp").is_none());
		assert!(store.request("canc").is_none());
		assert!(store.request("decl").is_none());

		// Bounded ingest under the cap stores normally.
		assert!(store.save_incoming_request(&req_status("new", RequestStatus::Pending, 6)));
		assert!(store.request("new").is_some());
	}

	/// The real bounded ingest path at the true `REQUEST_CAP`: fill to the cap with
	/// pending rows + one terminal row, then a new incoming request evicts the
	/// terminal row (not any pending). A further incoming with the store full of
	/// pending is refused, and every pending row is still present.
	#[test]
	fn save_incoming_request_respects_cap_without_dropping_pending() {
		let store = temp_store_tagged("req-cap");
		let cap = NostrStore::REQUEST_CAP;
		// (cap - 1) pending rows + 1 terminal row = cap total.
		for i in 0..(cap - 1) {
			store.save_request(&req_status(
				&format!("p{i}"),
				RequestStatus::Pending,
				100 + i as i64,
			));
		}
		store.save_request(&req_status("terminal", RequestStatus::Expired, 1));
		assert_eq!(store.all_requests().len(), cap);

		// New incoming: evict the terminal row, store the newcomer, stay at cap.
		assert!(store.save_incoming_request(&req_status("newA", RequestStatus::Pending, 999)));
		assert!(store.request("terminal").is_none(), "terminal row evicted");
		assert!(store.request("newA").is_some(), "newcomer stored");
		assert_eq!(store.all_requests().len(), cap);
		assert_eq!(
			store.pending_requests().len(),
			cap,
			"all rows are now pending and none were dropped"
		);

		// Store now full of pending only → next incoming is refused (backpressure),
		// and NO existing pending row is dropped.
		assert!(
			!store.save_incoming_request(&req_status("newB", RequestStatus::Pending, 1000)),
			"refuse when only pending rows remain"
		);
		assert!(
			store.request("newB").is_none(),
			"refused newcomer not stored"
		);
		assert_eq!(store.all_requests().len(), cap, "no pending row evicted");
		assert!(store.request("newA").is_some());
		for i in 0..(cap - 1) {
			assert!(
				store.request(&format!("p{i}")).is_some(),
				"pending p{i} survives"
			);
		}
	}
}
