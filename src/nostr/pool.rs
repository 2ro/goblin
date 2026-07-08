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

//! Relay candidate pool: a maintained list of vetted public relays fetched
//! from the project gist over Tor, cached on disk, with a pinned
//! copy compiled in for first-run/offline. Pool relays are gated LAZILY: a
//! NIP-11 probe (also over Tor) runs only right before a relay is actually
//! used — no background sweeps.

use lazy_static::lazy_static;
use log::{info, warn};
use parking_lot::RwLock;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::Settings;
use crate::nostr::types::unix_time;

/// Raw gist URL serving the maintained candidate pool (schema v1). Fetched
/// UNSIGNED: authenticity rests on the gist account's public edit history.
/// TODO(signing): verify a maintainer signature (minisign or a signed nostr
/// event) before trusting a fetched pool.
const POOL_URL: &str = "https://gist.githubusercontent.com/2ro/79cd885540c88d074fe52f8388a3e5b4/raw/goblin-relay-pool.json";

/// Pool cache file name inside the app base dir (`~/.goblin`).
const CACHE_FILE: &str = "relay-pool.json";

/// Refresh the disk cache on start when older than this (7 days).
const CACHE_MAX_AGE_SECS: u64 = 7 * 86_400;

/// NIP-11 probe results are reused for this long (24 h, in memory).
const PROBE_TTL_SECS: i64 = 24 * 3600;

/// Per-probe cap: a dead relay must not stall the caller for the full Tor
/// HTTP timeout — a failed probe just skips the relay this time.
const PROBE_TIMEOUT: Duration = Duration::from_secs(12);

/// Gift-wrap size floor: a worst-case Goblin payment (30 KB slatepack) is a
/// ~66 KB event on the wire, so a DM relay must accept at least 128 KiB
/// messages for 2x headroom. The gist can only RAISE this, never lower it.
pub const MIN_MESSAGE_LENGTH: u64 = 131_072;

/// NIP-59 backdates wrap timestamps up to 2 days; a relay whose
/// `created_at_lower_limit` is tighter than this rejects our wraps.
const MIN_BACKDATE_SECS: u64 = 172_800;

/// Pinned fallback pool, byte-for-byte the gist contents, so first-run and
/// offline behave exactly like a fresh fetch.
const PINNED_POOL: &str = r#"{
  "version": 1,
  "updated": "2026-07-04",
  "notes": "Goblin wallet relay candidate pool. Clients verify each entry locally (NIP-11 probe) before use. Requirements: max_message_length >= 131072, no payment or auth required for writes, tolerates NIP-59 backdating. Every relay is reached over a Tor exit to its clearnet host, so the wallet's IP stays hidden behind Tor.",
  "min_message_length": 131072,
  "relays": [
    { "url": "wss://relay.floonet.dev", "roles": ["dm", "discovery"], "vetted": "2026-07-04" },
    { "url": "wss://relay.0xchat.com",  "roles": ["dm", "discovery"], "vetted": "2026-07-04" },
    { "url": "wss://offchain.pub",      "roles": ["dm"],              "vetted": "2026-07-04" }
  ]
}"#;

/// One pool entry.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PoolRelay {
	pub url: String,
	/// Roles: "dm" (gift-wrap inbox duty) and/or "discovery" (indexer for the
	/// replaceable identity events 0/10002/10050 — never a wrap target).
	pub roles: Vec<String>,
	/// Last-vetted date; presence marks the entry as vetted.
	#[serde(default)]
	pub vetted: Option<String>,
}

impl PoolRelay {
	fn has_role(&self, role: &str) -> bool {
		self.roles.iter().any(|r| r == role)
	}
}

/// The candidate pool (gist schema v1).
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RelayPool {
	pub version: u32,
	pub updated: String,
	pub min_message_length: u64,
	pub relays: Vec<PoolRelay>,
}

impl RelayPool {
	/// Parse and validate a pool document; `None` for anything unusable so the
	/// caller falls back rather than trusting a broken or hostile file.
	pub fn parse(raw: &str) -> Option<RelayPool> {
		let pool: RelayPool = serde_json::from_str(raw).ok()?;
		// Bound the probe/cache work a fetched file can demand.
		if pool.version != 1 || pool.relays.is_empty() || pool.relays.len() > 64 {
			return None;
		}
		Some(pool)
	}

	/// Entries carrying the "dm" role.
	pub fn dm_relays(&self) -> Vec<PoolRelay> {
		self.relays
			.iter()
			.filter(|r| r.has_role("dm"))
			.cloned()
			.collect()
	}

	/// Urls of entries carrying the "discovery" role.
	pub fn discovery_relays(&self) -> Vec<String> {
		self.relays
			.iter()
			.filter(|r| r.has_role("discovery"))
			.map(|r| r.url.clone())
			.collect()
	}
}

/// Disk path of the cached pool file.
fn cache_path() -> PathBuf {
	Settings::config_path(CACHE_FILE, None)
}

/// Current pool: the disk cache when present and valid, the pinned copy
/// otherwise.
pub fn load() -> RelayPool {
	std::fs::read_to_string(cache_path())
		.ok()
		.and_then(|raw| RelayPool::parse(&raw))
		.unwrap_or_else(|| RelayPool::parse(PINNED_POOL).expect("pinned pool parses"))
}

/// Refresh the disk cache from the gist — over Tor, like all other
/// HTTP — when it is absent or older than 7 days. At most one attempt per app
/// run; call only once Tor is up.
pub async fn refresh_if_stale() {
	static TRIED: AtomicBool = AtomicBool::new(false);
	if TRIED.swap(true, Ordering::SeqCst) {
		return;
	}
	let path = cache_path();
	let fresh = std::fs::metadata(&path)
		.ok()
		.and_then(|m| m.modified().ok())
		.and_then(|t| t.elapsed().ok())
		.map(|age| age.as_secs() < CACHE_MAX_AGE_SECS)
		.unwrap_or(false);
	if fresh {
		return;
	}
	let Some(raw) = crate::tor::http_request("GET", POOL_URL.to_string(), None, vec![]).await
	else {
		warn!("relay pool: refresh fetch failed, keeping current pool");
		return;
	};
	match RelayPool::parse(&raw) {
		Some(pool) => {
			if let Err(e) = std::fs::write(&path, &raw) {
				warn!("relay pool: cache write failed: {e}");
			} else {
				info!(
					"relay pool: refreshed (v{}, {} relays, updated {})",
					pool.version,
					pool.relays.len(),
					pool.updated
				);
			}
		}
		None => warn!("relay pool: fetched file failed validation, keeping current pool"),
	}
}

lazy_static! {
	/// Probe cache: url → (passed, checked_at unix secs).
	static ref PROBES: RwLock<HashMap<String, (bool, i64)>> = RwLock::new(HashMap::new());
}

/// The NIP-11 gate: a pool relay is usable only when its info document does
/// not advertise a constraint that breaks gift-wrapped payments. Absent
/// fields pass (most relays publish sparse documents); `min_len` is the
/// message-size floor.
fn nip11_pass(doc: &serde_json::Value, min_len: u64) -> bool {
	let lim = doc.get("limitation");
	let field = |k: &str| lim.and_then(|l| l.get(k));
	let off = |k: &str| !field(k).and_then(|v| v.as_bool()).unwrap_or(false);
	// Our worst-case wrap must fit.
	field("max_message_length")
		.and_then(|v| v.as_u64())
		.map(|n| n >= min_len)
		.unwrap_or(true)
		// Free, open writes; phase 1 speaks no NIP-42 AUTH.
		&& off("payment_required")
		&& off("restricted_writes")
		&& off("auth_required")
		// Must admit NIP-59's up-to-2-day backdated timestamps.
		&& field("created_at_lower_limit")
			.and_then(|v| v.as_u64())
			.map(|n| n >= MIN_BACKDATE_SECS)
			.unwrap_or(true)
}

/// Lazy per-use probe: fetch the relay's NIP-11 document (HTTP over Tor,
/// `Accept: application/nostr+json`) and apply the gate. Results are cached
/// for 24 h; an unreachable or unparseable document fails, which just skips
/// the relay this time.
pub async fn probe(url: &str) -> bool {
	let now = unix_time();
	if let Some(&(ok, at)) = PROBES.read().get(url)
		&& now - at < PROBE_TTL_SECS
	{
		return ok;
	}
	let http_url = url
		.replacen("wss://", "https://", 1)
		.replacen("ws://", "http://", 1);
	let min_len = load().min_message_length.max(MIN_MESSAGE_LENGTH);
	let headers = vec![("Accept".to_string(), "application/nostr+json".to_string())];
	let ok = tokio::time::timeout(
		PROBE_TIMEOUT,
		crate::tor::http_request("GET", http_url, None, headers),
	)
	.await
	.ok()
	.flatten()
	.and_then(|body| serde_json::from_str::<serde_json::Value>(&body).ok())
	.map(|doc| nip11_pass(&doc, min_len))
	.unwrap_or(false);
	if !ok {
		info!("relay pool: NIP-11 gate failed for {url}, skipping");
	}
	PROBES.write().insert(url.to_string(), (ok, now));
	ok
}

/// The pool's "discovery" relays that pass the lazy NIP-11 gate right now.
pub async fn usable_discovery_relays() -> Vec<String> {
	// Probe every candidate CONCURRENTLY (each is a NIP-11 HTTP round trip over
	// Tor — sequentially this cost ~N × a full round trip). The PROBES
	// cache is RwLock-safe under concurrent access. Zip the pass/fail results back
	// to the urls and keep the passing ones in the original pool order.
	let urls = load().discovery_relays();
	let results = futures::future::join_all(urls.iter().map(|url| probe(url))).await;
	urls.into_iter()
		.zip(results)
		.filter_map(|(url, ok)| ok.then_some(url))
		.collect()
}

/// Weighted-random candidate ORDER for the advertised set: the Goblin relay
/// first, then every "dm" candidate exactly once, drawn without replacement
/// with vetted entries weighted 3:1. The caller walks the order and keeps the
/// first candidates that pass the NIP-11 gate, so only relays about to be
/// used are probed. `pick` receives the remaining total weight and returns a
/// roll below it (injectable for tests).
pub fn weighted_order(
	goblin_relay: &str,
	candidates: &[PoolRelay],
	mut pick: impl FnMut(u64) -> u64,
) -> Vec<String> {
	let goblin = goblin_relay.trim_end_matches('/').to_string();
	let mut out = vec![goblin.clone()];
	let mut pool: Vec<(&PoolRelay, u64)> = candidates
		.iter()
		.filter(|r| r.url.trim_end_matches('/') != goblin)
		.map(|r| (r, if r.vetted.is_some() { 3 } else { 1 }))
		.collect();
	while !pool.is_empty() {
		let total: u64 = pool.iter().map(|(_, w)| w).sum();
		let mut roll = pick(total) % total.max(1);
		let idx = pool
			.iter()
			.position(|(_, w)| {
				if roll < *w {
					true
				} else {
					roll -= w;
					false
				}
			})
			.unwrap_or(0);
		out.push(pool.remove(idx).0.url.clone());
	}
	out
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn pinned_pool_parses() {
		let pool = RelayPool::parse(PINNED_POOL).expect("pinned pool must parse");
		assert_eq!(pool.version, 1);
		assert_eq!(pool.min_message_length, MIN_MESSAGE_LENGTH);
		// Three Tor-friendly relays matching the live gist; no relay pins an onion
		// any more (the onion money path was dropped in build134 — every relay is
		// reached over a Tor exit to its clearnet host).
		assert_eq!(pool.relays.len(), 3);
		let dm = pool.dm_relays();
		assert_eq!(dm.len(), 3);
		assert!(dm.iter().any(|r| r.url == "wss://relay.floonet.dev"));
		assert!(dm.iter().all(|r| r.vetted.is_some()));
		let disc = pool.discovery_relays();
		// relay.floonet.dev and relay.0xchat.com carry the discovery role too.
		assert_eq!(disc.len(), 2);
		assert!(disc.contains(&"wss://relay.floonet.dev".to_string()));
		assert!(disc.contains(&"wss://relay.0xchat.com".to_string()));
	}

	#[test]
	fn pool_validation_rejects_bad_documents() {
		assert!(RelayPool::parse("not json").is_none());
		assert!(RelayPool::parse("{}").is_none());
		// Wrong schema version.
		assert!(
			RelayPool::parse(
				r#"{"version":2,"updated":"x","min_message_length":1,
				"relays":[{"url":"wss://a","roles":["dm"]}]}"#
			)
			.is_none()
		);
		// Empty relay list.
		assert!(
			RelayPool::parse(r#"{"version":1,"updated":"x","min_message_length":1,"relays":[]}"#)
				.is_none()
		);
		// Unknown fields (the gist's "notes", or a stray per-relay "exit" left
		// over from the retired co-located-exit schema) are tolerated; a missing
		// "vetted" parses as unvetted.
		let pool = RelayPool::parse(
			r#"{"version":1,"updated":"x","notes":"n","min_message_length":131072,
			"relays":[{"url":"wss://a","roles":["dm"],"exit":"aaa.bbb@ccc"}]}"#,
		)
		.unwrap();
		assert!(pool.relays[0].vetted.is_none());
	}

	fn doc(limitation: &str) -> serde_json::Value {
		serde_json::from_str(&format!(r#"{{"name":"r","limitation":{limitation}}}"#)).unwrap()
	}

	#[test]
	fn nip11_gate_predicate() {
		let min = MIN_MESSAGE_LENGTH;
		// Sparse documents pass: absent limitation and absent fields.
		assert!(nip11_pass(&serde_json::json!({}), min));
		assert!(nip11_pass(&doc("{}"), min));
		// Size floor.
		assert!(nip11_pass(&doc(r#"{"max_message_length":131072}"#), min));
		assert!(nip11_pass(&doc(r#"{"max_message_length":1000000}"#), min));
		assert!(!nip11_pass(&doc(r#"{"max_message_length":65535}"#), min));
		// Paid / restricted / AUTH-gated relays fail; explicit false passes.
		assert!(!nip11_pass(&doc(r#"{"payment_required":true}"#), min));
		assert!(!nip11_pass(&doc(r#"{"restricted_writes":true}"#), min));
		assert!(!nip11_pass(&doc(r#"{"auth_required":true}"#), min));
		assert!(nip11_pass(
			&doc(r#"{"payment_required":false,"auth_required":false}"#),
			min
		));
		// created_at window must admit 2-day backdating.
		assert!(nip11_pass(
			&doc(r#"{"created_at_lower_limit":94608000}"#),
			min
		));
		assert!(!nip11_pass(&doc(r#"{"created_at_lower_limit":3600}"#), min));
		// One bad field fails the whole gate.
		assert!(!nip11_pass(
			&doc(r#"{"max_message_length":1000000,"payment_required":true}"#),
			min
		));
	}

	fn candidates() -> Vec<PoolRelay> {
		let mk = |url: &str, vetted: bool| PoolRelay {
			url: url.to_string(),
			roles: vec!["dm".to_string()],
			vetted: vetted.then(|| "2026-07-01".to_string()),
		};
		vec![
			mk("wss://a.example", false),
			mk("wss://b.example", true),
			mk("wss://c.example", true),
		]
	}

	#[test]
	fn weighted_order_selection() {
		// Goblin relay always first; every candidate appears exactly once.
		let order = weighted_order("wss://relay.goblin.st", &candidates(), |_| 0);
		assert_eq!(order[0], "wss://relay.goblin.st");
		assert_eq!(order.len(), 4);
		for url in ["wss://a.example", "wss://b.example", "wss://c.example"] {
			assert_eq!(order.iter().filter(|u| *u == url).count(), 1);
		}

		// The goblin relay is never duplicated when it is also a pool entry.
		let mut with_goblin = candidates();
		with_goblin.push(PoolRelay {
			url: "wss://relay.goblin.st".to_string(),
			roles: vec!["dm".to_string()],
			vetted: Some("2026-07-01".to_string()),
		});
		let order = weighted_order("wss://relay.goblin.st", &with_goblin, |_| 0);
		assert_eq!(order.len(), 4);
		assert_eq!(
			order
				.iter()
				.filter(|u| *u == "wss://relay.goblin.st")
				.count(),
			1
		);

		// Weights: [a:1, b:3, c:3]. A roll of 0 lands on a (first weight
		// bracket); a roll of 1 skips a's single unit and lands on vetted b.
		let order = weighted_order("wss://g", &candidates(), |_| 1);
		assert_eq!(order[1], "wss://b.example");
		// Total weight offered to the first draw is 1 + 3 + 3 = 7.
		let mut seen_total = 0;
		let _ = weighted_order("wss://g", &candidates(), |total| {
			if seen_total == 0 {
				seen_total = total;
			}
			0
		});
		assert_eq!(seen_total, 7);
	}
}
