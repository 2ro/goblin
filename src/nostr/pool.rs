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
//! from the project gist over the Nym mixnet, cached on disk, with a pinned
//! copy compiled in for first-run/offline. Pool relays are gated LAZILY: a
//! NIP-11 probe (also over Nym) runs only right before a relay is actually
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

/// Per-probe cap: a dead relay must not stall the caller for the full mixnet
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
  "updated": "2026-07-02",
  "notes": "Goblin wallet relay candidate pool. Clients verify each entry locally (NIP-11 probe) before use. Requirements: max_message_length >= 131072, no payment or auth required for writes, tolerates NIP-59 backdating. The optional per-relay 'exit' is that operator's co-located scoped mixnet exit (Recipient address): a MixnetStream the wallet dials directly to reach the relay with no public DNS and no public IPR — the fast money path.",
  "min_message_length": 131072,
  "relays": [
    { "url": "wss://relay.floonet.dev", "roles": ["dm", "discovery"], "vetted": "2026-07-02", "exit": "EqbUPt7aYkar2CTmjBVnyWaKzb2WT8NdojUGXU4mrfNG.AF5YCD8hgEUqByamrPqZz72h7GE599LbqQrhaew9bBip@HfyUPUv4z8uMQoZYuZGMWf6oe2vaKBVPrfgHk6WvwFPe" },
    { "url": "wss://relay.goblin.st",    "roles": ["dm", "discovery"], "vetted": "2026-07-01", "exit": "4XPnpmFdieZBY1BM2jU9Qn915v5RGz58ywpgQhuFKBao.8NMrW1i4VaPhY6qhV7supid7P1YcWJ9mGZBKjGEuqN9U@B8bX5x5yKa7oQMCNioLS9seYwNCio3U9jYPxgCZoKjk5" },
    { "url": "wss://relay.primal.net",   "roles": ["dm"],              "vetted": "2026-07-01" },
    { "url": "wss://relay.damus.io",     "roles": ["dm"],              "vetted": "2026-07-01" },
    { "url": "wss://nos.lol",            "roles": ["dm"],              "vetted": "2026-07-01" },
    { "url": "wss://relay.0xchat.com",   "roles": ["dm"],              "vetted": "2026-07-01" },
    { "url": "wss://offchain.pub",       "roles": ["dm"],              "vetted": "2026-07-01" },
    { "url": "wss://relay.snort.social", "roles": ["dm"],              "vetted": "2026-07-01" },
    { "url": "wss://nostr.mom",          "roles": ["dm"],              "vetted": "2026-07-01" },
    { "url": "wss://nostr.oxtr.dev",     "roles": ["dm"],              "vetted": "2026-07-01" },
    { "url": "wss://relay.nostr.net",    "roles": ["dm"],              "vetted": "2026-07-01" },
    { "url": "wss://purplepag.es",           "roles": ["discovery"],   "vetted": "2026-07-01" },
    { "url": "wss://indexer.coracle.social", "roles": ["discovery"],   "vetted": "2026-07-01" }
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
	/// This relay operator's CO-LOCATED Nym exit address, when they run one (the
	/// bundled floonet-rs / floonet-strfry `exit = true` feature). It is a Nym
	/// `Recipient` (`<client>.<enc>@<gateway>`) for a SCOPED MixnetStream proxy
	/// that forwards ONLY to this relay — so the wallet can reach the relay over
	/// the mixnet WITHOUT public DNS and WITHOUT depending on a public IPR exit
	/// (the anchor; see [`crate::nym::nymproc`]). Absent → this relay is reached
	/// the old way (public-IPR smolmix + in-tunnel DoT). Carried in the pinned
	/// pool so the money-path default relay's exit bootstraps OFFLINE, before any
	/// network — breaking the chicken-and-egg of learning it over the very path
	/// it is meant to replace.
	#[serde(default)]
	pub exit: Option<String>,
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

	/// The operator's co-located Nym exit address for `url`, if the pool
	/// advertises one (url compared modulo a trailing slash). `None` → reach the
	/// relay over the public-IPR path as before. This is how the wallet learns
	/// the anchor exit for its money-path relay (see [`PoolRelay::exit`]).
	pub fn exit_for(&self, url: &str) -> Option<String> {
		let want = url.trim_end_matches('/');
		self.relays
			.iter()
			.find(|r| r.url.trim_end_matches('/') == want)
			.and_then(|r| r.exit.clone())
			.filter(|e| !e.trim().is_empty())
	}

	/// Like [`Self::exit_for`], but keyed on the HOSTNAME — the HTTP dial site
	/// ([`crate::nym::request_once`]) knows only `host`, never the relay's ws
	/// URL. HTTPS to a host whose relay advertises a co-located exit (its
	/// NIP-11 probe, in practice) rides that exit too.
	pub fn exit_for_host(&self, host: &str) -> Option<String> {
		self.relays
			.iter()
			.find(|r| {
				url::Url::parse(&r.url)
					.ok()
					.and_then(|u| u.host_str().map(|h| h.eq_ignore_ascii_case(host)))
					.unwrap_or(false)
			})
			.and_then(|r| r.exit.clone())
			.filter(|e| !e.trim().is_empty())
	}

	/// Whether ANY relay in the pool advertises a co-located exit. The cold-start
	/// sequencer ([`crate::nym::nymproc`]) reads this to decide whether to give
	/// the scoped-exit client its bandwidth-grant head start before building the
	/// public-IPR tunnel — no exit anywhere → no wait, unchanged behavior.
	pub fn has_exit(&self) -> bool {
		self.relays
			.iter()
			.any(|r| r.exit.as_deref().is_some_and(|e| !e.trim().is_empty()))
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
		// A cache written by a pre-exit build parses fine but hides the
		// scoped-exit money path (and the current primary relay) for up to
		// CACHE_MAX_AGE_SECS after an app update — relay connects then ride
		// the slow public-IPR path for days. The pinned pool is newer than
		// any exit-less file, so prefer it until the next gist refresh.
		.filter(RelayPool::has_exit)
		.unwrap_or_else(|| RelayPool::parse(PINNED_POOL).expect("pinned pool parses"))
}

/// Refresh the disk cache from the gist — over the Nym mixnet, like all other
/// HTTP — when it is absent or older than 7 days. At most one attempt per app
/// run; call only once the Nym tunnel is up.
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
		.unwrap_or(false)
		// An exit-less cache predates the current pool shape (see `load`,
		// which already ignores it) — replace it now instead of serving the
		// pinned fallback for the rest of the file's 7 days.
		&& std::fs::read_to_string(&path)
			.ok()
			.and_then(|raw| RelayPool::parse(&raw))
			.is_some_and(|p| p.has_exit());
	if fresh {
		return;
	}
	let Some(raw) = crate::nym::http_request("GET", POOL_URL.to_string(), None, vec![]).await
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

/// Lazy per-use probe: fetch the relay's NIP-11 document (HTTP over Nym,
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
		crate::nym::http_request("GET", http_url, None, headers),
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
	let mut out = vec![];
	for url in load().discovery_relays() {
		if probe(&url).await {
			out.push(url);
		}
	}
	out
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
		assert_eq!(pool.relays.len(), 13);
		let dm = pool.dm_relays();
		assert_eq!(dm.len(), 11);
		assert!(dm.iter().any(|r| r.url == "wss://relay.floonet.dev"));
		assert!(dm.iter().any(|r| r.url == "wss://relay.goblin.st"));
		assert!(dm.iter().all(|r| r.vetted.is_some()));
		let disc = pool.discovery_relays();
		// relay.floonet.dev + relay.goblin.st carry both roles; the two indexers
		// are discovery-only.
		assert_eq!(disc.len(), 4);
		assert!(disc.contains(&"wss://purplepag.es".to_string()));
		assert!(disc.contains(&"wss://indexer.coracle.social".to_string()));
	}

	#[test]
	fn exit_field_is_optional_and_looked_up_by_url() {
		// The pinned pool advertises the money-path relay's co-located scoped
		// exit (the .8 floonet-mixexit) so it bootstraps OFFLINE, before any
		// network; every other relay is exit-less (reached over the tunnel).
		let pinned = RelayPool::parse(PINNED_POOL).unwrap();
		assert!(pinned.has_exit());
		assert!(pinned.exit_for("wss://relay.goblin.st").is_some());
		assert!(pinned.exit_for("wss://nos.lol").is_none());

		// A pool that DOES advertise an exit for one relay.
		let pool = RelayPool::parse(
			r#"{"version":1,"updated":"x","min_message_length":131072,"relays":[
			  {"url":"wss://relay.goblin.st/","roles":["dm"],"exit":"aaa.bbb@ccc"},
			  {"url":"wss://nos.lol","roles":["dm"]},
			  {"url":"wss://blank.example","roles":["dm"],"exit":"  "}
			]}"#,
		)
		.unwrap();
		// Trailing-slash-insensitive lookup.
		assert_eq!(
			pool.exit_for("wss://relay.goblin.st"),
			Some("aaa.bbb@ccc".to_string())
		);
		// No exit field → None; blank exit → None (treated as unset).
		assert!(pool.exit_for("wss://nos.lol").is_none());
		assert!(pool.exit_for("wss://blank.example").is_none());
		// Unknown url → None.
		assert!(pool.exit_for("wss://unknown.example").is_none());

		// Host-keyed lookup (the HTTP dial site): same answers by hostname.
		assert_eq!(
			pool.exit_for_host("relay.goblin.st"),
			Some("aaa.bbb@ccc".to_string())
		);
		assert_eq!(
			pool.exit_for_host("RELAY.GOBLIN.ST"),
			Some("aaa.bbb@ccc".to_string())
		);
		assert!(pool.exit_for_host("nos.lol").is_none());
		assert!(pool.exit_for_host("blank.example").is_none());
		assert!(pool.exit_for_host("unknown.example").is_none());
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
		// Unknown fields (like the gist's "notes") are tolerated; a missing
		// "vetted" parses as unvetted.
		let pool = RelayPool::parse(
			r#"{"version":1,"updated":"x","notes":"n","min_message_length":131072,
			"relays":[{"url":"wss://a","roles":["dm"]}]}"#,
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
			exit: None,
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
			exit: None,
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
