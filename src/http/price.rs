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

//! GRIN price preview, cached per currency. Off by default (no pairing → no
//! fetch); only once the user opts into a pairing is the rate fetched — and it
//! goes over the Nym mixnet like everything else, never the clear net. The rate
//! barely moves and CoinGecko's free tier rate-limits frequent polling (the
//! shared exit IP all the more), so it refreshes on a slow cache, not live.

use lazy_static::lazy_static;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::AppConfig;
use crate::tor;

/// Cache refresh interval (seconds).
const REFRESH_SECS: i64 = 300;

/// Minimum delay between fetch attempts for a currency, so a failing fetch
/// (e.g. no network) does not respawn a thread every frame.
const RETRY_SECS: i64 = 30;

/// How stale a disk-cached rate may be and still be worth painting on cold start
/// (48h). Older than this and we start blank rather than show a very wrong price.
const SEED_MAX_AGE_SECS: i64 = 48 * 3600;

/// Eager-probe per-try timeout. The eager fetch on tunnel-ready doubles as the
/// end-to-end exit probe: a healthy warm fetch is ~800ms, a dead exit hangs until
/// timeout, so a short cap lets us fail fast and condemn a bad exit in seconds.
const PROBE_TIMEOUT: Duration = Duration::from_secs(12);

/// How many eager-probe fetch attempts before we conclude the (still-"ready")
/// exit is blackholing HTTP and condemn it.
const PROBE_ATTEMPTS: u32 = 3;

lazy_static! {
	/// Cached GRIN rates per `vs_currency`: code -> (rate, fetched_at).
	static ref RATES: RwLock<HashMap<String, (f64, i64)>> = RwLock::new(HashMap::new());
	/// Currencies with a fetch currently in flight.
	static ref FETCHING: RwLock<HashSet<String>> = RwLock::new(HashSet::new());
	/// Last fetch attempt per currency (unix secs).
	static ref LAST_TRY: RwLock<HashMap<String, i64>> = RwLock::new(HashMap::new());
}

fn now() -> i64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_secs() as i64)
		.unwrap_or(0)
}

/// Get the cached GRIN rate against `vs` (e.g. "usd", "eur", "btc") if fresh,
/// triggering a background refresh otherwise. Returns `None` until the first
/// successful fetch for that currency.
pub fn grin_rate(vs: &str) -> Option<f64> {
	let cached = { RATES.read().get(vs).cloned() };
	let needs_refresh = match cached {
		Some((_, ts)) => now() - ts > REFRESH_SECS,
		None => true,
	};
	if needs_refresh {
		trigger_refresh(vs.to_string());
	}
	cached.map(|(rate, _)| rate)
}

/// Spawn a background refresh for one currency (deduped per code).
fn trigger_refresh(vs: String) {
	let t = now();
	{
		let last = LAST_TRY.read().get(&vs).copied().unwrap_or(0);
		if t - last < RETRY_SECS {
			return;
		}
	}
	{
		let mut fetching = FETCHING.write();
		if fetching.contains(&vs) {
			return;
		}
		fetching.insert(vs.clone());
	}
	LAST_TRY.write().insert(vs.clone(), t);
	std::thread::spawn(move || {
		let rt = tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
			.unwrap();
		rt.block_on(async {
			if let Some(rate) = fetch_rate(&vs).await {
				record_rate(&vs, rate);
			}
		});
		FETCHING.write().remove(&vs);
	});
}

/// Record a freshly fetched rate: into the in-memory cache (with `now()`) AND to
/// disk, so the next cold start can paint it instantly (see [`seed_from_disk`]).
fn record_rate(vs: &str, rate: f64) {
	let t = now();
	RATES.write().insert(vs.to_string(), (rate, t));
	AppConfig::set_last_rate(vs, rate, t);
}

/// Seed the in-memory cache from the disk-persisted last rate, if it is fresh
/// enough (< 48h). Inserted with its ORIGINAL timestamp so it reads as stale —
/// [`grin_rate`] returns it immediately for an instant preview, yet `needs_refresh`
/// stays true so a live refresh is still kicked. Called once, early in start().
pub fn seed_from_disk() {
	if let Some((vs, rate, at)) = AppConfig::last_rate() {
		if now() - at <= SEED_MAX_AGE_SECS {
			RATES.write().entry(vs).or_insert((rate, at));
		}
	}
}

/// Kick a refresh for the current pairing's currency the moment the tunnel is
/// ready, bypassing the [`RETRY_SECS`] gate (but keeping the [`FETCHING`] dedupe).
/// It doubles as the end-to-end exit probe: if every attempt fails while the
/// tunnel still reports ready, the exit is blackholing HTTP despite passing the
/// cheap liveness probe, so we condemn it (bounded: at most one condemnation per
/// tunnel generation) rather than let it stall the wallet for minutes.
pub fn eager_refresh() {
	let vs = match AppConfig::pairing().vs_currency() {
		Some(vs) => vs.to_string(),
		// Pairing off → nothing to fetch, so no probe either (we never fetch a
		// price the user hasn't opted into). The watchdog's own signals govern.
		None => return,
	};
	{
		let mut fetching = FETCHING.write();
		if fetching.contains(&vs) {
			return;
		}
		fetching.insert(vs.clone());
	}
	LAST_TRY.write().insert(vs.clone(), now());
	let rt = tokio::runtime::Builder::new_current_thread()
		.enable_all()
		.build()
		.unwrap();
	rt.block_on(async {
		let generation = tor::tunnel_generation();
		let mut ok = false;
		for attempt in 1..=PROBE_ATTEMPTS {
			match tokio::time::timeout(PROBE_TIMEOUT, fetch_rate(&vs)).await {
				Ok(Some(rate)) => {
					record_rate(&vs, rate);
					ok = true;
					break;
				}
				_ => {
					log::warn!(
						"price: eager probe fetch {attempt}/{PROBE_ATTEMPTS} failed \
						 (vs {vs}, gen {generation})"
					);
				}
			}
		}
		// Every attempt failed AND the tunnel still claims ready on the SAME
		// generation we probed: the exit is up but blackholing our HTTP. Condemn
		// it so a fresh exit is selected in seconds, not minutes. Guarded to the
		// probed generation so a reselect that already happened is never hit.
		if !ok && tor::is_ready() && tor::tunnel_generation() == generation {
			tor::condemn_exit(generation);
		}
	});
	FETCHING.write().remove(&vs);
}

/// Fetch the GRIN/`vs` rate from CoinGecko over the Nym mixnet.
async fn fetch_rate(vs: &str) -> Option<f64> {
	let url = format!(
		"https://api.coingecko.com/api/v3/simple/price?ids=grin&vs_currencies={}",
		vs
	);
	// CoinGecko rejects requests without a User-Agent (403). A static,
	// non-identifying UA is fine over the mixnet.
	let headers = vec![("User-Agent".to_string(), "goblin-wallet".to_string())];
	let body = tor::http_request("GET", url, None, headers).await?;
	let parsed: Option<f64> = serde_json::from_str::<serde_json::Value>(&body)
		.ok()
		.and_then(|doc| doc.get("grin")?.get(vs)?.as_f64());
	if parsed.is_none() {
		log::warn!(
			"price: unexpected response from rate API: {}",
			body.chars().take(120).collect::<String>()
		);
	}
	parsed
}
