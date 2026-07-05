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

//! GRIN price preview. Off by default (no pairing → no fetch); only once the
//! user opts into a pairing is the rate fetched — and it goes over Tor like
//! everything else, never the clear net.
//!
//! The rate is fetched LIVE, on view: the fiat subline asks for the rate only
//! while the balance is actually on screen, and a fetch is kicked whenever the
//! last one aged past a short freshness window ([`FRESH_SECS`]). There is no
//! disk cache and no background timer — an idle or payment-listening wallet
//! never polls, so it costs nothing on battery. The rate lives in memory for
//! the freshness window so flipping between screens does not refetch, and a
//! fresh session starts blank and fetches on the first view.

use lazy_static::lazy_static;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::AppConfig;
use crate::tor;

/// How long an in-memory rate is considered current (seconds). Viewing the
/// balance with a rate older than this kicks a live refetch, and until a fresh
/// rate lands the stale value is NOT painted — the line shows loading, then the
/// new rate (or unavailable on failure). Short enough to track the market, long
/// enough that screen flips within the window reuse the same fetch.
const FRESH_SECS: i64 = 180;

/// Minimum delay between fetch attempts for a currency, so a failing fetch
/// (e.g. no network) does not respawn a thread every frame.
const RETRY_SECS: i64 = 30;

/// Eager-probe per-try timeout. The eager fetch on tunnel-ready doubles as the
/// end-to-end exit probe: a healthy warm fetch is ~800ms, a dead exit hangs until
/// timeout, so a short cap lets us fail fast and condemn a bad exit in seconds.
const PROBE_TIMEOUT: Duration = Duration::from_secs(12);

/// How many eager-probe fetch attempts before we conclude the (still-"ready")
/// exit is blackholing HTTP and condemn it.
const PROBE_ATTEMPTS: u32 = 3;

lazy_static! {
	/// In-session GRIN rates per `vs_currency`: code -> (rate, fetched_at). Memory
	/// only — never persisted, so a fresh session starts empty.
	static ref RATES: RwLock<HashMap<String, (f64, i64)>> = RwLock::new(HashMap::new());
	/// Currencies with a fetch currently in flight.
	static ref FETCHING: RwLock<HashSet<String>> = RwLock::new(HashSet::new());
	/// Last fetch attempt per currency (unix secs).
	static ref LAST_TRY: RwLock<HashMap<String, i64>> = RwLock::new(HashMap::new());
	/// Currencies whose most recent completed attempt failed (with no fresh rate),
	/// so the line can honestly say "unavailable" instead of spinning forever.
	static ref FAILED: RwLock<HashSet<String>> = RwLock::new(HashSet::new());
}

/// What the fiat line should render for a currency right now.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum RateState {
	/// A rate fetched within the freshness window — safe to paint as current.
	Fresh(f64),
	/// No current rate yet, but a fetch is in flight (or just kicked): show a
	/// subtle placeholder, not a stale number.
	Loading,
	/// The last fetch failed and nothing fresh is available: say so (or hide),
	/// never fall back to an old value.
	Unavailable,
}

fn now() -> i64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_secs() as i64)
		.unwrap_or(0)
}

/// True if a rate fetched at `fetched_at` is still current as of `now`.
fn is_fresh(fetched_at: i64, now: i64) -> bool {
	now - fetched_at <= FRESH_SECS
}

/// Pure state decision, factored out for testing: given the (optional) cached
/// rate and the current fetch bookkeeping, decide what to render. A cached rate
/// older than the freshness window is deliberately NOT returned as `Fresh`.
fn classify(cached: Option<(f64, i64)>, now: i64, fetching: bool, failed: bool) -> RateState {
	if let Some((rate, ts)) = cached {
		if is_fresh(ts, now) {
			return RateState::Fresh(rate);
		}
	}
	// No fresh rate. A fetch in flight (or just kicked) reads as loading; a
	// recently failed attempt with nothing fresh reads as unavailable.
	if fetching {
		RateState::Loading
	} else if failed {
		RateState::Unavailable
	} else {
		RateState::Loading
	}
}

/// Get the render state of the GRIN rate against `vs` (e.g. "usd", "eur",
/// "btc"). Called from the fiat line while the balance is on screen: if the
/// in-session rate is missing or stale it kicks a live refetch over Tor, and it
/// never reports a rate older than the freshness window as current.
pub fn grin_rate(vs: &str) -> RateState {
	let cached = { RATES.read().get(vs).cloned() };
	let fresh = cached.map(|(_, ts)| is_fresh(ts, now())).unwrap_or(false);
	if !fresh {
		trigger_refresh(vs.to_string());
	}
	classify(
		cached,
		now(),
		FETCHING.read().contains(vs),
		FAILED.read().contains(vs),
	)
}

/// Spawn a background refresh for one currency (deduped per code). Kicked only
/// from a view that is actually asking for the rate — never on a timer.
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
		let ok = rt.block_on(async {
			if let Some(rate) = fetch_rate(&vs).await {
				record_rate(&vs, rate);
				true
			} else {
				false
			}
		});
		if ok {
			FAILED.write().remove(&vs);
		} else {
			FAILED.write().insert(vs.clone());
		}
		FETCHING.write().remove(&vs);
	});
}

/// Record a freshly fetched rate into the in-memory cache (with `now()`) and
/// clear any prior failure flag. Nothing is written to disk.
fn record_rate(vs: &str, rate: f64) {
	RATES.write().insert(vs.to_string(), (rate, now()));
	FAILED.write().remove(vs);
}

/// Kick a refresh for the current pairing's currency the moment the tunnel is
/// ready, bypassing the [`RETRY_SECS`] gate (but keeping the [`FETCHING`] dedupe).
/// It doubles as the end-to-end exit probe: if every attempt fails while the
/// tunnel still reports ready, the exit is blackholing HTTP despite passing the
/// cheap liveness probe, so we condemn it (bounded: at most one condemnation per
/// tunnel generation) rather than let it stall the wallet for minutes. This is a
/// one-shot per tunnel connection, not a poll loop.
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
		if ok {
			FAILED.write().remove(&vs);
		} else {
			FAILED.write().insert(vs.clone());
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

/// Fetch the GRIN/`vs` rate from CoinGecko over Tor.
async fn fetch_rate(vs: &str) -> Option<f64> {
	let url = format!(
		"https://api.coingecko.com/api/v3/simple/price?ids=grin&vs_currencies={}",
		vs
	);
	// CoinGecko rejects requests without a User-Agent (403). A static,
	// non-identifying UA is fine over Tor.
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

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn freshness_window_is_a_few_minutes() {
		// Guards the ruling: a short window in minutes, not the old 48h cache.
		assert!(
			(120..=300).contains(&FRESH_SECS),
			"FRESH_SECS = {FRESH_SECS}"
		);
	}

	#[test]
	fn is_fresh_at_boundary() {
		let now = 1_000_000;
		assert!(is_fresh(now, now)); // just fetched
		assert!(is_fresh(now - FRESH_SECS, now)); // exactly on the edge is still fresh
		assert!(!is_fresh(now - FRESH_SECS - 1, now)); // one second past → stale
	}

	#[test]
	fn classify_fresh_rate_is_painted() {
		let now = 1_000_000;
		let cached = Some((1.23, now - 10));
		// Even mid-fetch, a fresh rate wins.
		assert_eq!(classify(cached, now, true, false), RateState::Fresh(1.23));
	}

	#[test]
	fn classify_stale_rate_never_painted_shows_loading_while_fetching() {
		let now = 1_000_000;
		let cached = Some((1.23, now - FRESH_SECS - 60));
		assert_eq!(classify(cached, now, true, false), RateState::Loading);
	}

	#[test]
	fn classify_stale_rate_after_failure_is_unavailable() {
		let now = 1_000_000;
		let cached = Some((1.23, now - FRESH_SECS - 60));
		// Not fetching, last attempt failed → honest "unavailable", not the old value.
		assert_eq!(classify(cached, now, false, true), RateState::Unavailable);
	}

	#[test]
	fn classify_missing_rate_loads_then_reports_failure() {
		let now = 1_000_000;
		// First view: nothing cached, fetch just kicked.
		assert_eq!(classify(None, now, true, false), RateState::Loading);
		// Fetch finished and failed, nothing fresh → unavailable.
		assert_eq!(classify(None, now, false, true), RateState::Unavailable);
		// Freshly triggered, not yet marked fetching or failed → still loading.
		assert_eq!(classify(None, now, false, false), RateState::Loading);
	}
}
