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

//! GRIN price preview, fetched over the Nym mixnet and cached per currency.

use lazy_static::lazy_static;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::nym;

/// Cache refresh interval (seconds).
const REFRESH_SECS: i64 = 300;

/// Minimum delay between fetch attempts for a currency, so a failing fetch
/// (e.g. the mixnet still bootstrapping) does not respawn a thread every frame.
const RETRY_SECS: i64 = 30;

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

/// Spawn a background refresh over the mixnet for one currency (deduped per code).
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
				RATES.write().insert(vs.clone(), (rate, now()));
			}
		});
		FETCHING.write().remove(&vs);
	});
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
	let body = nym::http_request("GET", url, None, headers).await?;
	let parsed: Option<f64> = serde_json::from_str::<serde_json::Value>(&body)
		.ok()
		.and_then(|doc| doc.get("grin")?.get(vs)?.as_f64());
	if parsed.is_none() {
		log::warn!(
			"price: unexpected response from rate API (mixnet exit blocked?): {}",
			body.chars().take(120).collect::<String>()
		);
	}
	parsed
}
