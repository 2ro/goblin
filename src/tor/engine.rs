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

//! Embedded Tor (arti) client — the DIALING half only. Copied from our sister
//! wallet GRIM's proven, shipping engine (`grim/src/tor/`), stripped to what
//! Goblin needs: connect OUT to the relay's `.onion` (and to clearnet HTTP hosts
//! through a Tor exit). Goblin never HOSTS an onion service (GRIM's receiving
//! half), so the onion-service hosting, keystore-seeding and reverse-proxy code
//! is dropped.
//!
//! Two technical choices are inherited VERBATIM from GRIM because it already paid
//! for them: **arti 0.43** across the arti family, and the **native-tls Tor
//! runtime** ([`TokioNativeTlsRuntime`]) — deliberately NOT rustls, so arti's TLS
//! stays on native-tls and never touches the rustls/ring provider our relay and
//! HTTP TLS install.
//!
//! The arti client runs on its OWN dedicated tokio runtime (created once, kept
//! alive for the process). `TorClient::connect()` returns a [`DataStream`] that
//! is `AsyncRead + AsyncWrite`; that byte source is handed to the websocket layer
//! ([`super::transport`]) and the HTTP layer ([`super`]), each driven by their
//! own caller runtime — a `DataStream` is runtime-agnostic once the client's
//! circuit tasks are running on the arti runtime.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use std::{fs, thread};

use arti_client::config::TorClientConfigBuilder;
use arti_client::{DataStream, TorClient, TorClientConfig};
use lazy_static::lazy_static;
use log::{error, info, warn};
use parking_lot::RwLock;
use tor_rtcompat::SpawnExt;
use tor_rtcompat::tokio::TokioNativeTlsRuntime;

/// The Tor runtime type — native-tls, matching GRIM (never rustls).
type Runtime = TokioNativeTlsRuntime;
/// The concrete arti client type.
pub type Client = TorClient<Runtime>;

/// How long a single cold Tor bootstrap may take before we declare it failed and
/// let a later `warm_up()`/`wait_ready()` retry. A cold bootstrap with no cached
/// consensus can take tens of seconds; a warm one (cached dir) is a few.
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(90);

lazy_static! {
	/// Process-lifetime Tor state. The dedicated arti runtime lives here so its
	/// worker threads (which drive every circuit) persist for the whole process.
	static ref TOR: Tor = Tor::new();
}

struct Tor {
	/// The dedicated arti runtime (native-tls). All arti tasks run on this.
	runtime: Runtime,
	/// The bootstrapped client, once it is up.
	client: RwLock<Option<Arc<Client>>>,
	/// Guards the background bootstrap so `warm_up()` is idempotent.
	launching: AtomicBool,
}

impl Tor {
	fn new() -> Self {
		Self {
			runtime: TokioNativeTlsRuntime::create().expect("create tor runtime"),
			client: RwLock::new(None),
			launching: AtomicBool::new(false),
		}
	}
}

// --- Readiness signals ---------------------------------------------------------

/// Set once arti has bootstrapped (mirrors `TUNNEL_GEN != 0`); cheap to poll.
static READY: AtomicBool = AtomicBool::new(false);

/// Monotonic "transport generation". With Tor there is no exit-reselect churn —
/// arti rebuilds circuits transparently under the `DataStream` — so this simply
/// becomes 1 once bootstrapped and stays there. The relay-gated readiness logic
/// still works this way: a relay-liveness report tagged with an older
/// generation can never mark a newer transport ready.
static TUNNEL_GEN: AtomicU64 = AtomicU64::new(0);

/// The generation on which the nostr client currently has a relay connected AND
/// subscribed, or 0 for "no relay live". A single atomic so [`transport_ready`]
/// can compare it to `TUNNEL_GEN` in one shot.
static RELAY_LIVE_GEN: AtomicU64 = AtomicU64::new(0);

/// Whether a nostr consumer currently wants relays over Tor. The UI/service
/// bracket it; Tor needs no exit-health governance, so it is otherwise inert.
static RELAY_CONSUMER: AtomicBool = AtomicBool::new(false);

/// Pre-warm the embedded Tor client in the background so relays / NIP-05 / price
/// are ready by first use. Idempotent — a call while a bootstrap is in flight, or
/// once one has succeeded, is a no-op.
pub fn warm_up() {
	if TOR.client.read().is_some() {
		return;
	}
	if TOR.launching.swap(true, Ordering::SeqCst) {
		return;
	}
	thread::spawn(|| {
		bootstrap_once();
		TOR.launching.store(false, Ordering::SeqCst);
	});
}

/// Whether the embedded Tor client has bootstrapped. Cheap and cached — safe to
/// poll from the UI each frame. Distinct from a relay being connected (see
/// [`transport_ready`]): Tor can be up while no relay yet rides it.
pub fn is_ready() -> bool {
	READY.load(Ordering::Relaxed)
}

/// The current transport generation. The nostr client reads this right before it
/// dials so it can tag its relay-liveness reports.
pub fn tunnel_generation() -> u64 {
	TUNNEL_GEN.load(Ordering::Acquire)
}

/// Relay-gated readiness — the AUTHORITATIVE "ready to receive/send over Tor"
/// signal, distinct from the bootstrap-only [`is_ready`]. True only when Tor is
/// bootstrapped AND a required relay is connected+subscribed on the CURRENT
/// generation, so the UI never shows a false "Connected".
pub fn transport_ready() -> bool {
	let generation = TUNNEL_GEN.load(Ordering::Acquire);
	generation != 0 && RELAY_LIVE_GEN.load(Ordering::Acquire) == generation && is_ready()
}

/// Client → transport report: a relay is connected+subscribed on `generation`.
/// `fetch_max` so a late report for an older generation can never move liveness
/// backwards over a newer one.
pub fn report_relay_live(generation: u64) {
	RELAY_LIVE_GEN.fetch_max(generation, Ordering::AcqRel);
}

/// Client → transport report: no relay is currently live on `generation`. Clears
/// liveness only when `generation` is still the live one.
pub fn report_relay_down(generation: u64) {
	let _ = RELAY_LIVE_GEN.compare_exchange(generation, 0, Ordering::AcqRel, Ordering::Acquire);
}

/// Bracket a nostr consumer's lifetime. Inert for Tor — arti manages its own
/// circuit health — but kept so the service's existing calls compile unchanged.
pub fn set_relay_consumer(active: bool) {
	RELAY_CONSUMER.store(active, Ordering::Release);
}

/// External condemnation request (kept for API parity with earlier transports).
/// Under Tor there is no exit to abandon — arti rebuilds circuits itself — so this
/// is a logged no-op rather than triggering a reselect.
pub fn condemn_exit(generation: u64) {
	if generation != 0 {
		warn!("tor: condemn_exit(gen {generation}) is a no-op (arti rebuilds circuits itself)");
	}
}

/// The bootstrapped client, if it is up. Cloning the `Arc` is cheap.
pub fn client() -> Option<Arc<Client>> {
	TOR.client.read().clone()
}

/// Wait until the embedded Tor client has bootstrapped, starting it if nothing
/// has yet (lazy init on first use). Returns `false` once `timeout` lapses.
pub async fn wait_ready(timeout: Duration) -> bool {
	warm_up();
	let deadline = Instant::now() + timeout;
	loop {
		if is_ready() {
			return true;
		}
		if Instant::now() >= deadline {
			return false;
		}
		tokio::time::sleep(Duration::from_millis(250)).await;
	}
}

/// Open a Tor stream to `host:port`. `host` may be a `.onion` address (dialed as
/// a real onion connection — no exit node) or a clearnet host (dialed through a
/// Tor exit). Returns a [`DataStream`] (`AsyncRead + AsyncWrite`) — the byte
/// source the websocket / HTTP layers wrap. The caller is responsible for its own
/// connect timeout.
pub async fn connect(host: &str, port: u16) -> Result<DataStream, String> {
	let client = client().ok_or_else(|| "tor client not bootstrapped".to_string())?;
	client
		.connect((host, port))
		.await
		.map_err(|e| format!("tor connect to {host}:{port} failed: {e}"))
}

/// Build the arti client config: fs-backed state + cache in Goblin's base dir,
/// and — crucially — `allow_onion_addrs(true)` so `.onion` targets are dialable
/// (this plus the `onion-service-client` cargo feature is what enables onion
/// connections). Matches GRIM's `build_config`, minus the bridge plumbing Goblin
/// does not use.
fn build_config() -> TorClientConfig {
	let mut builder =
		TorClientConfigBuilder::from_directories(super::state_path(), super::cache_path());
	builder.address_filter().allow_onion_addrs(true);
	builder.build().expect("build tor client config")
}

/// One bootstrap attempt, driven on the arti runtime (GRIM's proven pattern:
/// spawn the bootstrap on arti's runtime, poll a flag from this thread). On
/// success the client is published and the readiness signals flip.
fn bootstrap_once() {
	// Ensure the state/cache dirs exist (arti creates them, but on a fresh device
	// the parent must be present first).
	let _ = fs::create_dir_all(super::state_path());
	let _ = fs::create_dir_all(super::cache_path());

	let config = build_config();
	let client = match TorClient::with_runtime(TOR.runtime.clone())
		.config(config)
		.create_unbootstrapped()
	{
		Ok(c) => c,
		Err(e) => {
			error!("tor: could not create client: {e}");
			return;
		}
	};

	let started = Instant::now();
	let bootstrapping = Arc::new(AtomicBool::new(true));
	let success = Arc::new(AtomicBool::new(false));
	let bootstrapping_t = bootstrapping.clone();
	let success_t = success.clone();
	let c = client.clone();
	let spawned = TOR.runtime.spawn(async move {
		match tokio::time::timeout(BOOTSTRAP_TIMEOUT, c.bootstrap()).await {
			Ok(Ok(())) => success_t.store(true, Ordering::Relaxed),
			Ok(Err(e)) => error!("tor: bootstrap error: {e}"),
			Err(_) => error!(
				"tor: bootstrap timed out after {}s",
				BOOTSTRAP_TIMEOUT.as_secs()
			),
		}
		bootstrapping_t.store(false, Ordering::Relaxed);
	});
	if spawned.is_err() {
		error!("tor: could not spawn bootstrap task");
		return;
	}
	// Wait for the bootstrap task to finish.
	while bootstrapping.load(Ordering::Relaxed) {
		thread::sleep(Duration::from_millis(500));
	}
	if !success.load(Ordering::Relaxed) {
		return;
	}

	// `create_unbootstrapped()` already hands back an `Arc<TorClient>`, so store it
	// as-is (no extra wrapping).
	TOR.client.write().replace(client);
	// A NEW transport is live: publish generation 1 (relay-liveness left over from
	// a prior generation is instantly stale) and flip the bootstrap-ready flag.
	TUNNEL_GEN.store(1, Ordering::Release);
	READY.store(true, Ordering::Release);
	info!(
		"tor: bootstrapped and ready in {}ms (gen 1)",
		started.elapsed().as_millis()
	);
	// Eager price fetch the moment Tor is ready: prefetch the pairing's rate so the
	// amount preview has a live value by first use. One-shot — bootstrap_once only
	// reaches here once.
	std::thread::spawn(crate::http::price::eager_refresh);
}
