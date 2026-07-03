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

//! In-process Nym mixnet tunnel — the wallet's PUBLIC-EXIT path. Goblin links
//! smolmix directly (no sidecar, no bundled binary, no loopback SOCKS5 seam).
//! One process-lifetime [`Tunnel`] carries relay websockets and HTTP requests
//! as raw TCP over the mixnet to an IPR exit gateway, with PREFER-WITH-FALLBACK
//! selection ([`ExitSelector`]): `GOBLIN_NYM_IPR` may name a PREFERRED PUBLIC
//! IPR to try first each cycle; on bootstrap/liveness failure the cycle falls
//! back to an AUTO-SELECTED public exit and retries the preferred one on the
//! next reselect. Unset → pure auto-select, as before. Losing any one exit just
//! re-selects, so there is no single-exit SPOF. Hostnames resolve via
//! [`super::dns`] over DoT through the same tunnel, so nothing touches clearnet.
//!
//! This is the FALLBACK / discovery-and-secondary-relay path. The MONEY-PATH
//! primary relay is reached over a SCOPED MixnetStream to a Floonet operator's
//! CO-LOCATED exit when the pool advertises one ([`crate::nostr::pool::PoolRelay::exit`]),
//! which needs no public DNS and no public IPR — see the streamexit egress
//! (design in ~/.claude/plans/floonet-nym-exit.md). That anchor+fallback split
//! is the "prefer our exit, never pin-only" rule at the transport level.
//!
//! Should smolmix ever regress, the fallback design (SOCKS5 network requester
//! + ordered exit failover) is specified in the plan, section G14.
//!
//! Cover traffic: the public READ tunnel is now backed by a tuned
//! `MixnetClient` (built in [`build_tunnel`] via `IpMixStream::from_client`) on
//! the balanced "high default traffic volume" preset — ~250 real msgs/s, ~10 ms
//! per-hop delay, loop cover traffic effectively off. Per-hop mix delays are
//! KEPT (no `set_no_per_hop_delays`), so timing obfuscation stays on; only cover
//! traffic is reduced, for the G13 low-power posture. The MONEY-PATH scoped exit
//! ([`super::streamexit`]) is a SEPARATE client and keeps full SDK defaults.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use log::{debug, error, info, warn};
use parking_lot::RwLock;
use smolmix::{Recipient, Tunnel};

use crate::AppConfig;

/// The shared process-lifetime tunnel, set once the mixnet bootstrap finishes.
static TUNNEL: RwLock<Option<Tunnel>> = RwLock::new(None);

/// Set once the tunnel is up (mirrors `TUNNEL`, but cheap to poll each frame).
static MIXNET_READY: AtomicBool = AtomicBool::new(false);

/// Monotonic tunnel generation: bumped each time a NEW tunnel (a freshly
/// auto-selected exit) is published. This is the crux of relay-gated readiness:
/// a relay-liveness report tagged with an older generation can never mark the
/// current tunnel ready, so readiness cannot latch true on a stale exit. Starts
/// at 0 ("no tunnel yet"); the first tunnel is generation 1.
static TUNNEL_GEN: AtomicU64 = AtomicU64::new(0);

/// The tunnel generation on which the nostr client currently has a relay
/// connected AND subscribed, or 0 for "no relay live". A SINGLE atomic (not a
/// bool+gen pair) so [`transport_ready`] can compare it to `TUNNEL_GEN` in one
/// shot — no half-updated `(live, gen)` tuple can slip a stale-exit "ready"
/// through. Written by the nostr client via [`report_relay_live`] /
/// [`report_relay_down`], read by the watchdog and [`transport_ready`].
static RELAY_LIVE_GEN: AtomicU64 = AtomicU64::new(0);

/// Whether a nostr consumer (a running `NostrService`) currently WANTS relays
/// over the tunnel. Relay reachability governs exit health ONLY while this is
/// true: the tunnel also carries plain HTTP (NIP-05, price, relay pool) with no
/// relay at all — e.g. before a wallet is open — and such usage must NOT get an
/// otherwise-healthy exit condemned for "no relay". Bracketed by the service via
/// [`set_relay_consumer`]; when false the DNS keepalive is the sole health
/// signal, exactly as before this hardening.
static RELAY_CONSUMER: AtomicBool = AtomicBool::new(false);

/// Guards the background bootstrap thread so `warm_up()` is idempotent.
static STARTED: AtomicBool = AtomicBool::new(false);

/// Guards the one-shot scoped-exit prewarm so it fires exactly once — after the
/// FIRST tunnel is published — and never again on a later reselect.
static PREWARMED: AtomicBool = AtomicBool::new(false);

/// Guards the one-shot eager price fetch / end-to-end exit probe so it fires
/// exactly once — after the FIRST tunnel is published — and never again on a
/// later reselect.
static PRICE_KICKED: AtomicBool = AtomicBool::new(false);

/// The highest tunnel generation for which an external caller (the eager price
/// probe) has requested condemnation. The watchdog compares it against the
/// generation it is watching each tick, so a dead exit whose cheap probes still
/// pass but which blackholes real HTTP can be abandoned in seconds. `fetch_max`
/// so a stale request can never move it backwards. Never triggers a reselect on
/// a NEWER generation than the one requested.
static CONDEMN_REQUEST_GEN: AtomicU64 = AtomicU64::new(0);

/// Pre-warm the mixnet tunnel in the background so relays / NIP-05 / price are
/// ready by first use. Idempotent — later calls (including the lazy-init path
/// in [`wait_for_tunnel`]) are no-ops.
pub fn warm_up() {
	if STARTED.swap(true, Ordering::SeqCst) {
		return;
	}
	thread::spawn(run_tunnel);
}

/// Whether the mixnet tunnel is warm. Cheap and cached — safe to poll from the
/// UI each frame. Distinct from a relay being connected (see
/// [`transport_ready`]): the tunnel can be up while no relay yet rides it.
pub fn is_ready() -> bool {
	MIXNET_READY.load(Ordering::Relaxed)
}

/// The current tunnel generation. The nostr client reads this right before it
/// dials so it can tag its relay-liveness reports with the exit they ride.
pub fn tunnel_generation() -> u64 {
	TUNNEL_GEN.load(Ordering::Acquire)
}

/// Relay-gated readiness — the AUTHORITATIVE "ready to receive/send over Nym"
/// signal, distinct from the tunnel-only [`is_ready`]. True only when the
/// tunnel is up AND a required relay is connected+subscribed on the CURRENT
/// generation. Money path: when in doubt this is false, so the UI shows
/// "connecting/reconnecting" rather than a false "Connected over Nym", and the
/// dead-for-our-purposes exit gets condemned rather than blackholing us.
pub fn transport_ready() -> bool {
	let generation = TUNNEL_GEN.load(Ordering::Acquire);
	generation != 0 && RELAY_LIVE_GEN.load(Ordering::Acquire) == generation && is_ready()
}

/// Client → transport report: a relay is connected+subscribed on `generation`.
/// `fetch_max` so a late report for an older exit can never move liveness
/// backwards over a newer one.
pub fn report_relay_live(generation: u64) {
	RELAY_LIVE_GEN.fetch_max(generation, Ordering::AcqRel);
}

/// Client → transport report: no relay is currently live on `generation` (all
/// dropped). Clears liveness only when `generation` is still the live one, so a
/// stale "down" can't wipe a fresh report from a newer exit.
pub fn report_relay_down(generation: u64) {
	let _ = RELAY_LIVE_GEN.compare_exchange(generation, 0, Ordering::AcqRel, Ordering::Acquire);
}

/// External condemnation request for `generation`: the end-to-end eager probe
/// found the exit up (cheap probes pass) yet blackholing real HTTP. The watchdog
/// picks this up on its next tick and re-selects a fresh exit. Bounded by design:
/// it only ever condemns the generation it targets, never a newer one, and the
/// probe that calls it is one-shot per tunnel generation.
pub fn condemn_exit(generation: u64) {
	if generation == 0 {
		return;
	}
	CONDEMN_REQUEST_GEN.fetch_max(generation, Ordering::AcqRel);
	warn!("[timing] nym: eager probe requested condemnation of exit gen {generation}");
}

/// Bracket a nostr consumer's lifetime: the running `NostrService` sets this
/// true while it wants relays and false when it stops. Arms/disarms
/// relay-reachability governance of exit health (see [`RELAY_CONSUMER`]).
pub fn set_relay_consumer(active: bool) {
	RELAY_CONSUMER.store(active, Ordering::Release);
}

/// Whether a nostr consumer currently wants relays over the tunnel.
fn relay_consumer() -> bool {
	RELAY_CONSUMER.load(Ordering::Acquire)
}

/// Whether a relay is live on `generation` — the watchdog's authoritative view
/// of whether the current exit actually carries our relay traffic.
fn relay_live_for(generation: u64) -> bool {
	generation != 0 && RELAY_LIVE_GEN.load(Ordering::Acquire) == generation
}

/// The shared tunnel, if it is up. Cloning is a cheap `Arc` bump.
pub fn tunnel() -> Option<Tunnel> {
	TUNNEL.read().clone()
}

/// Wait until the shared tunnel is up, starting the bootstrap if nothing has
/// yet (lazy init on first use). Returns `None` once `timeout` lapses.
pub async fn wait_for_tunnel(timeout: Duration) -> Option<Tunnel> {
	warm_up();
	let deadline = Instant::now() + timeout;
	loop {
		if let Some(t) = tunnel() {
			return Some(t);
		}
		if Instant::now() >= deadline {
			return None;
		}
		tokio::time::sleep(Duration::from_millis(250)).await;
	}
}

/// Build the mixnet tunnel on a dedicated multi-thread tokio runtime, then
/// keep the tunnel (its bridge + smoltcp reactor tasks) AND the runtime alive
/// for the lifetime of the process. Retries with backoff on bootstrap failure
/// (a dead gateway pick just re-selects on the next attempt). Blocks the
/// calling thread.
fn run_tunnel() {
	let rt = match tokio::runtime::Builder::new_multi_thread()
		.worker_threads(2)
		.enable_all()
		.build()
	{
		Ok(rt) => rt,
		Err(e) => {
			error!("nym: could not build mixnet runtime: {e}");
			return;
		}
	};
	rt.block_on(async move {
		let mut delay = Duration::from_secs(5);
		let mut attempt = 0u64;
		let mut selector = ExitSelector::new();
		// True while a FALLBACK (auto-selected) exit carries the traffic even
		// though an anchor is configured — makes the ANCHOR RECOVERED log honest.
		let mut fell_back = false;
		// WARM-CONNECT CACHES (biggest cold-connect win). The last-known-good ENTRY
		// GATEWAY (item 1) is applied to EVERY build so a warm reconnect skips
		// re-picking a random — and possibly dead — first hop; a build timeout/error
		// while it was in use drops it for the rest of THIS process (disk untouched,
		// since a blip must not throw away a good hint). The last-known-good IPR
		// (item 2) is tried once per process as a pin, ordered Anchor -> Cached ->
		// Auto by the selector.
		let mut cached_gw = AppConfig::nym_entry_gateway();
		let mut cached_ipr = AppConfig::nym_last_ipr().and_then(|s| parse_anchor(&s));
		// Don't double up: if the cached IPR is the configured anchor, the anchor
		// slot already covers it.
		if let (Some(c), Some(a)) = (cached_ipr, anchor_recipient()) {
			if c == a {
				cached_ipr = None;
			}
		}
		// COLD-START SEQUENCING (reads-first): the TUNNEL bootstraps first and takes
		// its Nym free-tier bandwidth grant, so interactive reads get the tunnel
		// ~2-3s sooner. The scoped money-path exit is prewarmed AFTER the first
		// tunnel is published (see the `PREWARMED` guard below `MIXNET_READY`), which
		// preserves grant-sequencing (tunnel first, then exit) without making reads
		// wait out an exit head-start on cold start.
		loop {
			let started = Instant::now();
			attempt += 1;
			// Prefer-with-fallback exit selection: the anchor (when configured)
			// exactly once per select cycle, auto-select for every further
			// attempt in the cycle. Env re-read each attempt so the timing
			// harness / a debug session can flip it without a restart.
			let anchor = anchor_recipient();
			let choice = selector.next_choice(anchor.is_some(), cached_ipr.is_some());
			let pin = match choice {
				ExitChoice::Anchor => {
					info!(
						"[timing] nym: ANCHOR attempt — trying our preferred IPR exit first (attempt {attempt})"
					);
					anchor
				}
				ExitChoice::Cached => {
					info!(
						"[timing] nym: CACHED attempt — trying last-known-good IPR exit (attempt {attempt})"
					);
					// One-shot for this process: take it so a failure falls through
					// to Auto and the slot never re-arms (unlike the anchor).
					cached_ipr.take()
				}
				ExitChoice::Auto => None,
			};
			info!(
				"[timing] nym: BOOTSTRAP start (attempt {attempt}, {} exit select+build)",
				choice.label()
			);
			// Cap the build: a dead gateway pick otherwise blocks on the Nym SDK's
			// own long "connection response" timeout (~74s measured) before we can
			// reselect. Abandoning the future drops the half-built tunnel.
			let build_cap = tunnel_build_timeout();
			let entry_gw = cached_gw.clone();
			let used_cached_gw = entry_gw.is_some();
			let build = match tokio::time::timeout(build_cap, build_tunnel(pin, entry_gw)).await {
				Ok(result) => result,
				Err(_) => {
					// A cached entry gateway that timed out is not reused for the rest
					// of this process (disk kept — it may be a transient blip).
					if used_cached_gw {
						cached_gw = None;
					}
					match choice {
						ExitChoice::Anchor => {
							// A dead anchor must not delay connectivity: fall back
							// to auto-select IMMEDIATELY (no backoff), same cycle.
							warn!(
								"[timing] nym: ANCHOR DEAD — anchor build exceeded {}s (attempt {attempt}); \
								 FALLBACK to auto-select now",
								build_cap.as_secs()
							);
						}
						ExitChoice::Cached => {
							warn!(
								"[timing] nym: CACHED IPR build exceeded {}s (attempt {attempt}); \
								 clearing the cached exit and auto-selecting now",
								build_cap.as_secs()
							);
							AppConfig::set_nym_last_ipr(None);
						}
						ExitChoice::Auto => {
							warn!(
								"[timing] nym: DEAD GATEWAY — build_tunnel exceeded {}s (attempt {attempt}); \
								 re-selecting immediately",
								build_cap.as_secs()
							);
							delay = Duration::from_secs(5);
						}
					}
					continue;
				}
			};
			match build {
				Ok((tunnel, used_gw, used_ipr)) => {
					let build_ms = started.elapsed().as_millis();
					info!(
						"[timing] nym: tunnel BUILT in {build_ms}ms (attempt {attempt}); probing exit liveness"
					);
					// Gate readiness on one end-to-end probe: some exits accept
					// the IPR handshake but never deliver data (seen live);
					// publishing such a tunnel would blackhole every consumer
					// until the watchdog caught it minutes later. Re-select
					// immediately instead. (This is a CHEAP early signal; relay
					// reachability below is the authoritative one.) Uses the FAST
					// fresh-gate budget (~10s worst case) — NOT the patient
					// established-tunnel probe (~32s doubled here before) — so a
					// dead fresh exit no longer dominates the cold-start tail; see
					// `dns::probe_fresh`.
					let probe_started = Instant::now();
					let alive = super::dns::probe_fresh(&tunnel).await;
					let probe_ms = probe_started.elapsed().as_millis();
					if !alive {
						warn!(
							"[timing] nym: DEAD EXIT — fresh {} tunnel failed liveness probe in {probe_ms}ms \
							 ({}ms total incl. build; attempt {attempt}); {}",
							choice.label(),
							started.elapsed().as_millis(),
							match choice {
								ExitChoice::Anchor => "FALLBACK to auto-select now",
								ExitChoice::Cached =>
									"clearing the cached exit and auto-selecting now",
								ExitChoice::Auto => "re-selecting immediately",
							}
						);
						tunnel.shutdown().await;
						match choice {
							// A cached exit that fails its probe is stale: drop the
							// disk hint so we don't keep re-trying a dead IPR.
							ExitChoice::Cached => AppConfig::set_nym_last_ipr(None),
							ExitChoice::Auto => {
								delay = (delay * 2).min(Duration::from_secs(60));
							}
							ExitChoice::Anchor => {}
						}
						continue;
					}
					// A NEW exit is live: bump the generation BEFORE publishing so
					// any relay-liveness left over from the previous exit is
					// instantly stale (RELAY_LIVE_GEN != TUNNEL_GEN) and cannot
					// mark this tunnel ready.
					let generation = TUNNEL_GEN.fetch_add(1, Ordering::AcqRel) + 1;
					let published = Instant::now();
					info!(
						"[timing] nym: TUNNEL READY in ~{}ms total (build {build_ms}ms + probe, \
						 {} exit, allocated ip {}, gen {generation}, attempt {attempt})",
						started.elapsed().as_millis(),
						choice.label(),
						tunnel.allocated_ips().ipv4
					);
					// Close the select cycle: the NEXT reselect tries the anchor
					// first again, whichever exit won this one.
					selector.tunnel_published();
					match choice {
						ExitChoice::Anchor => {
							if fell_back {
								info!(
									"[timing] nym: ANCHOR RECOVERED — back on our preferred exit (gen {generation})"
								);
							}
							fell_back = false;
						}
						// A cached exit only wins after the anchor slot was tried this
						// cycle, so with an anchor configured this is still a FALLBACK —
						// retry the anchor on the next reselect.
						ExitChoice::Cached if anchor.is_some() => {
							fell_back = true;
							info!(
								"[timing] nym: running on cached FALLBACK exit (gen {generation}); \
								 anchor will be retried on the next reselect"
							);
						}
						ExitChoice::Cached => {}
						ExitChoice::Auto if anchor.is_some() => {
							fell_back = true;
							info!(
								"[timing] nym: running on FALLBACK auto-selected exit (gen {generation}); \
								 anchor will be retried on the next reselect"
							);
						}
						ExitChoice::Auto => {}
					}
					// Persist the warm-connect caches for the next cold start: the ENTRY
					// GATEWAY (item 1) and the winning IPR (item 2), each only when
					// changed so a steady exit doesn't rewrite app.toml on every reselect.
					if AppConfig::nym_entry_gateway().as_deref() != Some(used_gw.as_str()) {
						info!("[timing] nym: caching entry gateway {used_gw} for warm reconnect");
						AppConfig::set_nym_entry_gateway(Some(used_gw.clone()));
					}
					cached_gw = Some(used_gw);
					let ipr_str = used_ipr.to_string();
					if AppConfig::nym_last_ipr().as_deref() != Some(ipr_str.as_str()) {
						AppConfig::set_nym_last_ipr(Some(ipr_str));
					}
					*TUNNEL.write() = Some(tunnel.clone());
					MIXNET_READY.store(true, Ordering::Relaxed);
					// Prewarm the scoped money-path exit ONCE, now that the tunnel is
					// up (grant-sequencing: the tunnel already took its grant, the exit
					// takes the next one) — but reads already have the tunnel. Guarded
					// so a later reselect never re-fires it, and gated on the pool
					// actually advertising a co-located exit.
					if crate::nostr::pool::load().has_exit()
						&& !PREWARMED.swap(true, Ordering::SeqCst)
					{
						tokio::spawn(super::streamexit::prewarm());
					}
					// Eager price fetch the moment the tunnel is ready (item 3) — it
					// also serves as the end-to-end exit probe (item 5): if every
					// attempt fails while the tunnel still reads ready, the exit is
					// blackholing HTTP and gets condemned. One-shot, like the prewarm.
					if !PRICE_KICKED.swap(true, Ordering::SeqCst) {
						std::thread::spawn(crate::http::price::eager_refresh);
					}
					delay = Duration::from_secs(5);
					// Hold the exit warm and govern its health. The watchdog weighs TWO
					// signals: the cheap DNS keepalive (as before) AND — authoritatively,
					// whenever a nostr consumer is present — RELAY REACHABILITY. The DNS
					// probe only proves the exit reaches the internet; some exits pass it
					// yet never carry our relay traffic (exit policy blocks the relay, relay
					// unreachable through it, subscription never establishes). Such an exit
					// is condemned and rebuilt on a fresh auto-selected one rather than left
					// blackholing the wallet while the UI (falsely) reads "Connected over
					// Nym". Losing any one exit must never take the wallet down.
					watch_tunnel(&tunnel, generation).await;
					error!(
						"[timing] nym: exit gen {generation} condemned after {}s alive; rebuilding on a fresh exit",
						published.elapsed().as_secs()
					);
					MIXNET_READY.store(false, Ordering::Relaxed);
					*TUNNEL.write() = None;
					tunnel.shutdown().await;
					// Rebuild floor: never re-select faster than once per
					// MIN_EXIT_LIFETIME. Whatever condemned the exit (or any
					// future bug), this is the hard guarantee that a condemnation
					// can't thrash the mixnet into a tight reselect loop.
					let alive = published.elapsed();
					if alive < MIN_EXIT_LIFETIME {
						let floor = MIN_EXIT_LIFETIME - alive;
						info!(
							"[timing] nym: rebuild floor — waiting {}ms before next exit select",
							floor.as_millis()
						);
						tokio::time::sleep(floor).await;
					}
				}
				Err(e) => {
					// A cached entry gateway that errored is not reused for the rest
					// of this process (disk kept — it may be a transient blip).
					if used_cached_gw {
						cached_gw = None;
					}
					match choice {
						ExitChoice::Anchor => {
							// Anchor unreachable (not bonded yet / condemned by the
							// network / bad address): fall back to auto-select
							// IMMEDIATELY — no backoff, connectivity first.
							warn!(
								"[timing] nym: ANCHOR failed to build: {e}; FALLBACK to auto-select now"
							);
						}
						ExitChoice::Cached => {
							warn!(
								"[timing] nym: CACHED IPR failed to build: {e}; \
								 clearing the cached exit and auto-selecting now"
							);
							AppConfig::set_nym_last_ipr(None);
						}
						ExitChoice::Auto => {
							error!(
								"nym: mixnet tunnel failed to start: {e}; retrying in {}s",
								delay.as_secs()
							);
							tokio::time::sleep(delay).await;
							delay = (delay * 2).min(Duration::from_secs(60));
						}
					}
				}
			}
		}
	});
}

/// Exit-liveness keepalive period and the consecutive probe failures that
/// declare death (the probe is now a TCP connect through the tunnel, not UDP DNS).
const KEEPALIVE_PERIOD: Duration = Duration::from_secs(60);
const KEEPALIVE_MAX_FAILS: u32 = 3;

/// How long a running nostr consumer may go with ZERO reachable relays through
/// the current exit before the exit-liveness gate is consulted. Covers BOTH
/// cases the relay signal governs: an exit that never carries a relay after a
/// consumer starts dialing (relay-dead-on-arrival), and one that was carrying
/// relays and then can't re-establish any (exit went bad, as opposed to a single
/// relay bouncing — which nostr-sdk auto-reconnects within seconds, resetting
/// this timer). The timer resets on every live report, so only CONTINUOUS relay
/// absence counts. With clearnet DNS a healthy relay connects in ~1s, so this
/// window is never reached in normal operation; when it IS reached we do NOT
/// condemn on "no relay yet" alone — we first probe the exit for genuine
/// connectivity (see [`watch_tunnel`]).
const RELAY_GRACE: Duration = Duration::from_secs(25);

/// Hard backstop: even if the exit keeps PASSING its connectivity probe (so it
/// reaches the internet) yet a consumer still has zero live relays for this
/// long, condemn anyway — this is the "exit reaches the net but its policy
/// blocks our relay port / the relay is unreachable through it" case the G14
/// hardening guards. Long enough that a slow-but-working handshake never trips
/// it, so it can't drive a reselect loop.
const RELAY_HARD_GRACE: Duration = Duration::from_secs(90);

/// Rebuild floor: an exit must live at least this long before the watchdog may
/// condemn+rebuild it, and `run_tunnel` waits out any remainder before selecting
/// the next exit. This bounds the reselect rate to at most once per
/// MIN_EXIT_LIFETIME no matter what, so a transient hiccup can never thrash the
/// mixnet into the 2-3 minute loop this build fixes.
const MIN_EXIT_LIFETIME: Duration = Duration::from_secs(20);

/// The scoped-exit (money-path) mixnet dial cap: how long
/// [`super::streamexit::open_stream`] (and the HTTP exit fallback in
/// [`super::exit_connect`]) may spend bootstrapping before failing over. Without a
/// cap a DEAD pick blocked for ~74s (measured) on the Nym SDK's own "listening for
/// connection response" timeout. The TUNNEL's own build uses the shorter
/// [`TUNNEL_BUILD_TIMEOUT`]; this stays at 20s so the money path — which has no
/// tunnel to fall back to — gets more patience before it gives up.
pub(crate) const BOOTSTRAP_TIMEOUT: Duration = Duration::from_secs(20);

/// Abandon a single `build_tunnel()` that hasn't finished within this and
/// re-select — the TUNNEL's build cap (the exit keeps [`BOOTSTRAP_TIMEOUT`] as
/// its money-path dial cap). A healthy gateway+IPR bootstrap completes in ~4-7s,
/// so 10s gives one slow-but-working build room while a dead first pick is
/// abandoned in a third of the old 30s. Runtime-overridable (seconds) via
/// `GOBLIN_NYM_BUILD_TIMEOUT` for the timing harness.
const TUNNEL_BUILD_TIMEOUT: Duration = Duration::from_secs(10);

/// The effective tunnel build cap: [`TUNNEL_BUILD_TIMEOUT`] unless
/// `GOBLIN_NYM_BUILD_TIMEOUT` (whole seconds) overrides it. Re-read each attempt
/// so a timing harness can flip it without a restart.
fn tunnel_build_timeout() -> Duration {
	std::env::var("GOBLIN_NYM_BUILD_TIMEOUT")
		.ok()
		.and_then(|s| s.parse::<u64>().ok())
		.map(Duration::from_secs)
		.unwrap_or(TUNNEL_BUILD_TIMEOUT)
}

/// Watchdog poll cadence. The relay-reachability check is a bare atomic load
/// (free), so a short cadence costs nothing and never touches the network; the
/// DNS keepalive still only fires every [`KEEPALIVE_PERIOD`], preserving the
/// G13 low-power posture.
const WATCH_TICK: Duration = Duration::from_secs(5);

/// Hold the tunnel warm and govern exit health for generation `generation`. Two
/// signals, cheapest first:
///  * relay reachability (AUTHORITATIVE, but only while a nostr consumer is
///    present — see [`RELAY_CONSUMER`]) — a bare atomic read every
///    [`WATCH_TICK`]; a consumer with zero live relays on this exit for
///    [`RELAY_GRACE`] condemns it. Without a consumer (onboarding / HTTP-only)
///    this signal is inert, so plain HTTP usage never condemns a good exit.
///  * DNS keepalive (cheaper backstop, always on) — one tiny mixnet round trip
///    every [`KEEPALIVE_PERIOD`]; [`KEEPALIVE_MAX_FAILS`] in a row condemns the
///    exit and, as a side effect, keeps the gateway/IPR session from idling out.
///
/// Returns once either signal declares the current exit dead, whereupon
/// `run_tunnel` rebuilds on a fresh auto-selected exit.
async fn watch_tunnel(tunnel: &smolmix::Tunnel, generation: u64) {
	let published = Instant::now();
	let mut dns_fails = 0u32;
	let mut since_dns = Duration::ZERO;
	let mut relay_lost: Option<Instant> = None;
	loop {
		tokio::time::sleep(WATCH_TICK).await;
		// (0) External condemnation request — the eager end-to-end probe found this
		// exit up (cheap probes pass) yet blackholing real HTTP. Honor it only for
		// THIS generation (never a newer one): abandon the exit now so a fresh one
		// is selected in seconds instead of the minutes a blackhole would otherwise
		// cost. The MIN_EXIT_LIFETIME rebuild floor still bounds the reselect rate.
		if CONDEMN_REQUEST_GEN.load(Ordering::Acquire) >= generation {
			warn!(
				"[timing] nym: CONDEMN gen {generation} reason=eager-probe-blackhole; \
				 exit lived {}s, re-selecting",
				published.elapsed().as_secs()
			);
			return;
		}
		// (1) Relay reachability — authoritative, but ONLY when a nostr consumer
		// actually wants relays on this exit. No consumer → the DNS keepalive
		// below is the sole health signal, exactly as before this hardening.
		if relay_consumer() && !relay_live_for(generation) {
			let lost = *relay_lost.get_or_insert_with(Instant::now);
			let absent = lost.elapsed();
			if published.elapsed() >= MIN_EXIT_LIFETIME && absent >= RELAY_GRACE {
				// Past the settle floor AND relays absent for the grace.
				// Don't condemn on "no relay yet" alone — first prove the exit
				// itself has NO connectivity (a genuine blackhole). If the probe
				// SUCCEEDS the exit reaches the internet, so relays are merely slow
				// or the relay is blocked; only the HARD backstop condemns then.
				let exit_reachable = super::dns::probe(tunnel).await;
				if !exit_reachable {
					warn!(
						"[timing] nym: CONDEMN gen {generation} reason=exit-no-connectivity \
						 (no relay {}s + probe failed); exit lived {}s, re-selecting",
						absent.as_secs(),
						published.elapsed().as_secs()
					);
					return;
				}
				if absent >= RELAY_HARD_GRACE {
					warn!(
						"[timing] nym: CONDEMN gen {generation} reason=relay-blocked-{}s \
						 (exit reaches net but no relay); exit lived {}s, re-selecting",
						RELAY_HARD_GRACE.as_secs(),
						published.elapsed().as_secs()
					);
					return;
				}
			}
		} else {
			// Relay live, or no consumer demanding one: clear the timer.
			relay_lost = None;
		}
		// (2) Backstop: cheap DNS keepalive, only every KEEPALIVE_PERIOD. This is a
		// real mixnet round trip through the exit, so it is the authoritative
		// "does this exit reach the internet at all" signal.
		since_dns += WATCH_TICK;
		if since_dns >= KEEPALIVE_PERIOD {
			since_dns = Duration::ZERO;
			if super::dns::probe(tunnel).await {
				dns_fails = 0;
			} else {
				dns_fails += 1;
				warn!("nym: tunnel keepalive probe failed ({dns_fails}/{KEEPALIVE_MAX_FAILS})");
				if dns_fails >= KEEPALIVE_MAX_FAILS {
					warn!(
						"[timing] nym: CONDEMN gen {generation} reason=keepalive-{}-fails; \
						 exit lived {}s, re-selecting",
						KEEPALIVE_MAX_FAILS,
						published.elapsed().as_secs()
					);
					return;
				}
			}
		}
	}
}

/// Which exit the next tunnel build targets. Decided per attempt by
/// [`ExitSelector`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExitChoice {
	/// A PREFERRED public IPR exit (`GOBLIN_NYM_IPR`) tried first — the anchor
	/// of the public-exit path. (The money-path anchor to a Floonet operator's
	/// own co-located exit is the separate scoped-MixnetStream egress; this
	/// selector governs only the public-IPR fallback layer.)
	Anchor,
	/// The last-known-good IPR from a previous run, tried once per process after
	/// the anchor and before pure auto-select — a warm-connect hint, not a pin.
	Cached,
	/// A public exit auto-selected from the network pool — the FALLBACK.
	Auto,
}

impl ExitChoice {
	/// Short tag for the `[timing]` logs.
	fn label(self) -> &'static str {
		match self {
			ExitChoice::Anchor => "ANCHOR",
			ExitChoice::Cached => "cached",
			ExitChoice::Auto => "auto-selected",
		}
	}
}

/// Prefer-with-fallback exit selection (the G14 anchor+fallback rule). A
/// SELECT CYCLE spans every build attempt between two published tunnels. The
/// policy, kept deliberately tiny so it is exhaustively unit-testable:
///
///  * anchor configured → the FIRST attempt of each cycle targets the anchor;
///  * anchor failed (build timeout, build error or dead-exit probe) → every
///    further attempt in the SAME cycle auto-selects, so a dead anchor can
///    never lock the wallet out (this is why pin-ONLY is forbidden);
///  * a tunnel got published (either exit) → cycle over; the NEXT cycle —
///    i.e. the next reselect after a fallback — tries the anchor first again,
///    because it may have recovered while a public exit carried the traffic;
///  * no anchor configured → pure auto-select, byte-for-byte the old behavior.
///
/// Thrash safety: the anchor adds at most one bounded attempt
/// ([`BOOTSTRAP_TIMEOUT`] + probe) per cycle, and cycles themselves are rate-
/// limited by [`MIN_EXIT_LIFETIME`] + the watchdog graces, so a permanently
/// dead anchor costs seconds per reselect, never a loop.
struct ExitSelector {
	/// Whether the anchor has been tried in the current select cycle.
	anchor_tried: bool,
	/// Whether the cached last-known-good IPR has been tried. Unlike the anchor
	/// this is ONCE PER PROCESS — a warm-connect hint spends itself and never
	/// re-arms, so it can't keep re-pinning a possibly-stale exit on every cycle.
	cached_tried: bool,
}

impl ExitSelector {
	const fn new() -> Self {
		Self {
			anchor_tried: false,
			cached_tried: false,
		}
	}

	/// The exit to target for the next build attempt. Order per cycle:
	/// anchor (if configured, once per cycle) → cached (if available, once per
	/// process) → auto-select.
	fn next_choice(&mut self, anchor_available: bool, cached_available: bool) -> ExitChoice {
		if anchor_available && !self.anchor_tried {
			self.anchor_tried = true;
			ExitChoice::Anchor
		} else if cached_available && !self.cached_tried {
			self.cached_tried = true;
			ExitChoice::Cached
		} else {
			ExitChoice::Auto
		}
	}

	/// A tunnel was published: the select cycle is over. Re-arms the anchor for
	/// the next cycle. The cached slot is NOT re-armed — it is a one-shot
	/// warm-connect hint (see [`cached_tried`](Self::cached_tried)).
	fn tunnel_published(&mut self) {
		self.anchor_tried = false;
	}
}

/// Compile-time default: building with `GOBLIN_NYM_IPR=<recipient>` in the
/// environment BAKES a preferred PUBLIC IPR into the binary — the only way to
/// configure it on Android, where the app gets no user env. A runtime
/// `GOBLIN_NYM_IPR` still overrides the baked value (set it EMPTY to disable a
/// baked anchor, e.g. for a pure-auto-select measurement run).
const BAKED_ANCHOR: Option<&str> = option_env!("GOBLIN_NYM_IPR");

/// The PREFERRED public-IPR exit's recipient, if one is configured. Unset (no
/// runtime env, nothing baked) → `None` → pure auto-select, exactly the
/// behavior before the anchor existed — so the build works and ships fine
/// whether or not a Floonet exit is deployed.
fn anchor_recipient() -> Option<Recipient> {
	let raw = match std::env::var("GOBLIN_NYM_IPR") {
		Ok(runtime) => runtime,              // runtime wins; "" disables
		Err(_) => BAKED_ANCHOR?.to_string(), // baked default (release builds)
	};
	parse_anchor(&raw)
}

/// Parse an IPR recipient (`<client_id>.<client_enc>@<gateway_id>`). Empty or
/// whitespace disables the anchor silently; garbage warns and disables — a bad
/// placeholder degrades gracefully to pure auto-select, never a crash.
fn parse_anchor(raw: &str) -> Option<Recipient> {
	let raw = raw.trim();
	if raw.is_empty() {
		return None;
	}
	match raw.parse() {
		Ok(recipient) => Some(recipient),
		Err(e) => {
			warn!("nym: ignoring invalid GOBLIN_NYM_IPR anchor (pure auto-select): {e}");
			None
		}
	}
}

/// Build the tunnel — pinned to the anchor's IPR when `pin` is set, otherwise
/// with an auto-selected exit. When `entry_gateway` is set, the client REQUESTS
/// that specific first-hop gateway (a warm-connect hint) instead of a random one.
///
/// Keys stay EPHEMERAL — a fresh mixnet identity per run, no sqlite, nothing
/// persisted about the client itself. The ONLY thing that persists across runs is
/// the gateway CHOICE (and the exit IPR), remembered by [`run_tunnel`] so a warm
/// reconnect skips re-picking a possibly-dead first hop; the requested gateway
/// resolves to `GatewaySelectionSpecification::Specified` while storage stays
/// ephemeral, so no gateway keys are written to disk.
///
/// Returns the built tunnel PLUS the ENTRY GATEWAY it actually used (base58) and
/// the EXIT IPR recipient it rode — both captured so `run_tunnel` can persist the
/// last-known-good pair. The gateway is read from the client's own nym-address
/// BEFORE [`IpMixStream::from_client`] consumes the client.
///
/// NEVER make the anchor the ONLY exit: `pin` must always be allowed to fall
/// back to `None` (see [`ExitSelector`]) or the single-exit SPOF — and a
/// single party seeing all exit traffic — comes back.
async fn build_tunnel(
	pin: Option<Recipient>,
	entry_gateway: Option<String>,
) -> Result<(Tunnel, String, Recipient), smolmix::SmolmixError> {
	use nym_sdk::DebugConfig;
	use nym_sdk::ipr_wrapper::IpMixStream;
	use nym_sdk::mixnet::MixnetClientBuilder;

	// READ-TUNNEL ANONYMITY TUNING — PUBLIC PATH ONLY. This tunes the mixnet
	// client that backs the public read tunnel (relay/NIP-11/price/DoT); the
	// MONEY-PATH scoped exit (`streamexit.rs`) is a SEPARATE MixnetClient and is
	// deliberately left on full SDK defaults, untouched.
	//
	// The "balanced" preset (mirrors `Config::set_high_default_traffic_volume`
	// upstream): ~10 ms average per-hop delay, ~250 real msgs/s send rate, and
	// loop cover traffic effectively disabled. Per-hop delays are KEPT ON (we do
	// NOT call `set_no_per_hop_delays`) so mix-layer timing obfuscation still
	// applies to this public read tunnel — the tradeoff here is reduced *cover*
	// traffic, not reduced mixing.
	let mut cfg = DebugConfig::default();
	cfg.traffic.average_packet_delay = Duration::from_millis(10);
	cfg.cover_traffic.loop_cover_traffic_average_delay = Duration::from_millis(2_000_000);
	cfg.traffic.message_sending_average_delay = Duration::from_millis(4);

	// Mirror the mainnet env setup the SDK's own constructors run before connect.
	// Done ONCE here (not per-raced-client): `setup_env` writes process-wide env
	// vars and must not be raced across the two connect tasks on the cold path.
	nym_sdk::setup_env(None::<&std::path::Path>);

	// GATEWAY CONNECT. Two shapes, both on the identical anonymity `cfg` (`Copy`):
	//  * WARM hint (`entry_gateway.is_some()`): reconnect to the KNOWN-good first
	//    hop — a Specified gateway, ephemeral storage, no persisted keys. NO race:
	//    we want that specific gateway.
	//  * COLD / auto (`entry_gateway.is_none()`): the first hop is a RANDOM draw and
	//    a dead draw blocks `connect_to_mixnet()` until `run_tunnel`'s 10s cap, with
	//    consecutive dead draws stacking into a multi-second tail. Race TWO ephemeral
	//    gateway connects and take the first up (see `connect_gateway_racing`). Only
	//    the gateway handshake is doubled — the exit/IPR below is still built ONCE.
	let client = match entry_gateway {
		Some(gw) => {
			MixnetClientBuilder::new_ephemeral()
				.debug_config(cfg)
				.request_gateway(gw)
				.build()?
				.connect_to_mixnet()
				.await?
		}
		None => connect_gateway_racing(cfg).await?,
	};

	// Capture the ENTRY GATEWAY actually used, from the client's own nym-address,
	// BEFORE `from_client` consumes the client.
	let entry_gw = client.nym_address().gateway().to_base58_string();

	// Pinned anchor/cached exit when provided, else the auto-selected best public
	// IPR — the same discovery the untuned `IpMixStream::new` path used, so
	// anchor/fallback selection in `run_tunnel` is unchanged.
	let ipr = match pin {
		Some(recipient) => recipient,
		None => IpMixStream::best_ipr().await?,
	};
	let stream = IpMixStream::from_client(client, ipr).await?;
	let tunnel = Tunnel::from_stream(stream).await?;
	Ok((tunnel, entry_gw, ipr))
}

/// Cold/auto gateway connect with a BOUNDED latency tail — the fix for the Nym
/// cold-start "gateway lottery". Used ONLY on the auto path (no warm hint), where
/// the entry gateway is a RANDOM draw: a dead draw blocks `connect_to_mixnet()`
/// until `run_tunnel`'s 10s cap and consecutive dead draws stack into the tail.
///
/// Race EXACTLY TWO ephemeral `MixnetClient`s — IDENTICAL anonymity `cfg`,
/// ephemeral keys, nothing persisted — through the gateway handshake and return
/// the FIRST that connects. Only the gateway handshake is doubled; the caller
/// builds the exit/IPR ONCE on the winner. Two (not more) bounds the Nym
/// free-tier bandwidth burst.
///
/// The loser is REAPED so a CONNECTED client is never leaked: it is aborted (a
/// still-pending connect just drops its half-built client) and, in a DETACHED task
/// so the winner returns immediately, `disconnect()`ed IFF it had already
/// connected. If BOTH draws fail, the error is returned so `run_tunnel`'s loop
/// re-selects — the same contract as the single build.
async fn connect_gateway_racing(
	cfg: nym_sdk::DebugConfig,
) -> Result<nym_sdk::mixnet::MixnetClient, smolmix::SmolmixError> {
	use nym_sdk::mixnet::{MixnetClient, MixnetClientBuilder};

	async fn connect_one(cfg: nym_sdk::DebugConfig) -> Result<MixnetClient, smolmix::SmolmixError> {
		Ok(MixnetClientBuilder::new_ephemeral()
			.debug_config(cfg)
			.build()?
			.connect_to_mixnet()
			.await?)
	}

	// Spawn both so the loser can be aborted cleanly. `cfg` is `Copy`, so each task
	// gets the identical anonymity config.
	let race_started = Instant::now();
	let mut a = tokio::spawn(connect_one(cfg));
	let mut b = tokio::spawn(connect_one(cfg));
	debug!("[timing] nym: gateway race START — 2 ephemeral draws, first up wins");

	// Whichever finishes first; keep `other` to reap (on a win) or fall back to (if
	// the first draw errored). `winner` tags WHICH draw finished first.
	let (first, other, winner) = tokio::select! {
		r = &mut a => (r, b, 'A'),
		r = &mut b => (r, a, 'B'),
	};
	// A JoinError (task panic) folds into an error so `other` still gets its turn.
	let first = first.unwrap_or_else(|e| {
		Err(smolmix::SmolmixError::Io(std::io::Error::new(
			std::io::ErrorKind::Other,
			format!("nym gateway connect task failed: {e}"),
		)))
	});

	match first {
		// First to finish connected — it WINS. Reap the loser off the hot path.
		Ok(client) => {
			info!(
				"[timing] nym: gateway race WON by draw {winner} in {}ms; reaping loser off the hot path",
				race_started.elapsed().as_millis()
			);
			other.abort();
			tokio::spawn(async move {
				// If the loser connected before the abort landed, disconnect it so
				// no live gateway session leaks; a pending connect was just dropped.
				match other.await {
					Ok(Ok(loser)) => {
						debug!(
							"[timing] nym: gateway race loser had connected before abort — \
							 disconnecting so no gateway session leaks"
						);
						loser.disconnect().await;
					}
					_ => debug!(
						"[timing] nym: gateway race loser still pending at reap — dropped \
						 (no session to close)"
					),
				}
			});
			Ok(client)
		}
		// First draw failed — a lone client has no dead-draw tail, so just await the
		// survivor; if it fails too, surface an error and `run_tunnel` re-selects.
		Err(first_err) => match other.await {
			Ok(Ok(client)) => {
				info!(
					"[timing] nym: gateway race — draw {winner} errored, survivor connected in {}ms",
					race_started.elapsed().as_millis()
				);
				Ok(client)
			}
			Ok(Err(second_err)) => {
				warn!(
					"[timing] nym: both raced gateway connects failed \
					 ({first_err}; {second_err}); run_tunnel will re-select"
				);
				Err(second_err)
			}
			Err(_join) => Err(first_err),
		},
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn no_anchor_is_pure_auto_select() {
		let mut s = ExitSelector::new();
		for _ in 0..5 {
			assert_eq!(s.next_choice(false, false), ExitChoice::Auto);
		}
		// Publishing changes nothing without an anchor.
		s.tunnel_published();
		assert_eq!(s.next_choice(false, false), ExitChoice::Auto);
	}

	#[test]
	fn anchor_first_then_auto_within_a_cycle() {
		let mut s = ExitSelector::new();
		assert_eq!(s.next_choice(true, false), ExitChoice::Anchor);
		// Anchor failed — every further attempt in the cycle falls back.
		assert_eq!(s.next_choice(true, false), ExitChoice::Auto);
		assert_eq!(s.next_choice(true, false), ExitChoice::Auto);
	}

	#[test]
	fn anchor_retried_on_the_next_cycle_after_a_fallback() {
		let mut s = ExitSelector::new();
		// Cycle 1: anchor fails, a fallback exit gets published.
		assert_eq!(s.next_choice(true, false), ExitChoice::Anchor);
		assert_eq!(s.next_choice(true, false), ExitChoice::Auto);
		s.tunnel_published();
		// Cycle 2 (the reselect after the fallback): anchor first again.
		assert_eq!(s.next_choice(true, false), ExitChoice::Anchor);
	}

	#[test]
	fn anchor_publish_also_rearms_the_anchor() {
		let mut s = ExitSelector::new();
		assert_eq!(s.next_choice(true, false), ExitChoice::Anchor);
		s.tunnel_published(); // the anchor itself came up
		// Condemned later → next cycle prefers the anchor again.
		assert_eq!(s.next_choice(true, false), ExitChoice::Anchor);
	}

	#[test]
	fn anchor_appearing_mid_cycle_is_tried() {
		let mut s = ExitSelector::new();
		// No anchor yet (env unset / invalid): auto, without burning the try.
		assert_eq!(s.next_choice(false, false), ExitChoice::Auto);
		// Anchor becomes available (env fixed mid-run): tried on the next attempt.
		assert_eq!(s.next_choice(true, false), ExitChoice::Anchor);
		assert_eq!(s.next_choice(true, false), ExitChoice::Auto);
	}

	#[test]
	fn cached_after_anchor_then_auto_within_a_cycle() {
		let mut s = ExitSelector::new();
		// Order per cycle: anchor → cached → auto.
		assert_eq!(s.next_choice(true, true), ExitChoice::Anchor);
		assert_eq!(s.next_choice(true, true), ExitChoice::Cached);
		assert_eq!(s.next_choice(true, true), ExitChoice::Auto);
		assert_eq!(s.next_choice(true, true), ExitChoice::Auto);
	}

	#[test]
	fn cached_tried_before_auto_when_no_anchor() {
		let mut s = ExitSelector::new();
		// No anchor, but a cached hint exists: cached first, then auto.
		assert_eq!(s.next_choice(false, true), ExitChoice::Cached);
		assert_eq!(s.next_choice(false, true), ExitChoice::Auto);
	}

	#[test]
	fn cached_is_one_shot_across_the_whole_process() {
		let mut s = ExitSelector::new();
		// Spend the cached hint in cycle 1.
		assert_eq!(s.next_choice(false, true), ExitChoice::Cached);
		assert_eq!(s.next_choice(false, true), ExitChoice::Auto);
		s.tunnel_published();
		// Cycle 2: the cached slot never re-arms, even if still "available".
		assert_eq!(s.next_choice(false, true), ExitChoice::Auto);
		// And with an anchor present the anchor is still retried each cycle.
		assert_eq!(s.next_choice(true, true), ExitChoice::Anchor);
		assert_eq!(s.next_choice(true, true), ExitChoice::Auto);
	}

	#[test]
	fn parse_anchor_disables_on_empty_or_garbage() {
		assert!(parse_anchor("").is_none());
		assert!(parse_anchor("   ").is_none());
		assert!(parse_anchor("placeholder").is_none());
		assert!(parse_anchor("not.a@recipient").is_none());
		// A dead-but-well-formed anchor is exercised end to end by the
		// connect_timing harness instead (needs a live mixnet).
	}
}
