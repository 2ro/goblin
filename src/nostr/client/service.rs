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

//! Background service loop: relay connect/redial, identity publish,
//! the guarded ingest of channel and gift-wrap events, expiry reconcile
//! and receipt/proof delivery.

use super::*;

impl NostrService {
	/// Auto-expire stale pending transactions after the configured window
	/// (`NostrConfig::expiry_secs`, default 24h). A transaction that never
	/// completed is canceled/expired:
	/// - Outgoing sends and invoices we paid LOCK our outputs, so they are
	///   cancelled at the wallet level (reusing GRIM's `cancel_tx` via
	///   `WalletTask::Cancel`) to release those funds.
	/// - Incoming payments and invoices we issued lock nothing of ours, so we
	///   only annotate the metadata `Cancelled`; if a payment posts late,
	///   on-chain confirmation still wins (the UI only shows "canceled" while
	///   unconfirmed).
	/// - Pending incoming requests become `Expired`.
	///
	/// Runs from the wallet sync loop, so a lowered `expiry_secs` (set in
	/// `nostr.toml` for testing) takes effect within a sync cycle.
	pub fn expire_stale(&self, wallet: &Wallet) {
		let now = unix_time();
		let window = self.config.read().expiry_secs();
		if window <= 0 {
			return;
		}

		let stale: Vec<TxNostrMeta> = self
			.store
			.all_tx_meta()
			.into_iter()
			.filter(|m| !expiry_terminal(m.status))
			.filter(|m| now - m.created_at > window)
			.collect();

		if !stale.is_empty() {
			// Map slate uuid → wallet tx id once (public wallet data), so we can
			// cancel the underlying GRIM tx for the funds-locking cases.
			let tx_ids: HashMap<String, u32> = wallet
				.get_data()
				.and_then(|d| d.txs)
				.map(|txs| {
					txs.iter()
						.filter_map(|t| t.data.tx_slate_id.map(|u| (u.to_string(), t.data.id)))
						.collect()
				})
				.unwrap_or_default();

			for meta in stale {
				// Only outgoing sends + invoices we paid lock our outputs.
				if expiry_locks_outputs(meta.direction, meta.status) {
					if let Some(&tx_id) = tx_ids.get(&meta.slate_id) {
						info!(
							"nostr: expiring stale send {} → cancel wallet tx {}",
							meta.slate_id, tx_id
						);
						wallet.task(WalletTask::Cancel(tx_id));
					}
				} else {
					info!(
						"nostr: expiring stale {} ({:?})",
						meta.slate_id, meta.direction
					);
				}
				self.store
					.update_tx_status(&meta.slate_id, NostrSendStatus::Cancelled);
			}
		}

		// Incoming payment requests we never approved.
		for req in self.store.pending_requests() {
			if now - req.received_at > window {
				info!("nostr: expiring stale incoming request {}", req.rumor_id);
				self.store
					.update_request_status(&req.rumor_id, RequestStatus::Expired);
			}
		}

		// Actually reclaim the disk that terminal rows hold: the requests just
		// flipped to `Expired` above, plus any previously Cancelled/Declined, will
		// never transition again, so delete them. A live PENDING request is never
		// touched — this only removes terminal rows (the disk-DoS bound, F1).
		let pruned = self.store.prune_terminal_requests();
		if pruned > 0 {
			info!("nostr: pruned {pruned} terminal payment-request row(s)");
		}
	}
}

/// Extract a human-readable message from a caught panic payload (F2 logging).
fn panic_message(panic: &(dyn std::any::Any + Send)) -> String {
	if let Some(s) = panic.downcast_ref::<&str>() {
		(*s).to_string()
	} else if let Some(s) = panic.downcast_ref::<String>() {
		s.clone()
	} else {
		"unknown panic".to_string()
	}
}

pub(super) async fn run_service(svc: Arc<NostrService>, wallet: Wallet) {
	// Publish the service runtime handle so worker-thread one-shots (profile
	// lookups) can run their fetches here, where the relay I/O actually lives.
	*svc.rt_handle.write() = Some(tokio::runtime::Handle::current());
	// Mirror the configured name authority so resolution + display follow it.
	crate::nostr::nip05::set_home_domain(&svc.config.read().home_domain());

	// Resolve THIS wallet's transport choice and mirror it into the process-global
	// so free-function HTTP callers (NIP-05, price, pool) take the matching path.
	// `None` (every legacy nostr.toml) resolves to Tor ON — upgraders keep Tor.
	let over_tor = svc.config.read().tor_enabled();
	crate::tor::set_route_over_tor(over_tor);

	// One relay pool serves the whole wallet; its transport is fixed when the
	// Client is built. Pick Tor vs clearnet from the wallet setting. A settings
	// toggle calls restart(), which re-enters here and rebuilds on the new choice.
	//
	// Opportunistic NIP-42 auto-auth (invisible, never a requirement):
	// `automatic_authentication(true)` makes the pool answer a relay's AUTH
	// challenge automatically — and ONLY when a relay actually challenges. The
	// flow the SDK runs (nostr-relay-pool 0.44, relay/inner.rs): on a
	// `RelayMessage::Auth { challenge }` it signs a kind-22242 auth event with the
	// client signer (the active identity below), sends it, then re-issues the
	// pending REQ on OK. A relay that never challenges (every public relay today,
	// including the current floonet relay) is read openly exactly as before — the
	// wallet never forces auth and never refuses a non-challenging relay, so this
	// is INERT until the recipient-only-reads strfry fork ships and starts
	// challenging kind-1059 reads. This is a `true` default in the SDK; we set it
	// explicitly so a future default flip can't silently break DM reads on the
	// hardened relay.
	//
	// Multi-identity status: ACTIVE-IDENTITY ONLY. The client is built with a
	// single signer, so auto-auth authenticates the connection as just the active
	// identity's pubkey. The wallet can hold up to 8 identities (`recv`) and the
	// hardened fork accepts up to 8 authed pubkeys per connection, but the SDK
	// signs the challenge with one signer, and a plain switch
	// (`set_active_by_pubkey`) re-points `svc.keys` WITHOUT rebuilding this client,
	// so the authed pubkey only changes on a full service restart(). FULL
	// multi-identity (all held inboxes readable on one shared connection against
	// the fork) would require the wallet to catch the challenge itself: the pool
	// surfaces `RelayPoolNotification::Message { relay_url, RelayMessage::Auth {
	// challenge } }` for every relay, so a future change can, for each held
	// identity in `recv` other than the active one, build+sign
	// `EventBuilder::auth(challenge, relay_url)` and send it to that relay — using
	// the pool's own relay URL so the fork's relay-tag match check passes. Until
	// then, the wallet's all-pubkeys giftwrap REQ would be `restricted:` by the
	// fork for the non-active `#p` recipients; on today's non-challenging relays it
	// is unaffected.
	let mut builder = Client::builder()
		.signer(svc.keys.read().clone())
		.opts(ClientOptions::new().automatic_authentication(true));
	builder = if over_tor {
		builder.websocket_transport(TorWebSocketTransport)
	} else {
		builder.websocket_transport(ClearnetWebSocketTransport)
	};
	let client = builder.build();
	// Tor wallets: wait for the embedded Tor client before any network work (relay
	// dials, pool refresh, NIP-11 probes). `warm_up()` starts it at launch, but a
	// fast wallet-open can beat the cold Tor bootstrap — and dialing before it's up
	// drops every relay into nostr-sdk's backing-off reconnect, leaving the wallet
	// on "Connecting…" long after Tor is actually ready. Once it's bootstrapped
	// this returns immediately. Clearnet wallets skip the wait entirely.
	if over_tor {
		for i in 0..240u32 {
			if crate::tor::is_ready() {
				if i > 0 {
					info!("nostr: Tor ready after ~{}ms, dialing relays", i * 500);
				}
				break;
			}
			tokio::time::sleep(Duration::from_millis(500)).await;
		}
	}
	// We are now a relay consumer (API parity with the old transport; inert under
	// Tor, which manages its own circuit health). Disarmed when the loop exits.
	crate::tor::set_relay_consumer(true);
	// Refresh the relay candidate pool cache (gist over Tor) when stale.
	tokio::spawn(crate::nostr::pool::refresh_if_stale());
	// Select this identity's advertised relay set if it hasn't one yet.
	ensure_advertised_set(&svc).await;

	let relays = svc.relays();
	info!(
		"nostr: starting service for {} with relays {:?}",
		svc.npub(),
		relays
	);
	// (No DNS prewarm here: arti resolves relay and
	// HTTP hostnames internally as part of the circuit dial — there is no
	// separate in-tunnel DoT round trip to warm. The node host was never on this
	// path and still isn't — it never rides the private transport.)
	for relay in &relays {
		if let Err(e) = client.add_relay(relay.clone()).await {
			warn!("nostr: add relay {relay} failed: {e}");
		}
	}
	// The transport generation these relays are being dialed on. With Tor this is
	// stable (arti rebuilds circuits transparently), so the reselect-driven
	// re-dial below simply never fires — the status loop still re-checks liveness.
	let mut dial_gen = crate::tor::tunnel_generation();
	let connect_started = std::time::Instant::now();
	client.connect().await;
	{
		let mut w_client = svc.client.write();
		*w_client = Some(client.clone());
	}

	// Log when the first relay reaches Connected over Tor, measured from
	// the connect() call. Non-blocking; exits on first success.
	{
		let client_probe = client.clone();
		let svc_probe = svc.clone();
		let report_gen = dial_gen;
		tokio::spawn(async move {
			loop {
				tokio::time::sleep(Duration::from_millis(250)).await;
				if relays_connected(&client_probe).await {
					info!(
						"nostr: first relay Connected ~{}ms after connect()",
						connect_started.elapsed().as_millis()
					);
					// Flip the UI "Connected" flag on the REAL relay-up signal
					// (~2-4s over the exit) instead of gating it behind
					// publish_identity + the up-to-30s catch-up fetch below: those are
					// receive-side housekeeping and keep running in the background,
					// while the relay is already usable the moment it reaches
					// Connected. Without this, one relay slow to EOSE pinned the
					// indicator on "Connecting relays…" for ~30s even though the
					// connection was live in ~2-4s.
					//
					// Accepted tradeoff: between here and the 2s status loop taking
					// over, a relay DROP wouldn't flip the flag back for up to ~30s
					// (until the post-catch-up re-check re-syncs it to reality) — the
					// same-order staleness as the old pessimistic gap, just optimistic
					// instead. The relay-gated readiness signal still tracks real relay
					// health independently of this UI flag.
					svc_probe.connected.store(true, Ordering::Relaxed);
					// FAST relay-live report: closes the relay-readiness
					// window as soon as the exit is proven to carry relay traffic,
					// independent of the up-to-30s catch-up fetch below (a slow
					// catch-up must not get a good exit wrongly condemned).
					crate::tor::report_relay_live(report_gen);
					return;
				}
				if svc_probe.shutdown.load(Ordering::SeqCst)
					|| connect_started.elapsed() > Duration::from_secs(150)
				{
					warn!(
						"nostr: no relay Connected within {}ms of connect()",
						connect_started.elapsed().as_millis()
					);
					return;
				}
			}
		});
	}

	// Publish identity events (kind 10050 DM relays; kind 0 only when named).
	publish_identity(&svc, &client).await;

	// Catch-up + live subscription for our gift wraps — targeted at our OWN
	// advertised set only. A pool-wide subscription would be inherited by
	// relays added later for sends and discovery fan-out, handing them a REQ
	// filter that names our pubkey as a listener.
	// Catch up from the wallet's last connection (all held identities listen
	// continuously, so there is nothing identity-specific to catch up — the whole
	// wallet was offline together). The generous lookback bounds re-fetch; the
	// relay retention window is the real bound.
	let since = svc
		.store
		.last_connected_at()
		.map(|t| t - LOOKBACK_SECS)
		.unwrap_or_else(|| unix_time() - LOOKBACK_SECS)
		.max(0) as u64;
	// One subscription for gift wraps addressed to ANY held identity: a single
	// filter with all our pubkeys (OR over #p). Each wrap is p-tagged to exactly
	// one identity, so it arrives once and is handled once — dedup stays exactly
	// as safe as the single-identity path (no concurrent processing).
	let filter = Filter::new()
		.kind(Kind::GiftWrap)
		.pubkeys(svc.recv_pubkeys())
		.since(Timestamp::from_secs(since));

	// News feed: the owner's kind-30023 long-form posts on our own relay set.
	// Kept owned like `filter` for the re-subscribe after a tunnel reselect.
	let news_pk = PublicKey::from_bech32(NEWS_NPUB).ok();
	let news_filter = news_pk.map(|pk| {
		Filter::new()
			.kind(Kind::LongFormTextNote)
			.author(pk)
			.limit(18)
	});

	if let Ok(events) = client
		.fetch_events_from(&relays, filter.clone(), FETCH_TIMEOUT)
		.await
	{
		info!("nostr: catch-up fetched {} wraps", events.len());
		for event in events.into_iter() {
			handle_wrap(&svc, &wallet, event).await;
		}
	}
	if let (Some(pk), Some(nf)) = (news_pk, news_filter.clone())
		&& let Ok(events) = client.fetch_events_from(&relays, nf, FETCH_TIMEOUT).await
	{
		for event in events.into_iter() {
			handle_news(&svc, pk, event).await;
		}
	}
	// Stable-id subscription so a re-subscribe after a tunnel reselect replaces
	// rather than duplicates it. Keep `filter` owned for that re-subscribe.
	if let Err(e) = client
		.subscribe_with_id_to(
			&relays,
			SubscriptionId::new(GIFTWRAP_SUB),
			filter.clone(),
			None,
		)
		.await
	{
		error!("nostr: subscribe failed: {e}");
	}
	if let Some(nf) = news_filter.clone()
		&& let Err(e) = client
			.subscribe_with_id_to(&relays, SubscriptionId::new(NEWS_SUB), nf, None)
			.await
	{
		error!("nostr: news subscribe failed: {e}");
	}

	// Re-dispatch pending outgoing messages after restart.
	reconcile(&svc, &wallet).await;

	// Backfill @usernames for contacts we only know by npub (e.g. from before
	// this resolved on every interaction), so activity shows names not keys.
	for contact in svc.store.all_contacts() {
		if contact.nip05.is_none() || contact.nip05_verified_at.is_none() {
			svc.resolve_contact_identity(&contact.npub);
		}
	}

	svc.store.set_last_connected_at(unix_time());
	svc.store.prune_processed();

	// Reflect the connection the moment we reach the loop instead of leaving the
	// UI on "Connecting…" until the first heartbeat — by now catch-up has run, so
	// a relay is typically already up.
	let connected = relays_connected(&client).await;
	svc.connected.store(connected, Ordering::Relaxed);
	// Feed the relay-gated readiness signal so "Connected over Tor" reflects an
	// actual connected+subscribed relay on THIS tunnel generation, not merely a
	// warm tunnel — and so the relay-readiness window closes successfully.
	if connected {
		crate::tor::report_relay_live(dial_gen);
	}

	let mut notifications = client.notifications();
	// Poll connection state on a SHORT, INDEPENDENT interval. This used to live in
	// the `select!` behind a `sleep(30s)` that restarted on every notification, so
	// the flag could lag the real relay state by 30s+ (or, under steady event
	// flow, never update) — that's the "stuck on Connecting…" Tor gets
	// blamed for, even though a relay handshake over Tor takes ~2s. An `interval`
	// fires on its own schedule regardless of notifications; the heavier heartbeat
	// work (persisting last-seen, TTL pruning) stays on a ~30s cadence.
	let mut status_tick = tokio::time::interval(Duration::from_secs(2));
	status_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
	let mut last_heartbeat = unix_time();
	let mut last_prune = unix_time();
	// Seed from the persisted sweep time, NOT now: a fresh launch should re-check
	// names right away (so you see refreshed info from app open), unless one ran
	// within the last interval.
	let mut last_name_sweep = svc.store.last_name_sweep_at().unwrap_or(0);
	// Tracks the app foreground state so a background→foreground transition drains
	// any session-channel requests queued on the relay while the wallet slept.
	let mut was_foreground = crate::app_foreground();
	loop {
		if svc.shutdown.load(Ordering::SeqCst) || !wallet.is_open() {
			break;
		}
		tokio::select! {
			notification = notifications.recv() => {
				match notification {
					Ok(RelayPoolNotification::Event { event, .. }) => {
						// Isolate each per-event handler in catch_unwind (F2): a panic in
						// ONE event (a malformed wrap, a parser edge) must not unwind out
						// of the runtime and kill the service thread — which would leave
						// `started` stuck true (so restart() would hang forever) and let
						// the next-launch catch-up re-run the same event and re-panic (a
						// self-reinforcing brick). The happy path is unchanged: the
						// handler still runs to completion inline, in order, on this
						// runtime. (Effective only where panics unwind — desktop/dev
						// builds; the Android APK profile is panic=abort, where the drop
						// guard on the service thread is the remaining safeguard.)
						let ev_id_hex = event.id.to_hex();
						let svc_ref = &svc;
						let wallet_ref = &wallet;
						let client_ref = &client;
						let dispatch = std::panic::AssertUnwindSafe(async move {
							// News long-form posts, session-channel envelopes, and gift
							// wraps ride the same feed; route by kind.
							if event.kind.as_u16() == crate::nostr::session::CHANNEL_EVENT_KIND {
								handle_channel(svc_ref, client_ref, &event).await;
							} else if let Some(pk) = news_pk && event.kind == Kind::LongFormTextNote {
								handle_news(svc_ref, pk, *event).await;
							} else {
								handle_wrap(svc_ref, wallet_ref, *event).await;
							}
						});
						if let Err(panic) = futures::FutureExt::catch_unwind(dispatch).await {
							error!(
								"nostr: event handler panicked ({}); skipping event {} to keep the service alive",
								panic_message(&panic),
								ev_id_hex
							);
							// Poison-pill guard: record the offending event as processed so
							// a reliably-panicking event is not retried forever by catch-up.
							// Only reached AFTER an actual panic, so a legitimate event is
							// never pre-skipped.
							svc.store.mark_processed(&ev_id_hex);
						}
					}
					Ok(_) => {}
					Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
						warn!("nostr: notifications lagged by {n}");
					}
					Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
				}
			}
			_ = status_tick.tick() => {
				// A tunnel reselect (new exit) bumps the generation. The current
				// relay sockets rode the now-dead exit, so drop them and re-dial
				// through the fresh tunnel, re-establishing the kind:1059
				// subscription — a reselect thus transparently restores
				// receive+send. (An individual relay bounce with the exit still
				// healthy is left to nostr-sdk's own auto-reconnect + resubscribe.)
				let generation = crate::tor::tunnel_generation();
				if generation != dial_gen {
					info!("nostr: tunnel reselected (gen {dial_gen} -> {generation}); re-dialing relays over the new exit");
					redial_on_new_tunnel(&client, &relays, &filter, news_filter.as_ref()).await;
					dial_gen = generation;
				}
				let connected = relays_connected(&client).await;
				svc.connected.store(connected, Ordering::Relaxed);
				// Relay-gated readiness + exit-health feedback for THIS generation:
				// a live relay closes/keeps-open the readiness window; all
				// relays down for too long condemns the exit and reselects.
				if connected {
					crate::tor::report_relay_live(dial_gen);
				} else {
					crate::tor::report_relay_down(dial_gen);
				}
				let now = unix_time();
				if now - last_heartbeat >= 30 {
					last_heartbeat = now;
					svc.store.set_last_connected_at(now);
					if now - last_prune >= 3600 {
						svc.store.prune_processed();
						last_prune = now;
					}
				}
				// Re-validate cached @usernames so a released/reassigned name
				// stops showing. Only the stalest few per sweep (capped) to bound
				// Tor lookups; each worker re-checks against the identity server.
				// Skipped while the app is backgrounded — no point spending Tor
				// round-trips when nobody's looking. We DON'T advance last_name_sweep
				// in that case, so the very next foreground tick runs the sweep
				// immediately to catch up on resume.
				if now - last_name_sweep >= NAME_REVERIFY_INTERVAL_SECS && crate::app_foreground() {
					last_name_sweep = now;
					svc.store.set_last_name_sweep_at(now);
					let mut due: Vec<_> = svc
						.store
						.all_contacts()
						.into_iter()
						.filter(|c| {
							c.nip05.is_some()
								&& c.nip05_verified_at
									.map(|at| now - at >= NAME_REVERIFY_INTERVAL_SECS)
									.unwrap_or(true)
						})
						.collect();
					// Stalest first (oldest verification), so a big list rolls through.
					due.sort_by_key(|c| c.nip05_verified_at.unwrap_or(0));
					for c in due.into_iter().take(NAME_REVERIFY_MAX_PER_TICK) {
						svc.resolve_contact_identity(&c.npub);
					}
				}
				// Authorize Sessions (v2): when the session set changed, re-subscribe
				// the encrypted channel and publish `session-open` for new sessions;
				// then sign/decline any money-tier prompts the user answered.
				if svc.has_sessions() {
					sweep_expired_sessions(&svc, &client).await;
				}
				if svc.sessions_dirty.swap(false, Ordering::SeqCst) {
					resubscribe_channel(&client, &svc).await;
					announce_new_sessions(&svc, &client).await;
				}
				serve_money_answers(&svc, &client).await;
				// Drain requests queued while backgrounded on a resume (the Build-95
				// frame-heartbeat pattern), gated on the app being foregrounded.
				let fg = crate::app_foreground();
				if fg && !was_foreground && svc.has_sessions() {
					drain_channel(&svc, &client).await;
				}
				was_foreground = fg;
			}
		}
	}

	// No longer a relay consumer: disarm relay-reachability governance so the
	// idle tunnel isn't condemned for "no relay" once we stop dialing.
	crate::tor::set_relay_consumer(false);
	{
		let mut w_client = svc.client.write();
		*w_client = None;
	}
	client.disconnect().await;
}

/// Add + dial every relay in `urls` so a targeted send reaches relays we don't
/// already hold (NIP-65/gossip: the recipient's relays may differ from ours).
/// `add_relay` is idempotent and `try_connect_relay` returns once connected or
/// the timeout lapses; dialed concurrently so a slow relay doesn't stall the rest.
pub(super) async fn connect_relays(client: &Client, urls: &[String]) {
	let dials = urls.iter().map(|url| {
		let url = url.clone();
		async move {
			let _ = client.add_relay(&url).await;
			// Short cap: a reachable relay connects in ~2-4s over Tor; we
			// don't want one dead relay in the list to stall the whole send. Once
			// connected it stays connected, so only the first send pays this.
			let _ = client.try_connect_relay(&url, Duration::from_secs(6)).await;
		}
	});
	futures::future::join_all(dials).await;
}

/// A tunnel reselect happened: the pool's relay sockets rode the now-dead exit.
/// Drop them and re-dial every required relay through the fresh tunnel, then
/// re-establish the kind:1059 gift-wrap subscription (same stable id → replaces,
/// never duplicates) so we never silently stop receiving. Bounded by
/// nostr-sdk's own connect timeouts — no busy loop; the generation-aware re-dial
/// is ours, the per-relay reconnect backoff is the pool's.
async fn redial_on_new_tunnel(
	client: &Client,
	relays: &[String],
	filter: &Filter,
	news_filter: Option<&Filter>,
) {
	// Close the stale sockets so nostr-sdk re-dials through the current tunnel
	// (the transport grabs the freshly-selected exit on each new connect).
	client.disconnect().await;
	for url in relays {
		let _ = client.add_relay(url).await;
	}
	client.connect().await;
	if let Err(e) = client
		.subscribe_with_id_to(
			relays,
			SubscriptionId::new(GIFTWRAP_SUB),
			filter.clone(),
			None,
		)
		.await
	{
		error!("nostr: re-subscribe after reselect failed: {e}");
	}
	if let Some(nf) = news_filter
		&& let Err(e) = client
			.subscribe_with_id_to(relays, SubscriptionId::new(NEWS_SUB), nf.clone(), None)
			.await
	{
		error!("nostr: news re-subscribe after reselect failed: {e}");
	}
}

/// True when at least one relay has completed its handshake.
async fn relays_connected(client: &Client) -> bool {
	client
		.relays()
		.await
		.values()
		.any(|r| r.status() == RelayStatus::Connected)
}

/// One-time CLEARNET advertised-set selection: the Goblin relay plus up to two
/// pool "dm" relays, weighted-random (vetted entries 3:1), each gated by a NIP-11
/// probe at pick time so only relays about to be used are probed. Persisted
/// on the identity and sticky thereafter — no timer rotation, since 10050
/// churn breaks payers' cached routing. A user relay override in nostr.toml
/// disables selection entirely. When no pool relay passes (e.g. offline),
/// nothing is persisted and the built-in defaults serve this session;
/// selection retries next start.
///
/// Only runs on CLEARNET: on Tor every identity uses the fixed [`TOR_RELAYS`]
/// set (per-user-tor §4), so there is nothing to select — and we must NOT touch
/// the identity's persisted clearnet `dm_relays` subset (it stays stable so a
/// switch back to clearnet keeps the same per-identity relays).
async fn ensure_advertised_set(svc: &Arc<NostrService>) {
	use crate::nostr::pool;
	use crate::nostr::relays::DEFAULT_RELAYS;
	use rand::Rng;
	if svc.tor_routing() {
		return;
	}
	if svc.config.read().relays_override(false).is_some()
		|| !svc.identity.read().dm_relays.is_empty()
	{
		return;
	}
	let goblin = DEFAULT_RELAYS[0];
	let candidates = pool::load().dm_relays();
	let order = pool::weighted_order(goblin, &candidates, |total| {
		rand::rng().random_range(0..total.max(1))
	});
	let mut set = vec![goblin.to_string()];
	for url in order.into_iter().skip(1) {
		if set.len() >= MAX_DM_RELAYS {
			break;
		}
		if pool::probe(&url).await {
			set.push(url);
		}
	}
	if set.len() < 2 {
		warn!("nostr: no pool relay passed vetting, keeping default relays for now");
		return;
	}
	info!("nostr: selected advertised relay set {:?}", set);
	svc.identity.write().dm_relays = set;
	svc.save_identity();
}

/// Publish the replaceable identity events — the kind 10050 DM relay list,
/// its kind 10002 (NIP-65) mirror, and kind 0 metadata for named identities —
/// to the advertised set, then fan the SAME events out to the pool's
/// discovery indexers so payers who share no relay with us can still find our
/// inbox list. The fan-out is additive and publish-only: we never subscribe
/// on discovery relays.
pub(super) async fn publish_identity(svc: &Arc<NostrService>, client: &Client) {
	let advertised: Vec<String> = svc.relays().into_iter().take(MAX_DM_RELAYS).collect();
	let allow_requests = svc.config.read().allow_incoming_requests();

	// Publish the DM-relay list (kind 10050 + NIP-65) for EVERY held identity, and
	// a kind-0 profile for each named one, so senders can route to any of them —
	// all listen on this shared advertised set. Each event is signed with ITS OWN
	// identity key (not the active one), and all are collected for the discovery
	// fan-out below.
	let mut events = vec![];
	for h in svc.recv_snapshot() {
		let mut dm_tags: Vec<Tag> = advertised
			.iter()
			.map(|r| Tag::custom(TagKind::custom("relay"), [r.clone()]))
			.collect();
		// NIP-17 backward-compat extension: advertise our NIP-44 capabilities,
		// space-separated best-first, so v3-aware senders pick v3 (G4).
		dm_tags.push(Tag::custom(
			TagKind::custom("encryption"),
			[wrapv3::ENCRYPTION_CAPABILITY.to_string()],
		));
		let mut builders = vec![
			EventBuilder::new(Kind::InboxRelays, "").tags(dm_tags),
			// The NIP-65 list mirrors the same set, unmarked (read + write).
			EventBuilder::relay_list(
				advertised
					.iter()
					.filter_map(|r| nostr_sdk::RelayUrl::parse(r).ok())
					.map(|u| (u, None)),
			),
		];
		if !h.identity.anonymous {
			if let Some(nip05) = h.identity.nip05.clone() {
				let name = nip05.split('@').next().unwrap_or_default().to_string();
				let metadata = Metadata::new()
					.name(name)
					.nip05(nip05)
					.custom_field("goblin_accepts_requests", allow_requests);
				builders.push(EventBuilder::metadata(&metadata));
			}
		}
		for builder in builders {
			// Sign with THIS identity's key so each advertisement is authored by the
			// identity it describes.
			let event = match builder.sign_with_keys(&h.keys) {
				Ok(event) => event,
				Err(e) => {
					warn!("nostr: identity event signing failed: {e}");
					continue;
				}
			};
			// Time-box each publish (mirrors dispatch_dm's SEND_TIMEOUT) so a stalled
			// relay never delays incoming-message delivery; warn and move on.
			match tokio::time::timeout(SEND_TIMEOUT, client.send_event_to(&advertised, &event))
				.await
			{
				Ok(Ok(_)) => {}
				Ok(Err(e)) => warn!("nostr: publish kind {} failed: {e}", event.kind),
				Err(_) => warn!("nostr: publish kind {} timed out", event.kind),
			}
			events.push(event);
		}
	}

	// Discovery fan-out off the caller's path: each indexer is gated by the
	// lazy NIP-11 probe (over Tor) before use.
	let client = client.clone();
	tokio::spawn(async move {
		let targets: Vec<String> = crate::nostr::pool::usable_discovery_relays()
			.await
			.into_iter()
			.filter(|u| !advertised.contains(u))
			.collect();
		if targets.is_empty() {
			return;
		}
		connect_relays(&client, &targets).await;
		for event in &events {
			if let Err(e) = client.send_event_to(&targets, event).await {
				warn!("nostr: discovery publish kind {} failed: {e}", event.kind);
			}
		}
	});
}

/// A transaction in a terminal state never expires (already done or canceled).
fn expiry_terminal(status: NostrSendStatus) -> bool {
	matches!(
		status,
		NostrSendStatus::Finalized | NostrSendStatus::Cancelled
	)
}

/// Whether an expired transaction with this (direction, status) locked OUR
/// outputs and therefore needs a wallet-level `cancel_tx` to release them
/// (outgoing sends and invoices we paid). Incoming payments and invoices we
/// issued lock nothing of ours, so those are only annotated as canceled.
fn expiry_locks_outputs(direction: NostrTxDirection, status: NostrSendStatus) -> bool {
	matches!(
		(direction, status),
		(NostrTxDirection::Sent, NostrSendStatus::Created)
			| (NostrTxDirection::Sent, NostrSendStatus::AwaitingS2)
			| (NostrTxDirection::Sent, NostrSendStatus::SendFailed)
			| (
				NostrTxDirection::RequestedOfUs,
				NostrSendStatus::PaidAwaitingFinalize
			)
	)
}

/// Whether the plain "payment sent" receipt (frozen contract 4.3.1) still owes a
/// (re)publish for this tx. True for a proof-mode SEND whose payment envelope has
/// been accepted by a relay (status past `Created`, the UI has flipped to
/// "sent") but whose receipt has not landed yet. This is the crash/offline retry
/// gate: the receipt normally publishes inline at dispatch, and this catches the
/// case where that publish failed or the process crashed after dispatch. Once
/// `receipt_sent` flips, it is never republished: the one-receipt-per-tx guard.
fn receipt_retry_due(meta: &TxNostrMeta) -> bool {
	meta.direction == NostrTxDirection::Sent
		&& meta.proof_mode
		&& !meta.receipt_sent
		&& matches!(
			meta.status,
			NostrSendStatus::AwaitingS2 | NostrSendStatus::Finalized
		)
}

/// Whether the encrypted proof delivery (frozen contract 4.3.2) still owes a
/// (re)publish for this tx. True only for a FINALIZED proof-mode SEND whose proof
/// delivery has not landed: the proof does not exist before finalize, so unlike
/// the receipt it is never attempted at dispatch.
fn proof_delivery_due(meta: &TxNostrMeta) -> bool {
	meta.direction == NostrTxDirection::Sent
		&& meta.status == NostrSendStatus::Finalized
		&& meta.proof_mode
		&& !meta.proof_delivered
}

/// Publish the plain "payment sent" receipt for a dispatched proof-mode send and,
/// on success, flip `receipt_sent` so it is never republished. Retry-safe: driven
/// from the reconcile pass whenever [`receipt_retry_due`] holds.
async fn deliver_receipt(svc: &Arc<NostrService>, meta: &TxNostrMeta) {
	let Some(order) = meta.proof_order.clone() else {
		return;
	};
	let amount = meta.proof_amount.unwrap_or(0);
	match svc.publish_receipt_sent(&order, amount).await {
		Ok(()) => {
			let mut updated = meta.clone();
			updated.receipt_sent = true;
			updated.updated_at = unix_time();
			svc.store.save_tx_meta(&updated);
		}
		Err(e) => warn!(
			"nostr: reconcile receipt publish failed for {}: {e}",
			meta.slate_id
		),
	}
}

/// Deliver the encrypted proof-on-request artifact for a finalized SEND (frozen
/// contract 4.3.2): the gift-wrapped proof to the watcher's npub. The plain
/// "payment sent" receipt is deliberately NOT published here; it already went
/// out at S1 dispatch (4.3.1), gated by `receipt_sent`, so exactly one receipt
/// exists per tx and finalize never duplicates it. Idempotent/retry-safe (the
/// watcher dedupes its inputs), so it is driven from both the finalize task and
/// the reconcile pass. Returns true when the required delivery for this context
/// landed, so the caller can set `proof_delivered` and stop retrying.
async fn deliver_proof(svc: &Arc<NostrService>, wallet: &Wallet, meta: &TxNostrMeta) -> bool {
	// No watcher target (4.1) => nothing to encrypt. The dispatch receipt was the
	// whole job; treat as done so the reconcile pass stops retrying.
	let Some(notify) = meta.proof_notify.clone() else {
		return true;
	};
	let Some(order) = meta.proof_order.clone() else {
		// No order handle => no `payment-request` routing key the watcher can match.
		warn!(
			"nostr: proof mode without order handle for {}, skipping proof delivery",
			meta.slate_id
		);
		return true;
	};
	let amount = meta.proof_amount.unwrap_or(0);
	let Ok(slate_id) = uuid::Uuid::parse_str(&meta.slate_id) else {
		return false;
	};
	match wallet.payment_proof_delivery(slate_id) {
		Some((json, kernel_hex)) => {
			match svc
				.deliver_proof_wrap(&notify, &order, amount, &kernel_hex, &json)
				.await
			{
				Ok(()) => true,
				Err(e) => {
					warn!("nostr: proof delivery failed for {}: {e}", meta.slate_id);
					false
				}
			}
		}
		None => {
			warn!(
				"nostr: no payment proof retrievable yet for {}",
				meta.slate_id
			);
			false
		}
	}
}

/// Re-dispatch our pending outgoing messages (crash/offline recovery).
async fn reconcile(svc: &Arc<NostrService>, wallet: &Wallet) {
	let now = unix_time();
	for meta in svc.store.all_tx_meta() {
		if now - meta.created_at > RESEND_WINDOW_SECS {
			continue;
		}
		// Receipt retry (frozen contract 4.3.1): the plain "payment sent" receipt
		// normally publishes inline at dispatch, the moment the UI flips to "sent".
		// This catches the crash/offline case where that publish failed. Retried
		// every pass until `receipt_sent` flips, and independent of the proof
		// delivery below: the receipt closes the buyer's double-send window at
		// "sent", the proof waits for finalize. A Finalized tx can owe both, so this
		// does NOT `continue`; it falls through to the proof block.
		if receipt_retry_due(&meta) {
			deliver_receipt(svc, &meta).await;
		}
		// Proof-on-request delivery retry (frozen contract 4.3.2, W4): a finalized
		// send in proof mode whose encrypted proof delivery has not landed yet.
		// Retried on every reconcile pass until `proof_delivered` flips.
		if proof_delivery_due(&meta) {
			// Re-read: deliver_receipt above may have flipped receipt_sent on disk.
			let meta = svc.store.tx_meta(&meta.slate_id).unwrap_or(meta);
			if deliver_proof(svc, wallet, &meta).await {
				let mut updated = meta.clone();
				updated.proof_delivered = true;
				updated.updated_at = unix_time();
				svc.store.save_tx_meta(&updated);
			}
			continue;
		}
		let resend_state = match (meta.direction, meta.status) {
			// S1 never dispatched or failed.
			(NostrTxDirection::Sent, NostrSendStatus::Created)
			| (NostrTxDirection::Sent, NostrSendStatus::SendFailed) => {
				Some(grin_wallet_libwallet::SlateState::Standard1)
			}
			// I1 request never dispatched or failed.
			(NostrTxDirection::RequestedByUs, NostrSendStatus::Created)
			| (NostrTxDirection::RequestedByUs, NostrSendStatus::SendFailed) => {
				Some(grin_wallet_libwallet::SlateState::Invoice1)
			}
			// We received and processed S1 but the S2 reply may not have left.
			(NostrTxDirection::Received, NostrSendStatus::ReceivedNoReply) => {
				Some(grin_wallet_libwallet::SlateState::Standard2)
			}
			// We paid a request (I2) but the reply may not have left.
			(NostrTxDirection::RequestedOfUs, NostrSendStatus::ReceivedNoReply) => {
				Some(grin_wallet_libwallet::SlateState::Invoice2)
			}
			_ => None,
		};
		let Some(state) = resend_state else { continue };
		let Ok(slate_id) = uuid::Uuid::parse_str(&meta.slate_id) else {
			continue;
		};
		let Some(text) = wallet.read_slatepack_text(slate_id, &state) else {
			continue;
		};
		info!(
			"nostr: reconcile re-dispatch {} ({:?})",
			meta.slate_id, state
		);
		match svc
			.send_payment_dm(&meta.npub, &text, meta.note.as_deref(), &[])
			.await
		{
			Ok(event_id) => {
				let mut updated = meta.clone();
				updated.sent_event_id = Some(event_id);
				updated.status = match state {
					grin_wallet_libwallet::SlateState::Standard1 => NostrSendStatus::AwaitingS2,
					grin_wallet_libwallet::SlateState::Invoice1 => NostrSendStatus::AwaitingI2,
					grin_wallet_libwallet::SlateState::Standard2 => NostrSendStatus::RepliedS2,
					_ => NostrSendStatus::PaidAwaitingFinalize,
				};
				updated.updated_at = unix_time();
				svc.store.save_tx_meta(&updated);
			}
			Err(e) => warn!(
				"nostr: reconcile dispatch failed for {}: {e}",
				meta.slate_id
			),
		}
	}
}

/// Full guarded pipeline for one incoming gift wrap event.
/// Apply a request-void control message. Two roles, distinguished by what we
/// hold for `slate_id`; in both the `sender` must match the stored counterparty,
/// so an attacker can't void a request they're not party to.
fn handle_request_void(svc: &Arc<NostrService>, wallet: &Wallet, slate_id: &str, sender: &str) {
	// Role A — we are the payer and the requester withdrew. Drop the pending card.
	let mut voided = false;
	for req in svc.store.pending_requests() {
		if req.slate_id == slate_id && req.npub == sender {
			info!(
				"nostr: incoming request {} withdrawn by requester",
				req.rumor_id
			);
			svc.store
				.update_request_status(&req.rumor_id, RequestStatus::Cancelled);
			svc.has_new_requests.store(true, Ordering::Relaxed);
			voided = true;
		}
	}
	if voided {
		return;
	}
	// The `sender` must match the stored counterparty (binding checked below) so
	// a stranger can't void someone else's tx.
	let Some(meta) = svc.store.tx_meta(slate_id) else {
		return;
	};
	if meta.npub != sender {
		return;
	}
	match (meta.direction, meta.status) {
		// Role B — we are the requester and the payer declined our invoice. An
		// issued invoice locks no outputs of ours, so cancelling the grin tx is
		// safe and keeps the ledger tidy.
		(NostrTxDirection::RequestedByUs, NostrSendStatus::Created)
		| (NostrTxDirection::RequestedByUs, NostrSendStatus::AwaitingI2) => {
			info!("nostr: outgoing request {slate_id} declined by payer");
			if let Some(tx_id) = wallet.get_data().and_then(|d| d.txs).and_then(|txs| {
				txs.iter()
					.find(|t| {
						t.data.tx_slate_id.map(|u| u.to_string()).as_deref() == Some(slate_id)
					})
					.map(|t| t.data.id)
			}) {
				wallet.task(WalletTask::Cancel(tx_id));
			}
			svc.store
				.update_tx_status(slate_id, NostrSendStatus::Cancelled);
		}
		// Role C — we received a payment the SENDER now says is void. Only mark
		// the meta cancelled for display; do NOT cancel the grin tx. Cancelling a
		// received tx DELETES our incoming output from wallet tracking, and a
		// malicious sender could void-then-still-finalize (they hold our S2 once
		// we replied), confirming funds our wallet would no longer see. Leaving
		// the output tracked means it still confirms if they post; if they don't,
		// it simply never confirms (and shows Cancelled while unconfirmed).
		(NostrTxDirection::Received, NostrSendStatus::ReceivedNoReply)
		| (NostrTxDirection::Received, NostrSendStatus::RepliedS2) => {
			info!("nostr: incoming payment {slate_id} voided by sender");
			svc.store
				.update_tx_status(slate_id, NostrSendStatus::Cancelled);
		}
		_ => {}
	}
}

/// First value of the first tag named `name`, if any.
fn first_tag_value(event: &Event, name: &str) -> Option<String> {
	event.tags.iter().find_map(|t| {
		let parts = t.as_slice();
		if parts.first().map(|s| s.as_str()) == Some(name) {
			parts.get(1).cloned()
		} else {
			None
		}
	})
}

/// Serve one Authorize Sessions channel event (kind 24140). Matches it to a
/// live session by the site's channel key, decrypts under the session key,
/// enforces every rule (via the pure `session` core), and either publishes a
/// signed `sign_result` back to the site, enqueues a money-tier prompt for the
/// GUI, or tears the session down on a `session-end` signal. Fails closed and
/// silent on anything it cannot match, decrypt, or parse.
async fn handle_channel(svc: &Arc<NostrService>, client: &Client, event: &Event) {
	use crate::nostr::session::{self, PendingMoney, SignRequest};
	if event.kind.as_u16() != session::CHANNEL_EVENT_KIND || event.verify().is_err() {
		return;
	}
	let now = unix_time() as u64;
	let mut publish: Option<Event> = None;
	let mut money: Option<PendingMoney> = None;
	let mut notice = false;
	let mut decrypt_notice = false;
	let mut ended = false;
	{
		let mut sessions = svc.sessions.write();
		// Origin binding: the only key allowed to request is the site channel key
		// bound at grant time. Nothing else can even open an envelope.
		let Some(s) = sessions
			.iter_mut()
			.find(|s| s.site_session_pubkey == event.pubkey && !s.ended)
		else {
			return;
		};
		let Ok(plaintext) = s.decrypt(&event.pubkey, &event.content) else {
			return;
		};
		if !session::envelope_within_cap(&plaintext) {
			return;
		}
		let Ok(val) = serde_json::from_str::<serde_json::Value>(&plaintext) else {
			return;
		};
		let msg_type = val.get("type").and_then(|t| t.as_str()).map(str::to_string);
		if msg_type.as_deref() == Some("session-end") {
			s.end();
			ended = true;
		} else if matches!(msg_type.as_deref(), Some("sign" | "encrypt" | "decrypt")) {
			// The signing identity's unlocked keys from the in-memory snapshot.
			let keys = svc
				.recv_snapshot()
				.into_iter()
				.find(|h| h.keys.public_key() == s.identity_pubkey)
				.map(|h| h.keys);
			match keys {
				Some(keys) => {
					let (served, op) = match msg_type.as_deref() {
						Some("sign") => match serde_json::from_value::<SignRequest>(val) {
							Ok(req) => (
								session::serve(s, &req, &keys, now),
								Some(session::ChannelOp::Sign(req)),
							),
							Err(_) => return,
						},
						Some("encrypt") => {
							match serde_json::from_value::<session::EncryptRequest>(val) {
								Ok(e) => (
									session::serve_encrypt(s, &e, &keys, now),
									Some(session::ChannelOp::Encrypt(e)),
								),
								Err(_) => return,
							}
						}
						Some("decrypt") => {
							match serde_json::from_value::<session::DecryptRequest>(val) {
								Ok(d) => (session::serve_decrypt(s, &d, &keys, now), None),
								Err(_) => return,
							}
						}
						_ => return,
					};
					notice = served.notify_high_volume;
					decrypt_notice = served.notify_decrypt_volume;
					if served.money_pending {
						if let Some(op) = op {
							money = Some(PendingMoney {
								domain: s.domain.clone(),
								site_session_pubkey: s.site_session_pubkey,
								identity_pubkey: s.identity_pubkey,
								op,
							});
						}
					} else if let Some(json) = served.response {
						publish = s.wrap_channel_event(&json, now).ok();
					}
				}
				None => {
					// Identity no longer held mid-session: answer identity_mismatch
					// so the site fails fast (re-login) instead of waiting out its
					// request timeout.
					if let (Some(op_type), Some(id)) =
						(msg_type.as_deref(), val.get("id").and_then(|i| i.as_str()))
					{
						let json = session::refusal_json(
							op_type,
							id,
							session::SignError::IdentityMismatch,
						);
						publish = s.wrap_channel_event(&json, now).ok();
					}
				}
			}
		}
	}
	if ended {
		svc.sessions.write().retain(|s| !s.ended);
		svc.sessions_dirty.store(true, Ordering::SeqCst);
	}
	// Distinct notices: heavy silent signing vs heavy DM reading (honest wording).
	if decrypt_notice {
		*svc.session_notice.write() = Some("reading".to_string());
	} else if notice {
		*svc.session_notice.write() = Some("signing".to_string());
	}
	if let Some(p) = money {
		svc.money_pending.lock().push(p);
	}
	if let Some(ev) = publish {
		let urls = channel_relays(svc);
		let _ = tokio::time::timeout(SEND_TIMEOUT, client.send_event_to(&urls, &ev)).await;
	}
}

/// Prune sessions past their TTL or idle timeout, sending each site a courtesy
/// `session-end` with reason "expired" so it fails fast to its re-login state
/// instead of timing out request by request. Called from the loop tick.
async fn sweep_expired_sessions(svc: &Arc<NostrService>, client: &Client) {
	let now = unix_time() as u64;
	let mut end_events = Vec::new();
	{
		let mut sessions = svc.sessions.write();
		for s in sessions.iter_mut() {
			if !s.ended && s.is_expired(now) {
				s.end();
				if let Ok(ev) = s.session_end_event(now, "expired") {
					end_events.push(ev);
				}
			}
		}
		if end_events.is_empty() && sessions.iter().all(|s| !s.ended) {
			return;
		}
		sessions.retain(|s| !s.ended);
	}
	svc.sessions_dirty.store(true, Ordering::SeqCst);
	let urls = channel_relays(svc);
	for ev in end_events {
		let _ = tokio::time::timeout(SEND_TIMEOUT, client.send_event_to(&urls, &ev)).await;
	}
}

/// Drain the GUI's answers to money-tier prompts: sign (or decline) each and
/// publish the `sign_result` on its session channel. Called from the loop tick.
async fn serve_money_answers(svc: &Arc<NostrService>, client: &Client) {
	use crate::nostr::session;
	let answers: Vec<(session::PendingMoney, bool)> =
		std::mem::take(&mut *svc.money_answers.lock());
	if answers.is_empty() {
		return;
	}
	let now = unix_time() as u64;
	let snapshot = svc.recv_snapshot();
	for (pending, approved) in answers {
		let mut publish: Option<Event> = None;
		{
			let mut sessions = svc.sessions.write();
			// Route by the session's CHANNEL key, never the display domain: two
			// sessions with a lookalike domain string can never receive each
			// other's approvals.
			if let Some(s) = sessions
				.iter_mut()
				.find(|s| s.site_session_pubkey == pending.site_session_pubkey && !s.ended)
			{
				let keys = snapshot
					.iter()
					.find(|h| h.keys.public_key() == s.identity_pubkey)
					.map(|h| h.keys.clone());
				if let Some(keys) = keys {
					let json = session::complete_money(s, &pending.op, &keys, approved, now);
					publish = s.wrap_channel_event(&json, now).ok();
				}
			}
		}
		if let Some(ev) = publish {
			let urls = channel_relays(svc);
			let _ = tokio::time::timeout(SEND_TIMEOUT, client.send_event_to(&urls, &ev)).await;
		}
	}
}

/// The relays the session channel runs on: the wallet's own configured relays
/// UNION every live session's relay hint, deduplicated. Honouring the site's
/// hint (spec 5.9) while keeping the wallet's own relays as fallback is what lets
/// the wallet and a site meet even when they share no default relay.
fn channel_relays(svc: &Arc<NostrService>) -> Vec<String> {
	let hints: Vec<String> = svc
		.sessions
		.read()
		.iter()
		.filter(|s| !s.ended)
		.flat_map(|s| s.relays.clone())
		.collect();
	dedup_relay_union(svc.relays(), hints)
}

/// Canonical form of a relay URL for identity comparison: trimmed, with a
/// trailing slash dropped and ASCII-lowercased. `RelayUrl` in nostr-sdk 0.44
/// does NOT fold `wss://h` and `wss://h/` (it preserves the path verbatim), so
/// we normalize ourselves. Lets us dedup the wallet's own relays against a
/// site's `r=` hint AND match a publish's `Output.success` set regardless of a
/// trailing-slash or host-case difference. Without this a hint of
/// `wss://relay.floonet.dev/` reads as a different relay than the configured
/// `wss://relay.floonet.dev`, so the union grows a phantom (cold) entry and a
/// hint-relay confirm can never match.
fn canonical_relay(url: &str) -> String {
	url.trim().trim_end_matches('/').to_ascii_lowercase()
}

/// Union `base` (the wallet's own relays) with `hints` (the sessions' relay
/// hints), deduplicated by canonical relay identity, preserving order and the
/// original (un-normalized) spelling of the first occurrence.
fn dedup_relay_union(base: Vec<String>, hints: impl IntoIterator<Item = String>) -> Vec<String> {
	let mut out = base;
	let mut seen: HashSet<String> = out.iter().map(|r| canonical_relay(r)).collect();
	for hint in hints {
		if seen.insert(canonical_relay(&hint)) {
			out.push(hint);
		}
	}
	out
}

/// Max `session-open` publish attempts before the loop gives up re-announcing a
/// session. At the loop's 2s tick this covers a generous window past the GUI's
/// confirm deadline, then stops so a permanently unreachable hint relay can't
/// spin the service for the whole session TTL.
const ANNOUNCE_MAX_ATTEMPTS: u32 = 15;

/// True when a `session-open` publish reached a relay the SITE actually
/// subscribes on: at least one of the session's relay `hints` (the `r=` app
/// relay) appears in the publish `success` set. Confirming on ANY wallet relay
/// is not enough — the site listens only on its own hint, so an accept
/// elsewhere would let the wallet "succeed" while the site never sees the
/// session (the return-to-caller-but-never-logs-in failure). A session with no
/// hint (defensive; grants always carry one) confirms on any accept.
fn announce_confirmed(success: &HashSet<RelayUrl>, hints: &[String]) -> bool {
	if hints.is_empty() {
		return !success.is_empty();
	}
	let accepted: HashSet<String> = success
		.iter()
		.map(|u| canonical_relay(&u.to_string()))
		.collect();
	hints.iter().any(|h| accepted.contains(&canonical_relay(h)))
}

/// Whether the loop should re-arm to publish this session's `session-open`
/// again: only when it has NOT confirmed and the attempt cap is not yet spent.
fn should_reannounce(confirmed: bool, attempts_after: u32) -> bool {
	!confirmed && attempts_after < ANNOUNCE_MAX_ATTEMPTS
}

/// The channel subscription/fetch filter over the live sessions' wallet channel
/// keys, or `None` when there are no sessions. Bounded `since` to the request
/// expiration: anything older has lapsed its NIP-40 expiration anyway.
fn channel_filter(svc: &Arc<NostrService>) -> Option<Filter> {
	let pks: Vec<PublicKey> = svc
		.sessions
		.read()
		.iter()
		.filter(|s| !s.ended)
		.map(|s| s.wallet_channel_pk)
		.collect();
	if pks.is_empty() {
		return None;
	}
	let now = unix_time() as u64;
	let since = now.saturating_sub(crate::nostr::session::REQUEST_EXPIRATION_SECS);
	Some(
		Filter::new()
			.kind(Kind::from(crate::nostr::session::CHANNEL_EVENT_KIND))
			.pubkeys(pks)
			.since(Timestamp::from_secs(since)),
	)
}

/// (Re)subscribe the encrypted session channel over the current session set,
/// dialing any relay hint the wallet is not already connected to first.
async fn resubscribe_channel(client: &Client, svc: &Arc<NostrService>) {
	let relays = channel_relays(svc);
	// `add_relay`/`connect` are idempotent, so re-dialing already-live relays is
	// cheap; this brings up any newly hinted relay.
	connect_relays(client, &relays).await;
	if let Some(filter) = channel_filter(svc)
		&& let Err(e) = client
			.subscribe_with_id_to(&relays, SubscriptionId::new(CHANNEL_SUB), filter, None)
			.await
	{
		warn!("nostr: session-channel subscribe failed: {e}");
	}
}

/// Publish the one-time `session-open` for every session not yet announced, and
/// mark them announced. Called when the session set changes.
async fn announce_new_sessions(svc: &Arc<NostrService>, client: &Client) {
	let now = unix_time() as u64;
	let relays = channel_relays(svc);
	// One session-open per not-yet-confirmed session under the retry cap. Carry
	// each session's relay HINTS so we confirm on the relay the site is actually
	// listening on, not just any wallet relay. We do NOT pre-mark `announced`:
	// it flips true only once a hint relay confirms, so a failed publish is
	// retried on the next dirty tick instead of being lost.
	struct Todo {
		pk_hex: String,
		hints: Vec<String>,
		ev: Event,
	}
	let todo: Vec<Todo> = {
		let sessions = svc.sessions.read();
		sessions
			.iter()
			.filter(|s| !s.announced && !s.ended && s.announce_attempts < ANNOUNCE_MAX_ATTEMPTS)
			.filter_map(|s| {
				s.session_open_event(now).ok().map(|ev| Todo {
					pk_hex: s.wallet_channel_pk.to_hex(),
					hints: s.relays.clone(),
					ev,
				})
			})
			.collect()
	};
	if todo.is_empty() {
		return;
	}
	let mut rearm = false;
	for t in todo {
		// The event's own pubkey IS the wallet channel key (see
		// `session_open_event`). Confirm delivery only when a relay the SITE
		// subscribes on (the hint) accepted it, so the GUI's return-to-caller
		// wait is a real confirmation the site can see, not a queued-and-hoping.
		let confirmed =
			match tokio::time::timeout(SEND_TIMEOUT, client.send_event_to(&relays, &t.ev)).await {
				Ok(Ok(out)) => announce_confirmed(&out.success, &t.hints),
				Ok(Err(e)) => {
					warn!("nostr: session-open publish failed: {e}");
					false
				}
				Err(_) => {
					warn!("nostr: session-open publish timed out");
					false
				}
			};
		// Record the attempt (and confirm, if any) against the live session under
		// a single write lock.
		let attempts_after = {
			let mut sessions = svc.sessions.write();
			match sessions
				.iter_mut()
				.find(|s| s.wallet_channel_pk.to_hex() == t.pk_hex)
			{
				Some(s) => {
					s.announce_attempts = s.announce_attempts.saturating_add(1);
					if confirmed {
						s.announced = true;
					}
					s.announce_attempts
				}
				// Session ended while we published: nothing to retry.
				None => ANNOUNCE_MAX_ATTEMPTS,
			}
		};
		if confirmed {
			svc.announced_ok.write().insert(t.pk_hex);
		} else if should_reannounce(confirmed, attempts_after) {
			rearm = true;
		}
	}
	// A session whose hint relay has not accepted yet stays unconfirmed: re-arm
	// the dirty flag so the next loop tick re-publishes (a cold Tor circuit to
	// the site's relay can outlast a single publish). Bounded by
	// `ANNOUNCE_MAX_ATTEMPTS`.
	if rearm {
		svc.sessions_dirty.store(true, Ordering::SeqCst);
	}
}

/// Drain any channel requests queued on the relay while the wallet was asleep,
/// serving each. Called on a background→foreground transition (the Build-95
/// frame-heartbeat resume pattern) and once at loop start.
async fn drain_channel(svc: &Arc<NostrService>, client: &Client) {
	let Some(filter) = channel_filter(svc) else {
		return;
	};
	let relays = channel_relays(svc);
	if let Ok(events) = client
		.fetch_events_from(&relays, filter, FETCH_TIMEOUT)
		.await
	{
		for ev in events.into_iter() {
			handle_channel(svc, client, &ev).await;
		}
	}
}

/// Ingest one kind-30023 news post from the Goblin news key and cache it (the
/// store dedupes newest-per-`d`). Guards kind + author so a stray event on the
/// news subscription can't spoof the panel.
async fn handle_news(svc: &Arc<NostrService>, news_pk: PublicKey, event: Event) {
	if event.kind != Kind::LongFormTextNote || event.pubkey != news_pk {
		return;
	}
	let d = first_tag_value(&event, "d").unwrap_or_default();
	let title = first_tag_value(&event, "title").unwrap_or_default();
	let summary = news_summary_text(
		first_tag_value(&event, "summary").as_deref(),
		&event.content,
	);
	let lang = news_lang_tag(&event);
	let published_at =
		first_tag_value(&event, "published_at").and_then(|s| s.trim().parse::<i64>().ok());
	svc.store.save_news(NewsItem {
		d,
		created_at: event.created_at.as_secs() as i64,
		title,
		summary,
		lang,
		published_at,
	});
}

/// Detect an article's language from an event tag, if it carries one. Accepts
/// both the NIP-32-style label `["l", "<code>", "ISO-639-1"]` and the bare
/// `["l", "<code>"]` / `["lang", "<code>"]` shapes; in every case the code is
/// the tag's second element. Returns a lower-case ISO 639-1 two-letter code, or
/// `None` (no tag / not a two-letter code) so the data layer falls back to the
/// title-suffix marker, then to English.
fn news_lang_tag(event: &Event) -> Option<String> {
	event.tags.iter().find_map(|t| {
		let parts = t.as_slice();
		let key = parts.first().map(|s| s.as_str())?;
		if key != "l" && key != "lang" {
			return None;
		}
		let code = parts.get(1)?.trim().to_lowercase();
		if code.len() == 2 && code.chars().all(|c| c.is_ascii_alphabetic()) {
			Some(code)
		} else {
			None
		}
	})
}

/// The panel's summary line: the `summary` tag when present, otherwise the first
/// couple of lines of the markdown content flattened to plain text. Capped to a
/// sensible length so the panel stays ~two lines. No markdown is ever rendered.
fn news_summary_text(summary_tag: Option<&str>, content: &str) -> String {
	if let Some(s) = summary_tag {
		let s = s.trim();
		if !s.is_empty() {
			return truncate_summary(s);
		}
	}
	let plain = strip_markdown_inline(content);
	let joined = plain
		.lines()
		.map(|l| l.trim())
		.filter(|l| !l.is_empty())
		.take(2)
		.collect::<Vec<_>>()
		.join(" ");
	truncate_summary(&joined)
}

/// Cap a summary to ~160 chars on a char boundary, adding an ellipsis.
fn truncate_summary(s: &str) -> String {
	const MAX: usize = 160;
	if s.chars().count() <= MAX {
		return s.to_string();
	}
	let head: String = s.chars().take(MAX).collect();
	format!("{}…", head.trim_end())
}

/// Strip inline markdown for the fallback summary: drop image `![alt](url)`
/// entirely, reduce link `[text](url)` to its text, and remove common emphasis /
/// heading markers. Deliberately minimal — the owner usually sets the summary
/// tag, so this only runs as a fallback.
fn strip_markdown_inline(s: &str) -> String {
	let chars: Vec<char> = s.chars().collect();
	let mut out = String::new();
	let mut i = 0;
	while i < chars.len() {
		match chars[i] {
			'!' if chars.get(i + 1) == Some(&'[') => {
				// Image: drop ![alt](url) wholesale.
				i += 2;
				while i < chars.len() && chars[i] != ']' {
					i += 1;
				}
				i += 1; // past ']'
				if chars.get(i) == Some(&'(') {
					while i < chars.len() && chars[i] != ')' {
						i += 1;
					}
					i += 1; // past ')'
				}
			}
			'[' => {
				// Link: keep the text, drop the (url).
				i += 1;
				while i < chars.len() && chars[i] != ']' {
					out.push(chars[i]);
					i += 1;
				}
				i += 1; // past ']'
				if chars.get(i) == Some(&'(') {
					while i < chars.len() && chars[i] != ')' {
						i += 1;
					}
					i += 1; // past ')'
				}
			}
			'#' | '*' | '`' | '>' | '_' => i += 1,
			c => {
				out.push(c);
				i += 1;
			}
		}
	}
	out
}

async fn handle_wrap(svc: &Arc<NostrService>, wallet: &Wallet, event: Event) {
	// 0. Only gift wraps.
	if event.kind != Kind::GiftWrap {
		return;
	}
	let wrap_id = event.id.to_hex();
	// 1. Cheap size cap before any crypto.
	if event.content.len() > protocol::MAX_WRAP_CONTENT {
		svc.store.mark_processed(&wrap_id);
		return;
	}
	// 2. Wrap-level dedupe.
	if svc.store.is_processed(&wrap_id) {
		return;
	}
	// 2.5 Global decrypt ceiling: bound total NIP-44 unwrap work regardless of
	// sender, so fresh-keypair spam can't burn unbounded CPU/battery. Not marked
	// processed — a genuine backlog re-attempts once the window reopens.
	if !svc.allow_global_unwrap() {
		return;
	}
	// 3. Unwrap (NIP-59: seal signature is verified, rumor must not be signed),
	// dispatched on the NIP-44 payload version byte: 0x02 = the unchanged
	// nostr-sdk path, 0x03 = the nip44 crate (G4); anything else errors cleanly.
	//
	// The wallet listens for ALL held identities, so the wrap may be addressed to
	// any of them. Try each held key until one opens it; the key that succeeds is
	// the RECIPIENT identity (the front door this payment came in on). Trying is
	// bounded (a handful of held keys) and only runs for wraps the subscription
	// already restricted to our own pubkeys; the global decrypt ceiling above
	// still bounds total unwrap work against spam.
	let held = svc.recv_snapshot();
	let mut opened: Option<(PublicKey, nostr_sdk::nips::nip59::UnwrappedGift)> = None;
	for h in &held {
		if let Ok(u) = wrapv3::unwrap(&h.keys, &event).await {
			opened = Some((h.keys.public_key(), u));
			break;
		}
	}
	let (recipient_pk, unwrapped) = match opened {
		Some(x) => x,
		None => {
			// Addressed to one of our identities (the filter names only our
			// pubkeys) but no held key opened it — most often a NIP-44 v2/v3
			// negotiation mismatch or a decrypt bug, i.e. potentially a real
			// incoming payment. Do NOT mark processed, so a corrected build can
			// re-attempt on the next catch-up instead of the dedup cache eating it.
			warn!(
				"nostr: gift wrap {wrap_id} addressed to us failed to unwrap with any \
				 held identity; leaving unprocessed for retry"
			);
			return;
		}
	};
	let recipient_hex = recipient_pk.to_hex();
	let sender = unwrapped.sender;
	let mut rumor = unwrapped.rumor;
	// 4. The rumor author must be the seal signer (NIP-17 requirement).
	if rumor.pubkey != sender {
		warn!("nostr: rumor author differs from seal signer, dropping");
		svc.store.mark_processed(&wrap_id);
		return;
	}
	// Ignore our own messages (e.g. wrap-to-self copies) from ANY held identity.
	if svc.is_own_pubkey(&sender) {
		svc.store.mark_processed(&wrap_id);
		return;
	}
	// 5. Only kind 14 with bounded content.
	if rumor.kind != Kind::PrivateDirectMessage || rumor.content.len() > protocol::MAX_RUMOR_CONTENT
	{
		svc.store.mark_processed(&wrap_id);
		return;
	}
	let sender_hex = sender.to_hex();
	// Blocked sender: drop silently, a nostr-level mute. Mark processed so we
	// don't reconsider it on every catch-up.
	if svc
		.store
		.contact(&sender_hex)
		.map(|c| c.blocked)
		.unwrap_or(false)
	{
		svc.store.mark_processed(&wrap_id);
		return;
	}
	let is_contact = svc
		.store
		.contact(&sender_hex)
		.map(|c| !c.unknown)
		.unwrap_or(false);
	// 6. Rate limit per sender.
	if !svc.allow_sender(&sender_hex, is_contact) {
		// Deliberately NOT marked processed: legitimate bursts can retry later.
		return;
	}
	// 7. Rumor-level dedupe (the same rumor can arrive in different wraps).
	let rumor_id = rumor.id().to_hex();
	if svc.store.is_processed(&rumor_id) {
		svc.store.mark_processed(&wrap_id);
		return;
	}
	// 8. Request-void control message (a decline by the payer or a cancel by the
	// requester): it carries no slatepack, just an action tag naming a slate id.
	// Handle it before slatepack extraction; the sender is bound to the stored
	// counterparty inside, so a stranger can't void someone else's request.
	if let Some(void_slate_id) = protocol::extract_control(&rumor.tags) {
		handle_request_void(svc, wallet, &void_slate_id, &sender_hex);
		// A decline/cancel is still an interaction with a known counterparty —
		// (re)resolve their @name so it never drops to a bare npub just because the
		// request didn't go through. Cheap, authoritative (reverse lookup), and a
		// no-op for anonymous keys.
		svc.resolve_contact_identity(&sender_hex);
		// Record the void keyed by (slate, sender) so a payment S1 that arrives
		// AFTER its void (relays reorder; NIP-59 randomizes timestamps) is dropped.
		// Binding to the sender stops a stranger pre-voiding someone else's slate.
		// A slate id is a UUID (36 chars); ignore anything longer so an attacker
		// can't bloat the processed-key store with an oversized tag value.
		if void_slate_id.len() <= 64 {
			svc.store
				.mark_processed(&format!("void:{}:{}", void_slate_id, sender_hex));
		}
		svc.store.mark_processed(&wrap_id);
		svc.store.mark_processed(&rumor_id);
		return;
	}
	// 8b. Extract the slatepack; non-payment DMs are ignored entirely.
	let Some(armor) = protocol::extract_slatepack(&rumor.content) else {
		svc.store.mark_processed(&wrap_id);
		svc.store.mark_processed(&rumor_id);
		return;
	};
	let note = protocol::extract_subject(&rumor.tags);
	// 9. Parse and validate the slate itself.
	let Ok((slate, _)) = wallet.parse_slatepack(&armor) else {
		svc.store.mark_processed(&wrap_id);
		svc.store.mark_processed(&rumor_id);
		return;
	};
	// 10. Slate-level dedupe.
	let slate_marker = format!("slate:{}:{}", slate.id, slate.state);
	if svc.store.is_processed(&slate_marker) {
		svc.store.mark_processed(&wrap_id);
		svc.store.mark_processed(&rumor_id);
		return;
	}
	// 10b. Void-before-payment: the sender cancelled this payment and the void
	// reached us before the S1. Drop the dead slate rather than auto-receiving it.
	if matches!(slate.state, grin_wallet_libwallet::SlateState::Standard1)
		&& svc
			.store
			.is_processed(&format!("void:{}:{}", slate.id, sender_hex))
	{
		info!(
			"nostr: dropping S1 for slate {} already voided by sender",
			slate.id
		);
		svc.store.mark_processed(&wrap_id);
		svc.store.mark_processed(&rumor_id);
		svc.store.mark_processed(&slate_marker);
		return;
	}
	// 11. Policy decision.
	let meta = svc.store.tx_meta(&slate.id.to_string());
	let tx_exists = wallet.has_tx_for_slate(&slate.id);
	let accept = svc.config.read().accept_from();
	let allow_requests = svc.config.read().allow_incoming_requests();
	let decision = decide(&IngestContext {
		state: slate.state.clone(),
		amount: slate.amount,
		sender: &sender_hex,
		meta: meta.as_ref(),
		tx_exists,
		is_contact,
		accept,
		allow_requests,
	});
	info!(
		"nostr: wrap {} slate {} state {} from {}…: {:?}",
		&wrap_id[..8],
		slate.id,
		slate.state,
		&sender_hex[..8],
		decision
	);

	match decision {
		IngestDecision::AutoReceive => {
			svc.ensure_contact(&sender_hex);
			// Resolve the sender's @username so the receive shows their name in
			// activity, not a bare npub.
			svc.resolve_contact_identity(&sender_hex);
			// A payment is arriving: un-pause on-demand node polling BEFORE the
			// receive so confirmation tracking is never dropped — polling stays
			// live until the tx confirms (see `maybe_pause_node_polling`).
			wallet.resume_node_polling();
			match wallet.nostr_receive(&slate) {
				Ok((_, reply_text)) => {
					// Record BEFORE dispatching the reply: crash here is
					// recovered by reconcile() re-sending the S2 from disk.
					let now = unix_time();
					svc.store.save_tx_meta(&TxNostrMeta {
						ver: 1,
						slate_id: slate.id.to_string(),
						npub: sender_hex.clone(),
						direction: NostrTxDirection::Received,
						note: note.clone(),
						status: NostrSendStatus::ReceivedNoReply,
						sent_event_id: None,
						received_rumor_id: Some(rumor_id.clone()),
						created_at: now,
						updated_at: now,
						proof_mode: false,
						proof_order: None,
						proof_notify: None,
						proof_amount: None,
						proof_delivered: false,
						receipt_sent: false,
						// Tag the front door this payment came in on: the identity
						// this wrap was actually addressed to (whichever held key
						// opened it), NOT necessarily the active one. All identities
						// redeem into the one grin balance; this records provenance.
						recipient_pubkey: recipient_hex.clone(),
						proof_address: None,
					});
					// Commit dedup markers now the receive is durable, BEFORE
					// the reply + sync tail. A crash there must not let this
					// wrap re-trigger a second receive on catch-up (decide()
					// and grin's TransactionAlreadyReceived also backstop it).
					svc.store.mark_processed(&wrap_id);
					svc.store.mark_processed(&rumor_id);
					svc.store.mark_processed(&slate_marker);
					// "Payment received" system notification (Android; no-op
					// on desktop): payer's display name (or short npub) and
					// the human-readable amount.
					{
						// Notification privacy (Advanced Privacy → Notifications):
						// "hide details" trumps the finer toggles with a generic
						// alert that leaks neither name nor amount (empty amount
						// collapses the Java template to just the private line).
						if crate::AppConfig::notif_hide_details() {
							crate::notify_payment_received(
								&t!("goblin.settings.notif_private_received"),
								"",
							);
						} else {
							let name = if crate::AppConfig::notif_hide_names() {
								t!("goblin.settings.notif_someone").to_string()
							} else {
								crate::gui::views::goblin::data::contact_title(
									&svc.store,
									&sender_hex,
								)
							};
							// Honor the "hide amounts" setting: keep the numeric
							// grin out of the alert when the user opted in.
							let amount = if crate::AppConfig::hide_amounts() {
								"•••".to_string()
							} else {
								amount_to_hr_string(slate.amount, true)
							};
							crate::notify_payment_received(&name, &amount);
						}
					}
					match svc
						.send_payment_dm(&sender_hex, &reply_text, None, &[])
						.await
					{
						Ok(event_id) => {
							if let Some(mut meta) = svc.store.tx_meta(&slate.id.to_string()) {
								meta.status = NostrSendStatus::RepliedS2;
								meta.sent_event_id = Some(event_id);
								meta.updated_at = unix_time();
								svc.store.save_tx_meta(&meta);
							}
						}
						Err(e) => warn!("nostr: S2 reply dispatch failed: {e}"),
					}
					wallet.sync();
				}
				Err(e) => {
					error!("nostr: receive failed for slate {}: {:?}", slate.id, e);
				}
			}
		}
		IngestDecision::SurfaceIncoming | IngestDecision::SurfaceRequest => {
			svc.ensure_contact(&sender_hex);
			// Resolve the requester's @username so the card isn't a bare npub.
			svc.resolve_contact_identity(&sender_hex);
			let stored = svc.store.save_incoming_request(&PaymentRequest {
				ver: 1,
				rumor_id: rumor_id.clone(),
				slate_id: slate.id.to_string(),
				slatepack: armor.clone(),
				npub: sender_hex.clone(),
				amount: slate.amount,
				note: note.clone(),
				received_at: unix_time(),
				status: RequestStatus::Pending,
			});
			if !stored {
				// Disk-DoS backpressure (F1): the request store is at its cap with
				// no terminal row to evict, so we REFUSE this new request rather than
				// drop a live pending one. Deliberately NOT marked processed — once
				// capacity frees (terminal rows age out on expiry / the user acts on
				// pending requests) a later catch-up re-surfaces it.
				warn!(
					"nostr: request store at cap ({}), refusing incoming request {} (backpressure)",
					crate::nostr::NostrStore::REQUEST_CAP,
					rumor_id
				);
				return;
			}
			svc.has_new_requests.store(true, Ordering::Relaxed);
			// The request is durably saved — safe to mark this wrap processed.
			svc.store.mark_processed(&wrap_id);
			svc.store.mark_processed(&rumor_id);
			svc.store.mark_processed(&slate_marker);
			// "Payment requested" system notification (Android; no-op on
			// desktop): only for a genuine incoming request (Invoice1 →
			// SurfaceRequest, someone asking us to pay them), not a payment
			// pending approval (SurfaceIncoming). Fires exactly once — this
			// branch is reached only for a not-yet-seen slate (slate-level
			// dedupe above + decide() drops already-known slates), mirroring the
			// received-payment notification's dedup. Requester's display name
			// (or short npub) and the human-readable amount, with the ツ mark.
			if decision == IngestDecision::SurfaceRequest {
				// Same notification-privacy ladder as the received-payment alert.
				if crate::AppConfig::notif_hide_details() {
					crate::notify_payment_requested(
						&t!("goblin.settings.notif_private_requested"),
						"",
					);
				} else {
					let name = if crate::AppConfig::notif_hide_names() {
						t!("goblin.settings.notif_someone").to_string()
					} else {
						crate::gui::views::goblin::data::contact_title(&svc.store, &sender_hex)
					};
					let amount = if crate::AppConfig::hide_amounts() {
						"•••".to_string()
					} else {
						amount_to_hr_string(slate.amount, true)
					};
					crate::notify_payment_requested(&name, &amount);
				}
			}
		}
		IngestDecision::FinalizePost => {
			// The payer's reply is our first contact with their key on this side of
			// a request we sent — make sure they're a known contact and resolve their
			// @username so the completed request shows their name, not a bare npub.
			svc.ensure_contact(&sender_hex);
			svc.resolve_contact_identity(&sender_hex);
			// Node work ahead (finalize + broadcast + confirm): un-pause
			// on-demand node polling BEFORE it so confirmation tracking is
			// never dropped.
			wallet.resume_node_polling();
			match wallet.nostr_finalize_post(&slate) {
				Ok(true) => {
					svc.store
						.update_tx_status(&slate.id.to_string(), NostrSendStatus::Finalized);
					// Finalize+post committed; mark dedup before the sync tail so a
					// crash can't re-finalize on catch-up (grin rejects a second
					// finalize and the meta is now Finalized, which decide() drops —
					// this just avoids the redundant attempt).
					svc.store.mark_processed(&wrap_id);
					svc.store.mark_processed(&rumor_id);
					svc.store.mark_processed(&slate_marker);
					if let Some(mut contact) = svc.store.contact(&sender_hex) {
						contact.last_paid_at = Some(unix_time());
						svc.store.save_contact(&contact);
					}
					// Proof-on-request delivery (frozen contract 4.3.2): this finalized
					// SEND (our own payment) now holds a real, receiver-signed Grin
					// payment proof. Deliver the ENCRYPTED proof to the watcher here.
					// The plain "payment sent" receipt is NOT (re)published at finalize:
					// it already went out at S1 dispatch (4.3.1), gated by receipt_sent,
					// so there is exactly one receipt per tx. On failure we leave
					// proof_delivered=false so the reconcile pass retries.
					if let Some(mut m) = svc.store.tx_meta(&slate.id.to_string()) {
						if proof_delivery_due(&m) && deliver_proof(svc, wallet, &m).await {
							m.proof_delivered = true;
							m.updated_at = unix_time();
							svc.store.save_tx_meta(&m);
						}
					}
					wallet.sync();
				}
				Ok(false) => {
					// The send was cancelled out-of-band (the meta usually already
					// reflects this and decide() drops the S2 before we get here; this
					// covers a tx-list cancel that left the meta untouched). Reconcile
					// the status and treat the reply as handled — never retry/re-post.
					svc.store
						.update_tx_status(&slate.id.to_string(), NostrSendStatus::Cancelled);
					svc.store.mark_processed(&wrap_id);
					svc.store.mark_processed(&rumor_id);
					svc.store.mark_processed(&slate_marker);
					info!("nostr: skipped finalize of cancelled slate {}", slate.id);
				}
				Err(e) => {
					error!("nostr: finalize failed for slate {}: {:?}", slate.id, e);
				}
			}
		}
		IngestDecision::Drop(reason) => {
			info!("nostr: dropped slate {}: {}", slate.id, reason);
			// A dropped slate is a permanent decision — don't re-evaluate it.
			svc.store.mark_processed(&wrap_id);
			svc.store.mark_processed(&rumor_id);
			svc.store.mark_processed(&slate_marker);
		}
	}
	// NOTE: AutoReceive and FinalizePost mark the wrap processed only inside their
	// success arms. On a transient failure they deliberately leave it UNMARKED so
	// the next catch-up fetch retries — otherwise an incoming payment could be
	// silently lost on a momentary wallet/node hiccup. decide() + grin's
	// already-received / re-post guards keep a retried success idempotent.
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn terminal_states_do_not_expire() {
		assert!(expiry_terminal(NostrSendStatus::Finalized));
		assert!(expiry_terminal(NostrSendStatus::Cancelled));
		// Everything in flight is eligible to expire.
		for s in [
			NostrSendStatus::Created,
			NostrSendStatus::AwaitingS2,
			NostrSendStatus::ReceivedNoReply,
			NostrSendStatus::RepliedS2,
			NostrSendStatus::AwaitingI2,
			NostrSendStatus::PaidAwaitingFinalize,
			NostrSendStatus::SendFailed,
		] {
			assert!(!expiry_terminal(s), "{s:?} should be expirable");
		}
	}

	#[test]
	fn only_our_committed_outputs_get_cancelled() {
		use NostrSendStatus::*;
		use NostrTxDirection::*;
		// Our sends (we locked outputs) and invoices we paid → cancel to unlock.
		assert!(expiry_locks_outputs(Sent, Created));
		assert!(expiry_locks_outputs(Sent, AwaitingS2));
		assert!(expiry_locks_outputs(Sent, SendFailed));
		assert!(expiry_locks_outputs(RequestedOfUs, PaidAwaitingFinalize));
		// Incoming payments and invoices we issued lock nothing of ours →
		// annotate only, never cancel a tx that could still settle/pay.
		assert!(!expiry_locks_outputs(Received, ReceivedNoReply));
		assert!(!expiry_locks_outputs(Received, RepliedS2));
		assert!(!expiry_locks_outputs(RequestedByUs, AwaitingI2));
		assert!(!expiry_locks_outputs(RequestedByUs, Created));
		assert!(!expiry_locks_outputs(RequestedOfUs, ReceivedNoReply));
	}

	/// A proof-mode SEND meta at a given lifecycle status, order context present,
	/// no watcher target (the receipt-only shape). Callers tweak fields per case.
	fn sample_send_meta(status: NostrSendStatus) -> TxNostrMeta {
		TxNostrMeta {
			ver: 1,
			slate_id: "00000000-0000-0000-0000-000000000000".to_string(),
			npub: "npub".to_string(),
			direction: NostrTxDirection::Sent,
			note: None,
			status,
			sent_event_id: None,
			received_rumor_id: None,
			created_at: 0,
			updated_at: 0,
			proof_mode: true,
			proof_order: Some("MM-abcd".to_string()),
			proof_notify: None,
			proof_amount: Some(1_000),
			proof_delivered: false,
			receipt_sent: false,
			recipient_pubkey: String::new(),
			proof_address: None,
		}
	}

	#[test]
	fn receipt_at_dispatch_only_with_order_context() {
		// With order context (proof mode + order handle) the receipt publishes at
		// dispatch, the moment the UI flips to "sent".
		assert!(receipt_due_at_dispatch(true, Some("MM-abcd")));
		// A person-to-person send carries no order: no receipt at all, ever.
		assert!(!receipt_due_at_dispatch(false, None));
		assert!(!receipt_due_at_dispatch(false, Some("MM-abcd")));
		// Proof mode but an empty/blank order handle is not routable → no receipt.
		assert!(!receipt_due_at_dispatch(true, None));
		assert!(!receipt_due_at_dispatch(true, Some("")));
		assert!(!receipt_due_at_dispatch(true, Some("   ")));
	}

	#[test]
	fn receipt_retry_gated_by_flag_no_duplicate() {
		// Dispatched (envelope accepted, UI "sent") but receipt not landed → retry.
		let m = sample_send_meta(NostrSendStatus::AwaitingS2);
		assert!(receipt_retry_due(&m));
		// A finalized send may still owe an un-landed receipt → still retried.
		let m = sample_send_meta(NostrSendStatus::Finalized);
		assert!(receipt_retry_due(&m));
		// Once the receipt has landed, it is NEVER republished: the guard against
		// a duplicate at finalize (and on every later reconcile pass).
		let mut m = sample_send_meta(NostrSendStatus::Finalized);
		m.receipt_sent = true;
		assert!(!receipt_retry_due(&m));
		// Not yet dispatched (Created / SendFailed): the UI has not flipped to
		// "sent", so nothing is published yet.
		let m = sample_send_meta(NostrSendStatus::Created);
		assert!(!receipt_retry_due(&m));
		let m = sample_send_meta(NostrSendStatus::SendFailed);
		assert!(!receipt_retry_due(&m));
		// A non-proof (person-to-person) send never publishes a receipt.
		let mut m = sample_send_meta(NostrSendStatus::AwaitingS2);
		m.proof_mode = false;
		assert!(!receipt_retry_due(&m));
	}

	#[test]
	fn proof_delivery_only_at_finalize() {
		// The proof does not exist before finalize, so it is due ONLY once
		// finalized (never at dispatch/AwaitingS2).
		let m = sample_send_meta(NostrSendStatus::Finalized);
		assert!(proof_delivery_due(&m));
		let m = sample_send_meta(NostrSendStatus::AwaitingS2);
		assert!(!proof_delivery_due(&m));
		// Already delivered → not retried.
		let mut m = sample_send_meta(NostrSendStatus::Finalized);
		m.proof_delivered = true;
		assert!(!proof_delivery_due(&m));
		// Non-proof send delivers nothing.
		let mut m = sample_send_meta(NostrSendStatus::Finalized);
		m.proof_mode = false;
		assert!(!proof_delivery_due(&m));
	}

	// --- Session-open announce: normalization, confirm, retry ---------------

	#[test]
	fn canonical_relay_normalizes_trailing_slash_and_case() {
		// A trailing slash and host case must not create distinct identities:
		// nostr-sdk normalizes to a lowercased host with an explicit trailing
		// slash, and both spellings must land on the same canonical string.
		let a = canonical_relay("wss://relay.floonet.dev");
		let b = canonical_relay("wss://relay.floonet.dev/");
		let c = canonical_relay("wss://RELAY.floonet.dev/");
		assert_eq!(a, b);
		assert_eq!(a, c);
		// Unparseable input falls back to the trimmed original (never panics).
		assert_eq!(canonical_relay("  not a url  "), "not a url");
	}

	#[test]
	fn dedup_union_folds_trailing_slash_hint_into_warm_relay() {
		// The wallet already holds a warm connection to the no-slash relay; a
		// site hint that differs only by a trailing slash must NOT be appended as
		// a phantom second relay (which would be a cold dial and break confirm).
		let base = vec![
			"wss://relay.floonet.dev".to_string(),
			"wss://relay.0xchat.com".to_string(),
		];
		let hints = vec!["wss://relay.floonet.dev/".to_string()];
		let out = dedup_relay_union(base.clone(), hints);
		assert_eq!(
			out, base,
			"trailing-slash hint should dedup into the warm relay"
		);

		// A genuinely new hint is appended, preserving its original spelling.
		let out2 = dedup_relay_union(base.clone(), vec!["wss://relay.magick.market".to_string()]);
		assert_eq!(out2.len(), 3);
		assert_eq!(out2[2], "wss://relay.magick.market");
	}

	#[test]
	fn announce_confirmed_requires_the_site_hint_relay() {
		let hint = "wss://relay.floonet.dev".to_string();
		let floonet = RelayUrl::parse("wss://relay.floonet.dev").unwrap();
		let other = RelayUrl::parse("wss://relay.0xchat.com").unwrap();

		// Accept on the hint relay confirms (even spelled with a trailing slash).
		let mut ok = HashSet::new();
		ok.insert(floonet.clone());
		assert!(announce_confirmed(&ok, &[hint.clone()]));
		assert!(announce_confirmed(
			&ok,
			&["wss://relay.floonet.dev/".to_string()]
		));

		// Accept ONLY on some other wallet relay does NOT confirm: the site
		// subscribes only on its hint, so this is the "returns to browser but
		// never logs in" case we must reject.
		let mut only_other = HashSet::new();
		only_other.insert(other);
		assert!(!announce_confirmed(&only_other, &[hint.clone()]));

		// No relay accepted → not confirmed.
		assert!(!announce_confirmed(&HashSet::new(), &[hint]));

		// Defensive: a session with no hint confirms on any accept.
		assert!(announce_confirmed(&ok, &[]));
		assert!(!announce_confirmed(&HashSet::new(), &[]));
	}

	#[test]
	fn should_reannounce_retries_until_confirmed_or_capped() {
		// Unconfirmed and under the cap → keep retrying.
		assert!(should_reannounce(false, 1));
		assert!(should_reannounce(false, ANNOUNCE_MAX_ATTEMPTS - 1));
		// Confirmed → stop, regardless of attempts.
		assert!(!should_reannounce(true, 1));
		// Cap reached → give up so a dead hint relay can't spin the loop forever.
		assert!(!should_reannounce(false, ANNOUNCE_MAX_ATTEMPTS));
		assert!(!should_reannounce(false, ANNOUNCE_MAX_ATTEMPTS + 5));
	}

	// Opportunistic NIP-42 auto-auth: a Client built with a signer + explicit
	// `automatic_authentication(true)` answers a relay's AUTH challenge with a
	// signer-signed kind-22242 event and ONLY when challenged. This asserts the
	// options + signer wiring the `run_service` builder relies on constructs, so a
	// signature change in the SDK (or a lost `.opts(...)` call) fails the build
	// here rather than silently disabling DM reads on the hardened relay. It does
	// NOT open a connection, so it stays inert against non-challenging relays.
	#[tokio::test]
	async fn auto_auth_client_builds_with_active_signer() {
		use nostr_sdk::prelude::NostrSigner;
		let keys = Keys::generate();
		let pubkey = keys.public_key();
		let client = Client::builder()
			.signer(keys)
			.opts(ClientOptions::new().automatic_authentication(true))
			.build();
		// The active identity is the single signer this connection auto-auths as
		// (multi-identity beyond this is documented at the `run_service` builder).
		let signer = client.signer().await.expect("signer is set");
		assert_eq!(signer.get_public_key().await.unwrap(), pubkey);
	}
}
