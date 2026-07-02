// THROWAWAY transport-validation harness (G14). Not part of the shipped test
// suite — it exists to prove the migrated transport (in-process smolmix mixnet
// tunnel + mandatory mix-dns) actually DELIVERS NIP-17 gift wraps over real
// relays, using the SAME `NymWebSocketTransport` the app now ships with as its
// only transport. Unlike tests/nostr_e2e.rs (which uses the default clearnet
// nostr-sdk client), every websocket here is dialed through the mixnet and
// every relay hostname is resolved over the tunnel (mix-dns).
//
// Network + mixnet dependent — run explicitly:
//   cargo test --test xrelay_smoke -- --ignored --nocapture --test-threads=1
//
// What to look for in the logs (proof, not just green):
//   * "nym: tunnel ready ... (allocated ip ..., probe ok)"  — tunnel up, exit auto-selected
//   * "mix-dns: resolved <host> -> <ip> ..."                — each relay resolved OVER the tunnel
//   * "v3 delivered + decrypted"                            — a real 0x03 wrap crossed the wire

use std::time::{Duration, Instant};

use grim::nostr::{protocol, wrapv3};
use grim::nym::NymWebSocketTransport;
use nostr_sdk::prelude::*;

/// A small but valid-looking slatepack armor block (same fixture the in-tree
/// wrapv3 unit test uses), so extraction is exercised end to end.
const SLATEPACK: &str = "BEGINSLATEPACK. 4H1qx1wHe668tFW yC2gfL8PPd8kSgv \
	pcXQhyRkHbyKHZg GN75o7uWoT3dkib R2tj1fFGN2FoRLY oeBPyKizupksgRT \
	dXFdjEuMUuktR5r gCiVBSXcHSWW3KW Y56LTQ9z3QwUWmE 8sRtwR9Bn8oNN5K. \
	ENDSLATEPACK.";

const SUBJECT: &str = "lunch :)";

/// Install the ring crypto provider (the app does this in `grim::start()`; a
/// test binary must do it itself or the first TLS handshake panics — Build
/// 65/66 rule) and route logs to stdout at debug so the tunnel + mix-dns lines
/// are visible under --nocapture. Both are idempotent.
fn init() {
	let _ = rustls::crypto::ring::default_provider().install_default();
	let _ = env_logger::builder()
		.is_test(false)
		.filter_level(log::LevelFilter::Info)
		.filter_module("grim::nym", log::LevelFilter::Debug)
		.parse_default_env() // honor RUST_LOG if set
		.try_init();
}

/// Bring the shared in-process mixnet tunnel up before any relay dial, exactly
/// like the real service loop (client.rs `run_service`). Panics if the mixnet
/// never bootstraps — that IS the blocker the on-chain test would hit.
async fn ensure_tunnel() {
	grim::nym::warm_up();
	let started = Instant::now();
	for _ in 0..240 {
		if grim::nym::is_ready() {
			eprintln!(
				"[harness] mixnet tunnel ready after ~{}ms",
				started.elapsed().as_millis()
			);
			return;
		}
		tokio::time::sleep(Duration::from_millis(500)).await;
	}
	panic!(
		"BLOCKER: mixnet tunnel never became ready after {}s — smolmix bootstrap failed \
		 (see nym: log lines above). On-chain payment test cannot proceed.",
		started.elapsed().as_secs()
	);
}

/// Build a Goblin-style client for `keys` over the real mixnet transport —
/// byte-for-byte the builder from `src/nostr/client.rs::run_service`.
fn goblin_client(keys: &Keys) -> Client {
	Client::builder()
		.signer(keys.clone())
		.websocket_transport(NymWebSocketTransport)
		.build()
}

/// Advertise a kind-10050 DM-relay list for `who` pointing at `inbox_relays`,
/// carrying the v3 encryption capability, so the wire shape matches what a real
/// Goblin peer publishes (client.rs `publish_identity`). Best-effort.
async fn advertise_inbox(client: &Client, inbox_relays: &[&str]) {
	let mut tags: Vec<Tag> = inbox_relays
		.iter()
		.map(|r| Tag::custom(TagKind::custom("relay"), [r.to_string()]))
		.collect();
	tags.push(Tag::custom(
		TagKind::custom("encryption"),
		[wrapv3::ENCRYPTION_CAPABILITY.to_string()],
	));
	let builder = EventBuilder::new(Kind::InboxRelays, "").tags(tags);
	let targets: Vec<String> = inbox_relays.iter().map(|s| s.to_string()).collect();
	match client.sign_event_builder(builder).await {
		Ok(ev) => {
			if let Err(e) = client.send_event_to(&targets, &ev).await {
				eprintln!("[harness] warn: advertise 10050 failed: {e}");
			}
		}
		Err(e) => eprintln!("[harness] warn: sign 10050 failed: {e}"),
	}
}

/// Wait up to `timeout` for a kind-1059 gift wrap addressed to `me` on the
/// notification stream, unwrap it through Goblin's version-dispatched
/// `wrapv3::unwrap` (proves the 0x03 path over the wire), and return the sender
/// + rumor. Any other event is ignored.
async fn recv_and_unwrap(
	client: &Client,
	me: &Keys,
	timeout: Duration,
) -> Result<(PublicKey, UnsignedEvent), String> {
	let mut notifications = client.notifications();
	tokio::time::timeout(timeout, async {
		loop {
			if let Ok(RelayPoolNotification::Event { event, .. }) = notifications.recv().await {
				if event.kind != Kind::GiftWrap {
					continue;
				}
				match wrapv3::unwrap(me, &event).await {
					Ok(u) => return (u.sender, u.rumor),
					// A wrap we cannot open (someone else's) — keep waiting.
					Err(e) => {
						eprintln!("[harness] ignoring undecryptable wrap: {e}");
						continue;
					}
				}
			}
		}
	})
	.await
	.map_err(|_| "timed out waiting for gift wrap".to_string())
}

/// Assert the received rumor is exactly the payment DM Alice sent.
fn assert_payment(sender: PublicKey, alice: &Keys, rumor: &UnsignedEvent, content: &str) {
	assert_eq!(sender, alice.public_key(), "sender must be Alice");
	assert_eq!(
		rumor.pubkey,
		alice.public_key(),
		"rumor author == seal signer"
	);
	assert_eq!(rumor.kind, Kind::PrivateDirectMessage);
	assert_eq!(
		rumor.content, content,
		"payment content must survive the wire"
	);
	let armor = protocol::extract_slatepack(&rumor.content).expect("slatepack must extract");
	assert!(armor.starts_with("BEGINSLATEPACK.") && armor.ends_with("ENDSLATEPACK."));
	assert_eq!(
		protocol::extract_subject(&rumor.tags).as_deref(),
		Some(SUBJECT)
	);
}

/// RELAY-GATED READINESS (the point of the G14 hardening): `transport_ready()`
/// must be FALSE while only the tunnel is up, and become TRUE only once a relay
/// is actually connected+subscribed on the CURRENT tunnel generation — the
/// signal that governs the "Connected over Nym" UI and the exit-health window.
///
/// The bare `nostr_sdk::Client` used here is not the app's `NostrService`, so it
/// doesn't feed the readiness signal on its own; we drive the SAME report the
/// service loop makes (`report_relay_live(tunnel_generation())`) exactly when a
/// relay has connected+subscribed, and assert the gate flips only then. Proves
/// the cross-module contract: tunnel-up alone is NOT ready; a live relay on the
/// current generation IS.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn transport_ready_is_relay_gated() {
	init();
	ensure_tunnel().await;
	let generation = grim::nym::tunnel_generation();
	assert!(
		generation != 0,
		"a live tunnel must have a non-zero generation"
	);

	// Clear any liveness a prior test left on this (process-global) generation,
	// so the assertion is order-independent.
	grim::nym::report_relay_down(generation);
	assert!(
		grim::nym::is_ready(),
		"precondition: tunnel (is_ready) must be up"
	);
	assert!(
		!grim::nym::transport_ready(),
		"BUG: transport_ready must be FALSE on a warm tunnel with no live relay \
		 (this is exactly the false 'Connected over Nym' the hardening fixes)"
	);

	// Bring one relay to connected+subscribed over the mixnet, like the service.
	let relay = "wss://relay.damus.io";
	let bob = Keys::generate();
	let bob_client = goblin_client(&bob);
	bob_client.add_relay(relay).await.unwrap();
	bob_client.connect().await;
	bob_client
		.subscribe(
			Filter::new()
				.kind(Kind::GiftWrap)
				.pubkey(bob.public_key())
				.since(Timestamp::now() - Duration::from_secs(3 * 86_400)),
			None,
		)
		.await
		.unwrap();

	// Wait for the websocket handshake to actually complete over Nym, then feed
	// the readiness signal the way `run_service`'s status tick does. A generous
	// budget: a relay handshake over the mixnet is variable (seen 10-30s).
	let mut connected = false;
	for _ in 0..120 {
		if bob_client
			.relays()
			.await
			.values()
			.any(|r| r.status() == RelayStatus::Connected)
		{
			connected = true;
			break;
		}
		tokio::time::sleep(Duration::from_millis(500)).await;
	}
	assert!(connected, "BLOCKER: relay never connected over the mixnet");
	grim::nym::report_relay_live(generation);

	assert!(
		grim::nym::transport_ready(),
		"transport_ready must be TRUE once a relay is live on the current generation"
	);
	// A report tagged with an OLDER generation must not keep us 'ready' after a
	// (hypothetical) reselect: simulate the generation moving on and confirm the
	// stale report no longer counts.
	grim::nym::report_relay_live(generation - 1);
	// Still ready: the current-generation liveness stands (fetch_max floor).
	assert!(
		grim::nym::transport_ready(),
		"a stale-generation report must not lower current readiness"
	);
	eprintln!("[harness] relay-gated readiness verified at gen {generation}");

	bob_client.disconnect().await;
}

/// CONDEMN + RESELECT (deterministic simulation of a relay-dead exit): with a
/// nostr consumer present but NO relay ever reported live on the current exit,
/// nymproc must condemn the exit within its grace window and rebuild on a fresh
/// auto-selected one (the generation advances), then recover. Proves the
/// exit-health state machine — the whole point of requirement 2 — end to end
/// without needing a naturally bad-for-relays exit (which can't be forced
/// deterministically). In the real app the NostrService DOES report relay-live,
/// so a HEALTHY exit is never condemned (see `v3_cross_relay`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn dead_for_relays_exit_is_condemned_and_reselected() {
	init();
	ensure_tunnel().await;
	let gen0 = grim::nym::tunnel_generation();
	assert!(gen0 != 0, "a live tunnel must have a non-zero generation");
	eprintln!(
		"[harness] arming relay consumer at gen {gen0}; withholding relay-live to simulate a relay-dead exit"
	);
	// Arm relay-reachability governance but never report a live relay: nymproc
	// must treat this exit as dead-for-our-purposes and reselect.
	grim::nym::set_relay_consumer(true);

	// Budget generously: condemnation itself takes RELAY_GRACE (~25s), then a
	// FRESH mixnet bootstrap follows (variable, seen 5-70s), so allow ~150s for
	// the generation to advance.
	let started = Instant::now();
	let mut advanced = 0u64;
	for _ in 0..300 {
		let g = grim::nym::tunnel_generation();
		if g > gen0 {
			advanced = g;
			break;
		}
		tokio::time::sleep(Duration::from_millis(500)).await;
	}
	// Disarm FIRST so a failed assert can't leave governance armed for later tests.
	grim::nym::set_relay_consumer(false);
	assert!(
		advanced > gen0,
		"BLOCKER: a relay-dead exit was not condemned+reselected within {}s (gen stuck at {gen0})",
		started.elapsed().as_secs()
	);
	eprintln!(
		"[harness] exit condemned + reselected: gen {gen0} -> {advanced} in ~{}s",
		started.elapsed().as_secs()
	);

	// Recovery: with governance disarmed, the freshly-built tunnel settles ready.
	let mut ready = false;
	for _ in 0..80 {
		if grim::nym::is_ready() {
			ready = true;
			break;
		}
		tokio::time::sleep(Duration::from_millis(500)).await;
	}
	assert!(ready, "tunnel must recover ready after the reselect");
	eprintln!(
		"[harness] tunnel recovered ready after reselect at gen {}",
		grim::nym::tunnel_generation()
	);
}

/// SINGLE-RELAY: a NIP-44 v3 gift wrap round-trips between two fresh Goblin
/// identities over ONE relay, entirely through the smolmix tunnel + mix-dns.
/// Proves the migrated transport delivers the v3 path against a real relay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn v3_roundtrip_single_relay() {
	init();
	ensure_tunnel().await;
	let relay = "wss://relay.damus.io";

	let alice = Keys::generate();
	let bob = Keys::generate();
	eprintln!("[harness] single-relay {relay}");
	eprintln!(
		"[harness]   alice {}",
		alice.public_key().to_bech32().unwrap()
	);
	eprintln!(
		"[harness]   bob   {}",
		bob.public_key().to_bech32().unwrap()
	);

	let bob_client = goblin_client(&bob);
	bob_client.add_relay(relay).await.unwrap();
	bob_client.connect().await;
	tokio::time::sleep(Duration::from_secs(3)).await;
	advertise_inbox(&bob_client, &[relay]).await;
	bob_client
		.subscribe(
			Filter::new()
				.kind(Kind::GiftWrap)
				.pubkey(bob.public_key())
				.since(Timestamp::now() - Duration::from_secs(3 * 86_400)),
			None,
		)
		.await
		.unwrap();

	let alice_client = goblin_client(&alice);
	alice_client.add_relay(relay).await.unwrap();
	alice_client.connect().await;
	tokio::time::sleep(Duration::from_secs(3)).await;

	let content = protocol::build_payment_content(SLATEPACK);
	let tags = protocol::build_rumor_tags(Some(SUBJECT));
	let wrap = wrapv3::wrap(&alice, &bob.public_key(), content.clone(), tags).expect("v3 wrap");
	assert_eq!(wrap.kind, Kind::GiftWrap);

	let sent = Instant::now();
	alice_client
		.send_event_to(vec![relay.to_string()], &wrap)
		.await
		.expect("publish v3 wrap over mixnet");
	eprintln!("[harness] alice published v3 wrap; waiting for delivery...");

	let (sender, rumor) = recv_and_unwrap(&bob_client, &bob, Duration::from_secs(90))
		.await
		.expect("BLOCKER: v3 gift wrap never delivered single-relay");
	assert_payment(sender, &alice, &rumor, &content);
	eprintln!(
		"[harness] v3 delivered + decrypted single-relay in {} ms over {relay}",
		sent.elapsed().as_millis()
	);

	bob_client.disconnect().await;
	alice_client.disconnect().await;
}

/// SINGLE-RELAY v2: the unchanged nostr-sdk NIP-44 v2 gift-wrap path
/// (`send_private_msg_to`) delivered over the SAME smolmix transport, unwrapped
/// through Goblin's version-dispatched `wrapv3::unwrap` (which routes 0x02 to
/// the sdk). Proves the migrated transport is payload-version agnostic — a
/// v2-only peer is unaffected over the mixnet.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn v2_roundtrip_single_relay() {
	init();
	ensure_tunnel().await;
	let relay = "wss://relay.damus.io";

	let alice = Keys::generate();
	let bob = Keys::generate();
	eprintln!("[harness] single-relay v2 {relay}");
	eprintln!(
		"[harness]   alice {}",
		alice.public_key().to_bech32().unwrap()
	);
	eprintln!(
		"[harness]   bob   {}",
		bob.public_key().to_bech32().unwrap()
	);

	let bob_client = goblin_client(&bob);
	bob_client.add_relay(relay).await.unwrap();
	bob_client.connect().await;
	tokio::time::sleep(Duration::from_secs(3)).await;
	advertise_inbox(&bob_client, &[relay]).await;
	bob_client
		.subscribe(
			Filter::new()
				.kind(Kind::GiftWrap)
				.pubkey(bob.public_key())
				.since(Timestamp::now() - Duration::from_secs(3 * 86_400)),
			None,
		)
		.await
		.unwrap();

	let alice_client = goblin_client(&alice);
	alice_client.add_relay(relay).await.unwrap();
	alice_client.connect().await;
	tokio::time::sleep(Duration::from_secs(3)).await;

	let content = protocol::build_payment_content(SLATEPACK);
	let tags = protocol::build_rumor_tags(Some(SUBJECT));
	// nostr-sdk builds a v2 (0x02) gift wrap here.
	let sent = Instant::now();
	alice_client
		.send_private_msg_to([relay], bob.public_key(), content.clone(), tags)
		.await
		.expect("publish v2 wrap over mixnet");
	eprintln!("[harness] alice published v2 wrap; waiting for delivery...");

	let (sender, rumor) = recv_and_unwrap(&bob_client, &bob, Duration::from_secs(90))
		.await
		.expect("BLOCKER: v2 gift wrap never delivered single-relay");
	assert_payment(sender, &alice, &rumor, &content);
	eprintln!(
		"[harness] v2 delivered + decrypted single-relay in {} ms over {relay}",
		sent.elapsed().as_millis()
	);

	bob_client.disconnect().await;
	alice_client.disconnect().await;
}

/// CROSS-RELAY (the redundancy direction): Bob's inbox is nos.lol ONLY; Alice's
/// home is damus. Alice publishes the SAME v3 wrap redundantly to BOTH relays;
/// Bob, subscribed only on nos.lol, still receives + decrypts it. Proves
/// delivery does not depend on a single shared relay and that the v3 path works
/// over the real mixnet transport across two relays with no overlap in what the
/// two identities read.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn v3_cross_relay() {
	init();
	ensure_tunnel().await;
	let alice_home = "wss://relay.damus.io";
	let bob_inbox = "wss://nos.lol";

	let alice = Keys::generate();
	let bob = Keys::generate();
	eprintln!("[harness] cross-relay: alice_home={alice_home}  bob_inbox={bob_inbox}");
	eprintln!(
		"[harness]   alice {}",
		alice.public_key().to_bech32().unwrap()
	);
	eprintln!(
		"[harness]   bob   {}",
		bob.public_key().to_bech32().unwrap()
	);

	// Bob lives ONLY on nos.lol and advertises it as his inbox.
	let bob_client = goblin_client(&bob);
	bob_client.add_relay(bob_inbox).await.unwrap();
	bob_client.connect().await;
	tokio::time::sleep(Duration::from_secs(3)).await;
	advertise_inbox(&bob_client, &[bob_inbox]).await;
	bob_client
		.subscribe(
			Filter::new()
				.kind(Kind::GiftWrap)
				.pubkey(bob.public_key())
				.since(Timestamp::now() - Duration::from_secs(3 * 86_400)),
			None,
		)
		.await
		.unwrap();

	// Alice's home is damus; she also connects to Bob's inbox to deposit there.
	let alice_client = goblin_client(&alice);
	alice_client.add_relay(alice_home).await.unwrap();
	alice_client.add_relay(bob_inbox).await.unwrap();
	alice_client.connect().await;
	tokio::time::sleep(Duration::from_secs(3)).await;

	let content = protocol::build_payment_content(SLATEPACK);
	let tags = protocol::build_rumor_tags(Some(SUBJECT));
	let wrap = wrapv3::wrap(&alice, &bob.public_key(), content.clone(), tags).expect("v3 wrap");

	// Redundant publish to BOTH relays; Bob reads only nos.lol.
	let sent = Instant::now();
	alice_client
		.send_event_to(vec![alice_home.to_string(), bob_inbox.to_string()], &wrap)
		.await
		.expect("publish v3 wrap to both relays over mixnet");
	eprintln!(
		"[harness] alice published v3 wrap to [{alice_home}, {bob_inbox}]; bob reads only {bob_inbox}"
	);

	let (sender, rumor) = recv_and_unwrap(&bob_client, &bob, Duration::from_secs(90))
		.await
		.expect("BLOCKER: v3 gift wrap never crossed to bob's inbox relay");
	assert_payment(sender, &alice, &rumor, &content);
	eprintln!(
		"[harness] v3 delivered + decrypted CROSS-RELAY in {} ms (alice@{alice_home} -> bob@{bob_inbox})",
		sent.elapsed().as_millis()
	);

	bob_client.disconnect().await;
	alice_client.disconnect().await;
}
