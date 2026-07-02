// COLD-CONNECT TIMING HARNESS (Build 98 latency investigation). Not part of the
// shipped test suite — it exists to MEASURE, on this machine, how long the real
// Nym transport takes to go from a cold start to "transport ready" (a relay
// connected+subscribed on the current tunnel generation), broken down per stage,
// and to detect the exit-reselect LOOP (watchdog condemning a healthy exit
// because relays were slow to connect through lossy mix-dns).
//
// It drives the SAME `NymWebSocketTransport` the app ships with, over the SAME
// default relay set, arming the relay-consumer governance exactly like
// `client.rs::run_service`, so the watchdog behaves as it does in the app.
//
// Run BEFORE (reproduce the old UDP mix-dns + legacy-watchdog loop) vs AFTER
// (DoT-over-mixnet + robust watchdog), same binary, via env toggles:
//
//   # BEFORE (old behavior): UDP mix-dns on + legacy watchdog
//   GOBLIN_DNS_UDP=1 GOBLIN_LEGACY_WATCHDOG=1 \
//     cargo test --test connect_timing -- --ignored --nocapture --test-threads=1
//
//   # AFTER (shipped default): DoT-over-mixnet + robust watchdog
//   cargo test --test connect_timing -- --ignored --nocapture --test-threads=1
//
// Grep the captured log for lines tagged "[timing]" and "[TIMELINE]".

use std::time::{Duration, Instant};

use grim::nym::NymWebSocketTransport;
use nostr_sdk::prelude::*;

/// The app's default relay set (src/nostr/relays.rs).
const DEFAULT_RELAYS: &[&str] = &[
	"wss://relay.goblin.st",
	"wss://relay.damus.io",
	"wss://nos.lol",
];

/// Overall budget for the measured window. Long enough to observe several
/// reselect cycles if the loop is present (BEFORE), short enough to keep the run
/// bounded. Overridable with GOBLIN_TIMING_WINDOW_SECS.
fn window() -> Duration {
	let secs = std::env::var("GOBLIN_TIMING_WINDOW_SECS")
		.ok()
		.and_then(|s| s.parse().ok())
		.unwrap_or(180);
	Duration::from_secs(secs)
}

fn init() {
	let _ = rustls::crypto::ring::default_provider().install_default();
	let _ = env_logger::builder()
		.is_test(false)
		.format_timestamp_millis() // absolute wall-clock ms on every line
		.filter_level(log::LevelFilter::Info)
		.filter_module("grim::nym", log::LevelFilter::Debug)
		.parse_default_env()
		.try_init();
}

/// One cold-connect measurement: bring the tunnel up, dial the default relays
/// with the relay-consumer governance armed (as the app does), and record the
/// per-stage timeline + any exit reselects over the window.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn cold_connect_timing() {
	init();
	let mode_dns = if std::env::var("GOBLIN_DNS_UDP").as_deref() == Ok("1") {
		"udp-dns(legacy)"
	} else {
		"dot-dns"
	};
	let mode_wd = if std::env::var("GOBLIN_LEGACY_WATCHDOG").as_deref() == Ok("1") {
		"legacy-watchdog"
	} else {
		"robust-watchdog"
	};
	eprintln!("[TIMELINE] === cold_connect_timing START (dns={mode_dns}, watchdog={mode_wd}) ===");

	let t0 = Instant::now();

	// Stage A: mixnet tunnel bootstrap (select exit + build + liveness probe).
	grim::nym::warm_up();
	let mut tunnel_ready_ms = None;
	for _ in 0..480 {
		if grim::nym::is_ready() {
			tunnel_ready_ms = Some(t0.elapsed().as_millis());
			break;
		}
		tokio::time::sleep(Duration::from_millis(250)).await;
	}
	let gen0 = grim::nym::tunnel_generation();
	match tunnel_ready_ms {
		Some(ms) => eprintln!("[TIMELINE] A. tunnel READY at t+{ms}ms (gen {gen0})"),
		None => {
			eprintln!(
				"[TIMELINE] A. tunnel NEVER became ready within {}s — mixnet bootstrap failed on this machine",
				t0.elapsed().as_secs()
			);
			panic!("mixnet never bootstrapped; cannot measure connect timing");
		}
	}

	// Stage B: dial the default relays over the mixnet, exactly like run_service:
	// arm relay-consumer governance so the watchdog treats a relay-dead exit as
	// condemnable (this is what produces the loop in the BEFORE case).
	grim::nym::set_relay_consumer(true);
	let client = Client::builder()
		.signer(Keys::generate())
		.websocket_transport(NymWebSocketTransport)
		.build();
	for r in DEFAULT_RELAYS {
		let _ = client.add_relay(*r).await;
	}
	let dial_gen = grim::nym::tunnel_generation();
	let connect_started = Instant::now();
	client.connect().await;

	// Report relay-live on the current generation as soon as a relay connects,
	// exactly like run_service's fast-report task — this is what closes the
	// watchdog's readiness window in the healthy case.
	let mut first_relay_ms = None;
	let mut transport_ready_ms = None;
	let mut reselects = 0u64;
	let mut last_gen = dial_gen;
	let mut gen_events: Vec<(u128, u64)> = vec![(t0.elapsed().as_millis(), dial_gen)];

	loop {
		if connect_started.elapsed() > window() {
			break;
		}
		let gen_now = grim::nym::tunnel_generation();
		if gen_now != last_gen {
			reselects += 1;
			gen_events.push((t0.elapsed().as_millis(), gen_now));
			eprintln!(
				"[TIMELINE]    !! exit RESELECT #{reselects}: gen {last_gen} -> {gen_now} at t+{}ms (the loop)",
				t0.elapsed().as_millis()
			);
			last_gen = gen_now;
			// Re-dial on the fresh exit like the status loop does.
			client.disconnect().await;
			for r in DEFAULT_RELAYS {
				let _ = client.add_relay(*r).await;
			}
			client.connect().await;
		}

		let connected = client
			.relays()
			.await
			.values()
			.any(|r| r.status() == RelayStatus::Connected);
		if connected {
			// Feed liveness on the CURRENT generation (what run_service does).
			grim::nym::report_relay_live(grim::nym::tunnel_generation());
			if first_relay_ms.is_none() {
				first_relay_ms = Some(t0.elapsed().as_millis());
				eprintln!(
					"[TIMELINE] B. first relay CONNECTED at t+{}ms (~{}ms after connect())",
					t0.elapsed().as_millis(),
					connect_started.elapsed().as_millis()
				);
			}
		} else if first_relay_ms.is_some() {
			grim::nym::report_relay_down(grim::nym::tunnel_generation());
		}

		if grim::nym::transport_ready() && transport_ready_ms.is_none() {
			transport_ready_ms = Some(t0.elapsed().as_millis());
			eprintln!(
				"[TIMELINE] C. TRANSPORT READY at t+{}ms (relay live on gen {})",
				t0.elapsed().as_millis(),
				grim::nym::tunnel_generation()
			);
			// Once ready, watch a little longer to confirm it STAYS ready (no loop),
			// then finish early rather than burn the whole window.
			let settle_until = Instant::now() + Duration::from_secs(20);
			let mut stayed = true;
			while Instant::now() < settle_until {
				tokio::time::sleep(Duration::from_millis(500)).await;
				if grim::nym::tunnel_generation() != last_gen {
					stayed = false; // a reselect during settle — loop still live
					break;
				}
			}
			if stayed {
				eprintln!("[TIMELINE]    transport stayed ready for 20s — no loop");
				break;
			}
		}
		tokio::time::sleep(Duration::from_millis(250)).await;
	}

	grim::nym::set_relay_consumer(false);
	client.disconnect().await;

	eprintln!("[TIMELINE] === SUMMARY (dns={mode_dns}, watchdog={mode_wd}) ===");
	eprintln!(
		"[TIMELINE]   tunnel_ready:    {}",
		tunnel_ready_ms
			.map(|m| format!("{m}ms"))
			.unwrap_or("n/a".into())
	);
	eprintln!(
		"[TIMELINE]   first_relay:     {}",
		first_relay_ms
			.map(|m| format!("{m}ms"))
			.unwrap_or("NEVER".into())
	);
	eprintln!(
		"[TIMELINE]   transport_ready: {}",
		transport_ready_ms
			.map(|m| format!("{m}ms"))
			.unwrap_or("NEVER".into())
	);
	eprintln!("[TIMELINE]   exit reselects during window: {reselects}  (0 = no loop)");
	eprintln!("[TIMELINE]   generation timeline: {gen_events:?}");
	eprintln!("[TIMELINE] === cold_connect_timing END ===");

	// The measurement itself shouldn't fail the suite; it's diagnostic. But a
	// total failure to ever connect is worth surfacing loudly.
	assert!(
		first_relay_ms.is_some(),
		"no relay ever connected within the window"
	);
}

/// Prove DNS resolves END TO END over the tunnel (DoT, or DoH fallback) — no
/// clearnet. Loops across exit reselects (the mixnet hands out the odd dead
/// exit) until a healthy exit resolves a real relay host, then asserts success.
/// Watch the log for "dot-dns: resolved" / "doh-dns: resolved".
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn dns_resolve_smoke() {
	init();
	grim::nym::warm_up();
	for _ in 0..480 {
		if grim::nym::is_ready() {
			break;
		}
		tokio::time::sleep(Duration::from_millis(250)).await;
	}
	let deadline = Instant::now() + Duration::from_secs(150);
	let mut ok = false;
	while Instant::now() < deadline {
		if let Some(tunnel) = grim::nym::nymproc::tunnel() {
			for host in ["relay.damus.io", "goblin.st", "api.coingecko.com"] {
				let t = Instant::now();
				match grim::nym::dns::resolve(&tunnel, host, 443).await {
					Some(addr) => {
						eprintln!(
							"[DNSPROOF] resolved {host} -> {addr} in {}ms OVER THE TUNNEL",
							t.elapsed().as_millis()
						);
						ok = true;
					}
					None => eprintln!(
						"[DNSPROOF] {host} unresolved on this exit ({}ms) — waiting for a better exit",
						t.elapsed().as_millis()
					),
				}
			}
			if ok {
				break;
			}
		}
		tokio::time::sleep(Duration::from_secs(3)).await;
	}
	assert!(
		ok,
		"DNS never resolved over the tunnel within the window (all exits bad?)"
	);
}

/// Probe whether the Nym IPR exit policy lets us open TCP to the DoT port (853)
/// through the tunnel. 443 is the control (known-open — relays + HTTPS ride it).
/// Decides DoT-vs-DoH for the private DNS transport. Run:
///   cargo test --test connect_timing probe_dns_ports -- --ignored --nocapture --test-threads=1
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn probe_dns_ports() {
	init();
	grim::nym::warm_up();
	let mut ready = false;
	for _ in 0..480 {
		if grim::nym::is_ready() {
			ready = true;
			break;
		}
		tokio::time::sleep(Duration::from_millis(250)).await;
	}
	assert!(ready, "tunnel never bootstrapped; cannot probe ports");
	let tunnel = grim::nym::nymproc::tunnel().expect("tunnel up");
	let targets = [
		("cloudflare:853 (DoT)", "1.1.1.1:853"),
		("quad9:853 (DoT)", "9.9.9.9:853"),
		("cloudflare:443 (control)", "1.1.1.1:443"),
	];
	for (label, addr) in targets {
		let sa: std::net::SocketAddr = addr.parse().unwrap();
		let t = Instant::now();
		match tokio::time::timeout(Duration::from_secs(12), tunnel.tcp_connect(sa)).await {
			Ok(Ok(_)) => eprintln!(
				"[PORTPROBE] {label} = CONNECTED in {}ms",
				t.elapsed().as_millis()
			),
			Ok(Err(e)) => eprintln!(
				"[PORTPROBE] {label} = REFUSED/ERR after {}ms: {e}",
				t.elapsed().as_millis()
			),
			Err(_) => eprintln!(
				"[PORTPROBE] {label} = TIMEOUT after {}ms",
				t.elapsed().as_millis()
			),
		}
	}
}
