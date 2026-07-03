// Local network measurement for the Nym read tunnel. Uses the wallet's REAL
// transport (warm_up + tuned tunnel + reselect + DNS cache + HTTP keep-alive
// pool), then fetches the live price API over the mixnet on a fixed interval
// so we can see (a) cold connect time, (b) whether the connection stays warm,
// (c) per-fetch latency over time.
//
//   cargo run --release --example tunnel_measure -- <seconds> [interval_secs]
//
// e.g. `-- 300` (5 min) or `-- 600 15` (10 min, every 15s).

use std::time::{Duration, Instant};

const PRICE_URL: &str = "https://api.coingecko.com/api/v3/simple/price?ids=grin&vs_currencies=usd";

#[tokio::main]
async fn main() {
	let _ = rustls::crypto::ring::default_provider().install_default();

	let args: Vec<String> = std::env::args().collect();
	let total_secs: u64 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(300);
	let interval_secs: u64 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(15);

	let run_start = Instant::now();
	println!("[t=0.0s] warm_up(): starting the tunnel");
	grim::nym::warm_up();

	// Cold connect time: poll is_ready().
	let mut connect_ms = None;
	let t_connect = Instant::now();
	while t_connect.elapsed() < Duration::from_secs(120) {
		if grim::nym::is_ready() {
			connect_ms = Some(t_connect.elapsed().as_millis());
			break;
		}
		tokio::time::sleep(Duration::from_millis(200)).await;
	}
	match connect_ms {
		Some(ms) => println!(
			"[t={:.1}s] TUNNEL READY (cold connect {} ms)",
			run_start.elapsed().as_secs_f64(),
			ms
		),
		None => {
			println!("tunnel never became ready in 120s; aborting");
			return;
		}
	}

	// Warm-loop: fetch price over the mixnet every interval, record latency.
	let mut lats: Vec<u128> = vec![];
	let mut fails = 0u32;
	let deadline = run_start + Duration::from_secs(total_secs);
	let mut n = 0u32;
	while Instant::now() < deadline {
		n += 1;
		let t = Instant::now();
		let ok = grim::nym::http_request("GET", PRICE_URL.to_string(), None, vec![]).await;
		let ms = t.elapsed().as_millis();
		match ok {
			Some(body) if body.contains("grin") => {
				lats.push(ms);
				println!(
					"[t={:.1}s] fetch #{n}: {} ms  ready={}",
					run_start.elapsed().as_secs_f64(),
					ms,
					grim::nym::is_ready()
				);
			}
			other => {
				fails += 1;
				println!(
					"[t={:.1}s] fetch #{n}: FAIL after {} ms (ready={}, body={:?})",
					run_start.elapsed().as_secs_f64(),
					ms,
					grim::nym::is_ready(),
					other.map(|b| b.chars().take(40).collect::<String>())
				);
			}
		}
		tokio::time::sleep(Duration::from_secs(interval_secs)).await;
	}

	// Summary.
	lats.sort_unstable();
	let n_ok = lats.len();
	let sum: u128 = lats.iter().sum();
	let median = lats.get(n_ok / 2).copied().unwrap_or(0);
	println!(
		"\n==== SUMMARY ({}s run, {}s interval) ====",
		total_secs, interval_secs
	);
	println!("cold connect: {} ms", connect_ms.unwrap());
	println!("fetches: {} ok, {} failed", n_ok, fails);
	if n_ok > 0 {
		println!(
			"warm fetch latency ms: min {} / median {} / max {} / mean {}",
			lats.first().unwrap(),
			median,
			lats.last().unwrap(),
			sum / n_ok as u128
		);
		let head: Vec<u128> = lats.iter().take(3).copied().collect();
		println!("(sorted sample) fastest 3: {:?}", head);
	}
}
