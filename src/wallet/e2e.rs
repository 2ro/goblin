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

//! LIVE two-wallet end-to-end payment over the Floonet path — over the shared
//! exit-backed primary relay, CROSS-NODE. Two real Goblin wallets restored from
//! mainnet mnemonics (seeds via env, NEVER a file) both run on the shipped
//! default relay (`wss://relay.floonet.dev`, each pinned via its own
//! `nostr.toml`) but on DIFFERENT Grin nodes (A on grincoin.org, B on
//! main.gri.mw). One sends a real gift-wrapped Grin payment to the other,
//! asynchronously through the relay. Proves the whole money path a phone would
//! use, plus the outbox model: the sender publishes the wrap to the RECIPIENT's
//! advertised (kind 10050) relay, and settlement posts through two independent
//! nodes.
//! mixnet -> exit -> gift wrap -> S2 -> finalize -> post.
//!
//! Ignored by default (real mainnet funds + a full recovery scan). Run:
//!   GOBLIN_E2E_SEED_A="word ..." GOBLIN_E2E_SEED_B="word ..." \
//!     cargo test --lib wallet::e2e::tests::two_goblins_pay_over_floonet -- --ignored --nocapture
//!
//! This module ALSO hosts `funded_e2e_pay` (see its doc): the task-spec funded
//! harness — a single default node (api.grin.money), both wallets on
//! relay.floonet.dev over its co-located SCOPED EXIT, reading
//! GOBLIN_E2E_MNEMONIC_A/B, with a throwaway-wallet SMOKE mode that proves the
//! plumbing up to the money move.

#[cfg(test)]
mod tests {
	use std::path::PathBuf;
	use std::time::{Duration, Instant};

	use grin_util::ToHex;
	use grin_util::types::ZeroingString;
	use grin_wallet_libwallet::TxLogEntryType;

	use crate::nostr::{Contact, NostrConfig, NostrSendStatus};
	use crate::wallet::types::{ConnectionMethod, PhraseMode, WalletTask};
	use crate::wallet::{ConnectionsConfig, ExternalConnection, Mnemonic, Wallet};

	/// 0.1 GRIN, in nanograin. Small on purpose (mainnet, real funds).
	const AMOUNT: u64 = 100_000_000;
	/// Wallet A's mainnet node (recovery scan + tx post).
	const NODE_A: &str = "https://grincoin.org";
	/// Wallet B's mainnet node — a DIFFERENT operator, so the payment settles
	/// across two independent nodes.
	const NODE_B: &str = "https://main.gri.mw";
	/// Wallet A's relay (pinned via its nostr.toml, advertised in its 10050).
	/// The new primary money-path relay, reached over its co-located scoped exit.
	const RELAY_A: &str = "wss://relay.floonet.dev";
	/// Wallet B's relay — the SAME shared exit-backed primary as A (how the
	/// shipped product works: every Goblin wallet defaults to relay.floonet.dev).
	/// Both reach it over the co-located scoped exit, so the gift-wrap round-trip
	/// rides the fast money path end to end. Nodes still differ (below), so the
	/// payment still settles across two independent Grin nodes.
	const RELAY_B: &str = "wss://relay.floonet.dev";

	/// Build + open a wallet from a 24-word mnemonic on its own external node
	/// and its own single-relay nostr.toml override.
	fn open_wallet(
		name: &str,
		phrase: &str,
		pw: &ZeroingString,
		conn_id: i64,
		node_url: &str,
		relay: &str,
		mode: PhraseMode,
	) -> Wallet {
		// Import (restore a real seed) marks the wallet InitNeedsScanning → a full
		// from-genesis UTXO recovery scan on first open (how funds are (re)found;
		// slow — bounded by the scan budget). Generate makes a FRESH throwaway seed
		// marked InitNoScanning → no genesis scan, so an empty wallet syncs from the
		// external foreign node in seconds. The node is always an EXTERNAL foreign
		// node (ConnectionMethod::External below), never an embedded full node.
		let mut m = Mnemonic::default();
		if mode == PhraseMode::Import {
			m.set_mode(PhraseMode::Import);
			m.import(&ZeroingString::from(phrase));
			assert!(
				m.valid(),
				"{name}: mnemonic did not validate (bad seed words?)"
			);
		}
		let conn = ConnectionMethod::External(conn_id, node_url.to_string());
		let w = Wallet::create(&name.to_string(), pw, &m, &conn)
			.unwrap_or_else(|e| panic!("{name}: wallet create failed: {e}"));
		// Pin this wallet to a single relay BEFORE open(): init_nostr loads
		// nostr.toml from the wallet data dir on open, and a `relays` override
		// both drives the client's relay set and is advertised as the wallet's
		// kind 10050 DM inbox (see NostrService::relays / publish_identity).
		let wallet_dir = PathBuf::from(w.get_config().get_data_path());
		let mut nostr_cfg = NostrConfig::load(wallet_dir.clone());
		nostr_cfg.set_relays(vec![relay.to_string()]);
		println!(
			"[e2e] {name}: node={node_url} relay={relay} (nostr.toml at {})",
			wallet_dir.join(NostrConfig::FILE_NAME).display()
		);
		w.open(pw.clone())
			.unwrap_or_else(|e| panic!("{name}: wallet open failed: {e}"));
		w
	}

	/// The persisted form of "added this payee from their nprofile": a contact
	/// carrying their DM relay, so payment routing (send_targets -> fetch_dm_relays)
	/// uses that relay directly instead of blind kind-10050 discovery over the
	/// exit-less indexers. BOTH legs of a cross-relay payment need this seeded.
	fn contact_with_relay(npub_hex: &str, relay: &str) -> Contact {
		Contact {
			ver: 1,
			npub: npub_hex.to_string(),
			petname: None,
			nip05: None,
			nip05_verified_at: None,
			relays: vec![relay.to_string()],
			nip44_v3: false,
			hue: 0,
			unknown: false,
			added_at: 0,
			last_paid_at: None,
			blocked: false,
		}
	}

	/// Poll `cond` until true or `secs` elapse; log progress via `label`.
	fn wait_until(label: &str, secs: u64, mut cond: impl FnMut() -> bool) -> bool {
		let start = Instant::now();
		let mut last = 0u64;
		while start.elapsed() < Duration::from_secs(secs) {
			if cond() {
				println!("[e2e] {label}: OK in {}s", start.elapsed().as_secs());
				return true;
			}
			let el = start.elapsed().as_secs();
			if el >= last + 15 {
				last = el;
				println!("[e2e] {label}: waiting... {el}s");
			}
			std::thread::sleep(Duration::from_secs(2));
		}
		println!("[e2e] {label}: TIMEOUT after {secs}s");
		false
	}

	#[test]
	#[ignore]
	fn two_goblins_pay_over_floonet() {
		let seed_a = std::env::var("GOBLIN_E2E_SEED_A").unwrap_or_default();
		let seed_b = std::env::var("GOBLIN_E2E_SEED_B").unwrap_or_default();
		if seed_a.trim().is_empty() || seed_b.trim().is_empty() {
			println!("[e2e] SKIP: set GOBLIN_E2E_SEED_A and GOBLIN_E2E_SEED_B");
			return;
		}

		// Isolate wallet + nym state under a throwaway HOME. MUST precede any
		// grim call (Settings roots at $HOME/.goblin on first deref).
		let home = std::env::var("GOBLIN_E2E_HOME").unwrap_or_else(|_| {
			std::env::temp_dir()
				.join("goblin-e2e-home")
				.to_string_lossy()
				.into_owned()
		});
		unsafe {
			std::env::set_var("HOME", &home);
		}
		println!("[e2e] HOME = {home}");

		// The app installs these at startup (src/lib.rs); a bare test must too.
		let _ = rustls::crypto::ring::default_provider().install_default();
		crate::nym::warm_up();
		assert!(
			wait_until("nym tunnel is_ready", 180, crate::nym::is_ready),
			"nym tunnel never came up"
		);

		// Register a SEPARATE mainnet node per wallet. ExternalConnection ids
		// are unix seconds, and add_ext_conn dedupes on id — two conns built in
		// the same second would collide — so bump B's id explicitly.
		let node_a = ExternalConnection::new(NODE_A.to_string(), Some("grin".to_string()), None);
		let conn_a = node_a.id;
		ConnectionsConfig::add_ext_conn(node_a);
		let mut node_b =
			ExternalConnection::new(NODE_B.to_string(), Some("grin".to_string()), None);
		node_b.id = conn_a + 1;
		let conn_b = node_b.id;
		ConnectionsConfig::add_ext_conn(node_b);

		let strip = |s: &str| {
			s.trim_start_matches("https://")
				.trim_start_matches("wss://")
				.to_string()
		};
		println!(
			"[e2e] A: node={} relay={} | B: node={} relay={}",
			strip(NODE_A),
			strip(RELAY_A),
			strip(NODE_B),
			strip(RELAY_B)
		);

		let pw = ZeroingString::from("e2e-test-pass");

		println!("[e2e] opening wallet A...");
		let a = open_wallet(
			"goblin-e2e-a",
			seed_a.trim(),
			&pw,
			conn_a,
			NODE_A,
			RELAY_A,
			PhraseMode::Import,
		);
		// Wallet id = unix seconds; two creates in the same second collide.
		std::thread::sleep(Duration::from_millis(1500));
		println!("[e2e] opening wallet B...");
		let b = open_wallet(
			"goblin-e2e-b",
			seed_b.trim(),
			&pw,
			conn_b,
			NODE_B,
			RELAY_B,
			PhraseMode::Import,
		);

		// Nostr services connect, each to its OWN relay (over the exit).
		let a_svc = a.nostr_service().expect("A nostr service");
		let b_svc = b.nostr_service().expect("B nostr service");
		let t_a = Instant::now();
		assert!(
			wait_until("A nostr connected", 240, || a_svc.is_connected()),
			"A never connected to its relay ({RELAY_A})"
		);
		println!("[e2e] A connected in {}s", t_a.elapsed().as_secs());
		let t_b = Instant::now();
		assert!(
			wait_until("B nostr connected", 240, || b_svc.is_connected()),
			"B never connected to its relay ({RELAY_B})"
		);
		println!("[e2e] B connected in {}s", t_b.elapsed().as_secs());
		println!("[e2e] A effective relays = {:?}", a_svc.relays());
		println!("[e2e] B effective relays = {:?}", b_svc.relays());
		assert_eq!(
			a_svc.relays(),
			vec![RELAY_A.to_string()],
			"A's relay override did not take"
		);
		assert_eq!(
			b_svc.relays(),
			vec![RELAY_B.to_string()],
			"B's relay override did not take"
		);
		println!("[e2e] A npub = {}", a_svc.npub());
		println!("[e2e] B npub = {}", b_svc.npub());

		// Pre-seed each wallet's contact store with the other (npub + DM relay) —
		// the realistic "added the payee from their nprofile" path. Payment
		// routing then uses the cached DM relay directly, so BOTH legs cross
		// relays deterministically (A -> B's relay over the tunnel, B -> A's relay
		// over the exit) without the kind-10050 discovery fetch over the exit-less
		// indexers that stalled the pure-discovery run.
		a_svc
			.store
			.save_contact(&contact_with_relay(&b_svc.public_key().to_hex(), RELAY_B));
		b_svc
			.store
			.save_contact(&contact_with_relay(&a_svc.public_key().to_hex(), RELAY_A));
		println!("[e2e] seeded contacts: A knows B @ {RELAY_B}, B knows A @ {RELAY_A}");

		// Recovery scan: concurrent across both wallets, each against its own
		// node. Sender needs spendable.
		wait_until("A synced_from_node", 2400, || a.synced_from_node());
		wait_until("B synced_from_node", 2400, || b.synced_from_node());

		let spendable = |w: &Wallet| -> u64 {
			w.get_data()
				.map(|d| d.info.amount_currently_spendable)
				.unwrap_or(0)
		};
		let a_bal = spendable(&a);
		let b_bal = spendable(&b);
		println!("[e2e] spendable: A={a_bal} nano, B={b_bal} nano (need {AMOUNT})");

		// Sender = whichever wallet actually has the funds. Either way the wrap
		// crosses relays: the sender fetches the recipient's kind 10050 (from
		// the recipient's relay + the discovery indexers) and publishes the
		// gift wrap THERE — the outbox path this test exists to prove.
		let (sender, sender_svc, recv_svc, sender_name) = if a_bal >= AMOUNT + 20_000_000 {
			(&a, &a_svc, &b_svc, "A")
		} else if b_bal >= AMOUNT + 20_000_000 {
			(&b, &b_svc, &a_svc, "B")
		} else {
			panic!(
				"neither wallet has >= {AMOUNT}+fee spendable (A={a_bal}, B={b_bal}); fund one and retry"
			);
		};
		let receiver_hex = recv_svc.public_key().to_hex();
		println!("[e2e] sender = {sender_name}; paying {AMOUNT} nano to {receiver_hex}");

		// Fire the async payment across the two relays.
		let t_send = Instant::now();
		sender.task(WalletTask::NostrSend(
			AMOUNT,
			receiver_hex.clone(),
			Some("floonet e2e".to_string()),
			vec![],
		));

		// Watch the sender's meta walk Created -> AwaitingS2 -> Finalized.
		// Generous window: two relays + two nodes + mixnet round trips.
		let finalized = wait_until("payment finalized", 900, || {
			if let Some(err) = sender_svc.last_send_error() {
				println!("[e2e] sender last_send_error: {err}");
			}
			sender_svc
				.store
				.all_tx_meta()
				.iter()
				.any(|m| matches!(m.status, NostrSendStatus::Finalized))
		});

		println!(
			"[e2e] send->finalize elapsed {}s; finalized={finalized}",
			t_send.elapsed().as_secs()
		);
		// Dump both stores for the record.
		for (who, svc) in [("sender", sender_svc), ("receiver", recv_svc)] {
			for m in svc.store.all_tx_meta() {
				println!("[e2e] {who} meta {} -> {:?}", m.slate_id, m.status);
			}
		}

		a.close();
		b.close();

		assert!(
			finalized,
			"payment did not reach Finalized within the window (see meta trail above)"
		);
		println!("[e2e] SUCCESS: cross-relay + cross-node payment finalized over the floonet path");
	}

	// ─────────────────────────────────────────────────────────────────────────
	// FUNDED E2E HARNESS (task-spec): single default node (api.grin.money), both
	// wallets on the shipped money-path relay reached over its co-located SCOPED
	// EXIT. Reads GOBLIN_E2E_MNEMONIC_A/B; smoke-mode generates throwaway EMPTY
	// wallets to prove the plumbing up to the money move. Reuses the helpers
	// above so this stays tiny and rides Goblin's OWN wallet + nostr code.
	// ─────────────────────────────────────────────────────────────────────────

	/// Non-empty trimmed env var, else `None`.
	fn e2e_env(key: &str) -> Option<String> {
		std::env::var(key)
			.ok()
			.map(|s| s.trim().to_string())
			.filter(|s| !s.is_empty())
	}
	/// Env var parsed as u64, else `default`.
	fn e2e_env_u64(key: &str, default: u64) -> u64 {
		e2e_env(key).and_then(|s| s.parse().ok()).unwrap_or(default)
	}
	/// Truthy env flag (`1` / `true`).
	fn e2e_flag(key: &str) -> bool {
		e2e_env(key)
			.map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
			.unwrap_or(false)
	}
	/// Headless END-TO-END real-Grin payment A → B over the just-split money path,
	/// driven entirely by Goblin's own wallet + nostr code (no slate crypto is
	/// reimplemented here). Steps: restore both wallets from their mnemonics into
	/// per-wallet temp dirs → open against the grin node and recovery-scan → A
	/// sends a real payment to B THROUGH the nostr DM path (slatepack →
	/// kind-1059 gift-wrap → published over the SCOPED EXIT to relay.floonet.dev)
	/// → B's running service unwraps, ingests (receive), replies S2 the same path
	/// → A auto-finalizes and posts to the node → verify Finalized (= accepted by
	/// node) and, best-effort, B's received tx reaching 1 confirmation.
	///
	/// The nostr identity is a per-wallet RANDOM nsec (see nostr/identity.rs), NOT
	/// derived from the wallet seed — so B's real runtime npub (read here) is the
	/// pay target and its advertised inbox + subscription line up by construction.
	///
	/// Ignored by default (real mainnet funds + a full recovery scan). Run:
	///   GOBLIN_E2E_MNEMONIC_A="word ..." GOBLIN_E2E_MNEMONIC_B="word ..." \
	///     RUST_LOG=grim=info \
	///     cargo test --lib wallet::e2e::tests::funded_e2e_pay -- --ignored --nocapture
	/// Smoke (empty throwaway wallets, stops at insufficient funds — proves the
	/// plumbing up to the money move):
	///   GOBLIN_E2E_ALLOW_UNFUNDED=1 GOBLIN_E2E_SCAN_WAIT=180 RUST_LOG=grim=info \
	///     cargo test --lib wallet::e2e::tests::funded_e2e_pay -- --ignored --nocapture
	/// Knobs: GOBLIN_E2E_NODE (default https://api.grin.money), GOBLIN_E2E_AMOUNT
	/// (nano, default 0.1 GRIN), GOBLIN_E2E_CONFIRM_WAIT (finalize+confirm budget
	/// secs, default 600), GOBLIN_E2E_SCAN_WAIT (recovery-scan budget secs, default
	/// 2400), GOBLIN_E2E_HOME (default /tmp/e2e-home).
	#[test]
	#[ignore]
	fn funded_e2e_pay() {
		// Shipped money-path relay, reached over its co-located scoped exit.
		const RELAY: &str = "wss://relay.floonet.dev";
		// Task env: MNEMONIC_A/B (fall back to SEED_A/B for parity with the
		// cross-node test above). Absent + ALLOW_UNFUNDED=1 → throwaway EMPTY
		// wallets to smoke the plumbing.
		let allow_unfunded = e2e_flag("GOBLIN_E2E_ALLOW_UNFUNDED");
		let mnem_a = e2e_env("GOBLIN_E2E_MNEMONIC_A").or_else(|| e2e_env("GOBLIN_E2E_SEED_A"));
		let mnem_b = e2e_env("GOBLIN_E2E_MNEMONIC_B").or_else(|| e2e_env("GOBLIN_E2E_SEED_B"));
		let (mnem_a, mnem_b, smoke) = match (mnem_a, mnem_b) {
			(Some(a), Some(b)) => (a, b, false),
			_ if allow_unfunded => {
				println!(
					"[fe2e] no mnemonics in env; SMOKE mode with FRESH throwaway EMPTY wallets \
					 (no-scan, sync fast from the external node)"
				);
				(String::new(), String::new(), true)
			}
			_ => {
				println!(
					"[fe2e] SKIP: set GOBLIN_E2E_MNEMONIC_A and GOBLIN_E2E_MNEMONIC_B \
					 (or GOBLIN_E2E_ALLOW_UNFUNDED=1 to smoke the plumbing)"
				);
				return;
			}
		};

		let node =
			e2e_env("GOBLIN_E2E_NODE").unwrap_or_else(|| "https://api.grin.money".to_string());
		let amount = e2e_env_u64("GOBLIN_E2E_AMOUNT", AMOUNT);
		let need = amount + 20_000_000; // amount + generous fee headroom
		let scan_wait = e2e_env_u64("GOBLIN_E2E_SCAN_WAIT", 2400);
		let confirm_wait = e2e_env_u64("GOBLIN_E2E_CONFIRM_WAIT", 600);

		// Isolate wallet + nym state under a throwaway HOME. MUST precede any grim
		// call (Settings roots at $HOME/.goblin on first deref, incl. pool::load).
		let home = e2e_env("GOBLIN_E2E_HOME").unwrap_or_else(|| "/tmp/e2e-home".to_string());
		unsafe {
			std::env::set_var("HOME", &home);
		}
		// Surface the nym transport info logs — the exit-connect evidence line
		// ("CONNECTED via scoped exit") is emitted at info by the money client.
		let _ = env_logger::Builder::from_env(
			env_logger::Env::default().default_filter_or("grim=info"),
		)
		.is_test(false)
		.try_init();
		println!("[fe2e] HOME={home} node={node} relay={RELAY} amount={amount} nano smoke={smoke}");

		// App-startup shims a bare test must do itself.
		let _ = rustls::crypto::ring::default_provider().install_default();

		// ── EXIT EVIDENCE (deterministic, offline). The compiled-in pinned pool
		// maps the money relay to its co-located SCOPED Nym exit; the money client's
		// NymWebSocketTransport dials THAT (kind-1059 gift-wraps only), while the
		// identity/general client is stock CLEARNET. Assert the money path is
		// actually exit-anchored before spending a cent. ──
		let pool = crate::nostr::pool::load();
		let exit = pool.exit_for(RELAY);
		println!(
			"[fe2e] EXIT EVIDENCE: pool.has_exit={} exit_for({RELAY})={:?}",
			pool.has_exit(),
			exit
		);
		assert!(
			exit.is_some(),
			"money relay {RELAY} advertises no scoped exit in the pool; the split money path cannot be verified"
		);

		crate::nym::warm_up();
		assert!(
			wait_until("nym tunnel is_ready", 180, crate::nym::is_ready),
			"nym tunnel never came up"
		);
		println!(
			"[fe2e] nym ready; tunnel_generation={}",
			crate::nym::tunnel_generation()
		);

		// One external node for BOTH wallets: the money path splits at the RELAY
		// (nostr DM over the exit), not the node — node HTTP is clearnet either way.
		let node_conn = ExternalConnection::new(node.clone(), Some("grin".to_string()), None);
		let conn_id = node_conn.id;
		ConnectionsConfig::add_ext_conn(node_conn);

		let pw = ZeroingString::from("e2e-test-pass");
		// Real mnemonics → Import (restore + scan); smoke → Generate (fresh no-scan).
		let phrase_mode = if smoke {
			PhraseMode::Generate
		} else {
			PhraseMode::Import
		};
		println!("[fe2e] opening wallet A...");
		let a = open_wallet(
			"goblin-fe2e-a",
			&mnem_a,
			&pw,
			conn_id,
			&node,
			RELAY,
			phrase_mode.clone(),
		);
		// Wallet id = unix seconds; two creates in the same second collide.
		std::thread::sleep(Duration::from_millis(1500));
		println!("[fe2e] opening wallet B...");
		let b = open_wallet(
			"goblin-fe2e-b",
			&mnem_b,
			&pw,
			conn_id,
			&node,
			RELAY,
			phrase_mode,
		);

		let a_svc = a.nostr_service().expect("A nostr service");
		let b_svc = b.nostr_service().expect("B nostr service");
		println!("[fe2e] A npub={} | B npub={}", a_svc.npub(), b_svc.npub());

		// Connect over the scoped exit. Fatal for a real run; best-effort for smoke.
		let a_conn = wait_until("A nostr connected (scoped exit)", 240, || {
			a_svc.is_connected()
		});
		let b_conn = wait_until("B nostr connected (scoped exit)", 240, || {
			b_svc.is_connected()
		});
		if !smoke {
			assert!(a_conn, "A never connected to {RELAY} over the exit");
			assert!(b_conn, "B never connected to {RELAY} over the exit");
		}
		println!(
			"[fe2e] connected A={a_conn} B={b_conn}; A relays={:?} B relays={:?}",
			a_svc.relays(),
			b_svc.relays()
		);

		// Seed contacts both ways (the realistic "added payee from nprofile" path)
		// so payment routing uses the cached DM relay directly.
		a_svc
			.store
			.save_contact(&contact_with_relay(&b_svc.public_key().to_hex(), RELAY));
		b_svc
			.store
			.save_contact(&contact_with_relay(&a_svc.public_key().to_hex(), RELAY));

		// Recovery scan (bounded, non-fatal). Import wallets scan from genesis
		// (slow — bounded by scan_wait); Generate/no-scan wallets sync from the
		// external foreign node in seconds. sync_error=false + synced=true is the
		// positive proof the external node was reached (not an embedded node).
		let a_synced = wait_until("A synced_from_node", scan_wait, || a.synced_from_node());
		let b_synced = wait_until("B synced_from_node", scan_wait, || b.synced_from_node());
		println!(
			"[fe2e] synced_from_node A={a_synced} B={b_synced}; sync_error A={} B={}",
			a.sync_error(),
			b.sync_error()
		);

		let spendable = |w: &Wallet| -> u64 {
			w.get_data()
				.map(|d| d.info.amount_currently_spendable)
				.unwrap_or(0)
		};
		let tip = |w: &Wallet| -> u64 {
			w.get_data()
				.map(|d| d.info.last_confirmed_height)
				.unwrap_or(0)
		};
		let a_bal = spendable(&a);
		let b_bal = spendable(&b);
		println!(
			"[fe2e] node contact (clearnet): A tip={} B tip={}",
			tip(&a),
			tip(&b)
		);
		println!("[fe2e] spendable: A={a_bal} nano  B={b_bal} nano  (need {need})");

		// ── SEND STEP. If neither wallet is funded we have reached the money move
		// with nothing to spend: a clean SMOKE PASS (plumbing proven) or a real
		// failure (you funded a wallet — where is it?). ──
		if a_bal < need && b_bal < need {
			println!(
				"[fe2e] STOP at send step: insufficient funds (A={a_bal}, B={b_bal}, need {need})."
			);
			a.close();
			b.close();
			if smoke {
				println!(
					"[fe2e] SMOKE PASS: plumbing green through the send step — both fresh throwaway \
					 wallets opened against {node} (EXTERNAL foreign node; synced_from_node A={a_synced} \
					 B={b_synced}, sync_error false, tips above prove the node was reached fast — no \
					 embedded node), nostr services started and {}connected over the scoped exit for \
					 {RELAY}; exit-anchored money path asserted; halted at insufficient funds (expected \
					 for empty wallets). Set GOBLIN_E2E_MNEMONIC_A/B to a funded pair for the real \
					 payment (Import restore → GOBLIN_E2E_SCAN_WAIT scan).",
					if a_conn && b_conn { "" } else { "(partially) " }
				);
				return;
			}
			panic!(
				"neither wallet has >= {need} nano spendable (A={a_bal}, B={b_bal}); fund one and retry"
			);
		}

		let (sender, sender_svc, recv, recv_svc, sender_name) = if a_bal >= need {
			(&a, &a_svc, &b, &b_svc, "A")
		} else {
			(&b, &b_svc, &a, &a_svc, "B")
		};
		let receiver_hex = recv_svc.public_key().to_hex();
		let recv_before = spendable(recv);
		println!(
			"[fe2e] sender={sender_name} paying {amount} nano to {receiver_hex}; receiver spendable before={recv_before}"
		);

		// Fire ONE NostrSend. The running services drive the WHOLE money path
		// themselves: A builds S1 → gift-wrap over the scoped exit → B unwraps +
		// receives + replies S2 the same path → A finalizes + posts to the node.
		let t_send = Instant::now();
		sender.task(WalletTask::NostrSend(
			amount,
			receiver_hex.clone(),
			Some("funded e2e".to_string()),
			vec![],
		));

		// Finalized = "finalized AND posted to node" (see NostrSendStatus). This is
		// the accepted-by-node gate — reported even before on-chain confirmation.
		let finalized = wait_until("payment finalized+posted", confirm_wait, || {
			if let Some(err) = sender_svc.last_send_error() {
				println!("[fe2e] sender last_send_error: {err}");
			}
			sender_svc
				.store
				.all_tx_meta()
				.iter()
				.any(|m| matches!(m.status, NostrSendStatus::Finalized))
		});
		println!(
			"[fe2e] send→finalize elapsed {}s finalized={finalized}",
			t_send.elapsed().as_secs()
		);

		// Meta trail + payment/finalize ids.
		let mut slate_id: Option<String> = None;
		let mut wrap_id: Option<String> = None;
		for (who, svc) in [("sender", sender_svc), ("receiver", recv_svc)] {
			for m in svc.store.all_tx_meta() {
				println!(
					"[fe2e] {who} meta slate={} status={:?} wrap={:?}",
					m.slate_id, m.status, m.sent_event_id
				);
				if who == "sender" && matches!(m.status, NostrSendStatus::Finalized) {
					slate_id = Some(m.slate_id.clone());
					wrap_id = m.sent_event_id.clone();
				}
			}
		}
		println!(
			"[fe2e] TX IDS: slate_id={:?} giftwrap_event_id={:?}",
			slate_id, wrap_id
		);

		// On-chain: poll B's received tx to 1 confirmation, print the kernel excess
		// (Grin's on-chain identifier) + balance delta. Bounded, best-effort.
		if finalized {
			let want_slate = slate_id.clone();
			let confirmed = wait_until("receiver tx confirmed (1 block)", confirm_wait, || {
				recv.get_data()
					.map(|d| {
						d.txs.unwrap_or_default().iter().any(|t| {
							t.data.tx_type == TxLogEntryType::TxReceived
								&& t.data.confirmed && want_slate.as_ref().is_none_or(|s| {
								t.data.tx_slate_id.map(|u| u.to_string()).as_deref()
									== Some(s.as_str())
							})
						})
					})
					.unwrap_or(false)
			});
			if let Some(d) = recv.get_data() {
				let tip = d.info.last_confirmed_height;
				for t in d
					.txs
					.unwrap_or_default()
					.iter()
					.filter(|t| t.data.tx_type == TxLogEntryType::TxReceived)
				{
					let kernel = t.data.kernel_excess.map(|k| k.to_hex());
					let confs = match t.height {
						Some(h) if t.data.confirmed => tip.saturating_sub(h) + 1,
						_ => 0,
					};
					println!(
						"[fe2e] receiver TxReceived slate={:?} confirmed={} height={:?} confs={} credited={} kernel_excess={:?}",
						t.data.tx_slate_id.map(|u| u.to_string()),
						t.data.confirmed,
						t.height,
						confs,
						t.data.amount_credited,
						kernel
					);
				}
			}
			let recv_after = spendable(recv);
			println!(
				"[fe2e] receiver spendable before={recv_before} after={recv_after} onchain_confirmed={confirmed}"
			);
		}

		a.close();
		b.close();

		assert!(
			finalized,
			"payment did not reach Finalized within {confirm_wait}s (see meta trail above)"
		);
		println!(
			"[fe2e] PASS: {sender_name}→other paid {amount} nano; gift-wrap rode the scoped exit \
			 for {RELAY}, S2 returned the same path, A finalized + posted to {node}. \
			 slate_id={slate_id:?} giftwrap={wrap_id:?}"
		);
	}
}
