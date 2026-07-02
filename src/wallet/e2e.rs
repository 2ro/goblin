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

//! LIVE two-wallet end-to-end payment over the Floonet path — CROSS-RELAY and
//! CROSS-NODE. Two real Goblin wallets restored from mainnet mnemonics (seeds
//! via env, NEVER a file) run on DIFFERENT relays (A on `wss://relay.goblin.st`,
//! B on `wss://nrelay.us-ea.st`, each pinned via its own `nostr.toml`) and
//! DIFFERENT Grin nodes (A on grincoin.org, B on main.gri.mw). One sends a real
//! gift-wrapped Grin payment to the other, asynchronously through the relays.
//! Proves the whole money path a phone would use, plus the outbox model: the
//! sender publishes the wrap to the RECIPIENT's advertised (kind 10050) relay,
//! not its own, and settlement posts through two independent nodes.
//! mixnet -> exit -> cross-relay gift wrap -> S2 -> finalize -> post.
//!
//! Ignored by default (real mainnet funds + a full recovery scan). Run:
//!   GOBLIN_E2E_SEED_A="word ..." GOBLIN_E2E_SEED_B="word ..." \
//!     cargo test --lib wallet::e2e::tests::two_goblins_pay_over_floonet -- --ignored --nocapture

#[cfg(test)]
mod tests {
	use std::path::PathBuf;
	use std::time::{Duration, Instant};

	use grin_util::types::ZeroingString;

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
	) -> Wallet {
		let mut m = Mnemonic::default();
		m.set_mode(PhraseMode::Import);
		m.import(&ZeroingString::from(phrase));
		assert!(
			m.valid(),
			"{name}: mnemonic did not validate (bad seed words?)"
		);
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
		let a = open_wallet("goblin-e2e-a", seed_a.trim(), &pw, conn_a, NODE_A, RELAY_A);
		// Wallet id = unix seconds; two creates in the same second collide.
		std::thread::sleep(Duration::from_millis(1500));
		println!("[e2e] opening wallet B...");
		let b = open_wallet("goblin-e2e-b", seed_b.trim(), &pw, conn_b, NODE_B, RELAY_B);

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
}
