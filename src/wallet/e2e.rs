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

//! LIVE two-wallet end-to-end payment over the Floonet path. Two real Goblin
//! wallets restored from mainnet mnemonics (seeds via env, NEVER a file) connect
//! to `wss://relay.goblin.st` — which rides the scoped Nym exit (.8) per the
//! pinned pool — and one sends a real gift-wrapped Grin payment to the other,
//! asynchronously through the relay. Proves the whole money path a phone would
//! use: mixnet -> exit -> relay -> gift wrap -> S2 -> finalize -> post.
//!
//! Ignored by default (real mainnet funds + a full recovery scan). Run:
//!   GOBLIN_E2E_SEED_A="word ..." GOBLIN_E2E_SEED_B="word ..." \
//!     cargo test --lib wallet::e2e::tests::two_goblins_pay_over_floonet -- --ignored --nocapture

#[cfg(test)]
mod tests {
	use std::time::{Duration, Instant};

	use grin_util::types::ZeroingString;

	use crate::nostr::NostrSendStatus;
	use crate::wallet::types::{ConnectionMethod, PhraseMode, WalletTask};
	use crate::wallet::{ConnectionsConfig, ExternalConnection, Mnemonic, Wallet};

	/// 0.1 GRIN, in nanograin. Small on purpose (mainnet, real funds).
	const AMOUNT: u64 = 100_000_000;
	/// Public mainnet node for the recovery scan + tx post.
	const NODE_URL: &str = "https://grincoin.org";

	/// Build + open a wallet from a 24-word mnemonic on an external node.
	fn open_wallet(name: &str, phrase: &str, pw: &ZeroingString, conn_id: i64) -> Wallet {
		let mut m = Mnemonic::default();
		m.set_mode(PhraseMode::Import);
		m.import(&ZeroingString::from(phrase));
		assert!(
			m.valid(),
			"{name}: mnemonic did not validate (bad seed words?)"
		);
		let conn = ConnectionMethod::External(conn_id, NODE_URL.to_string());
		let w = Wallet::create(&name.to_string(), pw, &m, &conn)
			.unwrap_or_else(|e| panic!("{name}: wallet create failed: {e}"));
		w.open(pw.clone())
			.unwrap_or_else(|e| panic!("{name}: wallet open failed: {e}"));
		w
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

		// Register the mainnet node once; reuse its id for both wallets.
		let node = ExternalConnection::new(NODE_URL.to_string(), Some("grin".to_string()), None);
		let conn_id = node.id;
		ConnectionsConfig::add_ext_conn(node);

		let pw = ZeroingString::from("e2e-test-pass");

		println!("[e2e] opening wallet A...");
		let a = open_wallet("goblin-e2e-a", seed_a.trim(), &pw, conn_id);
		// Wallet id = unix seconds; two creates in the same second collide.
		std::thread::sleep(Duration::from_millis(1500));
		println!("[e2e] opening wallet B...");
		let b = open_wallet("goblin-e2e-b", seed_b.trim(), &pw, conn_id);

		// Nostr services connect to relay.goblin.st (over the exit).
		let a_svc = a.nostr_service().expect("A nostr service");
		let b_svc = b.nostr_service().expect("B nostr service");
		let t_conn = Instant::now();
		assert!(
			wait_until("A nostr connected", 120, || a_svc.is_connected()),
			"A never connected to a relay"
		);
		assert!(
			wait_until("B nostr connected", 120, || b_svc.is_connected()),
			"B never connected to a relay"
		);
		println!(
			"[e2e] both goblins connected to the relay over the exit in {}s",
			t_conn.elapsed().as_secs()
		);
		println!("[e2e] A npub = {}", a_svc.npub());
		println!("[e2e] B npub = {}", b_svc.npub());

		// Recovery scan: concurrent across both wallets. Sender needs spendable.
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

		// Sender = whichever wallet actually has the funds.
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

		// Fire the async payment over the floonet relay.
		let t_send = Instant::now();
		sender.task(WalletTask::NostrSend(
			AMOUNT,
			receiver_hex.clone(),
			Some("floonet e2e".to_string()),
			vec![],
		));

		// Watch the sender's meta walk Created -> AwaitingS2 -> Finalized.
		let finalized = wait_until("payment finalized", 420, || {
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
		println!("[e2e] SUCCESS: two goblins completed a payment over the floonet relay");
	}
}
