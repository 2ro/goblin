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

//! Scoped-MixnetStream egress — the MONEY-PATH ANCHOR. When the relay pool
//! advertises a relay operator's CO-LOCATED Nym exit
//! ([`crate::nostr::pool::PoolRelay::exit`]), the wallet dials that exit
//! directly over the mixnet with a [`MixnetStream`]; the exit pipes the bytes
//! to its ONE configured relay. No public DNS, no public IPR — the two flaky
//! dependencies of the fallback path are gone from the money path. The exit is
//! scoped (it forwards nowhere else), so the wallet writes nothing but the TLS
//! ClientHello: the dial sites run the SAME hostname-validated TLS (SNI = the
//! relay host) + websocket/HTTP wrap over this stream as over the smolmix
//! tunnel's TCP stream, and the exit sees only ciphertext.
//!
//! ANCHOR + FALLBACK, never pin-only: every failure here (bad address, client
//! bootstrap, stream open, timeout) just returns `Err`, and the dial sites
//! ([`super::transport`], [`super::request_once`]) fall through to the
//! public-IPR tunnel ([`super::nymproc`]) — losing the operator's exit never
//! locks the wallet out. Server side: the bundled `floonet-mixexit` binary
//! (design in ~/.claude/plans/floonet-nym-exit.md).

use std::time::Duration;

use log::{info, warn};
use nym_sdk::mixnet::{MixnetClient, MixnetStream, Recipient};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

/// Everything the TLS/websocket layer needs from the egress stream.
pub trait ExitStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> ExitStream for T {}

/// The boxed transport stream handed to the TLS/websocket layer — the same
/// seat the smolmix tunnel's TCP stream occupies on the fallback path.
pub type BoxedStream = Box<dyn ExitStream>;

/// After the Open is SENT, wait this long before handing back a writable
/// stream. `open_stream` returns once the Open message leaves the client, NOT
/// once the exit has `accept()`ed and wired its inbound half. But the caller
/// speaks first (TLS ClientHello over a raw-pipe exit), so a write landing in
/// that gap is dropped and the handshake stalls into a fallback. One mixnet
/// round of slack lets the exit be listening before the first byte.
/// ponytail: fixed settle (measured: 0s always stalls, 3s is reliable). The
/// exit pipes raw bytes to its relay, so it can't inject an accept-ack for the
/// client to wait on; if mixnet jitter ever makes 3s flaky, raise it.
const STREAM_SETTLE: Duration = Duration::from_secs(3);

/// Process-lifetime mixnet client for the scoped-exit egress, lazily connected
/// on first use (mirrors the tunnel singleton in [`super::nymproc`]).
/// Ephemeral in-memory identity, like the tunnel — a fresh mixnet identity per
/// run. Behind an async mutex because `open_stream` needs `&mut`; a dead
/// client (cancelled shutdown token or a failed open) is dropped so the next
/// dial reconnects fresh.
static CLIENT: Mutex<Option<MixnetClient>> = Mutex::const_new(None);

// NOTE ON FIRST-DIAL LATENCY: the exit rides a SECOND ephemeral MixnetClient
// (separate from the smolmix tunnel). On a cold app start both clients acquire
// Nym free-tier bandwidth, and the grants serialize — so the first dial that
// bootstraps this client can take ~a minute while the tunnel already has its
// grant. Measured: a startup pre-warm does NOT help — a second client warming
// in parallel just starves the tunnel/fallback for the same total, and slows
// the tunnel too. The real fix is sharing ONE mixnet client for tunnel + exit
// (larger change; tracked separately). Meanwhile the cost is one-time per cold
// start, the payment itself is fast once connected, and discovery/secondary
// relays + the fallback ride the tunnel, so availability is never blocked.

/// Open a scoped MixnetStream to `exit` — a pool-advertised Nym address
/// (`<client>.<enc>@<gateway>`) of a relay operator's co-located exit. The
/// whole dial (client bootstrap when cold + stream open) is capped at
/// `min(timeout, BOOTSTRAP_TIMEOUT)` so a stuck bootstrap fails FAST into the
/// caller's public-IPR fallback. NOTE: `open_stream` is fire-and-forget on the
/// mixnet — a DEAD exit still hands back a stream, and its death surfaces at
/// the caller's (timeout-bounded) TLS handshake, which doubles as the
/// liveness probe: no ServerHello through the pipe → fall back.
pub async fn open_stream(exit: &str, timeout: Duration) -> Result<BoxedStream, String> {
	let recipient: Recipient = exit
		.trim()
		.parse()
		.map_err(|e| format!("invalid exit address: {e}"))?;
	let cap = timeout.min(super::nymproc::BOOTSTRAP_TIMEOUT);
	let stream = match tokio::time::timeout(cap, open(recipient)).await {
		Ok(result) => result?,
		Err(_) => return Err(format!("exit dial exceeded {}s", cap.as_secs())),
	};
	// Let the exit accept() + wire its inbound half before the caller writes.
	tokio::time::sleep(STREAM_SETTLE).await;
	Ok(Box::new(stream) as BoxedStream)
}

/// Ensure the shared client is connected, then open a stream on it.
async fn open(recipient: Recipient) -> Result<MixnetStream, String> {
	let mut guard = CLIENT.lock().await;
	// A dead client (gateway dropped, hosting runtime gone) is discarded and
	// rebuilt — the auto-reconnect-on-drop rule.
	if guard
		.as_ref()
		.is_some_and(|c| c.cancellation_token().is_cancelled())
	{
		warn!("nym: streamexit client died; reconnecting");
		*guard = None;
	}
	if guard.is_none() {
		let started = std::time::Instant::now();
		let client = MixnetClient::connect_new()
			.await
			.map_err(|e| format!("mixnet client bootstrap failed: {e}"))?;
		info!(
			"[timing] nym: streamexit client CONNECTED in {}ms",
			started.elapsed().as_millis()
		);
		*guard = Some(client);
	}
	let client = guard.as_mut().expect("client ensured above");
	match client.open_stream(recipient, None).await {
		Ok(stream) => Ok(stream),
		Err(e) => {
			// `open_stream` fails only LOCALLY (the client's input channel) —
			// it never waits on the peer — so an error means the client itself
			// is broken, not the exit. Drop it; the next dial reconnects.
			*guard = None;
			Err(format!("open_stream failed: {e}"))
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[tokio::test]
	async fn bad_exit_address_fails_fast_without_touching_the_mixnet() {
		// The address parse runs BEFORE any client bootstrap, so garbage from
		// a hostile pool costs nothing and degrades to the fallback path.
		let err = open_stream("not-a-recipient", Duration::from_secs(5))
			.await
			.err()
			.expect("garbage address must fail");
		assert!(err.contains("invalid exit address"), "got: {err}");
	}

	/// LIVE end-to-end smoke test of the money path against the DEPLOYED
	/// floonet-mixexit (.8): dial the pinned pool's `exit` for relay.goblin.st
	/// over the mixnet with the real [`open_stream`], run the SAME
	/// hostname-validated TLS + websocket wrap the wallet uses
	/// ([`super::super::transport`]), then send a nostr REQ and require the
	/// relay to answer (EVENT/EOSE). Proves mixnet -> exit -> relay:443 ->
	/// nostr actually carries traffic. Ignored (needs network + a cold mixnet
	/// bootstrap). Run:
	///   cargo test --lib nym::streamexit::tests::live_exit_roundtrip -- --ignored --nocapture
	#[tokio::test]
	#[ignore]
	async fn live_exit_roundtrip() {
		use futures::{SinkExt, StreamExt};
		use tokio_tungstenite::tungstenite::Message;

		// The app installs this at startup (src/lib.rs); an isolated test must
		// too, or rustls 0.23 can't pick a provider for the TLS handshake.
		let _ = rustls::crypto::ring::default_provider().install_default();

		let exit = crate::nostr::pool::load()
			.exit_for("wss://relay.goblin.st")
			.expect("pinned pool advertises the relay.goblin.st exit");
		println!("dialing scoped exit {exit}");

		// A cold ephemeral mixnet bootstrap can exceed the per-dial cap; the
		// real wallet just falls back and retries, so retry until one dial wins.
		let mut stream = None;
		for attempt in 1..=6 {
			let t = std::time::Instant::now();
			match open_stream(&exit, Duration::from_secs(90)).await {
				Ok(s) => {
					println!(
						"open_stream OK on attempt {attempt} in {}ms",
						t.elapsed().as_millis()
					);
					stream = Some(s);
					break;
				}
				Err(e) => println!(
					"attempt {attempt} failed in {}ms: {e}",
					t.elapsed().as_millis()
				),
			}
		}
		let stream = stream.expect("exit stream opened within retries");

		let url = "wss://relay.goblin.st";
		let (mut ws, _resp) = tokio::time::timeout(
			Duration::from_secs(45),
			tokio_tungstenite::client_async_tls(url, stream),
		)
		.await
		.expect("TLS+ws handshake timed out (dead exit?)")
		.expect("TLS+ws handshake through exit failed");
		println!("TLS+ws handshake through .8 exit OK");

		ws.send(Message::Text(
			r#"["REQ","smoke",{"kinds":[1],"limit":1}]"#.into(),
		))
		.await
		.expect("send REQ");

		let reply = tokio::time::timeout(Duration::from_secs(30), ws.next())
			.await
			.expect("relay reply timed out")
			.expect("ws stream closed early")
			.expect("ws frame error");
		let txt = match reply {
			Message::Text(t) => t.to_string(),
			other => format!("{other:?}"),
		};
		println!("relay answered through exit: {txt}");
		assert!(
			txt.contains("EVENT") || txt.contains("EOSE"),
			"unexpected relay reply: {txt}"
		);
	}
}
