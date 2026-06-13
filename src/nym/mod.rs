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

//! Nym mixnet transport. Everything Goblin sends — nostr relay traffic and
//! every HTTP request (NIP-05, price, avatars) — is routed through a local
//! Nym SOCKS5 client (`nym-socks5-client`) that tunnels over the 5-hop mixnet
//! to a network requester. This replaces the embedded Tor (arti) client: the
//! mixnet breaks the sender↔receiver timing correlation that Mimblewimble's
//! interactive slate exchange otherwise leaks at the network layer, and it
//! bootstraps in ~2s rather than Tor's tens of seconds. Nothing goes clearnet.

pub mod sidecar;
pub mod transport;

use std::time::Duration;

pub use sidecar::warm_up;
pub use transport::NymWebSocketTransport;

/// Local SOCKS5 endpoint exposed by the bundled `nym-socks5-client` sidecar.
/// `socks5h` keeps DNS resolution inside the proxy so the destination host is
/// never resolved on the clear.
pub const SOCKS5_HOST: &str = "127.0.0.1";
pub const SOCKS5_PORT: u16 = 1080;

/// `socks5h://127.0.0.1:1080` proxy URL for reqwest.
pub fn proxy_url() -> String {
	format!("socks5h://{SOCKS5_HOST}:{SOCKS5_PORT}")
}

/// `127.0.0.1:1080` for the raw SOCKS5 TCP dialer (relay websockets).
pub fn socks5_addr() -> String {
	format!("{SOCKS5_HOST}:{SOCKS5_PORT}")
}

/// An HTTP request routed over the Nym mixnet via the local SOCKS5 sidecar.
/// Mirrors the old `Tor::http_request_bytes` signature so call sites swap 1:1.
/// Returns `(status, body)`.
pub async fn http_request_bytes(
	method: &str,
	url: String,
	body: Option<Vec<u8>>,
	headers: Vec<(String, String)>,
) -> Option<(u16, Vec<u8>)> {
	let proxy = reqwest::Proxy::all(proxy_url()).ok()?;
	let client = reqwest::Client::builder()
		.proxy(proxy)
		.user_agent("goblin-wallet")
		// The mixnet adds deliberate per-hop delay; allow generous time.
		.timeout(Duration::from_secs(60))
		.build()
		.ok()?;
	let m = reqwest::Method::from_bytes(method.as_bytes()).ok()?;
	let mut req = client.request(m, &url);
	for (k, v) in headers {
		req = req.header(k, v);
	}
	if let Some(b) = body {
		req = req.body(b);
	}
	let resp = req.send().await.ok()?;
	let code = resp.status().as_u16();
	let bytes = resp.bytes().await.ok()?.to_vec();
	Some((code, bytes))
}

/// String-bodied convenience wrapper (mirrors the old `Tor::http_request`).
pub async fn http_request(
	method: &str,
	url: String,
	body: Option<String>,
	headers: Vec<(String, String)>,
) -> Option<String> {
	http_request_bytes(method, url, body.map(|b| b.into_bytes()), headers)
		.await
		.map(|(_, raw)| String::from_utf8_lossy(&raw).to_string())
}
