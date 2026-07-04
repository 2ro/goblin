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

//! Embedded-Tor transport. Everything Goblin sends over the network — nostr relay
//! websockets and every HTTP request (NIP-05, price, relay pool, avatars) — rides
//! Tor, embedded in-process (arti), copied from our sister wallet GRIM's proven,
//! shipping engine. Every relay is reached over a Tor exit to its clearnet host,
//! with the usual hostname-validated TLS for `wss://`: the wallet's own IP is
//! never exposed, while the relay stays a normal public endpoint. (Earlier builds
//! could pin a per-relay `.onion` for a direct onion-circuit money path; that was
//! dropped in build134 — onion services flapped — in favour of Tor-exit only.)
//!
//! This replaces the Nym-mixnet transport (`crate::nym`, left dormant): Tor is
//! free, unmetered, has no token or grant to expire, and GRIM has already proven
//! the whole embedded path on desktop and Android.
//!
//! The Grin blockchain node is NOT routed here — it stays on the clear internet
//! exactly as before; it never sees who pays whom.

mod engine;
mod transport;

pub use engine::{
	Client, client, condemn_exit, connect, is_ready, report_relay_down, report_relay_live,
	set_relay_consumer, transport_ready, tunnel_generation, wait_ready, warm_up,
};
pub use transport::TorWebSocketTransport;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use log::{debug, warn};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::Settings;

/// How long a single HTTP exchange (one redirect hop) may take end to end.
const HTTP_TIMEOUT: Duration = Duration::from_secs(60);

/// How long to wait for the embedded Tor client to bootstrap before giving up on
/// a request. A cold Tor bootstrap can take tens of seconds; a warm one is fast.
const TUNNEL_WAIT: Duration = Duration::from_secs(60);

/// Redirect hops to follow before giving up.
const MAX_REDIRECTS: usize = 5;

// --- Tor data directories -----------------------------------------------------

/// Base Tor data directory (`<base>/tor`).
fn base_path() -> PathBuf {
	Settings::base_path(Some("tor".to_string()))
}

/// Tor state directory (consensus, guards, …). Used by [`engine`].
pub(crate) fn state_path() -> String {
	let mut base = base_path();
	base.push("state");
	base.to_str().unwrap().to_string()
}

/// Tor cache directory (directory documents). Used by [`engine`].
pub(crate) fn cache_path() -> String {
	let mut base = base_path();
	base.push("cache");
	base.to_str().unwrap().to_string()
}

// --- HTTP over Tor ------------------------------------------------------------

/// An HTTP request routed over Tor: dial the host over Tor (an onion via a real
/// onion circuit, a clearnet host via a Tor exit — arti resolves the name
/// internally, so nothing leaks a clearnet DNS lookup), then rustls (webpki
/// roots) for https, then HTTP/1.1. Follows redirects. Returns `(status, body)`.
///
/// For now clearnet-over-Tor is fine for the small lookups (names at goblin.st,
/// relay hints, pool refresh, price, avatars); pinning those behind onions is a
/// later pass.
pub async fn http_request_bytes(
	method: &str,
	url: String,
	body: Option<Vec<u8>>,
	headers: Vec<(String, String)>,
) -> Option<(u16, Vec<u8>)> {
	if !wait_ready(TUNNEL_WAIT).await {
		warn!("tor http: client not bootstrapped, dropping request");
		return None;
	}
	let mut url = url::Url::parse(&url).ok()?;
	let mut method = method.to_uppercase();
	let mut body = body;
	for _ in 0..=MAX_REDIRECTS {
		let (status, resp_body, location) = tokio::time::timeout(
			HTTP_TIMEOUT,
			request_once(&method, &url, body.clone(), &headers),
		)
		.await
		.map_err(|_| warn!("tor http: request to {} timed out", redacted(&url)))
		.ok()??;
		match location {
			Some(loc) => {
				url = url.join(&loc).ok()?;
				// 303 (and legacy 301/302) turn into a bodiless GET; 307/308 replay.
				if matches!(status, 301..=303) {
					method = "GET".to_string();
					body = None;
				}
				debug!(
					"tor http: following {status} redirect to {}",
					redacted(&url)
				);
			}
			None => return Some((status, resp_body)),
		}
	}
	warn!("tor http: too many redirects for {}", redacted(&url));
	None
}

/// String-bodied convenience wrapper around [`http_request_bytes`].
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

/// Host without path/query, for logs (never log full URLs).
fn redacted(url: &url::Url) -> String {
	url.host_str().unwrap_or("<no-host>").to_string()
}

/// A single HTTP/1.1 exchange over Tor. Returns the status, the collected body
/// and, for 3xx responses, the `Location` target.
async fn request_once(
	method: &str,
	url: &url::Url,
	body: Option<Vec<u8>>,
	headers: &[(String, String)],
) -> Option<(u16, Vec<u8>, Option<String>)> {
	let host = url.host_str()?.to_string();
	let https = url.scheme() == "https";
	let port = url.port().unwrap_or(if https { 443 } else { 80 });

	let tcp = connect(&host, port)
		.await
		.map_err(|e| warn!("tor http: connect to {host} failed: {e}"))
		.ok()?;
	let io: Box<dyn Stream> = if https {
		Box::new(tls_connect(&host, tcp).await?)
	} else {
		Box::new(tcp)
	};

	let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
		.await
		.map_err(|e| warn!("tor http: handshake with {host} failed: {e}"))
		.ok()?;
	// Drive the connection in the background for this one exchange.
	tokio::spawn(async move {
		let _ = conn.await;
	});

	let m = hyper::Method::from_bytes(method.as_bytes()).ok()?;
	let path = match url.query() {
		Some(q) => format!("{}?{q}", url.path()),
		None => url.path().to_string(),
	};
	let host_header = if (https && port == 443) || (!https && port == 80) {
		host.clone()
	} else {
		format!("{host}:{port}")
	};
	let mut req = hyper::Request::builder()
		.method(m)
		.uri(path)
		.header(hyper::header::HOST, host_header)
		.header(hyper::header::USER_AGENT, "goblin-wallet");
	for (k, v) in headers {
		req = req.header(k, v);
	}
	let req = req
		.body(Full::new(Bytes::from(body.unwrap_or_default())))
		.ok()?;

	let resp = sender
		.send_request(req)
		.await
		.map_err(|e| warn!("tor http: request to {host} failed: {e}"))
		.ok()?;
	let status = resp.status().as_u16();
	let location = if resp.status().is_redirection() {
		resp.headers()
			.get(hyper::header::LOCATION)
			.and_then(|v| v.to_str().ok())
			.map(|s| s.to_string())
	} else {
		None
	};
	let bytes = resp.into_body().collect().await.ok()?.to_bytes().to_vec();
	Some((status, bytes, location))
}

/// Everything hyper (and the TLS layer) needs from a Tor-carried stream, boxable
/// for the plain-http / https split.
pub(crate) trait Stream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Stream for T {}

lazy_static::lazy_static! {
	/// Shared rustls client config (webpki roots; ring provider installed at
	/// startup — see lib.rs), reused by every clearnet-over-Tor https handshake.
	/// Never the platform verifier — it panics on Android outside a full app
	/// context.
	static ref TLS_CONFIG: Arc<rustls::ClientConfig> = {
		let mut roots = rustls::RootCertStore::empty();
		roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
		Arc::new(
			rustls::ClientConfig::builder()
				.with_root_certificates(roots)
				.with_no_client_auth(),
		)
	};
}

/// The shared rustls client config (cheap `Arc` bump).
pub(crate) fn tls_config() -> Arc<rustls::ClientConfig> {
	TLS_CONFIG.clone()
}

/// TLS-wrap a Tor-carried TCP stream with rustls + webpki roots. The certificate
/// is validated against the HOSTNAME, so a hostile Tor exit cannot MITM a
/// clearnet https fetch.
async fn tls_connect<S>(host: &str, stream: S) -> Option<tokio_rustls::client::TlsStream<S>>
where
	S: AsyncRead + AsyncWrite + Send + Unpin,
{
	let server_name = rustls::pki_types::ServerName::try_from(host.to_string()).ok()?;
	tokio_rustls::TlsConnector::from(tls_config())
		.connect(server_name, stream)
		.await
		.map_err(|e| warn!("tor http: tls handshake with {host} failed: {e}"))
		.ok()
}
