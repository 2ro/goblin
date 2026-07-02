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
//! every HTTP request (NIP-05, price, relay pool) — rides the 5-hop mixnet:
//! by default one in-process smolmix [`Tunnel`](smolmix::Tunnel) to an
//! auto-selected public IPR exit, so neither the payload nor the
//! destination-in-flight ever touches the clearnet. Hostnames resolve through
//! the same tunnel too ([`dns`], DoT — DNS-over-TLS), so nothing goes
//! clearnet. MONEY-PATH ANCHOR: a host whose relay advertises a co-located
//! scoped exit in the pool is instead dialed over a MixnetStream straight to
//! that exit ([`streamexit`]) — no DNS and no public IPR at all — falling
//! back to the tunnel on any failure. The mixnet breaks the sender↔receiver
//! timing correlation that Mimblewimble's interactive slate exchange
//! otherwise leaks at the network layer.
//!
//! DNS reliability was the one weak spot: the original mix-dns sent UDP over the
//! mixnet, and mixnet UDP loses packets — resolves stalled on multi-second
//! timeouts (~10s measured), tipping relay connects past the exit-condemnation
//! grace and driving a 2-3 minute reselect loop. Build 98 moves DNS to DoT
//! (TCP+TLS through the tunnel): TCP retransmits (no packet-loss stalls) and TLS
//! encrypts the query from the exit — reliable AND private.

pub mod dns;
pub mod nymproc;
pub mod streamexit;
pub mod transport;

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use log::{debug, warn};
use tokio::io::{AsyncRead, AsyncWrite};

pub use nymproc::{
	is_ready, report_relay_down, report_relay_live, set_relay_consumer, transport_ready,
	tunnel_generation, warm_up,
};
pub use transport::NymWebSocketTransport;

/// How long a single HTTP exchange (one redirect hop) may take end to end.
/// The mixnet adds deliberate per-hop delay; allow generous time.
const HTTP_TIMEOUT: Duration = Duration::from_secs(60);

/// How long to wait for the shared tunnel before giving up on a request.
const TUNNEL_WAIT: Duration = Duration::from_secs(30);

/// Redirect hops to follow before giving up (matches the old client, which
/// followed redirects transparently).
const MAX_REDIRECTS: usize = 5;

/// An HTTP request routed over the Nym mixnet: resolve the host over the tunnel
/// (DoT — see [`dns`]), then `tcp_connect` to that IP through the tunnel, then
/// rustls (webpki roots) for https, then HTTP/1.1. Follows redirects. Returns
/// `(status, body)`.
pub async fn http_request_bytes(
	method: &str,
	url: String,
	body: Option<Vec<u8>>,
	headers: Vec<(String, String)>,
) -> Option<(u16, Vec<u8>)> {
	let tunnel = nymproc::wait_for_tunnel(TUNNEL_WAIT).await?;
	let mut url = url::Url::parse(&url).ok()?;
	let mut method = method.to_uppercase();
	let mut body = body;
	for _ in 0..=MAX_REDIRECTS {
		let (status, resp_body, location) = tokio::time::timeout(
			HTTP_TIMEOUT,
			request_once(&tunnel, &method, &url, body.clone(), &headers),
		)
		.await
		.map_err(|_| warn!("nym http: request to {} timed out", redacted(&url)))
		.ok()??;
		match location {
			Some(loc) => {
				url = url.join(&loc).ok()?;
				// Like the old client: 303 (and legacy 301/302) turn into a
				// bodiless GET; 307/308 replay the method + body.
				if matches!(status, 301..=303) {
					method = "GET".to_string();
					body = None;
				}
				debug!(
					"nym http: following {status} redirect to {}",
					redacted(&url)
				);
			}
			None => return Some((status, resp_body)),
		}
	}
	warn!("nym http: too many redirects for {}", redacted(&url));
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

/// A single HTTP/1.1 exchange over the tunnel. Returns the status, the
/// collected body and, for 3xx responses, the `Location` target.
async fn request_once(
	tunnel: &smolmix::Tunnel,
	method: &str,
	url: &url::Url,
	body: Option<Vec<u8>>,
	headers: &[(String, String)],
) -> Option<(u16, Vec<u8>, Option<String>)> {
	let host = url.host_str()?.to_string();
	let https = url.scheme() == "https";
	let port = url.port().unwrap_or(if https { 443 } else { 80 });

	// MONEY-PATH ANCHOR fork: HTTPS to a host whose relay advertises a
	// co-located scoped Nym exit (its NIP-11 probe, in practice) rides a
	// MixnetStream to that exit instead of the tunnel — no public DNS, no
	// public IPR. Failure just falls through to the tunnel path below (anchor
	// + fallback, never pin-only).
	let exit_io = if https {
		match crate::nostr::pool::load().exit_for_host(&host) {
			Some(exit) => exit_connect(&host, &exit).await,
			None => None,
		}
	} else {
		None
	};

	let io: Box<dyn Stream> = match exit_io {
		Some(io) => io,
		None => {
			// Resolve the host over the tunnel (DoT — see dns), then dial that
			// IP through the same tunnel so nothing (lookup or body) touches
			// the clear.
			let addr = dns::resolve(tunnel, &host, port).await?;
			let tcp = match tunnel.tcp_connect(addr).await {
				Ok(s) => s,
				Err(e) => {
					warn!("nym http: connect to {host} failed: {e}");
					return None;
				}
			};
			if https {
				match tls_connect(&host, tcp).await {
					Some(tls) => Box::new(tls),
					None => return None,
				}
			} else {
				Box::new(tcp)
			}
		}
	};

	let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
		.await
		.map_err(|e| warn!("nym http: handshake with {host} failed: {e}"))
		.ok()?;
	// Drive the connection until the exchange finishes; it ends itself once
	// the response (and body) is done or the sender is dropped.
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
		.map_err(|e| warn!("nym http: request to {host} failed: {e}"))
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

/// Try the scoped-exit egress for an HTTPS `host`: a MixnetStream to the
/// relay operator's exit ([`streamexit`]), then the SAME hostname-validated
/// [`tls_connect`] as the tunnel path — SNI = `host`, so the exit sees only
/// ciphertext. `None` (logged) on ANY failure, and the whole attempt is
/// bounded by the shared bootstrap cap — a dead exit costs seconds inside the
/// caller's [`HTTP_TIMEOUT`] budget, leaving room to fall back to the tunnel.
async fn exit_connect(host: &str, exit: &str) -> Option<Box<dyn Stream>> {
	let cap = nymproc::BOOTSTRAP_TIMEOUT;
	let dial = async {
		let stream = streamexit::open_stream(exit, cap)
			.await
			.map_err(|e| warn!("nym http: scoped exit for {host} unavailable: {e}"))
			.ok()?;
		let tls = tls_connect(host, stream).await?;
		debug!("nym http: {host} riding its operator's scoped exit");
		Some(Box::new(tls) as Box<dyn Stream>)
	};
	match tokio::time::timeout(cap, dial).await {
		Ok(io) => io,
		Err(_) => {
			warn!(
				"nym http: scoped exit dial for {host} exceeded {}s; falling back to the tunnel",
				cap.as_secs()
			);
			None
		}
	}
}

/// Everything hyper (and the TLS/websocket layers) needs from a mixnet-carried
/// stream, boxable for the plain http / https / scoped-exit split. Shared with
/// the scoped-exit egress ([`streamexit::BoxedStream`]).
pub(crate) trait Stream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Stream for T {}

lazy_static::lazy_static! {
	/// Shared rustls client config (webpki roots; ring provider installed at
	/// startup — the Build 65/66 rule), reused by every in-tunnel TLS handshake
	/// (HTTPS here, DoT/DoH in [`dns`]).
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

/// TLS-wrap a tunneled TCP stream with rustls + webpki roots (never the
/// platform verifier — it panics on Android outside a full app context). The
/// certificate is validated against the HOSTNAME even though the dial went to a
/// DoT-resolved IP, so a lying resolver or a hostile exit cannot MITM.
async fn tls_connect<S>(host: &str, stream: S) -> Option<tokio_rustls::client::TlsStream<S>>
where
	S: AsyncRead + AsyncWrite + Send + Unpin,
{
	let server_name = rustls::pki_types::ServerName::try_from(host.to_string()).ok()?;
	tokio_rustls::TlsConnector::from(tls_config())
		.connect(server_name, stream)
		.await
		.map_err(|e| warn!("nym http: tls handshake with {host} failed: {e}"))
		.ok()
}
