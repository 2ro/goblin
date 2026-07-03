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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use log::{debug, warn};
use tokio::io::{AsyncRead, AsyncWrite};

pub use nymproc::{
	condemn_exit, is_ready, report_relay_down, report_relay_live, set_relay_consumer,
	transport_ready, tunnel_generation, warm_up,
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

/// How long a pooled keep-alive connection may sit idle before we discard it
/// rather than reuse a possibly half-dead handle (hyper's `is_closed()` catches
/// cleanly-closed ones; this bounds the silent-death window).
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

/// Pool key: a live HTTP/1.1 keep-alive connection is reusable only for the same
/// host, port and scheme.
#[derive(Clone, PartialEq, Eq, Hash)]
struct ConnKey {
	host: String,
	port: u16,
	https: bool,
}

/// A pooled hyper request handle. The body type matches [`request_once`]'s.
type HttpSender = hyper::client::conn::http1::SendRequest<Full<Bytes>>;

struct Pooled {
	sender: HttpSender,
	idle_since: Instant,
}

lazy_static::lazy_static! {
	/// Idle keep-alive connections, keyed by (host, port, https). A sender is
	/// REMOVED while in use and reinserted when the exchange finishes, so the map
	/// only ever holds idle handles and the lock is never held across an await.
	static ref CONN_POOL: Mutex<HashMap<ConnKey, Pooled>> = Mutex::new(HashMap::new());
}

/// Take a live, non-idle-expired pooled sender for `key`, if one exists. A
/// closed or stale handle is dropped (tearing down its connection) and `None`
/// returned so the caller builds a fresh one.
fn take_pooled(key: &ConnKey) -> Option<HttpSender> {
	let mut pool = CONN_POOL.lock().ok()?;
	let pooled = pool.remove(key)?;
	if pooled.sender.is_closed() || pooled.idle_since.elapsed() >= POOL_IDLE_TIMEOUT {
		return None;
	}
	Some(pooled.sender)
}

/// Return a still-live sender to the pool for the next request to reuse.
fn store_pooled(key: ConnKey, sender: HttpSender) {
	if sender.is_closed() {
		return;
	}
	if let Ok(mut pool) = CONN_POOL.lock() {
		pool.insert(
			key,
			Pooled {
				sender,
				idle_since: Instant::now(),
			},
		);
	}
}

/// Send one request/response exchange on `sender`. On success returns the parsed
/// `(status, body, location)` AND the sender (drained and ready for the next
/// request, so the caller can pool it). `None` if the connection failed.
async fn exchange(
	mut sender: HttpSender,
	method: &str,
	url: &url::Url,
	body: Option<Vec<u8>>,
	headers: &[(String, String)],
	host: &str,
	https: bool,
	port: u16,
) -> Option<((u16, Vec<u8>, Option<String>), HttpSender)> {
	let m = hyper::Method::from_bytes(method.as_bytes()).ok()?;
	let path = match url.query() {
		Some(q) => format!("{}?{q}", url.path()),
		None => url.path().to_string(),
	};
	let host_header = if (https && port == 443) || (!https && port == 80) {
		host.to_string()
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
	Some(((status, bytes, location), sender))
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
	let key = ConnKey {
		host: host.clone(),
		port,
		https,
	};

	// KEEP-ALIVE FAST PATH: reuse a pooled connection for this (host, port,
	// https) when one is live, skipping a fresh mixnet TCP + TLS + HTTP handshake.
	// This is what makes the many small reads (price, contact-name resolution)
	// fast. Only steady-state tunnel connections are pooled (see below); the
	// cold-start scoped-exit fallback is one-shot.
	if let Some(sender) = take_pooled(&key) {
		if let Some((resp, sender)) = exchange(
			sender,
			method,
			url,
			body.clone(),
			headers,
			&host,
			https,
			port,
		)
		.await
		{
			store_pooled(key, sender);
			return Some(resp);
		}
		// Pooled connection died mid-exchange: fall through and build a fresh one.
	}

	// TUNNEL-FIRST for HTTP. NIP-11/HTTP is PUBLIC data (relay docs, price, name
	// authority) and both egresses are mixnet-private, so in steady state we ride
	// the already-warm tunnel — opening a fresh MixnetStream + settle to a scoped
	// exit PER request was pure latency here. Only when the tunnel isn't up yet
	// (`!is_ready()`) do we fall to a host's co-located scoped exit to avoid a cold
	// wait; failure there just falls through to the tunnel path below. transport.rs
	// (relay websockets) stays exit-first and is untouched — this is the HTTP path
	// only.
	let exit_io = if https && !nymproc::is_ready() {
		match crate::nostr::pool::load().exit_for_host(&host) {
			Some(exit) => exit_connect(&host, &exit).await,
			None => None,
		}
	} else {
		None
	};
	// The one-shot scoped-exit fallback is NOT pooled — it's a cold-start bridge
	// while the tunnel comes up. Only tunnel-borne connections go in the pool.
	let poolable = exit_io.is_none();

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

	let (sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(io))
		.await
		.map_err(|e| warn!("nym http: handshake with {host} failed: {e}"))
		.ok()?;
	// Drive the connection in the background. It stays alive for keep-alive reuse
	// as long as the pooled sender is held; it ends once the sender is dropped
	// (evicted from the pool) or the peer closes the connection.
	tokio::spawn(async move {
		let _ = conn.await;
	});

	let (resp, sender) = exchange(sender, method, url, body, headers, &host, https, port).await?;
	if poolable {
		store_pooled(key, sender);
	}
	Some(resp)
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
