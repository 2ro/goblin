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

//! Embedded-Tor transport. For a wallet with Tor on, everything Goblin sends over
//! the network (nostr relay websockets and every HTTP request: NIP-05, price,
//! relay pool, avatars) rides Tor, embedded in-process (arti), copied from our
//! sister wallet GRIM's proven, shipping engine. A wallet with Tor off goes direct.
//! Each HTTP request names its own [`Route`]: a request made for a wallet carries
//! that wallet's setting, and only requests that belong to no wallet use
//! [`app_route`]. Every relay is reached over a Tor exit to its clearnet host,
//! with the usual hostname-validated TLS for `wss://`: the wallet's own IP is
//! never exposed, while the relay stays a normal public endpoint. (Earlier builds
//! could pin a per-relay `.onion` for a direct onion-circuit money path; that was
//! dropped in build134 — onion services flapped — in favour of Tor-exit only.)
//!
//! Tor is free, unmetered, has no token or grant to expire, and GRIM has already
//! proven the whole embedded path on desktop and Android.
//!
//! The Grin blockchain node is NOT routed here — it stays on the clear internet
//! exactly as before; it never sees who pays whom.

mod engine;
mod transport;

pub use engine::{
	Client, client, condemn_exit, connect, is_ready, report_relay_down, report_relay_live,
	set_relay_consumer, transport_ready, tunnel_generation, wait_ready, warm_up,
};
pub use transport::{ClearnetWebSocketTransport, TorWebSocketTransport};

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper_util::rt::TokioIo;
use log::{debug, warn};
use parking_lot::RwLock;
use tokio::io::{AsyncRead, AsyncWrite};

use crate::Settings;

/// How long a single HTTP exchange (one redirect hop) may take end to end.
const HTTP_TIMEOUT: Duration = Duration::from_secs(60);

/// How long to wait for the embedded Tor client to bootstrap before giving up on
/// a request. A cold Tor bootstrap can take tens of seconds; a warm one is fast.
const TUNNEL_WAIT: Duration = Duration::from_secs(60);

/// Redirect hops to follow before giving up.
const MAX_REDIRECTS: usize = 5;

/// Default `User-Agent` for every Tor-carried HTTP request. A common desktop
/// browser string (not "goblin-wallet"), so the wallet's traffic is not trivially
/// classifiable as Goblin at the destination. Callers may still override it by
/// passing their own `User-Agent` in the headers list; the endpoints Goblin talks
/// to (GitHub API, CoinGecko, name authorities) all accept a generic UA.
pub(crate) const DEFAULT_USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) \
	 Chrome/131.0.0.0 Safari/537.36";

/// The network path of one HTTP request. The caller always names it: a request
/// made for a wallet passes THAT wallet's resolved `NostrConfig::tor_enabled()`.
/// No process-wide flag decides it, because several wallets can be open at once
/// with different settings, and one wallet's Tor-off choice must never send
/// another wallet's signed request out from the real IP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
	/// Over the embedded Tor client. When Tor is not ready the request is
	/// dropped; it never falls back to clearnet.
	Tor,
	/// Direct (clearnet, optionally via the user's AppConfig proxy). Never waits
	/// on, or fails because of, the Tor bootstrap.
	Clearnet,
}

impl From<bool> for Route {
	/// A wallet's resolved Tor setting: `true` = [`Route::Tor`].
	fn from(over_tor: bool) -> Route {
		if over_tor {
			Route::Tor
		} else {
			Route::Clearnet
		}
	}
}

/// Whether a request takes the clearnet branch. Decided by the request's own
/// route only, never by the open-wallet registry (split out so a test can hold
/// that line).
fn goes_clearnet(route: Route) -> bool {
	route == Route::Clearnet
}

lazy_static::lazy_static! {
	/// Tor setting of every wallet whose nostr service runs, keyed by wallet id
	/// (`WalletConfig::id`, fixed for the life of the wallet). Only
	/// [`app_route`] reads it, for requests that belong to no wallet.
	static ref WALLET_ROUTES: RwLock<HashMap<i64, bool>> = RwLock::new(HashMap::new());
}

/// Record a wallet's Tor setting. Called when its nostr service starts, and by
/// the Tor toggles so the app-level answer follows the new choice at once.
pub fn set_wallet_route(wallet_id: i64, over_tor: bool) {
	WALLET_ROUTES.write().insert(wallet_id, over_tor);
}

/// Forget a wallet's Tor setting (its wallet closed).
pub fn remove_wallet_route(wallet_id: i64) {
	WALLET_ROUTES.write().remove(&wallet_id);
}

/// Route for a request that belongs to no wallet (update check, price): Tor
/// unless at least one wallet is open and every open wallet has Tor off.
pub fn app_route() -> Route {
	app_route_of(WALLET_ROUTES.read().values().copied())
}

/// The app-level rule over the open wallets' settings (pure, for tests). With
/// no wallet open the answer is Tor; one Tor-on wallet is enough for Tor.
fn app_route_of(mut open_wallets: impl Iterator<Item = bool>) -> Route {
	match open_wallets.next() {
		None => Route::Tor,
		Some(first) => Route::from(first || open_wallets.any(|over_tor| over_tor)),
	}
}

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

/// An HTTP request on the given [`Route`]. On [`Route::Tor`]: dial the host over
/// Tor (an onion via a real onion circuit, a clearnet host via a Tor exit; arti
/// resolves the name internally, so nothing leaks a clearnet DNS lookup), then
/// rustls (webpki roots) for https, then HTTP/1.1. Follows redirects. Returns
/// `(status, body)`. On [`Route::Clearnet`] the same request goes direct.
///
/// For now clearnet-over-Tor is fine for the small lookups (names at goblin.st,
/// relay hints, pool refresh, price, avatars); pinning those behind onions is a
/// later pass.
pub async fn http_request_bytes(
	route: Route,
	method: &str,
	url: String,
	body: Option<Vec<u8>>,
	headers: Vec<(String, String)>,
) -> Option<(u16, Vec<u8>)> {
	// Tor-off route: go direct (clearnet, honoring the user's AppConfig proxy).
	// Never wait on / hard-fail against the Tor bootstrap in this mode.
	if goes_clearnet(route) {
		return crate::http::clearnet_request_bytes(method, url, body, headers).await;
	}
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
	route: Route,
	method: &str,
	url: String,
	body: Option<String>,
	headers: Vec<(String, String)>,
) -> Option<String> {
	http_request_bytes(route, method, url, body.map(|b| b.into_bytes()), headers)
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
		.header(hyper::header::USER_AGENT, DEFAULT_USER_AGENT);
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
	// Bound the collected body so a hostile exit / endpoint can't OOM the wallet
	// with a multi-GB stream (shared cap with the clearnet path).
	let bytes = crate::http::collect_body_capped(resp).await?;
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

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn default_user_agent_is_browser_like_not_goblin() {
		// The default UA must read as a common desktop browser, so Goblin's Tor
		// traffic is not trivially fingerprintable at the destination.
		assert!(DEFAULT_USER_AGENT.starts_with("Mozilla/5.0"));
		assert!(DEFAULT_USER_AGENT.contains("Chrome/"));
		assert!(DEFAULT_USER_AGENT.contains("Safari/"));
		// No line-continuation whitespace leaked into the literal.
		assert!(!DEFAULT_USER_AGENT.contains("  "));
		assert!(!DEFAULT_USER_AGENT.contains('\n'));
		// The old identifying string is gone.
		assert!(!DEFAULT_USER_AGENT.to_lowercase().contains("goblin"));
	}

	#[test]
	fn route_follows_the_wallet_setting() {
		assert_eq!(Route::from(true), Route::Tor);
		assert_eq!(Route::from(false), Route::Clearnet);
	}

	#[test]
	fn app_route_rule_over_open_wallets() {
		// No wallet open: Tor (the historical default).
		assert_eq!(app_route_of(std::iter::empty()), Route::Tor);
		// One Tor-on wallet and one Tor-off wallet: Tor, in either order.
		assert_eq!(app_route_of([true, false].into_iter()), Route::Tor);
		assert_eq!(app_route_of([false, true].into_iter()), Route::Tor);
		// Every open wallet has Tor off: clearnet.
		assert_eq!(app_route_of([false].into_iter()), Route::Clearnet);
		assert_eq!(app_route_of([false, false].into_iter()), Route::Clearnet);
		// Every open wallet has Tor on: Tor.
		assert_eq!(app_route_of([true, true].into_iter()), Route::Tor);
	}

	/// Serializes the tests that touch the process-wide registry, so parallel
	/// tests cannot disturb each other's answer.
	static GLOBAL_REGISTRY: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

	/// Wallet ids here are far outside real ones (unix seconds).
	#[test]
	fn registry_tracks_open_wallets_and_never_routes_a_wallet_request() {
		const TOR_ON: i64 = -1_690_001;
		const TOR_OFF: i64 = -1_690_002;
		let _registry = GLOBAL_REGISTRY.lock();
		WALLET_ROUTES.write().clear();
		assert_eq!(app_route(), Route::Tor);

		// Only a Tor-off wallet open: app-level requests go direct.
		set_wallet_route(TOR_OFF, false);
		assert_eq!(app_route(), Route::Clearnet);
		// F1: even then, a request made for a Tor-on wallet keeps the Tor branch.
		// The branch follows the request's own route, not the registry.
		assert!(!goes_clearnet(Route::Tor));
		assert!(goes_clearnet(Route::Clearnet));

		// A Tor-on wallet opens: app-level requests ride Tor again.
		set_wallet_route(TOR_ON, true);
		assert_eq!(app_route(), Route::Tor);
		// And a request made for the Tor-off wallet still goes direct.
		assert!(goes_clearnet(Route::Clearnet));

		// The Tor-on wallet's toggle flips it off: every open wallet is off.
		set_wallet_route(TOR_ON, false);
		assert_eq!(app_route(), Route::Clearnet);
		set_wallet_route(TOR_ON, true);

		// The Tor-on wallet closes: its entry is removed.
		remove_wallet_route(TOR_ON);
		assert!(!WALLET_ROUTES.read().contains_key(&TOR_ON));
		assert_eq!(app_route(), Route::Clearnet);
		// The last wallet closes: no wallet open, back to Tor.
		remove_wallet_route(TOR_OFF);
		assert_eq!(app_route(), Route::Tor);
	}

	/// V3-1: an entry whose service never ran its exit (onboarding registered it
	/// and the wallet closed before start(), or the service died) is cleared by
	/// the removal `Wallet::close` makes, so no leftover Tor-off entry keeps
	/// app-level requests on clearnet once no wallet is open. A pure registry
	/// test: it replays the calls; a full `Wallet::close` needs an opened wallet.
	#[test]
	fn close_path_removal_clears_an_entry_its_service_never_removed() {
		const ONBOARDED_TOR_OFF: i64 = -1_690_003;
		let _registry = GLOBAL_REGISTRY.lock();
		WALLET_ROUTES.write().clear();

		// Onboarding records the new wallet's Tor-off choice; its service never
		// starts, so run_service's exit-time removal never runs.
		set_wallet_route(ONBOARDED_TOR_OFF, false);
		assert_eq!(app_route(), Route::Clearnet);

		// Wallet::close removes the entry right after taking the service out.
		remove_wallet_route(ONBOARDED_TOR_OFF);
		assert!(!WALLET_ROUTES.read().contains_key(&ONBOARDED_TOR_OFF));
		// No wallet open: app-level requests ride Tor again.
		assert_eq!(app_route(), Route::Tor);
		// A second removal (the service exit path running later) is harmless.
		remove_wallet_route(ONBOARDED_TOR_OFF);
		assert_eq!(app_route(), Route::Tor);
	}
}
