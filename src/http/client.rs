// Copyright 2025 The Grim Developers
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

use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::{Body, Incoming};
use hyper::{Request, Response};
use hyper_proxy2::{Intercept, Proxy, ProxyConnector};
use hyper_tls::HttpsConnector;
use hyper_util::client::legacy::{Client, Error};
use hyper_util::rt::TokioExecutor;
use log::warn;
use serde::de::StdError;

use crate::AppConfig;

/// How long a single clearnet HTTP exchange (one redirect hop) may take.
/// Matches the Tor path's ceiling so both transports behave the same to callers.
const HTTP_TIMEOUT: Duration = Duration::from_secs(60);

/// Redirect hops to follow before giving up (mirrors the Tor path).
const MAX_REDIRECTS: usize = 5;

/// Handles http requests.
pub struct HttpClient {}

impl HttpClient {
	/// Send request.
	pub async fn send<B>(req: Request<B>) -> Result<Response<Incoming>, Error>
	where
		B: Body + Send + 'static + Unpin,
		<B as Body>::Data: Send,
		B::Data: Send,
		B::Error: Into<Box<dyn StdError + Send + Sync>>,
	{
		if AppConfig::use_proxy() {
			if let Some(url) = AppConfig::socks_proxy_url() {
				Self::send_socks_proxy(url, req).await
			} else {
				Self::send_http_proxy(AppConfig::http_proxy_url().unwrap(), req).await
			}
		} else {
			let client = Client::builder(TokioExecutor::new()).build::<_, B>(HttpsConnector::new());
			client.request(req).await
		}
	}

	/// Create socks proxy client.
	pub async fn send_socks_proxy<B>(
		proxy_url: String,
		req: Request<B>,
	) -> Result<Response<Incoming>, Error>
	where
		B: Body + Send + 'static + Unpin,
		<B as Body>::Data: Send,
		B::Data: Send,
		B::Error: Into<Box<dyn StdError + Send + Sync>>,
	{
		let connector = HttpsConnector::new();
		let uri = proxy_url.parse().unwrap();
		let proxy = hyper_socks2::SocksConnector {
			proxy_addr: uri,
			auth: None,
			connector,
		}
		.with_tls()
		.unwrap();
		let client = Client::builder(TokioExecutor::new()).build::<_, B>(proxy);
		client.request(req).await
	}

	/// Create http proxy client.
	pub async fn send_http_proxy<B>(
		proxy_url: String,
		req: Request<B>,
	) -> Result<Response<Incoming>, Error>
	where
		B: Body + Send + 'static + Unpin,
		<B as Body>::Data: Send,
		B::Data: Send,
		B::Error: Into<Box<dyn StdError + Send + Sync>>,
	{
		let uri = proxy_url.parse().unwrap();
		let proxy = Proxy::new(Intercept::All, uri);
		let connector = HttpsConnector::new();
		let proxy_connector = ProxyConnector::from_proxy(connector, proxy).unwrap();
		let client = Client::builder(TokioExecutor::new()).build::<_, B>(proxy_connector);
		client.request(req).await
	}
}

/// A clearnet HTTP request, the direct counterpart to `crate::tor::http_request_bytes`
/// for Tor-off wallets. Same shape and redirect behavior, so every existing
/// caller (NIP-05, price, relay pool, NIP-11 probe) works unchanged once the
/// transport branch in `tor::http_request_bytes` routes here. Honors the user's
/// AppConfig proxy transparently via [`HttpClient::send`]. Returns `(status, body)`.
pub async fn clearnet_request_bytes(
	method: &str,
	url: String,
	body: Option<Vec<u8>>,
	headers: Vec<(String, String)>,
) -> Option<(u16, Vec<u8>)> {
	let mut url = url::Url::parse(&url).ok()?;
	let mut method = method.to_uppercase();
	let mut body = body;
	for _ in 0..=MAX_REDIRECTS {
		let (status, resp_body, location) = tokio::time::timeout(
			HTTP_TIMEOUT,
			clearnet_once(&method, &url, body.clone(), &headers),
		)
		.await
		.map_err(|_| {
			warn!(
				"clearnet http: request to {} timed out",
				url.host_str().unwrap_or("<no-host>")
			)
		})
		.ok()??;
		match location {
			Some(loc) => {
				url = url.join(&loc).ok()?;
				// 303 (and legacy 301/302) turn into a bodiless GET; 307/308 replay.
				if matches!(status, 301..=303) {
					method = "GET".to_string();
					body = None;
				}
			}
			None => return Some((status, resp_body)),
		}
	}
	warn!(
		"clearnet http: too many redirects for {}",
		url.host_str().unwrap_or("<no-host>")
	);
	None
}

/// A single clearnet HTTP/1.1 exchange (optionally proxied per AppConfig).
/// Returns the status, the collected body and, for 3xx responses, the
/// `Location` target — mirroring the Tor path's `request_once`.
async fn clearnet_once(
	method: &str,
	url: &url::Url,
	body: Option<Vec<u8>>,
	headers: &[(String, String)],
) -> Option<(u16, Vec<u8>, Option<String>)> {
	let m = hyper::Method::from_bytes(method.as_bytes()).ok()?;
	let mut req = Request::builder()
		.method(m)
		.uri(url.as_str())
		// Same browser-like default UA as the Tor path, so the wallet's clearnet
		// requests are not trivially classifiable as Goblin at the destination.
		.header(hyper::header::USER_AGENT, crate::tor::DEFAULT_USER_AGENT);
	for (k, v) in headers {
		req = req.header(k.as_str(), v.as_str());
	}
	let req = req
		.body(Full::new(Bytes::from(body.unwrap_or_default())))
		.ok()?;
	let resp = HttpClient::send(req)
		.await
		.map_err(|e| {
			warn!(
				"clearnet http: request to {} failed: {e}",
				url.host_str().unwrap_or("<no-host>")
			)
		})
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
