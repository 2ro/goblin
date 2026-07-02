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

//! WebSocket transport for the Nostr relay pool routed through the Nym
//! mixnet, with TWO egresses picked per relay. ANCHOR: a relay whose pool
//! entry advertises its operator's co-located scoped exit
//! ([`crate::nostr::pool::PoolRelay::exit`]) is dialed over a MixnetStream
//! straight to that exit ([`super::streamexit`]) — no DNS, no public IPR.
//! FALLBACK (and every relay without an exit): Goblin's in-process smolmix
//! tunnel — the relay host is resolved by [`super::dns`], the TCP stream is
//! opened via `tunnel.tcp_connect`. Either way the SAME TLS (rustls, webpki
//! roots) + websocket handshake runs over the mixnet-carried stream, so the
//! payload + in-flight destination never touch the clear, and an exit failure
//! only ever falls back — never a lockout.

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use async_wsocket::futures_util::{Sink, SinkExt, StreamExt};
use async_wsocket::{ConnectionMode, Message};
use nostr_relay_pool::transport::error::TransportError;
use nostr_relay_pool::transport::websocket::{WebSocketSink, WebSocketStream, WebSocketTransport};
use nostr_sdk::Url;
use nostr_sdk::util::BoxedFuture;
use tokio_tungstenite::tungstenite::Message as TgMessage;

/// A backend transport error (failures outside the websocket layer) carrying
/// `msg` as its display text.
fn terr(msg: impl Into<String>) -> TransportError {
	TransportError::backend(std::io::Error::other(msg.into()))
}

/// Nostr websocket transport over the in-process Nym mixnet tunnel.
#[derive(Debug, Clone, Copy, Default)]
pub struct NymWebSocketTransport;

impl WebSocketTransport for NymWebSocketTransport {
	fn support_ping(&self) -> bool {
		true
	}

	fn connect<'a>(
		&'a self,
		url: &'a Url,
		_mode: &'a ConnectionMode,
		timeout: Duration,
	) -> BoxedFuture<'a, Result<(WebSocketSink, WebSocketStream), TransportError>> {
		Box::pin(async move {
			let host = url
				.host_str()
				.ok_or_else(|| terr("relay url has no host"))?
				.to_string();
			let port = url.port().unwrap_or(match url.scheme() {
				"ws" => 80,
				_ => 443,
			});

			// MONEY-PATH ANCHOR: when the pool advertises this relay
			// operator's co-located scoped Nym exit, dial THROUGH it — a
			// MixnetStream straight to the exit (which pipes to its one
			// relay), no public DNS, no public IPR, no tunnel dependency. The
			// TLS + websocket wrap inside is byte-for-byte the tunnel path's
			// (same `client_async_tls`, SNI = the relay host), so the exit
			// sees only ciphertext. ANY failure — bootstrap, open, handshake,
			// timeout — falls through to the public-IPR tunnel dial below:
			// anchor + fallback, never pin-only.
			if let Some(exit) = crate::nostr::pool::load().exit_for(url.as_str()) {
				let t_exit = std::time::Instant::now();
				match exit_connect(url, &exit, timeout).await {
					Ok(parts) => {
						log::info!(
							"[timing] nym: relay {host} CONNECTED via scoped exit — \
							 stream+tls+ws {}ms",
							t_exit.elapsed().as_millis()
						);
						return Ok(parts);
					}
					Err(e) => log::warn!(
						"nym: scoped exit dial for {host} failed after {}ms ({e}); \
						 falling back to the public-IPR tunnel",
						t_exit.elapsed().as_millis()
					),
				}
			}

			// The shared mixnet tunnel (lazy-started at app launch).
			let tunnel = crate::nym::nymproc::wait_for_tunnel(timeout)
				.await
				.ok_or_else(|| terr("nym tunnel not ready"))?;

			// Resolve the relay host (clearnet by default — see nym::dns), then
			// dial the resolved IP THROUGH the same tunnel so the TCP, TLS and
			// websocket all still ride the mixnet. Each stage is timed so the
			// connect-timing harness can attribute cost per relay.
			let t_resolve = std::time::Instant::now();
			let addr =
				tokio::time::timeout(timeout, crate::nym::dns::resolve(&tunnel, &host, port))
					.await
					.map_err(|_| terr("dns resolve timeout"))?
					.ok_or_else(|| terr(format!("could not resolve relay host {host}")))?;
			let resolve_ms = t_resolve.elapsed().as_millis();

			let t_tcp = std::time::Instant::now();
			let stream = tokio::time::timeout(timeout, tunnel.tcp_connect(addr))
				.await
				.map_err(|_| terr("nym tunnel connect timeout"))?
				.map_err(|e| terr(format!("nym tunnel connect failed: {e}")))?;
			let tcp_ms = t_tcp.elapsed().as_millis();

			// Perform TLS (for wss) + websocket handshake over the mixnet stream.
			let t_ws = std::time::Instant::now();
			let (ws, _response) = tokio::time::timeout(
				timeout,
				tokio_tungstenite::client_async_tls(url.as_str(), stream),
			)
			.await
			.map_err(|_| terr("websocket handshake timeout"))?
			.map_err(|e| terr(format!("websocket handshake failed: {e}")))?;
			log::info!(
				"[timing] nym: relay {host} CONNECTED — resolve {resolve_ms}ms, \
				 tcp_connect(mixnet) {tcp_ms}ms, tls+ws(mixnet) {}ms",
				t_ws.elapsed().as_millis()
			);

			Ok(split_ws(ws))
		})
	}
}

/// Dial `url` through the relay operator's scoped Nym exit `exit`: a
/// MixnetStream to the exit (which pipes to its one configured relay), then
/// the SAME hostname-validated TLS + websocket handshake as the tunnel path.
/// The handshake doubles as the exit liveness probe — `open_stream` is
/// fire-and-forget, so a dead exit surfaces here as a (bounded) timeout and
/// the caller falls back.
async fn exit_connect(
	url: &Url,
	exit: &str,
	timeout: Duration,
) -> Result<(WebSocketSink, WebSocketStream), TransportError> {
	let stream = crate::nym::streamexit::open_stream(exit, timeout)
		.await
		.map_err(terr)?;
	let (ws, _response) = tokio::time::timeout(
		timeout,
		tokio_tungstenite::client_async_tls(url.as_str(), stream),
	)
	.await
	.map_err(|_| terr("websocket handshake timeout (exit stream)"))?
	.map_err(|e| terr(format!("websocket handshake failed: {e}")))?;
	Ok(split_ws(ws))
}

/// Split a websocket into the pool's boxed sink/stream halves — shared by the
/// scoped-exit and tunnel dial paths, so everything above the byte transport
/// is identical whichever egress carried the connection.
fn split_ws<S>(ws: tokio_tungstenite::WebSocketStream<S>) -> (WebSocketSink, WebSocketStream)
where
	S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
	let (tx, rx) = ws.split();

	let sink: WebSocketSink = Box::new(NymSink(tx)) as WebSocketSink;
	let stream: WebSocketStream = Box::pin(rx.filter_map(|msg| async move {
		match msg {
			Ok(tg) => tg_to_message(tg).map(Ok),
			Err(e) => Some(Err(TransportError::backend(e))),
		}
	})) as WebSocketStream;

	(sink, stream)
}

/// Convert a tungstenite message into an async-wsocket pool message.
/// Returns `None` for raw frames (never surfaced while reading).
fn tg_to_message(msg: TgMessage) -> Option<Message> {
	match msg {
		TgMessage::Text(text) => Some(Message::Text(text.to_string())),
		TgMessage::Binary(data) => Some(Message::Binary(data.to_vec())),
		TgMessage::Ping(data) => Some(Message::Ping(data.to_vec())),
		TgMessage::Pong(data) => Some(Message::Pong(data.to_vec())),
		TgMessage::Close(_) => Some(Message::Close(None)),
		TgMessage::Frame(_) => None,
	}
}

/// Sink adapter converting pool messages into tungstenite messages.
struct NymSink<S>(S);

impl<S> Sink<Message> for NymSink<S>
where
	S: Sink<TgMessage, Error = tokio_tungstenite::tungstenite::Error> + Send + Unpin,
{
	type Error = TransportError;

	fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		Pin::new(&mut self.0)
			.poll_ready_unpin(cx)
			.map_err(TransportError::backend)
	}

	fn start_send(mut self: Pin<&mut Self>, item: Message) -> Result<(), Self::Error> {
		Pin::new(&mut self.0)
			.start_send_unpin(TgMessage::from(item))
			.map_err(TransportError::backend)
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		Pin::new(&mut self.0)
			.poll_flush_unpin(cx)
			.map_err(TransportError::backend)
	}

	fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		Pin::new(&mut self.0)
			.poll_close_unpin(cx)
			.map_err(TransportError::backend)
	}
}
