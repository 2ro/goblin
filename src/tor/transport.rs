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

//! WebSocket transport for the Nostr relay pool routed over embedded Tor. Every
//! relay is dialed the same way: reach its clearnet host over a Tor exit and run
//! the usual hostname-validated TLS + websocket
//! ([`tokio_tungstenite::client_async_tls`]) for `wss://`. The payload and the
//! in-flight destination never touch the clear, and the wallet's own IP is never
//! exposed. (Earlier builds could dial a relay's pinned `.onion` directly over a
//! real onion circuit as a money-path anchor; that was dropped in build134 — the
//! onion services flapped — leaving the Tor-exit path as the only one.)

use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

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

/// Nostr websocket transport over embedded Tor.
#[derive(Debug, Clone, Copy, Default)]
pub struct TorWebSocketTransport;

impl WebSocketTransport for TorWebSocketTransport {
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

			// The embedded Tor client must be bootstrapped before any dial.
			if !crate::tor::wait_ready(timeout).await {
				return Err(terr("tor client not bootstrapped"));
			}

			// Reach the relay's clearnet host over a Tor exit, with the usual
			// hostname-validated TLS + websocket for wss (SNI = the relay host).
			// This is the single dial path: the wallet's IP never leaves Tor, and a
			// send fans out to a recipient's arbitrary public DM relays exactly the
			// way it reaches the shared floor relay (relay.floonet.dev).
			let port = url.port().unwrap_or(match url.scheme() {
				"ws" => 80,
				_ => 443,
			});
			let t = Instant::now();
			let stream = tokio::time::timeout(timeout, crate::tor::connect(&host, port))
				.await
				.map_err(|_| terr("tor connect timeout"))?
				.map_err(terr)?;
			let (ws, _response) = tokio::time::timeout(
				timeout,
				tokio_tungstenite::client_async_tls(url.as_str(), stream),
			)
			.await
			.map_err(|_| terr("websocket handshake timeout"))?
			.map_err(|e| terr(format!("websocket handshake failed: {e}")))?;
			log::info!(
				"[timing] tor: relay {host} CONNECTED via exit — tls+ws {}ms",
				t.elapsed().as_millis()
			);
			Ok(split_ws(ws))
		})
	}
}

/// Split a websocket into the pool's boxed sink/stream halves, so everything above
/// the byte transport is identical regardless of which Tor circuit carried it.
fn split_ws<S>(ws: tokio_tungstenite::WebSocketStream<S>) -> (WebSocketSink, WebSocketStream)
where
	S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
	let (tx, rx) = ws.split();

	let sink: WebSocketSink = Box::new(TorSink(tx)) as WebSocketSink;
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
struct TorSink<S>(S);

impl<S> Sink<Message> for TorSink<S>
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
