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

//! WebSocket transport for the Nostr relay pool routed through the embedded
//! Tor (arti) client that Goblin already runs for slatepack exchange.
//! Every connection uses a fresh isolated circuit.

use std::fmt;
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

use crate::tor::Tor;

/// Error type for transport failures outside the websocket layer.
#[derive(Debug)]
struct ArtiTransportError(String);

impl fmt::Display for ArtiTransportError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		write!(f, "{}", self.0)
	}
}

impl std::error::Error for ArtiTransportError {}

fn terr(msg: impl Into<String>) -> TransportError {
	TransportError::backend(ArtiTransportError(msg.into()))
}

/// Nostr websocket transport over the embedded arti Tor client.
#[derive(Debug, Clone, Copy, Default)]
pub struct ArtiWebSocketTransport;

impl WebSocketTransport for ArtiWebSocketTransport {
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

			// Get an isolated Tor client, launching the embedded client if needed.
			let client = tokio::task::spawn_blocking(Tor::isolated_client_blocking)
				.await
				.map_err(|e| terr(format!("tor client task failed: {e}")))?
				.ok_or_else(|| terr("tor client is not available"))?;

			// Open a Tor data stream to the relay host.
			let stream = tokio::time::timeout(timeout, client.connect((host.as_str(), port)))
				.await
				.map_err(|_| terr("tor connect timeout"))?
				.map_err(|e| terr(format!("tor connect failed: {e}")))?;

			// Perform TLS (for wss) + websocket handshake over the Tor stream.
			let (ws, _response) = tokio::time::timeout(
				timeout,
				tokio_tungstenite::client_async_tls(url.as_str(), stream),
			)
			.await
			.map_err(|_| terr("websocket handshake timeout"))?
			.map_err(|e| terr(format!("websocket handshake failed: {e}")))?;

			let (tx, rx) = ws.split();

			let sink: WebSocketSink = Box::new(ArtiSink(tx)) as WebSocketSink;
			let stream: WebSocketStream = Box::pin(rx.filter_map(|msg| async move {
				match msg {
					Ok(tg) => tg_to_message(tg).map(Ok),
					Err(e) => Some(Err(TransportError::backend(e))),
				}
			})) as WebSocketStream;

			Ok((sink, stream))
		})
	}
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
struct ArtiSink<S>(S);

impl<S> Sink<Message> for ArtiSink<S>
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
