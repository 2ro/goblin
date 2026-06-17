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

//! In-process Nym mixnet client. Goblin links the Nym SDK directly — there is no
//! sidecar subprocess and no bundled/sideloaded binary. It runs the SDK's SOCKS5
//! client on a private internal tokio runtime, exposing the mixnet at
//! `127.0.0.1:1080`; every relay + HTTP request in the app is pointed at that
//! loopback port, so all traffic egresses through the 5-hop mixnet to our network
//! requester. Nothing goes clearnet.

use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use log::{error, info, warn};

use nym_sdk::mixnet::{MixnetClientBuilder, Socks5, Socks5MixnetClient, StoragePaths};

use super::{SOCKS5_HOST, SOCKS5_PORT};

/// Network requester (the mixnet exit) Goblin routes through — the SOCKS5
/// client's `--provider`. Standard Nym exit policy, which permits the wss/443 +
/// HTTPS hosts Goblin needs. Overridable at runtime with `GOBLIN_NYM_PROVIDER`. If
/// left empty, the in-process client isn't started, but an already-running SOCKS5
/// endpoint on :1080 is still reused.
pub const NETWORK_REQUESTER: &str = "5ibBQ9SS1er3tks5tfmrzCQ29qU1uBSvZN2dUwLKPRwu.HdbktiMVniUyaKBnorFVXLRHdwRb8iG9dV481r5xyopV@2RmEBKhQHsqvw5sjnnt2Bhpy96MPDUkbfWkT6r2RWNCR";

/// Pre-warm the mixnet transport in the background so relays / NIP-05 / price are
/// ready by first use. If a SOCKS5 endpoint is already listening on :1080 it is
/// reused as-is; otherwise the in-process client is started.
pub fn warm_up() {
	thread::spawn(|| {
		if port_open(Duration::from_millis(300)) {
			info!("nym: reusing SOCKS5 endpoint already listening on {SOCKS5_HOST}:{SOCKS5_PORT}");
			MIXNET_READY.store(true, Ordering::Relaxed);
			return;
		}
		run_client();
	});
}

/// Set once the local mixnet SOCKS5 proxy (:1080) is up and accepting.
static MIXNET_READY: AtomicBool = AtomicBool::new(false);

/// Whether the mixnet proxy is warm. Cheap and cached — safe to poll from the UI
/// each frame, unlike a fresh TCP probe. Distinct from a relay being connected.
pub fn is_ready() -> bool {
	MIXNET_READY.load(Ordering::Relaxed)
}

/// True when something accepts TCP on the SOCKS5 port.
fn port_open(timeout: Duration) -> bool {
	let addr: SocketAddr = match format!("{SOCKS5_HOST}:{SOCKS5_PORT}").parse() {
		Ok(a) => a,
		Err(_) => return false,
	};
	TcpStream::connect_timeout(&addr, timeout).is_ok()
}

/// The network requester address to register against (`--provider`).
fn provider() -> String {
	std::env::var("GOBLIN_NYM_PROVIDER")
		.ok()
		.filter(|s| !s.is_empty())
		.unwrap_or_else(|| NETWORK_REQUESTER.to_string())
}

/// Persistent storage dir for the in-process client's identity + gateway choice,
/// so the gateway is selected once and reused across launches (cuts cold-start
/// time). `<home>/.goblin/nym`. `None` ⇒ fall back to ephemeral in-memory keys.
fn storage_dir() -> Option<PathBuf> {
	dirs::home_dir().map(|h| h.join(".goblin").join("nym"))
}

/// Build the in-process SOCKS5 mixnet client on a dedicated multi-thread tokio
/// runtime, then keep the client (its SOCKS5 listener + mixnet tasks) AND the
/// runtime alive for the lifetime of the process. Blocks the calling thread.
fn run_client() {
	let prov = provider();
	if prov.is_empty() {
		warn!(
			"nym: no network requester configured (set GOBLIN_NYM_PROVIDER or bake NETWORK_REQUESTER); mixnet disabled"
		);
		return;
	}
	let rt = match tokio::runtime::Builder::new_multi_thread()
		.worker_threads(2)
		.enable_all()
		.build()
	{
		Ok(rt) => rt,
		Err(e) => {
			error!("nym: could not build mixnet runtime: {e}");
			return;
		}
	};
	rt.block_on(async move {
		let started = Instant::now();
		info!("nym: starting in-process SOCKS5 mixnet client on {SOCKS5_HOST}:{SOCKS5_PORT}");
		let client = match build_client(prov).await {
			Ok(c) => c,
			Err(e) => {
				error!("nym: mixnet client failed to start: {e}");
				return;
			}
		};
		info!(
			"nym: mixnet ready on {SOCKS5_HOST}:{SOCKS5_PORT} in ~{}ms (nym addr {})",
			started.elapsed().as_millis(),
			client.nym_address()
		);
		MIXNET_READY.store(true, Ordering::Relaxed);
		// Hold the client (and thus the SOCKS5 listener + mixnet tasks) open for
		// the whole process lifetime; the runtime keeps polling them.
		std::future::pending::<()>().await;
		drop(client);
	});
}

/// Persistent identity if we have a home dir, else ephemeral in-memory keys.
async fn build_client(provider: String) -> Result<Socks5MixnetClient, nym_sdk::Error> {
	match storage_dir() {
		Some(dir) => {
			let _ = std::fs::create_dir_all(&dir);
			let paths = StoragePaths::new_from_dir(&dir)?;
			MixnetClientBuilder::new_with_default_storage(paths)
				.await?
				.socks5_config(Socks5::new(provider))
				.build()?
				.connect_to_mixnet_via_socks5()
				.await
		}
		None => {
			MixnetClientBuilder::new_ephemeral()
				.socks5_config(Socks5::new(provider))
				.build()?
				.connect_to_mixnet_via_socks5()
				.await
		}
	}
}
