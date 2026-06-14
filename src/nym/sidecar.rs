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

//! Lifecycle for the bundled `nym-socks5-client` sidecar. Goblin doesn't link
//! the Nym SDK (its native-lib graph conflicts with ours — see the project
//! notes); instead it ships the standalone SOCKS5 client binary and runs it as
//! a child process, exposing the mixnet at `127.0.0.1:1080`. Every relay and
//! HTTP request in the app is pointed at that port, so all traffic egresses
//! through the 5-hop mixnet to our network requester. Nothing goes clearnet.

use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

use lazy_static::lazy_static;
use log::{error, info, warn};

use super::{SOCKS5_HOST, SOCKS5_PORT};

/// Bundled SOCKS5 client binary name. Windows release archives ship the `.exe`;
/// `Command`/`current_exe().parent().join(..)` need the suffix to find it. On
/// Android the sidecar is shipped inside the APK's `jniLibs` as a `lib*.so` (the
/// only files extracted to the exec-allowed native-library dir) — same trick
/// upstream Grim used for Tor's webtunnel binary.
#[cfg(target_os = "windows")]
const BIN_NAME: &str = "nym-socks5-client.exe";
#[cfg(target_os = "android")]
const BIN_NAME: &str = "libnym_socks5_client.so";
#[cfg(not(any(target_os = "windows", target_os = "android")))]
const BIN_NAME: &str = "nym-socks5-client";

/// Per-app client id; namespaces the config/keys under the Nym data root.
const CLIENT_ID: &str = "goblin";

/// Network requester (the mixnet exit) Goblin routes through — the SOCKS5
/// client's `--provider`. This is the always-on requester we run on us-ea.st
/// (standard Nym exit policy, which permits the wss/443 + HTTPS hosts Goblin
/// needs). Overridable at runtime with `GOBLIN_NYM_PROVIDER`. If left empty,
/// the sidecar isn't auto-launched but an already-running SOCKS5 endpoint (a
/// dev sidecar / system service on :1080) is still reused.
pub const NETWORK_REQUESTER: &str = "5ibBQ9SS1er3tks5tfmrzCQ29qU1uBSvZN2dUwLKPRwu.HdbktiMVniUyaKBnorFVXLRHdwRb8iG9dV481r5xyopV@2RmEBKhQHsqvw5sjnnt2Bhpy96MPDUkbfWkT6r2RWNCR";

lazy_static! {
	/// Handle to the spawned child so it is killed when Goblin exits.
	static ref CHILD: Mutex<Option<Child>> = Mutex::new(None);
}

/// Pre-warm the mixnet transport in the background so relays / NIP-05 / price
/// are ready by first use. Mirrors the old `Tor::warm_up()` seam. If a SOCKS5
/// endpoint is already listening (a dev sidecar, or a system-managed service),
/// it is reused as-is; otherwise the bundled client is launched.
pub fn warm_up() {
	thread::spawn(|| {
		if port_open(Duration::from_millis(300)) {
			info!("nym: reusing SOCKS5 sidecar already listening on {SOCKS5_HOST}:{SOCKS5_PORT}");
			return;
		}
		if let Err(e) = launch() {
			error!("nym: could not start the SOCKS5 sidecar: {e}");
		}
	});
}

/// True when something accepts TCP on the SOCKS5 port.
fn port_open(timeout: Duration) -> bool {
	let addr: SocketAddr = match format!("{SOCKS5_HOST}:{SOCKS5_PORT}").parse() {
		Ok(a) => a,
		Err(_) => return false,
	};
	TcpStream::connect_timeout(&addr, timeout).is_ok()
}

/// Locate the `nym-socks5-client` binary: an explicit `GOBLIN_NYM_BIN`
/// override, then alongside the running executable (how release archives ship
/// it), then a bare name resolved against `PATH`.
fn binary_path() -> PathBuf {
	if let Ok(p) = std::env::var("GOBLIN_NYM_BIN") {
		if !p.is_empty() {
			return PathBuf::from(p);
		}
	}
	// Android: `current_exe()` is the zygote/app_process, not us — the sidecar
	// rides in the APK's jniLibs and is extracted to the native-library dir
	// (the one exec-allowed location). MainActivity exports it as
	// `NATIVE_LIBS_DIR` (see android/.../MainActivity.java).
	#[cfg(target_os = "android")]
	if let Ok(dir) = std::env::var("NATIVE_LIBS_DIR") {
		let p = PathBuf::from(dir).join(BIN_NAME);
		if p.exists() {
			return p;
		}
	}
	if let Ok(exe) = std::env::current_exe() {
		if let Some(dir) = exe.parent() {
			let sibling = dir.join(BIN_NAME);
			if sibling.exists() {
				return sibling;
			}
		}
	}
	PathBuf::from(BIN_NAME)
}

/// The network requester address to register against (`--provider`).
fn provider() -> String {
	std::env::var("GOBLIN_NYM_PROVIDER")
		.ok()
		.filter(|s| !s.is_empty())
		.unwrap_or_else(|| NETWORK_REQUESTER.to_string())
}

/// `~/.nym/socks5-clients/<id>/config/config.toml` — present once initialized.
fn config_marker() -> Option<PathBuf> {
	dirs::home_dir().map(|h| {
		h.join(".nym")
			.join("socks5-clients")
			.join(CLIENT_ID)
			.join("config")
			.join("config.toml")
	})
}

/// Extract (if bundled), initialize (once), then spawn the SOCKS5 client and
/// block until its port is accepting connections.
fn launch() -> std::io::Result<()> {
	if provider().is_empty() {
		warn!(
			"nym: no network requester configured (set GOBLIN_NYM_PROVIDER or bake \
			 NETWORK_REQUESTER); not launching a sidecar"
		);
		return Ok(());
	}
	let bin = binary_path();
	ensure_initialized(&bin);

	info!("nym: launching SOCKS5 sidecar ({})", bin.display());
	let child = Command::new(&bin)
		.arg("run")
		.arg("--id")
		.arg(CLIENT_ID)
		.stdin(Stdio::null())
		.stdout(Stdio::null())
		.stderr(Stdio::null())
		.spawn()?;
	*CHILD.lock().unwrap() = Some(child);

	// The mixnet bootstraps in ~2s; give it generous headroom on cold start.
	let deadline = Instant::now() + Duration::from_secs(60);
	while Instant::now() < deadline {
		if port_open(Duration::from_millis(500)) {
			info!("nym: SOCKS5 sidecar ready on {SOCKS5_HOST}:{SOCKS5_PORT}");
			return Ok(());
		}
		thread::sleep(Duration::from_millis(500));
	}
	warn!("nym: SOCKS5 sidecar did not open its port within 60s");
	Ok(())
}

/// Run `init` once, when the client has no config yet. `init` selects a gateway
/// and writes keys; it needs the network but no funds (zero-value mode).
fn ensure_initialized(bin: &PathBuf) {
	let needs_init = config_marker().map(|p| !p.exists()).unwrap_or(true);
	if !needs_init {
		return;
	}
	info!("nym: initializing SOCKS5 client '{CLIENT_ID}'");
	let res = Command::new(bin)
		.arg("init")
		.arg("--id")
		.arg(CLIENT_ID)
		.arg("--provider")
		.arg(provider())
		.stdin(Stdio::null())
		.stdout(Stdio::null())
		.stderr(Stdio::null())
		.status();
	match res {
		Ok(s) if s.success() => info!("nym: SOCKS5 client initialized"),
		Ok(s) => warn!("nym: SOCKS5 client init exited with {s}"),
		Err(e) => error!("nym: SOCKS5 client init failed to run: {e}"),
	}
}

/// Stop the sidecar if Goblin spawned one (best-effort; no-op when reusing an
/// externally-managed client).
#[allow(dead_code)]
pub fn shutdown() {
	if let Some(mut child) = CHILD.lock().unwrap().take() {
		let _ = child.kill();
		let _ = child.wait();
	}
}
