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

//! Texture layer over the avatar disk cache: hands the UI ready
//! [`egui::TextureHandle`]s for usernames, fetching stale entries from the
//! NIP-05 server on background threads. Textures are only created on the UI
//! thread; workers send raw PNG bytes back over a channel.

use std::collections::{HashMap, HashSet};
use std::sync::mpsc::{Receiver, Sender, channel};

use crate::nostr::avatar::AvatarCache;
use crate::nostr::nip05;
use crate::settings::Settings;

/// Worker outcome for one name's avatar probe.
enum Fetched {
	/// A custom avatar (content hash, png bytes).
	Found(String, Vec<u8>),
	/// The server confirmed the name has no avatar.
	Absent,
	/// The probe failed (network) — do NOT cache; retry later.
	Failed,
}
type FetchResult = (String, Fetched);

pub struct AvatarTextures {
	cache: AvatarCache,
	/// Ready textures; `None` records a known letter-fallback (no avatar).
	textures: HashMap<String, Option<egui::TextureHandle>>,
	inflight: HashSet<String>,
	tx: Sender<FetchResult>,
	rx: Receiver<FetchResult>,
}

impl Default for AvatarTextures {
	fn default() -> Self {
		let (tx, rx) = channel();
		Self {
			cache: AvatarCache::new(Settings::base_path(Some("cache/avatars".to_string()))),
			textures: HashMap::new(),
			inflight: HashSet::new(),
			tx,
			rx,
		}
	}
}

fn decode(png: &[u8]) -> Option<egui::ColorImage> {
	// Server-fed bytes: decode under explicit limits so a hostile or breached
	// avatar host can't blow up memory on the texture path. `fetch_avatar`
	// only checks ≤1 MiB + PNG magic, not the decoded dimensions.
	let mut reader = image::ImageReader::new(std::io::Cursor::new(png));
	reader.set_format(image::ImageFormat::Png);
	let mut limits = image::Limits::default();
	limits.max_image_width = Some(1024);
	limits.max_image_height = Some(1024);
	limits.max_alloc = Some(8 * 1024 * 1024);
	reader.limits(limits);
	let img = reader.decode().ok()?.to_rgba8();
	Some(egui::ColorImage::from_rgba_unmultiplied(
		[img.width() as usize, img.height() as usize],
		img.as_raw(),
	))
}

impl AvatarTextures {
	/// Texture for a bare username (no `@`), if it has a custom avatar.
	/// Triggers a background refresh when the cache entry is stale.
	pub fn texture_for(
		&mut self,
		ctx: &egui::Context,
		server: &str,
		name: &str,
	) -> Option<egui::TextureHandle> {
		self.drain(ctx);
		let name = name.trim_start_matches('@').to_lowercase();
		if name.is_empty() {
			return None;
		}
		if let Some(t) = self.textures.get(&name).cloned() {
			// A known state (texture or confirmed-absent); refresh if stale.
			if self.cache.stale(&name) {
				self.spawn_fetch(server, &name);
			}
			return t;
		}
		// Disk cache hit → texture now, refresh in background if stale.
		if let Some((_, bytes)) = self.cache.cached(&name) {
			let tex = decode(&bytes)
				.map(|img| ctx.load_texture(format!("avatar_{name}"), img, Default::default()));
			self.textures.insert(name.clone(), tex.clone());
			if self.cache.stale(&name) {
				self.spawn_fetch(server, &name);
			}
			return tex;
		}
		if self.cache.stale(&name) {
			self.spawn_fetch(server, &name);
		} else {
			// Fresh negative entry: letter fallback without re-probing.
			self.textures.insert(name.clone(), None);
		}
		None
	}

	/// Install the just-uploaded avatar without waiting for a round-trip.
	pub fn set_own(&mut self, ctx: &egui::Context, name: &str, hash: &str, png: &[u8]) {
		let name = name.trim_start_matches('@').to_lowercase();
		self.cache.store(&name, hash, png);
		let tex = decode(png)
			.map(|img| ctx.load_texture(format!("avatar_{name}"), img, Default::default()));
		self.textures.insert(name, tex);
	}

	/// Forget a name (released or rotated away).
	pub fn invalidate(&mut self, name: &str) {
		let name = name.trim_start_matches('@').to_lowercase();
		self.cache.remove(&name);
		self.textures.remove(&name);
	}

	fn drain(&mut self, ctx: &egui::Context) {
		while let Ok((name, fetched)) = self.rx.try_recv() {
			self.inflight.remove(&name);
			match fetched {
				Fetched::Found(hash, png) => {
					self.cache.store(&name, &hash, &png);
					let tex = decode(&png).map(|img| {
						ctx.load_texture(format!("avatar_{name}"), img, Default::default())
					});
					self.textures.insert(name, tex);
				}
				Fetched::Absent => {
					self.cache.mark_absent(&name);
					self.textures.insert(name, None);
				}
				// Network failure: leave the entry stale so the next frame
				// retries. Never cache it as a confirmed "no avatar".
				Fetched::Failed => {}
			}
			ctx.request_repaint();
		}
	}

	fn spawn_fetch(&mut self, server: &str, name: &str) {
		if self.inflight.contains(name) {
			return;
		}
		self.inflight.insert(name.to_string());
		let tx = self.tx.clone();
		let server = server.to_string();
		let name = name.to_string();
		std::thread::spawn(move || {
			let rt = match tokio::runtime::Builder::new_current_thread()
				.enable_all()
				.build()
			{
				Ok(rt) => rt,
				Err(_) => return,
			};
			let fetched = rt.block_on(async {
				match nip05::fetch_profile(&server, &name).await {
					Some(Some(hash)) => match nip05::fetch_avatar(&server, &hash).await {
						Some(png) => Fetched::Found(hash, png),
						None => Fetched::Failed,
					},
					Some(None) => Fetched::Absent,
					None => Fetched::Failed,
				}
			});
			let _ = tx.send((name, fetched));
		});
	}
}
