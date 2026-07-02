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

//! Client-side avatar handling: a small disk cache of fetched avatars keyed
//! by username.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// One cached profile probe.
#[derive(Serialize, Deserialize, Clone)]
pub struct CacheEntry {
	/// Avatar content hash; `None` records a confirmed has-no-avatar.
	pub hash: Option<String>,
	/// When the server was last asked, unix seconds.
	pub checked_at: i64,
}

/// Disk cache of fetched avatars: `<dir>/<hash>.png` files plus an index
/// mapping names to hashes with probe timestamps (negative entries too).
pub struct AvatarCache {
	dir: PathBuf,
	index: HashMap<String, CacheEntry>,
}

const PRESENT_TTL_SECS: i64 = 24 * 3600;
const ABSENT_TTL_SECS: i64 = 6 * 3600;

fn unix_now() -> i64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_secs() as i64)
		.unwrap_or(0)
}

impl AvatarCache {
	/// Open (or create) the cache at the given directory.
	pub fn new(dir: PathBuf) -> Self {
		let _ = std::fs::create_dir_all(&dir);
		let index = std::fs::read(dir.join("index.json"))
			.ok()
			.and_then(|raw| serde_json::from_slice(&raw).ok())
			.unwrap_or_default();
		Self { dir, index }
	}

	fn save_index(&self) {
		if let Ok(raw) = serde_json::to_vec(&self.index) {
			let _ = std::fs::write(self.dir.join("index.json"), raw);
		}
	}

	/// Cached avatar bytes for a name, if a fresh positive entry exists.
	pub fn cached(&self, name: &str) -> Option<(String, Vec<u8>)> {
		let entry = self.index.get(name)?;
		let hash = entry.hash.clone()?;
		let bytes = std::fs::read(self.dir.join(format!("{hash}.png"))).ok()?;
		Some((hash, bytes))
	}

	/// Whether the entry for a name is missing or past its TTL.
	pub fn stale(&self, name: &str) -> bool {
		match self.index.get(name) {
			None => true,
			Some(e) => {
				let ttl = if e.hash.is_some() {
					PRESENT_TTL_SECS
				} else {
					ABSENT_TTL_SECS
				};
				unix_now() - e.checked_at > ttl
			}
		}
	}

	/// Record a fetched avatar.
	pub fn store(&mut self, name: &str, hash: &str, png: &[u8]) {
		let _ = std::fs::write(self.dir.join(format!("{hash}.png")), png);
		self.index.insert(
			name.to_string(),
			CacheEntry {
				hash: Some(hash.to_string()),
				checked_at: unix_now(),
			},
		);
		self.save_index();
	}

	/// Record a confirmed has-no-avatar probe.
	pub fn mark_absent(&mut self, name: &str) {
		self.index.insert(
			name.to_string(),
			CacheEntry {
				hash: None,
				checked_at: unix_now(),
			},
		);
		self.save_index();
	}

	/// Forget a name (released, rotated away, or replaced).
	pub fn remove(&mut self, name: &str) {
		if let Some(CacheEntry {
			hash: Some(hash), ..
		}) = self.index.remove(name)
		{
			// Unlink only when no other name shares the file.
			let shared = self
				.index
				.values()
				.any(|e| e.hash.as_deref() == Some(hash.as_str()));
			if !shared {
				let _ = std::fs::remove_file(self.dir.join(format!("{hash}.png")));
			}
		}
		self.save_index();
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn cache_round_trip_and_remove() {
		let dir = std::env::temp_dir().join(format!("goblin-avatar-test-{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		let mut cache = AvatarCache::new(dir.clone());
		assert!(cache.stale("ada"));
		cache.store("ada", "ab12", b"pngbytes");
		assert!(!cache.stale("ada"));
		let (hash, bytes) = cache.cached("ada").unwrap();
		assert_eq!(hash, "ab12");
		assert_eq!(bytes, b"pngbytes");
		// Reload from disk.
		let cache2 = AvatarCache::new(dir.clone());
		assert!(cache2.cached("ada").is_some());
		// Negative entries.
		let mut cache = cache2;
		cache.mark_absent("bob");
		assert!(!cache.stale("bob"));
		assert!(cache.cached("bob").is_none());
		// Removal unlinks unshared files.
		cache.remove("ada");
		assert!(cache.cached("ada").is_none());
		assert!(!dir.join("ab12.png").exists());
		let _ = std::fs::remove_dir_all(&dir);
	}
}
