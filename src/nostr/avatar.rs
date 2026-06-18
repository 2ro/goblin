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

//! Client-side avatar handling: local preprocessing of a picked picture
//! (mirrors the server pipeline so uploads over the mixnet stay small and previews
//! are instant — the server still re-validates everything), plus a small
//! disk cache of fetched avatars keyed by username.

use image::codecs::png::PngEncoder;
use image::metadata::Orientation;
use image::{DynamicImage, ImageDecoder, ImageFormat, ImageReader, Limits};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Cursor;
use std::path::PathBuf;

/// Output dimensions (square), matching the server.
pub const SIZE: u32 = 256;
/// Raw picked files larger than this are rejected before decoding.
const MAX_FILE_BYTES: u64 = 10 * 1024 * 1024;

/// Identify the image format from magic bytes alone (PNG/JPEG/WebP).
fn sniff(raw: &[u8]) -> Option<ImageFormat> {
	if raw.len() >= 8 && raw.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]) {
		return Some(ImageFormat::Png);
	}
	if raw.len() >= 3 && raw.starts_with(&[0xFF, 0xD8, 0xFF]) {
		return Some(ImageFormat::Jpeg);
	}
	if raw.len() >= 12 && &raw[0..4] == b"RIFF" && &raw[8..12] == b"WEBP" {
		return Some(ImageFormat::WebP);
	}
	None
}

/// Read a picked picture file and normalize it to the canonical 256×256
/// PNG (EXIF orientation applied, every byte of metadata destroyed).
pub fn process_avatar_file(path: &str) -> Result<Vec<u8>, String> {
	let meta = std::fs::metadata(path).map_err(|_| "Couldn't read that file".to_string())?;
	if meta.len() > MAX_FILE_BYTES {
		return Err("That picture is too large (10 MB max)".to_string());
	}
	let raw = std::fs::read(path).map_err(|_| "Couldn't read that file".to_string())?;
	process_avatar_bytes(&raw)
}

/// Normalize raw image bytes to the canonical avatar PNG.
pub fn process_avatar_bytes(raw: &[u8]) -> Result<Vec<u8>, String> {
	let err = || "That file doesn't look like a usable picture".to_string();
	let format = sniff(raw).ok_or_else(err)?;
	let mut reader = ImageReader::with_format(Cursor::new(raw), format);
	let mut limits = Limits::default();
	limits.max_image_width = Some(8192);
	limits.max_image_height = Some(8192);
	limits.max_alloc = Some(128 * 1024 * 1024);
	reader.limits(limits);
	let mut decoder = reader.into_decoder().map_err(|_| err())?;
	let orientation = decoder.orientation().unwrap_or(Orientation::NoTransforms);
	let mut img = DynamicImage::from_decoder(decoder).map_err(|_| err())?;
	img.apply_orientation(orientation);
	let (w, h) = (img.width(), img.height());
	if w == 0 || h == 0 {
		return Err(err());
	}
	let side = w.min(h);
	let img = img.crop_imm((w - side) / 2, (h - side) / 2, side, side);
	let img = img.resize_exact(SIZE, SIZE, image::imageops::FilterType::Lanczos3);
	let rgba = img.to_rgba8();
	let mut out = Vec::new();
	rgba.write_with_encoder(PngEncoder::new(&mut out))
		.map_err(|_| err())?;
	Ok(out)
}

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
	use image::RgbaImage;

	fn png_bytes(w: u32, h: u32) -> Vec<u8> {
		let img = RgbaImage::from_fn(w, h, |x, y| {
			image::Rgba([(x % 256) as u8, (y % 256) as u8, 7, 255])
		});
		let mut out = Vec::new();
		image::DynamicImage::ImageRgba8(img)
			.write_with_encoder(PngEncoder::new(&mut out))
			.unwrap();
		out
	}

	#[test]
	fn processes_to_canonical_png() {
		let out = process_avatar_bytes(&png_bytes(500, 300)).unwrap();
		assert!(out.starts_with(&[0x89, b'P', b'N', b'G']));
		let img = image::load_from_memory(&out).unwrap();
		assert_eq!((img.width(), img.height()), (SIZE, SIZE));
	}

	#[test]
	fn rejects_non_images() {
		assert!(process_avatar_bytes(b"<svg onload=alert(1)></svg>").is_err());
		assert!(process_avatar_bytes(b"GIF89a....").is_err());
		assert!(process_avatar_bytes(&[]).is_err());
	}

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
