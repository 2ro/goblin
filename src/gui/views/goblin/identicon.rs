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

//! Deterministic gradient avatars for anonymous nostr users.
//!
//! `avatar = f(pubkey)`: a two-tone gradient tile seeded by the pubkey, with the
//! Grin mark composited on top. Same key → identical SVG on every device, so
//! there is nothing to upload, store, or sync — each surface regenerates the
//! same bytes locally. The fallback avatar for anyone with no @handle and no
//! kind-0 `picture`, instead of a meaningless lettered tile.
//!
//! Seed = the **lowercase 64-char hex pubkey** hashed as UTF-8. Keep this byte
//! identical to the shared reference port (`identicon.rs` / `avatar.ts`): same
//! SHA-256 input, f64 math, and constants — or two surfaces draw two different
//! avatars for one person. All math is f64 (f32 drifts ±1 per channel vs JS).

use nostr_sdk::{FromBech32, PublicKey};
use sha2::{Digest, Sha256};

/// The Grin nav mark in its native 61×61 coordinate space.
const GRIN_PATH: &str = "M43.341 20.2793C42.6915 18.8211 42.0862 15.94 40.4204 15.2994C38.2758 14.4747 36.9501 19.8734 36.6342 21.2375H36.3149C35.7742 18.9002 35.0485 15.5878 32.4824 14.85C31.2943 19.8399 33.7235 25.2229 35.9955 29.5411C38.4215 28.3818 39.6035 24.7512 39.8279 22.1956H40.1473L42.7023 29.8605C44.7578 29.2697 45.4729 27.2356 46.2151 25.3893C47.8084 21.4265 49.1453 16.5529 48.1317 12.295C45.0641 13.1637 44.1309 17.5503 43.341 20.2793ZM12.6813 30.4993C15.4263 29.1886 16.7325 25.0399 17.1525 22.1956H17.4719C17.7967 23.5666 18.665 27.1037 20.3781 27.3307C22.5607 27.6195 23.7051 22.7765 23.8593 21.2375H24.1787C24.8746 23.642 25.6079 26.769 28.0112 27.9443C28.8978 24.2204 27.8361 20.249 26.4744 16.7662C26.1243 15.8707 25.4054 13.4562 24.1707 13.4562C22.1478 13.4562 21.0105 18.7885 20.6656 20.2793H20.3462L17.7913 12.6144C13.297 14.7605 10.8557 26.1727 12.6813 30.4993ZM7.89066 34.3317C11.2259 48.8795 26.6098 57.1266 40.4667 50.9832C45.5099 48.7472 49.5104 44.7634 51.8169 39.7611C52.4128 38.4686 53.5834 36.1291 52.9008 34.4333C52.2212 32.7441 45.6297 35.5041 43.9827 36.225C43.7514 36.3278 43.5883 36.5411 43.5503 36.7915C43.4963 37.1457 43.5921 37.5066 43.8153 37.7874C44.0383 38.0681 44.3682 38.2431 44.7256 38.2706C45.9331 38.3635 47.4929 38.4836 47.4929 38.4836C42.4829 48.1813 28.9371 52.4692 19.3881 44.7215C17.2509 42.9877 15.3442 40.9274 14.061 38.4836C13.4404 37.3019 12.8649 35.7906 11.81 34.9797C10.7966 34.2004 9.25919 33.9335 7.89066 34.3317Z";

/// Mark spans 90% of the tile; black at 67% opacity (matches the nav styling).
const LOGO_FRAC: f64 = 0.90;
const LOGO_OPACITY: f64 = 0.67;
const GRIN_NATIVE: f64 = 61.0;

/// Standard HSL → RGB bytes. f64 throughout for cross-port byte-identity.
pub(super) fn hsl_rgb8(h: f64, s: f64, l: f64) -> (u8, u8, u8) {
	let c = (1.0 - (2.0 * l - 1.0).abs()) * s;
	let hp = h / 60.0;
	let x = c * (1.0 - ((hp % 2.0) - 1.0).abs());
	let (r, g, b) = match hp.floor() as i32 {
		0 => (c, x, 0.0),
		1 => (x, c, 0.0),
		2 => (0.0, c, x),
		3 => (0.0, x, c),
		4 => (x, 0.0, c),
		_ => (c, 0.0, x),
	};
	let m = l - c / 2.0;
	let to = |v: f64| ((v + m) * 255.0).round() as u8;
	(to(r), to(g), to(b))
}

/// Normalise any caller-supplied id (npub bech32 OR raw hex) to the canonical
/// lowercase hex pubkey used as the seed everywhere.
pub fn to_hex_seed(id: &str) -> String {
	if let Ok(pk) = PublicKey::from_bech32(id) {
		pk.to_hex()
	} else {
		id.to_lowercase()
	}
}

/// Gradient stop colors (RGB bytes) + rotation angle derived from the seed `hex`.
/// The single source of the per-identity gradient math; both the `#rrggbb`
/// string form (for the SVG avatar) and the byte form (for the small egui cue)
/// come from here, so a dot/edge cue matches the avatar exactly. Keep this in
/// lockstep with the shared reference port.
fn gradient_rgb(hex: &str) -> ((u8, u8, u8), (u8, u8, u8), f64) {
	let hash = Sha256::digest(hex.as_bytes());
	let base = ((u16::from(hash[0]) << 8 | u16::from(hash[1])) as f64 / 65_535.0) * 360.0;
	let offset = 40.0 + (hash[2] as f64 / 255.0) * 120.0;
	let h2 = (base + offset) % 360.0;
	let angle = (hash[3] as f64 / 255.0) * 360.0;
	let c1 = hsl_rgb8(base, 0.62, 0.55);
	let c2 = hsl_rgb8(h2, 0.62, 0.42);
	(c1, c2, angle)
}

/// Gradient stop colors (`#rrggbb`) + rotation angle for the SVG avatar.
fn gradient_params(hex: &str) -> (String, String, f64) {
	let (c1, c2, angle) = gradient_rgb(hex);
	let hex_of = |(r, g, b): (u8, u8, u8)| format!("#{r:02x}{g:02x}{b:02x}");
	(hex_of(c1), hex_of(c2), angle)
}

/// The two gradient stop colors (RGB bytes) for an identity, seeded by the same
/// pubkey math as its gradient avatar, so a small dot or edge cue drawn from
/// these matches that identity's avatar. `id` may be an npub or raw hex.
pub fn gradient_rgb8(id: &str) -> ((u8, u8, u8), (u8, u8, u8)) {
	let hex = to_hex_seed(id);
	let (c1, c2, _angle) = gradient_rgb(&hex);
	(c1, c2)
}

/// The identity's gradient stops PLUS the rotation angle (degrees), so a small
/// egui-drawn badge can reproduce the same rotated linear gradient the SVG
/// avatar uses (`gradient_avatar_svg`: `x1=0 y1=0 x2=1 y2=1` then
/// `rotate(angle, 0.5, 0.5)`). `id` may be an npub or raw hex.
pub fn gradient_stops(id: &str) -> ((u8, u8, u8), (u8, u8, u8), f32) {
	let hex = to_hex_seed(id);
	let (c1, c2, angle) = gradient_rgb(&hex);
	(c1, c2, angle as f32)
}

/// The gradient avatar as a standalone SVG document, seeded by `hex` (lowercase
/// hex pubkey). `id_suffix` makes the gradient element id unique when several
/// are inlined into ONE html document; for a standalone document (how egui
/// rasterizes each one) `""` is fine.
pub fn gradient_avatar_svg(hex: &str, size: u32, id_suffix: &str) -> String {
	let (c1, c2, angle) = gradient_params(hex);

	let target = size as f64 * LOGO_FRAC;
	let scale = target / GRIN_NATIVE;
	let off = (size as f64 - target) / 2.0;
	format!(
		r##"<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" viewBox="0 0 {size} {size}" role="img"><defs><linearGradient id="g{id_suffix}" gradientUnits="objectBoundingBox" gradientTransform="rotate({angle:.1},0.5,0.5)"><stop offset="0" stop-color="{c1}"/><stop offset="1" stop-color="{c2}"/></linearGradient></defs><rect width="{size}" height="{size}" fill="url(#g{id_suffix})"/><g transform="translate({off:.2},{off:.2}) scale({scale:.4})"><path d="{GRIN_PATH}" fill="#000000" fill-opacity="{LOGO_OPACITY}"/></g></svg>"##
	)
}
