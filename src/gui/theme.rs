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

//! Goblin design tokens: three themes (light/dark/yellow) and density scales,
//! taken verbatim from the Goblin design handoff.

use std::cell::Cell;

use egui::Color32;

use crate::AppConfig;

/// Available color themes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ThemeKind {
	Light,
	Dark,
	Yellow,
}

impl ThemeKind {
	pub fn id(&self) -> &'static str {
		match self {
			ThemeKind::Light => "light",
			ThemeKind::Dark => "dark",
			ThemeKind::Yellow => "yellow",
		}
	}

	pub fn from_id(id: &str) -> Option<ThemeKind> {
		match id {
			"light" => Some(ThemeKind::Light),
			"dark" => Some(ThemeKind::Dark),
			"yellow" => Some(ThemeKind::Yellow),
			_ => None,
		}
	}
}

/// Color tokens for a theme.
pub struct ThemeTokens {
	pub bg: Color32,
	pub surface: Color32,
	pub surface2: Color32,
	pub text: Color32,
	pub text_dim: Color32,
	pub text_mute: Color32,
	/// Text on surface/surface2 fills. Matches `text` in light/dark, but the
	/// yellow theme has dark surfaces on a bright bg, so on-surface text must
	/// be light there while `text` stays dark for the bg.
	pub surface_text: Color32,
	pub surface_text_dim: Color32,
	pub surface_text_mute: Color32,
	pub line: Color32,
	pub accent: Color32,
	pub accent_dark: Color32,
	pub accent_ink: Color32,
	pub pos: Color32,
	pub neg: Color32,
	/// Blueviolet ("tor purple") accent for the Tor-on privacy state (CSS
	/// `blueviolet` = #8A2BE2). Carries the "private traffic on" color on the
	/// network-privacy status dots and the active big Tor switch.
	pub tor_purple: Color32,
	pub chip: Color32,
	pub hover: Color32,
	/// Avatar background palette (initial ink picked by luminance).
	pub avatar_pairs: [(Color32, Color32); 8],
	/// Whether egui widgets should use the dark base style.
	pub dark_base: bool,
}

/// Avatar (background, ink) pairs shared by all themes — bright pastels
/// carry dark ink, saturated darks carry light ink.
const AVATAR_PAIRS: [(Color32, Color32); 8] = [
	(
		Color32::from_rgb(0xFF, 0xD6, 0x0A),
		Color32::from_rgb(0x0E, 0x0E, 0x0C),
	), // accent yellow / ink
	(
		Color32::from_rgb(0xFF, 0x8E, 0x3C),
		Color32::from_rgb(0x26, 0x10, 0x02),
	), // orange / deep brown
	(
		Color32::from_rgb(0x5B, 0xD2, 0x7A),
		Color32::from_rgb(0x0E, 0x0E, 0x0C),
	), // light green / black
	(
		Color32::from_rgb(0x7B, 0xA7, 0xFF),
		Color32::from_rgb(0x0B, 0x14, 0x33),
	), // periwinkle / navy ink
	(
		Color32::from_rgb(0x6B, 0x4F, 0xC8),
		Color32::from_rgb(0xF4, 0xF0, 0xFF),
	), // purple / light text
	(
		Color32::from_rgb(0xE1, 0x74, 0xD0),
		Color32::from_rgb(0x32, 0x07, 0x2B),
	), // pink / dark plum
	(
		Color32::from_rgb(0x1F, 0x7A, 0x5C),
		Color32::from_rgb(0xE7, 0xFF, 0xF4),
	), // deep teal / light mint
	(
		Color32::from_rgb(0xA0, 0xE6, 0x6E),
		Color32::from_rgb(0x14, 0x22, 0x0A),
	), // lime / dark moss
];

/// The Goblin brand yellow (#FFD60A). Unlike [`ThemeTokens::accent`] (which
/// inverts to dark on the yellow theme so it reads on a bright bg), this is the
/// same brand yellow in every theme — used for status dots that must always
/// carry the brand color, e.g. the always-direct Grin-node dot.
pub const GOBLIN_YELLOW: Color32 = Color32::from_rgb(0xFF, 0xD6, 0x0A);

pub const LIGHT: ThemeTokens = ThemeTokens {
	bg: Color32::from_rgb(0xFA, 0xFA, 0xF7),
	surface: Color32::from_rgb(0xFF, 0xFF, 0xFF),
	surface2: Color32::from_rgb(0xF2, 0xF1, 0xEC),
	text: Color32::from_rgb(0x0E, 0x0E, 0x0C),
	text_dim: Color32::from_rgb(0x6B, 0x6A, 0x63),
	text_mute: Color32::from_rgb(0xA6, 0xA3, 0x9B),
	surface_text: Color32::from_rgb(0x0E, 0x0E, 0x0C),
	surface_text_dim: Color32::from_rgb(0x6B, 0x6A, 0x63),
	surface_text_mute: Color32::from_rgb(0xA6, 0xA3, 0x9B),
	// rgba(14,14,12,0.08) premultiplied.
	line: Color32::from_rgba_premultiplied(1, 1, 1, 20),
	accent: Color32::from_rgb(0xFF, 0xD6, 0x0A),
	accent_dark: Color32::from_rgb(0xEF, 0xC8, 0x00),
	accent_ink: Color32::from_rgb(0x0E, 0x0E, 0x0C),
	pos: Color32::from_rgb(0x0E, 0x7C, 0x3A),
	neg: Color32::from_rgb(0xB0, 0x48, 0x1E),
	tor_purple: Color32::from_rgb(0x8A, 0x2B, 0xE2),
	chip: Color32::from_rgb(0xF2, 0xF1, 0xEC),
	hover: Color32::from_rgb(0xE9, 0xE7, 0xE0),
	avatar_pairs: AVATAR_PAIRS,
	dark_base: false,
};

pub const DARK: ThemeTokens = ThemeTokens {
	bg: Color32::from_rgb(0x0E, 0x0E, 0x0C),
	surface: Color32::from_rgb(0x1A, 0x1A, 0x17),
	surface2: Color32::from_rgb(0x24, 0x24, 0x20),
	text: Color32::from_rgb(0xFA, 0xFA, 0xF7),
	text_dim: Color32::from_rgb(0x9A, 0x98, 0x8F),
	text_mute: Color32::from_rgb(0x60, 0x5E, 0x58),
	surface_text: Color32::from_rgb(0xFA, 0xFA, 0xF7),
	surface_text_dim: Color32::from_rgb(0x9A, 0x98, 0x8F),
	surface_text_mute: Color32::from_rgb(0x60, 0x5E, 0x58),
	// rgba(255,255,255,0.08) premultiplied.
	line: Color32::from_rgba_premultiplied(20, 20, 20, 20),
	accent: Color32::from_rgb(0xFF, 0xD6, 0x0A),
	accent_dark: Color32::from_rgb(0xEF, 0xC8, 0x00),
	accent_ink: Color32::from_rgb(0x0E, 0x0E, 0x0C),
	pos: Color32::from_rgb(0x5B, 0xD2, 0x7A),
	neg: Color32::from_rgb(0xFF, 0x8B, 0x5E),
	tor_purple: Color32::from_rgb(0x8A, 0x2B, 0xE2),
	chip: Color32::from_rgb(0x24, 0x24, 0x20),
	hover: Color32::from_rgb(0x2E, 0x2E, 0x29),
	avatar_pairs: AVATAR_PAIRS,
	dark_base: true,
};

pub const YELLOW: ThemeTokens = ThemeTokens {
	bg: Color32::from_rgb(0xFF, 0xD6, 0x0A),
	surface: Color32::from_rgb(0x0E, 0x0E, 0x0C),
	surface2: Color32::from_rgb(0x1A, 0x1A, 0x17),
	text: Color32::from_rgb(0x0E, 0x0E, 0x0C),
	text_dim: Color32::from_rgb(0x3A, 0x3A, 0x36),
	// Muted on-bg tier darkened for the bright yellow bg: #6B6A63 was only
	// 3.85:1 (sub-WCAG-AA); #55534A is 5.5:1 and still the faintest tier.
	text_mute: Color32::from_rgb(0x55, 0x53, 0x4A),
	surface_text: Color32::from_rgb(0xFA, 0xFA, 0xF7),
	surface_text_dim: Color32::from_rgb(0x9A, 0x98, 0x8F),
	surface_text_mute: Color32::from_rgb(0x60, 0x5E, 0x58),
	// rgba(14,14,12,0.18) premultiplied.
	line: Color32::from_rgba_premultiplied(2, 2, 2, 46),
	accent: Color32::from_rgb(0x0E, 0x0E, 0x0C),
	accent_dark: Color32::from_rgb(0x24, 0x24, 0x20),
	accent_ink: Color32::from_rgb(0xFF, 0xD6, 0x0A),
	pos: Color32::from_rgb(0x0E, 0x7C, 0x3A),
	neg: Color32::from_rgb(0x9E, 0x2E, 0x0E),
	tor_purple: Color32::from_rgb(0x8A, 0x2B, 0xE2),
	chip: Color32::from_rgba_premultiplied(2, 2, 2, 20),
	hover: Color32::from_rgb(0xEF, 0xC8, 0x00),
	avatar_pairs: AVATAR_PAIRS,
	dark_base: false,
};

thread_local! {
	/// Per-frame theme override (see [`scoped`]). egui renders on one thread, so
	/// a thread-local Cell scopes a different theme to a single surface without
	/// touching the persisted app config.
	static OVERRIDE: Cell<Option<ThemeKind>> = const { Cell::new(None) };
}

/// RAII guard that forces [`kind`]/[`tokens`] to a specific theme for its
/// lifetime, restoring the previous value on drop (panic-safe). Used to paint
/// one surface — the Pay tab — in the yellow theme regardless of the user's
/// chosen theme, à la a modern pay app's brand-colored pay screen.
#[must_use = "the override only lasts while the guard is alive"]
pub struct ScopedTheme(Option<ThemeKind>);

impl Drop for ScopedTheme {
	fn drop(&mut self) {
		OVERRIDE.with(|c| c.set(self.0.take()));
	}
}

/// Override the active theme until the returned guard drops.
pub fn scoped(kind: ThemeKind) -> ScopedTheme {
	ScopedTheme(OVERRIDE.with(|c| c.replace(Some(kind))))
}

/// Current theme kind: a scoped override if one is active, else app config
/// (dark is the product default).
pub fn kind() -> ThemeKind {
	OVERRIDE.with(|c| c.get()).unwrap_or_else(AppConfig::theme)
}

/// Current theme tokens.
pub fn tokens() -> &'static ThemeTokens {
	match kind() {
		ThemeKind::Light => &LIGHT,
		ThemeKind::Dark => &DARK,
		ThemeKind::Yellow => &YELLOW,
	}
}

/// Set each frame by the Pay surface (which paints a bright yellow top under a
/// possibly-dark global theme), so the status bar can pick readable icons for it.
static YELLOW_SURFACE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Flag whether the bright Pay/yellow surface is currently on screen.
pub fn set_status_surface_yellow(yellow: bool) {
	YELLOW_SURFACE.store(yellow, std::sync::atomic::Ordering::Relaxed);
}

/// Whether the status bar should use light (white) icons: true on the dark
/// theme (dark top), false on the light/yellow themes (bright top). The bright
/// Pay surface forces dark icons even when the global theme is dark.
pub fn status_bar_white_icons() -> bool {
	if YELLOW_SURFACE.load(std::sync::atomic::Ordering::Relaxed) {
		return false;
	}
	tokens().dark_base
}

/// Density scales from the design handoff.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum DensityKind {
	Compact,
	Regular,
	Comfy,
}

impl DensityKind {
	pub fn id(&self) -> &'static str {
		match self {
			DensityKind::Compact => "compact",
			DensityKind::Regular => "regular",
			DensityKind::Comfy => "comfy",
		}
	}

	pub fn from_id(id: &str) -> Option<DensityKind> {
		match id {
			"compact" => Some(DensityKind::Compact),
			"regular" => Some(DensityKind::Regular),
			"comfy" => Some(DensityKind::Comfy),
			_ => None,
		}
	}
}

/// Spacing tokens for a density.
#[derive(Clone, Copy)]
pub struct DensityTokens {
	pub pad: f32,
	pub gap: f32,
	pub radius: f32,
	pub row: f32,
}

pub const COMPACT: DensityTokens = DensityTokens {
	pad: 12.0,
	gap: 10.0,
	radius: 10.0,
	row: 56.0,
};
pub const REGULAR: DensityTokens = DensityTokens {
	pad: 16.0,
	gap: 14.0,
	radius: 16.0,
	row: 64.0,
};
pub const COMFY: DensityTokens = DensityTokens {
	pad: 20.0,
	gap: 18.0,
	radius: 22.0,
	row: 72.0,
};

/// Current density tokens from app config (comfy is the product default).
pub fn density() -> DensityTokens {
	match AppConfig::density() {
		DensityKind::Compact => COMPACT,
		DensityKind::Regular => REGULAR,
		DensityKind::Comfy => COMFY,
	}
}

/// Font family helpers for the Geist weight stack registered in `setup_fonts`.
pub mod fonts {
	use egui::{FontFamily, FontId};

	pub fn regular() -> FontFamily {
		FontFamily::Proportional
	}

	pub fn medium() -> FontFamily {
		FontFamily::Name("geist-medium".into())
	}

	pub fn semibold() -> FontFamily {
		FontFamily::Name("geist-semibold".into())
	}

	pub fn bold() -> FontFamily {
		FontFamily::Name("geist-bold".into())
	}

	pub fn mono() -> FontFamily {
		FontFamily::Monospace
	}

	pub fn mono_semibold() -> FontFamily {
		FontFamily::Name("geist-mono-sb".into())
	}

	/// Uppercase kicker label size (11px in the design).
	pub fn kicker() -> FontId {
		FontId::new(11.0, semibold())
	}
}

/// Pick a readable ink (black or white) for the given background by luminance.
pub fn ink_for(bg: Color32) -> Color32 {
	let lum = 0.299 * bg.r() as f32 + 0.587 * bg.g() as f32 + 0.114 * bg.b() as f32;
	if lum > 140.0 {
		Color32::from_rgb(0x0E, 0x0E, 0x0C)
	} else {
		Color32::from_rgb(0xFA, 0xFA, 0xF7)
	}
}

/// Number of avatar color pairs (hue derivation modulus).
pub fn avatar_pairs_len() -> usize {
	tokens().avatar_pairs.len()
}
