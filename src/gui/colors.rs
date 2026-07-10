// Copyright 2023 The Grim Developers
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

//! Legacy color API mapped onto the Goblin design tokens in [`crate::gui::theme`].
//! Existing call sites keep compiling; everything sources from the active theme.

use egui::Color32;

use crate::gui::theme;

/// Provides color values based on the current theme tokens.
pub struct Colors;

const SEMI_TRANSPARENT: Color32 = Color32::from_black_alpha(100);
const DARK_SEMI_TRANSPARENT: Color32 = Color32::from_black_alpha(170);

const INK: Color32 = Color32::from_rgb(0x0E, 0x0E, 0x0C);
const PAPER: Color32 = Color32::from_rgb(0xFA, 0xFA, 0xF7);

fn dark_base() -> bool {
	theme::tokens().dark_base
}

impl Colors {
	pub const FILL_DEEP: Color32 = Color32::from_rgb(0xF2, 0xF1, 0xEC);
	pub const TRANSPARENT: Color32 = Color32::from_rgba_premultiplied(0, 0, 0, 0);
	pub const STROKE: Color32 = Color32::from_rgba_premultiplied(1, 1, 1, 20);

	/// Ink when `true`, paper when `false` (theme aware: maps to text/bg).
	pub fn white_or_black(black_in_white: bool) -> Color32 {
		let t = theme::tokens();
		if black_in_white { t.text } else { t.bg }
	}

	pub fn semi_transparent() -> Color32 {
		if dark_base() {
			DARK_SEMI_TRANSPARENT
		} else {
			SEMI_TRANSPARENT
		}
	}

	pub fn gold() -> Color32 {
		theme::tokens().accent
	}

	pub fn gold_dark() -> Color32 {
		theme::tokens().accent_dark
	}

	pub fn yellow() -> Color32 {
		theme::tokens().accent
	}

	pub fn yellow_dark() -> Color32 {
		theme::tokens().accent_dark
	}

	/// Ink color to draw on top of accent fills.
	pub fn accent_ink() -> Color32 {
		theme::tokens().accent_ink
	}

	pub fn green() -> Color32 {
		theme::tokens().pos
	}

	pub fn red() -> Color32 {
		theme::tokens().neg
	}

	/// Blueviolet ("tor purple") accent for the Tor-on privacy state.
	pub fn tor_purple() -> Color32 {
		theme::tokens().tor_purple
	}

	pub fn blue() -> Color32 {
		if dark_base() {
			Color32::from_rgb(0x7B, 0xA7, 0xFF)
		} else {
			Color32::from_rgb(0x0E, 0x62, 0xD0)
		}
	}

	pub fn fill() -> Color32 {
		theme::tokens().bg
	}

	pub fn fill_deep() -> Color32 {
		theme::tokens().surface2
	}

	pub fn fill_lite() -> Color32 {
		theme::tokens().surface
	}

	pub fn checkbox() -> Color32 {
		theme::tokens().text_dim
	}

	pub fn text(always_light: bool) -> Color32 {
		if always_light {
			// Forced light-theme ink, used over always-light surfaces like QR cards.
			Color32::from_rgb(0x6B, 0x6A, 0x63)
		} else {
			theme::tokens().text_dim
		}
	}

	pub fn text_button() -> Color32 {
		theme::tokens().text
	}

	pub fn title(always_light: bool) -> Color32 {
		if always_light {
			INK
		} else {
			theme::tokens().text
		}
	}

	pub fn gray() -> Color32 {
		theme::tokens().text_mute
	}

	pub fn stroke() -> Color32 {
		theme::tokens().line
	}

	pub fn inactive_text() -> Color32 {
		theme::tokens().text_mute
	}

	pub fn item_button_text() -> Color32 {
		theme::tokens().text_dim
	}

	pub fn item_stroke() -> Color32 {
		theme::tokens().line
	}

	pub fn item_hover() -> Color32 {
		theme::tokens().hover
	}

	/// Positive amount color.
	pub fn pos() -> Color32 {
		theme::tokens().pos
	}

	/// Always-dark ink (brand black).
	pub const fn ink() -> Color32 {
		INK
	}

	/// Always-light paper (brand white).
	pub const fn paper() -> Color32 {
		PAPER
	}
}
