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

//! Display sanitization shared by every untrusted-string surface.
//!
//! A single classifier, [`is_display_dangerous`], decides whether a codepoint
//! is unsafe to render raw in the payment/UI strip. It is the one source of
//! truth behind the DM-note sanitizer, the memo/URI sanitizer, the
//! name-authority `@name` cap, and the authorize/login prompt escaper. This
//! completes `TODO(audit M5)`: the set is Unicode-category driven (Cc controls
//! via [`char::is_control`], plus the explicit bidi / zero-width format
//! codepoints) rather than an ad-hoc per-caller list.
//!
//! Threat: a right-to-left override, isolate, or invisible/zero-width codepoint
//! embedded in an attacker-controlled name / memo / subject can visually
//! reorder or hide the surrounding UI text so the DISPLAY lies about identity
//! or amount (a "Trojan Source" style spoof). Funds are unaffected — they
//! always go to the correct npub — but the rendered strip must not be
//! forgeable.
//!
//! Non-goal: mangling legitimate non-Latin text. Only the invisible
//! FORMAT/CONTROL codepoints are neutralized; the visible LETTERS of every
//! script — Latin (incl. accents), Arabic, Hebrew, CJK, Hangul — and
//! standalone emoji pass through untouched.

/// Whether `c` must never reach a label raw.
///
/// Neutralized set:
/// - **Cc controls** — C0 `U+0000..=U+001F`, DEL `U+007F`, and C1
///   `U+0080..=U+009F`. Matched by [`char::is_control`], which is exactly the
///   `Cc` general category.
/// - **Bidi controls / overrides / isolates** (the classic Trojan-Source
///   vector): `U+202A..=U+202E` (LRE, RLE, PDF, LRO, RLO),
///   `U+2066..=U+2069` (LRI, RLI, FSI, PDI), `U+200E`/`U+200F` (LRM/RLM),
///   and `U+061C` (ARABIC LETTER MARK).
/// - **Zero-width / invisible joiners and the BOM**: `U+200B` (ZWSP),
///   `U+200C` (ZWNJ), `U+200D` (ZWJ), `U+FEFF` (ZWNBSP / BOM).
///
/// Deliberately NOT flagged: ordinary letters of any script and standalone
/// emoji. Arabic and Hebrew LETTERS render right-to-left on their own and are
/// perfectly safe — it is only the explicit override/isolate FORMAT codepoints
/// that are dangerous.
pub fn is_display_dangerous(c: char) -> bool {
	if c.is_control() {
		// Cc: C0, DEL, and the C1 block.
		return true;
	}
	matches!(
		c as u32,
		0x200E | 0x200F // LRM, RLM
		| 0x061C        // ARABIC LETTER MARK
		| 0x202A..=0x202E // LRE, RLE, PDF, LRO, RLO
		| 0x2066..=0x2069 // LRI, RLI, FSI, PDI
		| 0x200B..=0x200D // ZWSP, ZWNJ, ZWJ
		| 0xFEFF          // ZWNBSP / BOM
	)
}

/// Sanitize an attacker-controlled display name (e.g. the `@name` an authority
/// reports for a pubkey): drop every [`is_display_dangerous`] codepoint, trim
/// surrounding whitespace, and hard-cap at `max_chars` characters. Returns
/// `None` when nothing legible remains — a name that was empty, or was made
/// only of control/bidi/zero-width chars, is not a usable handle.
///
/// A display name has no legitimate need for hundreds of characters, so the cap
/// also bounds a hostile authority that returns a wall of text.
pub fn sanitize_name(raw: &str, max_chars: usize) -> Option<String> {
	let cleaned: String = raw.chars().filter(|c| !is_display_dangerous(*c)).collect();
	let trimmed = cleaned.trim();
	if trimmed.is_empty() {
		return None;
	}
	Some(trimmed.chars().take(max_chars).collect())
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The full set of format/control codepoints the classifier must flag.
	const DANGEROUS: &[char] = &[
		'\u{0000}', '\u{0007}', '\u{001B}', '\u{007F}', // C0 + DEL
		'\u{0085}', '\u{009F}', // C1
		'\u{200E}', '\u{200F}', '\u{061C}', // marks
		'\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}', '\u{202E}', // bidi overrides
		'\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}', // bidi isolates
		'\u{200B}', '\u{200C}', '\u{200D}', // zero-width
		'\u{FEFF}', // BOM
	];

	/// Legitimate, visible text from the locales Goblin ships — must ALL pass.
	const SAFE: &[&str] = &[
		"café",     // accented Latin
		"Grüße",    // German umlaut + ß
		"日本語",   // Japanese / CJK
		"中文名字", // Chinese
		"한국어",   // Korean Hangul
		"مرحبا",    // Arabic letters (naturally RTL — safe)
		"שלום",     // Hebrew letters (naturally RTL — safe)
		"Ñoño",     // Spanish
		"🎉",       // emoji
		"🍺 grin",  // emoji + ASCII
	];

	#[test]
	fn flags_every_dangerous_codepoint() {
		for &c in DANGEROUS {
			assert!(
				is_display_dangerous(c),
				"{:?} (U+{:04X}) must be flagged",
				c,
				c as u32
			);
		}
	}

	#[test]
	fn passes_every_legitimate_letter() {
		for s in SAFE {
			for c in s.chars() {
				assert!(
					!is_display_dangerous(c),
					"{:?} (U+{:04X}) in {:?} must NOT be flagged",
					c,
					c as u32,
					s
				);
			}
		}
	}

	#[test]
	fn sanitize_name_neutralizes_bidi_and_zero_width() {
		// A right-to-left override that would visually reverse "1cnp" → "npc1".
		assert_eq!(
			sanitize_name("Alice\u{202E}eve", 64),
			Some("Aliceeve".to_string())
		);
		// Zero-width joiner splicing two look-alike halves.
		assert_eq!(
			sanitize_name("go\u{200D}blin", 64),
			Some("goblin".to_string())
		);
		// BOM + control noise.
		assert_eq!(
			sanitize_name("\u{FEFF}bob\u{0000}", 64),
			Some("bob".to_string())
		);
	}

	#[test]
	fn sanitize_name_preserves_non_latin_scripts() {
		for s in SAFE {
			assert_eq!(
				sanitize_name(s, 64).as_deref(),
				Some(s.trim()),
				"{s:?} must survive sanitization unchanged"
			);
		}
	}

	#[test]
	fn sanitize_name_caps_length() {
		let long = "本".repeat(200); // 200 CJK chars, none dangerous
		let out = sanitize_name(&long, 64).expect("non-empty");
		assert_eq!(out.chars().count(), 64);
	}

	#[test]
	fn sanitize_name_rejects_all_noise() {
		assert_eq!(sanitize_name("\u{202E}\u{200B}\u{0000}", 64), None);
		assert_eq!(sanitize_name("   ", 64), None);
		assert_eq!(sanitize_name("", 64), None);
	}
}
