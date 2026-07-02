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

//! Pay-URI parser for scanned payment QRs.
//!
//! A GoblinPay checkout QR extends the plain `nostr:` URI with an optional
//! amount (and memo):
//!
//! ```text
//! nostr:<nprofile-or-npub>?amount=<decimal GRIN>&memo=<percent-encoded>
//! ```
//!
//! This module is a PURE, side-effect-free parser over UNTRUSTED scan input.
//! It never sends, never resolves — it only extracts a recipient string to
//! feed the existing recipient resolver plus a validated amount/memo to
//! prefill. Every failure mode degrades to "recipient only, manual amount"
//! (fail-closed): a bad amount is dropped, a bad memo is dropped, and a
//! non-`nostr:` payload is returned verbatim exactly as the scanner treated it
//! before this URI existed.
//!
//! Trust model: the recipient bech32 is the ONLY trust anchor (verified later
//! by the resolver). Amount, memo and any relay hints are untrusted hints.

use grin_core::core::amount_from_hr_string;

/// Total scanned-payload byte cap. Anything larger is abuse, not an address.
const MAX_URI_LEN: usize = 4096;
/// Memo byte cap (post control-strip), display / tx-message only.
const MAX_MEMO_BYTES: usize = 256;

/// A parsed pay-URI. `recipient` is fed to the existing resolver as-is (the
/// bech32/name that used to go straight into the search box). `amount` is the
/// raw decimal-GRIN string, present only when `amount_from_hr_string` accepted
/// it and it is strictly positive. `memo` is already control-stripped and
/// length-capped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayUri {
	pub recipient: String,
	pub amount: Option<String>,
	pub memo: Option<String>,
}

impl PayUri {
	/// A recipient-only result with no prefilled amount/memo (today's behavior).
	fn bare(recipient: String) -> Self {
		PayUri {
			recipient,
			amount: None,
			memo: None,
		}
	}
}

/// Parse a scanned payload into a [`PayUri`]. Pure and total: never panics,
/// never performs I/O, always returns a value. On any problem it falls back to
/// recipient-only (fail-closed).
pub fn parse(scanned: &str) -> PayUri {
	let text = scanned.trim();

	// Fail closed on clear abuse: oversize payload or an embedded NUL. Return
	// nothing usable rather than feeding a hostile blob to the resolver.
	if text.len() > MAX_URI_LEN || text.as_bytes().contains(&0) {
		return PayUri::bare(String::new());
	}

	// Strict scheme: only the `nostr:` prefix (case-insensitive) unlocks
	// amount/memo parsing, matching the scanner's existing strip logic. Any
	// other payload (a bare npub, or some other scheme) is returned verbatim,
	// exactly as the scanner treated it before pay-URIs existed.
	let rest = match strip_nostr_prefix(text) {
		Some(rest) => rest,
		None => return PayUri::bare(text.to_string()),
	};

	// Split `<recipient>?<query>`. A bare `nostr:<nprofile>` has no `?`, so the
	// whole remainder is the recipient — identical to the pre-URI behavior.
	let (recipient, query) = match rest.split_once('?') {
		Some((r, q)) => (r.to_string(), Some(q)),
		None => (rest.to_string(), None),
	};

	let mut amount = None;
	let mut memo = None;
	if let Some(query) = query {
		for pair in query.split('&') {
			let Some((key, val)) = pair.split_once('=') else {
				continue; // valueless / malformed segment — ignore
			};
			match key {
				// First occurrence wins; later duplicates are ignored so a
				// second `amount=` can't override a validated one.
				"amount" if amount.is_none() => amount = validate_amount(val),
				"memo" if memo.is_none() => memo = validate_memo(val),
				// Unknown params are ignored for forward-compat.
				_ => {}
			}
		}
	}

	PayUri {
		recipient,
		amount,
		memo,
	}
}

/// Strip a case-insensitive `nostr:` scheme prefix, returning the remainder.
/// Byte-safe against a leading multibyte char (no `[..6]` slice panic).
fn strip_nostr_prefix(text: &str) -> Option<&str> {
	let head = text.get(..6)?;
	if head.eq_ignore_ascii_case("nostr:") {
		Some(&text[6..])
	} else {
		None
	}
}

/// Validate an `amount` value: percent-decode, then accept it ONLY if the
/// wallet's own `amount_from_hr_string` parses it to a strictly positive
/// atomic amount. Never custom float parsing; any error → `None` (fall back to
/// manual entry). Returns the clean decoded decimal string on success.
fn validate_amount(raw: &str) -> Option<String> {
	let decoded = String::from_utf8_lossy(&percent_decode(raw)).into_owned();
	match amount_from_hr_string(&decoded) {
		Ok(atomic) if atomic > 0 => Some(decoded),
		_ => None,
	}
}

/// Validate a `memo` value: percent-decode, strip ASCII control chars and
/// newlines (untrusted free text — display / tx-message only, never a path or
/// route), then hard-cap at [`MAX_MEMO_BYTES`] on a UTF-8 boundary. Empty →
/// `None`.
fn validate_memo(raw: &str) -> Option<String> {
	let decoded = percent_decode(raw);
	// Drop ASCII control bytes (< 0x20, covering NUL / newline / tab) and DEL.
	let cleaned: Vec<u8> = decoded
		.into_iter()
		.filter(|&b| b >= 0x20 && b != 0x7f)
		.collect();
	let text = String::from_utf8_lossy(&cleaned).into_owned();
	let text = truncate_on_char_boundary(text, MAX_MEMO_BYTES);
	let text = text.trim().to_string();
	if text.is_empty() { None } else { Some(text) }
}

/// Truncate a string to at most `max` bytes without splitting a UTF-8 char.
fn truncate_on_char_boundary(s: String, max: usize) -> String {
	if s.len() <= max {
		return s;
	}
	let mut end = max;
	while end > 0 && !s.is_char_boundary(end) {
		end -= 1;
	}
	s[..end].to_string()
}

/// Minimal, correct RFC-3986 percent-decode over bytes. `%XX` (hex) becomes one
/// byte; a stray `%` or a non-hex escape is passed through literally. No new
/// dependency — the wallet has no direct percent-encoding crate and this is a
/// few lines. `+` is left literal (RFC-3986 query, not form-encoding).
fn percent_decode(s: &str) -> Vec<u8> {
	let bytes = s.as_bytes();
	let mut out = Vec::with_capacity(bytes.len());
	let mut i = 0;
	while i < bytes.len() {
		if bytes[i] == b'%' && i + 2 < bytes.len() {
			if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
				out.push((hi << 4) | lo);
				i += 3;
				continue;
			}
		}
		out.push(bytes[i]);
		i += 1;
	}
	out
}

/// Hex-nibble value for an ASCII hex digit, or `None`.
fn hex_val(b: u8) -> Option<u8> {
	match b {
		b'0'..=b'9' => Some(b - b'0'),
		b'a'..=b'f' => Some(b - b'a' + 10),
		b'A'..=b'F' => Some(b - b'A' + 10),
		_ => None,
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	const NPROFILE: &str =
		"nprofile1qqsw3v0m5v6h9q8n0hkxg6l4l5xk2z7z0n6f6q9m8x0q5v4l3k2j1h0gpz3mhxue69uhhyetvv9uju";

	#[test]
	fn bare_nprofile_unchanged() {
		let uri = format!("nostr:{NPROFILE}");
		let out = parse(&uri);
		assert_eq!(out.recipient, NPROFILE);
		assert_eq!(out.amount, None);
		assert_eq!(out.memo, None);
	}

	#[test]
	fn bare_npub_no_scheme_is_verbatim() {
		// No scheme at all → returned exactly as today (fed to the resolver).
		let out = parse("npub1abcdef");
		assert_eq!(out.recipient, "npub1abcdef");
		assert_eq!(out.amount, None);
		assert_eq!(out.memo, None);
	}

	#[test]
	fn uppercase_scheme_accepted() {
		let out = parse(&format!("NOSTR:{NPROFILE}?amount=2"));
		assert_eq!(out.recipient, NPROFILE);
		assert_eq!(out.amount.as_deref(), Some("2"));
	}

	#[test]
	fn with_amount() {
		let out = parse(&format!("nostr:{NPROFILE}?amount=1.5"));
		assert_eq!(out.recipient, NPROFILE);
		assert_eq!(out.amount.as_deref(), Some("1.5"));
		assert_eq!(out.memo, None);
	}

	#[test]
	fn with_amount_and_memo() {
		let out = parse(&format!("nostr:{NPROFILE}?amount=0.25&memo=Coffee"));
		assert_eq!(out.recipient, NPROFILE);
		assert_eq!(out.amount.as_deref(), Some("0.25"));
		assert_eq!(out.memo.as_deref(), Some("Coffee"));
	}

	#[test]
	fn negative_amount_rejected() {
		let out = parse(&format!("nostr:{NPROFILE}?amount=-1"));
		assert_eq!(out.recipient, NPROFILE);
		assert_eq!(out.amount, None);
	}

	#[test]
	fn zero_and_empty_amount_rejected() {
		assert_eq!(parse(&format!("nostr:{NPROFILE}?amount=0")).amount, None);
		assert_eq!(parse(&format!("nostr:{NPROFILE}?amount=")).amount, None);
	}

	#[test]
	fn garbage_amount_rejected() {
		for bad in ["abc", "1.5xyz", "1,5", "0x10", "1 5", " 1"] {
			let out = parse(&format!("nostr:{NPROFILE}?amount={bad}"));
			assert_eq!(out.amount, None, "expected {bad:?} to be rejected");
		}
	}

	#[test]
	fn overlong_memo_truncated() {
		let long = "a".repeat(500);
		let out = parse(&format!("nostr:{NPROFILE}?memo={long}"));
		let memo = out.memo.expect("memo present");
		assert_eq!(memo.len(), 256);
		assert!(memo.bytes().all(|b| b == b'a'));
	}

	#[test]
	fn memo_control_chars_stripped() {
		// Percent-encoded NUL, newline, tab and a raw CR are all removed.
		let out = parse(&format!("nostr:{NPROFILE}?memo=A%00B%0AC%09D\rE"));
		assert_eq!(out.memo.as_deref(), Some("ABCDE"));
	}

	#[test]
	fn memo_percent_decoded() {
		// "Hi there & co =2" with reserved chars percent-encoded.
		let out = parse(&format!(
			"nostr:{NPROFILE}?memo=Hi%20there%20%26%20co%20%3D2"
		));
		assert_eq!(out.memo.as_deref(), Some("Hi there & co =2"));
	}

	#[test]
	fn non_nostr_scheme_treated_as_today() {
		// A different scheme is NOT parsed for amount/memo; returned verbatim.
		let out = parse("bitcoin:bc1qxyz?amount=1.5");
		assert_eq!(out.recipient, "bitcoin:bc1qxyz?amount=1.5");
		assert_eq!(out.amount, None);
		assert_eq!(out.memo, None);
	}

	#[test]
	fn unknown_params_ignored() {
		let out = parse(&format!(
			"nostr:{NPROFILE}?lightning=zzz&amount=3&foo=bar&memo=Hey"
		));
		assert_eq!(out.recipient, NPROFILE);
		assert_eq!(out.amount.as_deref(), Some("3"));
		assert_eq!(out.memo.as_deref(), Some("Hey"));
	}

	#[test]
	fn over_length_rejected() {
		let huge = format!("nostr:{}", "a".repeat(5000));
		let out = parse(&huge);
		assert_eq!(out.recipient, "");
		assert_eq!(out.amount, None);
		assert_eq!(out.memo, None);
	}

	#[test]
	fn embedded_nul_rejected() {
		let out = parse(&format!("nostr:{NPROFILE}\0?amount=1"));
		assert_eq!(out.recipient, "");
		assert_eq!(out.amount, None);
	}

	#[test]
	fn duplicate_amount_first_wins() {
		let out = parse(&format!("nostr:{NPROFILE}?amount=1&amount=999"));
		assert_eq!(out.amount.as_deref(), Some("1"));
	}

	#[test]
	fn leading_trailing_whitespace_trimmed() {
		let out = parse(&format!("  nostr:{NPROFILE}?amount=1.5  "));
		assert_eq!(out.recipient, NPROFILE);
		assert_eq!(out.amount.as_deref(), Some("1.5"));
	}

	#[test]
	fn empty_input_is_bare_empty() {
		let out = parse("");
		assert_eq!(out.recipient, "");
		assert_eq!(out.amount, None);
		assert_eq!(out.memo, None);
	}
}
