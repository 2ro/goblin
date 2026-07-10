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

//! Pay-URI parser for scanned payment QRs and payment deep links.
//!
//! A GoblinPay checkout QR (or an "Open in Goblin" web button) carries an
//! optional amount (and memo) on the recipient, under either the `goblin:`
//! scheme (Goblin's own registered deep-link scheme, so the OS routes it to the
//! wallet) or the plain `nostr:` scheme (what a QR/social payload spells). Both
//! are the SAME payload — only the scheme differs:
//!
//! ```text
//! goblin:<nprofile-or-npub>?amount=<decimal GRIN>&memo=<percent-encoded>
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
/// Order-handle byte cap (post percent-decode + control-strip). The order
/// param is an opaque routing key (magick's `MM-<hex>` invoice number), never
/// free text, so it is capped tight per the frozen contract (section 4.1).
const MAX_ORDER_BYTES: usize = 64;
/// Upper bound on the whole-GRIN part of an accepted amount. It sits far below
/// the point where `amount_from_hr_string`'s `grins * GRIN_BASE` would overflow
/// u64 (which in release wraps to a small atomic value while the review screen
/// still shows the giant figure), yet comfortably above Grin's real circulating
/// supply (~10^8 GRIN). A scanned amount above this is abuse, not a payment.
const MAX_WHOLE_GRIN: u64 = 1_000_000_000;

/// Schemes that unlock amount/memo parsing. `goblin:` is Goblin's registered
/// deep-link scheme (web "Open in Goblin" buttons, so the OS opens the wallet);
/// `nostr:` is the equivalent QR/social payload. Both spell the same payment.
const PAY_SCHEMES: [&str; 2] = ["goblin:", "nostr:"];

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
	/// Proof-on-request: the merchant's Grin slatepack (`grin1`/`tgrin1`) proof
	/// address. Presence turns proof mode ON for this one transaction; the value
	/// is threaded verbatim as `payment_proof_recipient_address` on the send.
	/// Fail-closed: an unparseable value is dropped to `None` (a proof-less
	/// send), never blocking the payment. Frozen contract section 4.1.
	pub proof: Option<String>,
	/// The opaque order handle (magick's `MM-<hex>` invoice number) the wallet
	/// echoes verbatim into the delivery events' `payment-request` tag. Distinct
	/// from `memo`: `order` is a non-editable routing key, `memo` is editable
	/// display text. Dropped if empty after sanitization.
	pub order: Option<String>,
	/// The watcher's Nostr pubkey (`npub…`) the wallet gift-wraps the full proof
	/// delivery to. Dropped if it is not a valid npub; absence simply means no
	/// encrypted delivery target (the plain receipt still publishes).
	pub notify: Option<String>,
	/// Batch size for an invoice-request URI: how many payment requests the
	/// wallet is asked to issue, each with its own fresh per-sale proof
	/// address. Default 1 (single flow, unchanged when absent); capped at
	/// [`MAX_BATCH_COUNT`]; fail-closed to 1 on anything unparseable or zero.
	pub count: u32,
}

impl PayUri {
	/// A recipient-only result with no prefilled amount/memo (today's behavior).
	fn bare(recipient: String) -> Self {
		PayUri {
			recipient,
			amount: None,
			memo: None,
			proof: None,
			order: None,
			notify: None,
			count: 1,
		}
	}
}

/// Cap on the `count` batch parameter: the most invoices one URI may ask the
/// wallet to issue in a single approval.
pub const MAX_BATCH_COUNT: u32 = 20;

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

	// Strict scheme: only a `goblin:`/`nostr:` prefix (case-insensitive) unlocks
	// amount/memo parsing, matching the scanner's existing strip logic. Any
	// other payload (a bare npub, or some other scheme) is returned verbatim,
	// exactly as the scanner treated it before pay-URIs existed.
	let rest = match strip_pay_scheme(text) {
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
	let mut proof = None;
	let mut order = None;
	let mut notify = None;
	let mut count = None;
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
				// Proof-on-request params (frozen contract section 4.1). Each is
				// fail-closed: an invalid value is dropped to `None`, degrading to
				// a normal proof-less payment rather than blocking the send.
				"proof" if proof.is_none() => proof = validate_proof(val),
				"order" if order.is_none() => order = validate_order(val),
				"notify" if notify.is_none() => notify = validate_notify(val),
				"count" if count.is_none() => count = validate_count(val),
				// Unknown params are ignored for forward-compat.
				_ => {}
			}
		}
	}

	PayUri {
		recipient,
		amount,
		memo,
		proof,
		order,
		notify,
		count: count.unwrap_or(1),
	}
}

/// Validate a `count` value: a positive integer, clamped to [`MAX_BATCH_COUNT`].
/// Fail-closed: unparseable or zero drops to `None` (treated as 1, the single
/// flow), never blocking the URI.
fn validate_count(raw: &str) -> Option<u32> {
	match raw.trim().parse::<u32>() {
		Ok(0) | Err(_) => None,
		Ok(n) => Some(n.min(MAX_BATCH_COUNT)),
	}
}

/// Strip a case-insensitive payment scheme prefix (`goblin:` or `nostr:`),
/// returning the remainder. Byte-safe against a leading multibyte char (the
/// `text.get(..n)` guards against a `[..n]` slice panic). Crate-visible so the
/// login-URI parser (see [`crate::nostr::loginuri`]) shares the exact same
/// scheme handling.
pub(crate) fn strip_pay_scheme(text: &str) -> Option<&str> {
	for scheme in PAY_SCHEMES {
		let n = scheme.len();
		if let Some(head) = text.get(..n) {
			if head.eq_ignore_ascii_case(scheme) {
				return Some(&text[n..]);
			}
		}
	}
	None
}

/// True when `scanned` (once trimmed) carries a Goblin payment scheme
/// (`goblin:` or `nostr:`) — i.e. a payment deep link rather than a slatepack
/// message or opened file. Used to route an incoming argv/intent payload to the
/// send-review flow instead of the slatepack message handler.
pub fn is_pay_uri(scanned: &str) -> bool {
	strip_pay_scheme(scanned.trim()).is_some()
}

/// Validate an `amount` value: percent-decode, then accept it ONLY if the
/// wallet's own `amount_from_hr_string` parses it to a strictly positive
/// atomic amount. Never custom float parsing; any error → `None` (fall back to
/// manual entry). Returns the clean decoded decimal string on success.
fn validate_amount(raw: &str) -> Option<String> {
	let decoded = String::from_utf8_lossy(&percent_decode(raw)).into_owned();
	// A Grin amount is only ASCII `[0-9.]`. Reject any non-ASCII up front:
	// `amount_from_hr_string` slices the fractional tail at a fixed byte index,
	// which panics if that index lands inside a multibyte UTF-8 char. The scan /
	// deep-link thread has no catch_unwind, so a crafted amount like `0.€€€€`
	// would crash the wallet. Fail closed to manual entry instead.
	if !decoded.is_ascii() {
		return None;
	}
	// Cap the whole-GRIN part below the u64 overflow point. Without this a giant
	// amount wraps (in release) to a small atomic value that is what actually
	// gets dispatched, while the review screen shows the giant figure. A whole
	// part that does not even fit u64 is left for `amount_from_hr_string` to
	// reject (its own `parse::<u64>` errors, so no wrap can occur).
	if let Ok(whole) = decoded.split('.').next().unwrap_or("").parse::<u64>() {
		if whole > MAX_WHOLE_GRIN {
			return None;
		}
	}
	match amount_from_hr_string(&decoded) {
		Ok(atomic) if atomic > 0 => Some(decoded),
		_ => None,
	}
}

/// Validate a `memo` value: percent-decode, then drop every display-dangerous
/// codepoint — ASCII control chars/newlines AND the bidi-override / isolate /
/// zero-width format chars (see
/// [`crate::nostr::sanitize::is_display_dangerous`]) — because a memo is
/// untrusted free text rendered in the payment strip (display / tx-message
/// only, never a path or route). Then hard-cap at [`MAX_MEMO_BYTES`] on a UTF-8
/// boundary. Empty → `None`. Filtering by CHAR after decoding (not by byte) is
/// what catches the multibyte bidi codepoints a byte filter would miss.
fn validate_memo(raw: &str) -> Option<String> {
	let decoded = percent_decode(raw);
	let text = String::from_utf8_lossy(&decoded);
	// Drop control chars (NUL / newline / tab / DEL) and bidi/zero-width format
	// chars — leaving legitimate letters of every script intact.
	let cleaned: String = text
		.chars()
		.filter(|c| !crate::nostr::sanitize::is_display_dangerous(*c))
		.collect();
	let text = truncate_on_char_boundary(cleaned, MAX_MEMO_BYTES);
	let text = text.trim().to_string();
	if text.is_empty() { None } else { Some(text) }
}

/// Validate a `proof` value: percent-decode, then accept it ONLY if it has the
/// shape of a Grin slatepack address (`grin1…`/`tgrin1…`, bech32 charset, long
/// enough to be a real key). This is a fail-closed SHAPE check; the send path
/// re-parses it authoritatively via `SlatepackAddress::try_from` and drops it
/// again if that fails, so an almost-valid string can never turn into a bad
/// proof recipient. Returns the clean decoded address on success.
fn validate_proof(raw: &str) -> Option<String> {
	let decoded = String::from_utf8_lossy(&percent_decode(raw)).into_owned();
	let decoded = decoded.trim();
	if looks_like_slatepack_address(decoded) {
		Some(decoded.to_string())
	} else {
		None
	}
}

/// Loose shape test for a Grin slatepack address: a `grin1`/`tgrin1` bech32
/// human-readable prefix followed by a bech32-charset data part of plausible
/// length. Mirrors magick's `isValidGoblinPayAddress` grin1 arm; authoritative
/// decode happens at send time.
fn looks_like_slatepack_address(s: &str) -> bool {
	let lower = s.to_ascii_lowercase();
	let data = if let Some(d) = lower.strip_prefix("tgrin1") {
		d
	} else if let Some(d) = lower.strip_prefix("grin1") {
		d
	} else {
		return false;
	};
	// bech32 data charset excludes `1`, `b`, `i`, `o`; a real key is well over
	// 20 data chars. We only guard obvious garbage here.
	data.len() >= 20
		&& data
			.chars()
			.all(|c| c.is_ascii_alphanumeric() && !matches!(c, '1' | 'b' | 'i' | 'o'))
}

/// Validate an `order` value: percent-decode, strip ASCII control chars (it is a
/// routing key, never display text or a path), hard-cap at [`MAX_ORDER_BYTES`]
/// on a UTF-8 boundary, trim. Empty → `None`. The wallet echoes this verbatim
/// into the `payment-request` tag of every delivery event, so it must survive
/// the round trip unchanged.
fn validate_order(raw: &str) -> Option<String> {
	let decoded = percent_decode(raw);
	let cleaned: Vec<u8> = decoded
		.into_iter()
		.filter(|&b| b >= 0x20 && b != 0x7f)
		.collect();
	let text = String::from_utf8_lossy(&cleaned).into_owned();
	let text = truncate_on_char_boundary(text, MAX_ORDER_BYTES);
	let text = text.trim().to_string();
	if text.is_empty() { None } else { Some(text) }
}

/// Validate a `notify` value: percent-decode, then accept it ONLY if it has the
/// shape of an `npub` (bech32 `npub1…`). Fail-closed SHAPE check; the delivery
/// path re-decodes it authoritatively via `PublicKey::from_bech32` and drops it
/// again on failure. Returns the clean decoded npub on success.
fn validate_notify(raw: &str) -> Option<String> {
	let decoded = String::from_utf8_lossy(&percent_decode(raw)).into_owned();
	let decoded = decoded.trim();
	let lower = decoded.to_ascii_lowercase();
	if let Some(data) = lower.strip_prefix("npub1") {
		// A bech32-encoded 32-byte key is ~59 data chars; guard obvious garbage.
		if data.len() >= 50
			&& data
				.chars()
				.all(|c| c.is_ascii_alphanumeric() && !matches!(c, '1' | 'b' | 'i' | 'o'))
		{
			return Some(decoded.to_string());
		}
	}
	None
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
/// Crate-visible so the login-URI parser decodes identically.
pub(crate) fn percent_decode(s: &str) -> Vec<u8> {
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

	#[test]
	fn count_parses_defaults_and_caps() {
		const NPUB: &str = "npub15gsytqvs5c78u83yv2agl4twjkk6qgem7gtwe2agu7s90tkelxys0xxely";
		// Absent -> 1 (single flow unchanged).
		assert_eq!(parse(&format!("goblin:{NPUB}?amount=1.5")).count, 1);
		// Present -> parsed.
		assert_eq!(parse(&format!("goblin:{NPUB}?amount=1.5&count=5")).count, 5);
		// Capped at MAX_BATCH_COUNT.
		assert_eq!(
			parse(&format!("goblin:{NPUB}?amount=1.5&count=999")).count,
			MAX_BATCH_COUNT
		);
		// Fail-closed: zero or garbage -> 1.
		assert_eq!(parse(&format!("goblin:{NPUB}?amount=1.5&count=0")).count, 1);
		assert_eq!(
			parse(&format!("goblin:{NPUB}?amount=1.5&count=abc")).count,
			1
		);
		// First occurrence wins.
		assert_eq!(parse(&format!("goblin:{NPUB}?count=3&count=9")).count, 3);
	}

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
	fn goblin_scheme_equivalent_to_nostr() {
		// The `goblin:` deep-link scheme is the same payload as `nostr:` — it
		// MUST parse to the identical recipient / amount / memo. This is the
		// contract behind the web "Open in Goblin" buttons.
		let nostr = parse(&format!("nostr:{NPROFILE}?amount=1.5&memo=Coffee"));
		let goblin = parse(&format!("goblin:{NPROFILE}?amount=1.5&memo=Coffee"));
		assert_eq!(goblin, nostr);
		assert_eq!(goblin.recipient, NPROFILE);
		assert_eq!(goblin.amount.as_deref(), Some("1.5"));
		assert_eq!(goblin.memo.as_deref(), Some("Coffee"));
	}

	#[test]
	fn goblin_scheme_case_insensitive() {
		let out = parse(&format!("GOBLIN:{NPROFILE}?amount=2"));
		assert_eq!(out.recipient, NPROFILE);
		assert_eq!(out.amount.as_deref(), Some("2"));
	}

	#[test]
	fn bare_goblin_nprofile_unchanged() {
		let out = parse(&format!("goblin:{NPROFILE}"));
		assert_eq!(out.recipient, NPROFILE);
		assert_eq!(out.amount, None);
		assert_eq!(out.memo, None);
	}

	#[test]
	fn is_pay_uri_recognizes_both_schemes() {
		assert!(is_pay_uri(&format!("goblin:{NPROFILE}?amount=1")));
		assert!(is_pay_uri(&format!("nostr:{NPROFILE}")));
		assert!(is_pay_uri(&format!("  GOBLIN:{NPROFILE}  ")));
		// A slatepack message / bare key / other scheme is NOT a pay URI.
		assert!(!is_pay_uri("BEGINSLATEPACK. abc DEFG. ENDSLATEPACK."));
		assert!(!is_pay_uri("npub1abcdef"));
		assert!(!is_pay_uri("bitcoin:bc1qxyz?amount=1"));
		assert!(!is_pay_uri(""));
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
	fn multibyte_amount_rejected_no_panic() {
		// A crafted multibyte amount must never reach grin_core's fixed-index
		// fractional-tail slice (which panics on a non-char-boundary). It is
		// dropped to None and the payment degrades to manual entry; no panic on
		// the scan/deep-link thread. The `0.€€€€` case slices mid-char in
		// grin_core without the ASCII guard.
		for bad in [
			"0.\u{20ac}\u{20ac}\u{20ac}\u{20ac}", // 3-byte euro signs
			"0.\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}", // 2-byte accents past WIDTH
			"\u{20ac}",
			"1\u{e9}",
			"0.5\u{1f600}", // 4-byte emoji
		] {
			let out = parse(&format!("nostr:{NPROFILE}?amount={bad}"));
			assert_eq!(out.amount, None, "expected {bad:?} to be dropped");
			assert_eq!(out.recipient, NPROFILE);
		}
	}

	#[test]
	fn oversized_amount_rejected() {
		// Above the whole-GRIN ceiling → dropped before the grin parse, so a huge
		// display value can't overflow-wrap into a small dispatched atomic amount.
		for bad in [
			"2000000000",           // 2e9 GRIN, over the 1e9 ceiling
			"99999999999",          // ~1e11 GRIN
			"1000000001.5",         // just over the ceiling, with a fraction
			"18446744073709551615", // u64::MAX whole grins (would wrap grins*BASE)
		] {
			let out = parse(&format!("nostr:{NPROFILE}?amount={bad}"));
			assert_eq!(out.amount, None, "expected {bad:?} to be rejected");
		}
		// The ceiling itself and just under it still parse.
		assert_eq!(
			parse(&format!("nostr:{NPROFILE}?amount=1000000000"))
				.amount
				.as_deref(),
			Some("1000000000")
		);
		assert_eq!(
			parse(&format!("nostr:{NPROFILE}?amount=999999999.5"))
				.amount
				.as_deref(),
			Some("999999999.5")
		);
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

	// --- magick.market interop contract -------------------------------------
	// These guard the magick.market <-> Goblin pay-URI contract: a checkout QR
	// from magick MUST parse here to the exact recipient / amount / memo. magick
	// emits this canonical format from `buildGoblinPayUri` in src/lib/grin.ts,
	// converting its internal integer nanogrin to a decimal-GRIN `amount` string
	// and carrying the opaque `MM-<hex>` invoice number as the `memo`.

	#[test]
	fn magick_market_checkout_uri_round_trips() {
		// 1_500_000_000 nanogrin == "1.5" GRIN (magick's formatGrin() output);
		// memo is the opaque invoice number that bridges payment <-> order.
		let invoice = "MM-1A2B3C4D5E6F7A8B9C0D1E2F";
		let uri = format!("nostr:{NPROFILE}?amount=1.5&memo={invoice}");
		let out = parse(&uri);
		assert_eq!(out.recipient, NPROFILE);
		assert_eq!(out.amount.as_deref(), Some("1.5"));
		assert_eq!(out.memo.as_deref(), Some(invoice));
	}

	#[test]
	fn magick_market_amount_precision_range() {
		// Whole GRIN and the smallest Grin unit (1 nanogrin == 0.000000001 GRIN),
		// the two ends of the decimal-GRIN strings magick can emit.
		let whole = parse(&format!("nostr:{NPROFILE}?amount=1&memo=MM-ABC123"));
		assert_eq!(whole.amount.as_deref(), Some("1"));
		assert_eq!(whole.memo.as_deref(), Some("MM-ABC123"));

		let smallest = parse(&format!(
			"nostr:{NPROFILE}?amount=0.000000001&memo=MM-ABC123"
		));
		assert_eq!(smallest.amount.as_deref(), Some("0.000000001"));
		assert_eq!(smallest.memo.as_deref(), Some("MM-ABC123"));
	}

	// --- proof-on-request params (frozen contract section 4.1) --------------

	/// A shape-valid grin1 slatepack address (charset excludes 1/b/i/o).
	const GRIN1: &str = "grin1qqvqzqzpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqsz";
	/// A shape-valid npub (the Goblin news key).
	const NPUB: &str = "npub15gsytqvs5c78u83yv2agl4twjkk6qgem7gtwe2agu7s90tkelxys0xxely";

	#[test]
	fn parses_all_three_proof_params() {
		let uri = format!(
			"nostr:{NPROFILE}?amount=1.5&memo=Coffee&proof={GRIN1}&order=MM-ABC123&notify={NPUB}"
		);
		let out = parse(&uri);
		assert_eq!(out.recipient, NPROFILE);
		assert_eq!(out.amount.as_deref(), Some("1.5"));
		assert_eq!(out.memo.as_deref(), Some("Coffee"));
		assert_eq!(out.proof.as_deref(), Some(GRIN1));
		assert_eq!(out.order.as_deref(), Some("MM-ABC123"));
		assert_eq!(out.notify.as_deref(), Some(NPUB));
	}

	#[test]
	fn goblin_scheme_carries_proof_params() {
		// The clickable `goblin:` deep link must parse identically to `nostr:`.
		let query = format!("amount=2&proof={GRIN1}&order=MM-1&notify={NPUB}");
		let nostr = parse(&format!("nostr:{NPROFILE}?{query}"));
		let goblin = parse(&format!("goblin:{NPROFILE}?{query}"));
		assert_eq!(goblin, nostr);
		assert_eq!(goblin.proof.as_deref(), Some(GRIN1));
	}

	#[test]
	fn proof_absent_leaves_none() {
		// A normal magick / p2p payment carries no proof params: all three None.
		let out = parse(&format!("nostr:{NPROFILE}?amount=1&memo=MM-1"));
		assert_eq!(out.proof, None);
		assert_eq!(out.order, None);
		assert_eq!(out.notify, None);
	}

	#[test]
	fn tgrin1_proof_accepted() {
		let tgrin1 = format!("t{GRIN1}");
		let out = parse(&format!("nostr:{NPROFILE}?proof={tgrin1}"));
		assert_eq!(out.proof.as_deref(), Some(tgrin1.as_str()));
	}

	#[test]
	fn bad_proof_dropped_fail_closed() {
		// Not a slatepack address (wrong hrp, too short, or plain garbage) → the
		// param is dropped and the payment degrades to a normal proof-less send.
		for bad in [
			"npub1abcdef",
			"grin1",      // hrp only, no data
			"grin1short", // data too short
			"bc1qxyz",    // wrong network
			"notanaddress",
			"",
		] {
			let out = parse(&format!("nostr:{NPROFILE}?amount=1&proof={bad}"));
			assert_eq!(out.proof, None, "expected {bad:?} proof to be dropped");
			// Dropping proof never blocks the rest of the payment.
			assert_eq!(out.amount.as_deref(), Some("1"));
		}
	}

	#[test]
	fn order_is_control_stripped_and_capped() {
		// Percent-encoded control chars are removed; a routing key survives verbatim.
		let out = parse(&format!("nostr:{NPROFILE}?order=MM-A%00B%0AC"));
		assert_eq!(out.order.as_deref(), Some("MM-ABC"));
		// Over-cap orders truncate at 64 bytes.
		let long = "M".repeat(200);
		let out = parse(&format!("nostr:{NPROFILE}?order={long}"));
		assert_eq!(out.order.as_deref().map(|s| s.len()), Some(64));
	}

	#[test]
	fn empty_order_dropped() {
		assert_eq!(parse(&format!("nostr:{NPROFILE}?order=")).order, None);
		// Whitespace-only after decode is also empty.
		assert_eq!(parse(&format!("nostr:{NPROFILE}?order=%20%20")).order, None);
	}

	#[test]
	fn bad_notify_dropped_fail_closed() {
		for bad in [
			"nprofile1abc",
			"npub1",
			"hex0123",
			"grin1qqqqqqqqqqqqqqqqqqqqqq",
			"",
		] {
			let out = parse(&format!("nostr:{NPROFILE}?amount=1&notify={bad}"));
			assert_eq!(out.notify, None, "expected {bad:?} notify to be dropped");
			assert_eq!(out.amount.as_deref(), Some("1"));
		}
	}

	#[test]
	fn proof_params_first_occurrence_wins() {
		let out = parse(&format!(
			"nostr:{NPROFILE}?order=MM-1&order=MM-EVIL&proof={GRIN1}&proof=grin1short"
		));
		assert_eq!(out.order.as_deref(), Some("MM-1"));
		assert_eq!(out.proof.as_deref(), Some(GRIN1));
	}

	#[test]
	fn old_wallet_forward_compat_unaffected() {
		// The pre-existing recipient/amount/memo contract is unchanged when the
		// new params ride alongside (a shipped old wallet just ignores them).
		let out = parse(&format!(
			"nostr:{NPROFILE}?amount=1.5&memo=MM-1&proof={GRIN1}&order=MM-1&notify={NPUB}"
		));
		assert_eq!(out.recipient, NPROFILE);
		assert_eq!(out.amount.as_deref(), Some("1.5"));
		assert_eq!(out.memo.as_deref(), Some("MM-1"));
	}
}
