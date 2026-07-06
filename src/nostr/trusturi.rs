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

//! "Trust with Goblin" (Authorize Sessions, v2) request parser.
//!
//! A site (magick.market) asks the wallet to establish a signing SESSION for a
//! domain by handing it a challenge plus session parameters over either the
//! `goblin:` deep-link scheme or the equivalent `nostr:` QR payload:
//!
//! ```text
//! goblin:trust?c=<64-hex nonce>&d=<domain>&cb=<https callback>&sk=<site session pubkey, 64-hex x-only>&r=<wss relay hint>&k=<csv kind set>
//! nostr:trust?...   (same, for QR payloads)
//! ```
//!
//! The grant is a superset of login: on approval the wallet signs the one-time
//! kind-22242 login event AND opens an encrypted relay channel bound to the
//! site's ephemeral `sk` channel key, over which the site can then have the
//! wallet silently sign an approved LOW-tier kind set for the life of the
//! session. Money-tier signs are never silent: they arrive on the same channel
//! and raise a per-action password prompt. See the Authorize Sessions spec.
//!
//! Parsing is PURE and fail-closed over UNTRUSTED input, mirroring
//! [`crate::nostr::loginuri`] and [`crate::nostr::authuri`] exactly (same scheme
//! handling, same percent-decoding, first occurrence of a duplicate param wins,
//! unknown params ignored). ANY single validation failure rejects the whole
//! URI: no modal, no partial handling, no fallthrough to the pay path. The
//! `sk`/`r`/`k` session fields are validated here, before any modal can open, so
//! the wallet never even considers a malformed session request.

use super::authuri::domain_bound;
use super::payuri::{percent_decode, strip_pay_scheme};
use super::session::sanitize_kind_set;

/// Total payload byte cap, same bar as the pay/login/authorize parsers.
const MAX_URI_LEN: usize = 4096;
/// Domain byte cap (a DNS name is at most 253 bytes).
const MAX_DOMAIN_LEN: usize = 253;
/// Callback URL byte cap.
const MAX_CALLBACK_LEN: usize = 2048;
/// Relay-hint URL byte cap (a single `wss://` URL).
const MAX_RELAY_LEN: usize = 512;
/// Maximum number of distinct kinds a site may request for the silent set.
const MAX_KINDS: usize = 64;

/// A validated trust (session) request: the one-time login nonce, the requesting
/// domain the user approves, the HTTPS login callback, the site's ephemeral
/// channel public key, the relay hint the channel runs on, and the raw requested
/// kind set (deduplicated, in range, BEFORE the wallet strips the ceiling).
/// Only constructed by [`parse`], so holding one means every field validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustUri {
	/// The one-time login-request nonce, exactly 64 hex chars.
	pub challenge: String,
	/// The requesting domain, shown to the user for approval.
	pub domain: String,
	/// The login callback the kind-22242 event is delivered to (identity step).
	pub callback: String,
	/// The site's ephemeral CHANNEL public key (x-only, 64 hex). NOT an identity
	/// key: it only encrypts and addresses the request/response envelopes.
	pub site_session_pubkey: String,
	/// The relay hint the encrypted channel runs on (`wss://`, or dev
	/// `ws://localhost`). The wallet honours it and may add its own fallbacks.
	pub relay: String,
	/// The kinds the site requested for the SILENT low-tier set, deduplicated and
	/// in range, exactly as sent. The wallet strips the ceiling (22242 and every
	/// money-tier kind) before storing this as `silent_kind_set`; the modal
	/// renders the remainder as categories and shows caution lines for anything
	/// stripped. Guaranteed non-empty, and guaranteed non-empty after stripping.
	pub requested_kinds: Vec<u16>,
}

/// True when `scanned` carries a Goblin scheme with the `trust` keyword, i.e. it
/// is a trust request (valid or not) and must NEVER be fed to the pay path. The
/// dispatcher checks this after [`super::loginuri::is_login_shaped`] and
/// [`super::authuri::is_authorize_shaped`] and BEFORE the pay path; a
/// shaped-but-invalid trust URI is then dropped entirely (no modal, no send).
pub fn is_trust_shaped(scanned: &str) -> bool {
	let text = scanned.trim();
	if text.len() > MAX_URI_LEN {
		return false;
	}
	match strip_pay_scheme(text) {
		Some(rest) => {
			let head = rest.split('?').next().unwrap_or("");
			head.eq_ignore_ascii_case("trust")
		}
		None => false,
	}
}

/// Parse a trust URI. `Some` only when EVERY field validates: `c` is exactly 64
/// hex, `d` is a shaped domain, `cb` is an https (or dev localhost) callback
/// bound to `d`, `sk` is 64-hex x-only, `r` is a single `wss://` (or dev
/// `ws://localhost`) URL, and `k` is a non-empty, in-range, deduplicated kind
/// list that still holds at least one kind after the wallet strips the ceiling.
/// Anything else is `None` and the whole request is ignored. Pure, total, no I/O.
pub fn parse(scanned: &str) -> Option<TrustUri> {
	let text = scanned.trim();
	if text.len() > MAX_URI_LEN || text.as_bytes().contains(&0) {
		return None;
	}
	let rest = strip_pay_scheme(text)?;
	let (head, query) = rest.split_once('?')?;
	if !head.eq_ignore_ascii_case("trust") {
		return None;
	}
	let mut challenge = None;
	let mut domain = None;
	let mut callback = None;
	let mut site_key = None;
	let mut relay = None;
	let mut kinds = None;
	for pair in query.split('&') {
		let Some((key, val)) = pair.split_once('=') else {
			continue; // valueless / malformed segment, ignore
		};
		match key {
			// First occurrence wins, matching the pay/login/authorize convention,
			// so a second value can never override a validated one.
			"c" if challenge.is_none() => challenge = Some(val),
			"d" if domain.is_none() => domain = Some(val),
			"cb" if callback.is_none() => callback = Some(val),
			"sk" if site_key.is_none() => site_key = Some(val),
			"r" if relay.is_none() => relay = Some(val),
			"k" if kinds.is_none() => kinds = Some(val),
			// Unknown params are ignored for forward-compat.
			_ => {}
		}
	}
	let challenge = validate_challenge(challenge?)?;
	let domain = validate_domain(domain?)?;
	let callback = validate_callback(callback?)?;
	// Same domain binding as login and authorize: the login callback host must
	// belong to the displayed domain, so a site cannot show one domain while
	// harvesting a login event for a host it does not control.
	if !domain_bound(&callback, &domain) {
		return None;
	}
	let site_session_pubkey = validate_x_only_hex(site_key?)?;
	let relay = validate_relay(relay?)?;
	let requested_kinds = validate_kinds(kinds?)?;
	Some(TrustUri {
		challenge,
		domain,
		callback,
		site_session_pubkey,
		relay,
		requested_kinds,
	})
}

/// The challenge nonce must be exactly 64 hex chars (same rule as login).
fn validate_challenge(raw: &str) -> Option<String> {
	let decoded = String::from_utf8_lossy(&percent_decode(raw)).into_owned();
	if decoded.len() == 64 && decoded.chars().all(|c| c.is_ascii_hexdigit()) {
		Some(decoded)
	} else {
		None
	}
}

/// The domain must be non-empty, printable ASCII without spaces, within DNS
/// length bounds. Display data plus one binding check, never a route (same rule
/// as login and authorize).
fn validate_domain(raw: &str) -> Option<String> {
	let decoded = String::from_utf8_lossy(&percent_decode(raw)).into_owned();
	let decoded = decoded.trim();
	if decoded.is_empty()
		|| decoded.len() > MAX_DOMAIN_LEN
		|| !decoded.chars().all(|c| c.is_ascii_graphic())
	{
		return None;
	}
	Some(decoded.to_string())
}

/// The callback must be `https://...`, or `http://localhost[:port]...` as the
/// one development exception (same rule as login and authorize).
fn validate_callback(raw: &str) -> Option<String> {
	let decoded = String::from_utf8_lossy(&percent_decode(raw)).into_owned();
	let decoded = decoded.trim();
	if decoded.len() > MAX_CALLBACK_LEN || decoded.bytes().any(|b| b < 0x20 || b == 0x7f) {
		return None;
	}
	if let Some(rest) = strip_prefix_ignore_case(decoded, "https://") {
		if !rest.is_empty() {
			return Some(decoded.to_string());
		}
		return None;
	}
	if let Some(rest) = strip_prefix_ignore_case(decoded, "http://") {
		if is_localhost_authority(rest) {
			return Some(decoded.to_string());
		}
	}
	None
}

/// A channel public key: exactly 64 hex chars (an x-only secp256k1 key). This is
/// NOT the identity key; it only encrypts and addresses the channel envelopes.
fn validate_x_only_hex(raw: &str) -> Option<String> {
	let decoded = String::from_utf8_lossy(&percent_decode(raw)).into_owned();
	let decoded = decoded.trim();
	if decoded.len() == 64 && decoded.chars().all(|c| c.is_ascii_hexdigit()) {
		Some(decoded.to_ascii_lowercase())
	} else {
		None
	}
}

/// The relay hint must be a single `wss://` URL, or `ws://localhost[:port]` as
/// the one development exception. Everything else rejects, so channel traffic
/// can never be pointed at a plaintext or non-relay endpoint.
fn validate_relay(raw: &str) -> Option<String> {
	let decoded = String::from_utf8_lossy(&percent_decode(raw)).into_owned();
	let decoded = decoded.trim();
	if decoded.is_empty()
		|| decoded.len() > MAX_RELAY_LEN
		|| decoded.bytes().any(|b| b < 0x20 || b == 0x7f)
		// A single URL only: no spaces, no comma-separated list.
		|| decoded.chars().any(|c| c == ' ' || c == ',')
	{
		return None;
	}
	if let Some(rest) = strip_prefix_ignore_case(decoded, "wss://") {
		if !rest.is_empty() {
			return Some(decoded.to_string());
		}
		return None;
	}
	if let Some(rest) = strip_prefix_ignore_case(decoded, "ws://") {
		if is_localhost_authority(rest) {
			return Some(decoded.to_string());
		}
	}
	None
}

/// The requested low-tier kind set: a comma-separated list of unsigned integers,
/// each a valid `u16`, deduplicated preserving first-seen order. Empty rejects (a
/// session must request at least one kind), the count is capped at [`MAX_KINDS`],
/// and — critically — a set that is empty AFTER the wallet strips the ceiling
/// (22242 and every money-tier kind) also rejects, since a session with nothing
/// left to sign silently is not a session.
fn validate_kinds(raw: &str) -> Option<Vec<u16>> {
	let decoded = String::from_utf8_lossy(&percent_decode(raw)).into_owned();
	let decoded = decoded.trim();
	if decoded.is_empty() {
		return None;
	}
	let mut out: Vec<u16> = Vec::new();
	for part in decoded.split(',') {
		let part = part.trim();
		// `parse::<u16>` rejects negatives, floats, out-of-range, and non-digits.
		let kind: u16 = part.parse().ok()?;
		if !out.contains(&kind) {
			out.push(kind);
		}
		if out.len() > MAX_KINDS {
			return None;
		}
	}
	if out.is_empty() {
		return None;
	}
	// A request the wallet would strip down to nothing (all login/money kinds) is
	// no session at all.
	if sanitize_kind_set(&out).is_empty() {
		return None;
	}
	Some(out)
}

/// Strip a case-insensitive ASCII prefix.
fn strip_prefix_ignore_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
	let n = prefix.len();
	match s.get(..n) {
		Some(head) if head.eq_ignore_ascii_case(prefix) => Some(&s[n..]),
		_ => None,
	}
}

/// True when the URL remainder after `http://`/`ws://` names exactly
/// `localhost`, optionally with a `:port` (a valid non-zero u16), followed by
/// nothing or a `/ ? #` delimiter. `localhost.evil.com` and friends do NOT pass.
fn is_localhost_authority(rest: &str) -> bool {
	let authority_end = rest
		.find(|c| c == '/' || c == '?' || c == '#')
		.unwrap_or(rest.len());
	let authority = &rest[..authority_end];
	let (host, port) = match authority.split_once(':') {
		Some((h, p)) => (h, Some(p)),
		None => (authority, None),
	};
	if !host.eq_ignore_ascii_case("localhost") {
		return false;
	}
	match port {
		None => true,
		Some(p) => {
			!p.is_empty()
				&& p.chars().all(|c| c.is_ascii_digit())
				&& p.parse::<u16>().map(|n| n > 0).unwrap_or(false)
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A well-formed 64-hex nonce / channel key.
	const C: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
	const SK: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
	const NPUB: &str = "npub15gsytqvs5c78u83yv2agl4twjkk6qgem7gtwe2agu7s90tkelxys0xxely";

	fn valid_uri(scheme: &str) -> String {
		format!(
			"{scheme}trust?c={C}&d=magick.market&cb=https://magick.market/api/login&sk={SK}&r=wss://relay.magick.market&k=1,7,1059,30402"
		)
	}

	#[test]
	fn valid_goblin_and_nostr_trust_accepted() {
		for scheme in ["goblin:", "nostr:"] {
			let out = parse(&valid_uri(scheme)).expect("valid trust URI must parse");
			assert_eq!(out.challenge, C);
			assert_eq!(out.domain, "magick.market");
			assert_eq!(out.callback, "https://magick.market/api/login");
			assert_eq!(out.site_session_pubkey, SK);
			assert_eq!(out.relay, "wss://relay.magick.market");
			assert_eq!(out.requested_kinds, vec![1, 7, 1059, 30402]);
		}
	}

	#[test]
	fn scheme_and_keyword_case_insensitive() {
		let uri = format!(
			"GOBLIN:TRUST?c={C}&d=magick.market&cb=https://magick.market/cb&sk={SK}&r=wss://r.magick.market&k=1"
		);
		let out = parse(&uri).expect("uppercase scheme/keyword must parse");
		assert_eq!(out.domain, "magick.market");
		assert!(is_trust_shaped(&uri));
	}

	#[test]
	fn is_trust_shaped_detects_keyword() {
		assert!(is_trust_shaped(&valid_uri("goblin:")));
		assert!(is_trust_shaped(&valid_uri("nostr:")));
		// Shaped even when invalid, so the dispatcher grabs it before pay.
		assert!(is_trust_shaped("goblin:trust?c=&d=&cb=&sk=&r=&k="));
		assert!(!is_trust_shaped("goblin:login?c=x"));
		assert!(!is_trust_shaped("goblin:authorize?e=x"));
		assert!(!is_trust_shaped("bitcoin:trust?c=x"));
		assert!(!is_trust_shaped("trust?c=x"));
		assert!(!is_trust_shaped(""));
	}

	#[test]
	fn challenge_must_be_exactly_64_hex() {
		for bad in [&C[..63], &format!("{C}0")[..], ""] {
			let uri = format!(
				"goblin:trust?c={bad}&d=magick.market&cb=https://m.m/cb&sk={SK}&r=wss://r.m/&k=1"
			);
			assert_eq!(parse(&uri), None, "expected c={bad:?} rejected");
		}
	}

	#[test]
	fn site_key_must_be_64_hex() {
		for bad in [&SK[..63], &format!("{SK}0")[..], "", "not-hex-not-hex"] {
			let uri = format!(
				"goblin:trust?c={C}&d=magick.market&cb=https://magick.market/cb&sk={bad}&r=wss://r.magick.market&k=1"
			);
			assert_eq!(parse(&uri), None, "expected sk={bad:?} rejected");
		}
	}

	#[test]
	fn relay_must_be_wss_or_localhost_ws() {
		// Accepted: wss, and the dev ws://localhost exception.
		for ok in ["wss://relay.magick.market", "ws://localhost:7777"] {
			let uri = format!(
				"goblin:trust?c={C}&d=magick.market&cb=https://magick.market/cb&sk={SK}&r={ok}&k=1"
			);
			assert!(parse(&uri).is_some(), "expected r={ok:?} accepted");
		}
		// Rejected: plain ws to a non-localhost host, http, garbage, a list.
		for bad in [
			"ws://relay.evil.com",
			"http://relay.magick.market",
			"relay.magick.market",
			"wss://a.com,wss://b.com",
			"",
		] {
			let uri = format!(
				"goblin:trust?c={C}&d=magick.market&cb=https://magick.market/cb&sk={SK}&r={bad}&k=1"
			);
			assert_eq!(parse(&uri), None, "expected r={bad:?} rejected");
		}
	}

	#[test]
	fn kinds_parsed_deduped_and_capped() {
		// Dedup preserving first-seen order.
		let uri = format!(
			"goblin:trust?c={C}&d=magick.market&cb=https://magick.market/cb&sk={SK}&r=wss://r.magick.market&k=7,1,7,1"
		);
		assert_eq!(parse(&uri).unwrap().requested_kinds, vec![7, 1]);
		// Empty k rejects.
		let uri = format!(
			"goblin:trust?c={C}&d=magick.market&cb=https://magick.market/cb&sk={SK}&r=wss://r.magick.market&k="
		);
		assert_eq!(parse(&uri), None);
		// Non-integer / out of range rejects the whole URI.
		for bad in ["1,two,3", "1,-2", "1,70000", "1,1.0"] {
			let uri = format!(
				"goblin:trust?c={C}&d=magick.market&cb=https://magick.market/cb&sk={SK}&r=wss://r.magick.market&k={bad}"
			);
			assert_eq!(parse(&uri), None, "expected k={bad:?} rejected");
		}
	}

	#[test]
	fn kinds_that_strip_to_empty_reject() {
		// 22242 (login) alone strips to nothing: no session.
		let uri = format!(
			"goblin:trust?c={C}&d=magick.market&cb=https://magick.market/cb&sk={SK}&r=wss://r.magick.market&k=22242"
		);
		assert_eq!(parse(&uri), None);
		// Money-only (kind 17) strips to nothing: no session.
		let uri = format!(
			"goblin:trust?c={C}&d=magick.market&cb=https://magick.market/cb&sk={SK}&r=wss://r.magick.market&k=17"
		);
		assert_eq!(parse(&uri), None);
		// But a set that keeps something after stripping is fine, and the raw set
		// is preserved for the modal to render caution lines.
		let uri = format!(
			"goblin:trust?c={C}&d=magick.market&cb=https://magick.market/cb&sk={SK}&r=wss://r.magick.market&k=22242,1,17"
		);
		assert_eq!(parse(&uri).unwrap().requested_kinds, vec![22242, 1, 17]);
	}

	#[test]
	fn missing_params_rejected() {
		let base = format!(
			"c={C}&d=magick.market&cb=https://magick.market/cb&sk={SK}&r=wss://r.magick.market&k=1"
		);
		for drop in ["c=", "d=", "cb=", "sk=", "r=", "k="] {
			// Rebuild the query omitting one param entirely.
			let key = &drop[..drop.len() - 1];
			let kept: Vec<&str> = base
				.split('&')
				.filter(|p| !p.starts_with(&format!("{key}=")))
				.collect();
			let uri = format!("goblin:trust?{}", kept.join("&"));
			assert_eq!(parse(&uri), None, "dropping {key} must reject");
		}
		assert_eq!(parse("goblin:trust"), None);
		assert_eq!(parse("goblin:trust?"), None);
	}

	#[test]
	fn callback_domain_binding_enforced() {
		// Cross-domain callback rejected.
		let bad = format!(
			"goblin:trust?c={C}&d=magick.market&cb=https://evil.com/cb&sk={SK}&r=wss://r.magick.market&k=1"
		);
		assert_eq!(parse(&bad), None);
		// Subdomain accepted.
		let ok = format!(
			"goblin:trust?c={C}&d=magick.market&cb=https://auth.magick.market/cb&sk={SK}&r=wss://r.magick.market&k=1"
		);
		assert!(parse(&ok).is_some());
	}

	#[test]
	fn duplicate_params_first_wins() {
		let uri = format!(
			"goblin:trust?c={C}&c={}&d=magick.market&d=evil.com&cb=https://magick.market/cb&sk={SK}&r=wss://r.magick.market&k=1&k=7",
			"f".repeat(64)
		);
		let out = parse(&uri).expect("must parse");
		assert_eq!(out.challenge, C);
		assert_eq!(out.domain, "magick.market");
		assert_eq!(out.requested_kinds, vec![1]);
	}

	#[test]
	fn whitespace_trimmed_and_oversize_rejected() {
		let uri = format!("  {}  ", valid_uri("nostr:"));
		assert!(parse(&uri).is_some());
		let huge = format!(
			"goblin:trust?c={C}&d=magick.market&cb=https://m.m/{}&sk={SK}&r=wss://r.m/&k=1",
			"a".repeat(5000)
		);
		assert_eq!(parse(&huge), None);
		assert!(!is_trust_shaped(&huge));
	}

	#[test]
	fn trust_is_not_pay_login_or_authorize() {
		let trust = valid_uri("goblin:");
		assert!(is_trust_shaped(&trust));
		assert!(!crate::nostr::loginuri::is_login_shaped(&trust));
		assert!(!crate::nostr::authuri::is_authorize_shaped(&trust));
		// A pay URI is never trust-shaped.
		let pay = format!("goblin:{NPUB}?amount=1.5");
		assert!(!is_trust_shaped(&pay));
		assert_eq!(parse(&pay), None);
	}
}
