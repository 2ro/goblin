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

//! "Sign in with Goblin" login-URI parser and one-time login-event signer.
//!
//! A site (magick.market) asks the wallet to approve a one-time login by
//! handing it a challenge over either the `goblin:` deep-link scheme or the
//! equivalent `nostr:` QR payload:
//!
//! ```text
//! goblin:login?c=<64-hex nonce>&d=<domain>&cb=<https callback URL>
//! nostr:login?c=<64-hex nonce>&d=<domain>&cb=<https callback URL>
//! ```
//!
//! On approval the wallet signs a kind-22242 event (content empty, tags
//! `[["challenge", c], ["domain", d]]`) with the CHOSEN identity's key and
//! POSTs it to the callback as `{"event": <event-json>}`. The signed event
//! proves control of the key for this one nonce; it shares no secret and
//! grants the site no capability to act as the user.
//!
//! Parsing is PURE and fail-closed over UNTRUSTED input, mirroring
//! [`crate::nostr::payuri`] (same scheme handling, same percent-decoding,
//! first occurrence of a duplicate param wins). A login-shaped URI that fails
//! validation is REJECTED as a whole — it is never fed to the pay path and it
//! never opens an approval modal. The `login` keyword cannot collide with a
//! pay recipient: a bech32 npub/nprofile always starts `npub1`/`nprofile1`.

use super::payuri::{percent_decode, strip_pay_scheme};
use nostr_sdk::{Event, EventBuilder, Keys, Kind, Tag, TagKind};

/// Total payload byte cap, same bar as the pay-URI parser.
const MAX_URI_LEN: usize = 4096;
/// Domain byte cap (a DNS name is at most 253 bytes).
const MAX_DOMAIN_LEN: usize = 253;
/// Callback URL byte cap.
const MAX_CALLBACK_LEN: usize = 2048;

/// The nostr event kind of a signed login challenge (NIP-42 client auth).
pub const LOGIN_EVENT_KIND: u16 = 22242;

/// A validated login request: the one-time challenge nonce, the requesting
/// domain the user approves, and the HTTPS callback the signed event is
/// POSTed to. Only constructed by [`parse`], so holding one means every field
/// already passed validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginUri {
	/// The one-time challenge nonce, exactly 64 hex chars.
	pub challenge: String,
	/// The requesting domain, shown to the user for approval.
	pub domain: String,
	/// The callback URL the signed event is delivered to: `https://...`, or
	/// `http://localhost[:port]...` for development.
	pub callback: String,
}

/// True when `scanned` carries a Goblin scheme with the `login` keyword, i.e.
/// it is a login request (valid or not) and must NEVER be fed to the pay
/// path. The dispatcher checks this BEFORE [`super::payuri::is_pay_uri`]; a
/// shaped-but-invalid login URI is then dropped entirely (no modal, no send).
pub fn is_login_shaped(scanned: &str) -> bool {
	let text = scanned.trim();
	if text.len() > MAX_URI_LEN {
		return false;
	}
	match strip_pay_scheme(text) {
		Some(rest) => {
			let head = rest.split('?').next().unwrap_or("");
			head.eq_ignore_ascii_case("login")
		}
		None => false,
	}
}

/// Parse a login URI. `Some` only when EVERY field validates: `c` is exactly
/// 64 hex chars, `d` is non-empty, and `cb` is `https://` (or
/// `http://localhost[:port]` for dev). Anything else is `None` and the whole
/// request is ignored. Pure, total, no I/O.
pub fn parse(scanned: &str) -> Option<LoginUri> {
	let text = scanned.trim();
	if text.len() > MAX_URI_LEN || text.as_bytes().contains(&0) {
		return None;
	}
	let rest = strip_pay_scheme(text)?;
	let (head, query) = rest.split_once('?')?;
	if !head.eq_ignore_ascii_case("login") {
		return None;
	}
	let mut challenge = None;
	let mut domain = None;
	let mut callback = None;
	for pair in query.split('&') {
		let Some((key, val)) = pair.split_once('=') else {
			continue; // valueless / malformed segment, ignore
		};
		match key {
			// First occurrence wins, matching the pay-URI convention, so a
			// second `cb=` can never override a validated one.
			"c" if challenge.is_none() => challenge = Some(val),
			"d" if domain.is_none() => domain = Some(val),
			"cb" if callback.is_none() => callback = Some(val),
			// Unknown params are ignored for forward-compat.
			_ => {}
		}
	}
	let challenge = validate_challenge(challenge?)?;
	let domain = validate_domain(domain?)?;
	let callback = validate_callback(callback?)?;
	Some(LoginUri {
		challenge,
		domain,
		callback,
	})
}

/// The challenge nonce must be exactly 64 hex chars (a 32-byte value): wrong
/// length or any non-hex char rejects the whole URI.
fn validate_challenge(raw: &str) -> Option<String> {
	let decoded = String::from_utf8_lossy(&percent_decode(raw)).into_owned();
	if decoded.len() == 64 && decoded.chars().all(|c| c.is_ascii_hexdigit()) {
		Some(decoded)
	} else {
		None
	}
}

/// The domain must be non-empty, printable ASCII without spaces, and within
/// DNS length bounds. It is DISPLAY data (the user approves it by eye) and a
/// tag value, never a route, so a shape check is enough.
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
/// one development exception. Everything else (plain http, ftp, garbage)
/// rejects the whole URI so a signed event can never be posted somewhere
/// unexpected in the clear.
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

/// Strip a case-insensitive ASCII prefix.
fn strip_prefix_ignore_case<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
	let n = prefix.len();
	match s.get(..n) {
		Some(head) if head.eq_ignore_ascii_case(prefix) => Some(&s[n..]),
		_ => None,
	}
}

/// True when the URL remainder after `http://` names exactly `localhost`,
/// optionally with a `:port` (a valid non-zero u16), followed by nothing or a
/// `/ ? #` delimiter. `localhost.evil.com` and friends do NOT pass.
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

/// Build and sign the one-time login event with the CHOSEN identity's keys:
/// kind 22242, empty content, tags exactly
/// `[["challenge", challenge], ["domain", domain]]`, `created_at` now. The
/// signature proves control of the key for this one nonce; nothing secret
/// leaves the wallet.
pub fn build_login_event(keys: &Keys, challenge: &str, domain: &str) -> Result<Event, String> {
	EventBuilder::new(Kind::Custom(LOGIN_EVENT_KIND), "")
		.tags(vec![
			Tag::custom(TagKind::custom("challenge"), [challenge.to_string()]),
			Tag::custom(TagKind::custom("domain"), [domain.to_string()]),
		])
		.sign_with_keys(keys)
		.map_err(|e| e.to_string())
}

/// POST the signed login event to the callback as `{"event": <event-json>}`.
/// Goes through the app's shared [`crate::http::HttpClient`], so it follows
/// the exact same transport policy (proxy settings included) as every other
/// clearnet call. The caller wraps this in its own timeout.
pub async fn post_login_event(callback: &str, event: &Event) -> Result<(), String> {
	let body = serde_json::json!({ "event": event }).to_string();
	let req = hyper::Request::builder()
		.method(hyper::Method::POST)
		.uri(callback)
		.header("Content-Type", "application/json")
		.header("User-Agent", "goblin-wallet")
		.body(http_body_util::Full::new(bytes::Bytes::from(body)))
		.map_err(|e| e.to_string())?;
	let resp = crate::http::HttpClient::send(req)
		.await
		.map_err(|e| e.to_string())?;
	let status = resp.status().as_u16();
	if (200..300).contains(&status) {
		Ok(())
	} else {
		Err(format!("callback returned status {status}"))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A well-formed 64-hex challenge nonce.
	const C: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
	/// A real, valid bech32 npub (the Goblin news key), for the pay-vs-login
	/// dispatch tests.
	const NPUB: &str = "npub15gsytqvs5c78u83yv2agl4twjkk6qgem7gtwe2agu7s90tkelxys0xxely";

	fn valid_uri(scheme: &str) -> String {
		format!("{scheme}login?c={C}&d=magick.market&cb=https://magick.market/api/login")
	}

	#[test]
	fn valid_goblin_and_nostr_login_accepted() {
		for scheme in ["goblin:", "nostr:"] {
			let out = parse(&valid_uri(scheme)).expect("valid login URI must parse");
			assert_eq!(out.challenge, C);
			assert_eq!(out.domain, "magick.market");
			assert_eq!(out.callback, "https://magick.market/api/login");
		}
	}

	#[test]
	fn scheme_and_keyword_case_insensitive() {
		let uri = format!("GOBLIN:LOGIN?c={C}&d=magick.market&cb=https://magick.market/cb");
		let out = parse(&uri).expect("uppercase scheme/keyword must parse");
		assert_eq!(out.domain, "magick.market");
		assert!(is_login_shaped(&uri));
	}

	#[test]
	fn challenge_must_be_exactly_64_hex() {
		// Wrong length: 63, 65, empty.
		for bad in [&C[..63], &format!("{C}0")[..], ""] {
			let uri = format!("goblin:login?c={bad}&d=magick.market&cb=https://m.m/cb");
			assert_eq!(parse(&uri), None, "expected c={bad:?} to be rejected");
		}
		// Right length, non-hex chars.
		let bad = format!("{}zz", &C[..62]);
		let uri = format!("goblin:login?c={bad}&d=magick.market&cb=https://m.m/cb");
		assert_eq!(parse(&uri), None, "non-hex challenge must be rejected");
	}

	#[test]
	fn empty_domain_rejected() {
		let uri = format!("goblin:login?c={C}&d=&cb=https://magick.market/cb");
		assert_eq!(parse(&uri), None);
		// Whitespace-only after decode is also empty.
		let uri = format!("goblin:login?c={C}&d=%20%20&cb=https://magick.market/cb");
		assert_eq!(parse(&uri), None);
	}

	#[test]
	fn missing_params_rejected() {
		assert_eq!(
			parse(&format!("goblin:login?d=m.m&cb=https://m.m/cb")),
			None
		);
		assert_eq!(
			parse(&format!("goblin:login?c={C}&cb=https://m.m/cb")),
			None
		);
		assert_eq!(parse(&format!("goblin:login?c={C}&d=m.m")), None);
		assert_eq!(parse("goblin:login"), None);
		assert_eq!(parse("goblin:login?"), None);
	}

	#[test]
	fn non_localhost_http_callback_rejected() {
		for bad in [
			"http://magick.market/cb",
			"http://localhost.evil.com/cb",
			"http://evillocalhost/cb",
			"http://localhost:0/cb",
			"http://localhost:99999/cb",
			"http://localhost:12a/cb",
		] {
			let uri = format!("goblin:login?c={C}&d=magick.market&cb={bad}");
			assert_eq!(parse(&uri), None, "expected cb={bad:?} to be rejected");
		}
	}

	#[test]
	fn ftp_and_garbage_callback_rejected() {
		for bad in [
			"ftp://magick.market/cb",
			"javascript:alert(1)",
			"m.m/cb",
			"",
		] {
			let uri = format!("goblin:login?c={C}&d=magick.market&cb={bad}");
			assert_eq!(parse(&uri), None, "expected cb={bad:?} to be rejected");
		}
	}

	#[test]
	fn localhost_callback_accepted_for_dev() {
		for ok in [
			"http://localhost:3000/api/login",
			"http://localhost/cb",
			"http://localhost:3000",
		] {
			let uri = format!("goblin:login?c={C}&d=magick.market&cb={ok}");
			let out = parse(&uri).unwrap_or_else(|| panic!("expected cb={ok:?} accepted"));
			assert_eq!(out.callback, ok);
		}
	}

	#[test]
	fn percent_encoded_callback_decoded() {
		let cb = "https%3A%2F%2Fmagick.market%2Fapi%2Flogin%3Fs%3D1";
		let uri = format!("goblin:login?c={C}&d=magick.market&cb={cb}");
		let out = parse(&uri).expect("encoded cb must parse");
		assert_eq!(out.callback, "https://magick.market/api/login?s=1");
	}

	#[test]
	fn duplicate_params_first_wins() {
		let uri = format!(
			"goblin:login?c={C}&c={}&d=magick.market&d=evil.com&cb=https://magick.market/cb&cb=https://evil.com/cb",
			"f".repeat(64)
		);
		let out = parse(&uri).expect("must parse");
		assert_eq!(out.challenge, C);
		assert_eq!(out.domain, "magick.market");
		assert_eq!(out.callback, "https://magick.market/cb");
	}

	#[test]
	fn pay_uri_is_not_login_and_login_is_not_pay() {
		// Dispatch contract: the router checks is_login_shaped() FIRST, then
		// falls through to the pay path. A pay URI must never look
		// login-shaped, and a login URI must never be classified as anything
		// but login (valid or dropped).
		let pay = format!("goblin:{NPUB}?amount=1.5");
		assert!(!is_login_shaped(&pay));
		assert_eq!(parse(&pay), None);
		// The pay parser still handles it exactly as before.
		let parsed = crate::nostr::payuri::parse(&pay);
		assert_eq!(parsed.recipient, NPUB);
		assert_eq!(parsed.amount.as_deref(), Some("1.5"));

		// A login URI IS login-shaped (so the router grabs it before the pay
		// path can see it), whether or not its params validate.
		let login = valid_uri("goblin:");
		assert!(is_login_shaped(&login));
		assert!(parse(&login).is_some());
		let broken = "goblin:login?c=nothex&d=m.m&cb=https://m.m/cb";
		assert!(is_login_shaped(broken));
		assert_eq!(parse(broken), None);
		// Non-goblin schemes and bare payloads are not login-shaped at all.
		assert!(!is_login_shaped("bitcoin:login?c=x"));
		assert!(!is_login_shaped("login?c=x"));
		assert!(!is_login_shaped(""));
	}

	#[test]
	fn whitespace_trimmed_and_oversize_rejected() {
		let uri = format!("  {}  ", valid_uri("nostr:"));
		assert!(parse(&uri).is_some());
		let huge = format!(
			"goblin:login?c={C}&d=magick.market&cb=https://m.m/{}",
			"a".repeat(5000)
		);
		assert_eq!(parse(&huge), None);
		assert!(!is_login_shaped(&huge));
	}

	#[test]
	fn login_event_signed_by_the_chosen_identity() {
		// Two held identities; the user picks the NON-active one. The event
		// must verify against exactly that key.
		let active = Keys::generate();
		let chosen = Keys::generate();
		let before = nostr_sdk::Timestamp::now().as_u64();
		let event = build_login_event(&chosen, C, "magick.market").expect("sign");
		let after = nostr_sdk::Timestamp::now().as_u64();

		assert_eq!(event.kind.as_u16(), LOGIN_EVENT_KIND);
		assert_eq!(event.content, "");
		let tags: Vec<Vec<String>> = event.tags.iter().map(|t| t.as_slice().to_vec()).collect();
		assert_eq!(
			tags,
			vec![
				vec!["challenge".to_string(), C.to_string()],
				vec!["domain".to_string(), "magick.market".to_string()],
			]
		);
		let ts = event.created_at.as_u64();
		assert!(ts >= before && ts <= after, "created_at must be now");
		assert!(event.verify().is_ok(), "signature must verify");
		assert_eq!(event.pubkey, chosen.public_key());
		assert_ne!(event.pubkey, active.public_key());
	}
}
