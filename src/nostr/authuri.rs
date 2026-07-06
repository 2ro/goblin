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

//! "Authorize with Goblin" request parser and one-shot event signer.
//!
//! A site (magick.market) asks the wallet to sign exactly one Nostr event by
//! handing it a template over either the `goblin:` deep-link scheme or the
//! equivalent `nostr:` QR payload:
//!
//! ```text
//! goblin:authorize?e=<base64url template JSON>&d=<domain>&cb=<https callback>&c=<64-hex nonce>
//! nostr:authorize?...   (same, for QR payloads, mirroring login)
//! ```
//!
//! On approval the wallet composes the event itself, filling `pubkey` (the
//! CHOSEN identity), `created_at` (now), `id`, and `sig`; the requester only
//! ever supplies `kind`, `content`, and `tags`. The signed event is POSTed to
//! the callback as `{"c": <nonce>, "d": <domain>, "event": <event-json>}`. One
//! approval signs one event and hands it over: no key is shared, no session is
//! created, and nothing is published by the wallet.
//!
//! Parsing is PURE and fail-closed over UNTRUSTED input, mirroring
//! [`crate::nostr::loginuri`] and [`crate::nostr::payuri`] exactly (same scheme
//! handling, same percent-decoding, first occurrence of a duplicate param
//! wins, unknown params ignored). ANY single validation failure rejects the
//! whole URI: no modal, no partial handling, no fallthrough to the pay path.
//! The kind allowlist and the strict three-key template shape are enforced here
//! at parse time, before any modal can open, so the wallet never even considers
//! signing something outside the v1 policy.

use super::payuri::{percent_decode, strip_pay_scheme};
use base64::Engine;
use nostr_sdk::{Event, EventBuilder, Keys, Kind, Tag};

/// Total payload byte cap, same bar as the pay-URI and login-URI parsers.
const MAX_URI_LEN: usize = 4096;
/// Domain byte cap (a DNS name is at most 253 bytes).
const MAX_DOMAIN_LEN: usize = 253;
/// Callback URL byte cap.
const MAX_CALLBACK_LEN: usize = 2048;
/// Decoded template-JSON byte cap: keeps the whole URI comfortably inside
/// practical QR capacity, and bounds the untrusted JSON we parse.
const MAX_TEMPLATE_LEN: usize = 2048;

/// The v1 kind allowlist. Everything else, including kind 22242 (which routes
/// only through the login flow), is rejected at parse time. See the spec,
/// section 3, for the reasoning behind each exclusion.
const ALLOWED_KINDS: [u16; 4] = [1, 6, 7, 30023];

/// The requester-supplied event template: exactly the three fields a site is
/// allowed to choose. `pubkey`, `created_at`, `id`, and `sig` are NOT here on
/// purpose, the wallet fills those itself so no confusion is possible about who
/// owns which field. Only constructed by [`parse`], so holding one means the
/// kind is on the allowlist and every field already validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Template {
	/// The event kind, guaranteed on [`ALLOWED_KINDS`].
	pub kind: u16,
	/// The event content, verbatim from the requester.
	pub content: String,
	/// The event tags, each an array of strings, verbatim from the requester.
	pub tags: Vec<Vec<String>>,
}

impl Template {
	/// The value of the first tag whose name (position 0) equals `name` and
	/// which carries at least a value at position 1. Used by the modal to pull
	/// the key tags (`e`, `p`, `title`) it summarizes. Pure, no allocation.
	pub fn first_tag_value(&self, name: &str) -> Option<&str> {
		self.tags
			.iter()
			.find(|t| t.len() >= 2 && t.first().map(|k| k == name).unwrap_or(false))
			.map(|t| t[1].as_str())
	}
}

/// A validated authorize request: the one-time nonce, the requesting domain the
/// user approves, the HTTPS callback the signed event is delivered to, and the
/// strictly-shaped event template. Only constructed by [`parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizeUri {
	/// The one-time request nonce, exactly 64 hex chars.
	pub challenge: String,
	/// The requesting domain, shown to the user for approval.
	pub domain: String,
	/// The callback URL the signed event is delivered to: `https://...`, or
	/// `http://localhost[:port]...` for development.
	pub callback: String,
	/// The event template the site wants signed.
	pub template: Template,
}

/// True when `scanned` carries a Goblin scheme with the `authorize` keyword,
/// i.e. it is an authorize request (valid or not) and must NEVER be fed to the
/// pay path. The dispatcher checks this BEFORE [`super::payuri::is_pay_uri`]
/// (and after [`super::loginuri::is_login_shaped`]); a shaped-but-invalid
/// authorize URI is then dropped entirely (no modal, no send).
pub fn is_authorize_shaped(scanned: &str) -> bool {
	let text = scanned.trim();
	if text.len() > MAX_URI_LEN {
		return false;
	}
	match strip_pay_scheme(text) {
		Some(rest) => {
			let head = rest.split('?').next().unwrap_or("");
			head.eq_ignore_ascii_case("authorize")
		}
		None => false,
	}
}

/// Parse an authorize URI. `Some` only when EVERY field validates: `c` is
/// exactly 64 hex chars, `d` is a shaped domain, `cb` is an https (or dev
/// localhost) URL bound to `d`, and `e` decodes to a strictly-shaped template
/// whose kind is on the allowlist. Anything else is `None` and the whole
/// request is ignored. Pure, total, no I/O.
pub fn parse(scanned: &str) -> Option<AuthorizeUri> {
	let text = scanned.trim();
	if text.len() > MAX_URI_LEN || text.as_bytes().contains(&0) {
		return None;
	}
	let rest = strip_pay_scheme(text)?;
	let (head, query) = rest.split_once('?')?;
	if !head.eq_ignore_ascii_case("authorize") {
		return None;
	}
	let mut challenge = None;
	let mut domain = None;
	let mut callback = None;
	let mut template = None;
	for pair in query.split('&') {
		let Some((key, val)) = pair.split_once('=') else {
			continue; // valueless / malformed segment, ignore
		};
		match key {
			// First occurrence wins, matching the pay-URI convention, so a
			// second value can never override a validated one.
			"c" if challenge.is_none() => challenge = Some(val),
			"d" if domain.is_none() => domain = Some(val),
			"cb" if callback.is_none() => callback = Some(val),
			"e" if template.is_none() => template = Some(val),
			// Unknown params are ignored for forward-compat.
			_ => {}
		}
	}
	let challenge = validate_challenge(challenge?)?;
	let domain = validate_domain(domain?)?;
	let callback = validate_callback(callback?)?;
	// Domain binding hardens on login: an arbitrary authorized event carries no
	// server-verified `domain` tag, so the wallet closes the gap itself by
	// requiring the callback host to belong to the displayed domain.
	if !domain_bound(&callback, &domain) {
		return None;
	}
	let template = validate_template(template?)?;
	Some(AuthorizeUri {
		challenge,
		domain,
		callback,
		template,
	})
}

/// The challenge nonce must be exactly 64 hex chars (a 32-byte value): wrong
/// length or any non-hex char rejects the whole URI (same rule as login).
fn validate_challenge(raw: &str) -> Option<String> {
	let decoded = String::from_utf8_lossy(&percent_decode(raw)).into_owned();
	if decoded.len() == 64 && decoded.chars().all(|c| c.is_ascii_hexdigit()) {
		Some(decoded)
	} else {
		None
	}
}

/// The domain must be non-empty, printable ASCII without spaces, and within DNS
/// length bounds. It is DISPLAY data (the user approves it by eye) plus one
/// binding check, never a route, so a shape check is enough (same as login).
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
/// unexpected in the clear (same rule as login).
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

/// The new domain binding: the callback host must equal `domain` or be a
/// subdomain of it, matched on a label boundary (case-insensitive, ports
/// ignored). The `http://localhost` dev callback is exempt, since a local dev
/// server legitimately serves any domain's flow. This is what makes the
/// attacker-supplied `d` trustworthy: the signed event can only ever travel to
/// a host that belongs to the domain the user approved.
fn domain_bound(callback: &str, domain: &str) -> bool {
	// The localhost dev callback is validated already and exempt from binding.
	if strip_prefix_ignore_case(callback, "http://").is_some() {
		return true;
	}
	let Some(rest) = strip_prefix_ignore_case(callback, "https://") else {
		return false;
	};
	let authority_end = rest
		.find(|c| c == '/' || c == '?' || c == '#')
		.unwrap_or(rest.len());
	let authority = &rest[..authority_end];
	// Drop any userinfo (`user:pass@`), keep the host:port that follows.
	let hostport = authority.rsplit('@').next().unwrap_or(authority);
	// Drop the port, if any (a bare host has no colon).
	let host = match hostport.rfind(':') {
		Some(i) => &hostport[..i],
		None => hostport,
	};
	let host = host.trim().to_ascii_lowercase();
	let domain = domain.trim().to_ascii_lowercase();
	if host.is_empty() || domain.is_empty() {
		return false;
	}
	host == domain || host.ends_with(&format!(".{domain}"))
}

/// Decode and validate the `e` template. Unpadded base64url only (any `=`
/// padding or non-`A-Za-z0-9-_` char rejects), decoding to a UTF-8 JSON object
/// with EXACTLY the three keys `kind`, `content`, `tags` and nothing else. The
/// kind must be an actual integer on the allowlist (a JSON float like `1.0` or
/// `1e0` is not an integer and rejects); content a string; tags an array of
/// arrays of strings. A `delegation` tag is rejected outright (defense in depth,
/// even though delegation tokens are unreachable here). Any deviation rejects.
fn validate_template(raw: &str) -> Option<Template> {
	// Percent-decode for parity with the other params (base64url never needs
	// encoding, so this is a no-op on well-formed input), then enforce the
	// strict unpadded-base64url charset ourselves.
	let b64 = String::from_utf8(percent_decode(raw)).ok()?;
	let b64 = b64.trim();
	if b64.is_empty()
		|| b64
			.bytes()
			.any(|b| !(b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
	{
		return None;
	}
	let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
		.decode(b64)
		.ok()?;
	if bytes.len() > MAX_TEMPLATE_LEN {
		return None;
	}
	let json = std::str::from_utf8(&bytes).ok()?;
	let value: serde_json::Value = serde_json::from_str(json).ok()?;
	let obj = value.as_object()?;
	// Exactly three keys, and each is one of the allowed three: this rejects any
	// extra field (pubkey, created_at, id, sig, or anything else) and any
	// missing field in one shot.
	if obj.len() != 3 {
		return None;
	}
	for key in obj.keys() {
		if key != "kind" && key != "content" && key != "tags" {
			return None;
		}
	}
	// `as_u64` yields None for a float (`1.0`, `1e0`) or a negative, so a
	// non-integer kind can never sneak through.
	let kind_num = obj.get("kind")?.as_u64()?;
	if kind_num > u16::MAX as u64 {
		return None;
	}
	let kind = kind_num as u16;
	if !ALLOWED_KINDS.contains(&kind) {
		return None;
	}
	let content = obj.get("content")?.as_str()?.to_string();
	let tags_val = obj.get("tags")?.as_array()?;
	let mut tags = Vec::with_capacity(tags_val.len());
	for t in tags_val {
		let arr = t.as_array()?;
		let mut row = Vec::with_capacity(arr.len());
		for item in arr {
			row.push(item.as_str()?.to_string());
		}
		if row.first().map(|k| k == "delegation").unwrap_or(false) {
			return None;
		}
		tags.push(row);
	}
	Some(Template {
		kind,
		content,
		tags,
	})
}

/// Build and sign the authorize event with the CHOSEN identity's keys. The
/// wallet sets `pubkey` (from `keys`), `created_at` (now), `id`, and `sig`; the
/// `kind`, `content`, and `tags` come verbatim from the template. Only the
/// NIP-01 canonical serialization of this composed event is ever signed, so an
/// authorize signature can never be repurposed as any other credential.
pub fn build_authorize_event(keys: &Keys, template: &Template) -> Result<Event, String> {
	let mut tags = Vec::with_capacity(template.tags.len());
	for row in &template.tags {
		tags.push(Tag::parse(row.clone()).map_err(|e| e.to_string())?);
	}
	EventBuilder::new(Kind::from(template.kind), template.content.clone())
		.tags(tags)
		.sign_with_keys(keys)
		.map_err(|e| e.to_string())
}

/// POST the signed authorize event to the callback as
/// `{"c": <nonce>, "d": <domain>, "event": <event-json>}`. Goes through the
/// app's shared [`crate::http::HttpClient`], so it follows the exact same
/// transport policy (proxy settings included) as every other clearnet call.
/// The `c` and `d` fields correlate the delivery to the request the server
/// minted, since the arbitrary event carries no challenge or domain tag of its
/// own. The caller wraps this in its own timeout.
pub async fn post_authorize_event(
	callback: &str,
	challenge: &str,
	domain: &str,
	event: &Event,
) -> Result<(), String> {
	let body = serde_json::json!({ "c": challenge, "d": domain, "event": event }).to_string();
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

// ---------------------------------------------------------------------------
// Rendering helpers (pure, so the modal stays thin and everything is testable
// under `cargo test --lib`).
// ---------------------------------------------------------------------------

/// The plain-language label for a kind. The mapping is the contract the modal
/// renders; keeping it here (with a stable i18n key each) makes it unit-testable
/// without a running GUI. `Unknown` covers every kind off the allowlist: it
/// cannot occur on a parsed [`AuthorizeUri`] in v1, but the helper is total so
/// future allowlist additions degrade to the caution renderer instead of a
/// blind approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KindLabel {
	/// Kind 1: a public post.
	Post,
	/// Kind 6: a repost.
	Repost,
	/// Kind 7: a reaction.
	Reaction,
	/// Kind 30023: a long-form article.
	Article,
	/// Any kind off the allowlist.
	Unknown,
}

impl KindLabel {
	/// The i18n key for this label. `Unknown` carries a `%{n}` placeholder the
	/// caller fills with the raw kind number.
	pub fn key(self) -> &'static str {
		match self {
			KindLabel::Post => "goblin.authorize.kind_post",
			KindLabel::Repost => "goblin.authorize.kind_repost",
			KindLabel::Reaction => "goblin.authorize.kind_reaction",
			KindLabel::Article => "goblin.authorize.kind_article",
			KindLabel::Unknown => "goblin.authorize.kind_unknown",
		}
	}
}

/// Map a kind to its [`KindLabel`]. Total over all `u16`.
pub fn kind_label(kind: u16) -> KindLabel {
	match kind {
		1 => KindLabel::Post,
		6 => KindLabel::Repost,
		7 => KindLabel::Reaction,
		30023 => KindLabel::Article,
		_ => KindLabel::Unknown,
	}
}

/// The content preview: the first 240 CHARS (char-boundary safe), plus the
/// count of remaining chars for the "truncated, N more characters" marker (0
/// when nothing was cut). Never splits a multibyte char.
pub fn content_preview(content: &str) -> (String, usize) {
	const PREVIEW_CHARS: usize = 240;
	let mut chars = content.chars();
	let head: String = chars.by_ref().take(PREVIEW_CHARS).collect();
	let remaining = chars.count();
	(head, remaining)
}

/// Render every control character (C0 range and DEL) and Unicode
/// bidi/format-override character as a visible `\u{XXXX}` escape, never raw, so
/// content can neither reorder nor hide the surrounding UI text. Normal text
/// passes through unchanged. Used on ALL requester-controlled strings (content,
/// tag values, titles) before they reach a label.
pub fn escape_for_display(s: &str) -> String {
	let mut out = String::with_capacity(s.len());
	for c in s.chars() {
		let code = c as u32;
		let dangerous = code < 0x20
			|| code == 0x7f
			|| c == '\u{200E}' // LEFT-TO-RIGHT MARK
			|| c == '\u{200F}' // RIGHT-TO-LEFT MARK
			|| c == '\u{061C}' // ARABIC LETTER MARK
			|| (0x202A..=0x202E).contains(&code) // LRE, RLE, PDF, LRO, RLO
			|| (0x2066..=0x2069).contains(&code); // LRI, RLI, FSI, PDI
		if dangerous {
			out.push_str(&format!("\\u{{{code:04X}}}"));
		} else {
			out.push(c);
		}
	}
	out
}

/// Truncate a long id/pubkey hex to `head…tail` for the tag-summary lines. Short
/// values pass through unchanged. Char-boundary safe (ids are hex, but this
/// stays total for any input).
pub fn truncate_id(id: &str) -> String {
	let chars: Vec<char> = id.chars().collect();
	if chars.len() > 20 {
		let head: String = chars[..10].iter().collect();
		let tail: String = chars[chars.len() - 6..].iter().collect();
		format!("{head}…{tail}")
	} else {
		id.to_string()
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A well-formed 64-hex request nonce.
	const C: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
	/// A real, valid bech32 npub (the Goblin news key), for the pay-vs-authorize
	/// dispatch tests.
	const NPUB: &str = "npub15gsytqvs5c78u83yv2agl4twjkk6qgem7gtwe2agu7s90tkelxys0xxely";

	/// Unpadded-base64url encode a template JSON string.
	fn b64(json: &str) -> String {
		base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json.as_bytes())
	}

	/// A minimal valid template (kind 1, empty tags).
	fn valid_template() -> String {
		b64(r#"{"kind":1,"content":"gm from goblin","tags":[]}"#)
	}

	fn valid_uri(scheme: &str) -> String {
		format!(
			"{scheme}authorize?e={}&d=magick.market&cb=https://magick.market/api/authorize&c={C}",
			valid_template()
		)
	}

	/// Build an authorize URI carrying an arbitrary template JSON, all other
	/// params valid.
	fn uri_with_template(json: &str) -> String {
		format!(
			"goblin:authorize?e={}&d=magick.market&cb=https://magick.market/api/authorize&c={C}",
			b64(json)
		)
	}

	/// Build an authorize URI carrying a raw (already-encoded) `e` value.
	fn uri_with_raw_e(raw_e: &str) -> String {
		format!(
			"goblin:authorize?e={raw_e}&d=magick.market&cb=https://magick.market/api/authorize&c={C}"
		)
	}

	#[test]
	fn valid_goblin_and_nostr_authorize_accepted() {
		for scheme in ["goblin:", "nostr:"] {
			let out = parse(&valid_uri(scheme)).expect("valid authorize URI must parse");
			assert_eq!(out.challenge, C);
			assert_eq!(out.domain, "magick.market");
			assert_eq!(out.callback, "https://magick.market/api/authorize");
			assert_eq!(out.template.kind, 1);
			assert_eq!(out.template.content, "gm from goblin");
			assert!(out.template.tags.is_empty());
		}
	}

	#[test]
	fn scheme_and_keyword_case_insensitive() {
		let uri = format!(
			"GOBLIN:AUTHORIZE?e={}&d=magick.market&cb=https://magick.market/cb&c={C}",
			valid_template()
		);
		let out = parse(&uri).expect("uppercase scheme/keyword must parse");
		assert_eq!(out.domain, "magick.market");
		assert!(is_authorize_shaped(&uri));
	}

	#[test]
	fn is_authorize_shaped_detects_keyword() {
		assert!(is_authorize_shaped(&valid_uri("goblin:")));
		assert!(is_authorize_shaped(&valid_uri("nostr:")));
		// Shaped even when invalid, so the dispatcher grabs it before pay.
		assert!(is_authorize_shaped("goblin:authorize?e=&d=&cb=&c="));
		// Not the authorize keyword.
		assert!(!is_authorize_shaped("goblin:login?c=x"));
		assert!(!is_authorize_shaped("bitcoin:authorize?e=x"));
		assert!(!is_authorize_shaped("authorize?e=x"));
		assert!(!is_authorize_shaped(""));
	}

	#[test]
	fn challenge_must_be_exactly_64_hex() {
		for bad in [&C[..63], &format!("{C}0")[..], ""] {
			let uri = format!(
				"goblin:authorize?e={}&d=magick.market&cb=https://m.m/cb&c={bad}",
				valid_template()
			);
			assert_eq!(parse(&uri), None, "expected c={bad:?} to be rejected");
		}
		let bad = format!("{}zz", &C[..62]);
		let uri = format!(
			"goblin:authorize?e={}&d=magick.market&cb=https://m.m/cb&c={bad}",
			valid_template()
		);
		assert_eq!(parse(&uri), None, "non-hex challenge must be rejected");
	}

	#[test]
	fn empty_domain_rejected() {
		let uri = format!(
			"goblin:authorize?e={}&d=&cb=https://magick.market/cb&c={C}",
			valid_template()
		);
		assert_eq!(parse(&uri), None);
		let uri = format!(
			"goblin:authorize?e={}&d=%20%20&cb=https://magick.market/cb&c={C}",
			valid_template()
		);
		assert_eq!(parse(&uri), None);
	}

	#[test]
	fn missing_params_rejected() {
		// Missing e.
		assert_eq!(
			parse(&format!(
				"goblin:authorize?d=magick.market&cb=https://magick.market/cb&c={C}"
			)),
			None
		);
		// Missing d.
		assert_eq!(
			parse(&format!(
				"goblin:authorize?e={}&cb=https://magick.market/cb&c={C}",
				valid_template()
			)),
			None
		);
		// Missing cb.
		assert_eq!(
			parse(&format!(
				"goblin:authorize?e={}&d=magick.market&c={C}",
				valid_template()
			)),
			None
		);
		// Missing c.
		assert_eq!(
			parse(&format!(
				"goblin:authorize?e={}&d=magick.market&cb=https://magick.market/cb",
				valid_template()
			)),
			None
		);
		assert_eq!(parse("goblin:authorize"), None);
		assert_eq!(parse("goblin:authorize?"), None);
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
			let uri = format!(
				"goblin:authorize?e={}&d=magick.market&cb={bad}&c={C}",
				valid_template()
			);
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
			let uri = format!(
				"goblin:authorize?e={}&d=magick.market&cb={bad}&c={C}",
				valid_template()
			);
			assert_eq!(parse(&uri), None, "expected cb={bad:?} to be rejected");
		}
	}

	#[test]
	fn localhost_callback_accepted_and_exempt_from_binding() {
		// The dev callback is accepted AND exempt from the domain binding (its
		// host is `localhost`, never the displayed domain).
		for ok in [
			"http://localhost:3000/api/authorize",
			"http://localhost/cb",
			"http://localhost:3000",
		] {
			let uri = format!(
				"goblin:authorize?e={}&d=magick.market&cb={ok}&c={C}",
				valid_template()
			);
			let out = parse(&uri).unwrap_or_else(|| panic!("expected cb={ok:?} accepted"));
			assert_eq!(out.callback, ok);
		}
	}

	#[test]
	fn callback_domain_binding_enforced() {
		// Host equals the domain: accepted.
		let ok = format!(
			"goblin:authorize?e={}&d=magick.market&cb=https://magick.market/cb&c={C}",
			valid_template()
		);
		assert!(parse(&ok).is_some());
		// Subdomain of the domain: accepted.
		let ok = format!(
			"goblin:authorize?e={}&d=magick.market&cb=https://shop.magick.market/checkout&c={C}",
			valid_template()
		);
		assert!(parse(&ok).is_some());
		// Port on the callback is ignored for the binding.
		let ok = format!(
			"goblin:authorize?e={}&d=magick.market&cb=https://magick.market:8443/cb&c={C}",
			valid_template()
		);
		assert!(parse(&ok).is_some());
		// Suffix without a label boundary: rejected.
		let bad = format!(
			"goblin:authorize?e={}&d=magick.market&cb=https://evilmagick.market/cb&c={C}",
			valid_template()
		);
		assert_eq!(parse(&bad), None);
		// Unrelated host: rejected.
		let bad = format!(
			"goblin:authorize?e={}&d=magick.market&cb=https://evil.com/cb&c={C}",
			valid_template()
		);
		assert_eq!(parse(&bad), None);
		// Domain as a subdomain of the callback host is NOT a match either.
		let bad = format!(
			"goblin:authorize?e={}&d=shop.magick.market&cb=https://magick.market/cb&c={C}",
			valid_template()
		);
		assert_eq!(parse(&bad), None);
	}

	#[test]
	fn duplicate_params_first_wins() {
		let uri = format!(
			"goblin:authorize?e={}&e={}&d=magick.market&d=evil.com&cb=https://magick.market/cb&cb=https://evil.com/cb&c={C}&c={}",
			valid_template(),
			b64(r#"{"kind":7,"content":"+","tags":[]}"#),
			"f".repeat(64)
		);
		let out = parse(&uri).expect("must parse");
		assert_eq!(out.challenge, C);
		assert_eq!(out.domain, "magick.market");
		assert_eq!(out.callback, "https://magick.market/cb");
		assert_eq!(out.template.kind, 1);
		assert_eq!(out.template.content, "gm from goblin");
	}

	#[test]
	fn whitespace_trimmed_and_oversize_rejected() {
		let uri = format!("  {}  ", valid_uri("nostr:"));
		assert!(parse(&uri).is_some());
		let huge = format!(
			"goblin:authorize?e={}&d=magick.market&cb=https://m.m/{}&c={C}",
			valid_template(),
			"a".repeat(5000)
		);
		assert_eq!(parse(&huge), None);
		assert!(!is_authorize_shaped(&huge));
	}

	#[test]
	fn template_base64_padding_rejected() {
		// Valid base64url but with `=` padding appended: rejected.
		let padded = format!("{}=", valid_template());
		assert_eq!(parse(&uri_with_raw_e(&padded)), None);
	}

	#[test]
	fn template_non_base64url_chars_rejected() {
		// `+`, `/`, `*`, `!` are not in the unpadded-base64url alphabet.
		for bad in ["abc+def", "abc/def", "abc*def", "not base64!"] {
			assert_eq!(
				parse(&uri_with_raw_e(bad)),
				None,
				"expected e={bad:?} rejected"
			);
		}
	}

	#[test]
	fn template_non_utf8_rejected() {
		// Base64url of invalid UTF-8 bytes.
		let e = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0xff, 0xfe, 0xfd]);
		assert_eq!(parse(&uri_with_raw_e(&e)), None);
	}

	#[test]
	fn template_non_json_rejected() {
		assert_eq!(parse(&uri_with_template("not json at all")), None);
		assert_eq!(parse(&uri_with_template("{\"kind\":1,")), None);
		// A JSON array, not an object.
		assert_eq!(parse(&uri_with_template("[1,2,3]")), None);
	}

	#[test]
	fn template_over_2048_decoded_rejected() {
		let big = "a".repeat(2100);
		let json = format!(r#"{{"kind":1,"content":"{big}","tags":[]}}"#);
		assert!(json.len() > MAX_TEMPLATE_LEN);
		assert_eq!(parse(&uri_with_template(&json)), None);
	}

	#[test]
	fn template_field_injection_rejected() {
		// Any extra key rejects, including the wallet-owned fields.
		for extra in [
			r#""pubkey":"deadbeef""#,
			r#""created_at":123"#,
			r#""id":"abc""#,
			r#""sig":"abc""#,
			r#""foo":"bar""#,
		] {
			let json = format!(r#"{{"kind":1,"content":"x","tags":[],{extra}}}"#);
			assert_eq!(
				parse(&uri_with_template(&json)),
				None,
				"extra {extra} must reject"
			);
		}
	}

	#[test]
	fn template_missing_keys_rejected() {
		for json in [
			r#"{"kind":1,"content":"x"}"#,
			r#"{"kind":1,"tags":[]}"#,
			r#"{"content":"x","tags":[]}"#,
			r#"{}"#,
		] {
			assert_eq!(
				parse(&uri_with_template(json)),
				None,
				"missing key in {json} must reject"
			);
		}
	}

	#[test]
	fn template_wrong_types_rejected() {
		// content not a string.
		assert_eq!(
			parse(&uri_with_template(r#"{"kind":1,"content":5,"tags":[]}"#)),
			None
		);
		// tags not an array.
		assert_eq!(
			parse(&uri_with_template(r#"{"kind":1,"content":"x","tags":"e"}"#)),
			None
		);
		// tag element not an array.
		assert_eq!(
			parse(&uri_with_template(
				r#"{"kind":1,"content":"x","tags":["e"]}"#
			)),
			None
		);
		// tag item not a string.
		assert_eq!(
			parse(&uri_with_template(
				r#"{"kind":1,"content":"x","tags":[["e",5]]}"#
			)),
			None
		);
	}

	#[test]
	fn template_non_integer_kind_rejected() {
		for kind in ["1.0", "1e0", "\"1\"", "-1", "null", "true"] {
			let json = format!(r#"{{"kind":{kind},"content":"x","tags":[]}}"#);
			assert_eq!(
				parse(&uri_with_template(&json)),
				None,
				"kind={kind} must reject"
			);
		}
	}

	#[test]
	fn template_delegation_tag_rejected() {
		let json = r#"{"kind":1,"content":"x","tags":[["delegation","pubkey","cond","sig"]]}"#;
		assert_eq!(parse(&uri_with_template(json)), None);
	}

	#[test]
	fn kind_allowlist_enforced() {
		// Allowed.
		for kind in [1u16, 6, 7, 30023] {
			let json = format!(r#"{{"kind":{kind},"content":"x","tags":[]}}"#);
			let out = parse(&uri_with_template(&json))
				.unwrap_or_else(|| panic!("kind {kind} must be accepted"));
			assert_eq!(out.template.kind, kind);
		}
		// Rejected: 22242 (login only), plus a spread of excluded kinds.
		for kind in [0u16, 3, 4, 5, 14, 1059, 10002, 22242, 30000, 40000] {
			let json = format!(r#"{{"kind":{kind},"content":"x","tags":[]}}"#);
			assert_eq!(
				parse(&uri_with_template(&json)),
				None,
				"kind {kind} must be rejected"
			);
		}
	}

	#[test]
	fn pay_uri_is_not_authorize_and_authorize_is_not_pay() {
		// A pay URI must never look authorize-shaped, and the pay parser still
		// handles it exactly as before.
		let pay = format!("goblin:{NPUB}?amount=1.5");
		assert!(!is_authorize_shaped(&pay));
		assert_eq!(parse(&pay), None);
		let parsed = crate::nostr::payuri::parse(&pay);
		assert_eq!(parsed.recipient, NPUB);
		assert_eq!(parsed.amount.as_deref(), Some("1.5"));

		// An authorize URI IS authorize-shaped (so the router grabs it before the
		// pay path), whether or not its params validate.
		let auth = valid_uri("goblin:");
		assert!(is_authorize_shaped(&auth));
		assert!(parse(&auth).is_some());
		let broken = uri_with_raw_e("notbase64!");
		assert!(is_authorize_shaped(&broken));
		assert_eq!(parse(&broken), None);
	}

	#[test]
	fn authorize_event_signed_by_the_chosen_identity() {
		// Two held identities; the user picks the NON-active one. The event must
		// verify against exactly that key, with kind/content/tags verbatim.
		let active = Keys::generate();
		let chosen = Keys::generate();
		let template = Template {
			kind: 1,
			content: "gm".to_string(),
			tags: vec![
				vec!["e".to_string(), "abc123".to_string()],
				vec!["p".to_string(), "def456".to_string()],
			],
		};
		let before = nostr_sdk::Timestamp::now().as_u64();
		let event = build_authorize_event(&chosen, &template).expect("sign");
		let after = nostr_sdk::Timestamp::now().as_u64();

		assert_eq!(event.kind.as_u16(), 1);
		assert_eq!(event.content, "gm");
		let tags: Vec<Vec<String>> = event.tags.iter().map(|t| t.as_slice().to_vec()).collect();
		assert_eq!(tags, template.tags);
		let ts = event.created_at.as_u64();
		assert!(ts >= before && ts <= after, "created_at must be now");
		assert!(event.verify().is_ok(), "signature must verify");
		assert_eq!(event.pubkey, chosen.public_key());
		assert_ne!(event.pubkey, active.public_key());
	}

	#[test]
	fn kind_label_mapping() {
		assert_eq!(kind_label(1), KindLabel::Post);
		assert_eq!(kind_label(6), KindLabel::Repost);
		assert_eq!(kind_label(7), KindLabel::Reaction);
		assert_eq!(kind_label(30023), KindLabel::Article);
		assert_eq!(kind_label(0), KindLabel::Unknown);
		assert_eq!(kind_label(22242), KindLabel::Unknown);
		assert_eq!(kind_label(1).key(), "goblin.authorize.kind_post");
		assert_eq!(kind_label(6).key(), "goblin.authorize.kind_repost");
		assert_eq!(kind_label(7).key(), "goblin.authorize.kind_reaction");
		assert_eq!(kind_label(30023).key(), "goblin.authorize.kind_article");
		assert_eq!(kind_label(9).key(), "goblin.authorize.kind_unknown");
	}

	#[test]
	fn content_preview_truncates_at_240() {
		// Exactly 240 chars: no truncation.
		let exact = "a".repeat(240);
		let (head, rem) = content_preview(&exact);
		assert_eq!(head.chars().count(), 240);
		assert_eq!(rem, 0);
		// 250 chars: 240 shown, 10 remaining.
		let over = "a".repeat(250);
		let (head, rem) = content_preview(&over);
		assert_eq!(head.chars().count(), 240);
		assert_eq!(rem, 10);
		// Multibyte: 245 'é' chars, boundary-safe, 5 remaining.
		let multi = "é".repeat(245);
		let (head, rem) = content_preview(&multi);
		assert_eq!(head.chars().count(), 240);
		assert_eq!(rem, 5);
		// The head must be valid on its own (no split multibyte char).
		assert!(head.chars().all(|c| c == 'é'));
	}

	#[test]
	fn escape_for_display_escapes_control_and_bidi() {
		// A right-to-left override followed by text and a bell.
		let raw = "\u{202E}gnp.exe\u{07}";
		let out = escape_for_display(raw);
		assert!(out.contains("\\u{202E}"), "RLO must be escaped: {out}");
		assert!(out.contains("\\u{0007}"), "bell must be escaped: {out}");
		// The raw dangerous chars must never survive into the output.
		assert!(!out.contains('\u{202E}'));
		assert!(!out.contains('\u{07}'));
		// Every bidi/format char in the spec list is escaped.
		for c in [
			'\u{200E}', '\u{200F}', '\u{061C}', '\u{202A}', '\u{202B}', '\u{202C}', '\u{202D}',
			'\u{202E}', '\u{2066}', '\u{2067}', '\u{2068}', '\u{2069}',
		] {
			let out = escape_for_display(&c.to_string());
			assert!(!out.contains(c), "{:?} must not appear raw", c);
			assert!(out.starts_with("\\u{"), "{:?} must be escaped", c);
		}
		// Ordinary text (incl. multibyte and emoji) passes through unchanged.
		assert_eq!(escape_for_display("héllo 🜁 café"), "héllo 🜁 café");
	}

	#[test]
	fn tag_summary_extraction() {
		let template = Template {
			kind: 30023,
			content: "body".to_string(),
			tags: vec![
				vec![
					"e".to_string(),
					"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
				],
				vec!["p".to_string(), "cafebabecafebabecafebabe".to_string()],
				vec!["title".to_string(), "My Review".to_string()],
			],
		};
		assert_eq!(
			template.first_tag_value("e"),
			Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
		);
		assert_eq!(
			template.first_tag_value("p"),
			Some("cafebabecafebabecafebabe")
		);
		assert_eq!(template.first_tag_value("title"), Some("My Review"));
		assert_eq!(template.first_tag_value("missing"), None);
		// A tag with no value is not returned.
		let no_value = Template {
			kind: 1,
			content: String::new(),
			tags: vec![vec!["e".to_string()]],
		};
		assert_eq!(no_value.first_tag_value("e"), None);
		// Truncation keeps head and tail, drops the middle.
		let id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
		assert_eq!(truncate_id(id), "0123456789…abcdef");
		assert_eq!(truncate_id("short"), "short");
	}
}
