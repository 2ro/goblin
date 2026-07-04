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

//! NIP-05 username resolution/verification and goblin.st registration,
//! all HTTP routed through the Nym mixnet (the in-process smolmix tunnel). Nothing
//! here touches clearnet.

use base64::Engine;
use nostr_sdk::{EventBuilder, JsonUtil, Keys, Kind, PublicKey, Tag, TagKind};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::nostr::relays::HOME_NIP05_DOMAIN;
use crate::tor;
use parking_lot::RwLock;

/// The active name-authority "home" domain, mirrored here from the wallet config
/// once per frame so resolution + display (some on worker threads) can read it
/// without threading the config through every call site. `None` = the default
/// (goblin.st). Federation: set this to another authority and bare names resolve
/// there and own-domain names display without a domain suffix.
static HOME_DOMAIN: RwLock<Option<String>> = RwLock::new(None);

/// Mirror the configured name authority's host (e.g. `goblin.st`). Empty resets
/// to the default.
pub fn set_home_domain(domain: &str) {
	*HOME_DOMAIN.write() = if domain.trim().is_empty() {
		None
	} else {
		Some(domain.trim().to_lowercase())
	};
}

/// The current name-authority home domain (configured or the goblin.st default).
pub fn home_domain() -> String {
	HOME_DOMAIN
		.read()
		.clone()
		.unwrap_or_else(|| HOME_NIP05_DOMAIN.to_string())
}

/// Result of resolving a NIP-05 identifier.
#[derive(Debug, Clone)]
pub struct Nip05Resolution {
	pub pubkey: PublicKey,
	pub relays: Vec<String>,
}

/// Parse `user@domain` into (name, domain). A bare `@user` or `user`
/// resolves against the home domain (goblin.st).
pub fn split_identifier(input: &str) -> Option<(String, String)> {
	let trimmed = input.trim().trim_start_matches('@');
	if trimmed.is_empty() {
		return None;
	}
	match trimmed.split_once('@') {
		Some((name, domain)) if !name.is_empty() => {
			let domain = domain.to_lowercase();
			if !is_valid_hostname(&domain) {
				return None;
			}
			Some((name.to_lowercase(), domain))
		}
		Some(_) => None,
		None => Some((trimmed.to_lowercase(), home_domain())),
	}
}

/// A bare DNS hostname: dotted ASCII labels only — no path, query, port,
/// userinfo or whitespace. Stops a `user@domain` from smuggling an
/// attacker-chosen path/host into the `/.well-known/nostr.json` URL.
fn is_valid_hostname(d: &str) -> bool {
	if d.len() > 253 || !d.contains('.') || d.contains("..") {
		return false;
	}
	d.split('.').all(|label| {
		!label.is_empty()
			&& label.len() <= 63
			&& !label.starts_with('-')
			&& !label.ends_with('-')
			&& label
				.bytes()
				.all(|b| b.is_ascii_alphanumeric() || b == b'-')
	})
}

/// Resolve a NIP-05 identifier (user@domain) to a pubkey + relay hints.
pub async fn resolve(name: &str, domain: &str) -> Option<Nip05Resolution> {
	let url = format!(
		"https://{}/.well-known/nostr.json?name={}",
		domain,
		urlencode(name)
	);
	let body = tor::http_request("GET", url, None, vec![]).await?;
	parse_well_known(&body, name)
}

/// Reverse lookup against an authority: the active `@name` a pubkey holds, if
/// any. Authoritative and single-request — unlike fetching the peer's kind-0 off
/// a relay and verifying the NIP-05 it advertises, this needs no profile fetch,
/// so a contact's name resolves even when their profile can't be retrieved.
/// `Some(name)` = server-confirmed; `None` = the key has no name on this
/// authority OR the server was unreachable (the two are indistinguishable here,
/// so callers must NOT treat `None` as "released" — fall back to the kind-0 +
/// verify path, which can tell a definitive miss from a network blip).
pub async fn name_by_pubkey(domain: &str, pubkey_hex: &str) -> Option<String> {
	let url = format!(
		"https://{}/api/v1/by-pubkey/{}",
		domain,
		urlencode(pubkey_hex)
	);
	let body = tor::http_request("GET", url, None, vec![]).await?;
	let doc: Value = serde_json::from_str(&body).ok()?;
	doc.get("name")
		.and_then(|v| v.as_str())
		.filter(|s| !s.is_empty())
		.map(|s| s.to_string())
}

/// Verify that a pubkey matches its claimed NIP-05 identifier.
pub async fn verify(pubkey: &PublicKey, name: &str, domain: &str) -> bool {
	match resolve(name, domain).await {
		Some(res) => res.pubkey == *pubkey,
		None => false,
	}
}

/// Outcome of re-checking whether a name still belongs to a key — distinguishes
/// a definitive "no longer ours" from a transient network failure, so a cached
/// name is only cleared when the server actually says it's gone/reassigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Nip05Check {
	/// Server reachable; the name maps to this key.
	Verified,
	/// Server reachable and answered, but the name is absent or maps to a
	/// DIFFERENT key (released, or reassigned to someone else).
	Mismatch,
	/// Couldn't reach/parse the server — unknown; keep what we have.
	Unreachable,
}

/// Freshness-aware NIP-05 check (see [`Nip05Check`]). Only returns `Mismatch`
/// when the server gives a well-formed answer that doesn't include this key —
/// any network error or non-well-known response is `Unreachable`.
pub async fn check(pubkey: &PublicKey, name: &str, domain: &str) -> Nip05Check {
	let url = format!(
		"https://{}/.well-known/nostr.json?name={}",
		domain,
		urlencode(name)
	);
	let Some(body) = tor::http_request("GET", url, None, vec![]).await else {
		return Nip05Check::Unreachable;
	};
	check_body(&body, pubkey, name)
}

/// Decide a [`Nip05Check`] from a fetched well-known body (split out for tests).
fn check_body(body: &str, pubkey: &PublicKey, name: &str) -> Nip05Check {
	// A reachable server that returns non-JSON, or a doc without a `names` map,
	// is treated as Unreachable — never clear a good name on a server hiccup.
	let Ok(doc) = serde_json::from_str::<Value>(body) else {
		return Nip05Check::Unreachable;
	};
	let Some(names) = doc.get("names").and_then(|n| n.as_object()) else {
		return Nip05Check::Unreachable;
	};
	match names.get(name).and_then(|v| v.as_str()) {
		Some(hex) if PublicKey::from_hex(hex).ok().as_ref() == Some(pubkey) => Nip05Check::Verified,
		// Name absent, or present but a different key → definitively not ours.
		_ => Nip05Check::Mismatch,
	}
}

/// Parse a .well-known/nostr.json document for a specific name.
pub fn parse_well_known(body: &str, name: &str) -> Option<Nip05Resolution> {
	let doc: Value = serde_json::from_str(body).ok()?;
	let pk_hex = doc.get("names")?.get(name)?.as_str()?;
	let pubkey = PublicKey::from_hex(pk_hex).ok()?;
	let relays = doc
		.get("relays")
		.and_then(|r| r.get(pk_hex))
		.and_then(|r| r.as_array())
		.map(|arr| {
			arr.iter()
				.filter_map(|v| v.as_str().map(|s| s.to_string()))
				.collect()
		})
		.unwrap_or_default();
	Some(Nip05Resolution { pubkey, relays })
}

/// Availability result from the registration server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Availability {
	Available,
	Taken,
	Reserved,
	Invalid,
	Quarantined,
	Unknown,
}

/// Check name availability against the identity server.
pub async fn check_availability(server: &str, name: &str) -> Availability {
	let url = format!(
		"{}/api/v1/name/{}",
		server.trim_end_matches('/'),
		urlencode(name)
	);
	let body = match tor::http_request("GET", url, None, vec![]).await {
		Some(b) => b,
		None => return Availability::Unknown,
	};
	let Ok(doc) = serde_json::from_str::<Value>(&body) else {
		return Availability::Unknown;
	};
	if doc.get("available").and_then(|v| v.as_bool()) == Some(true) {
		return Availability::Available;
	}
	match doc.get("reason").and_then(|v| v.as_str()) {
		Some("taken") => Availability::Taken,
		Some("reserved") => Availability::Reserved,
		Some("invalid") => Availability::Invalid,
		Some("quarantined") => Availability::Quarantined,
		_ => Availability::Unknown,
	}
}

/// Build a NIP-98 Authorization header value for a request.
fn nip98_auth(keys: &Keys, url: &str, method: &str, body: Option<&[u8]>) -> Option<String> {
	let mut tags = vec![
		Tag::custom(TagKind::custom("u"), [url.to_string()]),
		Tag::custom(TagKind::custom("method"), [method.to_string()]),
	];
	if let Some(body) = body {
		let hash = hex::encode(Sha256::digest(body));
		tags.push(Tag::custom(TagKind::custom("payload"), [hash]));
	}
	let event = EventBuilder::new(Kind::HttpAuth, "")
		.tags(tags)
		.sign_with_keys(keys)
		.ok()?;
	let encoded = base64::engine::general_purpose::STANDARD.encode(event.as_json());
	Some(format!("Nostr {}", encoded))
}

/// Registration outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterResult {
	/// Registered (or already owned): full nip05 identifier.
	Ok(String),
	/// Name conflict (taken/quarantined/pubkey already has a name).
	Conflict(String),
	/// Request rejected (invalid/reserved/unauthorized).
	Rejected(String),
	/// Network failure.
	Network,
}

/// Register `name` for our keys at the identity server (NIP-98 authed).
pub async fn register(server: &str, name: &str, keys: &Keys) -> RegisterResult {
	let server = server.trim_end_matches('/');
	let url = format!("{}/api/v1/register", server);
	let body = serde_json::json!({
		"name": name.to_lowercase(),
		"pubkey": keys.public_key().to_hex(),
	})
	.to_string();
	let Some(auth) = nip98_auth(keys, &url, "POST", Some(body.as_bytes())) else {
		return RegisterResult::Rejected("auth event build failed".into());
	};
	let headers = vec![
		("Authorization".to_string(), auth),
		("Content-Type".to_string(), "application/json".to_string()),
	];
	let Some(resp) = tor::http_request("POST", url, Some(body), headers).await else {
		return RegisterResult::Network;
	};
	let Ok(doc) = serde_json::from_str::<Value>(&resp) else {
		return RegisterResult::Rejected(format!("bad response: {}", resp));
	};
	if let Some(nip05) = doc.get("nip05").and_then(|v| v.as_str()) {
		return RegisterResult::Ok(nip05.to_string());
	}
	let err = doc
		.get("error")
		.and_then(|v| v.as_str())
		.unwrap_or("unknown error")
		.to_string();
	if err.contains("taken") || err.contains("quarantined") || err.contains("already has") {
		RegisterResult::Conflict(err)
	} else {
		RegisterResult::Rejected(err)
	}
}

/// Release a registered name (NIP-98 authed by the owner).
pub async fn unregister(server: &str, name: &str, keys: &Keys) -> Result<(), String> {
	let server = server.trim_end_matches('/');
	let url = format!("{}/api/v1/register/{}", server, urlencode(name));
	let Some(auth) = nip98_auth(keys, &url, "DELETE", None) else {
		return Err("couldn't sign the request".to_string());
	};
	let headers = vec![("Authorization".to_string(), auth)];
	match tor::http_request("DELETE", url, None, headers).await {
		Some(resp) if resp.contains("\"released\":true") => Ok(()),
		Some(resp) => Err(serde_json::from_str::<serde_json::Value>(&resp)
			.ok()
			.and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
			.unwrap_or_else(|| "server refused the release".to_string())),
		None => Err("network unreachable".to_string()),
	}
}

/// Public profile probe: `None` = network failure, `Some(None)` = name has
/// no avatar (or no such name), `Some(Some(hash))` = avatar content hash.
pub async fn fetch_profile(server: &str, name: &str) -> Option<Option<String>> {
	let server = server.trim_end_matches('/');
	let url = format!("{}/api/v1/profile/{}", server, urlencode(name));
	let (code, raw) = tor::http_request_bytes("GET", url, None, vec![]).await?;
	if code == 404 {
		return Some(None);
	}
	if code != 200 {
		return None;
	}
	let v: serde_json::Value = serde_json::from_slice(&raw).ok()?;
	Some(v.get("avatar").and_then(|h| h.as_str()).map(String::from))
}

/// Download a processed avatar by content hash. Verifies size and PNG
/// magic before returning — a misbehaving server can't feed the UI junk.
pub async fn fetch_avatar(server: &str, hash: &str) -> Option<Vec<u8>> {
	if hash.len() != 64 || !hash.bytes().all(|c| c.is_ascii_hexdigit()) {
		return None;
	}
	let server = server.trim_end_matches('/');
	let url = format!("{}/api/v1/avatar/{}.png", server, hash);
	let (code, raw) = tor::http_request_bytes("GET", url, None, vec![]).await?;
	if code != 200 || raw.len() > 1_048_576 || !raw.starts_with(&[0x89, b'P', b'N', b'G']) {
		return None;
	}
	Some(raw)
}

/// Minimal percent-encoding for name path/query segments.
fn urlencode(s: &str) -> String {
	s.chars()
		.flat_map(|c| {
			if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
				vec![c]
			} else {
				format!("%{:02X}", c as u32).chars().collect()
			}
		})
		.collect()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn splits_identifiers() {
		assert_eq!(
			split_identifier("@ada"),
			Some(("ada".to_string(), "goblin.st".to_string()))
		);
		assert_eq!(
			split_identifier("ada"),
			Some(("ada".to_string(), "goblin.st".to_string()))
		);
		assert_eq!(
			split_identifier("Ada@Example.COM"),
			Some(("ada".to_string(), "example.com".to_string()))
		);
		assert_eq!(split_identifier("ada@"), None);
		assert_eq!(split_identifier(""), None);
		// Reject anything that isn't a bare hostname (SSRF / path smuggling).
		assert_eq!(split_identifier("a@evil.tld/.well-known/x?u="), None);
		assert_eq!(split_identifier("a@1.2.3.4:8080"), None);
		assert_eq!(split_identifier("a@nodot"), None);
	}

	#[test]
	fn parses_well_known() {
		let body = r#"{
			"names": {"ada": "91cf9dbbea5e6511fd2bbb190b112055ee4131c5d2bbb9faedf3ee8cbeac0d05"},
			"relays": {"91cf9dbbea5e6511fd2bbb190b112055ee4131c5d2bbb9faedf3ee8cbeac0d05": ["wss://relay.goblin.st"]}
		}"#;
		let res = parse_well_known(body, "ada").unwrap();
		assert_eq!(res.relays, vec!["wss://relay.goblin.st".to_string()]);
		assert!(parse_well_known(body, "bob").is_none());
		assert!(parse_well_known("not json", "ada").is_none());
	}

	#[test]
	fn check_body_classifies() {
		let ada_hex = "91cf9dbbea5e6511fd2bbb190b112055ee4131c5d2bbb9faedf3ee8cbeac0d05";
		let ada = PublicKey::from_hex(ada_hex).unwrap();
		let other =
			PublicKey::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
				.unwrap();
		let body = format!(r#"{{"names":{{"ada":"{ada_hex}"}},"relays":{{}}}}"#);

		// Name maps to this key → Verified.
		assert_eq!(check_body(&body, &ada, "ada"), Nip05Check::Verified);
		// Name present but a DIFFERENT key (reassigned) → Mismatch.
		assert_eq!(check_body(&body, &other, "ada"), Nip05Check::Mismatch);
		// Name absent from a valid doc (released) → Mismatch.
		assert_eq!(check_body(&body, &ada, "bob"), Nip05Check::Mismatch);
		// Empty names map (the exact "released" shape) → Mismatch.
		assert_eq!(
			check_body(r#"{"names":{},"relays":{}}"#, &ada, "testuser"),
			Nip05Check::Mismatch
		);
		// Non-JSON / server error → Unreachable (never clears a good name).
		assert_eq!(
			check_body("503 Service Unavailable", &ada, "ada"),
			Nip05Check::Unreachable
		);
		// Valid JSON but no `names` map (unexpected response) → Unreachable.
		assert_eq!(
			check_body(r#"{"error":"oops"}"#, &ada, "ada"),
			Nip05Check::Unreachable
		);
	}
}
