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
//! all HTTP routed through the embedded Tor client.

use base64::Engine;
use nostr_sdk::{EventBuilder, JsonUtil, Keys, Kind, PublicKey, Tag, TagKind};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::nostr::relays::HOME_NIP05_DOMAIN;
use crate::tor::Tor;

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
		None => Some((trimmed.to_lowercase(), HOME_NIP05_DOMAIN.to_string())),
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
	let body = Tor::http_request("GET", url, None, vec![]).await?;
	parse_well_known(&body, name)
}

/// Verify that a pubkey matches its claimed NIP-05 identifier.
pub async fn verify(pubkey: &PublicKey, name: &str, domain: &str) -> bool {
	match resolve(name, domain).await {
		Some(res) => res.pubkey == *pubkey,
		None => false,
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
	let Some(body) = Tor::http_request("GET", url, None, vec![]).await else {
		return Availability::Unknown;
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
	let Some(resp) = Tor::http_request("POST", url, Some(body), headers).await else {
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

/// Atomically move an owned name to a new pubkey (key rotation).
/// Signed by the OLD key; the server enforces ownership and the
/// one-name-per-pubkey rule for the target key.
pub async fn transfer(
	server: &str,
	name: &str,
	old_keys: &Keys,
	new_pubkey_hex: &str,
) -> Result<(), String> {
	let server = server.trim_end_matches('/');
	let url = format!("{}/api/v1/transfer", server);
	let body = serde_json::json!({
		"name": name.to_lowercase(),
		"new_pubkey": new_pubkey_hex,
	})
	.to_string();
	let Some(auth) = nip98_auth(old_keys, &url, "POST", Some(body.as_bytes())) else {
		return Err("auth event build failed".to_string());
	};
	let headers = vec![
		("Authorization".to_string(), auth),
		("Content-Type".to_string(), "application/json".to_string()),
	];
	let Some(resp) = Tor::http_request("POST", url, Some(body), headers).await else {
		return Err("network unavailable".to_string());
	};
	if resp.contains("\"transferred\":true") {
		return Ok(());
	}
	let err = serde_json::from_str::<Value>(&resp)
		.ok()
		.and_then(|d| d.get("error").and_then(|e| e.as_str()).map(String::from))
		.unwrap_or_else(|| {
			if resp.trim().is_empty() {
				"name server does not support transfer yet".to_string()
			} else {
				format!("unexpected response: {}", resp)
			}
		});
	Err(err)
}

/// Release a registered name (NIP-98 authed by the owner).
pub async fn unregister(server: &str, name: &str, keys: &Keys) -> Result<(), String> {
	let server = server.trim_end_matches('/');
	let url = format!("{}/api/v1/register/{}", server, urlencode(name));
	let Some(auth) = nip98_auth(keys, &url, "DELETE", None) else {
		return Err("couldn't sign the request".to_string());
	};
	let headers = vec![("Authorization".to_string(), auth)];
	match Tor::http_request("DELETE", url, None, headers).await {
		Some(resp) if resp.contains("\"released\":true") => Ok(()),
		Some(resp) => Err(serde_json::from_str::<serde_json::Value>(&resp)
			.ok()
			.and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
			.unwrap_or_else(|| "server refused the release".to_string())),
		None => Err("network unreachable".to_string()),
	}
}

/// Upload a processed avatar PNG for an owned name. Returns the content
/// hash on success. NIP-98 payload hashing makes the request replay-proof.
pub async fn upload_avatar(
	server: &str,
	name: &str,
	keys: &Keys,
	png: Vec<u8>,
) -> Result<String, String> {
	let server = server.trim_end_matches('/');
	let url = format!("{}/api/v1/avatar/{}", server, urlencode(name));
	let Some(auth) = nip98_auth(keys, &url, "POST", Some(&png)) else {
		return Err("couldn't sign the request".to_string());
	};
	let headers = vec![
		("Authorization".to_string(), auth),
		(
			"Content-Type".to_string(),
			"application/octet-stream".to_string(),
		),
	];
	match Tor::http_request_bytes("POST", url, Some(png), headers).await {
		Some((201, raw)) => serde_json::from_slice::<serde_json::Value>(&raw)
			.ok()
			.and_then(|v| v.get("avatar").and_then(|h| h.as_str()).map(String::from))
			.ok_or_else(|| "unexpected server response".to_string()),
		Some((429, _)) => Err("Avatar limit reached — try again tomorrow".to_string()),
		Some((413, _)) => Err("Image too large".to_string()),
		Some((422, _)) => Err("That file doesn't look like a usable image".to_string()),
		Some((code, raw)) => Err(serde_json::from_slice::<serde_json::Value>(&raw)
			.ok()
			.and_then(|v| v.get("error").and_then(|e| e.as_str()).map(String::from))
			.unwrap_or_else(|| format!("server error ({code})"))),
		None => Err("network unreachable".to_string()),
	}
}

/// Remove the avatar for an owned name.
pub async fn delete_avatar(server: &str, name: &str, keys: &Keys) -> Result<(), String> {
	let server = server.trim_end_matches('/');
	let url = format!("{}/api/v1/avatar/{}", server, urlencode(name));
	let Some(auth) = nip98_auth(keys, &url, "DELETE", None) else {
		return Err("couldn't sign the request".to_string());
	};
	let headers = vec![("Authorization".to_string(), auth)];
	match Tor::http_request_bytes("DELETE", url, None, headers).await {
		Some((200, _)) => Ok(()),
		Some((code, _)) => Err(format!("server error ({code})")),
		None => Err("network unreachable".to_string()),
	}
}

/// Public profile probe: `None` = network failure, `Some(None)` = name has
/// no avatar (or no such name), `Some(Some(hash))` = avatar content hash.
pub async fn fetch_profile(server: &str, name: &str) -> Option<Option<String>> {
	let server = server.trim_end_matches('/');
	let url = format!("{}/api/v1/profile/{}", server, urlencode(name));
	let (code, raw) = Tor::http_request_bytes("GET", url, None, vec![]).await?;
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
	let (code, raw) = Tor::http_request_bytes("GET", url, None, vec![]).await?;
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
			"relays": {"91cf9dbbea5e6511fd2bbb190b112055ee4131c5d2bbb9faedf3ee8cbeac0d05": ["wss://nrelay.us-ea.st"]}
		}"#;
		let res = parse_well_known(body, "ada").unwrap();
		assert_eq!(res.relays, vec!["wss://nrelay.us-ea.st".to_string()]);
		assert!(parse_well_known(body, "bob").is_none());
		assert!(parse_well_known("not json", "ada").is_none());
	}
}
