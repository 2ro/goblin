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

//! Per-wallet nostr identity: a random standalone nsec (or an imported one),
//! deliberately independent of the wallet seed — the seed proves nothing about
//! the identity and cannot resurrect it; the nsec is its own backup.
//! Stored at rest as NIP-49 ncryptsec encrypted with the wallet password.

use nostr_sdk::nips::nip44;
use nostr_sdk::nips::nip49::{EncryptedSecretKey, KeySecurity};
use nostr_sdk::{FromBech32, Keys, SecretKey, ToBech32};
use serde_derive::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Where the keys came from. The legacy NIP-06 `Derived` source is gone: a
/// pre-Build-8 `"source":"Derived"` file no longer parses, so `load()` returns
/// `None` and wallet init writes a fresh random identity (the wanted behavior;
/// binding a messaging identity to the money seed was the dangerous design).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum IdentitySource {
	/// Imported nsec.
	Imported,
	/// Freshly generated random key, independent of the wallet seed: the
	/// seed proves nothing about the identity and cannot resurrect it.
	Random,
}

/// Identity file stored at `wallet_data/nostr/identity.json`.
// TODO(audit L2): redact secret material (the ncryptsec) from Debug output.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NostrIdentity {
	pub ver: u8,
	pub source: IdentitySource,
	/// NIP-49 encrypted secret key (bech32 ncryptsec).
	pub ncryptsec: String,
	/// Public key, bech32 npub (plaintext so the UI can render pre-unlock).
	pub npub: String,
	/// Registered NIP-05 identifier (user@goblin.st).
	pub nip05: Option<String>,
	/// User chose to stay anonymous (no NIP-05, no kind-0 metadata).
	pub anonymous: bool,
	/// Previous npubs from key rotations (newest last), for reference.
	#[serde(default)]
	pub prev_npubs: Vec<String>,
	/// Advertised DM relays (kind 10050): the Goblin relay plus 1-2 pool
	/// relays picked once for this identity and kept sticky — no timer
	/// rotation, since 10050 churn breaks payers' cached routing. Empty until
	/// the first service start selects them.
	#[serde(default)]
	pub dm_relays: Vec<String>,
	/// PRIVATE, app-only label the user sets to name this identity for
	/// themselves. Stays local: it lives in this 0600 file (and rides inside the
	/// NIP-44-sealed .backup envelope, which serializes the whole struct), and is
	/// NEVER published — not in kind-0 metadata, not in any event.
	#[serde(default)]
	pub private_tag: Option<String>,
}

/// NIP-49 scrypt work factor (~64 MiB, interactive-grade).
const NCRYPTSEC_LOG_N: u8 = 16;

/// Write a file with owner-only (0600) permissions on Unix.
fn write_private(path: &PathBuf, data: &[u8]) -> std::io::Result<()> {
	#[cfg(unix)]
	{
		use std::io::Write;
		use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
		let mut f = std::fs::OpenOptions::new()
			.write(true)
			.create(true)
			.truncate(true)
			.mode(0o600)
			.open(path)?;
		f.write_all(data)?;
		// Also fix the mode if the file already existed with looser perms.
		let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
		Ok(())
	}
	#[cfg(not(unix))]
	{
		std::fs::write(path, data)
	}
}

/// Restrict a directory to owner-only access on Unix.
fn restrict_dir(dir: &PathBuf) {
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
	}
	#[cfg(not(unix))]
	{
		let _ = dir;
	}
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
	#[error("identity io error: {0}")]
	Io(#[from] std::io::Error),
	#[error("identity parse error: {0}")]
	Parse(#[from] serde_json::Error),
	#[error("key error: {0}")]
	Key(String),
	#[error("wrong password")]
	WrongPassword,
}

impl NostrIdentity {
	pub const FILE_NAME: &'static str = "identity.json";

	/// Identity file path inside the wallet nostr directory.
	pub fn path(nostr_dir: &PathBuf) -> PathBuf {
		let mut path = nostr_dir.clone();
		path.push(Self::FILE_NAME);
		path
	}

	/// Load the identity file if it exists.
	pub fn load(nostr_dir: &PathBuf) -> Option<NostrIdentity> {
		let path = Self::path(nostr_dir);
		let raw = fs::read_to_string(path).ok()?;
		serde_json::from_str(&raw).ok()
	}

	/// Persist the identity file with owner-only permissions (the ncryptsec
	/// blob must not be world-readable: a local attacker could grind the
	/// wallet password offline otherwise).
	pub fn save(&self, nostr_dir: &PathBuf) -> Result<(), IdentityError> {
		fs::create_dir_all(nostr_dir)?;
		restrict_dir(nostr_dir);
		let raw = serde_json::to_string_pretty(self)?;
		let path = Self::path(nostr_dir);
		write_private(&path, raw.as_bytes())?;
		Ok(())
	}

	/// Delete the identity file (used when the user discards the identity).
	pub fn delete(nostr_dir: &PathBuf) {
		let _ = fs::remove_file(Self::path(nostr_dir));
	}

	/// Load an identity from an explicit file path — a member of the held
	/// identity set (see [`crate::nostr::identities`]), which stores each
	/// additional identity in its own `identities/<hex>/identity.json`.
	pub fn load_at(path: &PathBuf) -> Option<NostrIdentity> {
		let raw = fs::read_to_string(path).ok()?;
		serde_json::from_str(&raw).ok()
	}

	/// Persist this identity to an explicit file path with owner-only (0600)
	/// permissions, creating (and 0700-restricting) the parent directory. Used
	/// by the held identity set for the non-legacy identities; the ncryptsec
	/// blob must never be world-readable.
	pub fn save_at(&self, path: &PathBuf) -> Result<(), IdentityError> {
		if let Some(dir) = path.parent() {
			fs::create_dir_all(dir)?;
			restrict_dir(&dir.to_path_buf());
		}
		let raw = serde_json::to_string_pretty(self)?;
		write_private(path, raw.as_bytes())?;
		Ok(())
	}

	/// The identity's public key as lowercase hex — the stable id used to key it
	/// in the held-identity index and on disk. `None` if the stored npub is
	/// malformed (never expected for an identity we wrote).
	pub fn pubkey_hex(&self) -> Option<String> {
		use nostr_sdk::PublicKey;
		PublicKey::from_bech32(&self.npub)
			.ok()
			.map(|pk| pk.to_hex())
	}

	/// Build an identity from already-unlocked keys under a (possibly
	/// different) password — used when importing a backup that was exported
	/// under another wallet's password.
	pub fn from_unlocked_keys(
		keys: &Keys,
		password: &str,
		source: IdentitySource,
	) -> Result<NostrIdentity, IdentityError> {
		Self::from_keys(keys, password, source)
	}

	/// Create a brand-new random identity, independent of the wallet seed.
	pub fn create_random(password: &str) -> Result<(NostrIdentity, Keys), IdentityError> {
		let keys = Keys::generate();
		let identity = Self::from_keys(&keys, password, IdentitySource::Random)?;
		Ok((identity, keys))
	}

	/// Create an imported identity from an nsec string.
	pub fn create_imported(
		nsec: &str,
		password: &str,
	) -> Result<(NostrIdentity, Keys), IdentityError> {
		let secret = SecretKey::parse(nsec.trim())
			.map_err(|e| IdentityError::Key(format!("invalid nsec: {e}")))?;
		let keys = Keys::new(secret);
		let identity = Self::from_keys(&keys, password, IdentitySource::Imported)?;
		Ok((identity, keys))
	}

	fn from_keys(
		keys: &Keys,
		password: &str,
		source: IdentitySource,
	) -> Result<NostrIdentity, IdentityError> {
		let encrypted = EncryptedSecretKey::new(
			keys.secret_key(),
			password,
			NCRYPTSEC_LOG_N,
			KeySecurity::Medium,
		)
		.map_err(|e| IdentityError::Key(format!("encrypt failed: {e}")))?;
		let ncryptsec = encrypted
			.to_bech32()
			.map_err(|e| IdentityError::Key(format!("bech32 failed: {e}")))?;
		let npub = keys
			.public_key()
			.to_bech32()
			.map_err(|e| IdentityError::Key(format!("bech32 failed: {e}")))?;
		Ok(NostrIdentity {
			ver: 1,
			source,
			ncryptsec,
			npub,
			nip05: None,
			anonymous: true,
			prev_npubs: Vec::new(),
			dm_relays: Vec::new(),
			private_tag: None,
		})
	}

	/// Decrypt the stored key with the wallet password.
	pub fn unlock(&self, password: &str) -> Result<Keys, IdentityError> {
		let encrypted = EncryptedSecretKey::from_bech32(&self.ncryptsec)
			.map_err(|e| IdentityError::Key(format!("invalid ncryptsec: {e}")))?;
		let secret = encrypted
			.decrypt(password)
			.map_err(|_| IdentityError::WrongPassword)?;
		Ok(Keys::new(secret))
	}

	/// Re-encrypt the stored key under a new password.
	pub fn reencrypt(&mut self, old: &str, new: &str) -> Result<(), IdentityError> {
		let keys = self.unlock(old)?;
		let encrypted =
			EncryptedSecretKey::new(keys.secret_key(), new, NCRYPTSEC_LOG_N, KeySecurity::Medium)
				.map_err(|e| IdentityError::Key(format!("encrypt failed: {e}")))?;
		self.ncryptsec = encrypted
			.to_bech32()
			.map_err(|e| IdentityError::Key(format!("bech32 failed: {e}")))?;
		Ok(())
	}

	/// A single, fully-encrypted, portable backup of this identity (the contents
	/// of a `GOBLIN-*.backup` file). Two sealed layers, no plaintext: the secret
	/// key is the password-protected NIP-49 ncryptsec, and the rest of the
	/// identity (username, history, source) is NIP-44-sealed to our own key. An
	/// outside party sees only ciphertext — no npub, no name. Any Goblin wallet
	/// reopens it with the backup's password. `keys` must be this identity's
	/// unlocked keys (the caller unlocks with the password first).
	pub fn to_encrypted_backup(&self, keys: &Keys) -> Result<String, IdentityError> {
		let json = serde_json::to_string(self)?;
		let sealed = nip44::encrypt(
			keys.secret_key(),
			&keys.public_key(),
			json,
			nip44::Version::V2,
		)
		.map_err(|e| IdentityError::Key(format!("seal failed: {e}")))?;
		let envelope = serde_json::json!({
			"goblin_backup": 1,
			"k": self.ncryptsec,
			"d": sealed,
		});
		serde_json::to_string(&envelope).map_err(IdentityError::from)
	}

	/// True if `s` is a Goblin encrypted-backup envelope (vs a bare nsec or the
	/// legacy plaintext identity JSON).
	pub fn is_encrypted_backup(s: &str) -> bool {
		serde_json::from_str::<serde_json::Value>(s.trim())
			.ok()
			.and_then(|v| v.get("goblin_backup").cloned())
			.is_some()
	}

	/// Open an encrypted backup with its password, returning the embedded
	/// identity and its unlocked keys.
	pub fn from_encrypted_backup(
		envelope: &str,
		password: &str,
	) -> Result<(NostrIdentity, Keys), IdentityError> {
		let v: serde_json::Value = serde_json::from_str(envelope.trim())?;
		let k = v
			.get("k")
			.and_then(|x| x.as_str())
			.ok_or_else(|| IdentityError::Key("backup missing key".into()))?;
		let d = v
			.get("d")
			.and_then(|x| x.as_str())
			.ok_or_else(|| IdentityError::Key("backup missing data".into()))?;
		// Unlock the wrapper key with the password, then open the sealed JSON.
		let enc = EncryptedSecretKey::from_bech32(k)
			.map_err(|e| IdentityError::Key(format!("invalid backup: {e}")))?;
		let secret = enc
			.decrypt(password)
			.map_err(|_| IdentityError::WrongPassword)?;
		let keys = Keys::new(secret);
		let json = nip44::decrypt(keys.secret_key(), &keys.public_key(), d)
			.map_err(|_| IdentityError::WrongPassword)?;
		let identity: NostrIdentity = serde_json::from_str(&json)?;
		Ok((identity, keys))
	}
}

/// The decrypted contents of a full wallet backup (see [`build_full_backup`]):
/// the money seed phrase plus every held identity (each with its unlocked keys),
/// and the hex of the identity that was active when the backup was made.
pub struct FullBackup {
	/// The 24-word grin recovery phrase, in memory only.
	pub seed_phrase: String,
	/// Hex pubkey of the identity that was active at backup time (may be empty).
	pub active: String,
	/// Every held identity with its unlocked keys, re-openable by the restorer.
	pub identities: Vec<(NostrIdentity, Keys)>,
	/// The wallet's sealed activity history (an [`crate::nostr::ArchiveSnapshot`]
	/// serialized to JSON), if the backup carried one. `None` for a legacy backup
	/// written before the format included history; the caller deserializes and
	/// merges it into the restored store.
	pub history: Option<String>,
}

/// Seal an arbitrary UTF-8 string under a password with NO plaintext, reusing the
/// exact two-layer scheme of [`NostrIdentity::to_encrypted_backup`]: a fresh
/// random wrapper key is password-protected as a NIP-49 ncryptsec (scrypt), and
/// the text is NIP-44-sealed to that key. Returns `(k, d)` — the ncryptsec and
/// the sealed blob. The wrapper key is otherwise meaningless; only recovering the
/// text matters. No new crypto and no new dependency: same primitives the
/// identity backup already uses.
pub fn seal_secret_text(
	plaintext: &str,
	password: &str,
) -> Result<(String, String), IdentityError> {
	let wrapper = Keys::generate();
	let encrypted = EncryptedSecretKey::new(
		wrapper.secret_key(),
		password,
		NCRYPTSEC_LOG_N,
		KeySecurity::Medium,
	)
	.map_err(|e| IdentityError::Key(format!("encrypt failed: {e}")))?;
	let k = encrypted
		.to_bech32()
		.map_err(|e| IdentityError::Key(format!("bech32 failed: {e}")))?;
	let d = nip44::encrypt(
		wrapper.secret_key(),
		&wrapper.public_key(),
		plaintext,
		nip44::Version::V2,
	)
	.map_err(|e| IdentityError::Key(format!("seal failed: {e}")))?;
	Ok((k, d))
}

/// Reverse [`seal_secret_text`]: unlock the wrapper key with the password, then
/// open the NIP-44-sealed text. A wrong password fails at the ncryptsec layer.
pub fn open_secret_text(k: &str, d: &str, password: &str) -> Result<String, IdentityError> {
	let enc = EncryptedSecretKey::from_bech32(k)
		.map_err(|e| IdentityError::Key(format!("invalid backup: {e}")))?;
	let secret = enc
		.decrypt(password)
		.map_err(|_| IdentityError::WrongPassword)?;
	let keys = Keys::new(secret);
	nip44::decrypt(keys.secret_key(), &keys.public_key(), d)
		.map_err(|_| IdentityError::WrongPassword)
}

/// Build the contents of a FULL wallet `.backup` file (format version 2): the
/// money seed AND every held identity, all sealed under one password. The seed is
/// sealed with [`seal_secret_text`]; each identity is sealed with the SAME
/// per-identity scheme as the single-identity backup ([`NostrIdentity::to_encrypted_backup`]),
/// so every element is itself a valid v1 identity envelope. No plaintext (no
/// seed, no npub, no name) ever appears in the output. `identities` carries each
/// identity with its already-unlocked keys; `active_hex` is the identity active
/// at backup time.
///
/// `history_json`, when present, is the wallet's activity metadata (an
/// [`crate::nostr::ArchiveSnapshot`] serialized to JSON: tx notes, counterparty
/// npubs/names, request records) sealed under the SAME password with
/// [`seal_secret_text`], so the restored wallet's activity list survives a chain
/// rescan. It carries npubs, names and notes, so it is sealed, never plaintext.
/// An empty or `None` value simply omits the field, keeping the output
/// byte-shaped exactly like the pre-history format.
pub fn build_full_backup(
	seed_phrase: &str,
	identities: &[(NostrIdentity, Keys)],
	active_hex: &str,
	history_json: Option<&str>,
	password: &str,
) -> Result<String, IdentityError> {
	let (k, d) = seal_secret_text(seed_phrase, password)?;
	let mut elems = Vec::with_capacity(identities.len());
	for (id, keys) in identities {
		elems.push(id.to_encrypted_backup(keys)?);
	}
	let mut envelope = serde_json::json!({
		"goblin_backup": 2,
		"seed": { "k": k, "d": d },
		"identities": elems,
		"active": active_hex,
	});
	// Optional sealed history. A new field older builds don't read (they pull the
	// envelope apart with `.get()` on the fields they know), so a NEW file still
	// restores on an OLD app; and its absence is tolerated on open below, so an
	// OLD file still restores on a NEW app.
	if let Some(hist) = history_json.filter(|h| !h.is_empty()) {
		let (hk, hd) = seal_secret_text(hist, password)?;
		envelope["history"] = serde_json::json!({ "k": hk, "d": hd });
	}
	serde_json::to_string(&envelope).map_err(IdentityError::from)
}

/// True if `s` is a FULL wallet backup (format version 2 — seed + identities),
/// as opposed to a v1 single-identity backup or a bare nsec. Both formats set
/// `goblin_backup`; only v2 carries a seed, so callers that must create the
/// wallet check this FIRST.
pub fn is_full_backup(s: &str) -> bool {
	serde_json::from_str::<serde_json::Value>(s.trim())
		.ok()
		.and_then(|v| v.get("goblin_backup").and_then(|x| x.as_u64()))
		.map(|ver| ver >= 2)
		.unwrap_or(false)
}

/// Open a full wallet backup with its password, returning the seed phrase, the
/// active identity's hex, and every held identity with its unlocked keys. A wrong
/// password fails at the seed's ncryptsec layer.
pub fn open_full_backup(blob: &str, password: &str) -> Result<FullBackup, IdentityError> {
	let v: serde_json::Value = serde_json::from_str(blob.trim())?;
	let seed = v
		.get("seed")
		.ok_or_else(|| IdentityError::Key("backup missing seed".into()))?;
	let k = seed
		.get("k")
		.and_then(|x| x.as_str())
		.ok_or_else(|| IdentityError::Key("backup missing seed key".into()))?;
	let d = seed
		.get("d")
		.and_then(|x| x.as_str())
		.ok_or_else(|| IdentityError::Key("backup missing seed data".into()))?;
	let seed_phrase = open_secret_text(k, d, password)?;
	let active = v
		.get("active")
		.and_then(|x| x.as_str())
		.unwrap_or("")
		.to_string();
	// Optional sealed activity history — absent on legacy backups, in which case
	// the restore simply has nothing extra to merge. Sealed with the same
	// password as the seed, so a present-but-unopenable blob is a hard error (the
	// file is corrupt), not silently dropped.
	let history = match v.get("history") {
		Some(h) => {
			let hk = h
				.get("k")
				.and_then(|x| x.as_str())
				.ok_or_else(|| IdentityError::Key("backup missing history key".into()))?;
			let hd = h
				.get("d")
				.and_then(|x| x.as_str())
				.ok_or_else(|| IdentityError::Key("backup missing history data".into()))?;
			Some(open_secret_text(hk, hd, password)?)
		}
		None => None,
	};
	let mut identities = Vec::new();
	if let Some(arr) = v.get("identities").and_then(|x| x.as_array()) {
		for elem in arr {
			let elem_str = elem
				.as_str()
				.ok_or_else(|| IdentityError::Key("malformed identity element".into()))?;
			let (id, keys) = NostrIdentity::from_encrypted_backup(elem_str, password)?;
			identities.push((id, keys));
		}
	}
	Ok(FullBackup {
		seed_phrase,
		active,
		identities,
		history,
	})
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn full_backup_roundtrips_seed_identities_and_active() {
		// Build a full backup from a seed + several identities, then reopen it:
		// the seed text, every identity's key, and the active marker must survive,
		// and NOTHING sensitive (seed word, npub, name) may appear in the file.
		let seed = "abandon abandon abandon abandon abandon abandon abandon abandon \
			abandon abandon abandon abandon abandon abandon abandon abandon abandon \
			abandon abandon abandon abandon abandon abandon art";
		let (mut a, ka) = NostrIdentity::create_random("walletpw").unwrap();
		a.nip05 = Some("alice@goblin.st".to_string());
		a.anonymous = false;
		let (b, kb) = NostrIdentity::create_random("walletpw").unwrap();
		let active_hex = b.pubkey_hex().unwrap();
		let ids = vec![(a.clone(), ka.clone()), (b.clone(), kb.clone())];

		// Seal a scrap of activity history alongside the seed and identities.
		let history = r#"{"ver":1,"tx_meta":[],"contacts":[],"requests":[]}"#;
		let blob = build_full_backup(seed, &ids, &active_hex, Some(history), "walletpw").unwrap();
		assert!(is_full_backup(&blob));
		// A full backup is NOT a v1 single-identity backup, but the shared
		// `goblin_backup` marker still reads as "an encrypted backup".
		assert!(NostrIdentity::is_encrypted_backup(&blob));
		// Opaque: no seed word, no npub, no username leaks.
		assert!(!blob.contains("abandon"));
		assert!(!blob.contains(&a.npub));
		assert!(!blob.contains(&b.npub));
		assert!(!blob.contains("alice"));

		let opened = open_full_backup(&blob, "walletpw").unwrap();
		assert_eq!(opened.seed_phrase, seed);
		assert_eq!(opened.active, active_hex);
		assert_eq!(opened.identities.len(), 2);
		// The sealed history survives the round trip verbatim.
		assert_eq!(opened.history.as_deref(), Some(history));
		// Both identities and their keys restore exactly, metadata intact.
		let npubs: Vec<_> = opened
			.identities
			.iter()
			.map(|(i, _)| i.npub.clone())
			.collect();
		assert!(npubs.contains(&a.npub));
		assert!(npubs.contains(&b.npub));
		let restored_a = opened
			.identities
			.iter()
			.find(|(i, _)| i.npub == a.npub)
			.unwrap();
		assert_eq!(restored_a.0.nip05.as_deref(), Some("alice@goblin.st"));
		assert!(!restored_a.0.anonymous);
		assert_eq!(restored_a.1.public_key(), ka.public_key());
		// Wrong password opens nothing.
		assert!(open_full_backup(&blob, "wrong").is_err());
	}

	#[test]
	fn legacy_full_backup_without_history_opens_cleanly() {
		// A v2 backup written before the history field existed carries no
		// `history` key. It must still open, with `history == None` (nothing extra
		// to merge), on the new app.
		let seed = "abandon abandon abandon abandon abandon abandon abandon abandon \
			abandon abandon abandon abandon abandon abandon abandon abandon abandon \
			abandon abandon abandon abandon abandon abandon art";
		let (a, ka) = NostrIdentity::create_random("pw").unwrap();
		let active_hex = a.pubkey_hex().unwrap();
		let ids = vec![(a, ka)];
		// history_json = None reproduces the exact pre-history envelope.
		let blob = build_full_backup(seed, &ids, &active_hex, None, "pw").unwrap();
		assert!(
			!blob.contains("history"),
			"omitted history must not appear in the file"
		);
		let opened = open_full_backup(&blob, "pw").unwrap();
		assert_eq!(opened.seed_phrase, seed);
		assert!(opened.history.is_none());
	}

	#[test]
	fn new_full_backup_keeps_legacy_open_path_fields() {
		// Forward-compat: an OLD app opens a full backup by pulling the `seed`,
		// `active` and `identities` fields out of the JSON with `.get()` and
		// ignoring anything else. Adding `history` must leave those three exactly
		// where the old path looks, so a NEW file still restores on an OLD build.
		let seed = "abandon abandon abandon abandon abandon abandon abandon abandon \
			abandon abandon abandon abandon abandon abandon abandon abandon abandon \
			abandon abandon abandon abandon abandon abandon art";
		let (a, ka) = NostrIdentity::create_random("pw").unwrap();
		let active_hex = a.pubkey_hex().unwrap();
		let ids = vec![(a, ka)];
		let history = r#"{"ver":1,"tx_meta":[],"contacts":[],"requests":[]}"#;
		let blob = build_full_backup(seed, &ids, &active_hex, Some(history), "pw").unwrap();
		let v: serde_json::Value = serde_json::from_str(&blob).unwrap();
		// The fields the legacy open path reads are all present and well-shaped.
		assert_eq!(v.get("goblin_backup").and_then(|x| x.as_u64()), Some(2));
		assert!(v.get("seed").and_then(|s| s.get("k")).is_some());
		assert!(v.get("seed").and_then(|s| s.get("d")).is_some());
		assert_eq!(
			v.get("active").and_then(|x| x.as_str()),
			Some(active_hex.as_str())
		);
		assert_eq!(
			v.get("identities")
				.and_then(|x| x.as_array())
				.map(|a| a.len()),
			Some(1)
		);
	}

	#[test]
	fn old_single_identity_backup_is_not_a_full_backup() {
		// A v1 single-identity envelope must NOT be mistaken for a full backup, and
		// must keep restoring through the v1 path exactly as before.
		let (a, keys) = NostrIdentity::create_random("pw-1").unwrap();
		let v1 = a.to_encrypted_backup(&keys).unwrap();
		assert!(NostrIdentity::is_encrypted_backup(&v1));
		assert!(!is_full_backup(&v1), "v1 must not read as a full backup");
		let (restored, _) = NostrIdentity::from_encrypted_backup(&v1, "pw-1").unwrap();
		assert_eq!(restored.npub, a.npub);
	}

	#[test]
	fn seal_secret_text_roundtrips_and_is_opaque() {
		let secret = "the quick brown fox";
		let (k, d) = seal_secret_text(secret, "pw").unwrap();
		assert!(!k.contains(secret) && !d.contains(secret));
		assert_eq!(open_secret_text(&k, &d, "pw").unwrap(), secret);
		assert!(open_secret_text(&k, &d, "nope").is_err());
	}

	#[test]
	fn backup_restores_under_new_password() {
		// Export under one wallet password, restore on a device with another.
		let (a, _) = NostrIdentity::create_random("old-pw").unwrap();
		let json = serde_json::to_string(&a).unwrap();
		let parsed: NostrIdentity = serde_json::from_str(&json).unwrap();
		let keys = parsed.unlock("old-pw").unwrap();
		let b = NostrIdentity::from_unlocked_keys(&keys, "new-pw", parsed.source).unwrap();
		assert_eq!(b.npub, a.npub);
		assert!(b.unlock("new-pw").is_ok());
		assert!(b.unlock("old-pw").is_err());
	}

	#[test]
	fn encrypted_backup_roundtrips_and_is_opaque() {
		// A .backup file: sealed under one password, reopened with it. The
		// envelope must carry no plaintext npub/name, and a wrong password fails.
		let (mut a, keys) = NostrIdentity::create_random("pw-1").unwrap();
		a.nip05 = Some("jimbob@goblin.st".to_string());
		a.anonymous = false;
		let envelope = a.to_encrypted_backup(&keys).unwrap();
		assert!(NostrIdentity::is_encrypted_backup(&envelope));
		// Opaque: neither the public key nor the username leaks in the file.
		assert!(!envelope.contains(&a.npub));
		assert!(!envelope.contains("jimbob"));
		// Reopen with the password → same identity.
		let (restored, rkeys) = NostrIdentity::from_encrypted_backup(&envelope, "pw-1").unwrap();
		assert_eq!(restored.npub, a.npub);
		assert_eq!(restored.nip05.as_deref(), Some("jimbob@goblin.st"));
		assert_eq!(rkeys.public_key(), keys.public_key());
		// Wrong password can't open it.
		assert!(NostrIdentity::from_encrypted_backup(&envelope, "wrong").is_err());
	}

	#[test]
	fn random_identities_are_unlinked_and_unlock() {
		let (a, ka) = NostrIdentity::create_random("pw-1").unwrap();
		let (b, _) = NostrIdentity::create_random("pw-1").unwrap();
		// Fresh entropy every time: no chain between identities.
		assert_ne!(a.npub, b.npub);
		assert_eq!(a.source, IdentitySource::Random);
		// NIP-49 roundtrip with the right password; wrong one fails.
		let unlocked = a.unlock("pw-1").unwrap();
		assert_eq!(unlocked.public_key(), ka.public_key());
		assert!(a.unlock("wrong").is_err());
	}

	#[test]
	fn encrypt_unlock_roundtrip() {
		let (identity, keys) = NostrIdentity::create_random("hunter2").unwrap();
		assert_eq!(identity.source, IdentitySource::Random);
		assert!(identity.anonymous);
		let unlocked = identity.unlock("hunter2").unwrap();
		assert_eq!(unlocked.public_key(), keys.public_key());
		assert!(identity.unlock("wrong").is_err());
	}

	#[test]
	fn import_nsec_roundtrip() {
		let keys = Keys::generate();
		let nsec = keys.secret_key().to_bech32().unwrap();
		let (identity, imported) = NostrIdentity::create_imported(&nsec, "pw").unwrap();
		assert_eq!(identity.source, IdentitySource::Imported);
		assert_eq!(imported.public_key(), keys.public_key());
		let unlocked = identity.unlock("pw").unwrap();
		assert_eq!(unlocked.public_key(), keys.public_key());
	}

	#[cfg(unix)]
	#[test]
	fn identity_file_is_owner_only() {
		use std::os::unix::fs::PermissionsExt;
		let dir = std::env::temp_dir().join(format!("goblin-id-test-{}", std::process::id()));
		let (identity, _) = NostrIdentity::create_random("pw").unwrap();
		identity.save(&dir).unwrap();
		let meta = std::fs::metadata(NostrIdentity::path(&dir)).unwrap();
		// The ncryptsec blob must never be group/world readable.
		assert_eq!(
			meta.permissions().mode() & 0o077,
			0,
			"identity.json must be 0600"
		);
		let _ = std::fs::remove_dir_all(&dir);
	}

	#[test]
	fn reencrypt_changes_password() {
		let (mut identity, keys) = NostrIdentity::create_random("old").unwrap();
		identity.reencrypt("old", "new").unwrap();
		assert!(identity.unlock("old").is_err());
		assert_eq!(
			identity.unlock("new").unwrap().public_key(),
			keys.public_key()
		);
	}
}
