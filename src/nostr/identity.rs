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

//! Per-wallet nostr identity: NIP-06 derived from the wallet mnemonic by
//! default (one seed restores money AND identity) or imported from an nsec.
//! Stored at rest as NIP-49 ncryptsec encrypted with the wallet password.

use nostr_sdk::nips::nip49::{EncryptedSecretKey, KeySecurity};
use nostr_sdk::prelude::FromMnemonic;
use nostr_sdk::{FromBech32, Keys, SecretKey, ToBech32};
use serde_derive::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Where the keys came from.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
pub enum IdentitySource {
	/// NIP-06 derivation from the wallet BIP-39 mnemonic (legacy: binds the
	/// identity to the seed forever; superseded by `Random`).
	Derived,
	/// Imported nsec.
	Imported,
	/// Freshly generated random key, independent of the wallet seed: the
	/// seed proves nothing about the identity and cannot resurrect it.
	Random,
}

/// Identity file stored at `wallet_data/nostr/identity.json`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NostrIdentity {
	pub ver: u8,
	pub source: IdentitySource,
	/// NIP-06 account index used for derivation.
	pub derivation_account: u32,
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

	/// Derive keys from a BIP-39 mnemonic phrase via NIP-06.
	pub fn derive_keys(mnemonic: &str, account: u32) -> Result<Keys, IdentityError> {
		Keys::from_mnemonic_with_account(mnemonic, None, Some(account))
			.map_err(|e| IdentityError::Key(format!("{e}")))
	}

	/// Create a derived identity from the wallet mnemonic, encrypting the
	/// secret key with the wallet password.
	pub fn create_derived(
		mnemonic: &str,
		password: &str,
		account: u32,
	) -> Result<(NostrIdentity, Keys), IdentityError> {
		let keys = Self::derive_keys(mnemonic, account)?;
		let identity = Self::from_keys(&keys, password, IdentitySource::Derived, account)?;
		Ok((identity, keys))
	}

	/// Build an identity from already-unlocked keys under a (possibly
	/// different) password — used when importing a backup that was exported
	/// under another wallet's password.
	pub fn from_unlocked_keys(
		keys: &Keys,
		password: &str,
		source: IdentitySource,
		account: u32,
	) -> Result<NostrIdentity, IdentityError> {
		Self::from_keys(keys, password, source, account)
	}

	/// Create a brand-new random identity, independent of the wallet seed.
	pub fn create_random(password: &str) -> Result<(NostrIdentity, Keys), IdentityError> {
		let keys = Keys::generate();
		let identity = Self::from_keys(&keys, password, IdentitySource::Random, 0)?;
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
		let identity = Self::from_keys(&keys, password, IdentitySource::Imported, 0)?;
		Ok((identity, keys))
	}

	fn from_keys(
		keys: &Keys,
		password: &str,
		source: IdentitySource,
		account: u32,
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
			derivation_account: account,
			ncryptsec,
			npub,
			nip05: None,
			anonymous: true,
			prev_npubs: Vec::new(),
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
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn backup_restores_under_new_password() {
		// Export under one wallet password, restore on a device with another.
		let (a, _) = NostrIdentity::create_random("old-pw").unwrap();
		let json = serde_json::to_string(&a).unwrap();
		let parsed: NostrIdentity = serde_json::from_str(&json).unwrap();
		let keys = parsed.unlock("old-pw").unwrap();
		let b = NostrIdentity::from_unlocked_keys(
			&keys,
			"new-pw",
			parsed.source,
			parsed.derivation_account,
		)
		.unwrap();
		assert_eq!(b.npub, a.npub);
		assert!(b.unlock("new-pw").is_ok());
		assert!(b.unlock("old-pw").is_err());
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

	// NIP-06 test vector: this mnemonic must derive this npub (account 0).
	const NIP06_MNEMONIC: &str =
		"leader monkey parrot ring guide accident before fence cannon height naive bean";
	const NIP06_NPUB: &str = "npub1zutzeysacnf9rru6zqwmxd54mud0k44tst6l70ja5mhv8jjumytsd2x7nu";

	#[test]
	fn nip06_derivation_vector() {
		let keys = NostrIdentity::derive_keys(NIP06_MNEMONIC, 0).unwrap();
		assert_eq!(keys.public_key().to_bech32().unwrap(), NIP06_NPUB);
	}

	#[test]
	fn encrypt_unlock_roundtrip() {
		let (identity, keys) = NostrIdentity::create_derived(NIP06_MNEMONIC, "hunter2", 0).unwrap();
		assert_eq!(identity.source, IdentitySource::Derived);
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
		let (identity, _) = NostrIdentity::create_derived(NIP06_MNEMONIC, "pw", 0).unwrap();
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
		let (mut identity, keys) = NostrIdentity::create_derived(NIP06_MNEMONIC, "old", 0).unwrap();
		identity.reencrypt("old", "new").unwrap();
		assert!(identity.unlock("old").is_err());
		assert_eq!(
			identity.unlock("new").unwrap().public_key(),
			keys.public_key()
		);
	}
}
