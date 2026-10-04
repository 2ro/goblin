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
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// Where the keys came from. The legacy NIP-06 `Derived` source is gone: a
/// pre-Build-8 `"source":"Derived"` file no longer parses, so wallet init moves
/// it aside (see `NostrIdentity::load_or_set_aside`) and writes a fresh random
/// identity (the wanted behavior; binding a messaging identity to the money
/// seed was the dangerous design).
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

/// Counter that keeps two staged writes apart when they start in the same
/// nanosecond: the service thread and a GUI worker can save at the same time.
static STAGE_SEQ: AtomicU64 = AtomicU64::new(0);

/// A fresh temp path beside `target` for [`write_private`]: same directory,
/// because a rename is only atomic inside one filesystem. The name is
/// `<target name, at most 32 chars>.tmp-<pid>-<nanos>-<counter>`: unique per
/// write, so two writers never share a temp file and a temp left by a crash is
/// never reused, and short whatever the target's name. It never ends in
/// `.json`, and no loader opens it: every loader reads an exact file name.
pub(crate) fn staging_path(target: &Path) -> PathBuf {
	let nanos = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_nanos())
		.unwrap_or(0);
	let seq = STAGE_SEQ.fetch_add(1, Ordering::Relaxed);
	let name: String = target
		.file_name()
		.map(|n| n.to_string_lossy().chars().take(32).collect())
		.unwrap_or_default();
	target.with_file_name(format!("{name}.tmp-{}-{nanos}-{seq}", std::process::id()))
}

/// Stage `data` in the temp file `tmp` (beside its target) for an atomic
/// replace: owner-only (0600 on Unix) before any byte lands in it, and flushed
/// to disk. [`commit_staged`] then moves it over the target. On any error the
/// temp file is removed and the target is not touched.
pub(crate) fn stage_private(tmp: &Path, data: &[u8]) -> std::io::Result<()> {
	let written = (|| -> std::io::Result<()> {
		let mut opts = fs::OpenOptions::new();
		opts.write(true).create(true).truncate(true);
		#[cfg(unix)]
		{
			use std::os::unix::fs::OpenOptionsExt;
			opts.mode(0o600);
		}
		let mut f = opts.open(tmp)?;
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			// The create mode does not apply to a file that was already there;
			// set it on the open handle as well, before the data is written.
			let _ = f.set_permissions(fs::Permissions::from_mode(0o600));
		}
		f.write_all(data)?;
		f.sync_all()
	})();
	if written.is_err() {
		let _ = fs::remove_file(tmp);
	}
	written
}

/// Move a temp file from [`stage_private`] over `target`. The rename is atomic:
/// a reader finds the old file or the new one, never a cut one. The directory
/// is then flushed so the rename itself survives a power cut. Some Android
/// filesystems refuse that flush; it is logged and the write still counts,
/// because the rename has already happened. If the rename fails, the temp file
/// is removed and the target keeps its previous content.
pub(crate) fn commit_staged(tmp: &Path, target: &Path) -> std::io::Result<()> {
	if let Err(e) = fs::rename(tmp, target) {
		let _ = fs::remove_file(tmp);
		return Err(e);
	}
	sync_parent_dir(target);
	Ok(())
}

/// Flush the directory that holds `path`, so a rename in it is on disk. Unix
/// only: a directory cannot be opened as a file on Windows. A failure is only
/// logged (see [`commit_staged`]).
fn sync_parent_dir(path: &Path) {
	#[cfg(unix)]
	{
		let dir = match path.parent() {
			Some(d) if !d.as_os_str().is_empty() => d,
			_ => Path::new("."),
		};
		if let Err(e) = fs::File::open(dir).and_then(|d| d.sync_all()) {
			log::warn!("nostr: could not flush directory {}: {e}", dir.display());
		}
	}
	#[cfg(not(unix))]
	{
		let _ = path;
	}
}

/// Write a file atomically with owner-only (0600) permissions on Unix: stage it
/// in a temp file beside the target, then rename that over the target. A crash
/// or a full disk during the write leaves the previous file whole.
pub(crate) fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
	let tmp = staging_path(path);
	stage_private(&tmp, data)?;
	commit_staged(&tmp, path)
}

/// Rename a damaged file to `<name>.unreadable-<unix time>` in the same
/// directory and return the new path. A free name is picked first: a rename
/// silently replaces an existing file, and an earlier set-aside file must never
/// be lost. No loader opens such a name (every loader reads an exact name).
fn set_aside(path: &Path) -> std::io::Result<PathBuf> {
	let secs = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.map(|d| d.as_secs())
		.unwrap_or(0);
	let name = path
		.file_name()
		.map(|n| n.to_string_lossy().into_owned())
		.unwrap_or_default();
	for n in 0..100u32 {
		let aside = if n == 0 {
			path.with_file_name(format!("{name}.unreadable-{secs}"))
		} else {
			path.with_file_name(format!("{name}.unreadable-{secs}-{n}"))
		};
		if fs::symlink_metadata(&aside).is_ok() {
			continue;
		}
		fs::rename(path, &aside)?;
		sync_parent_dir(path);
		return Ok(aside);
	}
	Err(std::io::Error::new(
		std::io::ErrorKind::AlreadyExists,
		"no free name to set the damaged file aside",
	))
}

/// Read and parse the JSON file at `path` (an identity file or the held
/// identity index), never leaving a damaged one where a later write would
/// replace it.
/// - `Ok(Some)`: the parsed value.
/// - `Ok(None)`: no usable file. Either there is none, or its content is
///   damaged (it does not parse, or is not even text, as a torn write can
///   leave it) and it has been renamed aside (see [`set_aside`]) with its
///   bytes unchanged and an error logged that names both paths.
/// - `Err`: the file is there but could not be read (permissions, an I/O
///   error). Its content is unknown, so it is left in place and the caller
///   must not write over it.
pub(crate) fn read_or_set_aside<T: serde::de::DeserializeOwned>(
	path: &Path,
) -> std::io::Result<Option<T>> {
	let parsed = match fs::read_to_string(path) {
		Ok(raw) => serde_json::from_str::<T>(&raw).ok(),
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
		Err(e) if e.kind() == std::io::ErrorKind::InvalidData => None,
		Err(e) => return Err(e),
	};
	if parsed.is_some() {
		return Ok(parsed);
	}
	let aside = set_aside(path)?;
	log::error!(
		"nostr: {} could not be parsed; moved it to {} with its bytes unchanged",
		path.display(),
		aside.display()
	);
	Ok(None)
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

	/// Load identity #1 when the wallet opens, and never let a damaged file be
	/// written over.
	/// - `Ok(Some)`: the parsed identity.
	/// - `Ok(None)`: no usable file, the caller may create one. Either there is
	///   none, or its content is damaged (it does not parse, or is not even
	///   text, as a torn write can leave it) and it has been renamed aside to
	///   `identity.json.unreadable-<unix time>` with its bytes unchanged.
	/// - `Err`: the file is there but could not be read (permissions, an I/O
	///   error). Its content is unknown, so it is left in place and the caller
	///   must not write a new identity over it.
	pub fn load_or_set_aside(nostr_dir: &Path) -> std::io::Result<Option<NostrIdentity>> {
		read_or_set_aside(&nostr_dir.join(Self::FILE_NAME))
	}

	/// Persist the identity file with owner-only permissions (the ncryptsec
	/// blob must not be world-readable: a local attacker could grind the
	/// wallet password offline otherwise). The write is atomic, so a crash
	/// mid-save leaves the previous key file whole.
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
	/// blob must never be world-readable. Atomic, like [`Self::save`].
	pub fn save_at(&self, path: &Path) -> Result<(), IdentityError> {
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

	/// A fresh, unique scratch directory for one test.
	fn test_dir(tag: &str) -> PathBuf {
		let d = std::env::temp_dir().join(format!(
			"goblin-id-test-{tag}-{}-{}",
			std::process::id(),
			SystemTime::now()
				.duration_since(UNIX_EPOCH)
				.unwrap()
				.as_nanos()
		));
		fs::create_dir_all(&d).unwrap();
		d
	}

	/// File names in `dir` that contain `needle`.
	fn names_with(dir: &Path, needle: &str) -> Vec<String> {
		fs::read_dir(dir)
			.unwrap()
			.filter_map(|e| e.ok())
			.map(|e| e.file_name().to_string_lossy().into_owned())
			.filter(|n| n.contains(needle))
			.collect()
	}

	#[test]
	fn atomic_write_keeps_the_old_file_until_the_rename() {
		// A crash after the new bytes are staged but before the rename must leave
		// the target holding the OLD content, whole. The abandoned temp must not
		// stop the next write.
		let dir = test_dir("atomic");
		let target = dir.join(NostrIdentity::FILE_NAME);
		write_private(&target, b"old").unwrap();
		let tmp = staging_path(&target);
		stage_private(&tmp, b"new").unwrap();
		assert_eq!(
			fs::read(&target).unwrap(),
			b"old",
			"staging must not touch the target"
		);
		assert_eq!(fs::read(&tmp).unwrap(), b"new");
		// The process dies here: the temp is never renamed. The next write still
		// lands in full, on a temp of its own.
		write_private(&target, b"newer").unwrap();
		assert_eq!(fs::read(&target).unwrap(), b"newer");
		assert_eq!(
			fs::read(&tmp).unwrap(),
			b"new",
			"a leftover temp is never reused"
		);
		let _ = fs::remove_dir_all(&dir);
	}

	#[test]
	fn a_save_never_rewrites_the_old_file_in_place() {
		// The Build 169 writer truncated identity.json and wrote into the same
		// file, so a kill or a full disk mid-write left it empty or cut. A hard
		// link to the old file shows whether its bytes were ever rewritten: with
		// the atomic writer the new key lands in a new file and the old one is
		// left whole until the rename replaces it.
		let dir = test_dir("inplace");
		let (first, _) = NostrIdentity::create_random("pw").unwrap();
		first.save(&dir).unwrap();
		let before = fs::read(NostrIdentity::path(&dir)).unwrap();
		let witness = dir.join("witness");
		fs::hard_link(NostrIdentity::path(&dir), &witness).unwrap();
		let mut changed = first.clone();
		changed.dm_relays = vec!["wss://relay.example".to_string()];
		changed.save(&dir).unwrap();
		assert_eq!(
			fs::read(&witness).unwrap(),
			before,
			"the old identity file must never be rewritten in place"
		);
		assert_eq!(
			NostrIdentity::load(&dir).unwrap().dm_relays,
			vec!["wss://relay.example"]
		);
		let _ = fs::remove_dir_all(&dir);
	}

	#[test]
	fn a_failed_rename_keeps_the_target_and_removes_the_temp() {
		// Force the commit to fail: a file cannot be renamed over a non-empty
		// directory. The caller gets the error, the target is untouched, and no
		// temp file is left behind.
		let dir = test_dir("failcommit");
		let target = dir.join(NostrIdentity::FILE_NAME);
		fs::create_dir_all(target.join("keep")).unwrap();
		assert!(write_private(&target, b"new").is_err());
		assert!(target.join("keep").is_dir(), "the target must be untouched");
		assert!(
			names_with(&dir, ".tmp-").is_empty(),
			"a failed write must remove its temp"
		);
		let _ = fs::remove_dir_all(&dir);
	}

	// Unix only: the test needs the 255-byte file name limit, and a Windows temp
	// path this deep can hit MAX_PATH before it.
	#[cfg(unix)]
	#[test]
	fn the_write_temp_name_stays_short_for_a_long_target() {
		// The temp name must not grow with the target's name: a target near the
		// 255-byte file name limit must still be writable.
		let dir = test_dir("longname");
		let target = dir.join(format!("{}.json", "a".repeat(230)));
		let tmp = staging_path(&target);
		assert!(tmp.file_name().unwrap().len() < 100);
		assert_eq!(
			tmp.parent(),
			target.parent(),
			"the temp is beside its target"
		);
		write_private(&target, b"data").unwrap();
		assert_eq!(fs::read(&target).unwrap(), b"data");
		let _ = fs::remove_dir_all(&dir);
	}

	#[test]
	fn identity_round_trips_through_the_atomic_writer() {
		// Both identity writers (legacy path and explicit path) go through the
		// atomic writer, read back identically, and leave no temp behind.
		let dir = test_dir("roundtrip");
		let (identity, _) = NostrIdentity::create_random("pw").unwrap();
		identity.save(&dir).unwrap();
		let loaded = NostrIdentity::load(&dir).unwrap();
		assert_eq!(loaded.npub, identity.npub);
		assert_eq!(loaded.ncryptsec, identity.ncryptsec);
		let nested = dir
			.join("identities")
			.join("abc")
			.join(NostrIdentity::FILE_NAME);
		identity.save_at(&nested).unwrap();
		let loaded_at = NostrIdentity::load_at(&nested).unwrap();
		assert_eq!(loaded_at.npub, identity.npub);
		assert_eq!(loaded_at.ncryptsec, identity.ncryptsec);
		assert!(names_with(&dir, ".tmp-").is_empty());
		assert!(names_with(nested.parent().unwrap(), ".tmp-").is_empty());
		let _ = fs::remove_dir_all(&dir);
	}

	#[cfg(unix)]
	#[test]
	fn staged_temp_is_owner_only_before_the_rename() {
		use std::os::unix::fs::PermissionsExt;
		let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
		let dir = test_dir("tmpmode");
		let target = dir.join(NostrIdentity::FILE_NAME);
		// A target left with looser permissions by some earlier writer.
		fs::write(&target, b"old").unwrap();
		fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).unwrap();
		let tmp = staging_path(&target);
		stage_private(&tmp, b"secret").unwrap();
		assert_eq!(
			mode(&tmp),
			0o600,
			"the temp is owner-only before the rename"
		);
		commit_staged(&tmp, &target).unwrap();
		assert_eq!(mode(&target), 0o600, "the committed file is owner-only");
		assert!(!tmp.exists());
		let _ = fs::remove_dir_all(&dir);
	}

	/// The `identity.json.unreadable-*` files in `dir`.
	fn aside_files(dir: &Path) -> Vec<PathBuf> {
		let mut v: Vec<PathBuf> = names_with(dir, ".unreadable-")
			.into_iter()
			.map(|n| dir.join(n))
			.collect();
		v.sort();
		v
	}

	#[test]
	fn an_unparseable_identity_is_set_aside_with_its_bytes() {
		// A torn identity.json (here: the first half of a real one) must never
		// be written over. It is renamed aside with every byte kept, the loader
		// reports "no usable file", and nothing new is written by the loader.
		let dir = test_dir("setaside");
		let (identity, _) = NostrIdentity::create_random("pw").unwrap();
		let full = serde_json::to_string_pretty(&identity).unwrap();
		let torn = full.as_bytes()[..full.len() / 2].to_vec();
		fs::write(NostrIdentity::path(&dir), &torn).unwrap();

		assert!(NostrIdentity::load_or_set_aside(&dir).unwrap().is_none());
		assert!(
			!NostrIdentity::path(&dir).exists(),
			"the damaged file is moved, and the loader writes no new one"
		);
		let aside = aside_files(&dir);
		assert_eq!(aside.len(), 1);
		assert!(
			aside[0]
				.file_name()
				.unwrap()
				.to_string_lossy()
				.starts_with("identity.json.unreadable-")
		);
		assert_eq!(fs::read(&aside[0]).unwrap(), torn, "every byte is kept");
		// No loader takes the set-aside file for an identity.
		assert!(NostrIdentity::load(&dir).is_none());

		// A second damaged file (bytes that are not even text) in the same second
		// gets a name of its own: the first set-aside file is never replaced.
		let garbage = vec![0xff, 0xfe, 0x00, 0x7b];
		fs::write(NostrIdentity::path(&dir), &garbage).unwrap();
		assert!(NostrIdentity::load_or_set_aside(&dir).unwrap().is_none());
		let aside = aside_files(&dir);
		assert_eq!(aside.len(), 2, "both damaged files are kept");
		let kept: Vec<Vec<u8>> = aside.iter().map(|p| fs::read(p).unwrap()).collect();
		assert!(kept.contains(&torn));
		assert!(kept.contains(&garbage));
		let _ = fs::remove_dir_all(&dir);
	}

	#[test]
	fn load_or_set_aside_keeps_a_good_file_and_reports_a_missing_one() {
		let dir = test_dir("goodmissing");
		// Missing: nothing to load, nothing created.
		assert!(NostrIdentity::load_or_set_aside(&dir).unwrap().is_none());
		assert!(fs::read_dir(&dir).unwrap().next().is_none());
		// Good: loaded, and the file is left exactly as it was.
		let (identity, _) = NostrIdentity::create_random("pw").unwrap();
		identity.save(&dir).unwrap();
		let before = fs::read(NostrIdentity::path(&dir)).unwrap();
		let loaded = NostrIdentity::load_or_set_aside(&dir).unwrap().unwrap();
		assert_eq!(loaded.npub, identity.npub);
		assert_eq!(fs::read(NostrIdentity::path(&dir)).unwrap(), before);
		assert!(aside_files(&dir).is_empty());
		let _ = fs::remove_dir_all(&dir);
	}

	#[test]
	fn an_identity_path_that_cannot_be_read_is_left_in_place() {
		// Not a damaged file but an unreadable path (here a directory where the
		// file should be): the content is unknown, so the loader returns an error
		// and moves nothing. The caller must not write over it.
		let dir = test_dir("unreadable");
		fs::create_dir_all(NostrIdentity::path(&dir).join("keep")).unwrap();
		assert!(NostrIdentity::load_or_set_aside(&dir).is_err());
		assert!(NostrIdentity::path(&dir).join("keep").is_dir());
		assert!(aside_files(&dir).is_empty());
		let _ = fs::remove_dir_all(&dir);
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
