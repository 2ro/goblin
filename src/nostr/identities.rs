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

//! One wallet, one grin seed / one balance, but MANY nostr identities (nsecs),
//! exactly one of which is ACTIVE at a time. This module is the wallet-level
//! held-identity INDEX: it owns which identities the wallet holds, their display
//! order, and which is active. It stores NO secrets. Each held identity is a
//! full [`NostrIdentity`] on disk (its own NIP-49 ncryptsec, see
//! [`crate::nostr::identity`]); this index only points at those files.
//!
//! On-disk layout under `<base_data>/nostr/`:
//! ```text
//! nostr/
//!   identities.json            # this index (0600, no secrets): active + order + entries
//!   identity.json              # identity #1 (the legacy file, NEVER overwritten by a switch)
//!   identities/<hex>/identity.json   # each additional held identity
//!   db/                        # shared rkv store (dedup, contacts, meta) — one for all identities
//! ```
//!
//! Migration is trivial and fund-safe: a pre-feature wallet has only a bare
//! `identity.json`. On first load the index adopts it as the single, active
//! identity #1 — no key regeneration, no rewrite of the legacy file, and the
//! grin seed/balance are never touched (this module cannot reach them).
//!
//! A switch only moves the `active` pointer here and rebinds the running service
//! to the target's key (the wallet does the teardown + bring-up + catch-up). The
//! legacy `identity.json` is deliberately never overwritten, so an older build
//! that ignores this index still opens the wallet on identity #1 (clean rollback).

use crate::nostr::identity::NostrIdentity;
use serde_derive::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Index file name inside the nostr directory.
const INDEX_FILE: &str = "identities.json";
/// The legacy single-identity file, which becomes identity #1.
const LEGACY_FILE: &str = "identity.json";
/// Sub-directory holding each additional (non-legacy) identity.
const SUBDIR: &str = "identities";

/// Cap on how many identities one wallet may hold. Bounds the on-disk key files
/// and the switcher list, and stops a hostile import loop from ballooning either.
pub const MAX_IDENTITIES: usize = 8;

/// One held identity, referenced by the index. No secret material.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct HeldEntry {
	/// Public key, lowercase hex — the stable id of this identity.
	#[serde(default)]
	pub pubkey: String,
	/// Path to the identity's `identity.json`, RELATIVE to the nostr dir:
	/// `"identity.json"` for the legacy identity #1, else
	/// `"identities/<hex>/identity.json"`.
	#[serde(default)]
	pub path: String,
	/// A short human label: the identity's claimed name (local part of its NIP-05)
	/// when it has one, else empty. NOT rendered — the UI derives its display from
	/// the name or a truncated npub — kept only as a convenience field in the
	/// index. Plaintext by design (this index carries no secret). Never a
	/// placeholder word.
	#[serde(default)]
	pub label: String,
}

impl HeldEntry {
	/// Absolute path to this entry's identity file under `nostr_dir`.
	pub fn abs_path(&self, nostr_dir: &PathBuf) -> PathBuf {
		let mut p = nostr_dir.clone();
		for seg in self.path.split('/') {
			p.push(seg);
		}
		p
	}

	/// Load the full [`NostrIdentity`] this entry points at.
	pub fn load(&self, nostr_dir: &PathBuf) -> Option<NostrIdentity> {
		NostrIdentity::load_at(&self.abs_path(nostr_dir))
	}
}

/// The held-identity index: which identities the wallet holds and which is
/// active. Persisted as `identities.json`.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HeldIdentities {
	/// Format version. Defaults to 1 when absent so a file that dropped the field
	/// still parses.
	#[serde(default = "default_held_ver")]
	pub ver: u8,
	/// Active identity, lowercase hex. Drives the single live subscription and
	/// all display; the only pointer a switch moves.
	#[serde(default)]
	pub active: String,
	/// Display order, lowercase hex.
	#[serde(default)]
	pub order: Vec<String>,
	/// Entry metadata (no secrets).
	#[serde(default)]
	pub identities: Vec<HeldEntry>,
}

/// The held-index format version default (1).
fn default_held_ver() -> u8 {
	1
}

impl HeldIdentities {
	/// Index file path inside the nostr dir.
	pub fn index_path(nostr_dir: &PathBuf) -> PathBuf {
		let mut p = nostr_dir.clone();
		p.push(INDEX_FILE);
		p
	}

	/// Relative path an additional identity's file lives at.
	fn rel_path_for(hex: &str) -> String {
		format!("{SUBDIR}/{hex}/{LEGACY_FILE}")
	}

	/// Load the index if present and parseable.
	pub fn load(nostr_dir: &PathBuf) -> Option<HeldIdentities> {
		let raw = fs::read_to_string(Self::index_path(nostr_dir)).ok()?;
		serde_json::from_str(&raw).ok()
	}

	/// Persist the index with owner-only (0600) permissions. It carries no
	/// secret, but a consistent 0700/0600 posture across the nostr dir is
	/// simplest to reason about.
	pub fn save(&self, nostr_dir: &PathBuf) -> std::io::Result<()> {
		fs::create_dir_all(nostr_dir)?;
		let raw = serde_json::to_string_pretty(self)
			.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
		write_private_0600(&Self::index_path(nostr_dir), raw.as_bytes())
	}

	/// The active entry, if the pointer resolves to a held identity.
	pub fn active_entry(&self) -> Option<&HeldEntry> {
		self.identities.iter().find(|e| e.pubkey == self.active)
	}

	/// Look up an entry by hex.
	pub fn entry(&self, hex: &str) -> Option<&HeldEntry> {
		self.identities.iter().find(|e| e.pubkey == hex)
	}

	/// Whether the wallet already holds this pubkey (dedupe guard on add/import).
	pub fn contains(&self, hex: &str) -> bool {
		self.identities.iter().any(|e| e.pubkey == hex)
	}

	/// Held-identity count.
	pub fn len(&self) -> usize {
		self.identities.len()
	}

	pub fn is_empty(&self) -> bool {
		self.identities.is_empty()
	}

	/// True if another identity may still be added under the cap.
	pub fn has_room(&self) -> bool {
		self.identities.len() < MAX_IDENTITIES
	}

	/// Build a fresh single-identity index from the legacy identity #1. This is
	/// the migration shape: exactly one held identity, active, referencing the
	/// legacy `identity.json` in place (never rewritten).
	pub fn from_legacy(legacy: &NostrIdentity) -> Option<HeldIdentities> {
		let hex = legacy.pubkey_hex()?;
		Some(HeldIdentities {
			ver: 1,
			active: hex.clone(),
			order: vec![hex.clone()],
			identities: vec![HeldEntry {
				pubkey: hex,
				path: LEGACY_FILE.to_string(),
				label: label_for(legacy),
			}],
		})
	}

	/// Load the index, migrating a legacy single-identity wallet in place, and
	/// self-healing an index whose `active` pointer no longer resolves. Returns
	/// the index plus the ACTIVE identity to run. `legacy` is the identity loaded
	/// from the bare `identity.json` (identity #1), used for migration/repair.
	///
	/// Never touches funds and never regenerates a key. Writes only the index
	/// (`identities.json`) — the identity files themselves are left as they are.
	pub fn load_or_migrate(
		nostr_dir: &PathBuf,
		legacy: &NostrIdentity,
	) -> Option<(HeldIdentities, NostrIdentity)> {
		let legacy_hex = legacy.pubkey_hex()?;
		match Self::load(nostr_dir) {
			Some(mut idx) => {
				// Self-heal: drop any entry whose file holds a DIFFERENT key than the
				// entry claims. Such an entry is a lie about disk — it makes the same
				// identity load twice (once under its own entry, once under the stale
				// one) and hides the fact that the key the entry names is gone.
				// Dropping it is honest: the switcher then shows what the wallet can
				// actually still open. Only a parsed mismatch prunes; an unreadable
				// file is left alone (a transient read error must not evict a key).
				let before = idx.identities.len();
				idx.identities.retain(|e| match e.load(nostr_dir) {
					Some(id) => id.pubkey_hex().as_deref() == Some(e.pubkey.as_str()),
					None => true,
				});
				if idx.identities.len() != before {
					let kept: Vec<&str> =
						idx.identities.iter().map(|e| e.pubkey.as_str()).collect();
					idx.order.retain(|h| kept.contains(&h.as_str()));
					let _ = idx.save(nostr_dir);
				}
				// Repair: ensure identity #1 is always represented (it is the
				// rollback anchor), without disturbing the active pointer.
				if !idx.contains(&legacy_hex) {
					idx.identities.push(HeldEntry {
						pubkey: legacy_hex.clone(),
						path: LEGACY_FILE.to_string(),
						label: label_for(legacy),
					});
					if !idx.order.contains(&legacy_hex) {
						idx.order.push(legacy_hex.clone());
					}
					let _ = idx.save(nostr_dir);
				}
				// Resolve the active identity; if its file is missing/corrupt,
				// fall back to identity #1 so the wallet always has a running
				// identity rather than none.
				let active = idx
					.active_entry()
					.and_then(|e| e.load(nostr_dir))
					.or_else(|| {
						idx.active = legacy_hex.clone();
						let _ = idx.save(nostr_dir);
						Some(legacy.clone())
					})?;
				Some((idx, active))
			}
			None => {
				// Legacy layout: adopt identity.json as the sole, active identity.
				let idx = Self::from_legacy(legacy)?;
				let _ = idx.save(nostr_dir);
				Some((idx, legacy.clone()))
			}
		}
	}

	/// Add an already-built identity to the set (does NOT change the active
	/// pointer). Writes the identity's file under `identities/<hex>/` and records
	/// the entry. Enforces the cap and dedupe. Returns the new entry's hex.
	pub fn add(
		&mut self,
		nostr_dir: &PathBuf,
		identity: &NostrIdentity,
	) -> Result<String, HeldError> {
		let hex = identity.pubkey_hex().ok_or(HeldError::BadPubkey)?;
		if self.contains(&hex) {
			return Err(HeldError::AlreadyHeld);
		}
		if !self.has_room() {
			return Err(HeldError::AtCapacity);
		}
		let rel = Self::rel_path_for(&hex);
		let mut abs = nostr_dir.clone();
		for seg in rel.split('/') {
			abs.push(seg);
		}
		identity
			.save_at(&abs)
			.map_err(|e| HeldError::Io(e.to_string()))?;
		self.identities.push(HeldEntry {
			pubkey: hex.clone(),
			path: rel,
			label: label_for(identity),
		});
		self.order.push(hex.clone());
		self.save(nostr_dir)
			.map_err(|e| HeldError::Io(e.to_string()))?;
		Ok(hex)
	}

	/// The file a given identity MUST be written to: its own entry's path when the
	/// wallet holds it, else the legacy `identity.json`.
	///
	/// Every writer of an identity file goes through this. Writing a non-primary
	/// identity to the fixed legacy path overwrites identity #1's encrypted key
	/// with the other identity's — the key is then unrecoverable and, because the
	/// index still points `hex1 -> identity.json`, the next open loads identity #2
	/// under identity #1's entry, so #1 vanishes from the switcher. That is a
	/// permanent identity loss, not a display glitch.
	pub fn path_for(&self, nostr_dir: &PathBuf, hex: &str) -> PathBuf {
		match self.entry(hex) {
			Some(e) => e.abs_path(nostr_dir),
			None => {
				let mut p = nostr_dir.clone();
				p.push(LEGACY_FILE);
				p
			}
		}
	}

	/// Repoint the PRIMARY entry (the one living in the legacy `identity.json`) at
	/// a different key, which the caller has already written to that file, and make
	/// it active. Keeps the index in step with disk: leaving the old pubkey on the
	/// `identity.json` entry would make the index describe a key that no longer
	/// exists there, which [`Self::load_or_migrate`] then drops as a mismatch.
	pub fn replace_primary(
		&mut self,
		nostr_dir: &PathBuf,
		identity: &NostrIdentity,
	) -> Result<(), HeldError> {
		let hex = identity.pubkey_hex().ok_or(HeldError::BadPubkey)?;
		let old = self
			.identities
			.iter()
			.find(|e| e.path == LEGACY_FILE)
			.map(|e| e.pubkey.clone());
		// The new key may already be held under its own file; that entry is now
		// redundant with the primary one, so drop it and keep a single entry.
		self.identities
			.retain(|e| e.pubkey != hex || e.path == LEGACY_FILE);
		self.order.retain(|h| h != &hex);
		match old {
			Some(old_hex) => {
				for e in self.identities.iter_mut() {
					if e.pubkey == old_hex && e.path == LEGACY_FILE {
						e.pubkey = hex.clone();
						e.label = label_for(identity);
					}
				}
				for h in self.order.iter_mut() {
					if h == &old_hex {
						*h = hex.clone();
					}
				}
			}
			None => {
				self.identities.push(HeldEntry {
					pubkey: hex.clone(),
					path: LEGACY_FILE.to_string(),
					label: label_for(identity),
				});
			}
		}
		if !self.order.contains(&hex) {
			self.order.push(hex.clone());
		}
		self.active = hex;
		self.save(nostr_dir)
			.map_err(|e| HeldError::Io(e.to_string()))
	}

	/// Move the active pointer to a held identity. The caller is responsible for
	/// tearing down and re-standing the service on the new key; this only records
	/// the choice so the next open lands on it too.
	pub fn set_active(&mut self, nostr_dir: &PathBuf, hex: &str) -> Result<(), HeldError> {
		if !self.contains(hex) {
			return Err(HeldError::NotHeld);
		}
		self.active = hex.to_string();
		self.save(nostr_dir)
			.map_err(|e| HeldError::Io(e.to_string()))
	}

	/// Re-encrypt every held identity's ncryptsec from `old` to `new`, in place
	/// on disk, ALL-OR-NOTHING. Used by the wallet-password change so all front
	/// doors follow the one password. A partial move (some identities on the new
	/// password, some still on the old) would be a split state the user cannot
	/// recover with a single password, so this stages every re-encryption to a
	/// sibling temp file first and only commits (renames into place) once EVERY
	/// identity has re-encrypted cleanly. Any phase-1 failure deletes the temps
	/// and leaves every identity untouched on the old password.
	pub fn reencrypt_all(
		&self,
		nostr_dir: &PathBuf,
		old: &str,
		new: &str,
	) -> Result<(), HeldError> {
		let suffix = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map(|d| d.as_nanos())
			.unwrap_or(0);
		// Phase 1: decrypt+re-encrypt every identity and stage it to a temp file
		// beside its target. Nothing is committed yet, so a failure here (wrong old
		// password, unreadable file, encrypt error) aborts the WHOLE change with
		// every identity still untouched on the old password, never a split.
		let mut staged: Vec<(PathBuf, PathBuf)> = Vec::new();
		let cleanup = |staged: &[(PathBuf, PathBuf)]| {
			for (tmp, _) in staged {
				let _ = fs::remove_file(tmp);
			}
		};
		for entry in &self.identities {
			let abs = entry.abs_path(nostr_dir);
			let Some(mut id) = NostrIdentity::load_at(&abs) else {
				cleanup(&staged);
				return Err(HeldError::Io(format!(
					"identity file unreadable: {}",
					entry.path
				)));
			};
			if let Err(e) = id.reencrypt(old, new) {
				cleanup(&staged);
				return Err(HeldError::Io(e.to_string()));
			}
			let tmp =
				abs.with_extension(format!("reencrypt-tmp-{}-{}", std::process::id(), suffix));
			if let Err(e) = id.save_at(&tmp) {
				cleanup(&staged);
				return Err(HeldError::Io(e.to_string()));
			}
			staged.push((tmp, abs));
		}
		// Phase 2: every identity re-encrypted cleanly; commit by renaming each
		// temp over its target. This window is small; a rename that still fails
		// returns an explicit error rather than pretending the change succeeded.
		for (tmp, abs) in &staged {
			if let Err(e) = fs::rename(tmp, abs) {
				return Err(HeldError::Io(format!(
					"committing re-encrypted identity {}: {e}",
					abs.display()
				)));
			}
		}
		Ok(())
	}
}

/// Errors from held-identity index operations. Carries no secret material.
#[derive(Debug, thiserror::Error)]
pub enum HeldError {
	#[error("that identity is already in this wallet")]
	AlreadyHeld,
	#[error("this wallet already holds the maximum number of identities")]
	AtCapacity,
	#[error("identity not held by this wallet")]
	NotHeld,
	#[error("identity has a malformed public key")]
	BadPubkey,
	#[error("identity store error: {0}")]
	Io(String),
}

/// A convenience label for an identity: the local part of its claimed NIP-05
/// name when it has one, else EMPTY (never a placeholder word — an unnamed
/// identity is shown by its truncated npub in the UI, not by a label). Never
/// includes secret material.
fn label_for(id: &NostrIdentity) -> String {
	id.nip05
		.as_deref()
		.and_then(|n| n.split('@').next())
		.filter(|s| !s.is_empty())
		.map(|s| s.to_string())
		.unwrap_or_default()
}

/// The catch-up `since` (unix seconds) for the identity we are bringing up. We
/// want to cover "since THIS identity last listened", not "since the wallet last
/// connected on any identity", so a payment that arrived while this identity was
/// dormant is fetched and redeemed on switch. Falls back to the wallet-wide last
/// connection, then to now, and always subtracts the same generous lookback so a
/// boundary payment is never missed. Pure — unit tested.
pub fn catchup_since(
	identity_last_active: Option<i64>,
	wallet_last_connected: Option<i64>,
	now: i64,
	lookback: i64,
) -> i64 {
	let base = identity_last_active
		.or(wallet_last_connected)
		.unwrap_or(now);
	(base - lookback).max(0)
}

/// Write a file with owner-only (0600) permissions on Unix.
fn write_private_0600(path: &PathBuf, data: &[u8]) -> std::io::Result<()> {
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
		let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
		Ok(())
	}
	#[cfg(not(unix))]
	{
		std::fs::write(path, data)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn tmpdir(tag: &str) -> PathBuf {
		let d = std::env::temp_dir().join(format!(
			"goblin-held-test-{tag}-{}-{:?}",
			std::process::id(),
			std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.unwrap()
				.as_nanos()
		));
		let _ = std::fs::create_dir_all(&d);
		d
	}

	#[test]
	fn migration_adopts_legacy_as_single_active_identity() {
		let dir = tmpdir("migrate");
		let (legacy, _) = NostrIdentity::create_random("pw").unwrap();
		legacy.save(&dir).unwrap(); // writes identity.json
		let legacy_hex = legacy.pubkey_hex().unwrap();

		// No index yet -> migrate.
		assert!(HeldIdentities::load(&dir).is_none());
		let (idx, active) = HeldIdentities::load_or_migrate(&dir, &legacy).unwrap();
		assert_eq!(idx.len(), 1);
		assert_eq!(idx.active, legacy_hex);
		assert_eq!(active.npub, legacy.npub);
		// Legacy entry points at the untouched identity.json.
		assert_eq!(idx.active_entry().unwrap().path, "identity.json");
		// Index now persisted and reloads identically.
		let reloaded = HeldIdentities::load(&dir).unwrap();
		assert_eq!(reloaded.active, legacy_hex);
		assert_eq!(reloaded.len(), 1);
		let _ = std::fs::remove_dir_all(&dir);
	}

	#[test]
	fn add_switch_and_cap() {
		let dir = tmpdir("addswitch");
		let (legacy, _) = NostrIdentity::create_random("pw").unwrap();
		legacy.save(&dir).unwrap();
		let (mut idx, _) = HeldIdentities::load_or_migrate(&dir, &legacy).unwrap();
		let legacy_hex = legacy.pubkey_hex().unwrap();

		// Add a second identity; active stays on #1 until we switch.
		let (second, _) = NostrIdentity::create_random("pw").unwrap();
		let second_hex = idx.add(&dir, &second).unwrap();
		assert_eq!(idx.len(), 2);
		assert_eq!(idx.active, legacy_hex);
		// It has its own file under identities/<hex>/.
		assert!(idx.entry(&second_hex).unwrap().load(&dir).is_some());

		// Dedupe: adding the same pubkey again is refused.
		assert!(matches!(
			idx.add(&dir, &second),
			Err(HeldError::AlreadyHeld)
		));

		// Switch active pointer.
		idx.set_active(&dir, &second_hex).unwrap();
		assert_eq!(idx.active, second_hex);
		// Persisted.
		assert_eq!(HeldIdentities::load(&dir).unwrap().active, second_hex);
		// Switching to an unknown identity is refused.
		assert!(matches!(
			idx.set_active(&dir, "deadbeef"),
			Err(HeldError::NotHeld)
		));

		// Fill to the cap and assert the (N+1)th is rejected.
		while idx.has_room() {
			let (extra, _) = NostrIdentity::create_random("pw").unwrap();
			idx.add(&dir, &extra).unwrap();
		}
		assert_eq!(idx.len(), MAX_IDENTITIES);
		let (overflow, _) = NostrIdentity::create_random("pw").unwrap();
		assert!(matches!(
			idx.add(&dir, &overflow),
			Err(HeldError::AtCapacity)
		));
		let _ = std::fs::remove_dir_all(&dir);
	}

	#[test]
	fn active_resolves_after_reload_and_survives_switch() {
		let dir = tmpdir("resolve");
		let (legacy, _) = NostrIdentity::create_random("pw").unwrap();
		legacy.save(&dir).unwrap();
		let (mut idx, _) = HeldIdentities::load_or_migrate(&dir, &legacy).unwrap();
		let (second, _) = NostrIdentity::create_random("pw").unwrap();
		let second_hex = idx.add(&dir, &second).unwrap();
		idx.set_active(&dir, &second_hex).unwrap();

		// Reopen: load_or_migrate must return the ACTIVE identity (#2), and the
		// legacy identity.json must be UNCHANGED (still identity #1 for rollback).
		let (reidx, active) = HeldIdentities::load_or_migrate(&dir, &legacy).unwrap();
		assert_eq!(reidx.active, second_hex);
		assert_eq!(active.npub, second.npub);
		let legacy_on_disk = NostrIdentity::load(&dir).unwrap();
		assert_eq!(legacy_on_disk.npub, legacy.npub);
		let _ = std::fs::remove_dir_all(&dir);
	}

	#[test]
	fn corrupt_index_active_falls_back_to_legacy() {
		let dir = tmpdir("fallback");
		let (legacy, _) = NostrIdentity::create_random("pw").unwrap();
		legacy.save(&dir).unwrap();
		let legacy_hex = legacy.pubkey_hex().unwrap();
		// Index points active at an identity whose file does not exist.
		let idx = HeldIdentities {
			ver: 1,
			active: "00ff00ff".repeat(8),
			order: vec![legacy_hex.clone()],
			identities: vec![HeldEntry {
				pubkey: legacy_hex.clone(),
				path: "identity.json".to_string(),
				label: String::new(),
			}],
		};
		idx.save(&dir).unwrap();
		let (repaired, active) = HeldIdentities::load_or_migrate(&dir, &legacy).unwrap();
		// Falls back to identity #1 rather than leaving no running identity.
		assert_eq!(active.npub, legacy.npub);
		assert_eq!(repaired.active, legacy_hex);
		let _ = std::fs::remove_dir_all(&dir);
	}

	#[test]
	fn saving_a_non_primary_identity_never_clobbers_identity_one() {
		// THE identity-loss regression. Saving the ACTIVE identity (e.g. after a
		// name claim or advertised-relay selection) used to go to the fixed legacy
		// identity.json, so any save made while identity #2 was active overwrote
		// identity #1's encrypted key with #2's — #1 unrecoverable, and gone from
		// the switcher on the next open. `path_for` must route each identity to its
		// OWN file.
		let dir = tmpdir("noclobber");
		let (legacy, _) = NostrIdentity::create_random("pw").unwrap();
		legacy.save(&dir).unwrap();
		let legacy_hex = legacy.pubkey_hex().unwrap();
		let (mut idx, _) = HeldIdentities::load_or_migrate(&dir, &legacy).unwrap();
		let (second, _) = NostrIdentity::create_random("pw").unwrap();
		let second_hex = idx.add(&dir, &second).unwrap();
		idx.set_active(&dir, &second_hex).unwrap();

		// Mutate and save identity #2 exactly as the service does.
		let mut active = idx.entry(&second_hex).unwrap().load(&dir).unwrap();
		active.dm_relays = vec!["wss://relay.example".to_string()];
		active.save_at(&idx.path_for(&dir, &second_hex)).unwrap();

		// identity.json still holds identity #1, untouched.
		let primary_on_disk = NostrIdentity::load(&dir).unwrap();
		assert_eq!(
			primary_on_disk.npub, legacy.npub,
			"saving identity #2 must not overwrite identity #1's key file"
		);
		// Both identities still resolve, each to its own key, and the mutation stuck.
		let (reidx, _) = HeldIdentities::load_or_migrate(&dir, &legacy).unwrap();
		assert_eq!(reidx.len(), 2, "both identities must survive the save");
		assert_eq!(
			reidx.entry(&legacy_hex).unwrap().load(&dir).unwrap().npub,
			legacy.npub
		);
		let reloaded_second = reidx.entry(&second_hex).unwrap().load(&dir).unwrap();
		assert_eq!(reloaded_second.npub, second.npub);
		assert_eq!(reloaded_second.dm_relays, vec!["wss://relay.example"]);
		// An identity the index does not hold falls back to the legacy path.
		assert_eq!(
			idx.path_for(&dir, "not-held"),
			NostrIdentity::path(&dir),
			"an unheld identity has no file of its own"
		);
		let _ = std::fs::remove_dir_all(&dir);
	}

	#[test]
	fn stale_entry_pointing_at_another_key_is_dropped_on_load() {
		// A wallet already damaged by the old writer: identity.json holds identity
		// #2's key while the index still claims it holds #1. Loading must not report
		// identity #2 twice (once per entry) — the entry that lies about disk is
		// dropped, so the switcher shows only what the wallet can really open.
		let dir = tmpdir("mismatch");
		let (legacy, _) = NostrIdentity::create_random("pw").unwrap();
		legacy.save(&dir).unwrap();
		let legacy_hex = legacy.pubkey_hex().unwrap();
		let (mut idx, _) = HeldIdentities::load_or_migrate(&dir, &legacy).unwrap();
		let (second, _) = NostrIdentity::create_random("pw").unwrap();
		let second_hex = idx.add(&dir, &second).unwrap();
		idx.set_active(&dir, &second_hex).unwrap();
		// The old bug: identity #2 written over identity.json.
		second.save(&dir).unwrap();

		let damaged = NostrIdentity::load(&dir).unwrap();
		let (healed, active) = HeldIdentities::load_or_migrate(&dir, &damaged).unwrap();
		assert_eq!(healed.len(), 1, "the lying entry must be dropped");
		assert!(
			!healed.contains(&legacy_hex),
			"identity #1 is gone from disk and must not be listed as switchable"
		);
		assert_eq!(healed.active, second_hex);
		assert_eq!(active.npub, second.npub);
		assert!(!healed.order.contains(&legacy_hex));
		let _ = std::fs::remove_dir_all(&dir);
	}

	#[test]
	fn replace_primary_repoints_the_index_at_the_new_key() {
		// Import-over-primary writes a new key into identity.json; the index must
		// follow, or the next open drops the now-mismatched entry and the import
		// silently disappears.
		let dir = tmpdir("replaceprimary");
		let (legacy, _) = NostrIdentity::create_random("pw").unwrap();
		legacy.save(&dir).unwrap();
		let legacy_hex = legacy.pubkey_hex().unwrap();
		let (mut idx, _) = HeldIdentities::load_or_migrate(&dir, &legacy).unwrap();
		let (other, _) = NostrIdentity::create_random("pw").unwrap();
		let other_hex = idx.add(&dir, &other).unwrap();

		let (imported, _) = NostrIdentity::create_random("pw").unwrap();
		let imported_hex = imported.pubkey_hex().unwrap();
		imported.save(&dir).unwrap();
		idx.replace_primary(&dir, &imported).unwrap();

		assert!(
			!idx.contains(&legacy_hex),
			"the replaced key is no longer held"
		);
		assert_eq!(idx.active, imported_hex, "the import becomes active");
		assert_eq!(idx.entry(&imported_hex).unwrap().path, "identity.json");
		assert!(idx.contains(&other_hex), "other identities are untouched");
		assert_eq!(idx.order.len(), 2);
		// Survives a reload with no entry dropped as a mismatch.
		let (reidx, active) = HeldIdentities::load_or_migrate(&dir, &imported).unwrap();
		assert_eq!(reidx.len(), 2);
		assert_eq!(active.npub, imported.npub);
		let _ = std::fs::remove_dir_all(&dir);
	}

	#[test]
	fn reencrypt_all_moves_every_identity_to_new_password() {
		let dir = tmpdir("reencrypt");
		let (legacy, _) = NostrIdentity::create_random("old").unwrap();
		legacy.save(&dir).unwrap();
		let (mut idx, _) = HeldIdentities::load_or_migrate(&dir, &legacy).unwrap();
		let (second, _) = NostrIdentity::create_random("old").unwrap();
		idx.add(&dir, &second).unwrap();

		idx.reencrypt_all(&dir, "old", "new").unwrap();
		for entry in &idx.identities {
			let id = entry.load(&dir).unwrap();
			assert!(id.unlock("new").is_ok(), "must open under the new password");
			assert!(id.unlock("old").is_err(), "must not open under the old one");
		}
		let _ = std::fs::remove_dir_all(&dir);
	}

	#[test]
	fn reencrypt_all_is_all_or_nothing() {
		// Two held identities, one with a corrupted ncryptsec so its decrypt (and
		// thus the whole re-encryption) fails. The batch must fail AND leave the
		// other identity untouched on the OLD password (no partial move).
		let dir = tmpdir("allornothing");
		let (legacy, _) = NostrIdentity::create_random("old").unwrap();
		legacy.save(&dir).unwrap();
		let legacy_hex = legacy.pubkey_hex().unwrap();
		let (mut idx, _) = HeldIdentities::load_or_migrate(&dir, &legacy).unwrap();
		let (second, _) = NostrIdentity::create_random("old").unwrap();
		let second_hex = idx.add(&dir, &second).unwrap();

		// Corrupt the second identity's ncryptsec on disk.
		let second_abs = idx.entry(&second_hex).unwrap().abs_path(&dir);
		let mut broken = NostrIdentity::load_at(&second_abs).unwrap();
		broken.ncryptsec = "ncryptsec1qqqqqbroken".to_string();
		broken.save_at(&second_abs).unwrap();

		// All-or-nothing: the batch fails...
		assert!(
			idx.reencrypt_all(&dir, "old", "new").is_err(),
			"a failing identity must abort the whole re-encryption"
		);
		// ...and the untouched legacy identity still opens under the OLD password,
		// never having been committed to the new one.
		let legacy_still = idx.entry(&legacy_hex).unwrap().load(&dir).unwrap();
		assert!(
			legacy_still.unlock("old").is_ok(),
			"untouched identity must still open under the old password"
		);
		assert!(
			legacy_still.unlock("new").is_err(),
			"untouched identity must not have moved to the new password"
		);
		// No temp files left behind after the aborted batch.
		let leftovers: Vec<_> = std::fs::read_dir(&dir)
			.unwrap()
			.filter_map(|e| e.ok())
			.filter(|e| e.file_name().to_string_lossy().contains("reencrypt-tmp"))
			.collect();
		assert!(
			leftovers.is_empty(),
			"aborted batch must clean up its temps"
		);
		let _ = std::fs::remove_dir_all(&dir);
	}

	#[test]
	fn imported_nsec_adds_as_held_identity_and_unlocks() {
		// The multi-identity import path: a bare nsec becomes a held identity via
		// the same NIP-49 encrypted store, keyed by its own pubkey, openable under
		// the wallet password. (Regression guard for the add-import flow.)
		use nostr_sdk::{Keys, ToBech32};
		let dir = tmpdir("import");
		let (legacy, _) = NostrIdentity::create_random("pw").unwrap();
		legacy.save(&dir).unwrap();
		let (mut idx, _) = HeldIdentities::load_or_migrate(&dir, &legacy).unwrap();

		// A distinct external key, as an nsec string.
		let ext = Keys::generate();
		let nsec = ext.secret_key().to_bech32().unwrap();
		let (imported, _) = NostrIdentity::create_imported(&nsec, "pw").unwrap();
		let hex = idx.add(&dir, &imported).unwrap();

		// Held, active pointer unchanged (add never switches), file openable.
		assert_eq!(idx.len(), 2);
		assert_eq!(idx.active, legacy.pubkey_hex().unwrap());
		let stored = idx.entry(&hex).unwrap().load(&dir).unwrap();
		assert_eq!(stored.source, crate::nostr::IdentitySource::Imported);
		assert_eq!(stored.unlock("pw").unwrap().public_key(), ext.public_key());
		let _ = std::fs::remove_dir_all(&dir);
	}

	#[test]
	fn held_index_parse_is_forward_compatible() {
		// A blob in the CURRENT format plus an unknown extra field still parses
		// (unknown fields ignored), so a newer build's index is not rejected.
		let idx: HeldIdentities = serde_json::from_str(
			r#"{"ver":1,"active":"ab","order":["ab"],"identities":[{"pubkey":"ab","path":"identity.json","label":"","future_field":true}],"future_top":42}"#,
		)
		.unwrap();
		assert_eq!(idx.ver, 1);
		assert_eq!(idx.active, "ab");
		assert_eq!(idx.len(), 1);
		// A blob MISSING non-essential fields parses with the correct defaults:
		// ver -> 1, order/identities -> empty, active -> empty.
		let idx: HeldIdentities = serde_json::from_str(r#"{"active":"cd"}"#).unwrap();
		assert_eq!(idx.ver, 1, "ver must default to 1");
		assert_eq!(idx.active, "cd");
		assert!(idx.order.is_empty());
		assert!(idx.identities.is_empty());
		// A HeldEntry missing its label still parses (label defaults empty).
		let idx: HeldIdentities = serde_json::from_str(
			r#"{"ver":1,"active":"ab","order":["ab"],"identities":[{"pubkey":"ab","path":"identity.json"}]}"#,
		)
		.unwrap();
		assert_eq!(idx.identities[0].label, "");
	}

	#[test]
	fn catchup_since_prefers_identity_then_wallet_then_now() {
		let lookback = 3 * 86_400;
		let now = 1_000_000;
		// Per-identity value wins: cover from when THIS identity last listened.
		assert_eq!(
			catchup_since(Some(500_000), Some(900_000), now, lookback),
			500_000 - lookback
		);
		// Falls back to the wallet-wide last connection when the identity has none.
		assert_eq!(
			catchup_since(None, Some(900_000), now, lookback),
			900_000 - lookback
		);
		// Falls back to now when nothing is known (never worse than a fresh start).
		assert_eq!(catchup_since(None, None, now, lookback), now - lookback);
		// Never negative.
		assert_eq!(catchup_since(Some(10), None, now, lookback), 0);
	}
}
