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

//! Per-sale proof-address INDEX allocator. One wallet has one slatepack/proof
//! address per derivation index (`address_from_derivation_path`); index 0 is
//! the app's default address and every per-offer/per-sale address is minted at
//! the next fresh index, so no two sales ever share an address. This registry
//! is just the persisted allocation counter — the keys themselves live in the
//! wallet seed (an index carries no secret; the file only reveals how many
//! addresses were minted). Indices are single-use and never reused: a burned
//! index (minted but the offer never completed) is simply skipped forever.
//!
//! The allocator must stay at or below the receive-side scan bound — the
//! (patched) wallet receive path detects which allocated address a
//! payment-proof slate is addressed to by scanning `0..=bound`, and an index
//! outside it could not be detected, so its proof would be signed with the
//! wrong key and fail the sender's check.

use serde_derive::{Deserialize, Serialize};
use std::path::PathBuf;

/// Highest allocatable proof-address derivation index. MUST equal the wallet
/// receive path's scan bound (`address::MAX_PROOF_ADDRESS_INDEX` in the
/// grin-wallet submodule patch) — kept as a local constant so this crate also
/// builds against the unpatched upstream submodule.
pub const MAX_PROOF_ADDRESS_INDEX: u32 = 1023;

/// The persisted allocation state: the next index to hand out. Index 0 is the
/// app's default address, so per-sale allocation starts at 1.
#[derive(Serialize, Deserialize, Clone, Debug)]
struct ProofAddrRegistry {
	ver: u8,
	next: u32,
}

impl Default for ProofAddrRegistry {
	fn default() -> Self {
		Self { ver: 1, next: 1 }
	}
}

/// Allocate the next fresh proof-address derivation index, persisting the
/// counter at `path` (a JSON file in the wallet's data dir). Starts at 1
/// (index 0 is the default app address), increments monotonically, and
/// refuses to allocate past the receive-side scan bound. The counter is
/// persisted BEFORE the index is returned, so a crash after allocation burns
/// the index rather than ever reusing it.
pub fn allocate(path: &PathBuf) -> Result<u32, String> {
	let mut reg: ProofAddrRegistry = std::fs::read_to_string(path)
		.ok()
		.and_then(|raw| serde_json::from_str(&raw).ok())
		.unwrap_or_default();
	let index = reg.next;
	if index > MAX_PROOF_ADDRESS_INDEX {
		return Err("proof address space exhausted".to_string());
	}
	reg.next = index + 1;
	let raw = serde_json::to_string(&reg).map_err(|e| e.to_string())?;
	std::fs::write(path, raw).map_err(|e| e.to_string())?;
	Ok(index)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn tmpfile(tag: &str) -> PathBuf {
		std::env::temp_dir().join(format!(
			"goblin-proofaddr-{tag}-{}-{:?}.json",
			std::process::id(),
			std::time::SystemTime::now()
				.duration_since(std::time::UNIX_EPOCH)
				.unwrap()
				.as_nanos()
		))
	}

	#[test]
	fn allocates_monotonically_from_one_and_persists() {
		let path = tmpfile("mono");
		// Index 0 is the app address: per-sale minting starts at 1.
		assert_eq!(allocate(&path).unwrap(), 1);
		assert_eq!(allocate(&path).unwrap(), 2);
		assert_eq!(allocate(&path).unwrap(), 3);
		// Persistence: a fresh load (new call, same file) continues, never reuses.
		assert_eq!(allocate(&path).unwrap(), 4);
		let _ = std::fs::remove_file(&path);
	}

	#[test]
	fn refuses_past_receive_scan_bound() {
		let path = tmpfile("cap");
		// Pre-seed the counter at the bound: the last index allocates, then stop.
		let max = MAX_PROOF_ADDRESS_INDEX;
		std::fs::write(&path, format!("{{\"ver\":1,\"next\":{}}}", max)).unwrap();
		assert_eq!(allocate(&path).unwrap(), max);
		assert!(allocate(&path).is_err(), "past the scan bound must refuse");
		let _ = std::fs::remove_file(&path);
	}

	#[test]
	fn corrupt_registry_restarts_at_one() {
		// A corrupt counter must not brick minting; restarting at 1 can re-hand
		// out an index, which at worst reuses an address (same as the old
		// single-address world) — never a fund risk.
		let path = tmpfile("corrupt");
		std::fs::write(&path, "not json").unwrap();
		assert_eq!(allocate(&path).unwrap(), 1);
		let _ = std::fs::remove_file(&path);
	}
}
