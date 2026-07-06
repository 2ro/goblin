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
use std::sync::Mutex;

/// Serializes the whole load-bump-persist in [`allocate`] across threads. The
/// counter lives in a file, so without this two concurrent mints would each
/// read the same `next`, hand out the SAME derivation index, and mis-address a
/// payment proof (money path). This process-wide lock makes allocation one
/// atomic step so every index handed out is unique.
static ALLOC_LOCK: Mutex<()> = Mutex::new(());

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
	// One allocation at a time. Without this the load-bump-persist below is a
	// racy read-modify-write and two concurrent mints hand out the same index.
	let _guard = ALLOC_LOCK
		.lock()
		.map_err(|_| "proof-address allocator lock poisoned".to_string())?;
	let mut reg = load_registry(path)?;
	let index = reg.next;
	if index > MAX_PROOF_ADDRESS_INDEX {
		return Err("proof address space exhausted".to_string());
	}
	reg.next = index + 1;
	persist_registry(path, &reg)?;
	Ok(index)
}

/// Load the persisted counter. A MISSING file is the fresh-wallet case and
/// defaults to `{ver:1, next:1}`. A file that EXISTS but cannot be read or
/// parsed is REFUSED (`Err`) rather than silently reset: resetting the counter
/// to 1 would re-hand-out already-minted indices and reuse an address, so a
/// corrupt registry must stop minting, not quietly start over. Unknown extra
/// fields are ignored (forward-compat), so only genuinely malformed content
/// refuses.
fn load_registry(path: &PathBuf) -> Result<ProofAddrRegistry, String> {
	match std::fs::read_to_string(path) {
		Ok(raw) => serde_json::from_str(&raw)
			.map_err(|e| format!("proof-address registry is corrupt, refusing to allocate: {e}")),
		Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ProofAddrRegistry::default()),
		Err(e) => Err(format!("proof-address registry unreadable: {e}")),
	}
}

/// Persist the counter atomically: write a sibling temp file in the SAME
/// directory, flush it, then rename it over the target. The rename is atomic, so
/// a crash mid-write can never leave a half-written (and then corrupt-refused)
/// registry, and a reader never sees a torn file.
fn persist_registry(path: &PathBuf, reg: &ProofAddrRegistry) -> Result<(), String> {
	use std::io::Write;
	let raw = serde_json::to_string(reg).map_err(|e| e.to_string())?;
	let suffix = std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|d| d.as_nanos())
		.unwrap_or(0);
	// Sibling of the target (same directory, so the rename stays on one volume).
	let tmp = path.with_extension(format!("tmp-{}-{}", std::process::id(), suffix));
	{
		let mut f = std::fs::File::create(&tmp).map_err(|e| e.to_string())?;
		f.write_all(raw.as_bytes()).map_err(|e| e.to_string())?;
		let _ = f.sync_all();
	}
	std::fs::rename(&tmp, path).map_err(|e| {
		let _ = std::fs::remove_file(&tmp);
		e.to_string()
	})
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
	fn corrupt_registry_refuses() {
		// A corrupt counter must REFUSE rather than silently restart at 1:
		// restarting would re-hand-out an already-minted index and reuse an
		// address (a mis-addressed payment proof), so a corrupt registry stops
		// minting instead of quietly starting over. Only a MISSING file defaults.
		let path = tmpfile("corrupt");
		std::fs::write(&path, "not json").unwrap();
		assert!(allocate(&path).is_err(), "corrupt registry must refuse");
		let _ = std::fs::remove_file(&path);
	}

	#[test]
	fn missing_file_defaults_but_present_survives() {
		// A missing file is the fresh-wallet case: default and allocate 1.
		let path = tmpfile("missing");
		assert_eq!(allocate(&path).unwrap(), 1);
		// After the first allocate the file exists and the counter persisted.
		assert_eq!(allocate(&path).unwrap(), 2);
		let _ = std::fs::remove_file(&path);
	}

	#[test]
	fn concurrent_allocation_hands_out_unique_indices() {
		use std::collections::HashSet;
		// Many threads racing on one shared registry must never hand out the same
		// index twice, which is exactly what the allocator lock prevents.
		let path = tmpfile("concurrent");
		let threads = 8usize;
		let per_thread = 6usize;
		let mut handles = Vec::new();
		for _ in 0..threads {
			let p = path.clone();
			handles.push(std::thread::spawn(move || {
				let mut got = Vec::with_capacity(per_thread);
				for _ in 0..per_thread {
					got.push(allocate(&p).unwrap());
				}
				got
			}));
		}
		let mut all = Vec::new();
		for h in handles {
			all.extend(h.join().unwrap());
		}
		let total = threads * per_thread;
		assert_eq!(all.len(), total);
		let unique: HashSet<u32> = all.iter().copied().collect();
		assert_eq!(unique.len(), total, "every allocated index must be unique");
		// Counter started at 1, so after `total` allocations `next` == 1 + total.
		let reg: ProofAddrRegistry =
			serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
		assert_eq!(reg.next, 1 + total as u32);
		let _ = std::fs::remove_file(&path);
	}
}
