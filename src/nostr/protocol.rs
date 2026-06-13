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

//! Goblin payment message protocol over NIP-17 (kind 14 rumors).
//!
//! Content layout: a one-line human readable preamble, a blank line and the
//! raw slatepack armor. The per-payment note travels in the standard
//! `subject` tag; a `goblin` tag marks the protocol version. Classification
//! NEVER trusts tags — only the parsed slate.

use nostr_sdk::{Tag, TagKind, Tags};
use regex::Regex;
use std::sync::LazyLock;

/// Maximum gift wrap content size accepted before unwrapping.
pub const MAX_WRAP_CONTENT: usize = 64 * 1024;
/// Maximum rumor content size accepted after unwrapping.
pub const MAX_RUMOR_CONTENT: usize = 32 * 1024;
/// Maximum slatepack armor size accepted.
pub const MAX_SLATEPACK: usize = 30 * 1024;
/// Maximum note length in characters after sanitization.
pub const MAX_NOTE_CHARS: usize = 256;
/// Protocol marker tag name.
pub const GOBLIN_TAG: &str = "goblin";
/// Protocol version value.
pub const PROTOCOL_VERSION: &str = "1";

/// Human readable preamble other NIP-17 clients render.
pub const PREAMBLE: &str =
	"[Goblin] GRIN payment message — open in Goblin (https://goblin.st) to process.";

static SLATEPACK_RE: LazyLock<Regex> = LazyLock::new(|| {
	Regex::new(r"BEGINSLATEPACK\.[\s\S]*?ENDSLATEPACK\.").expect("slatepack regex")
});

/// Sanitize a user note: strip control characters, collapse whitespace,
/// trim and cap the length. Returns `None` when nothing readable remains.
pub fn sanitize_note(raw: &str) -> Option<String> {
	let cleaned: String = raw
		.chars()
		.map(|c| if c.is_control() { ' ' } else { c })
		.collect();
	let collapsed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
	let trimmed = collapsed.trim();
	if trimmed.is_empty() {
		return None;
	}
	Some(trimmed.chars().take(MAX_NOTE_CHARS).collect())
}

/// Build the kind-14 rumor content for a slatepack payment message.
pub fn build_payment_content(slatepack: &str) -> String {
	format!("{}\n\n{}", PREAMBLE, slatepack.trim())
}

/// Build rumor tags: protocol marker plus optional subject note.
pub fn build_rumor_tags(note: Option<&str>) -> Vec<Tag> {
	let mut tags = vec![Tag::custom(
		TagKind::custom(GOBLIN_TAG),
		[PROTOCOL_VERSION.to_string()],
	)];
	if let Some(note) = note.and_then(sanitize_note) {
		tags.push(Tag::custom(TagKind::custom("subject"), [note]));
	}
	tags
}

/// Extract exactly one slatepack armor block from rumor content.
/// More than one block, none at all, or an oversized block returns `None`.
pub fn extract_slatepack(content: &str) -> Option<String> {
	if content.len() > MAX_RUMOR_CONTENT {
		return None;
	}
	let mut matches = SLATEPACK_RE.find_iter(content);
	let first = matches.next()?;
	if matches.next().is_some() {
		// Multiple blocks: ambiguous, refuse.
		return None;
	}
	let armor = first.as_str().trim().to_string();
	if armor.len() > MAX_SLATEPACK {
		return None;
	}
	Some(armor)
}

/// Read the sanitized subject (note) from rumor tags.
pub fn extract_subject(tags: &Tags) -> Option<String> {
	for tag in tags.iter() {
		let parts = tag.as_slice();
		if parts.first().map(|s| s.as_str()) == Some("subject") {
			if let Some(value) = parts.get(1) {
				return sanitize_note(value);
			}
		}
	}
	None
}

#[cfg(test)]
mod tests {
	use super::*;

	const PACK: &str = "BEGINSLATEPACK. 4H1qx1wHe668tFW yC2gfL8PPd8kSgv \
		pcXQhyRkHbyKHZg GN75o7uWoT3dkib R2tj1fFGN2FoRLY oeBPyKizupksgRT \
		dXFdjEuMUuktR5r gCiVBSXcHSWW3KW Y56LTQ9z3QwUWmE 8sRtwR9Bn8oNN5K \
		bRGBoQbtTNCb12u DBMTNGsCT7iqGd3 7Sya3iCMu9PdcKW QzL3Wh4qsuTRMyL \
		R3Atup1Bf3wgEbi ENMmTon9zFMD3fE 2muWLSZJYnSbN16 89zvvW45w3sQekX \
		7d6FGCdJqDXfsmt Gh3CSNNRz7emxZw uHEDFmYqgUkSCk2 ZXAeFCSWZ3nogyB \
		o9LL75ZAYTbAQ3d e1bQAGmiKWWQAJ8 oCWk5NHnf6QJhLB ZAtNYUiBu6dgNRM \
		ZqxYBhWHtcSkpFn PmJh1nLDfyTbAmM 1AQpoxFBRMUyDmf nNZ75bL5xX9KQVB \
		C1q4HEgqgRtAvNo 1deUSPYsCfRZ1Wd k2Lqo6w8oCe2cyU rMcLnRYrFgL27dT \
		gZBYLgAfqqHRWaR cnNnnXMNpdNuQbe ojMNMTBuFFHJSus PCBVcvHGEKnYHWS \
		W3PCH1MFowyfDxX 4D3DcsGnSAEAxFt 9rEzNuKbcKEfL9z gKVQoCKqzUXVNCZ \
		jaG7M8B7etApvXr i1qzezfk7rTQz1k 6XJDjFb1JoTL5wo bSdkzfXJDBfWtAB \
		gVMVkSdSXgcZqWS XL4MwBR8VfPv78s g7eRJVuRrBaQTKn xGRT7keqLBPMRRA \
		LXkPDgQpHWpFei4 fnUVcuV4EWXarmm 3a1tBZpAvgTKuvF mvVAyeJTagrEXrS \
		J2scK99rjQuLpAZ 1135LqkGfMQRmkN 4cWEoYzM3U6BS2y mD3sCctEMNHJKKa \
		amGfXo16VLEjvw1 LvAVGFqyo64UQHV V63ufGc3qZkZcSU 1bSaCSDsKs8jzkz \
		6jztk3DqqUiZBV3 reNzHKAEhMCfWtD W9STzaTwiakwwGq mcsHcUVJ9SVi7Hd \
		1cKB9PNJ6FRJUjh AHWoaXBHRRGCNcm fpPMA9Hxn3BNXgs 8gDosk8mTpnDFRA \
		uYbA8eX4d2BG2Hd YsApEnjGBkXuXdg eEdyDvfqQEUDRRG iAjp6X5ZQ6JCNYP \
		LFNAFwkjqQ8XqRs aXmDgYTV4hpVtuc 5w69tnULM7vEnXm 14tHK9GktqgNBVy \
		LJiVf8feoFc1Lao MEXVJSdpu7sUSn2 8Mz9zPS7XJWyAyT 36WuJSx7DjMpnB2 \
		2vqXAjMwYAXmL2V Vmm2Y8wmhomBd1A YwPmTKAm5gFBL5W RkAGUJxq46DCWbz \
		mzaBhLqswMGcRUf qmiPiQGqGEMnyQy yMa2HSc9wbXc78d 8GCkRgYepCFK7tC \
		Ynw5HuANFLBJgXM zYbR6XLkP8cSC7. ENDSLATEPACK.";

	#[test]
	fn extracts_single_slatepack() {
		let content = format!("{}\n\n{}", PREAMBLE, PACK);
		let got = extract_slatepack(&content).unwrap();
		assert!(got.starts_with("BEGINSLATEPACK."));
		assert!(got.ends_with("ENDSLATEPACK."));
	}

	#[test]
	fn rejects_no_slatepack() {
		assert!(extract_slatepack("hi there, no payment here").is_none());
		assert!(extract_slatepack("").is_none());
		assert!(extract_slatepack("BEGINSLATEPACK. truncated junk").is_none());
	}

	#[test]
	fn rejects_two_slatepacks() {
		let content = format!("{} {}", PACK, PACK);
		assert!(extract_slatepack(&content).is_none());
	}

	#[test]
	fn rejects_oversize() {
		let huge = format!(
			"BEGINSLATEPACK. {} ENDSLATEPACK.",
			"A".repeat(MAX_SLATEPACK + 1)
		);
		assert!(extract_slatepack(&huge).is_none());
		let oversize_content = "x".repeat(MAX_RUMOR_CONTENT + 1);
		assert!(extract_slatepack(&oversize_content).is_none());
	}

	#[test]
	fn sanitizes_notes() {
		assert_eq!(sanitize_note("  lunch :)  "), Some("lunch :)".to_string()));
		assert_eq!(
			sanitize_note("a\u{0000}b\u{001b}[31mc"),
			Some("a b [31mc".to_string())
		);
		assert_eq!(
			sanitize_note("multi   space\n\nnewline"),
			Some("multi space newline".to_string())
		);
		assert_eq!(sanitize_note("\u{0007}\u{0008}"), None);
		assert_eq!(sanitize_note(""), None);
		let long = "y".repeat(MAX_NOTE_CHARS + 50);
		assert_eq!(
			sanitize_note(&long).unwrap().chars().count(),
			MAX_NOTE_CHARS
		);
	}

	#[test]
	fn builds_content_with_preamble() {
		let c = build_payment_content(PACK);
		assert!(c.starts_with(PREAMBLE));
		assert!(extract_slatepack(&c).is_some());
	}
}
