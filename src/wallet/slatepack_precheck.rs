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

//! Goblin-side guard in front of the pinned grin-wallet Slatepack parser.
//!
//! The pinned parser (wallet submodule c2db7545) panics on some hostile input
//! instead of returning an error. On Android the release profile aborts on
//! panic, so one such message from a stranger crashes the app, and the catch-up
//! fetch replays it at every launch. [`precheck`] walks the same steps as the
//! parser and refuses input at the points where the parser would panic:
//!
//! - H1: armor framing without a footer period (armor.rs:85), a payload that
//!   decodes to fewer than 4 bytes (armor.rs:103), and payment proof keys or a
//!   signature the slate reader unwraps (v4_bin.rs:348-352).
//! - H2: an age payload with a passphrase (scrypt) stanza, which reaches
//!   `unreachable!()` in types.rs:202-205. An encrypted payload must also name
//!   at least one X25519 recipient.
//!
//! It never refuses a Slatepack the parser accepts: where the parser would
//! return an error anyway it may refuse early, and where it cannot tell it lets
//! the parser decide. The panics that follow a successful decryption
//! (types.rs:211-214) cannot be seen before decrypting; the nostr ingest
//! refuses encrypted Slatepacks outright for that reason.

use grin_util::secp::constants::MAX_PROOF_SIZE;
use grin_wallet_libwallet::slatepack::{max_size, min_size};
use grin_wallet_libwallet::{Slatepack, SlatepackBin};
use grin_wallet_util::OnionV3Address;
use grin_wallet_util::byte_ser;
use sha2::{Digest, Sha256};
use std::fmt;

/// Armor header, as armor.rs and packer.rs compare it.
const HEADER: &[u8] = b"BEGINSLATEPACK.";
/// Bytes armor.rs drops from the payload and allows around the framing words.
const WHITESPACE: [u8; 5] = [b'>', b'\n', b'\r', b'\t', b' '];
/// The Bitcoin base58 alphabet, the one bs58 decodes armor with.
const BASE58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
/// First line of an age v1 file.
const AGE_V1: &[u8] = b"age-encryption.org/v1\n";

/// What the precheck learned about a Slatepack it let through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SlatepackShape {
	/// Delivery mode: 0 is plain, anything else is decrypted by the parser.
	pub mode: u8,
}

/// Why a Slatepack was refused before the parser saw it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reject {
	/// Shorter or longer than the parser accepts.
	Size,
	/// Armor header or footer the parser would slice past or refuse.
	Framing,
	/// Not base58, or fewer than the 4 check bytes after decoding.
	Payload,
	/// The 4 check bytes do not match the data.
	Checksum,
	/// Neither a binary nor a JSON Slatepack.
	Unreadable,
	/// A payment proof key or signature the slate reader would unwrap.
	PaymentProof,
	/// Encrypted, but not an age file for X25519 recipients without a passphrase.
	Encryption,
}

impl fmt::Display for Reject {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(match self {
			Reject::Size => "size out of bounds",
			Reject::Framing => "bad armor framing",
			Reject::Payload => "bad or too short payload",
			Reject::Checksum => "check code mismatch",
			Reject::Unreadable => "not a binary or JSON slatepack",
			Reject::PaymentProof => "invalid payment proof key or signature",
			Reject::Encryption => "passphrase or no X25519 recipient",
		})
	}
}

/// Check a Slatepack message before handing it to the pinned parser.
///
/// Takes the text exactly as `Wallet::parse_slatepack` gets it; the trim
/// matches the one it applies before the controller sees the text.
pub fn precheck(text: &str) -> Result<SlatepackShape, Reject> {
	let data = text.trim().as_bytes();
	// packer.rs:53-57: the parser refuses these sizes before anything else.
	let len = data.len() as u64;
	if len < min_size() || len > max_size() {
		return Err(Reject::Size);
	}
	// packer.rs:59-70: armored text is unwrapped, anything else is read as is.
	let body = if data.starts_with(HEADER) {
		dearmor(data)?
	} else {
		data.to_vec()
	};
	let (mode, payload) = unpack(body)?;
	if mode == 0 {
		if proof_would_panic(&payload) {
			return Err(Reject::PaymentProof);
		}
	} else {
		check_age_recipients(&payload)?;
	}
	Ok(SlatepackShape { mode })
}

/// Mirror of `SlatepackArmor::decode` (armor.rs:64-107) with its slices and
/// its 4-byte split bounds-checked, as upstream d4867d5 does.
fn dearmor(data: &[u8]) -> Result<Vec<u8>, Reject> {
	let header_len = data.iter().take_while(|b| **b != b'.').count();
	if !framing_is(&data[..header_len], b"BEGINSLATEPACK") {
		return Err(Reject::Framing);
	}
	let payload_start = header_len + 1;
	let payload_source = data.get(payload_start..).ok_or(Reject::Framing)?;
	let payload_len = payload_source.iter().take_while(|b| **b != b'.').count();
	// armor.rs:85 slices here without a check: no period after the payload
	// means the footer starts past the end of the text.
	let footer_source = data
		.get(payload_start + payload_len + 1..)
		.ok_or(Reject::Framing)?;
	let footer_len = footer_source.iter().take_while(|b| **b != b'.').count();
	if !framing_is(&footer_source[..footer_len], b"ENDSLATEPACK") {
		return Err(Reject::Framing);
	}
	let clean: Vec<u8> = payload_source[..payload_len]
		.iter()
		.filter(|b| !WHITESPACE.contains(b))
		.cloned()
		.collect();
	let decoded = base58_decode(&clean).ok_or(Reject::Payload)?;
	// armor.rs:103 takes [0..4] without a check.
	if decoded.len() < 4 {
		return Err(Reject::Payload);
	}
	let (code, slatepack) = decoded.split_at(4);
	let check = Sha256::digest(Sha256::digest(slatepack));
	if code != &check[..4] {
		return Err(Reject::Checksum);
	}
	Ok(slatepack.to_vec())
}

/// The armor regexes (armor.rs:52-56) accept the word with only the armor
/// whitespace bytes around it.
fn framing_is(bytes: &[u8], word: &[u8]) -> bool {
	let start = bytes.iter().take_while(|b| WHITESPACE.contains(b)).count();
	let end = bytes.len()
		- bytes
			.iter()
			.rev()
			.take_while(|b| WHITESPACE.contains(b))
			.count();
	start <= end && &bytes[start..end] == word
}

/// Base58 decode as bs58 0.3.1 does it: leading '1's become zero bytes, any
/// byte outside the alphabet is an error.
fn base58_decode(input: &[u8]) -> Option<Vec<u8>> {
	// Little-endian accumulator, reversed at the end.
	let mut out: Vec<u8> = Vec::with_capacity(input.len());
	for c in input {
		let mut val = BASE58.iter().position(|a| a == c)? as u32;
		for byte in out.iter_mut() {
			val += (*byte as u32) * 58;
			*byte = (val & 0xFF) as u8;
			val >>= 8;
		}
		while val > 0 {
			out.push((val & 0xFF) as u8);
			val >>= 8;
		}
	}
	let zeros = input.iter().take_while(|c| **c == b'1').count();
	out.extend(std::iter::repeat_n(0, zeros));
	out.reverse();
	Some(out)
}

/// The parser's own binary-then-JSON read (packer.rs:72-86), returning the
/// delivery mode and payload it would go on with.
fn unpack(body: Vec<u8>) -> Result<(u8, Vec<u8>), Reject> {
	// The binary reader subtracts the sender address length from a header
	// field without a check (types.rs:361). Release builds wrap and then fail
	// at the end of the data; debug builds panic. Take the release outcome.
	if !sender_len_underflows(&body)
		&& let Ok(bin) = byte_ser::from_bytes::<SlatepackBin>(&body)
	{
		return Ok((bin.0.mode, bin.0.payload));
	}
	let content = String::from_utf8(body).map_err(|_| Reject::Unreadable)?;
	let slatepack: Slatepack = serde_json::from_str(&content).map_err(|_| Reject::Unreadable)?;
	Ok((slatepack.mode, slatepack.payload))
}

/// True when a binary Slatepack names a sender whose encoded length is larger
/// than the header's byte count to the payload.
fn sender_len_underflows(body: &[u8]) -> bool {
	// version (2), mode (1), flags (2), bytes to payload (4), address length (1)
	let (Some(flags), Some(skip), Some(addr_len)) = (body.get(3..5), body.get(5..9), body.get(9))
	else {
		return false;
	};
	let flags = u16::from_be_bytes([flags[0], flags[1]]);
	let skip = u32::from_be_bytes([skip[0], skip[1], skip[2], skip[3]]);
	// A parsed address re-encodes to its own length, plus the length byte.
	flags & 0x01 != 0 && (skip as u64) < (*addr_len as u64) + 1
}

/// Byte reader over a plain slate payload that says None at the end of data.
struct Bytes<'a>(&'a [u8]);

impl<'a> Bytes<'a> {
	fn take(&mut self, n: usize) -> Option<&'a [u8]> {
		if self.0.len() < n {
			return None;
		}
		let (head, tail) = self.0.split_at(n);
		self.0 = tail;
		Some(head)
	}

	fn u8(&mut self) -> Option<u8> {
		self.take(1).map(|b| b[0])
	}

	fn u16(&mut self) -> Option<u16> {
		self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
	}

	fn u64(&mut self) -> Option<u64> {
		let mut a = [0u8; 8];
		a.copy_from_slice(self.take(8)?);
		Some(u64::from_be_bytes(a))
	}
}

/// True when the pinned `ProofWrap` reader (v4_bin.rs:347-355) would unwrap an
/// invalid key or signature in this binary slate. The walk only counts bytes
/// the way `SlateV4Bin::read` (v4_bin.rs:451-489) consumes them; anything it
/// cannot follow is left to the parser, which then fails on its own.
fn proof_would_panic(payload: &[u8]) -> bool {
	let mut r = Bytes(payload);
	proof_walk(&mut r).unwrap_or(false)
}

fn proof_walk(r: &mut Bytes) -> Option<bool> {
	// version, block header version, id, state, offset
	r.take(2 + 2 + 16 + 1 + 32)?;
	// SlateOptFields: num parts, amount, fee, features, ttl
	let opts = r.u8()?;
	for (bit, len) in [(0x01, 1), (0x02, 8), (0x04, 8), (0x08, 1), (0x10, 8)] {
		if opts & bit != 0 {
			r.take(len)?;
		}
	}
	// SigsWrap: only a flag of exactly 1 carries a partial signature.
	for _ in 0..r.u8()? {
		let has_partial = r.u8()?;
		r.take(33 + 33)?;
		if has_partial == 1 {
			r.take(64)?;
		}
	}
	let structs = r.u8()?;
	// ComsWrap: a range proof reads its length, then at most MAX_PROOF_SIZE.
	if structs & 0x01 != 0 {
		for _ in 0..r.u16()? {
			let is_output = r.u8()?;
			r.take(1 + 33)?;
			if is_output == 1 {
				let len = r.u64()?;
				r.take(std::cmp::min(len as usize, MAX_PROOF_SIZE))?;
			}
		}
	}
	if structs & 0x02 == 0 {
		return Some(false);
	}
	// ProofWrap: sender and receiver keys, then any non-zero flag reads a
	// signature. Each is unwrapped as soon as it is read.
	for _ in 0..2 {
		let mut key = [0u8; 32];
		key.copy_from_slice(r.take(32)?);
		// The same ed25519-dalek 1.0.1 PublicKey::from_bytes the reader uses.
		if OnionV3Address::from_bytes(key).to_ed25519().is_err() {
			return Some(true);
		}
	}
	if r.u8()? != 0 {
		let sig = r.take(64)?;
		// ed25519 1.5.3 Signature::from_bytes refuses a set top 3 bits.
		if sig[63] & 0b1110_0000 != 0 {
			return Some(true);
		}
	}
	Some(false)
}

/// Accept only an age v1 header with at least one X25519 stanza and no scrypt
/// stanza. age 0.7.2 turns a lone scrypt stanza into a passphrase decryptor
/// (protocol.rs:161-175), which types.rs:202-205 meets with `unreachable!()`.
/// Other tags stay allowed: age 0.7.2 adds a random "<x>-grease" stanza to
/// every file it encrypts (protocol.rs:91), so real Slatepacks carry one.
fn check_age_recipients(payload: &[u8]) -> Result<(), Reject> {
	let header = payload.strip_prefix(AGE_V1).ok_or(Reject::Encryption)?;
	let mut x25519 = 0;
	// Stanza bodies are base64 lines, so every stanza starts a line with "-> "
	// and the header ends at the first line starting with "---".
	for line in header.split(|b| *b == b'\n') {
		if line.starts_with(b"---") {
			return if x25519 > 0 {
				Ok(())
			} else {
				Err(Reject::Encryption)
			};
		}
		if let Some(args) = line.strip_prefix(b"-> ") {
			match args.split(|b| *b == b' ').next() {
				Some(b"scrypt") => return Err(Reject::Encryption),
				Some(b"X25519") => x25519 += 1,
				_ => {}
			}
		}
	}
	// No end of header: age cannot read it either.
	Err(Reject::Encryption)
}

/// Real and hostile Slatepacks for the tests here and in the wallet tests.
#[cfg(test)]
pub(crate) mod fixtures {
	use super::*;
	use grin_core::core::{FeeFields, Input, Output, OutputFeatures};
	use grin_core::global::{self, ChainTypes};
	use grin_util::secp::key::{PublicKey, SecretKey};
	use grin_util::secp::pedersen::{Commitment, RangeProof};
	use grin_util::secp::{ContextFlag, Secp256k1, Signature};
	use grin_wallet_libwallet::slate_versions::v4::{PaymentInfoV4, SlateV4};
	use grin_wallet_libwallet::{
		ParticipantData, Slate, SlateState, SlatepackAddress, SlatepackArmor, Slatepacker,
		SlatepackerArgs, VersionedSlate, dalek_ser,
	};
	use std::convert::TryFrom;

	/// Signature bytes for a payment proof: valid for the pinned reader.
	pub const RSIG: [u8; 64] = [0x11; 64];
	/// Bytes of the secret key the tests decrypt with.
	pub const DEC_KEY: [u8; 32] = [7; 32];

	/// The parser reads the chain type for its size bound.
	pub fn chain() {
		global::set_local_chain_type(ChainTypes::Mainnet);
	}

	/// The Slatepack address the parser decrypts with when its key is [`DEC_KEY`].
	pub fn own_address() -> SlatepackAddress {
		let secp = Secp256k1::with_caps(ContextFlag::None);
		let sk = SecretKey::from_slice(&secp, &DEC_KEY).unwrap();
		SlatepackAddress::try_from(&sk).unwrap()
	}

	/// A slate with every optional part of the binary format: amount, fee, ttl,
	/// one participant with and one without a partial signature, an input, an
	/// output with a range proof, and optionally a payment proof.
	pub fn full_slate(state: SlateState, amount: u64, proof: Option<bool>) -> Slate {
		let secp = Secp256k1::with_caps(ContextFlag::SignOnly);
		let invoice = matches!(
			state,
			SlateState::Invoice1 | SlateState::Invoice2 | SlateState::Invoice3
		);
		let mut slate = Slate::blank(2, invoice);
		slate.state = state;
		slate.amount = amount;
		slate.fee_fields = FeeFields::new(0, 23_500_000).unwrap();
		slate.ttl_cutoff_height = 4_100_000;
		for (seed, part) in [
			(1u8, Some(Signature::from_raw_data(&[3; 64]).unwrap())),
			(2, None),
		] {
			let sk = SecretKey::from_slice(&secp, &[seed; 32]).unwrap();
			let pk = PublicKey::from_secret_key(&secp, &sk).unwrap();
			slate.participant_data.push(ParticipantData {
				public_blind_excess: pk,
				public_nonce: pk,
				part_sig: part,
			});
		}
		slate.tx = Some(
			Slate::empty_transaction()
				.with_input(Input::new(
					OutputFeatures::Plain,
					Commitment::from_vec(vec![8; 33]),
				))
				.with_output(Output::new(
					OutputFeatures::Plain,
					Commitment::from_vec(vec![9; 33]),
					RangeProof::zero(),
				)),
		);
		if let Some(signed) = proof {
			let mut v4 = SlateV4::from(slate);
			let rsig = if signed {
				dalek_ser::option_dalek_sig_serde::deserialize(serde_json::Value::String(
					RSIG.iter().map(|b| format!("{b:02x}")).collect(),
				))
				.unwrap()
			} else {
				None
			};
			v4.proof = Some(PaymentInfoV4 {
				saddr: SlatepackAddress::random().pub_key,
				raddr: own_address().pub_key,
				rsig,
			});
			slate = Slate::upgrade(VersionedSlate::V4(v4)).unwrap();
		}
		slate
	}

	/// Pack a slate the way the wallet does, optionally with a sender and
	/// encrypted to recipients.
	pub fn pack(
		slate: &Slate,
		sender: Option<SlatepackAddress>,
		recipients: Vec<SlatepackAddress>,
	) -> Slatepack {
		Slatepacker::new(SlatepackerArgs {
			sender,
			recipients,
			dec_key: None,
		})
		.create_slatepack(slate)
		.unwrap()
	}

	pub fn armor(slatepack: &Slatepack) -> String {
		SlatepackArmor::encode(slatepack).unwrap()
	}

	/// Re-armor a Slatepack with one byte run of its payload replaced.
	pub fn patched(slatepack: &Slatepack, from: &[u8], to: &[u8]) -> String {
		let mut sp = slatepack.clone();
		let at = sp
			.payload
			.windows(from.len())
			.position(|w| w == from)
			.expect("bytes to patch are in the payload");
		sp.payload[at..at + from.len()].copy_from_slice(to);
		armor(&sp)
	}

	/// 32 bytes ed25519-dalek 1.0.1 cannot decompress into a point.
	pub fn invalid_point() -> [u8; 32] {
		(2u8..=255)
			.map(|k| {
				let mut b = [0u8; 32];
				b[0] = k;
				b
			})
			.find(|b| OnionV3Address::from_bytes(*b).to_ed25519().is_err())
			.unwrap()
	}

	/// Base58 encode (test side of [`base58_decode`]).
	pub fn base58(bytes: &[u8]) -> String {
		let mut digits: Vec<u8> = vec![];
		for b in bytes {
			let mut carry = *b as u32;
			for d in digits.iter_mut() {
				carry += (*d as u32) << 8;
				*d = (carry % 58) as u8;
				carry /= 58;
			}
			while carry > 0 {
				digits.push((carry % 58) as u8);
				carry /= 58;
			}
		}
		let zeros = bytes.iter().take_while(|b| **b == 0).count();
		std::iter::repeat_n('1', zeros)
			.chain(digits.iter().rev().map(|d| BASE58[*d as usize] as char))
			.collect()
	}

	/// Armor arbitrary bytes with a valid check code.
	pub fn armor_bytes(bytes: &[u8]) -> String {
		let check = Sha256::digest(Sha256::digest(bytes));
		let mut all = check[..4].to_vec();
		all.extend_from_slice(bytes);
		format!("BEGINSLATEPACK. {}. ENDSLATEPACK.", base58(&all))
	}

	/// An age v1 file whose only stanza is a passphrase (scrypt) one, with the
	/// 16-byte nonce age reads before it picks the decryptor.
	pub fn age_scrypt() -> Vec<u8> {
		let mut age = format!(
			"age-encryption.org/v1\n-> scrypt {} 18\n{}\n--- {}\n",
			"A".repeat(22),
			"A".repeat(43),
			"A".repeat(43)
		)
		.into_bytes();
		age.extend_from_slice(&[0u8; 16]);
		age.extend_from_slice(&[0u8; 32]);
		age
	}

	fn json_slatepack(mode: u8, payload: &[u8]) -> String {
		use base64::Engine;
		format!(
			r#"{{"slatepack":"1.0","mode":{mode},"payload":"{}"}}"#,
			base64::engine::general_purpose::STANDARD.encode(payload)
		)
	}

	/// Messages that panic the pinned parser, with the reject the precheck
	/// gives each and whether the nostr ingest can deliver it (the ingest only
	/// passes text matching `BEGINSLATEPACK\. ... ENDSLATEPACK\.`).
	pub fn hostile() -> Vec<(&'static str, String, Reject, bool)> {
		chain();
		let with_proof = pack(
			&full_slate(SlateState::Standard1, 5, Some(true)),
			None,
			vec![],
		);
		let saddr = with_proof.payload.clone();
		let proof_start = saddr.len() - (32 + 32 + 1 + 64);
		let saddr_bytes = saddr[proof_start..proof_start + 32].to_vec();
		let raddr_bytes = own_address().pub_key.to_bytes().to_vec();
		let mut bad_sig = RSIG;
		bad_sig[63] = 0xFF;
		let mut scrypt = Slatepack::default();
		scrypt.mode = 1;
		scrypt.payload = age_scrypt();
		vec![
			(
				"payload decodes to 1 byte (armor.rs:103)",
				"BEGINSLATEPACK. 1 . ENDSLATEPACK.".to_string(),
				Reject::Payload,
				true,
			),
			(
				"payload decodes to 0 bytes (armor.rs:103)",
				"BEGINSLATEPACK. . ENDSLATEPACK.".to_string(),
				Reject::Payload,
				true,
			),
			(
				"no period after the payload (armor.rs:85)",
				"BEGINSLATEPACK. 4H1qx1wHe668tFW".to_string(),
				Reject::Framing,
				false,
			),
			(
				"proof sender key is not a point (v4_bin.rs:348)",
				patched(&with_proof, &saddr_bytes, &invalid_point()),
				Reject::PaymentProof,
				true,
			),
			(
				"proof receiver key is not a point (v4_bin.rs:349)",
				patched(&with_proof, &raddr_bytes, &invalid_point()),
				Reject::PaymentProof,
				true,
			),
			(
				"proof signature with the top bits set (v4_bin.rs:352)",
				patched(&with_proof, &RSIG, &bad_sig),
				Reject::PaymentProof,
				true,
			),
			(
				"binary mode 1 with an age scrypt stanza (types.rs:204)",
				armor(&scrypt),
				Reject::Encryption,
				true,
			),
			(
				"armored JSON mode 1 with an age scrypt stanza (types.rs:204)",
				armor_bytes(json_slatepack(1, &age_scrypt()).as_bytes()),
				Reject::Encryption,
				true,
			),
			(
				"bare JSON mode 1 with an age scrypt stanza (types.rs:204)",
				json_slatepack(1, &age_scrypt()),
				Reject::Encryption,
				false,
			),
		]
	}

	/// Real Slatepacks the parser accepts: every slate state, with and without
	/// a sender, with and without a payment proof (signed or not), plain, and
	/// encrypted to our own key or to someone else.
	pub fn real() -> Vec<(String, String)> {
		chain();
		let mut out = vec![];
		for state in [
			SlateState::Standard1,
			SlateState::Standard2,
			SlateState::Standard3,
			SlateState::Invoice1,
			SlateState::Invoice2,
			SlateState::Invoice3,
		] {
			for proof in [None, Some(false), Some(true)] {
				let slate = full_slate(state.clone(), 1_234_567_890, proof);
				for sender in [None, Some(SlatepackAddress::random())] {
					let name = format!("{state} proof {proof:?} sender {}", sender.is_some());
					out.push((
						format!("{name} plain"),
						armor(&pack(&slate, sender.clone(), vec![])),
					));
					out.push((
						format!("{name} to own key"),
						armor(&pack(&slate, sender.clone(), vec![own_address()])),
					));
					out.push((
						format!("{name} to another key"),
						armor(&pack(&slate, sender, vec![SlatepackAddress::random()])),
					));
				}
			}
		}
		out
	}

	/// The slatepack the nostr protocol tests use (src/nostr/protocol.rs). Its
	/// check code does not match, so the parser refuses it too.
	pub const PACK: &str = "BEGINSLATEPACK. 4H1qx1wHe668tFW yC2gfL8PPd8kSgv \
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
}

#[cfg(test)]
mod tests {
	use super::fixtures::*;
	use super::*;
	use grin_wallet_libwallet::{Slatepacker, SlatepackerArgs, dalek_ser};
	use std::panic::{AssertUnwindSafe, catch_unwind};

	/// The pinned parser as the wallet runs it (controller parse_slatepack ->
	/// slate_from_slatepack_message): decode with a decryption key, then read
	/// the slate. Err means it panicked; Ok(parsed) otherwise.
	fn pinned_parse(text: &str) -> std::thread::Result<bool> {
		let key = dalek_ser::dalek_seckey_serde::deserialize(serde_json::Value::String(
			DEC_KEY.iter().map(|b| format!("{b:02x}")).collect(),
		))
		.unwrap();
		catch_unwind(AssertUnwindSafe(|| {
			let packer = Slatepacker::new(SlatepackerArgs {
				sender: None,
				recipients: vec![],
				dec_key: Some(&key),
			});
			packer
				.deser_slatepack(text.trim().as_bytes(), true)
				.and_then(|sp| packer.get_slate(&sp))
				.is_ok()
		}))
	}

	/// Test A: each hostile message panics the pinned parser (H1, H2).
	#[test]
	fn hostile_slatepacks_panic_the_pinned_parser() {
		for (name, text, _, _) in hostile() {
			assert!(
				pinned_parse(&text).is_err(),
				"pinned parser did not panic: {name}"
			);
		}
	}

	/// Test B: the precheck refuses each of them, for the reason expected.
	#[test]
	fn precheck_refuses_hostile_slatepacks() {
		for (name, text, reject, _) in hostile() {
			assert_eq!(precheck(&text), Err(reject), "{name}");
		}
	}

	/// The brief's "truncated binary header" does not panic the pinned parser
	/// (the reader returns an error at the end of data); the precheck refuses it
	/// for the same reason the parser does.
	#[test]
	fn truncated_header_is_an_error_not_a_panic() {
		chain();
		let text = armor_bytes(&[1, 0, 0, 0]);
		assert_eq!(pinned_parse(&text).ok(), Some(false));
		assert_eq!(precheck(&text), Err(Reject::Unreadable));
	}

	/// Test C: every real Slatepack passes, and the pinned parser agrees it
	/// is no panic. Encrypted ones keep their mode for the ingest to refuse.
	#[test]
	fn precheck_accepts_real_slatepacks() {
		for (name, text) in real() {
			let shape = precheck(&text).unwrap_or_else(|r| panic!("{name}: refused ({r})"));
			let expect_mode = if name.contains(" to ") { 1 } else { 0 };
			assert_eq!(shape.mode, expect_mode, "{name}");
			let parsed = pinned_parse(&text).unwrap_or_else(|_| panic!("{name}: parser panicked"));
			// Ours to read: plain, or encrypted to the decryption key.
			assert_eq!(parsed, !name.ends_with("to another key"), "{name}");
			// Every encrypted one carries age's grease stanza next to the X25519
			// one, so a rule that refuses unknown stanza tags fails here.
			if expect_mode == 1 {
				let (_, payload) = unpack(dearmor(text.as_bytes()).unwrap()).unwrap();
				let header_end = payload.windows(4).position(|w| w == b"\n---").unwrap();
				let header = &payload[..header_end];
				assert!(
					header.windows(9).any(|w| w == b"\n-> X2551"),
					"{name}: no X25519 stanza"
				);
				assert!(
					header
						.windows(8)
						.any(|w| w == b"-grease\n" || w == b"-grease "),
					"{name}: no grease stanza"
				);
			}
		}
	}

	/// The nostr tests' slatepack is not a valid one: the parser refuses it
	/// without a panic, and the precheck refuses it for the same reason.
	#[test]
	fn protocol_test_pack_is_refused_by_both() {
		chain();
		assert_eq!(pinned_parse(PACK).ok(), Some(false));
		assert_eq!(precheck(PACK), Err(Reject::Checksum));
	}

	/// The test base58 encoder and the precheck decoder agree with bs58 as the
	/// parser uses it, leading zero bytes included.
	#[test]
	fn base58_round_trip() {
		for bytes in [
			vec![],
			vec![0],
			vec![0, 0, 1],
			vec![255; 40],
			(0..=255).collect(),
		] {
			assert_eq!(base58_decode(base58(&bytes).as_bytes()), Some(bytes));
		}
		assert_eq!(base58_decode(b"0OIl"), None);
	}

	/// An age header passes with an X25519 stanza and no scrypt one; grease
	/// stanzas are fine; the header ends at "---".
	#[test]
	fn age_recipients_rule() {
		let x = b"age-encryption.org/v1\n-> X25519 abc\nAAAA\n--- mac\n\x00-> scrypt";
		assert_eq!(check_age_recipients(x), Ok(()));
		let greased = b"age-encryption.org/v1\n-> X25519 abc\nAAAA\n-> b8#K5-grease\nAA\n--- m\n";
		assert_eq!(check_age_recipients(greased), Ok(()));
		let mixed = b"age-encryption.org/v1\n-> X25519 abc\nAAAA\n-> scrypt s 18\nAA\n--- m\n";
		assert_eq!(check_age_recipients(mixed), Err(Reject::Encryption));
		let other = b"age-encryption.org/v1\n-> ssh-ed25519 a b\nAA\n--- m\n";
		assert_eq!(check_age_recipients(other), Err(Reject::Encryption));
		let none = b"age-encryption.org/v1\n--- m\n";
		assert_eq!(check_age_recipients(none), Err(Reject::Encryption));
		let open = b"age-encryption.org/v1\n-> X25519 abc\nAAAA\n";
		assert_eq!(check_age_recipients(open), Err(Reject::Encryption));
		assert_eq!(check_age_recipients(b"not age"), Err(Reject::Encryption));
	}
}
