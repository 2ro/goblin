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

//! NIP-44 v3 gift wrapping and the version-dispatched unwrap (the NIP-17
//! backward-compat extension, plan G4).
//!
//! nostr-sdk's gift-wrap builders hardcode NIP-44 v2, so [`wrap`] constructs
//! the NIP-59 layers itself when the recipient advertises `nip44_v3`:
//! the seal (kind 13) carries the v3-encrypted rumor JSON with context
//! `kind=13`/scope `""`, the gift wrap (kind 1059, ephemeral key) carries the
//! v3-encrypted seal JSON with context `kind=1059`/scope `""`. Tags and
//! created_at fuzzing mirror nostr-sdk's v2 builders exactly.
//!
//! [`unwrap`] dispatches on the payload version byte: `0x02` goes through the
//! unchanged nostr-sdk path, `0x03` through the `nip44` crate — a v2-only
//! peer is completely unaffected.

use nostr_sdk::nips::nip59::{self, UnwrappedGift};
use nostr_sdk::{
	Event, EventBuilder, JsonUtil, Keys, Kind, PublicKey, Tag, Timestamp, UnsignedEvent,
};

/// The capability Goblin advertises in its kind 10050 `encryption` tag,
/// space-separated best-first (NIP-17 backward-compat extension).
pub const ENCRYPTION_CAPABILITY: &str = "nip44_v3 nip44_v2";

/// The token a peer's `encryption` tag must contain for us to send v3.
const V3_TOKEN: &str = "nip44_v3";

/// v3 context bound into the seal's ciphertext: the seal event kind, no scope.
const SEAL_CTX_KIND: u32 = 13;
/// v3 context bound into the gift wrap's ciphertext: the wrap event kind.
const WRAP_CTX_KIND: u32 = 1059;
/// Both layers use the empty scope.
const SCOPE: &[u8] = b"";

/// True when a kind 10050 `encryption` tag value advertises NIP-44 v3.
/// `None` (no tag) = v2 only, per the extension.
pub fn peer_supports_v3(encryption: Option<&str>) -> bool {
	encryption
		.map(|v| v.split_whitespace().any(|t| t == V3_TOKEN))
		.unwrap_or(false)
}

/// Derive the v3 conversation key between our secret key and a peer's
/// public key, bridging nostr-sdk's key types (secp256k1 0.29) to the nip44
/// crate's (0.31) via their byte serializations.
fn conversation_key(secret: &nostr_sdk::SecretKey, public: &PublicKey) -> Result<[u8; 32], String> {
	let sk = secp256k1::SecretKey::from_byte_array(secret.to_secret_bytes())
		.map_err(|e| format!("invalid secret key: {e}"))?;
	let pk = secp256k1::XOnlyPublicKey::from_byte_array(*public.as_bytes())
		.map_err(|e| format!("invalid public key: {e}"))?;
	Ok(nip44::get_conversation_key_v3(sk, pk))
}

/// Build a NIP-17 private-message gift wrap encrypted with NIP-44 v3.
/// Mirrors `EventBuilder::private_msg` (rumor shape, tags, created_at
/// fuzzing), with only the two encryption layers switched to v3.
pub fn wrap(
	sender: &Keys,
	receiver: &PublicKey,
	content: String,
	rumor_extra_tags: Vec<Tag>,
) -> Result<Event, String> {
	// Rumor: kind 14, receiver p-tag first, then the extra tags — the same
	// shape `EventBuilder::private_msg_rumor` builds. Never signed (NIP-59).
	let mut rumor: UnsignedEvent = EventBuilder::new(Kind::PrivateDirectMessage, content)
		.tag(Tag::public_key(*receiver))
		.tags(rumor_extra_tags)
		.build(sender.public_key());
	rumor.ensure_id();

	// Seal (kind 13): v3-encrypted rumor JSON, context kind=13/scope "",
	// signed by the sender, created_at fuzzed up to 2 days into the past
	// exactly like nostr-sdk's v2 `make_seal`.
	let ck = conversation_key(sender.secret_key(), receiver)?;
	let sealed = nip44::encrypt_v3(&ck, rumor.as_json().as_bytes(), SEAL_CTX_KIND, SCOPE)
		.map_err(|e| format!("v3 seal encrypt failed: {e}"))?;
	let seal: Event = EventBuilder::new(Kind::Seal, sealed)
		.custom_created_at(Timestamp::tweaked(nip59::RANGE_RANDOM_TIMESTAMP_TWEAK))
		.sign_with_keys(sender)
		.map_err(|e| format!("seal signing failed: {e}"))?;

	// Gift wrap (kind 1059): one-time ephemeral key, v3-encrypted seal JSON,
	// context kind=1059/scope "", canonical receiver p-tag and the same
	// created_at fuzzing as nostr-sdk's `gift_wrap_from_seal`.
	let ephemeral = Keys::generate();
	let ck = conversation_key(ephemeral.secret_key(), receiver)?;
	let wrapped = nip44::encrypt_v3(&ck, seal.as_json().as_bytes(), WRAP_CTX_KIND, SCOPE)
		.map_err(|e| format!("v3 wrap encrypt failed: {e}"))?;
	EventBuilder::new(Kind::GiftWrap, wrapped)
		.tag(Tag::public_key(*receiver))
		.custom_created_at(Timestamp::tweaked(nip59::RANGE_RANDOM_TIMESTAMP_TWEAK))
		.sign_with_keys(&ephemeral)
		.map_err(|e| format!("wrap signing failed: {e}"))
}

/// Unwrap a gift wrap addressed to `keys`, dispatching on the NIP-44 payload
/// version byte: v2 payloads go through the unchanged nostr-sdk path, v3
/// through the nip44 crate. Unknown or malformed payloads error cleanly.
pub async fn unwrap(keys: &Keys, event: &Event) -> Result<UnwrappedGift, String> {
	if event.kind != Kind::GiftWrap {
		return Err("not a gift wrap".to_string());
	}
	match nip44::payload_version(&event.content) {
		Ok(3) => unwrap_v3(keys, event),
		Ok(2) => UnwrappedGift::from_gift_wrap(keys, event)
			.await
			.map_err(|e| format!("v2 unwrap failed: {e}")),
		Ok(v) => Err(format!("unsupported NIP-44 payload version {v}")),
		Err(e) => Err(format!("undecodable NIP-44 payload: {e}")),
	}
}

/// The v3 leg of [`unwrap`]: decrypt the wrap (context 1059/""), verify the
/// seal's kind and signature, decrypt the seal (context 13/"") and enforce
/// the NIP-17 rumor-author == seal-signer rule, mirroring nostr-sdk's
/// `UnwrappedGift::from_gift_wrap`.
fn unwrap_v3(keys: &Keys, event: &Event) -> Result<UnwrappedGift, String> {
	let ck = conversation_key(keys.secret_key(), &event.pubkey)?;
	let seal_json = nip44::decrypt_v3(&ck, &event.content, WRAP_CTX_KIND, SCOPE)
		.map_err(|e| format!("v3 wrap decrypt failed: {e}"))?;
	let seal = Event::from_json(seal_json).map_err(|e| format!("seal parse failed: {e}"))?;
	if seal.kind != Kind::Seal {
		return Err("decrypted inner event is not a seal".to_string());
	}
	seal.verify()
		.map_err(|e| format!("seal signature invalid: {e}"))?;

	let ck = conversation_key(keys.secret_key(), &seal.pubkey)?;
	let rumor_json = nip44::decrypt_v3(&ck, &seal.content, SEAL_CTX_KIND, SCOPE)
		.map_err(|e| format!("v3 seal decrypt failed: {e}"))?;
	let rumor =
		UnsignedEvent::from_json(rumor_json).map_err(|e| format!("rumor parse failed: {e}"))?;
	if rumor.pubkey != seal.pubkey {
		return Err("rumor author differs from seal signer".to_string());
	}
	Ok(UnwrappedGift {
		sender: seal.pubkey,
		rumor,
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::nostr::protocol;
	use base64::Engine;

	const SLATEPACK: &str = "BEGINSLATEPACK. 4H1qx1wHe668tFW yC2gfL8PPd8kSgv \
		pcXQhyRkHbyKHZg GN75o7uWoT3dkib R2tj1fFGN2FoRLY oeBPyKizupksgRT. \
		ENDSLATEPACK.";

	/// (a) v3 <-> v3: a payment gift wrap round-trips between two fresh
	/// Goblin identities through the wrap + unwrap seam, no network.
	#[tokio::test]
	async fn v3_gift_wrap_round_trip() {
		let alice = Keys::generate();
		let bob = Keys::generate();
		let content = protocol::build_payment_content(SLATEPACK);
		let tags = protocol::build_rumor_tags(Some("lunch :)"));

		let wrap = wrap(&alice, &bob.public_key(), content.clone(), tags).unwrap();
		// Wire shape: kind 1059, signed by an EPHEMERAL key, receiver p-tag,
		// v3 version byte, created_at not in the future.
		assert_eq!(wrap.kind, Kind::GiftWrap);
		assert_ne!(wrap.pubkey, alice.public_key());
		assert!(wrap.verify().is_ok());
		assert!(wrap.tags.public_keys().any(|pk| *pk == bob.public_key()));
		let decoded = base64::engine::general_purpose::STANDARD
			.decode(&wrap.content)
			.unwrap();
		assert_eq!(decoded[0], 0x03);
		assert!(wrap.created_at <= Timestamp::now());

		let unwrapped = unwrap(&bob, &wrap).await.unwrap();
		assert_eq!(unwrapped.sender, alice.public_key());
		assert_eq!(unwrapped.rumor.pubkey, alice.public_key());
		assert_eq!(unwrapped.rumor.kind, Kind::PrivateDirectMessage);
		assert_eq!(unwrapped.rumor.content, content);
		assert_eq!(
			protocol::extract_slatepack(&unwrapped.rumor.content).unwrap(),
			SLATEPACK
		);
		assert_eq!(
			protocol::extract_subject(&unwrapped.rumor.tags),
			Some("lunch :)".to_string())
		);

		// Only the addressee can open it.
		let mallory = Keys::generate();
		assert!(unwrap(&mallory, &wrap).await.is_err());
	}

	/// (b) v3 -> v2 regression: a recipient with no `encryption` tag (or a
	/// v2-only one) negotiates v2, and the sdk-built v2 wrap still decrypts
	/// through the same unwrap seam — a v2-only peer is unaffected.
	#[tokio::test]
	async fn v2_only_peer_unaffected() {
		// Negotiation: absent or v2-only tag never selects v3; our own
		// advertised capability does.
		assert!(!peer_supports_v3(None));
		assert!(!peer_supports_v3(Some("")));
		assert!(!peer_supports_v3(Some("nip44_v2")));
		assert!(!peer_supports_v3(Some("nip44_v3000"))); // whole-token match
		assert!(peer_supports_v3(Some("nip44_v3 nip44_v2")));
		assert!(peer_supports_v3(Some("nip44_v2 nip44_v3")));
		assert!(peer_supports_v3(Some(ENCRYPTION_CAPABILITY)));

		// The v2 path (what the sender produces for such a peer) is the
		// unchanged nostr-sdk builder; our unwrap dispatches it to the sdk.
		let alice = Keys::generate();
		let bob = Keys::generate();
		let content = protocol::build_payment_content(SLATEPACK);
		let rumor = EventBuilder::new(Kind::PrivateDirectMessage, content.clone())
			.tag(Tag::public_key(bob.public_key()))
			.tags(protocol::build_rumor_tags(None))
			.build(alice.public_key());
		let wrap_v2 = EventBuilder::gift_wrap(&alice, &bob.public_key(), rumor, [])
			.await
			.unwrap();
		let decoded = base64::engine::general_purpose::STANDARD
			.decode(&wrap_v2.content)
			.unwrap();
		assert_eq!(decoded[0], 0x02);

		let unwrapped = unwrap(&bob, &wrap_v2).await.unwrap();
		assert_eq!(unwrapped.sender, alice.public_key());
		assert_eq!(unwrapped.rumor.content, content);
	}

	/// (c) Version-byte dispatch on malformed or unknown payloads errors
	/// cleanly — no panic, no misrouting.
	#[tokio::test]
	async fn dispatch_rejects_malformed_payloads() {
		let bob = Keys::generate();
		let make = |content: String| {
			EventBuilder::new(Kind::GiftWrap, content)
				.tag(Tag::public_key(bob.public_key()))
				.sign_with_keys(&Keys::generate())
				.unwrap()
		};
		let b64 = |bytes: &[u8]| base64::engine::general_purpose::STANDARD.encode(bytes);

		// Unknown version byte.
		let mut junk = vec![0x01u8];
		junk.extend_from_slice(&[7u8; 90]);
		assert!(unwrap(&bob, &make(b64(&junk))).await.is_err());
		// Version byte from the future.
		junk[0] = 0x04;
		assert!(unwrap(&bob, &make(b64(&junk))).await.is_err());
		// Not base64 at all.
		assert!(
			unwrap(&bob, &make("not base64!!".to_string()))
				.await
				.is_err()
		);
		// Empty content.
		assert!(unwrap(&bob, &make(String::new())).await.is_err());
		// Truncated v3 payload (version byte right, body too short).
		assert!(unwrap(&bob, &make(b64(&[0x03, 1, 2, 3]))).await.is_err());
		// Valid v3 framing but garbage ciphertext.
		let mut garbage = vec![0x03u8];
		garbage.extend_from_slice(&[9u8; 120]);
		assert!(unwrap(&bob, &make(b64(&garbage))).await.is_err());
		// Not a gift wrap at all.
		let not_wrap = EventBuilder::new(Kind::TextNote, "hi")
			.sign_with_keys(&Keys::generate())
			.unwrap();
		assert!(unwrap(&bob, &not_wrap).await.is_err());
	}

	/// Context binding: a v3 payload encrypted for one layer must not decrypt
	/// as the other (kind is authenticated by the MAC).
	#[test]
	fn v3_context_binding_enforced() {
		let alice = Keys::generate();
		let bob = Keys::generate();
		let ck = conversation_key(alice.secret_key(), &bob.public_key()).unwrap();
		let sealed = nip44::encrypt_v3(&ck, b"payload", SEAL_CTX_KIND, SCOPE).unwrap();
		let ck_bob = conversation_key(bob.secret_key(), &alice.public_key()).unwrap();
		assert!(nip44::decrypt_v3(&ck_bob, &sealed, SEAL_CTX_KIND, SCOPE).is_ok());
		assert!(nip44::decrypt_v3(&ck_bob, &sealed, WRAP_CTX_KIND, SCOPE).is_err());
	}
}
