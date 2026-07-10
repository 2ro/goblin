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

//! Request/channel wire types, the client-pinned `created_at` signer
//! with its skew guard, the NIP-44 envelope shapes and the runtime
//! serving orchestration (sign / encrypt / decrypt / money completion).

use super::*;
// ---------------------------------------------------------------------------
// Wire envelope shapes (the plaintext inside the NIP-44 channel envelope).
// ---------------------------------------------------------------------------

/// The full event as the client (NDK) composed it, WITHOUT `id` and `sig`. The
/// wallet signs exactly this: it computes the NIP-01 `id` over these fields and
/// produces `sig`, but never re-stamps `created_at` and never adopts a
/// client-supplied `id`/`sig` (finding A).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestEvent {
	/// Must equal the session identity or the request is rejected.
	pub pubkey: String,
	/// Client-owned, bounded by the skew guard. The wallet signs this exact time.
	pub created_at: u64,
	pub kind: u16,
	pub tags: Vec<Vec<String>>,
	pub content: String,
}

/// A sign request (site to wallet), the plaintext inside a NIP-44 envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignRequest {
	/// Always `"sign"`.
	#[serde(rename = "type")]
	pub msg_type: String,
	/// A UUID, unique per request; the replay-dedup key.
	pub id: String,
	/// Envelope timestamp, checked against the skew window independently.
	pub ts: u64,
	pub event: RequestEvent,
}

/// An encrypt request (site to wallet): NIP-44-encrypt `plaintext` to
/// `peer_pubkey` with the SESSION IDENTITY key. magick needs this to build the
/// kind-13 seal of an order DM (silent signing alone cannot construct a seal).
/// Low tier and rate-limited like a silent sign, BUT because the plaintext is
/// visible here, the content-escalation rule runs on it: a pay-committing order
/// message escalates to the money-tier password prompt at the encrypt step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptRequest {
	/// Always `"encrypt"`.
	#[serde(rename = "type")]
	pub msg_type: String,
	pub id: String,
	pub ts: u64,
	/// The recipient the identity key encrypts to (hex).
	pub peer_pubkey: String,
	/// The plaintext to seal (inspected for a payment commitment).
	pub plaintext: String,
}

/// A decrypt request (site to wallet): NIP-44-decrypt `ciphertext` from
/// `peer_pubkey` with the SESSION IDENTITY key. THE RISKIEST OP: a compromised
/// site could read that identity's DMs during a live session, so it is
/// rate-limited like a silent sign and called out prominently for the security
/// pass. Its ciphertext is opaque, so no content escalation is possible here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptRequest {
	/// Always `"decrypt"`.
	#[serde(rename = "type")]
	pub msg_type: String,
	pub id: String,
	pub ts: u64,
	/// The counterparty the identity key decrypts from (hex).
	pub peer_pubkey: String,
	/// The opaque ciphertext to open.
	pub ciphertext: String,
}

/// A channel operation the wallet may be asked to perform. `Sign` and (a
/// pay-committing) `Encrypt` can escalate to the money-tier prompt, so a pending
/// money item carries one of these.
#[derive(Debug, Clone)]
pub enum ChannelOp {
	Sign(SignRequest),
	Encrypt(EncryptRequest),
}

impl ChannelOp {
	/// The correlation id, for replay dedup and the money-answer routing.
	pub fn id(&self) -> &str {
		match self {
			ChannelOp::Sign(r) => &r.id,
			ChannelOp::Encrypt(e) => &e.id,
		}
	}
}

/// The session-open envelope (wallet to site), sent once at channel
/// establishment. The site reads the WALLET CHANNEL KEY from the outer event's
/// `pubkey` (the envelope sender) and binds the channel to it; this payload is
/// the client-side authority that confirms the signing identity. It is sent in
/// ADDITION to the server-side kind-22242 login callback (which authenticates
/// the server session): the two bind different layers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionOpen {
	/// Always `"session-open"`.
	#[serde(rename = "type")]
	pub msg_type: String,
	/// A correlation id (the wallet channel pubkey hex; unique per session).
	pub id: String,
	/// The confirmed signing identity public key (hex).
	pub identity_pubkey: String,
}

/// The session-end envelope (either direction): the site's logout signal, or the
/// wallet announcing a unilateral end. Only the type is trusted; `reason` is
/// display data the receiving side may show ("logout" from the site, "revoked"
/// or "expired" from the wallet).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEnd {
	/// Always `"session-end"`.
	#[serde(rename = "type")]
	pub msg_type: String,
	/// Why the session ended: "logout" | "revoked" | "expired".
	#[serde(default)]
	pub reason: String,
}

/// A sign response (wallet to site). On success `ok` is true and `event` carries
/// the fully signed event; on refusal `ok` is false and `error` carries a typed
/// code. Exactly one of `event`/`error` is set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignResult {
	/// Always `"sign_result"`.
	#[serde(rename = "type")]
	pub msg_type: String,
	/// The request UUID this answers.
	pub id: String,
	pub ok: bool,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub event: Option<serde_json::Value>,
	#[serde(skip_serializing_if = "Option::is_none")]
	pub error: Option<String>,
}

impl SignResult {
	/// A success response carrying the signed event JSON.
	pub fn ok(id: &str, event: &Event) -> Self {
		SignResult {
			msg_type: "sign_result".to_string(),
			id: id.to_string(),
			ok: true,
			event: serde_json::to_value(event).ok(),
			error: None,
		}
	}

	/// A refusal response carrying a typed error code.
	pub fn refused(id: &str, error: SignError) -> Self {
		SignResult {
			msg_type: "sign_result".to_string(),
			id: id.to_string(),
			ok: false,
			event: None,
			error: Some(error.code().to_string()),
		}
	}
}

// ---------------------------------------------------------------------------
// Typed errors (the wire `error` codes).
// ---------------------------------------------------------------------------

/// Every refusal returns one of these typed codes on the channel so the site can
/// show an honest state. The wire strings match the cross-worker error set
/// (user_declined, kind_not_in_session, identity_mismatch, stale_request,
/// too_large, session_paused, session_ended). `Refused` (a login-capable or
/// delegation-bearing event the session will never sign) maps onto the site's
/// `kind_not_in_session` handling; `Malformed` is internal and rarely emitted
/// (an unparseable envelope carries no id to answer, so it is simply dropped).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignError {
	/// A low-tier kind the session was not granted.
	KindNotInSession,
	/// `event.pubkey` did not equal the session identity.
	IdentityMismatch,
	/// `created_at` or envelope `ts` outside the skew window.
	StaleRequest,
	/// Over a size cap.
	TooLarge,
	/// The user declined a money-tier prompt.
	UserDeclined,
	/// The hard rate cap tripped and the session is paused.
	SessionPaused,
	/// The session ended (logout, wallet-side end, TTL, or idle).
	SessionEnded,
	/// Outright refusal: a login-capable (22242) or delegation-bearing event.
	/// Never signed by the session path at all, not even via the money prompt.
	Refused,
	/// The envelope or event JSON was not well-formed.
	Malformed,
}

impl SignError {
	/// The wire error string.
	pub fn code(self) -> &'static str {
		match self {
			SignError::KindNotInSession => "kind_not_in_session",
			SignError::IdentityMismatch => "identity_mismatch",
			SignError::StaleRequest => "stale_request",
			SignError::TooLarge => "too_large",
			SignError::UserDeclined => "user_declined",
			SignError::SessionPaused => "session_paused",
			SignError::SessionEnded => "session_ended",
			// An outright refusal reads to the site exactly as "not covered by
			// this session": re-grant, do not retry. Kept aligned with the
			// cross-worker code set rather than a wallet-only "refused" string.
			SignError::Refused => "kind_not_in_session",
			SignError::Malformed => "malformed",
		}
	}
}

// ---------------------------------------------------------------------------
// The client-pinned `created_at` signer.
// ---------------------------------------------------------------------------

/// Sign exactly the event the client composed: the wallet fills `pubkey` (from
/// `keys`, which must already equal `req.pubkey`) and computes `id`/`sig`, but
/// pins `created_at` to the client's value so the signed event matches NDK's
/// `id` and relays accept it. Defense in depth re-checks the invariants the
/// enforcement layer also checks: the pubkey must equal the identity, the skew
/// must hold, kind 22242 and any `delegation` tag are refused outright. Only the
/// canonical NIP-01 serialization this computes is ever signed; no client hash.
pub fn sign_session_event(keys: &Keys, ev: &RequestEvent, now: u64) -> Result<Event, SignError> {
	// Identity binding: a session for identity A can never sign as identity B.
	let want = keys.public_key();
	let got = PublicKey::from_hex(&ev.pubkey).map_err(|_| SignError::Malformed)?;
	if got != want {
		return Err(SignError::IdentityMismatch);
	}
	// Skew guard on the client-pinned time.
	if abs_diff(ev.created_at, now) > CREATED_AT_SKEW_SECS {
		return Err(SignError::StaleRequest);
	}
	// The wallet never yields a login-capable signature, in any build, ever.
	if ev.kind == LOGIN_EVENT_KIND {
		return Err(SignError::Refused);
	}
	let mut tags = Vec::with_capacity(ev.tags.len());
	for row in &ev.tags {
		// A delegation token is unreachable (we sign a composed event, not a
		// hash), but refuse it at sign time regardless, exactly as v1.
		if row.first().map(|k| k == "delegation").unwrap_or(false) {
			return Err(SignError::Refused);
		}
		tags.push(Tag::parse(row.clone()).map_err(|_| SignError::Malformed)?);
	}
	EventBuilder::new(Kind::from(ev.kind), ev.content.clone())
		.tags(tags)
		.custom_created_at(Timestamp::from(ev.created_at))
		.sign_with_keys(keys)
		.map_err(|_| SignError::Malformed)
}

// ---------------------------------------------------------------------------
// NIP-44 channel envelope crypto (standard NIP-44 v2, the shape the site uses).
// ---------------------------------------------------------------------------

/// Encrypt a plaintext payload to `recipient` under the wallet channel key.
/// Standard NIP-44 v2, the same shape magick's browser side uses.
pub fn seal_envelope(
	wallet_channel_sk: &SecretKey,
	recipient: &PublicKey,
	plaintext: &str,
) -> Result<String, String> {
	nip44::encrypt(wallet_channel_sk, recipient, plaintext, nip44::Version::V2)
		.map_err(|e| e.to_string())
}

/// Decrypt a channel envelope sent by `sender` (the site's channel key, taken
/// from the outer event's `pubkey`) under the wallet channel key.
pub fn open_envelope(
	wallet_channel_sk: &SecretKey,
	sender: &PublicKey,
	payload: &str,
) -> Result<String, String> {
	nip44::decrypt(wallet_channel_sk, sender, payload).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Runtime serving orchestration (thin, so the async relay loop stays dumb).
// ---------------------------------------------------------------------------

/// The upshot of serving one decoded request against a session. The async loop
/// acts on it and never touches classification, signing, or bookkeeping itself.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Served {
	/// A `sign_result` JSON to publish back to the site on the channel, or `None`
	/// when the request is a money-tier prompt still pending the user (or a
	/// replay of one).
	pub response: Option<String>,
	/// True when the soft rate cap tripped: surface a single non-blocking notice.
	pub notify_high_volume: bool,
	/// True when the decrypt soft cap tripped: surface the honest "reading your
	/// messages" notice (distinct from the signing-volume wording).
	pub notify_decrypt_volume: bool,
	/// True when this request needs the money-tier password prompt (the loop
	/// enqueues it for the GUI and publishes nothing yet).
	pub money_pending: bool,
}

/// Serve a decoded sign request against a live session. Silent low-tier requests
/// are signed here and turned into a `sign_result` JSON; refusals and cached
/// duplicates likewise return a JSON to publish; a money-tier request returns
/// `money_pending` with no response (the GUI raises the prompt, then the loop
/// calls [`complete_money`]). `sign_keys` are the session identity's unlocked
/// keys, looked up by the loop from the wallet's in-memory snapshot.
pub fn serve(session: &mut Session, req: &SignRequest, sign_keys: &Keys, now: u64) -> Served {
	match session.decide(req, now) {
		Decision::Duplicate(json) => served_response(json),
		// A replayed money request whose prompt is still up: no second prompt, no
		// response; the original prompt's answer covers this id.
		Decision::AlreadyPending => Served::default(),
		Decision::Refuse(err) => {
			let json =
				serde_json::to_string(&SignResult::refused(&req.id, err)).unwrap_or_default();
			session.remember(&req.id, &json, false, now);
			served_response(json)
		}
		Decision::MoneyPrompt => Served {
			money_pending: true,
			..Served::default()
		},
		Decision::Silent { notify_high_volume } => {
			let result = match sign_session_event(sign_keys, &req.event, now) {
				Ok(ev) => SignResult::ok(&req.id, &ev),
				Err(err) => SignResult::refused(&req.id, err),
			};
			let json = serde_json::to_string(&result).unwrap_or_default();
			// A produced silent signature counts toward the rate window; a refusal
			// on the silent path does not.
			session.remember(&req.id, &json, result.ok, now);
			Served {
				response: Some(json),
				notify_high_volume,
				..Served::default()
			}
		}
	}
}

/// Complete a money-tier operation after the user answered the password prompt.
/// `approved` true performs the op (sign, or a pay-committing encrypt) and
/// returns its result JSON; false returns the `user_declined` refusal in the
/// matching result shape. Either way the result is remembered so a replay of the
/// same id returns it verbatim. Money operations are individually gated and so
/// never count toward the silent rate window.
pub fn complete_money(
	session: &mut Session,
	op: &ChannelOp,
	keys: &Keys,
	approved: bool,
	now: u64,
) -> String {
	let json = match op {
		ChannelOp::Sign(req) => {
			let result = if approved {
				match sign_session_event(keys, &req.event, now) {
					Ok(ev) => SignResult::ok(&req.id, &ev),
					Err(err) => SignResult::refused(&req.id, err),
				}
			} else {
				SignResult::refused(&req.id, SignError::UserDeclined)
			};
			serde_json::to_string(&result).unwrap_or_default()
		}
		ChannelOp::Encrypt(e) => {
			if approved {
				perform_encrypt(e, keys)
			} else {
				crypto_error("encrypt_result", &e.id, SignError::UserDeclined)
			}
		}
	};
	session.remember(op.id(), &json, false, now);
	json
}

// ---------------------------------------------------------------------------
// Encrypt / decrypt channel ops (identity-key NIP-44, for the order-DM path).
// ---------------------------------------------------------------------------

/// A crypto-op refusal JSON in the matching `*_result` shape.
fn crypto_error(result_type: &str, id: &str, err: SignError) -> String {
	serde_json::json!({ "type": result_type, "id": id, "ok": false, "error": err.code() })
		.to_string()
}

/// Perform an identity-key NIP-44 encrypt, returning the `encrypt_result` JSON.
fn perform_encrypt(e: &EncryptRequest, keys: &Keys) -> String {
	let Ok(peer) = PublicKey::from_hex(&e.peer_pubkey) else {
		return crypto_error("encrypt_result", &e.id, SignError::Malformed);
	};
	match nip44::encrypt(keys.secret_key(), &peer, &e.plaintext, nip44::Version::V2) {
		Ok(ct) => {
			serde_json::json!({ "type": "encrypt_result", "id": e.id, "ok": true, "ciphertext": ct })
				.to_string()
		}
		Err(_) => crypto_error("encrypt_result", &e.id, SignError::Malformed),
	}
}

/// Perform an identity-key NIP-44 decrypt, returning the `decrypt_result` JSON.
fn perform_decrypt(d: &DecryptRequest, keys: &Keys) -> String {
	let Ok(peer) = PublicKey::from_hex(&d.peer_pubkey) else {
		return crypto_error("decrypt_result", &d.id, SignError::Malformed);
	};
	match nip44::decrypt(keys.secret_key(), &peer, &d.ciphertext) {
		Ok(pt) => {
			serde_json::json!({ "type": "decrypt_result", "id": d.id, "ok": true, "plaintext": pt })
				.to_string()
		}
		Err(_) => crypto_error("decrypt_result", &d.id, SignError::Malformed),
	}
}

/// Serve an encrypt or decrypt op against a live session. Both are low tier and
/// rate-limited like a silent sign; an encrypt whose plaintext commits to a
/// payment escalates to the money prompt (`money_pending`, op carried for
/// [`complete_money`]). Decrypt never escalates (its ciphertext is opaque).
/// `keys` are the session identity's unlocked keys.
pub fn serve_encrypt(session: &mut Session, e: &EncryptRequest, keys: &Keys, now: u64) -> Served {
	let escalate = content_commits_payment(&e.plaintext);
	match session.decide_crypto(&e.id, e.ts, now, escalate) {
		Decision::Duplicate(json) => served_response(json),
		Decision::AlreadyPending => Served::default(),
		Decision::Refuse(err) => {
			let json = crypto_error("encrypt_result", &e.id, err);
			session.remember(&e.id, &json, false, now);
			served_response(json)
		}
		Decision::MoneyPrompt => Served {
			money_pending: true,
			..Served::default()
		},
		Decision::Silent { notify_high_volume } => {
			let json = perform_encrypt(e, keys);
			session.remember(&e.id, &json, true, now);
			Served {
				response: Some(json),
				notify_high_volume,
				..Served::default()
			}
		}
	}
}

/// Serve a decrypt op (see [`serve_encrypt`]; decrypt never escalates). Counts
/// toward its own soft window so heavy DM-reading surfaces the honest notice.
pub fn serve_decrypt(session: &mut Session, d: &DecryptRequest, keys: &Keys, now: u64) -> Served {
	match session.decide_crypto(&d.id, d.ts, now, false) {
		Decision::Duplicate(json) => served_response(json),
		Decision::AlreadyPending => Served::default(),
		Decision::Refuse(err) => {
			let json = crypto_error("decrypt_result", &d.id, err);
			session.remember(&d.id, &json, false, now);
			served_response(json)
		}
		// Decrypt never escalates, so MoneyPrompt cannot occur; treat defensively.
		Decision::MoneyPrompt => {
			served_response(crypto_error("decrypt_result", &d.id, SignError::Refused))
		}
		Decision::Silent { .. } => {
			let json = perform_decrypt(d, keys);
			session.remember(&d.id, &json, true, now);
			let notify_decrypt = session.note_decrypt(now);
			Served {
				response: Some(json),
				notify_decrypt_volume: notify_decrypt,
				..Served::default()
			}
		}
	}
}

/// A `Served` carrying just a response JSON.
fn served_response(json: String) -> Served {
	Served {
		response: Some(json),
		..Served::default()
	}
}

/// The typed refusal JSON for any channel op, keyed by its request `type` (the
/// runtime uses this when it cannot even look up keys, e.g. the identity was
/// dropped mid-session, so the site fails fast instead of timing out).
pub fn refusal_json(op_type: &str, id: &str, err: SignError) -> String {
	match op_type {
		"encrypt" => crypto_error("encrypt_result", id, err),
		"decrypt" => crypto_error("decrypt_result", id, err),
		// "sign" and anything else answers in the sign_result shape.
		_ => serde_json::to_string(&SignResult::refused(id, err)).unwrap_or_default(),
	}
}
