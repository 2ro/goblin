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

//! Authorize Sessions (v2): the two-tier session signer's PURE core.
//!
//! Everything a running GUI does not need lives here and is unit-tested without
//! one: the tier classifier (kind-to-tier table plus the content-escalation hook
//! for the flagged conversation kinds), the kind-to-category display mapping, the
//! kind-set sanitation that strips the wallet ceiling, the NIP-44 channel
//! envelope shapes, the client-pinned `created_at` signer with its skew guard,
//! and the per-session enforcement (identity binding, replay dedup, size caps,
//! rate limiting, lifetime). The relay subscription and the two modals that use
//! this core live in the GUI; this module never touches I/O beyond the crypto
//! helpers `nip44` already gives us.
//!
//! THE WALLET DECIDES THE TIER, from the event kind and its content, never from
//! anything the site asserts. A money-tier request is never signed silently.

use nostr_sdk::nips::nip44;
use nostr_sdk::{Event, EventBuilder, Keys, Kind, PublicKey, SecretKey, Tag, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

use super::loginuri::LOGIN_EVENT_KIND;

// ---------------------------------------------------------------------------
// Locked constants (the spec's section 12 recommendations, taken as decided).
// ---------------------------------------------------------------------------

/// The Goblin-native channel event kind: a stored, addressed, NIP-44-encrypted
/// envelope carrying a sign request or response, with a NIP-40 `expiration` tag.
/// Stored (not ephemeral) so a request sent while the wallet is backgrounded
/// waits on the relay until the wallet resumes and drains it.
pub const CHANNEL_EVENT_KIND: u16 = 24140;

/// Client `created_at` (and envelope `ts`) must be within this many seconds of
/// the wallet's own clock, matching what the relays and the magick server
/// enforce. Bounds a compromised site from pre/post-dating events.
pub const CREATED_AT_SKEW_SECS: u64 = 300;

/// Hard TTL backstop: a session cannot outlive this, even if neither the site
/// nor the user ends it (spec section 6, recommendation 12.2).
pub const SESSION_TTL_SECS: u64 = 12 * 3600;

/// Idle timeout: a session with no served request for this long ends (12.2).
pub const SESSION_IDLE_SECS: u64 = 30 * 60;

/// The NIP-40 `expiration` a channel request carries: short, so a queued request
/// the wallet never drains lapses rather than lingering.
pub const REQUEST_EXPIRATION_SECS: u64 = 120;

/// Envelope plaintext cap: generous enough for a 1059 gift wrap, small enough to
/// bound abuse (spec section 5.8).
pub const MAX_ENVELOPE_BYTES: usize = 128 * 1024;
/// `event.content` cap.
pub const MAX_CONTENT_BYTES: usize = 64 * 1024;
/// Tag-count and per-tag-byte caps.
pub const MAX_TAGS: usize = 512;
pub const MAX_TAG_BYTES: usize = 8 * 1024;

/// Silent-path rate limits (12.4). Soft: surface a single notice, keep signing.
/// Hard: pause the session (stop serving silent, stay listed as paused).
pub const RATE_SOFT_PER_MIN: usize = 60;
pub const RATE_HARD_PER_5MIN: usize = 600;
/// Decrypt-specific soft cap: reading DMs is the sharpest session capability,
/// so its notice fires sooner and with honest wording ("reading your messages").
pub const RATE_SOFT_DECRYPT_PER_MIN: usize = 30;

/// Cap on the per-session replay-dedup ring. The skew window makes an
/// evicted-then-replayed id already stale, so eviction cannot reopen a replay.
const SEEN_IDS_CAP: usize = 4096;

/// The money-tier kinds: never silent, always a per-action password prompt,
/// always stripped from a requested set. Kind 17 finalizes a purchase and grants
/// value; kind 30402 (a product listing) is a seller's commitment to a price
/// (owner ruling: listing and buying both require the password round-trip).
const MONEY_KINDS: &[u16] = &[17, 30402];

/// The flagged conversation kinds: low as messaging, but their content may
/// commit the user to a payment, so the classifier escalates such a request to
/// the money tier (spec sections 5.5, 5.6, finding B).
const FLAGGED_CONVERSATION_KINDS: &[u16] = &[13, 14, 16, 1059];

// ---------------------------------------------------------------------------
// Tier classification (the security-critical surface).
// ---------------------------------------------------------------------------

/// The risk tier of a request. LOW is silent under a grant; MONEY always raises
/// a per-action password prompt and is never covered by the silent grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
	/// Signed silently when the kind is in the session's `silent_kind_set`.
	Low,
	/// Never silent: a value-moving or value-committing sign.
	Money,
}

/// True for a kind the wallet always treats as money tier, by kind alone.
pub fn is_money_kind(kind: u16) -> bool {
	MONEY_KINDS.contains(&kind)
}

/// The wallet's tier decision for a request, from the event kind AND its
/// content. Never trusts the site. Fail-safe: on any ambiguity about whether a
/// request commits value, this resolves to [`Tier::Money`] (prompt), never
/// [`Tier::Low`] (silent).
///
/// - A money-tier kind ([`is_money_kind`]) is always [`Tier::Money`].
/// - A flagged conversation kind (13, 14, 16, 1059) is [`Tier::Low`] as
///   messaging, but escalates to [`Tier::Money`] when its inspectable content
///   commits the user to a payment ([`content_commits_payment`]).
/// - Everything else follows the kind alone and is [`Tier::Low`].
pub fn classify(kind: u16, content: &str) -> Tier {
	if is_money_kind(kind) {
		return Tier::Money;
	}
	if FLAGGED_CONVERSATION_KINDS.contains(&kind) && content_commits_payment(content) {
		return Tier::Money;
	}
	Tier::Low
}

/// The first-build content-escalation hook for the flagged conversation kinds.
///
/// TODO(audit): the security pass owns the real detector (spec section 9b). This
/// hook parses INSPECTABLE plaintext content and escalates on a payment marker;
/// it cannot see inside opaque NIP-44 ciphertext (a sealed kind 13 or wrapped
/// kind 1059), so a genuine pay-commitment there surfaces instead as a separate
/// money-tier kind-17 sign, which always prompts. Escalation only (never a
/// downgrade), so a false positive costs at most one extra prompt, the bias the
/// spec asks for.
pub fn content_commits_payment(content: &str) -> bool {
	let trimmed = content.trim();
	if trimmed.is_empty() {
		return false;
	}
	match serde_json::from_str::<serde_json::Value>(trimmed) {
		Ok(v) => value_has_payment_marker(&v, 0),
		// Not JSON we can read (plain text, or opaque ciphertext): no escalation
		// here; a real commitment surfaces as a money-tier kind-17 sign.
		Err(_) => false,
	}
}

/// Keys whose presence in an order/message JSON marks a payment commitment.
/// Deliberately broad (amount/total/price catch generic order shapes): a false
/// positive costs one extra prompt, the bias the spec asks for.
const PAYMENT_MARKER_KEYS: &[&str] = &[
	"payment",
	"payment_request",
	"bolt11",
	"invoice",
	"amount",
	"amount_sat",
	"amount_sats",
	"msat",
	"total",
	"price",
	"payment_hash",
	"preimage",
];

/// Recursively (bounded depth) scan a JSON value for a payment marker.
fn value_has_payment_marker(v: &serde_json::Value, depth: usize) -> bool {
	if depth > 6 {
		return false;
	}
	match v {
		serde_json::Value::Object(map) => {
			for (k, val) in map {
				let lk = k.to_ascii_lowercase();
				if PAYMENT_MARKER_KEYS.contains(&lk.as_str()) && !val.is_null() {
					return true;
				}
				if value_has_payment_marker(val, depth + 1) {
					return true;
				}
			}
			false
		}
		serde_json::Value::Array(items) => {
			items.iter().any(|x| value_has_payment_marker(x, depth + 1))
		}
		_ => false,
	}
}

// ---------------------------------------------------------------------------
// Kind-set sanitation (strip the wallet ceiling) and category display.
// ---------------------------------------------------------------------------

/// The `silent_kind_set` the wallet stores from a requested set: deduplicated,
/// first-seen order preserved, with the ceiling removed. The ceiling is kind
/// 22242 (login, never in any session set) and every money-tier kind (never
/// silent). Everything left may be signed silently once the tier classifier also
/// agrees it is low tier per request.
pub fn sanitize_kind_set(requested: &[u16]) -> Vec<u16> {
	let mut out = Vec::new();
	for &k in requested {
		if k == LOGIN_EVENT_KIND || is_money_kind(k) {
			continue;
		}
		if !out.contains(&k) {
			out.push(k);
		}
	}
	out
}

/// A human category the grant prompt renders instead of raw kind numbers. Each
/// carries a stable i18n key. Money-tier kinds never map here (they are covered
/// by the fixed "money will always ask" line); unrecognized low kinds fall
/// through to a per-kind caution line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustCategory {
	/// Posts and reactions: 1, 6, 7, 1111.
	Social,
	/// Direct messages: 13, 14, 16, 1059.
	DirectMessages,
	/// Listings: 30405, 30406, 31990 (30402 is money tier, owner ruling).
	Market,
	/// Profile and lists: 0, 10000, 30000, 30003, 30078.
	Identity,
	/// Deletes: 5.
	Delete,
	/// Uploads and HTTP auth: 24242, 27235.
	Http,
}

impl TrustCategory {
	/// The i18n key for this category's label.
	pub fn key(self) -> &'static str {
		match self {
			TrustCategory::Social => "goblin.trust.cat_social",
			TrustCategory::DirectMessages => "goblin.trust.cat_dm",
			TrustCategory::Market => "goblin.trust.cat_market",
			TrustCategory::Identity => "goblin.trust.cat_identity",
			TrustCategory::Delete => "goblin.trust.cat_delete",
			TrustCategory::Http => "goblin.trust.cat_http",
		}
	}

	/// A stable render order, so the prompt reads the same every time.
	const ORDER: [TrustCategory; 6] = [
		TrustCategory::Social,
		TrustCategory::DirectMessages,
		TrustCategory::Market,
		TrustCategory::Identity,
		TrustCategory::Delete,
		TrustCategory::Http,
	];
}

/// The category a LOW-tier kind belongs to, or `None` for an unrecognized kind
/// (which the prompt renders on its own caution line). Total over all `u16`.
pub fn category_for_kind(kind: u16) -> Option<TrustCategory> {
	match kind {
		1 | 6 | 7 | 1111 => Some(TrustCategory::Social),
		13 | 14 | 16 | 1059 => Some(TrustCategory::DirectMessages),
		// 30402 (listing) is money tier by owner ruling, never a granted category.
		30405 | 30406 | 31990 => Some(TrustCategory::Market),
		0 | 10000 | 30000 | 30003 | 30078 => Some(TrustCategory::Identity),
		5 => Some(TrustCategory::Delete),
		24242 | 27235 => Some(TrustCategory::Http),
		_ => None,
	}
}

/// What the trust prompt renders from the site's RAW requested kind set: the
/// deduplicated low-tier categories being granted, the unrecognized low kinds
/// shown one caution line each, and whether login (22242) was requested and
/// stripped. Money-tier kinds requested are silently folded into the fixed
/// "money always asks" line and appear nowhere as a grant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantDisplay {
	/// Granted low-tier categories, in [`TrustCategory::ORDER`].
	pub categories: Vec<TrustCategory>,
	/// Unrecognized low-tier kinds (each a caution line).
	pub unknown_kinds: Vec<u16>,
	/// True when the site requested kind 22242 and the wallet stripped it.
	pub stripped_login: bool,
}

/// Build the grant prompt's render plan from the raw requested kinds. Pure and
/// unit-testable, so it is verifiable without a running GUI.
pub fn render_grant(requested: &[u16]) -> GrantDisplay {
	let mut present = [false; 6];
	let mut unknown_kinds = Vec::new();
	let mut stripped_login = false;
	for &k in requested {
		if k == LOGIN_EVENT_KIND {
			stripped_login = true;
			continue;
		}
		if is_money_kind(k) {
			// Covered by the fixed money line; never a granted category.
			continue;
		}
		match category_for_kind(k) {
			Some(cat) => {
				let idx = TrustCategory::ORDER.iter().position(|c| *c == cat).unwrap();
				present[idx] = true;
			}
			None => {
				if !unknown_kinds.contains(&k) {
					unknown_kinds.push(k);
				}
			}
		}
	}
	let categories = TrustCategory::ORDER
		.iter()
		.enumerate()
		.filter(|(i, _)| present[*i])
		.map(|(_, c)| *c)
		.collect();
	GrantDisplay {
		categories,
		unknown_kinds,
		stripped_login,
	}
}

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

/// `|a - b|` on unsigned clocks without overflow.
fn abs_diff(a: u64, b: u64) -> u64 {
	a.abs_diff(b)
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
// The session object and its enforcement.
// ---------------------------------------------------------------------------

/// A live signing session for one domain and one identity. Held in memory only
/// (restart equals end). The channel keypair, the site's channel key, and the
/// approved silent kind set are set once at grant time and never widened.
#[derive(Debug, Clone)]
pub struct Session {
	/// The trusted domain, exactly as approved. The channel's origin binding.
	pub domain: String,
	/// The chosen signing identity. Every silent sign uses this key and no other.
	pub identity_pubkey: PublicKey,
	/// A display label for the Trusted Sites list.
	pub label: String,
	/// The approved LOW-tier kinds. Ceiling already stripped (never 22242, never
	/// a money kind).
	pub silent_kind_set: Vec<u16>,
	/// The wallet's ephemeral channel secret key for this session.
	pub wallet_channel_sk: SecretKey,
	/// The wallet's ephemeral channel public key (published in `session-open`).
	pub wallet_channel_pk: PublicKey,
	/// The site's ephemeral channel public key. The only key allowed to request.
	pub site_session_pubkey: PublicKey,
	/// The relay hint plus wallet fallbacks the channel runs on.
	pub relays: Vec<String>,
	/// Grant time (unix seconds).
	pub created_at: u64,
	/// Hard TTL backstop.
	pub expires_at: u64,
	/// Updated on every served request; drives the idle timeout.
	pub last_used_at: u64,
	/// True once the hard rate cap tripped: the silent path stops serving until
	/// the user resumes or ends the session.
	pub paused: bool,
	/// Set when the session has ended (logout, wallet end, TTL, idle).
	pub ended: bool,
	/// True once the wallet's `session-open` envelope was CONFIRMED accepted by a
	/// relay the site is listening on (the hint relay). Only then is the channel
	/// live for the site; until then the loop keeps re-publishing.
	pub announced: bool,
	/// How many times the loop has attempted to publish this session's
	/// `session-open`. Bounds the confirm-or-retry loop so a dead hint relay can
	/// never spin the service for the whole session TTL.
	pub announce_attempts: u32,
	/// Replay-dedup ring: request id -> cached response JSON. A duplicate id
	/// returns the cached result, never a second signature.
	seen: HashMap<String, String>,
	/// FIFO of seen ids for bounded eviction.
	seen_order: VecDeque<String>,
	/// Timestamps (unix seconds) of served silent signs, for the rate windows.
	silent_times: VecDeque<u64>,
	/// Timestamps of served decrypts, for the decrypt-specific soft notice
	/// ("this site is reading your messages"), separate from the sign counter.
	decrypt_times: VecDeque<u64>,
	/// Request ids whose money-tier prompt is currently awaiting the user. A
	/// replayed envelope (normal when a drain overlaps the live subscription)
	/// finds its id here and does NOT raise a second prompt or re-sign; the id
	/// moves to `seen` when the prompt completes.
	money_pending_ids: std::collections::HashSet<String>,
}

/// The wallet's decision for a request, produced by [`Session::decide`] before
/// any signing. The runtime acts on it: sign silently, raise the money prompt,
/// send a refusal, or return the cached duplicate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
	/// Low tier, in the set, all checks pass: sign silently. `notify_high_volume`
	/// is set when the soft rate cap tripped (surface a notice, still sign).
	Silent { notify_high_volume: bool },
	/// Money tier: raise the per-action password prompt, never silent.
	MoneyPrompt,
	/// This id's money prompt is already awaiting the user: do nothing (no second
	/// prompt, no response; the original prompt's answer covers it).
	AlreadyPending,
	/// Refuse and return this typed error on the channel.
	Refuse(SignError),
	/// A replayed id: return the cached response JSON verbatim.
	Duplicate(String),
}

impl Session {
	/// Create a session at grant time. `requested` is the site's RAW kind set;
	/// the ceiling is stripped here so `silent_kind_set` can never hold 22242 or
	/// a money kind.
	#[allow(clippy::too_many_arguments)]
	pub fn new(
		domain: String,
		identity_pubkey: PublicKey,
		label: String,
		requested: &[u16],
		wallet_channel: &Keys,
		site_session_pubkey: PublicKey,
		relays: Vec<String>,
		now: u64,
	) -> Self {
		Session {
			domain,
			identity_pubkey,
			label,
			silent_kind_set: sanitize_kind_set(requested),
			wallet_channel_sk: wallet_channel.secret_key().clone(),
			wallet_channel_pk: wallet_channel.public_key(),
			site_session_pubkey,
			relays,
			created_at: now,
			expires_at: now + SESSION_TTL_SECS,
			last_used_at: now,
			paused: false,
			ended: false,
			announced: false,
			announce_attempts: 0,
			seen: HashMap::new(),
			seen_order: VecDeque::new(),
			silent_times: VecDeque::new(),
			decrypt_times: VecDeque::new(),
			money_pending_ids: std::collections::HashSet::new(),
		}
	}

	/// True when the TTL or idle timeout has lapsed as of `now`.
	pub fn is_expired(&self, now: u64) -> bool {
		now >= self.expires_at || now.saturating_sub(self.last_used_at) >= SESSION_IDLE_SECS
	}

	/// Seconds until the hard TTL, for the session-detail screen (0 once past).
	pub fn ttl_remaining(&self, now: u64) -> u64 {
		self.expires_at.saturating_sub(now)
	}

	/// Classify a decoded request against this live session, mutating only the
	/// rate window and lifetime flags. Every rule fails closed. Does NOT record
	/// the request as seen or bump the served counter: the runtime calls
	/// [`Session::remember`] once it has actually produced a response, so a
	/// refused or still-pending request never consumes replay/rate budget.
	pub fn decide(&mut self, req: &SignRequest, now: u64) -> Decision {
		if self.ended {
			return Decision::Refuse(SignError::SessionEnded);
		}
		if self.is_expired(now) {
			self.ended = true;
			return Decision::Refuse(SignError::SessionEnded);
		}
		if self.paused {
			return Decision::Refuse(SignError::SessionPaused);
		}
		// Replay: a duplicate id returns the cached prior result, never a re-sign.
		if let Some(cached) = self.seen.get(&req.id) {
			return Decision::Duplicate(cached.clone());
		}
		// A money prompt already awaiting the user for this id: never a second
		// prompt (a re-delivered envelope is normal when a drain overlaps the
		// live subscription).
		if self.money_pending_ids.contains(&req.id) {
			return Decision::AlreadyPending;
		}
		// Envelope timestamp skew, checked before the inner event is examined.
		if abs_diff(req.ts, now) > CREATED_AT_SKEW_SECS {
			return Decision::Refuse(SignError::StaleRequest);
		}
		// Size caps.
		if let Err(e) = self.check_size(req) {
			return Decision::Refuse(e);
		}
		// Identity binding.
		match PublicKey::from_hex(&req.event.pubkey) {
			Ok(pk) if pk == self.identity_pubkey => {}
			Ok(_) => return Decision::Refuse(SignError::IdentityMismatch),
			Err(_) => return Decision::Refuse(SignError::Malformed),
		}
		// Inner-event skew.
		if abs_diff(req.event.created_at, now) > CREATED_AT_SKEW_SECS {
			return Decision::Refuse(SignError::StaleRequest);
		}
		// Outright refusals: never signed by the session path, not even money.
		if req.event.kind == LOGIN_EVENT_KIND {
			return Decision::Refuse(SignError::Refused);
		}
		if req
			.event
			.tags
			.iter()
			.any(|t| t.first().map(|k| k == "delegation").unwrap_or(false))
		{
			return Decision::Refuse(SignError::Refused);
		}
		// Tier classification runs before the silent path, from kind AND content.
		match classify(req.event.kind, &req.event.content) {
			Tier::Money => {
				// Reserve the id the moment the prompt is raised, so a replay can
				// never re-prompt or re-sign; released into `seen` on completion.
				self.money_pending_ids.insert(req.id.clone());
				Decision::MoneyPrompt
			}
			Tier::Low => {
				if !self.silent_kind_set.contains(&req.event.kind) {
					return Decision::Refuse(SignError::KindNotInSession);
				}
				// Rate limiting on the silent path only.
				self.trim_rate_window(now);
				if self.silent_times.len() >= RATE_HARD_PER_5MIN {
					self.paused = true;
					return Decision::Refuse(SignError::SessionPaused);
				}
				let notify = self.count_last_minute(now) >= RATE_SOFT_PER_MIN;
				Decision::Silent {
					notify_high_volume: notify,
				}
			}
		}
	}

	/// The session-level decision for an encrypt/decrypt op (no kind/tier by
	/// event, since there is no event): the same lifetime, pause, replay, skew,
	/// and rate gates as [`Session::decide`], then `MoneyPrompt` when `escalate`
	/// (a pay-committing encrypt plaintext) else `Silent`.
	pub fn decide_crypto(&mut self, id: &str, ts: u64, now: u64, escalate: bool) -> Decision {
		if self.ended {
			return Decision::Refuse(SignError::SessionEnded);
		}
		if self.is_expired(now) {
			self.ended = true;
			return Decision::Refuse(SignError::SessionEnded);
		}
		if self.paused {
			return Decision::Refuse(SignError::SessionPaused);
		}
		if let Some(cached) = self.seen.get(id) {
			return Decision::Duplicate(cached.clone());
		}
		if self.money_pending_ids.contains(id) {
			return Decision::AlreadyPending;
		}
		if abs_diff(ts, now) > CREATED_AT_SKEW_SECS {
			return Decision::Refuse(SignError::StaleRequest);
		}
		self.trim_rate_window(now);
		if self.silent_times.len() >= RATE_HARD_PER_5MIN {
			self.paused = true;
			return Decision::Refuse(SignError::SessionPaused);
		}
		let notify = self.count_last_minute(now) >= RATE_SOFT_PER_MIN;
		if escalate {
			// Reserve the id so a replay never raises a second prompt.
			self.money_pending_ids.insert(id.to_string());
			Decision::MoneyPrompt
		} else {
			Decision::Silent {
				notify_high_volume: notify,
			}
		}
	}

	/// Record a produced response for `id` (both tiers) so a replay returns it
	/// verbatim, bump the idle clock, and — for a served silent sign — count it
	/// toward the rate windows. Call this exactly once per request the wallet
	/// answers (success OR typed refusal that should not be retried into a second
	/// signature); do NOT call it for a still-pending money prompt.
	pub fn remember(&mut self, id: &str, response_json: &str, counted_silent_sign: bool, now: u64) {
		self.last_used_at = now;
		// A completed money prompt releases its pending reservation; replays of
		// the id now hit the `seen` cache below instead.
		self.money_pending_ids.remove(id);
		if counted_silent_sign {
			self.silent_times.push_back(now);
			self.trim_rate_window(now);
		}
		if self.seen.contains_key(id) {
			return;
		}
		self.seen.insert(id.to_string(), response_json.to_string());
		self.seen_order.push_back(id.to_string());
		while self.seen_order.len() > SEEN_IDS_CAP {
			if let Some(old) = self.seen_order.pop_front() {
				self.seen.remove(&old);
			}
		}
	}

	/// Count one served decrypt toward the decrypt-specific window and report
	/// whether the decrypt soft cap tripped (the "reading your messages" notice).
	fn note_decrypt(&mut self, now: u64) -> bool {
		let cutoff = now.saturating_sub(60);
		while let Some(&front) = self.decrypt_times.front() {
			if front < cutoff {
				self.decrypt_times.pop_front();
			} else {
				break;
			}
		}
		self.decrypt_times.push_back(now);
		self.decrypt_times.len() > RATE_SOFT_DECRYPT_PER_MIN
	}

	/// End the session unilaterally (wallet-side end, or on a `session-end`
	/// envelope). Immediate and final: any later request refuses.
	pub fn end(&mut self) {
		self.ended = true;
	}

	/// The wallet's ephemeral channel keypair (reconstructed from the stored
	/// secret) for signing and decrypting channel envelopes.
	fn channel_keys(&self) -> Keys {
		Keys::new(self.wallet_channel_sk.clone())
	}

	/// Decrypt a channel envelope from the site (its outer event `pubkey` must be
	/// `site_session_pubkey`, checked by the caller) into its plaintext payload.
	pub fn decrypt(&self, sender: &PublicKey, payload: &str) -> Result<String, String> {
		open_envelope(&self.wallet_channel_sk, sender, payload)
	}

	/// Wrap a plaintext payload as a signed, NIP-44-encrypted, addressed channel
	/// event (kind [`CHANNEL_EVENT_KIND`]) carrying a NIP-40 `expiration` tag,
	/// ready to publish back to the site.
	pub fn wrap_channel_event(&self, plaintext: &str, now: u64) -> Result<Event, String> {
		let content = seal_envelope(
			&self.wallet_channel_sk,
			&self.site_session_pubkey,
			plaintext,
		)?;
		let exp = Timestamp::from(now + REQUEST_EXPIRATION_SECS);
		EventBuilder::new(Kind::from(CHANNEL_EVENT_KIND), content)
			.tags(vec![
				Tag::public_key(self.site_session_pubkey),
				Tag::expiration(exp),
			])
			.sign_with_keys(&self.channel_keys())
			.map_err(|e| e.to_string())
	}

	/// The `session-open` channel event: hands the site the wallet channel key
	/// (the event's own `pubkey`) and confirms the signing identity.
	pub fn session_open_event(&self, now: u64) -> Result<Event, String> {
		let open = SessionOpen {
			msg_type: "session-open".to_string(),
			id: self.wallet_channel_pk.to_hex(),
			identity_pubkey: self.identity_pubkey.to_hex(),
		};
		let json = serde_json::to_string(&open).map_err(|e| e.to_string())?;
		self.wrap_channel_event(&json, now)
	}

	/// The `session-end` channel event: tells the site the wallet ended the
	/// session, with why ("revoked" for a wallet-side end, "expired" for the
	/// TTL/idle backstop). A courtesy the site displays; the teardown is
	/// unilateral regardless of delivery.
	pub fn session_end_event(&self, now: u64, reason: &str) -> Result<Event, String> {
		let end = SessionEnd {
			msg_type: "session-end".to_string(),
			reason: reason.to_string(),
		};
		let json = serde_json::to_string(&end).map_err(|e| e.to_string())?;
		self.wrap_channel_event(&json, now)
	}

	/// A read-only snapshot for the Trusted Sites list.
	pub fn summary(&self, now: u64) -> SessionSummary {
		SessionSummary {
			domain: self.domain.clone(),
			label: self.label.clone(),
			categories: render_grant(&self.silent_kind_set).categories,
			ttl_remaining_secs: self.ttl_remaining(now),
			paused: self.paused,
		}
	}

	/// Resume a paused session (the user tapped "resume"). Clears the pause and
	/// the rate window so counting starts fresh.
	pub fn resume(&mut self, now: u64) {
		self.paused = false;
		self.silent_times.clear();
		self.last_used_at = now;
	}

	/// Size caps: envelope plaintext, content, tag count, per-tag bytes.
	fn check_size(&self, req: &SignRequest) -> Result<(), SignError> {
		if req.event.content.len() > MAX_CONTENT_BYTES {
			return Err(SignError::TooLarge);
		}
		if req.event.tags.len() > MAX_TAGS {
			return Err(SignError::TooLarge);
		}
		for tag in &req.event.tags {
			let bytes: usize = tag.iter().map(|s| s.len()).sum();
			if bytes > MAX_TAG_BYTES {
				return Err(SignError::TooLarge);
			}
		}
		Ok(())
	}

	/// Drop rate-window entries older than 5 minutes.
	fn trim_rate_window(&mut self, now: u64) {
		let cutoff = now.saturating_sub(5 * 60);
		while let Some(&front) = self.silent_times.front() {
			if front < cutoff {
				self.silent_times.pop_front();
			} else {
				break;
			}
		}
	}

	/// Count served silent signs in the last minute.
	fn count_last_minute(&self, now: u64) -> usize {
		let cutoff = now.saturating_sub(60);
		self.silent_times.iter().filter(|&&t| t >= cutoff).count()
	}
}

/// Total plaintext-envelope byte check, applied at the transport layer before
/// JSON parse (the whole decrypted plaintext, not just `content`).
pub fn envelope_within_cap(plaintext: &str) -> bool {
	plaintext.len() <= MAX_ENVELOPE_BYTES
}

/// A read-only snapshot of a session for the Trusted Sites list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSummary {
	pub domain: String,
	pub label: String,
	/// The low-tier categories this session can sign silently.
	pub categories: Vec<TrustCategory>,
	/// Seconds until the hard TTL (the session-detail "time remaining").
	pub ttl_remaining_secs: u64,
	/// True when the hard rate cap paused the silent path.
	pub paused: bool,
}

/// A money-tier request awaiting the user's per-action password prompt. The
/// runtime hands one of these to the GUI, which raises the v1-style authorize
/// modal; the GUI's answer routes back through [`complete_money`].
#[derive(Debug, Clone)]
pub struct PendingMoney {
	/// The trusted domain the request arrived on (display only).
	pub domain: String,
	/// The site channel key of the session the request arrived on: the answer is
	/// routed back by THIS key, never by the display domain, so two sessions with
	/// a lookalike domain string can never receive each other's approvals.
	pub site_session_pubkey: PublicKey,
	/// The signing identity for this session (looked up to act on approval).
	pub identity_pubkey: PublicKey,
	/// The operation to perform on approval (a sign, or a pay-committing encrypt).
	pub op: ChannelOp,
}

impl PendingMoney {
	/// The correlation id, used to route the user's answer.
	pub fn id(&self) -> &str {
		self.op.id()
	}
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

#[cfg(test)]
mod tests {
	use super::*;

	fn low_content() -> &'static str {
		"gm"
	}

	#[test]
	fn money_kind_always_money() {
		assert_eq!(classify(17, ""), Tier::Money);
		// Owner ruling: a product listing (30402) is a commitment, money tier.
		assert_eq!(classify(30402, ""), Tier::Money);
		assert!(is_money_kind(17));
		assert!(is_money_kind(30402));
		assert!(!is_money_kind(1));
		assert!(!is_money_kind(30405));
	}

	#[test]
	fn plain_low_kinds_are_low() {
		for k in [
			0u16, 1, 5, 7, 1111, 10000, 30000, 30003, 30078, 30405, 30406, 24242, 27235,
		] {
			assert_eq!(classify(k, low_content()), Tier::Low, "kind {k}");
		}
	}

	#[test]
	fn flagged_conversation_low_by_default_money_on_payment_content() {
		for k in [13u16, 14, 16, 1059] {
			// Plain message: low.
			assert_eq!(classify(k, "hello there"), Tier::Low, "kind {k} plain");
			// Order JSON with a payment marker: escalates to money.
			let paying = r#"{"type":"order","payment":{"bolt11":"lnbc1..."}}"#;
			assert_eq!(classify(k, paying), Tier::Money, "kind {k} paying");
			// A nested marker is caught too.
			let nested = r#"{"order":{"items":[{"amount_sat":1000}]}}"#;
			assert_eq!(classify(k, nested), Tier::Money, "kind {k} nested");
		}
		// A non-flagged kind is NOT escalated even with payment-looking content.
		assert_eq!(
			classify(1, r#"{"payment":{"bolt11":"x"}}"#),
			Tier::Low,
			"kind 1 is not a flagged conversation kind"
		);
	}

	#[test]
	fn content_marker_ignores_opaque_and_plain() {
		assert!(!content_commits_payment("just some text"));
		assert!(!content_commits_payment("")); // empty
		assert!(!content_commits_payment("Agk7d9...base64ish-ciphertext")); // not JSON
		assert!(content_commits_payment(r#"{"invoice":"lnbc1"}"#));
		assert!(!content_commits_payment(r#"{"invoice":null}"#)); // null marker ignored
	}

	#[test]
	fn sanitize_strips_login_and_money_and_dedups() {
		let got = sanitize_kind_set(&[22242, 1, 17, 7, 1, 17, 22242, 1059]);
		assert_eq!(got, vec![1, 7, 1059]);
		// All-ceiling strips to empty.
		assert!(sanitize_kind_set(&[22242, 17]).is_empty());
	}

	#[test]
	fn category_mapping_matches_spec_table() {
		assert_eq!(category_for_kind(1), Some(TrustCategory::Social));
		assert_eq!(category_for_kind(7), Some(TrustCategory::Social));
		assert_eq!(category_for_kind(1111), Some(TrustCategory::Social));
		assert_eq!(category_for_kind(13), Some(TrustCategory::DirectMessages));
		assert_eq!(category_for_kind(1059), Some(TrustCategory::DirectMessages));
		// 30402 (listing) is money tier by owner ruling, not a low category.
		assert_eq!(category_for_kind(30402), None);
		assert_eq!(category_for_kind(30405), Some(TrustCategory::Market));
		assert_eq!(category_for_kind(31990), Some(TrustCategory::Market));
		assert_eq!(category_for_kind(0), Some(TrustCategory::Identity));
		assert_eq!(category_for_kind(30078), Some(TrustCategory::Identity));
		assert_eq!(category_for_kind(5), Some(TrustCategory::Delete));
		assert_eq!(category_for_kind(24242), Some(TrustCategory::Http));
		assert_eq!(category_for_kind(27235), Some(TrustCategory::Http));
		// Kind 17 (money) is not a display category.
		assert_eq!(category_for_kind(17), None);
		assert_eq!(category_for_kind(60000), None);
	}

	#[test]
	fn render_grant_dedups_orders_and_flags_ceiling() {
		let d = render_grant(&[1, 7, 1059, 30405, 30402, 22242, 17, 55555]);
		assert_eq!(
			d.categories,
			vec![
				TrustCategory::Social,
				TrustCategory::DirectMessages,
				TrustCategory::Market,
			]
		);
		assert_eq!(d.unknown_kinds, vec![55555]);
		assert!(d.stripped_login);
		// 30402 is money now: stripped, never an unknown/caution line.
		assert!(!d.unknown_kinds.contains(&30402));
		// Money kind 17 appears nowhere: not a category, not an unknown line.
		assert!(!d.unknown_kinds.contains(&17));
	}

	#[test]
	fn sign_pins_created_at_and_matches_ndk_id() {
		let keys = Keys::generate();
		let now = 1_751_800_000u64;
		let pinned = now - 42; // client-composed time, inside skew
		let ev = RequestEvent {
			pubkey: keys.public_key().to_hex(),
			created_at: pinned,
			kind: 7,
			tags: vec![
				vec!["e".to_string(), "abc".to_string()],
				vec!["p".to_string(), "def".to_string()],
			],
			content: "+".to_string(),
		};
		let signed = sign_session_event(&keys, &ev, now).expect("sign");
		assert_eq!(
			signed.created_at.as_secs(),
			pinned,
			"created_at must be pinned"
		);
		assert_eq!(signed.pubkey, keys.public_key());
		assert_eq!(signed.kind.as_u16(), 7);
		assert_eq!(signed.content, "+");
		assert!(signed.verify().is_ok());
		// Recomputing NDK-style over the same fields yields the same id: build a
		// second event with the same pinned time and compare ids.
		let again = sign_session_event(&keys, &ev, now).expect("sign again");
		assert_eq!(
			signed.id, again.id,
			"id is a pure function of pinned fields"
		);
	}

	#[test]
	fn sign_rejects_wrong_identity_login_and_delegation() {
		let keys = Keys::generate();
		let other = Keys::generate();
		let now = 1_751_800_000u64;
		let base = RequestEvent {
			pubkey: keys.public_key().to_hex(),
			created_at: now,
			kind: 1,
			tags: vec![],
			content: "x".to_string(),
		};
		// Wrong pubkey.
		let mut wrong = base.clone();
		wrong.pubkey = other.public_key().to_hex();
		assert_eq!(
			sign_session_event(&keys, &wrong, now),
			Err(SignError::IdentityMismatch)
		);
		// Login kind refused outright.
		let mut login = base.clone();
		login.kind = LOGIN_EVENT_KIND;
		assert_eq!(
			sign_session_event(&keys, &login, now),
			Err(SignError::Refused)
		);
		// Delegation tag refused outright.
		let mut deleg = base.clone();
		deleg.tags = vec![vec!["delegation".to_string(), "x".to_string()]];
		assert_eq!(
			sign_session_event(&keys, &deleg, now),
			Err(SignError::Refused)
		);
		// Out-of-skew created_at.
		let mut stale = base.clone();
		stale.created_at = now + CREATED_AT_SKEW_SECS + 5;
		assert_eq!(
			sign_session_event(&keys, &stale, now),
			Err(SignError::StaleRequest)
		);
	}

	fn mk_session(kinds: &[u16], now: u64) -> (Session, Keys) {
		let identity = Keys::generate();
		let wallet_channel = Keys::generate();
		let site = Keys::generate();
		let s = Session::new(
			"magick.market".to_string(),
			identity.public_key(),
			"magick.market".to_string(),
			kinds,
			&wallet_channel,
			site.public_key(),
			vec!["wss://relay.magick.market".to_string()],
			now,
		);
		(s, identity)
	}

	fn mk_req(identity: &Keys, kind: u16, content: &str, now: u64, id: &str) -> SignRequest {
		SignRequest {
			msg_type: "sign".to_string(),
			id: id.to_string(),
			ts: now,
			event: RequestEvent {
				pubkey: identity.public_key().to_hex(),
				created_at: now,
				kind,
				tags: vec![],
				content: content.to_string(),
			},
		}
	}

	#[test]
	fn decide_silent_money_and_not_in_set() {
		let now = 1_751_800_000u64;
		let (mut s, id) = mk_session(&[1, 7, 14], now);
		// Low + in set -> silent.
		let r = mk_req(&id, 7, "+", now, "a");
		assert_eq!(
			s.decide(&r, now),
			Decision::Silent {
				notify_high_volume: false
			}
		);
		// Money kind -> prompt (even though the site never listed 17).
		let r = mk_req(&id, 17, "{}", now, "b");
		assert_eq!(s.decide(&r, now), Decision::MoneyPrompt);
		// Flagged kind with paying content -> prompt, despite kind 14 being in set.
		let r = mk_req(&id, 14, r#"{"payment":{"bolt11":"x"}}"#, now, "c");
		assert_eq!(s.decide(&r, now), Decision::MoneyPrompt);
		// Low kind NOT in set -> refuse (not prompt).
		let r = mk_req(&id, 5, "", now, "d");
		assert_eq!(
			s.decide(&r, now),
			Decision::Refuse(SignError::KindNotInSession)
		);
	}

	#[test]
	fn decide_identity_skew_login_delegation() {
		let now = 1_751_800_000u64;
		let (mut s, id) = mk_session(&[1], now);
		// Wrong identity.
		let mut r = mk_req(&id, 1, "x", now, "a");
		r.event.pubkey = Keys::generate().public_key().to_hex();
		assert_eq!(
			s.decide(&r, now),
			Decision::Refuse(SignError::IdentityMismatch)
		);
		// Envelope ts stale.
		let r = mk_req(&id, 1, "x", now, "b");
		let mut stale = r.clone();
		stale.ts = now + 10_000;
		assert_eq!(
			s.decide(&stale, now),
			Decision::Refuse(SignError::StaleRequest)
		);
		// Login kind.
		let r = mk_req(&id, LOGIN_EVENT_KIND, "", now, "c");
		assert_eq!(s.decide(&r, now), Decision::Refuse(SignError::Refused));
		// Delegation tag.
		let mut r = mk_req(&id, 1, "x", now, "e");
		r.event.tags = vec![vec!["delegation".to_string(), "z".to_string()]];
		assert_eq!(s.decide(&r, now), Decision::Refuse(SignError::Refused));
	}

	#[test]
	fn replay_returns_cached_result() {
		let now = 1_751_800_000u64;
		let (mut s, id) = mk_session(&[7], now);
		let r = mk_req(&id, 7, "+", now, "dup");
		assert_eq!(
			s.decide(&r, now),
			Decision::Silent {
				notify_high_volume: false
			}
		);
		// The runtime signs and remembers the response.
		s.remember(
			"dup",
			r#"{"type":"sign_result","id":"dup","ok":true}"#,
			true,
			now,
		);
		// A second decide with the same id returns the cached JSON.
		match s.decide(&r, now) {
			Decision::Duplicate(json) => assert!(json.contains("\"id\":\"dup\"")),
			other => panic!("expected Duplicate, got {other:?}"),
		}
	}

	#[test]
	fn rate_soft_then_hard_pause() {
		let now = 1_751_800_000u64;
		let (mut s, id) = mk_session(&[7], now);
		// Serve up to the soft cap: no notify until the window hits the soft cap.
		for i in 0..RATE_SOFT_PER_MIN {
			let r = mk_req(&id, 7, "+", now, &format!("s{i}"));
			let d = s.decide(&r, now);
			assert_eq!(
				d,
				Decision::Silent {
					notify_high_volume: false
				}
			);
			s.remember(&format!("s{i}"), "{}", true, now);
		}
		// The next one trips the soft cap notice.
		let r = mk_req(&id, 7, "+", now, "soft");
		assert_eq!(
			s.decide(&r, now),
			Decision::Silent {
				notify_high_volume: true
			}
		);
		s.remember("soft", "{}", true, now);
		// Fill to the hard cap.
		for i in 0..(RATE_HARD_PER_5MIN - RATE_SOFT_PER_MIN - 1) {
			s.remember(&format!("h{i}"), "{}", true, now);
		}
		// Now at the hard cap: the next decide pauses the session.
		let r = mk_req(&id, 7, "+", now, "hard");
		assert_eq!(
			s.decide(&r, now),
			Decision::Refuse(SignError::SessionPaused)
		);
		assert!(s.paused);
		// Resume clears it.
		s.resume(now);
		let r = mk_req(&id, 7, "+", now, "after");
		assert_eq!(
			s.decide(&r, now),
			Decision::Silent {
				notify_high_volume: false
			}
		);
	}

	#[test]
	fn size_caps_refuse() {
		let now = 1_751_800_000u64;
		let (mut s, id) = mk_session(&[1], now);
		let mut r = mk_req(&id, 1, "x", now, "big");
		r.event.content = "a".repeat(MAX_CONTENT_BYTES + 1);
		assert_eq!(s.decide(&r, now), Decision::Refuse(SignError::TooLarge));
		assert!(!envelope_within_cap(&"x".repeat(MAX_ENVELOPE_BYTES + 1)));
		assert!(envelope_within_cap("small"));
	}

	#[test]
	fn lifetime_expiry_and_idle_and_end() {
		let now = 1_751_800_000u64;
		let (mut s, id) = mk_session(&[7], now);
		// Past the hard TTL.
		let later = now + SESSION_TTL_SECS + 1;
		let r = mk_req(&id, 7, "+", later, "x");
		let mut expired = r.clone();
		expired.ts = later;
		expired.event.created_at = later;
		assert_eq!(
			s.decide(&expired, later),
			Decision::Refuse(SignError::SessionEnded)
		);
		// A fresh session that goes idle also ends.
		let (mut s2, id2) = mk_session(&[7], now);
		let idle_at = now + SESSION_IDLE_SECS + 1;
		let mut idle = mk_req(&id2, 7, "+", idle_at, "y");
		idle.ts = idle_at;
		idle.event.created_at = idle_at;
		assert_eq!(
			s2.decide(&idle, idle_at),
			Decision::Refuse(SignError::SessionEnded)
		);
		// Wallet-side end refuses immediately.
		let (mut s3, id3) = mk_session(&[7], now);
		s3.end();
		let r = mk_req(&id3, 7, "+", now, "z");
		assert_eq!(
			s3.decide(&r, now),
			Decision::Refuse(SignError::SessionEnded)
		);
	}

	#[test]
	fn envelope_roundtrip_and_result_shapes() {
		let wallet = Keys::generate();
		let site = Keys::generate();
		let plaintext = r#"{"type":"session-open","wallet_pubkey":"aa","identity":"bb"}"#;
		let sealed = seal_envelope(wallet.secret_key(), &site.public_key(), plaintext).unwrap();
		// The site opens it with (site sk, wallet pk).
		let opened = open_envelope(site.secret_key(), &wallet.public_key(), &sealed).unwrap();
		assert_eq!(opened, plaintext);
		// SignResult ok/refused serialize with the exact wire fields.
		let keys = Keys::generate();
		let ev = sign_session_event(
			&keys,
			&RequestEvent {
				pubkey: keys.public_key().to_hex(),
				created_at: 1_751_800_000,
				kind: 1,
				tags: vec![],
				content: "hi".to_string(),
			},
			1_751_800_000,
		)
		.unwrap();
		let ok = serde_json::to_string(&SignResult::ok("u1", &ev)).unwrap();
		assert!(ok.contains("\"type\":\"sign_result\""));
		assert!(ok.contains("\"ok\":true"));
		assert!(ok.contains("\"id\":\"u1\""));
		let refused =
			serde_json::to_string(&SignResult::refused("u2", SignError::KindNotInSession)).unwrap();
		assert!(refused.contains("\"ok\":false"));
		assert!(refused.contains("\"error\":\"kind_not_in_session\""));
		assert!(!refused.contains("\"event\"")); // omitted on refusal
	}

	#[test]
	fn request_envelope_deserializes_from_wire() {
		let wire = r#"{
			"type":"sign","id":"uuid-1","ts":1751800000,
			"event":{"pubkey":"aa","created_at":1751800000,"kind":7,"tags":[["e","x"]],"content":"+"}
		}"#;
		let req: SignRequest = serde_json::from_str(wire).unwrap();
		assert_eq!(req.msg_type, "sign");
		assert_eq!(req.id, "uuid-1");
		assert_eq!(req.event.kind, 7);
		assert_eq!(req.event.tags, vec![vec!["e".to_string(), "x".to_string()]]);
	}

	#[test]
	fn serve_silent_signs_and_publishes_result() {
		let now = 1_751_800_000u64;
		let (mut s, id) = mk_session(&[7], now);
		let req = mk_req(&id, 7, "+", now, "sv1");
		let out = serve(&mut s, &req, &id, now);
		assert!(!out.money_pending);
		let json = out.response.expect("silent sign yields a response");
		assert!(json.contains("\"ok\":true"));
		assert!(json.contains("\"id\":\"sv1\""));
		// The signed event rides back in the result and verifies.
		let parsed: SignResult = serde_json::from_str(&json).unwrap();
		let ev: Event = serde_json::from_value(parsed.event.unwrap()).unwrap();
		assert!(ev.verify().is_ok());
		assert_eq!(ev.pubkey, id.public_key());
	}

	#[test]
	fn serve_money_is_pending_then_completes_or_declines() {
		let now = 1_751_800_000u64;
		let (mut s, id) = mk_session(&[1], now);
		let req = mk_req(&id, 17, "{}", now, "mv1");
		let out = serve(&mut s, &req, &id, now);
		assert!(out.money_pending);
		assert!(out.response.is_none(), "money pends: nothing published yet");
		// User approves -> signed result.
		let json = complete_money(&mut s, &ChannelOp::Sign(req.clone()), &id, true, now);
		assert!(json.contains("\"ok\":true"));
		// A replay of the same id now returns the cached signed result.
		match s.decide(&req, now) {
			Decision::Duplicate(cached) => assert!(cached.contains("\"ok\":true")),
			other => panic!("expected Duplicate, got {other:?}"),
		}
		// A fresh money request the user declines -> user_declined.
		let req2 = mk_req(&id, 17, "{}", now, "mv2");
		let declined = complete_money(&mut s, &ChannelOp::Sign(req2), &id, false, now);
		assert!(declined.contains("\"error\":\"user_declined\""));
	}

	#[test]
	fn money_replay_cannot_reprompt_or_resign() {
		let now = 1_751_800_000u64;
		let (mut s, id) = mk_session(&[1], now);
		let req = mk_req(&id, 17, "{}", now, "rp1");
		// First delivery raises the prompt.
		let first = serve(&mut s, &req, &id, now);
		assert!(first.money_pending);
		// A replayed envelope while the prompt is still up (a drain overlapping
		// the live subscription, or a deliberate replay): NO second prompt, no
		// response, nothing signed.
		let replay = serve(&mut s, &req, &id, now);
		assert!(
			!replay.money_pending,
			"replay must not raise a second prompt"
		);
		assert!(
			replay.response.is_none(),
			"replay publishes nothing while pending"
		);
		assert_eq!(s.decide(&req, now), Decision::AlreadyPending);
		// After completion, a replay returns the cached result verbatim, never a
		// second signature.
		let json = complete_money(&mut s, &ChannelOp::Sign(req.clone()), &id, true, now);
		let after = serve(&mut s, &req, &id, now);
		assert_eq!(after.response.as_deref(), Some(json.as_str()));
		assert!(!after.money_pending);
		// Same guarantee on the escalated-encrypt path.
		let peer = Keys::generate();
		let e = EncryptRequest {
			msg_type: "encrypt".to_string(),
			id: "rp2".to_string(),
			ts: now,
			peer_pubkey: peer.public_key().to_hex(),
			plaintext: r#"{"invoice":"lnbc1"}"#.to_string(),
		};
		assert!(serve_encrypt(&mut s, &e, &id, now).money_pending);
		let replay = serve_encrypt(&mut s, &e, &id, now);
		assert!(!replay.money_pending && replay.response.is_none());
		let done = complete_money(&mut s, &ChannelOp::Encrypt(e.clone()), &id, false, now);
		assert!(done.contains("\"error\":\"user_declined\""));
		let after = serve_encrypt(&mut s, &e, &id, now);
		assert_eq!(after.response.as_deref(), Some(done.as_str()));
	}

	#[test]
	fn decrypt_soft_cap_fires_honest_notice() {
		let now = 1_751_800_000u64;
		let (mut s, id) = mk_session(&[13], now);
		let peer = Keys::generate();
		let ct =
			nip44::encrypt(peer.secret_key(), &id.public_key(), "m", nip44::Version::V2).unwrap();
		for i in 0..RATE_SOFT_DECRYPT_PER_MIN {
			let d = DecryptRequest {
				msg_type: "decrypt".to_string(),
				id: format!("dn{i}"),
				ts: now,
				peer_pubkey: peer.public_key().to_hex(),
				ciphertext: ct.clone(),
			};
			let out = serve_decrypt(&mut s, &d, &id, now);
			assert!(
				!out.notify_decrypt_volume,
				"under the cap: no notice (i={i})"
			);
		}
		// The next decrypt trips the decrypt-specific notice, not the sign one.
		let d = DecryptRequest {
			msg_type: "decrypt".to_string(),
			id: "dn-over".to_string(),
			ts: now,
			peer_pubkey: peer.public_key().to_hex(),
			ciphertext: ct,
		};
		let out = serve_decrypt(&mut s, &d, &id, now);
		assert!(out.notify_decrypt_volume);
		assert!(!out.notify_high_volume);
	}

	#[test]
	fn session_end_carries_reason_and_refusal_json_shapes() {
		let now = 1_751_800_000u64;
		let (s, _id) = mk_session(&[1], now);
		// The wallet's session-end payload carries the reason for the site to
		// show. The conversation key is symmetric, so the wallet can open its own
		// envelope to verify the plaintext that went on the wire.
		let ev = s.session_end_event(now, "revoked").unwrap();
		let pt = open_envelope(&s.wallet_channel_sk, &s.site_session_pubkey, &ev.content).unwrap();
		assert!(pt.contains("\"reason\":\"revoked\""));
		let end = SessionEnd {
			msg_type: "session-end".to_string(),
			reason: "expired".to_string(),
		};
		let json = serde_json::to_string(&end).unwrap();
		assert!(json.contains("\"reason\":\"expired\""));
		// Incoming site session-end without a reason still parses (serde default).
		let parsed: SessionEnd = serde_json::from_str(r#"{"type":"session-end"}"#).unwrap();
		assert_eq!(parsed.reason, "");
		// refusal_json answers in the right result shape per op type.
		assert!(
			refusal_json("sign", "x", SignError::IdentityMismatch)
				.contains("\"type\":\"sign_result\"")
		);
		assert!(
			refusal_json("encrypt", "x", SignError::IdentityMismatch)
				.contains("\"type\":\"encrypt_result\"")
		);
		assert!(
			refusal_json("decrypt", "x", SignError::IdentityMismatch)
				.contains("\"type\":\"decrypt_result\"")
		);
		assert!(
			refusal_json("sign", "x", SignError::IdentityMismatch)
				.contains("\"error\":\"identity_mismatch\"")
		);
	}

	#[test]
	fn serve_refuses_kind_not_in_set() {
		let now = 1_751_800_000u64;
		let (mut s, id) = mk_session(&[7], now);
		let req = mk_req(&id, 1, "hi", now, "rf1");
		let out = serve(&mut s, &req, &id, now);
		assert!(!out.money_pending);
		assert!(
			out.response
				.unwrap()
				.contains("\"error\":\"kind_not_in_session\"")
		);
	}

	#[test]
	fn encrypt_roundtrips_and_escalates_on_payment() {
		let now = 1_751_800_000u64;
		let (mut s, id) = mk_session(&[13], now);
		let peer = Keys::generate();
		let e = EncryptRequest {
			msg_type: "encrypt".to_string(),
			id: "e1".to_string(),
			ts: now,
			peer_pubkey: peer.public_key().to_hex(),
			plaintext: "hello".to_string(),
		};
		let out = serve_encrypt(&mut s, &e, &id, now);
		assert!(!out.money_pending);
		let json = out.response.unwrap();
		assert!(json.contains("\"type\":\"encrypt_result\""));
		assert!(json.contains("\"ok\":true"));
		let v: serde_json::Value = serde_json::from_str(&json).unwrap();
		let ct = v["ciphertext"].as_str().unwrap();
		let back = nip44::decrypt(peer.secret_key(), &id.public_key(), ct).unwrap();
		assert_eq!(back, "hello");
		// A pay-committing plaintext escalates to the money prompt at encrypt time.
		let e2 = EncryptRequest {
			msg_type: "encrypt".to_string(),
			id: "e2".to_string(),
			ts: now,
			peer_pubkey: peer.public_key().to_hex(),
			plaintext: r#"{"payment":{"bolt11":"lnbc1"}}"#.to_string(),
		};
		let out = serve_encrypt(&mut s, &e2, &id, now);
		assert!(out.money_pending);
		assert!(out.response.is_none());
		let json = complete_money(&mut s, &ChannelOp::Encrypt(e2), &id, true, now);
		assert!(json.contains("\"type\":\"encrypt_result\""));
		assert!(json.contains("\"ok\":true"));
	}

	#[test]
	fn decrypt_reads_a_peer_message_and_is_low_tier() {
		let now = 1_751_800_000u64;
		let (mut s, id) = mk_session(&[13], now);
		let peer = Keys::generate();
		let ct = nip44::encrypt(
			peer.secret_key(),
			&id.public_key(),
			"secret",
			nip44::Version::V2,
		)
		.unwrap();
		let d = DecryptRequest {
			msg_type: "decrypt".to_string(),
			id: "d1".to_string(),
			ts: now,
			peer_pubkey: peer.public_key().to_hex(),
			ciphertext: ct,
		};
		let out = serve_decrypt(&mut s, &d, &id, now);
		assert!(!out.money_pending);
		let json = out.response.unwrap();
		assert!(json.contains("\"type\":\"decrypt_result\""));
		assert!(json.contains("\"plaintext\":\"secret\""));
	}

	/// Cross-implementation NIP-44 v2 round trip against nostr-tools (magick's
	/// browser side). Gated on the GOBLIN_CT1 env var so the normal suite skips it;
	/// the interop harness sets it to a nostr-tools ciphertext (A->B), the wallet
	/// (B) decrypts it, then encrypts a reply (A->B) to /tmp/ct2.txt for nostr-tools
	/// to open. Proves the two NIP-44 v2 implementations actually interoperate.
	#[test]
	fn nip44_v2_interop_with_nostr_tools() {
		let ct1 = match std::env::var("GOBLIN_CT1") {
			Ok(v) => v,
			Err(_) => return,
		};
		let sk_a =
			SecretKey::from_hex("0000000000000000000000000000000000000000000000000000000000000001")
				.unwrap();
		let sk_b =
			SecretKey::from_hex("0000000000000000000000000000000000000000000000000000000000000002")
				.unwrap();
		let pk_a = Keys::new(sk_a.clone()).public_key();
		let pk_b = Keys::new(sk_b.clone()).public_key();
		let pt = nip44::decrypt(&sk_b, &pk_a, &ct1).expect("rust must decrypt nostr-tools ct");
		assert_eq!(pt, "hello from nostr-tools (magick browser side)");
		let ct2 = nip44::encrypt(
			&sk_a,
			&pk_b,
			"hello from rust (goblin wallet side)",
			nip44::Version::V2,
		)
		.unwrap();
		std::fs::write("/tmp/ct2.txt", ct2).unwrap();
	}
}
