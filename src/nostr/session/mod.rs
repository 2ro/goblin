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

mod classify;
mod sign;

pub use classify::*;
pub use sign::*;

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

/// The direct-message kinds whose grant lets a session use the identity key for
/// NIP-44 encrypt and decrypt: the NIP-17 rumor (14), its seal (13) and the
/// gift wrap (1059). Sealing or reading messages is a messaging capability, so
/// a session granted only, say, posts and reactions never touches the
/// identity's conversations.
const DM_CRYPTO_KINDS: &[u16] = &[13, 14, 1059];

/// `|a - b|` on unsigned clocks without overflow.
fn abs_diff(a: u64, b: u64) -> u64 {
	a.abs_diff(b)
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
				// NIP-98 HTTP auth is judged by the host it authorizes: silent for
				// the session's own site, refused for any other host, the wallet's
				// name authority included (see http_auth_target).
				if req.event.kind == HTTP_AUTH_KIND
					&& http_auth_target(&req.event.tags, &self.domain, &name_authority_hosts())
						!= HttpAuthTarget::OwnSite
				{
					return Decision::Refuse(SignError::Refused);
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
	/// and rate gates as [`Session::decide`], plus the grant gate (the session
	/// must hold a direct-message kind, [`DM_CRYPTO_KINDS`]), then `MoneyPrompt`
	/// when `escalate` (a pay-committing encrypt plaintext) else `Silent`.
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
		// Encrypt and decrypt act on the identity's conversations, so they need a
		// direct-message grant like any other messaging capability. Checked before
		// the escalation, so an ungranted site cannot even raise a prompt.
		if !self
			.silent_kind_set
			.iter()
			.any(|k| DM_CRYPTO_KINDS.contains(k))
		{
			return Decision::Refuse(SignError::KindNotInSession);
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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::nostr::protocol;
	use nostr_sdk::{JsonUtil, UnsignedEvent};

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
		let signed = sign_session_event(&keys, &ev, "magick.market", now).expect("sign");
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
		let again = sign_session_event(&keys, &ev, "magick.market", now).expect("sign again");
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
			sign_session_event(&keys, &wrong, "magick.market", now),
			Err(SignError::IdentityMismatch)
		);
		// Login kind refused outright.
		let mut login = base.clone();
		login.kind = LOGIN_EVENT_KIND;
		assert_eq!(
			sign_session_event(&keys, &login, "magick.market", now),
			Err(SignError::Refused)
		);
		// Delegation tag refused outright.
		let mut deleg = base.clone();
		deleg.tags = vec![vec!["delegation".to_string(), "x".to_string()]];
		assert_eq!(
			sign_session_event(&keys, &deleg, "magick.market", now),
			Err(SignError::Refused)
		);
		// Out-of-skew created_at.
		let mut stale = base.clone();
		stale.created_at = now + CREATED_AT_SKEW_SECS + 5;
		assert_eq!(
			sign_session_event(&keys, &stale, "magick.market", now),
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

	/// The kind set magick.market really requests in its trust URI
	/// (market/src/lib/goblin/session/protocol.ts, MAGICK_LOW_TIER_KINDS).
	const MAGICK_KINDS: &[u16] = &[
		0, 1, 5, 7, 13, 14, 16, 1059, 1111, 10000, 30000, 30003, 30078, 30405, 30406, 31990, 24242,
		27235,
	];

	fn mk_encrypt(id: &str, now: u64, peer: &PublicKey, plaintext: &str) -> EncryptRequest {
		EncryptRequest {
			msg_type: "encrypt".to_string(),
			id: id.to_string(),
			ts: now,
			peer_pubkey: peer.to_hex(),
			plaintext: plaintext.to_string(),
		}
	}

	fn mk_decrypt(id: &str, now: u64, peer: &PublicKey, ciphertext: &str) -> DecryptRequest {
		DecryptRequest {
			msg_type: "decrypt".to_string(),
			id: id.to_string(),
			ts: now,
			peer_pubkey: peer.to_hex(),
			ciphertext: ciphertext.to_string(),
		}
	}

	#[test]
	fn crypto_refused_without_dm_grant() {
		let now = 1_751_800_000u64;
		let peer = Keys::generate();
		// A site granted only posts and reactions.
		let (mut s, id) = mk_session(&[1, 7], now);
		let out = serve_encrypt(
			&mut s,
			&mk_encrypt("e1", now, &peer.public_key(), "hello"),
			&id,
			now,
		);
		assert!(!out.money_pending);
		assert!(
			out.response
				.unwrap()
				.contains("\"error\":\"kind_not_in_session\"")
		);
		// Not even a pay-committing encrypt reaches the password prompt.
		let paying = r#"{"payment":{"bolt11":"lnbc1"}}"#;
		let out = serve_encrypt(
			&mut s,
			&mk_encrypt("e2", now, &peer.public_key(), paying),
			&id,
			now,
		);
		assert!(!out.money_pending);
		assert!(
			out.response
				.unwrap()
				.contains("\"error\":\"kind_not_in_session\"")
		);
		// Decrypt is refused and the plaintext never comes back.
		let ct = nip44::encrypt(
			peer.secret_key(),
			&id.public_key(),
			"secret",
			nip44::Version::V2,
		)
		.unwrap();
		let out = serve_decrypt(
			&mut s,
			&mk_decrypt("d1", now, &peer.public_key(), &ct),
			&id,
			now,
		);
		let json = out.response.unwrap();
		assert!(json.contains("\"error\":\"kind_not_in_session\""));
		assert!(!json.contains("secret"));
		// Kind 16 alone (order messages) is not a direct-message grant either.
		let (mut s16, id16) = mk_session(&[16], now);
		let ct16 = nip44::encrypt(
			peer.secret_key(),
			&id16.public_key(),
			"secret",
			nip44::Version::V2,
		)
		.unwrap();
		let out = serve_decrypt(
			&mut s16,
			&mk_decrypt("d2", now, &peer.public_key(), &ct16),
			&id16,
			now,
		);
		assert!(
			out.response
				.unwrap()
				.contains("\"error\":\"kind_not_in_session\"")
		);
	}

	#[test]
	fn crypto_served_with_a_dm_grant_and_magicks_set() {
		let now = 1_751_800_000u64;
		let peer = Keys::generate();
		let mut grants: Vec<&[u16]> = vec![MAGICK_KINDS];
		grants.extend([&[13u16][..], &[14u16][..], &[1059u16][..]]);
		for kinds in grants {
			let (mut s, id) = mk_session(kinds, now);
			let out = serve_encrypt(
				&mut s,
				&mk_encrypt("e1", now, &peer.public_key(), "hello"),
				&id,
				now,
			);
			assert!(
				out.response.unwrap().contains("\"ok\":true"),
				"encrypt with {kinds:?}"
			);
			let ct = nip44::encrypt(
				peer.secret_key(),
				&id.public_key(),
				"secret",
				nip44::Version::V2,
			)
			.unwrap();
			let out = serve_decrypt(
				&mut s,
				&mk_decrypt("d1", now, &peer.public_key(), &ct),
				&id,
				now,
			);
			assert!(
				out.response.unwrap().contains("\"plaintext\":\"secret\""),
				"decrypt with {kinds:?}"
			);
		}
	}

	/// A shape-correct slatepack armor (the receiver finds it by these markers).
	const ARMOR: &str =
		"BEGINSLATEPACK. 4H1qx1wHe668tFW yC2gfL8PPd8kSgv pcXQhyRkHbyKHZg. ENDSLATEPACK.";

	/// The kind-14 rumor a Goblin wallet seals for a payment, built the way
	/// `send_payment_dm` builds it (protocol content and tags, receiver p tag).
	fn goblin_payment_rumor(sender: &Keys, receiver: &PublicKey) -> UnsignedEvent {
		let mut rumor = EventBuilder::new(
			Kind::PrivateDirectMessage,
			protocol::build_payment_content(ARMOR),
		)
		.tag(Tag::public_key(*receiver))
		.tags(protocol::build_rumor_tags(Some("lunch")))
		.build(sender.public_key());
		rumor.ensure_id();
		rumor
	}

	/// The request-void control rumor (`send_control_dm`): no slatepack, only the
	/// wallet's control text and its `goblin-action` tag.
	fn goblin_void_rumor(sender: &Keys, receiver: &PublicKey) -> UnsignedEvent {
		let mut rumor = EventBuilder::new(
			Kind::PrivateDirectMessage,
			protocol::build_control_content(),
		)
		.tag(Tag::public_key(*receiver))
		.tags(protocol::build_control_tags(
			"0f3a9d4e-7b21-4c55-9a0e-5d1f2b3c4d5e",
		))
		.build(sender.public_key());
		rumor.ensure_id();
		rumor
	}

	/// magick.market's real NIP-17 order traffic, as the rumor JSON its NIP-59
	/// helper hands to session encrypt (market/src/lib/orders/orderMessageRumor.ts,
	/// privateOrderMessage.ts, nostr/nip59.ts normalizeUnsignedRumorId).
	fn magick_rumors(sender: &PublicKey, peer: &PublicKey, now: u64) -> Vec<String> {
		let (from, to) = (sender.to_hex(), peer.to_hex());
		let item = format!("30402:{to}:enchanted-wand");
		let ship = format!("30406:{to}:tracked-post");
		let proof = r#"{"amount":"2500000000","excess":"08ab12","recipient_address":"grin1qqqq","recipient_sig":"aa","sender_address":"grin1pppp","sender_sig":"bb"}"#;
		let shapes = vec![
			// Order creation (kind 16, type 1) with the buyer's delivery details.
			(
				16,
				"Please gift wrap it",
				serde_json::json!([
					["p", to],
					["subject", "order-info"],
					["type", "1"],
					["order", "ord-7c1e"],
					["amount", "2500000000"],
					["item", item, "1"],
					["shipping", ship],
					["name", "Ada"],
					["address", "1 Main St, Springfield, 12345, US"],
					["email", "ada@example.com"],
					["contact", "signal", "@ada.01"],
					["phone", "+1 555 0100"]
				]),
			),
			// Payment request (kind 16, type 2) carrying the seller's Grin address.
			(
				16,
				"Payment request for your order",
				serde_json::json!([
					["p", to],
					["subject", "order-payment"],
					["type", "2"],
					["order", "ord-7c1e"],
					["amount", "2500000000"],
					[
						"payment",
						"grin",
						"grin1dhvv9mvarqwl6fgqsysaqctg8wdmt0pz0lwnc6ga6uhcmjfu08lsnaszwx"
					],
					["expiration", (now + 3600).to_string()]
				]),
			),
			// Status (type 3) and shipping (type 4) updates.
			(
				16,
				"Order status updated to confirmed",
				serde_json::json!([
					["p", to],
					["subject", "order-info"],
					["type", "3"],
					["order", "ord-7c1e"],
					["status", "confirmed"]
				]),
			),
			(
				16,
				"Shipping update",
				serde_json::json!([
					["p", to],
					["subject", "shipping-info"],
					["type", "4"],
					["order", "ord-7c1e"],
					["status", "shipped"],
					["tracking", "1Z999AA10123456784"],
					["carrier", "UPS"]
				]),
			),
			// Payment receipt (kind 17) carrying a Grin payment proof.
			(
				17,
				"Payment confirmation",
				serde_json::json!([
					["p", to],
					["subject", "order-receipt"],
					["order", "ord-7c1e"],
					["payment", "grin", "08ab12", proof],
					["amount", "2500000000"]
				]),
			),
			// Order chat (kind 14).
			(
				14,
				"Is this still available? Happy to pay in GRIN.",
				serde_json::json!([["p", to], ["subject", "Order ord-7c1e"]]),
			),
		];
		shapes
			.into_iter()
			.map(|(kind, content, tags)| {
				serde_json::json!({
					"pubkey": from,
					"created_at": now,
					"kind": kind,
					"tags": tags,
					"content": content,
					"id": "5c8f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff",
				})
				.to_string()
			})
			.collect()
	}

	#[test]
	fn wallet_protocol_detector_flags_goblin_messages_only() {
		let now = 1_751_800_000u64;
		let (a, b) = (Keys::generate(), Keys::generate());
		// The wallet's own payment and control rumors.
		assert!(is_wallet_protocol_payload(
			&goblin_payment_rumor(&a, &b.public_key()).as_json()
		));
		assert!(is_wallet_protocol_payload(
			&goblin_void_rumor(&a, &b.public_key()).as_json()
		));
		// Raw text forms, any ASCII case.
		assert!(is_wallet_protocol_payload(ARMOR));
		assert!(is_wallet_protocol_payload(&ARMOR.to_ascii_lowercase()));
		assert!(is_wallet_protocol_payload(
			&protocol::build_payment_content(ARMOR)
		));
		assert!(is_wallet_protocol_payload(protocol::PREAMBLE));
		// The armor behind a JSON string escape is still found.
		let escaped = r#"{"kind":14,"content":"\u0042EGINSLATEPACK. x. ENDSLATEPACK.","tags":[]}"#;
		assert!(!escaped.contains("BEGINSLATEPACK"));
		assert!(is_wallet_protocol_payload(escaped));
		// Only the wallet's tags, with neutral content.
		assert!(is_wallet_protocol_payload(
			r#"{"kind":14,"content":"hi","tags":[["goblin","1"]]}"#
		));
		// Nested past the scan bound: the escaped armor is still found (fail
		// closed), while the same depth with no marker passes.
		let deep = |inner: &str| format!("{}{inner}{}", "[".repeat(12), "]".repeat(12));
		assert!(is_wallet_protocol_payload(&deep(
			r#"{"content":"\u0042EGINSLATEPACK."}"#
		)));
		assert!(!is_wallet_protocol_payload(&deep(r#"{"content":"hi"}"#)));
		// magick's real order and message traffic is not wallet protocol.
		for rumor in magick_rumors(&a.public_key(), &b.public_key(), now) {
			assert!(!is_wallet_protocol_payload(&rumor), "{rumor}");
		}
		// Plain text, a grin1 address and an order-style JSON are not either.
		assert!(!is_wallet_protocol_payload("hello there"));
		assert!(!is_wallet_protocol_payload(
			"pay me at grin1dhvv9mvarqwl6fgqsysaqctg8wdmt0pz0lwnc6ga6uhcmjfu08lsnaszwx"
		));
		assert!(!is_wallet_protocol_payload(
			r#"{"type":"order","payment":{"bolt11":"lnbc1"}}"#
		));
	}

	#[test]
	fn encrypt_refuses_wallet_protocol_payloads() {
		let now = 1_751_800_000u64;
		let (mut s, id) = mk_session(MAGICK_KINDS, now);
		let peer = Keys::generate();
		let forged = [
			// An S2 reply forged as the identity (the C2 attack payload).
			goblin_payment_rumor(&id, &peer.public_key()).as_json(),
			// A forged request void.
			goblin_void_rumor(&id, &peer.public_key()).as_json(),
			// A bare payment rumor, no preamble and no wallet tag, with the armor
			// behind a JSON string escape (the receiver decodes it back).
			format!(
				r#"{{"pubkey":"{}","created_at":{now},"kind":14,"tags":[["p","{}"]],"content":"\u0042EGINSLATEPACK. 4H1qx1wHe668tFW. ENDSLATEPACK."}}"#,
				id.public_key().to_hex(),
				peer.public_key().to_hex()
			),
			// A bare slatepack.
			ARMOR.to_string(),
		];
		for (i, plaintext) in forged.iter().enumerate() {
			let e = mk_encrypt(&format!("w{i}"), now, &peer.public_key(), plaintext);
			let out = serve_encrypt(&mut s, &e, &id, now);
			assert!(!out.money_pending, "no prompt for case {i}");
			let json = out.response.expect("refusal is answered");
			assert!(json.contains("\"ok\":false"), "case {i}: {json}");
			assert!(json.contains("\"error\":\"kind_not_in_session\""));
			assert!(!json.contains("ciphertext"));
			// Even a password-approved encrypt never seals it.
			let done = complete_money(&mut s, &ChannelOp::Encrypt(e), &id, true, now);
			assert!(done.contains("\"ok\":false"), "approved case {i}");
		}
	}

	#[tokio::test]
	async fn decrypt_never_returns_a_goblin_payment() {
		let now = 1_751_800_000u64;
		let (mut s, bob) = mk_session(MAGICK_KINDS, now);
		let alice = Keys::generate();
		// A real NIP-44 v2 gift wrap of a payment S1, from the unchanged nostr-sdk
		// builder (what a v2 payer sends).
		let rumor = goblin_payment_rumor(&alice, &bob.public_key());
		let wrap = EventBuilder::gift_wrap(&alice, &bob.public_key(), rumor, [])
			.await
			.unwrap();
		// Layer 1 (gift wrap -> seal) is refused too: the seal carries no slate,
		// but its pubkey would tell the site who paid the user.
		let out = serve_decrypt(
			&mut s,
			&mk_decrypt("l1", now, &wrap.pubkey, &wrap.content),
			&bob,
			now,
		);
		let json = out.response.unwrap();
		assert!(json.contains("\"error\":\"malformed\""), "{json}");
		assert!(!json.contains(&alice.public_key().to_hex()));
		assert!(!json.contains("plaintext"));
		// The seal, opened here with the identity key directly.
		let seal = Event::from_json(
			nip44::decrypt(bob.secret_key(), &wrap.pubkey, &wrap.content).unwrap(),
		)
		.unwrap();
		assert_eq!(seal.kind, Kind::Seal);
		// Layer 2 (seal -> rumor) would hand the site the slate: refused, and it
		// answers exactly like a ciphertext that does not open.
		let out = serve_decrypt(
			&mut s,
			&mk_decrypt("l2", now, &seal.pubkey, &seal.content),
			&bob,
			now,
		);
		let json = out.response.unwrap();
		assert!(json.contains("\"error\":\"malformed\""), "{json}");
		assert!(!json.to_ascii_uppercase().contains("SLATEPACK"));
		assert!(!json.contains("plaintext"));
		// A plain v2 message carrying a void control is refused the same way.
		let ct = nip44::encrypt(
			alice.secret_key(),
			&bob.public_key(),
			goblin_void_rumor(&alice, &bob.public_key()).as_json(),
			nip44::Version::V2,
		)
		.unwrap();
		let out = serve_decrypt(
			&mut s,
			&mk_decrypt("l3", now, &alice.public_key(), &ct),
			&bob,
			now,
		);
		assert!(out.response.unwrap().contains("\"error\":\"malformed\""));
	}

	/// Goblin-to-Goblin payment wraps are NIP-44 v3 (wrapv3.rs). A session can
	/// not open them today only because the nostr SDK's nip44::decrypt refuses
	/// the 0x03 version byte before any key agreement. This test pins that: an
	/// SDK upgrade that adds v3 decrypt would silently re-open both layers (the
	/// seal names the payer, the rumor carries the slate), and it must then fail
	/// here until the session refuses the v3 shapes as it refuses v2.
	#[tokio::test]
	async fn v3_goblin_payment_never_opens_through_a_session() {
		let now = 1_751_800_000u64;
		let (mut s, me) = mk_session(MAGICK_KINDS, now);
		let payer = Keys::generate();
		let wrap = crate::nostr::wrapv3::wrap(
			&payer,
			&me.public_key(),
			protocol::build_payment_content(ARMOR),
			protocol::build_rumor_tags(Some("lunch")),
		)
		.unwrap();
		// The fixture is a real payment to this identity: the wallet opens it.
		let opened = crate::nostr::wrapv3::unwrap(&me, &wrap).await.unwrap();
		assert!(opened.rumor.content.contains("BEGINSLATEPACK"));
		// Through the session, the outer layer never opens.
		let out = serve_decrypt(
			&mut s,
			&mk_decrypt("v3", now, &wrap.pubkey, &wrap.content),
			&me,
			now,
		);
		let json = out.response.unwrap();
		assert!(json.contains("\"error\":\"malformed\""), "{json}");
		assert!(!json.contains(&payer.public_key().to_hex()));
		assert!(!json.contains("plaintext"));
	}

	#[tokio::test]
	async fn real_gift_wraps_open_for_orders_not_for_goblin_payments() {
		let now = 1_751_800_000u64;
		let (mut s, seller) = mk_session(MAGICK_KINDS, now);
		let buyer = Keys::generate();
		// magick's order traffic, wrapped by the unchanged nostr-sdk v2 builder:
		// both layers still open, back to the exact rumor.
		for (i, json) in magick_rumors(&buyer.public_key(), &seller.public_key(), now)
			.into_iter()
			.enumerate()
		{
			let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
			v.as_object_mut().unwrap().remove("id");
			let rumor = UnsignedEvent::from_json(v.to_string()).unwrap();
			let wrap = EventBuilder::gift_wrap(&buyer, &seller.public_key(), rumor.clone(), [])
				.await
				.unwrap();
			let out = serve_decrypt(
				&mut s,
				&mk_decrypt(&format!("o1-{i}"), now, &wrap.pubkey, &wrap.content),
				&seller,
				now,
			);
			let v: serde_json::Value = serde_json::from_str(&out.response.unwrap()).unwrap();
			assert_eq!(v["ok"], true, "case {i} wrap layer");
			let seal = Event::from_json(v["plaintext"].as_str().unwrap()).unwrap();
			assert_eq!((seal.kind, seal.pubkey), (Kind::Seal, buyer.public_key()));
			let out = serve_decrypt(
				&mut s,
				&mk_decrypt(&format!("o2-{i}"), now, &seal.pubkey, &seal.content),
				&seller,
				now,
			);
			let v: serde_json::Value = serde_json::from_str(&out.response.unwrap()).unwrap();
			assert_eq!(v["ok"], true, "case {i} seal layer");
			let opened = UnsignedEvent::from_json(v["plaintext"].as_str().unwrap()).unwrap();
			assert_eq!(opened.content, rumor.content, "case {i}");
		}
		// The payment S1 and the request void, wrapped the same way: refused at
		// the first layer already.
		for (i, rumor) in [
			goblin_payment_rumor(&buyer, &seller.public_key()),
			goblin_void_rumor(&buyer, &seller.public_key()),
		]
		.into_iter()
		.enumerate()
		{
			let wrap = EventBuilder::gift_wrap(&buyer, &seller.public_key(), rumor, [])
				.await
				.unwrap();
			let out = serve_decrypt(
				&mut s,
				&mk_decrypt(&format!("g1-{i}"), now, &wrap.pubkey, &wrap.content),
				&seller,
				now,
			);
			let json = out.response.unwrap();
			assert!(json.contains("\"error\":\"malformed\""), "case {i}: {json}");
			assert!(!json.contains(&buyer.public_key().to_hex()));
		}
	}

	#[test]
	fn magick_order_and_dm_traffic_still_encrypts_and_decrypts() {
		let now = 1_751_800_000u64;
		let ephemeral = Keys::generate();
		// The buyer seals each message to the seller through its session.
		let (mut buyer_s, buyer) = mk_session(MAGICK_KINDS, now);
		let (mut seller_s, seller) = mk_session(MAGICK_KINDS, now);
		for (i, rumor) in magick_rumors(&buyer.public_key(), &seller.public_key(), now)
			.into_iter()
			.enumerate()
		{
			let e = mk_encrypt(&format!("e{i}"), now, &seller.public_key(), &rumor);
			let out = serve_encrypt(&mut buyer_s, &e, &buyer, now);
			assert!(!out.money_pending, "case {i} encrypts silently");
			let json = out.response.unwrap();
			assert!(json.contains("\"ok\":true"), "case {i}: {json}");
			let v: serde_json::Value = serde_json::from_str(&json).unwrap();
			let seal_ct = v["ciphertext"].as_str().unwrap().to_string();
			// The seal and gift wrap the buyer's browser then builds.
			let seal = EventBuilder::new(Kind::Seal, seal_ct)
				.sign_with_keys(&buyer)
				.unwrap();
			let wrap_ct = nip44::encrypt(
				ephemeral.secret_key(),
				&seller.public_key(),
				seal.as_json(),
				nip44::Version::V2,
			)
			.unwrap();
			// The seller's session opens both layers back to the same rumor.
			let out = serve_decrypt(
				&mut seller_s,
				&mk_decrypt(&format!("w{i}"), now, &ephemeral.public_key(), &wrap_ct),
				&seller,
				now,
			);
			let v: serde_json::Value = serde_json::from_str(&out.response.unwrap()).unwrap();
			assert_eq!(v["ok"], true, "case {i} wrap layer");
			let opened = Event::from_json(v["plaintext"].as_str().unwrap()).unwrap();
			let out = serve_decrypt(
				&mut seller_s,
				&mk_decrypt(&format!("s{i}"), now, &opened.pubkey, &opened.content),
				&seller,
				now,
			);
			let v: serde_json::Value = serde_json::from_str(&out.response.unwrap()).unwrap();
			assert_eq!(v["ok"], true, "case {i} seal layer");
			assert_eq!(v["plaintext"].as_str().unwrap(), rumor);
		}
	}

	/// A tag list from string rows.
	fn tags(rows: &[&[&str]]) -> Vec<Vec<String>> {
		rows.iter()
			.map(|r| r.iter().map(|s| s.to_string()).collect())
			.collect()
	}

	#[test]
	fn nip98_target_follows_the_u_host() {
		use HttpAuthTarget::*;
		let authorities = vec!["goblin.st".to_string(), "names.example".to_string()];
		let target = |u: &str| {
			http_auth_target(
				&tags(&[&["u", u], &["method", "POST"]]),
				"magick.market",
				&authorities,
			)
		};
		// The session's own site and its subdomains.
		for u in [
			"https://magick.market/api/v1/upload",
			"https://cdn.magick.market/upload",
			"https://MAGICK.Market:8443/x",
		] {
			assert_eq!(target(u), OwnSite, "{u}");
		}
		// The name authority in any spelling, and a configured authority.
		for u in [
			"https://goblin.st/api/v1/register/alice",
			"https://GOBLIN.ST/api/v1/register/alice",
			"https://goblin.st./api/v1/register/alice",
			"https://api.goblin.st/x",
			"http://goblin.st/x",
			"https://names.example/api/v1/transfer/claim",
		] {
			assert_eq!(target(u), NameAuthority, "{u}");
		}
		// Any other host is not the site's to authorize: refused.
		for u in [
			"https://nostr.build/api/v2/upload",
			"https://evilmagick.market/x",
			"https://203.0.113.7/x",
		] {
			assert_eq!(target(u), OtherHost, "{u}");
		}
		// Unusable or ambiguous `u` values.
		for u in [
			"not a url",
			"wss://magick.market/x",
			"https://magick.market\\@goblin.st/x",
			"https://magick.market@goblin.st/x",
		] {
			assert_eq!(target(u), Invalid, "{u}");
		}
		// No `u`, a valueless `u`, and two `u` tags (the authority honours the
		// last one, so a harmless first one must not decide).
		let invalid = [
			tags(&[&["method", "POST"]]),
			tags(&[&["u"], &["method", "POST"]]),
			tags(&[
				&["u", "https://magick.market/x"],
				&["u", "https://goblin.st/api/v1/register/alice"],
				&["method", "DELETE"],
			]),
		];
		for t in invalid {
			assert_eq!(
				http_auth_target(&t, "magick.market", &authorities),
				Invalid,
				"{t:?}"
			);
		}
		// A site domain with a port still matches by its host.
		assert_eq!(
			http_auth_target(
				&tags(&[&["u", "https://magick.market:8443/api/x"]]),
				"magick.market:8443",
				&authorities
			),
			OwnSite
		);
	}

	#[test]
	fn nip98_single_label_site_is_never_own_site() {
		use HttpAuthTarget::*;
		let authorities = vec!["goblin.st".to_string()];
		let target = |site: &str, u: &str| {
			http_auth_target(&tags(&[&["u", u], &["method", "POST"]]), site, &authorities)
		};
		// A session opened for `d=market` (bound to evil.market) must not cover
		// magick.market or any other *.market host, nor `market` itself.
		for u in [
			"https://magick.market/api/x",
			"https://evil.market/api/x",
			"https://market/api/x",
		] {
			assert_eq!(target("market", u), OtherHost, "{u}");
			assert_eq!(target("market.", u), OtherHost, "{u} (trailing dot)");
		}
		// The localhost dev domain is single-label too: no silent HTTP auth.
		assert_eq!(
			target("localhost:3000", "http://localhost:3000/api/x"),
			OtherHost
		);
		// A real two-label site is unaffected.
		assert_eq!(
			target("magick.market", "https://magick.market/api/x"),
			OwnSite
		);
	}

	#[test]
	fn nip98_session_signs_own_site_refuses_elsewhere() {
		let now = 1_751_800_000u64;
		let (mut s, id) = mk_session(MAGICK_KINDS, now);
		let http_auth = |rid: &str, rows: &[&[&str]]| {
			let mut r = mk_req(&id, HTTP_AUTH_KIND, "", now, rid);
			r.event.tags = tags(rows);
			r
		};
		// The site's own endpoint: silent, signed.
		let r = http_auth(
			"h1",
			&[
				&["u", "https://magick.market/api/v1/upload"],
				&["method", "POST"],
			],
		);
		let out = serve(&mut s, &r, &id, now);
		assert!(!out.money_pending);
		assert!(out.response.unwrap().contains("\"ok\":true"));
		// The exact event the wallet uses to release @alice (nip05::unregister),
		// a registration with a payload hash, any other host, two `u` tags and
		// no `u`: all refused, never a prompt.
		let payload = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
		for (rid, rows) in [
			(
				"h2",
				vec![
					vec!["u", "https://goblin.st/api/v1/register/alice"],
					vec!["method", "DELETE"],
				],
			),
			(
				"h3",
				vec![
					vec!["u", "https://goblin.st/api/v1/register"],
					vec!["method", "POST"],
					vec!["payload", payload],
				],
			),
			// Two `u` tags, the authority last.
			(
				"h4",
				vec![
					vec!["u", "https://magick.market/x"],
					vec!["u", "https://goblin.st/api/v1/register/alice"],
					vec!["method", "DELETE"],
				],
			),
			// Another host is not the site's to authorize.
			(
				"h6",
				vec![
					vec!["u", "https://nostr.build/api/v2/upload"],
					vec!["method", "POST"],
				],
			),
			// No `u` at all.
			("h5", vec![vec!["method", "GET"]]),
		] {
			let rows: Vec<&[&str]> = rows.iter().map(|r| r.as_slice()).collect();
			let out = serve(&mut s, &http_auth(rid, &rows), &id, now);
			assert!(!out.money_pending, "{rid} must not prompt");
			assert!(
				out.response
					.unwrap()
					.contains("\"error\":\"kind_not_in_session\""),
				"{rid} must be refused"
			);
		}
		// Defense in depth: the signer itself, which the password-approved path
		// also uses, signs HTTP auth only for the session's own site.
		for (rid, u) in [
			("h7", "https://goblin.st/api/v1/register/alice"),
			("h8", "https://nostr.build/api/v2/upload"),
		] {
			let r = http_auth(rid, &[&["u", u], &["method", "DELETE"]]);
			assert_eq!(
				sign_session_event(&id, &r.event, "magick.market", now),
				Err(SignError::Refused),
				"{u}"
			);
			let json = complete_money(&mut s, &ChannelOp::Sign(r), &id, true, now);
			assert!(json.contains("\"ok\":false"), "{u} approved");
		}
		let r = http_auth(
			"h9",
			&[&["u", "https://magick.market/x"], &["method", "GET"]],
		);
		assert!(sign_session_event(&id, &r.event, "magick.market", now).is_ok());
		// A session not granted HTTP auth refuses even its own site.
		let (mut s2, id2) = mk_session(&[1, 7], now);
		let mut r = mk_req(&id2, HTTP_AUTH_KIND, "", now, "h10");
		r.event.tags = tags(&[&["u", "https://magick.market/x"], &["method", "GET"]]);
		assert_eq!(
			s2.decide(&r, now),
			Decision::Refuse(SignError::KindNotInSession)
		);
	}

	#[test]
	fn blossom_upload_auth_is_unchanged() {
		// NDKBlossom's real kind-24242 shape: t, x, expiration and no host tag.
		// Uploads go to third-party Blossom servers, and the name authority only
		// accepts kind 27235, so 24242 keeps its plain low-tier rule.
		let now = 1_751_800_000u64;
		let (mut s, id) = mk_session(MAGICK_KINDS, now);
		let mut r = mk_req(&id, 24242, "Upload blob", now, "b1");
		let hash = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
		let exp = (now + 3600).to_string();
		r.event.tags = tags(&[&["t", "upload"], &["x", hash], &["expiration", &exp]]);
		let out = serve(&mut s, &r, &id, now);
		assert!(!out.money_pending);
		assert!(out.response.unwrap().contains("\"ok\":true"));
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
			"magick.market",
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
		// Kind 13 grants the encrypt op used at the end of this test.
		let (mut s, id) = mk_session(&[1, 13], now);
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
