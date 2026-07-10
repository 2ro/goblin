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

//! Tier classification and the trust/grant taxonomy: the kind-to-tier
//! table, the content-escalation hook, kind-set sanitation and the
//! kind-to-category display mapping. Security-critical, I/O-free.

use super::*;
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
