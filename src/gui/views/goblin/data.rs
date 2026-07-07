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

//! Activity model: wallet transactions joined with nostr metadata.

use grin_wallet_libwallet::TxLogEntryType;

use crate::nostr::{Contact, NewsItem, NostrSendStatus, NostrStore, TxNostrMeta};
use crate::wallet::Wallet;
use crate::wallet::types::WalletTx;

/// A unified activity entry for the Goblin feed.
pub struct ActivityItem {
	pub tx_id: u32,
	pub title: String,
	pub note: Option<String>,
	pub amount: u64,
	pub incoming: bool,
	pub confirmed: bool,
	/// Canceled/expired before completing (wallet-cancelled tx or expired meta).
	pub canceled: bool,
	pub system: bool,
	pub time: i64,
	/// Counterparty npub hex, when known.
	pub npub: Option<String>,
	/// The wallet's OWN nostr identity (pubkey hex) that was active when this tx
	/// happened — the front door it used. Empty/None on pre-feature rows (treated
	/// as the primary identity). Drives the subtle per-identity row cue.
	pub owner_pubkey: Option<String>,
}

/// Full detail for the receipt / transaction-detail screen: GRIM tx data
/// joined with the nostr counterparty + note. Mimblewimble keeps the chain
/// private, but this is a LOCAL archive (like GRIM), so we surface whatever
/// the wallet recorded plus the npub/username we exchanged with.
pub struct ReceiptDetail {
	pub tx_id: u32,
	pub title: String,
	pub npub: Option<String>,
	pub amount: u64,
	pub incoming: bool,
	pub confirmed: bool,
	/// Canceled/expired before completing.
	pub canceled: bool,
	/// Whether the counterparty has a real identity (petname / verified NIP-05)
	/// rather than just a bare npub. Gates the redundant To/From name rows.
	pub has_identity: bool,
	/// (current confirmations, required) when still pending and computable.
	pub confs: Option<(u64, u64)>,
	pub time: i64,
	pub note: Option<String>,
	/// Network fee in atomic units (sends only; unknown for receives).
	pub fee: Option<u64>,
	pub slate_id: Option<String>,
	/// Whether a manual grin cancel is possible for this tx (unconfirmed, not
	/// broadcasting, not already cancelled). Drives the universal fallback
	/// Cancel that is always offered for a stuck pending, even when the
	/// nostr-aware cancel paths do not apply (e.g. a tx orphaned by an identity
	/// switch, whose meta lives in another identity's store).
	pub can_cancel: bool,
	/// Whether this still-cancellable pending has been waiting long enough to
	/// nudge the user (a soft flag; never triggers an automatic cancel).
	pub stale: bool,
}

/// Build the receipt detail for a transaction id.
pub fn receipt_detail(wallet: &Wallet, tx_id: u32) -> Option<ReceiptDetail> {
	let data = wallet.get_data()?;
	let txs = data.txs.as_ref()?;
	let tx = txs.iter().find(|t| t.data.id == tx_id)?;
	let incoming = matches!(
		tx.data.tx_type,
		TxLogEntryType::TxReceived | TxLogEntryType::ConfirmedCoinbase
	);
	let system = matches!(tx.data.tx_type, TxLogEntryType::ConfirmedCoinbase);
	let slate_id = tx.data.tx_slate_id.map(|u| u.to_string());
	let store = wallet.nostr_service().map(|s| s.store.clone());
	let store_ref = store.as_deref();
	let meta: Option<TxNostrMeta> = slate_id
		.as_ref()
		.and_then(|sid| store_ref.and_then(|s| s.tx_meta(sid)));
	let title = if system {
		"Mining reward".to_string()
	} else if let Some(m) = &meta {
		store_ref
			.map(|s| contact_title(s, &m.npub))
			.unwrap_or_else(|| short_npub(&m.npub))
	} else if incoming {
		"Received".to_string()
	} else {
		"Sent".to_string()
	};
	let note = meta.as_ref().and_then(|m| m.note.clone());
	let time = tx
		.data
		.confirmation_ts
		.or(Some(tx.data.creation_ts))
		.map(|t| t.timestamp())
		.unwrap_or(0);
	// The actual network fee from the tx kernel; a receive doesn't pay one.
	let fee = if incoming {
		None
	} else {
		Some(tx.data.fee.map(|f| f.fee()).unwrap_or(0))
	};
	// Confirmation progress toward the spendable threshold (min_confirmations).
	// grin flips `confirmed` to true at the FIRST on-chain block, but a payment
	// isn't spendable until min_confirmations — so keep counting 1/10 … 10/10
	// instead of jumping straight to "complete" at one block (which is why the
	// count never appeared to move).
	let min_conf = data.info.minimum_confirmations;
	let confs = match tx.height {
		Some(h) if h > 0 && data.info.last_confirmed_height >= h => {
			let count = data.info.last_confirmed_height - h + 1;
			if count >= min_conf {
				None // matured — fully spendable
			} else {
				Some((count, min_conf))
			}
		}
		// On-chain but exact height not yet known: at least one block in.
		_ if tx.data.confirmed => Some((1.min(min_conf), min_conf)),
		// Broadcast but not yet mined.
		_ => Some((0, min_conf)),
	};
	let canceled = is_canceled(tx, meta.as_ref());
	let has_identity = meta
		.as_ref()
		.and_then(|m| store_ref.map(|s| has_real_identity(s, &m.npub)))
		.unwrap_or(false);
	Some(ReceiptDetail {
		tx_id,
		title,
		npub: meta.map(|m| m.npub),
		amount: tx.amount,
		incoming,
		confirmed: tx.data.confirmed,
		canceled,
		has_identity,
		confs,
		time,
		note,
		fee,
		slate_id,
		can_cancel: tx.can_cancel(),
		stale: tx.stale(),
	})
}

/// Activity entries exchanged with a single counterparty (for their profile).
pub fn history_with(wallet: &Wallet, npub: &str) -> Vec<ActivityItem> {
	activity_items(wallet)
		.into_iter()
		.filter(|i| i.npub.as_deref() == Some(npub))
		.collect()
}

/// True when a counterparty has a real, human identity (a local petname or a
/// verified NIP-05) rather than just a bare npub. Used to suppress the
/// redundant To/From name rows on the receipt when the name would just be the
/// same truncated npub shown in the "nostr" row.
pub fn has_real_identity(store: &NostrStore, npub: &str) -> bool {
	store
		.contact(npub)
		.map(|c| {
			c.petname.as_deref().map(|p| !p.is_empty()).unwrap_or(false)
				|| c.nip05_verified_at.is_some()
		})
		.unwrap_or(false)
}

/// Whether a transaction was canceled/expired before completing: a wallet-level
/// cancel (GRIM `TxSentCancelled`/`TxReceivedCancelled`), or expired nostr
/// metadata while still unconfirmed (a late on-chain confirmation still wins).
fn is_canceled(tx: &WalletTx, meta: Option<&TxNostrMeta>) -> bool {
	matches!(
		tx.data.tx_type,
		TxLogEntryType::TxSentCancelled | TxLogEntryType::TxReceivedCancelled
	) || (!tx.data.confirmed
		&& meta
			.map(|m| m.status == NostrSendStatus::Cancelled)
			.unwrap_or(false))
}

/// Resolve the display title for a contact npub.
pub fn contact_title(store: &NostrStore, npub: &str) -> String {
	if let Some(contact) = store.contact(npub) {
		display_name(&contact)
	} else {
		short_npub(npub)
	}
}

/// Display rule: petname → bare name (verified, home authority) → `name · domain`
/// (verified, foreign authority — never bare, so a foreign "alice" can't pose as
/// your home "alice") → short npub. We never show the `@`.
pub fn display_name(contact: &Contact) -> String {
	if let Some(petname) = &contact.petname {
		if !petname.is_empty() {
			return petname.clone();
		}
	}
	if let (Some(nip05), Some(_)) = (&contact.nip05, contact.nip05_verified_at) {
		if let Some((name, domain)) = nip05.split_once('@') {
			if domain == crate::nostr::nip05::home_domain() {
				return name.to_string();
			}
			// Foreign authority: show the domain (no @) so it can't masquerade
			// as a home name.
			return format!("{name} · {domain}");
		}
	}
	short_npub(&contact.npub)
}

/// Whether this contact's name is verified against a name authority (gets the
/// little check), and the foreign domain to surface (None when it's the home
/// authority, where the domain is implied).
pub fn name_verification(contact: &Contact) -> Option<Option<String>> {
	let nip05 = contact.nip05.as_ref()?;
	contact.nip05_verified_at?;
	let (_, domain) = nip05.split_once('@')?;
	if domain == crate::nostr::nip05::home_domain() {
		Some(None)
	} else {
		Some(Some(domain.to_string()))
	}
}

/// Avatar hue index derived from a hex pubkey (stable per identity, spread
/// across the full color-pair palette). Only fills the persisted
/// `Contact.hue` field these days — nothing reads it for rendering anymore.
pub fn hue_of(hex: &str) -> usize {
	usize::from_str_radix(&hex[..2.min(hex.len())], 16).unwrap_or(0)
		% crate::gui::theme::avatar_pairs_len()
}

/// Single-line display form of a handle for narrow chips: middle-ellipsis
/// past 16 chars, keeping the tail (names often differ at the end).
pub fn short_handle(handle: &str) -> String {
	let chars: Vec<char> = handle.chars().collect();
	if chars.len() <= 16 {
		return handle.to_string();
	}
	let head: String = chars[..10].iter().collect();
	let tail: String = chars[chars.len() - 4..].iter().collect();
	format!("{head}…{tail}")
}

/// Short npub display (npub1abcd…wxyz) from a hex pubkey.
pub fn short_npub(hex: &str) -> String {
	use nostr_sdk::{PublicKey, ToBech32};
	if let Ok(pk) = PublicKey::from_hex(hex) {
		// `to_bech32` for a valid key is infallible.
		let Ok(npub) = pk.to_bech32();
		// Standard truncation: "npub1" + 7 head chars … 6 tail chars.
		if npub.len() > 18 {
			return format!("{}…{}", &npub[..12], &npub[npub.len() - 6..]);
		}
		return npub;
	}
	format!("{}…", &hex[..8.min(hex.len())])
}

/// Full bech32 npub (no truncation), for the recipient picker's grey subtitle
/// where showing the complete key is more useful than repeating the truncation.
pub fn full_npub(hex: &str) -> String {
	use nostr_sdk::{PublicKey, ToBech32};
	PublicKey::from_hex(hex)
		.ok()
		.and_then(|pk| pk.to_bech32().ok())
		.unwrap_or_else(|| hex.to_string())
}

/// Build the activity feed for a wallet, newest first.
pub fn activity_items(wallet: &Wallet) -> Vec<ActivityItem> {
	let data = match wallet.get_data() {
		Some(d) => d,
		None => return vec![],
	};
	let txs = data.txs.unwrap_or_default();
	let store = wallet.nostr_service().map(|s| s.store.clone());
	let mut items: Vec<ActivityItem> = txs
		.iter()
		.map(|tx| build_item(tx, store.as_deref()))
		.collect();
	items.sort_by_key(|i| std::cmp::Reverse(i.time));
	items
}

fn build_item(tx: &WalletTx, store: Option<&NostrStore>) -> ActivityItem {
	let incoming = matches!(
		tx.data.tx_type,
		TxLogEntryType::TxReceived | TxLogEntryType::ConfirmedCoinbase
	);
	let system = matches!(tx.data.tx_type, TxLogEntryType::ConfirmedCoinbase);
	let slate_id = tx.data.tx_slate_id.map(|u| u.to_string());
	let meta: Option<TxNostrMeta> = slate_id
		.as_ref()
		.and_then(|sid| store.and_then(|s| s.tx_meta(sid)));

	let title = if system {
		"Mining reward".to_string()
	} else if let Some(meta) = &meta {
		store
			.map(|s| contact_title(s, &meta.npub))
			.unwrap_or_else(|| short_npub(&meta.npub))
	} else if incoming {
		// Fall back to a generic label when there's no nostr counterparty.
		"Received".to_string()
	} else {
		"Sent".to_string()
	};

	let note = meta.as_ref().and_then(|m| m.note.clone());
	let time = tx
		.data
		.confirmation_ts
		.or(Some(tx.data.creation_ts))
		.map(|t| t.timestamp())
		.unwrap_or(0);
	let canceled = is_canceled(tx, meta.as_ref());
	let owner_pubkey = meta
		.as_ref()
		.map(|m| m.recipient_pubkey.clone())
		.filter(|h| !h.is_empty());

	ActivityItem {
		tx_id: tx.data.id,
		title,
		note,
		amount: tx.amount,
		incoming,
		confirmed: tx.data.confirmed,
		canceled,
		system,
		time,
		npub: meta.map(|m| m.npub),
		owner_pubkey,
	}
}

/// Recent unique peers for the home strip (most recent first), as
/// `(display name, npub hex)`.
pub fn recent_peers(wallet: &Wallet, limit: usize) -> Vec<(String, String)> {
	let store = match wallet.nostr_service() {
		Some(s) => s.store.clone(),
		None => return vec![],
	};
	let mut contacts = store.all_contacts();
	contacts.sort_by_key(|c| std::cmp::Reverse(c.last_paid_at.unwrap_or(c.added_at)));
	contacts
		.into_iter()
		.take(limit)
		.map(|c| (display_name(&c), c.npub))
		.collect()
}

/// Local contacts whose petname / nip05 / npub contains `query` (case-
/// insensitive) — the instant, no-network half of the recipient search.
/// Returns `(display name, npub hex)` pairs.
pub fn search_contacts(wallet: &Wallet, query: &str, limit: usize) -> Vec<(String, String)> {
	let store = match wallet.nostr_service() {
		Some(s) => s.store.clone(),
		None => return vec![],
	};
	let q = query.trim().trim_start_matches('@').to_lowercase();
	if q.is_empty() {
		return vec![];
	}
	let mut hits: Vec<(String, String)> = store
		.all_contacts()
		.into_iter()
		.filter(|c| {
			c.petname
				.as_deref()
				.map(|p| p.to_lowercase().contains(&q))
				.unwrap_or(false)
				|| c.nip05
					.as_deref()
					.map(|n| n.to_lowercase().contains(&q))
					.unwrap_or(false)
				|| c.npub.to_lowercase().contains(&q)
		})
		.map(|c| (display_name(&c), c.npub))
		.collect();
	hits.truncate(limit);
	hits
}

/// The news post to show in the Home panel for the wallet's active language, or
/// `None` (panel hides). Selection is language-aware: the newest article whose
/// detected language matches the app locale, falling back to the newest English
/// article. The returned item's title has any `[xx]` language marker stripped
/// for display. `GOBLIN_FAKE_NEWS=1` injects a fixed multilingual set in debug
/// builds so the panel can be screenshotted without a live relay feed.
pub fn news_latest(wallet: &Wallet) -> Option<NewsItem> {
	let items = news_pool(wallet);
	let mut item = select_news(&items, &news_locale_code())?;
	item.title = news_display_title(&item.title);
	Some(item)
}

/// The candidate news set (all cached posts), or a fixed multilingual sample
/// under `GOBLIN_FAKE_NEWS` in debug builds. Kept separate from selection so the
/// selection logic stays a pure, unit-testable function.
fn news_pool(wallet: &Wallet) -> Vec<NewsItem> {
	#[cfg(debug_assertions)]
	if std::env::var("GOBLIN_FAKE_NEWS").is_ok() {
		return vec![
			NewsItem {
				d: "welcome-en".to_string(),
				created_at: 100,
				title: "Welcome to Goblin".to_string(),
				summary: "Private grin payments over Tor. Read more: https://docs.goblin.st"
					.to_string(),
				lang: None,
				published_at: Some(1_782_864_000), // 2026-07-01 UTC
			},
			NewsItem {
				d: "welcome-de".to_string(),
				created_at: 100,
				title: "Willkommen bei Goblin [de]".to_string(),
				summary: "Private Grin-Zahlungen über Tor. Mehr dazu: https://docs.goblin.st"
					.to_string(),
				lang: None,
				published_at: Some(1_782_864_000), // 2026-07-01 UTC
			},
		];
	}
	wallet
		.nostr_service()
		.map(|s| s.store.all_news())
		.unwrap_or_default()
}

/// The app's active locale folded to the ISO 639-1 code used to match news
/// articles. The shipped locales are `en/de/fr/ru/tr/zh-CN/es/ko`; only
/// `zh-CN` needs folding to its 639-1 primary `zh`, and every other locale
/// already is a two-letter primary. Region and separator (`-`/`_`) are
/// dropped.
fn news_locale_code() -> String {
	let loc = rust_i18n::locale().to_string().to_lowercase();
	loc.split(['-', '_']).next().unwrap_or("en").to_string()
}

/// Detect an article's language as a lower-case ISO 639-1 code. Priority: the
/// stored event language tag, then a trailing `[xx]` marker on the title, else
/// English (`None`). Pure — the unit tests exercise it directly.
pub fn news_language(item: &NewsItem) -> Option<String> {
	if let Some(l) = &item.lang {
		let l = l.trim().to_lowercase();
		if is_lang_code(&l) {
			return Some(l);
		}
	}
	title_lang_marker(&item.title)
}

/// The trailing `[xx]` marker on a title (case-insensitive, `xx` = two ASCII
/// letters), as a lower-case code, or `None`. Only a marker at the very end of
/// the (trimmed) title counts, so a `[link]` mid-sentence is never mistaken for
/// a language.
fn title_lang_marker(title: &str) -> Option<String> {
	let t = title.trim();
	let inner = t.strip_suffix(']')?.rsplit_once('[')?.1;
	let code = inner.trim().to_lowercase();
	if is_lang_code(&code) {
		Some(code)
	} else {
		None
	}
}

/// A displayable title with any trailing `[xx]` language marker removed.
pub fn news_display_title(title: &str) -> String {
	match title_lang_marker(title) {
		Some(_) => {
			let t = title.trim_end();
			// Drop the `[xx]` token and the whitespace that preceded it.
			match t.rfind('[') {
				Some(idx) => t[..idx].trim_end().to_string(),
				None => t.to_string(),
			}
		}
		None => title.to_string(),
	}
}

/// Format a unix timestamp (seconds) as an ISO-8601 calendar date in UTC
/// (`YYYY-MM-DD`), never a US `M/D/Y`, and date only (no time-of-day, unlike the
/// activity feed). Dates the Home news panel. An out-of-range stamp falls back to
/// the epoch date rather than panicking.
pub fn news_date_iso(ts: i64) -> String {
	use chrono::{TimeZone, Utc};
	Utc.timestamp_opt(ts, 0)
		.single()
		.map(|dt| dt.format("%Y-%m-%d").to_string())
		.unwrap_or_else(|| "1970-01-01".to_string())
}

/// The hard character budget for a Home news title before it ellipsizes. Titles
/// up to ~34 chars sit at the full 16pt on a 390px phone; between there and this
/// cap the panel shrinks the font to keep one line; past it they are ellipsized.
/// This is the author's predictable writing budget.
pub const NEWS_TITLE_MAX_CHARS: usize = 48;

/// A news title clamped to [`NEWS_TITLE_MAX_CHARS`], ellipsizing (`…`) past it so
/// an over-long title is handled predictably rather than relying on layout alone.
/// The shrink-to-fit font sizing in the panel is the second, screen-width-aware
/// half of the guardrail. Clamps on `char` boundaries so multi-byte titles are
/// never split mid-codepoint.
pub fn news_title_clamped(title: &str) -> String {
	let chars: Vec<char> = title.chars().collect();
	if chars.len() > NEWS_TITLE_MAX_CHARS {
		let keep = NEWS_TITLE_MAX_CHARS.saturating_sub(1);
		format!("{}…", chars[..keep].iter().collect::<String>())
	} else {
		title.to_string()
	}
}

/// True for a two-letter ASCII-alphabetic language code.
fn is_lang_code(s: &str) -> bool {
	s.len() == 2 && s.chars().all(|c| c.is_ascii_alphabetic())
}

/// Select the news article to show for `target` (an ISO 639-1 code): the newest
/// article in that language, else the newest English article (English = an
/// explicit `en` OR no detected language). Pure so it is unit-testable without a
/// wallet/store. Ties on `created_at` resolve to the last such article.
pub fn select_news(items: &[NewsItem], target: &str) -> Option<NewsItem> {
	let target = if target.is_empty() { "en" } else { target };
	let lang_of = |it: &NewsItem| news_language(it).unwrap_or_else(|| "en".to_string());
	items
		.iter()
		.filter(|it| lang_of(it) == target)
		.max_by_key(|it| it.created_at)
		.or_else(|| {
			items
				.iter()
				.filter(|it| lang_of(it) == "en")
				.max_by_key(|it| it.created_at)
		})
		.cloned()
}

/// Split a plain-text summary into (segment, is_url) runs so http(s) URLs render
/// as tappable links and the rest as plain labels. Trailing sentence
/// punctuation is trimmed off a URL so "…goblin.st." doesn't link the dot.
pub fn split_urls(s: &str) -> Vec<(String, bool)> {
	let mut out = Vec::new();
	let mut rest = s;
	while let Some(idx) = rest.find("http") {
		let candidate = &rest[idx..];
		if candidate.starts_with("http://") || candidate.starts_with("https://") {
			if idx > 0 {
				out.push((rest[..idx].to_string(), false));
			}
			let end = candidate
				.find(char::is_whitespace)
				.unwrap_or(candidate.len());
			let mut url = &candidate[..end];
			while let Some(last) = url.chars().last() {
				if matches!(last, '.' | ',' | ')' | ']' | '}' | '!' | '?' | ';' | ':') {
					url = &url[..url.len() - last.len_utf8()];
				} else {
					break;
				}
			}
			out.push((url.to_string(), true));
			rest = &candidate[url.len()..];
		} else {
			// A bare "http" that isn't a scheme; emit it as text and move past it.
			let split_at = idx + 4;
			out.push((rest[..split_at].to_string(), false));
			rest = &rest[split_at..];
		}
	}
	if !rest.is_empty() {
		out.push((rest.to_string(), false));
	}
	out
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn split_urls_isolates_links() {
		let segs = split_urls("Tor is live. Read more: https://docs.goblin.st now");
		assert_eq!(
			segs,
			vec![
				("Tor is live. Read more: ".to_string(), false),
				("https://docs.goblin.st".to_string(), true),
				(" now".to_string(), false),
			]
		);
	}

	#[test]
	fn split_urls_trims_trailing_punctuation_and_handles_no_url() {
		let segs = split_urls("See https://x.io.");
		assert_eq!(
			segs,
			vec![
				("See ".to_string(), false),
				("https://x.io".to_string(), true),
				(".".to_string(), false),
			]
		);
		assert_eq!(
			split_urls("plain text"),
			vec![("plain text".to_string(), false)]
		);
	}

	fn news(d: &str, created_at: i64, title: &str, lang: Option<&str>) -> NewsItem {
		NewsItem {
			d: d.to_string(),
			created_at,
			title: title.to_string(),
			summary: String::new(),
			lang: lang.map(|s| s.to_string()),
			published_at: None,
		}
	}

	#[test]
	fn language_from_event_tag_wins() {
		// A stored event language tag is authoritative, even if the title has no
		// marker (bare `["l","de"]`) or a differing marker.
		let it = news("a", 1, "Neuigkeiten", Some("de"));
		assert_eq!(news_language(&it).as_deref(), Some("de"));
		// NIP-32-style tag is stored the same way (code already extracted upstream).
		let it = news("b", 1, "News", Some("FR"));
		assert_eq!(news_language(&it).as_deref(), Some("fr"));
		// A non-code tag value is ignored, falling through to the title (English).
		let it = news("c", 1, "News", Some("english"));
		assert_eq!(news_language(&it), None);
	}

	#[test]
	fn language_from_title_suffix_marker() {
		let it = news("a", 1, "2026-07-05 Welcome to Goblin [de]", None);
		assert_eq!(news_language(&it).as_deref(), Some("de"));
		// Case-insensitive.
		let it = news("b", 1, "Bonjour [FR]", None);
		assert_eq!(news_language(&it).as_deref(), Some("fr"));
		// Only a marker at the very end counts; a bracketed word mid-title does not.
		let it = news("c", 1, "Read the [guide] today", None);
		assert_eq!(news_language(&it), None);
	}

	#[test]
	fn no_marker_means_english() {
		let it = news("a", 1, "Welcome to Goblin", None);
		assert_eq!(news_language(&it), None);
		// A non-two-letter bracket suffix is not a language marker.
		let it = news("b", 1, "Build 137 [beta]", None);
		assert_eq!(news_language(&it), None);
	}

	#[test]
	fn display_title_strips_marker() {
		assert_eq!(
			news_display_title("2026-07-05 Welcome to Goblin [de]"),
			"2026-07-05 Welcome to Goblin"
		);
		assert_eq!(news_display_title("Bonjour [FR]"), "Bonjour");
		// No marker: unchanged.
		assert_eq!(news_display_title("Welcome to Goblin"), "Welcome to Goblin");
		// Non-language bracket suffix: left intact.
		assert_eq!(news_display_title("Build 137 [beta]"), "Build 137 [beta]");
	}

	#[test]
	fn date_is_iso_utc_day_only() {
		// 2026-07-01 00:00:00 UTC.
		assert_eq!(news_date_iso(1_782_864_000), "2026-07-01");
		// A within-the-day stamp still yields the same calendar date (no time).
		assert_eq!(news_date_iso(1_782_864_000 + 3600 * 13 + 59), "2026-07-01");
		// Epoch.
		assert_eq!(news_date_iso(0), "1970-01-01");
	}

	#[test]
	fn title_clamped_ellipsizes_past_max() {
		// Short titles pass through untouched.
		let short = "News in Your Language";
		assert_eq!(news_title_clamped(short), short);
		// Exactly the cap is untouched.
		let at_cap = "x".repeat(NEWS_TITLE_MAX_CHARS);
		assert_eq!(news_title_clamped(&at_cap), at_cap);
		// One over the cap ellipsizes to exactly the cap length (… included).
		let over = "y".repeat(NEWS_TITLE_MAX_CHARS + 10);
		let clamped = news_title_clamped(&over);
		assert_eq!(clamped.chars().count(), NEWS_TITLE_MAX_CHARS);
		assert!(clamped.ends_with('…'));
		// Multi-byte titles clamp on char boundaries (no panic / no split codepoint).
		let cjk = "语".repeat(NEWS_TITLE_MAX_CHARS + 5);
		let clamped = news_title_clamped(&cjk);
		assert_eq!(clamped.chars().count(), NEWS_TITLE_MAX_CHARS);
	}

	#[test]
	fn select_matches_locale_then_falls_back_to_english() {
		let pool = vec![
			news("en", 100, "Welcome to Goblin", None),
			news("de", 90, "Willkommen bei Goblin [de]", None),
			news("fr", 80, "Bonjour", Some("fr")),
		];
		// German locale → the German article.
		assert_eq!(select_news(&pool, "de").unwrap().d, "de");
		// French locale (via event tag) → the French article.
		assert_eq!(select_news(&pool, "fr").unwrap().d, "fr");
		// English locale → the English (unmarked) article.
		assert_eq!(select_news(&pool, "en").unwrap().d, "en");
		// A locale with no article → fall back to the newest English article.
		assert_eq!(select_news(&pool, "ru").unwrap().d, "en");
	}

	#[test]
	fn select_picks_newest_within_language_slice() {
		let pool = vec![
			news("de-old", 50, "Alt [de]", None),
			news("de-new", 150, "Neu [de]", None),
			news("en", 200, "Newest overall", None),
		];
		// Within German, the newest German article wins — NOT the newer English one.
		assert_eq!(select_news(&pool, "de").unwrap().d, "de-new");
	}

	#[test]
	fn locale_folding_maps_zh_cn_to_zh() {
		rust_i18n::set_locale("zh-CN");
		assert_eq!(news_locale_code(), "zh");
		rust_i18n::set_locale("de");
		assert_eq!(news_locale_code(), "de");
		rust_i18n::set_locale("en");
		assert_eq!(news_locale_code(), "en");
	}

	#[test]
	fn empty_pool_selects_nothing() {
		assert!(select_news(&[], "de").is_none());
	}
}
