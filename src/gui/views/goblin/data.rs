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

use crate::nostr::{Contact, NostrSendStatus, NostrStore, TxNostrMeta};
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
	pub hue: usize,
	pub time: i64,
	/// Counterparty npub hex, when known.
	pub npub: Option<String>,
}

/// Full detail for the receipt / transaction-detail screen: GRIM tx data
/// joined with the nostr counterparty + note. Mimblewimble keeps the chain
/// private, but this is a LOCAL archive (like GRIM), so we surface whatever
/// the wallet recorded plus the npub/username we exchanged with.
pub struct ReceiptDetail {
	pub tx_id: u32,
	pub title: String,
	pub hue: usize,
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
	let (title, hue) = if system {
		("Mining reward".to_string(), 5)
	} else if let Some(m) = &meta {
		store_ref
			.map(|s| contact_title(s, &m.npub))
			.unwrap_or_else(|| (short_npub(&m.npub), 0))
	} else {
		let label = if incoming { "Received" } else { "Sent" };
		(
			label.to_string(),
			(tx.data.id as usize) % crate::gui::theme::avatar_pairs_len(),
		)
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
		hue,
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
pub fn contact_title(store: &NostrStore, npub: &str) -> (String, usize) {
	if let Some(contact) = store.contact(npub) {
		(display_name(&contact), contact.hue as usize)
	} else {
		let hue = hue_of(&npub);
		(short_npub(npub), hue)
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

/// Short npub display (npub1abcd…wxyz) from a hex pubkey.
/// Avatar hue index derived from a hex pubkey (stable per identity, spread
/// across the full color-pair palette).
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

pub fn short_npub(hex: &str) -> String {
	use nostr_sdk::{PublicKey, ToBech32};
	if let Ok(pk) = PublicKey::from_hex(hex) {
		if let Ok(npub) = pk.to_bech32() {
			// Standard truncation: "npub1" + 7 head chars … 6 tail chars.
			if npub.len() > 18 {
				return format!("{}…{}", &npub[..12], &npub[npub.len() - 6..]);
			}
			return npub;
		}
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

	let (title, hue) = if system {
		("Mining reward".to_string(), 5)
	} else if let Some(meta) = &meta {
		store
			.map(|s| contact_title(s, &meta.npub))
			.unwrap_or_else(|| (short_npub(&meta.npub), 0))
	} else {
		// Fall back to slatepack address counterparty or generic label.
		let label = if incoming {
			"Received".to_string()
		} else {
			"Sent".to_string()
		};
		(
			label,
			(tx.data.id as usize) % crate::gui::theme::avatar_pairs_len(),
		)
	};

	let note = meta.as_ref().and_then(|m| m.note.clone());
	let time = tx
		.data
		.confirmation_ts
		.or(Some(tx.data.creation_ts))
		.map(|t| t.timestamp())
		.unwrap_or(0);
	let canceled = is_canceled(tx, meta.as_ref());

	ActivityItem {
		tx_id: tx.data.id,
		title,
		note,
		amount: tx.amount,
		incoming,
		confirmed: tx.data.confirmed,
		canceled,
		system,
		hue,
		time,
		npub: meta.map(|m| m.npub),
	}
}

/// Recent unique peers for the home strip (most recent first).
pub fn recent_peers(wallet: &Wallet, limit: usize) -> Vec<(String, usize, String)> {
	let store = match wallet.nostr_service() {
		Some(s) => s.store.clone(),
		None => return vec![],
	};
	let mut contacts = store.all_contacts();
	contacts.sort_by_key(|c| std::cmp::Reverse(c.last_paid_at.unwrap_or(c.added_at)));
	contacts
		.into_iter()
		.take(limit)
		.map(|c| (display_name(&c), c.hue as usize, c.npub))
		.collect()
}

/// Local contacts whose petname / nip05 / npub contains `query` (case-
/// insensitive) — the instant, no-network half of the recipient search.
pub fn search_contacts(wallet: &Wallet, query: &str, limit: usize) -> Vec<(String, usize, String)> {
	let store = match wallet.nostr_service() {
		Some(s) => s.store.clone(),
		None => return vec![],
	};
	let q = query.trim().trim_start_matches('@').to_lowercase();
	if q.is_empty() {
		return vec![];
	}
	let mut hits: Vec<(String, usize, String)> = store
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
		.map(|c| (display_name(&c), c.hue as usize, c.npub))
		.collect();
	hits.truncate(limit);
	hits
}
