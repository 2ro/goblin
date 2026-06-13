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

use crate::nostr::{Contact, NostrStore, TxNostrMeta};
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
	pub system: bool,
	pub hue: usize,
	pub time: i64,
	/// Counterparty npub hex, when known.
	pub npub: Option<String>,
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

/// Display rule: petname → @user (verified goblin.st) → user@domain → npub short.
pub fn display_name(contact: &Contact) -> String {
	if let Some(petname) = &contact.petname {
		if !petname.is_empty() {
			return petname.clone();
		}
	}
	if let (Some(nip05), Some(_)) = (&contact.nip05, contact.nip05_verified_at) {
		if let Some((name, domain)) = nip05.split_once('@') {
			if domain == crate::nostr::relays::HOME_NIP05_DOMAIN {
				return format!("@{}", name);
			}
			return nip05.clone();
		}
	}
	short_npub(&contact.npub)
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

	ActivityItem {
		tx_id: tx.data.id,
		title,
		note,
		amount: tx.amount,
		incoming,
		confirmed: tx.data.confirmed,
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
