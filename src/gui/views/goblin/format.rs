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

//! Pure formatting and summary helpers.

use super::*;

/// Number of dots a censored money value renders as. FIXED (never the real
/// digit count) so anonymous mode can't leak the balance magnitude.
pub(super) const CENSOR_DOT_COUNT: usize = 5;

/// The fixed dot string a censored name renders as (activity rows and the Recent
/// strip). A constant width, never derived from the real name, so its length
/// can't hint at who the counterparty is.
pub(super) const CENSOR_NAME_DOTS: &str = "••••••";

pub(super) fn relay_summary(wallet: &Wallet) -> String {
	wallet
		.nostr_service()
		.map(|s| {
			let relays = s.relays();
			match relays.len() {
				0 => t!("goblin.relays.none").to_string(),
				1 => relays[0].replace("wss://", ""),
				n => t!("goblin.relays.count", n => n).to_string(),
			}
		})
		.unwrap_or_else(|| "—".to_string())
}

/// Compute a fiat preview line for the balance, when a rate is available.
/// One-line node summary: "Block 1,847,221 · main.gri.mw".
/// Bare node host (or "integrated node") for the sidebar card's third line.
pub(super) fn node_host(wallet: &Wallet) -> String {
	match wallet.get_current_connection() {
		crate::wallet::types::ConnectionMethod::Integrated => {
			t!("goblin.node.integrated_host").to_string()
		}
		crate::wallet::types::ConnectionMethod::External(_, url) => url
			.replace("https://", "")
			.replace("http://", "")
			.trim_end_matches('/')
			.to_string(),
	}
}

pub(super) fn node_summary(wallet: &Wallet) -> String {
	let height = wallet
		.get_data()
		.map(|d| d.info.last_confirmed_height)
		.unwrap_or(0);
	let conn = match wallet.get_current_connection() {
		crate::wallet::types::ConnectionMethod::Integrated => {
			t!("goblin.node.integrated_host").to_string()
		}
		crate::wallet::types::ConnectionMethod::External(_, url) => url
			.replace("https://", "")
			.replace("http://", "")
			.trim_end_matches('/')
			.to_string(),
	};
	if height == 0 {
		t!("goblin.node.summary_syncing", conn => conn).to_string()
	} else {
		t!("goblin.node.summary_block", height => fmt_thousands(height), conn => conn).to_string()
	}
}

/// Format a number with thousands separators.
pub(super) fn fmt_thousands(n: u64) -> String {
	let s = n.to_string();
	let mut out = String::with_capacity(s.len() + s.len() / 3);
	for (i, c) in s.chars().enumerate() {
		if i > 0 && (s.len() - i) % 3 == 0 {
			out.push(',');
		}
		out.push(c);
	}
	out
}

pub(super) fn fiat_line(data: &Option<WalletData>) -> Option<w::FiatLine> {
	use crate::http::RateState;
	let p = crate::AppConfig::pairing();
	let vs = p.vs_currency()?;
	// Asking for the rate here (while the balance is on screen) is what kicks a
	// live refetch when the in-session rate has aged out; an idle wallet never
	// reaches this path.
	Some(match crate::http::grin_rate(vs) {
		RateState::Fresh(rate) => {
			let spendable = data
				.as_ref()
				.map(|d| d.info.amount_currently_spendable)
				.unwrap_or(0);
			let grin = spendable as f64 / 1_000_000_000.0;
			w::FiatLine::Text(format!(
				"≈ {}  ·  1ツ = {}",
				fmt_pairing(grin * rate, p),
				fmt_pairing(rate, p)
			))
		}
		RateState::Loading => w::FiatLine::Loading,
		RateState::Unavailable => w::FiatLine::Unavailable,
	})
}

/// The anonymous-mode censor for a money value: always [`CENSOR_DOT_COUNT`]
/// dots, deliberately ignoring the real amount so its magnitude never leaks.
/// `spaced` widens the dots for the balance hero; activity amounts pass false.
pub(super) fn censored_amount_dots(_atomic: u64, spaced: bool) -> String {
	let sep = if spaced { "  " } else { "" };
	["•"; CENSOR_DOT_COUNT].join(sep)
}

/// The anonymous-mode balance: a centered row of dots standing in for the
/// number, tappable to reveal. Returns true on the frame it is tapped. No fiat
/// line is drawn (and no rate fetch is triggered) while censored. `total` is
/// passed only so the censor is computed the same way everywhere; it is ignored
/// (the dot count is fixed) so the balance size never leaks.
pub(super) fn censored_balance_hero(ui: &mut egui::Ui, total: u64) -> bool {
	let t = theme::tokens();
	let mut clicked = false;
	ui.vertical_centered(|ui| {
		w::kicker(ui, "Balance");
		ui.add_space(6.0);
		let resp = ui.add(
			egui::Label::new(
				RichText::new(censored_amount_dots(total, true))
					.font(FontId::new(56.0, fonts::bold()))
					.color(t.text),
			)
			.sense(Sense::click()),
		);
		let resp = resp
			.on_hover_cursor(egui::CursorIcon::PointingHand)
			.on_hover_text(t!("goblin.settings.tap_reveal"));
		ui.add_space(4.0);
		ui.label(
			RichText::new(t!("goblin.settings.tap_reveal"))
				.font(FontId::new(12.5, fonts::medium()))
				.color(t.text_dim),
		);
		clicked = resp.clicked();
	});
	clicked
}

/// Format a value already in the pairing's unit (dollars, BTC, …) with the
/// right symbol/precision. Sats scales the BTC value by 1e8.
pub(super) fn fmt_pairing(value: f64, p: crate::settings::Pairing) -> String {
	use crate::settings::Pairing;
	match p {
		Pairing::Usd => format!("${:.2}", value),
		Pairing::Eur => format!("€{:.2}", value),
		Pairing::Gbp => format!("£{:.2}", value),
		Pairing::Jpy => format!("¥{:.0}", value),
		Pairing::Cny => format!("CN¥{:.2}", value),
		Pairing::Btc => {
			let s = format!("{:.8}", value);
			let s = s.trim_end_matches('0').trim_end_matches('.');
			format!("₿{}", if s.is_empty() { "0" } else { s })
		}
		Pairing::Sats => format!("{} sats", fmt_thousands((value * 1e8).round() as u64)),
		Pairing::Off => String::new(),
	}
}

/// The "≈ …" amount preview for the current pairing, or `None` when off / no
/// rate yet. Shared by the Pay screen, the send flow, and the balance hero.
pub(super) fn pairing_preview(grin: f64, ctx: &egui::Context) -> Option<String> {
	use crate::http::RateState;
	let p = crate::AppConfig::pairing();
	let vs = p.vs_currency()?;
	match crate::http::grin_rate(vs) {
		RateState::Fresh(rate) => Some(format!("≈ {}", fmt_pairing(grin * rate, p))),
		// No stale fallback: show nothing until a fresh rate lands. Nudge a repaint
		// while loading so the preview appears once the live fetch returns.
		RateState::Loading => {
			ctx.request_repaint_after(std::time::Duration::from_millis(300));
			None
		}
		RateState::Unavailable => None,
	}
}

/// Convert a bech32 npub to hex for short display fallbacks.
pub(super) fn hex_of(npub: &str) -> String {
	use nostr_sdk::{FromBech32, PublicKey};
	PublicKey::from_bech32(npub)
		.map(|pk| pk.to_hex())
		.unwrap_or_else(|_| npub.to_string())
}

/// Largest point size in `[12.0, 16.0]` at which the semibold news title fits on
/// one line within `avail` px, measured against the live font atlas and stepping
/// down by 0.5. Returns the 12pt floor when even that overflows (the caller pairs
/// it with `.truncate()`). This is the shrink-to-fit safety net that keeps a
/// title readable on a 390px screen; the hard char cap (`news_title_clamped`) is
/// the predictable ceiling.
pub(super) fn fit_news_title_pt(ui: &egui::Ui, text: &str, avail: f32) -> f32 {
	const CEIL: f32 = 16.0;
	const FLOOR: f32 = 12.0;
	let mut pt = CEIL;
	while pt > FLOOR {
		let w = ui
			.painter()
			.layout_no_wrap(
				text.to_owned(),
				FontId::new(pt, fonts::semibold()),
				egui::Color32::WHITE,
			)
			.size()
			.x;
		if w <= avail {
			return pt;
		}
		pt -= 0.5;
	}
	FLOOR
}

#[cfg(test)]
mod tests {
	use super::*;

	/// The censored money display must be a fixed number of dots that never
	/// reflects the real amount — otherwise anonymous mode leaks the magnitude
	/// (a bigger balance would show more/longer digits).
	#[test]
	fn censored_amount_is_fixed_width_regardless_of_size() {
		for spaced in [false, true] {
			let zero = censored_amount_dots(0, spaced);
			let small = censored_amount_dots(1, spaced);
			let huge = censored_amount_dots(u64::MAX, spaced);
			assert_eq!(zero, small, "censor must not vary with amount");
			assert_eq!(small, huge, "censor must not vary with amount");
			assert_eq!(
				zero.chars().filter(|c| *c == '•').count(),
				CENSOR_DOT_COUNT,
				"censor must always show exactly {CENSOR_DOT_COUNT} dots"
			);
		}
	}

	/// The censored name is a fixed run of dots, never empty and containing no
	/// alphanumerics, so a dotted name on the activity feed or the Recent strip
	/// can't leak any characters of who the counterparty is.
	#[test]
	fn censored_name_is_fixed_dots_only() {
		assert!(
			!CENSOR_NAME_DOTS.is_empty(),
			"censored name must not be blank"
		);
		assert!(
			CENSOR_NAME_DOTS.chars().all(|c| c == '•'),
			"censored name must be dots only, no leaked characters"
		);
	}
}
