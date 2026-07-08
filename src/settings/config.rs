// Copyright 2023 The Grim Developers
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

use grin_core::global;
use grin_core::global::ChainTypes;
use serde_derive::{Deserialize, Serialize};

use crate::Settings;
use crate::gui::views::Content;
use crate::http::ReleaseInfo;
use crate::node::NodeConfig;
use crate::wallet::ConnectionsConfig;

/// Application update information.
#[derive(Serialize, Deserialize, Clone)]
pub struct AppUpdate {
	/// Version of release.
	pub version: String,
	/// Size of release in megabytes.
	pub size: Option<String>,
	/// Date of release.
	pub date: String,
	/// Changes in the release.
	pub changelog: String,
	/// Link to download the release.
	pub url: String,
}

/// Application configuration, stored at toml file.
#[derive(Serialize, Deserialize)]
pub struct AppConfig {
	/// Run node server on startup.
	pub(crate) auto_start_node: bool,
	/// Chain type for node and wallets.
	pub(crate) chain_type: ChainTypes,

	/// Flag to check if Android integrated node warning was shown.
	android_integrated_node_warning: Option<bool>,

	/// Flag to show wallet list at dual panel wallets mode.
	show_wallets_at_dual_panel: bool,
	/// Flag to show all connections at network panel or integrated node info.
	show_connections_network_panel: bool,

	/// Width of the desktop window.
	width: f32,
	/// Height of the desktop window.
	height: f32,

	/// Position of the desktop window.
	x: Option<f32>,
	y: Option<f32>,

	/// Locale code for i18n.
	lang: Option<String>,
	/// Flag to use English locale layout on keyboard.
	english_keyboard: Option<bool>,

	/// Flag to check if dark theme should be used, use system settings if not set.
	use_dark_theme: Option<bool>,
	/// Color theme identifier: "light", "dark" or "yellow".
	theme: Option<String>,
	/// Density identifier: "compact", "regular" or "comfy".
	density: Option<String>,
	/// Identifier of the last opened wallet to boot into.
	last_wallet_id: Option<i64>,
	/// Show fiat (USD) preview alongside amounts (legacy; migrated to pairing).
	fiat_preview: Option<bool>,
	/// Amount pairing code: off|usd|eur|gbp|jpy|cny|btc|sats (default usd).
	pairing: Option<String>,

	/// Flag to use proxy for network requests.
	use_proxy: Option<bool>,
	/// Flag to use SOCKS5 or HTTP proxy for network requests.
	use_socks_proxy: Option<bool>,
	/// HTTP proxy URL.
	http_proxy_url: Option<String>,
	/// SOCKS5 proxy URL.
	socks_proxy_url: Option<String>,

	/// Flag to check updates on startup.
	check_updates: Option<bool>,
	/// Application update information.
	app_update: Option<AppUpdate>,

	/// Hide received grin amounts in payment notifications/alerts. Default false
	/// so existing configs (and new wallets) keep showing the amount.
	hide_amounts: Option<bool>,

	/// Hide the payer/requester name in payment notifications/alerts. Default
	/// false. Independent of `hide_amounts`; a notification can hide either or
	/// both.
	notif_hide_names: Option<bool>,
	/// Hide every detail in payment notifications/alerts: the alert becomes a
	/// generic "you got paid / a request arrived" line with no name and no
	/// amount. Default false. When on, it overrides the two finer toggles.
	notif_hide_details: Option<bool>,
	/// Anonymous mode: censor the wallet home balance and the activity list
	/// (dots until tapped to reveal). Presentation-only, no money-path or
	/// storage effect. Default false.
	anonymous_mode: Option<bool>,
}

/// What the amount preview is paired to: nothing, a fiat currency, or bitcoin.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Pairing {
	Off,
	Usd,
	Eur,
	Gbp,
	Jpy,
	Cny,
	Btc,
	Sats,
}

impl Pairing {
	/// All variants, in picker order.
	pub const ALL: [Pairing; 8] = [
		Pairing::Off,
		Pairing::Usd,
		Pairing::Eur,
		Pairing::Gbp,
		Pairing::Jpy,
		Pairing::Cny,
		Pairing::Btc,
		Pairing::Sats,
	];

	/// Stable config code.
	pub fn code(&self) -> &'static str {
		match self {
			Pairing::Off => "off",
			Pairing::Usd => "usd",
			Pairing::Eur => "eur",
			Pairing::Gbp => "gbp",
			Pairing::Jpy => "jpy",
			Pairing::Cny => "cny",
			Pairing::Btc => "btc",
			Pairing::Sats => "sats",
		}
	}

	pub fn from_code(s: &str) -> Option<Pairing> {
		Some(match s {
			"off" => Pairing::Off,
			"usd" => Pairing::Usd,
			"eur" => Pairing::Eur,
			"gbp" => Pairing::Gbp,
			"jpy" => Pairing::Jpy,
			"cny" => Pairing::Cny,
			"btc" => Pairing::Btc,
			"sats" => Pairing::Sats,
			_ => return None,
		})
	}

	/// The CoinGecko `vs_currency` to price against (sats prices vs btc).
	/// `None` when pairing is off.
	pub fn vs_currency(&self) -> Option<&'static str> {
		match self {
			Pairing::Off => None,
			Pairing::Sats => Some("btc"),
			other => Some(other.code()),
		}
	}

	/// Human label for the picker / settings row.
	pub fn label(&self) -> &'static str {
		match self {
			Pairing::Off => "Off",
			Pairing::Usd => "USD",
			Pairing::Eur => "EUR",
			Pairing::Gbp => "GBP",
			Pairing::Jpy => "JPY",
			Pairing::Cny => "CNY",
			Pairing::Btc => "Bitcoin",
			Pairing::Sats => "Sats",
		}
	}
}

impl Default for AppConfig {
	fn default() -> Self {
		Self {
			auto_start_node: false,
			chain_type: ChainTypes::default(),
			android_integrated_node_warning: None,
			show_wallets_at_dual_panel: false,
			show_connections_network_panel: false,
			width: Self::DEFAULT_WIDTH,
			height: Self::DEFAULT_HEIGHT,
			x: None,
			y: None,
			lang: None,
			english_keyboard: None,
			use_dark_theme: None,
			theme: None,
			density: None,
			last_wallet_id: None,
			fiat_preview: None,
			pairing: None,
			use_proxy: None,
			use_socks_proxy: None,
			http_proxy_url: None,
			socks_proxy_url: None,
			// On by default, like upstream Grim: checks Goblin's own GitHub
			// releases direct over HTTPS (see http/release.rs). This is the same
			// non-sensitive-metadata-over-clearnet posture Grim uses for its
			// update check — payments, relays and identity still egress over Tor.
			check_updates: Some(true),
			app_update: None,
			hide_amounts: None,
			notif_hide_names: None,
			notif_hide_details: None,
			anonymous_mode: None,
		}
	}
}

impl AppConfig {
	/// Desktop window frame margin sum, horizontal or vertical.
	const FRAME_MARGIN: f32 = Content::WINDOW_FRAME_MARGIN * 2.0;
	/// Default desktop window width.
	pub const DEFAULT_WIDTH: f32 = Content::SIDE_PANEL_WIDTH * 3.0 + Self::FRAME_MARGIN;
	/// Default desktop window height.
	pub const DEFAULT_HEIGHT: f32 = 706.0;
	/// Minimal desktop window width.
	pub const MIN_WIDTH: f32 = Content::SIDE_PANEL_WIDTH + Self::FRAME_MARGIN;
	/// Minimal desktop window height.
	pub const MIN_HEIGHT: f32 = 630.0 + Content::WINDOW_TITLE_HEIGHT + Self::FRAME_MARGIN;

	/// Application configuration file name.
	pub const FILE_NAME: &'static str = "app.toml";

	/// Default i18n locale.
	pub const DEFAULT_LOCALE: &'static str = "en";

	/// Save application configuration to the file.
	pub fn save(&self) {
		Settings::write_to_file(self, Settings::config_path(Self::FILE_NAME, None));
	}

	/// Change global [`ChainTypes`] and load new [`NodeConfig`].
	pub fn change_chain_type(chain_type: &ChainTypes) {
		let current_chain_type = Self::chain_type();
		if current_chain_type != *chain_type {
			// Save chain type at app config.
			{
				let mut w_app_config = Settings::app_config_to_update();
				w_app_config.chain_type = *chain_type;
				w_app_config.save();
			}
			// Load node configuration for selected chain type.
			{
				let mut w_node_config = Settings::node_config_to_update();
				let node_config = NodeConfig::for_chain_type(chain_type);
				w_node_config.node = node_config.node;
				w_node_config.peers = node_config.peers;
			}
			// Load connections configuration
			{
				let mut w_conn_config = Settings::conn_config_to_update();
				*w_conn_config = ConnectionsConfig::for_chain_type(chain_type);
			}
		}
		if !global::GLOBAL_CHAIN_TYPE.is_init() {
			global::init_global_chain_type(*chain_type);
		} else {
			global::set_global_chain_type(*chain_type);
			global::set_local_chain_type(*chain_type);
		}
	}

	/// Get current [`ChainTypes`] for node and wallets.
	pub fn chain_type() -> ChainTypes {
		let r_config = Settings::app_config_to_read();
		r_config.chain_type
	}

	/// Check if integrated node is starting with application.
	pub fn autostart_node() -> bool {
		let r_config = Settings::app_config_to_read();
		r_config.auto_start_node
	}

	/// Toggle integrated node autostart.
	pub fn toggle_node_autostart() {
		let autostart = Self::autostart_node();
		let mut w_app_config = Settings::app_config_to_update();
		w_app_config.auto_start_node = !autostart;
		w_app_config.save();
	}

	/// Check if it's needed to show wallet list at dual panel wallets mode.
	pub fn show_wallets_at_dual_panel() -> bool {
		let r_config = Settings::app_config_to_read();
		r_config.show_wallets_at_dual_panel
	}

	/// Toggle flag to show wallet list at dual panel wallets mode.
	pub fn toggle_show_wallets_at_dual_panel() {
		let show = Self::show_wallets_at_dual_panel();
		let mut w_app_config = Settings::app_config_to_update();
		w_app_config.show_wallets_at_dual_panel = !show;
		w_app_config.save();
	}

	/// Check if it's needed to show all connections or integrated node info at network panel.
	pub fn show_connections_network_panel() -> bool {
		let r_config = Settings::app_config_to_read();
		r_config.show_connections_network_panel
	}

	/// Toggle flag to show all connections or integrated node info at network panel.
	pub fn toggle_show_connections_network_panel() {
		let show = Self::show_connections_network_panel();
		let mut w_app_config = Settings::app_config_to_update();
		w_app_config.show_connections_network_panel = !show;
		w_app_config.save();
	}

	/// Save desktop window width and height.
	pub fn save_window_size(w: f32, h: f32) {
		let mut w_app_config = Settings::app_config_to_update();
		w_app_config.width = w;
		w_app_config.height = h;
		w_app_config.save();
	}

	/// Get desktop window width and height.
	pub fn window_size() -> (f32, f32) {
		let r_config = Settings::app_config_to_read();
		(r_config.width, r_config.height)
	}

	/// Save desktop window position.
	pub fn save_window_pos(x: f32, y: f32) {
		let mut w_app_config = Settings::app_config_to_update();
		w_app_config.x = Some(x);
		w_app_config.y = Some(y);
		w_app_config.save();
	}

	/// Get desktop window position.
	pub fn window_pos() -> Option<(f32, f32)> {
		let r_config = Settings::app_config_to_read();
		if r_config.x.is_some() && r_config.y.is_some() {
			return Some((r_config.x.unwrap(), r_config.y.unwrap()));
		}
		None
	}

	/// Save locale code.
	pub fn save_locale(lang: &str) {
		let mut w_app_config = Settings::app_config_to_update();
		w_app_config.lang = Some(lang.to_string());
		w_app_config.save();
	}

	/// Get current saved locale code.
	pub fn locale() -> Option<String> {
		let r_config = Settings::app_config_to_read();
		if r_config.lang.is_some() {
			return Some(r_config.lang.clone().unwrap());
		}
		None
	}

	/// Toggle English locale layout. for software keyboard.
	pub fn toggle_english_keyboard() {
		let english = Self::english_keyboard();
		let mut w_app_config = Settings::app_config_to_update();
		w_app_config.english_keyboard = Some(!english);
		w_app_config.save();
	}

	/// Check if English locale layout should be used for software keyboard.
	pub fn english_keyboard() -> bool {
		let r_config = Settings::app_config_to_read();
		r_config.english_keyboard.unwrap_or(false)
	}

	/// Check if integrated node warning is needed for Android.
	pub fn android_integrated_node_warning_needed() -> bool {
		let r_config = Settings::app_config_to_read();
		r_config.android_integrated_node_warning.unwrap_or(true)
	}

	/// Mark integrated node warning for Android as shown.
	pub fn show_android_integrated_node_warning() {
		let mut w_config = Settings::app_config_to_update();
		w_config.android_integrated_node_warning = Some(false);
		w_config.save();
	}

	/// Check if dark theme should be used (derived from the theme tokens).
	pub fn dark_theme() -> Option<bool> {
		let r_config = Settings::app_config_to_read();
		if let Some(theme) = r_config.theme.clone() {
			if let Some(kind) = crate::gui::theme::ThemeKind::from_id(&theme) {
				return Some(match kind {
					crate::gui::theme::ThemeKind::Light => false,
					crate::gui::theme::ThemeKind::Dark => true,
					// Yellow paints dark ink on a light background.
					crate::gui::theme::ThemeKind::Yellow => false,
				});
			}
		}
		r_config.use_dark_theme.clone()
	}

	/// Setup flag to use dark theme (legacy path, maps to theme identifier).
	pub fn set_dark_theme(use_dark: bool) {
		Self::set_theme(if use_dark {
			crate::gui::theme::ThemeKind::Dark
		} else {
			crate::gui::theme::ThemeKind::Light
		});
	}

	/// Get current color theme, migrating the legacy dark flag when present.
	pub fn theme() -> crate::gui::theme::ThemeKind {
		let r_config = Settings::app_config_to_read();
		if let Some(theme) = r_config.theme.clone() {
			if let Some(kind) = crate::gui::theme::ThemeKind::from_id(&theme) {
				return kind;
			}
		}
		match r_config.use_dark_theme {
			Some(false) => crate::gui::theme::ThemeKind::Light,
			// Goblin defaults to the dark theme.
			_ => crate::gui::theme::ThemeKind::Dark,
		}
	}

	/// Save color theme.
	pub fn set_theme(kind: crate::gui::theme::ThemeKind) {
		let mut w_config = Settings::app_config_to_update();
		w_config.theme = Some(kind.id().to_string());
		w_config.use_dark_theme = Some(kind == crate::gui::theme::ThemeKind::Dark);
		w_config.save();
	}

	/// Get current density.
	pub fn density() -> crate::gui::theme::DensityKind {
		let r_config = Settings::app_config_to_read();
		r_config
			.density
			.clone()
			.and_then(|d| crate::gui::theme::DensityKind::from_id(&d))
			.unwrap_or(crate::gui::theme::DensityKind::Comfy)
	}

	/// Save density.
	pub fn set_density(kind: crate::gui::theme::DensityKind) {
		let mut w_config = Settings::app_config_to_update();
		w_config.density = Some(kind.id().to_string());
		w_config.save();
	}

	/// What amount previews are paired to (default USD). Migrates the legacy
	/// `fiat_preview = false` to `Off`.
	pub fn pairing() -> Pairing {
		let r_config = Settings::app_config_to_read();
		if let Some(code) = r_config.pairing.clone() {
			if let Some(p) = Pairing::from_code(&code) {
				return p;
			}
		}
		// No pairing chosen yet → off by default: no conversion is shown anywhere
		// and no price is fetched until the user opts into a pairing. (A legacy
		// `fiat_preview = true` still defaults to USD for existing users.)
		match r_config.fiat_preview {
			Some(true) => Pairing::Usd,
			_ => Pairing::Off,
		}
	}

	/// Save the amount pairing.
	pub fn set_pairing(p: Pairing) {
		let mut w_config = Settings::app_config_to_update();
		w_config.pairing = Some(p.code().to_string());
		w_config.save();
	}

	/// Get identifier of the last opened wallet.
	pub fn last_wallet_id() -> Option<i64> {
		let r_config = Settings::app_config_to_read();
		r_config.last_wallet_id
	}

	/// Save identifier of the last opened wallet.
	pub fn set_last_wallet_id(id: Option<i64>) {
		let mut w_config = Settings::app_config_to_update();
		w_config.last_wallet_id = id;
		w_config.save();
	}

	/// Check if proxy for network requests is needed.
	pub fn use_proxy() -> bool {
		let r_config = Settings::app_config_to_read();
		r_config.use_proxy.clone().unwrap_or(false)
	}

	/// Enable or disable proxy for network requests.
	pub fn toggle_use_proxy() {
		let use_proxy = Self::use_proxy();
		let mut w_config = Settings::app_config_to_update();
		w_config.use_proxy = Some(!use_proxy);
		w_config.save();
	}

	/// Check if SOCKS5 or HTTP proxy should be used.
	pub fn use_socks_proxy() -> bool {
		let r_config = Settings::app_config_to_read();
		r_config.use_socks_proxy.clone().unwrap_or(true)
	}

	/// Enable SOCKS5 or HTTP proxy.
	pub fn toggle_use_socks_proxy() {
		let use_proxy = Self::use_socks_proxy();
		let mut w_config = Settings::app_config_to_update();
		w_config.use_socks_proxy = Some(!use_proxy);
		w_config.save();
	}

	/// Get SOCKS proxy URL.
	pub fn socks_proxy_url() -> Option<String> {
		let r_config = Settings::app_config_to_read();
		r_config.socks_proxy_url.clone()
	}

	/// Save SOCKS proxy URL.
	pub fn save_socks_proxy_url(url: Option<String>) {
		let mut w_config = Settings::app_config_to_update();
		w_config.socks_proxy_url = url;
		w_config.save();
	}

	/// Get HTTP proxy URL.
	pub fn http_proxy_url() -> Option<String> {
		let r_config = Settings::app_config_to_read();
		r_config.http_proxy_url.clone()
	}

	/// Save HTTP proxy URL.
	pub fn save_http_proxy_url(url: Option<String>) {
		let mut w_config = Settings::app_config_to_update();
		w_config.http_proxy_url = url;
		w_config.save();
	}

	/// Check updates on startup.
	pub fn check_updates() -> bool {
		let r_config = Settings::app_config_to_read();
		r_config.check_updates.unwrap_or(false)
	}

	/// Disable or enable updates checking.
	pub fn toggle_check_updates() {
		let check = Self::check_updates();
		// Clear update info on disable.
		if !check {
			Self::save_update(None);
		}
		let mut w_config = Settings::app_config_to_update();
		w_config.check_updates = Some(!check);
		w_config.save();
	}

	/// Get last update information, that includes: version, date and description.
	pub fn app_update() -> Option<AppUpdate> {
		let r_config = Settings::app_config_to_read();
		r_config.app_update.clone()
	}

	/// Save update information.
	pub fn save_update(release: Option<&ReleaseInfo>) {
		let mut w_config = Settings::app_config_to_update();
		match release {
			None => {
				w_config.app_update = None;
			}
			Some(release) => {
				let url = release.url();
				if let Some(url) = url {
					let app_update = AppUpdate {
						version: release.version(),
						size: release.size(),
						date: release.date(),
						changelog: release.body.clone(),
						url,
					};
					w_config.app_update = Some(app_update);
				}
			}
		}
		w_config.save();
	}

	/// Whether received grin amounts are hidden in payment notifications/alerts.
	pub fn hide_amounts() -> bool {
		let r_config = Settings::app_config_to_read();
		r_config.hide_amounts.unwrap_or(false)
	}

	/// Set whether received grin amounts are hidden in notifications/alerts.
	pub fn set_hide_amounts(hide: bool) {
		let mut w_config = Settings::app_config_to_update();
		w_config.hide_amounts = Some(hide);
		w_config.save();
	}

	/// Whether the payer/requester name is hidden in payment notifications.
	pub fn notif_hide_names() -> bool {
		Settings::app_config_to_read()
			.notif_hide_names
			.unwrap_or(false)
	}

	/// Set whether the payer/requester name is hidden in payment notifications.
	pub fn set_notif_hide_names(hide: bool) {
		let mut w_config = Settings::app_config_to_update();
		w_config.notif_hide_names = Some(hide);
		w_config.save();
	}

	/// Whether payment notifications are reduced to a generic private alert.
	pub fn notif_hide_details() -> bool {
		Settings::app_config_to_read()
			.notif_hide_details
			.unwrap_or(false)
	}

	/// Set whether payment notifications are reduced to a generic private alert.
	pub fn set_notif_hide_details(hide: bool) {
		let mut w_config = Settings::app_config_to_update();
		w_config.notif_hide_details = Some(hide);
		w_config.save();
	}

	/// Whether anonymous mode censors the home balance and activity list.
	pub fn anonymous_mode() -> bool {
		Settings::app_config_to_read()
			.anonymous_mode
			.unwrap_or(false)
	}

	/// Set whether anonymous mode censors the home balance and activity list.
	pub fn set_anonymous_mode(on: bool) {
		let mut w_config = Settings::app_config_to_update();
		w_config.anonymous_mode = Some(on);
		w_config.save();
	}
}

#[cfg(test)]
mod tests {
	use super::AppConfig;

	/// An old config carrying the now-removed price-cache fields (last_rate /
	/// last_rate_vs / last_rate_at) must still load: serde ignores unknown keys,
	/// so no migration is needed and the dead fields are simply dropped on the
	/// next save.
	#[test]
	fn loads_config_with_removed_price_cache_fields() {
		let mut toml = toml::to_string(&AppConfig::default()).expect("serialize default");
		toml.push_str("\nlast_rate = 1.23\nlast_rate_vs = \"usd\"\nlast_rate_at = 1700000000\n");
		let parsed = toml::from_str::<AppConfig>(&toml);
		assert!(
			parsed.is_ok(),
			"old config with removed price-cache fields should still load"
		);
	}

	/// A pre-redesign config carries `hide_amounts` but none of the new privacy
	/// fields. It must load unchanged (serde fills the absent Options with None),
	/// so the notification hide-amounts choice is preserved and the new controls
	/// default off: no user surprise on upgrade.
	#[test]
	fn old_config_without_new_privacy_fields_migrates_sensibly() {
		let mut cfg = AppConfig::default();
		cfg.hide_amounts = Some(true);
		let mut toml = toml::to_string(&cfg).expect("serialize");
		// Emulate a pre-redesign file that never knew the new keys.
		toml = toml
			.lines()
			.filter(|l| {
				!l.starts_with("notif_hide_names")
					&& !l.starts_with("notif_hide_details")
					&& !l.starts_with("anonymous_mode")
			})
			.collect::<Vec<_>>()
			.join("\n");
		let parsed = toml::from_str::<AppConfig>(&toml).expect("legacy config should load");
		assert_eq!(parsed.hide_amounts, Some(true), "existing choice preserved");
		assert_eq!(parsed.notif_hide_names, None, "new control defaults off");
		assert_eq!(parsed.notif_hide_details, None, "new control defaults off");
		assert_eq!(parsed.anonymous_mode, None, "anonymous mode defaults off");
	}
}
