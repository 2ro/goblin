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

//! Network-privacy screen: transport (Tor) panels and status.

use super::*;

/// One channel row on the Network-privacy page: a status dot, a title and a
/// wrapped blurb explaining where that traffic goes.
pub(super) fn privacy_line(ui: &mut egui::Ui, dot: Color32, title: &str, blurb: &str) {
	let t = theme::tokens();
	ui.horizontal_top(|ui| {
		let (rect, _) = ui.allocate_exact_size(Vec2::new(14.0, 20.0), Sense::hover());
		ui.painter()
			.circle_filled(rect.center() + Vec2::new(0.0, -2.0), 4.0, dot);
		ui.vertical(|ui| {
			ui.label(
				RichText::new(title)
					.font(FontId::new(14.0, fonts::semibold()))
					.color(t.surface_text),
			);
			ui.add_space(2.0);
			ui.label(
				RichText::new(blurb)
					.font(FontId::new(12.0, fonts::regular()))
					.color(t.surface_text_dim),
			);
		});
	});
	ui.add_space(10.0);
}

/// Like [`settings_group`] but with a colored header kicker — used by the
/// Network-privacy private-traffic panel, whose header is red ("TOR OFF") or
/// green ("TOR ON") to signal the current state.
pub(super) fn settings_group_colored(
	ui: &mut egui::Ui,
	title: &str,
	color: Color32,
	add: impl FnOnce(&mut egui::Ui),
) {
	ui.label(
		RichText::new(title.to_uppercase())
			.font(fonts::kicker())
			.color(color),
	);
	ui.add_space(8.0);
	w::card(ui, |ui| add(ui));
}

/// The shared Network-privacy body, rendered by BOTH the onboarding privacy
/// step and the Settings privacy screen so the two never drift. Draws the intro
/// copy (what Goblin sends + how privacy works — deliberately no crypto version
/// numbers), the always-direct Grin-node panel, the private-traffic panel whose
/// header/dots reflect `tor_on`, the large Tor switch, and the VPN nudge.
///
/// Returns `Some(new_value)` on the frame the switch is toggled; the caller
/// persists it (Settings writes the wallet Tor setting + restarts the service;
/// onboarding stashes it and writes it before the service starts).
pub(super) fn network_privacy_panels(ui: &mut egui::Ui, tor_on: bool) -> Option<bool> {
	let t = theme::tokens();
	// One short intro block: what Goblin sends + how it stays private
	// (deliberately no crypto version numbers).
	ui.label(
		RichText::new(t!("goblin.privacy.intro"))
			.font(FontId::new(14.0, fonts::regular()))
			.color(t.text_dim),
	);
	ui.add_space(16.0);

	// Grin node — ALWAYS DIRECT, brand-yellow dot, full width. Public chain
	// data, the same for everyone, never routed over Tor.
	settings_group(ui, &t!("goblin.privacy.always_direct"), |ui| {
		ui.set_min_width(ui.available_width());
		privacy_line(
			ui,
			theme::GOBLIN_YELLOW,
			&t!("goblin.privacy.grin_node"),
			&t!("goblin.privacy.grin_node_blurb"),
		);
	});
	ui.add_space(16.0);

	// Private traffic — header "TOR OFF" (red) / "TOR ON" (green); status dots
	// goblin-yellow when off (clearnet), blueviolet when on.
	let (header, header_color) = if tor_on {
		(t!("goblin.privacy.tor_on"), t.pos)
	} else {
		(t!("goblin.privacy.tor_off"), t.neg)
	};
	let dot = if tor_on { t.tor_purple } else { t.accent };
	let transport = [
		(
			t!("goblin.privacy.payments"),
			t!("goblin.privacy.payments_blurb"),
		),
		(
			t!("goblin.privacy.usernames"),
			t!("goblin.privacy.usernames_blurb"),
		),
		(
			t!("goblin.privacy.price_avatars"),
			t!("goblin.privacy.price_avatars_blurb"),
		),
	];
	settings_group_colored(ui, &header, header_color, |ui| {
		ui.set_min_width(ui.available_width());
		for (title, blurb) in &transport {
			privacy_line(ui, dot, title, blurb);
		}
	});
	ui.add_space(18.0);

	// Large Tor switch — the whole card is stacked and centered so it reads as
	// "flip between Tor and direct": title on top, the big switch on its own
	// row, then a full-width caption below that can never clip. The switch is
	// dormant gray when off, blueviolet when on (never yellow) — the color state
	// lives on the dots above; this reads on/off.
	let mut toggled = None;
	w::card(ui, |ui| {
		ui.set_min_width(ui.available_width());
		ui.vertical_centered(|ui| {
			ui.label(
				RichText::new(t!("goblin.privacy.tor_switch"))
					.font(FontId::new(15.0, fonts::semibold()))
					.color(t.surface_text),
			);
			ui.add_space(12.0);
			if w::toggle_large(ui, tor_on).clicked() {
				toggled = Some(!tor_on);
			}
			ui.add_space(12.0);
			ui.label(
				RichText::new(t!("goblin.privacy.tor_switch_sub"))
					.font(FontId::new(12.5, fonts::regular()))
					.color(t.surface_text_dim),
			);
		});
	});
	ui.add_space(12.0);
	ui.label(
		RichText::new(t!("goblin.privacy.vpn_note"))
			.font(FontId::new(12.5, fonts::regular()))
			.color(t.text_mute),
	);
	toggled
}

/// Localized transport-status label for the identity status lines. Tor and
/// clearnet are distinct states so a Tor-off wallet reads "Connected (direct)"
/// instead of forever "connecting over Tor".
pub(super) fn transport_status_label(
	status: crate::nostr::TransportStatus,
) -> std::borrow::Cow<'static, str> {
	use crate::nostr::TransportStatus::*;
	match status {
		ConnectedTor => t!("goblin.home.connected_tor"),
		TorReady => t!("goblin.home.tor_ready"),
		ConnectingTor => t!("goblin.home.connecting_tor"),
		ConnectedDirect => t!("goblin.home.connected_direct"),
		ConnectingDirect => t!("goblin.home.connecting_direct"),
	}
}

impl GoblinWalletView {
	/// Network-privacy screen: the interactive Tor toggle shared with onboarding.
	/// The Grin node is always direct; the private traffic (payments, name
	/// lookups, price) rides Tor when the switch is on, else connects directly.
	/// Flipping the switch writes the wallet Tor setting and restarts the service
	/// so the relay pool is rebuilt on the newly-selected transport.
	pub(super) fn privacy_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet) {
		if self.sub_header(ui, &t!("goblin.privacy.title")) {
			self.settings_page = SettingsPage::Main;
			return;
		}
		let tor_on = wallet
			.nostr_service()
			.map(|s| s.tor_routing())
			.unwrap_or(true);
		let mut toggled = None;
		ScrollArea::vertical()
			.id_salt("goblin_privacy_scroll")
			.auto_shrink([false; 2])
			.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
			.show(ui, |ui| {
				toggled = network_privacy_panels(ui, tor_on);
				ui.add_space(16.0);
			});
		if let Some(new_val) = toggled {
			if let Some(s) = wallet.nostr_service() {
				// Persist the explicit choice (auto-saves nostr.toml) and mirror
				// the process-global route flag so free-function HTTP callers pick
				// the matching transport immediately, then rebuild the pool.
				s.config.write().set_tor_enabled(new_val);
				crate::tor::set_route_over_tor(new_val);
				s.restart(wallet.clone());
			}
		}
	}

	/// Advanced Privacy page — notification hiding (amounts / names / all
	/// details) and the anonymous-mode toggle that dots the home balance and the
	/// activity list. All presentation-only; nothing here touches the money path.
	pub(super) fn advanced_privacy_ui(
		&mut self,
		ui: &mut egui::Ui,
		wallet: &Wallet,
		cb: &dyn PlatformCallbacks,
	) {
		let t = theme::tokens();
		if self.sub_header(ui, &t!("goblin.settings.advanced_privacy")) {
			self.settings_page = SettingsPage::Main;
			return;
		}
		ScrollArea::vertical()
			.id_salt("goblin_adv_privacy_scroll")
			.auto_shrink([false; 2])
			.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
			.show(ui, |ui| {
				ui.label(
					RichText::new(t!("goblin.advprivacy.intro"))
						.font(FontId::new(14.0, fonts::regular()))
						.color(t.text_dim),
				);
				ui.add_space(16.0);
				settings_group(ui, &t!("goblin.advprivacy.notifications"), |ui| {
					if let Some(v) = settings_row_toggle(
						ui,
						&t!("goblin.settings.hide_amounts"),
						&t!("goblin.settings.hide_amounts_sub"),
						crate::AppConfig::hide_amounts(),
					) {
						crate::AppConfig::set_hide_amounts(v);
					}
					if let Some(v) = settings_row_toggle(
						ui,
						&t!("goblin.advprivacy.hide_names"),
						&t!("goblin.advprivacy.hide_names_sub"),
						crate::AppConfig::notif_hide_names(),
					) {
						crate::AppConfig::set_notif_hide_names(v);
					}
					if let Some(v) = settings_row_toggle(
						ui,
						&t!("goblin.advprivacy.hide_details"),
						&t!("goblin.advprivacy.hide_details_sub"),
						crate::AppConfig::notif_hide_details(),
					) {
						crate::AppConfig::set_notif_hide_details(v);
					}
				});
				ui.add_space(16.0);
				settings_group(ui, &t!("goblin.advprivacy.anon"), |ui| {
					if let Some(v) = settings_row_toggle(
						ui,
						&t!("goblin.advprivacy.anon_toggle"),
						&t!("goblin.advprivacy.anon_sub"),
						crate::AppConfig::anonymous_mode(),
					) {
						crate::AppConfig::set_anonymous_mode(v);
					}
				});
				ui.add_space(16.0);
				// The local archive (contacts + payment history + requests) lives
				// here under Advanced privacy.
				settings_group(ui, &t!("goblin.settings.archive"), |ui| {
					if settings_row_btn(ui, &t!("goblin.settings.export_archive"), COPY) {
						if let Some(s) = wallet.nostr_service() {
							let json = s.store.export_json(&s.npub());
							cb.copy_string_to_buffer(json);
							cb.vibrate_copy();
						}
					}
					advanced_desc(ui, &t!("goblin.settings.export_archive_caption"));
					ui.add_space(10.0);
					// Destructive: danger styling + tap-twice confirm (like the
					// receipt's "Cancel payment") before the archive is wiped.
					let wipe_label = if self.wipe_confirm {
						t!("goblin.settings.wipe_history_confirm")
					} else {
						t!("goblin.settings.wipe_history")
					};
					if settings_row_danger(ui, &wipe_label, crate::gui::icons::X) {
						if self.wipe_confirm {
							if let Some(s) = wallet.nostr_service() {
								s.store.wipe_archive();
							}
							self.wipe_confirm = false;
						} else {
							self.wipe_confirm = true;
						}
					}
				});
				ui.add_space(16.0);
			});
	}
}
