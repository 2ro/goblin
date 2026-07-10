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

//! Settings index and simple settings screens.

use super::*;

impl GoblinWalletView {
	/// Back header for Settings sub-pages; returns true when back is tapped.
	pub(super) fn sub_header(&mut self, ui: &mut egui::Ui, title: &str) -> bool {
		let t = theme::tokens();
		let mut back = false;
		ui.add_space(8.0);
		ui.horizontal(|ui| {
			let (rect, resp) = ui.allocate_exact_size(Vec2::splat(36.0), Sense::click());
			ui.painter().circle_filled(rect.center(), 18.0, t.surface2);
			ui.painter().text(
				rect.center(),
				egui::Align2::CENTER_CENTER,
				crate::gui::icons::ARROW_LEFT,
				FontId::new(16.0, fonts::regular()),
				theme::ink_for(t.surface2),
			);
			back = resp.clicked();
			ui.add_space(12.0);
			ui.label(
				RichText::new(title)
					.font(FontId::new(24.0, fonts::bold()))
					.color(t.text),
			);
		});
		ui.add_space(16.0);
		back
	}

	/// Node connection editor: pick integrated/external, add or remove nodes.
	pub(super) fn pairing_settings_ui(&mut self, ui: &mut egui::Ui) {
		let t = theme::tokens();
		if self.sub_header(ui, &t!("goblin.pairing.title")) {
			self.settings_page = SettingsPage::Main;
			return;
		}
		ScrollArea::vertical()
			.id_salt("goblin_pairing_scroll")
			.auto_shrink([false; 2])
			.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
			.show(ui, |ui| {
				ui.label(
					RichText::new(t!("goblin.pairing.intro"))
						.font(FontId::new(13.0, fonts::regular()))
						.color(t.text_dim),
				);
				ui.add_space(12.0);
				let current = crate::AppConfig::pairing();
				settings_group(ui, &t!("goblin.pairing.pair_with"), |ui| {
					for p in crate::settings::Pairing::ALL {
						let active = p == current;
						let row = ui.horizontal(|ui| {
							ui.label(
								RichText::new(p.label())
									.font(FontId::new(15.0, fonts::medium()))
									.color(t.surface_text),
							);
							ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
								if active {
									ui.label(
										RichText::new(crate::gui::icons::CHECK)
											.font(FontId::new(16.0, fonts::regular()))
											.color(t.pos),
									);
								}
							});
						});
						ui.add_space(10.0);
						if !active && row.response.interact(Sense::click()).clicked() {
							crate::AppConfig::set_pairing(p);
						}
					}
				});
				ui.add_space(10.0);
				ui.label(
					RichText::new(t!("goblin.pairing.rates_note"))
						.font(FontId::new(12.0, fonts::regular()))
						.color(t.text_dim),
				);
				ui.add_space(16.0);
			});
	}

	/// Language picker: the nine shipped locales, each in its own name. Tapping one
	/// switches the active locale and persists it (mirrors the GRIM interface
	/// settings, but in Goblin's row style like the pairing picker).
	pub(super) fn language_settings_ui(&mut self, ui: &mut egui::Ui) {
		let t = theme::tokens();
		if self.sub_header(ui, &t!("goblin.settings.language")) {
			self.settings_page = SettingsPage::Main;
			return;
		}
		let current = crate::AppConfig::locale().unwrap_or_else(|| rust_i18n::locale().to_string());
		ScrollArea::vertical()
			.id_salt("goblin_language_scroll")
			.auto_shrink([false; 2])
			.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
			.show(ui, |ui| {
				settings_group(ui, &t!("goblin.settings.language"), |ui| {
					for locale in rust_i18n::available_locales!() {
						let active = current == locale;
						let row = ui.horizontal(|ui| {
							ui.label(
								RichText::new(t!("lang_name", locale = locale))
									.font(FontId::new(15.0, fonts::medium()))
									.color(t.surface_text),
							);
							ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
								if active {
									ui.label(
										RichText::new(crate::gui::icons::CHECK)
											.font(FontId::new(16.0, fonts::regular()))
											.color(t.pos),
									);
								}
							});
						});
						ui.add_space(10.0);
						if !active && row.response.interact(Sense::click()).clicked() {
							rust_i18n::set_locale(locale);
							crate::AppConfig::save_locale(locale);
						}
					}
				});
				ui.add_space(16.0);
			});
	}

	/// What-is-nostr explainer and tappable NIP reference list.
	pub(super) fn nips_ui(&mut self, ui: &mut egui::Ui) {
		let t = theme::tokens();
		if self.sub_header(ui, &t!("goblin.nips.title")) {
			self.settings_page = SettingsPage::Main;
			return;
		}
		ScrollArea::vertical()
			.id_salt("goblin_nips_scroll")
			.auto_shrink([false; 2])
			.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
			.show(ui, |ui| {
				ui.label(
					RichText::new(t!("goblin.nips.intro1"))
						.font(FontId::new(14.0, fonts::regular()))
						.color(t.text_dim),
				);
				ui.add_space(10.0);
				ui.label(
					RichText::new(t!("goblin.nips.intro2"))
						.font(FontId::new(14.0, fonts::regular()))
						.color(t.text_dim),
				);
				ui.add_space(16.0);
				let nips = [
					(
						"05",
						t!("goblin.nips.n05_title"),
						t!("goblin.nips.n05_blurb"),
					),
					(
						"17",
						t!("goblin.nips.n17_title"),
						t!("goblin.nips.n17_blurb"),
					),
					(
						"44",
						t!("goblin.nips.n44_title"),
						t!("goblin.nips.n44_blurb"),
					),
					(
						"49",
						t!("goblin.nips.n49_title"),
						t!("goblin.nips.n49_blurb"),
					),
					(
						"59",
						t!("goblin.nips.n59_title"),
						t!("goblin.nips.n59_blurb"),
					),
					(
						"98",
						t!("goblin.nips.n98_title"),
						t!("goblin.nips.n98_blurb"),
					),
				];
				for (num, title, blurb) in &nips {
					let resp = ui.scope(|ui| {
						w::card(ui, |ui| {
							ui.set_min_width(ui.available_width());
							ui.label(
								RichText::new(format!("NIP-{} · {}", num, title))
									.font(FontId::new(14.0, fonts::semibold()))
									.color(t.surface_text),
							);
							ui.add_space(2.0);
							ui.label(
								RichText::new(blurb.as_ref())
									.font(FontId::new(12.0, fonts::regular()))
									.color(t.surface_text_dim),
							);
						});
					});
					if resp.response.interact(Sense::click()).clicked() {
						open_url(
							ui,
							&format!(
								"https://github.com/nostr-protocol/nips/blob/master/{}.md",
								num
							),
						);
					}
					ui.add_space(8.0);
				}
				ui.add_space(16.0);
			});
	}

	/// Inline "back up identity to a file" flow: ask for the wallet password,
	/// seal the identity, and write a GOBLIN-*.backup file via the native picker.
	pub(super) fn backup_ui(
		&mut self,
		ui: &mut egui::Ui,
		wallet: &Wallet,
		cb: &dyn PlatformCallbacks,
	) {
		let t = theme::tokens();
		let bk = self.backup.as_mut().unwrap();
		let mut close = false;
		w::card(ui, |ui| {
			ui.set_min_width(ui.available_width());
			if bk.done {
				ui.label(
					RichText::new(t!("goblin.settings.backup_saved"))
						.font(FontId::new(15.0, fonts::semibold()))
						.color(t.pos),
				);
				ui.add_space(4.0);
				ui.label(
					RichText::new(t!("goblin.settings.backup_saved_sub"))
						.font(FontId::new(13.0, fonts::regular()))
						.color(t.surface_text_dim),
				);
				ui.add_space(10.0);
				if w::big_action(ui, &t!("goblin.settings.done"), false).clicked() {
					close = true;
				}
				return;
			}
			ui.label(
				RichText::new(t!("goblin.settings.backup_file_title"))
					.font(FontId::new(15.0, fonts::semibold()))
					.color(t.surface_text),
			);
			ui.add_space(6.0);
			ui.label(
				RichText::new(t!("goblin.settings.backup_file_blurb"))
					.font(FontId::new(13.0, fonts::regular()))
					.color(t.surface_text_dim),
			);
			ui.add_space(10.0);
			w::field_well(ui, |ui| {
				TextEdit::new(egui::Id::from("backup_pass"))
					.focus(false)
					.hint_text(t!("goblin.settings.wallet_password"))
					.password()
					.text_color(t.surface_text)
					.body()
					.ui(ui, &mut bk.password, cb);
			});
			if let Some(err) = &bk.error {
				ui.add_space(6.0);
				ui.label(
					RichText::new(err)
						.font(FontId::new(12.5, fonts::regular()))
						.color(t.neg),
				);
			}
			ui.add_space(10.0);
			ui.horizontal(|ui| {
				let half = (ui.available_width() - 10.0) / 2.0;
				ui.scope_builder(
					egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
						ui.cursor().min,
						Vec2::new(half, 44.0),
					)),
					|ui| {
						if w::big_action_on_card(ui, &t!("goblin.settings.cancel")).clicked() {
							close = true;
						}
					},
				);
				ui.add_space(10.0);
				ui.scope_builder(
					egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
						ui.cursor().min,
						Vec2::new(half, 44.0),
					)),
					|ui| {
						ui.add_enabled_ui(!bk.password.is_empty(), |ui| {
							if w::big_action(ui, &t!("goblin.settings.create_backup"), false)
								.clicked()
							{
								match wallet.create_full_backup(&bk.password) {
									Ok(envelope) => {
										let stamp = chrono::Local::now().format("%Y-%m-%d-%H%M");
										let fname = format!("GOBLIN-{stamp}.backup");
										match cb.save_file(fname, envelope.into_bytes()) {
											Ok(()) => {
												bk.done = true;
												bk.error = None;
												bk.password.clear();
											}
											Err(_) => {
												bk.error = Some(
													t!("goblin.settings.backup_write_failed")
														.to_string(),
												);
											}
										}
									}
									Err(e) => bk.error = Some(e),
								}
							}
						});
					},
				);
			});
		});
		if close {
			self.backup = None;
		}
	}
}
