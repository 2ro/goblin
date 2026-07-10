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

//! Node and connectivity screens.

use super::*;

impl GoblinWalletView {
	/// GRIM's four integrated-node tabs (Info / Metrics / Mining / Settings)
	/// hosted under a Goblin back header and segmented control — GRIM's
	/// dual-panel and floating-navbar chrome are never rendered. The header
	/// title follows the active tab, like GRIM's own title panel.
	pub(super) fn integrated_node_ui(&mut self, ui: &mut egui::Ui, cb: &dyn PlatformCallbacks) {
		use crate::gui::icons::{DATABASE, FACTORY, FADERS, GAUGE};
		use crate::gui::views::network::types::NodeTabType;
		use crate::gui::views::network::{
			NetworkContent, NetworkMetrics, NetworkMining, NetworkNode, NetworkSettings,
			disabled_node_ui, node_error_ui,
		};
		use crate::node::Node;
		let title = self.node_tab.get_type().title();
		if self.sub_header(ui, &title) {
			self.settings_page = self.node_tab_back;
			return;
		}
		let selected = match self.node_tab.get_type() {
			NodeTabType::Info => 0,
			NodeTabType::Metrics => 1,
			NodeTabType::Mining => 2,
			NodeTabType::Settings => 3,
		};
		if let Some(i) = w::segmented(ui, &[DATABASE, GAUGE, FACTORY, FADERS], selected) {
			self.node_tab = match i {
				0 => Box::new(NetworkNode),
				1 => Box::new(NetworkMetrics),
				2 => Box::new(NetworkMining::default()),
				_ => Box::new(NetworkSettings::default()),
			};
		}
		ui.add_space(12.0);
		// Same availability gate as GRIM's NetworkContent: the Settings tab is
		// editable with the node off; the live tabs need a running node with
		// stats before their content can draw.
		if self.node_tab.get_type() != NodeTabType::Settings {
			if let Some(err) = Node::get_error() {
				node_error_ui(ui, err);
			} else if !Node::is_running() {
				disabled_node_ui(ui);
			} else if Node::get_stats().is_none() || Node::is_restarting() || Node::is_stopping() {
				NetworkContent::loading_ui(ui, None::<String>);
			} else {
				self.node_tab.tab_ui(ui, cb);
			}
		} else {
			self.node_tab.tab_ui(ui, cb);
		}
		// Keep the stats fresh while the node runs.
		if Node::is_running() {
			ui.ctx().request_repaint_after(Node::STATS_UPDATE_DELAY);
		}
	}

	pub(super) fn node_settings_ui(
		&mut self,
		ui: &mut egui::Ui,
		wallet: &Wallet,
		cb: &dyn PlatformCallbacks,
	) {
		use crate::wallet::types::ConnectionMethod;
		use crate::wallet::{ConnectionsConfig, ExternalConnection};
		let t = theme::tokens();
		if self.sub_header(ui, &t!("goblin.node.title")) {
			self.settings_page = SettingsPage::Main;
			return;
		}
		ScrollArea::vertical()
			.id_salt("goblin_node_scroll")
			.auto_shrink([false; 2])
			.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
			.show(ui, |ui| {
				let live = wallet.get_current_connection();
				let saved = wallet.get_config().connection();
				settings_group(ui, &t!("goblin.node.connection"), |ui| {
					// Integrated node (run your own) sits at the top of the picker.
					{
						let active = matches!(&saved, ConnectionMethod::Integrated);
						let row = ui.horizontal(|ui| {
							ui.label(
								RichText::new(t!("goblin.node.integrated"))
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
							wallet.update_connection(&ConnectionMethod::Integrated);
							// Apply to the running session now, not on next unlock.
							wallet.reconnect_node();
						}
					}
					for conn in ConnectionsConfig::ext_conn_list() {
						let active =
							matches!(&saved, ConnectionMethod::External(id, _) if *id == conn.id);
						let label = conn.url.replace("https://", "").replace("http://", "");
						let mut removed = false;
						let row = ui.horizontal(|ui| {
							ui.label(
								RichText::new(&label)
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
								} else {
									// Trash, not an X: a grey × next to the active row's
									// green check read as a failed-status icon, not the
									// remove action it actually is.
									let x = ui.label(
										RichText::new(crate::gui::icons::TRASH_SIMPLE)
											.font(FontId::new(15.0, fonts::regular()))
											.color(t.surface_text_dim),
									);
									if x.interact(Sense::click()).clicked() {
										ConnectionsConfig::remove_ext_conn(conn.id);
										removed = true;
									}
								}
							});
						});
						ui.add_space(10.0);
						if !removed && !active && row.response.interact(Sense::click()).clicked() {
							wallet.update_connection(&ConnectionMethod::External(
								conn.id,
								conn.url.clone(),
							));
							// Apply to the running session now, not on next unlock.
							wallet.reconnect_node();
						}
					}
				});
				if saved != live {
					ui.add_space(8.0);
					ui.label(
						RichText::new(t!("goblin.node.applies_after"))
							.font(FontId::new(13.0, fonts::regular()))
							.color(t.text_dim),
					);
				}

				ui.add_space(16.0);
				settings_group(ui, &t!("goblin.node.add_external"), |ui| {
					TextEdit::new(egui::Id::from("set_node_url"))
						.focus(false)
						.hint_text("https://node.example.com:3413")
						.text_color(t.surface_text)
						.body()
						.ui(ui, &mut self.node_url_input, cb);
					ui.add_space(8.0);
					TextEdit::new(egui::Id::from("set_node_secret"))
						.focus(false)
						.hint_text(t!("goblin.node.api_secret_hint"))
						.text_color(t.surface_text)
						.body()
						.ui(ui, &mut self.node_secret_input, cb);
				});
				ui.add_space(10.0);
				let url = self.node_url_input.trim().to_string();
				let valid = url.starts_with("http://") || url.starts_with("https://");
				if w::big_action(ui, &t!("goblin.node.add_node"), false).clicked() && valid {
					let secret = {
						let s = self.node_secret_input.trim();
						if s.is_empty() {
							None
						} else {
							Some(s.to_string())
						}
					};
					let conn = ExternalConnection::new(url, None, secret);
					ConnectionsConfig::add_ext_conn(conn.clone());
					wallet
						.update_connection(&ConnectionMethod::External(conn.id, conn.url.clone()));
					// Apply to the running session now, not on next unlock.
					wallet.reconnect_node();
					self.node_url_input.clear();
					self.node_secret_input.clear();
				}
				// (The integrated-node tabs' single home is Settings → Advanced;
				// no duplicate entry here.)
				ui.add_space(16.0);
			});
	}

	/// Relay list editor; saving restarts the nostr service live.
	pub(super) fn relays_ui(
		&mut self,
		ui: &mut egui::Ui,
		wallet: &Wallet,
		cb: &dyn PlatformCallbacks,
	) {
		let t = theme::tokens();
		if self.sub_header(ui, &t!("goblin.relays.title")) {
			self.settings_page = SettingsPage::Main;
			return;
		}
		ScrollArea::vertical()
			.id_salt("goblin_relays_scroll")
			.auto_shrink([false; 2])
			.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
			.show(ui, |ui| {
				ui.label(
					RichText::new(t!("goblin.relays.intro"))
						.font(FontId::new(13.0, fonts::regular()))
						.color(t.text_dim),
				);
				ui.add_space(14.0);
				settings_group(ui, &t!("goblin.relays.your_relays"), |ui| {
					let mut remove: Option<usize> = None;
					let many = self.relay_edit.len() > 1;
					for (i, relay) in self.relay_edit.iter().enumerate() {
						ui.horizontal(|ui| {
							ui.label(
								RichText::new(relay)
									.font(FontId::new(14.0, fonts::medium()))
									.color(t.surface_text),
							);
							ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
								if many {
									let x = ui.label(
										RichText::new(crate::gui::icons::X)
											.font(FontId::new(15.0, fonts::regular()))
											.color(t.surface_text_mute),
									);
									if x.interact(Sense::click()).clicked() {
										remove = Some(i);
									}
								}
							});
						});
						ui.add_space(10.0);
					}
					if let Some(i) = remove {
						self.relay_edit.remove(i);
					}
				});

				ui.add_space(16.0);
				settings_group(ui, &t!("goblin.relays.add_relay"), |ui| {
					TextEdit::new(egui::Id::from("set_relay"))
						.focus(false)
						.hint_text("wss://relay.example.com")
						.text_color(t.surface_text)
						.body()
						.ui(ui, &mut self.relay_input, cb);
				});
				ui.add_space(10.0);
				let relay = self.relay_input.trim().to_string();
				let valid = relay.starts_with("wss://") || relay.starts_with("ws://");
				if w::big_action_on_card(ui, &t!("goblin.relays.add_relay_btn")).clicked()
					&& valid && !self.relay_edit.contains(&relay)
				{
					self.relay_edit.push(relay);
					self.relay_input.clear();
				}
				ui.add_space(10.0);
				if w::big_action(ui, &t!("goblin.relays.save_reconnect"), false).clicked() {
					if let Some(s) = wallet.nostr_service() {
						{
							let mut c = s.config.write();
							c.set_relays(self.relay_edit.clone());
							c.save();
						}
						s.restart(wallet.clone());
					}
					self.settings_page = SettingsPage::Main;
				}
				ui.add_space(16.0);
			});
	}

	/// Manual slatepack exchange — GRIM's native by-hand flow, exposed as an
	/// advanced fallback for when a payment can't ride a @username.
	pub(super) fn slatepack_ui(
		&mut self,
		ui: &mut egui::Ui,
		wallet: &Wallet,
		cb: &dyn PlatformCallbacks,
	) {
		let t = theme::tokens();
		if self.sub_header(ui, &t!("goblin.settings.slatepacks")) {
			self.settings_page = SettingsPage::Main;
			return;
		}
		ScrollArea::vertical()
			.id_salt("goblin_slatepack_scroll")
			.auto_shrink([false; 2])
			.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
			.show(ui, |ui| {
				ui.label(
					RichText::new(t!("goblin.settings.sp_intro"))
						.font(FontId::new(13.0, fonts::regular()))
						.color(t.text_dim),
				);
				ui.add_space(14.0);

				// Receive / continue: paste a slatepack, let the wallet route it.
				let mut do_process = false;
				settings_group(ui, &t!("goblin.settings.sp_receive_group"), |ui| {
					ui.label(
						RichText::new(t!("goblin.settings.sp_receive_blurb"))
							.font(FontId::new(12.5, fonts::regular()))
							.color(t.surface_text_dim),
					);
					ui.add_space(8.0);
					TextEdit::new(egui::Id::from("sp_paste"))
						.focus(false)
						.paste()
						.hint_text("BEGINSLATEPACK. … ENDSLATEPACK.")
						.text_color(t.surface_text)
						.body()
						.ui(ui, &mut self.slatepack.paste, cb);
				});
				ui.add_space(10.0);
				if w::big_action(ui, &t!("goblin.settings.sp_process"), false).clicked() {
					do_process = true;
				}
				if do_process {
					let text = self.slatepack.paste.trim().to_string();
					if text.is_empty() {
						self.slatepack.error =
							Some(t!("goblin.settings.sp_paste_first").to_string());
						self.slatepack.status = None;
					} else {
						use crate::wallet::types::ManualSlatepackOutcome as Out;
						match wallet.manual_process_slatepack(&text) {
							Ok(Out::Response(reply)) => {
								self.slatepack.result = reply;
								self.slatepack.status =
									Some(t!("goblin.settings.sp_reply_ready").to_string());
								self.slatepack.error = None;
								self.slatepack.paste.clear();
							}
							Ok(Out::Finalizing) => {
								self.slatepack.result.clear();
								self.slatepack.status =
									Some(t!("goblin.settings.sp_finalizing").to_string());
								self.slatepack.error = None;
								self.slatepack.paste.clear();
							}
							Err(e) => {
								self.slatepack.error = Some(e.to_string());
								self.slatepack.status = None;
							}
						}
					}
				}

				// Send: create a slatepack to hand over out-of-band.
				ui.add_space(16.0);
				let mut do_send = false;
				settings_group(ui, &t!("goblin.settings.sp_create_group"), |ui| {
					ui.label(
						RichText::new(t!("goblin.settings.sp_create_blurb"))
							.font(FontId::new(12.5, fonts::regular()))
							.color(t.surface_text_dim),
					);
					ui.add_space(8.0);
					TextEdit::new(egui::Id::from("sp_amount"))
						.focus(false)
						.numeric()
						.hint_text(t!("goblin.settings.sp_amount_hint"))
						.text_color(t.surface_text)
						.body()
						.ui(ui, &mut self.slatepack.amount, cb);
					ui.add_space(8.0);
					TextEdit::new(egui::Id::from("sp_addr"))
						.focus(false)
						.hint_text(t!("goblin.settings.sp_addr_hint"))
						.text_color(t.surface_text)
						.body()
						.ui(ui, &mut self.slatepack.address, cb);
				});
				ui.add_space(10.0);
				if w::big_action(ui, &t!("goblin.settings.sp_create"), false).clicked() {
					do_send = true;
				}
				if do_send {
					match grin_core::core::amount_from_hr_string(self.slatepack.amount.trim()) {
						Ok(a) if a > 0 => {
							let s = self.slatepack.address.trim();
							let dest = if s.is_empty() {
								None
							} else {
								Some(s.to_string())
							};
							match wallet.manual_send_slatepack(a, dest) {
								Ok(text) => {
									self.slatepack.result = text;
									self.slatepack.status =
										Some(t!("goblin.settings.sp_ready").to_string());
									self.slatepack.error = None;
								}
								Err(e) => {
									self.slatepack.error = Some(e.to_string());
									self.slatepack.status = None;
								}
							}
						}
						_ => {
							self.slatepack.error =
								Some(t!("goblin.settings.sp_amount_gt_zero").to_string());
							self.slatepack.status = None;
						}
					}
				}

				// Status, error, and the produced slatepack (copyable).
				if let Some(err) = self.slatepack.error.clone() {
					ui.add_space(10.0);
					ui.label(
						RichText::new(err)
							.font(FontId::new(13.0, fonts::regular()))
							.color(t.neg),
					);
				}
				if let Some(status) = self.slatepack.status.clone() {
					ui.add_space(10.0);
					ui.label(
						RichText::new(status)
							.font(FontId::new(13.0, fonts::regular()))
							.color(t.text_dim),
					);
				}
				let result = self.slatepack.result.clone();
				if !result.is_empty() {
					ui.add_space(14.0);
					settings_group(ui, &t!("goblin.settings.sp_to_send"), |ui| {
						let preview: String = result.chars().take(120).collect();
						let preview = if result.chars().count() > 120 {
							format!("{preview}…")
						} else {
							preview
						};
						ui.label(
							RichText::new(preview)
								.font(FontId::new(12.0, fonts::mono()))
								.color(t.surface_text_dim),
						);
					});
					ui.add_space(10.0);
					if w::big_action(ui, &t!("goblin.settings.sp_copy"), false).clicked() {
						cb.copy_string_to_buffer(result);
						cb.vibrate_copy();
					}
				}
				ui.add_space(16.0);
			});
	}
}
