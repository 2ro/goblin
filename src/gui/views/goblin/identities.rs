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

//! Identity switcher and identity-management modals.

use super::*;

impl GoblinWalletView {
	/// The identity switcher page: one wallet, one grin balance, many nostr
	/// identities. Lists the held identities (tap to make one active), and adds a
	/// new one (generate a fresh nsec or import an existing one). Switching runs a
	/// catch-up so payments that arrived while an identity was dormant land in the
	/// single shared balance; the syncing / "you were paid while away" state shows
	/// here. The wallet password (entered once on this page) unlocks a target on
	/// switch and encrypts a new identity on add — every held nsec is stored the
	/// same way: its own NIP-49 ncryptsec under the wallet password.
	pub(super) fn identities_ui(
		&mut self,
		ui: &mut egui::Ui,
		wallet: &Wallet,
		cb: &dyn PlatformCallbacks,
	) {
		let t = theme::tokens();
		if self.sub_header(ui, &t!("goblin.identities.title")) {
			self.settings_page = SettingsPage::Main;
			self.identity_switch = IdentitySwitchState::default();
			return;
		}
		// Poll the background switch/add worker.
		if self.identity_switch.busy
			&& let Some(res) = self.identity_switch.result.lock().unwrap().take()
		{
			self.identity_switch.busy = false;
			match res {
				Ok(_) => {
					self.identity_switch.error.clear();
					self.identity_switch.adding = false;
					self.identity_switch.import = false;
					self.identity_switch.nsec.clear();
					self.identity_switch.backup_input.clear();
					self.identity_switch.confirm_delete = None;
				}
				Err(e) => {
					self.identity_switch.error = e;
				}
			}
		}

		// Wallet-password modal — the unlock step for ADDING an identity only
		// (switching is instant and local, no password), mirroring the wallet-open
		// password modal (dimmed backdrop, same buttons).
		if Modal::opened() == Some(IDENTITY_PASS_MODAL) {
			Modal::ui(ui.ctx(), cb, |ui, modal, cb| {
				self.identity_pass_modal_content(ui, modal, wallet, cb);
			});
		}
		// Per-identity management modal (rename / delete): dims and locks the
		// list, disabling switching and row taps until it closes.
		if Modal::opened() == Some(IDENTITY_MANAGE_MODAL) {
			Modal::ui(ui.ctx(), cb, |ui, _modal, cb| {
				self.identity_manage_modal_content(ui, wallet, cb);
			});
		}
		// Step-1 delete confirmation modal (danger text), also background-locking.
		if Modal::opened() == Some(IDENTITY_DELETE_MODAL) {
			Modal::ui(ui.ctx(), cb, |ui, _modal, _cb| {
				self.identity_delete_modal_content(ui, wallet);
			});
		}

		let identities = wallet.nostr_identities();

		ScrollArea::vertical()
			.id_salt("goblin_identities_scroll")
			.auto_shrink([false; 2])
			.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
			.show(ui, |ui| {
				ui.label(
					RichText::new(t!("goblin.identities.blurb"))
						.font(FontId::new(13.5, fonts::regular()))
						.color(t.text_dim),
				);
				ui.add_space(8.0);
				ui.label(
					RichText::new(t!("goblin.identities.privacy_note"))
						.font(FontId::new(12.0, fonts::regular()))
						.color(t.text_mute),
				);
				ui.add_space(14.0);

				// Held identities. Tap a non-active one to switch to it INSTANTLY —
				// all identities are already unlocked and listening, so a switch is a
				// local change of which one is presented and used for sending.
				w::kicker(ui, &t!("goblin.identities.held"));
				ui.add_space(8.0);
				let busy = self.identity_switch.busy;
				let mut switch_to: Option<String> = None;
				let mut manage_target: Option<String> = None;
				for id in &identities {
					// Display precedence: private tag, else claimed name (bare, no
					// leading @), else truncated npub. Never a placeholder word.
					let short = data::short_npub(&id.pubkey_hex);
					let title = id.display();
					let mut pencil_hit = false;
					let row = w::card(ui, |ui| {
						ui.set_min_width(ui.available_width());
						ui.horizontal(|ui| {
							w::avatar_any(ui, &title, &id.pubkey_hex, 40.0, None);
							ui.add_space(12.0);
							ui.vertical(|ui| {
								ui.label(
									RichText::new(&title)
										.font(FontId::new(15.0, fonts::semibold()))
										.color(t.surface_text),
								);
								// The npub underneath, unless the title already IS the
								// npub (unnamed, untagged identity).
								if title != short {
									ui.label(
										RichText::new(&short)
											.font(FontId::new(12.0, fonts::regular()))
											.color(t.surface_text_mute),
									);
								}
							});
							ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
								if id.active {
									ui.label(
										RichText::new(crate::gui::icons::CHECK_CIRCLE)
											.font(FontId::new(18.0, fonts::regular()))
											.color(t.pos),
									);
								} else {
									ui.label(
										RichText::new(crate::gui::icons::ARROWS_LEFT_RIGHT)
											.font(FontId::new(16.0, fonts::regular()))
											.color(t.surface_text_dim),
									);
								}
								// Edit (pencil) affordance: opens the per-identity
								// management sheet (rename / delete). Its own tap target
								// so it never triggers the row switch.
								if !busy {
									ui.add_space(8.0);
									let (r, resp) =
										ui.allocate_exact_size(Vec2::splat(28.0), Sense::click());
									ui.painter().text(
										r.center(),
										egui::Align2::CENTER_CENTER,
										crate::gui::icons::PENCIL_SIMPLE,
										FontId::new(16.0, fonts::regular()),
										t.surface_text_dim,
									);
									if resp
										.on_hover_cursor(egui::CursorIcon::PointingHand)
										.clicked()
									{
										pencil_hit = true;
									}
								}
							});
						})
						.response
						.rect
					});
					// Tap anywhere else on a non-active row = INSTANT switch (skip
					// when the pencil was tapped, whose rect overlaps the row).
					if !id.active && !busy {
						let hit = ui.interact(
							row,
							egui::Id::new(("id_switch", id.pubkey_hex.as_str())),
							Sense::click(),
						);
						if !pencil_hit
							&& hit
								.on_hover_cursor(egui::CursorIcon::PointingHand)
								.clicked()
						{
							switch_to = Some(id.pubkey_hex.clone());
						}
					}
					if pencil_hit {
						manage_target = Some(id.pubkey_hex.clone());
					}
					ui.add_space(6.0);
				}

				// Tapping a held identity switches to it INSTANTLY — no password, no
				// sync (it was already unlocked and listening). Purely local.
				if let Some(target) = switch_to {
					self.identity_switch.error.clear();
					if let Err(e) = wallet.switch_nostr_identity(target) {
						self.identity_switch.error = e;
					}
				}
				// The pencil opens the management MODAL, pre-filled with the tag and
				// titled with the identity it manages. The GRIM Modal dims and locks
				// the list behind it, so no switching or row taps while it is open.
				if let Some(target) = manage_target {
					self.identity_switch.error.clear();
					self.identity_switch.confirm_delete = None;
					let display = identities
						.iter()
						.find(|i| i.pubkey_hex == target)
						.map(|i| i.display())
						.unwrap_or_else(|| data::short_npub(&target));
					self.identity_switch.tag_input = identities
						.iter()
						.find(|i| i.pubkey_hex == target)
						.and_then(|i| i.tag.clone())
						.unwrap_or_default();
					self.identity_switch.manage = Some(target);
					Modal::new(IDENTITY_MANAGE_MODAL)
						.position(ModalPosition::CenterTop)
						.title(display)
						.show();
				}

				ui.add_space(8.0);

				// Add-identity section.
				if !self.identity_switch.adding {
					if w::big_action(ui, &t!("goblin.identities.add"), false).clicked() {
						self.identity_switch.adding = true;
						self.identity_switch.error.clear();
					}
				} else {
					w::card(ui, |ui| {
						ui.set_min_width(ui.available_width());
						ui.label(
							RichText::new(t!("goblin.identities.add_title"))
								.font(FontId::new(15.0, fonts::semibold()))
								.color(t.surface_text),
						);
						ui.add_space(8.0);
						// The sheet defaults to GENERATE (a fresh anonymous key). What
						// generating means, in one line, so the default mode isn't blank.
						if !self.identity_switch.import {
							ui.label(
								RichText::new(t!("goblin.identities.generate_note"))
									.font(FontId::new(12.5, fonts::regular()))
									.color(t.surface_text_dim),
							);
						}
						if self.identity_switch.import {
							ui.add_space(8.0);
							// (a) Select a .backup file. Desktop returns the path now;
							// Android returns it asynchronously (poll picked_file()).
							if self.identity_switch.picking {
								if let Some(path) = cb.picked_file() {
									self.identity_switch.picking = false;
									if !path.is_empty() {
										match std::fs::read_to_string(&path) {
											Ok(c) => {
												self.identity_switch.backup_input =
													c.trim().to_string()
											}
											Err(_) => {
												self.identity_switch.error =
													t!("goblin.settings.backup_read_failed")
														.to_string()
											}
										}
									}
								} else {
									ui.ctx().request_repaint();
								}
							}
							let file_label = if self.identity_switch.backup_input.is_empty() {
								t!("goblin.identities.choose_backup").to_string()
							} else {
								t!("goblin.identities.backup_selected").to_string()
							};
							if w::big_action_on_card(ui, &file_label).clicked() {
								self.identity_switch.error.clear();
								match cb.pick_file() {
									Some(path) if !path.is_empty() => {
										match std::fs::read_to_string(&path) {
											Ok(c) => {
												self.identity_switch.backup_input =
													c.trim().to_string()
											}
											Err(_) => {
												self.identity_switch.error =
													t!("goblin.settings.backup_read_failed")
														.to_string()
											}
										}
									}
									Some(_) => self.identity_switch.picking = true,
									None => {}
								}
							}
							ui.add_space(8.0);
							// (b) Or paste an nsec.
							w::field_well(ui, |ui| {
								TextEdit::new(egui::Id::from("identity_add_nsec"))
									.focus(false)
									.hint_text(t!("goblin.identities.nsec_hint"))
									.password()
									.text_color(t.surface_text)
									.body()
									.ui(ui, &mut self.identity_switch.nsec, cb);
							});
						}
						ui.add_space(10.0);
						let import = self.identity_switch.import;
						let busy = self.identity_switch.busy;
						// Two real actions instead of a mode toggle: Generate is always
						// ready; Import first reveals the .backup/nsec inputs, then
						// confirms once one of them is filled. The password is entered
						// in the modal.
						let has_import = !self.identity_switch.backup_input.trim().is_empty()
							|| self.identity_switch.nsec.trim().starts_with("nsec1");
						let import_armed = (!import || has_import) && !busy;
						// The password-gated add to launch this frame: `Some(None)` for
						// a fresh key, `Some(Some(blob))` for an import.
						let mut open_add: Option<Option<String>> = None;
						ui.horizontal(|ui| {
							let half = (ui.available_width() - 10.0) / 2.0;
							// Generate on the LEFT, the positive (green) action: a
							// fresh anonymous key via the existing password step.
							ui.scope_builder(
								egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
									ui.cursor().min,
									Vec2::new(half, 44.0),
								)),
								|ui| {
									ui.add_enabled_ui(!busy, |ui| {
										if w::big_action_on_card_ink(
											ui,
											&t!("goblin.identities.generate"),
											if busy { t.surface_text_mute } else { t.pos },
										)
										.clicked()
										{
											open_add = Some(None);
										}
									});
								},
							);
							ui.add_space(10.0);
							// Import on the RIGHT, neutral: reveal-then-confirm.
							ui.scope_builder(
								egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
									ui.cursor().min,
									Vec2::new(half, 44.0),
								)),
								|ui| {
									ui.add_enabled_ui(import_armed, |ui| {
										if w::big_action_on_card_ink(
											ui,
											&t!("goblin.identities.import"),
											if import_armed {
												t.surface_text
											} else {
												t.surface_text_mute
											},
										)
										.clicked()
										{
											if !import {
												// First tap: reveal the import inputs.
												self.identity_switch.import = true;
												self.identity_switch.error.clear();
											} else {
												// Confirm: the selected .backup wins over
												// a pasted nsec.
												let b = self.identity_switch.backup_input.trim();
												let blob = if b.is_empty() {
													self.identity_switch.nsec.trim().to_string()
												} else {
													b.to_string()
												};
												open_add = Some(Some(blob));
											}
										}
									});
								},
							);
						});
						// Cancel centered BENEATH the pair: red, same uniform size.
						ui.add_space(10.0);
						ui.horizontal(|ui| {
							let half = (ui.available_width() - 10.0) / 2.0;
							ui.add_space((ui.available_width() - half) / 2.0);
							ui.scope_builder(
								egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
									ui.cursor().min,
									Vec2::new(half, 44.0),
								)),
								|ui| {
									if w::big_action_on_card_ink(
										ui,
										&t!("goblin.settings.cancel"),
										t.neg,
									)
									.clicked()
									{
										self.identity_switch.adding = false;
										self.identity_switch.import = false;
										self.identity_switch.nsec.clear();
										self.identity_switch.backup_input.clear();
										self.identity_switch.error.clear();
									}
								},
							);
						});
						if let Some(import_blob) = open_add {
							// Open the password modal to encrypt+store the new
							// identity. It is added WITHOUT switching; the user
							// activates it later by tapping it.
							self.identity_switch.error.clear();
							self.identity_switch.pass.clear();
							self.identity_switch.wrong_pass = false;
							self.identity_switch.pending =
								Some(PendingPassAction::Add(import_blob));
							Modal::new(IDENTITY_PASS_MODAL)
								.position(ModalPosition::CenterTop)
								.title(t!("goblin.identities.add_title"))
								.show();
						}
					});
				}

				if self.identity_switch.busy {
					ui.add_space(10.0);
					ui.horizontal(|ui| {
						View::small_loading_spinner(ui);
						ui.add_space(8.0);
						ui.label(
							RichText::new(t!("goblin.identities.working"))
								.font(FontId::new(13.0, fonts::regular()))
								.color(t.surface_text_dim),
						);
					});
					ui.ctx().request_repaint();
				}
				if !self.identity_switch.error.is_empty() {
					ui.add_space(8.0);
					ui.label(
						RichText::new(&self.identity_switch.error)
							.font(FontId::new(12.5, fonts::regular()))
							.color(t.neg),
					);
				}
				ui.add_space(24.0);
			});
	}

	/// Content of the wallet-password modal that gates ADDING an identity (encrypt
	/// + store its new nsec). Switching no longer uses this — it is instant and
	/// local. Mirrors the wallet-open password modal (open.rs): explanation, masked
	/// field, wrong-password line, Cancel/Continue. A correct password is verified
	/// synchronously before the add worker is spawned, so a wrong password stays in
	/// the modal instead of failing later.
	pub(super) fn identity_pass_modal_content(
		&mut self,
		ui: &mut egui::Ui,
		modal: &Modal,
		wallet: &Wallet,
		cb: &dyn PlatformCallbacks,
	) {
		let mut go = false;
		let mut cancel = false;
		ui.vertical_centered(|ui| {
			ui.add_space(6.0);
			ui.label(
				RichText::new(t!("goblin.identities.pass_prompt"))
					.size(16.0)
					.color(Colors::gray()),
			);
			ui.add_space(10.0);
			let mut field = TextEdit::new(egui::Id::from(modal.id).with("id_pass")).password();
			field.ui(ui, &mut self.identity_switch.pass, cb);
			if field.enter_pressed {
				go = true;
			}
			if self.identity_switch.pass.is_empty() {
				self.identity_switch.wrong_pass = false;
			} else if self.identity_switch.wrong_pass {
				ui.add_space(10.0);
				ui.label(
					RichText::new(t!("goblin.advanced.wrong_password"))
						.size(16.0)
						.color(Colors::red()),
				);
			}
			ui.add_space(12.0);
		});
		ui.scope(|ui| {
			ui.spacing_mut().item_spacing = egui::Vec2::new(8.0, 0.0);
			ui.columns(2, |columns| {
				columns[0].vertical_centered_justified(|ui| {
					View::button(
						ui,
						t!("modal.cancel"),
						Colors::white_or_black(false),
						|| {
							cancel = true;
						},
					);
				});
				columns[1].vertical_centered_justified(|ui| {
					View::button(ui, t!("continue"), Colors::white_or_black(false), || {
						go = true;
					});
				});
			});
			ui.add_space(6.0);
		});
		if cancel {
			self.identity_switch.pass.clear();
			self.identity_switch.pending = None;
			self.identity_switch.wrong_pass = false;
			Modal::close();
		}
		if go && !self.identity_switch.pass.is_empty() {
			if !wallet.verify_nostr_password(&self.identity_switch.pass) {
				self.identity_switch.wrong_pass = true;
			} else if let Some(action) = self.identity_switch.pending.take() {
				let password = std::mem::take(&mut self.identity_switch.pass);
				self.identity_switch.wrong_pass = false;
				self.identity_switch.error.clear();
				self.identity_switch.busy = true;
				let slot = self.identity_switch.result.clone();
				let w = wallet.clone();
				std::thread::spawn(move || {
					let r = match action {
						// Add only — never auto-switch into the new identity.
						PendingPassAction::Add(import) => w.add_nostr_identity(import, password),
						// Delete returns the surviving active npub for the result slot.
						PendingPassAction::Delete(hex) => w
							.delete_nostr_identity(hex, password)
							.map(|_| String::new()),
					};
					*slot.lock().unwrap() = Some(r);
				});
				Modal::close();
			}
		}
	}

	/// Content of the per-identity management MODAL (title = the identity's
	/// display name). Rename (the private, app-only tag — never published) on
	/// top with uniform paired Cancel/Save buttons; Delete at the bottom,
	/// separated and red, feeding the delete-confirmation modal. Being a GRIM
	/// Modal, the identity list behind it is dimmed and locked.
	pub(super) fn identity_manage_modal_content(
		&mut self,
		ui: &mut egui::Ui,
		wallet: &Wallet,
		cb: &dyn PlatformCallbacks,
	) {
		let Some(target) = self.identity_switch.manage.clone() else {
			Modal::close();
			return;
		};
		ui.vertical_centered(|ui| {
			ui.add_space(6.0);
			ui.label(
				RichText::new(t!("goblin.identities.tag_note"))
					.size(16.0)
					.color(Colors::gray()),
			);
			ui.add_space(10.0);
			let mut field = TextEdit::new(egui::Id::from(IDENTITY_MANAGE_MODAL).with("tag"))
				.hint_text(t!("goblin.identities.tag_hint"));
			field.ui(ui, &mut self.identity_switch.tag_input, cb);
			ui.add_space(12.0);
		});
		let mut save = false;
		let mut cancel = false;
		let mut delete = false;
		ui.scope(|ui| {
			ui.spacing_mut().item_spacing = egui::Vec2::new(8.0, 0.0);
			ui.columns(2, |columns| {
				columns[0].vertical_centered_justified(|ui| {
					View::button(
						ui,
						t!("modal.cancel"),
						Colors::white_or_black(false),
						|| {
							cancel = true;
						},
					);
				});
				columns[1].vertical_centered_justified(|ui| {
					View::button(
						ui,
						t!("goblin.identities.tag_save"),
						Colors::white_or_black(false),
						|| {
							save = true;
						},
					);
				});
			});
			// Delete lives at the bottom, clearly apart from rename, red, same
			// button shape. Only while more than one identity is held.
			if wallet.nostr_identities().len() > 1 {
				ui.add_space(10.0);
				ui.vertical_centered_justified(|ui| {
					View::colored_text_button(
						ui,
						t!("goblin.identities.delete_short").to_string(),
						Colors::red(),
						Colors::white_or_black(false),
						|| {
							delete = true;
						},
					);
				});
			}
			ui.add_space(6.0);
		});
		if cancel {
			self.identity_switch.manage = None;
			self.identity_switch.tag_input.clear();
			Modal::close();
		}
		if save {
			let tag = std::mem::take(&mut self.identity_switch.tag_input);
			if let Err(e) = wallet.rename_nostr_identity(target.clone(), tag) {
				self.identity_switch.error = e;
			}
			self.identity_switch.manage = None;
			Modal::close();
		}
		if delete {
			// Step 1 of the delete gate: the danger-confirmation modal.
			self.identity_switch.manage = None;
			self.identity_switch.confirm_delete = Some(target.clone());
			let display = wallet
				.nostr_identities()
				.iter()
				.find(|i| i.pubkey_hex == target)
				.map(|i| i.display())
				.unwrap_or_else(|| data::short_npub(&target));
			Modal::close();
			Modal::new(IDENTITY_DELETE_MODAL)
				.position(ModalPosition::CenterTop)
				.title(display)
				.show();
		}
	}

	/// Content of the step-1 delete-confirmation MODAL (title = the identity's
	/// display name): states the removal is PERMANENT with a prominent back-up
	/// reminder, then uniform paired Cancel/Delete buttons — Delete red, same
	/// size and shape. Confirming opens the wallet-password modal (step 2).
	pub(super) fn identity_delete_modal_content(&mut self, ui: &mut egui::Ui, wallet: &Wallet) {
		let Some(target) = self.identity_switch.confirm_delete.clone() else {
			Modal::close();
			return;
		};
		let display = wallet
			.nostr_identities()
			.iter()
			.find(|i| i.pubkey_hex == target)
			.map(|i| i.display())
			.unwrap_or_else(|| data::short_npub(&target));
		ui.vertical_centered(|ui| {
			ui.add_space(6.0);
			ui.label(
				RichText::new(t!("goblin.identities.delete_title", name => display))
					.size(17.0)
					.color(Colors::red()),
			);
			ui.add_space(8.0);
			ui.label(
				RichText::new(t!("goblin.identities.delete_blurb"))
					.size(15.0)
					.color(Colors::gray()),
			);
			ui.add_space(8.0);
			ui.label(
				RichText::new(t!("goblin.identities.delete_backup_note"))
					.size(15.0)
					.color(Colors::red()),
			);
			ui.add_space(12.0);
		});
		let mut cancel = false;
		let mut confirm = false;
		ui.scope(|ui| {
			ui.spacing_mut().item_spacing = egui::Vec2::new(8.0, 0.0);
			ui.columns(2, |columns| {
				columns[0].vertical_centered_justified(|ui| {
					View::button(
						ui,
						t!("modal.cancel"),
						Colors::white_or_black(false),
						|| {
							cancel = true;
						},
					);
				});
				columns[1].vertical_centered_justified(|ui| {
					View::colored_text_button(
						ui,
						t!("goblin.identities.delete_confirm").to_string(),
						Colors::red(),
						Colors::white_or_black(false),
						|| {
							confirm = true;
						},
					);
				});
			});
			ui.add_space(6.0);
		});
		if cancel {
			self.identity_switch.confirm_delete = None;
			Modal::close();
		}
		if confirm {
			// Step 2: the wallet-password modal executes the delete.
			self.identity_switch.pass.clear();
			self.identity_switch.wrong_pass = false;
			self.identity_switch.pending = Some(PendingPassAction::Delete(target));
			Modal::close();
			Modal::new(IDENTITY_PASS_MODAL)
				.position(ModalPosition::CenterTop)
				.title(t!("goblin.identities.delete_short"))
				.show();
		}
	}
}
