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

//! Username / name-authority settings and the claim flow.

use super::*;

/// Map an availability probe to user-facing state: `None` availability
/// means the check itself failed — never present that as "Taken".
pub(super) fn availability_feedback(
	avail: crate::nostr::nip05::Availability,
) -> (Option<bool>, String) {
	use crate::nostr::nip05::Availability::*;
	match avail {
		Available => (
			Some(true),
			t!("goblin.settings.avail_available").to_string(),
		),
		Taken => (Some(false), t!("goblin.settings.avail_taken").to_string()),
		Reserved => (
			Some(false),
			t!("goblin.settings.avail_reserved").to_string(),
		),
		Invalid => (Some(false), t!("goblin.settings.avail_invalid").to_string()),
		Quarantined => (
			Some(false),
			t!("goblin.settings.avail_quarantined").to_string(),
		),
		Unknown => (None, t!("goblin.settings.avail_unknown").to_string()),
	}
}

/// Spawn the combined claim: availability check first, then registration
/// in the same worker — one button, no separate Check step.
pub(super) fn start_claim_flow(claim: &mut ClaimState, name: &str, wallet: &Wallet) {
	let Some(service) = wallet.nostr_service() else {
		return;
	};
	let server = service.config.read().nip05_server();
	// Reuse the service's keys directly — never round-trip the secret through a
	// plaintext nsec String to rebuild keys the service already holds.
	let keys = service.keys();
	claim.checking = true;
	claim.message = None;
	claim.available = None;
	let slot = claim.result.clone();
	let name = name.to_string();
	std::thread::spawn(move || {
		let rt = match tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
		{
			Ok(rt) => rt,
			Err(_) => return,
		};
		let msg = rt.block_on(async {
			use crate::nostr::nip05::{Availability, RegisterResult, check_availability, register};
			match check_availability(&server, &name).await {
				Availability::Available => match register(&server, &name, &keys).await {
					RegisterResult::Ok(nip05) => ClaimMsg::Registered(nip05),
					RegisterResult::Conflict(_) => {
						ClaimMsg::Error(t!("goblin.settings.err_just_taken").to_string())
					}
					RegisterResult::Rejected(e) if e == "name_change_cooldown" => {
						ClaimMsg::Error(t!("goblin.settings.err_cooldown").to_string())
					}
					RegisterResult::Rejected(e) => ClaimMsg::Error(e),
					RegisterResult::Network => {
						ClaimMsg::Error(t!("goblin.settings.err_unreachable").to_string())
					}
				},
				other => ClaimMsg::Availability(other),
			}
		});
		*slot.lock().unwrap() = Some(msg);
	});
}

/// Spawn the username release; the server deletes its avatar with it.
pub(super) fn start_release(claim: &mut ClaimState, name: &str, wallet: &Wallet) {
	let Some(service) = wallet.nostr_service() else {
		return;
	};
	let server = service.config.read().nip05_server();
	// Reuse the service's keys directly — never round-trip the secret through a
	// plaintext nsec String to rebuild keys the service already holds.
	let keys = service.keys();
	claim.checking = true;
	claim.message = None;
	let slot = claim.result.clone();
	let name = name.to_string();
	std::thread::spawn(move || {
		let rt = match tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
		{
			Ok(rt) => rt,
			Err(_) => return,
		};
		// Release is always allowed server-side (it's what arms the cooldown),
		// so there's no cooldown rejection to handle here.
		let msg = match rt.block_on(crate::nostr::nip05::unregister(&server, &name, &keys)) {
			Ok(()) => ClaimMsg::Released,
			Err(e) => ClaimMsg::Error(t!("goblin.settings.err_release", err => e).to_string()),
		};
		*slot.lock().unwrap() = Some(msg);
	});
}

impl GoblinWalletView {
	/// Username page — the single home for everything name-related: claim one if
	/// you have none, release the one you own, and choose the name authority from
	/// a known list or by free-typing a custom server. Reuses [`claim_ui`] for the
	/// claim/release card; the authority controls live only here.
	pub(super) fn username_ui(
		&mut self,
		ui: &mut egui::Ui,
		wallet: &Wallet,
		cb: &dyn PlatformCallbacks,
	) {
		let t = theme::tokens();
		if self.sub_header(ui, &t!("goblin.username.title")) {
			self.settings_page = SettingsPage::Main;
			return;
		}
		if self.claim.is_none() {
			self.claim = Some(ClaimState::default());
		}
		if self.name_authority.is_none() {
			let cur = wallet
				.nostr_service()
				.map(|s| s.config.read().nip05_server())
				.unwrap_or_default();
			self.name_authority = Some(NameAuthorityState {
				input: cur,
				error: None,
			});
		}
		ScrollArea::vertical()
			.id_salt("goblin_username_scroll")
			.auto_shrink([false; 2])
			.scroll_bar_visibility(egui::scroll_area::ScrollBarVisibility::AlwaysHidden)
			.show(ui, |ui| {
				// Name authority first: pick where your name lives, then claim
				// it on that authority below.
				w::kicker(ui, &t!("goblin.username.authority"));
				ui.add_space(8.0);
				ui.label(
					RichText::new(t!("goblin.username.authority_blurb"))
						.font(FontId::new(13.0, fonts::regular()))
						.color(t.text_dim),
				);
				ui.add_space(6.0);
				// "Learn more" opens the name-authority docs chapter in the
				// browser (same open_url idiom used elsewhere in Settings).
				let learn = ui
					.add(
						egui::Label::new(
							RichText::new(t!("goblin.username.learn_more"))
								.font(FontId::new(13.0, fonts::semibold()))
								.color(t.accent),
						)
						.sense(Sense::click()),
					)
					.on_hover_cursor(egui::CursorIcon::PointingHand);
				if learn.clicked() {
					open_url(ui, "https://docs.goblin.st/features/name-authority.html");
				}
				ui.add_space(10.0);
				let cur_server = wallet
					.nostr_service()
					.map(|s| s.config.read().nip05_server())
					.unwrap_or_default();
				let norm = |u: &str| u.trim().trim_end_matches('/').to_lowercase();
				// Known authorities: a tap sets the server. Free-type handles the rest.
				let mut chosen: Option<String> = None;
				w::card(ui, |ui| {
					for (label, url) in KNOWN_AUTHORITIES {
						let active = norm(&cur_server) == norm(url);
						let row = ui.horizontal(|ui| {
							ui.vertical(|ui| {
								ui.label(
									RichText::new(*label)
										.font(FontId::new(15.0, fonts::medium()))
										.color(t.surface_text),
								);
								ui.label(
									RichText::new(url.replace("https://", ""))
										.font(FontId::new(12.5, fonts::regular()))
										.color(t.surface_text_dim),
								);
							});
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
							chosen = Some((*url).to_string());
						}
					}
				});
				if let Some(url) = chosen {
					if let Some(s) = wallet.nostr_service() {
						s.config.write().set_nip05_server(Some(url));
						crate::nostr::nip05::set_home_domain(&s.config.read().home_domain());
					}
					if let Some(na) = self.name_authority.as_mut() {
						na.input = wallet
							.nostr_service()
							.map(|s| s.config.read().nip05_server())
							.unwrap_or_default();
						na.error = None;
					}
				}

				ui.add_space(14.0);
				// Free-typed custom authority + Reset/Save.
				let (save, reset, input) = {
					let na = self.name_authority.as_mut().unwrap();
					ui.label(
						RichText::new(t!("goblin.username.custom"))
							.font(FontId::new(13.0, fonts::medium()))
							.color(t.text_dim),
					);
					ui.add_space(6.0);
					w::field_well(ui, |ui| {
						TextEdit::new(egui::Id::from("username_authority_input"))
							.focus(false)
							.hint_text("https://goblin.st")
							.text_color(t.surface_text)
							.body()
							.ui(ui, &mut na.input, cb);
					});
					if let Some(err) = &na.error {
						ui.add_space(6.0);
						ui.label(
							RichText::new(err)
								.font(FontId::new(12.5, fonts::regular()))
								.color(t.neg),
						);
					}
					ui.add_space(10.0);
					let mut save = false;
					let mut reset = false;
					ui.horizontal(|ui| {
						let half = (ui.available_width() - 10.0) / 2.0;
						ui.scope_builder(
							egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
								ui.cursor().min,
								Vec2::new(half, 44.0),
							)),
							|ui| {
								if w::big_action_on_card(ui, &t!("goblin.settings.reset")).clicked()
								{
									reset = true;
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
								if w::big_action(ui, &t!("goblin.settings.save"), false).clicked() {
									save = true;
								}
							},
						);
					});
					(save, reset, na.input.trim().to_string())
				};
				if reset {
					if let Some(s) = wallet.nostr_service() {
						s.config.write().set_nip05_server(None);
						crate::nostr::nip05::set_home_domain(&s.config.read().home_domain());
					}
					if let Some(na) = self.name_authority.as_mut() {
						na.input = wallet
							.nostr_service()
							.map(|s| s.config.read().nip05_server())
							.unwrap_or_default();
						na.error = None;
					}
				}
				if save {
					if !input.starts_with("https://") && !input.starts_with("http://") {
						if let Some(na) = self.name_authority.as_mut() {
							na.error =
								Some(t!("goblin.settings.name_authority_invalid").to_string());
						}
					} else if let Some(s) = wallet.nostr_service() {
						s.config.write().set_nip05_server(Some(input));
						crate::nostr::nip05::set_home_domain(&s.config.read().home_domain());
						if let Some(na) = self.name_authority.as_mut() {
							na.error = None;
						}
					}
				}

				ui.add_space(18.0);
				// Claim / release + the owned-name display.
				self.claim_ui(ui, wallet, cb);
				ui.add_space(16.0);
			});
	}

	/// Inline username-claim widget (availability check + registration).
	pub(super) fn claim_ui(
		&mut self,
		ui: &mut egui::Ui,
		wallet: &Wallet,
		cb: &dyn PlatformCallbacks,
	) {
		let t = theme::tokens();
		// Poll the worker result; avatar invalidation happens after the
		// claim borrow is released.
		let mut invalidate_avatar: Option<String> = None;
		{
			let claim = self.claim.as_mut().unwrap();
			if let Some(msg) = claim.result.lock().unwrap().take() {
				claim.checking = false;
				match msg {
					ClaimMsg::Availability(avail) => {
						let (available, msg) = availability_feedback(avail);
						claim.available = available;
						claim.message = Some(msg.to_string());
					}
					ClaimMsg::Registered(nip05) => {
						let name = nip05.split('@').next().unwrap_or("").to_string();
						claim.message =
							Some(t!("goblin.settings.registered", name => name).to_string());
						claim.available = Some(true);
						claim.input.clear();
						// Persist nip05 on the identity and republish.
						if let Some(s) = wallet.nostr_service() {
							{
								let mut id = s.identity.write();
								id.nip05 = Some(nip05.clone());
								id.anonymous = false;
							}
							s.save_identity();
						}
						// Publish kind 0 NOW so others can resolve our @name without
						// waiting for the next app start — otherwise a just-claimed
						// name is invisible over the relays (no kind-0 event exists).
						wallet.task(crate::wallet::types::WalletTask::NostrRepublishProfile);
					}
					ClaimMsg::Released => {
						claim.message = Some(t!("goblin.settings.released_msg").to_string());
						claim.available = None;
						claim.confirm_release = false;
						if let Some(s) = wallet.nostr_service() {
							let name = {
								let mut id = s.identity.write();
								let n = id.nip05.take();
								id.anonymous = true;
								n
							};
							s.save_identity();
							invalidate_avatar =
								name.map(|n| n.split('@').next().unwrap_or("").to_string());
						}
					}
					ClaimMsg::Error(e) => {
						claim.available = Some(false);
						claim.message = Some(e);
					}
				}
			}
		}
		if let Some(name) = invalidate_avatar {
			self.avatars.invalidate(&name);
		}
		let claim = self.claim.as_mut().unwrap();

		let registered: Option<String> = wallet
			.nostr_service()
			.and_then(|s| s.identity.read().nip05.clone())
			.map(|n| n.split('@').next().unwrap_or("").to_string());

		w::card(ui, |ui| {
			ui.set_min_width(ui.available_width());
			if let Some(name) = registered {
				if claim.confirm_release {
					// The are-you-sure gate.
					ui.label(
						RichText::new(t!("goblin.settings.release_confirm", name => name))
							.font(FontId::new(15.0, fonts::semibold()))
							.color(t.surface_text),
					);
					ui.add_space(4.0);
					ui.label(
						RichText::new(t!("goblin.settings.release_blurb"))
							.font(FontId::new(12.5, fonts::regular()))
							.color(t.surface_text_dim),
					);
					ui.add_space(10.0);
					if claim.checking {
						ui.horizontal(|ui| {
							View::small_loading_spinner(ui);
							ui.add_space(8.0);
							ui.label(
								RichText::new(t!("goblin.settings.releasing"))
									.color(t.surface_text_dim),
							);
						});
						ui.ctx().request_repaint();
					} else {
						ui.horizontal(|ui| {
							let half = (ui.available_width() - 10.0) / 2.0;
							ui.scope_builder(
								egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
									ui.cursor().min,
									Vec2::new(half, 44.0),
								)),
								|ui| {
									if w::big_action_on_card_ink(
										ui,
										&t!("goblin.settings.keep_it"),
										t.surface_text,
									)
									.clicked()
									{
										claim.confirm_release = false;
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
									if w::big_action_on_card_ink(
										ui,
										&t!("goblin.settings.release_it"),
										t.neg,
									)
									.clicked()
									{
										start_release(claim, &name, wallet);
									}
								},
							);
						});
					}
				} else {
					ui.label(
						RichText::new(t!("goblin.settings.username"))
							.font(FontId::new(15.0, fonts::semibold()))
							.color(t.surface_text),
					);
					ui.add_space(4.0);
					ui.label(
						RichText::new(name.to_string())
							.font(FontId::new(20.0, fonts::bold()))
							.color(t.surface_text),
					);
					ui.add_space(4.0);
					ui.label(
						RichText::new(t!("goblin.settings.username_note"))
							.font(FontId::new(12.0, fonts::regular()))
							.color(t.surface_text_mute),
					);
					if let Some(msg) = &claim.message {
						ui.add_space(6.0);
						ui.label(
							RichText::new(msg)
								.font(FontId::new(13.0, fonts::regular()))
								.color(match claim.available {
									Some(false) => t.neg,
									Some(true) => t.pos,
									None => t.surface_text_dim,
								}),
						);
					}
					ui.add_space(10.0);
					if w::big_action_on_card_ink(ui, &t!("goblin.settings.release_username"), t.neg)
						.clicked()
					{
						claim.confirm_release = true;
						claim.message = None;
					}
				}
			} else {
				ui.label(
					RichText::new(t!("goblin.settings.pick_username"))
						.font(FontId::new(15.0, fonts::semibold()))
						.color(t.surface_text),
				);
				ui.add_space(8.0);
				// Placeholder shows the bare handle ("yourname") — we never display
				// the "@" to users. A leading "@" the user happens to type is still
				// stripped when the name is read below.
				let before = claim.input.clone();
				TextEdit::new(egui::Id::from("settings_claim"))
					.focus(false)
					.hint_text(t!("goblin.onboarding.identity.username_field_hint"))
					.text_color(t.surface_text)
					.body()
					.ui(ui, &mut claim.input, cb);
				if claim.input != before {
					claim.available = None;
					claim.message = None;
				}
				ui.add_space(4.0);
				ui.label(
					RichText::new(t!("goblin.settings.username_note"))
						.font(FontId::new(12.0, fonts::regular()))
						.color(t.surface_text_mute),
				);
				if let Some(msg) = &claim.message {
					ui.add_space(6.0);
					ui.label(
						RichText::new(msg)
							.font(FontId::new(13.0, fonts::regular()))
							.color(match claim.available {
								Some(false) => t.neg,
								Some(true) => t.pos,
								None => t.surface_text_dim,
							}),
					);
				}
				ui.add_space(10.0);
				let name = claim.input.trim().trim_start_matches('@').to_lowercase();
				let valid = name.len() >= 3 && name.len() <= 20;
				if claim.checking {
					ui.horizontal(|ui| {
						View::small_loading_spinner(ui);
						ui.add_space(8.0);
						ui.label(
							RichText::new(t!("goblin.settings.working")).color(t.surface_text_dim),
						);
					});
					ui.ctx().request_repaint();
				} else {
					ui.add_enabled_ui(valid, |ui| {
						if w::big_action(ui, &t!("goblin.settings.claim"), false).clicked() {
							start_claim_flow(claim, &name, wallet);
						}
					});
				}
			}
		});
	}
}
