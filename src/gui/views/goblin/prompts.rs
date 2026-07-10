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

//! Session / authorization hold-to-confirm approval modals.

use super::*;

impl GoblinWalletView {
	/// Content of the "Sign in with Goblin" approval modal: the requesting
	/// domain up top, the signing identity (a picker when several are held;
	/// the truncated npub is always visible as the anchor), a one-line plain
	/// explanation, the wallet password, and uniform paired Cancel / Sign in
	/// buttons. Approving signs the one-time kind-22242 challenge with the
	/// CHOSEN identity's key and POSTs it to the callback off the UI thread;
	/// a wrong password stays in the modal without consuming the request.
	pub(super) fn login_modal_content(
		&mut self,
		ui: &mut egui::Ui,
		modal: &Modal,
		wallet: &Wallet,
		cb: &dyn PlatformCallbacks,
	) {
		let Some(st) = self.login.as_mut() else {
			Modal::close();
			return;
		};
		if st.posting {
			// Already signed and in flight; nothing left to gate here.
			Modal::close();
			return;
		}
		let domain = st.uri.domain.clone();
		let identities = wallet.nostr_identities();
		let mut go = false;
		let mut cancel = false;
		ui.vertical_centered(|ui| {
			ui.add_space(6.0);
			// Headline with the requesting domain prominent.
			ui.label(
				RichText::new(t!("goblin.login.headline", domain => domain.clone()))
					.size(17.0)
					.color(Colors::title(false)),
			);
			ui.add_space(10.0);
			// The signing identity. Display precedence is the switcher's:
			// private tag, else bare claimed name, else truncated npub — and
			// the truncated npub is ALWAYS shown as the anchor.
			ui.label(
				RichText::new(t!("goblin.login.identity"))
					.size(13.0)
					.color(Colors::gray()),
			);
			ui.add_space(6.0);
			if identities.len() > 1 {
				// Identity picker: the held-identities list, tap to choose
				// which one signs. Defaults to the active identity.
				for id in &identities {
					let selected = st.selected == id.pubkey_hex;
					let title = id.display();
					let short = data::short_npub(&id.pubkey_hex);
					let row = ui
						.scope(|ui| {
							ui.horizontal(|ui| {
								ui.add_space(4.0);
								ui.label(
									RichText::new(if selected {
										crate::gui::icons::CHECK_CIRCLE
									} else {
										crate::gui::icons::CIRCLE
									})
									.size(18.0)
									.color(if selected {
										Colors::green()
									} else {
										Colors::gray()
									}),
								);
								ui.add_space(8.0);
								ui.vertical(|ui| {
									if title != short {
										ui.label(
											RichText::new(&title)
												.size(15.0)
												.color(Colors::text(false)),
										);
									}
									ui.label(
										RichText::new(&short).size(12.5).color(Colors::gray()),
									);
								});
							});
						})
						.response
						.rect;
					let hit = ui.interact(
						row,
						egui::Id::from(modal.id).with(("login_id", id.pubkey_hex.as_str())),
						Sense::click(),
					);
					if hit
						.on_hover_cursor(egui::CursorIcon::PointingHand)
						.clicked()
					{
						st.selected = id.pubkey_hex.clone();
					}
					ui.add_space(4.0);
				}
			} else if let Some(id) = identities.first() {
				let title = id.display();
				let short = data::short_npub(&id.pubkey_hex);
				if title != short {
					ui.label(RichText::new(&title).size(15.0).color(Colors::text(false)));
				}
				ui.label(RichText::new(&short).size(12.5).color(Colors::gray()));
			}
			ui.add_space(10.0);
			// One plain line on what approving does (and does not do).
			ui.label(
				RichText::new(t!("goblin.login.explain"))
					.size(13.0)
					.color(Colors::gray()),
			);
			ui.add_space(10.0);
			// The wallet password gates the signature, mirroring the identity
			// password modal (masked field, same wrong-password line).
			ui.label(
				RichText::new(t!("goblin.login.pass_prompt"))
					.size(16.0)
					.color(Colors::gray()),
			);
			ui.add_space(10.0);
			let mut field = TextEdit::new(egui::Id::from(modal.id).with("login_pass")).password();
			field.ui(ui, &mut st.pass, cb);
			if field.enter_pressed {
				go = true;
			}
			if st.pass.is_empty() {
				st.wrong_pass = false;
			} else if st.wrong_pass {
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
					View::button(
						ui,
						t!("goblin.login.confirm"),
						Colors::white_or_black(false),
						|| {
							go = true;
						},
					);
				});
			});
			ui.add_space(6.0);
		});
		if cancel {
			// Cancel drops the request: it is single-use, no retry.
			self.login = None;
			Modal::close();
			return;
		}
		if go {
			let (pass, selected) = match self.login.as_ref() {
				Some(st) => (st.pass.clone(), st.selected.clone()),
				None => return,
			};
			if pass.is_empty() {
				return;
			}
			if !wallet.verify_nostr_password(&pass) {
				// Wrong password: stay in the modal, request NOT consumed.
				if let Some(st) = self.login.as_mut() {
					st.wrong_pass = true;
				}
				return;
			}
			// The chosen identity's unlocked in-memory keys, from the running
			// service (the Build-145 model: every held identity is unlocked).
			let keys = wallet.nostr_service().and_then(|s| {
				s.recv_snapshot()
					.into_iter()
					.find(|h| h.keys.public_key().to_hex() == selected)
					.map(|h| h.keys)
			});
			let Some(keys) = keys else {
				// No running service / identity gone: drop the request.
				self.login = None;
				Modal::close();
				return;
			};
			let st = self.login.as_mut().unwrap();
			st.pass.clear();
			st.wrong_pass = false;
			match crate::nostr::loginuri::build_login_event(
				&keys,
				&st.uri.challenge,
				&st.uri.domain,
			) {
				Ok(event) => {
					// Signed: the request is consumed from here on, whatever
					// the POST outcome. Deliver off the UI thread with the
					// shared HTTP client and a hard timeout.
					st.posting = true;
					let callback = st.uri.callback.clone();
					let slot = st.result.clone();
					std::thread::spawn(move || {
						let res = match tokio::runtime::Builder::new_current_thread()
							.enable_all()
							.build()
						{
							Ok(rt) => rt.block_on(async {
								let post =
									crate::nostr::loginuri::post_login_event(&callback, &event);
								match tokio::time::timeout(
									std::time::Duration::from_secs(LOGIN_POST_TIMEOUT_SECS),
									post,
								)
								.await
								{
									Ok(r) => r,
									Err(_) => Err("timeout".to_string()),
								}
							}),
							Err(e) => Err(e.to_string()),
						};
						*slot.lock().unwrap() = Some(res);
					});
					Modal::close();
					// The return-to-caller decision is DEFERRED to the outcome
					// poll: returning now would background the app with the POST
					// still in flight, stop the frame pump, and strand the
					// completion work (the Build 153 QR-trust bug). The app stays
					// foreground (frames pumping) until the POST result lands.
				}
				Err(e) => {
					// Signing failed (never expected): consume the request and
					// surface the quiet failure toast.
					log::error!("login event signing failed: {e}");
					self.login_toast = Some((
						t!("goblin.login.failed", domain => domain).to_string(),
						std::time::Instant::now(),
					));
					self.login = None;
					Modal::close();
				}
			}
		}
	}

	/// The "Authorize with Goblin" approval modal: headline, the rendered event
	/// (kind label, escaped content preview with an optional show-full view, and
	/// per-kind key-tag summary), the identity picker, the password gate, and the
	/// Cancel/Authorize buttons. Mirrors [`Self::login_modal_content`]; on
	/// confirm it signs one event with the chosen identity and POSTs it off the
	/// UI thread. Signed = consumed, whatever the POST outcome.
	pub(super) fn authorize_modal_content(
		&mut self,
		ui: &mut egui::Ui,
		modal: &Modal,
		wallet: &Wallet,
		cb: &dyn PlatformCallbacks,
	) {
		use crate::nostr::authuri;
		let Some(st) = self.authorize.as_mut() else {
			Modal::close();
			return;
		};
		if st.posting {
			// Already signed and in flight; nothing left to gate here.
			Modal::close();
			return;
		}
		let domain = st.uri.domain.clone();
		// Clone the small template once so the read-only render borrows nothing
		// from `st` while its password/show-full fields are mutated below.
		let template = st.uri.template.clone();
		let kind = template.kind;
		let label = authuri::kind_label(kind);
		let (preview, remaining) = authuri::content_preview(&template.content);
		let preview_esc = authuri::escape_for_display(&preview);
		let full_esc = authuri::escape_for_display(&template.content);
		// Key tags, all escaped before display.
		let e_tag = template
			.first_tag_value("e")
			.map(|v| authuri::escape_for_display(&authuri::truncate_id(v)));
		let p_tag = template
			.first_tag_value("p")
			.map(|v| authuri::escape_for_display(&authuri::truncate_id(v)));
		let title = template
			.first_tag_value("title")
			.map(authuri::escape_for_display);
		let identities = wallet.nostr_identities();
		let mut go = false;
		let mut cancel = false;
		ui.vertical_centered(|ui| {
			ui.add_space(6.0);
			// Headline with the requesting domain prominent.
			ui.label(
				RichText::new(t!("goblin.authorize.headline", domain => domain.clone()))
					.size(17.0)
					.color(Colors::title(false)),
			);
			ui.add_space(10.0);
			// The plain-language kind label (and, for an off-allowlist kind that
			// v1 cannot actually reach, a caution line).
			let kind_text = match label {
				authuri::KindLabel::Post => t!("goblin.authorize.kind_post"),
				authuri::KindLabel::Repost => t!("goblin.authorize.kind_repost"),
				authuri::KindLabel::Reaction => t!("goblin.authorize.kind_reaction"),
				authuri::KindLabel::Article => t!("goblin.authorize.kind_article"),
				authuri::KindLabel::Unknown => {
					t!("goblin.authorize.kind_unknown", n => kind.to_string())
				}
			};
			ui.label(
				RichText::new(kind_text)
					.size(15.0)
					.color(Colors::text(false)),
			);
			if label == authuri::KindLabel::Unknown {
				ui.add_space(4.0);
				ui.label(
					RichText::new(t!("goblin.authorize.unknown_caution", domain => domain.clone()))
						.size(12.5)
						.color(Colors::red()),
				);
			}
			ui.add_space(8.0);
			// Per-kind rendering of the event body and its key tags. All
			// requester-controlled text is escaped before it hits a label.
			let show_preview = |ui: &mut egui::Ui| {
				if !preview_esc.is_empty() {
					ui.label(RichText::new(&preview_esc).size(13.5).color(Colors::gray()));
				}
			};
			match kind {
				7 => {
					// Reaction: the reaction glyph (emoji or "+"), then target.
					let reaction = if full_esc.is_empty() {
						"+".to_string()
					} else {
						full_esc.clone()
					};
					ui.label(
						RichText::new(reaction)
							.size(20.0)
							.color(Colors::text(false)),
					);
					ui.add_space(4.0);
					if let Some(id) = &e_tag {
						ui.label(
							RichText::new(t!("goblin.authorize.reacts_to", id => id.clone()))
								.size(12.5)
								.color(Colors::gray()),
						);
					}
					if let Some(id) = &p_tag {
						ui.label(
							RichText::new(t!("goblin.authorize.by_author", id => id.clone()))
								.size(12.5)
								.color(Colors::gray()),
						);
					}
				}
				6 => {
					// Repost: reposted event id and author.
					if let Some(id) = &e_tag {
						ui.label(
							RichText::new(t!("goblin.authorize.repost_of", id => id.clone()))
								.size(12.5)
								.color(Colors::gray()),
						);
					}
					if let Some(id) = &p_tag {
						ui.label(
							RichText::new(t!("goblin.authorize.by_author", id => id.clone()))
								.size(12.5)
								.color(Colors::gray()),
						);
					}
				}
				30023 => {
					// Article: title tag if present, then the content preview.
					if let Some(t) = &title {
						ui.label(
							RichText::new(t!("goblin.authorize.article_title", title => t.clone()))
								.size(14.0)
								.color(Colors::text(false)),
						);
						ui.add_space(4.0);
					}
					show_preview(ui);
				}
				_ => {
					// Kind 1 (and the unreachable fallback): content preview, then
					// the reply/mention tags.
					show_preview(ui);
					if let Some(id) = &e_tag {
						ui.add_space(4.0);
						ui.label(
							RichText::new(t!("goblin.authorize.replying_to", id => id.clone()))
								.size(12.5)
								.color(Colors::gray()),
						);
					}
					if let Some(id) = &p_tag {
						ui.label(
							RichText::new(t!("goblin.authorize.mentions", id => id.clone()))
								.size(12.5)
								.color(Colors::gray()),
						);
					}
				}
			}
			// Truncation marker plus the mandatory show-full affordance. Approval
			// is never blocked on opening it.
			if remaining > 0 {
				ui.add_space(6.0);
				ui.label(
					RichText::new(t!("goblin.authorize.truncated", n => remaining.to_string()))
						.size(12.0)
						.color(Colors::gray()),
				);
				let toggle = if st.show_full {
					t!("goblin.authorize.show_less")
				} else {
					t!("goblin.authorize.show_full")
				};
				let rect = ui
					.label(RichText::new(toggle).size(13.0).color(Colors::green()))
					.rect;
				let hit = ui.interact(
					rect,
					egui::Id::from(modal.id).with("auth_showfull"),
					Sense::click(),
				);
				if hit
					.on_hover_cursor(egui::CursorIcon::PointingHand)
					.clicked()
				{
					st.show_full = !st.show_full;
				}
				if st.show_full {
					ui.add_space(6.0);
					ScrollArea::vertical()
						.max_height(160.0)
						.auto_shrink([false, true])
						.show(ui, |ui| {
							ui.label(RichText::new(&full_esc).size(13.0).color(Colors::gray()));
						});
				}
			}
			ui.add_space(10.0);
			// The signing identity. Display precedence is the switcher's: private
			// tag, else bare claimed name, else truncated npub, and the truncated
			// npub is ALWAYS shown as the anchor. Defaults to the active identity.
			ui.label(
				RichText::new(t!("goblin.authorize.identity"))
					.size(13.0)
					.color(Colors::gray()),
			);
			ui.add_space(6.0);
			if identities.len() > 1 {
				for id in &identities {
					let selected = st.selected == id.pubkey_hex;
					let name = id.display();
					let short = data::short_npub(&id.pubkey_hex);
					let row = ui
						.scope(|ui| {
							ui.horizontal(|ui| {
								ui.add_space(4.0);
								ui.label(
									RichText::new(if selected {
										crate::gui::icons::CHECK_CIRCLE
									} else {
										crate::gui::icons::CIRCLE
									})
									.size(18.0)
									.color(if selected {
										Colors::green()
									} else {
										Colors::gray()
									}),
								);
								ui.add_space(8.0);
								ui.vertical(|ui| {
									if name != short {
										ui.label(
											RichText::new(&name)
												.size(15.0)
												.color(Colors::text(false)),
										);
									}
									ui.label(
										RichText::new(&short).size(12.5).color(Colors::gray()),
									);
								});
							});
						})
						.response
						.rect;
					let hit = ui.interact(
						row,
						egui::Id::from(modal.id).with(("auth_id", id.pubkey_hex.as_str())),
						Sense::click(),
					);
					if hit
						.on_hover_cursor(egui::CursorIcon::PointingHand)
						.clicked()
					{
						st.selected = id.pubkey_hex.clone();
					}
					ui.add_space(4.0);
				}
			} else if let Some(id) = identities.first() {
				let name = id.display();
				let short = data::short_npub(&id.pubkey_hex);
				if name != short {
					ui.label(RichText::new(&name).size(15.0).color(Colors::text(false)));
				}
				ui.label(RichText::new(&short).size(12.5).color(Colors::gray()));
			}
			ui.add_space(10.0);
			// One plain line on what approving does (and does not do).
			ui.label(
				RichText::new(t!("goblin.authorize.explain", domain => domain.clone()))
					.size(13.0)
					.color(Colors::gray()),
			);
			ui.add_space(10.0);
			// The wallet password gates the signature, mirroring the identity
			// password modal (masked field, same wrong-password line).
			ui.label(
				RichText::new(t!("goblin.authorize.pass_prompt"))
					.size(16.0)
					.color(Colors::gray()),
			);
			ui.add_space(10.0);
			let mut field = TextEdit::new(egui::Id::from(modal.id).with("auth_pass")).password();
			field.ui(ui, &mut st.pass, cb);
			if field.enter_pressed {
				go = true;
			}
			if st.pass.is_empty() {
				st.wrong_pass = false;
			} else if st.wrong_pass {
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
					View::button(
						ui,
						t!("goblin.authorize.confirm"),
						Colors::white_or_black(false),
						|| {
							go = true;
						},
					);
				});
			});
			ui.add_space(6.0);
		});
		if cancel {
			// Cancel drops the request: it is single-use, no retry.
			self.authorize = None;
			Modal::close();
			return;
		}
		if go {
			let (pass, selected) = match self.authorize.as_ref() {
				Some(st) => (st.pass.clone(), st.selected.clone()),
				None => return,
			};
			if pass.is_empty() {
				return;
			}
			if !wallet.verify_nostr_password(&pass) {
				// Wrong password: stay in the modal, request NOT consumed.
				if let Some(st) = self.authorize.as_mut() {
					st.wrong_pass = true;
				}
				return;
			}
			// The chosen identity's unlocked in-memory keys, from the running
			// service (the Build-145 model: every held identity is unlocked).
			let keys = wallet.nostr_service().and_then(|s| {
				s.recv_snapshot()
					.into_iter()
					.find(|h| h.keys.public_key().to_hex() == selected)
					.map(|h| h.keys)
			});
			let Some(keys) = keys else {
				// No running service / identity gone: drop the request.
				self.authorize = None;
				Modal::close();
				return;
			};
			let st = self.authorize.as_mut().unwrap();
			st.pass.clear();
			st.wrong_pass = false;
			match crate::nostr::authuri::build_authorize_event(&keys, &st.uri.template) {
				Ok(event) => {
					// Signed: the request is consumed from here on, whatever the
					// POST outcome. Deliver off the UI thread with the shared HTTP
					// client and a hard timeout.
					st.posting = true;
					let callback = st.uri.callback.clone();
					let challenge = st.uri.challenge.clone();
					let domain = st.uri.domain.clone();
					let slot = st.result.clone();
					std::thread::spawn(move || {
						let res = match tokio::runtime::Builder::new_current_thread()
							.enable_all()
							.build()
						{
							Ok(rt) => rt.block_on(async {
								let post = crate::nostr::authuri::post_authorize_event(
									&callback, &challenge, &domain, &event,
								);
								match tokio::time::timeout(
									std::time::Duration::from_secs(LOGIN_POST_TIMEOUT_SECS),
									post,
								)
								.await
								{
									Ok(r) => r,
									Err(_) => Err("timeout".to_string()),
								}
							}),
							Err(e) => Err(e.to_string()),
						};
						*slot.lock().unwrap() = Some(res);
					});
					Modal::close();
					// Return-to-caller is DEFERRED to the outcome poll (see the
					// login flow): the app must stay foreground until the POST
					// result lands, or the completion work freezes backgrounded.
				}
				Err(e) => {
					// Signing failed (never expected): consume the request and
					// surface the quiet failure toast.
					log::error!("authorize event signing failed: {e}");
					self.login_toast = Some((
						t!("goblin.authorize.failed", domain => domain).to_string(),
						std::time::Instant::now(),
					));
					self.authorize = None;
					Modal::close();
				}
			}
		}
	}

	/// The "Trust with Goblin" (Authorize Sessions) grant modal: proves identity
	/// (folds login in) AND establishes the session in one password-gated,
	/// hold-to-confirm decision. Shows the identity, the low-tier categories being
	/// granted for silent signing, and the fixed line that money always asks.
	pub(super) fn trust_modal_content(
		&mut self,
		ui: &mut egui::Ui,
		modal: &Modal,
		wallet: &Wallet,
		cb: &dyn PlatformCallbacks,
	) {
		let Some(st) = self.trust.as_mut() else {
			Modal::close();
			return;
		};
		if st.posting {
			Modal::close();
			return;
		}
		let domain = st.uri.domain.clone();
		let identities = wallet.nostr_identities();
		let display = crate::nostr::session::render_grant(&st.uri.requested_kinds);
		let mut go = false;
		let mut cancel = false;
		ui.vertical_centered(|ui| {
			ui.add_space(6.0);
			ui.label(
				RichText::new(t!("goblin.trust.headline", domain => domain.clone()))
					.size(17.0)
					.color(Colors::title(false)),
			);
			ui.add_space(10.0);
			ui.label(
				RichText::new(t!("goblin.trust.identity"))
					.size(13.0)
					.color(Colors::gray()),
			);
			ui.add_space(6.0);
			// Identity picker (defaults to the active identity), the truncated
			// npub always shown as the anchor.
			if identities.len() > 1 {
				for id in &identities {
					let selected = st.selected == id.pubkey_hex;
					let title = id.display();
					let short = data::short_npub(&id.pubkey_hex);
					let row = ui
						.scope(|ui| {
							ui.horizontal(|ui| {
								ui.add_space(4.0);
								ui.label(
									RichText::new(if selected {
										crate::gui::icons::CHECK_CIRCLE
									} else {
										crate::gui::icons::CIRCLE
									})
									.size(18.0)
									.color(if selected {
										Colors::green()
									} else {
										Colors::gray()
									}),
								);
								ui.add_space(8.0);
								ui.vertical(|ui| {
									if title != short {
										ui.label(
											RichText::new(&title)
												.size(15.0)
												.color(Colors::text(false)),
										);
									}
									ui.label(
										RichText::new(&short).size(12.5).color(Colors::gray()),
									);
								});
							});
						})
						.response
						.rect;
					let hit = ui.interact(
						row,
						egui::Id::from(modal.id).with(("trust_id", id.pubkey_hex.as_str())),
						Sense::click(),
					);
					if hit
						.on_hover_cursor(egui::CursorIcon::PointingHand)
						.clicked()
					{
						st.selected = id.pubkey_hex.clone();
					}
					ui.add_space(4.0);
				}
			} else if let Some(id) = identities.first() {
				let title = id.display();
				let short = data::short_npub(&id.pubkey_hex);
				if title != short {
					ui.label(RichText::new(&title).size(15.0).color(Colors::text(false)));
				}
				ui.label(RichText::new(&short).size(12.5).color(Colors::gray()));
			}
			ui.add_space(12.0);
			// The gist in one short line (grant + the money rule), with the full
			// permission detail behind a small disclosure for anyone who wants it.
			ui.label(
				RichText::new(t!("goblin.trust.lead", domain => domain.clone()))
					.size(13.5)
					.color(Colors::text(false)),
			);
			// Caution lines are safety-relevant and stay visible even collapsed.
			for kind in &display.unknown_kinds {
				ui.label(
					RichText::new(format!(
						"• {}",
						t!("goblin.trust.cat_unknown", n => kind.to_string())
					))
					.size(13.5)
					.color(Colors::red()),
				);
			}
			if display.stripped_login {
				ui.label(
					RichText::new(t!("goblin.trust.login_excluded"))
						.size(12.5)
						.color(Colors::red()),
				);
			}
			ui.add_space(8.0);
			// The disclosure toggle, same idiom as the authorize full-content view.
			let toggle = if st.show_full {
				t!("goblin.authorize.show_less")
			} else {
				t!("goblin.authorize.show_full")
			};
			let rect = ui
				.label(RichText::new(toggle).size(13.0).color(Colors::green()))
				.rect;
			let hit = ui.interact(
				rect,
				egui::Id::from(modal.id).with("trust_showfull"),
				Sense::click(),
			);
			if hit
				.on_hover_cursor(egui::CursorIcon::PointingHand)
				.clicked()
			{
				st.show_full = !st.show_full;
			}
			if st.show_full {
				ui.add_space(6.0);
				// What the silent grant covers, as human categories.
				ui.label(
					RichText::new(t!("goblin.trust.grant_intro"))
						.size(13.0)
						.color(Colors::gray()),
				);
				ui.add_space(4.0);
				for cat in &display.categories {
					ui.label(
						RichText::new(format!("• {}", t!(cat.key())))
							.size(13.5)
							.color(Colors::text(false)),
					);
				}
				ui.add_space(6.0);
				// The fixed money line: the low-tier grant is not a money grant.
				ui.label(
					RichText::new(t!("goblin.trust.money_line"))
						.size(13.0)
						.color(Colors::title(false)),
				);
				ui.add_space(4.0);
				ui.label(
					RichText::new(t!("goblin.trust.duration"))
						.size(12.5)
						.color(Colors::gray()),
				);
			}
			ui.add_space(12.0);
			ui.label(
				RichText::new(t!("goblin.trust.pass_prompt"))
					.size(16.0)
					.color(Colors::gray()),
			);
			ui.add_space(10.0);
			let mut field = TextEdit::new(egui::Id::from(modal.id).with("trust_pass")).password();
			field.ui(ui, &mut st.pass, cb);
			if st.pass.is_empty() {
				st.wrong_pass = false;
			} else if st.wrong_pass {
				ui.add_space(10.0);
				ui.label(
					RichText::new(t!("goblin.advanced.wrong_password"))
						.size(16.0)
						.color(Colors::red()),
				);
			}
			ui.add_space(12.0);
		});
		// Hold-to-confirm: the single high-value decision cannot be a stray tap.
		if self.trust_hold.ui(ui, &t!("goblin.trust.confirm_hold")) {
			go = true;
		}
		ui.add_space(6.0);
		ui.scope(|ui| {
			ui.spacing_mut().item_spacing = egui::Vec2::new(8.0, 0.0);
			ui.vertical_centered_justified(|ui| {
				View::button(
					ui,
					t!("modal.cancel"),
					Colors::white_or_black(false),
					|| {
						cancel = true;
					},
				);
			});
			ui.add_space(6.0);
		});
		if cancel {
			self.trust = None;
			Modal::close();
			return;
		}
		if go {
			let (pass, selected) = match self.trust.as_ref() {
				Some(st) => (st.pass.clone(), st.selected.clone()),
				None => return,
			};
			if pass.is_empty() {
				self.trust_hold = w::HoldToSend::default();
				return;
			}
			if !wallet.verify_nostr_password(&pass) {
				if let Some(st) = self.trust.as_mut() {
					st.wrong_pass = true;
				}
				self.trust_hold = w::HoldToSend::default();
				return;
			}
			let keys = wallet.nostr_service().and_then(|s| {
				s.recv_snapshot()
					.into_iter()
					.find(|h| h.keys.public_key().to_hex() == selected)
					.map(|h| h.keys)
			});
			let Some(keys) = keys else {
				self.trust = None;
				Modal::close();
				return;
			};
			let st = self.trust.as_mut().unwrap();
			st.pass.clear();
			st.wrong_pass = false;
			// Sign and POST the kind-22242 login event exactly as Build 150 does;
			// the session is created by the router once this POST succeeds.
			match crate::nostr::loginuri::build_login_event(
				&keys,
				&st.uri.challenge,
				&st.uri.domain,
			) {
				Ok(event) => {
					st.posting = true;
					let callback = st.uri.callback.clone();
					let slot = st.result.clone();
					std::thread::spawn(move || {
						let res = match tokio::runtime::Builder::new_current_thread()
							.enable_all()
							.build()
						{
							Ok(rt) => rt.block_on(async {
								let post =
									crate::nostr::loginuri::post_login_event(&callback, &event);
								match tokio::time::timeout(
									std::time::Duration::from_secs(LOGIN_POST_TIMEOUT_SECS),
									post,
								)
								.await
								{
									Ok(r) => r,
									Err(_) => Err("timeout".to_string()),
								}
							}),
							Err(e) => Err(e.to_string()),
						};
						*slot.lock().unwrap() = Some(res);
					});
					Modal::close();
					// Return-to-caller is DEFERRED even further than login: past
					// the POST outcome AND past the session-open announce
					// confirmation (the trust_wait poll). Returning here was the
					// Build 153 QR-trust bug: the app backgrounded with the POST
					// in flight and the session-open never published.
				}
				Err(e) => {
					log::error!("trust login event signing failed: {e}");
					self.login_toast = Some((
						t!("goblin.trust.failed", domain => domain).to_string(),
						std::time::Instant::now(),
					));
					self.trust = None;
					Modal::close();
				}
			}
		}
	}

	/// The money-tier per-action approval modal: a value-moving sign (or a
	/// pay-committing encrypt) arriving over a live session channel. Identical
	/// gravity to a v1 authorize — what is being done, which identity, a masked
	/// password, hold-to-confirm — raised every time, never silent.
	pub(super) fn money_modal_content(
		&mut self,
		ui: &mut egui::Ui,
		modal: &Modal,
		wallet: &Wallet,
		cb: &dyn PlatformCallbacks,
	) {
		use crate::nostr::session::ChannelOp;
		let Some(st) = self.money.as_mut() else {
			Modal::close();
			return;
		};
		let domain = st.pending.domain.clone();
		let req_id = st.pending.id().to_string();
		let short_id = data::short_npub(&st.pending.identity_pubkey.to_hex());
		// A one-line description of exactly what is being committed to.
		let what = match &st.pending.op {
			ChannelOp::Sign(req) => {
				let label = crate::nostr::authuri::kind_label(req.event.kind);
				let (preview, _) = crate::nostr::authuri::content_preview(&req.event.content);
				let preview = crate::nostr::authuri::escape_for_display(&preview);
				if preview.trim().is_empty() {
					t!(label.key(), n => req.event.kind.to_string()).to_string()
				} else {
					format!(
						"{}: {}",
						t!(label.key(), n => req.event.kind.to_string()),
						preview
					)
				}
			}
			ChannelOp::Encrypt(e) => {
				// Order DMs are where payment agreements live: show the inspected
				// plaintext (escaped + truncated exactly like the sign path), so
				// the user sees WHAT they are agreeing to pay, not a blind label.
				let (preview, _) = crate::nostr::authuri::content_preview(&e.plaintext);
				let preview = crate::nostr::authuri::escape_for_display(&preview);
				if preview.trim().is_empty() {
					t!("goblin.money.encrypt_desc").to_string()
				} else {
					format!("{}: {}", t!("goblin.money.encrypt_desc"), preview)
				}
			}
		};
		let mut approve = false;
		let mut decline = false;
		ui.vertical_centered(|ui| {
			ui.add_space(6.0);
			ui.label(
				RichText::new(t!("goblin.money.headline", domain => domain.clone()))
					.size(17.0)
					.color(Colors::title(false)),
			);
			ui.add_space(8.0);
			ui.label(RichText::new(&what).size(14.0).color(Colors::text(false)));
			ui.add_space(8.0);
			ui.label(
				RichText::new(t!("goblin.money.identity", id => short_id.clone()))
					.size(12.5)
					.color(Colors::gray()),
			);
			ui.add_space(8.0);
			ui.label(
				RichText::new(t!("goblin.money.explain"))
					.size(13.0)
					.color(Colors::gray()),
			);
			ui.add_space(10.0);
			ui.label(
				RichText::new(t!("goblin.money.pass_prompt"))
					.size(16.0)
					.color(Colors::gray()),
			);
			ui.add_space(10.0);
			let mut field = TextEdit::new(egui::Id::from(modal.id).with("money_pass")).password();
			field.ui(ui, &mut st.pass, cb);
			if st.pass.is_empty() {
				st.wrong_pass = false;
			} else if st.wrong_pass {
				ui.add_space(10.0);
				ui.label(
					RichText::new(t!("goblin.advanced.wrong_password"))
						.size(16.0)
						.color(Colors::red()),
				);
			}
			ui.add_space(12.0);
		});
		if self.money_hold.ui(ui, &t!("goblin.money.confirm_hold")) {
			approve = true;
		}
		ui.add_space(6.0);
		ui.vertical_centered_justified(|ui| {
			View::button(
				ui,
				t!("modal.cancel"),
				Colors::white_or_black(false),
				|| {
					decline = true;
				},
			);
		});
		ui.add_space(6.0);
		if decline {
			if let Some(svc) = wallet.nostr_service() {
				svc.answer_money_prompt(&req_id, false);
			}
			self.money = None;
			Modal::close();
			return;
		}
		if approve {
			let pass = self
				.money
				.as_ref()
				.map(|s| s.pass.clone())
				.unwrap_or_default();
			if pass.is_empty() || !wallet.verify_nostr_password(&pass) {
				if let Some(st) = self.money.as_mut() {
					st.wrong_pass = true;
				}
				self.money_hold = w::HoldToSend::default();
				return;
			}
			if let Some(svc) = wallet.nostr_service() {
				svc.answer_money_prompt(&req_id, true);
			}
			self.money = None;
			Modal::close();
		}
	}
}
