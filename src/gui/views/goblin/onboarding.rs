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

//! First-run onboarding: what Goblin is → node choice → wallet create or
//! restore → optional payment-identity username. Wraps GRIM's mnemonic and
//! wallet-creation machinery without replacing it — the stock creation flow
//! stays available from the wallet list for later wallets.

use eframe::epaint::FontId;
use egui::{Align, Layout, RichText, ScrollArea, Sense, Vec2};
use grin_util::ZeroingString;

use crate::gui::icons::{ARROW_LEFT, CHECK};
use crate::gui::platform::PlatformCallbacks;
use crate::gui::theme::{self, fonts};
use crate::gui::views::types::{ContentContainer, ModalPosition, QrScanResult};
use crate::gui::views::wallets::creation::MnemonicSetup;
use crate::gui::views::{CameraScanContent, Content, Modal, TextEdit, View};
use crate::node::Node;
use crate::nostr::NostrIdentity;
use crate::wallet::types::{ConnectionMethod, PhraseMode, PhraseSize};
use crate::wallet::{ConnectionsConfig, ExternalConnection, Wallet, WalletList};

use super::widgets::{self as w};
use super::{ClaimMsg, ClaimState, start_claim_flow};

/// Identifier for the recovery-phrase QR scan [`Modal`].
const OB_PHRASE_SCAN_MODAL: &'static str = "ob_phrase_scan_modal";

/// Onboarding step.
#[derive(PartialEq, Eq, Clone, Copy)]
#[allow(dead_code)] // Node step retired from the flow; node mgmt lives in Settings/Advanced
enum Step {
	Intro,
	Node,
	WalletSetup,
	Words,
	ConfirmWords,
	Identity,
}

/// First-run onboarding content.
pub struct OnboardingContent {
	step: Step,
	/// Node choice: integrated (own node) or external URL.
	integrated: bool,
	ext_url: String,
	/// Wallet setup inputs.
	restore: bool,
	name: String,
	pass: String,
	pass2: String,
	/// GRIM's mnemonic machinery (word grid, validation, import).
	mnemonic_setup: MnemonicSetup,
	/// Wallet creation error, if any.
	error: Option<String>,
	/// QR scanner for recovery phrase import.
	scan_modal: Option<CameraScanContent>,
	/// Created and opened wallet, present from the Identity step on.
	wallet: Option<Wallet>,
	/// Optional username claim state (same machinery as Settings).
	claim: ClaimState,
	/// Optional "import an existing identity" sub-flow, opened from the identity
	/// step so a returning user can keep their old npub + username instead of the
	/// freshly-generated random key.
	import: Option<OnbImport>,
	/// Moment the recovery phrase was copied, for the transient "Copied" check.
	words_copied: Option<std::time::Instant>,
}

/// Onboarding identity-import state. Reuses the wallet password the user just
/// set, so it only needs the backup file / nsec (and the backup's own password
/// when restoring a sealed `.backup`).
#[derive(Default)]
struct OnbImport {
	/// 0 = form, 1 = working, 2 = error.
	stage: u8,
	/// Pasted nsec or the read-in contents of a `.backup` / identity JSON file.
	nsec: String,
	/// Password the backup was sealed under (blank for a bare nsec, or when it
	/// matches this wallet's password).
	backup_password: String,
	/// Last import error, shown on stage 2.
	error: String,
	/// A native file pick is in flight (Android resolves the path asynchronously).
	picking: bool,
	/// Worker result: Ok(new npub) or Err(message).
	result: std::sync::Arc<std::sync::Mutex<Option<Result<String, String>>>>,
}

impl Default for OnboardingContent {
	fn default() -> Self {
		Self {
			step: Step::Intro,
			// Default to the Instant path (connect to a public node) so a new
			// user is online immediately, with no chain-sync wait.
			integrated: false,
			ext_url: "https://grincoin.org".to_string(),
			restore: false,
			name: "Main wallet".to_string(),
			pass: String::new(),
			pass2: String::new(),
			mnemonic_setup: MnemonicSetup::default(),
			error: None,
			scan_modal: None,
			wallet: None,
			claim: ClaimState::default(),
			import: None,
			words_copied: None,
		}
	}
}

impl OnboardingContent {
	/// Render onboarding. Returns the wallet once the user finishes the
	/// final step, so the host can select it and drop this content.
	pub fn ui(
		&mut self,
		ui: &mut egui::Ui,
		wallets: &mut WalletList,
		cb: &dyn PlatformCallbacks,
	) -> Option<Wallet> {
		// Draw owned modals (word input, phrase scan) when opened.
		if let Some(id) = Modal::opened() {
			if id == OB_PHRASE_SCAN_MODAL {
				Modal::ui(ui.ctx(), cb, |ui, modal, cb| {
					self.scan_modal_ui(ui, modal, cb);
				});
			} else if self.mnemonic_setup.modal_ids().contains(&id) {
				Modal::ui(ui.ctx(), cb, |ui, modal, cb| {
					self.mnemonic_setup.modal_ui(ui, modal, cb);
				});
			}
		}

		let mut done = None;
		ScrollArea::vertical()
			.id_salt("goblin_onboarding")
			.auto_shrink([false; 2])
			.show(ui, |ui| {
				w::centered_column(ui, Content::SIDE_PANEL_WIDTH * 1.2, |ui| {
					ui.add_space(View::get_top_inset() + 24.0);
					match self.step {
						Step::Intro => self.intro_ui(ui),
						Step::Node => self.node_ui(ui, cb),
						Step::WalletSetup => self.wallet_setup_ui(ui, cb),
						Step::Words => self.words_ui(ui, wallets, cb),
						Step::ConfirmWords => self.confirm_ui(ui, wallets, cb),
						Step::Identity => done = self.identity_ui(ui, cb),
					}
					ui.add_space(View::get_bottom_inset() + 24.0);
				});
			});
		done
	}

	/// Back chip + step kicker shared by all steps after the intro.
	fn step_header(&mut self, ui: &mut egui::Ui, kicker: &str, title: &str, back: Step) {
		let t = theme::tokens();
		ui.horizontal(|ui| {
			let (rect, resp) = ui.allocate_exact_size(Vec2::splat(36.0), Sense::click());
			ui.painter().circle_filled(rect.center(), 18.0, t.surface2);
			ui.painter().text(
				rect.center(),
				egui::Align2::CENTER_CENTER,
				ARROW_LEFT,
				FontId::new(16.0, fonts::regular()),
				t.surface_text,
			);
			if resp
				.on_hover_cursor(egui::CursorIcon::PointingHand)
				.clicked()
			{
				self.error = None;
				self.step = back;
			}
			ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
				ui.label(
					RichText::new(kicker)
						.font(fonts::kicker())
						.color(t.text_mute),
				);
			});
		});
		ui.add_space(18.0);
		ui.label(
			RichText::new(title)
				.font(FontId::new(26.0, fonts::bold()))
				.color(t.text),
		);
		ui.add_space(14.0);
	}

	// ── Intro ────────────────────────────────────────────────────────────

	fn intro_ui(&mut self, ui: &mut egui::Ui) {
		let t = theme::tokens();
		ui.add_space(26.0);
		ui.vertical_centered(|ui| {
			super::widgets_logo_sized(ui, 72.0);
			ui.add_space(14.0);
			ui.label(
				RichText::new("goblin")
					.font(FontId::new(34.0, fonts::bold()))
					.color(t.text),
			);
		});
		ui.add_space(26.0);
		let lines: [(String, String); 3] = [
			(
				t!("goblin.onboarding.intro.private_money_head").to_string(),
				t!("goblin.onboarding.intro.private_money_body").to_string(),
			),
			(
				t!("goblin.onboarding.intro.send_like_message_head").to_string(),
				t!("goblin.onboarding.intro.send_like_message_body").to_string(),
			),
			(
				t!("goblin.onboarding.intro.yours_alone_head").to_string(),
				t!("goblin.onboarding.intro.yours_alone_body").to_string(),
			),
		];
		for (head, body) in lines {
			w::card(ui, |ui| {
				ui.set_min_width(ui.available_width());
				ui.label(
					RichText::new(head)
						.font(FontId::new(15.0, fonts::semibold()))
						.color(t.surface_text),
				);
				ui.add_space(4.0);
				ui.label(
					RichText::new(body)
						.font(FontId::new(13.5, fonts::regular()))
						.color(t.surface_text_dim),
				);
			});
			ui.add_space(10.0);
		}
		ui.add_space(16.0);
		if w::big_action(ui, &t!("goblin.onboarding.intro.get_started"), false).clicked() {
			self.step = Step::WalletSetup;
		}
		ui.add_space(8.0);
		ui.vertical_centered(|ui| {
			ui.label(
				RichText::new(t!("goblin.onboarding.intro.footnote"))
					.font(FontId::new(12.5, fonts::regular()))
					.color(t.text_mute),
			);
		});
	}

	// ── Node choice ──────────────────────────────────────────────────────

	fn node_card(ui: &mut egui::Ui, selected: bool, title: &str, word: &str, body: &str) -> bool {
		let t = theme::tokens();
		let resp = ui
			.scope(|ui| {
				w::card(ui, |ui| {
					ui.set_min_width(ui.available_width());
					ui.horizontal(|ui| {
						let (dot, _) = ui.allocate_exact_size(Vec2::splat(18.0), Sense::hover());
						ui.painter().circle_stroke(
							dot.center(),
							8.0,
							eframe::epaint::Stroke::new(1.5, t.surface_text_mute),
						);
						if selected {
							ui.painter().circle_filled(dot.center(), 5.0, t.accent);
						}
						ui.add_space(8.0);
						ui.label(
							RichText::new(title)
								.font(FontId::new(15.0, fonts::semibold()))
								.color(t.surface_text),
						);
						ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
							let galley = ui.painter().layout_no_wrap(
								word.to_string(),
								FontId::new(12.0, fonts::semibold()),
								t.bg,
							);
							let pad = Vec2::new(10.0, 5.0);
							let (rect, _) =
								ui.allocate_exact_size(galley.size() + pad * 2.0, Sense::hover());
							ui.painter().rect_filled(
								rect,
								eframe::epaint::CornerRadius::same(10),
								t.accent,
							);
							ui.painter().galley(rect.min + pad, galley, t.bg);
						});
					});
					ui.add_space(6.0);
					ui.label(
						RichText::new(body)
							.font(FontId::new(13.0, fonts::regular()))
							.color(t.surface_text_dim),
					);
				});
			})
			.response;
		resp.interact(Sense::click())
			.on_hover_cursor(egui::CursorIcon::PointingHand)
			.clicked()
	}

	fn node_ui(&mut self, ui: &mut egui::Ui, cb: &dyn PlatformCallbacks) {
		let t = theme::tokens();
		self.step_header(
			ui,
			&t!("goblin.onboarding.node.kicker"),
			&t!("goblin.onboarding.node.title"),
			Step::Intro,
		);
		// Instant (connect to a public node) leads — most people want to be
		// online immediately, with no chain-sync wait.
		if Self::node_card(
			ui,
			!self.integrated,
			&t!("goblin.onboarding.node.connect_title"),
			&t!("goblin.onboarding.node.connect_badge"),
			&t!("goblin.onboarding.node.connect_body"),
		) {
			self.integrated = false;
		}
		if !self.integrated {
			ui.add_space(10.0);
			w::field_well(ui, |ui| {
				TextEdit::new(egui::Id::from("onb_ext_url"))
					.focus(false)
					.hint_text("https://node.example.com")
					.text_color(t.surface_text)
					.body()
					.ui(ui, &mut self.ext_url, cb);
			});
		}
		ui.add_space(10.0);
		if Self::node_card(
			ui,
			self.integrated,
			&t!("goblin.onboarding.node.own_title"),
			&t!("goblin.onboarding.node.own_badge"),
			&t!("goblin.onboarding.node.own_body"),
		) {
			self.integrated = true;
		}
		ui.add_space(8.0);
		ui.label(
			RichText::new(t!("goblin.onboarding.node.changeable"))
				.font(FontId::new(12.5, fonts::regular()))
				.color(t.text_mute),
		);
		ui.add_space(16.0);
		let url_ok = self.integrated
			|| self.ext_url.trim().starts_with("http://")
			|| self.ext_url.trim().starts_with("https://");
		if w::big_action(ui, &t!("goblin.onboarding.node.continue"), false).clicked() && url_ok {
			self.step = Step::WalletSetup;
		}
		if !url_ok {
			ui.add_space(8.0);
			ui.label(
				RichText::new(t!("goblin.onboarding.node.url_invalid"))
					.font(FontId::new(13.0, fonts::regular()))
					.color(t.neg),
			);
		}
	}

	// ── Wallet name + password, create vs restore ───────────────────────

	fn wallet_setup_ui(&mut self, ui: &mut egui::Ui, cb: &dyn PlatformCallbacks) {
		let t = theme::tokens();
		self.step_header(
			ui,
			&t!("goblin.onboarding.wallet.kicker"),
			&t!("goblin.onboarding.wallet.title"),
			Step::Intro,
		);

		// Create / Restore segmented choice.
		ui.horizontal(|ui| {
			let half = (ui.available_width() - 10.0) / 2.0;
			for (restore, label) in [
				(false, t!("goblin.onboarding.wallet.create_new")),
				(true, t!("goblin.onboarding.wallet.restore_from_seed")),
			] {
				ui.scope_builder(
					egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
						ui.cursor().min,
						Vec2::new(half, 44.0),
					)),
					|ui| {
						let active = self.restore == restore;
						let resp = w::chip(ui, &label, active);
						if resp.clicked() {
							self.restore = restore;
						}
					},
				);
				ui.add_space(10.0);
			}
		});
		ui.add_space(14.0);

		w::field_well(ui, |ui| {
			TextEdit::new(egui::Id::from("onb_name"))
				.focus(false)
				.hint_text(t!("goblin.onboarding.wallet.name_hint"))
				.text_color(t.surface_text)
				.body()
				.ui(ui, &mut self.name, cb);
		});
		ui.add_space(8.0);
		w::field_well(ui, |ui| {
			TextEdit::new(egui::Id::from("onb_pass"))
				.focus(false)
				.hint_text(t!("goblin.onboarding.wallet.password_hint"))
				.password()
				.text_color(t.surface_text)
				.body()
				.ui(ui, &mut self.pass, cb);
		});
		ui.add_space(8.0);
		w::field_well(ui, |ui| {
			TextEdit::new(egui::Id::from("onb_pass2"))
				.focus(false)
				.hint_text(t!("goblin.onboarding.wallet.repeat_password_hint"))
				.password()
				.text_color(t.surface_text)
				.body()
				.ui(ui, &mut self.pass2, cb);
		});
		ui.add_space(10.0);
		ui.label(
			RichText::new(if self.restore {
				t!("goblin.onboarding.wallet.restore_hint")
			} else {
				t!("goblin.onboarding.wallet.create_hint")
			})
			.font(FontId::new(12.5, fonts::regular()))
			.color(t.text_mute),
		);
		ui.add_space(16.0);

		let pass_ok = !self.pass.is_empty() && self.pass == self.pass2;
		let name_ok = !self.name.trim().is_empty();
		if w::big_action(ui, &t!("goblin.onboarding.wallet.continue"), false).clicked()
			&& pass_ok
			&& name_ok
		{
			self.mnemonic_setup.reset();
			self.mnemonic_setup.mnemonic.set_mode(if self.restore {
				PhraseMode::Import
			} else {
				PhraseMode::Generate
			});
			self.mnemonic_setup.mnemonic.set_size(PhraseSize::Words24);
			self.error = None;
			self.step = Step::Words;
		}
		if !self.pass.is_empty() && self.pass != self.pass2 {
			ui.add_space(8.0);
			ui.label(
				RichText::new(t!("goblin.onboarding.wallet.passwords_no_match"))
					.font(FontId::new(13.0, fonts::regular()))
					.color(t.neg),
			);
		}
	}

	// ── Seed words (display for create, entry for restore) ──────────────

	fn words_ui(
		&mut self,
		ui: &mut egui::Ui,
		wallets: &mut WalletList,
		cb: &dyn PlatformCallbacks,
	) {
		let t = theme::tokens();
		let restore = self.mnemonic_setup.mnemonic.mode() == PhraseMode::Import;
		let words_title = if restore {
			t!("goblin.onboarding.words.title_restore")
		} else {
			t!("goblin.onboarding.words.title_create")
		};
		self.step_header(
			ui,
			&t!("goblin.onboarding.words.kicker"),
			&words_title,
			Step::WalletSetup,
		);
		if restore {
			// Word count picker for restores.
			ui.horizontal(|ui| {
				for size in PhraseSize::VALUES {
					let label = format!("{}", size.value());
					let active = self.mnemonic_setup.mnemonic.size() == size;
					if w::chip(ui, &label, active).clicked() {
						self.mnemonic_setup.mnemonic.set_size(size);
					}
					ui.add_space(6.0);
				}
			});
			ui.add_space(10.0);
		} else {
			ui.label(
				RichText::new(t!("goblin.onboarding.words.write_down_hint"))
					.font(FontId::new(13.0, fonts::regular()))
					.color(t.text_dim),
			);
			ui.add_space(10.0);
		}

		// GRIM's word grid (edit mode when restoring).
		self.mnemonic_setup.word_list_ui(ui, restore);
		ui.add_space(14.0);

		if restore {
			ui.horizontal(|ui| {
				let half = (ui.available_width() - 10.0) / 2.0;
				ui.scope_builder(
					egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
						ui.cursor().min,
						Vec2::new(half, 44.0),
					)),
					|ui| {
						if w::chip(ui, &t!("goblin.onboarding.words.paste"), false).clicked() {
							let data = ZeroingString::from(cb.get_string_from_buffer());
							self.mnemonic_setup.mnemonic.import(&data);
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
						if w::chip(ui, &t!("goblin.onboarding.words.scan_qr"), false).clicked() {
							self.scan_modal = Some(CameraScanContent::default());
							Modal::new(OB_PHRASE_SCAN_MODAL)
								.position(ModalPosition::CenterTop)
								.title(t!("scan_qr"))
								.closeable(false)
								.show();
							cb.start_camera();
						}
					},
				);
			});
			ui.add_space(14.0);
		} else {
			// Transient "Copied" feedback (the Build 82/89 pattern): a silent
			// copy of the recovery phrase reads as a dead button.
			let copied = matches!(self.words_copied, Some(at) if at.elapsed().as_millis() < 1500);
			if self.words_copied.is_some() {
				ui.ctx()
					.request_repaint_after(std::time::Duration::from_millis(200));
			}
			let label = if copied {
				format!("{} {}", CHECK, t!("goblin.receive.copied"))
			} else {
				t!("goblin.onboarding.words.copy_clipboard").to_string()
			};
			if w::chip(ui, &label, false).clicked() {
				cb.copy_string_to_buffer(self.mnemonic_setup.mnemonic.get_phrase());
				cb.vibrate_copy();
				self.words_copied = Some(std::time::Instant::now());
			}
		}
		if !restore {
			ui.add_space(14.0);
		}

		let ready = if restore {
			!self.mnemonic_setup.mnemonic.has_empty_or_invalid()
		} else {
			true
		};
		let label = if restore {
			t!("goblin.onboarding.words.restore_wallet")
		} else {
			t!("goblin.onboarding.words.wrote_them_down")
		};
		if ready {
			if w::big_action(ui, &label, false).clicked() {
				if restore {
					self.create_wallet(wallets);
				} else {
					self.step = Step::ConfirmWords;
				}
			}
		} else {
			ui.label(
				RichText::new(t!("goblin.onboarding.words.fill_every_word"))
					.font(FontId::new(13.0, fonts::regular()))
					.color(t.text_mute),
			);
		}
		self.error_ui(ui);
	}

	fn confirm_ui(
		&mut self,
		ui: &mut egui::Ui,
		wallets: &mut WalletList,
		cb: &dyn PlatformCallbacks,
	) {
		let t = theme::tokens();
		self.step_header(
			ui,
			&t!("goblin.onboarding.confirm.kicker"),
			&t!("goblin.onboarding.confirm.title"),
			Step::Words,
		);
		ui.label(
			RichText::new(t!("goblin.onboarding.confirm.enter_hint"))
				.font(FontId::new(13.0, fonts::regular()))
				.color(t.text_dim),
		);
		ui.add_space(10.0);
		self.mnemonic_setup.word_list_ui(ui, true);
		ui.add_space(14.0);
		if w::chip(ui, &t!("goblin.onboarding.confirm.paste"), false).clicked() {
			let data = ZeroingString::from(cb.get_string_from_buffer());
			self.mnemonic_setup.mnemonic.import(&data);
		}
		ui.add_space(14.0);
		if !self.mnemonic_setup.mnemonic.has_empty_or_invalid() {
			if w::big_action(ui, &t!("goblin.onboarding.confirm.create_wallet"), false).clicked() {
				self.create_wallet(wallets);
			}
		} else {
			ui.label(
				RichText::new(t!("goblin.onboarding.confirm.keep_going"))
					.font(FontId::new(13.0, fonts::regular()))
					.color(t.text_mute),
			);
		}
		self.error_ui(ui);
	}

	fn error_ui(&self, ui: &mut egui::Ui) {
		if let Some(err) = &self.error {
			ui.add_space(10.0);
			ui.label(
				RichText::new(err)
					.font(FontId::new(13.0, fonts::regular()))
					.color(theme::tokens().neg),
			);
		}
	}

	/// Resolve the connection method, create the wallet, open it and move
	/// to the identity step.
	fn create_wallet(&mut self, wallets: &mut WalletList) {
		// Connection: integrated starts the local node; external reuses an
		// existing saved connection with the same URL or saves a new one.
		let method = if self.integrated {
			if !Node::is_running() {
				Node::start();
			}
			ConnectionMethod::Integrated
		} else {
			let url = self.ext_url.trim().trim_end_matches('/').to_string();
			let existing = ConnectionsConfig::ext_conn_list()
				.into_iter()
				.find(|c| c.url.trim_end_matches('/') == url);
			let conn = match existing {
				Some(c) => c,
				None => {
					let c = ExternalConnection::new(url, None, None);
					ConnectionsConfig::add_ext_conn(c.clone());
					c
				}
			};
			ConnectionMethod::External(conn.id, conn.url.clone())
		};

		let pass = ZeroingString::from(self.pass.clone());
		match Wallet::create(
			&self.name.trim().to_string(),
			&pass,
			&self.mnemonic_setup.mnemonic,
			&method,
		) {
			Ok(w) => {
				self.mnemonic_setup.reset();
				wallets.add(w.clone());
				match w.open(pass) {
					Ok(_) => {
						self.wallet = Some(w);
						self.error = None;
						self.step = Step::Identity;
					}
					Err(e) => {
						self.error = Some(
							t!("goblin.onboarding.errors.cant_open", err => format!("{:?}", e))
								.to_string(),
						)
					}
				}
			}
			Err(e) => {
				self.error = Some(
					t!("goblin.onboarding.errors.cant_create", err => format!("{:?}", e))
						.to_string(),
				)
			}
		}
	}

	// ── Identity (optional username) ─────────────────────────────────────

	fn identity_ui(&mut self, ui: &mut egui::Ui, cb: &dyn PlatformCallbacks) -> Option<Wallet> {
		let t = theme::tokens();
		// No back from here: the wallet exists now.
		ui.label(
			RichText::new(t!("goblin.onboarding.identity.kicker"))
				.font(fonts::kicker())
				.color(t.text_mute),
		);
		ui.add_space(18.0);
		ui.label(
			RichText::new(t!("goblin.onboarding.identity.title"))
				.font(FontId::new(26.0, fonts::bold()))
				.color(t.text),
		);
		ui.add_space(14.0);

		let wallet = self.wallet.clone()?;
		let service = wallet.nostr_service();
		let (npub, connected) = service
			.as_ref()
			.map(|s| (s.npub(), s.is_connected()))
			.unwrap_or((String::new(), false));
		// The claimed @name (bare), if any — so the identity card shows the name
		// instead of the npub once a username is registered.
		let claimed_name = service
			.as_ref()
			.and_then(|s| s.identity.read().nip05.clone())
			.and_then(|n| n.split('@').next().map(|s| s.to_string()))
			.filter(|n| !n.is_empty());

		w::card(ui, |ui| {
			ui.set_min_width(ui.available_width());
			ui.horizontal(|ui| {
				// Same deterministic gradient + Grin mark the rest of the app shows
				// for this key; only fall back to a placeholder while the key is
				// still being generated (npub not yet available).
				if npub.is_empty() {
					// Key still generating: a fixed-seed gradient placeholder.
					w::gradient_avatar(ui, "goblin", 44.0);
				} else {
					w::gradient_avatar(ui, &npub, 44.0);
				}
				ui.add_space(10.0);
				ui.vertical(|ui| {
					// Once claimed, show the @name (with a check) instead of the npub
					// so the user can SEE the username applied.
					if let Some(name) = &claimed_name {
						ui.horizontal(|ui| {
							ui.spacing_mut().item_spacing.x = 5.0;
							ui.label(
								RichText::new(name)
									.font(FontId::new(16.0, fonts::bold()))
									.color(t.surface_text),
							);
							ui.label(
								RichText::new(crate::gui::icons::SEAL_CHECK)
									.font(FontId::new(14.0, fonts::regular()))
									.color(t.pos),
							);
						});
					} else {
						let short = if npub.len() > 20 {
							format!("{}…{}", &npub[..12], &npub[npub.len() - 6..])
						} else if npub.is_empty() {
							t!("goblin.onboarding.identity.key_being_made").to_string()
						} else {
							npub.clone()
						};
						ui.label(
							RichText::new(short)
								.font(FontId::new(15.0, fonts::semibold()))
								.color(t.surface_text),
						);
					}
					ui.label(
						// Relay-gated readiness: "connected over Nym" only once a
						// relay is actually live, not merely when the tunnel is warm.
						RichText::new(if crate::nym::transport_ready() {
							t!("goblin.onboarding.identity.connected_nym")
						} else {
							t!("goblin.onboarding.identity.connecting_nym")
						})
						.font(FontId::new(12.0, fonts::regular()))
						.color(t.surface_text_mute),
					);
				});
			});
			ui.add_space(8.0);
			ui.label(
				RichText::new(t!("goblin.onboarding.identity.fresh_key_blurb"))
					.font(FontId::new(12.5, fonts::regular()))
					.color(t.surface_text_dim),
			);
		});
		ui.add_space(14.0);

		// Optional username claim — the same machinery as Settings.
		if let Some(msg) = self.claim.result.lock().unwrap().take() {
			self.claim.checking = false;
			match msg {
				ClaimMsg::Availability(avail) => {
					let (available, msg) = super::availability_feedback(avail);
					self.claim.available = available;
					self.claim.message = Some(msg.to_string());
				}
				ClaimMsg::Registered(nip05) => {
					self.claim.message = Some(
						t!(
							"goblin.onboarding.identity.youre",
							name => nip05.split('@').next().unwrap_or("")
						)
						.to_string(),
					);
					self.claim.available = Some(true);
					if let Some(s) = wallet.nostr_service() {
						{
							let mut id = s.identity.write();
							id.nip05 = Some(nip05.clone());
							id.anonymous = false;
						}
						s.save_identity();
					}
					// Publish kind 0 now so the just-claimed name is visible to
					// others over the relay without waiting for the next app start.
					wallet.task(crate::wallet::types::WalletTask::NostrRepublishProfile);
				}
				ClaimMsg::Released => {}
				ClaimMsg::Error(e) => {
					self.claim.available = Some(false);
					self.claim.message = Some(e);
				}
			}
		}
		let registered = wallet
			.nostr_service()
			.map(|s| s.identity.read().nip05.is_some())
			.unwrap_or(false);
		if self.import.is_some() {
			// Returning user is swapping the random key for their existing identity.
			self.import_ui(ui, &wallet, cb);
		} else if !registered {
			w::card(ui, |ui| {
				ui.set_min_width(ui.available_width());
				ui.label(
					RichText::new(t!("goblin.onboarding.identity.pick_username"))
						.font(FontId::new(15.0, fonts::semibold()))
						.color(t.surface_text),
				);
				ui.add_space(4.0);
				ui.label(
					RichText::new(t!("goblin.onboarding.identity.username_blurb"))
						.font(FontId::new(12.5, fonts::regular()))
						.color(t.surface_text_dim),
				);
				ui.add_space(8.0);
				w::field_well(ui, |ui| {
					ui.horizontal(|ui| {
						let before = self.claim.input.clone();
						TextEdit::new(egui::Id::from("onb_claim"))
							.focus(false)
							.hint_text(t!("goblin.onboarding.identity.username_field_hint"))
							.text_color(t.surface_text)
							.body()
							.ui(ui, &mut self.claim.input, cb);
						if self.claim.input != before {
							self.claim.available = None;
							self.claim.message = None;
						}
					});
				});
				if let Some(msg) = &self.claim.message {
					ui.add_space(6.0);
					ui.label(
						RichText::new(msg)
							.font(FontId::new(13.0, fonts::regular()))
							.color(match self.claim.available {
								Some(false) => t.neg,
								Some(true) => t.pos,
								None => t.surface_text_dim,
							}),
					);
				}
				ui.add_space(10.0);
				let name = self.claim.input.trim().to_lowercase();
				let valid = name.len() >= 3 && name.len() <= 20;
				if self.claim.checking {
					ui.horizontal(|ui| {
						View::small_loading_spinner(ui);
						ui.add_space(8.0);
						ui.label(
							RichText::new(t!("goblin.onboarding.identity.working"))
								.color(t.surface_text_dim),
						);
					});
					ui.ctx().request_repaint();
				} else {
					ui.add_enabled_ui(valid && connected, |ui| {
						if w::big_action_on_card(
							ui,
							&t!("goblin.onboarding.identity.claim_username"),
						)
						.clicked()
						{
							start_claim_flow(&mut self.claim, &name, &wallet);
						}
					});
					if !connected {
						ui.add_space(6.0);
						ui.label(
							RichText::new(t!(
								"goblin.onboarding.identity.available_when_connected"
							))
							.font(FontId::new(12.0, fonts::regular()))
							.color(t.surface_text_mute),
						);
					}
				}
			});
			ui.add_space(10.0);
			// Returning user? Let them restore their existing identity (nsec or a
			// .backup file) instead of claiming a fresh name on the random key.
			let import_resp = ui
				.add(
					egui::Label::new(
						RichText::new(t!("goblin.onboarding.identity.import_existing"))
							.font(FontId::new(13.0, fonts::semibold()))
							.color(t.accent),
					)
					.sense(Sense::click()),
				)
				.on_hover_cursor(egui::CursorIcon::PointingHand);
			if import_resp.clicked() {
				self.import = Some(OnbImport::default());
			}
			ui.add_space(16.0);
		} else {
			// Claimed: show a clear success confirmation so the user knows the
			// username stuck before they tap through to the wallet.
			let claimed = claimed_name.clone().unwrap_or_default();
			w::card(ui, |ui| {
				ui.set_min_width(ui.available_width());
				ui.horizontal(|ui| {
					ui.spacing_mut().item_spacing.x = 8.0;
					ui.label(
						RichText::new(crate::gui::icons::SEAL_CHECK)
							.font(FontId::new(22.0, fonts::regular()))
							.color(t.pos),
					);
					ui.vertical(|ui| {
						ui.label(
							RichText::new(t!(
								"goblin.onboarding.identity.claimed_title",
								name => &claimed
							))
							.font(FontId::new(15.0, fonts::semibold()))
							.color(t.surface_text),
						);
						ui.add_space(2.0);
						ui.label(
							RichText::new(t!("goblin.onboarding.identity.claimed_blurb"))
								.font(FontId::new(12.5, fonts::regular()))
								.color(t.surface_text_dim),
						);
					});
				});
			});
			ui.add_space(16.0);
		}

		if !connected {
			ui.ctx()
				.request_repaint_after(std::time::Duration::from_millis(500));
		}

		let main_label = if registered {
			t!("goblin.onboarding.identity.open_wallet")
		} else {
			t!("goblin.onboarding.identity.skip_for_now")
		};
		if w::big_action(ui, &main_label, false).clicked() {
			return Some(wallet);
		}
		None
	}

	/// Onboarding identity-import sub-flow: paste an nsec or pick a `.backup`
	/// file to swap the freshly-generated random key for the user's existing
	/// identity (keeping their npub and any claimed username). Reuses the wallet
	/// password the user just set; a sealed `.backup` may carry its own password.
	fn import_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet, cb: &dyn PlatformCallbacks) {
		let t = theme::tokens();
		// Poll the worker first, WITHOUT holding a borrow across the reset below.
		if self.import.as_ref().map(|i| i.stage) == Some(1) {
			let res = self.import.as_ref().unwrap().result.lock().unwrap().take();
			if let Some(res) = res {
				match res {
					// Identity replaced: drop the sub-flow; the identity card and the
					// claim/success state re-render from the new service next frame.
					Ok(_) => {
						self.import = None;
						return;
					}
					Err(e) => {
						let imp = self.import.as_mut().unwrap();
						imp.error = e;
						imp.stage = 2;
					}
				}
			}
		}
		let wallet_pass = self.pass.clone();
		let imp = self.import.as_mut().unwrap();
		let mut close = false;
		w::card(ui, |ui| {
			ui.set_min_width(ui.available_width());
			match imp.stage {
				1 => {
					ui.horizontal(|ui| {
						View::small_loading_spinner(ui);
						ui.add_space(8.0);
						ui.label(
							RichText::new(t!("goblin.settings.importing"))
								.font(FontId::new(13.0, fonts::regular()))
								.color(t.surface_text_dim),
						);
					});
					ui.ctx().request_repaint();
				}
				2 => {
					ui.label(
						RichText::new(t!("goblin.settings.import_failed"))
							.font(FontId::new(15.0, fonts::semibold()))
							.color(t.neg),
					);
					ui.add_space(4.0);
					ui.label(
						RichText::new(&imp.error)
							.font(FontId::new(13.0, fonts::regular()))
							.color(t.surface_text_dim),
					);
					ui.add_space(10.0);
					if w::big_action_on_card(ui, &t!("goblin.settings.close")).clicked() {
						close = true;
					}
				}
				_ => {
					ui.label(
						RichText::new(t!("goblin.onboarding.identity.import_title"))
							.font(FontId::new(15.0, fonts::semibold()))
							.color(t.surface_text),
					);
					ui.add_space(6.0);
					ui.label(
						RichText::new(t!("goblin.onboarding.identity.import_blurb"))
							.font(FontId::new(12.5, fonts::regular()))
							.color(t.surface_text_dim),
					);
					ui.add_space(10.0);
					// Native ".backup file" picker. Desktop returns the path now;
					// Android resolves it asynchronously (poll picked_file()).
					if imp.picking {
						if let Some(path) = cb.picked_file() {
							imp.picking = false;
							if !path.is_empty() {
								match std::fs::read_to_string(&path) {
									Ok(contents) => imp.nsec = contents.trim().to_string(),
									Err(_) => {
										imp.error =
											t!("goblin.settings.backup_read_failed").to_string();
									}
								}
							}
						} else {
							ui.ctx().request_repaint();
						}
					}
					if w::big_action_on_card(ui, &t!("goblin.settings.choose_backup_file"))
						.clicked()
					{
						imp.error.clear();
						match cb.pick_file() {
							Some(path) if !path.is_empty() => {
								match std::fs::read_to_string(&path) {
									Ok(contents) => imp.nsec = contents.trim().to_string(),
									Err(_) => {
										imp.error =
											t!("goblin.settings.backup_read_failed").to_string();
									}
								}
							}
							// Empty string = Android async pick in flight.
							Some(_) => imp.picking = true,
							None => {}
						}
					}
					ui.add_space(8.0);
					w::field_well(ui, |ui| {
						TextEdit::new(egui::Id::from("onb_import_nsec"))
							.focus(false)
							.hint_text(t!("goblin.settings.import_nsec_hint"))
							.password()
							.text_color(t.surface_text)
							.body()
							.ui(ui, &mut imp.nsec, cb);
					});
					ui.add_space(8.0);
					w::field_well(ui, |ui| {
						TextEdit::new(egui::Id::from("onb_import_bpw"))
							.focus(false)
							.hint_text(t!("goblin.settings.backup_password_hint"))
							.password()
							.text_color(t.surface_text)
							.body()
							.ui(ui, &mut imp.backup_password, cb);
					});
					if !imp.error.is_empty() {
						ui.add_space(6.0);
						ui.label(
							RichText::new(&imp.error)
								.font(FontId::new(12.5, fonts::regular()))
								.color(t.neg),
						);
					}
					ui.add_space(10.0);
					let pasted = imp.nsec.trim();
					// Only an nsec paste or a sealed .backup file — nothing else.
					let armed =
						pasted.starts_with("nsec1") || NostrIdentity::is_encrypted_backup(pasted);
					ui.horizontal(|ui| {
						let half = (ui.available_width() - 10.0) / 2.0;
						ui.scope_builder(
							egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
								ui.cursor().min,
								Vec2::new(half, 44.0),
							)),
							|ui| {
								if w::big_action_on_card(ui, &t!("goblin.settings.cancel"))
									.clicked()
								{
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
								ui.add_enabled_ui(armed, |ui| {
									if w::big_action(ui, &t!("goblin.settings.import_btn"), false)
										.clicked()
									{
										imp.stage = 1;
										let slot = imp.result.clone();
										let nsec = std::mem::take(&mut imp.nsec);
										let bpw = std::mem::take(&mut imp.backup_password);
										let bpw = if bpw.is_empty() { None } else { Some(bpw) };
										let wallet = wallet.clone();
										let pass = wallet_pass.clone();
										std::thread::spawn(move || {
											let res = wallet.import_nostr_identity(nsec, pass, bpw);
											*slot.lock().unwrap() = Some(res);
										});
									}
								});
							},
						);
					});
				}
			}
		});
		if close {
			self.import = None;
		}
	}

	/// Recovery-phrase QR scan modal content.
	fn scan_modal_ui(&mut self, ui: &mut egui::Ui, _: &Modal, cb: &dyn PlatformCallbacks) {
		if let Some(content) = self.scan_modal.as_mut() {
			content.modal_ui(ui, cb, |result| match result {
				QrScanResult::Text(text) => {
					self.mnemonic_setup.mnemonic.import(&text);
					Modal::close();
				}
				QrScanResult::SeedQR(text) => {
					self.mnemonic_setup.mnemonic.import(&text);
					Modal::close();
				}
				_ => {}
			});
		}
	}
}
