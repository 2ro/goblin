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

use crate::gui::icons::ARROW_LEFT;
use crate::gui::platform::PlatformCallbacks;
use crate::gui::theme::{self, fonts};
use crate::gui::views::types::{ContentContainer, ModalPosition, QrScanResult};
use crate::gui::views::wallets::creation::MnemonicSetup;
use crate::gui::views::{CameraScanContent, Content, Modal, TextEdit, View};
use crate::node::Node;
use crate::wallet::types::{ConnectionMethod, PhraseMode, PhraseSize};
use crate::wallet::{ConnectionsConfig, ExternalConnection, Wallet, WalletList};

use super::widgets::{self as w};
use super::{ClaimMsg, ClaimState, start_claim_flow};

/// Identifier for the recovery-phrase QR scan [`Modal`].
const OB_PHRASE_SCAN_MODAL: &'static str = "ob_phrase_scan_modal";

/// Onboarding step.
#[derive(PartialEq, Eq, Clone, Copy)]
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
}

impl Default for OnboardingContent {
	fn default() -> Self {
		Self {
			step: Step::Intro,
			integrated: true,
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
		let lines: [(&str, &str); 3] = [
			(
				"Private money",
				"Goblin is a wallet for grin — digital cash with no amounts \
				 or addresses on its chain.",
			),
			(
				"Send like a message",
				"Pay a @username or npub and it arrives as an end-to-end \
				 encrypted message over nostr and the Nym mixnet — no one in \
				 between can see the amount or who's involved.",
			),
			(
				"Yours alone",
				"Keys, names and history live on this device. Built on the \
				 GRIM wallet.",
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
		if w::big_action(ui, "Get started", false).clicked() {
			self.step = Step::Node;
		}
		ui.add_space(8.0);
		ui.vertical_centered(|ui| {
			ui.label(
				RichText::new("Takes about a minute. You can change everything later.")
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
			"STEP 1 OF 3 · NETWORK",
			"How should Goblin\nwatch the chain?",
			Step::Intro,
		);
		if Self::node_card(
			ui,
			self.integrated,
			"Run my own node",
			"Private",
			"Trusts no one — your wallet checks the chain itself. Syncs in \
			 the background while you finish setup.",
		) {
			self.integrated = true;
		}
		ui.add_space(10.0);
		if Self::node_card(
			ui,
			!self.integrated,
			"Connect to a node",
			"Instant",
			"No sync wait. The node you pick can see your wallet's queries.",
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
		ui.add_space(8.0);
		ui.label(
			RichText::new("Changeable any time in Settings → Node.")
				.font(FontId::new(12.5, fonts::regular()))
				.color(t.text_mute),
		);
		ui.add_space(16.0);
		let url_ok = self.integrated
			|| self.ext_url.trim().starts_with("http://")
			|| self.ext_url.trim().starts_with("https://");
		if w::big_action(ui, "Continue", false).clicked() && url_ok {
			self.step = Step::WalletSetup;
		}
		if !url_ok {
			ui.add_space(8.0);
			ui.label(
				RichText::new("Node URL must start with http:// or https://")
					.font(FontId::new(13.0, fonts::regular()))
					.color(t.neg),
			);
		}
	}

	// ── Wallet name + password, create vs restore ───────────────────────

	fn wallet_setup_ui(&mut self, ui: &mut egui::Ui, cb: &dyn PlatformCallbacks) {
		let t = theme::tokens();
		self.step_header(ui, "STEP 2 OF 3 · WALLET", "Set up your wallet", Step::Node);

		// Create / Restore segmented choice.
		ui.horizontal(|ui| {
			let half = (ui.available_width() - 10.0) / 2.0;
			for (restore, label) in [(false, "Create new"), (true, "Restore from seed")] {
				ui.scope_builder(
					egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
						ui.cursor().min,
						Vec2::new(half, 44.0),
					)),
					|ui| {
						let active = self.restore == restore;
						let resp = w::chip(ui, label, active);
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
				.hint_text("Wallet name")
				.text_color(t.surface_text)
				.body()
				.ui(ui, &mut self.name, cb);
		});
		ui.add_space(8.0);
		w::field_well(ui, |ui| {
			TextEdit::new(egui::Id::from("onb_pass"))
				.focus(false)
				.hint_text("Password")
				.password()
				.text_color(t.surface_text)
				.body()
				.ui(ui, &mut self.pass, cb);
		});
		ui.add_space(8.0);
		w::field_well(ui, |ui| {
			TextEdit::new(egui::Id::from("onb_pass2"))
				.focus(false)
				.hint_text("Repeat password")
				.password()
				.text_color(t.surface_text)
				.body()
				.ui(ui, &mut self.pass2, cb);
		});
		ui.add_space(10.0);
		ui.label(
			RichText::new(if self.restore {
				"Have your seed words ready — you'll enter them next."
			} else {
				"Next you'll get 24 seed words to write down. They are the \
				 money — anyone holding them holds your funds."
			})
			.font(FontId::new(12.5, fonts::regular()))
			.color(t.text_mute),
		);
		ui.add_space(16.0);

		let pass_ok = !self.pass.is_empty() && self.pass == self.pass2;
		let name_ok = !self.name.trim().is_empty();
		if w::big_action(ui, "Continue", false).clicked() && pass_ok && name_ok {
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
				RichText::new("Passwords don't match")
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
		self.step_header(
			ui,
			"STEP 2 OF 3 · WALLET",
			if restore {
				"Enter your seed words"
			} else {
				"Write these words down"
			},
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
				RichText::new(
					"On paper, in order. Anyone with these words can take \
					 your funds; without them a lost device means lost funds.",
				)
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
						if w::chip(ui, "Paste", false).clicked() {
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
						if w::chip(ui, "Scan QR", false).clicked() {
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
		} else if w::chip(ui, "Copy to clipboard (avoid this)", false).clicked() {
			cb.copy_string_to_buffer(self.mnemonic_setup.mnemonic.get_phrase());
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
			"Restore wallet"
		} else {
			"I wrote them down"
		};
		if ready {
			if w::big_action(ui, label, false).clicked() {
				if restore {
					self.create_wallet(wallets);
				} else {
					self.step = Step::ConfirmWords;
				}
			}
		} else {
			ui.label(
				RichText::new("Fill every word — tap a word to edit it, or paste the phrase.")
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
		self.step_header(ui, "STEP 2 OF 3 · WALLET", "Now prove it", Step::Words);
		ui.label(
			RichText::new("Enter the words you just wrote down. Tap a word to type it.")
				.font(FontId::new(13.0, fonts::regular()))
				.color(t.text_dim),
		);
		ui.add_space(10.0);
		self.mnemonic_setup.word_list_ui(ui, true);
		ui.add_space(14.0);
		if w::chip(ui, "Paste", false).clicked() {
			let data = ZeroingString::from(cb.get_string_from_buffer());
			self.mnemonic_setup.mnemonic.import(&data);
		}
		ui.add_space(14.0);
		if !self.mnemonic_setup.mnemonic.has_empty_or_invalid() {
			if w::big_action(ui, "Create wallet", false).clicked() {
				self.create_wallet(wallets);
			}
		} else {
			ui.label(
				RichText::new("Keep going — every word, in order.")
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
					Err(e) => self.error = Some(format!("Couldn't open the wallet: {:?}", e)),
				}
			}
			Err(e) => self.error = Some(format!("Couldn't create the wallet: {:?}", e)),
		}
	}

	// ── Identity (optional username) ─────────────────────────────────────

	fn identity_ui(&mut self, ui: &mut egui::Ui, cb: &dyn PlatformCallbacks) -> Option<Wallet> {
		let t = theme::tokens();
		// No back from here: the wallet exists now.
		ui.label(
			RichText::new("STEP 3 OF 3 · IDENTITY")
				.font(fonts::kicker())
				.color(t.text_mute),
		);
		ui.add_space(18.0);
		ui.label(
			RichText::new("Your payment identity")
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

		w::card(ui, |ui| {
			ui.set_min_width(ui.available_width());
			ui.horizontal(|ui| {
				w::avatar(ui, "N", 44.0, 6);
				ui.add_space(10.0);
				ui.vertical(|ui| {
					let short = if npub.len() > 20 {
						format!("{}…{}", &npub[..12], &npub[npub.len() - 6..])
					} else if npub.is_empty() {
						"key being made…".to_string()
					} else {
						npub.clone()
					};
					ui.label(
						RichText::new(short)
							.font(FontId::new(15.0, fonts::semibold()))
							.color(t.surface_text),
					);
					ui.label(
						RichText::new(if connected {
							"connected over Nym"
						} else {
							"connecting over Nym…"
						})
						.font(FontId::new(12.0, fonts::regular()))
						.color(t.surface_text_mute),
					);
				});
			});
			ui.add_space(8.0);
			ui.label(
				RichText::new(
					"A fresh key, made for payments — deliberately not part \
					 of your seed, so you can rotate it anytime to maintain \
					 your privacy, without ever touching your funds. Back it \
					 up in Settings → Identity.",
				)
				.font(FontId::new(12.5, fonts::regular()))
				.color(t.surface_text_dim),
			);
			ui.add_space(6.0);
			ui.label(
				RichText::new(
					"Want a clean slate? Swap in a brand-new key any time — \
					 the new you isn't linked to the old one. Same wallet, \
					 fresh face.",
				)
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
					self.claim.message =
						Some(format!("You're @{}", nip05.split('@').next().unwrap_or("")));
					self.claim.available = Some(true);
					if let Some(s) = wallet.nostr_service() {
						{
							let mut id = s.identity.write();
							id.nip05 = Some(nip05.clone());
							id.anonymous = false;
						}
						s.save_identity();
					}
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
		if !registered {
			w::card(ui, |ui| {
				ui.set_min_width(ui.available_width());
				ui.label(
					RichText::new("Pick a username — optional")
						.font(FontId::new(15.0, fonts::semibold()))
						.color(t.surface_text),
				);
				ui.add_space(4.0);
				ui.label(
					RichText::new(
						"Friends pay @you instead of a long key. Public on \
						 goblin.st; payments stay encrypted. Skip it and \
						 you're simply anonymous — claim one any time later.",
					)
					.font(FontId::new(12.5, fonts::regular()))
					.color(t.surface_text_dim),
				);
				ui.add_space(8.0);
				w::field_well(ui, |ui| {
					ui.horizontal(|ui| {
						ui.label(
							RichText::new("@")
								.font(FontId::new(16.0, fonts::semibold()))
								.color(t.surface_text),
						);
						let before = self.claim.input.clone();
						TextEdit::new(egui::Id::from("onb_claim"))
							.focus(false)
							.hint_text("yourname")
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
				let valid = name.len() >= 3 && name.len() <= 30;
				if self.claim.checking {
					ui.horizontal(|ui| {
						View::small_loading_spinner(ui);
						ui.add_space(8.0);
						ui.label(RichText::new("Working…").color(t.surface_text_dim));
					});
					ui.ctx().request_repaint();
				} else {
					ui.add_enabled_ui(valid && connected, |ui| {
						if w::big_action_on_card(ui, "Claim username").clicked() {
							start_claim_flow(&mut self.claim, &name, &wallet);
						}
					});
					if !connected {
						ui.add_space(6.0);
						ui.label(
							RichText::new(
								"Available once the mixnet connects — or skip and claim later.",
							)
							.font(FontId::new(12.0, fonts::regular()))
							.color(t.surface_text_mute),
						);
					}
				}
			});
			ui.add_space(16.0);
		} else {
			ui.add_space(2.0);
		}

		if !connected {
			ui.ctx()
				.request_repaint_after(std::time::Duration::from_millis(500));
		}

		let main_label = if registered {
			"Open my wallet"
		} else {
			"Skip for now"
		};
		if w::big_action(ui, main_label, false).clicked() {
			return Some(wallet);
		}
		None
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
