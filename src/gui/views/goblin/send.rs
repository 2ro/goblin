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

//! The Goblin send flow: pick recipient → enter amount → review → success.

use eframe::epaint::FontId;
use egui::{Align, Layout, RichText, ScrollArea, Sense, Vec2};
use grin_core::core::amount_from_hr_string;

use crate::gui::Colors;
use crate::gui::icons::{ARROW_LEFT, MAGNIFYING_GLASS, SHARE, USERS};
use crate::gui::platform::PlatformCallbacks;
use crate::gui::theme::{self, fonts};
use crate::gui::views::types::{ModalPosition, QrScanResult};
use crate::gui::views::{CameraContent, Modal, TextEdit, View};

/// Modal id for the send-flow note editor (floats above the soft keyboard).
const NOTE_MODAL: &str = "send_note_modal";
use crate::nostr::nip05;
use crate::wallet::Wallet;
use crate::wallet::types::WalletTask;

use super::avatars::AvatarTextures;
use super::data::{self, display_name, recent_peers, search_contacts, short_npub};
use super::widgets::{self as w, HoldToSend};

/// Avatar texture for a display handle, if one is cached. Handles no longer
/// carry an '@'; bare-npub / empty names have no avatar on the server.
fn tex_for(
	avatars: &mut AvatarTextures,
	ctx: &egui::Context,
	wallet: &Wallet,
	name: &str,
) -> Option<egui::TextureHandle> {
	if name.is_empty() || name.starts_with("npub1") {
		return None;
	}
	let server = wallet
		.nostr_service()
		.map(|s| s.config.read().nip05_server())?;
	avatars.texture_for(ctx, &server, name)
}

/// Stage of the send flow.
#[derive(PartialEq, Eq)]
enum Stage {
	Recipient,
	Amount,
	Review,
	Sending,
	Success,
	Failed,
}

/// The two halves of the scan-to-pay screen: the camera, or your own code.
#[derive(Clone, Copy, PartialEq, Default)]
enum ScanTab {
	#[default]
	Scan,
	MyCode,
}

/// A resolved recipient.
#[derive(Clone)]
struct Recipient {
	name: String,
	npub: String,
	/// Recipient relay hints (nprofile / NIP-05 resolution), extra delivery
	/// targets for a recipient whose kind 10050 isn't discoverable yet.
	relay_hints: Vec<String>,
}

/// A recipient search hit shown as a tappable card.
#[derive(Clone)]
struct Candidate {
	name: String,
	npub: String,
	/// Known contact, resolved goblin handle, or has a published nostr
	/// profile. Unverified = a syntactically valid key with no profile.
	verified: bool,
	/// Short provenance tag shown on the card ("on nostr", "@goblin.st", …).
	tag: &'static str,
	/// Relay hints carried by an nprofile or NIP-05 resolution.
	relay_hints: Vec<String>,
}

/// Async network lookup result for the typed query.
enum LookupResult {
	/// A resolved/verified identity (nip05 hit or kind-0 profile found).
	Found(Candidate),
	/// A syntactically valid key with no published profile.
	Unverified(Candidate),
	/// Nothing found for a handle/name.
	NotFound(String),
}

/// The send flow state.
pub struct SendFlow {
	stage: Stage,
	search: String,
	recipient: Option<Recipient>,
	amount: String,
	note: String,
	hold: HoldToSend,
	error: Option<String>,
	/// Async lookup result for the current query, written by a worker.
	lookup_slot: std::sync::Arc<std::sync::Mutex<Option<LookupResult>>>,
	/// Network lookup in flight.
	looking_up: bool,
	/// The query the current network result/`looking_up` belongs to.
	lookup_query: String,
	/// egui time of the last search edit, for debounce.
	input_changed_at: f64,
	/// Network candidate from the last completed lookup (deduped into view).
	net_candidate: Option<Candidate>,
	/// Pending "pay an unverified key?" confirm gate.
	confirm_unverified: Option<Candidate>,
	/// Camera QR scanner when scanning for a recipient.
	scan: Option<CameraContent>,
	/// Start scanning on the next recipient frame (entry from header icon).
	start_scan: bool,
	/// Which half of the scan-to-pay screen is showing (camera vs. own code).
	scan_tab: ScanTab,
	/// The scan-to-pay screen is open (gates camera + My Code).
	scan_open: bool,
	/// Request mode: issue an Invoice1 to the recipient (ask them to pay) rather
	/// than sending them money. Reuses the recipient picker; no balance guard.
	request: bool,
	/// Set when the success screen's "Receipt" button is tapped: the host view
	/// opens the receipt for the latest tx with this npub after the flow closes.
	pub receipt_npub: Option<String>,
	/// Atomic amount (nanogrin) we last asked the wallet to price, so the review
	/// page dispatches one `CalculateFee` per amount instead of every frame.
	fee_requested_for: Option<u64>,
	/// Draft note held while the editor modal is open, so Cancel discards it.
	note_draft: String,
}

impl Default for SendFlow {
	fn default() -> Self {
		Self {
			stage: Stage::Recipient,
			search: String::new(),
			recipient: None,
			amount: String::new(),
			note: String::new(),
			hold: HoldToSend::default(),
			error: None,
			lookup_slot: std::sync::Arc::new(std::sync::Mutex::new(None)),
			looking_up: false,
			lookup_query: String::new(),
			input_changed_at: 0.0,
			net_candidate: None,
			confirm_unverified: None,
			scan: None,
			start_scan: false,
			scan_tab: ScanTab::Scan,
			scan_open: false,
			request: false,
			receipt_npub: None,
			fee_requested_for: None,
			note_draft: String::new(),
		}
	}
}

impl SendFlow {
	/// Pre-fill a contact and skip to amount entry.
	pub fn prefill_contact(&mut self, name: String, npub: String) {
		self.recipient = Some(Recipient {
			name,
			npub,
			relay_hints: vec![],
		});
		self.stage = Stage::Amount;
	}

	/// Pre-fill the amount (Pay tab, amount-first): the flow starts at the
	/// recipient picker and jumps straight to review once one is resolved.
	pub fn prefill_amount(&mut self, amount: String) {
		self.amount = amount;
		self.stage = Stage::Recipient;
	}

	/// Open the flow as a money REQUEST for `amount`: pick a recipient, then
	/// issue them a grin Invoice1 over nostr (they approve to pay). The amount is
	/// fixed up front, so resolving a recipient jumps straight to confirmation.
	pub fn new_request(amount: String) -> Self {
		Self {
			request: true,
			amount,
			..Self::default()
		}
	}

	/// Open the recipient picker with the QR scanner active (header entry).
	pub fn request_scan(&mut self) {
		self.start_scan = true;
		self.stage = Stage::Recipient;
	}

	/// Render the flow. Returns true when the flow is finished (close it).
	pub fn ui(
		&mut self,
		ui: &mut egui::Ui,
		wallet: &Wallet,
		cb: &dyn PlatformCallbacks,
		avatars: &mut AvatarTextures,
	) -> bool {
		let t = theme::tokens();
		let mut done = false;
		// Note editor modal — floats above the soft keyboard with a dimmed
		// backdrop (the GRIM Modal system), like the wallet-password modal.
		if Modal::opened() == Some(NOTE_MODAL) {
			Modal::ui(ui.ctx(), cb, |ui, _modal, cb| {
				self.note_modal_content(ui, cb);
			});
		}
		egui::CentralPanel::default()
			.frame(egui::Frame {
				fill: if self.stage == Stage::Success {
					t.accent
				} else {
					t.bg
				},
				inner_margin: egui::Margin {
					left: (View::far_left_inset_margin(ui) + 12.0) as i8,
					right: (View::get_right_inset() + 12.0) as i8,
					top: (View::get_top_inset() + 12.0) as i8,
					bottom: (View::get_bottom_inset() + 12.0) as i8,
				},
				..Default::default()
			})
			.show_inside(ui, |ui| {
				w::centered_column(
					ui,
					crate::gui::views::Content::SIDE_PANEL_WIDTH * 1.2,
					|ui| match self.stage {
						Stage::Recipient => done = self.recipient_ui(ui, wallet, cb, avatars),
						Stage::Amount => done = self.amount_ui(ui, wallet, avatars, cb),
						Stage::Review => done = self.review_ui(ui, wallet, avatars),
						Stage::Sending => self.sending_ui(ui, wallet),
						Stage::Success => done = self.success_ui(ui),
						Stage::Failed => done = self.failed_ui(ui, wallet),
					},
				);
			});
		done
	}

	/// Content of the note-editor modal: a focused text field + Cancel/Save.
	fn note_modal_content(&mut self, ui: &mut egui::Ui, cb: &dyn PlatformCallbacks) {
		let mut save = false;
		let mut cancel = false;
		ui.vertical_centered(|ui| {
			ui.add_space(4.0);
			let mut field = TextEdit::new(egui::Id::from(NOTE_MODAL).with("input"))
				.focus(true)
				.hint_text(t!("goblin.send.note_hint"));
			field.ui(ui, &mut self.note_draft, cb);
			if field.enter_pressed {
				save = true;
			}
			ui.add_space(10.0);
		});
		ui.columns(2, |columns| {
			columns[0].vertical_centered_justified(|ui| {
				View::button(
					ui,
					t!("goblin.send.note_cancel"),
					Colors::white_or_black(false),
					|| cancel = true,
				);
			});
			columns[1].vertical_centered_justified(|ui| {
				View::button(
					ui,
					t!("goblin.send.note_save"),
					Colors::white_or_black(false),
					|| save = true,
				);
			});
		});
		ui.add_space(4.0);
		if cancel {
			Modal::close();
		}
		if save {
			self.note = self.note_draft.trim().to_string();
			Modal::close();
		}
	}

	fn back_header(&self, ui: &mut egui::Ui, title: &str) -> bool {
		let t = theme::tokens();
		let mut back = false;
		ui.horizontal(|ui| {
			let (rect, resp) = ui.allocate_exact_size(Vec2::splat(36.0), Sense::click());
			ui.painter().circle_filled(rect.center(), 18.0, t.surface2);
			ui.painter().text(
				rect.center(),
				egui::Align2::CENTER_CENTER,
				ARROW_LEFT,
				FontId::new(16.0, fonts::regular()),
				t.text,
			);
			back = resp.clicked();
			ui.add_space(12.0);
			ui.label(
				RichText::new(title)
					.font(FontId::new(18.0, fonts::bold()))
					.color(t.text),
			);
		});
		ui.add_space(12.0);
		back
	}

	fn recipient_ui(
		&mut self,
		ui: &mut egui::Ui,
		wallet: &Wallet,
		cb: &dyn PlatformCallbacks,
		avatars: &mut AvatarTextures,
	) -> bool {
		let t = theme::tokens();

		// Header-icon entry opens the scan-to-pay screen on the camera tab.
		if self.start_scan {
			self.start_scan = false;
			self.scan_open = true;
			self.scan_tab = ScanTab::Scan;
		}

		// Scan-to-pay screen: a Scan | My Code toggle over the camera or your own
		// payment QR. Replaces the picker until closed.
		if self.scan_open {
			let title = if self.request {
				t!("goblin.send.scan_to_request")
			} else {
				t!("goblin.send.scan_to_pay")
			};
			if self.back_header(ui, &title) {
				cb.stop_camera();
				self.scan = None;
				self.scan_open = false;
				return false;
			}
			let sel = if self.scan_tab == ScanTab::Scan { 0 } else { 1 };
			let (tab_scan, tab_my_code) =
				(t!("goblin.send.tab_scan"), t!("goblin.send.tab_my_code"));
			if let Some(i) = w::segmented(ui, &[&tab_scan, &tab_my_code], sel) {
				self.scan_tab = if i == 0 {
					ScanTab::Scan
				} else {
					ScanTab::MyCode
				};
			}
			ui.add_space(14.0);
			match self.scan_tab {
				ScanTab::Scan => {
					// Keep the camera running on this tab.
					if self.scan.is_none() {
						cb.start_camera();
						self.scan = Some(CameraContent::default());
					}
					self.scan_ui(ui, wallet, cb);
				}
				ScanTab::MyCode => {
					// No camera needed while showing our own code.
					if self.scan.is_some() {
						cb.stop_camera();
						self.scan = None;
					}
					self.my_code_ui(ui, wallet, cb);
				}
			}
			return false;
		}

		let title = if self.request {
			t!("goblin.send.request_from")
		} else {
			t!("goblin.send.send_to")
		};
		if self.back_header(ui, &title) {
			return true;
		}

		// Search field: filled rounded box per the design, QR scan at right.
		let mut search = self.search.clone();
		let mut open_scan = false;
		egui::Frame {
			fill: t.surface2,
			corner_radius: eframe::epaint::CornerRadius::same(14),
			inner_margin: egui::Margin::symmetric(14, 13),
			..Default::default()
		}
		.show(ui, |ui| {
			ui.horizontal(|ui| {
				let (icon_rect, _) =
					ui.allocate_exact_size(egui::Vec2::new(24.0, 42.0), egui::Sense::hover());
				ui.painter().text(
					icon_rect.center(),
					egui::Align2::CENTER_CENTER,
					MAGNIFYING_GLASS,
					FontId::new(22.0, fonts::regular()),
					t.surface_text_dim,
				);
				ui.add_space(8.0);
				let mut te = TextEdit::new(egui::Id::from("send_search"))
					.focus(false)
					.hint_text(t!("goblin.send.search_hint"))
					.text_color(t.surface_text)
					.body()
					.paste()
					.scan_qr();
				te.ui(ui, &mut search, cb);
				// scan_qr() already starts the camera on tap.
				open_scan = te.scan_pressed;
			});
		});
		if open_scan {
			// The field's scan_qr already started the camera; open the scan-to-pay
			// screen on the Scan tab so the feed actually shows (the screen is gated
			// on `scan_open`, not `scan`).
			self.scan_open = true;
			self.scan_tab = ScanTab::Scan;
			self.scan = Some(CameraContent::default());
			self.error = None;
		}
		if search != self.search {
			self.search = search;
			self.error = None;
			self.input_changed_at = ui.input(|i| i.time);
			// New query — drop the stale network result until it re-resolves.
			self.net_candidate = None;
		}
		ui.add_space(14.0);

		// The pay-an-unverified-key gate pre-empts the picker.
		if let Some(cand) = self.confirm_unverified.clone() {
			self.unverified_gate_ui(ui, &cand);
			return false;
		}

		// Drive the debounced network lookup + poll its result.
		self.drive_lookup(wallet, ui.input(|i| i.time));

		let query = self.search.trim().to_string();
		if query.is_empty() {
			// Empty query → suggested recent peers, as before.
			ui.label(
				RichText::new(t!("goblin.send.suggested", "icon" => USERS))
					.font(fonts::kicker())
					.color(t.text_mute),
			);
			ui.add_space(8.0);
			let peers = recent_peers(wallet, 20);
			let texs: Vec<Option<egui::TextureHandle>> = peers
				.iter()
				.map(|(name, _)| tex_for(avatars, ui.ctx(), wallet, name))
				.collect();
			ScrollArea::vertical()
				.auto_shrink([false; 2])
				.show(ui, |ui| {
					if peers.is_empty() {
						ui.add_space(20.0);
						ui.label(
							RichText::new(t!("goblin.send.no_contacts"))
								.font(FontId::new(14.0, fonts::regular()))
								.color(t.text_dim),
						);
					}
					for ((name, npub), tex) in peers.into_iter().zip(texs.iter()) {
						if w::activity_row(
							ui,
							&name,
							&data::full_npub(&npub),
							&npub,
							"",
							false,
							false,
							false,
							tex.as_ref(),
						)
						.clicked()
						{
							self.pick(Candidate {
								name,
								npub,
								verified: true,
								tag: "",
								relay_hints: vec![],
							});
						}
					}
				});
			return false;
		}

		// Type-ahead results: instant local matches + the network candidate.
		let mut cands: Vec<Candidate> = search_contacts(wallet, &query, 6)
			.into_iter()
			.map(|(name, npub)| Candidate {
				name,
				npub,
				verified: true,
				tag: "contact",
				relay_hints: vec![],
			})
			.collect();
		if let Some(net) = &self.net_candidate {
			if !cands.iter().any(|c| c.npub == net.npub) {
				cands.push(net.clone());
			}
		}
		let texs: Vec<Option<egui::TextureHandle>> = cands
			.iter()
			.map(|c| tex_for(avatars, ui.ctx(), wallet, &c.name))
			.collect();
		ScrollArea::vertical()
			.auto_shrink([false; 2])
			.show(ui, |ui| {
				for (c, tex) in cands.iter().zip(texs.iter()) {
					let tag = if c.verified {
						// Localize the human-worded provenance tags; domain / protocol
						// tags (@goblin.st, nip-05) display verbatim.
						let label = match c.tag {
							"contact" => t!("goblin.send.tag_contact"),
							"on nostr" => t!("goblin.send.tag_on_nostr"),
							other => std::borrow::Cow::Borrowed(other),
						};
						format!("✓ {}", label)
					} else {
						t!("goblin.send.no_profile").to_string()
					};
					if w::activity_row(
						ui,
						&c.name,
						&tag,
						&c.npub,
						"",
						false,
						false,
						false,
						tex.as_ref(),
					)
					.clicked()
					{
						self.pick(c.clone());
					}
				}
				if self.looking_up {
					ui.add_space(10.0);
					ui.horizontal(|ui| {
						View::small_loading_spinner(ui);
						ui.add_space(8.0);
						ui.label(
							RichText::new(t!("goblin.send.searching_nostr"))
								.font(FontId::new(14.0, fonts::regular()))
								.color(t.text_dim),
						);
					});
					ui.ctx().request_repaint();
				}
				if let Some(err) = &self.error {
					ui.add_space(10.0);
					ui.label(
						RichText::new(err)
							.font(FontId::new(13.0, fonts::regular()))
							.color(t.neg),
					);
				}
			});
		false
	}

	/// Select a candidate: verified ones go straight in; unverified keys hit
	/// the confirm gate first.
	fn pick(&mut self, cand: Candidate) {
		if cand.verified {
			self.recipient = Some(Recipient {
				name: cand.name,
				npub: cand.npub,
				relay_hints: cand.relay_hints,
			});
			let preset = amount_from_hr_string(&self.amount)
				.map(|a| a > 0)
				.unwrap_or(false);
			self.stage = if preset { Stage::Review } else { Stage::Amount };
		} else {
			self.confirm_unverified = Some(cand);
		}
	}

	/// "Pay an unverified key?" gate for a valid key with no nostr profile.
	fn unverified_gate_ui(&mut self, ui: &mut egui::Ui, cand: &Candidate) {
		let t = theme::tokens();
		w::card(ui, |ui| {
			ui.set_min_width(ui.available_width());
			ui.label(
				RichText::new(t!("goblin.send.unverified_title"))
					.font(FontId::new(15.0, fonts::semibold()))
					.color(t.surface_text),
			);
			ui.add_space(4.0);
			ui.label(
				RichText::new(t!("goblin.send.unverified_body"))
					.font(FontId::new(12.5, fonts::regular()))
					.color(t.surface_text_dim),
			);
			ui.add_space(8.0);
			ui.label(
				RichText::new(short_npub(&cand.npub))
					.font(FontId::new(12.0, fonts::mono()))
					.color(t.surface_text_mute),
			);
			ui.add_space(12.0);
			ui.horizontal(|ui| {
				let half = (ui.available_width() - 10.0) / 2.0;
				ui.scope_builder(
					egui::UiBuilder::new().max_rect(egui::Rect::from_min_size(
						ui.cursor().min,
						Vec2::new(half, 44.0),
					)),
					|ui| {
						if w::big_action_on_card(ui, &t!("goblin.send.keep_looking")).clicked() {
							self.confirm_unverified = None;
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
						if w::big_action(ui, &t!("goblin.send.pay_anyway"), false).clicked() {
							let mut c = cand.clone();
							c.verified = true;
							self.confirm_unverified = None;
							self.pick(c);
						}
					},
				);
			});
		});
	}

	/// Camera feed scanning for a recipient QR (npub / nostr: URI / @handle).
	fn scan_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet, cb: &dyn PlatformCallbacks) {
		let t = theme::tokens();
		let result = self.scan.as_mut().and_then(|cam| {
			let res = cam.qr_scan_result();
			if res.is_none() {
				cam.ui(ui, cb);
			}
			res
		});
		if let Some(result) = result {
			cb.stop_camera();
			self.scan = None;
			// A captured code returns to the picker, where the resolved recipient
			// (or an error) shows.
			self.scan_open = false;
			// Only plain text payloads can name a recipient — never echo
			// seed words or slatepack contents into the search box.
			match &result {
				QrScanResult::Text(text) => {
					// Parse as a (possibly amount-bearing) pay-URI. UNTRUSTED
					// input: the parser is pure, fail-closed, and only ever
					// PREFILLS — the recipient still resolves + verifies via the
					// picker and the amount/review screens still gate the send.
					// A bad amount/memo is dropped; a bare `nostr:<nprofile>`
					// behaves exactly as before.
					let pay = crate::nostr::payuri::parse(text);
					// Drop the scanned key into the search box; the picker's
					// debounced lookup resolves + verifies it like typed input.
					self.search = pay.recipient;
					self.input_changed_at = ui.input(|i| i.time);
					self.lookup_query.clear();
					self.net_candidate = None;
					// Prefill the amount only when the wallet's own parser
					// accepted it (strictly positive). We stay on the normal
					// picker -> amount/review flow; nothing auto-advances.
					if let Some(amount) = pay.amount {
						self.amount = amount;
					}
					// Prefill the send note from the (already sanitized) memo;
					// it rides along into the tx message via `dispatch`.
					if let Some(memo) = pay.memo {
						self.note = memo;
					}
					let _ = wallet;
				}
				_ => self.error = Some(t!("goblin.send.scan_not_recipient").to_string()),
			}
			return;
		}
		ui.add_space(14.0);
		ui.vertical_centered(|ui| {
			ui.label(
				RichText::new(t!("goblin.send.scan_prompt"))
					.font(FontId::new(14.0, fonts::regular()))
					.color(t.text_dim),
			);
		});
	}

	/// "My Code" half of the scan-to-pay screen: our own payment QR (the nostr
	/// nprofile) with the Goblin mark nested in the middle, for someone to scan
	/// and pay us. Mirrors the Receive card, trimmed to the essentials.
	fn my_code_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet, cb: &dyn PlatformCallbacks) {
		let t = theme::tokens();
		let (handle, npub, nprofile) = wallet
			.nostr_service()
			.map(|s| {
				let nip05 = s.identity.read().nip05.clone();
				let handle = nip05
					.map(|n| n.split('@').next().unwrap_or("").to_string())
					.unwrap_or_else(|| short_npub(&s.public_key().to_hex()));
				(handle, s.npub(), s.nprofile())
			})
			.unwrap_or_else(|| ("—".to_string(), String::new(), String::new()));
		w::card(ui, |ui| {
			ui.vertical_centered(|ui| {
				ui.add_space(10.0);
				ui.label(
					RichText::new(&handle)
						.font(FontId::new(22.0, fonts::bold()))
						.color(t.surface_text),
				);
				ui.add_space(2.0);
				ui.label(
					RichText::new(t!("goblin.send.scan_to_pay_me"))
						.font(FontId::new(13.0, fonts::regular()))
						.color(t.surface_text_dim),
				);
				ui.add_space(18.0);
				let uri = format!("nostr:{}", nprofile);
				w::qr_code(ui, &uri, 248.0);
				ui.add_space(10.0);
			});
		});

		ui.add_space(12.0);
		if w::big_action(ui, &t!("goblin.send.share_btn", "icon" => SHARE), false).clicked() {
			// Share the full nostr identity (npub + relay hints), with the bare
			// npub as a fallback line, via the platform's native share sheet.
			let link = if nprofile.is_empty() {
				npub.clone()
			} else {
				format!("nostr:{}", nprofile)
			};
			let msg = t!(
				"goblin.send.share_message",
				"handle" => handle,
				"link" => link,
				"npub" => npub
			)
			.to_string();
			cb.share_text(msg);
		}
	}

	/// Debounced network resolution: ~0.4s after the last keystroke, kick off
	/// one lookup for the current query (npub/hex → nostr kind-0 profile;
	/// name/@handle → goblin.st nip05). Poll the worker's result each frame.
	fn drive_lookup(&mut self, wallet: &Wallet, now: f64) {
		// Poll a finished lookup first.
		if self.looking_up {
			if let Some(res) = self.lookup_slot.lock().unwrap().take() {
				self.looking_up = false;
				match res {
					LookupResult::Found(c) | LookupResult::Unverified(c) => {
						self.net_candidate = Some(c);
						self.error = None;
					}
					LookupResult::NotFound(label) => {
						self.net_candidate = None;
						self.error =
							Some(t!("goblin.send.none_found", "label" => label).to_string());
					}
				}
			} else {
				return; // still in flight
			}
		}

		let query = self.search.trim().to_string();
		if query.is_empty() {
			self.lookup_query.clear();
			return;
		}
		// Debounce, and only resolve a given query once.
		if query == self.lookup_query || now - self.input_changed_at < 0.4 {
			return;
		}
		self.lookup_query = query.clone();
		self.error = None;

		use nostr_sdk::nips::nip19::Nip19Profile;
		use nostr_sdk::{FromBech32, PublicKey};
		let key_input = query.strip_prefix("nostr:").unwrap_or(&query);
		let (hex, key_hints) = if let Ok(pk) = PublicKey::from_bech32(key_input) {
			(Some(pk.to_hex()), vec![])
		} else if let Ok(p) = Nip19Profile::from_bech32(key_input) {
			// nprofile carries the recipient's own relay hints — the only
			// routing info available for a fresh, undiscoverable key.
			let hints = p.relays.iter().map(|r| r.to_string()).collect();
			(Some(p.public_key.to_hex()), hints)
		} else if key_input.len() == 64 && key_input.chars().all(|c| c.is_ascii_hexdigit()) {
			(Some(key_input.to_lowercase()), vec![])
		} else {
			(None, vec![])
		};
		let slot = self.lookup_slot.clone();

		if let Some(hex) = hex {
			// Valid key → confirm it's a live identity via its kind-0 profile.
			self.looking_up = true;
			let service = wallet.nostr_service();
			let known = wallet
				.nostr_service()
				.and_then(|s| s.store.contact(&hex).map(|c| display_name(&c)));
			std::thread::spawn(move || {
				let profile = service.and_then(|s| s.fetch_profile_blocking(&hex, &key_hints));
				let res = match (known, profile) {
					// Already a saved contact — trust it.
					(Some(name), _) => LookupResult::Found(Candidate {
						name,
						npub: hex,
						verified: true,
						tag: "contact",
						relay_hints: key_hints,
					}),
					(None, Some(p)) => {
						let name = p
							.nip05
							.as_deref()
							.map(|n| n.split('@').next().unwrap_or("").to_string())
							.or(p.name)
							.unwrap_or_else(|| short_npub(&hex));
						LookupResult::Found(Candidate {
							name,
							npub: hex,
							verified: true,
							tag: "on nostr",
							relay_hints: key_hints,
						})
					}
					(None, None) => LookupResult::Unverified(Candidate {
						name: short_npub(&hex),
						npub: hex,
						verified: false,
						tag: "",
						relay_hints: key_hints,
					}),
				};
				*slot.lock().unwrap() = Some(res);
			});
		} else if let Some((name, domain)) = nip05::split_identifier(&query) {
			// Name / @handle → goblin.st (or other) nip05 resolution.
			self.looking_up = true;
			let label = name.to_string();
			std::thread::spawn(move || {
				let res = match resolve_nip05_blocking(&name, &domain) {
					Some(r) => {
						let hex = r.pubkey.to_hex();
						let home = domain == crate::nostr::nip05::home_domain();
						// Show the name without `@`; a foreign authority shows its
						// domain (`name · domain`) so it can't masquerade as a home
						// name. The NIP-05 root convention `_@domain` is just domain.
						let display = if home {
							name.to_string()
						} else if name == "_" {
							domain.clone()
						} else {
							format!("{name} · {domain}")
						};
						LookupResult::Found(Candidate {
							name: display,
							npub: hex.clone(),
							// A successful NIP-05 resolution (home OR a named foreign
							// authority) is verified — the user typed a specific
							// handle and the domain is shown, so no bare-key gate.
							verified: true,
							tag: if home { "verified" } else { "nip-05" },
							// Resolution relay hints help deliver to a
							// recipient whose kind 10050 we can't see.
							relay_hints: r.relays,
						})
					}
					None => LookupResult::NotFound(label),
				};
				*slot.lock().unwrap() = Some(res);
			});
		} else {
			self.error = Some(t!("goblin.send.enter_recipient").to_string());
		}
	}

	fn amount_ui(
		&mut self,
		ui: &mut egui::Ui,
		wallet: &Wallet,
		avatars: &mut AvatarTextures,
		cb: &dyn PlatformCallbacks,
	) -> bool {
		let t = theme::tokens();
		if self.back_header(ui, &t!("goblin.send.amount_title")) {
			self.stage = Stage::Recipient;
			return false;
		}
		let recipient = self.recipient.clone().unwrap();

		// Block sends over the spendable balance: red amount + a message + an
		// error buzz on tap, rather than letting it fail later at the node.
		let spendable = wallet
			.get_data()
			.map(|d| d.info.amount_currently_spendable)
			.unwrap_or(0);
		let over = amount_from_hr_string(&self.amount)
			.map(|a| a > spendable)
			.unwrap_or(false);

		// Recipient chip, centered per the design.
		let name_label = t!("goblin.send.to_name", "name" => recipient.name).to_string();
		let name_galley = ui.painter().layout_no_wrap(
			name_label.clone(),
			FontId::new(14.0, fonts::semibold()),
			t.text,
		);
		let chip_w = 28.0 + 8.0 + name_galley.size().x;
		let chip_tex = tex_for(avatars, ui.ctx(), wallet, &recipient.name);
		ui.horizontal(|ui| {
			ui.add_space(((ui.available_width() - chip_w) / 2.0).max(0.0));
			w::avatar_any(
				ui,
				&recipient.name,
				&recipient.npub,
				28.0,
				chip_tex.as_ref(),
			);
			ui.add_space(8.0);
			ui.label(
				RichText::new(name_label)
					.font(FontId::new(14.0, fonts::semibold()))
					.color(t.text),
			);
		});
		ui.add_space(20.0);

		// Big amount display.
		let display = if self.amount.is_empty() {
			"0".to_string()
		} else {
			self.amount.clone()
		};
		if over {
			w::amount_text_centered_ink(ui, &display, 64.0, t.neg, t.neg);
		} else {
			w::amount_text_centered(ui, &display, 64.0);
		}
		if let Ok(grin) = display.parse::<f64>() {
			if let Some(preview) = super::pairing_preview(grin) {
				ui.add_space(6.0);
				ui.vertical_centered(|ui| {
					ui.label(
						RichText::new(preview)
							.font(FontId::new(14.0, fonts::regular()))
							.color(t.text_dim),
					);
				});
			}
		}
		if over {
			ui.add_space(6.0);
			ui.vertical_centered(|ui| {
				ui.label(
					RichText::new(t!("goblin.send.not_enough"))
						.font(FontId::new(14.0, fonts::regular()))
						.color(t.neg),
				);
			});
		}
		ui.add_space(16.0);

		let note_id = egui::Id::from("send_note");
		// Numpad / typed amount FIRST, then the note BELOW it. On mobile the soft
		// keyboard for the note covers the bottom of the screen — keeping the pad
		// above it means the pad stays visible and tappable, instead of being
		// hidden behind the keyboard (the old order trapped you in the note).
		let note_focused = ui.ctx().memory(|m| m.has_focus(note_id));
		// The send column is capped at 480 by `centered_column`, so the old
		// `< 700` width gate was always narrow and the typed branch dead (same
		// fix as pay_ui, so both amount screens match): show the pad and accept
		// typed digits alongside it.
		if w::numpad(ui, &mut self.amount, cb) {
			// Tapping the pad means you're back on the amount — drop the note's
			// focus so its keyboard goes away.
			ui.ctx().memory_mut(|m| m.surrender_focus(note_id));
		}
		if !note_focused {
			// Only consume keystrokes for the amount when the note field is
			// not focused, so typing a note doesn't also edit the amount.
			w::amount_typed_input(ui, &mut self.amount);
		}
		ui.add_space(12.0);

		// Note: opens a modal editor that floats above the soft keyboard with a
		// dimmed backdrop, so the keyboard never covers it (works on every device).
		let _ = note_id;
		if self.note.trim().is_empty() {
			if w::big_action(ui, &t!("goblin.send.add_note"), true).clicked() {
				self.note_draft = self.note.clone();
				Modal::new(NOTE_MODAL)
					.position(ModalPosition::CenterTop)
					.title(t!("goblin.send.note_label"))
					.show();
			}
		} else {
			// Show the saved note, with an Edit button to re-open the editor.
			w::card(ui, |ui| {
				ui.set_min_width(ui.available_width());
				ui.label(
					RichText::new(format!("\u{201C}{}\u{201D}", self.note.trim()))
						.font(FontId::new(14.0, fonts::regular()))
						.color(t.surface_text),
				);
			});
			ui.add_space(8.0);
			if w::big_action(ui, &t!("goblin.send.edit_note"), true).clicked() {
				self.note_draft = self.note.clone();
				Modal::new(NOTE_MODAL)
					.position(ModalPosition::CenterTop)
					.title(t!("goblin.send.note_label"))
					.show();
			}
		}
		ui.add_space(8.0);

		let valid = amount_from_hr_string(&self.amount)
			.map(|a| a > 0)
			.unwrap_or(false);
		// Greyed out while over balance, matching the red guard above; the
		// `!over` in the click also refuses it in case the disabled state is
		// ever bypassed.
		ui.add_enabled_ui(valid && !over, |ui| {
			if w::big_action(ui, &t!("goblin.send.review_btn"), false).clicked() && !over {
				self.stage = Stage::Review;
			}
		});
		false
	}

	fn review_ui(
		&mut self,
		ui: &mut egui::Ui,
		wallet: &Wallet,
		avatars: &mut AvatarTextures,
	) -> bool {
		let t = theme::tokens();
		let title = if self.request {
			t!("goblin.send.confirm_request")
		} else {
			t!("goblin.send.review_title")
		};
		if self.back_header(ui, &title) {
			// Requests fix the amount on the Pay tab, so back returns to the
			// recipient picker rather than the send-style amount step.
			self.stage = if self.request {
				Stage::Recipient
			} else {
				Stage::Amount
			};
			return false;
		}
		let recipient = self.recipient.clone().unwrap();
		let amount = self.amount.clone();
		let hero_tex = tex_for(avatars, ui.ctx(), wallet, &recipient.name);

		// Over-balance guard: every path that reaches Review (including the
		// Pay-tab / scan prefill that jumps straight here, skipping the amount
		// step) must not offer a completable send for more than the spendable
		// balance. Re-checked each frame so a mid-flow balance drop disables it.
		let spendable = wallet
			.get_data()
			.map(|d| d.info.amount_currently_spendable)
			.unwrap_or(0);
		// Requests never spend our balance, so the guard does not apply to them.
		let over = !self.request
			&& amount_from_hr_string(&amount)
				.map(|a| a > spendable)
				.unwrap_or(false);

		w::card(ui, |ui| {
			ui.set_min_width(ui.available_width());
			ui.add_space(8.0);
			let label = if self.request {
				t!("goblin.send.requesting_from", "name" => recipient.name).to_string()
			} else {
				t!("goblin.send.youre_sending", "name" => recipient.name).to_string()
			};
			// Centered avatar + caption. A long counterparty (a bare npub) wraps
			// and stays centered instead of overflowing the card.
			ui.vertical_centered(|ui| {
				w::avatar_any(
					ui,
					&recipient.name,
					&recipient.npub,
					40.0,
					hero_tex.as_ref(),
				);
				ui.add_space(6.0);
				ui.label(
					RichText::new(label)
						.font(FontId::new(14.0, fonts::regular()))
						.color(t.surface_text_dim),
				);
			});
			ui.add_space(8.0);
			w::amount_text_centered_ink(ui, &amount, 48.0, t.surface_text, t.surface_text_dim);
			ui.add_space(8.0);
		});
		ui.add_space(16.0);

		let from_to = if self.request {
			t!("goblin.send.row_from")
		} else {
			t!("goblin.send.row_to")
		};
		w::info_row(ui, &from_to, &recipient.name);
		if !self.note.trim().is_empty() {
			w::info_row(
				ui,
				&t!("goblin.send.row_note"),
				&format!("\u{201C}{}\u{201D}", self.note.trim()),
			);
		}
		if self.request {
			w::info_row(
				ui,
				&t!("goblin.send.row_they_pay"),
				&t!("goblin.send.row_they_pay_val"),
			);
			w::info_row(
				ui,
				&t!("goblin.send.row_delivery"),
				&t!("goblin.send.row_delivery_val"),
			);
		} else {
			// Live network fee for this exact amount, priced by the wallet (one
			// async CalculateFee per amount, like GRIM's send modal). Until the
			// first result lands we show an ellipsis rather than a wrong number.
			let amount_nano = amount_from_hr_string(&amount).unwrap_or(0);
			if amount_nano > 0 && self.fee_requested_for != Some(amount_nano) {
				self.fee_requested_for = Some(amount_nano);
				wallet.task(WalletTask::CalculateFee(amount_nano, 0));
			}
			let fee_val = match wallet.calculated_fee(amount_nano) {
				Some(fee) => format!("{}{}", w::amount_str(fee), w::TSU),
				None => {
					// Result lands on a worker thread; poll until it does.
					ui.ctx()
						.request_repaint_after(std::time::Duration::from_millis(120));
					"…".to_string()
				}
			};
			w::info_row(ui, &t!("goblin.send.row_network_fee"), &fee_val);
			w::info_row(
				ui,
				&t!("goblin.send.row_privacy"),
				&t!("goblin.send.row_privacy_val"),
			);
			w::info_row(
				ui,
				&t!("goblin.send.row_delivery"),
				&t!("goblin.send.row_delivery_val"),
			);
		}
		ui.add_space(16.0);

		// Requests are not a spend: one tap sends the ask, no hold-to-confirm.
		if self.request {
			if w::big_action(ui, &t!("goblin.send.send_request_btn"), false).clicked() {
				self.dispatch(wallet);
				self.stage = Stage::Sending;
			}
			ui.add_space(6.0);
			ui.vertical_centered(|ui| {
				ui.label(
					RichText::new(t!("goblin.send.request_approve_hint"))
						.font(FontId::new(12.0, fonts::regular()))
						.color(t.text_mute),
				);
			});
			return false;
		}

		if over {
			ui.vertical_centered(|ui| {
				ui.label(
					RichText::new(t!("goblin.send.not_enough"))
						.font(FontId::new(14.0, fonts::regular()))
						.color(t.neg),
				);
			});
			ui.add_space(8.0);
		}
		// Greyed out while over balance; the `&& !over` also refuses the send in
		// case the hold widget ignores the disabled state.
		ui.add_enabled_ui(!over, |ui| {
			if self.hold.ui(ui, &t!("goblin.send.hold_to_send")) && !over {
				self.dispatch(wallet);
				self.stage = Stage::Sending;
			}
		});
		ui.add_space(6.0);
		ui.vertical_centered(|ui| {
			ui.label(
				RichText::new(if over {
					t!("goblin.send.lower_amount")
				} else {
					t!("goblin.send.hold_confirm_hint")
				})
				.font(FontId::new(12.0, fonts::regular()))
				.color(t.text_mute),
			);
		});
		false
	}

	fn dispatch(&mut self, wallet: &Wallet) {
		if let (Some(recipient), Ok(amount)) =
			(&self.recipient, amount_from_hr_string(&self.amount))
		{
			let note = if self.note.trim().is_empty() {
				None
			} else {
				Some(self.note.trim().to_string())
			};
			// Clear any stale picker error so the failure screen shows the right
			// message, and reset the send phase to Working so sending_ui waits for
			// the real dispatch result rather than flipping to Success prematurely.
			self.error = None;
			if let Some(service) = wallet.nostr_service() {
				service.set_send_phase(crate::nostr::send_phase::WORKING);
			}
			if self.request {
				wallet.task(WalletTask::NostrRequest(
					amount,
					recipient.npub.clone(),
					note,
					recipient.relay_hints.clone(),
				));
			} else {
				wallet.task(WalletTask::NostrSend(
					amount,
					recipient.npub.clone(),
					note,
					recipient.relay_hints.clone(),
				));
			}
		}
	}

	fn sending_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet) {
		let t = theme::tokens();
		ui.add_space(80.0);
		ui.vertical_centered(|ui| {
			View::big_loading_spinner(ui);
			ui.add_space(16.0);
			ui.label(
				RichText::new(if self.request {
					t!("goblin.send.requesting")
				} else {
					t!("goblin.send.sending")
				})
				.font(FontId::new(18.0, fonts::semibold()))
				.color(t.text),
			);
		});
		// Advance only on the real dispatch result: the payment DM must have
		// actually been sent (or failed) over the relay, not merely created.
		let phase = wallet
			.nostr_service()
			.map(|s| s.send_phase())
			.unwrap_or(crate::nostr::send_phase::FAILED);
		match phase {
			crate::nostr::send_phase::SENT => self.stage = Stage::Success,
			crate::nostr::send_phase::REQUEST_BLOCKED => {
				let who = self
					.recipient
					.as_ref()
					.map(|r| r.name.clone())
					.unwrap_or_else(|| t!("goblin.send.they").to_string());
				self.error = Some(t!("goblin.send.request_blocked", "who" => who).to_string());
				self.stage = Stage::Failed;
			}
			crate::nostr::send_phase::FAILED => {
				// Surface the real reason (e.g. funds still confirming).
				if self.error.is_none() {
					self.error = wallet.nostr_service().and_then(|s| s.last_send_error());
				}
				self.stage = Stage::Failed;
			}
			_ => {}
		}
		ui.ctx().request_repaint();
	}

	fn failed_ui(&mut self, ui: &mut egui::Ui, wallet: &Wallet) -> bool {
		let t = theme::tokens();
		ui.add_space(80.0);
		let mut done = false;
		ui.vertical_centered(|ui| {
			ui.label(
				RichText::new(crate::gui::icons::WARNING_CIRCLE)
					.font(FontId::new(56.0, fonts::regular()))
					.color(t.neg),
			);
			ui.add_space(16.0);
			ui.label(
				RichText::new(if self.request {
					t!("goblin.send.failed_request_title")
				} else {
					t!("goblin.send.failed_send_title")
				})
				.font(FontId::new(22.0, fonts::bold()))
				.color(t.text),
			);
			ui.add_space(6.0);
			ui.label(
				RichText::new(self.error.clone().unwrap_or_else(|| {
					if self.request {
						t!("goblin.send.failed_request_body").to_string()
					} else {
						t!("goblin.send.failed_send_body").to_string()
					}
				}))
				.font(FontId::new(14.0, fonts::regular()))
				.color(t.text_dim),
			);
		});
		ui.add_space(24.0);
		if w::big_action(ui, &t!("goblin.send.try_again_btn"), false).clicked() {
			self.dispatch(wallet);
			self.stage = Stage::Sending;
		}
		ui.add_space(10.0);
		if w::big_action(ui, &t!("goblin.send.close_btn"), true).clicked() {
			done = true;
		}
		done
	}

	fn success_ui(&mut self, ui: &mut egui::Ui) -> bool {
		let t = theme::tokens();
		let recipient = self.recipient.clone().unwrap();
		ui.add_space(80.0);
		ui.vertical_centered(|ui| {
			// Mascot in an ink circle.
			let (rect, _) = ui.allocate_exact_size(Vec2::splat(120.0), Sense::hover());
			ui.painter()
				.circle_filled(rect.center(), 60.0, t.accent_ink);
			let img = egui::Image::new(egui::include_image!("../../../../img/goblin-logo2.svg"))
				.tint(t.accent)
				.fit_to_exact_size(Vec2::splat(72.0));
			img.paint_at(
				ui,
				egui::Rect::from_center_size(rect.center(), Vec2::splat(72.0)),
			);
			ui.add_space(24.0);
			ui.label(
				RichText::new(if self.request { t!("goblin.send.success.requested") } else { t!("goblin.send.success.sent") })
					.font(FontId::new(34.0, fonts::bold()))
					.color(t.accent_ink),
			);
			ui.add_space(8.0);
			// Amount + ツ as one layout job so vertical_centered centers it exactly,
			// independent of the number's width (a fixed offset drifts off-center).
			let mut job = egui::text::LayoutJob::default();
			job.append(
				&self.amount,
				0.0,
				egui::text::TextFormat {
					font_id: FontId::new(40.0, fonts::mono_semibold()),
					color: t.accent_ink,
					..Default::default()
				},
			);
			job.append(
				w::TSU,
				0.0,
				egui::text::TextFormat {
					font_id: FontId::new(20.0, fonts::medium()),
					color: t.accent_ink,
					valign: Align::BOTTOM,
					..Default::default()
				},
			);
			ui.label(job);
			ui.add_space(8.0);
			ui.label(
				RichText::new(t!(
					"goblin.send.success.subtitle",
					"dir" => if self.request { t!("goblin.send.success.from") } else { t!("goblin.send.success.to") },
					"who" => recipient.name
				))
				.font(FontId::new(15.0, fonts::regular()))
				.color(t.accent_ink.gamma_multiply(0.7)),
			);
		});

		let mut done = false;
		let is_request = self.request;
		let mut want_receipt = false;
		ui.with_layout(Layout::bottom_up(Align::Center), |ui| {
			ui.add_space(20.0);
			let (rect, resp) =
				ui.allocate_exact_size(Vec2::new(ui.available_width(), 56.0), Sense::click());
			ui.painter().rect(
				rect,
				eframe::epaint::CornerRadius::same(14),
				t.accent_ink,
				eframe::epaint::Stroke::NONE,
				egui::StrokeKind::Inside,
			);
			ui.painter().text(
				rect.center(),
				egui::Align2::CENTER_CENTER,
				t!("goblin.send.success.done_btn"),
				FontId::new(17.0, fonts::semibold()),
				t.accent,
			);
			if resp.clicked() {
				done = true;
			}
			// Receipt (secondary; sends only) — sits above Done in bottom-up.
			if !is_request {
				ui.add_space(10.0);
				let (r2, resp2) =
					ui.allocate_exact_size(Vec2::new(ui.available_width(), 56.0), Sense::click());
				ui.painter().rect(
					r2,
					eframe::epaint::CornerRadius::same(14),
					egui::Color32::TRANSPARENT,
					eframe::epaint::Stroke::new(1.5, t.accent_ink),
					egui::StrokeKind::Inside,
				);
				ui.painter().text(
					r2.center(),
					egui::Align2::CENTER_CENTER,
					t!("goblin.send.success.receipt_btn"),
					FontId::new(17.0, fonts::semibold()),
					t.accent_ink,
				);
				if resp2.clicked() {
					want_receipt = true;
				}
			}
		});
		if want_receipt {
			self.receipt_npub = Some(recipient.npub.clone());
			done = true;
		}
		done
	}
}

/// Resolve a NIP-05 identifier on a short-lived runtime (blocking the UI
/// briefly is acceptable for an explicit "find recipient" action).
fn resolve_nip05_blocking(name: &str, domain: &str) -> Option<nip05::Nip05Resolution> {
	let name = name.to_string();
	let domain = domain.to_string();
	std::thread::spawn(move || {
		let rt = tokio::runtime::Builder::new_current_thread()
			.enable_all()
			.build()
			.ok()?;
		rt.block_on(nip05::resolve(&name, &domain))
	})
	.join()
	.ok()
	.flatten()
}
