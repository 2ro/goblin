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

use crate::gui::icons::{ARROW_LEFT, MAGNIFYING_GLASS, USERS};
use crate::gui::platform::PlatformCallbacks;
use crate::gui::theme::{self, fonts};
use crate::gui::views::types::QrScanResult;
use crate::gui::views::{CameraContent, TextEdit, View};
use crate::nostr::nip05;
use crate::wallet::Wallet;
use crate::wallet::types::WalletTask;

use super::avatars::AvatarTextures;
use super::data::{self, display_name, recent_peers, search_contacts, short_npub};
use super::widgets::{self as w, HoldToSend};

/// Avatar texture for a display handle ("@name"), if one is cached.
fn tex_for(
	avatars: &mut AvatarTextures,
	ctx: &egui::Context,
	wallet: &Wallet,
	name: &str,
) -> Option<egui::TextureHandle> {
	if !name.starts_with('@') {
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

/// A resolved recipient.
#[derive(Clone)]
struct Recipient {
	name: String,
	npub: String,
	hue: usize,
	/// Recipient relay hints (nprofile / NIP-05 resolution), extra delivery
	/// targets for a recipient whose kind 10050 isn't discoverable yet.
	relay_hints: Vec<String>,
}

/// A recipient search hit shown as a tappable card.
#[derive(Clone)]
struct Candidate {
	name: String,
	npub: String,
	hue: usize,
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
	/// Request mode: issue an Invoice1 to the recipient (ask them to pay) rather
	/// than sending them money. Reuses the recipient picker; no balance guard.
	request: bool,
	/// Set when the success screen's "Receipt" button is tapped: the host view
	/// opens the receipt for the latest tx with this npub after the flow closes.
	pub receipt_npub: Option<String>,
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
			request: false,
			receipt_npub: None,
		}
	}
}

impl SendFlow {
	/// Pre-fill a contact and skip to amount entry.
	pub fn prefill_contact(&mut self, name: String, npub: String) {
		let hue = data::hue_of(&npub);
		self.recipient = Some(Recipient {
			name,
			npub,
			hue,
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

		// Header-icon entry arms the scanner before the first frame.
		if self.start_scan {
			self.start_scan = false;
			cb.start_camera();
			self.scan = Some(CameraContent::default());
		}

		// Scanner mode: the camera feed replaces the picker until cancelled.
		if self.scan.is_some() {
			if self.back_header(
				ui,
				if self.request {
					"Scan to request"
				} else {
					"Scan to pay"
				},
			) {
				cb.stop_camera();
				self.scan = None;
				return false;
			}
			self.scan_ui(ui, wallet, cb);
			return false;
		}

		if self.back_header(
			ui,
			if self.request {
				"Request from"
			} else {
				"Send to"
			},
		) {
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
					.hint_text("@handle, npub, or name")
					.text_color(t.surface_text)
					.body()
					.scan_qr();
				te.ui(ui, &mut search, cb);
				// scan_qr() already starts the camera on tap.
				open_scan = te.scan_pressed;
			});
		});
		if open_scan {
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
				RichText::new(format!("{}  Suggested", USERS))
					.font(fonts::kicker())
					.color(t.text_mute),
			);
			ui.add_space(8.0);
			let peers = recent_peers(wallet, 20);
			let texs: Vec<Option<egui::TextureHandle>> = peers
				.iter()
				.map(|(name, _, _)| tex_for(avatars, ui.ctx(), wallet, name))
				.collect();
			ScrollArea::vertical()
				.auto_shrink([false; 2])
				.show(ui, |ui| {
					if peers.is_empty() {
						ui.add_space(20.0);
						ui.label(
							RichText::new("No contacts yet. Find someone by their @handle.")
								.font(FontId::new(14.0, fonts::regular()))
								.color(t.text_dim),
						);
					}
					for ((name, hue, npub), tex) in peers.into_iter().zip(texs.iter()) {
						if w::activity_row(
							ui,
							&name,
							&data::full_npub(&npub),
							hue,
							"",
							false,
							false,
							tex.as_ref(),
						)
						.clicked()
						{
							self.pick(Candidate {
								name,
								npub,
								hue,
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
			.map(|(name, hue, npub)| Candidate {
				name,
				npub,
				hue,
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
						format!("✓ {}", c.tag)
					} else {
						"no profile".to_string()
					};
					if w::activity_row(ui, &c.name, &tag, c.hue, "", false, false, tex.as_ref())
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
							RichText::new("Searching nostr…")
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
				hue: cand.hue,
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
				RichText::new("Pay an unverified key?")
					.font(FontId::new(15.0, fonts::semibold()))
					.color(t.surface_text),
			);
			ui.add_space(4.0);
			ui.label(
				RichText::new(
					"No nostr profile is published for this key — it may be \
					 brand new, anonymous, or mistyped. Double-check it's the \
					 right one before sending.",
				)
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
						if w::big_action_on_card(ui, "Keep looking").clicked() {
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
						if w::big_action(ui, "Pay anyway", false).clicked() {
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
		const NO_RECIPIENT: &str = "That QR isn't a goblin recipient — expected an npub or @handle";
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
			// Only plain text payloads can name a recipient — never echo
			// seed words or slatepack contents into the search box.
			match &result {
				QrScanResult::Text(text) => {
					let text = text.trim();
					let text = text
						.strip_prefix("nostr:")
						.or_else(|| text.strip_prefix("NOSTR:"))
						.unwrap_or(text);
					// Drop the scanned key into the search box; the picker's
					// debounced lookup resolves + verifies it like typed input.
					self.search = text.to_string();
					self.input_changed_at = ui.input(|i| i.time);
					self.lookup_query.clear();
					self.net_candidate = None;
					let _ = wallet;
				}
				_ => self.error = Some(NO_RECIPIENT.to_string()),
			}
			return;
		}
		ui.add_space(14.0);
		ui.vertical_centered(|ui| {
			ui.label(
				RichText::new("Point at a goblin receive QR")
					.font(FontId::new(14.0, fonts::regular()))
					.color(t.text_dim),
			);
		});
		ui.add_space(14.0);
		if w::big_action(ui, "Cancel", false).clicked() {
			cb.stop_camera();
			self.scan = None;
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
						self.error = Some(format!("No one found for {label}"));
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
			let known = wallet.nostr_service().and_then(|s| {
				s.store
					.contact(&hex)
					.map(|c| (display_name(&c), c.hue as usize))
			});
			std::thread::spawn(move || {
				let hue = data::hue_of(&hex);
				let profile = service.and_then(|s| s.fetch_profile_blocking(&hex));
				let res = match (known, profile) {
					// Already a saved contact — trust it.
					(Some((name, hue)), _) => LookupResult::Found(Candidate {
						name,
						npub: hex,
						hue,
						verified: true,
						tag: "contact",
						relay_hints: key_hints,
					}),
					(None, Some(p)) => {
						let name = p
							.nip05
							.as_deref()
							.map(|n| format!("@{}", n.split('@').next().unwrap_or("")))
							.or(p.name)
							.unwrap_or_else(|| short_npub(&hex));
						LookupResult::Found(Candidate {
							name,
							npub: hex,
							hue,
							verified: true,
							tag: "on nostr",
							relay_hints: key_hints,
						})
					}
					(None, None) => LookupResult::Unverified(Candidate {
						name: short_npub(&hex),
						npub: hex,
						hue,
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
			let label = format!("@{name}");
			std::thread::spawn(move || {
				let res = match resolve_nip05_blocking(&name, &domain) {
					Some(r) => {
						let hex = r.pubkey.to_hex();
						let home = domain == crate::nostr::relays::HOME_NIP05_DOMAIN;
						// Foreign handles display with their domain so they
						// can't masquerade as goblin handles; the NIP-05 root
						// convention `_@domain` displays as just the domain.
						let display = if home {
							format!("@{name}")
						} else if name == "_" {
							domain.clone()
						} else {
							format!("{name}@{domain}")
						};
						LookupResult::Found(Candidate {
							name: display,
							npub: hex.clone(),
							hue: data::hue_of(&hex),
							// Only goblin.st identities skip the confirm gate.
							// A third-party domain's well-known could point at
							// any key, so route those through the same "pay an
							// unverified key?" gate as a bare npub.
							verified: home,
							tag: if home { "@goblin.st" } else { "nip-05" },
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
			self.error = Some("Enter an @handle, npub, or name".to_string());
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
		if self.back_header(ui, "Amount") {
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
		let name_label = format!("To {}", recipient.name);
		let name_galley = ui.painter().layout_no_wrap(
			name_label.clone(),
			FontId::new(14.0, fonts::semibold()),
			t.text,
		);
		let chip_w = 28.0 + 8.0 + name_galley.size().x;
		let chip_tex = tex_for(avatars, ui.ctx(), wallet, &recipient.name);
		ui.horizontal(|ui| {
			ui.add_space(((ui.available_width() - chip_w) / 2.0).max(0.0));
			w::avatar_any(ui, &recipient.name, 28.0, recipient.hue, chip_tex.as_ref());
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
					RichText::new("You don't have enough grin")
						.font(FontId::new(14.0, fonts::regular()))
						.color(t.neg),
				);
			});
		}
		ui.add_space(16.0);

		// Quick chips.
		ui.horizontal(|ui| {
			ui.add_space((ui.available_width() - 220.0).max(0.0) / 2.0);
			for v in ["1", "10", "100", "Max"] {
				if w::chip_outline(ui, v).clicked() {
					if v == "Max" {
						let max = wallet
							.get_data()
							.map(|d| d.info.amount_currently_spendable)
							.unwrap_or(0);
						self.amount = w::amount_str(max);
					} else {
						self.amount = v.to_string();
					}
				}
				ui.add_space(8.0);
			}
		});
		ui.add_space(16.0);

		// Note field.
		let mut note_focused = false;
		w::card(ui, |ui| {
			ui.horizontal(|ui| {
				ui.label(
					RichText::new("Note")
						.font(FontId::new(14.0, fonts::regular()))
						.color(t.surface_text_dim),
				);
				ui.add_space(8.0);
				let note_id = egui::Id::from("send_note");
				TextEdit::new(note_id)
					.focus(false)
					.hint_text("Add a note…")
					.text_color(t.surface_text)
					.body()
					.ui(ui, &mut self.note, cb);
				note_focused = ui.ctx().memory(|m| m.has_focus(note_id));
			});
		});
		ui.add_space(12.0);

		// Numpad (mobile) — desktop also accepts keyboard via egui events.
		if !View::is_desktop() {
			w::numpad(ui, &mut self.amount);
		} else if !note_focused {
			// Only consume keystrokes for the amount when the note field is
			// not focused, so typing a note doesn't also edit the amount.
			w::amount_typed_input(ui, &mut self.amount);
		}
		ui.add_space(8.0);

		let valid = amount_from_hr_string(&self.amount)
			.map(|a| a > 0)
			.unwrap_or(false);
		ui.add_enabled_ui(valid, |ui| {
			if w::big_action(ui, "Review", false).clicked() {
				if over {
					cb.vibrate_error();
				} else {
					self.stage = Stage::Review;
				}
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
		if self.back_header(
			ui,
			if self.request {
				"Confirm request"
			} else {
				"Review"
			},
		) {
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
				format!("Requesting from {}", recipient.name)
			} else {
				format!("You're sending {}", recipient.name)
			};
			// Centered avatar + caption. A long counterparty (a bare npub) wraps
			// and stays centered instead of overflowing the card.
			ui.vertical_centered(|ui| {
				w::avatar_any(ui, &recipient.name, 40.0, recipient.hue, hero_tex.as_ref());
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

		w::info_row(
			ui,
			if self.request { "From" } else { "To" },
			&recipient.name,
		);
		if !self.note.trim().is_empty() {
			w::info_row(ui, "Note", &format!("\u{201C}{}\u{201D}", self.note.trim()));
		}
		if self.request {
			w::info_row(ui, "They pay", "Only if they approve");
			w::info_row(ui, "Delivery", "NIP-44 encrypted, over Nym");
		} else {
			w::info_row(ui, "Network fee", "Deducted from your balance");
			w::info_row(ui, "Privacy", "Mimblewimble + Nym");
			w::info_row(ui, "Delivery", "NIP-44 encrypted, over Nym");
		}
		ui.add_space(16.0);

		// Requests are not a spend: one tap sends the ask, no hold-to-confirm.
		if self.request {
			if w::big_action(ui, "Send request", false).clicked() {
				self.dispatch(wallet);
				self.stage = Stage::Sending;
			}
			ui.add_space(6.0);
			ui.vertical_centered(|ui| {
				ui.label(
					RichText::new("They'll get a request to approve")
						.font(FontId::new(12.0, fonts::regular()))
						.color(t.text_mute),
				);
			});
			return false;
		}

		if over {
			ui.vertical_centered(|ui| {
				ui.label(
					RichText::new("You don't have enough grin")
						.font(FontId::new(14.0, fonts::regular()))
						.color(t.neg),
				);
			});
			ui.add_space(8.0);
		}
		// Greyed out while over balance; the `&& !over` also refuses the send in
		// case the hold widget ignores the disabled state.
		ui.add_enabled_ui(!over, |ui| {
			if self.hold.ui(ui, "Hold to send") && !over {
				self.dispatch(wallet);
				self.stage = Stage::Sending;
			}
		});
		ui.add_space(6.0);
		ui.vertical_centered(|ui| {
			ui.label(
				RichText::new(if over {
					"Go back and lower the amount"
				} else {
					"Press and hold to confirm"
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
					"Requesting…"
				} else {
					"Sending…"
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
					.unwrap_or_else(|| "They".to_string());
				self.error = Some(format!(
					"{} isn't accepting requests. Ask them to send you grin instead.",
					who
				));
				self.stage = Stage::Failed;
			}
			crate::nostr::send_phase::FAILED => self.stage = Stage::Failed,
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
					"Couldn't request"
				} else {
					"Couldn't send"
				})
				.font(FontId::new(22.0, fonts::bold()))
				.color(t.text),
			);
			ui.add_space(6.0);
			ui.label(
				RichText::new(self.error.clone().unwrap_or_else(|| {
					if self.request {
						"We couldn't deliver the request. Ask them to send you grin instead."
							.to_string()
					} else {
						"The payment wasn't delivered. Your grin is safe — try again.".to_string()
					}
				}))
				.font(FontId::new(14.0, fonts::regular()))
				.color(t.text_dim),
			);
		});
		ui.add_space(24.0);
		if w::big_action(ui, "Try again", false).clicked() {
			self.dispatch(wallet);
			self.stage = Stage::Sending;
		}
		ui.add_space(10.0);
		if w::big_action(ui, "Close", true).clicked() {
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
				RichText::new(if self.request { "Requested" } else { "Sent" })
					.font(FontId::new(34.0, fonts::bold()))
					.color(t.accent_ink),
			);
			ui.add_space(8.0);
			ui.horizontal(|ui| {
				ui.spacing_mut().item_spacing.x = 0.0;
				let total_w = ui.available_width();
				ui.add_space(total_w / 2.0 - 60.0);
				ui.label(
					RichText::new(&self.amount)
						.font(FontId::new(40.0, fonts::mono_semibold()))
						.color(t.accent_ink),
				);
				ui.label(
					RichText::new(w::TSU)
						.font(FontId::new(20.0, fonts::medium()))
						.color(t.accent_ink),
				);
			});
			ui.add_space(8.0);
			ui.label(
				RichText::new(format!(
					"{} {} · just now",
					if self.request { "from" } else { "to" },
					recipient.name
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
				"Done",
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
					"Receipt",
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
