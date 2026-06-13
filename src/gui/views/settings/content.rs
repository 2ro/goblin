// Copyright 2025 The Grim Developers
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

use crate::AppConfig;
use crate::gui::Colors;
use crate::gui::icons::{DATABASE, FADERS, GLOBE_SIMPLE, POWER};
use crate::gui::platform::PlatformCallbacks;
use crate::gui::views::network::NetworkContent;
use crate::gui::views::settings::{InterfaceSettingsContent, NetworkSettingsContent};
use crate::gui::views::types::ContentContainer;
use crate::gui::views::{Content, View};
use crate::node::Node;

/// Application settings content.
pub struct SettingsContent {
	/// User interface settings.
	interface_settings: InterfaceSettingsContent,
	/// Network communication settings.
	network_settings: NetworkSettingsContent,
	// tor_settings: TorSettingsContent,
}

impl Default for SettingsContent {
	fn default() -> Self {
		Self {
			interface_settings: InterfaceSettingsContent::default(),
			network_settings: NetworkSettingsContent::default(),
			//tor_settings: TorSettingsContent::default(),
		}
	}
}

impl SettingsContent {
	/// Draw application settings content.
	pub fn ui(&mut self, ui: &mut egui::Ui, cb: &dyn PlatformCallbacks) {
		ui.add_space(5.0);
		View::checkbox(ui, AppConfig::check_updates(), t!("check_updates"), || {
			AppConfig::toggle_check_updates();
		});
		ui.add_space(6.0);
		View::horizontal_line(ui, Colors::stroke());

		// Show interface settings.
		self.interface_settings.ui(ui, cb);

		ui.add_space(8.0);
		View::horizontal_line(ui, Colors::stroke());
		ui.add_space(6.0);

		View::sub_title(ui, format!("{} {}", GLOBE_SIMPLE, t!("network.self")));
		View::horizontal_line(ui, Colors::stroke());
		ui.add_space(6.0);

		// Show network settings.
		self.network_settings.ui(ui, cb);
		ui.add_space(8.0);

		// Integrated node — relocated here from the wallet-list chip so the
		// list stays uncluttered. Quick status + enable/autorun, plus a button
		// into the full node panel (stats, mining, tuning, recovery).
		View::horizontal_line(ui, Colors::stroke());
		ui.add_space(6.0);
		View::sub_title(ui, format!("{} {}", DATABASE, t!("network.node")));
		View::horizontal_line(ui, Colors::stroke());
		ui.add_space(8.0);

		let running = Node::is_running();
		let (status_color, status_text) = if !running {
			(Colors::gray(), "Disabled")
		} else if Node::not_syncing() {
			(Colors::pos(), "Running · synced")
		} else {
			(Colors::gold(), "Running · syncing…")
		};
		ui.vertical_centered(|ui| {
			ui.label(
				egui::RichText::new(status_text)
					.size(15.0)
					.color(status_color),
			);
		});
		ui.add_space(8.0);

		if !running {
			View::action_button(
				ui,
				format!("{} {}", POWER, t!("network.enable_node")),
				|| {
					Node::start();
				},
			);
			ui.add_space(4.0);
		}
		NetworkContent::autorun_node_ui(ui);
		ui.add_space(8.0);
		View::action_button(ui, format!("{} {}", FADERS, t!("network.settings")), || {
			if !Content::is_network_panel_open() {
				Content::toggle_network_panel();
			}
		});
		ui.add_space(8.0);

		// Do not show Tor settings on Android.
		// let os = OperatingSystem::from_target_os();
		// let show_tor = os != OperatingSystem::Android;
		// if show_tor {
		//     View::horizontal_line(ui, Colors::stroke());
		//     ui.add_space(6.0);
		//
		//     View::sub_title(ui, format!("{} {}", CIRCLE_HALF, t!("transport.tor_network")));
		//     View::horizontal_line(ui, Colors::stroke());
		//     ui.add_space(6.0);
		//
		//     // Show Tor settings.
		//     self.tor_settings.ui(ui, cb);
		//     ui.add_space(8.0);
		// }
	}
}
