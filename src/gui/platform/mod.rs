// Copyright 2023 The Grim Developers
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

pub use self::platform::*;

#[cfg(target_os = "android")]
#[path = "android/mod.rs"]
pub mod platform;
#[cfg(not(target_os = "android"))]
#[path = "desktop/mod.rs"]
pub mod platform;

pub trait PlatformCallbacks {
	fn set_context(&mut self, ctx: &egui::Context);
	fn exit(&self);
	fn copy_string_to_buffer(&self, data: String);
	fn get_string_from_buffer(&self) -> String;
	fn start_camera(&self);
	fn stop_camera(&self);
	fn camera_image(&self) -> Option<(Vec<u8>, u32)>;
	fn can_switch_camera(&self) -> bool;
	fn switch_camera(&self);
	fn share_data(&self, name: String, data: Vec<u8>) -> Result<(), std::io::Error>;

	/// Save bytes to a user-chosen location on the device (a "save as" dialog).
	/// Desktop already does this via `share_data` (rfd save dialog); Android
	/// overrides to use the Storage Access Framework (ACTION_CREATE_DOCUMENT)
	/// instead of the share sheet.
	fn save_file(&self, name: String, data: Vec<u8>) -> Result<(), std::io::Error> {
		self.share_data(name, data)
	}
	/// Share plain text via the platform's native share sheet (e.g. a payment
	/// link). Defaults to copying to the clipboard on platforms without a share
	/// sheet (desktop).
	fn share_text(&self, text: String) {
		self.copy_string_to_buffer(text);
	}
	fn pick_file(&self) -> Option<String>;
	/// Native picker filtered to picture files; defaults to the plain picker
	/// on platforms without filter support (magic-byte sniffing protects).
	fn pick_image_file(&self) -> Option<String> {
		self.pick_file()
	}
	fn pick_folder(&self) -> Option<String>;
	fn picked_file(&self) -> Option<String>;
	fn request_user_attention(&self);
	fn user_attention_required(&self) -> bool;
	fn clear_user_attention(&self);

	/// Set the status-bar icon color to contrast the current theme. `white` =
	/// light icons (for a dark background). No-op off Android.
	fn set_status_bar_white_icons(&self, _white: bool) {}

	/// Play a short "error" haptic (e.g. a rejected over-balance payment).
	/// No-op off Android.
	fn vibrate_error(&self) {}

	/// Play a tiny "tick" haptic confirming a successful copy. No-op off Android.
	fn vibrate_copy(&self) {}
}
