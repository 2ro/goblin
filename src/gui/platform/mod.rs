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

use std::sync::atomic::{AtomicBool, Ordering};

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
	/// Copy a SECRET (e.g. a revealed nsec) to the clipboard, then auto-clear it
	/// after a short delay so it does not linger there forever. The clear is
	/// compare-then-clear: it only wipes the clipboard if it STILL holds exactly
	/// this secret, so whatever the user copied since is never clobbered.
	/// Defaults to a plain copy on platforms without a timed clear.
	fn copy_secret_to_buffer(&self, data: String) {
		self.copy_string_to_buffer(data);
	}
	fn get_string_from_buffer(&self) -> String;
	fn start_camera(&self);
	fn stop_camera(&self);
	fn camera_image(&self) -> Option<(Vec<u8>, u32)>;
	fn can_switch_camera(&self) -> bool;
	fn switch_camera(&self);
	fn share_data(&self, name: String, data: Vec<u8>) -> Result<(), std::io::Error>;

	/// Save bytes to a user-chosen location on the device (a "save as" dialog:
	/// the rfd save dialog on desktop, the Storage Access Framework
	/// ACTION_CREATE_DOCUMENT picker on Android). Returns the final outcome, or
	/// `None` when it is only known later (Android: after the picker closes),
	/// in which case it arrives through [`Self::save_file_result`]. Only
	/// [`SaveResult::Saved`] means the file was written.
	fn save_file(&self, name: String, data: Vec<u8>) -> Option<SaveResult>;
	/// Take the outcome of a [`Self::save_file`] that returned `None`, once it
	/// is known. Each outcome is handed out once.
	fn save_file_result(&self) -> Option<SaveResult> {
		None
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

	/// Return the user to the app that deep-linked into Goblin (the same-device
	/// app-switch flow: a browser hands off a `goblin:login`/`goblin:authorize`
	/// URI, we sign, then hand focus back). On Android this backgrounds our task
	/// so the OS surfaces the previous app (the polling browser tab). Best-effort
	/// and a no-op off Android, where there is no clean "return focus" primitive
	/// (egui/winit); desktop leaves the window where it is.
	fn return_to_caller(&self) {}

	/// Keep the window out of screenshots, screen recordings and the app
	/// switcher thumbnail while `secure` is true, i.e. while a secret (seed
	/// words, nsec, nsec QR) is on screen. Callers may report the state every
	/// frame; only a change reaches the OS. No-op off Android.
	fn set_secure_screen(&self, _secure: bool) {}
}

/// Final outcome of a [`PlatformCallbacks::save_file`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveResult {
	/// The bytes were written to the location the user chose.
	Saved,
	/// The user closed the dialog without choosing a location.
	Cancelled,
	/// The file could not be written.
	Failed,
}

impl SaveResult {
	/// Map the code Java reports through `MainActivity.onFileSave` (0 cancelled,
	/// 1 saved). Any other code is a failure: an unknown code never reads as a
	/// saved file.
	pub fn from_code(code: i32) -> Self {
		match code {
			0 => SaveResult::Cancelled,
			1 => SaveResult::Saved,
			_ => SaveResult::Failed,
		}
	}
}

/// Record the wanted secure-screen state in `last` and return true when it
/// differs from the state recorded before, i.e. when the OS window flag must
/// change now. Views report the state every frame; this keeps the platform
/// call to the frames where it actually changes.
pub fn secure_screen_changed(last: &AtomicBool, secure: bool) -> bool {
	last.swap(secure, Ordering::Relaxed) != secure
}

#[cfg(test)]
mod tests {
	use super::*;

	/// Only a change of the wanted state is reported, so a view that reports
	/// "secret on screen" every frame causes one platform call, not one a frame.
	#[test]
	fn secure_screen_reports_only_changes() {
		let last = AtomicBool::new(false);
		// Starts off: reporting off again is no change.
		assert!(!secure_screen_changed(&last, false));
		// A secret appears: one change, then steady.
		assert!(secure_screen_changed(&last, true));
		assert!(!secure_screen_changed(&last, true));
		assert!(!secure_screen_changed(&last, true));
		// It leaves the screen: one change, then steady.
		assert!(secure_screen_changed(&last, false));
		assert!(!secure_screen_changed(&last, false));
	}

	/// Java's save outcome codes map to the right result, and nothing but the
	/// "saved" code reads as a saved file.
	#[test]
	fn save_result_from_java_code() {
		assert_eq!(SaveResult::from_code(0), SaveResult::Cancelled);
		assert_eq!(SaveResult::from_code(1), SaveResult::Saved);
		assert_eq!(SaveResult::from_code(2), SaveResult::Failed);
		for code in [-1, 3, 42, i32::MAX, i32::MIN] {
			assert_eq!(SaveResult::from_code(code), SaveResult::Failed);
		}
	}
}
