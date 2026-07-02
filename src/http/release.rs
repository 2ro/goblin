// Copyright 2026 The Grim Developers
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

use crate::gui::views::View;
use crate::http::HttpClient;
use bytes::Bytes;
use chrono::NaiveDateTime;
use egui::os::OperatingSystem;
use http_body_util::{BodyExt, Empty};
use serde_derive::Deserialize;

#[derive(Deserialize)]
pub struct ReleaseAsset {
	pub name: String,
	pub browser_download_url: String,
	pub size: u64,
}

#[derive(Deserialize)]
pub struct ReleaseInfo {
	pub tag_name: String,
	pub body: String,
	pub published_at: String,
	pub assets: Vec<ReleaseAsset>,
}

#[cfg(target_arch = "x86_64")]
/// x86 CPU architecture.
const X86_ARCH: &str = "x86_64";
#[cfg(target_arch = "x86_64")]
const ARCH: &'static str = X86_ARCH;

/// ARM CPU architecture.
const ARM_ARCH: &str = "arm";
#[cfg(any(target_arch = "arm", target_arch = "aarch64"))]
const ARCH: &'static str = ARM_ARCH;

/// Base endpoint to download the release.
const BASE_DOWNLOAD_URL: &'static str = "https://github.com/2ro/goblin/releases/download/";

impl ReleaseInfo {
	/// Release version (the build tag, e.g. "build71").
	pub fn version(&self) -> String {
		self.tag_name.clone()
	}

	/// Get artifact release name based on current platform. Matches the assets
	/// attached to Goblin's GitHub releases; platforms Goblin doesn't ship
	/// (linux-arm, macOS, windows-arm) return None.
	fn name(&self) -> Option<String> {
		let os = OperatingSystem::from_target_os();
		match os {
			OperatingSystem::Unknown => None,
			OperatingSystem::Android => {
				let name = if ARCH == ARM_ARCH {
					format!("goblin-{}-android-arm.apk", self.tag_name)
				} else {
					format!("goblin-{}-android-x86_64.apk", self.tag_name)
				};
				Some(name)
			}
			OperatingSystem::IOS => None,
			OperatingSystem::Nix => {
				if ARCH == ARM_ARCH {
					None
				} else {
					Some(format!("goblin-{}-linux-x86_64.tar.gz", self.tag_name))
				}
			}
			OperatingSystem::Mac => None,
			OperatingSystem::Windows => {
				if ARCH == ARM_ARCH {
					None
				} else {
					Some(format!("goblin-{}-win-x86_64.zip", self.tag_name))
				}
			}
		}
	}

	/// Get link to download the release.
	pub fn url(&self) -> Option<String> {
		let base_url = format!("{}{}/", BASE_DOWNLOAD_URL, self.tag_name);
		if let Some(name) = self.name() {
			return Some(format!("{}{}", base_url, name));
		}
		None
	}

	/// Get formatted release date.
	pub fn date(&self) -> String {
		let date = self.published_at.clone().replace("T", " ").replace("Z", "");
		let date_format = NaiveDateTime::parse_from_str(date.as_str(), "%Y-%m-%d %H:%M:%S");
		if let Ok(date) = date_format {
			return View::format_time(date.and_utc().timestamp());
		}
		date
	}

	/// Get release size in megabytes.
	pub fn size(&self) -> Option<String> {
		let name = self.name()?;
		for a in &self.assets {
			if a.name == name {
				let size_mb = a.size as f64 / 1000000.0;
				return Some(format!("{:.2}", size_mb));
			}
		}
		None
	}

	/// Whether this release is newer than the running build. Goblin versions by
	/// build number ("buildNN" tags) rather than semver, so compare the numbers.
	pub fn is_update(&self) -> bool {
		let cur: u64 = crate::BUILD.trim().parse().unwrap_or(0);
		let rel: u64 = self
			.tag_name
			.trim()
			.trim_start_matches("build")
			.parse()
			.unwrap_or(0);
		rel > cur
	}
}

/// API endpoint to check last release (Goblin's own GitHub releases).
const REQUEST_URL: &'static str = "https://api.github.com/repos/2ro/goblin/releases/latest";

pub async fn retrieve_release() -> Result<ReleaseInfo, String> {
	let req = hyper::Request::builder()
		.method(hyper::Method::GET)
		.uri(REQUEST_URL)
		// GitHub's API rejects requests without a User-Agent.
		.header("User-Agent", "goblin-wallet")
		.header("Accept", "application/vnd.github+json")
		.body(Empty::<Bytes>::new())
		.unwrap();
	if let Ok(resp) = HttpClient::send(req).await {
		let status = resp.status().as_u16();
		if status == 200 {
			if let Ok(body) = resp.into_body().collect().await {
				let body_bytes = body.to_bytes();
				if let Ok(update_info) = serde_json::from_slice::<ReleaseInfo>(&body_bytes) {
					return Ok(update_info);
				}
			}
		}
	}
	Err("Error checking update".to_string())
}
