use std::env;
use std::path::PathBuf;
use std::process::Command;

/// The GRIM commit Goblin forked from; builds count commits on top of it.
const GOBLIN_FORK_BASE: &str = "b51a46b";

fn main() {
	built::write_built_file().expect("Failed to acquire build-time information");

	// Goblin versioning is build-based: Build N = commits since the fork.
	// An explicit GOBLIN_BUILD env wins (CI builds from the public single-commit
	// squash where the fork base isn't an ancestor, so the git count can't run);
	// otherwise count commits since the fork; "dev" only as a last resort.
	let build = env::var("GOBLIN_BUILD")
		.ok()
		.map(|s| s.trim().to_string())
		.filter(|s| !s.is_empty())
		.or_else(|| {
			Command::new("git")
				.args([
					"rev-list",
					"--count",
					&format!("{}..HEAD", GOBLIN_FORK_BASE),
				])
				.output()
				.ok()
				.filter(|o| o.status.success())
				.and_then(|o| String::from_utf8(o.stdout).ok())
				.map(|s| s.trim().to_string())
				.filter(|s| !s.is_empty())
		})
		.unwrap_or_else(|| "dev".to_string());
	println!("cargo:rustc-env=GOBLIN_BUILD={}", build);
	// .git/HEAD only changes on branch switches; the reflog is appended on
	// every commit, so the build number stays current.
	println!("cargo:rerun-if-changed=.git/HEAD");
	println!("cargo:rerun-if-changed=.git/logs/HEAD");
	println!("cargo:rerun-if-env-changed=GOBLIN_BUILD");

	// Setting up git hooks in the project: rustfmt and so on.
	let git_hooks = format!(
		"git config core.hooksPath {}",
		PathBuf::from("./.hooks").to_str().unwrap()
	);

	if cfg!(target_os = "windows") {
		Command::new("cmd")
			.args(["/C", &git_hooks])
			.output()
			.expect("failed to execute git config for hooks");
	} else {
		Command::new("sh")
			.args(["-c", &git_hooks])
			.output()
			.expect("failed to execute git config for hooks");
	}

	// Goblin links the Nym mixnet SDK in-process (see src/nym/) — no sidecar
	// subprocess, no bundled/embedded helper binary, and no Tor/webtunnel. There
	// is nothing transport-related to build or embed here.

	// Embed the Goblin icon into goblin.exe so Explorer, the taskbar and Alt-Tab
	// show it even for the bare exe (the .msi shortcuts already carry it). No-op
	// on every non-Windows platform.
	embed_windows_icon();
}

/// Embed `wix/Product.ico` (the yellow Goblin icon) as goblin.exe's application
/// icon resource. Gated to Windows hosts — that's where the `winresource`
/// build-dependency is compiled and where the MSVC resource compiler (`rc.exe`,
/// shipped on the windows-latest runner) is available; our Windows builds are
/// always native MSVC, so host == target == windows.
#[cfg(windows)]
fn embed_windows_icon() {
	if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
		return;
	}
	let mut res = winresource::WindowsResource::new();
	res.set_icon("wix/Product.ico");
	if let Err(e) = res.compile() {
		// Don't fail the build over the icon — just flag it.
		println!("cargo:warning=winresource icon embed failed: {e}");
	}
}

#[cfg(not(windows))]
fn embed_windows_icon() {}
