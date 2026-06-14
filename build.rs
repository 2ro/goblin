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
			.args(&["/C", &git_hooks])
			.output()
			.expect("failed to execute git config for hooks");
	} else {
		Command::new("sh")
			.args(&["-c", &git_hooks])
			.output()
			.expect("failed to execute git config for hooks");
	}

	// Goblin routes all traffic over the Nym mixnet via a bundled
	// `nym-socks5-client` sidecar (see src/nym/); there is no embedded Tor and
	// thus no webtunnel pluggable-transport binary to build here anymore.
}
