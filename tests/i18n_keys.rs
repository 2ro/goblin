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

//! Localization drift guard. en.yml is the source of truth: every `goblin.*`
//! key (and its `%{...}` interpolation placeholders) must exist, identically,
//! in every other locale, so the language picker never falls back to a raw key
//! or a string that drops a value. Fails CI the moment a translation lags.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// The locales shipped alongside English.
const OTHER_LOCALES: &[&str] = &["de", "fr", "ru", "tr", "zh-CN"];

/// Flatten a YAML mapping into dotted leaf keys → string value.
fn flatten(value: &serde_yaml::Value, prefix: &str, out: &mut BTreeMap<String, String>) {
	match value {
		serde_yaml::Value::Mapping(map) => {
			for (k, v) in map {
				let key = k.as_str().unwrap_or_default();
				let next = if prefix.is_empty() {
					key.to_string()
				} else {
					format!("{prefix}.{key}")
				};
				flatten(v, &next, out);
			}
		}
		other => {
			let s = match other {
				serde_yaml::Value::String(s) => s.clone(),
				serde_yaml::Value::Bool(b) => b.to_string(),
				serde_yaml::Value::Number(n) => n.to_string(),
				_ => String::new(),
			};
			out.insert(prefix.to_string(), s);
		}
	}
}

/// Load a locale file flattened to `goblin.*` keys only.
fn load_goblin(locale: &str) -> BTreeMap<String, String> {
	let path = Path::new(env!("CARGO_MANIFEST_DIR"))
		.join("locales")
		.join(format!("{locale}.yml"));
	let text = std::fs::read_to_string(&path)
		.unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
	let doc: serde_yaml::Value =
		serde_yaml::from_str(&text).unwrap_or_else(|e| panic!("invalid YAML in {locale}.yml: {e}"));
	let mut all = BTreeMap::new();
	flatten(&doc, "", &mut all);
	all.into_iter()
		.filter(|(k, _)| k.starts_with("goblin."))
		.collect()
}

/// `%{name}` placeholders contained in a value, sorted.
fn placeholders(s: &str) -> BTreeSet<String> {
	let mut out = BTreeSet::new();
	let bytes = s.as_bytes();
	let mut i = 0;
	while i + 1 < bytes.len() {
		if bytes[i] == b'%' && bytes[i + 1] == b'{' {
			if let Some(end) = s[i..].find('}') {
				out.insert(s[i..i + end + 1].to_string());
				i += end + 1;
				continue;
			}
		}
		i += 1;
	}
	out
}

#[test]
fn every_locale_has_all_goblin_keys() {
	let en = load_goblin("en");
	assert!(
		en.len() > 300,
		"en.yml goblin block looks too small ({} keys) — did it load?",
		en.len()
	);
	let en_keys: BTreeSet<&String> = en.keys().collect();

	let mut problems = Vec::new();
	for &loc in OTHER_LOCALES {
		let other = load_goblin(loc);
		let other_keys: BTreeSet<&String> = other.keys().collect();
		for missing in en_keys.difference(&other_keys) {
			problems.push(format!("{loc}: MISSING key {missing}"));
		}
		for extra in other_keys.difference(&en_keys) {
			problems.push(format!("{loc}: EXTRA key {extra} (not in en.yml)"));
		}
		// Placeholder parity: a translation must carry the same %{...} args.
		for (k, en_val) in &en {
			if let Some(other_val) = other.get(k) {
				if placeholders(en_val) != placeholders(other_val) {
					problems.push(format!(
						"{loc}: placeholder mismatch in {k} (en {:?} vs {:?})",
						placeholders(en_val),
						placeholders(other_val)
					));
				}
			}
		}
	}

	assert!(
		problems.is_empty(),
		"localization drift detected:\n{}",
		problems.join("\n")
	);
}

/// Every `t!("literal.key")` in the source must resolve to a key present in
/// en.yml. Guards against raw-key leaks (a call site typing a key that was
/// never added, or renamed out from under it) that render the dotted key
/// verbatim in the UI. The cross-locale check above only compares locale files
/// to each other; it cannot see the call sites.
#[test]
fn every_t_call_site_key_exists_in_en() {
	// Full en.yml, all namespaces (t! is used for goblin.*, wallets.*, network.*, …).
	let path = Path::new(env!("CARGO_MANIFEST_DIR"))
		.join("locales")
		.join("en.yml");
	let text = std::fs::read_to_string(&path)
		.unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
	let doc: serde_yaml::Value = serde_yaml::from_str(&text).expect("invalid YAML in en.yml");
	let mut en = BTreeMap::new();
	flatten(&doc, "", &mut en);
	let en_keys: BTreeSet<&String> = en.keys().collect();

	// A localization key: dotted, lowercase-ish namespace segments. This filters
	// out format strings, URIs, and other literals that happen to sit in a t! arg
	// position but are not keys (there are none today, but keep the guard honest).
	fn is_key_like(s: &str) -> bool {
		s.contains('.')
			&& s.bytes()
				.all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_')
			&& s.split('.').all(|seg| {
				!seg.is_empty()
					&& seg
						.bytes()
						.next()
						.map_or(false, |b| b.is_ascii_alphabetic())
			})
	}

	// Walk src/ collecting t!("…") literal keys with their location.
	fn walk(dir: &Path, out: &mut Vec<(String, String, usize)>) {
		let entries = match std::fs::read_dir(dir) {
			Ok(e) => e,
			Err(_) => return,
		};
		for entry in entries.flatten() {
			let p = entry.path();
			if p.is_dir() {
				walk(&p, out);
			} else if p.extension().and_then(|e| e.to_str()) == Some("rs") {
				let Ok(src) = std::fs::read_to_string(&p) else {
					continue;
				};
				for (lineno, line) in src.lines().enumerate() {
					collect_line(line, &p.display().to_string(), lineno + 1, out);
				}
			}
		}
	}

	// Find `t!("key"` occurrences on a line, honoring a word boundary so we do
	// not match `format!("…")`, `print!("…")`, etc.
	fn collect_line(line: &str, file: &str, lineno: usize, out: &mut Vec<(String, String, usize)>) {
		let bytes = line.as_bytes();
		let mut i = 0;
		while let Some(rel) = line[i..].find("t!(") {
			let start = i + rel;
			// word boundary before the `t`
			let boundary = start == 0
				|| !matches!(bytes[start - 1], b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_');
			let after = &line[start + 3..];
			let after_trim = after.trim_start();
			if boundary {
				if let Some(rest) = after_trim.strip_prefix('"') {
					if let Some(end) = rest.find('"') {
						out.push((rest[..end].to_string(), file.to_string(), lineno));
					}
				}
			}
			i = start + 3;
		}
	}

	let mut sites = Vec::new();
	walk(
		&Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
		&mut sites,
	);

	let mut leaks = Vec::new();
	for (key, file, lineno) in &sites {
		if is_key_like(key) && !en_keys.contains(key) {
			leaks.push(format!(
				"{file}:{lineno}: t!(\"{key}\") — key not in en.yml"
			));
		}
	}
	leaks.sort();
	leaks.dedup();

	assert!(
		leaks.is_empty(),
		"raw-key leak: {} t! call site(s) reference a key absent from en.yml:\n{}",
		leaks.len(),
		leaks.join("\n")
	);
}
