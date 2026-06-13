use base64::Engine;
use nostr_sdk::prelude::*;
use sha2::{Digest, Sha256};
use std::process::Command;

#[tokio::test]
#[ignore]
async fn replay_and_double_name_rejected() {
	let keys = Keys::generate();
	let pk = keys.public_key().to_hex();
	let server = "https://goblin.st";

	// Build a register POST for name A.
	let name_a = format!("r{}", &pk[..7]);
	let url = format!("{server}/api/v1/register");
	let body = serde_json::json!({"name": name_a, "pubkey": pk}).to_string();
	let ph = hex::encode(Sha256::digest(body.as_bytes()));
	let ev = EventBuilder::new(Kind::HttpAuth, "")
		.tag(Tag::custom(TagKind::custom("u"), [url.clone()]))
		.tag(Tag::custom(TagKind::custom("method"), ["POST".to_string()]))
		.tag(Tag::custom(TagKind::custom("payload"), [ph]))
		.sign_with_keys(&keys)
		.unwrap();
	let auth = format!(
		"Nostr {}",
		base64::engine::general_purpose::STANDARD.encode(ev.as_json())
	);
	let post = |a: &str, b: &str| {
		String::from_utf8_lossy(
			&Command::new("curl")
				.args([
					"-s",
					"-X",
					"POST",
					&url,
					"-H",
					&format!("Authorization: {a}"),
					"-H",
					"Content-Type: application/json",
					"-d",
					b,
				])
				.output()
				.unwrap()
				.stdout,
		)
		.to_string()
	};
	let r1 = post(&auth, &body);
	let r2 = post(&auth, &body); // exact replay (same auth event id)
	println!("first:  {r1}");
	println!("replay: {r2}");
	assert!(r1.contains("nip05"), "first register should succeed");
	assert!(
		r2.contains("replayed"),
		"replay should be rejected, got: {r2}"
	);

	// Second DISTINCT name with a FRESH signature but same pubkey -> blocked.
	// Two protections can fire here: the per-pubkey name-change cooldown (one
	// change per 10 min, which the just-completed register of name_a triggers)
	// and the one-active-name-per-pubkey rule. The cooldown is checked first, so
	// within 10 min of a successful register a same-pubkey second register is
	// rejected with name_change_cooldown; either rejection is a valid block.
	let name_b = format!("s{}", &pk[..7]);
	let body_b = serde_json::json!({"name": name_b, "pubkey": pk}).to_string();
	let ph_b = hex::encode(Sha256::digest(body_b.as_bytes()));
	let ev_b = EventBuilder::new(Kind::HttpAuth, "")
		.tag(Tag::custom(TagKind::custom("u"), [url.clone()]))
		.tag(Tag::custom(TagKind::custom("method"), ["POST".to_string()]))
		.tag(Tag::custom(TagKind::custom("payload"), [ph_b]))
		.sign_with_keys(&keys)
		.unwrap();
	let auth_b = format!(
		"Nostr {}",
		base64::engine::general_purpose::STANDARD.encode(ev_b.as_json())
	);
	let r3 = post(&auth_b, &body_b);
	println!("2nd name: {r3}");
	assert!(
		r3.contains("already has a name")
			|| r3.contains("pubkey already")
			|| r3.contains("name_change_cooldown"),
		"a same-pubkey second name should be blocked (one-name rule or cooldown), got: {r3}"
	);

	// Cleanup name A.
	let del_url = format!("{server}/api/v1/register/{name_a}");
	let ev_d = EventBuilder::new(Kind::HttpAuth, "")
		.tag(Tag::custom(TagKind::custom("u"), [del_url.clone()]))
		.tag(Tag::custom(
			TagKind::custom("method"),
			["DELETE".to_string()],
		))
		.sign_with_keys(&keys)
		.unwrap();
	let auth_d = format!(
		"Nostr {}",
		base64::engine::general_purpose::STANDARD.encode(ev_d.as_json())
	);
	let _ = Command::new("curl")
		.args([
			"-s",
			"-X",
			"DELETE",
			&del_url,
			"-H",
			&format!("Authorization: {auth_d}"),
		])
		.output();
	println!("✓ replay + one-name-per-pubkey enforced");
}
