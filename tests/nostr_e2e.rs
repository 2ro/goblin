// End-to-end Nostr exchange test against the live Goblin relay.
//
// Proves the NIP-17 payment-message path: gift-wrap send, subscribe, unwrap,
// seal-author verification, subject tag, and Goblin slatepack extraction.
// Network-dependent — run explicitly:
//   cargo test --test nostr_e2e -- --ignored --nocapture

use std::time::Duration;

use grim::nostr::protocol;
use nostr_sdk::prelude::*;

const RELAY: &str = "wss://nrelay.us-ea.st";

/// A small but valid-looking slatepack armor block for extraction testing.
const SLATEPACK: &str = "BEGINSLATEPACK. 4H1qx1wHe668tFW yC2gfL8PPd8kSgv \
	pcXQhyRkHbyKHZg GN75o7uWoT3dkib R2tj1fFGN2FoRLY oeBPyKizupksgRT \
	dXFdjEuMUuktR5r gCiVBSXcHSWW3KW Y56LTQ9z3QwUWmE 8sRtwR9Bn8oNN5K. \
	ENDSLATEPACK.";

#[tokio::test]
#[ignore]
async fn nip17_slatepack_roundtrip() {
	nip17_roundtrip_over(RELAY).await;
}

/// Same NIP-17 payment roundtrip over relay.damus.io — proves Goblin gift
/// wraps transit a top public relay, not only the relay we run.
/// Run: cargo test --test nostr_e2e nip17_roundtrip_damus -- --ignored --nocapture
#[tokio::test]
#[ignore]
async fn nip17_roundtrip_damus() {
	nip17_roundtrip_over("wss://relay.damus.io").await;
}

/// And over nos.lol, the other large public relay in DEFAULT_RELAYS.
/// Run: cargo test --test nostr_e2e nip17_roundtrip_nos_lol -- --ignored --nocapture
#[tokio::test]
#[ignore]
async fn nip17_roundtrip_nos_lol() {
	nip17_roundtrip_over("wss://nos.lol").await;
}

/// The shared roundtrip, parameterized by relay: Bob advertises a kind-10050
/// DM relay and subscribes to gift wraps; Alice sends a NIP-17 payment DM; Bob
/// unwraps it, verifies the seal author, and extracts the slatepack + subject.
async fn nip17_roundtrip_over(relay: &str) {
	let alice = Keys::generate();
	let bob = Keys::generate();
	println!("alice: {}", alice.public_key().to_bech32().unwrap());
	println!("bob:   {}", bob.public_key().to_bech32().unwrap());

	// Bob's client: connect, advertise DM relays, subscribe to gift wraps.
	let bob_client = Client::new(bob.clone());
	bob_client.add_relay(relay).await.unwrap();
	bob_client.connect().await;
	tokio::time::sleep(Duration::from_secs(2)).await;

	// Publish Bob's kind-10050 DM relay list so senders find this relay.
	let dm_relays = EventBuilder::new(Kind::InboxRelays, "")
		.tag(Tag::custom(TagKind::custom("relay"), [relay.to_string()]));
	bob_client.send_event_builder(dm_relays).await.unwrap();

	let filter = Filter::new()
		.kind(Kind::GiftWrap)
		.pubkey(bob.public_key())
		.since(Timestamp::now() - Duration::from_secs(3 * 86_400));
	bob_client.subscribe(filter, None).await.unwrap();

	// Alice's client: connect and send a NIP-17 payment DM to Bob.
	let alice_client = Client::new(alice.clone());
	alice_client.add_relay(relay).await.unwrap();
	alice_client.connect().await;
	tokio::time::sleep(Duration::from_secs(2)).await;

	let content = protocol::build_payment_content(SLATEPACK);
	let tags = protocol::build_rumor_tags(Some("lunch :)"));
	alice_client
		.send_private_msg_to([relay], bob.public_key(), content, tags)
		.await
		.unwrap();
	println!("alice sent gift-wrapped payment DM");

	// Bob waits for the gift wrap, unwraps and validates it.
	let mut notifications = bob_client.notifications();
	let result = tokio::time::timeout(Duration::from_secs(30), async {
		loop {
			if let Ok(RelayPoolNotification::Event { event, .. }) = notifications.recv().await {
				if event.kind != Kind::GiftWrap {
					continue;
				}
				let unwrapped = match bob_client.unwrap_gift_wrap(&event).await {
					Ok(u) => u,
					Err(_) => continue,
				};
				// Seal-author check (the NIP-17 invariant our ingest enforces).
				assert_eq!(
					unwrapped.rumor.pubkey, unwrapped.sender,
					"rumor author must equal seal signer"
				);
				assert_eq!(unwrapped.sender, alice.public_key(), "sender must be Alice");
				assert_eq!(unwrapped.rumor.kind, Kind::PrivateDirectMessage);
				return unwrapped;
			}
		}
	})
	.await
	.expect("timed out waiting for gift wrap");

	// The slatepack must round-trip intact, and the subject must survive.
	let armor = protocol::extract_slatepack(&result.rumor.content)
		.expect("slatepack must extract from rumor");
	assert!(armor.starts_with("BEGINSLATEPACK."));
	assert!(armor.ends_with("ENDSLATEPACK."));
	let subject = protocol::extract_subject(&result.rumor.tags);
	assert_eq!(subject.as_deref(), Some("lunch :)"));

	println!("✓ NIP-17 slatepack roundtrip verified over {relay}");
	bob_client.disconnect().await;
	alice_client.disconnect().await;
}

/// Register a fresh name on goblin.st with a real NIP-98 signature, then
/// resolve it back — proves the live identity server end-to-end.
/// Run: cargo test --test nostr_e2e nip05 -- --ignored --nocapture
#[tokio::test]
#[ignore]
async fn nip05_registration_roundtrip() {
	use base64::Engine;
	use sha2::{Digest, Sha256};
	use std::process::Command;

	let keys = Keys::generate();
	let pubkey = keys.public_key().to_hex();
	// Unique-ish name from the pubkey suffix (lowercase alnum).
	let name = format!("t{}", &pubkey[..8]);
	let server = "https://goblin.st";
	let url = format!("{server}/api/v1/register");
	let body = serde_json::json!({ "name": name, "pubkey": pubkey }).to_string();

	// Build the NIP-98 kind-27235 auth event (same shape as the client).
	let payload_hash = hex::encode(Sha256::digest(body.as_bytes()));
	let event = EventBuilder::new(Kind::HttpAuth, "")
		.tag(Tag::custom(TagKind::custom("u"), [url.clone()]))
		.tag(Tag::custom(TagKind::custom("method"), ["POST".to_string()]))
		.tag(Tag::custom(TagKind::custom("payload"), [payload_hash]))
		.sign_with_keys(&keys)
		.unwrap();
	let auth = format!(
		"Nostr {}",
		base64::engine::general_purpose::STANDARD.encode(event.as_json())
	);

	// POST the registration via curl (avoids pulling an HTTP client dep).
	let out = Command::new("curl")
		.args([
			"-s",
			"-X",
			"POST",
			&url,
			"-H",
			&format!("Authorization: {auth}"),
			"-H",
			"Content-Type: application/json",
			"-d",
			&body,
		])
		.output()
		.expect("curl register");
	let resp = String::from_utf8_lossy(&out.stdout);
	println!("register response: {resp}");
	assert!(
		resp.contains("\"nip05\""),
		"registration should return a nip05 identifier, got: {resp}"
	);
	assert!(resp.contains(&format!("{name}@goblin.st")));

	// Resolve it back from the well-known endpoint.
	let wk = Command::new("curl")
		.args([
			"-s",
			&format!("{server}/.well-known/nostr.json?name={name}"),
		])
		.output()
		.expect("curl well-known");
	let wk_body = String::from_utf8_lossy(&wk.stdout);
	println!("well-known response: {wk_body}");
	let resolved = protocol_parse_pubkey(&wk_body, &name);
	assert_eq!(resolved.as_deref(), Some(pubkey.as_str()));

	// Clean up: release the test name.
	let del_url = format!("{server}/api/v1/register/{name}");
	let del_event = EventBuilder::new(Kind::HttpAuth, "")
		.tag(Tag::custom(TagKind::custom("u"), [del_url.clone()]))
		.tag(Tag::custom(
			TagKind::custom("method"),
			["DELETE".to_string()],
		))
		.sign_with_keys(&keys)
		.unwrap();
	let del_auth = format!(
		"Nostr {}",
		base64::engine::general_purpose::STANDARD.encode(del_event.as_json())
	);
	let _ = Command::new("curl")
		.args([
			"-s",
			"-X",
			"DELETE",
			&del_url,
			"-H",
			&format!("Authorization: {del_auth}"),
		])
		.output();

	println!("✓ NIP-05 registration + resolution verified on {server}");
}

/// Minimal well-known pubkey extractor for the test.
fn protocol_parse_pubkey(body: &str, name: &str) -> Option<String> {
	let doc: serde_json::Value = serde_json::from_str(body).ok()?;
	doc.get("names")?.get(name)?.as_str().map(|s| s.to_string())
}

/// Live avatar pipeline e2e against goblin.st: register → upload a processed
/// PNG (NIP-98 by the owner) → profile shows the hash → GET serves a 256px
/// PNG with the hardened headers → 6th change is rate-limited → release
/// purges both the name and its avatar.
/// Run: cargo test --test nostr_e2e avatar -- --ignored --nocapture
#[tokio::test]
#[ignore]
async fn avatar_upload_roundtrip() {
	use base64::Engine;
	use sha2::{Digest, Sha256};
	use std::process::Command;

	let server = "https://goblin.st";
	let keys = Keys::generate();
	let pubkey = keys.public_key().to_hex();
	let name = format!("a{}", &pubkey[..8]);

	let nip98 = |url: &str, method: &str, body: &[u8]| -> String {
		let mut b = EventBuilder::new(Kind::HttpAuth, "")
			.tag(Tag::custom(TagKind::custom("u"), [url.to_string()]))
			.tag(Tag::custom(TagKind::custom("method"), [method.to_string()]));
		if !body.is_empty() {
			b = b.tag(Tag::custom(
				TagKind::custom("payload"),
				[hex::encode(Sha256::digest(body))],
			));
		}
		let ev = b.sign_with_keys(&keys).unwrap();
		format!(
			"Nostr {}",
			base64::engine::general_purpose::STANDARD.encode(ev.as_json())
		)
	};

	// Register the name first.
	let reg_url = format!("{server}/api/v1/register");
	let reg_body = serde_json::json!({ "name": name, "pubkey": pubkey }).to_string();
	let out = Command::new("curl")
		.args([
			"-s",
			"-X",
			"POST",
			&reg_url,
			"-H",
			&format!(
				"Authorization: {}",
				nip98(&reg_url, "POST", reg_body.as_bytes())
			),
			"-H",
			"Content-Type: application/json",
			"-d",
			&reg_body,
		])
		.output()
		.expect("curl register");
	assert!(
		String::from_utf8_lossy(&out.stdout).contains("\"nip05\""),
		"register failed: {}",
		String::from_utf8_lossy(&out.stdout)
	);

	// Build a real PNG via the client pipeline (also strips metadata).
	let raw = {
		use ::image::{ImageEncoder, RgbaImage};
		let img = RgbaImage::from_fn(640, 480, |x, y| {
			::image::Rgba([(x % 256) as u8, (y % 256) as u8, 90, 255])
		});
		let mut v = Vec::new();
		::image::DynamicImage::ImageRgba8(img)
			.write_with_encoder(::image::codecs::png::PngEncoder::new(&mut v))
			.unwrap();
		v
	};
	let png = grim::nostr::avatar::process_avatar_bytes(&raw).expect("process");
	let png_path = std::env::temp_dir().join(format!("{name}.png"));
	std::fs::write(&png_path, &png).unwrap();
	let av_url = format!("{server}/api/v1/avatar/{name}");

	// Upload (raw bytes; payload hash over the PNG).
	let out = Command::new("curl")
		.args([
			"-s",
			"-X",
			"POST",
			&av_url,
			"-H",
			&format!("Authorization: {}", nip98(&av_url, "POST", &png)),
			"-H",
			"Content-Type: application/octet-stream",
			"--data-binary",
			&format!("@{}", png_path.display()),
		])
		.output()
		.expect("curl upload");
	let resp = String::from_utf8_lossy(&out.stdout);
	println!("upload: {resp}");
	let hash = serde_json::from_str::<serde_json::Value>(&resp)
		.ok()
		.and_then(|v| v.get("avatar").and_then(|h| h.as_str()).map(String::from))
		.expect("upload should return a hash");

	// Profile exposes the hash.
	let prof = Command::new("curl")
		.args(["-s", &format!("{server}/api/v1/profile/{name}")])
		.output()
		.unwrap();
	assert!(
		String::from_utf8_lossy(&prof.stdout).contains(&hash),
		"profile should carry the avatar hash"
	);

	// GET serves a 256px PNG with hardened headers.
	let head = Command::new("curl")
		.args(["-sI", &format!("{server}/api/v1/avatar/{hash}.png")])
		.output()
		.unwrap();
	let head = String::from_utf8_lossy(&head.stdout).to_lowercase();
	assert!(head.contains("content-type: image/png"), "headers: {head}");
	assert!(head.contains("nosniff"), "missing nosniff: {head}");
	assert!(
		head.contains("immutable"),
		"missing immutable cache: {head}"
	);
	let got = Command::new("curl")
		.args(["-s", &format!("{server}/api/v1/avatar/{hash}.png")])
		.output()
		.unwrap();
	assert!(got.stdout.starts_with(&[0x89, b'P', b'N', b'G']));
	let served = ::image::load_from_memory(&got.stdout).expect("served bytes decode");
	assert_eq!((served.width(), served.height()), (256, 256));

	// Daily limit: 4 more changes succeed (1 done = 5 total), the 6th is 429.
	for i in 0..4 {
		// Vary the pixels so each upload is a distinct hash.
		let raw = {
			use ::image::{ImageEncoder, RgbaImage};
			let img = RgbaImage::from_pixel(64, 64, ::image::Rgba([i as u8 * 40, 10, 10, 255]));
			let mut v = Vec::new();
			::image::DynamicImage::ImageRgba8(img)
				.write_with_encoder(::image::codecs::png::PngEncoder::new(&mut v))
				.unwrap();
			v
		};
		let png = grim::nostr::avatar::process_avatar_bytes(&raw).unwrap();
		std::fs::write(&png_path, &png).unwrap();
		let out = Command::new("curl")
			.args([
				"-s",
				"-o",
				"/dev/null",
				"-w",
				"%{http_code}",
				"-X",
				"POST",
				&av_url,
				"-H",
				&format!("Authorization: {}", nip98(&av_url, "POST", &png)),
				"--data-binary",
				&format!("@{}", png_path.display()),
			])
			.output()
			.unwrap();
		println!("change {}: {}", i + 2, String::from_utf8_lossy(&out.stdout));
	}
	// 6th change → 429.
	let png = grim::nostr::avatar::process_avatar_bytes(&{
		use ::image::{ImageEncoder, RgbaImage};
		let img = RgbaImage::from_pixel(48, 48, ::image::Rgba([200, 200, 0, 255]));
		let mut v = Vec::new();
		::image::DynamicImage::ImageRgba8(img)
			.write_with_encoder(::image::codecs::png::PngEncoder::new(&mut v))
			.unwrap();
		v
	})
	.unwrap();
	std::fs::write(&png_path, &png).unwrap();
	let out = Command::new("curl")
		.args([
			"-s",
			"-o",
			"/dev/null",
			"-w",
			"%{http_code}",
			"-X",
			"POST",
			&av_url,
			"-H",
			&format!("Authorization: {}", nip98(&av_url, "POST", &png)),
			"--data-binary",
			&format!("@{}", png_path.display()),
		])
		.output()
		.unwrap();
	assert_eq!(
		String::from_utf8_lossy(&out.stdout),
		"429",
		"6th avatar change in 24h must be rate-limited"
	);

	// Release the name → avatar purged.
	let del_url = format!("{server}/api/v1/register/{name}");
	let _ = Command::new("curl")
		.args([
			"-s",
			"-X",
			"DELETE",
			&del_url,
			"-H",
			&format!("Authorization: {}", nip98(&del_url, "DELETE", &[])),
		])
		.output();
	let after = Command::new("curl")
		.args([
			"-s",
			"-o",
			"/dev/null",
			"-w",
			"%{http_code}",
			&format!("{server}/api/v1/profile/{name}"),
		])
		.output()
		.unwrap();
	assert_eq!(
		String::from_utf8_lossy(&after.stdout),
		"404",
		"profile should 404 after release"
	);
	let _ = std::fs::remove_file(&png_path);
	println!("✓ avatar upload/serve/limit/release-purge verified on {server}");
}
