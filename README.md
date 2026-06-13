<p align="center">
  <img src="Goblin-Banner.png" alt="Goblin" width="680"/>
</p>

# Goblin

Goblin is a private, Cash App-style wallet for [GRIN ツ](https://grin.mw) — confidential digital cash on [Mimblewimble](https://github.com/mimblewimble/grin), with no amounts or addresses on the chain.

Instead of passing slatepack files back and forth, you **pay a `@username` (or an `npub`)** and the payment is delivered for you as an **end-to-end encrypted message over [nostr](https://github.com/nostr-protocol/nips) and Tor**. Relays only ever see ciphertext — never the amount, the sender, or the recipient.

Goblin is a fork of the **Grim** egui GRIN wallet: it keeps Grim's full GRIN node/wallet engine and layers a Nostr-native, mobile-first payments experience on top.

## What it does

- **Send to people** — pay a `@username` or `npub`; the GRIN slatepack travels as a NIP-17 gift-wrapped DM (kind 1059) over Tor and is applied automatically by the recipient's wallet. No files to swap, no need to both be online at once.
- **In-app identity** — a nostr payment key that is deliberately *not* part of your seed, so you can rotate it any time to stay unlinkable without touching your funds. An optional human-readable `@name` (and hosted avatar) comes from the goblin.st identity service.
- **Private by construction** — GRIN's address-less, confidential chain; every relay and HTTP request routed through an embedded [arti](https://gitlab.torproject.org/tpo/core/arti) Tor client (webtunnel bridge by default); keys, names and history stay on your device.
- **Configurable amount pairing** — show balances against a world currency, Bitcoin, or sats (rates fetched over Tor), or turn the preview off.
- **Cross-platform** — Linux, macOS, Windows, Android, built in pure Rust on [egui](https://github.com/emilk/egui).

## How a payment travels

```
   you ──slatepack──▶ NIP-17 gift wrap (kind 1059, NIP-44 encrypted)
                          │
                     arti / Tor
                          │
            ┌─────────────┴─────────────┐
        your relays              recipient's DM relays (kind 10050)
            └─────────────┬─────────────┘
                          ▼
   recipient ◀──unwrap, verify seal author, apply slatepack
```

Both parties only need one relay in common. The default set is the Goblin relay plus large public relays (`relay.damus.io`, `nos.lol`), and the set is editable in **Settings → Relays**.

## Build

### Desktop (Linux / macOS / Windows)

```
git submodule update --init --recursive
cargo build --release
./target/release/goblin
```

Tor's webtunnel bridge is built from Go at compile time — install Go first (e.g. `pacman -S go`). Without it the bundled bridge is inert and Tor will not bootstrap on networks that block direct Tor connections.

### Android

Install the Android SDK / NDK, then from the repo root:

```
./scripts/android.sh build|release v7|v8|x86
```

`v7`/`v8`/`x86` is the device CPU architecture for `build`; for `release` pass a version in `major.minor.patch` form.

## Identity service (`goblin-nip05d`)

The optional `@name` + avatar service lives in `goblin-nip05d/` (axum + SQLite) and is deployed at [goblin.st](https://goblin.st). It implements NIP-05 resolution, NIP-98-authenticated registration/transfer/release, and a hardened avatar pipeline (magic-byte sniffing, bounded decode, full re-encode to a clean 256×256 PNG). The wallet is fully usable — and fully anonymous — without it.

## License

Apache License v2.0.

## Credits

🤖 Built with AI pair-programming assistance (Claude)

The underlying cross-platform GRIN wallet engine is the upstream **Grim** project.
