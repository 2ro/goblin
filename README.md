<p align="center">
  <img src="Goblin-Banner.png" alt="Goblin" width="680"/>
</p>

# Goblin

Goblin is a private, Cash App-style wallet for [GRIN ツ](https://grin.mw) — confidential digital cash on [Mimblewimble](https://github.com/mimblewimble/grin), with no amounts or addresses on the chain.

Instead of passing slatepack files back and forth, you **pay a `@username` (or an `npub`)** and the payment is delivered for you as an **end-to-end encrypted message over [nostr](https://github.com/nostr-protocol/nips), routed through the [Nym mixnet](https://nym.com)**. Relays only ever see ciphertext — never the amount, the sender, or the recipient — and the mixnet hides who is talking to whom at the network layer.

Goblin is a fork of the **Grim** egui GRIN wallet: it keeps Grim's full GRIN node/wallet engine and layers a Nostr-native, mobile-first payments experience on top.

## What it does

- **Send to people** — pay a `@username` or `npub`; the GRIN slatepack travels as a [NIP-17](https://nips.nostr.com/17) gift-wrapped DM ([kind 1059](https://nostrbook.dev/kinds/1059)) over the Nym mixnet and is applied automatically by the recipient's wallet. No files to swap, no need to both be online at once.
- **In-app identity** — a nostr payment key that is deliberately *not* part of your seed, so you can rotate it any time to stay unlinkable without touching your funds. An optional human-readable `@name` (and hosted avatar) comes from the goblin.st identity service.
- **Private by construction** — GRIN's address-less, confidential chain; every relay and HTTP request (relays, NIP-05 lookups, price, avatars) routed through the [Nym mixnet](https://nym.com) via a bundled `nym-socks5-client` sidecar, so nothing touches the clear net; keys, names and history stay on your device.
- **Configurable amount pairing** — show balances against a world currency, Bitcoin, or sats (rates fetched over the mixnet), or turn the preview off.
- **Cross-platform** — Linux, macOS, Windows, Android, built in pure Rust on [egui](https://github.com/emilk/egui).

## How a payment travels

```
   you ──slatepack──▶ NIP-17 gift wrap (kind 1059, NIP-44 encrypted)
                          │
                   Nym mixnet (5-hop)
                          │
            ┌─────────────┴─────────────┐
        your relays              recipient's DM relays (kind 10050)
            └─────────────┬─────────────┘
                          ▼
   recipient ◀──unwrap, verify seal author, apply slatepack
```

The wrap is [NIP-44](https://nips.nostr.com/44)-encrypted, and delivery uses the recipient's DM relay list ([kind 10050](https://nostrbook.dev/kinds/10050)).

Both parties only need one relay in common. The default set is the Goblin relay plus large public relays (`relay.damus.io`, `nos.lol`), and the set is editable in **Settings → Relays**.

## Build

### Desktop (Linux / macOS / Windows)

```
git submodule update --init --recursive
cargo build --release
./target/release/goblin
```

Goblin routes all of its traffic over the [Nym mixnet](https://nym.com) using a `nym-socks5-client` sidecar that runs alongside the wallet and exposes a local SOCKS5 proxy on `127.0.0.1:1080`. Ship the `nym-socks5-client` binary next to the `goblin` executable (or point `GOBLIN_NYM_BIN` at it), and set the network requester it routes through via `GOBLIN_NYM_PROVIDER` (or bake it into `NETWORK_REQUESTER` in `src/nym/sidecar.rs`). If a SOCKS5 endpoint is already listening on `127.0.0.1:1080`, Goblin reuses it.

### Android

Install the Android SDK / NDK, then from the repo root:

```
./scripts/android.sh build|release v7|v8|x86
```

`v7`/`v8`/`x86` is the device CPU architecture for `build`; for `release` pass a version in `major.minor.patch` form.

## Identity service (`goblin-nip05d`)

The optional `@name` + avatar service lives in `goblin-nip05d/` (axum + SQLite) and is deployed at [goblin.st](https://goblin.st). It implements [NIP-05](https://nips.nostr.com/5) resolution, [NIP-98](https://nips.nostr.com/98)-authenticated registration/transfer/release, and a hardened avatar pipeline (magic-byte sniffing, bounded decode, full re-encode to a clean 256×256 PNG). The wallet is fully usable — and fully anonymous — without it.

## License

Apache License v2.0.

## Credits

🤖 Built with AI pair-programming assistance (Claude)

The underlying cross-platform GRIN wallet engine is the upstream **Grim** project.
