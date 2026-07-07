<p align="center">
  <img src="Goblin-Banner.png" alt="Goblin" width="680"/>
</p>

# Goblin

Goblin is a private, pay-by-username wallet for [GRIN ツ](https://grin.mw) - confidential digital cash on [Mimblewimble](https://github.com/mimblewimble/grin), with no amounts or addresses on the chain.

Instead of passing slatepack files back and forth, you **pay a `username` (or an `npub`)** and the payment is delivered for you as an **end-to-end encrypted message over [nostr](https://github.com/nostr-protocol/nips), routed through [Tor](https://www.torproject.org)**. Relays only ever see ciphertext - never the amount, the sender, or the recipient. Tor hides your IP from the relay; the relay and encryption hide the rest - content, sender, timing.

Goblin is a fork of the **Grim** egui GRIN wallet: it keeps Grim's full GRIN node/wallet engine and layers a Nostr-native, mobile-first payments experience on top.

## What it does

- **Send to people** - pay a `username` or `npub`; the GRIN slatepack travels as a [NIP-17](https://nips.nostr.com/17) gift-wrapped DM ([kind 1059](https://nostrbook.dev/kinds/1059)) over Tor and is applied automatically by the recipient's wallet. No files to swap, no need to both be online at once.
- **Manual slatepacks too** - when you need to pay or get paid without a handle, **Settings → Wallet → Slatepacks** exposes the classic by-hand flow: create a slatepack to send, or paste one to receive, finalize, or pay.
- **Open-to-pay links** - a `goblin:` or `nostr:` pay link, or a scanned checkout QR, opens the wallet straight to a prefilled review screen (recipient, amount and note filled in, ready to hold-to-send) on desktop, macOS and Android.
- **Proofs on request** - payments can include a native Grin payment proof when the payment request asks for one, off by default, shown on the review screen. An ordinary person-to-person send carries none.
- **In-app identities** - one wallet holds many nostr payment keys, each deliberately *not* part of your seed, so you can rotate or switch between them any time to stay unlinkable without touching your funds. Generate a fresh identity, import an existing one (`nsec` or `.backup`), and switch the active one from the identity switcher. An optional human-readable `name` per identity comes from the goblin.st identity service.
- **Sign in with Goblin** - a site can ask your wallet to prove who you are with a one-time login. You review the requesting domain and approve once; the wallet signs a single [kind 22242](https://nostrbook.dev/kinds/22242) login event and returns to the calling app. A login is never signed silently by any granted session.
- **Authorize** - a site can request a single nostr event be signed. You see exactly what is being signed and approve it one time with your password; nothing is remembered.
- **Authorize Sessions** - grant a trusted site a session so it can sign low-risk events (messaging, listings) silently for its duration, while money-tier actions always ask for your password every single time. Money tier is kinds [17](https://nostrbook.dev/kinds/17) and [30402](https://nostrbook.dev/kinds/30402), which are never covered by a session grant. Every active grant is listed under **Settings → Trusted Sites**, where you can review what each site can sign and revoke it.
- **Merchant invoicing** - a batch invoice link is approved once, and each sale draws its own fresh proof address so receipts stay distinct without extra taps.
- **Private by construction** - GRIN's address-less, confidential chain; your payments and identity (nostr relays, NIP-05 lookups, price) are routed through [Tor](https://www.torproject.org), so who-pays-whom never touches the clear net. The GRIN node connection - block sync and broadcasting your transaction - is direct: public chain data, the same for everyone, and not tied to your identity. Keys, names and history stay on your device.
- **Configurable amount pairing** - show balances against a world currency, Bitcoin, or sats (rates fetched over Tor), or turn the preview off.
- **News on Home** - the latest post from the official Goblin news key (a [kind 30023](https://nostrbook.dev/kinds/30023) long-form article) appears on the Home screen in your wallet's language, falling back to English; it stays hidden when there is nothing to show, and only ever shows the newest article.
- **Cross-platform** - Linux, macOS, Windows, Android, built in pure Rust on [egui](https://github.com/emilk/egui).

## How a payment travels

```
   you ──slatepack──▶ NIP-17 gift wrap (kind 1059, NIP-44 encrypted)
                          │
                         Tor
                          │
            ┌─────────────┴─────────────┐
        your relays              recipient's DM relays (kind 10050)
            └─────────────┬─────────────┘
                          ▼
   recipient ◀──unwrap, verify seal author, apply slatepack
```

The wrap is [NIP-44](https://nips.nostr.com/44)-encrypted, and delivery uses the recipient's DM relay list ([kind 10050](https://nostrbook.dev/kinds/10050)). Tor hides your IP from the relay; the relay and the encryption above hide the rest - content, sender, timing.

Both parties only need one relay in common. The default set is the Floonet relay (`relay.floonet.dev`) plus Tor-friendly public relays (`relay.0xchat.com`, `offchain.pub`) that accept connections from Tor exits, and the set is editable in **Settings → Relays**.

## Build

### Desktop (Linux / macOS / Windows)

Goblin links [Tor](https://www.torproject.org) **in-process** via [arti](https://gitlab.torproject.org/tpo/core/arti) - the wallet is a single self-contained binary, no sidecar, nothing separate to install:

```
git submodule update --init --recursive
cargo build --release
./target/release/goblin
```

Goblin's identity and payment traffic (nostr relays, NIP-05 lookups and price fetches) rides Tor: every relay, the money-path relay included, is reached over a Tor exit to its ordinary clearnet host. The GRIN node connection (block sync and transaction broadcast) is **not** routed through Tor: it connects directly, as it carries only public chain data that isn't linked to your wallet.

### Android

Install the Android SDK / NDK, then from the repo root:

```
./scripts/android.sh build|release v7|v8|x86
```

`v7`/`v8`/`x86` is the device CPU architecture for `build`; for `release` pass a version in `major.minor.patch` form.

## Identity service (`goblin-nip05d`)

The optional `name` service lives in `goblin-nip05d/` (axum + SQLite) and is deployed at [goblin.st](https://goblin.st). It implements [NIP-05](https://nips.nostr.com/5) resolution, [NIP-98](https://nips.nostr.com/98)-authenticated registration and release (names are never transferred - on a key rotation you release the old name and re-register, or import your existing identity). The wallet is fully usable - and fully anonymous - without it. Avatars aren't stored or served - clients render them from the pubkey (an npub gradient with the username's first letter, else the Grin mark).

## License

Apache License v2.0.

## Credits

🤖 Built with AI pair-programming assistance (Claude)

The underlying cross-platform GRIN wallet engine is the upstream **Grim** project.
