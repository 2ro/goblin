<p align="center">
  <img src="Goblin-Banner.png" alt="Goblin" width="680"/>
</p>

# Goblin

Goblin is a private, pay-by-username wallet for [GRIN ツ](https://grin.mw) — confidential digital cash on [Mimblewimble](https://github.com/mimblewimble/grin), with no amounts or addresses on the chain.

Instead of passing slatepack files back and forth, you **pay a `username` (or an `npub`)** and the payment is delivered for you as an **end-to-end encrypted message over [nostr](https://github.com/nostr-protocol/nips), routed through the [Nym mixnet](https://nym.com)**. Relays only ever see ciphertext — never the amount, the sender, or the recipient — and the mixnet hides who is talking to whom at the network layer.

Goblin is a fork of the **Grim** egui GRIN wallet: it keeps Grim's full GRIN node/wallet engine and layers a Nostr-native, mobile-first payments experience on top.

## What it does

- **Send to people** — pay a `username` or `npub`; the GRIN slatepack travels as a [NIP-17](https://nips.nostr.com/17) gift-wrapped DM ([kind 1059](https://nostrbook.dev/kinds/1059)) over the Nym mixnet and is applied automatically by the recipient's wallet. No files to swap, no need to both be online at once.
- **Manual slatepacks too** — when you need to pay or get paid without a handle, **Settings → Wallet → Slatepacks** exposes the classic by-hand flow: create a slatepack to send, or paste one to receive, finalize, or pay.
- **In-app identity** — a nostr payment key that is deliberately *not* part of your seed, so you can rotate it any time to stay unlinkable without touching your funds. An optional human-readable `name` comes from the goblin.st identity service.
- **Private by construction** — GRIN's address-less, confidential chain; your payments and identity (nostr relays, NIP-05 lookups, price) are routed through the [Nym mixnet](https://nym.com), so who-pays-whom never touches the clear net. The GRIN node connection — block sync and broadcasting your transaction — is direct: public chain data, the same for everyone, and not tied to your identity. Keys, names and history stay on your device.
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

## Building

Official builds for every platform are on the [Releases](https://github.com/2ro/goblin/releases) page. This repository is the source for reference: the wallet links a patched [Nym mixnet](https://nym.com) SDK **in-process**, so it ships as a single self-contained binary with no sidecar.

Goblin's identity and payment traffic — nostr relays, NIP-05 lookups and price fetches — is routed over the mixnet; the SDK's SOCKS5 listener runs in-process on `127.0.0.1:1080`. The GRIN node connection (block sync and transaction broadcast) is **not** mixed — it connects directly, as it carries only public chain data that isn't linked to your wallet.

## Identity service (`goblin-nip05d`)

The optional `name` service lives in `goblin-nip05d/` (axum + SQLite) and is deployed at [goblin.st](https://goblin.st). It implements [NIP-05](https://nips.nostr.com/5) resolution, [NIP-98](https://nips.nostr.com/98)-authenticated registration/transfer/release. The wallet is fully usable — and fully anonymous — without it. Avatars aren't stored or served — clients render them from the pubkey (an npub gradient with the username's first letter, else the Grin mark).

## License

Apache License v2.0.

## Credits

🤖 Built with AI pair-programming assistance (Claude)

The underlying cross-platform GRIN wallet engine is the upstream **Grim** project.
