# GRIM to Goblin deviations audit

Audit date: 2026-07-01 (supersedes and incorporates the Build 39 deviation audit of 2026-06-12).

Comparison snapshot:

- Goblin: `git.us-ea.st/GRIN/goblin` at `1e8e0f6`, plus uncommitted Phase-0 UI work in the tree
  (avatar, back-nav, balance, notification edits, new locale keys, `examples/avatar_ring.rs`).
  Phase-0 changes are treated as intentional Goblin-side additive work, not drift.
- GRIM: `code.gri.mw/GUI/grim` local clone at `ee88415`, which is exactly `origin/master` (0 ahead, 0 behind).
- The two repos have separate git histories (no merge base), so this audit is a working tree
  directory diff, not a git diff.

## 1. Repo topology, corrected

Earlier notes described `goblin/wallet` as a plain vendored directory. That is wrong. Both grin
crates are real git submodules in Goblin (`goblin/.gitmodules`):

- `node/` -> `code.gri.mw/ardocrat/node`, checked out at `bce5a714`, working tree clean.
- `wallet/` -> `code.gri.mw/ardocrat/wallet`, branch `grim`, checked out at `c2db754` ("fix: ci"),
  working tree clean. `c2db754` is exactly the tip of `origin/grim`. So the vendored wallet is
  byte-for-byte an unmodified published upstream branch. Confirmed untouched.

GRIM pins the same wallet repo differently: its superproject HEAD records gitlink
`5c54e7c` (the tip of branch `grim-staging`), while the local `grim/wallet` checkout in this
workspace sits at `8847ee5` ("build: fix deps", a local commit on an older base; the clone is
shallow, which is why `8847ee5` looks parentless there). The two wallet branches are different
lineages of the same repo:

- `grim` branch (what Goblin pins): full history, merges `mimblewimble/master` (`a3e71a8`) and
  carries extra fixes GRIM staging does not have (`full_scan_fix` trio, `840bde7` lmdb backend
  migration, `ff1238c`/`b197aff` lmdb no-panic fixes).
- `grim-staging` branch (what GRIM pins): squashed shallow lineage plus the 2026-06 Tor arti work.

## 2. Application source audit (grim/src vs goblin/src)

40 inherited files are MODIFIED, 7 units are ADDITIVE (Goblin-only), 3 units are REMOVED
(GRIM-only). Everything checks out as intentional; risk flags are collected in section 3.

### 2.1 Additive (Goblin-only), 7 units

- `src/nostr/` (11 files): payment messaging subsystem. Contacts, NIP-17 DMs, NIP-44/59
  encryption, relay management, standalone identity (random or imported, never seed-derived),
  NIP-05 registration, message protocol/ingest, rkv store.
- `src/nym/` (3 files): Nym mixnet transport, in-process SDK (no sidecar since Build 65/66),
  SOCKS5 client, HTTP routing and WebSocket relay dial through the mixnet.
- `src/gui/views/goblin/`: the phone-first payment app surface (GoblinWalletView), the primary UI
  since the Phase-0 redesign.
- `src/gui/theme.rs`: design token system (Light/Dark/Yellow themes, density scales); `colors.rs`
  now maps its legacy API onto these tokens.
- `src/http/price.rs`: CoinGecko fiat/BTC rate fetch routed over the Nym mixnet, lazy cached per
  currency (backs the Pairing setting).
- `locales/*.yml`: ~370 goblin-prefixed keys across 6 locales (drift-tested), plus new
  uncommitted Phase-0 keys.
- `examples/avatar_ring.rs` (uncommitted Phase-0): avatar ring rendering example.

### 2.2 Removed (GRIM-only), 3 units

- `src/tor/` (4 files): Tor service, onion addresses, circuit management. Replaced by `src/nym`.
- `src/gui/views/settings/tor.rs`: Tor proxy/bridge settings UI. The settings screen block that
  used it is gone; an integrated node control panel took its place.
- `src/gui/views/wallets/wallet/transport/`: Tor transport panel (slatepack address over onion,
  QR). Replaced by the goblin payment surface and Nostr/Nym slatepack exchange.

### 2.3 Modified inherited files, 40 files, one line each

Core:

- `src/lib.rs`: nostr/nym modules replace tor; BUILD number constant; rustls ring provider setup;
  Nym warm-up; Goblin branding, fonts, theme wiring.
- `src/logger.rs`: drops the arti (Tor) log filter.
- `src/main.rs`: adds a Wayland app_id so the taskbar icon resolves.
- `src/gui/mod.rs`: exposes `pub mod theme`.
- `src/gui/app.rs`: Android status-bar icon heartbeat, app visibility frame mark, X11 background
  fill fix for light/yellow themes, "Goblin - Build N" title.
- `src/gui/colors.rs`: refactored from hard-coded constants to theme-token lookups, same API.

Platform:

- `src/gui/platform/mod.rs`: new platform hooks: save_file, share_text, pick_image_file,
  set_status_bar_white_icons, vibrate_error, vibrate_copy.
- `src/gui/platform/android/mod.rs`: JNI implementations of the above (SAF save, share sheet,
  status-bar icon color, haptics, image picker).
- `src/gui/platform/desktop/mod.rs`: camera rework for QR scanning: enumeration off the UI
  thread, native device indices (v4l gaps), YUYV/NV12 to JPEG transcoding, graceful frame errors;
  plus pick_image_file. Deliberate Build 9 robustness fix, confirmed again.

Views, shared:

- `src/gui/views/mod.rs`: exposes `pub mod goblin`.
- `src/gui/views/views.rs`: Goblin mark instead of Grim logo, quiet "Build N" label, theme-driven
  tinting.
- `src/gui/views/content.rs`: (Phase-0, uncommitted) integrated-node warning only shows when node
  autostart is enabled, so external-node setups are not nagged.
- `src/gui/views/camera.rs`: "No camera found" after 5 s wait, modal_ui inlined at callers, adds a
  QR decode test with the center mark.
- `src/gui/views/input/edit.rs`: additive builders (hint_text, text_color, body) plus native-IME
  path; soft-keyboard suppression default changed from `is_android()` to `true` on all platforms
  (post-Build-39 change, intentional: native input everywhere).

Views, network and settings:

- `src/gui/views/network/connections.rs`: adapts to the changed NodeConfig API
  (get_api_address returns a full address, URL built as http://address).
- `src/gui/views/network/settings.rs`: drops the "listen on all interfaces" toggle, direct radio
  IP selection.
- `src/gui/views/network/setup/node.rs`: uses get_api_ip_port instead of the removed combined
  call.
- `src/gui/views/network/setup/p2p.rs`: P2P setup reduced to port only, per-interface binding UI
  removed.
- `src/gui/views/settings/content.rs`: Tor block removed; integrated node controls (status,
  enable, autorun, link to full node settings) added.
- `src/gui/views/settings/mod.rs`: drops `mod tor`.

Views, wallets:

- `src/gui/views/wallets/mod.rs`: visibility widened (`pub mod wallet`) so the goblin surface can
  reuse wallet views; slightly broader than GRIM's pub(crate), cosmetic.
- `src/gui/views/wallets/content.rs`: transport content removed, goblin surface is the wallet
  screen; (Phase-0, uncommitted) back button no longer falls through to the wallet chooser, wallet
  switching goes through explicit switch/lock controls.
- `src/gui/views/wallets/creation/mnemonic.rs`: word_list_ui made pub(crate) for reuse.
- `src/gui/views/wallets/wallet/mod.rs`: drops `mod transport`.
- `src/gui/views/wallets/wallet/content.rs`: goblin surface owns the wallet screen and modal
  lifecycle; GRIM's legacy_container_ui kept under `#[allow(dead_code)]` on purpose.
- `src/gui/views/wallets/wallet/request/invoice.rs`: GRIM's newer sender-slatepack-address input
  (typed plus QR scan) not adopted; Goblin's request flow rides Nostr instead.
- `src/gui/views/wallets/wallet/request/send.rs`: scanner modal UI inlined here after the
  camera.rs modal_ui removal.
- `src/gui/views/wallets/wallet/txs/content.rs`: SendingTor state and SendTor/FinalizeTor task
  buttons removed.
- `src/gui/views/wallets/wallet/txs/tx.rs`: Tor finalization states and guards removed, slate
  state read simplified, generic "address" label.

HTTP, node, settings, wallet core:

- `src/http/mod.rs`: registers the price module.
- `src/http/release.rs`: update checks point at Goblin releases, build-number versioning instead
  of semver, goblin artifact names, platform list trimmed.
- `src/node/config.rs`: does not carry GRIM's newer IPv6/all-interfaces work (a91d901); Goblin
  stays IPv4 host:port with split get_api_address/get_api_ip_port. See section 3.
- `src/node/node.rs`: Android notification wording fix ("Listening" when the integrated node is
  off in external-node setups).
- `src/settings/config.rs`: adds theme, density, pairing (Off/Usd/Eur/Gbp/Jpy/Cny/Btc/Sats),
  last_wallet_id; migrates the legacy fiat_preview flag; check_updates fallback flipped to false
  when the key is absent (GRIM falls back to true). Intentional: no clearnet phone-home by
  default.
- `src/settings/settings.rs`: TorConfig removed, working dir renamed .grim to .goblin.
- `src/wallet/config.rs`: adds get_nostr_path/get_nostr_db_path storage helpers.
- `src/wallet/connections/external.rs`: default mainnet node list reordered and extended
  (api.grin.money first, then main.us-ea.st, grincoin.org, main.gri.mw, raubritter). See
  section 4, open decision.
- `src/wallet/store.rs`: rkv capacity headroom (+16) so the Nostr store can coexist with the tx
  store without reopen churn.
- `src/wallet/types.rs`: SendingTor action and SendTor/FinalizeTor tasks replaced by
  NostrSend/Request/Resend/PayRequest/DeclineRequest/CancelOutgoing/CancelSend; adds
  ManualSlatepackOutcome. No slate state machine change.
- `src/wallet/wallet.rs`: about +733 lines, additive only: nostr identity lifecycle, NostrService,
  payment-message tasks, last-fee cache; GRIM's slate/tx state machine, locking, and encryption
  untouched; Tor send/post paths removed. (Phase-0, uncommitted: from_unlocked_keys drops the
  derivation_account arg.) The garbled duplicate comment near line 333 noted in Build 39 remains,
  cosmetic.
- `Cargo.toml`: arti/tor dependency stack (9 crates) swapped for nostr-sdk, nym-sdk,
  nostr-relay-pool, reqwest(socks), tokio-socks, rustls(ring); openssl vendored on Android/Linux;
  grin crates come from the `node/` submodule via path deps.

## 3. Risky or unexpected findings

Nothing looks accidental or money-dangerous in inherited code. Items worth eyes:

1. IPv6/multi-interface node support (upstream-newer, not adopted). GRIM added all-interface
   binding, IPv6 parsing, and a listen-all toggle (node/config.rs plus the network settings UI).
   Goblin is IPv4 host:port only. Not a bug, but a growing gap against upstream; decide whether
   to pull it or declare it out of scope for a phone-first wallet.
2. Invoice sender-address input (upstream-newer, not adopted). GRIM's invoice request screen can
   attach the requester's slatepack address (typed or QR). Goblin's request flow carries identity
   over Nostr instead, so this was consciously not picked up. Revisit only if manual slatepack
   invoicing should reach feature parity with GRIM.
3. check_updates fallback flip (true in GRIM, false in Goblin when the config key is missing).
   Intentional privacy default, but the Default struct still writes Some(true) on first run, so
   the flipped fallback only matters for configs missing the key. Harmless, slightly inconsistent.
4. edit.rs soft-keyboard default now differs from GRIM on desktop too (true everywhere). This is
   a deliberate post-Build-39 change for the native IME path; noted because the Build 39 audit
   recorded it as byte-identical, which is no longer true.
5. Build 39 items re-confirmed: camera/MJPEG desktop rewrite is a deliberate QR fix; the X11
   background fill in app.rs is a real fix; legacy_container_ui is intentionally kept dead;
   wallet.rs nostr layer is additive and does not touch GRIM's slate handling.

## 4. Open product decision

Default mainnet node order (`src/wallet/connections/external.rs`): Goblin ships
api.grin.money first (Build 92, health-verified), then the Goblin-run main.us-ea.st, then
grincoin.org, with GRIM's main.gri.mw demoted to fourth. Intended infra lean for the fork, still
awaiting explicit owner confirmation. This remains the single open decision from the Build 39
audit.

## 5. Vendored wallet audit (goblin/wallet vs GRIM's wallet pins)

Reference points:

- Goblin pin: `c2db754` = tip of `ardocrat/wallet` branch `grim`, clean checkout, zero local edits.
- GRIM local checkout: `8847ee5` (branch-`grim`-side lineage plus "build: fix deps").
  File-level delta to Goblin: 20 files, all explained by the lineage split, none by Goblin edits.
- GRIM recorded pin (superproject HEAD): `5c54e7c` = `grim-staging` tip. File-level delta to
  Goblin: 29 files plus staging-only `.gitmodules`/`grin/` submodule and `impls/src/adapters/tor.rs`,
  `impls/src/tor/arti.rs` (arti Tor client). Goblin-side extra: `impls/src/adapters/http.rs`
  (staging folded it into the Tor adapter).

Two facts drive every verdict below:

- Goblin's app never enters the wallet's synchronous send flow: every `InitTxArgs` is built with
  `..Default::default()` (send_args always None) and `receive_tx` is always called with
  r_addr None (goblin/src/wallet/wallet.rs lines ~1400-1550). Slatepack exchange happens at the
  app layer over Nostr/Nym, and slatepack files are written by the app
  (create_slatepack_message), not by the wallet API. So every grim-staging hunk that lives inside
  the `try_slatepack_sync_workflow` call sites is unreachable code for Goblin.
- Goblin's wallet lineage already has `update_tx_slate_state` wired inside
  `libwallet/src/api_impl/foreign.rs` (lines ~131, 170, 230) with hard `?` propagation on the
  actual receive/finalize money path. Staging only calls it best-effort (`let _ =`) at the API
  layer after Tor sends.

### 5.1 Commit-by-commit verdicts (plan INCLUDE list vs grim-staging@5c54e7c)

| Commit | Subject | In Goblin wallet? | Verdict |
| --- | --- | --- | --- |
| `129ad2f` | save last-scanned block, wallet scanning (#748) | Yes, git ancestor | Already present; Goblin also carries the stronger `full_scan_fix` trio (2880-block window, last-block hash) staging lacks |
| `06ab92a` | lmdb update (#755) | Yes, git ancestor | Already present; plus `840bde7` backend migration and `ff1238c`/`b197aff` lmdb no-panic fixes on top |
| `9570ed4`/`e9e75c5` | openssl 0.10.80 (#752) | Yes (`9570ed4` ancestor) | Already present; Cargo.lock confirms openssl 0.10.80. `e9e75c5` is the same change on the shallow lineage |
| `602d79e`/`8401963` | rust edition 2021 (#749) | Yes (`602d79e` + `da3f60b` ancestors) | Already present; all member crates say edition 2021 |
| `d4867d5` | remove panics (slatepack/slate parsing) | No | PORT. `git apply --check` passes clean against `c2db754`. Turns unwrap/panic into typed errors in slatepack armor/types and slate_versions ser/v4_bin, adds a malformed-plaintext decrypt test. Directly protects Goblin: slatepacks arrive from untrusted Nostr peers |
| `1825e66` | lock on process-invoice while updating slate state | No | Hunk 1 (scope the wallet mutex tightly around owner::process_invoice_tx) is inert today because send_args is always None, but it is cheap future-proofing for a path Goblin does call (pay(), wallet.rs:1503). Hunk 2 patches an update_tx_slate_state block that only exists in the staging lineage. Port hunk 1 (optional), skip hunk 2 |
| `f92a2d6` | slatepack concrete error on sync workflow, send-requirement detection | Partially, effectively | The money substance (update_tx_slate_state with real error propagation) already exists in Goblin's libwallet, stronger than staging's. The rest changes try_slatepack_sync_workflow's signature/behavior (Tor send ergonomics), TorConfig::skip_send, and CLI command flows Goblin never runs. Skip |
| `5c20635`/`86bae1c` | version bumps to 5.4.1 | No | Metadata only; Goblin wallet is 5.4.0-alpha.1. Bumping would dirty a clean submodule for zero behavior. Skip |
| `ca5686a` | node submodules (#758), grin submodule build wiring | No, solved differently | Staging vendors grin node crates as a `grin/` submodule inside the wallet repo. Goblin's wallet branch already wires grin crates via `../../node/*` path deps to the goblin/node submodule. Adopting ca5686a would move the build base, explicitly off-limits. Skip |

### 5.2 MIXED commits, hunk classification

`3f89cbc` (api: output slatepack file after tor finalization for invoice, update slate state after
tor finalization on receive):

- Money hunks: `api/src/owner.rs` removal of the double state update in init_send_tx (fixes a bug
  f92a2d6 introduced in the staging lineage; the block does not exist in Goblin's lineage, N/A);
  `api/src/owner.rs` output_slatepack_file() helper plus its call after the invoice sync send
  (Goblin writes slatepack files at the app layer, dead path); `api/src/foreign.rs` slate state
  update after the receive-side sync send (Goblin's libwallet receive_tx already updates state
  internally, dead path).
- Tor hunk: `impls/src/tor/arti.rs` cosmetic cleanup, staging-only file. Skip.
- Net: nothing to port.

`2292cb3` (api: log errors on update tx slate state and slatepack file output after tor sync
flow):

- Money-adjacent observability only: converts two `let _ =` calls into match + error! logging, in
  `api/src/foreign.rs` and `api/src/owner.rs`. Both call sites are the Tor sync flow and do not
  exist in Goblin's lineage. Port only if the 3f89cbc-equivalent code ever lands. Skip.

Plan EXCLUDE list (`411bcff` arti client, `4587eb9` global Tor state, `1806098` tor send check,
`5c54e7c`/`8696288` pay_tor_result merges, all of `impls/src/tor/` arti work): confirmed skipped,
nothing from these is present in or needed by Goblin. Note Goblin's wallet still contains
upstream grin-wallet's old process-based `impls/src/tor/` module; it is unused by the app
(Owner::new is constructed with tor_config None) and harmless.

### 5.3 Port list

Mechanics: commit inside the wallet submodule on a Goblin-owned branch (or fork remote) on top of
`c2db754`, then bump the `wallet` gitlink in the goblin superproject. Do NOT rebase the submodule
onto grim-staging and do not advance grim's own submodule pointer.

- [x] 1. DONE 2026-07-01: cherry-picked as `906dc55` on new local branch `goblin-money` (base `c2db754`), unpushed. Libwallet slatepack tests pass incl. `slatepack_decrypt_rejects_malformed_plaintexts`; goblin lib tests (44) pass against the patched submodule. Original item: Cherry-pick `d4867d5` "Removing some panics" onto goblin/wallet `c2db754`. Applies clean
  (verified with `git apply --check`). Files:
  - `wallet/libwallet/src/slate_versions/ser.rs`
  - `wallet/libwallet/src/slate_versions/v4_bin.rs`
  - `wallet/libwallet/src/slatepack/armor.rs`
  - `wallet/libwallet/src/slatepack/types.rs`
  Then run the libwallet tests, including the new
  `slatepack_decrypt_rejects_malformed_plaintexts`.
- [x] 2. SKIPPED 2026-07-01 (ponytail): dead path in Goblin (send_args always None, no Tor sync workflow), mutex releases at fn end; revisit only if a slatepack sync workflow is ever adopted. Original item: (Optional hardening) Port hunk 1 of `1825e66` to `wallet/api/src/owner.rs`
  process_invoice_tx: wrap the `wallet_inst.lock()` / `lc_provider` / `owner::process_invoice_tx`
  sequence in an inner block so the wallet mutex drops before the send_args branch. About 6
  lines, adapt to Goblin's 6-arg try_slatepack_sync_workflow context. Skip hunk 2 (targets
  staging-only code).
- [x] 3. Confirmed skipped, already present: `129ad2f`, `06ab92a`, `9570ed4`/`e9e75c5`, `602d79e`/`8401963`.
- [x] 4. Confirmed skipped, Tor-only, dead-path, or build-base: `f92a2d6` (except its update_tx_slate_state
  substance, already present), `3f89cbc`, `2292cb3`, `1806098`, `411bcff`, `4587eb9`,
  `5c20635`/`86bae1c` (version metadata), `ca5686a` (grin submodule wiring, superseded by
  Goblin's node/ path deps), `5c54e7c`/`8696288` (merges).
- [ ] 5. PENDING at commit time (gitlink bump deferred per commit discipline; submodule working tree carries the patch now). After the gitlink bump: `cargo build`, `cargo clippy -- -D warnings`, wallet unit tests,
  and a slatepack round-trip between two Goblin identities (malformed-slatepack input now errors
  instead of panicking).

## 6. Summary counts

- Additive: 7 units (nostr 11 files, nym 3 files, views/goblin, theme.rs, http/price.rs, locale
  keys, Phase-0 example).
- Modified inherited files: 40 (all intentional; zero unexplained drift).
- Removed: 3 units (src/tor 4 files, settings/tor.rs, wallet transport panel).
- Vendored crates: untouched. wallet = ardocrat/wallet@grim `c2db754` exactly, node =
  ardocrat/node `bce5a714`, both clean.
- Wallet port work: 1 required cherry-pick (`d4867d5`), 1 optional adapted hunk (`1825e66` hunk
  1), everything else already present or correctly excluded.
