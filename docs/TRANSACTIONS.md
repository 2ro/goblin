# Goblin transactions — how a payment works, end to end

This document explains the full lifecycle of a Goblin payment: how money moves,
every status it passes through, and the small guarantees that keep it safe. It is
written against the code in `src/nostr/` and `src/wallet/` — function names and
files are cited (line numbers drift, so they aren't).

---

## 1. The big picture: two layers

A Goblin payment is **a Grin transaction wrapped in a private nostr message**.

1. **Grin layer (the money).** Grin/Mimblewimble transactions are *interactive*:
   the sender and recipient exchange a "slate" that passes through states until
   it's finalized and posted on-chain. There are no addresses and no amounts on
   the chain. Goblin reuses GRIM's full Grin node + wallet engine for this.

2. **Nostr layer (the delivery).** Instead of making you hand slate files back
   and forth, Goblin delivers each slate as an **end-to-end-encrypted nostr
   direct message**, routed through **Tor**. You pay a `username` or
   `npub`; the recipient's wallet applies the slate automatically.

The slate is the payload; nostr is the transport. Everything below is about how
those two layers move together and what state is tracked at each step.

### Slate states (Grin layer)

Interactive Grin slates pass through numbered states. Goblin uses two flows:

| Flow | States | Who builds what |
| --- | --- | --- |
| **Standard** (sender pushes money) | `Standard1` → `Standard2` → `Standard3` | Sender builds S1 (locks their outputs), recipient replies S2, sender finalizes S3 and posts |
| **Invoice** (recipient pulls money) | `Invoice1` → `Invoice2` → `Invoice3` | Requester builds I1 (the ask), payer replies I2 (pays), requester finalizes I3 and posts |

### Status + direction (Goblin's nostr metadata)

For each payment Goblin stores a `TxNostrMeta` (`src/nostr/types.rs`) keyed by
slate id, with a **direction** and a **status**:

`NostrTxDirection`:
- `Sent` — we pushed funds (we created S1).
- `Received` — we were paid (we replied S2).
- `RequestedByUs` — we issued an invoice (we created I1).
- `RequestedOfUs` — someone invoiced us and we paid it (we replied I2).

`NostrSendStatus`:
- `Created` — slate built locally, DM not dispatched yet (durable checkpoint).
- `AwaitingS2` — S1 sent, waiting for the recipient's S2 reply.
- `ReceivedNoReply` — we processed an incoming S1 (or I1) and built our reply, but haven't dispatched it yet (crash-recovery point).
- `RepliedS2` — our S2 reply was dispatched (we received a payment).
- `AwaitingI2` — our I1 invoice was sent, waiting for the payer's I2.
- `PaidAwaitingFinalize` — we paid an invoice (sent I2); the requester finalizes.
- `Finalized` — slate finalized and posted on-chain.
- `SendFailed` — DM dispatch failed; eligible for retry.
- `Cancelled` — cancelled locally (manual cancel or 24h expiry).

`Finalized` and `Cancelled` are **terminal**.

---

## 2. Identity & addressing

Your nostr identity is a key that is **deliberately not derived from your wallet
seed** (`src/nostr/identity.rs`) — so you can rotate it any time to stay
unlinkable without ever touching your funds. It's stored encrypted at rest
(NIP-49 ncryptsec under your wallet password).

You can optionally claim a human-readable **`username`** from a **name authority**
(a NIP-05 server). The authority is configurable (Settings → Identity → Name
authority; `NostrConfig::{nip05_server, home_domain, set_nip05_server}`), which is
what makes Goblin **federated**: a user on `bob@otherinstance.com` can pay
`alice@goblin.st`, because a full `name@domain` always resolves against that
domain's `/.well-known/nostr.json`. Bare names (`alice`) resolve against *your*
configured home authority.

Display rules (`data::display_name`, no `@` ever shown):
- A local **petname** wins.
- A verified name on **your home authority** shows bare (`alice`) + a check.
- A verified name on a **foreign authority** shows `alice · domain` + a check, so
  it can never masquerade as a home name.
- Otherwise: a short npub.

Names are kept fresh: see [§11 Name freshness](#11-contacts--name-freshness).

---

## 3. Transport: NIP-17 gift wraps over Tor

A payment DM is built and sent by `send_payment_dm`; control messages (voids) by
`send_control_dm` (both in `src/nostr/client.rs`). The message structure
(`src/nostr/protocol.rs`):

- The **payload** is the raw Grin slatepack armor (`BEGINSLATEPACK… ENDSLATEPACK`)
  inside a kind-14 rumor, prefixed with a human preamble (`[Goblin] GRIN payment
  message — open in Goblin …`) so a non-Goblin nostr client shows something sane.
- **Tags:** a `["goblin","1"]` protocol marker always; an optional `["subject", …]`
  carrying the user's note (sanitized); control DMs carry
  `["goblin-action","void", slate_id]` and **no** slatepack.
- The rumor is sealed and wrapped as a **kind-1059 gift wrap** (NIP-59 + NIP-44
  encryption) via nostr-sdk's `send_private_msg_to`. Relays only ever see
  ciphertext — never the amount, sender, or recipient.

**Where it's delivered:** the recipient's **kind-10050 DM-relay list**
(`fetch_dm_relays`), with our own default relays as fallback, plus any relay
hints carried by a pasted `nprofile`. Default relays: `relay.goblin.st`,
`relay.damus.io`, `nos.lol` (`src/nostr/relays.rs`), capped at `MAX_DM_RELAYS`.

**How relays are reached:** every relay connection runs through an in-process
**Tor** client (arti, linked directly into the wallet binary — no sidecar), via
`TorWebSocketTransport` (`run_service` waits for Tor to be ready before dialing).
So the relay never sees your IP: the money-path relay is dialed at its pinned
`.onion` address, and any relay without one is reached over a Tor exit to its
clearnet host. The Grin *node* connection (block sync + broadcasting the final tx)
is direct clearnet — it's public chain data, the same for everyone, not tied to
your identity.

The UI tracks an outgoing attempt via a coarse **send phase**
(`client::send_phase`): `IDLE / WORKING / SENT / FAILED / REQUEST_BLOCKED`, with a
human-readable failure reason on `FAILED`.

---

## 4. Flow A — Pay by username/npub (Standard, we send)

Dispatched as `WalletTask::NostrSend(amount, npub, note, relay_hints)`; handled in
`wallet.rs`.

1. `w.send(amount)` builds the **S1** slate and **locks our outputs** (the funds
   are reserved but not yet spent).
2. **Save meta `Created`** *before* any network call — this is the durable point
   a crash recovers from.
3. `send_payment_dm` delivers S1 → **`AwaitingS2`** (storing the gift-wrap event
   id). On dispatch failure → **`SendFailed`** (retryable). On success the contact
   is created/refreshed (so people you pay appear in Suggested) and a background
   NIP-05 lookup resolves their name.
4. The recipient replies S2 (Flow B). When their S2 gift wrap arrives, the ingest
   guard routes it to `nostr_finalize_post`, which finalizes **S3** and posts it
   on-chain → **`Finalized`**.

```
Created ──(S1 sent)──▶ AwaitingS2 ──(their S2 arrives)──▶ Finalized
   └──(dispatch fails)──▶ SendFailed ──(retry)──▶ AwaitingS2
   └──(manual cancel / 24h expiry)──▶ Cancelled  (outputs unlocked)
```

---

## 5. Flow B — Receiving (Standard, we're paid)

Our service subscribes to kind-1059 gift wraps addressed to us
(`run_service`). When an **S1** arrives, `handle_wrap` runs the ingest pipeline
(§7) and `decide()` classifies it by the **accept policy**:

- `Everyone` → **AutoReceive** (auto-reply S2).
- `Contacts` → AutoReceive if the sender is a known contact, else **SurfaceIncoming** (an approval card).
- `Ask` → always SurfaceIncoming.

**AutoReceive:** `nostr_receive` builds the **S2** reply; we save meta
`Received` / **`ReceivedNoReply`**, mark the message processed, then dispatch S2 →
**`RepliedS2`**. If the S2 dispatch fails we stay at `ReceivedNoReply` and resend
on the next start (§9). The sender then finalizes S3 (Flow A step 4).

```
(incoming S1) ──▶ ReceivedNoReply ──(S2 dispatched)──▶ RepliedS2
                      └──(dispatch fails)──▶ stays ReceivedNoReply → resent on restart
```

**SurfaceIncoming** instead stores a `PaymentRequest` (status `Pending`) for the
user to approve or decline — see Flow D.

---

## 6. Flow C — Request money (Invoice)

**We request** — `WalletTask::NostrRequest(amount, npub, note, …)`:

1. First we check the recipient hasn't opted out: `accepts_requests` reads their
   kind-0 `goblin_accepts_requests` field; an explicit `false` → phase
   `REQUEST_BLOCKED` and we stop (fail-open: unknown/unreachable = allowed).
2. `issue_invoice(amount)` builds **I1** (no outputs locked — it's just an ask).
3. Save meta `RequestedByUs / Created`, dispatch I1 → **`AwaitingI2`**.
4. When the payer's **I2** arrives, the ingest guard finalizes **I3** and posts →
   **`Finalized`**.

**They approve & pay** (the other side of the same flow) is Flow D.

```
Created ──(I1 sent)──▶ AwaitingI2 ──(their I2 arrives)──▶ Finalized
   └──(SendFailed → retry)        └──(cancel / expiry)──▶ Cancelled
```

---

## 7. Flow D — Approving an incoming request (we pay an invoice)

Someone's **I1** is *always* surfaced as a `PaymentRequest`, **never auto-paid**
(a hard security invariant). It shows in the Requests list. The user can:

- **Approve** → `WalletTask::NostrPayRequest(rumor_id)`: re-parse the stored
  slatepack (must still be I1), `nostr_pay` builds **I2** (this is where *we* pay),
  save meta `RequestedOfUs / ReceivedNoReply`, dispatch I2 → **`PaidAwaitingFinalize`**,
  mark the request `Approved`. The requester then finalizes I3.
  A "Paying…" spinner shows while this runs; the card clears on success.
- **Decline** → `WalletTask::NostrDeclineRequest(rumor_id)`: mark `Declined` and
  send a **void** control DM so the requester's side clears too.

A surfaced incoming *Standard* S1 (from SurfaceIncoming) is approved the same way,
but routes through `nostr_receive` (Flow B) rather than `nostr_pay`.

`RequestStatus`: `Pending → Approved | Declined | Expired | Cancelled`
(`Cancelled` = the requester withdrew it via a void).

---

## 8. The ingest guard — `decide()`

Every incoming gift wrap is judged by `decide()` (`src/nostr/ingest.rs`), a
**positive allow-list**: anything not explicitly accepted is `Drop`ped. This is
the security core. Summary:

| Incoming state | Condition | Decision |
| --- | --- | --- |
| `Standard1` | amount 0, or slate already known | **Drop** |
| `Standard1` | new, policy `Everyone` (or `Contacts` + known) | **AutoReceive** |
| `Standard1` | new, policy `Contacts` + unknown, or `Ask` | **SurfaceIncoming** |
| `Standard2` | matches our pending `Sent` tx (status `AwaitingS2/Created/SendFailed`) **and** sender == stored counterparty **and** the tx exists | **FinalizePost** |
| `Standard2` | sender mismatch, or status `Cancelled`/`Finalized`, or no meta | **Drop** |
| `Invoice1` | amount 0, already known, or incoming-requests disabled | **Drop** |
| `Invoice1` | otherwise | **SurfaceRequest** (never auto-pay) |
| `Invoice2` | matches our pending `RequestedByUs` tx + sender match | **FinalizePost** |
| `Invoice3` / unknown | — | **Drop** |

Key consequences:
- A **late S2 on a cancelled send** falls through to `Drop` — so cancelling is
  safe even if the recipient's reply is still in flight (the cancel marks the meta
  `Cancelled` *first*, and `decide()` then drops the S2).
- Finalize only happens for a slate we are actually waiting on, from the exact key
  we sent to.
- Invoices are never auto-paid.

---

## 9. Cancel & reclaim

A stuck outgoing send (recipient never replied) locks your outputs. You can
reclaim them manually from the receipt's **"Cancel payment"** button, or the 24h
auto-expiry does it for you (§10).

`WalletTask::NostrCancelSend(slate_id)` (`wallet.rs`):
1. Take the `cancel_finalize_lock` — this **serializes against a concurrent S2
   finalize** so the two can't both win (cancel-and-post would be a double action).
2. **Re-check live state under the lock.** If the tx is already `Finalized`, or
   confirmed/posted on-chain → do nothing and return `CancelOutcome::AlreadyCompleted`
   ("This payment already went through and can't be cancelled"). If already
   `Cancelled` → idempotent success.
3. Otherwise mark the meta **`Cancelled` first**, then `w.cancel(tx_id)` to unlock
   the Grin outputs, then best-effort send a **void** control DM to the recipient
   (they're likely offline). → `CancelOutcome::Cancelled` ("your funds are
   available again").

**Receipt button visibility** (`cancelable_send` gate): shown only while the send
is still unanswered — direction `Sent`, status in `{Created, AwaitingS2,
SendFailed}`, **not** confirmed, **not** already cancelled, and either it never
reached a relay (`SendFailed`, shown immediately) or the grace window
(`cancel_grace_secs`, default 600s) has passed. The instant the recipient accepts
(status leaves that set) the button disappears.

**Recipient side / void ordering:** a void control message marks the slate so that
if the recipient's wallet later (or earlier) sees the S1, it's dropped — including
the **void-before-S1** race, where the void arrives first and is recorded as
`void:{slate_id}:{sender}` so the subsequent S1 is dropped.

There are sibling tasks for the other directions: `NostrCancelOutgoing` (withdraw
an invoice we issued) and `NostrDeclineRequest` (decline an incoming request) —
both send a void and mark the local record.

---

## 10. Auto-expiry (24h)

`expire_stale` (`src/nostr/client.rs`) runs from the sync loop. Any non-terminal
meta older than `expiry_secs` (default 24h) is expired:

- If it **locked our outputs** (`expiry_locks_outputs`: a `Sent` send in
  `Created/AwaitingS2/SendFailed`, or a `RequestedOfUs` invoice we paid in
  `PaidAwaitingFinalize`) → cancel the Grin tx to unlock, and mark meta `Cancelled`.
- If it locked nothing of ours (incoming payments, invoices we issued) → just
  annotate `Cancelled`.
- Pending incoming `PaymentRequest`s flip to `Expired`.

This is the same unlock path as manual cancel; the manual button just lets you act
before the 24h.

---

## 11. Crash recovery (`reconcile`)

On service start, `reconcile` (`client.rs`) re-dispatches any pending outgoing
message within a 7-day window, by `(direction, status)`:

| Direction · status | Slate | Action |
| --- | --- | --- |
| `Sent` · `Created`/`SendFailed` | Standard1 | resend S1 → `AwaitingS2` |
| `RequestedByUs` · `Created`/`SendFailed` | Invoice1 | resend I1 → `AwaitingI2` |
| `Received` · `ReceivedNoReply` | Standard2 | resend S2 → `RepliedS2` |
| `RequestedOfUs` · `ReceivedNoReply` | Invoice2 | resend I2 → `PaidAwaitingFinalize` |

Because the slatepack text is persisted and the meta is written *before* every
dispatch, a crash at any point is recoverable: re-sending an already-delivered
message is harmless (the peer dedups it; see §12).

---

## 12. Confirmations (X / N)

A posted Grin tx matures over `min_confirmations` blocks (default 10) before it's
spendable. Grin marks a tx `confirmed` at the **first** block, but Goblin's
receipt counts toward the spendable threshold so the number actually moves
(`data::receipt_detail`):

- broadcast, no block yet → `0 / N`
- on-chain, immature → `count / N` where `count = tip − inclusion_height + 1`
- `count ≥ N` → matured (shown as complete; the receipt's network-fee row is shown
  only for outgoing payments — a recipient pays no fee).

---

## 13. Reliability primitives

- **Dedup / processed markers** (`store::{is_processed, mark_processed,
  prune_processed}`): every wrap is recorded at three levels — the gift-wrap event
  id, the inner rumor id, and `slate:{id}:{state}` — so a replayed or re-sent
  message is processed exactly once. Markers TTL out after 30 days
  (pruned on start + hourly).
- **Rate limiting** (`allow_sender`): per-sender sliding window — 30 events/hour
  for known contacts, 10/hour for unknowns — plus a global decrypt ceiling
  (~120 NIP-44 unwraps/min) to bound CPU/battery against fresh-keypair spam. A
  message dropped purely for the *global* ceiling isn't marked processed, so it can
  be retried later.
- **Seal integrity:** the gift-wrap seal signer must equal the inner rumor author,
  and self-addressed messages are dropped.
- **The cancel/finalize lock** (§9) prevents a cancel and a finalize from both
  succeeding on the same slate.

---

## 14. Name freshness (contacts)

Cached `@usernames` are re-validated against the name authority on a periodic
sweep (`NAME_REVERIFY_INTERVAL_SECS`, ~78s, capped per tick), and once at app open
(persisted `last_name_sweep_at`, gated to the interval).
`nip05::check` returns `Verified / Mismatch / Unreachable`: a name is only
**cleared** (falls back to the npub) on a definitive `Mismatch` (the server says
it's gone or now maps to a different key) — never on a transient network failure.
This catches released or reassigned names and stops a freed name from
impersonating someone. A user-set petname is never touched.

---

## 15. File map

| Concern | File |
| --- | --- |
| Status / direction / meta types | `src/nostr/types.rs` |
| Gift-wrap + control message build/parse | `src/nostr/protocol.rs` |
| Service loop, send/receive/finalize, expiry, reconcile, name sweep | `src/nostr/client.rs` |
| Ingest allow-list | `src/nostr/ingest.rs` |
| Wallet task handlers (NostrSend / Request / PayRequest / CancelSend / finalize) | `src/wallet/wallet.rs` |
| Task definitions | `src/wallet/types.rs` |
| Metadata + dedup + contacts store | `src/nostr/store.rs` |
| NIP-05 resolve / verify / register, name authority | `src/nostr/nip05.rs` |
| Identity (key, NIP-49 backup) | `src/nostr/identity.rs` |
| Receipt / activity / confirmations / display name | `src/gui/views/goblin/data.rs` |
| Relay defaults + name-authority defaults | `src/nostr/relays.rs` |

---

🤖 Documentation written with AI pair-programming assistance (Claude).
