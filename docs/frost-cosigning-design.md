# FROST P4 Cosigning - Implementation Guide

**Status:** Design draft
**Last updated:** 2026-06-29
**Extends:** docs/frost-2-of-n-design.md §5 (per-signature ceremony)
**Implements:** FROST roadmap phase P4

P3 made FROST keys creatable, persistable, and recoverable. P4 makes
them **signable** — a NIP-46 `sign_event` request against a
`KeyTypeFrostUser` key goes through a 2-round cosigning ceremony
between the signer and the user's browser before a valid BIP-340
Schnorr signature is returned.

This document closes the design questions left open in §5/§10 of the
main FROST design doc, fixes the wire formats, picks the
implementation library on both sides, and breaks the work into
shippable phases P4a–P4f.

---

## 1. Choices resolved in this doc

Three choices were marked open in the main design doc. Decisions
locked in here:

| Question | Decision | Section |
|---|---|---|
| Cosign-request channel | **NIP-46-style ephemeral relay event** (rejected: WebSocket, Web Push) | §2 |
| Cosign-request event kind | **`kind:24135`** (immediately after NIP-46's 24133/24134; ephemeral range) | §2.2 |
| WASM signing crate | **Hand-roll FROST-secp256k1 against `k256`** to byte-match `bytemare/frost` (rejected: `frost-secp256k1` from ZcashFoundation, because its commitment+share encodings don't match `bytemare/frost`) | §3 |
| NIP-46 dispatch | **Branch on `KeyType` inside `signer.handleSignEvent`**; FROST keys go to a new `cosignDispatcher`, non-FROST keys keep the existing path | §4 |

The remaining open question — auto-approval grant policy (§5 in the
main doc) — is deferred to P4f.

---

## 2. Cosign-request channel

### 2.1 Why relay-based, not WebSocket or Push

The main design doc §5.3 already chose this; restating the
rationale concisely:

- **WebSocket from browser → signer** is the simplest implementation
  but requires the browser to be on a long-lived connection to the
  signer specifically. That's another stateful service to operate,
  and it would not survive a future onion-endpoint migration cleanly
  (multiple WebSocket transports inside the Tor circuit).
- **Web Push API** adds Apple/Google/Mozilla as MITM partners
  (push payloads pass through their infrastructure). Inconsistent
  with privacy-architecture §1.1 (We Cannot Comply) unless we run
  our own push server, which is the same operational lift as
  websocketing it.
- **NIP-46-style ephemeral relay event** uses the relay infrastructure
  we already operate (cloistr-relay) and that the browser is already
  subscribed to for the regular NIP-46 flow. No new infrastructure,
  no new partner, and the user's existing relay-set governs visibility.

The cost is real: if the user's tab is closed, they cannot sign. This
is the **intended hardware-wallet-like UX**: keys controlled by
something you have, not by a process running unattended on a server.
The mobile share holder (item 16) is the future answer for
sign-when-laptop-asleep.

### 2.2 Event kinds and tags

We use **two new kinds**, both in the NIP-EE ephemeral range
(`20000–29999`) so relays don't persist them:

- **`kind:24135` — cosign request.** Signer → user.
- **`kind:24136` — cosign response.** User → signer.

Both events are wrapped in NIP-44-encrypted payloads addressed to the
counterparty. They live on the same relay set as the user's existing
NIP-46 connection so the browser already has the subscription open.

**`kind:24135` cosign request:**

```json
{
  "kind": 24135,
  "pubkey": "<signer's npub for this user's session>",
  "tags": [
    ["p", "<user's session ephemeral pubkey>"],
    ["session", "<cosign session id, 16 random bytes hex>"],
    ["key_id", "<the FROST key being signed for>"]
  ],
  "content": "<NIP-44-encrypted payload>",
  "created_at": <unix ts>,
  "sig": "..."
}
```

**Encrypted content:**

```json
{
  "v": 1,
  "event_to_sign": {
    "kind": 1,
    "content": "the post the user is about to send",
    "tags": [...],
    "created_at": ...,
    "pubkey": "<the FROST joint pubkey>"
  },
  "event_id": "<32-byte sha256 of the canonical serialization>",
  "client_app": {
    "name": "...",
    "url": "..."
  },
  "signer_commitment": {
    "hiding": "<33-byte SEC1 hex, signer's D_i>",
    "binding": "<33-byte SEC1 hex, signer's E_i>"
  }
}
```

**`kind:24136` cosign response:**

```json
{
  "kind": 24136,
  "pubkey": "<user's session ephemeral pubkey>",
  "tags": [
    ["p", "<signer pubkey>"],
    ["session", "<same cosign session id>"]
  ],
  "content": "<NIP-44-encrypted payload>",
  "created_at": <unix ts>,
  "sig": "..."
}
```

**Encrypted content (approval):**

```json
{
  "v": 1,
  "approved": true,
  "user_commitment": {
    "hiding": "<33-byte SEC1 hex, user's D_i>",
    "binding": "<33-byte SEC1 hex, user's E_i>"
  },
  "partial_signature_hex": "<32-byte scalar hex, user's z_i>"
}
```

**Encrypted content (denial):**

```json
{
  "v": 1,
  "approved": false,
  "reason": "user denied" | "wrong event kind" | "auto-rules rejected" | "..."
}
```

### 2.3 Why the commitments travel WITH the partial sig in one event

FROST signing is conceptually a 2-round protocol — both parties
commit, then both parties sign over the combined commitments. The
canonical FROST flow would be:

```
1. Signer  → user: signer commitment
2. User    → signer: user commitment
3. Signer  → user: nothing (just exchange complete)
4. User    → signer: user partial sig
5. Signer  → user: combined signature
```

Two relay round-trips on top of the existing NIP-46 latency is bad
UX. Compressing to one relay round-trip:

```
1. Signer  → user: signer commitment + event to sign  (kind:24135)
2. User    → signer: user commitment + user partial sig  (kind:24136)
3. Signer combines + returns the signed event via the existing
   NIP-46 response path
```

This works because the user can compute its partial sig as soon as
it has both commitments — the signer's commitment arrives in the
request, the user generates its own commitment + partial sig
together. The signer can do the same on its side after receiving
the user's commitment, then aggregate.

The trade-off: an adversarial signer could pre-compute its
commitment-and-partial against a chosen `event_to_sign`, then
adaptively reveal them after seeing the user's commitment. This
would let it slightly bias `R = D_signer + ρ_signer·E_signer +
D_user + ρ_user·E_user` toward chosen values, which in FROST is
already a non-attack (the signature is still valid; the signer can't
extract the user's share from it). Acceptable.

### 2.4 Cosign session lifecycle

- Signer creates a cosign session when a `sign_event` request comes
  in for a FROST-user key. Session state: `{session_id, key_id,
  signer_nonces (d, e), signer_commitment (D, E), event_hash,
  nip46_request_id, created_at}`.
- Session TTL: 60 seconds (same as DKG session TTL).
- On user response: signer combines, returns the NIP-46 response,
  drops the session.
- On timeout: signer drops the session and returns a NIP-46 error
  (`"cosign timed out"`) to the original client.
- On denial: signer drops the session, returns NIP-46 error
  (`"user denied"`).

---

## 3. Wire-format interop: WASM ↔ Go

### 3.1 The interop problem

`bytemare/frost` is the Go library powering the server side. Its
`Commitment.Encode()` and `SignatureShare.Encode()` produce bytes in
a specific layout. The Rust crate `frost-secp256k1` from
ZcashFoundation implements the same IRTF FROST draft but its on-the-
wire encoding differs subtly (field order, length prefixes,
identifier sizing). Two RFC-conformant implementations are not
guaranteed to byte-match.

We already chose to hand-roll the DKG math against `k256` in P3a
for exactly this reason. For P4 we stay on the same path: hand-roll
the signing math in the WASM module against `k256`, producing bytes
that `bytemare/frost.Commitment{}` and `bytemare/frost.SignatureShare{}`
will accept verbatim.

### 3.2 What the WASM module must compute

Mathematically, FROST round-1 nonce pairs are two random scalars
`(d_i, e_i)` and their commitments `(D_i, E_i) = (d_i·G, e_i·G)`.
Round 2's partial signature is

```
z_i = d_i + e_i · ρ_i + λ_i · s_i · c
```

where:

- `ρ_i = H("FROST-secp256k1-SHA256-v1 binding factors" || i || B || msg)` — the
  binding factor, with `B` being the encoded commitment list of all
  participants.
- `λ_i = ∏_{j≠i}(x_j / (x_j - x_i))` — Lagrange coefficient for index `i`
  evaluated at `0`.
- `s_i` — the participant's secret share.
- `c = H_{BIP340}("BIP0340/challenge" || R || P || msg)` where `R = ∑(D_j + ρ_j · E_j)`
  is the aggregated nonce and `P` is the joint pubkey, both
  x-only-encoded per BIP-340.

The exact byte layouts that `bytemare/frost` expects:

| Object | Encoding |
|---|---|
| Participant identifier | `uint16` big-endian, 2 bytes (`bytemare/frost` uses uint16) |
| Scalar (share, partial sig, binding factor) | 32-byte big-endian secp256k1 scalar |
| Element (commitment, R) | 33-byte SEC1 compressed |
| Commitment serialization | `id(2) || hiding(33) || binding(33)` = 68 bytes per participant |
| CommitmentList for binding factor | concatenated commitments, **sorted by id ascending** |
| Binding-factor hash domain tag | `"FROST-secp256k1-SHA256-v1"` (verify in bytemare/frost source — pinned by integration test, see §3.4) |

Identifiers in our 2-of-N user-cosigner case are fixed:
`UserIndex = 1`, `SignerIndex = 2`. CommitmentList is therefore
always `[user_commitment, signer_commitment]` after sorting.

### 3.3 What the WASM module exports

Adds five exports to `ui/frost-wasm/src/lib.rs`. All are stateless
in the same sense as the existing DKG primitives:

| Function | Returns |
|---|---|
| `generate_signing_nonce_pair() → { nonce_state_hex, commitment }` | Fresh `(d, e)` scalars (opaque hex blob) plus their commitments `(D, E)` as compressed-SEC1 hex |
| `compute_user_partial_signature(nonce_state_hex, user_share_hex, signer_commitment_hiding_hex, signer_commitment_binding_hex, joint_pubkey_hex, event_hash_hex) → partial_sig_hex` | The user's `z_user`, 32-byte scalar hex |
| `aggregate_frost_signature(user_partial_hex, signer_partial_hex, user_commitment, signer_commitment, joint_pubkey_hex, event_hash_hex) → bip340_sig_hex` | The combined 64-byte BIP-340 Schnorr signature, hex |
| `verify_bip340_signature(pubkey_hex, event_hash_hex, sig_hex) → bool` | Self-check the WASM can perform before submitting |

The aggregate + verify functions exist for two reasons:
- Defensive self-check before sending the partial sig over the
  relay — if the WASM combines its own contribution with the
  signer's expected contribution incorrectly, we want to find out
  before the signature is published.
- Test-harness reuse: the Go-side test can run both sides through
  WASM via a thin RPC layer (or use the equivalent Go logic that
  `bytemare/frost.AggregateSignatures` does).

### 3.4 Interop test (mandatory, gate for P4b → P4c)

A Go test in `internal/frost/user_signer_test.go` MUST do:

1. Generate a fixed 2-of-2 DKG output deterministically.
2. Run the existing `bytemare/frost.Signer` flow for both parties
   on a known message. Capture the resulting signature.
3. Run the WASM path for the user side (via `wasm-bindgen-test` or
   a Go-side reimplementation that follows §3.2 exactly).
4. Cross-combine: server-side sig + WASM-side commitments, and
   vice versa. All four combinations must produce identical
   BIP-340 signatures.

If this test ever regresses, no further P4 work merges. It is the
single point that proves the wire format matches.

---

## 4. NIP-46 dispatch for FROST keys

`internal/signer/signer.go::handleSignEvent` currently does:

```go
event.PubKey = targetPubkey
event.Sign(privateKey)  // direct ECDSA on the stored nsec
```

For FROST-user keys, `privateKey` is the empty string (we don't
hold a complete nsec). The dispatch must branch:

```go
key, err := s.storage.GetKeyByPubkey(ctx, targetPubkey)
if err == nil && key.KeyType == storage.KeyTypeFrostUser {
    return s.cosignDispatcher.SignEvent(ctx, key, &event, perm)
}
// existing path
```

`cosignDispatcher` is a new component (P4d) that:

1. Loads the FROST share for `key.id` from storage.
2. Decrypts the share via the user's Vault encryptor (we have the
   user's vault token via the NIP-46 session that resolved
   `targetPubkey` to a key).
3. Generates the signer's nonce pair via `bytemare/frost.Signer.Commit()`.
4. Publishes the cosign-request event (kind:24135) to the user's
   relays.
5. Subscribes for the cosign-response event (kind:24136) with the
   matching `session` tag.
6. On response: decrypts, decodes the user's commitment + partial
   sig, runs the signer's `Sign()`, aggregates, returns the
   signed event JSON.
7. On timeout or denial: returns a NIP-46 error.

### 4.1 Where the user's vault token comes from

NIP-46 sessions today don't carry the user's vault token directly.
The vault token lives in the user's signer-web session (JWT) — but
the NIP-46 client is a third-party app (Damus, etc.) that doesn't
have that JWT.

For FROST keys this is a real problem: we need the user's vault
token to decrypt the signer's share.

**Decision: store the vault token on the NIP-46 session row** when
the user creates the NIP-46 connection through the signer web UI.
At connection time the user is logged in and has a vault token; we
copy it into the session row.

For NIP-46 sessions created via bunker URI (where no web UI is
involved), FROST signing is not supported in v1. The bunker URI
flow falls back to a "this key cannot sign via this connection"
error message. The user must connect via the web UI to use FROST.
This restriction is documented at bunker URI generation time —
FROST keys get a different bunker URI flow that walks the user
through web-UI-initiated connection.

(This is the same UX trade-off Bitcoin hardware wallets make: some
flows just don't work without a UI present. It's the cost of
removing operator-side custody.)

---

## 5. Implementation phases

Decomposed into shippable PRs, each one self-contained and testable:

### P4a — server-side cosign coordinator + Go interop reference
- New `internal/frost/user_signer.go`: server-side coordinator that
  uses `bytemare/frost.Signer` for the signer-side contribution and
  accepts the user-side commitment + partial sig from over the wire.
- Test (`user_signer_test.go`) that simulates the user side IN GO
  (also via `bytemare/frost.Signer`) and proves the full ceremony
  produces a valid BIP-340 signature.
- NO HTTP endpoints, NO WASM, NO relay traffic yet. Just the pure
  Go protocol piece.
- Acceptance: existing FROST tests still green; new test passes;
  signed-message output verifies under `nostr.Verify`.

### P4b — Rust WASM partial-sig primitives
- Add the 5 exports listed in §3.3 to `ui/frost-wasm/src/lib.rs`.
- Hand-roll FROST signing against `k256` matching `bytemare/frost`'s
  encoding (§3.2).
- Native Rust tests for: nonce-pair determinism (random but
  reproducible-from-rng), partial-sig math under fixed inputs.
- Acceptance: interop test from §3.4 passes end-to-end; aggregated
  signature verifies under BIP-340 from both directions.

### P4c — relay channel + cosign-request publish/subscribe
- Server-side: publish kind:24135, subscribe for kind:24136. Reuse
  the existing per-key NIP-46 relay client.
- Browser-side: subscribe to kind:24135 events addressed to the
  user's session ephemeral pubkey, on the FROST key's relays. New
  module `ui/src/lib/cosign-listener.ts`.
- Acceptance: a Go integration test stands up a fake relay
  (`httptest`-style WebSocket) and exercises a full sign_event →
  cosign-request → cosign-response → signed-event flow with a
  WASM-driven user side.

### P4d — NIP-46 dispatch + Vault token in NIP-46 session
- Branch `handleSignEvent` on `key.KeyType`.
- Add `vault_token` field to NIP-46 session storage; populate when
  the session is created via the web UI; require non-empty for
  FROST sign requests.
- Acceptance: end-to-end integration test where a fake NIP-46
  client posts `sign_event` for a FROST key and gets back a valid
  signed event.

### P4e — Browser approval UI
- Cosign listener (P4c) opens an approval modal on incoming
  kind:24135 events. Modal renders the event content (kind label,
  human-readable summary, raw JSON expand), client app metadata,
  and Approve/Deny buttons.
- On approve: call the WASM partial-sig primitives and publish the
  kind:24136 response.
- On deny: publish a kind:24136 denial.
- Add an indicator on the Keys page that this device is actively
  listening for cosign requests.

### P4f — Auto-approval policies (deferred from main design §5.6)
- Per-permission, time-bounded auto-approval grants. Skipped for
  v1; comes in this phase once the manual flow is working and
  users actually need automation.

---

## 6. Risk register

| Risk | Mitigation |
|---|---|
| WASM signing math diverges from `bytemare/frost` wire format | Mandatory cross-impl test (§3.4) is the merge gate for P4b → P4c |
| Browser tab closed when sign request arrives | Documented; mobile share holder (item 16) is the future fix; in v1 the request times out and the NIP-46 client retries |
| Adversarial signer biases the nonce | FROST's one-round-compressed shape leaves this as a theoretical concern with no known attack (§2.3); revisit if academic literature shifts |
| User's vault token absent on bunker-URI-initiated NIP-46 session | FROST sign requests fail with an explicit "connect via web UI for FROST" error; documented at bunker URI generation |
| Cosign relay propagation latency > 1s feels broken | UX shows progress: "asking your device to cosign…" with the existing NIP-46 approval modal pattern. Acceptable per design doc §5.5. |
| Cosign request seen by relay operator (metadata leak) | Encrypted content (NIP-44); the only leakage is "the user with pubkey X is signing something now". For users who want this leak closed too, Tor egress per item #5 in the privacy architecture is the long answer. |

---

## 7. Out of scope (explicitly)

- Multi-device cosigning with `N > 2` shares. The design supports it
  (the math is unchanged) but the UX of "ask each device, gather
  signatures, aggregate" needs its own design pass. In v1 every
  FROST key is 2-of-2.
- Hardware token cosigning. Same shape as mobile (item 16); not
  here.
- Share refresh as part of signing. Refresh is its own ceremony
  (P5 in the main FROST roadmap).
- Threshold migration (changing 2-of-2 → 2-of-3 in place). Future.

---

## 8. Reference

- `draft-irtf-cfrg-frost` — IRTF FROST draft
- `bytemare/frost` Go library docs
- `k256` Rust crate, signing API
- BIP-340 (Schnorr Signatures for secp256k1)
- NIPs 44 (encrypted payloads), 46 (remote signing)
- docs/frost-2-of-n-design.md §5 — original cosigning sketch this
  doc extends
- docs/privacy-architecture.md §1.1 — We Cannot Comply (driving
  constraint for the vault-token-on-session decision)
