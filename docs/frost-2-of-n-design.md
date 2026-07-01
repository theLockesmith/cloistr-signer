# FROST 2-of-N User-Cosigner Design

**Status:** Design draft
**Last updated:** 2026-06-15
**Implements:** privacy-architecture.md §3.3 (custody — the architectural inversion)
**Dependencies:** None. This doc precedes any code work.

This document defines how the cloistr-signer moves from being a key *custodian* (Vault-encrypted nsecs decrypted in signer memory at sign time) to being a *cosigner* (FROST share-holder that cannot sign without an active user device). It is the design that makes privacy-architecture.md §1.1's "We Cannot Comply" claim structurally true rather than aspirational.

It is also the design that unblocks items 9, 10, and 16 of the privacy-architecture implementation sequence.

---

## 1. Goal and Threat Model Delta

### 1.1 What changes

| Property | Today (Vault transit) | After this design (FROST 2-of-N) |
|---|---|---|
| Master nsec exists in full | Yes, in signer memory at every sign | **Never. Anywhere. At any time.** |
| Operator can extract a usable key from running process | Yes (memory dump of decrypted nsec) | No (only a share, useless alone) |
| Operator can produce signatures alone | Yes (with Vault token from active session) | **No.** Every signature requires a live user-device cosignature |
| Operator can comply with "produce user X's signing keys" | Yes | **No** (operator can produce its share; recipient still cannot sign) |
| Each signature requires user device participation | No (one-time MFA at session login) | **Yes** (per-signature, not per-session) |
| User device compromise alone yields signing | No (operator share absent) | No (operator share absent) |
| Operator compromise alone yields signing | **Yes** (full nsec extractable) | No (user device share absent) |
| Both parties must be compromised to forge a signature | No | **Yes** — the architectural inversion |

This design exists specifically to flip the **"Operator can produce signatures alone"** row from Yes to No.

### 1.2 What stays the same

- The user's npub. Joint pubkey from FROST DKG IS the npub. Existing keys migrate to FROST-controlled npubs by keeping their pubkey; only the secret representation changes (from a Vault-encrypted nsec to two FROST shares).
- The NIP-46 bunker protocol. Clients (Damus, Amethyst, etc.) talk to the signer unchanged. The cosigning happens behind the signer's NIP-46 endpoint.
- The signer's per-key relay model and all the privacy guardrails shipped in items 1, 8, 12, 13.

### 1.3 Adversaries in scope (delta from privacy-architecture.md §1.2)

- **Operator with full server access** — must gain *nothing usable* from the share. This is the property that makes the design work.
- **Operator under lawful compulsion** — handing over the operator's share is structurally insufficient to forge signatures; the demanding party still needs the user's device.
- **Network attacker between user device and signer** — must not be able to swap, replay, or downgrade cosignature requests. Mitigated by the existing NIP-46 transport encryption + a signing-request authentication layer added below (§5).
- **User device compromise** — yields only the user share. Operator still required. Single-compromise does not produce signatures.

### 1.4 Adversaries explicitly NOT in scope

- **Both parties compromised at once.** If the operator and the user's device are both controlled by the attacker simultaneously, signatures can be forged. This is the irreducible floor of any 2-of-2 threshold scheme. We document it; we don't fix it. Higher thresholds (2-of-3 with hardware token) is the natural extension when users want it.
- **User-side malicious browser.** A malicious browser script can request signatures for events the user doesn't see (the script controls what the browser cosigns). We do not solve this; we minimize blast radius (clear cosignature prompts, user must approve event content visible in the UI before share contribution is computed).

---

## 2. Architecture Overview

### 2.1 Roles

```
┌──────────────────────────────────┐
│ User account (one human)         │
│                                  │
│  ┌──────────────────────────┐    │
│  │ User-side share-holders  │    │
│  │                          │    │
│  │  - browser (IndexedDB)   │    │
│  │  - phone app (optional)  │    │
│  │  - hardware token (opt.) │    │
│  │  - recovery phrase       │◀───┼── BIP39, derives share locally
│  │    (re-derivable)        │    │
│  └──────────────────────────┘    │
└──────────────────────────────────┘
                │
                │ NIP-46 + cosign protocol
                │ (see §5)
                ▼
┌──────────────────────────────────┐
│ Cloistr signer                   │
│  ┌──────────────────────────┐    │
│  │ Signer-side share        │    │
│  │ - encrypted with Vault   │    │
│  │   transit (user token)   │    │
│  │ - one per FROST identity │    │
│  └──────────────────────────┘    │
└──────────────────────────────────┘
                │
                │ NIP-46 ← from third-party clients
                ▼
┌──────────────────────────────────┐
│ Third-party Nostr clients        │
│ (Damus, Amethyst, etc.)          │
│ Do not hold shares.              │
│ Talk to signer over NIP-46       │
│ unchanged. Unaware of FROST.     │
└──────────────────────────────────┘
```

**Key invariant:** any signature on the user's joint pubkey requires the cooperation of (signer-share-holder) AND (at least one user-side share-holder). The two together produce a valid Schnorr signature; either alone produces nothing.

### 2.2 Threshold choice: 2-of-N

- **2 = the minimum threshold of cooperators required to sign.**
- **N = total share count.** Default N=2 (signer + one user device). User can add devices (N grows); each addition keeps the threshold at 2.

Why 2-of-N specifically and not 2-of-2:

- Multi-device UX (browser + phone) requires that EITHER user device can cosign with the signer. That's 2-of-N, not 2-of-2.
- The recovery phrase is a virtual share holder that can be re-derived; it counts toward N but is also the recovery anchor.
- Higher thresholds (e.g., 3-of-N requiring hardware token) are a configurable upgrade per privacy-architecture.md §3.1.

### 2.3 Why FROST (not other threshold schemes)

- **Schnorr-compatible.** FROST produces standard BIP340 Schnorr signatures indistinguishable from non-threshold signatures. Relays and clients see nothing unusual. Required because Nostr uses BIP340 Schnorr.
- **Deployed.** `bytemare/frost` already imported (see `go.mod`). The signer-to-signer DKG code in `internal/frost/dkg_distributed.go` validates the library on real workloads. Move to user-cosigner shape composes on top, not greenfield.
- **RFC-track.** `draft-irtf-cfrg-frost`. Active standardization, multiple independent implementations (Zcash, Ed25519, secp256k1), audit history.
- **Non-interactive at signing** (in the FROST3 variant): nonces precomputed offline, signing requires one round of partial signature exchange. Latency tractable.

Alternatives considered and rejected:

- **2-of-2 ECDSA threshold (Lindell17/Doerner-style).** Works for Bitcoin but Schnorr is what Nostr uses. Adds protocol-level distinguishability if anyone compares signature shape.
- **MuSig2.** Two-of-two aggregated Schnorr. Works for 2-of-2 specifically; doesn't generalize to N>2 in the device-add story. FROST does.
- **Password-derived envelope.** Discussed in privacy-architecture.md §3.3.1. The master nsec still exists in full at sign time; doesn't achieve the inversion.

---

## 3. Share Storage and Cryptographic Substrate

### 3.1 Signer-side share storage

The signer holds **one share per FROST identity** (one per user, possibly more if a user has multiple FROST-controlled npubs). Each share:

- Stored in PostgreSQL as a new `signer_frost_user_shares` table (distinct from the existing `signer_frost_shares` which holds shares for the signer-to-signer DKG product).
- Encrypted via the user's Vault transit key (same encryption envelope already used for nsecs today). Decryption requires the user's Vault token, which lives in the user-session and disappears at session expiry.
- Carries: `share_index`, `verification_share` (public, for partial-signature verification), `created_at`, `rotation_generation` (increments on share refresh).

The Vault encryption is belt-and-braces — even if an attacker reads the database, they get ciphertext useless without a live user-token-bearing session. With or without FROST, this stays.

### 3.2 User-side share storage

Each user device holds a share. Per-device storage:

- **Browser:** IndexedDB, encrypted with a key derived from the user's account password via PBKDF2 (high iteration count — ≥ 600,000 per current OWASP guidance, recomputed at first decrypt and cached in memory for the session). The share is never written to disk in plaintext.
- **Mobile app:** platform secure-element (iOS Keychain / Android Keystore). Direct OS-backed key material, no in-memory plaintext at rest.
- **Hardware token (future):** the token itself holds the share, partial signatures performed on-device.
- **Recovery phrase:** the phrase is not stored as such — it's *re-derivable* into the share via BIP39 → `PhraseToSeed` (already implemented in `internal/crypto/recovery_phrase.go`) → FROST share derivation function. The user holds the phrase on paper; the share is regenerated whenever they enter it.

### 3.3 Share derivation from the recovery phrase

This is the only non-standard primitive in the design. Standard FROST DKG generates shares from joint randomness; the recovery phrase reconstructs a share *deterministically* so the user can recover after losing all devices.

**Approach:** at DKG time, the user contributes their share's polynomial coefficients deterministically from the phrase, not from fresh randomness:

```
seed       = BIP39(phrase, "")        // 64 bytes
share_seed = HKDF-Expand(seed, "cloistr-frost-share-v1", 32)
polynomial = expand_polynomial(share_seed, threshold)
```

The signer's polynomial coefficients are still random (signer contributes fresh entropy from `crypto/rand`). The joint pubkey depends on both, so it varies across DKG sessions even with the same phrase.

**Why this works for recovery:** entering the phrase on a new device regenerates the same `polynomial` coefficients, hence the same share, hence cosigning still works with the existing signer-side share.

**Why this is safe:** the signer's share is independent of the phrase. Compromising the phrase alone yields one share; the operator share is still required to forge signatures. The phrase is structurally equivalent to one user device.

### 3.4 Cryptographic substrate

- **Curve:** secp256k1 (BIP340 / Nostr).
- **Hash:** SHA-256 (BIP340 standard).
- **Library:** `github.com/bytemare/frost` (already in `go.mod`).
- **Polynomial degree:** threshold − 1 = 1 (linear polynomial for 2-of-N).
- **WASM build:** for the browser share-holder. Either compile a Go subset to WASM (the existing `internal/frost/` could be reused) or use a JS/TS FROST implementation. See §8.

---

## 4. DKG Ceremony

This is how a fresh FROST identity gets created (at signup, or when a user migrates an existing key).

### 4.1 Channel choice

The existing signer-to-signer DKG uses Nostr ephemeral DMs (decision 2026-03-25). For user-cosigner DKG, that's wrong:

- **Latency.** Nostr DM round-trips are 100ms-1s+; a 3-round DKG would take 5+ seconds. Browser users will not tolerate that for signup.
- **Browser dependency.** A browser doesn't want to be a Nostr relay subscriber just to do its own signup.
- **Authentication.** The user is authenticated to the signer via the existing session token. We have a direct, mutually-authenticated channel to them — using it.

**Decision:** DKG runs over **the existing authenticated HTTPS channel between browser and signer** (a new `/api/v1/frost/user-dkg` endpoint family). Three rounds = three POST/response exchanges. Real wall-clock: well under a second.

For mobile apps that connect via NIP-46 only: a fallback over NIP-46 itself, using a new ephemeral session-bound message kind. Out of scope for v1; ship browser-only first.

### 4.2 DKG round structure (browser ↔ signer, 2-of-N specifically)

**Round 1 — commit:**

```
Browser:                                       Signer:
─ Generate phrase + show to user.
─ User confirms phrase backed up.
─ share_seed = HKDF(BIP39_seed)
─ Polynomial: f(x) = a0 + a1·x         ─ Polynomial: g(x) = b0 + b1·x  (random)
  where a0 = HKDF(share_seed, "a0")        random b0, b1
        a1 = HKDF(share_seed, "a1")
─ Browser commits: A0 = a0·G, A1 = a1·G ─ Signer commits: B0 = b0·G, B1 = b1·G

  POST /api/v1/frost/user-dkg/round1
    body: { commits: [A0, A1] }
  ────────────────────────────────────▶
                                       ─ Stores browser commits
                                       ─ Returns: { commits: [B0, B1], session_id }
  ◀────────────────────────────────────
```

**Round 2 — share exchange:**

```
Browser:                                       Signer:
─ Evaluates polynomial at index 2 (signer):
  share_for_signer = f(2) = a0 + a1·2
─ Encrypts share_for_signer to signer pubkey
  via NIP-44

                                       ─ Evaluates polynomial at index 1 (browser):
                                         share_for_browser = g(1) = b0 + b1
                                       ─ Encrypts via NIP-44 to browser pubkey

  POST /api/v1/frost/user-dkg/round2
    body: { encrypted_share_for_signer, session_id }
  ────────────────────────────────────▶
                                       ─ Decrypts received share
                                       ─ Verifies: share·G == f-commitment(2)
                                       ─ Returns: { encrypted_share_for_browser }
  ◀────────────────────────────────────
```

**Round 3 — finalize:**

```
Browser:                                       Signer:
─ Decrypts received share
─ Verifies: share·G == g-commitment(1)
─ Computes my final share:
  my_share = f(1) + g(1)
─ Computes joint pubkey:
  P = A0 + B0
─ Stores my_share in IndexedDB (encrypted)
                                       ─ Computes signer's final share:
                                         signer_share = f(2) + g(2)
                                       ─ Computes joint pubkey: P = A0 + B0
                                       ─ Stores signer_share Vault-encrypted
                                       ─ Creates Key record with Pubkey = P

  POST /api/v1/frost/user-dkg/finalize
    body: { confirm_pubkey: P, session_id }
  ────────────────────────────────────▶
                                       ─ Verifies P matches signer's computation
                                       ─ Marks DKG complete
                                       ─ Returns: { key_id, pubkey: P }
  ◀────────────────────────────────────
```

**Total wall-clock:** three HTTPS round-trips + crypto ≈ 200-500ms in practice.

**Failure modes:** any round can abort. The session_id binds the browser and signer to the same DKG attempt; if either aborts, the other discards and a new ceremony starts. Half-committed state is GC'd after a short timeout.

### 4.3 Session expiry during DKG

If the user's session expires mid-DKG, the encrypted shares can't be persisted (Vault token gone). Mitigation: DKG ceremony bounded to a 60-second window; on session timeout during DKG, the in-memory state is dropped and the user is prompted to restart.

---

## 5. Signing Ceremony (Per-Signature)

This is what happens every time a Nostr client (Damus, etc.) asks the signer to sign an event.

### 5.1 Today's flow (current Vault custody)

```
Nostr client            Signer (cloistr)
─ NIP-46 sign_event ───▶
                        ─ Loads decrypted nsec for the requested key
                        ─ Signs locally
                        ─ Returns signed event
                ◀──── signed event
```

### 5.2 New FROST flow

```
Nostr client            Signer                          User device (browser)
─ NIP-46 sign_event ───▶
                        ─ Looks up FROST key for pubkey
                        ─ Generates signing session_id
                        ─ Generates signer's nonce commitment R_S
                        ─ Pushes cosignature request:
                          { event, session_id, R_S }     ──────────────────▶
                                                              ─ Renders event in UI
                                                              ─ User reviews + approves
                                                              ─ Generates user's nonce R_U
                                                              ─ Computes partial sig σ_U
                                                                = nonce + share·challenge(event)
                                                          ◀──── { R_U, σ_U }
                        ─ Verifies σ_U against verification_share
                        ─ Computes its own partial sig σ_S
                        ─ Combines: σ = σ_U + σ_S
                        ─ Verifies σ against joint pubkey
                        ─ Returns signed event
                ◀──── signed event
```

### 5.3 Channel for the cosignature request

The signer needs a way to push a cosignature prompt to the user's device. Options:

**A. WebSocket / SSE from browser to signer.** Browser maintains a persistent connection to the signer; signer pushes prompts. Reliable when browser is open; doesn't reach a closed laptop.

**B. Web Push API.** Browser receives a push notification even when tab is closed. Requires user grant + a push service (Apple/Google/Mozilla). Adds a deanonymizing partner unless self-hosted (which is possible).

**C. NIP-46-style relay channel.** Signer publishes a kind:24134 (new) cosignature-request event to a known relay; browser subscribes. Same as how NIP-46 itself routes today. No new partner.

**Choice: C** for parity with existing infrastructure and to avoid adding a push service. Pre-condition: the browser has an open subscription to the cosignature-request kind on the same relay set as its key. Closed-laptop = no signing, which is *the correct UX*: if your device is offline, your identity cannot sign. This is the intended hardware-wallet-like UX.

For users who want signing-without-laptop-open, the answer is a mobile app share holder (item 16). Not solved by tweaking the browser path.

### 5.4 Approval UI

The user device must show the user what's being signed before contributing its partial signature. Renders:

- Event kind (resolved to plain English: "Note", "DM", "Profile update", etc.)
- Event content (truncated for long bodies, full available)
- Requesting client (from NIP-46 connect metadata)
- Approve / Deny buttons

On Approve: partial signature computed and sent. On Deny: explicit deny message sent so the signer can fail the NIP-46 request cleanly instead of timing out.

**Trust-on-first-use prompts:** for newly-connected NIP-46 clients, an additional "first time this app has asked you to sign" warning.

### 5.5 Latency budget

| Step | Estimated time |
|---|---|
| Signer receives NIP-46 request | 100-300ms (relay propagation) |
| Signer publishes cosignature-request | 50-150ms |
| Browser receives, prompts user | < 100ms |
| User reviews + approves | **human-scale, 1-5 seconds** |
| Browser computes σ_U, publishes | < 50ms |
| Signer combines, returns signed event | < 50ms |

Realistic user-perceived latency: 1.5-6 seconds per signature, dominated by user review time. For batch operations (`batch_sign`), one cosignature ceremony covers the batch.

### 5.6 Auto-approval policies

Some signing operations should not require explicit user approval per signature (e.g., a streaming app posting one note per second would be unusable). Solution: per-permission auto-approval grants, time-bounded and kind-bounded.

```
User approves: "Damus may sign kind:1 events for the next 24 hours without prompting"
```

The browser holds this grant; signs partial sigs automatically when the request matches. The grant lives in IndexedDB and applies only on this device. Other devices prompt the user.

Caveat: a compromised browser with such grants can produce signatures within the grant scope. The user trades convenience for blast radius. We display active grants clearly.

---

## 6. Device Add, Remove, Refresh

### 6.1 Adding a device

User wants to start using their phone in addition to their browser. Ceremony:

1. User on browser initiates "add device" — browser displays a one-time QR code containing a short-lived session token.
2. User scans QR on phone. Phone authenticates to signer with the session token.
3. **Re-share ceremony:** browser + signer cooperate to generate a fresh share for the phone, *without changing the joint pubkey*.
   - Browser contributes a 0-evaluation of a fresh polynomial whose constant term is 0 (so the joint key is preserved).
   - Signer does the same.
   - Phone's new share = sum of contributions.
4. Phone stores the share in iOS Keychain / Android Keystore.

The phone is now a peer cosigner. Either browser-or-phone + signer can sign. N has grown from 2 to 3; threshold remains 2.

### 6.2 Removing a device

User loses their phone. Ceremony:

1. User initiates "revoke device" from another active device.
2. Signer + remaining device perform a **share refresh** — both contribute new polynomial pieces whose constant terms are 0; the joint pubkey is preserved but all shares (including the removed phone's) are now invalid.
3. The removed phone's share, if recovered by an attacker, no longer combines with the new signer share to produce signatures.

This is the FROST share-refresh primitive. The bytemare library supports it natively.

### 6.3 Periodic share refresh (proactive)

Even without device removal, periodic share refresh defends against gradual compromise: an attacker who steals a share at time T cannot use it after the refresh at T+N. Recommended cadence: monthly.

The refresh runs automatically when the user logs in if N days have passed since the last refresh. No user-visible action.

### 6.4 Recovery from total device loss

User has lost browser, phone, hardware token. Holds only the BIP39 phrase.

1. User loads cloistr-signer in a fresh browser, enters username + password.
2. Browser sees "no share found for this user."
3. Recovery flow: "Enter your 24-word phrase."
4. Browser derives share locally: `share = expand_polynomial(HKDF(BIP39_seed), ...)`
5. Browser claims to have its share; offers proof via partial signature on a challenge from the signer.
6. Signer verifies the partial sig against its stored verification_share (which doesn't change across DKG, refreshes, etc.) — proves the user has the correct share.
7. **Critical step:** signer + browser run a share refresh to invalidate any historical browser shares (the lost phone's share, etc.) that the attacker who took the user's devices might still hold.

After step 7, the user is back to a 2-of-2 (browser + signer) configuration. They can re-add devices via §6.1.

### 6.5 Account-level recovery (forgot password)

If the user forgot their password but has the phrase: phrase decrypts a backup of the password-derived KEK from their encrypted blob (§3.1 of privacy-architecture.md option 4), or they use social recovery (option 3), or backup codes (option 2).

If they lost the phrase AND the password and have no other recovery option enabled: account is gone. By design.

---

## 7. Migration Path from Current Custody

Existing keys today are Vault-encrypted nsecs. Migration:

### 7.1 Opt-in per key

Migration is **per-key, opt-in.** Users keep their current Vault-encrypted keys until they explicitly choose to migrate. No forced migration; no flag day.

### 7.2 Per-key migration ceremony

1. User selects "Upgrade to FROST" on a specific key in the UI.
2. Browser warns: "This will require this device (and any future devices) to participate in every signature. Recovery phrase will be shown."
3. User confirms.
4. Browser generates phrase; ceremony runs (§4 DKG).
5. **Key swap, atomic on the signer:** signer reads its existing Vault-encrypted nsec, deletes it, and writes the FROST share with the same pubkey. The pubkey is preserved by the FROST DKG using the existing nsec as one input (see §7.3).

### 7.3 Joint pubkey preservation across migration

The DKG defined in §4 produces a *fresh* joint pubkey. To preserve the existing pubkey across migration, the ceremony is modified: the signer's polynomial constant term `b0` is set to `existing_nsec - a0` where `a0` is the user's polynomial constant term contributed in DKG round 1. Then:

```
P = A0 + B0 = a0·G + (nsec - a0)·G = nsec·G = existing pubkey
```

The signer needs the plaintext nsec briefly to compute `b0`. This is the **one** point in the migration where the existing nsec is fully reconstructed in signer memory. After the FROST shares are written and the migration is committed, the old Vault-encrypted nsec is deleted. The window of plaintext exposure is the migration itself — seconds, not session-long.

After migration completes, the property holds: the master nsec never exists in full at sign time.

### 7.4 Rollback

The migration is one-way. Once the FROST shares are written and the old nsec deleted, going back to Vault custody would require the user device to re-publish the constant term plus the signer's share — i.e., it's the same protection: the master nsec exists only with both parties' cooperation, and we don't want to reconstruct it.

For users who panic: re-running DKG to a fresh joint pubkey is an option, and they can publish a NIP-41 succession event from the old key to the new (signed at migration time and stored encrypted for later use).

---

## 8. Browser WASM Stack

### 8.1 Options

**Option A: Compile `internal/frost/` to WASM via Go's `js/wasm` target.**

- Pro: single source of truth; the Go code is already audited as part of the codebase.
- Pro: `bytemare/frost` library and ecc primitives compile to WASM cleanly.
- Con: Go WASM binaries are large (~5-10 MB even after minification). Initial page load cost.
- Con: Go's runtime in WASM has GC overhead; partial signatures aren't latency-critical but page-load is.
- Mitigation: lazy-load the WASM module only when the user first needs to cosign (not on every page).

**Option B: TypeScript/JS FROST implementation.**

- Pro: small bundle size, no WASM runtime overhead.
- Con: cryptographic code in JS is harder to audit and easier to side-channel. Constant-time guarantees vanish.
- Con: dual implementations (Go server-side, JS client-side) — divergence risk.
- Pro: existing libraries like `@cmdcode/frost` (the closest match in the JS ecosystem).

**Option C: WebAssembly FROST from a Rust implementation** (e.g., `frost-secp256k1` from ZcashFoundation).

- Pro: smallest WASM size (~200 KB), fastest, most-audited reference implementation.
- Pro: also reusable for the mobile app's WASM-bridged code path.
- Con: adds a Rust toolchain dependency in the build.
- Pro: matches the trajectory of the rest of the privacy-architecture work (item 14 ZK proofs likely also wants Rust/WASM).

**Recommendation: Option C.** Smallest, fastest, best-audited. Rust toolchain is a one-time setup cost. The build artifact is a `.wasm` file the browser fetches; no Rust runtime needed at the client.

### 8.2 Browser integration

- WASM module loaded lazily on first signing operation.
- Exposes: `dkg_round1`, `dkg_round2`, `dkg_finalize`, `partial_sign`, `share_refresh_contribute`, `derive_share_from_phrase`.
- Browser-side glue (TypeScript) handles IndexedDB encryption, cosignature request UI, and HTTPS/relay channel I/O.

### 8.3 Mobile

Same Rust core compiled to native (iOS/Android) via standard cross-compilation. The mobile app (item 16, future) consumes the same crate, ensuring share-format compatibility across the user's devices.

---

## 9. Implementation Phases

Sequenced for shippable PRs:

| Phase | Scope | Effort | Ships |
|---|---|---|---|
| P1 | Storage: `signer_frost_user_shares` table + Go types; per-user share CRUD with Vault encryption | M | Schema + storage layer only; no user-visible change |
| P2 | Server-side DKG endpoints (`/api/v1/frost/user-dkg/*`) using `internal/frost/` directly | L | DKG works server-to-server (a Go test harness can drive it); no browser yet |
| P3 | Rust FROST WASM module + browser glue + IndexedDB share storage | L | Browser can run DKG end-to-end with the server; user sees fresh FROST identity created |
| P4 | Per-signature cosignature ceremony: cosign-request kind, signer-side cosign dispatcher, browser-side approval UI | L | A user can sign events from a third-party Nostr client with FROST behind the scenes |
| P5 | Device add, remove, share refresh | M | Multi-device, share rotation |
| P6 | Recovery-phrase share derivation + recovery flow | M | Lost-device recovery works end-to-end |
| P7 | Migration ceremony for existing keys | M | Existing users can opt into FROST per key |
| P8 | Auto-approval policies + grant UI | S | UX polish; high-volume clients become usable |

Each phase is one PR. P1-P4 are the critical path to "users can actually sign with FROST." P5-P8 round out the feature.

---

## 10. Open Questions

Items not resolved in this design that need decisions before implementation:

1. **Auto-approval grant authority** — Can the user device alone grant auto-approval, or does the signer enforce a maximum (e.g., "no auto-approval window may exceed 7 days")?
2. **DKG abort GC timeout** — How long does the signer hold half-committed DKG state before discarding? 60 seconds is the working assumption; needs testing under network jitter.
3. **Share-refresh cadence** — Monthly is the working assumption. Calibrate against real session frequency to avoid refresh-on-every-login.
4. **Cosign request kind number** — Need to pick a kind in the application-specific range (30000-39999 ephemeral) and document it. Or use a Cloistr-specific kind with a clear range.
5. **Hardware token support shape** — Out of scope for v1 but the share-storage interface should not preclude it. The `share` field needs to accommodate "share lives in a token, we hold a pointer."
6. **Relay-level visibility of cosign requests** — Cosign-request events are encrypted (NIP-44), but the relay sees the request happened. Is that a privacy issue worth Tor-routing the cosign channel specifically?
7. **Mobile app authentication** — How does the phone authenticate to the signer for DKG/cosign messages? OAuth-style flow with QR code (§6.1)? Long-lived device tokens? Per-message NIP-46-style ephemeral keys?

These get resolved either in P1's pre-work or as sub-design docs.

---

## 11. Out of Scope (Explicitly)

Listed so future readers know these are NOT addressed here:

- **Threshold higher than 2.** Possible extension. Not in v1.
- **Cross-signer FROST (signer-to-signer multi-organization).** The existing `internal/frost/dkg_distributed.go` already handles this for shared-custody keys held across multiple cloistr-signer instances. That use case is distinct and stays as-is.
- **Forced migration.** Users keep Vault-custody keys until they opt into FROST.
- **Recovering from a leaked phrase.** If the phrase is compromised, the user must rotate to a fresh joint pubkey (item 7 NIP-41 succession). The design has no way to revoke a known-good phrase that's also known to an attacker.

---

## 12. Marketing-Claim Deltas vs Privacy-Architecture §7

This design changes the truth value of two claims listed in privacy-architecture.md §7:

| Claim | Pre-FROST status | Post-FROST status |
|---|---|---|
| "We cannot sign without you." | Aspirational (operator with Vault token CAN sign while user is logged in) | **Structurally true** (per-signature cosignature required) |
| "We cannot be compelled to produce data we don't hold." | Partially true (we hold the encrypted nsec; with subpoena + Vault root we could decrypt) | **Structurally true** (we hold only a share; share alone is useless to compelled disclosure) |

The other claims in §7 are unchanged.

---

## Reference

- `draft-irtf-cfrg-frost` — IETF draft, current revision
- `bytemare/frost` Go library, used today by `internal/frost/`
- `frost-secp256k1` Rust library (ZcashFoundation), proposed for the WASM module
- `internal/frost/dkg_distributed.go` — existing signer-to-signer DKG implementation, reference for protocol shape
- `internal/crypto/recovery_phrase.go` — BIP39 primitive, the phrase-to-share derivation hook
- privacy-architecture.md §1.1, §3.3 — the "We Cannot Comply" principle and custody design

---

## 13. 2026-07-01 Design refinements (P5 + P7 + org scaling)

Design conversation on 2026-07-01 resolved several open questions from
§6, §7, and §9. These refinements supersede the corresponding
subsections above where they conflict.

### 13.1 P5 refinements (device add/remove/refresh)

**Personal-only in v1.** Multi-device support ships for single-user
accounts first; org-scale multi-device (§13.3) is a follow-up phase
with its own UX and governance surface.

**Pairing UX = short code, not QR.** Rejected the §6.1 QR flow because
it requires camera access and forces desktop→mobile as the primary
direction. Chosen: existing device generates a 6-word cloistr-<verb>-
<noun>-<verb>-<noun>-<verb> pairing code valid for 60s. New device
enters code + phrase; existing device confirms in a modal. Works
symmetrically (mobile→desktop or desktop→mobile).

**Refresh trigger = manual button on the Keys page** in v1. Deferred:
scheduled auto-refresh (§6.3 "monthly"). Manual button first, measure
usage, then decide whether automation is worth the complexity.

**Device removal = refresh + narrow n.** §6.2's "share refresh"
approach confirmed. Reduces n by 1 so the removed device's share is
invalidated AND no longer counts toward quorum.

### 13.2 P7 refinements (migration from existing keys)

Three migration paths, all shipped simultaneously. User picks per key
at conversion time.

**Path A — Server-side conversion (default for signer-managed keys):**
User clicks "Convert to FROST" on a Vault-encrypted key. Signer
decrypts existing nsec via Vault, splits into `p_signer = random` +
`p_user = p - p_signer`, Vault-encrypts both halves, stores
`encrypted_user_share_at_dkg` for the P3e-b recovery path so the
browser can fetch it. Same pubkey, same Nostr identity. Nsec exposed
transiently to signer memory but that's identical to today's threat
model (signer already decrypts on every sign). Migration eliminates
future exposure without adding new exposure.

**Path B — Interactive additive split (for keys living in a different
client, shipped 2026-07-01):** Two-round protocol.

_Round 1 (init)._ Browser sends `{ pubkey, name }`. Signer verifies
the caller doesn't already own this pubkey and creates a 5-minute
session id. NO crypto material exchanged at init — the browser does
all the math in Round 2.

_Round 2 (finalize)._ Browser (with pasted nsec `p`):
1. Samples fresh random `p_user`
2. Computes `p_signer = (p - p_user) mod n`
3. Computes `R_user = p_user·G`
4. Drops `p` from memory
5. Sends `{ session_id, p_signer_hex, r_user_hex, relays }`
6. Retains `p_user` in IndexedDB

Signer verifies `p_signer·G + R_user == pubkey·G`. If yes, the
browser proved `(p_signer + p_user) = p` WITHOUT ever transmitting
`p`. Signer Vault-encrypts `p_signer`, persists Key + FrostUserShare.

**An earlier version of this doc had a broken variant** where the
signer generated `r_signer` and sent `R_signer` (commitment) to the
browser, expecting the browser to compute `r_user = p - r_signer`.
That doesn't work because R_signer is a curve POINT and the browser
can't extract the scalar r_signer (discrete log). The corrected
protocol above has the browser own the split, matching what actually
shipped.

Security properties preserved:
- Nsec `p` exists only in browser JS heap, briefly (steps 1–4)
- Nsec never on the wire, never on the signer
- Signer only sees `p_signer` (its own future share)
- Browser only retains `p_user` (its own future share)
- Neither party alone can reconstruct `p`

This is the theoretical floor for existing-key migration: someone
has to hold `p` momentarily and this minimizes that to the
browser's execution stack for the duration of Round 2.

**Path C — Fresh FROST + kind:0 rotation (paranoid path):** Mint fresh
FROST key, publish kind:0 profile update pointing at new pubkey,
kind:1776-style migration signal for followers. Some follower loss
over time; best cryptographic properties.

**Migration is one-way.** Rejected downgrade-from-FROST. Users who
want out mint a fresh non-FROST key and rotate via Path C. Simpler
mental model, one less footgun.

**Confirmation ceremony = password re-entry + "I understand my old
key material will be irrecoverable" checkbox.** Guards against
physical-access attacks on unlocked browsers.

### 13.3 Org scaling (new; addresses §9 P5-P7 not-yet-covered surface)

Org customers may want unusual (t, n) shapes (2/12 for social-media
teams, 3/15 for finance approvers). No cryptographic ceiling on n —
FROST math works for any t≥2, n≥t on secp256k1. Signing cost scales
with t (aggregation is O(t)), NOT n. DKG/refresh is O(n²) but
one-shot.

Real ceilings are UX and governance, not crypto:

- Refresh coordination: at n>25 herding all shareholders online for a
  refresh ceremony is hard
- Accountability loss: FROST aggregate sigs are cryptographically
  anonymous over which t-of-n produced them; signer audit log records
  participation but is a trust-the-signer surface
- Governance surface: who gets a share, when revoked, offboarding
  ceremony — all linear in n

**Decision: soft-warn, do not hard-cap:**

| Rule | Action |
|---|---|
| `t = 1` | refuse (no threshold security) |
| `t = n` | warn (lost share bricks the key) |
| `t < n/3` | warn (unusual outside social-media-team pattern) |
| `n > 10` | warn (real coordination cost) |
| `n > 25` | firmer warn (suggest two-tier — §13.3.1) |
| `n > 50` | still allow but UI says "talk to us first" |

**Default org onboarding presets:**

- "Small team" preset: `2/3` (three people, any two to sign) — probably
  60-70% of org users
- "Governance-heavy team" preset: `3/5` (five key people, majority) —
  another 20%
- "Custom" mode with above warnings — everyone else

#### 13.3.1 Two-tier pattern for orgs

Rather than fighting orgs into a single wide-quorum key, offer a
delegation shape:

- **Master FROST key** with tight quorum (e.g. 5/9 board/ownership
  group). Rarely signs. Used to delegate authority.
- **Operational subkeys** with loose quorums (e.g. 2/12 social media
  team, 3/15 finance approvers, etc.). Sign frequently. Owned by the
  master key.

Master signs a NIP-26-style delegation authorizing each subkey for
specific kinds/rate limits/durations. Losing an operational subkey is
a rotate-and-reissue; losing the master key is the org-level disaster
we keep the quorum tight around.

Architecturally same shape as the existing `KeyType 'proxy'`
machinery. Extending proxy chaining to FROST is a small structural
addition, not a rewrite.

### 13.4 Roadmap impact

The original §9 phases P5 and P7 stay valid, with the following
scope adjustments:

- **P5 now personal-only.** Org multi-device becomes a new phase P5-org
  after P5 ships.
- **P7 now covers all three migration paths.** UI presents them as a
  choice; user picks per key. Path A first (most users), then Path B
  (broadens address), then Path C (paranoid).
- **Two-tier org support becomes a new phase P9** (master-subkey
  delegation for FROST keys). Depends on P4 (cosigning must work) and
  the existing proxy-key mechanism.

