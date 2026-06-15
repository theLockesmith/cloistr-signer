# Privacy Architecture Design

**Status:** Design draft
**Last updated:** 2026-06-15

This document defines the privacy architecture for Cloistr Signer. It is the source of truth for *why* the signer is built the way it is, and the reference any future feature should be checked against before it ships.

It is also, deliberately, a marketing document. The claims it makes about what the operator can and cannot do are the claims we are willing to make to users. Every architectural choice in here is downstream of those claims.

---

## 1. Threat Model

### 1.1 Design principle: "We Cannot Comply"

The signer MUST be architected such that the operator, when served a lawful demand for user data, can truthfully respond that the requested information does not exist in retrievable form.

This is the load-bearing principle of the entire design. Every other decision in this document is downstream of it. Where two designs are equally good on every other axis but one of them leaves us holding data we could be compelled to produce, we pick the other.

The shorthand: **if the government comes knocking, we can honestly say we can't do it.**

### 1.2 Adversaries in scope

| Adversary | What they want | Our posture |
|---|---|---|
| Lawful demand (court order, subpoena) | User identity, signing keys, social graph, content | Operator structurally cannot produce |
| Compromised operator (insider) | Same as above | Cryptographically infeasible to extract |
| Compromised infrastructure (breach) | Same as above | At-rest data is useless without user-held secrets |
| Hostile relay operator | Pubkey-to-IP mapping, social graph correlation | Network-layer mitigations + per-key isolation |
| Network observer (ISP, transit) | Connection metadata, traffic patterns | Tor egress, ephemeral sessions, cover traffic |
| Behavioral correlator (sophisticated party) | Re-link disposable identities by behavior | Signer-side guardrails; user-side discipline required |

### 1.3 Adversaries out of scope

- **User device compromise.** We cannot prevent this. We minimize blast radius (no plaintext keys on the device beyond what's actively in use; per-device shares so one compromise doesn't grant signing).
- **Behavioral deanonymization by the user themselves.** A user who follows the same 200 accounts from their disposable as from their primary defeats the cryptography. The signer can refuse to *help*; it cannot enforce client discipline.
- **Public posts being readable.** Public broadcast is the medium, not a threat. The link between post and human is what we protect, not the post's existence.
- **State-level adversaries with persistent network surveillance.** Tor + our design raises the cost meaningfully but is not a guarantee. We say this out loud to users.

---

## 2. Privacy Axes

We use the Pfitzmann-Hansen terminology (four axes), specialized for our context. Each axis has a ceiling — sometimes a hard one — and the architecture targets that ceiling.

### 2.1 Pseudonymity

The user's identity is not linked to their real-world name.

- **Ceiling:** None worth naming. Maxable.
- **What it requires:** No identifying information at signup, no third-party processors who learn the user's identity, the option of Tor-anchored signup for users who care.

### 2.2 Unlinkability

Two identities of the same human cannot be tied together by an observer.

- **Cryptographic ceiling:** Maxable via Taproot-tweaked context keys derived client-side, combined with no signer-side knowledge of the master.
- **Behavioral ceiling:** Bounded by the user's own discipline. The signer can refuse to *help* (kind filtering, metadata withholding, relay isolation) but cannot prevent a user from re-correlating themselves.

### 2.3 Untraceability

The originator of an action cannot be determined.

- **For private content (DMs):** Signal-grade achievable. NIP-17 gift-wrap + Tor + relay diversity.
- **For network origin:** Tor-grade achievable.
- **For public posts:** The npub is the originator by protocol definition. The link between npub and human is severable (see 2.2); the link between npub and post is not.

### 2.4 Unobservability

An action cannot be detected.

- **For private subset (DMs, online presence, signer usage):** Maxable via gift-wrap, cover traffic, ephemeral sessions, no presence broadcast.
- **For public subset:** Zero. The post's existence is the point of posting.

### 2.5 The Snowden axis — credentialed authority

Distinct from the four classical axes: **the ability to assert credibility without identity.** "I have access to PRISM" or "I am authorized to sign on behalf of Empire" without revealing which credentialed individual is making the claim.

This deserves its own treatment because the cryptographic primitive (ring signatures, ZK set-membership, BBS+ anonymous credentials) is independent of the other axes.

- **Ceiling:** Maxable for any credential whose issuer publishes a public membership set.
- **Hard part:** The cryptography is mature; the social/institutional credentialing infrastructure is not. We ship the proof-generation side and let credentialing ecosystems form around it (or not).

---

## 3. Design Decisions

### 3.1 Pseudonymity

**No email, ever.** Email is a deanonymizer disguised as convenience. Recovery is handled by user-held secrets, not server-held identifiers. We do not have, and cannot be subpoenaed for, an email-to-user mapping that does not exist.

**Username + password account, with the username deterministically mapped to an account pubkey via HKDF.** This already exists (decision 2026-03-25). The user's "account npub" is derivable, idempotent, and contains no identifying information.

**TOTP MFA — already shipped** (`internal/auth/auth.go` — `GenerateMFASecret`, `ValidateMFACode`). MFA gates account access, orthogonal to share recovery; both layers compose.

**Recovery — two purposes, four mechanisms, 1-of-4 default:**

Recovery splits into two distinct purposes that the four mechanisms address:

- **Account-access recovery** — password / MFA lost, can't authenticate.
- **Share recovery** — FROST share gone (lost device, cleared browser), need to reconstitute cryptographic material.

| Mechanism | Recovers | Default? | Operator involved? | Status |
|---|---|---|---|---|
| 24-word recovery phrase | Share (pure client-side derivation) | Yes (mandatory) | No | Not yet built |
| 10 backup codes | Account-access + share (KDF-stretched, signer-held salts useless without the code) | Yes (mandatory) | Signer holds salts + rate-limits | **Account-access path shipped** (`GenerateBackupCodes`, `DefaultBackupCodeCount = 10` in `internal/auth/auth.go`). Share-derivation extension not yet built. |
| Social recovery | Share (M-of-N attesters cosign fresh DKG re-share) | Optional | Signer participates with attesters | Not yet built |
| User-managed encrypted blob | Share (user-stored, phrase-decrypted) | Optional | No | Not yet built |

**Composition:** any one of the four is sufficient to recover (1-of-4 default). High-security users can opt into N-of-M policies requiring multiple factors. Phrase-only mode disables operator-participating paths (codes, social) entirely.

**Each enabled recovery option is both a safety net and an attack surface.** Phrase / blob: an attacker who learns the secret wins. Codes: attacker with the codes + signer interaction wins (rate limits help). Social recovery: attacker who can coerce M of N attesters wins. The phrase-only mode is the strongest configuration and is recommended for users whose threat model includes coercion.

Lose all enabled mechanisms and the account is gone. By design.

**Payment.**

| Method | Status |
|---|---|
| Lightning | Primary |
| On-chain BTC | Supported for larger amounts |
| Monero | Supported for chain-side unlinkability |
| Cashu | Supported for unlinkable micropayments |
| Card processor (Stripe et al.) | NEVER. Adds a deanonymizing partner. |

**Account-pubkey rotation.** The HKDF-derived account npub is rotatable on demand. Same human, fresh account-npub. Old npub publishes a NIP-41 successor record signed by the rotation (see 3.7 for why this is a careful tradeoff).

### 3.2 Signup network exposure

**Cloudflare tunnel: dropped.** Cloudflare terminates TLS, sees every byte, holds logs, and is subpoenable independently of us. Inconsistent with the threat model.

**Replacement stack:**

- Direct nginx ingress with Let's Encrypt
- fail2ban + LB-tier rate limiting for DDoS mitigation
- Onion endpoint live as a co-equal entry point (not a fallback)

**Clearnet signup hardening (for users who don't use Tor):**

- Signup IP is not bound to the npub. If captured for fraud/quota purposes, it's encrypted to an admin-only key and auto-purged after a short retention window.
- Zero third-party analytics, font CDNs, or scripts. The signer is the only party that sees the user.
- Signer→relay egress can be routed via Tor when the user opts in per-key.

**Onion endpoint.** Live in parallel from day one. Same bunker URI scheme, same auth, just a `.onion` host. Promoted in the UI for users performing sensitive operations.

### 3.3 Custody — the central architectural decision

This is the largest single design call in the document.

**Today:** Vault transit per-user encryption. The signer holds the user's plaintext nsec in memory at sign time. An operator with access to the running process can extract live keys. Better than a shared encryption key, but not the target.

**Target:** **FROST 2-of-N threshold signing.** The master key is split between the signer and the user's devices. **It never exists in full form, ever** — not at rest, not in memory, not at sign time. Each signature is a multi-party computation between the signer and at least one user device.

The FROST scaffolding is largely built (decision 2026-03-25, learning 2026-04-01): distributed DKG, distributed signing API, share import/export, signer-chaining integration, Web UI. Share rotation and the browser-side share holder are the principal remaining pieces.

#### 3.3.1 Distinction from "password-derived envelope"

A password-derived envelope encrypts the master at rest under a key derived from the user's password. The master is decrypted in signer memory at sign time. **This is meaningfully weaker than FROST.** An operator with access to the running process during an active session can grab the decrypted master. We are not building this; it's listed only to disambiguate from the FROST design.

FROST is different in kind: there is no operation, anywhere, that produces the full master key. The signer only ever sees its share's contribution to the joint signature.

#### 3.3.2 Multi-device architecture

```
                    ┌─────────────────────────┐
                    │   User's Master Key     │
                    │  (joint pubkey only)    │
                    └────────────┬────────────┘
                                 │ split via DKG
              ┌──────────────────┼──────────────────┐
              ▼                  ▼                  ▼
       ┌────────────┐    ┌────────────┐    ┌────────────┐
       │  Signer    │    │  Browser   │    │  Phone     │
       │  share     │    │  share     │    │  share     │
       └────────────┘    └────────────┘    └────────────┘
              │                  │                  │
              └──────────┬───────┴──────────────────┘
                         │
                    Any 2-of-3 can sign
                    (signer + any 1 device)
```

- **Share holders are user devices.** Browser session (share in IndexedDB, wrapped by password-derived KEK), phone app, optional hardware token. Each device holds one share.
- **Signer holds its share.** Always required to participate (we are the second-of-two no matter which user device is involved).
- **Nostr clients (Damus, Amethyst, third-party apps) hold no shares.** They talk to the signer over NIP-46 unchanged. The signer prompts whichever user device is currently online for cosignature approval. The user approves on their device; the cosignature flows back; signer combines and returns to the Nostr client.
- **Adding a device:** DKG ceremony between an existing device + signer issues a new share. Joint pubkey unchanged. Identity unaffected.
- **Removing a device:** Share refresh without that device's contribution. The removed device's share becomes useless even if retained.
- **Losing all devices:** Recovery phrase or backup codes reconstruct a share locally.

#### 3.3.3 Why this isn't research-grade risk

This is a deployed pattern. Web3Auth, Lit Protocol, ZenGo, 1Password's recent crypto features, and several hardware wallet companion-app architectures ship variants of it. The cryptography (FROST) is RFC-track (`draft-irtf-cfrg-frost`). Our remaining work is integration, not invention.

#### 3.3.4 Honest costs

- **Latency:** ~100-500ms additional round-trip per signature for the cosignature step.
- **Offline-user UX:** A user with no reachable device cannot sign. Acceptable for a privacy product; matches hardware wallet UX.
- **Share-loss recovery:** Required, handled by recovery phrase / social recovery (see 3.1).
- **Engineering:** FROST partial-signing in WASM on the client. Real, but not exploratory.

### 3.4 Unlinkability — Taproot-tweaked context keys

For users who want multiple identities of the same human to be cryptographically unlinkable to outside observers:

- **Derivation:** `P_i = P + H(P‖ctx)·G`, `x_i = x + H(P‖ctx)`. Standard BIP340 / Taproot tweak.
- **Where computed:** Client-side. The signer participates in the cosignature for the derived key but does not learn the tweak unless the user discloses it.
- **Selective disclosure:** The user can reveal `ctx` to a chosen verifier who can then check `P_i == P + H(P‖ctx)·G`. Default-off; explicit per-disclosure action.
- **Tweak secrecy is critical.** Leaking a tweak plus the master pubkey lets an observer link siblings (the standard BIP32 non-hardened footgun). Tweaks are treated with the same care as private key material in the client.

The signer holds the joint pubkey as a watch-only anchor and a share for cosigning derived keys. It does not learn which `ctx` values exist or what they map to unless the user uses the same `ctx` repeatedly (which is fine — it's the user's choice of how much to compartmentalize).

### 3.5 Disposable-mode key flag

A first-class privacy mode on each registered key. When set:

- **Refuse to sign certain event kinds:** kind:0 (profile metadata), kind:3 (contact list), kind:10002 (relay list metadata) — by default. User can opt-in per-kind to override, with a warning.
- **Strip linking metadata:** refuse events that explicitly tag the master npub; refuse `client` tags that fingerprint the signing software.
- **Withhold metadata from queries:** `get_relays` returns this key's private relay set, not the user's globals. Same posture for any introspection.
- **Time-jitter signing:** random delays in the response timing (single-digit milliseconds to a few hundred ms) to break per-request timing correlation between disposable and primary activity.
- **Per-context client fingerprint:** different NIP-46 client metadata for this key, so requesting apps can't cross-reference.

None of this is anonymity. It is behavioral hygiene that makes accidental self-doxing harder. Users are told this explicitly.

### 3.6 Metadata retention

**No linkable per-request metadata. Period.**

The legitimate retentions are:

| Data | Why we keep it | How |
|---|---|---|
| Account billing artifacts | Required by payment method (mostly empty for LN/Cashu users) | Aggregated where possible |
| Aggregate quota counters | Enforce per-period limits | Sum-per-period only, not request history |
| Active-incident debug logs | Real-time troubleshooting | Encrypted to the user's key; user voluntarily decrypts and shares; never available to operator unilaterally |

Everything else — per-request IPs, per-request timing, per-key signature counts beyond the quota period, key-to-key associations beyond the user-account boundary — is not retained. The signer is structurally unable to produce records it does not write.

### 3.7 Key rotation — three primitives, three purposes

**Conflating these has caused confusion historically.** They are independent and serve different threats:

| Primitive | What rotates | Public artifact? | When used |
|---|---|---|---|
| **Vault rewrap** | At-rest encryption envelope | No | Operational hygiene, periodic |
| **FROST share refresh** | Signer + device shares (joint pubkey unchanged) | No | After a device removal, after a suspected device compromise, periodic |
| **NIP-41 successor** | The npub itself (new joint pubkey, old retired) | **Yes (publishes old→new linkage)** | Compromise recovery only |

The third primitive is the dangerous one for privacy. **NIP-41 succession publishes a permanent old-to-new linkage on Nostr.** That is anti-unlinkability by design. We make this clear in the UI: rotating your npub is for compromise recovery. Proactive rotation as a privacy hygiene is *worse* for unlinkability, not better.

For users who want continuity verification without rotation (e.g., "this anonymous author also posted X six months ago"), see 3.8.

### 3.8 Continuity proofs

Independent primitive from rotation. Lets an anonymous or disposable npub prove "the author of this post also authored these prior posts" *without* ever rotating to a known identity.

- **Mechanism:** ZK proof of knowledge of a private key that signed event A AND event B, without revealing the key.
- **Use case:** Whistleblower posts a series; readers can verify all posts come from the same source without learning who.
- **Status:** Tier 3 work (see implementation sequence). Independent of selective-disclosure proofs; can ship before or after.

### 3.9 The Snowden axis — credentialed authority

The cryptographic substrate is **anonymous credentials with selective attribute disclosure.**

**Primitives we ship:**

- **Ring signatures over a published npub set.** "This post is signed by SOMEONE in {set}." Verifier sees the set, not the member. Suitable for sets of dozens to hundreds.
- **ZK set-membership proofs** with Merkle-committed sets. Same property, scaling to very large sets without bandwidth penalty.
- **BBS+ anonymous credentials.** An issuer grants a credential ("verified employee of Empire," "holds X clearance," "is on team Y"). The holder later proves "I hold a credential of type T from issuer I" without revealing which credential or which holder.

**Use cases we explicitly support:**

1. **Whistleblower disclosure.** Anonymous post + ring signature over a published credential set ("NSA contractors with TS/SCI") proves credible authorship without identity.
2. **B2B delegated signing.** A team member signs on behalf of an organization. Verifier learns "this is a credentialed Empire team member" without learning which one. Empire is the credential issuer in this case.
3. **Web-of-trust attestation.** "This post is from someone followed by ≥N of these K well-known accounts." Proves social embeddedness without identity.
4. **Stake-based credibility.** Anonymous proof of N sats locked or burned. Skin-in-the-game without identity.

**What we don't promise:** the social/institutional credentialing infrastructure. We ship the proof-generation side. Whether "the set of verified journalists" or "the set of Empire team members" exists and is maintained is up to the issuer.

### 3.10 Network layer

**Ephemeral relay tunnels.** Per-key NIP-46 *sessions* layered on potentially shared TCP connections (not per-key sockets). Privacy unit is the subscription identity, not the underlying socket. Bounded by relay count, not key×relay count. Cheap at scale.

**No persistent signer-to-relay identity.** The signer does not advertise its presence to relays, does not maintain a long-lived identity-bearing connection, and does not announce key holdings.

**No key enumeration.** Bunker URI is the only discovery channel. We do not respond to "do you hold key X" probes, do not surface key counts, do not enumerate.

**Tor egress option.** Per-key opt-in routing of signer→relay traffic via Tor. Default off (latency cost); promoted in the UI for keys flagged disposable-mode or for users on the onion endpoint.

### 3.11 Cover traffic

**Free tier:** Jittered timing on real signing operations so a relay observer cannot tell whether "user X signed at 14:32:07.103" was a key-press response or a scheduled task. Cheap, partial, included.

**Paid tier:** Constant-rate dummy events that make on/off-line presence indistinguishable from background. Real bandwidth cost; legitimate paid feature.

### 3.12 Gift-wrap everything supportable

Default to NIP-17 gift-wrapped events for any kind that has a sealed variant. Specifically:

- **DMs:** NIP-17 default. NIP-04 only with explicit user downgrade and a "this leaks the recipient" warning shown each time.
- **Group membership / role events:** sealed variants where available.
- **Any kind with a sealed form:** prefer sealed by default; expose the unsealed path only behind explicit opt-in.

### 3.13 Pricing model — privacy primitives in the free tier

Decision 2026-03-31 (current pricing model) capped free tier at 4 keys with FROST as a premium feature. **This document supersedes that allocation.**

**New allocation:**

| Feature | Free | Premium |
|---|---|---|
| Master key + N disposable keys | Yes (generous N, > 4) | Higher N |
| Disposable-mode flag and guardrails | Yes | Yes |
| Manual rotation (Vault rewrap, share refresh) | Yes | Scheduled/automated |
| NIP-17 gift-wrap default | Yes | Yes |
| Tor egress opt-in | Yes | Yes |
| FROST 2-of-N custody | Yes | Yes |
| Onion endpoint access | Yes | Yes |
| Recovery (phrase, codes, social) | Yes | Yes |
| Jittered timing cover | Yes | Yes |
| Constant-rate cover traffic | — | Yes |
| Selective-disclosure proofs | Yes (manual) | Yes (programmatic / bulk) |
| Bulk programmatic disposable minting | — | Yes |
| Dedicated relay isolation | — | Yes |
| FROST coordination service tier | — | Yes |

**Principle:** Privacy is a right; scale and automation are a service. Anyone paying us "to not be surveilled" is a business model we explicitly reject.

### 3.14 Currently shipped foundations

The following components are already implemented in the codebase. Future work composes on top of them; it does not replace them.

| Component | Location | Section it supports |
|---|---|---|
| Username + password auth | `internal/auth/auth.go` | §3.1 |
| TOTP MFA (enrollment + validation) | `internal/auth/auth.go` — `GenerateMFASecret`, `ValidateMFACode` | §3.1 (account-access gate) |
| 10 backup codes (account-access path) | `internal/auth/auth.go` — `GenerateBackupCodes`, `DefaultBackupCodeCount = 10`, `ValidateBackupCode` | §3.1 (share-derivation extension still owed) |
| Vault per-user transit encryption | `internal/vault/`, `internal/crypto/vault_encryptor.go` | §3.3 (current custody floor; FROST 2-of-N is the target above it) |
| FROST DKG (distributed, via Nostr ephemeral DMs) | `internal/frost/dkg_distributed.go`, `internal/frost/protocol.go`, `internal/frost/remote_signer.go` | §3.3 (most of the threshold scaffolding) |
| FROST share import/export | `internal/frost/` | §3.3 |
| Per-key relay configuration, strict (no global fallback) | `internal/nostr/key_relay_manager.go`, `internal/discovery/selector.go` | §3.5, §3.10 |
| NIP-46 bunker:// + nostrconnect:// | `internal/bunker/`, `internal/signer/` | §3.3, §3.10 |
| HKDF-deterministic account pubkey | `internal/crypto/crypto.go` | §3.1 |
| NIP-05 endpoint (`/.well-known/nostr.json`) | `internal/api/` | §3.1, §3.7 |
| `KeyTypeProxy` (upstream signer chaining) | `internal/proxy/proxy.go`, `internal/storage/storage.go` | Distinct from disposable mode |
| Admin DM commands | `internal/admin/admin.go` | Operational |
| Vault-key restore on pod startup | `internal/api/handler.go` — `RestoreVaultKeysOnStartup` | §3.3 |
| `nostr.json` and core API endpoints | `internal/api/` | §3.1 |

**Greenfield work** (none of the below exists yet, sequenced in §4):

- 24-word recovery phrase generation + UI flow
- Backup-code extension to derive a FROST share (current implementation is account-access only)
- FROST share rotation / refresh
- Browser-side FROST share holder (WASM)
- Disposable-mode key flag (§3.5) with kind-allowlist and metadata-strip
- Vault rewrap automation (§3.7)
- Onion endpoint + Cloudflare drop + nginx replacement stack
- Tor egress per-key
- NIP-17 gift-wrap default audit + enforcement
- Metadata retention sweep
- Cover traffic (jittered free, constant-rate paid)
- Taproot-tweaked context keys
- Selective-disclosure proofs
- Continuity proofs

---

## 4. Implementation Sequence

Each item is a defensible privacy claim on its own. Sequence is by ratio of privacy-delivered to engineering-effort.

| # | Item | Effort | Privacy axis affected |
|---|---|---|---|
| 1 | Disposable-mode key flag with guardrails (3.5) | S | Unlinkability (behavioral) |
| 2 | Vault rewrap (3.7) | S | Operator-coercion |
| 3 | Drop Cloudflare; nginx + LE + fail2ban replacement | M | Pseudonymity, untraceability |
| 4 | Onion endpoint live (3.2) | M | Pseudonymity |
| 5 | Tor egress opt-in per key (3.10) | M | Untraceability |
| 6 | NIP-17 default for DMs (3.12); audit current default | S | Untraceability |
| 7 | Metadata retention sweep (3.6); strip linkable logs | M | All axes |
| 8 | No-enumeration / no-presence-broadcast hardening (3.10) | S | Unobservability |
| 9 | 10-code recovery + social recovery (3.1) | M | Pseudonymity |
| 10 | Tier 2 Taproot-tweaked context keys (3.4) | L | Unlinkability (cryptographic) |
| 11 | FROST 2-of-N custody, browser + signer (3.3) | XL | All axes; **the architectural inversion** |
| 12 | Ephemeral relay tunnels (3.10) | M | Untraceability |
| 13 | Cover traffic — jittered free, constant-rate paid (3.11) | M | Unobservability |
| 14 | Selective-disclosure proofs (3.9) | XL | Credentialed authority |
| 15 | Continuity proofs (3.8) | XL | Public-broadcast authorship |
| 16 | Mobile-app share holder | XL | Multi-device custody |

Items 1-9 are near-term hygiene. Item 11 is the architectural inversion that changes what we can claim. Items 14-15 are the headline features for the public-broadcast use case.

---

## 5. Explicitly Out of Scope

Listed here so we don't accidentally drift into them:

- **Hiding the existence of public posts.** Definitionally impossible.
- **Identifying credential issuers ourselves.** We ship the proof side; we are not in the business of being "the journalist credentialing authority."
- **Email or SMS recovery.** Permanently.
- **Card payment processing.** Permanently.
- **Compliance with content-moderation demands at the platform level.** We sign what the user asks us to sign, subject to the disposable-mode kind filters the user themselves enabled. We do not curate content.
- **Resisting determined state-level adversaries with global network surveillance.** We raise the cost meaningfully; we do not promise immunity. This is stated to users explicitly.

---

## 6. Open Questions

Items where a decision is still owed:

1. **DDoS mitigation post-Cloudflare.** Direct nginx + fail2ban + LB rate limiting needs a concrete capacity plan. What's the assumed peak load and how do we handle a determined L7 flood?
2. **Onion endpoint scaling.** Single hidden service or pool? Onion routing balancer (`obfs4` etc.) integration?
3. **FROST DKG over what channel?** The existing FROST implementation uses Nostr ephemeral DMs (decision 2026-03-25). Reuse that, or a dedicated client-to-signer channel for the browser-share DKG?
4. **Share refresh cadence.** Per-session, per-day, per-month? What triggers it?
5. **B2B credential issuance UX.** When Empire wants to issue credentials to team members, what does that flow look like in our admin UI? Is it a first-class signer feature or a separate product?
6. **Disposable-mode key default kind-allowlist.** The set of kinds-allowed-by-default needs to be enumerated explicitly, not just "obviously linking ones blocked."
7. **Backup-code resync.** If the user uses some codes and we need to issue new ones, how is that authorized?

---

## 7. Marketing Claims Derived from This Architecture

The claims we are willing to make to users, in plain language, with the section that backs each one:

- **"We cannot read your private messages."** — 3.3, 3.12
- **"We cannot identify which of your identities belong to the same person."** — 3.3, 3.4
- **"We do not know who you are."** — 3.1, 3.2, 3.6
- **"We cannot sign without you."** — 3.3
- **"We cannot tell anyone what you signed."** — 3.6
- **"We cannot be compelled to produce data we don't hold."** — 1.1
- **"You can prove credibility without identity."** — 3.9
- **"Your public posts are public. Everything else is yours."** — 2.3, 2.4

These are not aspirational. Each one is backed by a structural property of the design. If a claim ever becomes untrue, this document is wrong and must be updated *before* the implementation drifts.
