# FROST Integration: Distributed Key Custody for cloistr-signer

## Overview

This document describes the planned integration of FROST (Flexible Round-Optimized Schnorr Threshold) signatures into cloistr-signer, enabling distributed key custody for business Nostr identities.

## The Problem

Signer chaining (Phase 12) solves the team delegation problem - multiple people can sign on behalf of a shared identity with instant revocation. However, it introduces a single point of failure: the upstream signer holds the complete private key.

| Risk | Impact |
|------|--------|
| Server compromise | Business identity stolen |
| Rogue admin | Can sign anything |
| Data center outage | Signing offline |
| Key backup theft | Identity compromised |

## The Solution: FROST Threshold Signatures

FROST enables t-of-n threshold signing where:
- The private key is split into n shares
- Any t shares can collaborate to produce a valid signature
- **The full private key is never reconstructed during signing**
- Shares can be rotated without changing the public key

### Key Properties

| Property | Benefit |
|----------|---------|
| **Threshold security** | Compromise of t-1 shares reveals nothing |
| **No single point of failure** | Multiple shares must collaborate |
| **Key rotation** | Change shares, keep same npub |
| **Distributed custody** | Shares across locations/organizations |
| **Standard signatures** | Output is a normal Schnorr signature |

## Architecture

### Two-Layer Model

cloistr-signer combines **signer chaining** (permission layer) with **FROST** (custody layer):

```
┌─────────────────────────────────────────────────────────────┐
│                    PERMISSION LAYER                         │
│                   (Signer Chaining)                         │
│                                                             │
│   WHO can request signatures?                               │
│   - Delegate authentication (NIP-46)                        │
│   - Per-delegate permissions (kinds, methods)               │
│   - Rate limiting, expiration                               │
│   - Full audit logging                                      │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    CUSTODY LAYER                            │
│                       (FROST)                               │
│                                                             │
│   HOW is the key protected?                                 │
│   - t-of-n threshold signing                                │
│   - Geographic/organizational distribution                  │
│   - No single point of compromise                           │
│   - Key rotation without identity change                    │
└─────────────────────────────────────────────────────────────┘
```

### Component Architecture

```
                     ┌─────────────────────────────────────┐
                     │      Business npub (3-of-5)         │
                     └───────────────────┬─────────────────┘
                                         │
      ┌──────────┬──────────┬────────────┼────────────┬──────────┐
      │          │          │            │            │          │
   Share 1    Share 2    Share 3     Share 4      Share 5
   (Infra)    (Infra)    (Cold)      (John)       (Sarah)
      │          │          │            │            │
      ▼          ▼          ▼            ▼            ▼
┌──────────┐┌──────────┐┌──────────┐┌──────────┐┌──────────┐
│cloistr   ││cloistr   ││Igloo     ││John's    ││Sarah's   │
│signer #1 ││signer #2 ││(cold)    ││Signer    ││Signer    │
│(NYC)     ││(EU)      ││          ││          ││          │
└────┬─────┘└────┬─────┘└────┬─────┘└────┬─────┘└────┬─────┘
     │           │           │           │           │
     └───────────┴───────────┴─────┬─────┴───────────┘
                                   │
                    Coordinate via Nostr relays
                         (NIP-04 encrypted)
                                   │
                     ┌─────────────┴─────────────┐
                     │      FROST Coordinator    │
                     │   (cloistr-signer mode)   │
                     └─────────────┬─────────────┘
                                   │
                          NIP-46 interface
                      (unchanged for delegates)
                                   │
               ┌───────────────────┼───────────────────┐
               ▼                   ▼                   ▼
          ┌─────────┐         ┌─────────┐         ┌─────────┐
          │ John's  │         │ Sarah's │         │ Mike's  │
          │ Amber   │         │ nos2x   │         │ Signer  │
          └─────────┘         └─────────┘         └─────────┘
```

### Signing Flow

1. **Delegate initiates:** John's Amber sends NIP-46 sign_event request
2. **Permission check:** Coordinator verifies John is authorized
3. **FROST coordination:** Coordinator requests partial signatures from share holders
4. **Threshold met:** 3 of 5 shares respond with partials
5. **Aggregation:** Coordinator combines into final signature
6. **Response:** NIP-46 response sent to John's Amber
7. **Audit:** Log records delegate identity + participating shares

## Custody Models

### Model A: Infrastructure-Only

All shares held by infrastructure. Fast, automated signing.

```
3-of-5: Server1 + Server2 + Server3 + Cold1 + Cold2
Signing: Any 3 servers (sub-second)
Recovery: 2 cold shares if all servers compromised
```

**Use case:** High-volume social media accounts

### Model B: Team-Required

At least one team member must participate.

```
3-of-5: Server1 + Server2 + CEO + CTO + Cold
Policy: Require at least 1 human share
Signing: Server1 + Server2 + CEO (CEO must approve)
```

**Use case:** Official company communications

### Model C: Multi-Party

All shares held by different parties.

```
3-of-5: CEO + CTO + CFO + Legal + Cold
Signing: Any 3 executives must collaborate
```

**Use case:** Board-level statements, legal commitments

### Model D: Hybrid Delegate

Delegates can optionally contribute their share.

```
3-of-5: Infra1 + Infra2 + Cold + John + Sarah
Normal: Infra1 + Infra2 + Cold (John just has permission)
With John: Infra1 + Infra2 + John (John's share participates)
```

**Use case:** Flexible - routine auto-signing with optional human participation

## Team Members as Share Holders

Delegates can hold FROST shares in addition to (or instead of) just having permissions.

### How It Works

1. **Setup:** John receives Share 4 for the business key
2. **Storage:** John's signer (Amber, Igloo, or cloistr-signer) stores the share
3. **Signing:**
   - John's Amber authenticates as `npub_john` (his personal key)
   - John's Amber contributes Share 4 (business key fragment)
   - Combined with other shares → business signature

### Authentication vs Authorization

| Layer | Mechanism | Purpose |
|-------|-----------|---------|
| **Authentication** | John's personal npub | Proves John is John |
| **Authorization** | John's FROST share | Proves John can sign for business |

These are separate but complementary:
- **Permission only:** John can request signatures, but doesn't hold custody
- **Share only:** John holds custody, but any request triggers signing
- **Both:** John authenticated + John's share participates (most secure)

## Key Rotation

FROST supports proactive secret sharing - rotating shares without changing the public key.

### When to Rotate

- Employee leaves (revoke their share)
- Suspected compromise
- Periodic security hygiene (quarterly)
- Changing threshold (e.g., 2-of-3 → 3-of-5)

### Rotation Process

1. **Initiate:** Admin triggers rotation ceremony
2. **Coordinate:** Existing share holders collaborate
3. **Generate:** New shares computed, old shares invalidated
4. **Distribute:** New shares sent to holders
5. **Verify:** Each holder confirms receipt
6. **Complete:** Old shares are destroyed

**The npub never changes.** Followers, verification, reputation - all preserved.

## Implementation Approach

### Option 1: Native FROST Implementation

Build FROST directly into cloistr-signer using Go libraries.

**Pros:**
- Full control over implementation
- Tighter integration with existing codebase
- Single binary deployment

**Cons:**
- Significant crypto implementation work
- Must implement DKG, signing protocols
- Security audit required

### Option 2: FROSTR Integration

Leverage existing FROSTR libraries and ecosystem.

**Pros:**
- Battle-tested implementation
- Ecosystem interoperability (Igloo, Frost2x)
- Faster time to market

**Cons:**
- External dependency
- May need adaptation for our use case
- Less control over implementation

### Option 3: Hybrid

Use FROSTR for crypto primitives, custom integration layer.

**Recommended approach:**
1. Start with FROSTR's bifrost library for FROST primitives
2. Build custom coordinator that speaks NIP-46 to delegates
3. Use nostrp2p for share holder coordination
4. Maintain option to swap out primitives later

## Security Considerations

### Share Compromise

| Shares Compromised | Impact (3-of-5) |
|-------------------|-----------------|
| 1 | None - cannot sign |
| 2 | None - cannot sign |
| 3+ | Can sign - rotate immediately |

**Mitigation:** Distribute shares across security domains (different networks, jurisdictions, organizations).

### Coordinator Compromise

The coordinator can't sign alone - it only orchestrates. However:
- Can deny service (refuse to coordinate)
- Can log all signing requests
- Can potentially manipulate which shares are requested

**Mitigation:** Multiple coordinators, or coordinator-free mode where delegates initiate directly.

### Communication Security

All share holder communication uses NIP-04/NIP-44 encryption over Nostr relays.

**Mitigation:** Use dedicated relays, or direct connections between share holders for high-security setups.

### Offline Shares

Cold storage shares should:
- Never be online except during signing/rotation
- Use air-gapped devices
- Require physical access controls

## Related Work

### FROSTR

- **Website:** https://github.com/FROSTR-ORG/
- **Components:** bifrost (crypto), nostrp2p (coordination), Igloo (desktop app)
- **Status:** Active development, OpenSats funded

### MuSig2 vs FROST

| | MuSig2 | FROST |
|--|--------|-------|
| **Threshold** | n-of-n only | t-of-n |
| **Rounds** | 2 | 2-3 |
| **Use case** | All parties must sign | Subset can sign |

FROST is more flexible for our use case (not everyone online all the time).

### NIP-26 (Delegated Event Signing)

Abandoned approach using delegation tokens. Problems:
- No revocation (only time-bound)
- Required ecosystem-wide adoption
- Marked "unrecommended"

Our approach (signer chaining + FROST) solves the same problems without protocol changes.

## Roadmap

### Phase 13a: Research & Prototyping ✅ COMPLETE
- [x] Deep dive into FROSTR codebase
- [x] Prototype: cloistr-signer as FROST share holder
- [x] Prototype: cloistr-signer as FROST coordinator
- [x] Evaluate crypto libraries - **Decision:** bytemare/frost (native Go)

### Phase 13b: Core Implementation ✅ COMPLETE (DKG) / In Progress (Signing)
- [x] Share holder mode (local FROST key storage)
- [x] Coordinator mode (DKG initiation)
- [x] **Distributed DKG via Nostr DMs** - Full implementation
- [ ] Distributed signing session protocol

#### Distributed DKG Implementation (2026-03-25)

**Location:** `internal/frost/dkg_distributed.go`

Implemented 3-round Pedersen DKG over Nostr ephemeral DMs (kind 24133):

| Round | Purpose | Communication |
|-------|---------|---------------|
| 1 | Commitment Exchange | Broadcast polynomial commitments to all participants |
| 2 | Share Distribution | Send encrypted evaluations to each participant |
| 3 | Verification | Verify received shares against commitments |

**Key Features:**
- Pedersen VSS (Verifiable Secret Sharing) with commitment verification
- NIP-04 encrypted DMs for share distribution
- NIP-42 relay authentication support (required for DM subscriptions)
- Multi-dealer share aggregation (each participant is a dealer)
- Lagrange interpolation for threshold reconstruction

**Tests:** `internal/frost/dkg_distributed_test.go` - 24 tests covering:
- Polynomial evaluation
- VSS verification
- Commitment encoding/decoding
- Multi-dealer share aggregation
- Threshold reconstruction
- Session state management

**Status:** Deployed to production (`signer.cloistr.xyz`)

### Phase 13c: Integration
- [ ] **Distributed signing** - Coordinate partial signatures across signers
- [ ] Connect FROST to signer chaining layer
- [ ] Web UI for FROST key management
- [ ] Share rotation workflows
- [ ] Documentation and guides

### Phase 13d: Production Hardening
- [ ] Security audit
- [ ] Performance optimization
- [ ] Multi-coordinator support
- [ ] Monitoring and alerting

## References

- [FROST Paper](https://eprint.iacr.org/2020/852) - Original academic paper
- [FROSTR GitHub](https://github.com/FROSTR-ORG/) - Nostr FROST implementation
- [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) - Schnorr signatures
- [MuSig2 Paper](https://eprint.iacr.org/2020/1261) - Related multi-sig work
- [NIP-46](https://github.com/nostr-protocol/nips/blob/master/46.md) - Remote signing protocol

---

**Last Updated:** 2026-03-25
