# Cloistr Signer Roadmap

**Post-v1.0 Development Priorities**

All 12 original phases are complete. This document outlines the next evolution of the signer.

---

## Phase 13: Performance Optimization & Load Testing

**Priority: HIGH** | **Status: Not Started**

### Goals
- Establish performance baselines
- Identify bottlenecks under load
- Optimize critical paths
- Document capacity limits

### Tasks

1. **Load Testing Infrastructure**
   - Set up k6 or Locust test suite
   - Define test scenarios: signing throughput, concurrent sessions, FROST ceremonies
   - Establish baseline metrics

2. **Batch Signing** (see [Batch Signing Design](#batch-signing-design) below)
   - Reduce relay round-trips from N to 1
   - Critical for avoiding relay rate limits

3. **Connection Pooling**
   - Audit relay connection lifecycle
   - Implement connection reuse where possible

4. **Caching Layer**
   - Cache Vault tokens (with appropriate TTL)
   - Cache user policies
   - Cache relay metadata

5. **Metrics & Profiling**
   - Add detailed timing metrics
   - Profile hot paths (signing, encryption)
   - Identify memory allocation patterns

### Success Criteria
- [ ] Handle 100 concurrent signing sessions
- [ ] Sign 50 events/second sustained
- [ ] P99 latency under 500ms for single sign
- [ ] Batch signing reduces 4-event signing from 4 round-trips to 1

---

## Phase 14: Mobile Application

**Priority: HIGH** | **Status: Not Started**

### Goals
- Native iOS and Android apps
- Local key storage with hardware-backed security
- Optional connection to hosted signer

### Architecture Options

#### Option A: Pure Remote Client
Mobile app connects to cloistr-signer server. Keys stay on server.

**Pros**: Simple, keys protected by Vault
**Cons**: Requires network, server dependency

#### Option B: Local Signer with Sync
Mobile app stores keys locally, optionally syncs to server.

**Pros**: Works offline, user controls keys
**Cons**: Complex sync, need secure local storage

#### Option C: Hybrid (Recommended)
- Remote signing for primary keys (server-side)
- Local signing for session keys (device-side)
- FROST for distributed keys (multi-device)

### Secure Key Storage

#### The Problem
- Android has **Keystore** (hardware-backed, keys never leave secure element)
- iOS has **Secure Enclave** (hardware-backed) but limited API
- iOS **Keychain** is encrypted storage, not HSM
- We need consistency across platforms

#### Solution: Platform-Native with Abstraction Layer

```
┌─────────────────────────────────────────┐
│           Unified Crypto API            │
│  generateKey() / sign() / encrypt()     │
└─────────────────┬───────────────────────┘
                  │
        ┌─────────┴─────────┐
        │                   │
┌───────▼───────┐   ┌───────▼───────┐
│    Android    │   │      iOS      │
│   Keystore    │   │ Secure Enclave│
│  + StrongBox  │   │  + Keychain   │
└───────────────┘   └───────────────┘
```

**Android Implementation**:
- Use Keystore with `setIsStrongBoxBacked(true)` when available
- Keys generated inside hardware, never exported
- Sign operations happen in hardware

**iOS Implementation**:
- Use Secure Enclave for ECDSA keys (secp256r1 supported, NOT secp256k1)
- **Problem**: Secure Enclave doesn't support secp256k1 (Bitcoin/Nostr curve)
- **Workaround Options**:
  1. Store encrypted key in Keychain, decrypt into memory for signing
  2. Use Secure Enclave for device authentication, derive signing key from SE-protected secret
  3. Use a software HSM library (libsodium sealed boxes)

**Recommended iOS Approach**:
```
┌─────────────────────────────────────────┐
│           Nostr Private Key             │
│         (secp256k1, 32 bytes)           │
└─────────────────┬───────────────────────┘
                  │ encrypted with
                  ▼
┌─────────────────────────────────────────┐
│      Device Encryption Key (DEK)        │
│    (AES-256, derived from SE secret)    │
└─────────────────┬───────────────────────┘
                  │ protected by
                  ▼
┌─────────────────────────────────────────┐
│         Secure Enclave Secret           │
│   (P-256 key, hardware-protected)       │
│   Requires biometric to access          │
└─────────────────────────────────────────┘
```

This gives us:
- Hardware-backed key protection (SE protects the DEK)
- Biometric authentication required
- Key material only in memory during signing
- Consistent security model across platforms

#### Embedded Vault Alternative

For advanced users or enterprise deployments:
- Bundle HashiCorp Vault Agent with mobile app
- Agent handles token renewal, caching
- Connects to hosted Vault cluster
- Keys never on device at all

**Pros**: Same security model as server
**Cons**: Requires network, complex packaging, battery drain

#### Recommendation

1. **Default**: Platform-native (Keystore/SE+Keychain)
2. **Optional**: Connect to hosted signer (for users who prefer server-side)
3. **Future**: Embedded Vault Agent for enterprise

### Mobile Tasks

1. **React Native Setup**
   - Initialize project with Expo
   - Set up native module bridge for crypto

2. **Crypto Module**
   - Android: Keystore integration
   - iOS: Secure Enclave + Keychain integration
   - Abstract behind unified API

3. **NIP-46 Client**
   - WebSocket connection to relays
   - Handle all NIP-46 methods
   - Offline queue for signing requests

4. **UI/UX**
   - Key management
   - Connection approvals (with biometric)
   - Signing history

5. **Sync (Phase 2)**
   - Optional encrypted sync to server
   - FROST key shares across devices

---

## NIP-46 Extensions Discussion

### How NIP Extensions Work

NIPs (Nostr Implementation Possibilities) are proposals for protocol features. The process:

1. **Draft**: Write a document describing the extension
2. **Discuss**: Open PR to nostr-protocol/nips repo
3. **Iterate**: Address feedback, refine design
4. **Consensus**: Get buy-in from client/relay implementers
5. **Merge**: Becomes official NIP
6. **Adopt**: Implementers add support

Extensions to existing NIPs follow the same process but modify/extend an existing document.

### Current NIP-46 Methods

```
connect         - Establish session with optional secret
get_public_key  - Return signer's pubkey
sign_event      - Sign a single event
nip04_encrypt   - Encrypt (deprecated NIP-04)
nip04_decrypt   - Decrypt (deprecated NIP-04)
nip44_encrypt   - Encrypt (NIP-44)
nip44_decrypt   - Decrypt (NIP-44)
get_relays      - Return signer's relay list
ping            - Health check
```

### Potential Extensions

#### 1. Batch Signing (`sign_events`)

**Problem**: Signing N events requires N request-response round trips.

**Current Flow** (4 events):
```
Client ─── sign_event(e1) ───► Signer
Client ◄── signature(e1) ──── Signer
Client ─── sign_event(e2) ───► Signer
Client ◄── signature(e2) ──── Signer
Client ─── sign_event(e3) ───► Signer
Client ◄── signature(e3) ──── Signer
Client ─── sign_event(e4) ───► Signer
Client ◄── signature(e4) ──── Signer

Total: 8 messages, 4 round trips
```

**With Batch Signing**:
```
Client ─── sign_events([e1,e2,e3,e4]) ───► Signer
Client ◄── signatures([s1,s2,s3,s4]) ──── Signer

Total: 2 messages, 1 round trip
```

**Proposed Method**:
```json
{
  "method": "sign_events",
  "params": [
    "event_json_1",
    "event_json_2",
    "event_json_3"
  ]
}
```

**Response**:
```json
{
  "result": [
    "signature_1",
    "signature_2",
    "signature_3"
  ],
  "error": null
}
```

**Or with IDs for partial failures**:
```json
{
  "method": "sign_events",
  "params": {
    "events": [
      {"id": "req1", "event": "..."},
      {"id": "req2", "event": "..."}
    ]
  }
}

{
  "result": {
    "signatures": [
      {"id": "req1", "sig": "...", "error": null},
      {"id": "req2", "sig": null, "error": "kind 4 not allowed"}
    ]
  }
}
```

#### 2. Delegation Tokens

**Problem**: Full signing access is all-or-nothing.

**Solution**: Time-limited, scope-limited tokens.

```json
{
  "method": "create_delegation",
  "params": {
    "allowed_kinds": [1, 6, 7],
    "expires_at": 1714500000,
    "max_uses": 100
  }
}

{
  "result": {
    "delegation_token": "...",
    "conditions": "kind=1|6|7&created_at<1714500000"
  }
}
```

Client can then use delegation token for limited signing without full session.

#### 3. Event Filtering / Policies

**Problem**: Signer signs anything the client sends.

**Solution**: Signer-side policies.

```json
{
  "method": "set_policy",
  "params": {
    "deny_kinds": [4],
    "require_approval_kinds": [0, 3],
    "auto_approve_kinds": [1, 6, 7]
  }
}
```

#### 4. Key Rotation

**Problem**: No standard way to rotate keys.

**Solution**: Coordinated rotation protocol.

```json
{
  "method": "rotate_key",
  "params": {
    "new_pubkey": "...",
    "migration_event": "..." // NIP-? key migration event
  }
}
```

### Extension Implementation Without NIPs

We can implement extensions as **non-standard methods** that only work with Cloistr clients:

1. Add method to signer
2. Document in our API reference
3. Implement in our clients
4. If successful, propose as NIP

**Risk**: Other clients won't support it
**Benefit**: We can iterate quickly, prove the concept

---

## Batch Signing Design

### Current Problem

When publishing to multiple relays or signing multiple events, clients make sequential NIP-46 requests. Relays like nostr.wine rate limit at ~10 req/min, causing failures.

### Implementation Plan

#### Phase 1: Server-Side Support (No NIP change)

Add `sign_events` method to cloistr-signer:

```go
case "sign_events":
    var events []string
    if err := json.Unmarshal(params, &events); err != nil {
        return nil, err
    }
    signatures := make([]string, len(events))
    for i, eventJSON := range events {
        sig, err := s.signEvent(ctx, eventJSON)
        if err != nil {
            // Return partial results with errors
        }
        signatures[i] = sig
    }
    return signatures, nil
```

#### Phase 2: Client Support

Update Cloistr clients (web, mobile) to:
1. Detect if signer supports `sign_events`
2. Batch pending sign requests
3. Fall back to sequential if unsupported

#### Phase 3: NIP Proposal

If batch signing proves valuable:
1. Write NIP-46 amendment
2. Include our implementation experience
3. Propose to nostr-protocol/nips

### Parallel Signing (Interim Solution)

Even without batching, we can improve throughput:

```javascript
// Before: Sequential
for (const event of events) {
  await signer.sign(event);
}

// After: Parallel
await Promise.all(events.map(e => signer.sign(e)));
```

This doesn't reduce message count but improves latency by ~4x for 4 events.

---

## Phase 15: Public Launch

**Priority: MEDIUM** | **Status: Blocked on Phase 13**

### Tasks
- [ ] Performance validation complete
- [ ] Documentation review
- [ ] Security audit (optional but recommended)
- [ ] Landing page for signer.cloistr.xyz
- [ ] Announcement post
- [ ] NIP-89 service announcement published

---

## Summary

| Phase | Focus | Priority | Dependencies |
|-------|-------|----------|--------------|
| 13 | Performance & Load Testing | HIGH | None |
| 14 | Mobile Application | HIGH | None (parallel) |
| 15 | Public Launch | MEDIUM | Phase 13 |

**Immediate Actions**:
1. Set up load testing infrastructure
2. Implement batch signing (`sign_events`)
3. Begin mobile app scaffolding

---

**Last Updated**: 2026-04-29
