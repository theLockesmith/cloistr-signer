# Signer Chaining: Delegated Team Signing via NIP-46

**Status:** Proposed
**Author:** Coldforge
**Date:** 2026-02-21

## Abstract

Signer Chaining is a pattern that enables delegated signing for teams and organizations using existing NIP-46 infrastructure. By allowing personal signers (like Amber or nsecbunker) to proxy signing requests to an upstream business signer, teams can share a Nostr identity without sharing private keys, while maintaining instant revocation capabilities.

This document describes the pattern, its benefits over traditional delegation approaches (NIP-26), and implementation guidance for signer developers.

## The Problem

Organizations and teams face a common challenge: multiple people need to post on behalf of a shared identity (a business account, project account, etc.) without:

1. Sharing the actual private key (nsec) - security nightmare
2. Locking team members into a specific client or workflow
3. Losing the ability to instantly revoke access when someone leaves

### Why NIP-26 Delegation Failed

NIP-26 attempted to solve this with cryptographic delegation tokens, but faced critical issues:

| Issue | Impact |
|-------|--------|
| **No revocation** | Can't blacklist a compromised delegate; only time-bounded delegation works |
| **Ecosystem burden** | Every client and relay must implement verification for good UX |
| **Chicken-and-egg** | Broken experience between implementing and non-implementing clients |
| **Complexity** | "Adds unnecessary burden for little gain" - officially marked unrecommended |

The Nostr community has effectively abandoned NIP-26, leaving the delegation problem unsolved.

### Why Simple NIP-46 Isn't Enough

NIP-46 remote signing works great for a single user, but creates friction for teams:

- Each team member must configure their client to connect to the business signer
- Team members can't use their preferred personal signer (Amber, nsecbunker, etc.)
- Switching between personal and business identities requires reconfiguring clients

## The Solution: Signer Chaining

**Key insight: NIP-46 signers can also be NIP-46 clients.**

Nothing in the NIP-46 specification prevents a signer from connecting to another signer. This enables a "daisy chain" architecture:

```
┌─────────────────────────────────────────────────────────────────┐
│                         SIGNER CHAINING                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────┐     ┌──────────────┐     ┌──────────────────┐    │
│  │  User's  │────►│   Personal   │────►│    Business      │    │
│  │  Client  │     │    Signer    │     │     Signer       │    │
│  │ (Primal) │     │   (Amber)    │     │ (cloistr-signer) │    │
│  └──────────┘     └──────────────┘     └──────────────────┘    │
│       │                  │                      │               │
│       │   NIP-46         │      NIP-46          │               │
│       │   Request        │      Request         │               │
│       │                  │                      ▼               │
│       │                  │              ┌──────────────┐        │
│       │                  │              │  Business    │        │
│       │                  │              │  Private Key │        │
│       │                  │              └──────────────┘        │
│       │                  │                      │               │
│       │                  │      Signed          │               │
│       │   Signed         │◄─────Event───────────┘               │
│       │◄──Event──────────┘                                      │
│       │                                                         │
│       ▼                                                         │
│  ┌──────────┐                                                   │
│  │  Relay   │                                                   │
│  └──────────┘                                                   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### How It Works

1. **Team member (John)** uses their preferred client (Primal, Damus, etc.)
2. **John's client** connects to John's personal signer (Amber) via NIP-46
3. **Amber** has a "proxy key" configured - a bunker:// URI pointing to the business signer
4. When John wants to post as the business, **Amber forwards** the sign_event request to the business signer
5. **Business signer** verifies John's pubkey is authorized, signs with the business key
6. **Signed event flows back** through the chain to John's client
7. **John's client broadcasts** to relays

### Why This Solves Everything

| Problem | Signer Chaining Solution |
|---------|--------------------------|
| **Revocation** | Instant - delete permission in business signer's database |
| **No protocol changes** | Pure NIP-46, no new NIPs needed |
| **User freedom** | Team members keep their preferred signer |
| **Business control** | All signing goes through business signer |
| **Audit trail** | Business signer logs every signature request |
| **Ecosystem adoption** | Only personal signers need a new feature |

## Technical Specification

### Upstream Signer Requirements (Business Signer)

The upstream signer (e.g., cloistr-signer) needs:

1. **Permission system with pubkey authorization**
   - Map delegate pubkeys to signing keys
   - Support method-level permissions (sign_event, encrypt, etc.)
   - Support optional restrictions (event kinds, rate limits)

2. **Standard NIP-46 endpoint**
   - Accept connections from downstream signers
   - Authenticate based on connecting pubkey
   - Return signed events via standard NIP-46 flow

3. **Audit logging**
   - Log which delegate requested each signature
   - Track event content for compliance if needed

**Example permission structure:**
```json
{
  "signing_key_pubkey": "npub1business...",
  "delegate_pubkey": "npub1john...",
  "methods": ["sign_event", "get_public_key"],
  "allowed_kinds": [1, 6, 7],
  "created_at": "2026-02-21T00:00:00Z",
  "expires_at": null
}
```

### Downstream Signer Requirements (Personal Signer)

Personal signers (Amber, nsecbunker, etc.) need a new feature:

1. **Proxy key support**
   - Store bunker:// URIs as "remote keys"
   - When client requests signature for a proxied pubkey, forward to upstream
   - Maintain NIP-46 connection to upstream signer

2. **Key type indicator**
   - Distinguish between local keys (held in signer) and proxy keys (upstream)
   - UI to add/remove proxy keys

3. **Connection management**
   - Establish NIP-46 connection to upstream on demand or startup
   - Handle reconnection and errors gracefully

**Example proxy key configuration:**
```json
{
  "pubkey": "npub1business...",
  "name": "Coldforge Business",
  "type": "proxy",
  "bunker_uri": "bunker://npub1signer...?relay=wss://relay.example.com&secret=..."
}
```

### Authentication Flow

When a downstream signer proxies a request:

1. Downstream connects to upstream with its own ephemeral NIP-46 keypair
2. Upstream receives `connect` request, sees the connecting pubkey
3. Upstream checks: "Is this pubkey authorized to use the requested signing key?"
4. If yes, upstream processes the request and returns the result
5. If no, upstream returns an error

The delegate's identity is proven by the NIP-46 connection itself - only the holder of the delegate's private key can establish the encrypted session.

### Onboarding Flow

**Business admin inviting a team member:**

1. Admin opens business signer web UI
2. Clicks "Invite Team Member"
3. Enters delegate's pubkey (npub) and sets permissions
4. System generates a one-time bunker:// URI
5. Admin shares URI with team member (secure channel)
6. Team member adds URI to their personal signer as a "proxy key"
7. Team member can now sign as business from any client

**Revoking access:**

1. Admin opens business signer web UI
2. Navigates to "Team" or "Delegates"
3. Clicks "Revoke" next to the team member
4. Permission deleted - next signature request fails immediately

## Security Considerations

### Trust Model

- **Business signer is trusted** - it holds the business key and makes authorization decisions
- **Personal signers are semi-trusted** - they route requests but can't forge delegate identity
- **Clients are untrusted** - they never see any private keys

### Potential Attack Vectors

| Vector | Mitigation |
|--------|------------|
| Compromised personal signer | Can only sign with permissions already granted; revoke delegate on discovery |
| Stolen bunker:// URI | One-time secrets; can revoke and re-issue |
| Man-in-the-middle | NIP-46 encryption protects the channel |
| Replay attacks | NIP-46 request IDs prevent replay |

### Best Practices

1. **Use one-time secrets** in bunker:// URIs for initial connection
2. **Set expiration dates** on delegate permissions where appropriate
3. **Enable audit logging** on the business signer
4. **Use event kind restrictions** to limit what delegates can sign
5. **Monitor delegate activity** for anomalies

## Implementation Status

### cloistr-signer (Coldforge)

**Ready as upstream signer:**
- [x] Permission system with pubkey authorization
- [x] NIP-46 connection handling
- [x] bunker:// URI generation for delegates
- [x] Audit logging
- [ ] Team management UI (in development)
- [ ] Delegate activity dashboard (planned)

**Proxy signer support (in development):**
- [ ] Proxy key type in storage (bunker:// URI instead of local nsec)
- [ ] NIP-46 client mode for upstream connections
- [ ] Request forwarding (sign_event, encrypt, decrypt)
- [ ] Web UI for adding proxy keys
- [ ] Connection management and reconnection

**Test harness:**
- coldforge-signer instance (upstream/business signer)
- cloistr-signer instance (proxy/personal signer)
- Full chain: Client → cloistr-signer → coldforge-signer → signed event

This allows us to be the **reference implementation for both sides** of signer chaining.

### Personal Signers (Ecosystem)

**Feature requests needed:**

| Signer | Status | Notes |
|--------|--------|-------|
| Amber | Not yet | Need to file feature request |
| nsecbunker | Not yet | Need to file feature request |
| Keystache | Not yet | Need to file feature request |

Once cloistr-signer has working proxy support, we can point to it as a reference implementation.

## Ecosystem Adoption Path

1. **Phase 1: Proof of concept**
   - cloistr-signer operational as upstream signer
   - Document the pattern (this document)
   - Community feedback

2. **Phase 2: Personal signer support**
   - File feature requests on Amber, nsecbunker, etc.
   - Provide implementation guidance
   - Potentially contribute PRs

3. **Phase 3: Standardization**
   - If pattern gains traction, propose NIP-46 addendum
   - Document interoperability requirements
   - Reference implementations

## Comparison with Alternatives

| Approach | Revocation | Portability | Ecosystem Changes | Status |
|----------|------------|-------------|-------------------|--------|
| **Signer Chaining** | Instant | Full | Personal signers only | Proposed |
| NIP-26 Delegation | Time-bound only | Full | All clients + relays | Unrecommended |
| NIP-0b (On-Behalf-Of) | Yes | Full | All clients + relays | Draft PR |
| Shared nsec | N/A | Full | None | Insecure |
| Direct NIP-46 | Instant | Limited | None | Works today |

## Conclusion

Signer Chaining provides a pragmatic solution to the delegated signing problem by leveraging existing NIP-46 infrastructure. It achieves the portability benefits that NIP-26 promised while maintaining the instant revocation guarantees of centralized signing.

The pattern requires no protocol changes - only a new feature in personal signers. By being first to implement upstream signer support, cloistr-signer can help drive ecosystem adoption and establish best practices for team-based Nostr identities.

## References

- [NIP-46: Nostr Remote Signing](https://github.com/nostr-protocol/nips/blob/master/46.md)
- [NIP-26: Delegated Event Signing (Unrecommended)](https://github.com/nostr-protocol/nips/blob/master/26.md)
- [NIP-0b: On-Behalf-Of (Draft PR)](https://github.com/nostr-protocol/nips/pull/1482)
- [cloistr-signer Documentation](https://signer.cloistr.xyz/docs)
