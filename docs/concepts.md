# Key Concepts

This document explains the core concepts and advanced features of cloistr-signer.

## Key Types

### Standard Keys

A standard key is a Nostr private key (nsec) stored encrypted in the signer. When a signing request arrives, the signer decrypts the key, signs the event, and clears the key from memory.

### Proxy Keys

A proxy key doesn't hold a private key at all - it holds a **bunker URI** pointing to another NIP-46 signer. When a signing request arrives, the signer forwards it to the upstream bunker instead of signing locally.

**Use cases:**
- Chain your signer to nsecBunker for hardware key protection
- Use a hosted signer as a frontend to your self-hosted signer
- Add an approval layer without exposing your actual key

**How it works:**

```
Client App                Your Signer              Upstream Bunker
    │                          │                         │
    │ sign_event request       │                         │
    │─────────────────────────>│                         │
    │                          │ forward sign_event      │
    │                          │────────────────────────>│
    │                          │                         │ signs with real key
    │                          │     signed event        │
    │                          │<────────────────────────│
    │    signed event          │                         │
    │<─────────────────────────│                         │
```

### FROST Keys (Threshold Signing)

A FROST key is split into multiple shares using Shamir's Secret Sharing. No single share can sign alone - a threshold number of shares must collaborate.

**Example:** A 2-of-3 FROST key has 3 shares, and any 2 can sign together. If one share is compromised, the key remains secure.

## Importing Keys

### Import an nsec

Paste your nsec (starting with `nsec1...`) or hex private key. The signer encrypts it and stores it.

### Import a Proxy Key

Paste a bunker URI (starting with `bunker://`). The signer stores the URI and marks the key as a proxy. All signing requests are forwarded to that bunker.

**Bunker URI format:**
```
bunker://<pubkey>?relay=wss://relay.example.com&secret=<optional-secret>
```

### Generate a New Key

The signer generates a fresh keypair. The private key never leaves the signer.

## FROST (Threshold Signing)

### What is FROST?

FROST (Flexible Round-Optimized Schnorr Threshold) enables threshold signatures where:
- A key is split into N shares
- Any T shares can collaborate to sign (where T ≤ N)
- No single share holder can sign alone
- The original private key can be reconstructed only by combining T shares

### Distributed Key Generation (DKG)

Instead of splitting an existing key, FROST can generate a new key where:
- No single party ever sees the full private key
- Each participant generates their share independently
- The shares are mathematically linked to produce valid signatures

**DKG Process:**
1. Coordinator initiates DKG with participant list
2. Each participant generates commitment and sends to others via encrypted DMs
3. Participants verify commitments and generate shares
4. Group public key is derived - signing can begin

### Local vs Remote Signers

**Local FROST:** All shares are held by your signer instance. Useful for backup/recovery scenarios but provides no threshold security benefit.

**Distributed FROST:** Shares are held by multiple signer instances. When signing:
1. Coordinator collects signing commitments from remote signers
2. Each remote signer provides a partial signature
3. Coordinator combines partials into final signature

### FROST with Proxy Keys

FROST keys can designate remote signers as share holders:

```
Your Signer (Coordinator)         Remote Signer A         Remote Signer B
    │ holds share 1                   │ holds share 2          │ holds share 3
    │                                 │                        │
    │ signing request arrives         │                        │
    │─────────────────────────────────│────────────────────────│
    │ request partial sig             │                        │
    │────────────────────────────────>│                        │
    │                                 │ partial sig            │
    │<────────────────────────────────│                        │
    │ request partial sig             │                        │
    │─────────────────────────────────│───────────────────────>│
    │                                 │                        │ partial sig
    │<────────────────────────────────│────────────────────────│
    │                                 │                        │
    │ combine partials → final sig    │                        │
```

This enables true distributed custody - even if your signer is compromised, the attacker cannot sign without collaboration from other share holders.

## Permissions

Keys can have fine-grained permissions that control what operations are allowed:

| Permission | Description |
|------------|-------------|
| `sign_event` | Can sign events (optionally restricted by kind) |
| `nip04_encrypt` | Can encrypt using NIP-04 |
| `nip04_decrypt` | Can decrypt using NIP-04 |
| `nip44_encrypt` | Can encrypt using NIP-44 |
| `nip44_decrypt` | Can decrypt using NIP-44 |
| `get_public_key` | Can retrieve the public key |

Permissions can be granted to specific client pubkeys or to "any" for open access.

## Client Authorization

### Auto-Approve Mode

Any client can connect and use keys without approval. Suitable for personal use or trusted environments.

### Require Approval Mode

Unknown clients trigger an authorization request. An admin must approve before the client can use keys. Enables:
- DM notification to admins
- Web UI approval interface
- Audit trail of all authorizations

## Encryption at Rest

### Local Encryption

All private keys are encrypted with AES-256-GCM before storage. The encryption key is derived from `ENCRYPTION_KEY` environment variable.

**Security property:** Anyone with `ENCRYPTION_KEY` can decrypt all keys.

### Vault Transit Encryption

Each user gets their own Vault transit encryption key. Keys are encrypted with the user's transit key, which is only accessible with the user's Vault token.

**Security property:** Only the key owner can decrypt their keys. The operator cannot decrypt user keys.

## bunker:// URI Format

The bunker URI is how clients connect to your signer:

```
bunker://<signer-pubkey>?relay=wss://relay1.com&relay=wss://relay2.com&secret=<connection-secret>
```

| Component | Description |
|-----------|-------------|
| `<signer-pubkey>` | The key's public key (hex) |
| `relay` | Relay(s) where the signer listens (can repeat) |
| `secret` | Optional shared secret for connection auth |

Clients paste this URI into apps like Amethyst, Damus, or Coracle to use your signer.

## nostrconnect:// URI Format

For initiating connections from the signer side:

```
nostrconnect://<client-pubkey>?relay=wss://relay.com&metadata=<json>
```

Used when a client displays a QR code and you scan it with your signer.
