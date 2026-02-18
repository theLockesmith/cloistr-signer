# Cloistr Signer API Reference

This document describes the HTTP API for Cloistr Signer.

**Base URL:** `https://signer.cloistr.xyz` (or your self-hosted instance)

## Table of Contents

- [Health](#health)
- [Keys](#keys)
- [Permissions](#permissions)
- [Policies](#policies)
- [Tokens](#tokens)
- [Pending Requests](#pending-requests)
- [Users](#users)
- [bunker:// URI](#bunker-uri)
- [nostrconnect://](#nostrconnect)
- [NIP-05](#nip-05)
- [Audit](#audit)
- [Metrics](#metrics)

---

## Health

### GET /health

Overall health status.

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2026-02-18T12:00:00Z"
}
```

### GET /health/live

Liveness probe - is the process running?

**Response:** `200 OK` with same format as `/health`

### GET /health/ready

Readiness probe - can the service handle requests?

**Response:** `200 OK` with same format as `/health`

---

## Keys

### GET /api/v1/keys

List all signing keys.

**Response:**
```json
[
  {
    "id": "abc123",
    "name": "My Key",
    "pubkey": "0123456789abcdef...",
    "created_at": "2026-02-18T12:00:00Z"
  }
]
```

### POST /api/v1/keys

Create a new signing key.

**Request:**
```json
{
  "name": "My Key",
  "private_key": "nsec1... or hex (optional)"
}
```

If `private_key` is omitted, a new keypair is generated.

**Response:** `201 Created`
```json
{
  "id": "abc123",
  "name": "My Key",
  "pubkey": "0123456789abcdef...",
  "created_at": "2026-02-18T12:00:00Z"
}
```

### GET /api/v1/keys/{id}

Get a specific key by ID.

**Response:**
```json
{
  "id": "abc123",
  "name": "My Key",
  "pubkey": "0123456789abcdef...",
  "created_at": "2026-02-18T12:00:00Z"
}
```

**Errors:**
- `404 Not Found` - Key does not exist

### DELETE /api/v1/keys/{id}

Delete a key.

**Response:** `204 No Content`

**Errors:**
- `404 Not Found` - Key does not exist

---

## Permissions

### GET /api/v1/keys/{id}/permissions

List permissions for a key.

**Response:**
```json
[
  {
    "key_id": "pubkey123...",
    "user_pubkey": "clientpubkey456...",
    "methods": ["sign_event", "get_public_key"],
    "allowed_kinds": [1, 4],
    "expires_at": "2026-03-18T12:00:00Z"
  }
]
```

### POST /api/v1/keys/{id}/permissions

Create or update a permission.

**Request:**
```json
{
  "user_pubkey": "clientpubkey456...",
  "methods": ["sign_event", "get_public_key", "nip44_encrypt", "nip44_decrypt"],
  "allowed_kinds": [1, 4, 7],
  "expires_at": "2026-03-18T12:00:00Z"
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `user_pubkey` | Yes | Client's public key (64 hex chars) |
| `methods` | Yes | Allowed NIP-46 methods |
| `allowed_kinds` | No | Restrict to specific event kinds |
| `expires_at` | No | Permission expiration |

**Response:** `201 Created`

### DELETE /api/v1/keys/{id}/permissions/{pubkey}

Delete a permission.

**Response:** `204 No Content`

---

## Policies

Policies are reusable permission templates.

### GET /api/v1/policies

List all policies.

**Response:**
```json
[
  {
    "id": "policy123",
    "name": "Read Only",
    "description": "Can only read public key",
    "rules": [
      {
        "id": "rule1",
        "policy_id": "policy123",
        "method": "get_public_key",
        "max_usage": 0
      }
    ],
    "created_at": "2026-02-18T12:00:00Z"
  }
]
```

### POST /api/v1/policies

Create a policy.

**Request:**
```json
{
  "name": "Full Access",
  "description": "Can sign any event",
  "rules": [
    {
      "method": "sign_event",
      "allowed_kinds": [],
      "max_usage": 0
    },
    {
      "method": "get_public_key"
    }
  ]
}
```

**Response:** `201 Created`

### GET /api/v1/policies/{id}

Get a specific policy.

### DELETE /api/v1/policies/{id}

Delete a policy.

---

## Tokens

Tokens are one-time redeemable access grants.

### GET /api/v1/tokens?key_id={id}

List tokens for a key.

**Response:**
```json
[
  {
    "id": "token123",
    "policy_id": "policy456",
    "key_id": "key789",
    "client_name": "My App",
    "expires_at": "2026-02-19T12:00:00Z",
    "redeemed_at": null,
    "created_at": "2026-02-18T12:00:00Z"
  }
]
```

### POST /api/v1/tokens

Create a token.

**Request:**
```json
{
  "policy_id": "policy456",
  "key_id": "key789",
  "client_name": "My App",
  "expires_at": "2026-02-19T12:00:00Z"
}
```

**Response:** `201 Created`

### GET /api/v1/tokens/{id}

Get a specific token.

### POST /api/v1/tokens/{id}/redeem

Redeem a token to create permissions.

**Request:**
```json
{
  "user_pubkey": "clientpubkey..."
}
```

**Response:** `200 OK` with created permission

**Errors:**
- `400 Bad Request` - Token already redeemed
- `400 Bad Request` - Token expired

### DELETE /api/v1/tokens/{id}

Delete a token.

---

## Pending Requests

Authorization requests waiting for approval.

### GET /api/v1/requests?key_pubkey={pubkey}

List pending requests, optionally filtered by key.

**Response:**
```json
[
  {
    "id": "req123",
    "key_pubkey": "keypubkey...",
    "client_pubkey": "clientpubkey...",
    "method": "sign_event",
    "params": ["event-json"],
    "created_at": "2026-02-18T12:00:00Z",
    "expires_at": "2026-02-18T12:01:00Z"
  }
]
```

### GET /api/v1/requests/{id}

Get a specific pending request.

### POST /api/v1/requests/{id}/approve

Approve a pending request.

**Request (optional):**
```json
{
  "methods": ["sign_event"],
  "allowed_kinds": [1]
}
```

If body is provided, creates a permission with those settings.

**Response:** `200 OK`

### POST /api/v1/requests/{id}/deny

Deny a pending request.

**Response:** `200 OK`

---

## Users

User account management.

### POST /api/v1/users/register

Register a new user.

**Request:**
```json
{
  "username": "alice",
  "email": "alice@example.com",
  "password": "securepassword123"
}
```

**Response:** `201 Created`
```json
{
  "id": "user123",
  "username": "alice",
  "email": "alice@example.com",
  "role": "user",
  "created_at": "2026-02-18T12:00:00Z"
}
```

### POST /api/v1/users/login

Log in to get a JWT token.

**Request:**
```json
{
  "username": "alice",
  "password": "securepassword123",
  "mfa_code": "123456"
}
```

`mfa_code` is required if MFA is enabled.

**Response:**
```json
{
  "token": "eyJhbGciOiJIUzI1NiIs...",
  "user": {
    "id": "user123",
    "username": "alice",
    "role": "user"
  }
}
```

### POST /api/v1/users/logout

Log out and revoke session.

**Headers:** `Authorization: Bearer <token>`

**Response:** `200 OK`

### GET /api/v1/users/me

Get current user info.

**Headers:** `Authorization: Bearer <token>`

**Response:**
```json
{
  "id": "user123",
  "username": "alice",
  "email": "alice@example.com",
  "role": "user",
  "mfa_enabled": true,
  "pubkey": "npub1...",
  "created_at": "2026-02-18T12:00:00Z"
}
```

### POST /api/v1/users/mfa/setup

Set up MFA (TOTP).

**Headers:** `Authorization: Bearer <token>`

**Response:**
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_url": "otpauth://totp/Coldforge:alice?secret=...",
  "backup_codes": ["12345678", "87654321", ...]
}
```

### POST /api/v1/users/mfa/verify

Verify MFA code and enable MFA.

**Request:**
```json
{
  "code": "123456"
}
```

**Response:** `200 OK`

### POST /api/v1/users/mfa/disable

Disable MFA.

**Request:**
```json
{
  "code": "123456"
}
```

**Response:** `200 OK`

### GET /api/v1/users/sessions

List active sessions.

**Headers:** `Authorization: Bearer <token>`

**Response:**
```json
[
  {
    "id": "session123",
    "created_at": "2026-02-18T12:00:00Z",
    "expires_at": "2026-02-19T12:00:00Z",
    "ip_address": "192.168.1.1",
    "user_agent": "Mozilla/5.0..."
  }
]
```

### DELETE /api/v1/users/sessions

Revoke all sessions (logout everywhere).

**Headers:** `Authorization: Bearer <token>`

**Response:** `200 OK`

---

## bunker:// URI

### GET /api/v1/bunker/{id}

Generate a bunker:// connection URI for a key.

**Response:**
```json
{
  "uri": "bunker://pubkey123...?relay=wss://relay.cloistr.xyz&secret=onetimesecret"
}
```

The secret is one-time use and expires after 24 hours.

---

## nostrconnect://

### POST /api/v1/nostrconnect

Connect to an app using a nostrconnect:// URI.

**Request:**
```json
{
  "uri": "nostrconnect://apppubkey?relay=wss://relay.example.com&metadata=...",
  "key_id": "key123"
}
```

**Response:**
```json
{
  "success": true,
  "app_pubkey": "apppubkey...",
  "relay": "wss://relay.example.com"
}
```

---

## NIP-05

### GET /.well-known/nostr.json

NIP-05 identifier verification.

**Query Parameters:**
- `name` - The name to look up (optional, returns all if omitted)

**Response:**
```json
{
  "names": {
    "alice": "pubkey123...",
    "bob": "pubkey456..."
  }
}
```

---

## Audit

### GET /api/v1/audit

Query audit logs.

**Query Parameters:**
- `type` - Event type filter
- `actor` - Actor pubkey filter
- `target` - Target filter
- `limit` - Max results (default 100)
- `offset` - Pagination offset

**Response:**
```json
[
  {
    "id": "audit123",
    "type": "key_created",
    "actor": "pubkey...",
    "target": "key123",
    "metadata": {},
    "timestamp": "2026-02-18T12:00:00Z"
  }
]
```

---

## Metrics

### GET /metrics

Prometheus metrics endpoint.

**Response:** Prometheus text format

```
# HELP signer_keys_managed Number of signing keys managed
# TYPE signer_keys_managed gauge
signer_keys_managed 5

# HELP signer_requests_total Total signing requests
# TYPE signer_requests_total counter
signer_requests_total{method="sign_event"} 100
```

---

## NIP-46 Methods

The signer supports these NIP-46 methods via the Nostr relay protocol:

| Method | Description |
|--------|-------------|
| `connect` | Establish session |
| `ping` | Health check |
| `get_public_key` | Return signer pubkey |
| `get_relays` | List connected relays |
| `sign_event` | Sign a Nostr event |
| `nip04_encrypt` | NIP-04 encryption |
| `nip04_decrypt` | NIP-04 decryption |
| `nip44_encrypt` | NIP-44 encryption |
| `nip44_decrypt` | NIP-44 decryption |

---

## Error Responses

All errors return JSON:

```json
{
  "error": "error message"
}
```

Common HTTP status codes:

| Code | Meaning |
|------|---------|
| `400` | Bad request (invalid input) |
| `401` | Unauthorized (missing/invalid token) |
| `403` | Forbidden (insufficient permissions) |
| `404` | Not found |
| `409` | Conflict (resource already exists) |
| `500` | Internal server error |

---

## Authentication

Most endpoints require authentication via JWT token:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
```

Obtain a token via `POST /api/v1/users/login`.

Some endpoints (like health checks and NIP-05) are public.
