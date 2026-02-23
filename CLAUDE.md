# CLAUDE.md - coldforge-signer

**Go-based NIP-46 Remote Signing Service**

**Domain:** signer.cloistr.xyz (Cloistr is the consumer-facing brand for Coldforge Nostr services)

## REQUIRED READING (Before ANY Action)

**Claude MUST read this file at the start of every session:**
- `~/claude/coldforge/cloistr/CLAUDE.md` - Cloistr project rules (contains further required reading)

## Overview

coldforge-signer is our Kubernetes-native NIP-46 remote signer, serving as the identity foundation for all Coldforge services. Written in Go for minimal footprint and fast startup. (nsecbunker was deprecated 2026-02-19)

## Quick Start

```bash
# Build
go build -o coldforge-signer ./cmd/signer

# Run locally
RELAYS="wss://relay.coldforge.xyz" ./coldforge-signer

# Run tests
go test ./...

# Build Docker image
docker build -t coldforge-signer .
```

## Architecture

```
cmd/signer/main.go          # Entry point, server setup
internal/
  config/config.go          # Configuration (env + yaml)
  storage/
    storage.go              # Storage interface + in-memory backend
    postgres.go             # PostgreSQL storage backend
  nostr/
    client.go               # Relay client with NIP-42 auth
    key_relay_manager.go    # Per-key relay connections for scalability
  signer/signer.go          # NIP-46 request handling
  api/handler.go            # HTTP management API
  auth/auth.go              # JWT, bcrypt, TOTP, backup codes
  admin/admin.go            # Admin DM command handler
  bunker/bunker.go          # bunker:// URI generation/parsing
  nip05/nip05.go            # NIP-05 verification and serving
  nip89/nip89.go            # NIP-89 service announcements
  vault/vault.go            # HashiCorp Vault integration
  audit/audit.go            # Audit logging (memory/JSON backends)
  metrics/metrics.go        # Prometheus metrics and HTTP middleware
  crypto/crypto.go          # AES-256-GCM encryption for keys at rest
  discovery/                # Optional relay discovery integration
    discovery.go            # Discovery service client
    selector.go             # Relay selection with fallbacks
  web/                      # Web UI
    web.go                  # Web handlers and routes
    templates/              # HTML templates
    static/                 # CSS and JS
```

## NIP-46 Methods Supported

| Method | Status | Description |
|--------|--------|-------------|
| `connect` | ✅ | Establish session |
| `ping` | ✅ | Health check |
| `get_public_key` | ✅ | Return signer pubkey |
| `get_relays` | ✅ | List connected relays |
| `sign_event` | ✅ | Sign a Nostr event |
| `nip04_encrypt` | ✅ | NIP-04 encryption |
| `nip04_decrypt` | ✅ | NIP-04 decryption |
| `nip44_encrypt` | ✅ | NIP-44 encryption |
| `nip44_decrypt` | ✅ | NIP-44 decryption |

## HTTP API

### Health
- `GET /health` - Overall health
- `GET /health/live` - Liveness probe
- `GET /health/ready` - Readiness probe

### Keys
- `GET /api/v1/keys` - List keys
- `POST /api/v1/keys` - Create key
- `GET /api/v1/keys/{id}` - Get key
- `DELETE /api/v1/keys/{id}` - Delete key

### Permissions
- `GET /api/v1/keys/{id}/permissions` - List permissions
- `POST /api/v1/keys/{id}/permissions` - Set permission
- `DELETE /api/v1/keys/{id}/permissions/{pubkey}` - Delete permission

### Policies
- `GET /api/v1/policies` - List policies
- `POST /api/v1/policies` - Create policy
- `GET /api/v1/policies/{id}` - Get policy
- `DELETE /api/v1/policies/{id}` - Delete policy

### Tokens
- `GET /api/v1/tokens?key_id={id}` - List tokens for a key
- `POST /api/v1/tokens` - Create token
- `GET /api/v1/tokens/{id}` - Get token
- `POST /api/v1/tokens/{id}/redeem` - Redeem token (creates permissions)
- `DELETE /api/v1/tokens/{id}` - Delete token

### Pending Requests (Authorization)
- `GET /api/v1/requests?key_pubkey={pubkey}` - List pending requests
- `GET /api/v1/requests/{id}` - Get pending request
- `POST /api/v1/requests/{id}/approve` - Approve request
- `POST /api/v1/requests/{id}/deny` - Deny request

### User Management
- `POST /api/v1/users/register` - Register new user (username/email/password)
- `POST /api/v1/users/login` - Login (returns JWT, supports MFA)
- `POST /api/v1/users/logout` - Logout (revokes sessions)
- `GET /api/v1/users/me` - Get current user info (requires JWT)
- `POST /api/v1/users/mfa/setup` - Setup MFA (returns secret + backup codes)
- `POST /api/v1/users/mfa/verify` - Verify MFA code and enable
- `POST /api/v1/users/mfa/disable` - Disable MFA (requires current code)
- `GET /api/v1/users/sessions` - List active sessions
- `DELETE /api/v1/users/sessions` - Revoke all sessions

### bunker:// URI (Phase 6)
- `GET /api/v1/bunker/{id}` - Generate bunker:// connection URI for a key

### nostrconnect:// (Client-Initiated Connections)
- `POST /api/v1/nostrconnect` - Connect to app via nostrconnect:// URI
  - Body: `{"uri": "nostrconnect://...", "key_id": "<key-id>"}`
  - Parses the nostrconnect URI, creates permission, sends connect response

### NIP-05 (Phase 6)
- `GET /.well-known/nostr.json` - NIP-05 identifier endpoint

### Audit (Phase 6)
- `GET /api/v1/audit` - Query audit logs (supports filtering by type, actor, target)

## Admin DM Commands

Admins can manage the signer via encrypted Nostr DMs (kind:4). Send commands to the signer's pubkey:

| Command | Description |
|---------|-------------|
| `help` | Show available commands |
| `status` | Get signer status (keys, relays, users) |
| `get_keys` | List all signing keys |
| `get_key <id>` | Get key details |
| `create_key [name]` | Create a new signing key |
| `delete_key <id>` | Delete a key |
| `list_pending` | List pending authorization requests |
| `approve <id>` | Approve a pending request |
| `deny <id>` | Deny a pending request |
| `list_users` | List registered users |
| `list_policies` | List permission policies |

Admins receive boot notifications when the signer starts.

## Web UI

The signer includes a web interface for management:

| Route | Description |
|-------|-------------|
| `/` | Home/landing page |
| `/login` | Login with password or NIP-07 extension |
| `/register` | User registration |
| `/dashboard` | Admin dashboard with stats |
| `/keys` | Key management (create, delete, copy) |
| `/requests` | Pending authorization requests |
| `/users` | User management |
| `/approve/{id}` | Authorization approval page (shareable link) |

The approval page can be shared via link for async authorization.

## Configuration

| Env Variable | Description | Default |
|--------------|-------------|---------|
| `SERVER_ADDRESS` | HTTP listen address | `:7777` |
| `RELAYS` | Comma-separated relay URLs | `wss://relay.coldforge.xyz` |
| `RELAY_AUTH_KEY` | Hex private key for NIP-42 auth | (none) |
| `STORAGE_TYPE` | `memory` or `postgres` | `memory` |
| `DATABASE_URL` | PostgreSQL connection string | (none) |
| `ADMIN_PUBKEYS` | Comma-separated admin pubkeys | (none) |
| `REQUIRE_APPROVAL` | Require manual approval for unknown clients (see below) | `false` |
| `AUTHORIZATION_TIMEOUT` | Timeout for authorization in seconds | `60` |
| `NOTIFY_ADMINS` | Send DMs to admins for pending requests | `true` |
| `JWT_SECRET` | Secret for JWT signing (required for user auth) | (none) |
| `JWT_EXPIRY` | JWT expiry in hours | `24` |
| `MFA_ISSUER` | Issuer name for TOTP | `Coldforge` |
| `MAX_FAILED_LOGINS` | Max failed logins before lockout | `5` |
| `LOCKOUT_MINUTES` | Lockout duration in minutes | `15` |
| **Encryption** | | |
| `ENCRYPTION_KEY` | 32-byte hex key for AES-256-GCM encryption of keys at rest | (none) |
| **Vault** (optional) | | |
| `VAULT_ENABLED` | Enable HashiCorp Vault integration | `false` |
| `VAULT_ADDR` | Vault server address | (none) |
| `VAULT_TOKEN` | Vault authentication token | (none) |
| `VAULT_MOUNT_PATH` | KV secrets mount path | `secret` |
| **Audit** | | |
| `AUDIT_ENABLED` | Enable audit logging | `true` |
| `AUDIT_BACKEND` | Backend type: `memory`, `file`, `json` | `memory` |
| `AUDIT_FILE_PATH` | Path for file/json backend | (none) |
| **Service Metadata** | | |
| `SERVICE_NAME` | Service name for NIP-89 | `Coldforge Signer` |
| `SERVICE_DESCRIPTION` | Service description | `NIP-46 Remote Signing Service` |
| `SERVICE_URL` | Public service URL | (none) |
| `NIP05_DOMAIN` | Domain for NIP-05 identifiers | (none) |
| `PUBLISH_NIP89` | Publish NIP-89 announcements | `false` |
| **Proxy/Chaining** (Phase 12) | | |
| `PROXY_MODE` | How to handle local proxy keys: `internal` or `external` | `internal` |
| `PROXY_TIMEOUT` | Timeout for upstream proxy requests in seconds | `30` |
| **Discovery** (optional) | | |
| `DISCOVERY_URL` | Discovery service URL for relay selection (empty = disabled) | (none) |
| `DISCOVERY_TIMEOUT` | Discovery query timeout in seconds | `5` |
| `DISCOVERY_MAX_RELAYS` | Maximum relays to include from discovery | `3` |
| `DISCOVERY_INCLUDE_IN_BUNKER` | Include discovered relays in bunker:// URI | `true` |

### REQUIRE_APPROVAL Behavior

Controls how the signer handles requests from unknown clients (no existing permission):

- **`false` (default)**: Auto-approve all requests with full access. Simpler UX for personal bunkers - clients can connect immediately using the bunker:// URI. Recommended for new users.

- **`true`**: Requests wait for manual admin approval via the web UI (`/requests`) or admin DM commands. Opt-in for high-security or shared deployments where you want to vet each app.

**Bunker Secret Validation**: When a client connects with a valid bunker:// URI secret, they are auto-approved with full access regardless of `REQUIRE_APPROVAL` setting. Secrets are one-time use and expire after 24 hours. If the secret is invalid or missing, the normal `REQUIRE_APPROVAL` behavior applies.

### PROXY_MODE Behavior (Phase 12)

Controls how proxy keys (keys stored as bunker:// URIs pointing to upstream signers) are handled:

- **`internal` (default)**: When both the proxy key and the target key are in the same signer, handle the delegation internally without going through relays. Faster, more reliable, and more private.

- **`external`**: Always use NIP-46 over relays, even for local-to-local proxying. Useful for testing, auditing, or if you want delegation visible on relays.

**Multi-hop chains**: Proxy keys can chain through multiple signers (e.g., Personal → Business → Sub-brand). Each hop adds latency but the protocol supports unlimited depth.

**Privacy note**: `internal` mode keeps your delegation structure private. `external` mode exposes delegation requests on relays as kind:24133 events.

## Development Status

### Completed (Phase 1)
- [x] Project structure scaffolded
- [x] Configuration loading (env + yaml)
- [x] In-memory storage backend
- [x] Relay client with reconnection
- [x] NIP-46 request/response handling
- [x] All core NIP-46 methods
- [x] HTTP management API
- [x] Per-method permissions
- [x] Event kind filtering
- [x] NIP-42 relay authentication
- [x] Dockerfile + GitLab CI
- [x] Atlas role for Kubernetes
- [x] Deployed to Atlantis cluster

### Completed (Phase 2)
- [x] Policy engine (reusable permission templates)
- [x] Access tokens (one-time redeemable)
- [x] Token redemption with permission creation
- [x] Authorization callbacks (async approval framework)
- [x] Pending request queue with timeout

### Completed (Phase 2.5)
- [x] Interactive approval flow integration with NIP-46 handler
- [x] Admin DM notification for pending approvals
- [x] Policy usage tracking and limits
- [x] Configurable authorization timeout
- [x] Async request processing with goroutines

### Completed (Phase 3)
- [x] User registration (username/email/password)
- [x] Password auth with bcrypt
- [x] MFA (TOTP + backup codes)
- [x] Session management (JWT)
- [x] Account lockout after failed attempts
- [x] CI deploy stage for automatic deployment

### Completed (Phase 4)
- [x] Admin Nostr DM commands (help, status, get_keys, create_key, delete_key, list_pending, approve, deny, list_users, list_policies)
- [x] Admin RPC handler for encrypted DMs from admin pubkeys
- [x] Boot notification to admins on signer startup

### Completed (Phase 5)
- [x] Authorization approval page (/approve/{id})
- [x] Account registration page (/register)
- [x] Login page with NIP-07 support (/login)
- [x] Admin dashboard with stats (/dashboard)
- [x] Keys management page (/keys)
- [x] Pending requests page (/requests)
- [x] Users management page (/users)

### Completed (Phase 6)
- [x] bunker:// URI protocol (`internal/bunker/bunker.go`)
- [x] NIP-05 integration (`internal/nip05/nip05.go`)
- [x] NIP-89 service announcements (`internal/nip89/nip89.go`)
- [x] HashiCorp Vault integration (`internal/vault/vault.go`)
- [x] Audit logging (`internal/audit/audit.go`)

### Completed (Phase 7 - Connection Flows)
- [x] bunker:// URI connection flow working with Primal
- [x] nostrconnect:// client-initiated connections
- [x] NIP-44 encryption support (with NIP-04 fallback)
- [x] Auto-approve mode for simpler UX
- [x] Web UI for Connect to App (nostrconnect modal)
- [x] Password strength indicator on registration
- [x] Password visibility toggle on login

### Completed (Phase 8 - Production Ready)
- [x] PostgreSQL storage backend (persistent data across restarts)
- [x] Database migrations (auto-creates tables on startup)
- [x] User roles (admin/user) with first-user-is-admin logic
- [x] Admin-only access to Users page
- [x] Key import via web UI (nsec or hex)
- [x] Logout functionality (cookie-based)
- [x] npub registration (link Nostr identity to account)
- [x] NIP-07 login for any user with linked pubkey
- [x] Dark mode theming fixes for modals and forms

### Completed (Phase 9 - Security & Management)
- [x] Bunker secret validation (auto-approve only with valid secret)
- [x] One-time use secrets with 24-hour expiry
- [x] Connected apps management UI (/apps)

### Completed (Phase 10 - Test Coverage)
- [x] PostgreSQL storage tests (54 tests)
- [x] Metrics package tests (19 tests)
- [x] Fixed PostgreSQL array scanning bugs (pq.Array usage)
- [x] Fixed metrics path normalization bugs
- [x] Total: 311+ unit tests across all packages

### Roadmap to Production

**Core functionality and tests complete! Next:**
- [x] Production PostgreSQL deployment (Atlas vars/main.yml)
- [x] Key encryption at rest (AES-256-GCM via ENCRYPTION_KEY)
- [x] Documentation (docs/user-guide.md, admin-guide.md, api-reference.md)
- [x] Deprecate nsecbunker (2026-02-19: Atlas role removed, namespace deleted)

### Completed (Phase 11 - Enhanced Approval & Connection UX)

**Per-key approval mode:**
- [x] Per-key `require_approval` toggle in DB and UI
- [x] Per-permission approval override (hybrid: permission → key → global)
- [x] Auto-use signing key for NIP-42 relay auth

**Granular approval:**
- [x] Per-kind approval rules (allowed_kinds field, enforced in signer)
- [x] Approval UI showing event content preview (kind name, content, tags, mentions)
- [x] Remember approval choices per-app and per-kind
- [x] Edit permissions UI with kind restrictions and quick presets

**Bidirectional connection dialogs:**
- [x] Per-key "Connect" dialog with tabs (share bunker:// / paste nostrconnect://)
- [x] Per-key nostrconnect:// support (connect TO apps from specific key)
- [x] "Connect to App" modal for quick connections

### Phase 12 - Signer Chaining (Delegated Team Signing)

**The Problem:** Businesses need team members to post on behalf of a shared identity without sharing the nsec. Traditional delegation (NIP-26) failed due to revocation problems and poor ecosystem adoption.

**The Solution:** Signer Chaining - NIP-46 signers can act as clients to other signers, enabling a daisy-chain where personal signers (Amber, nsecbunker) proxy signing requests to an upstream business signer.

```
Team Member's Client ──► Personal Signer ──► Business Signer (cloistr)
                              (Amber)              │
                                              signs with
                                            business key
                                                   │
Team Member's Client ◄── Personal Signer ◄────────┘
```

**Why it works:**
- Revocation is instant (remove permission in cloistr-signer)
- No new NIPs or protocol changes needed (NIP-46 all the way down)
- Team members keep their preferred signer setup
- Business maintains full control over who can sign

**Implementation - Proxy Key Support (completed 2026-02-21):**
- [x] Add "proxy key" type to storage (bunker:// URI + local keypair for NIP-46)
- [x] NIP-46 client mode: `internal/proxy` package connects to upstream signers
- [x] Forward sign_event/encrypt/decrypt requests to upstream
- [x] Web UI: Add proxy key via bunker:// URI (keys page "Add Proxy Key" button)
- [x] Proxy mode config: PROXY_MODE and PROXY_TIMEOUT environment variables
- [x] Connection management: detect disconnect, cleanup, auto-reconnect on next request
- [ ] Test harness: spin up coldforge-signer (upstream) + cloistr-signer (proxy) for full chain

**Implementation - Upstream Signer Enhancements:**
- [x] Document cloistr-signer as "upstream signer" for chained connections
- [ ] Verify NIP-46 auth flow works when connecting signer is a proxy
- [ ] Add "delegate pubkey" field to permissions (optional override for proxy scenarios)
- [ ] Create onboarding flow: "Invite team member" generates bunker:// URI for their signer
- [ ] Add audit logging for chained signatures (which delegate signed what)
- [ ] Web UI: Team management page showing delegates and their activity

**Ecosystem outreach:**
- [x] Technical documentation (`docs/signer-chaining.md`)
- [x] Blog post for Nostr community
- [x] Reference implementation complete (cloistr-signer as both upstream AND proxy)
- [ ] Feature requests to Amber, nsecbunker for "proxy key" support
- [ ] Propose pattern as NIP-46 addendum (after adoption)

### Completed (Phase 12.5 - NIP-46 Relay Scalability)

**The Problem:** NIP-46 logins were failing ~90% of the time due to rate limiting on public relays like damus.io. Multiple rapid round-trips (connect → get_public_key → sign_event) triggered rate limits.

**The Solution:** Per-key relay architecture with intelligent retry:

**Per-Key Relay Connections:**
- [x] Each signing key gets its own relay client (`internal/nostr/key_relay_manager.go`)
- [x] Isolated rate limits per key (not shared across all keys)
- [x] NIP-42 authentication as the signing key (higher limits on some relays)
- [x] Pre-warming: Relay connections established on startup, not first request

**Subscription Optimization:**
- [x] #p filter in NIP-46 subscription (relay-side filtering, not firehose)
- [x] Event deduplication (same event from multiple relays processed once)
- [x] Subscription refresh when keys added/removed

**Intelligent Retry with NIP-01 Prefix Detection:**
- [x] Non-retryable errors: `invalid:`, `duplicate:`, `blocked:` (fail immediately)
- [x] Retryable errors: everything else (rate-limited, pow, error, unknown)
- [x] Exponential backoff: 1s initial, up to 30s max, 5 retries
- [x] Adaptive POW: mines proof-of-work if relay demands it

**Multi-Relay Fallback (User Freedom):**
- [x] User-specified relays always tried first
- [x] Global relays (relay.cloistr.xyz) included as reliable fallback
- [x] Messages published to ALL configured relays (success if any accepts)
- [x] relay.cloistr.xyz exempts kind:24133 from rate limiting

**Key Files:**
- `internal/nostr/key_relay_manager.go` - Per-key relay connections
- `internal/nostr/client.go` - `isRetryableError()` NIP-01 detection
- `internal/signer/signer.go` - Deduplication, #p filter subscription

### Phase 13 - FROST Threshold Signing (Distributed Key Custody)

**The Problem:** Signer chaining solves team delegation but introduces a single point of failure - the upstream business signer holds the complete private key. If compromised, the business identity is lost.

**The Solution:** FROST (Flexible Round-Optimized Schnorr Threshold) signatures distribute the private key across multiple share holders. A t-of-n threshold (e.g., 3-of-5) is required to produce a valid signature. No single party ever holds the complete key.

**Key Benefits:**
- **No single point of failure:** Compromise of 1-2 shares doesn't compromise the key
- **Key rotation without identity change:** Rotate shares, keep the same npub
- **Geographic/organizational distribution:** Shares across data centers, team members, cold storage
- **Combines with signer chaining:** Delegates request signatures, FROST handles custody

**Architecture:**

```
                    Business npub (3-of-5 FROST)
                              │
     ┌──────────┬──────────┬──┴───┬──────────┬──────────┐
     │          │          │      │          │          │
  Share 1    Share 2    Share 3  Share 4   Share 5
  (Infra)    (Infra)    (Cold)   (Team)    (Team)
     │          │          │      │          │
     └────┬─────┘          │      │          │
          │                │      │          │
    Coordinator         Cold     John's   Sarah's
   (NIP-46 frontend)   Storage   Signer   Signer
          │
          ▼
   Signer Chaining Layer
   (Delegate permissions,
    audit logging)
          │
    ┌─────┴─────┐
    ▼           ▼
  John's     Sarah's
  Amber      nos2x
```

**Signing Scenarios (3-of-5):**
- **Routine:** 2 infra shares + cold storage (automated, no human needed)
- **Team participation:** 2 infra shares + John's share (John actively participates)
- **Disaster recovery:** John + Sarah + cold (infrastructure down)
- **Maximum decentralization:** Any 3 team members (no auto-signing)

**Implementation - Core FROST Support:**
- [ ] Research FROSTR libraries (bifrost, frost, nostrp2p)
- [ ] Evaluate: build native FROST vs integrate FROSTR
- [ ] Implement share holder mode (cloistr-signer holds one FROST share)
- [ ] Implement coordinator mode (orchestrates signing across share holders)
- [ ] FROST share storage (encrypted, separate from regular keys)
- [ ] Signing session coordination via Nostr relays (NIP-04 encrypted DMs)

**Implementation - Distributed Key Generation (DKG):**
- [ ] Trusted dealer mode: admin generates key, distributes shares
- [ ] Distributed mode: share holders collaboratively generate without seeing full key
- [ ] Key ceremony UI: step-by-step DKG with verification
- [ ] Share backup/recovery procedures

**Implementation - Share Management:**
- [ ] Web UI: FROST key management (create, view shares, thresholds)
- [ ] Share rotation: refresh shares without changing npub
- [ ] Share recovery: regenerate lost share from t existing shares
- [ ] Threshold modification: change t-of-n (requires new DKG)

**Implementation - Hybrid Custody Models:**
- [ ] Team members as share holders (John holds Share 4 in his signer)
- [ ] Infrastructure shares (always-on servers for routine signing)
- [ ] Cold storage shares (offline, for emergencies)
- [ ] Configurable policies: "require at least 1 team share" vs "infra-only OK"

**Implementation - Integration with Signer Chaining:**
- [ ] FROST coordinator speaks NIP-46 to delegates (unchanged interface)
- [ ] Delegate permissions enforced BEFORE triggering FROST signing
- [ ] Audit logs capture: delegate identity + which shares participated
- [ ] Transparent to delegates: they don't know it's threshold-signed

**Research & Ecosystem:**
- [ ] Contact FROSTR team about integration/collaboration
- [ ] Evaluate Igloo, Frost2x for interoperability
- [ ] Document FROST + Signer Chaining architecture
- [ ] Consider: could Amber hold a FROST share? (feature request)

**Security Considerations:**
- Share compromise: rotate immediately, old share becomes useless
- Coordinator compromise: can't sign alone, only orchestrates
- Communication security: all share coordination via NIP-04/NIP-44 encrypted
- Offline shares: cold storage for disaster recovery, never online

**Future Extensions:**
- [ ] Hardware wallet support for share custody (Frostsnap integration?)
- [ ] Mobile share holder app
- [ ] Multi-organization federations (each org holds shares)
- [ ] Time-locked shares (require delay for high-value operations)

## Deployment

```bash
# Deploy via Atlas
cd ~/Atlas
K8S_AUTH_KUBECONFIG=~/.kube/config ansible-playbook -i inventory/kube.yaml playbooks/kube.yml \
  -e "manifest_names=['coldforge-signer']" \
  -e "kube_state=present"

# With NIP-42 auth key
ansible-playbook ... \
  -e "signer_relay_auth_key=<hex-private-key>"
```

## Testing

### Unit Tests

```bash
# Run all unit tests
go test ./...

# Run with verbose output
go test -v ./...

# Run tests for a specific package
go test ./internal/storage/...
go test ./internal/metrics/...

# Run PostgreSQL storage tests (requires database)
TEST_DATABASE_URL="postgres://user:pass@localhost:5432/testdb?sslmode=disable" go test -v ./internal/storage/...

# Run with coverage
go test -cover ./...
```

### Integration Tests

```bash
# Port-forward to deployed signer
oc -n coldforge-signer port-forward svc/coldforge-signer 7780:7777

# Create test key
curl -X POST http://localhost:7780/api/v1/keys \
  -H "Content-Type: application/json" \
  -d '{"name": "testkey"}'

# Set permission
curl -X POST http://localhost:7780/api/v1/keys/<id>/permissions \
  -H "Content-Type: application/json" \
  -d '{"user_pubkey": "<client-pubkey>", "methods": ["sign_event", "ping"]}'

# Run NIP-46 integration tests (Node.js)
cd test/integration
npm install
node test-nip46.mjs
node test-go-signer.mjs
```

## Related

- Full roadmap: `~/claude/coldforge/services/identity/CLAUDE.md`
- Integration tests: `test/integration/`
- Atlas role: `~/Atlas/roles/kube/coldforge-signer/`
- NIP-46 spec: https://github.com/nostr-protocol/nips/blob/master/46.md
- NIP-42 spec: https://github.com/nostr-protocol/nips/blob/master/42.md

---

**Last Updated:** 2026-02-23 (Phase 12: Proxy upstream reconnection - detect disconnect, fail pending requests, auto-reconnect)
