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
  nostr/client.go           # Relay client with NIP-42 auth
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

### REQUIRE_APPROVAL Behavior

Controls how the signer handles requests from unknown clients (no existing permission):

- **`false` (default)**: Auto-approve all requests with full access. Simpler UX for personal bunkers - clients can connect immediately using the bunker:// URI. Recommended for new users.

- **`true`**: Requests wait for manual admin approval via the web UI (`/requests`) or admin DM commands. Opt-in for high-security or shared deployments where you want to vet each app.

**Bunker Secret Validation**: When a client connects with a valid bunker:// URI secret, they are auto-approved with full access regardless of `REQUIRE_APPROVAL` setting. Secrets are one-time use and expire after 24 hours. If the secret is invalid or missing, the normal `REQUIRE_APPROVAL` behavior applies.

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

### Phase 11 - Enhanced Approval & Connection UX

**Per-key approval mode (basic):**
- [x] Per-key `require_approval` toggle in DB and UI
- [x] Per-permission approval override (hybrid: permission → key → global)
- [x] Auto-use signing key for NIP-42 relay auth

**Granular approval (in progress):**
- [ ] Per-kind approval rules (approve kinds 1,7 but require approval for kind 30023)
- [ ] Approval UI showing event content preview
- [ ] Remember approval choices per-app

**Bidirectional connection dialogs:**
- [ ] Per-key "Connect" dialog accepts nostrconnect:// URIs (connect TO apps)
- [ ] "Connect to App" dialog accepts both nostrconnect:// and bunker:// URIs
- [ ] Unified connection dialog for all connection flows

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

**Last Updated:** 2026-02-19 (Deprecated nsecbunker: Atlas role removed, namespace deleted)
