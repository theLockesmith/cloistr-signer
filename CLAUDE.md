# CLAUDE.md - coldforge-signer

**Go-based NIP-46 Remote Signing Service**

## Overview

coldforge-signer is our Kubernetes-native NIP-46 remote signer, replacing nsecbunker as the identity foundation for all Coldforge services. Written in Go for minimal footprint and fast startup.

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
  storage/storage.go        # Key and permission storage
  nostr/client.go           # Relay client with NIP-42 auth
  signer/signer.go          # NIP-46 request handling
  api/handler.go            # HTTP management API
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

## Configuration

| Env Variable | Description | Default |
|--------------|-------------|---------|
| `SERVER_ADDRESS` | HTTP listen address | `:7777` |
| `RELAYS` | Comma-separated relay URLs | `wss://relay.coldforge.xyz` |
| `RELAY_AUTH_KEY` | Hex private key for NIP-42 auth | (none) |
| `STORAGE_TYPE` | `memory` or `postgres` | `memory` |
| `DATABASE_URL` | PostgreSQL connection string | (none) |
| `ADMIN_PUBKEYS` | Comma-separated admin pubkeys | (none) |
| `VAULT_URL` | Vault URL for key encryption | (none) |

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

### Roadmap to nsecbunker Feature Parity

**Phase 2: Authorization System (NEXT)**
- [ ] Policy engine (reusable permission templates)
- [ ] Access tokens (one-time redeemable)
- [ ] Authorization callbacks (async approval)
- [ ] Interactive approval flow
- [ ] Admin DM notification for approvals

**Phase 3: User Management**
- [ ] User registration (username/email/password)
- [ ] Password auth with bcrypt
- [ ] MFA (TOTP + backup codes)
- [ ] Session management (JWT)
- [ ] Account lockout

**Phase 4: Admin Interface**
- [ ] Admin Nostr DM commands (get_keys, create_key, etc.)
- [ ] Admin RPC handler
- [ ] Boot notification to admins

**Phase 5: Web UI**
- [ ] Authorization approval page
- [ ] Account registration page
- [ ] Login page with NIP-07 support
- [ ] Admin dashboard

**Phase 6: Advanced Features**
- [ ] bunker:// URI protocol
- [ ] NIP-05 integration
- [ ] NIP-89 service announcements
- [ ] HashiCorp Vault integration
- [ ] Audit logging

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

# Run NIP-46 tests
cd ~/Development/coldforge-identity
node test-nip46.mjs
```

## Related

- Full roadmap: `~/claude/coldforge/services/identity/CLAUDE.md`
- Test scripts: `~/Development/coldforge-identity/`
- Atlas role: `~/Atlas/roles/kube/coldforge-signer/`
- NIP-46 spec: https://github.com/nostr-protocol/nips/blob/master/46.md
- NIP-42 spec: https://github.com/nostr-protocol/nips/blob/master/42.md

---

**Last Updated:** 2026-01-25
