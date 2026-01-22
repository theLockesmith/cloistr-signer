# CLAUDE.md - coldforge-signer

**Go-based NIP-46 Remote Signing Service**

## Overview

This is a ground-up rewrite of the NIP-46 signer in Go, replacing the Node.js nsecbunkerd. It provides remote signing capabilities for the Coldforge ecosystem.

## Quick Start

```bash
# Build
make build

# Run locally
make dev

# Run tests
make test

# Build Docker image
make docker
```

## Architecture

```
cmd/signer/main.go          # Entry point, server setup
internal/
  config/config.go          # Configuration (env + yaml)
  storage/storage.go        # Key and permission storage
  nostr/client.go           # Relay connection management
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

Environment variables (override yaml):
- `SERVER_ADDRESS` - HTTP server address (default: `:7777`)
- `RELAYS` - Comma-separated relay URLs
- `STORAGE_TYPE` - `memory`, `postgres`, or `sqlite`
- `DATABASE_URL` - Database connection string
- `VAULT_URL` - Vault URL for key encryption
- `ADMIN_PUBKEYS` - Comma-separated admin pubkeys

## Development Status

### Completed
- [x] Project structure scaffolded
- [x] Configuration loading (env + yaml)
- [x] In-memory storage backend
- [x] Relay client with reconnection
- [x] NIP-46 request/response handling
- [x] All NIP-46 methods implemented
- [x] HTTP management API
- [x] Dockerfile
- [x] Makefile

### Next Steps
- [ ] Postgres storage backend
- [ ] Vault integration for key encryption
- [ ] Admin authentication (NIP-98)
- [ ] Rate limiting
- [ ] Metrics/observability
- [ ] Unit tests
- [ ] Integration tests with existing test suite
- [ ] Atlas role for Kubernetes deployment

## Related

- Full docs: `~/claude/coldforge/services/identity/CLAUDE.md`
- Test scripts: `~/Development/coldforge-identity/` (can be used to test this signer)
- NIP-46 spec: https://github.com/nostr-protocol/nips/blob/master/46.md
