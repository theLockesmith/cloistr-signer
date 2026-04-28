# coldforge-signer Reference

**Comprehensive configuration and deployment reference for the NIP-46 signer service.**

For quick start and essential info, see [CLAUDE.md](../CLAUDE.md).

---

## Documentation Index

| Document | Content |
|----------|---------|
| [api-reference.md](api-reference.md) | Full HTTP API (keys, permissions, users, tokens) |
| [frost-integration.md](frost-integration.md) | FROST threshold signing |
| [signer-chaining.md](signer-chaining.md) | Proxy key architecture |
| [discovery-integration.md](discovery-integration.md) | Discovery service integration |
| [admin-guide.md](admin-guide.md) | Administrative operations |
| [user-guide.md](user-guide.md) | End-user documentation |

---

## Environment Variables

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_ADDRESS` | `:7777` | HTTP listen address |
| `RELAYS` | - | Comma-separated relay URLs (can use internal K8s DNS) |
| `RELAY_PUBLIC_MAPPINGS` | - | Internal→external URL mappings for bunker URIs (format: `internal=external,internal2=external2`) |
| `RELAY_AUTH_KEY` | - | NIP-42 auth key (optional) |
| `MIN_POW_DIFFICULTY` | `0` | Required PoW bits |

### Storage

| Variable | Default | Description |
|----------|---------|-------------|
| `STORAGE_TYPE` | `memory` | `memory` or `postgres` |
| `DATABASE_URL` | - | PostgreSQL DSN |
| `ENCRYPTION_KEY` | - | Key encryption master key (32 bytes hex) |

### HashiCorp Vault (Per-User Key Encryption)

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_ENABLED` | `false` | Enable Vault integration |
| `VAULT_ADDR` | - | Vault server URL |
| `VAULT_TOKEN` | - | Service account token (for user provisioning) |
| `VAULT_MOUNT_PATH` | `transit` | Transit secrets engine mount |
| `VAULT_SKIP_VERIFY` | `false` | Skip TLS certificate verification |

### Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET` | - | JWT signing secret |
| `JWT_EXPIRY` | `24h` | Token validity |
| `MFA_ISSUER` | `Coldforge Signer` | TOTP issuer name |
| `MAX_FAILED_LOGINS` | `5` | Before lockout |
| `LOCKOUT_MINUTES` | `15` | Lockout duration |
| `SESSION_INACTIVITY_MINUTES` | `30` | Idle timeout |
| `REMEMBER_DEVICE_DAYS` | `30` | Device trust duration |

### Authorization

| Variable | Default | Description |
|----------|---------|-------------|
| `ADMIN_PUBKEYS` | - | Comma-separated admin pubkeys |
| `REQUIRE_APPROVAL` | `true` | Require approval for new connections |
| `AUTHORIZATION_TIMEOUT` | `60s` | Request timeout |
| `NOTIFY_ADMINS` | `true` | DM admins on pending requests |

### Service Identity (NIP-89)

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVICE_NAME` | `Coldforge Signer` | Display name |
| `SERVICE_DESCRIPTION` | - | Service description |
| `SERVICE_URL` | - | Public URL |
| `NIP05_DOMAIN` | - | NIP-05 verification domain |
| `PUBLISH_NIP89` | `false` | Publish service announcement |

### Proxy Mode

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXY_MODE` | - | `forward`, `chain`, or empty |
| `PROXY_TIMEOUT` | `30s` | Upstream timeout |

### Discovery

| Variable | Default | Description |
|----------|---------|-------------|
| `DISCOVERY_URL` | - | Discovery service endpoint |
| `DISCOVERY_TIMEOUT` | `10s` | Discovery request timeout |
| `DISCOVERY_MAX_RELAYS` | `5` | Max relays in bunker:// |
| `DISCOVERY_INCLUDE_IN_BUNKER` | `true` | Include discovered relays |

### Audit

| Variable | Default | Description |
|----------|---------|-------------|
| `AUDIT_ENABLED` | `true` | Enable audit logging |
| `AUDIT_BACKEND` | `file` | `file`, `postgres`, or `none` |
| `AUDIT_FILE_PATH` | `audit.log` | Log file path |

---

## Prometheus Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `signer_keys_managed` | gauge | Number of signing keys |
| `signer_requests_total` | counter | Total signing requests by method |
| `signer_request_duration_seconds` | histogram | Request latency |
| `signer_active_sessions` | gauge | Active NIP-46 sessions |
| `signer_pending_requests` | gauge | Pending authorization requests |

---

## Deployment

### ArgoCD GitOps

- **App:** `signer-production` in argocd namespace
- **Source:** `overlays/production/signer` in coldforge-config
- **Image:** `oci.coldforge.xyz/coldforge/coldforge-signer`

### Cloudflare Tunnel

- `signer.cloistr.xyz` → coldforge-signer:8080

### Atlas Deployment

```bash
cd ~/Atlas && K8S_AUTH_KUBECONFIG=~/.kube/config ansible-playbook \
  -i inventory/kube.yaml playbooks/kube.yml \
  -e "manifest_names=['coldforge-signer']" -e "kube_state=present"
```

---

## Infrastructure

| Service | Endpoint |
|---------|----------|
| PostgreSQL | postgres-rw.db.coldforge.xyz:5432 |
| Relay | wss://relay.coldforge.xyz |
| Discovery | https://discovery.cloistr.xyz |

---

## Development Phases

| Phase | Focus | Status |
|-------|-------|--------|
| 1 | Core NIP-46 | Done |
| 2 | PostgreSQL + Auth | Done |
| 3 | MFA + Policies | Done |
| 4 | Admin DM Commands | Done |
| 5 | bunker:// + nostrconnect:// | Done |
| 6 | Signer Chaining | Done |
| 7 | Per-Key Connections | Done |
| 8 | FROST Threshold (API + Web UI) | Done |
| 9 | Distributed DKG | Done |
| 10 | Distributed Signing | Done |
| 11 | Multi-User Key Isolation | Done |
| 12 | Vault Per-User Encryption | Done |

### Phase 12: Vault Per-User Encryption (2026-04-28)

HashiCorp Vault integration for true per-user key encryption:
- Each user gets dedicated Vault transit key
- Operator cannot decrypt user keys - only user's Vault token can
- Automatic user provisioning (userpass auth + transit key + policy)
- Falls back to shared encryption key if Vault unavailable
- Full test coverage (19 packages, 109 FROST tests)

---

## Feature Coverage

| Feature | Code | Tests | Web UI | Notes |
|---------|------|-------|--------|-------|
| Core NIP-46 | ✓ | ✓ | N/A | Protocol layer |
| PostgreSQL + Encryption | ✓ | ✓ | N/A | Storage backend |
| User Auth (MFA, backup codes) | ✓ | ✓ | ✓ | /login, /register, /settings |
| Admin DM Commands | ✓ | ✓ | N/A | By design - via Nostr DMs |
| bunker:// + nostrconnect:// | ✓ | ✓ | ✓ | /keys shows URIs |
| Signer Chaining | ✓ | ✓ | ✓ | Proxy key modal in /keys |
| Per-Key Connections | ✓ | ✓ | N/A | Automatic |
| FROST Local Signing | ✓ | ✓ | ✓ | /frost page |
| Distributed DKG | ✓ | ✓ | N/A | Ceremony via Nostr DMs |
| Distributed Signing | ✓ | ✓ | N/A | Coordination via Nostr DMs |
| Multi-User Key Isolation | ✓ | ✓ | ✓ | Users see only their keys |
| Vault Per-User Encryption | ✓ | ✓ | N/A | Transparent to users |

**N/A** = Feature doesn't need Web UI (backend/protocol/by-design)

---

**Last Updated:** 2026-04-28
