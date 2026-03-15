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
| `SERVER_ADDRESS` | `:8080` | HTTP listen address |
| `RELAYS` | - | Comma-separated relay URLs |
| `RELAY_AUTH_KEY` | - | NIP-42 auth key (optional) |
| `MIN_POW_DIFFICULTY` | `0` | Required PoW bits |

### Storage

| Variable | Default | Description |
|----------|---------|-------------|
| `STORAGE_TYPE` | `memory` | `memory` or `postgres` |
| `DATABASE_URL` | - | PostgreSQL DSN |
| `ENCRYPTION_KEY` | - | Key encryption master key (32 bytes hex) |

### HashiCorp Vault

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_ENABLED` | `false` | Enable Vault integration |
| `VAULT_ADDR` | - | Vault server URL |
| `VAULT_TOKEN` | - | Vault access token |
| `VAULT_MOUNT_PATH` | `secret` | KV secrets mount |
| `VAULT_URL` | - | Alternative to VAULT_ADDR |

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

## Development Phases (Completed)

| Phase | Focus | Status |
|-------|-------|--------|
| 1 | Core NIP-46 | Done |
| 2 | PostgreSQL + Auth | Done |
| 3 | MFA + Policies | Done |
| 4 | Admin DM Commands | Done |
| 5 | bunker:// + nostrconnect:// | Done |
| 6 | Signer Chaining | Done |
| 7 | Per-Key Connections | Done |
| 8 | FROST Threshold (API) | Done |

---

**Last Updated:** 2026-03-11
