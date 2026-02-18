# Cloistr Signer Admin Guide

This guide covers deployment, configuration, and operation of Cloistr Signer for administrators and operators.

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Deployment](#deployment)
- [Monitoring](#monitoring)
- [Administration](#administration)
- [Backup and Recovery](#backup-and-recovery)
- [Troubleshooting](#troubleshooting)

## Requirements

### System Requirements

- Go 1.21+ (for building from source)
- Docker (for containerized deployment)
- PostgreSQL 14+ (for persistent storage)

### Network Requirements

- Outbound WebSocket connections to Nostr relays
- Inbound HTTP/HTTPS on port 7777 (configurable)

## Installation

### From Source

```bash
# Clone the repository
git clone https://git.coldforge.xyz/coldforge/cloistr-signer.git
cd cloistr-signer

# Build
go build -o cloistr-signer ./cmd/signer

# Run
./cloistr-signer
```

### Docker

```bash
# Build image
docker build -t cloistr-signer .

# Run container
docker run -d \
  -p 7777:7777 \
  -e RELAYS="wss://relay.example.com" \
  -e STORAGE_TYPE="memory" \
  cloistr-signer
```

### Kubernetes

See the Atlas role at `~/Atlas/roles/kube/cloistr-signer/` for Kubernetes deployment manifests.

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| **Server** | | |
| `SERVER_ADDRESS` | HTTP listen address | `:7777` |
| **Relays** | | |
| `RELAYS` | Comma-separated relay URLs | `wss://relay.coldforge.xyz` |
| `RELAY_AUTH_KEY` | Hex private key for NIP-42 auth | (none) |
| **Storage** | | |
| `STORAGE_TYPE` | `memory` or `postgres` | `memory` |
| `DATABASE_URL` | PostgreSQL connection string | (none) |
| `ENCRYPTION_KEY` | 32-byte hex key for AES-256-GCM | (none) |
| **Auth** | | |
| `ADMIN_PUBKEYS` | Comma-separated admin pubkeys | (none) |
| `REQUIRE_APPROVAL` | Require manual approval | `false` |
| `AUTHORIZATION_TIMEOUT` | Timeout in seconds | `60` |
| `NOTIFY_ADMINS` | DM admins for pending requests | `true` |
| `JWT_SECRET` | Secret for JWT signing | (none) |
| `JWT_EXPIRY` | JWT expiry in hours | `24` |
| `MFA_ISSUER` | TOTP issuer name | `Coldforge` |
| `MAX_FAILED_LOGINS` | Max failures before lockout | `5` |
| `LOCKOUT_MINUTES` | Lockout duration | `15` |
| **Encryption** | | |
| `ENCRYPTION_KEY` | 32-byte hex key for key encryption | (none) |
| **Vault** (optional) | | |
| `VAULT_ENABLED` | Enable HashiCorp Vault | `false` |
| `VAULT_ADDR` | Vault server address | (none) |
| `VAULT_TOKEN` | Vault auth token | (none) |
| `VAULT_MOUNT_PATH` | KV mount path | `secret` |
| **Audit** | | |
| `AUDIT_ENABLED` | Enable audit logging | `true` |
| `AUDIT_BACKEND` | `memory`, `file`, or `json` | `memory` |
| `AUDIT_FILE_PATH` | Path for file backend | (none) |
| **Service** | | |
| `SERVICE_NAME` | NIP-89 service name | `Coldforge Signer` |
| `SERVICE_DESCRIPTION` | Service description | (none) |
| `SERVICE_URL` | Public URL | (none) |
| `NIP05_DOMAIN` | NIP-05 domain | (none) |
| `PUBLISH_NIP89` | Publish NIP-89 announcements | `false` |

### Storage Backends

#### Memory (Development)

```bash
STORAGE_TYPE=memory
```

Data is lost on restart. Use only for development/testing.

#### PostgreSQL (Production)

```bash
STORAGE_TYPE=postgres
DATABASE_URL=postgresql://user:pass@host:5432/dbname?sslmode=require
```

Tables are auto-created on startup.

### Key Encryption

Generate an encryption key:

```bash
openssl rand -hex 32
```

Configure it:

```bash
ENCRYPTION_KEY=<64-character-hex-key>
```

Keys are encrypted with AES-256-GCM before storage. The `enc:` prefix identifies encrypted values.

### Authorization Modes

#### Auto-Approve (Default)

```bash
REQUIRE_APPROVAL=false
```

- Apps with valid bunker:// secrets are auto-approved
- Simpler UX for personal use
- Secrets are one-time use, expire after 24 hours

#### Manual Approval

```bash
REQUIRE_APPROVAL=true
```

- All requests require admin approval
- Higher security for shared deployments
- Admins notified via DM (if `NOTIFY_ADMINS=true`)

## Deployment

### Health Checks

| Endpoint | Purpose |
|----------|---------|
| `GET /health` | Overall health |
| `GET /health/live` | Liveness probe (is the process running?) |
| `GET /health/ready` | Readiness probe (can it serve traffic?) |

### Kubernetes Example

```yaml
livenessProbe:
  httpGet:
    path: /health/live
    port: 7777
  initialDelaySeconds: 30
  periodSeconds: 30

readinessProbe:
  httpGet:
    path: /health/ready
    port: 7777
  initialDelaySeconds: 10
  periodSeconds: 10
```

### Resource Recommendations

| Deployment | CPU | Memory |
|------------|-----|--------|
| Small (< 100 keys) | 100m | 128Mi |
| Medium (100-1000 keys) | 250m | 256Mi |
| Large (1000+ keys) | 500m | 512Mi |

### TLS Termination

The signer serves HTTP. Use a reverse proxy (nginx, Traefik, etc.) or ingress controller for TLS termination.

## Monitoring

### Prometheus Metrics

Metrics are exposed at `GET /metrics`:

| Metric | Type | Description |
|--------|------|-------------|
| `signer_keys_managed` | Gauge | Number of keys |
| `signer_requests_total` | Counter | Total signing requests |
| `signer_requests_approved` | Counter | Approved requests |
| `signer_requests_denied` | Counter | Denied requests |
| `signer_http_requests_total` | Counter | HTTP requests by path/method/status |
| `signer_http_request_duration_seconds` | Histogram | Request latency |

### Logging

Logs are JSON-formatted to stdout:

```json
{"time":"2026-02-18T12:00:00Z","level":"INFO","msg":"created key","name":"test","pubkey":"abc123..."}
```

Log levels: `DEBUG`, `INFO`, `WARN`, `ERROR`

### Alerting Recommendations

- **High error rate**: `rate(signer_requests_denied[5m]) > 0.1`
- **Latency**: `histogram_quantile(0.99, signer_http_request_duration_seconds) > 1`
- **No keys**: `signer_keys_managed == 0`

## Administration

### Admin DM Commands

Admins (configured via `ADMIN_PUBKEYS`) can manage the signer via encrypted Nostr DMs:

| Command | Description |
|---------|-------------|
| `help` | Show available commands |
| `status` | Get signer status |
| `get_keys` | List all keys |
| `get_key <id>` | Get key details |
| `create_key [name]` | Create new key |
| `delete_key <id>` | Delete a key |
| `list_pending` | List pending requests |
| `approve <id>` | Approve a request |
| `deny <id>` | Deny a request |
| `list_users` | List registered users |
| `list_policies` | List permission policies |

### Web Admin Interface

Access the web interface at the configured domain:

- `/dashboard` - Admin dashboard
- `/keys` - Key management
- `/requests` - Pending authorizations
- `/users` - User management (admin only)
- `/apps` - Connected apps

### User Roles

- **Admin**: Full access (first registered user, or linked to `ADMIN_PUBKEYS`)
- **User**: Can manage own keys only

## Backup and Recovery

### Database Backup

For PostgreSQL, use standard backup tools:

```bash
# Backup
pg_dump -h host -U user -d dbname > backup.sql

# Restore
psql -h host -U user -d dbname < backup.sql
```

### Encryption Key Backup

**Critical**: Back up your `ENCRYPTION_KEY`. Without it, encrypted keys cannot be recovered.

Store the key securely:
- Hardware security module (HSM)
- Secrets manager (Vault, AWS Secrets Manager)
- Encrypted offline storage

### Disaster Recovery

1. Restore PostgreSQL from backup
2. Configure signer with same `ENCRYPTION_KEY`
3. Start signer - keys will be decrypted automatically

## Troubleshooting

### Signer Won't Start

**Check logs for errors:**
```bash
kubectl logs -l app.kubernetes.io/name=cloistr-signer
```

**Common issues:**
- Database connection failed: Check `DATABASE_URL`
- Invalid encryption key: Must be 64 hex characters
- Port already in use: Change `SERVER_ADDRESS`

### Can't Connect to Relays

**Check relay connectivity:**
```bash
websocat wss://relay.example.com
```

**Common issues:**
- Firewall blocking outbound WebSocket
- Relay requires authentication: Set `RELAY_AUTH_KEY`
- Relay is down: Try alternative relays

### Keys Not Decrypting

**Symptoms:** Keys exist in DB but signer shows "no keys"

**Causes:**
- Wrong `ENCRYPTION_KEY`
- Key was stored with different encryption key

**Solution:** Ensure the same encryption key is used that was used to encrypt the keys.

### High Memory Usage

**Possible causes:**
- Too many concurrent connections
- Memory audit backend with many events

**Solutions:**
- Increase memory limits
- Switch to file/JSON audit backend
- Reduce `AUDIT_MAX_EVENTS`

### Signing Requests Timing Out

**Check:**
- Relay connectivity
- `AUTHORIZATION_TIMEOUT` setting
- Pending request queue

**Solutions:**
- Increase timeout
- Ensure admin approvals are timely
- Consider auto-approve mode for personal use

## Database Schema

The signer creates these tables in PostgreSQL:

| Table | Description |
|-------|-------------|
| `signer_keys` | Signing keys (encrypted) |
| `signer_permissions` | App permissions |
| `signer_policies` | Permission templates |
| `signer_policy_rules` | Policy rules |
| `signer_tokens` | One-time access tokens |
| `signer_pending_requests` | Authorization queue |
| `signer_users` | User accounts |
| `signer_user_sessions` | Active sessions |
| `signer_bunker_secrets` | bunker:// URI secrets |

---

*For API documentation, see [api-reference.md](api-reference.md)*
