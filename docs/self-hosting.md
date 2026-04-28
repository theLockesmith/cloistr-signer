# Self-Hosting Guide

This guide covers deploying cloistr-signer for self-hosters, from minimal single-user setups to multi-user deployments with enterprise-grade key isolation.

## Quick Start (Single User)

Minimal setup using SQLite and local encryption:

```bash
# Generate a 32-byte encryption key
ENCRYPTION_KEY=$(openssl rand -hex 32)

# Run with SQLite
docker run -d \
  -p 7777:7777 \
  -v ./data:/data \
  -e STORAGE_TYPE=sqlite \
  -e DATABASE_URL=file:/data/signer.db \
  -e ENCRYPTION_KEY=$ENCRYPTION_KEY \
  -e RELAYS=wss://relay.damus.io,wss://nos.lol \
  registry.aegis-hq.xyz/coldforge/cloistr-signer:latest
```

Access the web UI at `http://localhost:7777`.

## Storage Options

### SQLite (Recommended for Single-Node)

```bash
STORAGE_TYPE=sqlite
DATABASE_URL=file:/path/to/signer.db
```

SQLite stores everything in a single file. Back up this file to preserve all data.

### PostgreSQL (Recommended for Multi-Replica)

```bash
STORAGE_TYPE=postgres
DATABASE_URL=postgres://user:pass@host:5432/signer?sslmode=require
```

PostgreSQL supports multiple signer replicas and provides better concurrent write handling.

### Memory (Testing Only)

```bash
STORAGE_TYPE=memory
```

All data is lost on restart. Use only for development/testing.

## Encryption Options

### Local Encryption (Single Key)

```bash
ENCRYPTION_KEY=<64-char-hex-string>
```

All user keys are encrypted with a single AES-256-GCM key. The operator (whoever has `ENCRYPTION_KEY`) can decrypt any user's keys.

**Use when:** Single-user setup, or you're comfortable having access to all keys.

### Vault Transit (Per-User Keys)

```bash
VAULT_ENABLED=true
VAULT_ADDR=https://vault.example.com
VAULT_TOKEN=<service-account-token>
VAULT_MOUNT_PATH=transit
```

Each user gets their own Vault transit encryption key. The operator cannot decrypt user keys - only the user's Vault token (derived from their password) can decrypt their keys.

**Use when:** Multi-user deployment where users must not trust the operator with their keys.

## Vault Setup

### 1. Enable Transit Secrets Engine

```bash
vault secrets enable transit
```

### 2. Enable Userpass Auth

```bash
vault auth enable userpass
```

### 3. Create Service Account Policy

The signer needs a service account to create user resources (transit keys, policies, userpass accounts). Create `cloistr-signer-service.hcl`:

```hcl
# Create and manage transit keys for users
path "transit/keys/cloistr-user-*" {
  capabilities = ["create", "read", "update"]
}

# Create and manage policies for users
path "sys/policies/acl/cloistr-user-*" {
  capabilities = ["create", "read", "update", "delete"]
}

# Create and manage userpass accounts
path "auth/userpass/users/*" {
  capabilities = ["create", "read", "update", "delete"]
}

# Read auth methods (for login)
path "auth/userpass/login/*" {
  capabilities = ["create", "read"]
}

# Health check
path "sys/health" {
  capabilities = ["read"]
}
```

Apply the policy:

```bash
vault policy write cloistr-signer-service cloistr-signer-service.hcl
```

### 4. Create Service Account Token

```bash
vault token create \
  -policy=cloistr-signer-service \
  -period=768h \
  -display-name="cloistr-signer-service"
```

Use this token as `VAULT_TOKEN` in your signer configuration.

### 5. How User Policies Work

When a user registers, the signer automatically creates:

1. **Transit key**: `cloistr-user-<user_id>` - encrypts/decrypts only this user's keys
2. **Policy**: `cloistr-user-<user_id>` - restricts access to only their transit key
3. **Userpass account**: Linked to the policy

The generated user policy looks like:

```hcl
# Policy for user abc123
path "transit/encrypt/cloistr-user-abc123" {
  capabilities = ["update"]
}
path "transit/decrypt/cloistr-user-abc123" {
  capabilities = ["update"]
}
```

This ensures:
- Users can only encrypt/decrypt with their own key
- The service account cannot encrypt/decrypt (only create resources)
- Admins cannot access user keys without the user's password

## Migration: Local to Vault

If you're running with local encryption and want to migrate to Vault:

### 1. Configure Vault (Keep Local Key)

Add Vault configuration while keeping `ENCRYPTION_KEY`:

```bash
ENCRYPTION_KEY=<existing-key>        # Keep this!
VAULT_ENABLED=true
VAULT_ADDR=https://vault.example.com
VAULT_TOKEN=<service-token>
```

### 2. Run Migration Tool

```bash
# Dry run first
docker run --rm \
  -e ENCRYPTION_KEY=<existing-key> \
  -e VAULT_ENABLED=true \
  -e VAULT_ADDR=https://vault.example.com \
  -e VAULT_TOKEN=<service-token> \
  -e DATABASE_URL=<your-db-url> \
  registry.aegis-hq.xyz/coldforge/cloistr-signer:latest \
  /app/migrate --dry-run --verbose

# Run actual migration
docker run --rm \
  -e ... \
  registry.aegis-hq.xyz/coldforge/cloistr-signer:latest \
  /app/migrate --verbose
```

### 3. User Password Reset

After migration, users need to set their Vault password. This happens automatically on next login if using the same password, or users can reset via the web UI.

### 4. Remove Local Key (Optional)

Once all keys show `encryption_method=vault` in the database, you can remove `ENCRYPTION_KEY`. The signer will use Vault exclusively.

## Configuration Reference

### Required

| Variable | Description |
|----------|-------------|
| `RELAYS` | Comma-separated relay WebSocket URLs |

### Storage

| Variable | Default | Description |
|----------|---------|-------------|
| `STORAGE_TYPE` | `memory` | `memory`, `sqlite`, or `postgres` |
| `DATABASE_URL` | - | Connection string for sqlite/postgres |
| `ENCRYPTION_KEY` | - | 64-char hex key for local encryption |

### Vault

| Variable | Default | Description |
|----------|---------|-------------|
| `VAULT_ENABLED` | `false` | Enable Vault integration |
| `VAULT_ADDR` | - | Vault server URL |
| `VAULT_TOKEN` | - | Service account token |
| `VAULT_MOUNT_PATH` | `transit` | Transit secrets engine mount |

### Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_SECRET` | - | Secret for signing JWTs (required for web UI) |
| `JWT_EXPIRY` | `24` | JWT expiry in hours |
| `SESSION_INACTIVITY_MINUTES` | `1440` | Session timeout after inactivity |
| `MFA_ISSUER` | `Cloistr` | TOTP issuer name |
| `MAX_FAILED_LOGINS` | `5` | Failed attempts before lockout |
| `LOCKOUT_MINUTES` | `15` | Lockout duration |

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_ADDRESS` | `:7777` | HTTP listen address |
| `ADMIN_PUBKEYS` | - | Comma-separated admin npubs/hex pubkeys |

### Relay Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `RELAY_AUTH_KEY` | - | Private key (hex) for NIP-42 relay auth |
| `RELAY_PUBLIC_MAPPINGS` | - | Internal=public URL mappings for bunker URIs |
| `MIN_POW_DIFFICULTY` | `0` | Minimum PoW for publishing (0=disabled) |

### Discovery (Optional)

| Variable | Default | Description |
|----------|---------|-------------|
| `DISCOVERY_URL` | - | Discovery service URL (empty=disabled) |
| `DISCOVERY_TIMEOUT` | `5` | Query timeout in seconds |
| `DISCOVERY_MAX_RELAYS` | `3` | Max relays from discovery |

## Docker Compose Example

```yaml
version: '3.8'

services:
  signer:
    image: registry.aegis-hq.xyz/coldforge/cloistr-signer:latest
    ports:
      - "7777:7777"
    environment:
      STORAGE_TYPE: postgres
      DATABASE_URL: postgres://signer:${DB_PASSWORD}@db:5432/signer?sslmode=disable
      ENCRYPTION_KEY: ${ENCRYPTION_KEY}
      JWT_SECRET: ${JWT_SECRET}
      RELAYS: wss://relay.damus.io,wss://nos.lol,wss://relay.nostr.band
    depends_on:
      - db

  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: signer
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      POSTGRES_DB: signer
    volumes:
      - pgdata:/var/lib/postgresql/data

volumes:
  pgdata:
```

## Docker Compose with Vault

```yaml
version: '3.8'

services:
  signer:
    image: registry.aegis-hq.xyz/coldforge/cloistr-signer:latest
    ports:
      - "7777:7777"
    environment:
      STORAGE_TYPE: postgres
      DATABASE_URL: postgres://signer:${DB_PASSWORD}@db:5432/signer?sslmode=disable
      VAULT_ENABLED: "true"
      VAULT_ADDR: http://vault:8200
      VAULT_TOKEN: ${VAULT_SERVICE_TOKEN}
      JWT_SECRET: ${JWT_SECRET}
      RELAYS: wss://relay.damus.io,wss://nos.lol
    depends_on:
      - db
      - vault

  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: signer
      POSTGRES_PASSWORD: ${DB_PASSWORD}
      POSTGRES_DB: signer
    volumes:
      - pgdata:/var/lib/postgresql/data

  vault:
    image: hashicorp/vault:1.15
    cap_add:
      - IPC_LOCK
    environment:
      VAULT_DEV_ROOT_TOKEN_ID: ${VAULT_ROOT_TOKEN}
      VAULT_DEV_LISTEN_ADDRESS: 0.0.0.0:8200
    ports:
      - "8200:8200"
    volumes:
      - vault-data:/vault/data

volumes:
  pgdata:
  vault-data:
```

**Note:** The Vault dev server shown above is for testing only. For production, use a properly configured Vault cluster with TLS and persistent storage.

## Health Checks

The signer exposes health endpoints:

- `GET /health` - Overall health
- `GET /health/live` - Liveness probe (always 200 if running)
- `GET /health/ready` - Readiness probe (checks DB and relay connections)

## Metrics

Prometheus metrics are available at `GET /metrics`.

## Backup and Recovery

### SQLite

```bash
# Backup
cp /data/signer.db /backup/signer-$(date +%Y%m%d).db

# Restore
cp /backup/signer-20240428.db /data/signer.db
```

### PostgreSQL

```bash
# Backup
pg_dump -h host -U user signer > signer-$(date +%Y%m%d).sql

# Restore
psql -h host -U user signer < signer-20240428.sql
```

### Encryption Key

**Critical:** Back up your `ENCRYPTION_KEY` securely. Without it, all encrypted keys are unrecoverable.

For Vault deployments, ensure your Vault cluster is properly backed up according to HashiCorp's guidelines.

## Troubleshooting

### "permission denied" from Vault

The service account token doesn't have the required policy. Re-apply the `cloistr-signer-service` policy and create a new token.

### Keys showing as "vault" but decryption fails

The user's Vault token may have expired. User needs to log in again to get a fresh token.

### Relay connection failures

Check that `RELAYS` contains valid WebSocket URLs and that your network allows outbound WebSocket connections.

### NIP-42 auth failures

Set `RELAY_AUTH_KEY` to a valid hex private key for authenticating to relays that require NIP-42.
