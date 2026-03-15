# CLAUDE.md - coldforge-signer

**Go-based NIP-46 Remote Signing Service**

**Domain:** signer.cloistr.xyz | **Status:** Production

## Required Reading

| Document | Purpose |
|----------|---------|
| `~/claude/coldforge/cloistr/CLAUDE.md` | Cloistr project rules |
| [docs/reference.md](docs/reference.md) | Full API, config, phases |

## Overview

Kubernetes-native NIP-46 remote signer - identity foundation for all Coldforge services. Written in Go for minimal footprint and fast startup.

## Quick Start

```bash
go build -o coldforge-signer ./cmd/signer     # Build
RELAYS="wss://relay.coldforge.xyz" ./coldforge-signer  # Run
go test ./...                                  # Test
docker build -t coldforge-signer .             # Docker
```

## Architecture

```
cmd/signer/main.go         Entry point
internal/
  config/                   Configuration
  storage/                  Memory + PostgreSQL backends
  nostr/                    Relay client, per-key connections
  signer/                   NIP-46 request handling
  api/                      HTTP management API
  auth/                     JWT, bcrypt, TOTP, backup codes
  admin/                    Admin DM commands
  bunker/                   bunker:// URI handling
  frost/                    FROST threshold signing
  web/                      Web UI
```

## NIP-46 Methods

| Method | Description |
|--------|-------------|
| `connect` | Establish session |
| `ping` | Health check |
| `get_public_key` | Return signer pubkey |
| `get_relays` | List connected relays |
| `sign_event` | Sign a Nostr event |
| `nip04_encrypt/decrypt` | NIP-04 encryption |
| `nip44_encrypt/decrypt` | NIP-44 encryption |

## Core API Endpoints

| Path | Description |
|------|-------------|
| `/health`, `/health/live`, `/health/ready` | Health probes |
| `/api/v1/keys` | Key CRUD |
| `/api/v1/keys/{id}/permissions` | Permission management |
| `/api/v1/requests` | Pending authorization |
| `/api/v1/users/*` | User management (register, login, MFA) |
| `/api/v1/bunker/{id}` | Generate bunker:// URI |
| `/.well-known/nostr.json` | NIP-05 endpoint |

**Full API:** See [docs/reference.md](docs/reference.md)

## Web UI

| Route | Description |
|-------|-------------|
| `/login`, `/register` | Auth |
| `/dashboard` | Admin stats |
| `/keys` | Key management |
| `/requests` | Pending approvals |
| `/settings` | Account settings |

## Key Features

| Feature | Status |
|---------|--------|
| NIP-46 signing (all methods) | Done |
| PostgreSQL + encryption at rest | Done |
| User auth (password + MFA) | Done |
| Admin DM commands | Done |
| bunker:// + nostrconnect:// | Done |
| Signer chaining (proxy keys) | Done |
| Per-key relay connections | Done |
| FROST threshold signing (API) | Done |

## Deployment

```bash
cd ~/Atlas && K8S_AUTH_KUBECONFIG=~/.kube/config ansible-playbook \
  -i inventory/kube.yaml playbooks/kube.yml \
  -e "manifest_names=['coldforge-signer']" -e "kube_state=present"
```

## Related

- Service docs: `~/claude/coldforge/cloistr/services/identity/CLAUDE.md`
- Atlas role: `~/Atlas/roles/kube/coldforge-signer/`
- [NIP-46 spec](https://github.com/nostr-protocol/nips/blob/master/46.md)
