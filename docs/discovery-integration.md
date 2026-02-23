# Discovery Service Integration for NIP-46 Relay Selection

## Overview

This design adds optional discovery service integration to improve NIP-46 relay selection. The signer can query a discovery service to find optimal relays for communication, while remaining fully functional without it.

## Design Principles

1. **Optional by default** - Works without discovery service configured
2. **Graceful degradation** - Falls back to configured relays if discovery fails
3. **Open standard** - Uses NIP-65 relay lists, not proprietary APIs
4. **User freedom** - Users can override with their own relay preferences
5. **Privacy-preserving** - Discovery queries don't leak signing key info

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Relay Selection Pipeline                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. User-specified relays (per-key config)                      │
│     ↓ (if empty or "auto")                                      │
│  2. Discovery service query (if enabled)                        │
│     ↓ (if unavailable or returns empty)                         │
│  3. Global configured relays (RELAYS env var)                   │
│     ↓ (always included as fallback)                             │
│  4. Merge & deduplicate                                         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## Configuration

### Environment Variables

```bash
# Discovery service URL (optional - disabled if empty)
DISCOVERY_URL=https://discovery.cloistr.xyz

# Discovery timeout in seconds (default: 5)
DISCOVERY_TIMEOUT=5

# Whether to include discovered relays in bunker:// URIs (default: true)
DISCOVERY_INCLUDE_IN_BUNKER=true

# Maximum relays to include from discovery (default: 3)
DISCOVERY_MAX_RELAYS=3

# Fallback relays (always used, required)
RELAYS=wss://relay.cloistr.xyz,wss://relay.damus.io
```

### Per-Key Relay Configuration

Keys can have their own relay preferences stored in the database:

```go
type Key struct {
    // ... existing fields ...

    // Relay configuration for this key
    Relays       []string `json:"relays"`        // User-specified relays
    RelayMode    string   `json:"relay_mode"`    // "manual", "discovery", "auto"
    DiscoveryHint string  `json:"discovery_hint"` // npub to query for relay hints
}
```

**RelayMode options:**
- `manual` - Only use explicitly configured relays
- `discovery` - Query discovery, fall back to global relays
- `auto` (default) - Use key relays if set, else discovery, else global

## Discovery Query Protocol

### Option A: NIP-65 Relay List Query (Recommended)

Query for the user's published relay list (kind:10002):

```go
// Query discovery service for user's relay preferences
// GET /api/v1/relays/{pubkey}
// Returns: { "relays": ["wss://relay1.example", ...], "source": "nip65" }

type DiscoveryRelayResponse struct {
    Relays []string `json:"relays"`
    Source string   `json:"source"` // "nip65", "profile", "fallback"
}
```

This leverages existing NIP-65 data that discovery already indexes.

### Option B: Direct NIP-65 Query (No Discovery Dependency)

Query relays directly for kind:10002 events:

```go
// Fetch NIP-65 relay list directly from Nostr network
func (c *Client) FetchUserRelays(ctx context.Context, pubkey string) ([]string, error) {
    filter := nostr.Filter{
        Authors: []string{pubkey},
        Kinds:   []int{10002}, // NIP-65 relay list
        Limit:   1,
    }
    // Query configured relays for this event
    // Parse relay hints from "r" tags
}
```

### Recommended: Hybrid Approach

```go
func (s *Signer) GetRelaysForKey(ctx context.Context, key *storage.Key) []string {
    var relays []string

    // 1. Start with user-specified relays for this key
    if len(key.Relays) > 0 && key.RelayMode != "discovery" {
        relays = append(relays, key.Relays...)
    }

    // 2. Query discovery if enabled and mode allows
    if s.discoveryEnabled && key.RelayMode != "manual" {
        discovered := s.queryDiscovery(ctx, key.DiscoveryHint)
        relays = append(relays, discovered...)
    }

    // 3. Always include global fallback relays
    relays = append(relays, s.config.Relays...)

    // 4. Deduplicate and limit
    return deduplicateRelays(relays, s.config.MaxRelays)
}
```

## Discovery Service API

The discovery service should expose a simple relay lookup endpoint:

```
GET /api/v1/users/{pubkey}/relays

Response:
{
  "pubkey": "abc123...",
  "relays": [
    {"url": "wss://relay.example.com", "read": true, "write": true},
    {"url": "wss://relay2.example.com", "read": true, "write": false}
  ],
  "source": "nip65",
  "cached_at": "2026-02-23T12:00:00Z"
}
```

For NIP-46, we want relays where the user can both read AND write.

## Implementation Plan

### Phase 1: Discovery Client Package

Create `internal/discovery/discovery.go`:

```go
package discovery

type Client struct {
    baseURL    string
    httpClient *http.Client
    timeout    time.Duration
}

type RelayInfo struct {
    URL   string `json:"url"`
    Read  bool   `json:"read"`
    Write bool   `json:"write"`
}

type RelayResponse struct {
    Pubkey   string      `json:"pubkey"`
    Relays   []RelayInfo `json:"relays"`
    Source   string      `json:"source"`
    CachedAt time.Time   `json:"cached_at"`
}

// GetRelaysForUser queries discovery for a user's relay preferences
func (c *Client) GetRelaysForUser(ctx context.Context, pubkey string) ([]string, error) {
    // Returns write-capable relay URLs
}
```

### Phase 2: Signer Integration

Update `internal/signer/signer.go`:

```go
type Signer struct {
    // ... existing fields ...
    discovery *discovery.Client // nil if disabled
}

// GetRelaysForBunker returns relays to include in bunker:// URI
func (s *Signer) GetRelaysForBunker(ctx context.Context, keyPubkey string) []string {
    // Implementation of relay selection pipeline
}
```

### Phase 3: Bunker URI Generation

Update `internal/api/handler.go` to use dynamic relay selection:

```go
func (h *Handler) handleBunkerConnect(w http.ResponseWriter, r *http.Request) {
    // ... get key ...

    // Get relays using discovery-aware selection
    relays := h.signer.GetRelaysForBunker(r.Context(), key.Pubkey)

    // Build bunker URI with selected relays
    // ...
}
```

### Phase 4: Direct NIP-65 Fallback

Add direct NIP-65 query as fallback when discovery is unavailable:

```go
// FetchNIP65Relays queries the Nostr network directly for relay hints
func (c *Client) FetchNIP65Relays(ctx context.Context, pubkey string) ([]string, error) {
    // Query our connected relays for kind:10002 events
    // Parse and return write-capable relays
}
```

## Web UI Enhancements

### Key Settings Page

Add relay configuration to the key edit modal:

```
Relay Configuration
-------------------
Mode: [Auto ▼]  (Auto | Manual | Discovery)

Manual Relays:
  [wss://relay.example.com    ] [×]
  [+ Add Relay]

Discovery Hint (npub):
  [npub1abc... ] (optional - uses key's pubkey if empty)

Preview: Bunker URI will use these relays:
  • wss://relay.cloistr.xyz (fallback)
  • wss://relay.damus.io (fallback)
  • wss://user-relay.example.com (from NIP-65)
```

## Caching Strategy

Discovery results should be cached to avoid repeated queries:

```go
type RelayCache struct {
    mu      sync.RWMutex
    entries map[string]*cacheEntry
    ttl     time.Duration // default: 5 minutes
}

type cacheEntry struct {
    relays    []string
    fetchedAt time.Time
}
```

## Error Handling

| Scenario | Behavior |
|----------|----------|
| Discovery URL not configured | Skip discovery, use configured relays |
| Discovery timeout | Log warning, use configured relays |
| Discovery returns empty | Use configured relays |
| Discovery returns error | Log warning, use configured relays |
| All relays fail | Use hardcoded fallback (relay.cloistr.xyz) |

## Testing

### Unit Tests

```go
func TestRelaySelection_ManualMode(t *testing.T)
func TestRelaySelection_DiscoveryMode(t *testing.T)
func TestRelaySelection_AutoMode(t *testing.T)
func TestRelaySelection_DiscoveryTimeout(t *testing.T)
func TestRelaySelection_DiscoveryEmpty(t *testing.T)
func TestRelaySelection_Deduplication(t *testing.T)
```

### Integration Tests

```go
func TestBunkerURI_WithDiscovery(t *testing.T)
func TestBunkerURI_WithoutDiscovery(t *testing.T)
func TestNIP46Login_DiscoveredRelays(t *testing.T)
```

## Migration

Existing deployments continue working:
- `DISCOVERY_URL` defaults to empty (disabled)
- Per-key `relay_mode` defaults to "auto"
- "auto" mode falls back to existing behavior when discovery is disabled

## Security Considerations

1. **No key leakage**: Discovery queries use the key's public key, not private key
2. **User privacy**: Discovery hint is optional; defaults to the signing key's pubkey
3. **Relay trust**: All relays (discovered or not) go through the same auth/rate-limit checks
4. **Cache poisoning**: Discovery responses are validated (relay URL format, reasonable count)

## Future Enhancements

1. **Relay health scoring**: Prefer relays with better latency/reliability
2. **Geographic routing**: Use relays closer to the user
3. **Load balancing**: Spread NIP-46 traffic across multiple relays
4. **Relay reputation**: Integrate with WoT for relay trust scoring
