// Package ratelimit provides fixed-window counters for gating unauthenticated
// endpoints, backed by Dragonfly/Redis when available and by process memory
// otherwise.
//
// The shared backend matters: the signer runs multiple replicas, and a
// per-process limiter multiplies every ceiling by the replica count. The memory
// fallback exists so a single-replica or self-hosted deployment still gets a
// limit rather than none, and it says so rather than pretending to be
// cluster-wide.
package ratelimit

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// Limiter decides whether an action keyed by some identifier may proceed.
type Limiter interface {
	// Allow consumes one unit against key. It reports whether the caller is
	// within limit for the current window.
	//
	// On backend failure it returns true. A rate limiter that fails closed turns
	// a cache blip into an outage of the endpoint it guards; for account recovery
	// specifically, that would lock out exactly the users the flow exists to
	// rescue. The error is returned alongside so callers can log it.
	Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error)
}

// --- Redis-backed ---

type redisLimiter struct {
	client *redis.Client
	prefix string
}

// NewRedis builds a limiter over Dragonfly/Redis. url is a redis:// URL.
func NewRedis(url, prefix string) (Limiter, error) {
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("parse cache url: %w", err)
	}
	return &redisLimiter{client: redis.NewClient(opts), prefix: prefix}, nil
}

// Allow uses INCR plus an EXPIRE applied only on first increment, which is the
// standard fixed-window counter. The window boundary is set by whoever arrives
// first; that is intentional, and the imprecision at the edge is irrelevant next
// to the ceilings involved here.
func (r *redisLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	full := r.prefix + key
	pipe := r.client.TxPipeline()
	incr := pipe.Incr(ctx, full)
	pipe.Expire(ctx, full, window)
	if _, err := pipe.Exec(ctx); err != nil {
		return true, fmt.Errorf("ratelimit backend: %w", err)
	}
	return incr.Val() <= int64(limit), nil
}

// --- memory-backed ---

type memoryLimiter struct {
	mu      sync.Mutex
	windows map[string]*memWindow
}

type memWindow struct {
	count     int
	expiresAt time.Time
}

// NewMemory builds a process-local limiter. Correct for one replica; with
// several, each holds its own counters and the effective ceiling is multiplied.
func NewMemory() Limiter {
	m := &memoryLimiter{windows: make(map[string]*memWindow)}
	return m
}

func (m *memoryLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	// Opportunistic sweep: without it the map grows once per distinct key
	// forever, which on an unauthenticated endpoint is attacker-controlled.
	if len(m.windows) > 4096 {
		for k, w := range m.windows {
			if now.After(w.expiresAt) {
				delete(m.windows, k)
			}
		}
	}

	w, ok := m.windows[key]
	if !ok || now.After(w.expiresAt) {
		m.windows[key] = &memWindow{count: 1, expiresAt: now.Add(window)}
		return 1 <= limit, nil
	}
	w.count++
	return w.count <= limit, nil
}

// --- key derivation ---

// IPHasher turns a client IP into an opaque, rotating bucket key.
//
// The raw address is never stored, logged, or persisted -- only an HMAC under a
// secret that lives in memory and rotates, so buckets are unlinkable across
// rotations and the key cannot be reversed without the live secret. A plain hash
// would not do: IPv4 is 2^32, small enough to invert by brute force in seconds.
//
// This observes the address transiently, which every network service does; the
// privacy commitment is about retention, not about being unable to see the
// packet you are answering.
type IPHasher struct {
	mu       sync.RWMutex
	secret   []byte
	rotateAt time.Time
	period   time.Duration
}

// NewIPHasher creates a hasher rotating its secret every period.
func NewIPHasher(period time.Duration) (*IPHasher, error) {
	if period <= 0 {
		period = time.Hour
	}
	h := &IPHasher{period: period}
	if err := h.rotate(); err != nil {
		return nil, err
	}
	return h, nil
}

func (h *IPHasher) rotate() error {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return fmt.Errorf("generate rotation secret: %w", err)
	}
	h.secret = secret
	h.rotateAt = time.Now().Add(h.period)
	return nil
}

// Key returns the current bucket key for an address, rotating the secret if due.
func (h *IPHasher) Key(ip string) string {
	h.mu.RLock()
	if time.Now().Before(h.rotateAt) {
		mac := hmac.New(sha256.New, h.secret)
		mac.Write([]byte(ip))
		out := hex.EncodeToString(mac.Sum(nil)[:16])
		h.mu.RUnlock()
		return out
	}
	h.mu.RUnlock()

	h.mu.Lock()
	if time.Now().After(h.rotateAt) {
		if err := h.rotate(); err != nil {
			// Keep the old secret rather than fall back to something reversible.
			slog.Error("ip hasher rotation failed; retaining previous secret", "error", err)
			h.rotateAt = time.Now().Add(h.period)
		}
	}
	mac := hmac.New(sha256.New, h.secret)
	mac.Write([]byte(ip))
	out := hex.EncodeToString(mac.Sum(nil)[:16])
	h.mu.Unlock()
	return out
}

// HashKey derives an opaque bucket key from a non-secret identifier such as a
// username. Hashed rather than used raw so the value does not become a
// user-controlled Redis key, and so operators reading the keyspace do not see a
// list of accounts that attempted recovery.
func HashKey(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:16])
}
