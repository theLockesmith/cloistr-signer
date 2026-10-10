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

	// Release hands back one unit consumed by Allow, so a budget can count only
	// the attempts that end badly: reserve with Allow up front (atomic, so a
	// burst cannot overshoot), Release when the attempt turns out fine. It
	// never takes a counter below zero and never creates one: a key that has
	// already expired stays gone.
	Release(ctx context.Context, key string) error

	// Count reads a counter without changing it (0 if absent or expired).
	Count(ctx context.Context, key string) (int, error)
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
// allowScript counts an attempt and sets the window's expiry only when the
// counter is created (or somehow has none), so the window is fixed from the
// first attempt. Re-applying the expiry on every call would let a client that
// keeps retrying while blocked, and everyone behind its NAT address, stay
// blocked forever.
var allowScript = redis.NewScript(`
local c = redis.call('INCR', KEYS[1])
if c == 1 or redis.call('PTTL', KEYS[1]) < 0 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return c
`)

func (r *redisLimiter) Allow(ctx context.Context, key string, limit int, window time.Duration) (bool, error) {
	c, err := allowScript.Run(ctx, r.client, []string{r.prefix + key}, window.Milliseconds()).Int64()
	if err != nil {
		return true, fmt.Errorf("ratelimit backend: %w", err)
	}
	return c <= int64(limit), nil
}

func (r *redisLimiter) Count(ctx context.Context, key string) (int, error) {
	n, err := r.client.Get(ctx, r.prefix+key).Int()
	if err == redis.Nil {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("ratelimit backend: %w", err)
	}
	return n, nil
}

// releaseScript decrements only an existing, positive counter, so a release
// after the window expired cannot create a key without a TTL.
var releaseScript = redis.NewScript(`
local v = redis.call('GET', KEYS[1])
if v and tonumber(v) > 0 then
  return redis.call('DECR', KEYS[1])
end
return 0
`)

func (r *redisLimiter) Release(ctx context.Context, key string) error {
	if err := releaseScript.Run(ctx, r.client, []string{r.prefix + key}).Err(); err != nil && err != redis.Nil {
		return fmt.Errorf("ratelimit backend: %w", err)
	}
	return nil
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

func (m *memoryLimiter) Count(ctx context.Context, key string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if w, ok := m.windows[key]; ok && time.Now().Before(w.expiresAt) {
		return w.count, nil
	}
	return 0, nil
}

func (m *memoryLimiter) Release(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if w, ok := m.windows[key]; ok && time.Now().Before(w.expiresAt) && w.count > 0 {
		w.count--
	}
	return nil
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
//
// Two modes. NewSharedIPHasher derives each epoch's secret from a secret every
// replica shares, so one address is one bucket across pods; NewIPHasher keeps
// a random per-process secret (each replica then counts separately) for
// deployments without a shared secret.
type IPHasher struct {
	mu       sync.RWMutex
	secret   []byte
	rotateAt time.Time
	period   time.Duration

	base []byte           // shared mode: per-epoch secrets derive from this
	now  func() time.Time // shared mode clock
}

// NewSharedIPHasher derives the secret for epoch e (= unix time / period) as
// HMAC(base, "cloistr-ip-bucket|e"), so every replica built from the same base
// agrees on an address's key, and keys still rotate every period. base should
// be a replica-shared secret of at least 32 bytes; it never leaves memory.
func NewSharedIPHasher(base []byte, period time.Duration, now func() time.Time) *IPHasher {
	if period <= 0 {
		period = time.Hour
	}
	if now == nil {
		now = time.Now
	}
	return &IPHasher{base: append([]byte(nil), base...), period: period, now: now}
}

func (h *IPHasher) epochKey(epoch int64, ip string) string {
	sec := hmac.New(sha256.New, h.base)
	fmt.Fprintf(sec, "cloistr-ip-bucket|%d", epoch)
	mac := hmac.New(sha256.New, sec.Sum(nil))
	mac.Write([]byte(ip))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

// Keys returns the address's bucket key for the current epoch and, in shared
// mode, for the previous one (empty otherwise), so a caller can keep counting
// the previous epoch's attempts until they expire instead of resetting.
func (h *IPHasher) Keys(ip string) (current, previous string) {
	if h.base == nil {
		return h.Key(ip), ""
	}
	e := h.now().Unix() / int64(h.period.Seconds())
	return h.epochKey(e, ip), h.epochKey(e-1, ip)
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
	if h.base != nil {
		cur, _ := h.Keys(ip)
		return cur
	}
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

// AllowIP reserves one attempt against an address's budget. The previous
// epoch's count still counts, so key rotation never hands out a fresh budget
// mid-window; old-epoch counters simply expire. Returns the reserved key (for
// Release) when allowed; on refusal nothing stays reserved.
func AllowIP(ctx context.Context, lim Limiter, h *IPHasher, prefix, ip string, limit int, window time.Duration) (bool, string, error) {
	cur, prev := h.Keys(ip)
	used := 0
	if prev != "" {
		n, err := lim.Count(ctx, prefix+prev)
		if err != nil {
			return true, "", err // fail open like Allow
		}
		used = n
	}
	if used >= limit {
		return false, "", nil
	}
	key := prefix + cur
	allowed, err := lim.Allow(ctx, key, limit-used, window)
	if !allowed {
		_ = lim.Release(ctx, key)
		return false, "", err
	}
	return true, key, err
}

// HashKey derives an opaque bucket key from a non-secret identifier such as a
// username. Hashed rather than used raw so the value does not become a
// user-controlled Redis key, and so operators reading the keyspace do not see a
// list of accounts that attempted recovery.
func HashKey(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:16])
}
