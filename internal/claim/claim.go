// Package claim provides cross-replica exactly-once handling of NIP-46 requests.
//
// Each signer replica loads every key and, via its own per-key relay
// subscription, receives every NIP-46 request addressed to those keys. Without
// coordination all replicas decrypt, sign, and publish a response to the same
// request, so the client receives duplicate responses and logs "Response with
// no matching pending request id" for every replica past the first.
//
// Claimer resolves this with an atomic Dragonfly/Redis SET NX: the first
// replica to claim a request's event ID wins and answers it; the others skip.
package claim

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	keyPrefix      = "nip46:claim:"
	defaultTTL     = 60 * time.Second
	claimOpTimeout = 2 * time.Second
	connectTimeout = 5 * time.Second
)

// Claimer coordinates request ownership across signer replicas via Dragonfly.
//
// A nil *Claimer is valid and always grants the claim — the correct behavior
// when no CACHE_URL is configured or only one replica runs. Every Redis error
// also grants the claim (fail-open): a duplicate response is benign and the
// client de-dupes it, whereas a dropped response makes the client time out.
type Claimer struct {
	rdb   *redis.Client
	ttl   time.Duration
	podID string
}

// New connects to Dragonfly/Redis at url (redis://[:password@]host:port[/db]).
// Returns (nil, nil) when url is empty so the caller transparently degrades to
// no cross-replica coordination. ttl bounds how long a claim is held; it should
// comfortably exceed request processing time and the relay redelivery window
// (default 60s when ttl <= 0).
func New(url string, ttl time.Duration) (*Claimer, error) {
	if url == "" {
		return nil, nil
	}
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("invalid CACHE_URL: %w", err)
	}
	rdb := redis.NewClient(opts)

	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("failed to connect to Dragonfly at %s: %w", opts.Addr, err)
	}

	if ttl <= 0 {
		ttl = defaultTTL
	}
	pod, _ := os.Hostname()
	if pod == "" {
		pod = "unknown"
	}
	slog.Info("request-claim coordination enabled (Dragonfly)", "addr", opts.Addr, "ttl", ttl, "pod", pod)
	return &Claimer{rdb: rdb, ttl: ttl, podID: pod}, nil
}

// Claim atomically claims eventID for this replica. It returns true if this
// replica won the claim and must process the request, or false if another
// replica already owns it and this replica must skip. Fail-open: a nil Claimer
// or any Redis error returns true.
func (c *Claimer) Claim(ctx context.Context, eventID string) bool {
	if c == nil || c.rdb == nil {
		return true
	}
	ctx, cancel := context.WithTimeout(ctx, claimOpTimeout)
	defer cancel()

	// SET key pod NX EX ttl: won == true when the key did not exist (we set it),
	// false when another replica already holds the claim.
	won, err := c.rdb.SetNX(ctx, keyPrefix+eventID, c.podID, c.ttl).Result()
	if err != nil {
		slog.Warn("request claim failed; processing anyway (fail-open)", "event_id", eventID, "error", err)
		return true
	}
	return won
}

// Close releases the Dragonfly connection. Safe to call on a nil Claimer.
func (c *Claimer) Close() error {
	if c == nil || c.rdb == nil {
		return nil
	}
	return c.rdb.Close()
}
