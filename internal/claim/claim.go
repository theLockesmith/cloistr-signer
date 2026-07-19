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

	// doneValue marks a request as fully handled. It replaces the owner's lease
	// value so a watching replica can distinguish "completed" from "owner died".
	doneValue = "done"

	// Lease/watch defaults for Coordinate. The lease is deliberately SHORT and
	// heartbeated: that is what separates "owner crashed" (heartbeat stops, lease
	// expires) from "owner is legitimately slow" (heartbeat keeps renewing). A
	// long un-heartbeated TTL cannot tell those apart and would either fail over
	// too slowly or double-process a slow owner.
	defaultLeaseTTL     = 8 * time.Second
	defaultHeartbeatIvl = defaultLeaseTTL / 3
	defaultWatchPoll    = 1 * time.Second
	// Budget stays under the NIP-46 client timeout (30s) so a takeover still
	// produces a response the client is waiting for.
	defaultWatchBudget = 25 * time.Second
)

// CAS scripts: only the current owner may renew or mark done, so a replica that
// already lost its lease to a takeover cannot clobber the new owner's state.
var (
	renewScript = redis.NewScript(`
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('PEXPIRE', KEYS[1], ARGV[2])
end
return 0`)

	doneScript = redis.NewScript(`
if redis.call('GET', KEYS[1]) == ARGV[1] then
  redis.call('SET', KEYS[1], ARGV[2], 'PX', ARGV[3])
  return 1
end
return 0`)
)

// Claimer coordinates request ownership across signer replicas via Dragonfly.
//
// A nil *Claimer is valid and always grants the claim — the correct behavior
// when no CACHE_URL is configured or only one replica runs. Every Redis error
// also grants the claim (fail-open): a duplicate response is benign and the
// client de-dupes it, whereas a dropped response makes the client time out.
type Claimer struct {
	rdb   *redis.Client
	ttl   time.Duration // how long a completed request stays marked done (dedup window)
	podID string

	// Lease/watch timings; overridable in tests so they need not sleep for real.
	leaseTTL     time.Duration
	heartbeatIvl time.Duration
	watchPoll    time.Duration
	watchBudget  time.Duration
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
	return &Claimer{
		rdb: rdb, ttl: ttl, podID: pod,
		leaseTTL:     defaultLeaseTTL,
		heartbeatIvl: defaultHeartbeatIvl,
		watchPoll:    defaultWatchPoll,
		watchBudget:  defaultWatchBudget,
	}, nil
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

// Coordinate runs process exactly once across replicas for eventID, with
// failover if the owning replica dies mid-request.
//
//   - Winner: takes a short lease, starts a heartbeat, runs process INLINE (in
//     the caller's goroutine), then marks the request done.
//   - Loser: returns IMMEDIATELY and watches in the background. The signer
//     dispatches relay events synchronously on the subscription read loop, so
//     blocking here would stall every subsequent event on that relay.
//     If the owner completes, the watcher exits. If the owner's lease expires
//     without a done marker (it crashed), the watcher takes over and runs
//     process itself.
//   - Fail-open: a nil Claimer or any Redis error runs process inline. A
//     duplicate response is benign (clients de-dupe by request id); a dropped
//     one makes the client time out.
//
// Known race: if the owner is alive but partitioned from Dragonfly, its
// heartbeat fails, the lease expires and a watcher may take over while the
// owner also finishes — a duplicate response. That is the benign direction, and
// only during a Redis outage.
func (c *Claimer) Coordinate(ctx context.Context, eventID string, process func()) {
	if c == nil || c.rdb == nil {
		process()
		return
	}
	won, err := c.tryClaim(ctx, eventID)
	if err != nil {
		slog.Warn("request claim failed; processing anyway (fail-open)", "event_id", eventID, "error", err)
		process()
		return
	}
	if won {
		c.runOwned(eventID, process)
		return
	}
	// Another replica owns it. Never block the caller.
	go c.watchAndTakeOver(eventID, process)
}

// tryClaim attempts to take the lease for eventID.
func (c *Claimer) tryClaim(ctx context.Context, eventID string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, claimOpTimeout)
	defer cancel()
	return c.rdb.SetNX(ctx, keyPrefix+eventID, c.podID, c.leaseTTL).Result()
}

// runOwned heartbeats the lease for as long as process runs, then marks done.
func (c *Claimer) runOwned(eventID string, process func()) {
	stop := make(chan struct{})
	go c.heartbeat(eventID, stop)
	defer func() {
		close(stop)
		c.markDone(eventID)
	}()
	process()
}

// heartbeat renews the lease while we still own it, so a slow-but-alive owner
// is never mistaken for a dead one.
func (c *Claimer) heartbeat(eventID string, stop <-chan struct{}) {
	t := time.NewTicker(c.heartbeatIvl)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), claimOpTimeout)
			err := renewScript.Run(ctx, c.rdb, []string{keyPrefix + eventID},
				c.podID, c.leaseTTL.Milliseconds()).Err()
			cancel()
			if err != nil && err != redis.Nil {
				slog.Debug("claim heartbeat failed", "event_id", eventID, "error", err)
			}
		}
	}
}

// markDone replaces our lease with the done marker (CAS on ownership) so a
// watcher stops watching instead of taking over a completed request.
func (c *Claimer) markDone(eventID string) {
	ctx, cancel := context.WithTimeout(context.Background(), claimOpTimeout)
	defer cancel()
	if err := doneScript.Run(ctx, c.rdb, []string{keyPrefix + eventID},
		c.podID, doneValue, c.ttl.Milliseconds()).Err(); err != nil && err != redis.Nil {
		slog.Debug("marking request done failed", "event_id", eventID, "error", err)
	}
}

// watchAndTakeOver polls the claim until the owner finishes, the owner dies (in
// which case we take over), or the budget runs out.
func (c *Claimer) watchAndTakeOver(eventID string, process func()) {
	key := keyPrefix + eventID
	deadline := time.Now().Add(c.watchBudget)
	for time.Now().Before(deadline) {
		time.Sleep(c.watchPoll)

		ctx, cancel := context.WithTimeout(context.Background(), claimOpTimeout)
		val, err := c.rdb.Get(ctx, key).Result()
		cancel()

		switch {
		case err == redis.Nil:
			// Lease expired with no done marker: the owner died mid-request.
			ctx2, cancel2 := context.WithTimeout(context.Background(), claimOpTimeout)
			won, terr := c.tryClaim(ctx2, eventID)
			cancel2()
			if terr != nil {
				slog.Warn("takeover claim failed", "event_id", eventID, "error", terr)
				return
			}
			if won {
				slog.Info("taking over NIP-46 request abandoned by another replica", "event_id", eventID, "pod", c.podID)
				c.runOwned(eventID, process)
				return
			}
			// A different replica won the takeover; keep watching it.
		case err != nil:
			slog.Debug("claim watch failed; stopping watch", "event_id", eventID, "error", err)
			return
		case val == doneValue:
			return // owner completed it
		}
		// else: still held by a live owner — keep watching.
	}
	slog.Warn("claim watch budget exhausted; request may be unanswered", "event_id", eventID)
}

// Close releases the Dragonfly connection. Safe to call on a nil Claimer.
func (c *Claimer) Close() error {
	if c == nil || c.rdb == nil {
		return nil
	}
	return c.rdb.Close()
}
