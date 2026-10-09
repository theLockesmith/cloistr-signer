// Package keyloc records which signer replica holds which unlocked key, so a
// replica that receives a request for a key it does not hold can forward it to
// the one that does.
//
// Every key is user-held: it is unlocked in the memory of the replica that ran
// that user's login and nowhere else. Dragonfly carries ONLY the location
// record (key pubkey -> replica forward address, short TTL, refreshed while the
// key is held). Never key material, never a request body, never a signing
// request. Anyone holding the Dragonfly password can write these records, so
// a record is treated as a routing hint only: the forward it causes is sealed
// with a secret Dragonfly never sees (see internal/api/forward.go), and Lookup
// only ever returns a private IP:port.
package keyloc

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	keyPrefix     = "signer:keyloc:"
	recordTTL     = 45 * time.Second
	refreshEvery  = 15 * time.Second
	opTimeout     = 2 * time.Second
	connectTimout = 5 * time.Second
)

// forgetScript deletes the record only if this replica wrote it, so a replica
// evicting a key cannot erase another replica's claim to it.
var forgetScript = redis.NewScript(`
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0`)

// Registry publishes and looks up key locations. A nil *Registry is a valid,
// inert registry: Publish/Forget do nothing and Lookup finds nothing.
type Registry struct {
	rdb  *redis.Client
	self string // this replica's forward address, "ip:port"
}

// New wraps an existing client. self is this replica's forward address.
func New(rdb *redis.Client, self string) *Registry {
	return &Registry{rdb: rdb, self: self}
}

// NewFromURL connects to Dragonfly at url (CACHE_URL). An empty url returns a
// nil registry, which disables cross-replica forwarding.
func NewFromURL(url, self string) (*Registry, error) {
	if url == "" {
		return nil, nil
	}
	opts, err := redis.ParseURL(url)
	if err != nil {
		return nil, fmt.Errorf("invalid CACHE_URL: %w", err)
	}
	rdb := redis.NewClient(opts)
	ctx, cancel := context.WithTimeout(context.Background(), connectTimout)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("failed to connect to Dragonfly at %s: %w", opts.Addr, err)
	}
	return New(rdb, self), nil
}

// Self is this replica's forward address.
func (r *Registry) Self() string {
	if r == nil {
		return ""
	}
	return r.self
}

// Publish records that this replica holds the given keys.
func (r *Registry) Publish(ctx context.Context, pubkeys ...string) error {
	if r == nil || len(pubkeys) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	pipe := r.rdb.Pipeline()
	for _, pk := range pubkeys {
		pipe.Set(ctx, keyPrefix+pk, r.self, recordTTL)
	}
	_, err := pipe.Exec(ctx)
	return err
}

// Forget removes this replica's record for pubkey (another replica's record
// for the same key is left alone).
func (r *Registry) Forget(ctx context.Context, pubkey string) error {
	if r == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	return forgetScript.Run(ctx, r.rdb, []string{keyPrefix + pubkey}, r.self).Err()
}

// ForgetAll removes this replica's records for every given key (other
// replicas' records are left alone). Called on graceful shutdown, so a request
// arriving after this pod is gone does not try to forward to it.
func (r *Registry) ForgetAll(ctx context.Context, pubkeys ...string) error {
	if r == nil || len(pubkeys) == 0 {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	pipe := r.rdb.Pipeline()
	for _, pk := range pubkeys {
		// Eval, not Run: Run sends EVALSHA, and a pipeline cannot fall back to
		// EVAL when the server has not seen the script (NOSCRIPT).
		forgetScript.Eval(ctx, pipe, []string{keyPrefix + pk}, r.self)
	}
	_, err := pipe.Exec(ctx)
	return err
}

// Lookup returns the forward address of another replica that holds pubkey.
// It returns false when no replica is recorded, when the record names this
// replica, or when the record is not a private IP:port (a planted record must
// not be able to aim the signer at an arbitrary host).
func (r *Registry) Lookup(ctx context.Context, pubkey string) (string, bool) {
	if r == nil {
		return "", false
	}
	ctx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	addr, err := r.rdb.Get(ctx, keyPrefix+pubkey).Result()
	if err != nil || addr == r.self || !isPodAddr(addr) {
		return "", false
	}
	return addr, true
}

// Run refreshes this replica's records every refreshEvery until ctx is done.
// loaded returns the pubkeys this replica currently holds.
func (r *Registry) Run(ctx context.Context, loaded func() []string) {
	if r == nil {
		return
	}
	t := time.NewTicker(refreshEvery)
	defer t.Stop()
	for {
		if err := r.Publish(ctx, loaded()...); err != nil {
			slog.Warn("key location refresh failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// isPodAddr accepts only "private-ip:port": the form a pod address takes.
func isPodAddr(addr string) bool {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsPrivate()
}

// SelfAddr picks this replica's forward address: podIP if set (downward API),
// otherwise the first private IPv4 on the host, joined with port.
func SelfAddr(podIP, port string) (string, error) {
	if podIP != "" {
		return net.JoinHostPort(podIP, port), nil
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && n.IP.IsPrivate() {
			return net.JoinHostPort(n.IP.String(), port), nil
		}
	}
	return "", fmt.Errorf("no private IPv4 address found; set POD_IP")
}
