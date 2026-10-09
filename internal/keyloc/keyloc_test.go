package keyloc

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestRegistry(t *testing.T, mr *miniredis.Miniredis, self string) *Registry {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return New(rdb, self)
}

const pk = "cbba4bcfd576a4fbcbba4bcfd576a4fbcbba4bcfd576a4fbcbba4bcfd576a4fb"

func TestPublishLookupAcrossPods(t *testing.T) {
	mr := miniredis.RunT(t)
	a := newTestRegistry(t, mr, "10.128.4.104:7778")
	b := newTestRegistry(t, mr, "10.129.3.250:7778")
	ctx := context.Background()

	if err := a.Publish(ctx, pk); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if addr, ok := b.Lookup(ctx, pk); !ok || addr != "10.128.4.104:7778" {
		t.Fatalf("lookup from B = %q,%v; want A's address", addr, ok)
	}
	// A never forwards to itself.
	if _, ok := a.Lookup(ctx, pk); ok {
		t.Fatal("lookup from A returned A itself")
	}
}

func TestRecordExpires(t *testing.T) {
	mr := miniredis.RunT(t)
	a := newTestRegistry(t, mr, "10.128.4.104:7778")
	b := newTestRegistry(t, mr, "10.129.3.250:7778")
	ctx := context.Background()
	_ = a.Publish(ctx, pk)
	mr.FastForward(recordTTL + time.Second)
	if _, ok := b.Lookup(ctx, pk); ok {
		t.Fatal("record outlived its TTL; a dead pod would keep attracting forwards")
	}
}

func TestForgetOnlyOwnRecord(t *testing.T) {
	mr := miniredis.RunT(t)
	a := newTestRegistry(t, mr, "10.128.4.104:7778")
	b := newTestRegistry(t, mr, "10.129.3.250:7778")
	ctx := context.Background()
	_ = a.Publish(ctx, pk)
	_ = b.Forget(ctx, pk) // B does not own it; must not delete A's record
	if addr, ok := newTestRegistry(t, mr, "10.0.0.9:7778").Lookup(ctx, pk); !ok || addr != "10.128.4.104:7778" {
		t.Fatalf("B's Forget removed A's record: %q,%v", addr, ok)
	}
	_ = a.Forget(ctx, pk)
	if _, ok := b.Lookup(ctx, pk); ok {
		t.Fatal("A's Forget did not remove its own record")
	}
}

// A planted record must not turn the signer into a request cannon aimed at
// arbitrary hosts: only a private IP:port is ever returned.
func TestLookupRejectsNonPodAddresses(t *testing.T) {
	mr := miniredis.RunT(t)
	b := newTestRegistry(t, mr, "10.129.3.250:7778")
	ctx := context.Background()
	for _, bad := range []string{"evil.example.com:7778", "8.8.8.8:7778", "10.0.0.1", "not an address", "127.0.0.1:7778"} {
		mr.Set(keyPrefix+pk, bad)
		if addr, ok := b.Lookup(ctx, pk); ok {
			t.Errorf("Lookup accepted planted value %q -> %q", bad, addr)
		}
	}
}
