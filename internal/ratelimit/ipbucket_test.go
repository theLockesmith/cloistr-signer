package ratelimit

import (
	"context"
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

// Every replica built from the same shared secret maps an address to the same
// bucket, so one IP is one budget across pods.
func TestSharedIPHasher_SameKeyOnEveryReplica(t *testing.T) {
	base := []byte("0123456789abcdef0123456789abcdef")
	clk := &fakeClock{t: time.Date(2026, 10, 10, 12, 30, 0, 0, time.UTC)}
	a := NewSharedIPHasher(base, time.Hour, clk.now)
	b := NewSharedIPHasher(base, time.Hour, clk.now)
	if a.Key("198.51.100.7") != b.Key("198.51.100.7") {
		t.Fatal("two replicas with the same secret disagree on the bucket key")
	}
	other := NewSharedIPHasher([]byte("ffffffffffffffffffffffffffffffff"), time.Hour, clk.now)
	if other.Key("198.51.100.7") == a.Key("198.51.100.7") {
		t.Fatal("a different secret produced the same key")
	}
	if a.Key("198.51.100.7") == a.Key("198.51.100.8") {
		t.Fatal("different addresses share a key")
	}
}

// Keys rotate by epoch (unlinkable across epochs), and the previous epoch's
// key stays available so a budget is not reset at the boundary.
func TestSharedIPHasher_RotatesWithPrevious(t *testing.T) {
	base := []byte("0123456789abcdef0123456789abcdef")
	clk := &fakeClock{t: time.Date(2026, 10, 10, 12, 59, 0, 0, time.UTC)}
	h := NewSharedIPHasher(base, time.Hour, clk.now)
	before, _ := h.Keys("198.51.100.7")
	clk.t = clk.t.Add(2 * time.Minute)
	cur, prev := h.Keys("198.51.100.7")
	if cur == before {
		t.Fatal("key did not rotate across the epoch boundary")
	}
	if prev != before {
		t.Fatal("previous-epoch key is not the one used before the boundary")
	}
}

// Crossing an epoch boundary mid-window must not hand out a fresh budget: the
// previous epoch's count still counts until it expires naturally.
func TestAllowIP_NoFreshBudgetAtEpochBoundary(t *testing.T) {
	ctx := context.Background()
	l := NewMemory()
	base := []byte("0123456789abcdef0123456789abcdef")
	clk := &fakeClock{t: time.Date(2026, 10, 10, 12, 58, 0, 0, time.UTC)}
	h := NewSharedIPHasher(base, time.Hour, clk.now)
	for i := 0; i < 3; i++ {
		if ok, _, _ := AllowIP(ctx, l, h, "auth:ip:", "198.51.100.7", 3, 15*time.Minute); !ok {
			t.Fatalf("attempt %d refused within budget", i+1)
		}
	}
	clk.t = clk.t.Add(3 * time.Minute) // next epoch, same 15-minute window
	if ok, _, _ := AllowIP(ctx, l, h, "auth:ip:", "198.51.100.7", 3, 15*time.Minute); ok {
		t.Fatal("epoch rotation reset the budget mid-window")
	}
}
