package ratelimit

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

// --- NewMemory window behaviour ---

func TestMemory_AllowsUpToLimit(t *testing.T) {
	lim := NewMemory()
	ctx := context.Background()
	const limit = 3
	const window = time.Minute

	for i := 1; i <= limit; i++ {
		ok, err := lim.Allow(ctx, "key", limit, window)
		if err != nil {
			t.Fatalf("request %d: unexpected error: %v", i, err)
		}
		if !ok {
			t.Fatalf("request %d of %d: should be allowed but was blocked", i, limit)
		}
	}
}

func TestMemory_BlocksPastLimit(t *testing.T) {
	lim := NewMemory()
	ctx := context.Background()
	const limit = 2
	const window = time.Minute

	for i := 0; i < limit; i++ {
		lim.Allow(ctx, "key", limit, window) //nolint:errcheck
	}

	ok, err := lim.Allow(ctx, "key", limit, window)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("request past the limit should be blocked but was allowed")
	}
}

func TestMemory_ResetsAfterWindow(t *testing.T) {
	lim := NewMemory()
	ctx := context.Background()
	const limit = 1
	const window = 20 * time.Millisecond

	ok, _ := lim.Allow(ctx, "key", limit, window)
	if !ok {
		t.Fatal("first request should be allowed")
	}
	blocked, _ := lim.Allow(ctx, "key", limit, window)
	if blocked {
		t.Fatal("second request within window should be blocked")
	}

	time.Sleep(window + 5*time.Millisecond)

	ok, err := lim.Allow(ctx, "key", limit, window)
	if err != nil {
		t.Fatalf("post-window: unexpected error: %v", err)
	}
	if !ok {
		t.Error("first request after window reset should be allowed")
	}
}

func TestMemory_IndependentKeys(t *testing.T) {
	lim := NewMemory()
	ctx := context.Background()
	const limit = 1
	const window = time.Minute

	ok1, _ := lim.Allow(ctx, "alice", limit, window)
	ok2, _ := lim.Allow(ctx, "bob", limit, window)
	if !ok1 || !ok2 {
		t.Error("independent keys should not share quota")
	}
}

// --- HashKey determinism ---

func TestHashKey_Deterministic(t *testing.T) {
	a := HashKey("alice")
	b := HashKey("alice")
	if a != b {
		t.Errorf("HashKey is non-deterministic: %q != %q", a, b)
	}
}

func TestHashKey_DifferentInputsDifferentOutputs(t *testing.T) {
	a := HashKey("alice")
	b := HashKey("bob")
	if a == b {
		t.Errorf("HashKey collision: different inputs produced the same key %q", a)
	}
}

func TestHashKey_NonEmpty(t *testing.T) {
	if got := HashKey("x"); got == "" {
		t.Error("HashKey returned empty string")
	}
}

// --- IPHasher ---

func TestIPHasher_StableWithinRotationPeriod(t *testing.T) {
	h, err := NewIPHasher(time.Hour)
	if err != nil {
		t.Fatalf("NewIPHasher: %v", err)
	}
	k1 := h.Key("192.0.2.1")
	k2 := h.Key("192.0.2.1")
	if k1 != k2 {
		t.Errorf("key not stable within period: %q != %q", k1, k2)
	}
}

func TestIPHasher_DifferentIPsDifferentKeys(t *testing.T) {
	h, err := NewIPHasher(time.Hour)
	if err != nil {
		t.Fatalf("NewIPHasher: %v", err)
	}
	k1 := h.Key("192.0.2.1")
	k2 := h.Key("192.0.2.2")
	if k1 == k2 {
		t.Errorf("different IPs produced the same key: %q", k1)
	}
}

func TestIPHasher_KeyChangesAfterRotation(t *testing.T) {
	period := 30 * time.Millisecond
	h, err := NewIPHasher(period)
	if err != nil {
		t.Fatalf("NewIPHasher: %v", err)
	}
	before := h.Key("192.0.2.1")

	// Wait past the rotation period, then trigger a rotation by calling Key again.
	time.Sleep(period + 5*time.Millisecond)

	after := h.Key("192.0.2.1")
	if before == after {
		t.Error("key did not change after rotation period elapsed")
	}
}

// Release hands back one reserved unit, never below zero and never creating
// a counter that outlives its window.
func TestMemoryRelease(t *testing.T) {
	ctx := context.Background()
	l := NewMemory()
	for i := 0; i < 2; i++ {
		_, _ = l.Allow(ctx, "k", 2, time.Minute)
	}
	if ok, _ := l.Allow(ctx, "k", 2, time.Minute); ok {
		t.Fatal("third Allow within limit 2 should be refused")
	}
	_ = l.Release(ctx, "k")
	_ = l.Release(ctx, "k")
	if ok, _ := l.Allow(ctx, "k", 2, time.Minute); !ok {
		t.Fatal("after releasing, an attempt should be allowed again")
	}
	_ = l.Release(ctx, "missing")
	if ok, _ := l.Allow(ctx, "missing", 1, time.Minute); !ok {
		t.Fatal("releasing a missing key must not leave a negative or blocking counter")
	}
	if ok, _ := l.Allow(ctx, "missing", 1, time.Minute); ok {
		t.Fatal("releasing a missing key must not grant extra allowance")
	}
}

func TestRedisRelease(t *testing.T) {
	mr := miniredis.RunT(t)
	l, err := NewRedis("redis://"+mr.Addr(), "t:")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, _ = l.Allow(ctx, "k", 1, time.Minute)
	if ok, _ := l.Allow(ctx, "k", 1, time.Minute); ok {
		t.Fatal("second Allow within limit 1 should be refused")
	}
	_ = l.Release(ctx, "k")
	_ = l.Release(ctx, "k")
	if ok, _ := l.Allow(ctx, "k", 1, time.Minute); !ok {
		t.Fatal("after releasing, an attempt should be allowed again")
	}
	if err := l.Release(ctx, "gone"); err != nil {
		t.Fatal(err)
	}
	if mr.Exists("t:gone") {
		t.Fatal("Release created a counter for a key that did not exist (it would have no TTL)")
	}
}
