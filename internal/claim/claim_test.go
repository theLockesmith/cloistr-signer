package claim

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func newTestClaimer(t *testing.T) (*Claimer, *miniredis.Miniredis) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	c, err := New("redis://"+mr.Addr(), 60*time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, mr
}

// The core guarantee: for a single event ID, exactly one replica wins.
func TestClaim_ExactlyOneWinner(t *testing.T) {
	c, _ := newTestClaimer(t)
	ctx := context.Background()

	if !c.Claim(ctx, "event-A") {
		t.Fatal("first claim of event-A should win")
	}
	if c.Claim(ctx, "event-A") {
		t.Error("second claim of event-A must lose (already owned)")
	}
	// A different event is independently claimable.
	if !c.Claim(ctx, "event-B") {
		t.Error("first claim of event-B should win")
	}
}

// Two Claimers sharing one Dragonfly model two replicas: only one answers.
func TestClaim_TwoReplicasOneAnswers(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	url := "redis://" + mr.Addr()
	a, _ := New(url, 60*time.Second)
	b, _ := New(url, 60*time.Second)
	defer a.Close()
	defer b.Close()

	wonA := a.Claim(context.Background(), "shared-event")
	wonB := b.Claim(context.Background(), "shared-event")
	if wonA == wonB {
		t.Fatalf("exactly one replica must win, got a=%v b=%v", wonA, wonB)
	}
}

// The claim expires after its TTL so a later request with the same (recycled)
// id is not permanently blocked.
func TestClaim_ExpiresAfterTTL(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	defer mr.Close()
	c, _ := New("redis://"+mr.Addr(), 30*time.Second)
	defer c.Close()
	ctx := context.Background()

	if !c.Claim(ctx, "expiring") {
		t.Fatal("first claim should win")
	}
	mr.FastForward(31 * time.Second)
	if !c.Claim(ctx, "expiring") {
		t.Error("claim should be re-winnable after TTL expiry")
	}
}

// Fail-open: a nil Claimer always grants the claim (no coordination configured).
func TestClaim_NilClaimerFailsOpen(t *testing.T) {
	var c *Claimer
	if !c.Claim(context.Background(), "any") {
		t.Error("nil claimer must grant the claim (fail-open)")
	}
	if err := c.Close(); err != nil {
		t.Errorf("nil Close: %v", err)
	}
}

// Fail-open: when Dragonfly is unreachable, Claim grants rather than drops.
func TestClaim_RedisDownFailsOpen(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	c, _ := New("redis://"+mr.Addr(), 60*time.Second)
	defer c.Close()
	mr.Close() // Dragonfly goes away.

	if !c.Claim(context.Background(), "event-after-outage") {
		t.Error("claim must fail open (grant) when Dragonfly is unreachable")
	}
}

// Empty URL yields a nil Claimer (transparent no-coordination degradation).
func TestNew_EmptyURLReturnsNil(t *testing.T) {
	c, err := New("", 60*time.Second)
	if err != nil {
		t.Fatalf("New(\"\"): %v", err)
	}
	if c != nil {
		t.Error("empty URL should return a nil Claimer")
	}
}
