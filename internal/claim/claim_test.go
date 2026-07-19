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

// --- Coordinate: watch-and-take-over ---

// fastClaimer shrinks the lease/watch timings so tests need not sleep for real.
func fastClaimer(t *testing.T, addr string) *Claimer {
	t.Helper()
	c, err := New("redis://"+addr, 2*time.Second)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	c.leaseTTL = 300 * time.Millisecond
	c.heartbeatIvl = 80 * time.Millisecond
	c.watchPoll = 40 * time.Millisecond
	c.watchBudget = 4 * time.Second
	return c
}

// The uncontended owner runs process inline and marks the request done.
func TestCoordinate_OwnerRunsInlineAndMarksDone(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()
	c := fastClaimer(t, mr.Addr())

	ran := false
	c.Coordinate(context.Background(), "evt-1", func() { ran = true })
	if !ran {
		t.Fatal("owner must run process inline (synchronously) before Coordinate returns")
	}
	if got, _ := mr.Get(keyPrefix + "evt-1"); got != doneValue {
		t.Errorf("expected done marker after completion, got %q", got)
	}
}

// A replica that loses to an owner which then COMPLETES must not run process.
func TestCoordinate_LoserSkipsWhenOwnerCompletes(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()
	a := fastClaimer(t, mr.Addr())
	b := fastClaimer(t, mr.Addr())
	b.podID = "pod-b"

	a.Coordinate(context.Background(), "evt-2", func() {}) // owner completes -> done marker
	loserRan := make(chan struct{}, 1)
	b.Coordinate(context.Background(), "evt-2", func() { loserRan <- struct{}{} })

	select {
	case <-loserRan:
		t.Fatal("loser must not process a request the owner already completed")
	case <-time.After(600 * time.Millisecond):
	}
}

// The core failover: owner claims then dies (no heartbeat, no done marker); the
// watching replica must take over and run process.
func TestCoordinate_TakesOverWhenOwnerDies(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()
	dead := fastClaimer(t, mr.Addr())
	live := fastClaimer(t, mr.Addr())
	live.podID = "pod-live"

	// Simulate a crash: take the lease, never heartbeat, never mark done.
	if won, err := dead.tryClaim(context.Background(), "evt-3"); err != nil || !won {
		t.Fatalf("setup claim failed won=%v err=%v", won, err)
	}

	tookOver := make(chan struct{}, 1)
	live.Coordinate(context.Background(), "evt-3", func() { tookOver <- struct{}{} })

	mr.FastForward(400 * time.Millisecond) // lease expires with no done marker

	select {
	case <-tookOver:
	case <-time.After(3 * time.Second):
		t.Fatal("watcher failed to take over an abandoned request")
	}
}

// Losing must not block the caller: the signer dispatches relay events
// synchronously, so a blocking watch would stall the subscription.
func TestCoordinate_LoserReturnsImmediately(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()
	owner := fastClaimer(t, mr.Addr())
	loser := fastClaimer(t, mr.Addr())
	loser.podID = "pod-loser"

	if won, _ := owner.tryClaim(context.Background(), "evt-4"); !won {
		t.Fatal("setup claim failed")
	}
	start := time.Now()
	loser.Coordinate(context.Background(), "evt-4", func() {})
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Errorf("Coordinate blocked the caller for %v; must return immediately when losing", elapsed)
	}
}

// Only the current owner may mark done — a replica that lost its lease to a
// takeover must not clobber the new owner's state.
func TestMarkDone_OnlyByCurrentOwner(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatal(err)
	}
	defer mr.Close()
	a := fastClaimer(t, mr.Addr())
	b := fastClaimer(t, mr.Addr())
	b.podID = "pod-b"

	if won, _ := b.tryClaim(context.Background(), "evt-5"); !won {
		t.Fatal("setup claim failed")
	}
	a.markDone("evt-5") // a never owned it
	if got, _ := mr.Get(keyPrefix + "evt-5"); got != "pod-b" {
		t.Errorf("non-owner must not overwrite the lease; got %q", got)
	}
}

// Fail-open: a nil Claimer still runs the work.
func TestCoordinate_NilClaimerRunsProcess(t *testing.T) {
	var c *Claimer
	ran := false
	c.Coordinate(context.Background(), "evt-6", func() { ran = true })
	if !ran {
		t.Error("nil claimer must run process (fail-open)")
	}
}
