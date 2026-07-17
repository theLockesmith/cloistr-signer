package nostr

import (
	"context"
	"os"
	"testing"
	"time"

	nostr "github.com/nbd-wtf/go-nostr"
)

// TestPublishToRelay_ReconnectsAfterDeadCachedConnection reproduces the
// nostrconnect login-timeout regression: the client caches a persistent relay
// connection, that connection dies (e.g. relay pod restart), and every
// subsequent PublishToRelay must still succeed by redialing rather than reusing
// the dead socket.
//
// Integration test — requires a reachable relay that exempts kind 24133 from
// auth. Point RELAY_IT_URL at one (e.g. a port-forward of the internal relay:
//
//	kubectl -n cloistr port-forward svc/cloistr-relay 18080:80
//	RELAY_IT_URL=ws://localhost:18080 go test ./internal/nostr -run ReconnectsAfterDead -v
//
// Skips when RELAY_IT_URL is unset so normal `go test ./...` / CI is unaffected.
func TestPublishToRelay_ReconnectsAfterDeadCachedConnection(t *testing.T) {
	url := os.Getenv("RELAY_IT_URL")
	if url == "" {
		t.Skip("set RELAY_IT_URL to run this integration test")
	}

	ctx := context.Background()
	c := NewClient([]string{url})
	if err := c.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}

	sk := nostr.GeneratePrivateKey()
	mkEvent := func() *nostr.Event {
		e := &nostr.Event{
			Kind:      24133,
			CreatedAt: nostr.Timestamp(time.Now().Unix()),
			Tags:      nostr.Tags{},
			Content:   "reconnect-it-test",
			PubKey:    mustPub(t, sk),
		}
		if err := e.Sign(sk); err != nil {
			t.Fatalf("sign: %v", err)
		}
		return e
	}

	// 1. Baseline: publish over the live cached connection.
	if err := c.PublishToRelay(ctx, url, mkEvent()); err != nil {
		t.Fatalf("baseline publish over live cached connection: %v", err)
	}

	// 2. Simulate a relay restart: close the cached connection out from under
	//    the client, exactly the state that caused the outage.
	c.mu.RLock()
	relay := c.relays[url]
	c.mu.RUnlock()
	if relay == nil {
		t.Fatal("expected a cached relay connection after Connect")
	}
	relay.Close()
	for i := 0; i < 200 && relay.IsConnected(); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if relay.IsConnected() {
		t.Fatal("cached connection did not observe the close")
	}

	// 3. The fix: PublishToRelay must detect the dead cached connection, redial,
	//    and succeed. Before the fix this returned "connection closed".
	if err := c.PublishToRelay(ctx, url, mkEvent()); err != nil {
		t.Fatalf("publish after cached connection died (regression): %v", err)
	}
}

func mustPub(t *testing.T, sk string) string {
	t.Helper()
	pk, err := nostr.GetPublicKey(sk)
	if err != nil {
		t.Fatalf("pubkey: %v", err)
	}
	return pk
}
