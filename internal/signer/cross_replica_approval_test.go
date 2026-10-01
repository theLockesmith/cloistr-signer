package signer

import (
	"context"
	"testing"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/config"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

func TestWaitForAuthorization_CrossReplicaApproval(t *testing.T) {
	store := storage.NewMemoryStorage()
	cfg := &config.Config{}
	cfg.Auth.AuthorizationTimeout = 30
	signer := New(cfg, store, nil, nil, nil, nil, nil)

	keyPubkey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	clientPubkey := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	// Create the key so SetPermission succeeds
	store.CreateKey(context.Background(), &storage.Key{
		ID:     keyPubkey[:16],
		Name:   "test-key",
		Pubkey: keyPubkey,
	})

	reqCtx := &pendingRequestContext{
		targetPubkey: keyPubkey,
		clientPubkey: clientPubkey,
		request:      &NIP46Request{ID: "req1", Method: "connect"},
	}

	type result struct {
		approved bool
		perm     *storage.Permission
		err      error
	}
	ch := make(chan result, 1)

	go func() {
		approved, perm, err := signer.waitForAuthorization(context.Background(), reqCtx, 30*time.Second)
		ch <- result{approved, perm, err}
	}()

	// Simulate the other replica's approve handler: save the permission
	// to the database without touching the in-memory pendingCtx.
	time.Sleep(500 * time.Millisecond)
	err := store.SetPermission(context.Background(), &storage.Permission{
		KeyID:      keyPubkey,
		UserPubkey: clientPubkey,
		Methods:    []string{"sign_event", "connect"},
	})
	if err != nil {
		t.Fatalf("SetPermission: %v", err)
	}

	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("waitForAuthorization returned error: %v", r.err)
		}
		if !r.approved {
			t.Fatal("expected approved=true, got false")
		}
		if r.perm == nil {
			t.Fatal("expected non-nil permission")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("waitForAuthorization did not return within 10 seconds (DB poll fallback not working)")
	}
}

func TestWaitForAuthorization_InMemoryStillFast(t *testing.T) {
	store := storage.NewMemoryStorage()
	cfg := &config.Config{}
	cfg.Auth.AuthorizationTimeout = 30
	signer := New(cfg, store, nil, nil, nil, nil, nil)

	keyPubkey := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	clientPubkey := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

	store.CreateKey(context.Background(), &storage.Key{
		ID:     keyPubkey[:16],
		Name:   "test-key-2",
		Pubkey: keyPubkey,
	})

	reqCtx := &pendingRequestContext{
		targetPubkey: keyPubkey,
		clientPubkey: clientPubkey,
		request:      &NIP46Request{ID: "req2", Method: "connect"},
	}

	type result struct {
		approved bool
		perm     *storage.Permission
		err      error
	}
	ch := make(chan result, 1)

	go func() {
		approved, perm, err := signer.waitForAuthorization(context.Background(), reqCtx, 30*time.Second)
		ch <- result{approved, perm, err}
	}()

	// Simulate same-replica approval via the in-memory channel (fast path)
	time.Sleep(200 * time.Millisecond)

	// Look up the pending context and signal it directly
	signer.pendingCtxLock.RLock()
	var pendingCtx *pendingRequestContext
	for _, ctx := range signer.pendingCtx {
		if ctx.clientPubkey == clientPubkey {
			pendingCtx = ctx
			break
		}
	}
	signer.pendingCtxLock.RUnlock()

	if pendingCtx == nil {
		t.Fatal("pending context not found")
	}

	testPerm := &storage.Permission{
		KeyID:      keyPubkey,
		UserPubkey: clientPubkey,
		Methods:    []string{"*"},
	}
	pendingCtx.resultChan <- authResult{approved: true, perm: testPerm}

	select {
	case r := <-ch:
		if r.err != nil {
			t.Fatalf("waitForAuthorization returned error: %v", r.err)
		}
		if !r.approved {
			t.Fatal("expected approved=true")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("in-memory fast path took too long")
	}
}
