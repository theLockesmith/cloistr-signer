package api

import (
	"bytes"
	"context"
	"net/http"
	"testing"
)

// Deleting an account on replica B tells replica A (which holds the key in
// memory) to drop it.
func TestEvictRemote_HolderDropsKey(t *testing.T) {
	a, b, key, _, _ := twoReplicas(t)
	if !a.signer.IsKeyLoaded(key.Pubkey) {
		t.Fatal("fixture: A should hold the key")
	}
	b.forward.evictRemote(context.Background(), []string{key.Pubkey})
	if a.signer.IsKeyLoaded(key.Pubkey) {
		t.Fatal("A still holds the key after B's eviction request")
	}
}

func TestEvictRemote_DeleteAccountEvictsOnHolder(t *testing.T) {
	a, b, key, _, _ := twoReplicas(t)
	b.accountVault = &fakeAccountVault{fail: map[string]error{}}
	if _, err := b.deleteAccount(context.Background(), testUserIDSess); err != nil {
		t.Fatalf("deleteAccount on B: %v", err)
	}
	if a.signer.IsKeyLoaded(key.Pubkey) {
		t.Fatal("A still holds a deleted user's key")
	}
}

func TestEvictRemote_UnsealedRequestRefused(t *testing.T) {
	a, _, key, aSrv, _ := twoReplicas(t)
	req, _ := http.NewRequest(http.MethodPost, aSrv.URL+evictPath, bytes.NewReader([]byte(`{"pubkeys":["`+key.Pubkey+`"]}`)))
	req.Header.Set(hdrFwdTs, "1")
	req.Header.Set(hdrFwdNonce, "00")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if !a.signer.IsKeyLoaded(key.Pubkey) {
		t.Fatal("an unsealed request evicted the key")
	}
}
