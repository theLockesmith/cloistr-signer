package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// staticLocator stands in for the Dragonfly registry: it answers one address
// for every key.
type staticLocator struct {
	mu   sync.Mutex
	addr string
}

func (s *staticLocator) Lookup(_ context.Context, _ string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addr, s.addr != ""
}

var testForwardSecret = []byte("0123456789abcdef0123456789abcdef-forward-test")

// twoReplicas builds replicas A and B over one shared store (production's
// shared Postgres). A holds the user's unlocked key and serves the forward
// endpoint; B does not hold it.
func twoReplicas(t *testing.T) (a, b *Handler, key *storage.Key, aSrv *httptest.Server, loc *staticLocator) {
	t.Helper()
	a, store := testHandler(t)
	b, _ = testHandler(t)
	b.storage = store
	key = seedUserAndKey(t, store)
	unlockKey(a, key)

	if err := a.SetForwarding(testForwardSecret, &staticLocator{}); err != nil {
		t.Fatalf("A SetForwarding: %v", err)
	}
	aSrv = httptest.NewServer(a.ForwardHandler())
	t.Cleanup(aSrv.Close)

	loc = &staticLocator{addr: strings.TrimPrefix(aSrv.URL, "http://")}
	if err := b.SetForwarding(testForwardSecret, loc); err != nil {
		t.Fatalf("B SetForwarding: %v", err)
	}
	b.forward.allowAnyAddr = true // httptest listens on 127.0.0.1
	return a, b, key, aSrv, loc
}

func TestForward_LoginOnA_SessionOnB_Succeeds(t *testing.T) {
	_, b, _, _, _ := twoReplicas(t)

	rr := sessionPOST(t, b)
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 via forward to the replica holding the key\nbody: %s", rr.Code, rr.Body.String())
	}
	var resp NostrConnectSessionResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil || !resp.Success {
		t.Fatalf("response = %+v (err %v), want success", resp, err)
	}
}

// A planted location record pointing at something that does not hold the
// forward secret is misrouting only: the client gets key_locked, never the
// impostor's answer.
func TestForward_ForgedLocationRecordRefused(t *testing.T) {
	_, b, _, _, loc := twoReplicas(t)
	var got int
	impostor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer impostor.Close()
	loc.mu.Lock()
	loc.addr = strings.TrimPrefix(impostor.URL, "http://")
	loc.mu.Unlock()

	rr := sessionPOST(t, b)
	if rr.Code != http.StatusConflict || !strings.Contains(rr.Body.String(), "key_locked") {
		t.Fatalf("status = %d body %s; want 409 key_locked when the forward target is not a real replica", rr.Code, rr.Body.String())
	}
	if got != 1 {
		t.Fatalf("impostor saw %d requests, want 1 (it is reached, but learns nothing)", got)
	}
}

func TestForward_BadSealRefused(t *testing.T) {
	_, _, _, aSrv, _ := twoReplicas(t)
	req, _ := http.NewRequest(http.MethodPost, aSrv.URL+forwardPath, bytes.NewReader([]byte("not a sealed request")))
	req.Header.Set(hdrFwdTs, "1")
	req.Header.Set(hdrFwdNonce, "00")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 for a request not sealed with the forward secret", resp.StatusCode)
	}
}

func TestForward_WrongSecretRefused(t *testing.T) {
	_, b, _, _, _ := twoReplicas(t)
	// B now seals with a different secret than A expects.
	if err := b.SetForwarding([]byte("a-completely-different-secret-of-sufficient-length"), b.forward.locator); err != nil {
		t.Fatal(err)
	}
	b.forward.allowAnyAddr = true
	rr := sessionPOST(t, b)
	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 when replicas disagree on the secret", rr.Code)
	}
}

func TestForward_ReplayRefused(t *testing.T) {
	_, b, _, aSrv, _ := twoReplicas(t)
	sealed, ts, nonce, err := b.forward.sealRequest(forwardedRequest{Body: []byte(`{}`)})
	if err != nil {
		t.Fatal(err)
	}
	send := func() int {
		req, _ := http.NewRequest(http.MethodPost, aSrv.URL+forwardPath, bytes.NewReader(sealed))
		req.Header.Set(hdrFwdTs, ts)
		req.Header.Set(hdrFwdNonce, nonce)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if first := send(); first == http.StatusUnauthorized {
		t.Fatalf("first delivery refused (%d); it is validly sealed", first)
	}
	if second := send(); second != http.StatusUnauthorized {
		t.Fatalf("replayed delivery = %d, want 401", second)
	}
}

// The receiver re-validates the user's session itself: a correctly sealed
// forward carrying a bad token is refused like any unauthenticated request.
func TestForward_ReceiverRevalidatesSession(t *testing.T) {
	_, b, _, _, _ := twoReplicas(t)
	body, _ := json.Marshal(map[string]interface{}{
		"uri":    validNostrConnectURI(testClientPubkey, "wss://relay.cloistr.xyz", "TestApp"),
		"key_id": "key-sso-001",
	})
	status, _, err := b.forward.forwardSession(context.Background(), "", forwardedRequest{
		Authorization: "Bearer not-a-valid-token",
		Body:          body,
	})
	if err != nil {
		t.Fatalf("forward transport failed: %v", err)
	}
	if status != http.StatusUnauthorized {
		t.Fatalf("receiver answered %d for a forged session token, want 401", status)
	}
}

// A forwarded request that lands on a replica without the key ends there:
// key_locked, no second hop.
func TestForward_NoSecondHop(t *testing.T) {
	a, b, key, _, _ := twoReplicas(t)
	a.signer.UnregisterKey(key.Pubkey)
	// A would forward to B if it were allowed to forward a forwarded request.
	bSrv := httptest.NewServer(b.ForwardHandler())
	defer bSrv.Close()
	a.forward.locator = &staticLocator{addr: strings.TrimPrefix(bSrv.URL, "http://")}
	a.forward.allowAnyAddr = true

	rr := sessionPOST(t, b)
	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 key_locked when the holder no longer has the key", rr.Code)
	}
}

// Forwarding is off unless configured: no secret, no forward, today's 409.
func TestForward_DisabledWithoutSecret(t *testing.T) {
	h, store := testHandler(t)
	seedUserAndKey(t, store)
	if h.forward != nil {
		t.Fatal("forwarding enabled without SetForwarding")
	}
	if rr := sessionPOST(t, h); rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rr.Code)
	}
}
