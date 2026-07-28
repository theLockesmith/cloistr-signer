package api

// Rate-limiting tests for handleRecoveryChallenge.
//
// These tests are separate from recovery_test.go so the two concerns —
// correctness of the challenge/complete flow vs. enforcement of the four
// rate-limiting layers — stay readable independently.
//
// Design invariant under test: the per-username limit is existence-blind.
// A limit tripped for a real username must trip identically for a username
// that has no account.  Any difference would make a tripped limit an
// existence oracle — the very property the endpoint was built to avoid.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip13"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/config"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/ratelimit"
)

// stubLimiter is a test double that returns a predetermined (allowed, err) pair
// for every call.  Used to exercise the fail-open path.
type stubLimiter struct {
	allowed bool
	err     error
}

func (s *stubLimiter) Allow(_ context.Context, _ string, _ int, _ time.Duration) (bool, error) {
	return s.allowed, s.err
}

// rlCfg returns a RecoveryConfig with tight limits suitable for testing.
func rlCfg() config.RecoveryConfig {
	return config.RecoveryConfig{
		PoWDifficulty:      0, // off by default in all non-PoW tests
		PerUsernameLimit:   3,
		PerUsernameWindow:  time.Minute,
		GlobalLimit:        100,
		GlobalWindow:       time.Minute,
		PerIPLimit:         5,
		PerIPWindow:        time.Minute,
		TrustedProxyHeader: "", // off unless explicitly enabled
		IPSecretRotation:   time.Hour,
	}
}

// buildRLFixture creates a recoveryFixture wired with the given limiter and
// RecoveryConfig.  The fixture's mux is re-registered so that the handler
// running inside it has the updated config and limiter.
func buildRLFixture(t *testing.T, lim ratelimit.Limiter, rc config.RecoveryConfig) *recoveryFixture {
	t.Helper()
	f := newRecoveryFixture(t)
	f.h.limiter = lim
	f.h.config.Recovery = rc
	return f
}

// postChallenge hits /api/v1/recovery/challenge and returns the recorder.
func postChallenge(t *testing.T, f *recoveryFixture, username string) *httptest.ResponseRecorder {
	t.Helper()
	return f.post(t, "/api/v1/recovery/challenge", map[string]string{"username": username})
}

// --- Per-username limit ---

func TestRateLimit_PerUsernameTripsAfterN_ExistingAccount(t *testing.T) {
	lim := ratelimit.NewMemory()
	rc := rlCfg()
	rc.PerUsernameLimit = 3
	f := buildRLFixture(t, lim, rc)

	// First N requests must succeed.
	for i := 0; i < rc.PerUsernameLimit; i++ {
		w := postChallenge(t, f, "alice")
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: got %d, want 200", i+1, w.Code)
		}
	}
	// The next one must be blocked.
	w := postChallenge(t, f, "alice")
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("request %d: got %d, want 429", rc.PerUsernameLimit+1, w.Code)
	}
}

// Anti-oracle: the per-username limit must trip identically for a username
// that has no account.  This is the single most important test in this file.
func TestRateLimit_PerUsernameTripsIdentically_NonExistentAccount(t *testing.T) {
	lim := ratelimit.NewMemory()
	rc := rlCfg()
	rc.PerUsernameLimit = 3
	f := buildRLFixture(t, lim, rc)

	const ghost = "nobody-has-this-account"

	for i := 0; i < rc.PerUsernameLimit; i++ {
		w := postChallenge(t, f, ghost)
		if w.Code != http.StatusOK {
			t.Fatalf("request %d for non-existent account: got %d, want 200", i+1, w.Code)
		}
	}
	w := postChallenge(t, f, ghost)
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("non-existent account: got %d after limit, want 429 (anti-oracle property broken)", w.Code)
	}
}

// Confirm that tripping the limit for one username does not affect another.
func TestRateLimit_PerUsernameIsolated(t *testing.T) {
	lim := ratelimit.NewMemory()
	rc := rlCfg()
	rc.PerUsernameLimit = 2
	f := buildRLFixture(t, lim, rc)

	// Exhaust alice's quota.
	for i := 0; i < rc.PerUsernameLimit; i++ {
		postChallenge(t, f, "alice")
	}

	// bob is unaffected.
	w := postChallenge(t, f, "nobody-bob")
	if w.Code != http.StatusOK {
		t.Errorf("alice's limit should not affect bob: got %d, want 200", w.Code)
	}
}

// --- Global limit ---

func TestRateLimit_GlobalLimitTrips(t *testing.T) {
	lim := ratelimit.NewMemory()
	rc := rlCfg()
	rc.GlobalLimit = 5
	rc.PerUsernameLimit = 100 // high so it does not interfere
	f := buildRLFixture(t, lim, rc)

	// Use different usernames to avoid hitting the per-username limit.
	for i := 0; i < rc.GlobalLimit; i++ {
		username := strings.Repeat("x", i+1)
		w := postChallenge(t, f, username)
		if w.Code != http.StatusOK {
			t.Fatalf("global request %d: got %d, want 200", i+1, w.Code)
		}
	}
	w := postChallenge(t, f, "extra")
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("global limit not enforced: got %d, want 429", w.Code)
	}
}

// --- Per-IP: off when TrustedProxyHeader is empty ---

func TestRateLimit_PerIPInertWithoutHeader(t *testing.T) {
	lim := ratelimit.NewMemory()
	rc := rlCfg()
	rc.PerIPLimit = 2
	rc.TrustedProxyHeader = "" // explicitly off
	rc.PerUsernameLimit = 100
	rc.GlobalLimit = 1000

	ipHasher, err := ratelimit.NewIPHasher(time.Hour)
	if err != nil {
		t.Fatalf("NewIPHasher: %v", err)
	}
	f := buildRLFixture(t, lim, rc)
	f.h.ipHasher = ipHasher

	// Sending many requests with a forged IP header should not trigger 429
	// because TrustedProxyHeader is empty.
	for i := 0; i < 20; i++ {
		raw, _ := json.Marshal(map[string]string{"username": "alice"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/recovery/challenge", strings.NewReader(string(raw)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-For", "10.0.0.1")
		w := httptest.NewRecorder()
		f.mux.ServeHTTP(w, req)

		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d: got 429 but per-IP should be inactive when TrustedProxyHeader is empty", i+1)
		}
	}
}

// --- Per-IP: active when TrustedProxyHeader is set ---

func TestRateLimit_PerIPActiveWhenHeaderSet(t *testing.T) {
	lim := ratelimit.NewMemory()
	rc := rlCfg()
	rc.PerIPLimit = 3
	rc.TrustedProxyHeader = "CF-Connecting-IP"
	rc.PerUsernameLimit = 100
	rc.GlobalLimit = 1000

	ipHasher, err := ratelimit.NewIPHasher(time.Hour)
	if err != nil {
		t.Fatalf("NewIPHasher: %v", err)
	}
	f := buildRLFixture(t, lim, rc)
	f.h.ipHasher = ipHasher

	postWithIP := func(ip, username string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(map[string]string{"username": username})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/recovery/challenge", strings.NewReader(string(raw)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("CF-Connecting-IP", ip)
		w := httptest.NewRecorder()
		f.mux.ServeHTTP(w, req)
		return w
	}

	const ip = "203.0.113.42"
	for i := 0; i < rc.PerIPLimit; i++ {
		// vary username to avoid tripping per-username limit
		w := postWithIP(ip, strings.Repeat("u", i+1))
		if w.Code != http.StatusOK {
			t.Fatalf("per-IP request %d: got %d, want 200", i+1, w.Code)
		}
	}
	w := postWithIP(ip, "extra")
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("per-IP limit not enforced: got %d, want 429", w.Code)
	}
}

// --- Per-IP: different IPs use different buckets ---

func TestRateLimit_PerIPDifferentIPsDifferentBuckets(t *testing.T) {
	lim := ratelimit.NewMemory()
	rc := rlCfg()
	rc.PerIPLimit = 2
	rc.TrustedProxyHeader = "CF-Connecting-IP"
	rc.PerUsernameLimit = 100
	rc.GlobalLimit = 1000

	ipHasher, err := ratelimit.NewIPHasher(time.Hour)
	if err != nil {
		t.Fatalf("NewIPHasher: %v", err)
	}
	f := buildRLFixture(t, lim, rc)
	f.h.ipHasher = ipHasher

	postWithIP := func(ip, username string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(map[string]string{"username": username})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/recovery/challenge", strings.NewReader(string(raw)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("CF-Connecting-IP", ip)
		w := httptest.NewRecorder()
		f.mux.ServeHTTP(w, req)
		return w
	}

	// Exhaust ip1's bucket.
	for i := 0; i < rc.PerIPLimit; i++ {
		postWithIP("1.2.3.4", strings.Repeat("a", i+1))
	}

	// ip2 must still be allowed.
	w := postWithIP("5.6.7.8", "alice")
	if w.Code == http.StatusTooManyRequests {
		t.Error("ip2 blocked by ip1's quota — buckets are not isolated")
	}
}

// --- Per-IP: request missing the trusted-proxy header is not blocked ---

func TestRateLimit_PerIPMissingHeaderNotBlocked(t *testing.T) {
	lim := ratelimit.NewMemory()
	rc := rlCfg()
	rc.PerIPLimit = 1 // would block immediately if IP were in play
	rc.TrustedProxyHeader = "CF-Connecting-IP"
	rc.PerUsernameLimit = 100
	rc.GlobalLimit = 1000

	ipHasher, err := ratelimit.NewIPHasher(time.Hour)
	if err != nil {
		t.Fatalf("NewIPHasher: %v", err)
	}
	f := buildRLFixture(t, lim, rc)
	f.h.ipHasher = ipHasher

	// Exhaust the global shared IP bucket with an IP first so that any
	// accidental fallback to RemoteAddr would be caught.
	for i := 0; i < 10; i++ {
		raw, _ := json.Marshal(map[string]string{"username": strings.Repeat("u", i+1)})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/recovery/challenge", strings.NewReader(string(raw)))
		req.Header.Set("Content-Type", "application/json")
		// intentionally NO CF-Connecting-IP header
		w := httptest.NewRecorder()
		f.mux.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d blocked despite missing header: per-IP must be skipped, not applied to RemoteAddr", i+1)
		}
	}
}

// --- PoW: disabled (difficulty 0) ---

func TestRateLimit_PoWDisabledLetsRequestsThrough(t *testing.T) {
	f := buildRLFixture(t, nil, rlCfg()) // nil limiter = no rate limiting at all

	w := postChallenge(t, f, "alice")
	if w.Code != http.StatusOK {
		t.Errorf("PoW disabled: got %d, want 200", w.Code)
	}
}

// --- PoW: enabled ---

func TestRateLimit_PoWEnabledRejectsMissingEvent(t *testing.T) {
	rc := rlCfg()
	rc.PoWDifficulty = 4
	f := buildRLFixture(t, nil, rc)

	w := postChallenge(t, f, "alice") // no pow_event field
	if w.Code != http.StatusBadRequest {
		t.Errorf("missing pow_event: got %d, want 400", w.Code)
	}
}

func TestRateLimit_PoWEnabledRejectsUnderpoweredEvent(t *testing.T) {
	const difficulty = 8
	rc := rlCfg()
	rc.PoWDifficulty = difficulty
	f := buildRLFixture(t, nil, rc)

	// Build an event with difficulty 0 (no nonce tag) — trivially underpowered.
	priv := nostr.GeneratePrivateKey()
	pub, _ := nostr.GetPublicKey(priv)
	ev := nostr.Event{
		Kind:      27235,
		PubKey:    pub,
		Tags:      nostr.Tags{{"u", "alice"}},
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
	}
	ev.ID = ev.GetID()
	raw, _ := json.Marshal(ev)

	body := map[string]string{"username": "alice", "pow_event": string(raw)}
	w := f.post(t, "/api/v1/recovery/challenge", body)
	if w.Code != http.StatusBadRequest {
		t.Errorf("underpowered event: got %d, want 400", w.Code)
	}
}

func TestRateLimit_PoWEnabledAcceptsCorrectlyMinedEvent(t *testing.T) {
	const difficulty = 4 // low so the test finishes quickly
	rc := rlCfg()
	rc.PoWDifficulty = difficulty
	rc.GlobalLimit = 1000
	rc.PerUsernameLimit = 1000
	f := buildRLFixture(t, ratelimit.NewMemory(), rc)

	priv := nostr.GeneratePrivateKey()
	pub, _ := nostr.GetPublicKey(priv)
	ev := nostr.Event{
		Kind:      27235,
		PubKey:    pub,
		Tags:      nostr.Tags{{"u", "alice"}},
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
	}

	nonceTag, err := nip13.DoWork(context.Background(), ev, difficulty)
	if err != nil {
		t.Fatalf("DoWork: %v", err)
	}
	ev.Tags = append(ev.Tags, nonceTag)
	ev.ID = ev.GetID()

	raw, _ := json.Marshal(ev)
	body := map[string]string{"username": "alice", "pow_event": string(raw)}
	w := f.post(t, "/api/v1/recovery/challenge", body)
	if w.Code != http.StatusOK {
		t.Errorf("valid PoW: got %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

func TestRateLimit_PoWEnabledRejectsWrongUsernameBound(t *testing.T) {
	const difficulty = 4
	rc := rlCfg()
	rc.PoWDifficulty = difficulty
	f := buildRLFixture(t, nil, rc)

	priv := nostr.GeneratePrivateKey()
	pub, _ := nostr.GetPublicKey(priv)
	ev := nostr.Event{
		Kind:      27235,
		PubKey:    pub,
		Tags:      nostr.Tags{{"u", "carol"}}, // mined for carol, not alice
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
	}
	nonceTag, err := nip13.DoWork(context.Background(), ev, difficulty)
	if err != nil {
		t.Fatalf("DoWork: %v", err)
	}
	ev.Tags = append(ev.Tags, nonceTag)
	ev.ID = ev.GetID()

	raw, _ := json.Marshal(ev)
	body := map[string]string{"username": "alice", "pow_event": string(raw)}
	w := f.post(t, "/api/v1/recovery/challenge", body)
	if w.Code != http.StatusBadRequest {
		t.Errorf("wrong username bound: got %d, want 400", w.Code)
	}
}

// --- Fail-open: limiter backend errors result in ALLOWED ---

func TestRateLimit_FailOpen_BackendError(t *testing.T) {
	// The stub returns (true, error): the allow path of a failing backend.
	// Even though an error occurred, the request must be allowed through.
	stub := &stubLimiter{allowed: true, err: errors.New("simulated backend failure")}
	rc := rlCfg()
	f := buildRLFixture(t, stub, rc)

	w := postChallenge(t, f, "alice")
	if w.Code != http.StatusOK {
		t.Errorf("backend error should fail-open: got %d, want 200", w.Code)
	}
}

// Confirm the stub really does return an error so the test is meaningful.
func TestRateLimit_FailOpen_StubBehavesCorrectly(t *testing.T) {
	stub := &stubLimiter{allowed: true, err: errors.New("boom")}
	ok, err := stub.Allow(context.Background(), "k", 1, time.Second)
	if !ok {
		t.Error("stub.Allow should return true")
	}
	if err == nil {
		t.Error("stub.Allow should return an error")
	}
}
