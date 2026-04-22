package signer

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/config"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

func TestNormalizePubkey(t *testing.T) {
	tests := []struct {
		name   string
		pubkey string
		want   string
	}{
		{
			name:   "x-only pubkey (64 chars)",
			pubkey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name:   "compressed with 02 prefix",
			pubkey: "020123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name:   "compressed with 03 prefix",
			pubkey: "030123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want:   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		{
			name:   "short pubkey (not 66 chars)",
			pubkey: "02abcd",
			want:   "02abcd",
		},
		{
			name:   "66 chars but not 02/03 prefix",
			pubkey: "010123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			want:   "010123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizePubkey(tt.pubkey)
			if got != tt.want {
				t.Errorf("normalizePubkey(%q) = %q, want %q", tt.pubkey, got, tt.want)
			}
		})
	}
}

func TestNIP46Request_JSON(t *testing.T) {
	req := NIP46Request{
		ID:     "req123",
		Method: "sign_event",
		Params: []string{`{"kind":1,"content":"hello"}`},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var decoded NIP46Request
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if decoded.ID != req.ID {
		t.Errorf("ID = %q, want %q", decoded.ID, req.ID)
	}
	if decoded.Method != req.Method {
		t.Errorf("Method = %q, want %q", decoded.Method, req.Method)
	}
	if len(decoded.Params) != 1 {
		t.Errorf("Params length = %d, want 1", len(decoded.Params))
	}
}

func TestNIP46Response_JSON(t *testing.T) {
	t.Run("success response", func(t *testing.T) {
		resp := NIP46Response{
			ID:     "req123",
			Result: "signed-event-json",
		}

		data, err := json.Marshal(resp)
		if err != nil {
			t.Fatalf("Marshal() error = %v", err)
		}

		var decoded NIP46Response
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}

		if decoded.ID != resp.ID {
			t.Errorf("ID = %q, want %q", decoded.ID, resp.ID)
		}
		if decoded.Result != resp.Result {
			t.Errorf("Result = %q, want %q", decoded.Result, resp.Result)
		}
		if decoded.Error != "" {
			t.Errorf("Error should be empty")
		}
	})

	t.Run("error response", func(t *testing.T) {
		resp := NIP46Response{
			ID:    "req123",
			Error: "permission denied",
		}

		data, err := json.Marshal(resp)
		if err != nil {
			t.Fatalf("Marshal() error = %v", err)
		}

		var decoded NIP46Response
		if err := json.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("Unmarshal() error = %v", err)
		}

		if decoded.Error != resp.Error {
			t.Errorf("Error = %q, want %q", decoded.Error, resp.Error)
		}
	})
}

func TestNew(t *testing.T) {
	cfg := &config.Config{}
	store := storage.NewMemoryStorage()

	signer := New(cfg, store, nil, nil, nil, nil, nil)

	if signer == nil {
		t.Fatal("New() returned nil")
	}
	if signer.config != cfg {
		t.Error("signer.config not set correctly")
	}
	if signer.storage != store {
		t.Error("signer.storage not set correctly")
	}
	if signer.keys == nil {
		t.Error("signer.keys should be initialized")
	}
	if signer.pendingCtx == nil {
		t.Error("signer.pendingCtx should be initialized")
	}
}

func TestSigner_RegisterKey(t *testing.T) {
	signer := New(&config.Config{}, storage.NewMemoryStorage(), nil, nil, nil, nil, nil)

	pubkey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	privateKey := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

	signer.RegisterKey(pubkey, privateKey)

	if signer.keys[pubkey] != privateKey {
		t.Errorf("keys[%s] = %q, want %q", pubkey, signer.keys[pubkey], privateKey)
	}
}

func TestSigner_isMethodAllowed(t *testing.T) {
	signer := New(&config.Config{}, storage.NewMemoryStorage(), nil, nil, nil, nil, nil)

	tests := []struct {
		name    string
		perm    *storage.Permission
		method  string
		allowed bool
	}{
		{
			name:    "exact match",
			perm:    &storage.Permission{Methods: []string{"sign_event", "ping"}},
			method:  "sign_event",
			allowed: true,
		},
		{
			name:    "wildcard",
			perm:    &storage.Permission{Methods: []string{"*"}},
			method:  "sign_event",
			allowed: true,
		},
		{
			name:    "all keyword",
			perm:    &storage.Permission{Methods: []string{"all"}},
			method:  "nip04_encrypt",
			allowed: true,
		},
		{
			name:    "not in list",
			perm:    &storage.Permission{Methods: []string{"ping"}},
			method:  "sign_event",
			allowed: false,
		},
		{
			name:    "empty methods",
			perm:    &storage.Permission{Methods: []string{}},
			method:  "ping",
			allowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := signer.isMethodAllowed(tt.perm, tt.method)
			if got != tt.allowed {
				t.Errorf("isMethodAllowed(%v, %q) = %v, want %v", tt.perm.Methods, tt.method, got, tt.allowed)
			}
		})
	}
}

func TestSigner_KeysLoaded(t *testing.T) {
	signer := New(&config.Config{}, storage.NewMemoryStorage(), nil, nil, nil, nil, nil)

	// Register some keys
	signer.RegisterKey("pubkey1", "privkey1")
	signer.RegisterKey("pubkey2", "privkey2")

	// Verify keys are stored
	if len(signer.keys) != 2 {
		t.Errorf("keys count = %d, want 2", len(signer.keys))
	}
	if signer.keys["pubkey1"] != "privkey1" {
		t.Error("pubkey1 not stored correctly")
	}
	if signer.keys["pubkey2"] != "privkey2" {
		t.Error("pubkey2 not stored correctly")
	}
}

func TestSigner_storePendingContext(t *testing.T) {
	signer := New(&config.Config{}, storage.NewMemoryStorage(), nil, nil, nil, nil, nil)

	ctx := &pendingRequestContext{
		targetPubkey: "target123",
		clientPubkey: "client456",
		request:      &NIP46Request{ID: "req1", Method: "sign_event"},
	}

	signer.storePendingContext("req1", ctx)

	signer.pendingCtxLock.RLock()
	stored := signer.pendingCtx["req1"]
	signer.pendingCtxLock.RUnlock()

	if stored == nil {
		t.Fatal("stored context should not be nil")
	}
	if stored.targetPubkey != ctx.targetPubkey {
		t.Errorf("targetPubkey = %q, want %q", stored.targetPubkey, ctx.targetPubkey)
	}
}

func TestSigner_removePendingContext(t *testing.T) {
	signer := New(&config.Config{}, storage.NewMemoryStorage(), nil, nil, nil, nil, nil)

	ctx := &pendingRequestContext{
		targetPubkey: "target123",
		clientPubkey: "client456",
	}

	signer.storePendingContext("req1", ctx)
	signer.removePendingContext("req1")

	signer.pendingCtxLock.RLock()
	stored := signer.pendingCtx["req1"]
	signer.pendingCtxLock.RUnlock()

	if stored != nil {
		t.Error("context should be removed")
	}
}

func TestSigner_checkPolicyUsage(t *testing.T) {
	store := storage.NewMemoryStorage()
	signer := New(&config.Config{}, store, nil, nil, nil, nil, nil)
	ctx := context.Background()

	// Create a policy with usage limits
	policy := &storage.Policy{
		ID:   "policy1",
		Name: "Test Policy",
		Rules: []*storage.PolicyRule{
			{ID: "rule1", PolicyID: "policy1", Method: "sign_event", MaxUsage: 10, CurrentUsage: 5},
			{ID: "rule2", PolicyID: "policy1", Method: "ping", MaxUsage: 0}, // Unlimited
		},
	}
	store.CreatePolicy(ctx, policy)

	t.Run("allowed with usage remaining", func(t *testing.T) {
		allowed, ruleID, err := signer.checkPolicyUsage(ctx, "policy1", "sign_event")
		if err != nil {
			t.Fatalf("checkPolicyUsage() error = %v", err)
		}
		if !allowed {
			t.Error("should be allowed when usage < max")
		}
		if ruleID != "rule1" {
			t.Errorf("ruleID = %q, want %q", ruleID, "rule1")
		}
	})

	t.Run("allowed unlimited", func(t *testing.T) {
		allowed, _, err := signer.checkPolicyUsage(ctx, "policy1", "ping")
		if err != nil {
			t.Fatalf("checkPolicyUsage() error = %v", err)
		}
		if !allowed {
			t.Error("should be allowed for unlimited usage")
		}
	})

	t.Run("denied when limit exceeded", func(t *testing.T) {
		// Increment usage to exceed limit (was 5, max is 10, increment 5 times)
		for i := 0; i < 5; i++ {
			store.IncrementRuleUsage(ctx, "rule1")
		}

		allowed, _, err := signer.checkPolicyUsage(ctx, "policy1", "sign_event")
		if err != nil {
			t.Fatalf("checkPolicyUsage() error = %v", err)
		}
		if allowed {
			t.Error("should be denied when usage >= max")
		}
	})

	t.Run("allowed when policy not found", func(t *testing.T) {
		allowed, _, err := signer.checkPolicyUsage(ctx, "nonexistent", "sign_event")
		if err != nil {
			t.Fatalf("checkPolicyUsage() error = %v", err)
		}
		if !allowed {
			t.Error("should allow when policy not found (graceful degradation)")
		}
	})
}

func TestSigner_handleConnect(t *testing.T) {
	store := storage.NewMemoryStorage()
	signer := New(&config.Config{}, store, nil, nil, nil, nil, nil)
	ctx := context.Background()

	perm := &storage.Permission{
		Methods: []string{"*"},
	}

	result, err := signer.handleConnect(ctx, "target123", "client456", []string{}, perm)
	if err != nil {
		t.Fatalf("handleConnect() error = %v", err)
	}

	// Connect now returns JSON with pubkey to save a round-trip
	expected := `{"pubkey":"target123"}`
	if result != expected {
		t.Errorf("handleConnect() = %q, want %q", result, expected)
	}

	// Verify session was created
	session, err := store.GetSessionByClient(ctx, "target123", "client456")
	if err != nil {
		t.Errorf("session should be created: %v", err)
	}
	if session == nil {
		t.Error("session should not be nil")
	}
}

// Note: TestSigner_handleGetRelays is skipped because it requires a non-nil relay client
// The handleGetRelays function calls relayClient.GetConnectedRelays() which panics on nil

func TestSigner_handleSignEvent_AllowedKinds(t *testing.T) {
	store := storage.NewMemoryStorage()
	signer := New(&config.Config{}, store, nil, nil, nil, nil, nil)
	ctx := context.Background()

	// Register a key (using a test key)
	pubkey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	privateKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	signer.RegisterKey(pubkey, privateKey)

	t.Run("kind allowed", func(t *testing.T) {
		perm := &storage.Permission{
			Methods:      []string{"sign_event"},
			AllowedKinds: []int{1, 4, 30023},
		}

		eventJSON := `{"kind":1,"content":"hello","tags":[],"created_at":1234567890}`
		_, err := signer.handleSignEvent(ctx, pubkey, privateKey, []string{eventJSON}, perm)
		if err != nil {
			t.Errorf("handleSignEvent() error = %v, should allow kind 1", err)
		}
	})

	t.Run("kind not allowed", func(t *testing.T) {
		perm := &storage.Permission{
			Methods:      []string{"sign_event"},
			AllowedKinds: []int{1},
		}

		eventJSON := `{"kind":4,"content":"encrypted","tags":[],"created_at":1234567890}`
		_, err := signer.handleSignEvent(ctx, pubkey, privateKey, []string{eventJSON}, perm)
		if err == nil {
			t.Error("handleSignEvent() should return error for disallowed kind")
		}
	})

	t.Run("all kinds allowed when empty", func(t *testing.T) {
		perm := &storage.Permission{
			Methods:      []string{"sign_event"},
			AllowedKinds: []int{}, // Empty = all allowed
		}

		eventJSON := `{"kind":9999,"content":"test","tags":[],"created_at":1234567890}`
		_, err := signer.handleSignEvent(ctx, pubkey, privateKey, []string{eventJSON}, perm)
		if err != nil {
			t.Errorf("handleSignEvent() error = %v, should allow any kind when AllowedKinds is empty", err)
		}
	})

	t.Run("missing params", func(t *testing.T) {
		perm := &storage.Permission{Methods: []string{"sign_event"}}
		_, err := signer.handleSignEvent(ctx, pubkey, privateKey, []string{}, perm)
		if err == nil {
			t.Error("handleSignEvent() should return error for missing params")
		}
	})

	t.Run("invalid event JSON", func(t *testing.T) {
		perm := &storage.Permission{Methods: []string{"sign_event"}}
		_, err := signer.handleSignEvent(ctx, pubkey, privateKey, []string{"not-json"}, perm)
		if err == nil {
			t.Error("handleSignEvent() should return error for invalid JSON")
		}
	})
}

func TestSigner_handleBatchSign(t *testing.T) {
	store := storage.NewMemoryStorage()
	signer := New(&config.Config{}, store, nil, nil, nil, nil, nil)
	ctx := context.Background()

	// Register a key (using a test key)
	pubkey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	privateKey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	signer.RegisterKey(pubkey, privateKey)

	t.Run("batch sign multiple events", func(t *testing.T) {
		perm := &storage.Permission{Methods: []string{"batch_sign"}}

		events := []string{
			`{"kind":1,"content":"hello","tags":[],"created_at":1234567890}`,
			`{"kind":1,"content":"world","tags":[],"created_at":1234567891}`,
		}

		result, err := signer.handleBatchSign(ctx, pubkey, privateKey, events, perm)
		if err != nil {
			t.Fatalf("handleBatchSign() error = %v", err)
		}

		// Result should be a JSON array
		var signedEvents []json.RawMessage
		if err := json.Unmarshal([]byte(result), &signedEvents); err != nil {
			t.Fatalf("failed to unmarshal result: %v", err)
		}

		if len(signedEvents) != 2 {
			t.Errorf("expected 2 signed events, got %d", len(signedEvents))
		}
	})

	t.Run("empty params", func(t *testing.T) {
		perm := &storage.Permission{Methods: []string{"batch_sign"}}
		_, err := signer.handleBatchSign(ctx, pubkey, privateKey, []string{}, perm)
		if err == nil {
			t.Error("handleBatchSign() should return error for empty params")
		}
	})

	t.Run("kind not allowed", func(t *testing.T) {
		perm := &storage.Permission{
			Methods:      []string{"batch_sign"},
			AllowedKinds: []int{1}, // Only kind 1 allowed
		}

		events := []string{
			`{"kind":1,"content":"allowed","tags":[],"created_at":1234567890}`,
			`{"kind":4,"content":"not allowed","tags":[],"created_at":1234567891}`,
		}

		_, err := signer.handleBatchSign(ctx, pubkey, privateKey, events, perm)
		if err == nil {
			t.Error("handleBatchSign() should return error when kind not allowed")
		}
	})
}

func TestSigner_ApproveRequest(t *testing.T) {
	signer := New(&config.Config{}, storage.NewMemoryStorage(), nil, nil, nil, nil, nil)

	// Create pending context with result channel
	resultChan := make(chan authResult, 1)
	ctx := &pendingRequestContext{
		targetPubkey: "target",
		clientPubkey: "client",
		request:      &NIP46Request{ID: "req1", Method: "sign_event"},
		resultChan:   resultChan,
	}
	signer.storePendingContext("req1", ctx)

	pendingReq := &storage.PendingRequest{
		ID:     "req1",
		Method: "sign_event",
	}

	signer.ApproveRequest("req1", pendingReq)

	// Check that approval was sent
	select {
	case result := <-resultChan:
		if !result.approved {
			t.Error("result.approved should be true")
		}
	case <-time.After(time.Second):
		t.Error("approval should be sent to result channel")
	}
}

func TestSigner_DenyRequest(t *testing.T) {
	signer := New(&config.Config{}, storage.NewMemoryStorage(), nil, nil, nil, nil, nil)

	// Create pending context with result channel
	resultChan := make(chan authResult, 1)
	ctx := &pendingRequestContext{
		targetPubkey: "target",
		clientPubkey: "client",
		request:      &NIP46Request{ID: "req1", Method: "sign_event"},
		resultChan:   resultChan,
	}
	signer.storePendingContext("req1", ctx)

	pendingReq := &storage.PendingRequest{
		ID:     "req1",
		Method: "sign_event",
	}

	signer.DenyRequest("req1", pendingReq)

	// Check that denial was sent
	select {
	case result := <-resultChan:
		if result.approved {
			t.Error("result.approved should be false")
		}
	case <-time.After(time.Second):
		t.Error("denial should be sent to result channel")
	}
}

func TestSigner_ApproveRequest_NotFound(t *testing.T) {
	signer := New(&config.Config{}, storage.NewMemoryStorage(), nil, nil, nil, nil, nil)

	// Try to approve nonexistent request (should not panic)
	pendingReq := &storage.PendingRequest{ID: "nonexistent", Method: "sign_event"}
	signer.ApproveRequest("nonexistent", pendingReq)
	// Should log warning but not panic
}

func TestSigner_DenyRequest_NotFound(t *testing.T) {
	signer := New(&config.Config{}, storage.NewMemoryStorage(), nil, nil, nil, nil, nil)

	// Try to deny nonexistent request (should not panic)
	pendingReq := &storage.PendingRequest{ID: "nonexistent", Method: "sign_event"}
	signer.DenyRequest("nonexistent", pendingReq)
	// Should log warning but not panic
}

func TestKindConstants(t *testing.T) {
	if KindNIP46Request != 24133 {
		t.Errorf("KindNIP46Request = %d, want 24133", KindNIP46Request)
	}
	if KindNIP46Response != 24133 {
		t.Errorf("KindNIP46Response = %d, want 24133", KindNIP46Response)
	}
}

// ============================================================================
// Proxy Chain Tests (Phase 12)
// ============================================================================

func TestSigner_RegisterProxyKey(t *testing.T) {
	signer := New(&config.Config{}, storage.NewMemoryStorage(), nil, nil, nil, nil, nil)

	proxyPubkey := "proxy0123456789abcdef0123456789abcdef0123456789abcdef01234567"
	proxyPrivkey := "proxypriv123456789abcdef0123456789abcdef0123456789abcdef0123"
	bunkerURI := "bunker://upstream123456789abcdef0123456789abcdef0123456789ab?relay=wss://relay.test"

	signer.RegisterProxyKey(proxyPubkey, proxyPrivkey, bunkerURI)

	// Check proxy key is registered
	if uri, ok := signer.proxyKeys[proxyPubkey]; !ok {
		t.Error("proxy key not registered in proxyKeys map")
	} else if uri != bunkerURI {
		t.Errorf("expected bunker URI %q, got %q", bunkerURI, uri)
	}

	// Check private key is stored (for NIP-46 communication with upstream)
	if key, ok := signer.keys[proxyPubkey]; !ok {
		t.Error("proxy private key not stored in keys map")
	} else if key != proxyPrivkey {
		t.Errorf("expected private key %q, got %q", proxyPrivkey, key)
	}
}

func TestSigner_UnregisterKey_Proxy(t *testing.T) {
	signer := New(&config.Config{}, storage.NewMemoryStorage(), nil, nil, nil, nil, nil)

	proxyPubkey := "proxy0123456789abcdef0123456789abcdef0123456789abcdef01234567"
	proxyPrivkey := "proxypriv123456789abcdef0123456789abcdef0123456789abcdef0123"
	bunkerURI := "bunker://upstream123456789abcdef0123456789abcdef0123456789ab?relay=wss://relay.test"

	signer.RegisterProxyKey(proxyPubkey, proxyPrivkey, bunkerURI)
	signer.UnregisterKey(proxyPubkey)

	// Check proxy key is removed
	if _, ok := signer.proxyKeys[proxyPubkey]; ok {
		t.Error("proxy key should be removed from proxyKeys map")
	}

	if _, ok := signer.keys[proxyPubkey]; ok {
		t.Error("proxy private key should be removed from keys map")
	}
}

func TestSigner_InternalProxy_SignEvent(t *testing.T) {
	store := storage.NewMemoryStorage()
	signer := New(&config.Config{}, store, nil, nil, nil, nil, nil)

	// Register upstream key (the actual signing key) - must be 64 hex chars
	upstreamPubkey := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	upstreamPrivkey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	signer.RegisterKey(upstreamPubkey, upstreamPrivkey)

	// Register proxy key that points to the upstream key - must be 64 hex chars
	proxyPubkey := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	proxyPrivkey := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	bunkerURI := "bunker://" + upstreamPubkey + "?relay=wss://relay.test"
	signer.RegisterProxyKey(proxyPubkey, proxyPrivkey, bunkerURI)

	// Create the proxy key in storage so we can set permissions
	proxyKey := &storage.Key{
		ID:      proxyPubkey,
		Pubkey:  proxyPubkey,
		Name:    "proxy-key",
		KeyType: storage.KeyTypeProxy,
	}
	if err := store.CreateKey(context.Background(), proxyKey); err != nil {
		t.Fatalf("failed to create proxy key in storage: %v", err)
	}

	// Create permission for the proxy key - must be 64 hex chars
	clientPubkey := "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	perm := &storage.Permission{
		KeyID:      proxyPubkey,
		UserPubkey: clientPubkey,
		Methods:    []string{"sign_event"},
	}
	if err := store.SetPermission(context.Background(), perm); err != nil {
		t.Fatalf("failed to set permission: %v", err)
	}

	// Create a test event to sign
	event := map[string]interface{}{
		"kind":       1,
		"content":    "test content",
		"created_at": time.Now().Unix(),
		"tags":       [][]string{},
	}
	eventJSON, _ := json.Marshal(event)

	req := &NIP46Request{
		ID:     "test-123",
		Method: "sign_event",
		Params: []string{string(eventJSON)},
	}

	// Handle the request through the proxy
	result, err := signer.handleRequest(context.Background(), proxyPubkey, proxyPrivkey, clientPubkey, req, perm)
	if err != nil {
		t.Fatalf("handleRequest failed: %v", err)
	}

	// Verify we got a signed event back
	if result == "" {
		t.Error("expected non-empty result")
	}

	// Parse the result to verify it's a valid signed event
	var signedEvent map[string]interface{}
	if err := json.Unmarshal([]byte(result), &signedEvent); err != nil {
		t.Errorf("failed to parse signed event: %v", err)
	}

	// The signed event should have a pubkey (derived from the upstream private key)
	pubkey, ok := signedEvent["pubkey"].(string)
	if !ok || pubkey == "" {
		t.Error("signed event missing pubkey")
	}

	// The pubkey should NOT be the proxy pubkey (it should be derived from upstream privkey)
	if pubkey == proxyPubkey {
		t.Error("signed event should not have proxy pubkey")
	}

	// Should have a signature
	if sig, ok := signedEvent["sig"].(string); !ok || sig == "" {
		t.Error("signed event missing or empty signature")
	}

	// Should have an ID
	if id, ok := signedEvent["id"].(string); !ok || id == "" {
		t.Error("signed event missing or empty id")
	}

	// Verify the signing went through internal proxy path (check logs showed this)
	t.Logf("Successfully signed event via internal proxy, pubkey: %s", pubkey)
}

func TestSigner_InternalProxy_GetPublicKey(t *testing.T) {
	signer := New(&config.Config{}, storage.NewMemoryStorage(), nil, nil, nil, nil, nil)

	// Register upstream key - must be 64 hex chars
	upstreamPubkey := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	upstreamPrivkey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	signer.RegisterKey(upstreamPubkey, upstreamPrivkey)

	// Register proxy key - must be 64 hex chars
	proxyPubkey := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	proxyPrivkey := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	bunkerURI := "bunker://" + upstreamPubkey + "?relay=wss://relay.test"
	signer.RegisterProxyKey(proxyPubkey, proxyPrivkey, bunkerURI)

	clientPubkey := "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	perm := &storage.Permission{
		KeyID:      proxyPubkey,
		UserPubkey: clientPubkey,
		Methods:    []string{"get_public_key"},
	}

	req := &NIP46Request{
		ID:     "test-pubkey",
		Method: "get_public_key",
		Params: []string{},
	}

	// get_public_key on a proxy should return the UPSTREAM pubkey
	result, err := signer.handleRequest(context.Background(), proxyPubkey, proxyPrivkey, clientPubkey, req, perm)
	if err != nil {
		t.Fatalf("handleRequest failed: %v", err)
	}

	if result != upstreamPubkey {
		t.Errorf("expected upstream pubkey %q, got %q", upstreamPubkey, result)
	}
}

func TestSigner_ShouldProxyMethod(t *testing.T) {
	signer := New(&config.Config{}, storage.NewMemoryStorage(), nil, nil, nil, nil, nil)

	tests := []struct {
		method string
		want   bool
	}{
		{"sign_event", true},
		{"nip04_encrypt", true},
		{"nip04_decrypt", true},
		{"nip44_encrypt", true},
		{"nip44_decrypt", true},
		{"connect", false},
		{"ping", false},
		{"get_public_key", false}, // Handled specially, not proxied
		{"get_relays", false},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := signer.shouldProxyMethod(tt.method)
			if got != tt.want {
				t.Errorf("shouldProxyMethod(%q) = %v, want %v", tt.method, got, tt.want)
			}
		})
	}
}

func TestSigner_ShouldAuditMethod(t *testing.T) {
	signer := New(&config.Config{}, storage.NewMemoryStorage(), nil, nil, nil, nil, nil)

	tests := []struct {
		method string
		want   bool
	}{
		{"sign_event", true},
		{"nip04_encrypt", true},
		{"nip04_decrypt", true},
		{"nip44_encrypt", true},
		{"nip44_decrypt", true},
		{"connect", false},
		{"ping", false},
		{"get_public_key", false},
		{"get_relays", false},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			got := signer.shouldAuditMethod(tt.method)
			if got != tt.want {
				t.Errorf("shouldAuditMethod(%q) = %v, want %v", tt.method, got, tt.want)
			}
		})
	}
}

func TestSigner_ExtractEventKind(t *testing.T) {
	signer := New(&config.Config{}, storage.NewMemoryStorage(), nil, nil, nil, nil, nil)

	tests := []struct {
		name   string
		req    *NIP46Request
		want   int
	}{
		{
			name: "kind 1 note",
			req: &NIP46Request{
				Method: "sign_event",
				Params: []string{`{"kind":1,"content":"hello"}`},
			},
			want: 1,
		},
		{
			name: "kind 0 metadata",
			req: &NIP46Request{
				Method: "sign_event",
				Params: []string{`{"kind":0,"content":"{\"name\":\"test\"}"}`},
			},
			want: 0,
		},
		{
			name: "kind 30023 long-form",
			req: &NIP46Request{
				Method: "sign_event",
				Params: []string{`{"kind":30023,"content":"article"}`},
			},
			want: 30023,
		},
		{
			name: "not sign_event",
			req: &NIP46Request{
				Method: "ping",
				Params: []string{},
			},
			want: 0,
		},
		{
			name: "invalid JSON",
			req: &NIP46Request{
				Method: "sign_event",
				Params: []string{`not json`},
			},
			want: 0,
		},
		{
			name: "empty params",
			req: &NIP46Request{
				Method: "sign_event",
				Params: []string{},
			},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := signer.extractEventKind(tt.req)
			if got != tt.want {
				t.Errorf("extractEventKind() = %d, want %d", got, tt.want)
			}
		})
	}
}
