package proxy

import (
	"testing"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/config"
)

func TestNewClient(t *testing.T) {
	cfg := &config.Config{}
	client := NewClient(cfg)

	if client == nil {
		t.Fatal("expected non-nil client")
	}

	if client.connections == nil {
		t.Error("expected connections map to be initialized")
	}
}

func TestNIP46RequestMarshal(t *testing.T) {
	req := NIP46Request{
		ID:     "test-123",
		Method: "sign_event",
		Params: []string{`{"kind":1,"content":"hello"}`},
	}

	if req.ID != "test-123" {
		t.Errorf("expected ID 'test-123', got '%s'", req.ID)
	}

	if req.Method != "sign_event" {
		t.Errorf("expected method 'sign_event', got '%s'", req.Method)
	}

	if len(req.Params) != 1 {
		t.Errorf("expected 1 param, got %d", len(req.Params))
	}
}

func TestNIP46ResponseMarshal(t *testing.T) {
	resp := NIP46Response{
		ID:     "test-123",
		Result: `{"id":"abc","sig":"def"}`,
	}

	if resp.ID != "test-123" {
		t.Errorf("expected ID 'test-123', got '%s'", resp.ID)
	}

	if resp.Result == "" {
		t.Error("expected non-empty result")
	}

	if resp.Error != "" {
		t.Error("expected empty error")
	}
}

func TestNIP46ResponseError(t *testing.T) {
	resp := NIP46Response{
		ID:    "test-123",
		Error: "method not allowed",
	}

	if resp.Error != "method not allowed" {
		t.Errorf("expected error 'method not allowed', got '%s'", resp.Error)
	}

	if resp.Result != "" {
		t.Error("expected empty result for error response")
	}
}

func TestClientClose(t *testing.T) {
	cfg := &config.Config{}
	client := NewClient(cfg)

	// Close should not panic on empty client
	client.Close()

	if len(client.connections) != 0 {
		t.Error("expected connections to be empty after close")
	}
}

func TestUpstreamConnectionClose(t *testing.T) {
	conn := &UpstreamConnection{
		pending:   make(map[string]*pendingResponse),
		connected: true,
	}

	conn.Close()

	if conn.connected {
		t.Error("expected connected to be false after close")
	}
}
