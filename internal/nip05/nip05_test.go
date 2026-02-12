package nip05

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewHandler(t *testing.T) {
	h := NewHandler()
	if h == nil {
		t.Fatal("NewHandler() returned nil")
	}
	if h.names == nil {
		t.Error("NewHandler().names is nil")
	}
	if h.relays == nil {
		t.Error("NewHandler().relays is nil")
	}
}

func TestHandler_AddName(t *testing.T) {
	h := NewHandler()
	h.AddName("alice", "pubkey123")

	if h.names["alice"] != "pubkey123" {
		t.Errorf("names[alice] = %q, want %q", h.names["alice"], "pubkey123")
	}
}

func TestHandler_AddRelays(t *testing.T) {
	h := NewHandler()
	relays := []string{"wss://relay1.example.com", "wss://relay2.example.com"}
	h.AddRelays("pubkey123", relays)

	if len(h.relays["pubkey123"]) != 2 {
		t.Errorf("relays[pubkey123] length = %d, want 2", len(h.relays["pubkey123"]))
	}
}

func TestHandler_RemoveName(t *testing.T) {
	h := NewHandler()
	h.AddName("alice", "pubkey123")
	h.RemoveName("alice")

	if _, exists := h.names["alice"]; exists {
		t.Error("alice should be removed")
	}
}

func TestHandler_ServeHTTP(t *testing.T) {
	h := NewHandler()
	h.AddName("alice", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	h.AddName("bob", "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210")
	h.AddRelays("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", []string{"wss://relay.example.com"})

	t.Run("get all names", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/nostr.json", nil)
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}

		if w.Header().Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q, want %q", w.Header().Get("Content-Type"), "application/json")
		}

		if w.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Errorf("CORS header missing")
		}

		var resp WellKnownResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if len(resp.Names) != 2 {
			t.Errorf("names length = %d, want 2", len(resp.Names))
		}
	})

	t.Run("get specific name", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/nostr.json?name=alice", nil)
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}

		var resp WellKnownResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if len(resp.Names) != 1 {
			t.Errorf("names length = %d, want 1", len(resp.Names))
		}
		if resp.Names["alice"] == "" {
			t.Error("alice should be in response")
		}
		if len(resp.Relays) != 1 {
			t.Errorf("relays length = %d, want 1", len(resp.Relays))
		}
	})

	t.Run("get nonexistent name", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/.well-known/nostr.json?name=charlie", nil)
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
		}

		var resp WellKnownResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if len(resp.Names) != 0 {
			t.Errorf("names should be empty for nonexistent name")
		}
	})

	t.Run("method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/.well-known/nostr.json", nil)
		w := httptest.NewRecorder()

		h.ServeHTTP(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
		}
	})
}

func TestWellKnownResponse_JSON(t *testing.T) {
	resp := WellKnownResponse{
		Names: map[string]string{
			"alice": "pubkey123",
		},
		Relays: map[string][]string{
			"pubkey123": {"wss://relay1.com", "wss://relay2.com"},
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var decoded WellKnownResponse
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if decoded.Names["alice"] != "pubkey123" {
		t.Errorf("decoded.Names[alice] = %q, want %q", decoded.Names["alice"], "pubkey123")
	}

	if len(decoded.Relays["pubkey123"]) != 2 {
		t.Errorf("decoded.Relays[pubkey123] length = %d, want 2", len(decoded.Relays["pubkey123"]))
	}
}

func TestVerificationResult_JSON(t *testing.T) {
	result := VerificationResult{
		Valid:  true,
		Pubkey: "pubkey123",
		Relays: []string{"wss://relay.com"},
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	var decoded VerificationResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}

	if decoded.Valid != true {
		t.Error("decoded.Valid should be true")
	}
	if decoded.Pubkey != "pubkey123" {
		t.Errorf("decoded.Pubkey = %q, want %q", decoded.Pubkey, "pubkey123")
	}
}
