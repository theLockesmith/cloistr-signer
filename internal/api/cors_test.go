package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/config"
)

func TestIsAllowedOrigin(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{
			AllowedOrigins: []string{"https://staging.example.net"},
		},
	}

	tests := []struct {
		origin string
		want   bool
		desc   string
	}{
		// *.cloistr.xyz and apex
		{"https://signer.cloistr.xyz", true, "signer subdomain"},
		{"https://files.cloistr.xyz", true, "files subdomain"},
		{"https://cloistr.xyz", true, "apex domain"},
		{"https://relay.cloistr.xyz", true, "relay subdomain"},
		// localhost / loopback
		{"http://localhost:3000", true, "localhost with port"},
		{"http://localhost", true, "bare localhost"},
		{"http://127.0.0.1:5173", true, "loopback with port"},
		{"http://127.0.0.1", true, "bare loopback"},
		// Explicit allowlist
		{"https://staging.example.net", true, "explicit allowlist entry"},
		// Denied
		{"https://evil.com", false, "unrelated domain"},
		{"https://notcloistr.xyz", false, "suffix confusion — not .cloistr.xyz"},
		{"https://cloistr.xyz.evil.com", false, "subdomain of evil with cloistr.xyz in name"},
		{"https://xcloistr.xyz", false, "different TLD prefix"},
		{"", false, "empty origin (should not match)"},
	}

	for _, tt := range tests {
		got := isAllowedOrigin(tt.origin, cfg)
		if got != tt.want {
			t.Errorf("isAllowedOrigin(%q) = %v, want %v [%s]", tt.origin, got, tt.want, tt.desc)
		}
	}
}

func TestCORSMiddleware_SetHeaders(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{},
	}
	mw := CORSMiddleware(cfg)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := mw(next)

	// Allowed origin on an API path should get CORS headers.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req.Header.Set("Origin", "https://signer.cloistr.xyz")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rr.Code)
	}
	if v := rr.Header().Get("Access-Control-Allow-Origin"); v != "https://signer.cloistr.xyz" {
		t.Errorf("ACAO = %q, want origin reflected", v)
	}
	if v := rr.Header().Get("Access-Control-Allow-Credentials"); v != "true" {
		t.Errorf("ACAC = %q, want true", v)
	}
}

func TestCORSMiddleware_DeniedOrigin(t *testing.T) {
	cfg := &config.Config{}
	mw := CORSMiddleware(cfg)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := mw(next)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req.Header.Set("Origin", "https://evil.com")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Request is not blocked (CORS is advisory; the browser enforces it),
	// but ACAO must NOT be set for a disallowed origin.
	if v := rr.Header().Get("Access-Control-Allow-Origin"); v != "" {
		t.Errorf("ACAO for denied origin = %q, want empty", v)
	}
	if v := rr.Header().Get("Access-Control-Allow-Credentials"); v != "" {
		t.Errorf("ACAC for denied origin = %q, want empty", v)
	}
}

func TestCORSMiddleware_Preflight(t *testing.T) {
	cfg := &config.Config{}
	mw := CORSMiddleware(cfg)
	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	})
	handler := mw(next)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/users/login", nil)
	req.Header.Set("Origin", "https://signer.cloistr.xyz")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("preflight status = %d, want 204", rr.Code)
	}
	if reached {
		t.Error("preflight forwarded to handler, should have short-circuited")
	}
}

func TestCORSMiddleware_NonAPIPath(t *testing.T) {
	cfg := &config.Config{}
	mw := CORSMiddleware(cfg)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := mw(next)

	// NIP-05 and health paths must NOT get the CORS middleware headers.
	for _, path := range []string{"/.well-known/nostr.json", "/health", "/metrics"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Origin", "https://signer.cloistr.xyz")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		if v := rr.Header().Get("Access-Control-Allow-Origin"); v != "" {
			t.Errorf("path %s: unexpected ACAO header %q (should be untouched)", path, v)
		}
	}
}
