package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/vault"
)

type fakeTokenStatus struct{ st vault.TokenStatus }

func (f fakeTokenStatus) TokenStatus() vault.TokenStatus { return f.st }

func TestVaultTokenHealth(t *testing.T) {
	cases := []struct {
		name      string
		src       vaultTokenStatuser
		wantLabel string
		wantReady bool
	}{
		{"vault disabled", nil, "", true},
		{"not yet known", fakeTokenStatus{vault.TokenStatus{}}, "unknown", true},
		{"healthy", fakeTokenStatus{vault.TokenStatus{Known: true, TTL: 30 * 24 * time.Hour}}, "ok", true},
		// A shared token going low must not pull every endpoint while signing still works.
		{"low but alive stays ready", fakeTokenStatus{vault.TokenStatus{Known: true, TTL: 23 * time.Hour}}, "low", true},
		{"expired", fakeTokenStatus{vault.TokenStatus{Known: true, TTL: -time.Second, Invalid: true}}, "invalid", false},
		{"refused by vault", fakeTokenStatus{vault.TokenStatus{Invalid: true}}, "invalid", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			label, ready := vaultTokenHealth(tc.src)
			if label != tc.wantLabel || ready != tc.wantReady {
				t.Fatalf("vaultTokenHealth = (%q, %v), want (%q, %v)", label, ready, tc.wantLabel, tc.wantReady)
			}
		})
	}
}

func TestHandleHealth_ReportsVaultToken(t *testing.T) {
	h, _ := testHandler(t)
	h.vaultToken = fakeTokenStatus{vault.TokenStatus{Known: true, TTL: 2 * time.Hour}}

	rr := httptest.NewRecorder()
	h.handleHealth(rr, httptest.NewRequest(http.MethodGet, "/health", nil))

	var resp HealthResponse
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if rr.Code != http.StatusOK || resp.VaultToken != "low" {
		t.Fatalf("status=%d vault_token=%q, want 200 and \"low\"", rr.Code, resp.VaultToken)
	}
}

func TestHandleReady_FailsOnInvalidVaultToken(t *testing.T) {
	h, _ := testHandler(t)
	h.vaultToken = fakeTokenStatus{vault.TokenStatus{Invalid: true}}

	rr := httptest.NewRecorder()
	h.handleReady(rr, httptest.NewRequest(http.MethodGet, "/health/ready", nil))

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 for an invalid Vault token", rr.Code)
	}
}
