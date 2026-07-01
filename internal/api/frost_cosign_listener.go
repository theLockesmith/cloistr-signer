// FROST P4e: browser cosign-listener registration.
//
// The SPA (signer admin UI) generates a session-scoped ephemeral Nostr
// keypair and POSTs the pubkey here. The signer stores it keyed by
// user_id so handleFrostUserSignEvent can look up the correct p-tag
// when publishing kind:24135 cosign requests.
//
// Storage lives on the Signer via RegisterCosignListener (in-memory);
// no cross-restart persistence in v1 (SPA re-registers on page load).

package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// FrostCosignListenerRegisterRequest is the SPA → signer request body.
type FrostCosignListenerRegisterRequest struct {
	EphemeralPubkey string `json:"ephemeral_pubkey"`
}

// handleFrostCosignListenerRegister accepts a POST from the SPA
// registering an ephemeral cosign-listener pubkey.
// Route: POST /api/v1/frost/cosign-listener/register
func (h *Handler) handleFrostCosignListenerRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}
	var req FrostCosignListenerRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	pk := req.EphemeralPubkey
	if len(pk) != 64 || !isLowerHex(pk) {
		h.errorResponse(w, http.StatusBadRequest, "ephemeral_pubkey must be a 64-char lowercase hex x-only pubkey")
		return
	}
	// Register on the signer's in-memory registry.
	if h.signer != nil {
		h.signer.RegisterCosignListener(claims.UserID, pk)
	}
	slog.Info("cosign listener registered", "user_id", claims.UserID, "pubkey", pk[:16]+"...")
	h.jsonResponse(w, http.StatusOK, map[string]string{"status": "registered"})
}

func isLowerHex(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}
