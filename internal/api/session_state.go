package api

import (
	"errors"
	"net/http"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/auth"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/seal"
)

// Session states reported by GET /api/v1/users/session. Clients match on these
// strings, so they never change.
const (
	sessionStateLive      = "live"       // signed in, and the signing key can sign
	sessionStateKeyLocked = "key_locked" // signed in, but no replica holds the key
	sessionGoneCode       = "session_gone"
)

// SessionStateResponse is the 200 body of GET /api/v1/users/session.
type SessionStateResponse struct {
	State string `json:"state"` // live or key_locked
	// SigningPubkey is the key NIP-46 requests are signed with; empty when the
	// account has no key yet (state is then live: there is nothing to unlock).
	SigningPubkey string     `json:"signing_pubkey,omitempty"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"` // when this sign-in ends
	// NeedsSplitHalf: key_locked, but this sign-in holds a split seal. A browser
	// that still has the half cookie can POST /api/v1/users/session/unseal
	// instead of signing in again.
	NeedsSplitHalf bool `json:"needs_split_half,omitempty"`
}

// GET /api/v1/users/session answers "can this sign-in still sign?" without the
// client having to send a NIP-46 request and wait. (A NIP-46 request for a locked
// key gets no reply at all: the request is encrypted to that key, so the signer
// cannot read it, nor answer it.)
//
//	200 {"state":"live", "signing_pubkey", "expires_at"}
//	200 {"state":"key_locked", "signing_pubkey", "expires_at", "needs_split_half"?}
//	401 {"code":"session_gone", "reason":"missing|expired|ended|invalid", "error"}
//
// key_locked means sign in again (or unseal with the split half). session_gone
// means sign in again; reason is for logs, never for branching. The check
// recovers the key the same ways a signing request would (an unlock still in
// flight from the login, a stay-signed-in seal, the session's Vault token, or
// another replica holding it), so "live" is never a guess and key_locked is never
// reported for a key that a request could have unlocked.
func (h *Handler) handleSessionState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	token := requestToken(r)
	if token == "" {
		h.sessionGone(w, "missing")
		return
	}
	claims, err := auth.ValidateJWT(h.authConfig, token)
	if err != nil {
		reason := "invalid"
		if errors.Is(err, auth.ErrTokenExpired) {
			reason = "expired"
		}
		h.sessionGone(w, reason)
		return
	}
	if err := h.ensureSessionLive(r.Context(), claims); err != nil {
		h.sessionGone(w, "ended") // signed out, revoked, or expired server-side
		return
	}

	ctx := r.Context()
	resp := SessionStateResponse{State: sessionStateLive}
	if claims.SessionID != "" {
		if sess, err := h.storage.GetUserSession(ctx, claims.SessionID); err == nil {
			resp.ExpiresAt = &sess.ExpiresAt
		}
	}
	pubkey, ok := h.resolveSigningPubkey(ctx, claims.UserID)
	if !ok {
		h.jsonResponse(w, http.StatusOK, resp)
		return
	}
	resp.SigningPubkey = pubkey

	if !h.signer.IsKeyLoaded(pubkey) {
		h.keyLoads.wait(ctx, claims.UserID, keyUnlockWait)
	}
	if !h.signer.IsKeyLoaded(pubkey) {
		if key, err := h.storage.GetKeyByPubkey(ctx, pubkey); err == nil && key.OwnerID == claims.UserID {
			h.ensureNostrConnectKeyLoaded(ctx, claims.SessionID, claims.UserID, key)
		}
	}
	if !h.signer.IsKeyLoaded(pubkey) && !h.heldElsewhere(r, pubkey) {
		resp.State = sessionStateKeyLocked
		resp.NeedsSplitHalf = h.sessionHasSplitSeal(r, claims.SessionID)
	}
	h.jsonResponse(w, http.StatusOK, resp)
}

func (h *Handler) sessionGone(w http.ResponseWriter, reason string) {
	h.jsonResponse(w, http.StatusUnauthorized, map[string]string{
		"code":   sessionGoneCode,
		"reason": reason,
		"error":  "this sign-in has ended; sign in again",
	})
}

// heldElsewhere: another replica has recorded that it holds pubkey.
func (h *Handler) heldElsewhere(r *http.Request, pubkey string) bool {
	if h.forward == nil || h.forward.locator == nil {
		return false
	}
	_, ok := h.forward.locator.Lookup(r.Context(), pubkey)
	return ok
}

func (h *Handler) sessionHasSplitSeal(r *http.Request, sessionID string) bool {
	if sessionID == "" {
		return false
	}
	seals, err := h.storage.ListSessionSealsBySession(r.Context(), sessionID)
	if err != nil {
		return false
	}
	now := h.now()
	for _, sl := range seals {
		if sl.Mode == seal.ModeSplit && sl.ExpiresAt.After(now) {
			return true
		}
	}
	return false
}
