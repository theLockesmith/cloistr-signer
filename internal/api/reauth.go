package api

import (
	"net/http"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/auth"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// reauthenticate gates an irreversible or sensitive action (account
// deletion, key export) on a fresh password, an MFA code when MFA is on, and
// the username typed as confirmation. On failure it writes the response and
// returns ok=false. It shares sign-in's attempt limits, and a wrong password
// or MFA code counts toward the same lockout as at sign-in.
func (h *Handler) reauthenticate(w http.ResponseWriter, r *http.Request, userID, password, mfaCode, confirm, confirmMsg string) (*storage.User, bool) {
	user, err := h.storage.GetUser(r.Context(), userID)
	if err != nil {
		h.errorResponse(w, http.StatusNotFound, "user not found")
		return nil, false
	}
	guard := h.authGuard()
	attempt, ok := guard.Begin(r, user.Username)
	if !ok {
		h.errorResponse(w, http.StatusTooManyRequests, "too many attempts; try again later")
		return nil, false
	}
	defer attempt.End(r.Context())

	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		h.errorResponse(w, http.StatusForbidden, "account locked")
		return nil, false
	}
	if !auth.VerifyPassword(password, user.PasswordHash) {
		attempt.Fail(r.Context(), user, "password")
		h.errorResponse(w, http.StatusUnauthorized, "invalid credentials")
		return nil, false
	}
	if user.MFAEnabled {
		if mfaCode == "" {
			h.errorResponseCode(w, http.StatusUnauthorized, "mfa_required", "MFA code required")
			return nil, false
		}
		if !guard.CheckMFA(r.Context(), user, mfaCode) {
			attempt.Fail(r.Context(), user, "mfa")
			h.errorResponse(w, http.StatusUnauthorized, "invalid MFA code")
			return nil, false
		}
	}
	if confirm != user.Username {
		h.errorResponse(w, http.StatusBadRequest, confirmMsg)
		return nil, false
	}
	return user, true
}
