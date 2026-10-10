package api

import (
	"log/slog"
	"net/http"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/auth"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// reauthenticate gates an irreversible or sensitive action (account
// deletion, key export) on a fresh password, an MFA code when MFA is on, and
// the username typed as confirmation. On failure it writes the response and
// returns ok=false. A wrong password counts as a failed login and can lock
// the account, exactly as at sign-in.
func (h *Handler) reauthenticate(w http.ResponseWriter, r *http.Request, userID, password, mfaCode, confirm, confirmMsg string) (*storage.User, bool) {
	user, err := h.storage.GetUser(r.Context(), userID)
	if err != nil {
		h.errorResponse(w, http.StatusNotFound, "user not found")
		return nil, false
	}
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		h.errorResponse(w, http.StatusForbidden, "account locked")
		return nil, false
	}
	if !auth.VerifyPassword(password, user.PasswordHash) {
		h.storage.IncrementFailedLogins(r.Context(), user.ID)
		if user.FailedLoginAttempts+1 >= h.authConfig.MaxFailedAttempts {
			h.storage.LockUser(r.Context(), user.ID, time.Now().Add(h.authConfig.LockoutDuration))
			slog.Warn("account locked due to failed password at re-authentication", "user_id", user.ID)
		}
		h.errorResponse(w, http.StatusUnauthorized, "invalid credentials")
		return nil, false
	}
	if user.MFAEnabled {
		if mfaCode == "" {
			h.errorResponseCode(w, http.StatusUnauthorized, "mfa_required", "MFA code required")
			return nil, false
		}
		if !auth.ValidateMFACode(user.MFASecret, mfaCode) {
			idx := auth.ValidateBackupCode(mfaCode, user.BackupCodes)
			if idx < 0 {
				h.errorResponse(w, http.StatusUnauthorized, "invalid MFA code")
				return nil, false
			}
			user.BackupCodes = append(user.BackupCodes[:idx], user.BackupCodes[idx+1:]...)
			user.BackupCodesUsed++
			_ = h.storage.UpdateUser(r.Context(), user)
		}
	}
	if confirm != user.Username {
		h.errorResponse(w, http.StatusBadRequest, confirmMsg)
		return nil, false
	}
	return user, true
}
