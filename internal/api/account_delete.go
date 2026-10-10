package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/auth"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/vault"
)

// Account deletion: one shared path for self-service (DELETE /api/v1/users/me)
// and admin (DELETE /api/v1/admin/users/{id}) deletion. Leaving with
// everything is the product's founding promise, so deletion removes the
// account, its keys and grants, and the user's Vault objects.
//
// Order is chosen so a failure part-way never leaves a usable credential:
//  1. revoke sessions and grants, evict keys from this replica's memory;
//  2. delete the Vault login (userpass) and ACL policy;
//  3. delete the account row (keys, consents etc. cascade);
//  4. delete the Vault transit key that decrypts the user's key ciphertext.
//
// Steps 1-3 abort on failure and return an error; every step is idempotent, so
// the caller simply retries. Step 4 failing (today: the signer's Vault policy
// may not delete transit keys) does not fail the deletion: the key is recorded
// as retained by user ID and the sweep finishes it later.
//
// Limitation: another replica may still hold the user's key in memory. It is
// unreachable once the account, sessions and grants are gone, and is evicted
// when that replica restarts.

// accountVault is the subset of the Vault client account deletion needs.
type accountVault interface {
	DeleteUserpassAccount(ctx context.Context, username string) error
	DeletePolicy(ctx context.Context, name string) error
	DeleteTransitKey(ctx context.Context, name string) error
}

// retainedSweepEvery is how often the server retries retained deletions.
const retainedSweepEvery = time.Hour

type accountDeleteResult struct {
	Retained []string `json:"retained,omitempty"`
}

func transitObject(userID string) string {
	return "transit/keys/" + vault.UserTransitKeyName(userID)
}

func (h *Handler) deleteAccount(ctx context.Context, userID string) (accountDeleteResult, error) {
	var res accountDeleteResult

	// 1. Sessions, grants, in-memory keys.
	if err := h.storage.DeleteUserSessions(ctx, userID); err != nil {
		return res, fmt.Errorf("revoke sessions: %w", err)
	}
	keys, err := h.storage.ListKeys(ctx, userID)
	if err != nil {
		return res, fmt.Errorf("list keys: %w", err)
	}
	for _, k := range keys {
		perms, err := h.storage.ListPermissions(ctx, k.Pubkey)
		if err != nil {
			return res, fmt.Errorf("list grants: %w", err)
		}
		for _, p := range perms {
			if err := h.storage.DeletePermission(ctx, k.Pubkey, p.UserPubkey); err != nil {
				return res, fmt.Errorf("revoke grant: %w", err)
			}
		}
		h.signer.UnregisterKey(k.Pubkey)
		h.forgetKeyLocation(ctx, k.Pubkey)
	}
	consents, err := h.storage.ListAppConsents(ctx, userID)
	if err != nil {
		return res, fmt.Errorf("list app consents: %w", err)
	}
	for _, c := range consents {
		if err := h.storage.RevokeAppConsent(ctx, userID, c.AppID); err != nil && !errors.Is(err, storage.ErrConsentNotFound) {
			return res, fmt.Errorf("revoke app consent: %w", err)
		}
	}

	// 2. Vault login and policy.
	if h.accountVault != nil {
		if err := h.accountVault.DeleteUserpassAccount(ctx, userID); err != nil {
			return res, fmt.Errorf("delete vault login: %w", err)
		}
		if err := h.accountVault.DeletePolicy(ctx, vault.UserPolicyName(userID)); err != nil {
			return res, fmt.Errorf("delete vault policy: %w", err)
		}
	}

	// 3. Keys, then the account row. Keys are deleted explicitly rather than
	// relying on the Postgres cascade, so every backend behaves the same.
	for _, k := range keys {
		if err := h.storage.DeleteKey(ctx, k.ID); err != nil && !errors.Is(err, storage.ErrKeyNotFound) {
			return res, fmt.Errorf("delete key: %w", err)
		}
	}
	if err := h.storage.DeleteUser(ctx, userID); err != nil && !errors.Is(err, storage.ErrUserNotFound) {
		return res, fmt.Errorf("delete account: %w", err)
	}

	// 4. Transit key: best effort, retained for the sweep on failure.
	if h.accountVault != nil {
		obj := transitObject(userID)
		if err := h.accountVault.DeleteTransitKey(ctx, vault.UserTransitKeyName(userID)); err != nil {
			slog.Warn("account deleted; vault transit key retained for retry", "user_id", userID, "error", err)
			if rerr := h.storage.RecordRetainedDeletion(ctx, userID, obj, err.Error()); rerr != nil {
				slog.Error("failed to record retained deletion", "user_id", userID, "object", obj, "error", rerr)
			}
			res.Retained = append(res.Retained, obj)
		} else {
			_ = h.storage.ClearRetainedDeletion(ctx, userID, obj)
		}
	}

	slog.Info("account deleted", "user_id", userID, "keys", len(keys), "retained", len(res.Retained))
	return res, nil
}

// sweepRetainedDeletions retries every retained deletion and returns how many
// it cleared.
func (h *Handler) sweepRetainedDeletions(ctx context.Context) int {
	if h.accountVault == nil {
		return 0
	}
	pending, err := h.storage.ListRetainedDeletions(ctx)
	if err != nil {
		slog.Warn("retained-deletion sweep: list failed", "error", err)
		return 0
	}
	cleared := 0
	for _, r := range pending {
		if r.Object != transitObject(r.UserID) {
			continue
		}
		if err := h.accountVault.DeleteTransitKey(ctx, vault.UserTransitKeyName(r.UserID)); err != nil {
			_ = h.storage.RecordRetainedDeletion(ctx, r.UserID, r.Object, err.Error())
			continue
		}
		if err := h.storage.ClearRetainedDeletion(ctx, r.UserID, r.Object); err == nil {
			cleared++
			slog.Info("retained deletion completed", "user_id", r.UserID, "object", r.Object)
		}
	}
	return cleared
}

// RunRetainedDeletionSweep retries retained deletions every retainedSweepEvery
// until ctx is done.
func (h *Handler) RunRetainedDeletionSweep(ctx context.Context) {
	t := time.NewTicker(retainedSweepEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.sweepRetainedDeletions(ctx)
		}
	}
}

// selfDeleteRequest is the body of DELETE /api/v1/users/me.
type selfDeleteRequest struct {
	Password string `json:"password"`
	MFACode  string `json:"mfa_code,omitempty"`
	Confirm  string `json:"confirm"` // must equal the username exactly
}

// handleSelfDelete deletes the caller's own account after re-verifying the
// password (counted toward lockout), the MFA code when MFA is enabled, and a
// typed confirmation equal to the username.
func (h *Handler) handleSelfDelete(w http.ResponseWriter, r *http.Request, claims *auth.JWTClaims) {
	var req selfDeleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	user, err := h.storage.GetUser(r.Context(), claims.UserID)
	if err != nil {
		h.errorResponse(w, http.StatusNotFound, "user not found")
		return
	}
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		h.errorResponse(w, http.StatusForbidden, "account locked")
		return
	}
	if !auth.VerifyPassword(req.Password, user.PasswordHash) {
		h.storage.IncrementFailedLogins(r.Context(), user.ID)
		if user.FailedLoginAttempts+1 >= h.authConfig.MaxFailedAttempts {
			h.storage.LockUser(r.Context(), user.ID, time.Now().Add(h.authConfig.LockoutDuration))
			slog.Warn("account locked due to failed password at account deletion", "user_id", user.ID)
		}
		h.errorResponse(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if user.MFAEnabled {
		if req.MFACode == "" {
			h.errorResponseCode(w, http.StatusUnauthorized, "mfa_required", "MFA code required")
			return
		}
		if !auth.ValidateMFACode(user.MFASecret, req.MFACode) {
			idx := auth.ValidateBackupCode(req.MFACode, user.BackupCodes)
			if idx < 0 {
				h.errorResponse(w, http.StatusUnauthorized, "invalid MFA code")
				return
			}
			user.BackupCodes = append(user.BackupCodes[:idx], user.BackupCodes[idx+1:]...)
			user.BackupCodesUsed++
			_ = h.storage.UpdateUser(r.Context(), user)
		}
	}
	if req.Confirm != user.Username {
		h.errorResponse(w, http.StatusBadRequest, "type your username exactly to confirm deletion")
		return
	}

	res, err := h.deleteAccount(r.Context(), user.ID)
	if err != nil {
		slog.Error("self-service account deletion incomplete", "user_id", user.ID, "error", err)
		h.errorResponse(w, http.StatusInternalServerError, "account deletion did not complete; please try again")
		return
	}
	h.jsonResponse(w, http.StatusOK, map[string]interface{}{"deleted": true, "retained": res.Retained})
}

// handleAdminDeleteUser deletes another user's account (admin only).
func (h *Handler) handleAdminDeleteUser(w http.ResponseWriter, r *http.Request, userID string) {
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	if !h.isAdminClaims(r.Context(), claims) {
		h.errorResponse(w, http.StatusForbidden, "admin access required")
		return
	}
	if _, err := h.storage.GetUser(r.Context(), userID); err != nil {
		h.errorResponse(w, http.StatusNotFound, "user not found")
		return
	}
	res, err := h.deleteAccount(r.Context(), userID)
	if err != nil {
		slog.Error("admin account deletion incomplete", "user_id", userID, "admin", claims.UserID, "error", err)
		h.errorResponse(w, http.StatusInternalServerError, "account deletion did not complete; please try again")
		return
	}
	slog.Info("admin deleted account", "user_id", userID, "admin", claims.UserID)
	h.jsonResponse(w, http.StatusOK, map[string]interface{}{"deleted": true, "retained": res.Retained})
}

// isAdminClaims reports whether the caller is an admin (config-based admin
// usernames carry the "admin:" prefix; otherwise the stored role decides).
func (h *Handler) isAdminClaims(ctx context.Context, claims *auth.JWTClaims) bool {
	if len(claims.Username) > 6 && claims.Username[:6] == "admin:" {
		return true
	}
	user, err := h.storage.GetUser(ctx, claims.UserID)
	return err == nil && user.IsAdmin()
}
