package api

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/ratelimit"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// allowAuthAttempt applies the attempt limits shared by sign-in, self-delete
// and key export, before any password or MFA check: one budget per account
// (the requested username, counted whether or not it exists, so a tripped
// limit reveals nothing) and one per client IP. The IP comes only from the
// trusted proxy header, as for recovery; without it that layer is off. Like
// recovery, a limiter backend error lets the attempt through. Writes 429 and
// returns false when a budget is spent.
func (h *Handler) allowAuthAttempt(w http.ResponseWriter, r *http.Request, username string) bool {
	lim := h.limiter
	if lim == nil {
		return true
	}
	window := time.Duration(h.config.Auth.AttemptWindowMinutes) * time.Minute
	if window <= 0 {
		window = 15 * time.Minute
	}
	ctx := r.Context()

	if n := h.config.Auth.AttemptsPerAccount; n > 0 {
		key := "auth:acct:" + ratelimit.HashKey(strings.ToLower(strings.TrimSpace(username)))
		allowed, err := lim.Allow(ctx, key, n, window)
		if err != nil {
			slog.Warn("auth rate limiter error (per-account)", "error", err)
		}
		if !allowed {
			h.errorResponse(w, http.StatusTooManyRequests, "too many attempts; try again later")
			return false
		}
	}

	if n := h.config.Auth.AttemptsPerIP; n > 0 && h.ipHasher != nil && h.config.Recovery.TrustedProxyHeader != "" {
		raw := r.Header.Get(h.config.Recovery.TrustedProxyHeader)
		if ip := strings.TrimSpace(strings.SplitN(raw, ",", 2)[0]); ip != "" {
			allowed, err := lim.Allow(ctx, "auth:ip:"+h.ipHasher.Key(ip), n, window)
			if err != nil {
				slog.Warn("auth rate limiter error (per-IP)", "error", err)
			}
			if !allowed {
				h.errorResponse(w, http.StatusTooManyRequests, "too many attempts; try again later")
				return false
			}
		}
	}
	return true
}

// recordAuthFailure counts a wrong password or a wrong MFA code toward the
// account lockout. Both count the same: otherwise anyone holding the password
// could guess TOTP codes without limit.
func (h *Handler) recordAuthFailure(ctx context.Context, user *storage.User, what string) {
	h.storage.IncrementFailedLogins(ctx, user.ID)
	if user.FailedLoginAttempts+1 >= h.authConfig.MaxFailedAttempts {
		h.storage.LockUser(ctx, user.ID, time.Now().Add(h.authConfig.LockoutDuration))
		slog.Warn("account locked after failed authentication", "user_id", user.ID, "last_failure", what)
	}
}
