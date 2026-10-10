// Package authguard holds the protections every password-checking endpoint
// must share (sign-in, the legacy web sign-in, self-delete, key export):
// attempt limits, lockout on wrong passwords AND wrong MFA codes, and
// single-use backup codes. Keeping them in one place is the point: an
// endpoint that re-implements them is how the legacy web sign-in ended up
// with none.
package authguard

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/auth"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/config"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/ratelimit"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// Guard is cheap to build per request from a handler's fields.
type Guard struct {
	Store    storage.Storage
	Auth     *auth.Config
	Cfg      *config.Config
	Limiter  ratelimit.Limiter   // nil: no attempt limits (lockout still applies)
	IPHasher *ratelimit.IPHasher // nil: no per-IP limit
}

// Attempt is one credential check holding a reserved unit of each budget.
type Attempt struct {
	g      *Guard
	keys   []string
	failed bool
}

// Begin reserves one attempt against the per-account budget (the requested
// username, counted whether or not it exists, so a tripped limit reveals
// nothing) and the per-IP budget (client IP from the trusted proxy header
// only, as for recovery). Reserving up front is atomic, so a parallel burst
// cannot overshoot; End refunds the reservation unless the attempt failed, so
// only failed attempts spend the budget. Returns ok=false when a budget is
// spent; the caller answers 429. Like recovery, a limiter backend error lets
// the attempt through.
func (g *Guard) Begin(r *http.Request, username string) (*Attempt, bool) {
	a := &Attempt{g: g}
	if g.Limiter == nil {
		return a, true
	}
	ctx := r.Context()
	window := time.Duration(g.Cfg.Auth.AttemptWindowMinutes) * time.Minute
	if window <= 0 {
		window = 15 * time.Minute
	}
	type layer struct {
		key   string
		limit int
	}
	var layers []layer
	if n := g.Cfg.Auth.AttemptsPerAccount; n > 0 {
		layers = append(layers, layer{"auth:acct:" + ratelimit.HashKey(strings.ToLower(strings.TrimSpace(username))), n})
	}
	if n := g.Cfg.Auth.AttemptsPerIP; n > 0 && g.IPHasher != nil && g.Cfg.Recovery.TrustedProxyHeader != "" {
		raw := r.Header.Get(g.Cfg.Recovery.TrustedProxyHeader)
		if ip := strings.TrimSpace(strings.SplitN(raw, ",", 2)[0]); ip != "" {
			layers = append(layers, layer{"auth:ip:" + g.IPHasher.Key(ip), n})
		}
	}
	for _, l := range layers {
		allowed, err := g.Limiter.Allow(ctx, l.key, l.limit, window)
		if err != nil {
			slog.Warn("auth rate limiter error", "error", err)
		}
		a.keys = append(a.keys, l.key)
		if !allowed {
			a.release(ctx) // a refused attempt tests nothing; hand every unit back
			return nil, false
		}
	}
	return a, true
}

// Fail records a wrong password, wrong MFA code or unknown username. The
// attempt keeps its reservation, and for a known user it counts toward the
// account lockout: a wrong MFA code counts the same as a wrong password,
// otherwise anyone holding the password could guess codes without limit.
func (a *Attempt) Fail(ctx context.Context, user *storage.User, what string) {
	a.failed = true
	if user == nil {
		return
	}
	g := a.g
	if err := g.Store.IncrementFailedLogins(ctx, user.ID); err != nil {
		slog.Warn("failed to count failed authentication", "user_id", user.ID, "error", err)
	}
	if user.FailedLoginAttempts+1 >= g.Auth.MaxFailedAttempts {
		if err := g.Store.LockUser(ctx, user.ID, time.Now().Add(g.Auth.LockoutDuration)); err != nil {
			slog.Warn("failed to lock account", "user_id", user.ID, "error", err)
		}
		slog.Warn("account locked after failed authentication", "user_id", user.ID, "last_failure", what)
	}
}

// End refunds the reservation unless Fail was called. Call it with defer.
func (a *Attempt) End(ctx context.Context) {
	if !a.failed {
		a.release(ctx)
	}
}

func (a *Attempt) release(ctx context.Context) {
	for _, k := range a.keys {
		if err := a.g.Limiter.Release(ctx, k); err != nil {
			slog.Warn("auth rate limiter release error", "error", err)
		}
	}
	a.keys = nil
}

// CheckMFA accepts a valid TOTP code, or a backup code which it consumes and
// persists before accepting, so each backup code works once.
func (g *Guard) CheckMFA(ctx context.Context, user *storage.User, code string) bool {
	if auth.ValidateMFACode(user.MFASecret, code) {
		return true
	}
	idx := auth.ValidateBackupCode(code, user.BackupCodes)
	if idx < 0 {
		return false
	}
	// Remove exactly this code in storage, touching no other column: a full
	// UpdateUser from this request's copy of the user could overwrite a lockout
	// written meanwhile. A concurrent consume of the same code loses here.
	ok, err := g.Store.ConsumeBackupCode(ctx, user.ID, user.BackupCodes[idx])
	if err != nil {
		slog.Error("could not consume backup code; refusing it", "user_id", user.ID, "error", err)
		return false
	}
	if !ok {
		return false
	}
	user.BackupCodes = append(user.BackupCodes[:idx:idx], user.BackupCodes[idx+1:]...)
	user.BackupCodesUsed++
	return true
}
