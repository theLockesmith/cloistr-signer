package api

import "git.aegis-hq.xyz/coldforge/cloistr-signer/internal/authguard"

// authGuard returns the shared attempt-limit, lockout and MFA checks used by
// sign-in, self-delete and key export (and, via the web package, the legacy
// web sign-in).
func (h *Handler) authGuard() *authguard.Guard {
	return &authguard.Guard{Store: h.storage, Auth: h.authConfig, Cfg: h.config, Limiter: h.limiter, IPHasher: h.ipHasher}
}
