package api

import (
	"net/http"
	"strings"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/config"
)

// CORSMiddleware wraps the HTTP handler with credentialed CORS for
// cross-subdomain SSO. Only /api/v1/* routes are gated; public routes such as
// /.well-known/nostr.json and /metrics are left untouched (they set their own
// Access-Control-Allow-Origin: * independently).
//
// Origin allowlist: *.cloistr.xyz (prod/staging), localhost and 127.0.0.1 (dev),
// plus any explicit entries in cfg.Auth.AllowedOrigins.
//
// CSRF: All state-changing API endpoints require Content-Type: application/json,
// which is a non-simple header and forces a CORS preflight. The preflight must
// pass this origin check before the browser sends credentials. SameSite=Lax on
// the cookie provides defence-in-depth for same-origin navigation flows. No
// separate CSRF token scheme is needed.
func CORSMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Only apply credentialed CORS to API routes.
			if !strings.HasPrefix(r.URL.Path, "/api/v1/") {
				next.ServeHTTP(w, r)
				return
			}

			origin := r.Header.Get("Origin")
			if origin != "" && isAllowedOrigin(origin, cfg) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-Requested-With")
				w.Header().Set("Access-Control-Max-Age", "86400")
				// Vary: Origin so that caches don't return a response with the
				// wrong ACAO header to a different origin.
				w.Header().Add("Vary", "Origin")
			}

			// Handle OPTIONS preflight without forwarding to the actual handler.
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// isAllowedOrigin reports whether the given origin (full scheme+host[:port]
// string as sent in the Origin header) may use credentialed CORS against the
// signer API.
//
// Allowed:
//   - https://cloistr.xyz and https://*.cloistr.xyz (prod and staging)
//   - http://localhost[:<port>] and http://127.0.0.1[:<port>] (local dev)
//   - Any entry in cfg.Auth.AllowedOrigins (escape hatch)
//
// NEVER allowed when this function returns false: the middleware will NOT set
// Access-Control-Allow-Origin, so the browser blocks the credentialed request.
func isAllowedOrigin(origin string, cfg *config.Config) bool {
	// Extract host (without scheme and port) for suffix checks.
	host := origin
	if idx := strings.Index(host, "://"); idx >= 0 {
		host = host[idx+3:]
	}
	// Strip port — but be careful not to clip IPv6 brackets.
	if !strings.HasPrefix(host, "[") {
		if idx := strings.LastIndex(host, ":"); idx >= 0 {
			host = host[:idx]
		}
	}

	// *.cloistr.xyz and apex cloistr.xyz
	if host == "cloistr.xyz" || strings.HasSuffix(host, ".cloistr.xyz") {
		return true
	}

	// localhost and loopback (any port) for local development
	if host == "localhost" || host == "127.0.0.1" {
		return true
	}

	// Explicit per-deployment allowlist (e.g. staging on a non-cloistr.xyz domain)
	for _, allowed := range cfg.Auth.AllowedOrigins {
		if origin == allowed {
			return true
		}
	}

	return false
}
