package api

import (
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/vault"
)

// vaultTokenLowThreshold marks the signer's Vault token as "low" in /health.
// It is a reporting threshold only: both replicas share one token, so failing
// readiness on it would pull every endpoint while signing still works.
const vaultTokenLowThreshold = 24 * time.Hour

type vaultTokenStatuser interface {
	TokenStatus() vault.TokenStatus
}

// vaultTokenHealth labels the token for /health and says whether the replica
// is ready. Only a token that is actually expired or refused fails readiness.
func vaultTokenHealth(src vaultTokenStatuser) (label string, ready bool) {
	if src == nil {
		return "", true
	}
	st := src.TokenStatus()
	switch {
	case st.Invalid:
		return "invalid", false
	case !st.Known:
		return "unknown", true
	case st.TTL < vaultTokenLowThreshold:
		return "low", true
	default:
		return "ok", true
	}
}
