package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// A "yes, this is my account" answer at a Lightning login covers only the
// browser that gave it. The key's confirmed_at says that SOMEONE confirmed it,
// and an attacker who got the victim's wallet to sign one attacker-started
// login challenge can be that someone (review of !241). So the prompt is
// suppressed only by a marker cookie this browser received when it answered
// "yes", naming the key and the account it opens.
const (
	lightningConfirmCookiePrefix = "ln_confirmed_"
	lightningConfirmCookiePath   = "/api/v1/users/lightning"
	lightningConfirmMaxAge       = 400 * 24 * time.Hour // browsers cap cookie lifetime at 400 days
	lightningConfirmLabel        = "cloistr-signer lightning-confirm v1"
)

// lightningConfirmCookieName is per key, so one browser can hold markers for
// several wallets.
func lightningConfirmCookieName(lk *storage.LightningKey) string {
	sum := sha256.Sum256([]byte(lk.ID))
	return lightningConfirmCookiePrefix + hex.EncodeToString(sum[:8])
}

// lightningConfirmMAC binds the marker to the key, the account and the wallet
// key, under a key derived from the replica-shared JWT secret. ok is false
// when no secret is configured: then no marker is ever valid.
func (h *Handler) lightningConfirmMAC(lk *storage.LightningKey) (mac string, ok bool) {
	if h.authConfig == nil || h.authConfig.JWTSecret == "" {
		return "", false
	}
	kdf := hmac.New(sha256.New, []byte(h.authConfig.JWTSecret))
	kdf.Write([]byte(lightningConfirmLabel))
	m := hmac.New(sha256.New, kdf.Sum(nil))
	m.Write([]byte(lk.ID + "\x00" + lk.UserID + "\x00" + lk.LinkingKey))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil)), true
}

// lightningBrowserConfirmed reports whether this request carries a valid
// marker for lk opening lk.UserID.
func (h *Handler) lightningBrowserConfirmed(r *http.Request, lk *storage.LightningKey) bool {
	want, ok := h.lightningConfirmMAC(lk)
	if !ok {
		return false
	}
	c, err := r.Cookie(lightningConfirmCookieName(lk))
	if err != nil {
		return false
	}
	return hmac.Equal([]byte(c.Value), []byte(want))
}

// lightningConfirmCookie is the marker set when this browser answers "yes".
// Host-only, HttpOnly, and sent only to the Lightning endpoints.
func (h *Handler) lightningConfirmCookie(lk *storage.LightningKey) *http.Cookie {
	mac, ok := h.lightningConfirmMAC(lk)
	if !ok {
		return nil
	}
	return &http.Cookie{
		Name:     lightningConfirmCookieName(lk),
		Value:    mac,
		Path:     lightningConfirmCookiePath,
		MaxAge:   int(lightningConfirmMaxAge.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
}
