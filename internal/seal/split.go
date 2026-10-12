package seal

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"net/http"
)

// Split sealing (strict, opt-in per user). The sealing key is HKDF(serverHalf ||
// browserHalf). The DB row holds the server half and the ciphertext; the browser half
// is handed to the user's browser once, at sign-in, and never stored server-side.
// After a deploy, Cloistr apps hand the browser half back (POST
// /api/v1/users/session/unseal) and the key is restored; outside apps meanwhile get
// key_locked, which is the price of "neither the DB nor the server alone can unseal".
// Needs no Vault and no key file.
//
// Blob format: "sp1" || serverHalf[32] || nonce || ct.

// The browser half's cookie. Named here so the API and the web UI clear the same one.
const (
	SplitHalfCookieName = "cloistr_seal_half"
	SplitHalfCookiePath = "/api/v1/users/session/unseal"
)

// SplitHalfLen is the length of each half in bytes.
const SplitHalfLen = 32

var splitPrefix = []byte("sp1")

const splitPurpose = "split"

// NewSplitHalf returns a fresh random browser half. One half can cover all the keys
// sealed for one sign-in; each seal still gets its own server half.
func NewSplitHalf() ([]byte, error) {
	h := make([]byte, SplitHalfLen)
	if _, err := rand.Read(h); err != nil {
		return nil, err
	}
	return h, nil
}

// SplitSeal seals plaintext under a fresh server half combined with browserHalf and
// returns the DB blob. The browser half is not in the blob.
func SplitSeal(plaintext, browserHalf []byte, b Binding) ([]byte, error) {
	if err := b.validate(); err != nil {
		return nil, err
	}
	var zero [SplitHalfLen]byte
	if len(browserHalf) != SplitHalfLen || subtle.ConstantTimeCompare(browserHalf, zero[:]) == 1 {
		return nil, ErrOpen
	}
	server := make([]byte, SplitHalfLen)
	if _, err := rand.Read(server); err != nil {
		return nil, err
	}
	body, err := aeadSeal(splitIKM(server, browserHalf), splitPurpose, plaintext, b)
	if err != nil {
		return nil, err
	}
	blob := make([]byte, 0, len(splitPrefix)+SplitHalfLen+len(body))
	blob = append(blob, splitPrefix...)
	blob = append(blob, server...)
	return append(blob, body...), nil
}

// SplitOpen opens a split seal with the browser half.
func SplitOpen(blob, browserHalf []byte, b Binding) ([]byte, error) {
	if err := b.validate(); err != nil {
		return nil, err
	}
	n := len(splitPrefix) + SplitHalfLen
	if len(browserHalf) != SplitHalfLen || len(blob) < n || !bytes.HasPrefix(blob, splitPrefix) {
		return nil, ErrOpen
	}
	var zero [SplitHalfLen]byte
	if subtle.ConstantTimeCompare(browserHalf, zero[:]) == 1 {
		return nil, ErrOpen
	}
	return aeadOpen(splitIKM(blob[len(splitPrefix):n], browserHalf), splitPurpose, blob[n:], b)
}

func splitIKM(server, browser []byte) []byte {
	ikm := make([]byte, 0, 2*SplitHalfLen)
	return append(append(ikm, server...), browser...)
}

// ClearSplitHalfCookie expires the browser half's cookie.
func ClearSplitHalfCookie() *http.Cookie {
	return &http.Cookie{Name: SplitHalfCookieName, Value: "", Path: SplitHalfCookiePath, MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode}
}
