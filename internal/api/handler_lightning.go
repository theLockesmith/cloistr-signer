package api

// LNURL-auth (LUD-04) login and linking-key management endpoints.
//
// Challenge store design: in-memory map with 10-minute TTL (matches vault
// implementation). A pod restart invalidates in-flight sessions, which is
// acceptable given the 10-minute window. Sessions are cleaned up lazily on
// read (expiry check) and explicitly on successful status-poll (replay guard).
//
// Flow (login):
//   1. Client: POST /api/v1/users/lightning/challenge → {lnurl, k1, session_id}
//   2. Client: display lnurl as QR code
//   3. Wallet: GET /api/v1/lnurl-auth/callback?tag=login&k1=…&sig=…&key=…
//   4. Client: polls GET /api/v1/users/lightning/status?session_id=… until success
//
// Flow (linking):
//   Same as login but step 1 uses POST /api/v1/users/lightning/link/challenge
//   (auth required). The callback associates the linking key with the user
//   instead of resolving an existing account.

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/google/uuid"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/auth"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// ---- Challenge store ----

var (
	lightningSessionsMu sync.RWMutex
	lightningSessions   = make(map[string]*lightningPendingSession)
)

type lightningPendingSession struct {
	SessionID     string
	K1            string
	Status        string // "pending" | "authenticated"
	UserID        string // populated after wallet callback succeeds (login mode)
	BoundUserID   string // for link sessions: the authenticated user to link to
	IsLinkSession bool
	ExpiresAt     time.Time
	CreatedAt     time.Time
}

// ---- Helpers ----

// generateLightningChallenge generates a new k1 + session_id and builds the
// bech32-encoded lnurl string for the given domain.
func (h *Handler) generateLightningChallenge(boundUserID string, isLink bool) (lnurl, k1, sessionID string, err error) {
	// 32-byte random k1 per LUD-04
	k1Bytes := make([]byte, 32)
	if _, err = rand.Read(k1Bytes); err != nil {
		return "", "", "", fmt.Errorf("generate k1: %w", err)
	}
	k1 = hex.EncodeToString(k1Bytes)

	sessionID, err = passkeySessionID()
	if err != nil {
		return "", "", "", fmt.Errorf("generate session_id: %w", err)
	}

	domain := h.config.Lightning.Domain
	callbackURL := fmt.Sprintf("https://%s/api/v1/lnurl-auth/callback?tag=login&k1=%s", domain, k1)

	encoded, err := bech32.EncodeFromBase256("lnurl", []byte(callbackURL))
	if err != nil {
		return "", "", "", fmt.Errorf("bech32 encode lnurl: %w", err)
	}
	lnurl = strings.ToUpper(encoded)

	lightningSessionsMu.Lock()
	lightningSessions[k1] = &lightningPendingSession{
		SessionID:     sessionID,
		K1:            k1,
		Status:        "pending",
		BoundUserID:   boundUserID,
		IsLinkSession: isLink,
		ExpiresAt:     time.Now().Add(10 * time.Minute),
		CreatedAt:     time.Now(),
	}
	lightningSessionsMu.Unlock()

	return lnurl, k1, sessionID, nil
}

// verifyLNURLAuthSignature verifies an LNURL-auth compact secp256k1 ECDSA
// signature per LUD-04:
//   - message: sha256(k1_bytes)
//   - sig: 64-byte compact R||S
//   - key: 33-byte compressed secp256k1 pubkey
func verifyLNURLAuthSignature(k1Hex, sigHex, keyHex string) (bool, error) {
	k1Bytes, err := hex.DecodeString(k1Hex)
	if err != nil {
		return false, fmt.Errorf("invalid k1 hex: %w", err)
	}
	if len(k1Bytes) != 32 {
		return false, fmt.Errorf("k1 must be 32 bytes, got %d", len(k1Bytes))
	}

	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return false, fmt.Errorf("invalid signature hex: %w", err)
	}

	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return false, fmt.Errorf("invalid linking key hex: %w", err)
	}
	pubKey, err := secp256k1.ParsePubKey(keyBytes)
	if err != nil {
		return false, fmt.Errorf("parse linking key: %w", err)
	}

	msgHash := sha256.Sum256(k1Bytes)

	// Real-world LNURL-auth wallets (Alby, Zeus, Phoenix, …) send DER-encoded
	// ECDSA signatures per LUD-04 — that's the de-facto standard. Try DER first,
	// then fall back to 64-byte compact R||S for clients that send the raw form.
	if sig, derErr := ecdsa.ParseDERSignature(sigBytes); derErr == nil {
		return sig.Verify(msgHash[:], pubKey), nil
	}
	if len(sigBytes) == 64 {
		var r, s secp256k1.ModNScalar
		r.SetByteSlice(sigBytes[:32])
		s.SetByteSlice(sigBytes[32:])
		return ecdsa.NewSignature(&r, &s).Verify(msgHash[:], pubKey), nil
	}
	return false, fmt.Errorf("unrecognized signature format (len %d; expected DER or 64-byte compact)", len(sigBytes))
}

// lnurlError writes the LUD-04 error response format.
func lnurlError(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // LUD-04 always 200, error indicated in body
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "ERROR",
		"reason": reason,
	})
}

// lnurlOK writes the LUD-04 success response.
func lnurlOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "OK"})
}

// findSessionByID returns the pending session matching sessionID, or nil.
// Caller must not hold lightningSessionsMu.
func findSessionByID(sessionID string) *lightningPendingSession {
	lightningSessionsMu.RLock()
	defer lightningSessionsMu.RUnlock()
	for _, s := range lightningSessions {
		if s.SessionID == sessionID {
			return s
		}
	}
	return nil
}

// ---- Handlers ----

// POST /api/v1/users/lightning/challenge
// NO AUTH. Generates a new LUD-04 k1 challenge and returns the bech32 lnurl.
func (h *Handler) handleLightningChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	lnurlStr, k1, sessionID, err := h.generateLightningChallenge("", false)
	if err != nil {
		slog.Error("lightning challenge generation failed", "error", err)
		h.errorResponse(w, http.StatusInternalServerError, "failed to generate challenge")
		return
	}

	h.jsonResponse(w, http.StatusOK, map[string]string{
		"lnurl":      lnurlStr,
		"k1":         k1,
		"session_id": sessionID,
	})
}

// GET /api/v1/lnurl-auth/callback?tag=login&k1=&sig=&key=
// NO AUTH. Called by the wallet after the user scans the QR code.
func (h *Handler) handleLNURLAuthCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		lnurlError(w, "method not allowed")
		return
	}

	q := r.URL.Query()
	k1 := q.Get("k1")
	sig := q.Get("sig")
	key := q.Get("key")

	if k1 == "" || sig == "" || key == "" {
		lnurlError(w, "k1, sig, and key are required")
		return
	}

	lightningSessionsMu.RLock()
	session, ok := lightningSessions[k1]
	lightningSessionsMu.RUnlock()

	if !ok {
		lnurlError(w, "unknown or expired k1 challenge")
		return
	}
	if time.Now().After(session.ExpiresAt) {
		lightningSessionsMu.Lock()
		delete(lightningSessions, k1)
		lightningSessionsMu.Unlock()
		lnurlError(w, "k1 challenge expired")
		return
	}

	valid, err := verifyLNURLAuthSignature(k1, sig, key)
	if err != nil {
		lnurlError(w, "signature verification error: "+err.Error())
		return
	}
	if !valid {
		lnurlError(w, "invalid signature")
		return
	}

	if session.IsLinkSession && session.BoundUserID != "" {
		// Link mode: associate key with the bound user.
		lk := &storage.LightningKey{
			ID:         uuid.New().String(),
			UserID:     session.BoundUserID,
			LinkingKey: key,
			Name:       "",
			CreatedAt:  time.Now(),
		}
		if err := h.storage.CreateLightningKey(r.Context(), lk); err != nil {
			if err == storage.ErrLightningKeyExists {
				// Already linked to this user — idempotent, treat as success.
			} else {
				slog.Error("lightning link: store key failed", "error", err)
				lnurlError(w, "failed to link key")
				return
			}
		}

		lightningSessionsMu.Lock()
		session.Status = "authenticated"
		session.UserID = session.BoundUserID
		lightningSessionsMu.Unlock()

		slog.Info("lightning link successful", "user_id", session.BoundUserID)
		lnurlOK(w)
		return
	}

	// Login mode: resolve existing linking key.
	lk, err := h.storage.GetLightningKeyByLinkingKey(r.Context(), key)
	if err != nil {
		if err == storage.ErrLightningKeyNotFound {
			lnurlError(w, "no account linked to this key")
		} else {
			slog.Error("lightning login: lookup failed", "error", err)
			lnurlError(w, "internal error")
		}
		return
	}

	// Update last_used_at (non-fatal).
	if err := h.storage.UpdateLightningKeyLastUsed(r.Context(), lk.ID); err != nil {
		slog.Warn("lightning login: update last_used_at failed", "error", err)
	}

	lightningSessionsMu.Lock()
	session.Status = "authenticated"
	session.UserID = lk.UserID
	lightningSessionsMu.Unlock()

	slog.Info("lightning login callback authenticated", "user_id", lk.UserID)
	lnurlOK(w)
}

// GET /api/v1/users/lightning/status?session_id=
// NO AUTH. Polled by the client to determine if the wallet has completed auth.
func (h *Handler) handleLightningStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	sessionID := r.URL.Query().Get("session_id")
	if sessionID == "" {
		h.errorResponse(w, http.StatusBadRequest, "session_id required")
		return
	}

	session := findSessionByID(sessionID)
	if session == nil || time.Now().After(session.ExpiresAt) {
		if session != nil {
			lightningSessionsMu.Lock()
			delete(lightningSessions, session.K1)
			lightningSessionsMu.Unlock()
		}
		h.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"status":  "expired",
		})
		return
	}

	if session.Status == "pending" {
		h.jsonResponse(w, http.StatusOK, map[string]interface{}{
			"success": false,
			"status":  "pending",
		})
		return
	}

	// Authenticated: issue the auth_token cookie (single-use — delete session first).
	userID := session.UserID
	lightningSessionsMu.Lock()
	delete(lightningSessions, session.K1)
	lightningSessionsMu.Unlock()

	user, err := h.storage.GetUser(r.Context(), userID)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "user not found")
		return
	}

	dbSessionID, _ := auth.GenerateSessionID()
	token, expiresAt, err := auth.GenerateJWTWithSession(h.authConfig, user.ID, user.Username, dbSessionID)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	dbSession := &storage.UserSession{
		ID:        dbSessionID,
		UserID:    user.ID,
		Token:     token[:16],
		UserAgent: r.UserAgent(),
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}
	if err := h.storage.CreateUserSession(r.Context(), dbSession); err != nil {
		slog.Warn("lightning status: create db session failed", "user_id", user.ID, "error", err)
	}

	now := time.Now()
	user.LastLoginAt = &now
	_ = h.storage.UpdateUser(r.Context(), user)

	slog.Info("lightning login successful", "user_id", user.ID, "username", user.Username)

	http.SetCookie(w, h.newAuthCookie(token, expiresAt))
	h.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"username": user.Username,
	})
}

// POST /api/v1/users/lightning/link/challenge
// AUTH REQUIRED. Generates a challenge for linking a lightning key to the
// authenticated user's account.
func (h *Handler) handleLightningLinkChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	lnurlStr, k1, sessionID, err := h.generateLightningChallenge(claims.UserID, true)
	if err != nil {
		slog.Error("lightning link challenge generation failed", "error", err)
		h.errorResponse(w, http.StatusInternalServerError, "failed to generate challenge")
		return
	}

	h.jsonResponse(w, http.StatusOK, map[string]string{
		"lnurl":      lnurlStr,
		"k1":         k1,
		"session_id": sessionID,
	})
}

// GET /api/v1/users/lightning/keys
// AUTH REQUIRED. Lists linking keys for the authenticated user.
func (h *Handler) handleLightningKeys(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	keys, err := h.storage.ListLightningKeys(r.Context(), claims.UserID)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to list lightning keys")
		return
	}

	type keyResp struct {
		ID         string     `json:"id"`
		Name       string     `json:"name,omitempty"`
		CreatedAt  time.Time  `json:"created_at"`
		LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	}
	result := make([]keyResp, len(keys))
	for i, k := range keys {
		result[i] = keyResp{
			ID:         k.ID,
			Name:       k.Name,
			CreatedAt:  k.CreatedAt,
			LastUsedAt: k.LastUsedAt,
		}
	}

	h.jsonResponse(w, http.StatusOK, result)
}

// DELETE /api/v1/users/lightning/keys/{id}
// AUTH REQUIRED. Unlinks a lightning key from the authenticated user.
func (h *Handler) handleLightningKeyByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	keyID := strings.TrimPrefix(r.URL.Path, "/api/v1/users/lightning/keys/")
	if keyID == "" {
		h.errorResponse(w, http.StatusBadRequest, "missing key id")
		return
	}

	// Verify ownership before deletion.
	keys, err := h.storage.ListLightningKeys(r.Context(), claims.UserID)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to verify ownership")
		return
	}
	owned := false
	for _, k := range keys {
		if k.ID == keyID {
			owned = true
			break
		}
	}
	if !owned {
		h.errorResponse(w, http.StatusNotFound, "lightning key not found")
		return
	}

	if err := h.storage.DeleteLightningKey(r.Context(), keyID); err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to delete lightning key")
		return
	}

	slog.Info("lightning key unlinked", "user_id", claims.UserID, "key_id", keyID)
	w.WriteHeader(http.StatusNoContent)
}
