package api

// LNURL-auth (LUD-04) login and linking-key management endpoints.
//
// Challenge store: the storage backend (signer_lightning_challenges), shared by
// every replica, with a 10-minute expiry. The three steps of a login each
// reach whichever replica the load balancer picks; with the challenges in one
// pod's memory, a login completed only when all three hit the issuing pod
// (4 of 20 on production, 2026-10-16). Each step is single-use: a callback
// authenticates a pending challenge once, and a status poll turns an
// authenticated one into a sign-in once.
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
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/audit"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/auth"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
	"github.com/btcsuite/btcd/btcutil/bech32"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/google/uuid"
)

// lightningChallengeTTL is how long a QR code stays usable.
const lightningChallengeTTL = 10 * time.Minute

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
	// LUD-04 action: wallets show "link" for a link challenge rather than
	// "log in", so a swapped link QR reads differently to the person scanning.
	action := "login"
	if isLink {
		action = "link"
	}
	callbackURL := fmt.Sprintf("https://%s/api/v1/lnurl-auth/callback?tag=login&k1=%s&action=%s", domain, k1, action)

	encoded, err := bech32.EncodeFromBase256("lnurl", []byte(callbackURL))
	if err != nil {
		return "", "", "", fmt.Errorf("bech32 encode lnurl: %w", err)
	}
	lnurl = strings.ToUpper(encoded)

	ctx := context.Background()
	if err := h.storage.CleanExpiredLightningChallenges(ctx); err != nil {
		slog.Warn("lightning: clean expired challenges failed", "error", err)
	}
	now := time.Now()
	if err := h.storage.CreateLightningChallenge(ctx, &storage.LightningChallenge{
		K1:          k1,
		SessionID:   sessionID,
		Status:      "pending",
		BoundUserID: boundUserID,
		IsLink:      isLink,
		ExpiresAt:   now.Add(lightningChallengeTTL),
		CreatedAt:   now,
	}); err != nil {
		return "", "", "", fmt.Errorf("store challenge: %w", err)
	}
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

// claimLightningChallenge marks a pending challenge authenticated for userID,
// exactly once across all replicas. A second callback for the same k1 fails.
func (h *Handler) claimLightningChallenge(w http.ResponseWriter, r *http.Request, k1, userID, linkingKey string) bool {
	err := h.storage.AuthenticateLightningChallenge(r.Context(), k1, userID, linkingKey)
	if err == nil {
		return true
	}
	if errors.Is(err, storage.ErrLightningChallengeNotFound) {
		lnurlError(w, "k1 challenge already used or expired")
		return false
	}
	slog.Error("lightning callback: claim challenge failed", "error", err)
	lnurlError(w, "internal error")
	return false
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

	session, err := h.storage.GetLightningChallenge(r.Context(), k1)
	if err != nil {
		if !errors.Is(err, storage.ErrLightningChallengeNotFound) {
			slog.Error("lightning callback: challenge lookup failed", "error", err)
			lnurlError(w, "internal error")
			return
		}
		lnurlError(w, "unknown or expired k1 challenge")
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

	if session.IsLink && session.BoundUserID != "" {
		// Link mode. Store the key first and claim the challenge last, so the
		// browser's poll reports "linked" only once the key really is linked
		// to this user. A failed write leaves the challenge pending, and the
		// wallet can retry it.
		lk := &storage.LightningKey{
			ID:         uuid.New().String(),
			UserID:     session.BoundUserID,
			LinkingKey: key,
			Name:       "",
			CreatedAt:  time.Now(),
		}
		if err := h.storage.CreateLightningKey(r.Context(), lk); err != nil {
			if !errors.Is(err, storage.ErrLightningKeyExists) {
				slog.Error("lightning link: store key failed", "error", err)
				lnurlError(w, "failed to link key")
				return
			}
			// Linking keys are unique across accounts: "exists" is a no-op
			// only when it is already this user's.
			existing, err := h.storage.GetLightningKeyByLinkingKey(r.Context(), key)
			if err != nil {
				slog.Error("lightning link: look up existing key failed", "error", err)
				lnurlError(w, "failed to link key")
				return
			}
			if existing.UserID != session.BoundUserID {
				slog.Warn("lightning link: key already linked to another account", "user_id", session.BoundUserID)
				lnurlError(w, "this wallet key is already linked to another account")
				return
			}
		}
		if !h.claimLightningChallenge(w, r, k1, session.BoundUserID, "") {
			return
		}

		slog.Info("lightning link successful", "user_id", session.BoundUserID)
		h.auditLightningKey(r, audit.EventLightningKeyLinked, session.BoundUserID, key, "linked a Lightning wallet key")
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

	if !h.claimLightningChallenge(w, r, k1, lk.UserID, key) {
		return
	}

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

	expired := func() {
		h.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"status":  "expired",
		})
	}
	session, err := h.storage.GetLightningChallengeBySession(r.Context(), sessionID)
	if err != nil {
		if !errors.Is(err, storage.ErrLightningChallengeNotFound) {
			slog.Error("lightning status: challenge lookup failed", "error", err)
			h.errorResponse(w, http.StatusInternalServerError, "internal error")
			return
		}
		expired()
		return
	}

	if session.Status == "pending" {
		h.jsonResponse(w, http.StatusOK, map[string]interface{}{
			"success": false,
			"status":  "pending",
		})
		return
	}

	// A key's first login, when confirmation is on: show which account it
	// opens and wait for POST /lightning/confirm. Nothing is consumed and no
	// cookie is set here.
	if !session.IsLink && h.config.Lightning.ConfirmFirstLogin {
		if _, ok := h.unconfirmedLightningKey(r, session); ok {
			user, err := h.storage.GetUser(r.Context(), session.UserID)
			if err != nil {
				h.errorResponse(w, http.StatusInternalServerError, "user not found")
				return
			}
			h.jsonResponse(w, http.StatusOK, map[string]interface{}{
				"success":  false,
				"status":   "confirm_account",
				"username": user.Username,
			})
			return
		}
	}

	h.completeLightningLogin(w, r, sessionID)
}

// unconfirmedLightningKey returns the key that signed an authenticated login
// challenge when its owner has not yet confirmed it.
func (h *Handler) unconfirmedLightningKey(r *http.Request, c *storage.LightningChallenge) (*storage.LightningKey, bool) {
	if c.LinkingKey == "" {
		return nil, false
	}
	lk, err := h.storage.GetLightningKeyByLinkingKey(r.Context(), c.LinkingKey)
	if err != nil || lk.ConfirmedAt != nil || lk.UserID != c.UserID {
		return nil, false
	}
	return lk, true
}

// completeLightningLogin consumes an authenticated challenge (exactly once
// across replicas) and issues the auth_token cookie.
func (h *Handler) completeLightningLogin(w http.ResponseWriter, r *http.Request, sessionID string) {
	expired := func() {
		h.jsonResponse(w, http.StatusBadRequest, map[string]interface{}{
			"success": false,
			"status":  "expired",
		})
	}
	userID, err := h.storage.ConsumeLightningChallenge(r.Context(), sessionID)
	if err != nil {
		if !errors.Is(err, storage.ErrLightningChallengeNotFound) {
			slog.Error("lightning status: consume challenge failed", "error", err)
			h.errorResponse(w, http.StatusInternalServerError, "internal error")
			return
		}
		expired() // another poll already turned it into a sign-in
		return
	}

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

// POST /api/v1/users/lightning/confirm  {"session_id": "...", "confirm": true|false}
// NO AUTH: the session_id is the login browser's own secret (from the
// challenge response). Answers a "confirm_account" status:
//
//	confirm=true:  the key is marked confirmed and the login completes exactly
//	               as a status poll does (200 {success:true, username} + cookie).
//	confirm=false: "not my account": the key is unlinked from that account and
//	               an audit event recorded; no cookie (200 {success:false, status:"unlinked"}).
//
// 400 {success:false, status:"expired"}: unknown, expired or already used.
// 409 {success:false, status:"pending"|"not_required"}: the wallet has not
// signed yet, or this login needs no confirmation (poll status instead).
func (h *Handler) handleLightningConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req struct {
		SessionID string `json:"session_id"`
		Confirm   *bool  `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.SessionID == "" || req.Confirm == nil {
		h.errorResponse(w, http.StatusBadRequest, "session_id and confirm are required")
		return
	}
	reply := func(code int, status string) {
		h.jsonResponse(w, code, map[string]interface{}{"success": false, "status": status})
	}
	c, err := h.storage.GetLightningChallengeBySession(r.Context(), req.SessionID)
	if err != nil {
		if !errors.Is(err, storage.ErrLightningChallengeNotFound) {
			slog.Error("lightning confirm: challenge lookup failed", "error", err)
			h.errorResponse(w, http.StatusInternalServerError, "internal error")
			return
		}
		reply(http.StatusBadRequest, "expired")
		return
	}
	if c.IsLink {
		reply(http.StatusConflict, "not_required")
		return
	}
	if c.Status != "authenticated" {
		reply(http.StatusConflict, "pending")
		return
	}
	lk, ok := h.unconfirmedLightningKey(r, c)
	if !ok {
		reply(http.StatusConflict, "not_required")
		return
	}

	if !*req.Confirm {
		// Consume first, so this login can never be completed afterwards.
		if _, err := h.storage.ConsumeLightningChallenge(r.Context(), req.SessionID); err != nil {
			reply(http.StatusBadRequest, "expired")
			return
		}
		if err := h.storage.DeleteLightningKey(r.Context(), lk.ID); err != nil {
			slog.Error("lightning confirm: unlink failed", "key_id", lk.ID, "error", err)
			h.errorResponse(w, http.StatusInternalServerError, "could not unlink the key")
			return
		}
		slog.Warn("lightning key rejected at first login: unlinked", "user_id", lk.UserID, "key_id", lk.ID)
		h.auditLightningKey(r, audit.EventLightningKeyRejected, lk.UserID, lk.LinkingKey,
			"wallet holder said the account this key opened is not theirs; key unlinked")
		reply(http.StatusOK, "unlinked")
		return
	}

	if err := h.storage.ConfirmLightningKey(r.Context(), lk.ID); err != nil {
		slog.Error("lightning confirm: mark confirmed failed", "key_id", lk.ID, "error", err)
		h.errorResponse(w, http.StatusInternalServerError, "internal error")
		return
	}
	h.auditLightningKey(r, audit.EventLightningKeyConfirmed, lk.UserID, lk.LinkingKey, "confirmed the account at first Lightning login")
	h.completeLightningLogin(w, r, req.SessionID)
}

func (h *Handler) auditLightningKey(r *http.Request, typ audit.EventType, userID, linkingKey, action string) {
	logger := h.signer.AuditLogger()
	if logger == nil {
		return
	}
	ev := &audit.Event{
		Type: typ, Actor: userID, ActorType: "user",
		Target: linkingKey, TargetType: "lightning_key", Action: action, Success: true,
	}
	if err := logger.Log(r.Context(), ev); err != nil {
		slog.Warn("failed to log lightning key audit event", "error", err)
	}
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
