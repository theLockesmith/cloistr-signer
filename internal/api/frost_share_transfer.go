// FROST P5: share transfer between devices.
//
// For phrase-created FROST keys, users add a device by entering their
// BIP39 phrase on the new device — the recovery flow re-derives the
// share. That flow already works via P3e.
//
// For Path A/B migrated keys there is no phrase; the user's share was
// generated fresh. To add a device we need an active transfer from a
// device that already holds the share.
//
// Protocol:
//   1. Device A: encrypts p_user via AES-GCM under a pairing-password-
//      derived KEK (PBKDF2-HMAC-SHA-256, 600k iterations, matches the
//      IndexedDB storage KEK discipline from P3d).
//   2. Device A: POST /api/v1/frost/share-transfer/upload
//        body: { key_id, ciphertext_b64, salt_hex, iv_hex }
//        server verifies the user owns the key, stashes a 5-minute-TTL
//        transfer record keyed by a short session_id, returns
//        { session_id }.
//   3. Device B: GET /api/v1/frost/share-transfer/{session_id}
//        server verifies same user, returns
//        { key_id, ciphertext_b64, salt_hex, iv_hex, pubkey }.
//   4. Device B: prompts user for the same pairing password, derives
//      KEK, decrypts, stores in its IndexedDB under its own
//      login-password-derived KEK.
//
// The pairing password is user-chosen at export time and communicated
// out-of-band to Device B (usually the same user telling themselves).
// Recommend 6+ words of entropy. The signer only sees ciphertext + salt
// + iv, never plaintext p_user or the pairing password.

package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

type shareTransferSession struct {
	userID        string
	keyID         string
	pubkey        string
	ciphertextB64 string
	saltHex       string
	ivHex         string
	expiresAt     time.Time
}

var (
	shareTransferSessions   = make(map[string]*shareTransferSession)
	shareTransferSessionsMu sync.Mutex
)

const shareTransferTTL = 5 * time.Minute

type FrostShareTransferUploadRequest struct {
	KeyID         string `json:"key_id"`
	CiphertextB64 string `json:"ciphertext_b64"`
	SaltHex       string `json:"salt_hex"`
	IVHex         string `json:"iv_hex"`
}

type FrostShareTransferUploadResponse struct {
	SessionID     string `json:"session_id"`
	ExpiresAtUnix int64  `json:"expires_at_unix"`
}

type FrostShareTransferDownloadResponse struct {
	KeyID         string `json:"key_id"`
	Pubkey        string `json:"pubkey"`
	CiphertextB64 string `json:"ciphertext_b64"`
	SaltHex       string `json:"salt_hex"`
	IVHex         string `json:"iv_hex"`
}

// handleFrostShareTransferUpload - POST /api/v1/frost/share-transfer/upload
func (h *Handler) handleFrostShareTransferUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}
	var req FrostShareTransferUploadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.CiphertextB64 == "" || req.SaltHex == "" || req.IVHex == "" {
		h.errorResponse(w, http.StatusBadRequest, "ciphertext_b64, salt_hex, and iv_hex are all required")
		return
	}
	// Size cap - ciphertext for a 32-byte scalar + 16-byte GCM tag is
	// 48 bytes → base64 ~64 chars. Give plenty of headroom for future
	// share formats but cap the abuse potential.
	if len(req.CiphertextB64) > 4096 {
		h.errorResponse(w, http.StatusBadRequest, "ciphertext too large")
		return
	}

	ctx := r.Context()
	key, err := h.storage.GetKey(ctx, req.KeyID)
	if err != nil {
		if err == storage.ErrKeyNotFound {
			h.errorResponse(w, http.StatusNotFound, "key not found")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to load key")
		return
	}
	if key.OwnerID != claims.UserID {
		h.errorResponse(w, http.StatusNotFound, "key not found")
		return
	}
	if key.KeyType != storage.KeyTypeFrostUser {
		h.errorResponse(w, http.StatusBadRequest, "share transfer applies to FROST-user keys only")
		return
	}

	var sidBytes [8]byte
	if _, err := rand.Read(sidBytes[:]); err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to sample session id")
		return
	}
	sessionID := hex.EncodeToString(sidBytes[:])
	expiresAt := time.Now().Add(shareTransferTTL)

	shareTransferSessionsMu.Lock()
	shareTransferSessions[sessionID] = &shareTransferSession{
		userID:        claims.UserID,
		keyID:         key.ID,
		pubkey:        key.Pubkey,
		ciphertextB64: req.CiphertextB64,
		saltHex:       req.SaltHex,
		ivHex:         req.IVHex,
		expiresAt:     expiresAt,
	}
	shareTransferSessionsMu.Unlock()

	slog.Info("frost share transfer upload",
		"user_id", claims.UserID,
		"key_id", key.ID,
		"session_id", sessionID)

	h.jsonResponse(w, http.StatusOK, FrostShareTransferUploadResponse{
		SessionID:     sessionID,
		ExpiresAtUnix: expiresAt.Unix(),
	})
}

// handleFrostShareTransferDownload - GET /api/v1/frost/share-transfer/{session_id}
func (h *Handler) handleFrostShareTransferDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}
	const prefix = "/api/v1/frost/share-transfer/"
	sessionID := strings.TrimPrefix(r.URL.Path, prefix)
	if sessionID == "" || strings.Contains(sessionID, "/") {
		h.errorResponse(w, http.StatusBadRequest, "invalid session id in path")
		return
	}

	shareTransferSessionsMu.Lock()
	session, ok := shareTransferSessions[sessionID]
	if ok && time.Now().After(session.expiresAt) {
		delete(shareTransferSessions, sessionID)
		ok = false
	}
	shareTransferSessionsMu.Unlock()

	if !ok {
		h.errorResponse(w, http.StatusNotFound, "session not found or expired")
		return
	}
	// Same-user check: only the user who uploaded can download. Cross-
	// user share transfer is deliberately out of scope in v1.
	if session.userID != claims.UserID {
		h.errorResponse(w, http.StatusNotFound, "session not found or expired")
		return
	}

	h.jsonResponse(w, http.StatusOK, FrostShareTransferDownloadResponse{
		KeyID:         session.keyID,
		Pubkey:        session.pubkey,
		CiphertextB64: session.ciphertextB64,
		SaltHex:       session.saltHex,
		IVHex:         session.ivHex,
	})
	// Consume-on-read: successful download deletes the session so the
	// ciphertext isn't retrievable a second time.
	shareTransferSessionsMu.Lock()
	delete(shareTransferSessions, sessionID)
	shareTransferSessionsMu.Unlock()
}

// GCShareTransferSessions drops expired transfer sessions. Call from a
// janitor goroutine.
func GCShareTransferSessions() int {
	now := time.Now()
	shareTransferSessionsMu.Lock()
	defer shareTransferSessionsMu.Unlock()
	dropped := 0
	for id, s := range shareTransferSessions {
		if now.After(s.expiresAt) {
			delete(shareTransferSessions, id)
			dropped++
		}
	}
	return dropped
}
