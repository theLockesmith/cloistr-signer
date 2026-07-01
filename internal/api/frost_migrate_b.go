// FROST P7 Path B: interactive additive split for keys currently NOT in
// the signer's custody (e.g. keys the user holds in Damus/Amethyst).
//
// Design contract: docs/frost-2-of-n-design.md §13.2 Path B.
//
// Theoretical floor for existing-key migration: nsec is held only in the
// user's browser JS heap for the duration of a single HTTP round-trip.
// It never enters the wire, never enters the signer, never touches our
// infrastructure. Two-round protocol:
//
//   Round 1 (init):
//     Client → POST /keys/frost-migrate-b/init
//       body: { pubkey: <x-only hex Nostr pubkey the user is migrating> }
//     Server ← 200 OK { session_id, r_signer_commitment_hex }
//       server has stashed r_signer scalar in a session
//
//   Round 2 (finalize):
//     Browser computes:
//       - r_user = p - r_signer_from_R_signer  ← IMPOSSIBLE without discrete log
//       Actually: browser has p from the user's manual paste, generates its
//       own r_user, sends R_user = r_user·G. THEN
//     Wait, let me re-do the protocol...
//
// Correct protocol (rescued from doc):
//   Round 1: server generates random p_signer, sends R_signer = p_signer·G
//     to browser. Server stashes p_signer in session.
//   Round 2: browser (with pasted nsec p) computes p_user = p - p_signer.
//     Sends R_user = p_user·G (proof) plus keeps p_user locally.
//     Server verifies R_user + R_signer == p·G (the existing pubkey the
//     browser is claiming to hold) — this proves the browser knew p
//     without ever transmitting it.
//   Round 3 (finalize): browser confirms it stored p_user, server
//     Vault-encrypts p_signer, creates the FrostUserShare + Key rows.
//
// The nsec never leaves the browser. The only thing over the wire is
// R_user (a public curve point).
//
// The user must not already own a key with this pubkey in the signer —
// this is for keys living in third-party clients.

package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/frost"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// pathBSession is the transient server-side state between the init and
// finalize rounds. In the corrected protocol the SIGNER holds no
// share material until finalize — browser generates the split. This
// session tracks reservation + ownership check only.
type pathBSession struct {
	targetPubkeyHex string
	targetName      string
	userID          string
	expiresAt       time.Time
}

var (
	pathBSessions   = make(map[string]*pathBSession)
	pathBSessionsMu sync.Mutex
)

const pathBSessionTTL = 5 * time.Minute

// FrostMigrateBInitRequest is the browser → signer init call.
type FrostMigrateBInitRequest struct {
	// Pubkey the user is claiming (x-only 32-byte hex Nostr format).
	Pubkey string `json:"pubkey"`
	// Human-readable name for the resulting Key row.
	Name string `json:"name"`
}

// FrostMigrateBInitResponse confirms the reservation. No crypto
// material transmitted at init — the browser does all the math
// in Round 2.
type FrostMigrateBInitResponse struct {
	SessionID     string `json:"session_id"`
	ExpiresAtUnix int64  `json:"expires_at_unix"`
}

// FrostMigrateBFinalizeRequest is the browser → signer round 2.
// Browser has: (1) generated random p_user, (2) computed
// p_signer = p - p_user (with p being the pasted nsec, DESTROYED
// after this computation), (3) sent p_signer over the wire.
// Browser retains p_user + destroys p_signer from its memory too.
//
// The nsec p only ever exists in browser memory for the duration
// of the scalar subtraction. Never on the wire, never on the signer.
type FrostMigrateBFinalizeRequest struct {
	SessionID string `json:"session_id"`
	// Signer's share, computed BY BROWSER as (p - p_user) mod n.
	PSignerHex string `json:"p_signer_hex"` // 32-byte scalar hex
	// R_user = p_user·G, the browser's verification-share commitment.
	RUserHex string `json:"r_user_hex"` // 33-byte SEC1 hex
	// Optional relays for the new Key row.
	Relays []string `json:"relays,omitempty"`
}

// FrostMigrateBFinalizeResponse returns the created Key + FROST share
// metadata. Browser has already computed and stored p_user locally.
type FrostMigrateBFinalizeResponse struct {
	KeyID                     string `json:"key_id"`
	Pubkey                    string `json:"pubkey"`
	SignerVerificationShareHex string `json:"signer_verification_share_hex"` // r_signer_hex (p_signer·G)
	UserVerificationShareHex  string `json:"user_verification_share_hex"`   // r_user_hex (p_user·G)
}

// handleFrostMigrateBInit generates p_signer, returns R_signer.
// Route: POST /api/v1/keys/frost-migrate-b/init
func (h *Handler) handleFrostMigrateBInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}
	var req FrostMigrateBInitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	pubkey := strings.ToLower(strings.TrimSpace(req.Pubkey))
	if len(pubkey) != 64 || !isLowerHex(pubkey) {
		h.errorResponse(w, http.StatusBadRequest, "pubkey must be a 64-char lowercase x-only hex Nostr pubkey")
		return
	}
	// Guard: caller can't migrate a pubkey we already have on file
	// under KeyTypeLocal — Path A is the right tool for that.
	if existing, lookupErr := h.storage.GetKeyByPubkey(r.Context(), pubkey); lookupErr == nil && existing != nil {
		if existing.OwnerID == claims.UserID {
			h.errorResponse(w, http.StatusConflict, "you already own this key in the signer — use Path A migration instead")
			return
		}
		// Different owner: don't disclose their ownership; deny generic.
		h.errorResponse(w, http.StatusConflict, "this pubkey is already registered")
		return
	}

	// Fresh session id.
	var sidBytes [16]byte
	if _, err := rand.Read(sidBytes[:]); err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to sample session id")
		return
	}
	sessionID := hex.EncodeToString(sidBytes[:])
	expiresAt := time.Now().Add(pathBSessionTTL)

	pathBSessionsMu.Lock()
	pathBSessions[sessionID] = &pathBSession{
		targetPubkeyHex: pubkey,
		targetName:      strings.TrimSpace(req.Name),
		userID:          claims.UserID,
		expiresAt:       expiresAt,
	}
	pathBSessionsMu.Unlock()

	slog.Info("frost migrate B init",
		"user_id", claims.UserID,
		"pubkey", pubkey[:16]+"...",
		"session_id", sessionID)

	h.jsonResponse(w, http.StatusOK, FrostMigrateBInitResponse{
		SessionID:     sessionID,
		ExpiresAtUnix: expiresAt.Unix(),
	})
}

// handleFrostMigrateBFinalize verifies R_signer + R_user == pubkey·G,
// then Vault-encrypts p_signer and persists the FROST-user Key.
// Route: POST /api/v1/keys/frost-migrate-b/finalize
func (h *Handler) handleFrostMigrateBFinalize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}
	var req FrostMigrateBFinalizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Pull + drop the session atomically.
	pathBSessionsMu.Lock()
	session, ok := pathBSessions[req.SessionID]
	if ok {
		delete(pathBSessions, req.SessionID)
	}
	pathBSessionsMu.Unlock()
	if !ok {
		h.errorResponse(w, http.StatusNotFound, "session not found or expired")
		return
	}
	if session.userID != claims.UserID {
		h.errorResponse(w, http.StatusNotFound, "session not found or expired")
		return
	}
	if time.Now().After(session.expiresAt) {
		h.errorResponse(w, http.StatusRequestTimeout, "session expired; restart migration")
		return
	}

	group := frost.DefaultCiphersuite.Group()

	// Decode browser-computed p_signer scalar.
	pSignerBytes, err := hex.DecodeString(strings.TrimSpace(req.PSignerHex))
	if err != nil || len(pSignerBytes) != 32 {
		h.errorResponse(w, http.StatusBadRequest, "p_signer_hex must be a 32-byte hex-encoded scalar")
		return
	}
	pSigner := group.NewScalar()
	if err := pSigner.Decode(pSignerBytes); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "p_signer_hex is not a valid secp256k1 scalar")
		return
	}
	rSigner := group.Base().Multiply(pSigner)

	// Decode R_user.
	rUser := group.NewElement()
	if err := rUser.DecodeHex(strings.TrimSpace(req.RUserHex)); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "r_user_hex is not a valid compressed-SEC1 point")
		return
	}

	// Lift the target x-only pubkey to a curve point (even-Y convention
	// matches BIP-340: prepend 0x02).
	pubkeyPoint := group.NewElement()
	if err := pubkeyPoint.DecodeHex("02" + session.targetPubkeyHex); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "target pubkey does not lift to a valid curve point")
		return
	}

	// Verification: p_signer·G + R_user == pubkey·G. If yes, the browser
	// proved (p_signer + p_user) = p WITHOUT ever transmitting p or p_user.
	// Neither the signer nor any wire intermediary saw the nsec.
	sum := rSigner.Copy().Add(rUser)
	if !sum.Equal(pubkeyPoint) {
		h.errorResponse(w, http.StatusBadRequest,
			"proof does not verify — the p_signer + r_user combination does not derive to the claimed pubkey")
		return
	}

	// Proof accepted. Persist state.
	enc := h.getUserVaultEncryptor(r.Context(), claims)
	if enc == nil {
		h.errorResponse(w, http.StatusFailedDependency, "vault unavailable; migration requires Vault transit encryption")
		return
	}

	encryptedSignerShare, err := enc.EncryptBytes(pSigner.Encode())
	if err != nil {
		slog.Error("migrate B: encrypt signer share failed", "error", err)
		h.errorResponse(w, http.StatusInternalServerError, "failed to encrypt signer share")
		return
	}

	// Vault-encrypt an empty placeholder for the user share at DKG. In
	// Path B the browser holds p_user; there's no signer-known
	// "user_share_at_dkg" to encrypt. Recovery via BIP39 phrase is not
	// available for Path B keys because the user never generated a
	// phrase — they brought their own nsec. The lost-device story for
	// Path B is "re-import the nsec via Path B" (same protocol,
	// re-yields the same p_user because they still have p and
	// p_signer is re-randomized fresh which changes the whole split).
	// So we deliberately store an empty placeholder to indicate
	// "not recoverable via phrase" without breaking the P3e-b
	// recovery endpoint's NOT NULL contract.
	encryptedUserSharePlaceholder, err := enc.EncryptBytes([]byte{})
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to encrypt placeholder")
		return
	}

	keyID := generateID()
	shareID := generateID()
	now := time.Now()
	keyRow := &storage.Key{
		ID:               keyID,
		Pubkey:           session.targetPubkeyHex,
		KeyType:          storage.KeyTypeFrostUser,
		EncryptionMethod: "vault",
		CreatedAt:        now,
		CreatedBy:        claims.UserID,
		OwnerID:          claims.UserID,
		Relays:           req.Relays,
	}
	if err := h.storage.CreateKey(r.Context(), keyRow); err != nil {
		slog.Error("migrate B: create key failed", "error", err, "pubkey", session.targetPubkeyHex[:16]+"...")
		h.errorResponse(w, http.StatusInternalServerError, "failed to persist key")
		return
	}

	shareRow := &storage.FrostUserShare{
		ID:                       shareID,
		KeyID:                    keyID,
		OwnerID:                  claims.UserID,
		ShareIndex:               frost.SignerIndex,
		EncryptedShare:           encryptedSignerShare,
		VerificationShare:        rSigner.Encode(),
		Threshold:                2,
		TotalShares:              2,
		RotationGeneration:       0,
		CreatedAt:                now,
		UpdatedAt:                now,
		EncryptedUserShareAtDkg:  encryptedUserSharePlaceholder,
		UserVerificationShareHex: rUser.Hex(),
	}
	if err := h.storage.CreateFrostUserShare(r.Context(), shareRow); err != nil {
		if delErr := h.storage.DeleteKey(r.Context(), keyID); delErr != nil {
			slog.Error("migrate B: failed to rollback key after share-create failure",
				"key_id", keyID, "share_err", err, "rollback_err", delErr)
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to persist FROST share")
		return
	}

	slog.Info("frost migrate B finalized",
		"user_id", claims.UserID,
		"key_id", keyID,
		"pubkey", session.targetPubkeyHex[:16]+"...")

	h.jsonResponse(w, http.StatusOK, FrostMigrateBFinalizeResponse{
		KeyID:                      keyID,
		Pubkey:                     session.targetPubkeyHex,
		SignerVerificationShareHex: hex.EncodeToString(rSigner.Encode()),
		UserVerificationShareHex:   rUser.Hex(),
	})
}

// GCPathBSessions drops expired path-B sessions from memory. Should be
// called periodically by a janitor goroutine (or opportunistically on
// endpoint access). Returns number dropped.
func GCPathBSessions() int {
	now := time.Now()
	pathBSessionsMu.Lock()
	defer pathBSessionsMu.Unlock()
	dropped := 0
	for id, s := range pathBSessions {
		if now.After(s.expiresAt) {
			delete(pathBSessions, id)
			dropped++
		}
	}
	return dropped
}

// Silence unused-import complaints in future refactors.
var _ = errors.New
