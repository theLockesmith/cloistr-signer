package api

import (
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/frost"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// FROST 2-of-N user-cosigner DKG HTTP endpoints (docs/frost-2-of-n-design.md §4.2).
// All three rounds require authentication. The user_id used by the protocol
// is taken from the JWT claims, never trusted from the request body.

func (h *Handler) handleFrostUserDKGRound1(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	var body struct {
		UserCommitsHex []string `json:"user_commits_hex"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := h.userDKG.Round1(&frost.Round1Request{
		UserID:         claims.UserID,
		UserCommitsHex: body.UserCommitsHex,
	})
	if err != nil {
		slog.Warn("frost user-dkg round1 failed", "user_id", claims.UserID, "error", err)
		h.errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	h.jsonResponse(w, http.StatusOK, resp)
}

func (h *Handler) handleFrostUserDKGRound2(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if _, err := h.validateAuthHeader(r); err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	var req frost.Round2Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	resp, err := h.userDKG.Round2(&req)
	if err != nil {
		// Verification failures and session-not-found are 400 (client-driven).
		// Any non-200 means "restart DKG."
		h.errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	h.jsonResponse(w, http.StatusOK, resp)
}

// FrostUserDKGFinalizeResponse is what the handler returns after a successful
// finalize. The user device uses key_id to remember which Key its share is
// bound to.
type FrostUserDKGFinalizeResponse struct {
	KeyID  string `json:"key_id"`
	Pubkey string `json:"pubkey"` // hex-encoded x-only (BIP-340 / Nostr)
}

func (h *Handler) handleFrostUserDKGFinalize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	var req frost.FinalizeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	result, err := h.userDKG.Finalize(&req)
	if err != nil {
		slog.Warn("frost user-dkg finalize failed", "user_id", claims.UserID, "error", err)
		h.errorResponse(w, http.StatusBadRequest, err.Error())
		return
	}

	// Defense in depth: verify the session's user matches the authenticated
	// caller. Round1 stamps claims.UserID into the session, so this should
	// always match - but a buggy/malicious caller using someone else's
	// session ID must not succeed.
	if result.UserID != claims.UserID {
		slog.Error("frost user-dkg finalize: session user mismatch (possible session hijack)",
			"session_user", result.UserID, "auth_user", claims.UserID)
		h.errorResponse(w, http.StatusForbidden, "session does not belong to this user")
		return
	}

	// Encrypt the signer's share via the user's Vault transit key. Plaintext
	// share material lives in memory only as long as it takes to encrypt;
	// the FinalizeResult struct gets garbage-collected after this function
	// returns.
	enc := h.getUserVaultEncryptor(r.Context(), claims)
	if enc == nil {
		// No Vault means we cannot honor the "signer cannot decrypt at rest
		// without user token" property. Refuse rather than store under a
		// weaker envelope.
		h.errorResponse(w, http.StatusFailedDependency, "vault unavailable; FROST keys require Vault transit encryption")
		return
	}

	encryptedShare, err := enc.EncryptBytes(result.SignerShare)
	if err != nil {
		slog.Error("frost user-dkg finalize: encrypt share failed", "user_id", claims.UserID, "error", err)
		h.errorResponse(w, http.StatusInternalServerError, "failed to encrypt share")
		return
	}

	// Recovery materials (design doc §6.4): encrypt g(UserIndex) under the
	// user's Vault transit key so the user can fetch it back if their
	// device is wiped, decrypt locally, and re-derive their share from
	// the BIP39 phrase. The signer cannot decrypt this on its own.
	encryptedUserShareAtDkg, err := enc.EncryptBytes(result.SignerShareForUser)
	if err != nil {
		slog.Error("frost user-dkg finalize: encrypt user-share-at-dkg failed", "user_id", claims.UserID, "error", err)
		h.errorResponse(w, http.StatusInternalServerError, "failed to encrypt recovery material")
		return
	}

	pubkeyHex := encodeNostrPubkey(result.JointPubkey)
	keyID := generateID()
	shareID := generateID()

	now := time.Now()
	keyRow := &storage.Key{
		ID:               keyID,
		Pubkey:           pubkeyHex,
		KeyType:          storage.KeyTypeFrostUser,
		EncryptionMethod: "vault",
		CreatedAt:        now,
		CreatedBy:        claims.UserID,
		OwnerID:          claims.UserID,
	}
	if err := h.storage.CreateKey(r.Context(), keyRow); err != nil {
		slog.Error("frost user-dkg finalize: create key failed", "user_id", claims.UserID, "error", err)
		h.errorResponse(w, http.StatusInternalServerError, "failed to create key")
		return
	}

	shareRow := &storage.FrostUserShare{
		ID:                       shareID,
		KeyID:                    keyID,
		OwnerID:                  claims.UserID,
		ShareIndex:               frost.SignerIndex,
		EncryptedShare:           encryptedShare,
		VerificationShare:        result.VerificationShare,
		Threshold:                result.Threshold,
		TotalShares:              result.TotalShares,
		RotationGeneration:       0,
		CreatedAt:                now,
		UpdatedAt:                now,
		EncryptedUserShareAtDkg:  encryptedUserShareAtDkg,
		UserVerificationShareHex: result.UserVerificationShareHex,
	}
	if err := h.storage.CreateFrostUserShare(r.Context(), shareRow); err != nil {
		// Rollback the key insert on share-create failure to avoid orphan keys.
		if delErr := h.storage.DeleteKey(r.Context(), keyID); delErr != nil {
			slog.Error("frost user-dkg finalize: failed to rollback key after share-create failure",
				"key_id", keyID, "share_err", err, "rollback_err", delErr)
		}
		slog.Error("frost user-dkg finalize: create share failed", "user_id", claims.UserID, "error", err)
		h.errorResponse(w, http.StatusInternalServerError, "failed to persist signer share")
		return
	}

	slog.Info("frost user-dkg finalize succeeded",
		"user_id", claims.UserID,
		"key_id", keyID,
		"pubkey", pubkeyHex[:16]+"...",
	)

	h.jsonResponse(w, http.StatusOK, FrostUserDKGFinalizeResponse{
		KeyID:  keyID,
		Pubkey: pubkeyHex,
	})
}

// FrostUserDKGRecoveryResponse carries the materials a fresh browser needs
// to reconstruct an existing FROST share from its BIP39 phrase. See
// docs/frost-2-of-n-design.md §6.4 for the full flow.
type FrostUserDKGRecoveryResponse struct {
	KeyID                    string `json:"key_id"`
	Pubkey                   string `json:"pubkey"`                       // x-only Nostr pubkey
	SignerShareForUserHex    string `json:"signer_share_for_user_hex"`    // plaintext g(UserIndex); decrypted server-side from the Vault-encrypted at-rest value
	UserVerificationShareHex string `json:"user_verification_share_hex"`  // final_share·G that the user reported at DKG time
}

// handleFrostUserDKGRecovery returns the recovery materials for a FROST
// key owned by the authenticated user. Requires Vault to be unlocked
// (active session with a vault_token) because we decrypt the at-rest
// signer_share_for_user via the user's transit key before responding.
//
// Route: GET /api/v1/frost/user-dkg/recovery/{keyId}
func (h *Handler) handleFrostUserDKGRecovery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	// Extract key ID from the path: /api/v1/frost/user-dkg/recovery/{keyID}
	const prefix = "/api/v1/frost/user-dkg/recovery/"
	keyID := strings.TrimPrefix(r.URL.Path, prefix)
	if keyID == "" || strings.Contains(keyID, "/") {
		h.errorResponse(w, http.StatusBadRequest, "invalid key id in path")
		return
	}

	key, err := h.storage.GetKey(r.Context(), keyID)
	if err != nil {
		if err == storage.ErrKeyNotFound {
			h.errorResponse(w, http.StatusNotFound, "key not found")
			return
		}
		slog.Error("frost recovery: get key failed", "error", err, "key_id", keyID)
		h.errorResponse(w, http.StatusInternalServerError, "failed to get key")
		return
	}

	// Ownership check - identical to the rest of the API surface. A user
	// can only recover their own FROST keys.
	if key.OwnerID != claims.UserID {
		h.errorResponse(w, http.StatusNotFound, "key not found")
		return
	}
	if key.KeyType != storage.KeyTypeFrostUser {
		h.errorResponse(w, http.StatusBadRequest, "key is not a FROST user-cosigner key")
		return
	}

	share, err := h.storage.GetFrostUserShareByKeyID(r.Context(), keyID)
	if err != nil {
		if err == storage.ErrFrostUserShareNotFound {
			// The Key row exists but no FrostUserShare - the row is from
			// before P3e-b shipped. Recovery via phrase is not possible
			// for such keys; only re-DKG is.
			h.errorResponse(w, http.StatusConflict, "frost share row missing - key predates recovery support")
			return
		}
		slog.Error("frost recovery: get share failed", "error", err, "key_id", keyID)
		h.errorResponse(w, http.StatusInternalServerError, "failed to get share")
		return
	}
	if len(share.EncryptedUserShareAtDkg) == 0 || share.UserVerificationShareHex == "" {
		// Key was created before P3e-b. The user must re-DKG.
		h.errorResponse(w, http.StatusConflict, "recovery materials missing - key predates recovery support")
		return
	}

	enc := h.getUserVaultEncryptor(r.Context(), claims)
	if enc == nil {
		h.errorResponse(w, http.StatusFailedDependency, "vault unavailable; FROST recovery requires Vault transit decryption")
		return
	}

	plaintext, err := enc.DecryptBytes(share.EncryptedUserShareAtDkg)
	if err != nil {
		slog.Error("frost recovery: decrypt user-share failed", "error", err, "key_id", keyID)
		h.errorResponse(w, http.StatusInternalServerError, "failed to decrypt recovery material")
		return
	}

	h.jsonResponse(w, http.StatusOK, FrostUserDKGRecoveryResponse{
		KeyID:                    key.ID,
		Pubkey:                   key.Pubkey,
		SignerShareForUserHex:    hex.EncodeToString(plaintext),
		UserVerificationShareHex: share.UserVerificationShareHex,
	})
}

// encodeNostrPubkey converts a FROST-encoded compressed pubkey (33 bytes,
// 0x02|0x03 prefix + 32-byte x) into the BIP-340 / Nostr 32-byte x-only hex
// representation. See internal/frost/frost.go pubkeyToHex for the same
// behavior on the FROST-internal path.
func encodeNostrPubkey(encoded []byte) string {
	switch len(encoded) {
	case 33:
		return hex.EncodeToString(encoded[1:])
	case 65:
		return hex.EncodeToString(encoded[1:33])
	case 32:
		return hex.EncodeToString(encoded)
	default:
		return hex.EncodeToString(encoded)
	}
}
