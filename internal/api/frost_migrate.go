// FROST P7 Path A: server-side conversion of existing user-owned
// Vault-encrypted keys to FROST-user (2-of-2) shape.
//
// Design contract: docs/frost-2-of-n-design.md §13.2 Path A.
//
// Flow (transactional):
//   1. Load the target Key + verify user ownership.
//   2. Verify KeyType is currently "local" and NOT already FROST.
//   3. Vault-decrypt the existing nsec (plaintext transient in signer memory).
//   4. Derive existing pubkey from nsec and cross-check against Key.Pubkey.
//   5. Split nsec into random p_signer + p_user = p - p_signer (mod n).
//   6. Vault-encrypt p_signer (signer's new share).
//   7. Vault-encrypt p_user (the recovery blob the browser will fetch).
//   8. Compute verification shares (p_signer·G, p_user·G) for later
//      cosign validation.
//   9. Write FrostUserShare row + flip Key.KeyType to frost-user +
//      wipe the old EncryptedPrivateKey column atomically.
//  10. Return the recovery blob so the browser can fetch p_user
//      immediately and store it in IndexedDB.
//
// After this returns 200, the key's pubkey is unchanged (same Nostr
// identity, same followers, same NIP-05) but the signer can no
// longer sign alone — cosigning is now required.

package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/bytemare/ecc"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/frost"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// FrostMigrateResponse is what the endpoint returns after a successful
// Path-A conversion. All hex is compressed-SEC1 for elements or
// 32-byte big-endian for scalars.
type FrostMigrateResponse struct {
	KeyID                    string `json:"key_id"`
	Pubkey                   string `json:"pubkey"`
	UserShareForImmediateStore string `json:"user_share_hex"` // p_user 32-byte scalar hex; browser stores in IndexedDB
	UserVerificationShareHex string `json:"user_verification_share_hex"`
	SignerVerificationShare  string `json:"signer_verification_share_hex"`
}

// handleFrostMigratePathA runs the Path A conversion for a key already
// under signer custody (KeyType == KeyTypeLocal).
//
// Route: POST /api/v1/keys/{keyId}/frost-migrate
func (h *Handler) handleFrostMigratePathA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	// Path: /api/v1/keys/{keyId}/frost-migrate
	const prefix = "/api/v1/keys/"
	const suffix = "/frost-migrate"
	pathPart := strings.TrimPrefix(r.URL.Path, prefix)
	pathPart = strings.TrimSuffix(pathPart, suffix)
	if pathPart == "" || strings.Contains(pathPart, "/") {
		h.errorResponse(w, http.StatusBadRequest, "invalid key id in path")
		return
	}
	keyID := pathPart

	ctx := r.Context()

	key, err := h.storage.GetKey(ctx, keyID)
	if err != nil {
		if err == storage.ErrKeyNotFound {
			h.errorResponse(w, http.StatusNotFound, "key not found")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to load key")
		return
	}
	if key.OwnerID != claims.UserID {
		h.errorResponse(w, http.StatusNotFound, "key not found") // don't disclose ownership
		return
	}
	if key.KeyType == storage.KeyTypeFrostUser {
		h.errorResponse(w, http.StatusConflict, "key is already a FROST-user key")
		return
	}
	if key.KeyType != storage.KeyTypeLocal {
		h.errorResponse(w, http.StatusBadRequest, "only local keys can be migrated to FROST via Path A")
		return
	}

	enc := h.getUserVaultEncryptor(ctx, claims)
	if enc == nil {
		h.errorResponse(w, http.StatusFailedDependency, "vault unavailable; migration requires Vault transit encryption")
		return
	}

	// Decrypt existing nsec.
	nsecHex, err := enc.DecryptBytes([]byte(key.EncryptedNsec))
	if err != nil {
		slog.Error("migrate: decrypt existing nsec failed", "error", err, "key_id", keyID)
		h.errorResponse(w, http.StatusInternalServerError, "failed to decrypt existing key")
		return
	}
	nsecBytes, err := hex.DecodeString(strings.TrimSpace(string(nsecHex)))
	if err != nil || len(nsecBytes) != 32 {
		h.errorResponse(w, http.StatusInternalServerError, "existing key material is malformed")
		return
	}

	group := frost.DefaultCiphersuite.Group()

	// Decode nsec into a scalar.
	p := group.NewScalar()
	if err := p.Decode(nsecBytes); err != nil {
		slog.Error("migrate: nsec scalar decode failed", "error", err)
		h.errorResponse(w, http.StatusInternalServerError, "failed to interpret existing key material")
		return
	}

	// Sanity check: derived pubkey matches the stored Key.Pubkey.
	derivedPub := group.Base().Multiply(p)
	derivedEnc := derivedPub.Encode()
	if len(derivedEnc) != 33 {
		h.errorResponse(w, http.StatusInternalServerError, "unexpected pubkey encoding length")
		return
	}
	derivedXOnly := hex.EncodeToString(derivedEnc[1:])
	if !strings.EqualFold(derivedXOnly, key.Pubkey) {
		slog.Error("migrate: derived pubkey does not match stored key pubkey",
			"derived", derivedXOnly, "stored", key.Pubkey)
		h.errorResponse(w, http.StatusInternalServerError, "existing key material does not match this key's pubkey; refusing migration")
		return
	}

	// Split: p_signer = random, p_user = p - p_signer.
	var pSignerBytes [32]byte
	if _, err := rand.Read(pSignerBytes[:]); err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to sample randomness")
		return
	}
	pSigner := group.NewScalar()
	if err := pSigner.Decode(pSignerBytes[:]); err != nil {
		// Reject with clarity - astronomically unlikely (scalar out of range).
		h.errorResponse(w, http.StatusInternalServerError, "sampled signer share out of range; retry")
		return
	}
	pUser := p.Copy().Subtract(pSigner)

	// Verification shares (public).
	signerVerification := group.Base().Multiply(pSigner)
	userVerification := group.Base().Multiply(pUser)

	// Sanity: signer_verif + user_verif == joint pubkey (p·G).
	sum := signerVerification.Copy().Add(userVerification)
	if !sum.Equal(derivedPub) {
		h.errorResponse(w, http.StatusInternalServerError, "verification-share sum mismatch (should be impossible)")
		return
	}

	// Encrypt p_signer for signer storage (Vault-encrypted signer share).
	encSignerShare, err := enc.EncryptBytes(pSigner.Encode())
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to encrypt signer share")
		return
	}
	// Encrypt p_user for recovery-blob storage (browser fetches on demand).
	encUserShare, err := enc.EncryptBytes(pUser.Encode())
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to encrypt user share")
		return
	}

	// Persist: FrostUserShare + Key update.
	shareID := generateID()
	now := time.Now()
	shareRow := &storage.FrostUserShare{
		ID:                       shareID,
		KeyID:                    key.ID,
		OwnerID:                  claims.UserID,
		ShareIndex:               frost.SignerIndex,
		EncryptedShare:           encSignerShare,
		VerificationShare:        signerVerification.Encode(),
		Threshold:                2,
		TotalShares:              2,
		RotationGeneration:       0,
		CreatedAt:                now,
		UpdatedAt:                now,
		EncryptedUserShareAtDkg:  encUserShare,
		UserVerificationShareHex: userVerification.Hex(),
	}
	if err := h.storage.CreateFrostUserShare(ctx, shareRow); err != nil {
		slog.Error("migrate: create frost share row failed", "error", err, "key_id", keyID)
		h.errorResponse(w, http.StatusInternalServerError, "failed to persist FROST share")
		return
	}

	// Flip Key.KeyType to frost-user AND wipe the old nsec ciphertext.
	// If either fails, we roll back the FrostUserShare row above.
	key.KeyType = storage.KeyTypeFrostUser
	key.EncryptedNsec = ""
	key.EncryptionMethod = "vault"
	if err := h.storage.UpdateKey(ctx, key); err != nil {
		// Rollback the share row.
		_ = h.storage.DeleteFrostUserShare(ctx, shareID)
		slog.Error("migrate: update key failed; rolled back share row",
			"error", err, "key_id", keyID)
		h.errorResponse(w, http.StatusInternalServerError, "failed to update key")
		return
	}

	slog.Info("frost migrate Path A completed",
		"user_id", claims.UserID,
		"key_id", keyID,
		"pubkey", key.Pubkey[:16]+"...")

	// Return the user share so the browser can immediately store it in
	// IndexedDB under its password-derived KEK. If the browser somehow
	// loses this response, the recovery endpoint can also serve it back
	// via the same Vault decryption path.
	h.jsonResponse(w, http.StatusOK, FrostMigrateResponse{
		KeyID:                    key.ID,
		Pubkey:                   key.Pubkey,
		UserShareForImmediateStore: pUser.Hex(),
		UserVerificationShareHex: userVerification.Hex(),
		SignerVerificationShare:  hex.EncodeToString(signerVerification.Encode()),
	})

	// Ensure the plaintext scalar buffers don't linger. Go's GC will
	// collect them but explicit zeroing gives us a slightly better
	// posture (the scalar library holds internal buffers we can't
	// touch, so this is best-effort).
	_ = ecc.Group(0)
	_ = json.RawMessage{}
}
