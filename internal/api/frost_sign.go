// FROST direct-sign endpoints for the user's own browser (P7 Path C
// + admin UI sign flow). Distinct from the NIP-46 dispatch which
// routes cosign requests via relay events — this is a direct HTTP
// 2-round handshake between the SPA and the signer for the SPA's own
// admin operations on FROST keys.

package api

import (
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/frost"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

type FrostSignRound1Request struct {
	KeyID        string `json:"key_id"`
	EventHashHex string `json:"event_hash_hex"`
}

type FrostSignRound1Response struct {
	SessionID                  string `json:"session_id"`
	SignerCommitmentHidingHex  string `json:"signer_hiding_hex"`
	SignerCommitmentBindingHex string `json:"signer_binding_hex"`
}

type FrostSignRound2Request struct {
	SessionID                string `json:"session_id"`
	UserCommitmentHidingHex  string `json:"user_hiding_hex"`
	UserCommitmentBindingHex string `json:"user_binding_hex"`
	UserPartialSignatureHex  string `json:"user_partial_hex"`
}

type FrostSignRound2Response struct {
	SignatureHex string `json:"signature_hex"`
}

// handleFrostSignRound1 - POST /api/v1/frost/sign/round1
func (h *Handler) handleFrostSignRound1(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}
	var req FrostSignRound1Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	eventHash, err := hex.DecodeString(strings.TrimSpace(req.EventHashHex))
	if err != nil || len(eventHash) != 32 {
		h.errorResponse(w, http.StatusBadRequest, "event_hash_hex must be 32-byte hex")
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
		h.errorResponse(w, http.StatusBadRequest, "key is not a FROST-user key")
		return
	}

	share, err := h.storage.GetFrostUserShareByKeyID(ctx, req.KeyID)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to load FROST share")
		return
	}

	enc := h.getUserVaultEncryptor(ctx, claims)
	if enc == nil {
		h.errorResponse(w, http.StatusFailedDependency, "vault unavailable; direct sign requires Vault transit decryption")
		return
	}
	signerSharePlain, err := enc.DecryptBytes(share.EncryptedShare)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to decrypt signer share")
		return
	}

	jointPubkeyHex := "02" + key.Pubkey

	if h.signer == nil {
		h.errorResponse(w, http.StatusInternalServerError, "signer coordinator not wired")
		return
	}
	coord := h.signer.FrostUserSigner()
	if coord == nil {
		h.errorResponse(w, http.StatusInternalServerError, "FROST user signer coordinator not initialized")
		return
	}

	begin, err := coord.BeginCosign(frost.UserCosignSetup{
		KeyID:                    key.ID,
		JointPubkeyHex:           jointPubkeyHex,
		SignerShareScalar:        signerSharePlain,
		SignerVerificationShare:  share.VerificationShare,
		UserVerificationShareHex: share.UserVerificationShareHex,
		EventHash:                eventHash,
	})
	if err != nil {
		slog.Error("frost sign round1: BeginCosign failed", "error", err, "key_id", req.KeyID)
		h.errorResponse(w, http.StatusInternalServerError, "failed to begin FROST sign session")
		return
	}

	h.jsonResponse(w, http.StatusOK, FrostSignRound1Response{
		SessionID:                  begin.SessionID,
		SignerCommitmentHidingHex:  begin.SignerCommitmentHidingHex,
		SignerCommitmentBindingHex: begin.SignerCommitmentBindingHex,
	})
}

// handleFrostSignRound2 - POST /api/v1/frost/sign/round2
func (h *Handler) handleFrostSignRound2(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if _, err := h.validateAuthHeader(r); err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}
	var req FrostSignRound2Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if h.signer == nil {
		h.errorResponse(w, http.StatusInternalServerError, "signer coordinator not wired")
		return
	}
	coord := h.signer.FrostUserSigner()
	if coord == nil {
		h.errorResponse(w, http.StatusInternalServerError, "FROST user signer coordinator not initialized")
		return
	}

	sigBytes, err := coord.CompleteCosign(frost.CompleteCosignInput{
		SessionID:                req.SessionID,
		UserCommitmentHidingHex:  strings.TrimSpace(req.UserCommitmentHidingHex),
		UserCommitmentBindingHex: strings.TrimSpace(req.UserCommitmentBindingHex),
		UserPartialSignatureHex:  strings.TrimSpace(req.UserPartialSignatureHex),
	})
	if err != nil {
		if err == frost.ErrCosignSessionNotFound {
			h.errorResponse(w, http.StatusNotFound, "session not found or expired")
			return
		}
		slog.Warn("frost sign round2: CompleteCosign failed", "error", err)
		h.errorResponse(w, http.StatusBadRequest, "sign completion failed: "+err.Error())
		return
	}

	h.jsonResponse(w, http.StatusOK, FrostSignRound2Response{
		SignatureHex: hex.EncodeToString(sigBytes),
	})
}
