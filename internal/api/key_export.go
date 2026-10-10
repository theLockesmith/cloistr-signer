package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/audit"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/crypto"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/nbd-wtf/go-nostr/nip49"
)

// ncryptsecLogN is the NIP-49 scrypt cost (2^16 rounds, the spec's suggested
// interactive default).
const ncryptsecLogN = 16

// minExportPasswordLen is the shortest ncryptsec export password accepted;
// the ncryptsec is only as strong as this password against offline guessing.
const minExportPasswordLen = 8

type keyExportRequest struct {
	Password       string `json:"password"`
	MFACode        string `json:"mfa_code,omitempty"`
	Confirm        string `json:"confirm"`
	Format         string `json:"format"`                    // "nsec" or "ncryptsec"
	ExportPassword string `json:"export_password,omitempty"` // ncryptsec only
}

// KeyExportResponse carries the exported key exactly once. It is never
// logged, cached or stored.
type KeyExportResponse struct {
	Format string `json:"format"`
	Value  string `json:"value"`
	Pubkey string `json:"pubkey"`
	Npub   string `json:"npub"`
}

var errNoSingleSecret = errors.New("this key has no single private key to export")

// handleKeyExport: POST /api/v1/keys/{id}/export. Lets a user take their own
// signing key with them, as a bare nsec or a NIP-49 ncryptsec, after a fresh
// password, MFA when enabled, and their username typed as confirmation. The
// audit record names the user, key and format, never the key.
func (h *Handler) handleKeyExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}
	keyID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/v1/keys/"), "/export")

	var req keyExportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	switch req.Format {
	case "nsec":
	case "ncryptsec":
		if len([]rune(req.ExportPassword)) < minExportPasswordLen {
			h.errorResponse(w, http.StatusBadRequest, fmt.Sprintf("export_password must be at least %d characters for an ncryptsec export", minExportPasswordLen))
			return
		}
	default:
		h.errorResponse(w, http.StatusBadRequest, `format must be "nsec" or "ncryptsec"`)
		return
	}

	key, err := h.storage.GetKey(r.Context(), keyID)
	if err != nil || key == nil || key.OwnerID != claims.UserID {
		h.errorResponse(w, http.StatusNotFound, "key not found")
		return
	}
	user, ok := h.reauthenticate(w, r, claims.UserID, req.Password, req.MFACode, req.Confirm, "type your username exactly to confirm the export")
	if !ok {
		return
	}

	priv, err := h.decryptOwnedKey(r.Context(), user, req.Password, key)
	if err != nil {
		if errors.Is(err, errNoSingleSecret) {
			h.errorResponse(w, http.StatusConflict, err.Error())
			return
		}
		slog.Error("key export: could not decrypt key", "user_id", user.ID, "key_id", key.ID, "error", err)
		h.errorResponse(w, http.StatusInternalServerError, "could not decrypt the key")
		return
	}

	var value string
	if req.Format == "nsec" {
		value, err = nip19.EncodePrivateKey(priv)
	} else {
		value, err = nip49.Encrypt(priv, req.ExportPassword, ncryptsecLogN, nip49.ClientDoesNotTrackThisData)
	}
	if err != nil {
		slog.Error("key export: encoding failed", "user_id", user.ID, "key_id", key.ID, "format", req.Format)
		h.errorResponse(w, http.StatusInternalServerError, "could not encode the key")
		return
	}
	npub, _ := nip19.EncodePublicKey(key.Pubkey)

	if logger := h.signer.AuditLogger(); logger != nil {
		ev := &audit.Event{
			Type: audit.EventKeyExported, Actor: user.ID, ActorType: "user",
			Target: key.Pubkey, TargetType: "key", Action: "exported own signing key",
			Details: map[string]interface{}{"format": req.Format, "key_id": key.ID}, Success: true,
		}
		if err := logger.Log(r.Context(), ev); err != nil {
			slog.Warn("failed to log key export audit event", "error", err)
		}
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	h.jsonResponse(w, http.StatusOK, KeyExportResponse{Format: req.Format, Value: value, Pubkey: key.Pubkey, Npub: npub})
}

// decryptOwnedKey returns the hex private key for a key the user owns, from
// its stored ciphertext rather than from memory, so the export works on any
// replica. The result is checked against the stored pubkey.
func (h *Handler) decryptOwnedKey(ctx context.Context, user *storage.User, password string, key *storage.Key) (string, error) {
	var priv string
	switch {
	case key.IsProxy() || key.EncryptedNsec == "":
		return "", errNoSingleSecret
	case crypto.IsPassphraseEncrypted(key.EncryptedNsec):
		pe, err := crypto.NewPassphraseEncryptor(password)
		if err != nil {
			return "", err
		}
		if priv, err = pe.Decrypt(key.EncryptedNsec); err != nil {
			return "", err
		}
	case crypto.IsVaultEncrypted(key.EncryptedNsec):
		if h.vaultClient == nil || !h.config.Vault.Enabled {
			return "", errors.New("key is Vault-wrapped but Vault is not configured")
		}
		va, err := h.vaultClient.AuthenticateUserpass(ctx, user.ID, password)
		if err != nil {
			return "", err
		}
		p, ok := decryptAndVerifyVaultKey(ctx, crypto.NewVaultEncryptor(h.vaultClient, user.ID, va.Token), key)
		if !ok {
			return "", errors.New("vault decryption failed")
		}
		priv = p
	case h.encryptor != nil:
		p, err := h.encryptor.Decrypt(key.EncryptedNsec)
		if err != nil {
			return "", err
		}
		priv = p
	default:
		return "", errNoSingleSecret
	}
	if derived, err := nostr.GetPublicKey(priv); err != nil || derived != key.Pubkey {
		return "", errors.New("decrypted key does not match the stored pubkey")
	}
	return priv, nil
}

