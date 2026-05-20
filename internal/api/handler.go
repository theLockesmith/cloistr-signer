package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/audit"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/auth"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/bunker"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/config"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/crypto"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/frost"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/signer"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/vault"
)

// Handler manages HTTP API endpoints
type Handler struct {
	config           *config.Config
	signer           *signer.Signer
	storage          storage.Storage
	authConfig       *auth.Config
	encryptor        *crypto.Encryptor
	vaultClient      *vault.Client // For per-user key encryption via Vault transit
	frostCoordinator *frost.Coordinator
	frostKeyGen      *frost.KeyGenerator
	distributedDKG   *frost.DistributedDKG
	remoteSigner     *frost.RemoteSigner
}

// frostEncryptorAdapter wraps crypto.Encryptor to implement frost.Encryptor
type frostEncryptorAdapter struct {
	enc *crypto.Encryptor
}

func (a *frostEncryptorAdapter) Encrypt(plaintext []byte) ([]byte, error) {
	return a.enc.EncryptBytes(plaintext)
}

func (a *frostEncryptorAdapter) Decrypt(ciphertext []byte) ([]byte, error) {
	return a.enc.DecryptBytes(ciphertext)
}

// NewHandler creates a new API handler
func NewHandler(cfg *config.Config, signer *signer.Signer, store storage.Storage, encryptor *crypto.Encryptor, vaultClient *vault.Client) *Handler {
	// Create FROST components if encryptor is available
	var frostCoord *frost.Coordinator
	var frostKG *frost.KeyGenerator
	if encryptor != nil {
		adapter := &frostEncryptorAdapter{enc: encryptor}
		frostCoord = frost.NewCoordinator(store, adapter)
		frostKG = frost.NewKeyGenerator(adapter)
	}

	return &Handler{
		config:  cfg,
		signer:  signer,
		storage: store,
		authConfig: &auth.Config{
			JWTSecret:         cfg.Auth.JWTSecret,
			JWTIssuer:         "coldforge-signer",
			TokenExpiry:       time.Duration(cfg.Auth.JWTExpiry) * time.Hour,
			BcryptCost:        auth.DefaultBcryptCost,
			LockoutDuration:   time.Duration(cfg.Auth.LockoutMinutes) * time.Minute,
			MaxFailedAttempts: cfg.Auth.MaxFailedLogins,
			MFAIssuer:         cfg.Auth.MFAIssuer,
		},
		encryptor:        encryptor,
		vaultClient:      vaultClient,
		frostCoordinator: frostCoord,
		frostKeyGen:      frostKG,
	}
}

// SetDistributedDKG sets the distributed DKG coordinator (called after nostr client is ready)
func (h *Handler) SetDistributedDKG(dkg *frost.DistributedDKG) {
	h.distributedDKG = dkg
}

// SetRemoteSigner sets the remote signing coordinator (called after nostr client is ready)
func (h *Handler) SetRemoteSigner(rs *frost.RemoteSigner) {
	h.remoteSigner = rs
}

// RegisterRoutes registers all HTTP routes
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Health endpoints
	mux.HandleFunc("/health", h.handleHealth)
	mux.HandleFunc("/health/live", h.handleLive)
	mux.HandleFunc("/health/ready", h.handleReady)

	// Key management
	mux.HandleFunc("/api/v1/keys", h.handleKeys)
	mux.HandleFunc("/api/v1/keys/", h.handleKeyByID)

	// Policy management
	mux.HandleFunc("/api/v1/policies", h.handlePolicies)
	mux.HandleFunc("/api/v1/policies/", h.handlePolicyByID)

	// Token management
	mux.HandleFunc("/api/v1/tokens", h.handleTokens)
	mux.HandleFunc("/api/v1/tokens/", h.handleTokenByID)

	// Pending requests (authorization)
	mux.HandleFunc("/api/v1/requests", h.handleRequests)
	mux.HandleFunc("/api/v1/requests/", h.handleRequestByID)

	// User management
	mux.HandleFunc("/api/v1/users/register", h.handleUserRegister)
	mux.HandleFunc("/api/v1/users/login", h.handleUserLogin)
	mux.HandleFunc("/api/v1/users/logout", h.handleUserLogout)
	mux.HandleFunc("/api/v1/users/me", h.handleUserMe)
	mux.HandleFunc("/api/v1/users/mfa/setup", h.handleMFASetup)
	mux.HandleFunc("/api/v1/users/mfa/verify", h.handleMFAVerify)
	mux.HandleFunc("/api/v1/users/mfa/disable", h.handleMFADisable)
	mux.HandleFunc("/api/v1/users/sessions", h.handleUserSessions)

	// Status
	mux.HandleFunc("/api/v1/status", h.handleStatus)

	// Bunker URI
	mux.HandleFunc("/api/v1/bunker/", h.handleBunkerConnect)

	// Nostrconnect (client-initiated connection)
	mux.HandleFunc("/api/v1/nostrconnect", h.handleNostrConnect)

	// NIP-05
	mux.HandleFunc("/.well-known/nostr.json", h.handleNIP05)

	// Audit logs
	mux.HandleFunc("/api/v1/audit", h.handleAuditLogs)

	// Admin - Platform user management
	mux.HandleFunc("/api/v1/admin/users", h.handleAdminUsers)
	mux.HandleFunc("/api/v1/admin/users/", h.handleAdminUserByPubkey)
	mux.HandleFunc("/api/v1/admin/services", h.handleAdminServices)

	// FROST threshold signing
	mux.HandleFunc("/api/v1/frost/keys", h.handleFrostKeys)
	mux.HandleFunc("/api/v1/frost/keys/", h.handleFrostKeyByID)
	mux.HandleFunc("/api/v1/frost/shares/", h.handleFrostShares)

	// FROST distributed DKG
	mux.HandleFunc("/api/v1/frost/dkg", h.handleFrostDKG)
	mux.HandleFunc("/api/v1/frost/dkg/", h.handleFrostDKGByID)
}

// Health check response
type HealthResponse struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
}

func (h *Handler) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	h.jsonResponse(w, http.StatusOK, HealthResponse{
		Status:    "ok",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

func (h *Handler) handleLive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	h.jsonResponse(w, http.StatusOK, HealthResponse{
		Status:    "ok",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

func (h *Handler) handleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	status := h.signer.GetStatus()
	relays := status["connected_relays"].([]string)
	if len(relays) == 0 {
		h.jsonResponse(w, http.StatusServiceUnavailable, HealthResponse{
			Status:    "not ready - no relay connections",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		})
		return
	}

	h.jsonResponse(w, http.StatusOK, HealthResponse{
		Status:    "ok",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

// Key management endpoints

type CreateKeyRequest struct {
	Name       string `json:"name"`
	PrivateKey string `json:"private_key,omitempty"` // Optional - generate if not provided (for local keys)
	BunkerURI  string `json:"bunker_uri,omitempty"`  // For proxy keys - bunker:// URI to upstream signer
	KeyType    string `json:"key_type,omitempty"`    // "local" or "proxy" (default: local)
}

type KeyResponse struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Pubkey          string    `json:"pubkey"`
	KeyType         string    `json:"key_type,omitempty"`         // "local" or "proxy"
	UpstreamPubkey  string    `json:"upstream_pubkey,omitempty"`  // For proxy keys
	RequireApproval bool      `json:"require_approval"`
	Relays          []string  `json:"relays,omitempty"` // Custom relays for this key
	CreatedAt       time.Time `json:"created_at"`
}

func (h *Handler) handleKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.handleListKeys(w, r)
	case http.MethodPost:
		h.handleCreateKey(w, r)
	default:
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) handleKeyByID(w http.ResponseWriter, r *http.Request) {
	// Parse path: /api/v1/keys/{id} or /api/v1/keys/{id}/permissions or /api/v1/keys/{id}/permissions/{pubkey}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/keys/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || parts[0] == "" {
		h.errorResponse(w, http.StatusBadRequest, "missing key id")
		return
	}

	keyID := parts[0]

	if len(parts) == 1 {
		// /api/v1/keys/{id}
		switch r.Method {
		case http.MethodGet:
			h.handleGetKey(w, r, keyID)
		case http.MethodPatch:
			h.handleUpdateKey(w, r, keyID)
		case http.MethodDelete:
			h.handleDeleteKey(w, r, keyID)
		default:
			h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		}
		return
	}

	if len(parts) >= 2 && parts[1] == "permissions" {
		if len(parts) == 2 {
			// /api/v1/keys/{id}/permissions
			switch r.Method {
			case http.MethodGet:
				h.handleListPermissions(w, r, keyID)
			case http.MethodPost:
				h.handleSetPermission(w, r, keyID)
			default:
				h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}

		if len(parts) == 3 {
			// /api/v1/keys/{id}/permissions/{pubkey}
			pubkey := parts[2]
			switch r.Method {
			case http.MethodPatch:
				h.handleUpdatePermissionName(w, r, keyID, pubkey)
			case http.MethodDelete:
				h.handleDeletePermission(w, r, keyID, pubkey)
			default:
				h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}
	}

	h.errorResponse(w, http.StatusNotFound, "not found")
}

func (h *Handler) handleListKeys(w http.ResponseWriter, r *http.Request) {
	// Get authenticated user
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	// List only keys owned by this user
	keys, err := h.storage.ListKeys(r.Context(), claims.UserID)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to list keys")
		return
	}

	response := make([]KeyResponse, len(keys))
	for i, key := range keys {
		response[i] = KeyResponse{
			ID:              key.ID,
			Name:            key.Name,
			Pubkey:          key.Pubkey,
			KeyType:         key.KeyType,
			UpstreamPubkey:  key.UpstreamPubkey,
			RequireApproval: key.RequireApproval,
			Relays:          key.Relays,
			CreatedAt:       key.CreatedAt,
		}
	}

	h.jsonResponse(w, http.StatusOK, response)
}

func (h *Handler) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	// Get authenticated user
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	var req CreateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Handle proxy keys differently
	if req.KeyType == storage.KeyTypeProxy || req.BunkerURI != "" {
		h.handleCreateProxyKey(w, r, req)
		return
	}

	var privateKey string
	var pubkey string

	if req.PrivateKey != "" {
		// Use provided private key - handle both nsec and hex formats
		privateKey = strings.TrimSpace(req.PrivateKey)

		if strings.HasPrefix(privateKey, "nsec1") {
			// Decode nsec (bech32) to hex
			prefix, value, err := nip19.Decode(privateKey)
			if err != nil || prefix != "nsec" {
				h.errorResponse(w, http.StatusBadRequest, "invalid nsec format")
				return
			}
			privateKey = value.(string)
		}

		pk, err := nostr.GetPublicKey(privateKey)
		if err != nil {
			h.errorResponse(w, http.StatusBadRequest, "invalid private key")
			return
		}
		pubkey = pk
	} else {
		// Generate new keypair
		privateKey = nostr.GeneratePrivateKey()
		pk, err := nostr.GetPublicKey(privateKey)
		if err != nil {
			h.errorResponse(w, http.StatusInternalServerError, "failed to generate key")
			return
		}
		pubkey = pk
	}

	// Encrypt the private key - prefer Vault if user has a valid session
	encryptedKey := privateKey
	encryptionMethod := "local"

	// Try Vault encryption first (per-user keys)
	vaultEncryptor := h.getUserVaultEncryptor(r.Context(), claims)
	if vaultEncryptor != nil {
		encrypted, err := vaultEncryptor.Encrypt(privateKey)
		if err != nil {
			slog.Error("failed to encrypt private key with vault", "error", err, "user_id", claims.UserID)
			h.errorResponse(w, http.StatusInternalServerError, "failed to encrypt key")
			return
		}
		encryptedKey = encrypted
		encryptionMethod = "vault"
		slog.Debug("encrypted key with vault transit", "user_id", claims.UserID)
	} else if h.encryptor != nil {
		// Fall back to local encryption
		encrypted, err := h.encryptor.Encrypt(privateKey)
		if err != nil {
			slog.Error("failed to encrypt private key", "error", err)
			h.errorResponse(w, http.StatusInternalServerError, "failed to encrypt key")
			return
		}
		encryptedKey = encrypted
	}

	key := &storage.Key{
		ID:               pubkey[:16],
		Name:             req.Name,
		Pubkey:           pubkey,
		KeyType:          storage.KeyTypeLocal,
		EncryptedNsec:    encryptedKey,
		EncryptionMethod: encryptionMethod,
		CreatedAt:        time.Now(),
		OwnerID:          claims.UserID,
	}

	if err := h.storage.CreateKey(r.Context(), key); err != nil {
		if err == storage.ErrKeyExists {
			h.errorResponse(w, http.StatusConflict, "key already exists")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to create key")
		return
	}

	// Register key with signer for immediate use
	h.signer.RegisterKey(pubkey, privateKey)

	slog.Info("created key", "name", req.Name, "pubkey", pubkey[:16]+"...")

	h.jsonResponse(w, http.StatusCreated, KeyResponse{
		ID:              key.ID,
		Name:            key.Name,
		Pubkey:          key.Pubkey,
		KeyType:         key.KeyType,
		RequireApproval: key.RequireApproval,
		Relays:          key.Relays,
		CreatedAt:       key.CreatedAt,
	})
}

// handleCreateProxyKey creates a proxy key that forwards to an upstream signer
func (h *Handler) handleCreateProxyKey(w http.ResponseWriter, r *http.Request, req CreateKeyRequest) {
	// Get authenticated user for ownership
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	if req.BunkerURI == "" {
		h.errorResponse(w, http.StatusBadRequest, "bunker_uri is required for proxy keys")
		return
	}

	// Parse the bunker URI to extract upstream pubkey
	uri, err := bunker.Parse(req.BunkerURI)
	if err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid bunker URI: "+err.Error())
		return
	}

	// Generate a local keypair for NIP-46 communication
	localPrivateKey := nostr.GeneratePrivateKey()
	localPubkey, err := nostr.GetPublicKey(localPrivateKey)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to generate local key")
		return
	}

	// Encrypt the local private key - prefer Vault if user has a valid session
	encryptedKey := localPrivateKey
	encryptionMethod := "local"

	// Try Vault encryption first (per-user keys)
	vaultEncryptor := h.getUserVaultEncryptor(r.Context(), claims)
	if vaultEncryptor != nil {
		encrypted, err := vaultEncryptor.Encrypt(localPrivateKey)
		if err != nil {
			slog.Error("failed to encrypt private key with vault", "error", err, "user_id", claims.UserID)
			h.errorResponse(w, http.StatusInternalServerError, "failed to encrypt key")
			return
		}
		encryptedKey = encrypted
		encryptionMethod = "vault"
	} else if h.encryptor != nil {
		// Fall back to local encryption
		encrypted, err := h.encryptor.Encrypt(localPrivateKey)
		if err != nil {
			slog.Error("failed to encrypt private key", "error", err)
			h.errorResponse(w, http.StatusInternalServerError, "failed to encrypt key")
			return
		}
		encryptedKey = encrypted
	}

	key := &storage.Key{
		ID:               localPubkey[:16],
		Name:             req.Name,
		Pubkey:           localPubkey, // Local pubkey for NIP-46 communication
		KeyType:          storage.KeyTypeProxy,
		EncryptedNsec:    encryptedKey,
		EncryptionMethod: encryptionMethod,
		BunkerURI:        req.BunkerURI,
		UpstreamPubkey:   uri.SignerPubkey, // The upstream signer's pubkey
		CreatedAt:        time.Now(),
		OwnerID:          claims.UserID,
	}

	if err := h.storage.CreateKey(r.Context(), key); err != nil {
		if err == storage.ErrKeyExists {
			h.errorResponse(w, http.StatusConflict, "key already exists")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to create key")
		return
	}

	// Register the proxy key with signer for NIP-46 handling
	h.signer.RegisterProxyKey(localPubkey, localPrivateKey, req.BunkerURI)

	slog.Info("created proxy key",
		"name", req.Name,
		"local_pubkey", localPubkey[:16]+"...",
		"upstream_pubkey", uri.SignerPubkey[:16]+"...",
	)

	h.jsonResponse(w, http.StatusCreated, KeyResponse{
		ID:              key.ID,
		Name:            key.Name,
		Pubkey:          key.Pubkey,
		KeyType:         key.KeyType,
		UpstreamPubkey:  key.UpstreamPubkey,
		RequireApproval: key.RequireApproval,
		Relays:          key.Relays,
		CreatedAt:       key.CreatedAt,
	})
}

func (h *Handler) handleGetKey(w http.ResponseWriter, r *http.Request, id string) {
	// Get authenticated user for ownership check
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	key, err := h.storage.GetKey(r.Context(), id)
	if err != nil {
		if err == storage.ErrKeyNotFound {
			h.errorResponse(w, http.StatusNotFound, "key not found")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to get key")
		return
	}

	// Verify ownership - user can only access their own keys
	if key.OwnerID != claims.UserID {
		h.errorResponse(w, http.StatusNotFound, "key not found")
		return
	}

	h.jsonResponse(w, http.StatusOK, KeyResponse{
		ID:              key.ID,
		Name:            key.Name,
		Pubkey:          key.Pubkey,
		KeyType:         key.KeyType,
		UpstreamPubkey:  key.UpstreamPubkey,
		RequireApproval: key.RequireApproval,
		Relays:          key.Relays,
		CreatedAt:       key.CreatedAt,
	})
}

type UpdateKeyRequest struct {
	Name            *string  `json:"name,omitempty"`
	RequireApproval *bool    `json:"require_approval,omitempty"`
	Relays          []string `json:"relays,omitempty"` // Custom relays for this key (empty = use global config)
}

func (h *Handler) handleUpdateKey(w http.ResponseWriter, r *http.Request, id string) {
	// Get authenticated user for ownership check
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	var req UpdateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Get existing key
	key, err := h.storage.GetKey(r.Context(), id)
	if err != nil {
		if err == storage.ErrKeyNotFound {
			h.errorResponse(w, http.StatusNotFound, "key not found")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to get key")
		return
	}

	// Verify ownership - user can only update their own keys
	if key.OwnerID != claims.UserID {
		h.errorResponse(w, http.StatusNotFound, "key not found")
		return
	}

	// Apply updates
	if req.Name != nil {
		key.Name = *req.Name
	}
	if req.RequireApproval != nil {
		key.RequireApproval = *req.RequireApproval
	}
	if req.Relays != nil {
		key.Relays = req.Relays
	}

	// Save updates
	if err := h.storage.UpdateKey(r.Context(), key); err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to update key")
		return
	}

	slog.Info("updated key", "id", id, "require_approval", key.RequireApproval, "relays", len(key.Relays))

	h.jsonResponse(w, http.StatusOK, KeyResponse{
		ID:              key.ID,
		Name:            key.Name,
		Pubkey:          key.Pubkey,
		RequireApproval: key.RequireApproval,
		Relays:          key.Relays,
		CreatedAt:       key.CreatedAt,
	})
}

func (h *Handler) handleDeleteKey(w http.ResponseWriter, r *http.Request, id string) {
	// Get authenticated user for ownership check
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	// Get key to verify ownership before deletion
	key, err := h.storage.GetKey(r.Context(), id)
	if err != nil {
		if err == storage.ErrKeyNotFound {
			h.errorResponse(w, http.StatusNotFound, "key not found")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to get key")
		return
	}

	// Verify ownership - user can only delete their own keys
	if key.OwnerID != claims.UserID {
		h.errorResponse(w, http.StatusNotFound, "key not found")
		return
	}

	if err := h.storage.DeleteKey(r.Context(), id); err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to delete key")
		return
	}

	slog.Info("deleted key", "id", id, "owner", claims.UserID)
	w.WriteHeader(http.StatusNoContent)
}

// Permission management endpoints

type SetPermissionRequest struct {
	UserPubkey   string   `json:"user_pubkey"`
	Methods      []string `json:"methods"`
	AllowedKinds []int    `json:"allowed_kinds,omitempty"`
}

type PermissionResponse struct {
	KeyID        string   `json:"key_id"`
	UserPubkey   string   `json:"user_pubkey"`
	Methods      []string `json:"methods"`
	AllowedKinds []int    `json:"allowed_kinds,omitempty"`
	PolicyID     string   `json:"policy_id,omitempty"`
}

func (h *Handler) handleListPermissions(w http.ResponseWriter, r *http.Request, keyID string) {
	// Get authenticated user for ownership check
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	// Get the key to get the full pubkey
	key, err := h.storage.GetKey(r.Context(), keyID)
	if err != nil {
		if err == storage.ErrKeyNotFound {
			h.errorResponse(w, http.StatusNotFound, "key not found")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to get key")
		return
	}

	// Verify ownership
	if key.OwnerID != claims.UserID {
		h.errorResponse(w, http.StatusNotFound, "key not found")
		return
	}

	perms, err := h.storage.ListPermissions(r.Context(), key.Pubkey)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to list permissions")
		return
	}

	response := make([]PermissionResponse, len(perms))
	for i, perm := range perms {
		response[i] = PermissionResponse{
			KeyID:        perm.KeyID,
			UserPubkey:   perm.UserPubkey,
			Methods:      perm.Methods,
			AllowedKinds: perm.AllowedKinds,
			PolicyID:     perm.PolicyID,
		}
	}

	h.jsonResponse(w, http.StatusOK, response)
}

func (h *Handler) handleSetPermission(w http.ResponseWriter, r *http.Request, keyID string) {
	// Get authenticated user for ownership check
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	var req SetPermissionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate pubkey format
	if len(req.UserPubkey) != 64 {
		h.errorResponse(w, http.StatusBadRequest, "invalid pubkey format")
		return
	}

	// Get key to verify it exists
	key, err := h.storage.GetKey(r.Context(), keyID)
	if err != nil {
		if err == storage.ErrKeyNotFound {
			h.errorResponse(w, http.StatusNotFound, "key not found")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to get key")
		return
	}

	// Verify ownership
	if key.OwnerID != claims.UserID {
		h.errorResponse(w, http.StatusNotFound, "key not found")
		return
	}

	perm := &storage.Permission{
		KeyID:        key.Pubkey,
		UserPubkey:   req.UserPubkey,
		Methods:      req.Methods,
		AllowedKinds: req.AllowedKinds,
	}

	if err := h.storage.SetPermission(r.Context(), perm); err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to set permission")
		return
	}

	slog.Info("set permission",
		"key", keyID,
		"user", req.UserPubkey[:16]+"...",
		"methods", req.Methods,
	)

	h.jsonResponse(w, http.StatusOK, PermissionResponse{
		KeyID:        perm.KeyID,
		UserPubkey:   perm.UserPubkey,
		Methods:      perm.Methods,
		AllowedKinds: perm.AllowedKinds,
		PolicyID:     perm.PolicyID,
	})
}

func (h *Handler) handleDeletePermission(w http.ResponseWriter, r *http.Request, keyID, pubkey string) {
	// Get authenticated user for ownership check
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	// Get key to verify it exists and get full pubkey
	key, err := h.storage.GetKey(r.Context(), keyID)
	if err != nil {
		if err == storage.ErrKeyNotFound {
			h.errorResponse(w, http.StatusNotFound, "key not found")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to get key")
		return
	}

	// Verify ownership
	if key.OwnerID != claims.UserID {
		h.errorResponse(w, http.StatusNotFound, "key not found")
		return
	}

	if err := h.storage.DeletePermission(r.Context(), key.Pubkey, pubkey); err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to delete permission")
		return
	}

	slog.Info("deleted permission", "key", keyID, "user", pubkey[:16]+"...")
	w.WriteHeader(http.StatusNoContent)
}

type UpdatePermissionNameRequest struct {
	CustomName string `json:"custom_name"`
}

func (h *Handler) handleUpdatePermissionName(w http.ResponseWriter, r *http.Request, keyID, pubkey string) {
	// Get authenticated user for ownership check
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	var req UpdatePermissionNameRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Get key to verify it exists and get full pubkey
	key, err := h.storage.GetKey(r.Context(), keyID)
	if err != nil {
		if err == storage.ErrKeyNotFound {
			h.errorResponse(w, http.StatusNotFound, "key not found")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to get key")
		return
	}

	// Verify ownership
	if key.OwnerID != claims.UserID {
		h.errorResponse(w, http.StatusNotFound, "key not found")
		return
	}

	if err := h.storage.UpdatePermissionName(r.Context(), key.Pubkey, pubkey, req.CustomName); err != nil {
		if err == storage.ErrKeyNotFound {
			h.errorResponse(w, http.StatusNotFound, "permission not found")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to update permission name")
		return
	}

	slog.Info("updated permission name", "key", keyID, "user", pubkey[:16]+"...", "name", req.CustomName)
	h.jsonResponse(w, http.StatusOK, map[string]string{"status": "updated"})
}

// Policy management endpoints

type CreatePolicyRequest struct {
	Name        string             `json:"name"`
	Description string             `json:"description,omitempty"`
	Rules       []PolicyRuleInput  `json:"rules"`
	ExpiresAt   *time.Time         `json:"expires_at,omitempty"`
}

type PolicyRuleInput struct {
	Method       string `json:"method"`
	AllowedKinds []int  `json:"allowed_kinds,omitempty"`
	MaxUsage     int    `json:"max_usage,omitempty"`
}

type PolicyResponse struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Description string              `json:"description,omitempty"`
	Rules       []*storage.PolicyRule `json:"rules"`
	ExpiresAt   *time.Time          `json:"expires_at,omitempty"`
	CreatedAt   time.Time           `json:"created_at"`
}

func (h *Handler) handlePolicies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.handleListPolicies(w, r)
	case http.MethodPost:
		h.handleCreatePolicy(w, r)
	default:
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) handlePolicyByID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/policies/")
	if path == "" {
		h.errorResponse(w, http.StatusBadRequest, "missing policy id")
		return
	}

	policyID := path

	switch r.Method {
	case http.MethodGet:
		h.handleGetPolicy(w, r, policyID)
	case http.MethodDelete:
		h.handleDeletePolicy(w, r, policyID)
	default:
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	policies, err := h.storage.ListPolicies(r.Context())
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to list policies")
		return
	}

	response := make([]PolicyResponse, len(policies))
	for i, p := range policies {
		response[i] = PolicyResponse{
			ID:          p.ID,
			Name:        p.Name,
			Description: p.Description,
			Rules:       p.Rules,
			ExpiresAt:   p.ExpiresAt,
			CreatedAt:   p.CreatedAt,
		}
	}
	h.jsonResponse(w, http.StatusOK, response)
}

func (h *Handler) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	var req CreatePolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		h.errorResponse(w, http.StatusBadRequest, "name is required")
		return
	}

	if len(req.Rules) == 0 {
		h.errorResponse(w, http.StatusBadRequest, "at least one rule is required")
		return
	}

	policyID := generateID()
	rules := make([]*storage.PolicyRule, len(req.Rules))
	for i, r := range req.Rules {
		rules[i] = &storage.PolicyRule{
			ID:           generateID(),
			PolicyID:     policyID,
			Method:       r.Method,
			AllowedKinds: r.AllowedKinds,
			MaxUsage:     r.MaxUsage,
			CurrentUsage: 0,
		}
	}

	policy := &storage.Policy{
		ID:          policyID,
		Name:        req.Name,
		Description: req.Description,
		Rules:       rules,
		ExpiresAt:   req.ExpiresAt,
		CreatedAt:   time.Now(),
	}

	if err := h.storage.CreatePolicy(r.Context(), policy); err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to create policy")
		return
	}

	slog.Info("created policy", "id", policy.ID, "name", policy.Name, "rules", len(rules))

	h.jsonResponse(w, http.StatusCreated, PolicyResponse{
		ID:          policy.ID,
		Name:        policy.Name,
		Description: policy.Description,
		Rules:       policy.Rules,
		ExpiresAt:   policy.ExpiresAt,
		CreatedAt:   policy.CreatedAt,
	})
}

func (h *Handler) handleGetPolicy(w http.ResponseWriter, r *http.Request, id string) {
	policy, err := h.storage.GetPolicy(r.Context(), id)
	if err != nil {
		if err == storage.ErrPolicyNotFound {
			h.errorResponse(w, http.StatusNotFound, "policy not found")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to get policy")
		return
	}

	h.jsonResponse(w, http.StatusOK, PolicyResponse{
		ID:          policy.ID,
		Name:        policy.Name,
		Description: policy.Description,
		Rules:       policy.Rules,
		ExpiresAt:   policy.ExpiresAt,
		CreatedAt:   policy.CreatedAt,
	})
}

func (h *Handler) handleDeletePolicy(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.storage.DeletePolicy(r.Context(), id); err != nil {
		if err == storage.ErrPolicyNotFound {
			h.errorResponse(w, http.StatusNotFound, "policy not found")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to delete policy")
		return
	}

	slog.Info("deleted policy", "id", id)
	w.WriteHeader(http.StatusNoContent)
}

// Token management endpoints

type CreateTokenRequest struct {
	PolicyID   string     `json:"policy_id"`
	KeyID      string     `json:"key_id"`
	ClientName string     `json:"client_name,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
}

type TokenResponse struct {
	ID          string     `json:"id"`
	PolicyID    string     `json:"policy_id"`
	KeyID       string     `json:"key_id"`
	ClientName  string     `json:"client_name,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	RedeemedAt  *time.Time `json:"redeemed_at,omitempty"`
	RedeemedBy  string     `json:"redeemed_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

func (h *Handler) handleTokens(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.handleListTokens(w, r)
	case http.MethodPost:
		h.handleCreateToken(w, r)
	default:
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) handleTokenByID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/tokens/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || parts[0] == "" {
		h.errorResponse(w, http.StatusBadRequest, "missing token id")
		return
	}

	tokenID := parts[0]

	// Check for /redeem action
	if len(parts) >= 2 && parts[1] == "redeem" {
		if r.Method == http.MethodPost {
			h.handleRedeemToken(w, r, tokenID)
			return
		}
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.handleGetToken(w, r, tokenID)
	case http.MethodDelete:
		h.handleDeleteToken(w, r, tokenID)
	default:
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) handleListTokens(w http.ResponseWriter, r *http.Request) {
	keyID := r.URL.Query().Get("key_id")
	if keyID == "" {
		h.errorResponse(w, http.StatusBadRequest, "key_id query parameter required")
		return
	}

	tokens, err := h.storage.ListTokens(r.Context(), keyID)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to list tokens")
		return
	}

	response := make([]TokenResponse, len(tokens))
	for i, t := range tokens {
		response[i] = TokenResponse{
			ID:         t.ID,
			PolicyID:   t.PolicyID,
			KeyID:      t.KeyID,
			ClientName: t.ClientName,
			ExpiresAt:  t.ExpiresAt,
			RedeemedAt: t.RedeemedAt,
			RedeemedBy: t.RedeemedBy,
			CreatedAt:  t.CreatedAt,
		}
	}
	h.jsonResponse(w, http.StatusOK, response)
}

func (h *Handler) handleCreateToken(w http.ResponseWriter, r *http.Request) {
	var req CreateTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.PolicyID == "" {
		h.errorResponse(w, http.StatusBadRequest, "policy_id is required")
		return
	}

	if req.KeyID == "" {
		h.errorResponse(w, http.StatusBadRequest, "key_id is required")
		return
	}

	// Verify policy exists
	if _, err := h.storage.GetPolicy(r.Context(), req.PolicyID); err != nil {
		if err == storage.ErrPolicyNotFound {
			h.errorResponse(w, http.StatusBadRequest, "policy not found")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to verify policy")
		return
	}

	// Verify key exists
	if _, err := h.storage.GetKey(r.Context(), req.KeyID); err != nil {
		if err == storage.ErrKeyNotFound {
			h.errorResponse(w, http.StatusBadRequest, "key not found")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to verify key")
		return
	}

	token := &storage.Token{
		ID:         generateID(),
		PolicyID:   req.PolicyID,
		KeyID:      req.KeyID,
		ClientName: req.ClientName,
		ExpiresAt:  req.ExpiresAt,
		CreatedAt:  time.Now(),
	}

	if err := h.storage.CreateToken(r.Context(), token); err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to create token")
		return
	}

	slog.Info("created token", "id", token.ID, "policy", token.PolicyID, "key", token.KeyID)

	h.jsonResponse(w, http.StatusCreated, TokenResponse{
		ID:         token.ID,
		PolicyID:   token.PolicyID,
		KeyID:      token.KeyID,
		ClientName: token.ClientName,
		ExpiresAt:  token.ExpiresAt,
		CreatedAt:  token.CreatedAt,
	})
}

func (h *Handler) handleGetToken(w http.ResponseWriter, r *http.Request, id string) {
	token, err := h.storage.GetToken(r.Context(), id)
	if err != nil {
		if err == storage.ErrTokenNotFound {
			h.errorResponse(w, http.StatusNotFound, "token not found")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to get token")
		return
	}

	h.jsonResponse(w, http.StatusOK, TokenResponse{
		ID:         token.ID,
		PolicyID:   token.PolicyID,
		KeyID:      token.KeyID,
		ClientName: token.ClientName,
		ExpiresAt:  token.ExpiresAt,
		RedeemedAt: token.RedeemedAt,
		RedeemedBy: token.RedeemedBy,
		CreatedAt:  token.CreatedAt,
	})
}

type RedeemTokenRequest struct {
	RedeemerPubkey string `json:"redeemer_pubkey"`
}

func (h *Handler) handleRedeemToken(w http.ResponseWriter, r *http.Request, tokenID string) {
	var req RedeemTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.RedeemerPubkey) != 64 {
		h.errorResponse(w, http.StatusBadRequest, "invalid redeemer_pubkey format")
		return
	}

	token, err := h.storage.RedeemToken(r.Context(), tokenID, req.RedeemerPubkey)
	if err != nil {
		switch err {
		case storage.ErrTokenNotFound:
			h.errorResponse(w, http.StatusNotFound, "token not found")
		case storage.ErrTokenRedeemed:
			h.errorResponse(w, http.StatusConflict, "token already redeemed")
		case storage.ErrTokenExpired:
			h.errorResponse(w, http.StatusGone, "token expired")
		default:
			h.errorResponse(w, http.StatusInternalServerError, "failed to redeem token")
		}
		return
	}

	// Get the policy to apply permissions
	policy, err := h.storage.GetPolicy(r.Context(), token.PolicyID)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to get policy")
		return
	}

	// Get the key to get the full pubkey
	key, err := h.storage.GetKey(r.Context(), token.KeyID)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to get key")
		return
	}

	// Create permission from policy rules
	methods := make([]string, 0, len(policy.Rules))
	var allowedKinds []int
	for _, rule := range policy.Rules {
		methods = append(methods, rule.Method)
		if len(rule.AllowedKinds) > 0 {
			allowedKinds = append(allowedKinds, rule.AllowedKinds...)
		}
	}

	// Always add "connect" method
	hasConnect := false
	for _, m := range methods {
		if m == "connect" {
			hasConnect = true
			break
		}
	}
	if !hasConnect {
		methods = append(methods, "connect")
	}

	perm := &storage.Permission{
		KeyID:        key.Pubkey,
		UserPubkey:   req.RedeemerPubkey,
		Methods:      methods,
		AllowedKinds: allowedKinds,
		ExpiresAt:    policy.ExpiresAt,
		PolicyID:     policy.ID, // Track source policy for usage limits
	}

	if err := h.storage.SetPermission(r.Context(), perm); err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to set permission")
		return
	}

	slog.Info("token redeemed",
		"token", tokenID,
		"redeemer", req.RedeemerPubkey[:16]+"...",
		"key", token.KeyID,
		"methods", methods,
	)

	h.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"message":     "token redeemed successfully",
		"key_pubkey":  key.Pubkey,
		"methods":     methods,
		"expires_at":  policy.ExpiresAt,
	})
}

func (h *Handler) handleDeleteToken(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.storage.DeleteToken(r.Context(), id); err != nil {
		if err == storage.ErrTokenNotFound {
			h.errorResponse(w, http.StatusNotFound, "token not found")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to delete token")
		return
	}

	slog.Info("deleted token", "id", id)
	w.WriteHeader(http.StatusNoContent)
}

// Pending request (authorization) endpoints

type PendingRequestResponse struct {
	ID           string                 `json:"id"`
	KeyPubkey    string                 `json:"key_pubkey"`
	ClientPubkey string                 `json:"client_pubkey"`
	Method       string                 `json:"method"`
	Params       map[string]interface{} `json:"params,omitempty"`
	EventKind    *int                   `json:"event_kind,omitempty"`
	ExpiresAt    time.Time              `json:"expires_at"`
	CreatedAt    time.Time              `json:"created_at"`
}

func (h *Handler) handleRequests(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.handleListRequests(w, r)
	default:
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) handleRequestByID(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/requests/")
	parts := strings.Split(path, "/")

	if len(parts) == 0 || parts[0] == "" {
		h.errorResponse(w, http.StatusBadRequest, "missing request id")
		return
	}

	requestID := parts[0]

	// Check for /approve or /deny action
	if len(parts) >= 2 {
		switch parts[1] {
		case "approve":
			if r.Method == http.MethodPost {
				h.handleApproveRequest(w, r, requestID)
				return
			}
		case "deny":
			if r.Method == http.MethodPost {
				h.handleDenyRequest(w, r, requestID)
				return
			}
		}
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.handleGetRequest(w, r, requestID)
	case http.MethodDelete:
		h.handleDenyRequest(w, r, requestID) // DELETE = deny
	default:
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) handleListRequests(w http.ResponseWriter, r *http.Request) {
	keyPubkey := r.URL.Query().Get("key_pubkey")
	if keyPubkey == "" {
		h.errorResponse(w, http.StatusBadRequest, "key_pubkey query parameter required")
		return
	}

	requests, err := h.storage.ListPendingRequests(r.Context(), keyPubkey)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to list requests")
		return
	}

	response := make([]PendingRequestResponse, len(requests))
	for i, req := range requests {
		response[i] = PendingRequestResponse{
			ID:           req.ID,
			KeyPubkey:    req.KeyPubkey,
			ClientPubkey: req.ClientPubkey,
			Method:       req.Method,
			Params:       req.Params,
			EventKind:    req.EventKind,
			ExpiresAt:    req.ExpiresAt,
			CreatedAt:    req.CreatedAt,
		}
	}
	h.jsonResponse(w, http.StatusOK, response)
}

func (h *Handler) handleGetRequest(w http.ResponseWriter, r *http.Request, id string) {
	req, err := h.storage.GetPendingRequest(r.Context(), id)
	if err != nil {
		if err == storage.ErrRequestNotFound || err == storage.ErrRequestExpired {
			h.errorResponse(w, http.StatusNotFound, "request not found or expired")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to get request")
		return
	}

	h.jsonResponse(w, http.StatusOK, PendingRequestResponse{
		ID:           req.ID,
		KeyPubkey:    req.KeyPubkey,
		ClientPubkey: req.ClientPubkey,
		Method:       req.Method,
		Params:       req.Params,
		EventKind:    req.EventKind,
		ExpiresAt:    req.ExpiresAt,
		CreatedAt:    req.CreatedAt,
	})
}

type ApproveRequestInput struct {
	Methods      []string `json:"methods,omitempty"`       // Methods to allow (default: requested method only)
	AllowedKinds []int    `json:"allowed_kinds,omitempty"` // Kinds to allow for sign_event
	Remember     bool     `json:"remember"`                // Create persistent permission
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`  // Permission expiration (if remember=true)
}

func (h *Handler) handleApproveRequest(w http.ResponseWriter, r *http.Request, requestID string) {
	var input ApproveRequestInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		// Allow empty body (approve with defaults)
		input = ApproveRequestInput{}
	}

	pendingReq, err := h.storage.GetPendingRequest(r.Context(), requestID)
	if err != nil {
		if err == storage.ErrRequestNotFound || err == storage.ErrRequestExpired {
			h.errorResponse(w, http.StatusNotFound, "request not found or expired")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to get request")
		return
	}

	// If remember is true, create a persistent permission
	if input.Remember {
		methods := input.Methods
		if len(methods) == 0 {
			methods = []string{pendingReq.Method}
		}

		// Always include connect
		hasConnect := false
		for _, m := range methods {
			if m == "connect" {
				hasConnect = true
				break
			}
		}
		if !hasConnect {
			methods = append(methods, "connect")
		}

		perm := &storage.Permission{
			KeyID:        pendingReq.KeyPubkey,
			UserPubkey:   pendingReq.ClientPubkey,
			Methods:      methods,
			AllowedKinds: input.AllowedKinds,
			ExpiresAt:    input.ExpiresAt,
		}

		if err := h.storage.SetPermission(r.Context(), perm); err != nil {
			h.errorResponse(w, http.StatusInternalServerError, "failed to set permission")
			return
		}
	}

	// Delete the pending request
	if err := h.storage.DeletePendingRequest(r.Context(), requestID); err != nil {
		slog.Warn("failed to delete pending request", "id", requestID, "error", err)
	}

	// Notify the signer to process the approved request
	h.signer.ApproveRequest(requestID, pendingReq)

	slog.Info("approved request",
		"id", requestID,
		"client", pendingReq.ClientPubkey[:16]+"...",
		"method", pendingReq.Method,
		"remember", input.Remember,
	)

	h.jsonResponse(w, http.StatusOK, map[string]string{
		"message": "request approved",
		"id":      requestID,
	})
}

func (h *Handler) handleDenyRequest(w http.ResponseWriter, r *http.Request, requestID string) {
	pendingReq, err := h.storage.GetPendingRequest(r.Context(), requestID)
	if err != nil {
		if err == storage.ErrRequestNotFound || err == storage.ErrRequestExpired {
			h.errorResponse(w, http.StatusNotFound, "request not found or expired")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to get request")
		return
	}

	// Delete the pending request
	if err := h.storage.DeletePendingRequest(r.Context(), requestID); err != nil {
		slog.Warn("failed to delete pending request", "id", requestID, "error", err)
	}

	// Notify the signer to deny the request
	h.signer.DenyRequest(requestID, pendingReq)

	slog.Info("denied request",
		"id", requestID,
		"client", pendingReq.ClientPubkey[:16]+"...",
		"method", pendingReq.Method,
	)

	h.jsonResponse(w, http.StatusOK, map[string]string{
		"message": "request denied",
		"id":      requestID,
	})
}

// Helper to generate random IDs
func generateID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Fallback to timestamp-based ID
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}

// User management endpoints

type RegisterRequest struct {
	Username string `json:"username"`
	Email    string `json:"email,omitempty"`
	Password string `json:"password"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	MFACode  string `json:"mfa_code,omitempty"`
}

type LoginResponse struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
	User      UserResponse `json:"user"`
	MFARequired bool `json:"mfa_required,omitempty"`
}

type UserResponse struct {
	ID         string     `json:"id"`
	Username   string     `json:"username"`
	Email      string     `json:"email,omitempty"`
	MFAEnabled bool       `json:"mfa_enabled"`
	CreatedAt  time.Time  `json:"created_at"`
	LastLogin  *time.Time `json:"last_login,omitempty"`
}

type MFASetupResponse struct {
	Secret      string   `json:"secret"`
	QRCodeURL   string   `json:"qr_code_url"`
	BackupCodes []string `json:"backup_codes"`
}

func (h *Handler) handleUserRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate input
	if req.Username == "" || len(req.Username) < 3 {
		h.errorResponse(w, http.StatusBadRequest, "username must be at least 3 characters")
		return
	}
	if req.Password == "" || len(req.Password) < 8 {
		h.errorResponse(w, http.StatusBadRequest, "password must be at least 8 characters")
		return
	}

	// Check if username exists
	if _, err := h.storage.GetUserByUsername(r.Context(), req.Username); err == nil {
		h.errorResponse(w, http.StatusConflict, "username already exists")
		return
	}

	// Check if email exists (if provided)
	if req.Email != "" {
		if _, err := h.storage.GetUserByEmail(r.Context(), req.Email); err == nil {
			h.errorResponse(w, http.StatusConflict, "email already exists")
			return
		}
	}

	// Hash password
	passwordHash, err := auth.HashPassword(req.Password, h.authConfig.BcryptCost)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	// Generate user ID
	userID, err := auth.GenerateUserID()
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to generate user ID")
		return
	}

	// Derive identity pubkey deterministically from user ID
	// Every signer user gets a Nostr identity for cross-service authorization
	identityPubkey, err := h.storage.DeriveUserPubkey(r.Context(), userID)
	if err != nil {
		slog.Error("failed to derive identity pubkey", "error", err, "user_id", userID)
		h.errorResponse(w, http.StatusInternalServerError, "failed to generate identity")
		return
	}

	// Create user
	now := time.Now()
	user := &storage.User{
		ID:           userID,
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: passwordHash,
		Pubkey:       identityPubkey,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := h.storage.CreateUser(r.Context(), user); err != nil {
		if err == storage.ErrUserExists {
			h.errorResponse(w, http.StatusConflict, "user already exists")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to create user")
		return
	}

	// Provision Vault resources for the user (transit key, policy, userpass account)
	// This enables per-user key encryption where only the user can decrypt their keys
	if h.vaultClient != nil && h.config.Vault.Enabled {
		if err := h.vaultClient.ProvisionUser(r.Context(), userID, req.Username, req.Password); err != nil {
			// Log the error but don't fail registration - Vault can be provisioned later
			// However, key operations will fail until Vault is properly set up
			slog.Error("failed to provision vault user", "error", err, "user_id", userID)
		} else {
			slog.Info("vault user provisioned", "user_id", userID)
		}
	}

	// Ensure platform user exists for cross-service authorization
	if err := h.storage.EnsurePlatformUser(r.Context(), user.Pubkey); err != nil {
		// Log but don't fail registration - platform linking is supplementary
		slog.Warn("failed to ensure platform user", "error", err, "pubkey", user.Pubkey[:16]+"...")
	}

	slog.Info("user registered", "username", req.Username, "user_id", userID, "pubkey", user.Pubkey[:16]+"...")

	h.jsonResponse(w, http.StatusCreated, UserResponse{
		ID:         user.ID,
		Username:   user.Username,
		Email:      user.Email,
		MFAEnabled: user.MFAEnabled,
		CreatedAt:  user.CreatedAt,
	})
}

func (h *Handler) handleUserLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if h.authConfig.JWTSecret == "" {
		h.errorResponse(w, http.StatusServiceUnavailable, "authentication not configured")
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Get user
	user, err := h.storage.GetUserByUsername(r.Context(), req.Username)
	if err != nil {
		// Don't reveal whether user exists
		h.errorResponse(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Check if account is locked
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		h.errorResponse(w, http.StatusForbidden, "account locked")
		return
	}

	// Verify password
	if !auth.VerifyPassword(req.Password, user.PasswordHash) {
		// Increment failed login attempts
		h.storage.IncrementFailedLogins(r.Context(), user.ID)

		// Check if we should lock the account
		if user.FailedLoginAttempts+1 >= h.authConfig.MaxFailedAttempts {
			lockUntil := time.Now().Add(h.authConfig.LockoutDuration)
			h.storage.LockUser(r.Context(), user.ID, lockUntil)
			slog.Warn("account locked due to failed logins", "username", req.Username)
		}

		h.errorResponse(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	// Check MFA if enabled
	if user.MFAEnabled {
		if req.MFACode == "" {
			// Return indication that MFA is required
			h.jsonResponse(w, http.StatusOK, LoginResponse{MFARequired: true})
			return
		}

		// Validate MFA code
		if !auth.ValidateMFACode(user.MFASecret, req.MFACode) {
			// Check backup codes
			if idx := auth.ValidateBackupCode(req.MFACode, user.BackupCodes); idx >= 0 {
				// Mark backup code as used (remove from list)
				user.BackupCodes = append(user.BackupCodes[:idx], user.BackupCodes[idx+1:]...)
				user.BackupCodesUsed++
				h.storage.UpdateUser(r.Context(), user)
			} else {
				h.errorResponse(w, http.StatusUnauthorized, "invalid MFA code")
				return
			}
		}
	}

	// Reset failed login attempts
	h.storage.ResetFailedLogins(r.Context(), user.ID)

	// Authenticate to Vault to get user's token for key operations
	var vaultToken string
	if h.vaultClient != nil && h.config.Vault.Enabled {
		// Authenticate to Vault using user's credentials (userID is the Vault username)
		vaultAuth, err := h.vaultClient.AuthenticateUserpass(r.Context(), user.ID, req.Password)
		if err != nil {
			// User may exist in signer DB but not have Vault userpass account
			// (e.g., migrated from pre-Vault or registration failed to provision)
			// Try to provision and retry auth
			slog.Info("vault auth failed, attempting to provision userpass account", "user_id", user.ID, "error", err)
			if provisionErr := h.vaultClient.ProvisionUser(r.Context(), user.ID, user.Username, req.Password); provisionErr != nil {
				slog.Warn("failed to provision vault user on login", "error", provisionErr, "user_id", user.ID)
			} else {
				// Retry auth after provisioning
				vaultAuth, err = h.vaultClient.AuthenticateUserpass(r.Context(), user.ID, req.Password)
				if err != nil {
					slog.Warn("vault auth still failed after provisioning", "error", err, "user_id", user.ID)
				} else {
					vaultToken = vaultAuth.Token
					slog.Info("vault auth successful after provisioning", "user_id", user.ID)
				}
			}
		} else {
			vaultToken = vaultAuth.Token
			slog.Debug("vault authentication successful", "user_id", user.ID, "lease_duration", vaultAuth.LeaseDuration)
		}
	}

	// Generate session ID first (needed for JWT)
	sessionID, _ := auth.GenerateSessionID()

	// Generate JWT with session ID (so we can retrieve Vault token later)
	token, expiresAt, err := auth.GenerateJWTWithSession(h.authConfig, user.ID, user.Username, sessionID)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	// Create session (with Vault token if available)
	session := &storage.UserSession{
		ID:         sessionID,
		UserID:     user.ID,
		Token:      token[:16], // Store prefix for revocation check
		VaultToken: vaultToken, // Store Vault token for key operations
		UserAgent:  r.UserAgent(),
		IPAddress:  r.RemoteAddr,
		ExpiresAt:  expiresAt,
		CreatedAt:  time.Now(),
	}
	h.storage.CreateUserSession(r.Context(), session)

	// Update last login
	now := time.Now()
	user.LastLoginAt = &now
	user.LastLoginIP = r.RemoteAddr
	h.storage.UpdateUser(r.Context(), user)

	slog.Info("user logged in", "username", req.Username, "user_id", user.ID)

	h.jsonResponse(w, http.StatusOK, LoginResponse{
		Token:     token,
		ExpiresAt: expiresAt,
		User: UserResponse{
			ID:         user.ID,
			Username:   user.Username,
			Email:      user.Email,
			MFAEnabled: user.MFAEnabled,
			CreatedAt:  user.CreatedAt,
			LastLogin:  user.LastLoginAt,
		},
	})

	// Load user's Vault-encrypted keys into signer runtime asynchronously.
	// Uses context.Background() so the load is not canceled when the HTTP
	// request completes. Keys lazy-load on first signing request anyway.
	if vaultToken != "" {
		go h.loadUserVaultKeys(context.Background(), user.ID, vaultToken)
	}
}

func (h *Handler) handleUserLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Get token from Authorization header
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	// Unregister user's Vault-encrypted keys from signer runtime
	h.unloadUserVaultKeys(r.Context(), claims.UserID)

	// Revoke Vault tokens for all sessions before deleting them
	if h.vaultClient != nil && h.config.Vault.Enabled {
		sessions, err := h.storage.ListUserSessions(r.Context(), claims.UserID)
		if err == nil {
			for _, session := range sessions {
				if session.VaultToken != "" {
					if err := h.vaultClient.RevokeToken(r.Context(), session.VaultToken); err != nil {
						slog.Warn("failed to revoke vault token", "error", err, "session_id", session.ID)
					}
				}
			}
		}
	}

	// Delete all sessions for this user
	h.storage.DeleteUserSessions(r.Context(), claims.UserID)

	h.jsonResponse(w, http.StatusOK, map[string]string{"message": "logged out successfully"})
}

func (h *Handler) handleUserMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	user, err := h.storage.GetUser(r.Context(), claims.UserID)
	if err != nil {
		h.errorResponse(w, http.StatusNotFound, "user not found")
		return
	}

	h.jsonResponse(w, http.StatusOK, UserResponse{
		ID:         user.ID,
		Username:   user.Username,
		Email:      user.Email,
		MFAEnabled: user.MFAEnabled,
		CreatedAt:  user.CreatedAt,
		LastLogin:  user.LastLoginAt,
	})
}

func (h *Handler) handleMFASetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	user, err := h.storage.GetUser(r.Context(), claims.UserID)
	if err != nil {
		h.errorResponse(w, http.StatusNotFound, "user not found")
		return
	}

	if user.MFAEnabled {
		h.errorResponse(w, http.StatusConflict, "MFA already enabled")
		return
	}

	// Generate MFA secret
	secret, url, err := auth.GenerateMFASecret(h.authConfig.MFAIssuer, user.Username)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to generate MFA secret")
		return
	}

	// Generate backup codes
	codes, hashes, err := auth.GenerateBackupCodes(auth.DefaultBackupCodeCount)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to generate backup codes")
		return
	}

	// Store secret and backup codes (not enabled until verified)
	user.MFASecret = secret
	user.BackupCodes = hashes
	if err := h.storage.UpdateUser(r.Context(), user); err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to update user")
		return
	}

	h.jsonResponse(w, http.StatusOK, MFASetupResponse{
		Secret:      secret,
		QRCodeURL:   url,
		BackupCodes: codes, // Return plaintext codes only once
	})
}

type MFAVerifyRequest struct {
	Code string `json:"code"`
}

func (h *Handler) handleMFAVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	var req MFAVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	user, err := h.storage.GetUser(r.Context(), claims.UserID)
	if err != nil {
		h.errorResponse(w, http.StatusNotFound, "user not found")
		return
	}

	if user.MFASecret == "" {
		h.errorResponse(w, http.StatusBadRequest, "MFA not set up")
		return
	}

	// Validate the code
	if !auth.ValidateMFACode(user.MFASecret, req.Code) {
		h.errorResponse(w, http.StatusUnauthorized, "invalid MFA code")
		return
	}

	// Enable MFA
	user.MFAEnabled = true
	if err := h.storage.UpdateUser(r.Context(), user); err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to enable MFA")
		return
	}

	slog.Info("MFA enabled", "username", user.Username, "user_id", user.ID)

	h.jsonResponse(w, http.StatusOK, map[string]string{"message": "MFA enabled successfully"})
}

func (h *Handler) handleMFADisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	var req MFAVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	user, err := h.storage.GetUser(r.Context(), claims.UserID)
	if err != nil {
		h.errorResponse(w, http.StatusNotFound, "user not found")
		return
	}

	if !user.MFAEnabled {
		h.errorResponse(w, http.StatusBadRequest, "MFA not enabled")
		return
	}

	// Require current MFA code to disable
	if !auth.ValidateMFACode(user.MFASecret, req.Code) {
		h.errorResponse(w, http.StatusUnauthorized, "invalid MFA code")
		return
	}

	// Disable MFA
	user.MFAEnabled = false
	user.MFASecret = ""
	user.BackupCodes = nil
	user.BackupCodesUsed = 0
	if err := h.storage.UpdateUser(r.Context(), user); err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to disable MFA")
		return
	}

	slog.Info("MFA disabled", "username", user.Username, "user_id", user.ID)

	h.jsonResponse(w, http.StatusOK, map[string]string{"message": "MFA disabled successfully"})
}

type SessionResponse struct {
	ID        string    `json:"id"`
	UserAgent string    `json:"user_agent,omitempty"`
	IPAddress string    `json:"ip_address,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

func (h *Handler) handleUserSessions(w http.ResponseWriter, r *http.Request) {
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	switch r.Method {
	case http.MethodGet:
		sessions, err := h.storage.ListUserSessions(r.Context(), claims.UserID)
		if err != nil {
			h.errorResponse(w, http.StatusInternalServerError, "failed to list sessions")
			return
		}

		response := make([]SessionResponse, len(sessions))
		for i, s := range sessions {
			response[i] = SessionResponse{
				ID:        s.ID,
				UserAgent: s.UserAgent,
				IPAddress: s.IPAddress,
				ExpiresAt: s.ExpiresAt,
				CreatedAt: s.CreatedAt,
			}
		}
		h.jsonResponse(w, http.StatusOK, response)

	case http.MethodDelete:
		// Delete all sessions except current
		h.storage.DeleteUserSessions(r.Context(), claims.UserID)
		h.jsonResponse(w, http.StatusOK, map[string]string{"message": "all sessions revoked"})

	default:
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// validateAuthHeader validates the Authorization header or auth cookie and returns JWT claims
func (h *Handler) validateAuthHeader(r *http.Request) (*auth.JWTClaims, error) {
	var token string

	// First try Authorization header (API clients)
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		// Expect "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && parts[0] == "Bearer" {
			token = parts[1]
		}
	}

	// Fall back to auth_token cookie (web UI)
	if token == "" {
		cookie, err := r.Cookie("auth_token")
		if err == nil && cookie.Value != "" {
			token = cookie.Value
		}
	}

	if token == "" {
		return nil, auth.ErrInvalidToken
	}

	return auth.ValidateJWT(h.authConfig, token)
}

// getSessionVaultToken retrieves the Vault token from the user's session.
// Returns empty string if Vault is disabled, session not found, or no token.
func (h *Handler) getSessionVaultToken(ctx context.Context, claims *auth.JWTClaims) string {
	if h.vaultClient == nil || !h.config.Vault.Enabled {
		return ""
	}
	if claims.SessionID == "" {
		return ""
	}

	session, err := h.storage.GetUserSession(ctx, claims.SessionID)
	if err != nil {
		slog.Debug("failed to get session for vault token", "error", err, "session_id", claims.SessionID)
		return ""
	}

	return session.VaultToken
}

// getUserVaultEncryptor returns a VaultEncryptor for the user if Vault is enabled and they have a token.
// Falls back to nil if Vault is not configured or user has no Vault token.
func (h *Handler) getUserVaultEncryptor(ctx context.Context, claims *auth.JWTClaims) *crypto.VaultEncryptor {
	vaultToken := h.getSessionVaultToken(ctx, claims)
	if vaultToken == "" {
		return nil
	}
	return crypto.NewVaultEncryptor(h.vaultClient, claims.UserID, vaultToken)
}

// loadUserVaultKeys loads and registers a user's Vault-encrypted keys into the signer runtime.
// This is called when a user logs in to make their keys available for NIP-46 signing.
func (h *Handler) loadUserVaultKeys(ctx context.Context, userID, vaultToken string) {
	if h.vaultClient == nil || vaultToken == "" {
		return
	}

	// Get user's keys
	keys, err := h.storage.ListKeys(ctx, userID)
	if err != nil {
		slog.Error("failed to list user keys for vault loading", "error", err, "user_id", userID)
		return
	}

	// Create Vault encryptor for this user
	vaultEncryptor := crypto.NewVaultEncryptor(h.vaultClient, userID, vaultToken)

	loadedCount := 0
	for _, key := range keys {
		// Only process Vault-encrypted keys
		if !crypto.IsVaultEncrypted(key.EncryptedNsec) {
			continue
		}

		privateKey, ok := decryptAndVerifyVaultKey(ctx, vaultEncryptor, key)
		if !ok {
			continue
		}

		// Register with signer
		if key.IsProxy() {
			h.signer.RegisterProxyKey(key.Pubkey, privateKey, key.BunkerURI)
		} else {
			h.signer.RegisterKey(key.Pubkey, privateKey)
		}
		loadedCount++
	}

	if loadedCount > 0 {
		slog.Info("loaded vault-encrypted keys for user", "user_id", userID, "count", loadedCount)
	}
}

// RestoreVaultKeysOnStartup walks every user, picks their most recent active
// session, and loads that user's Vault-encrypted keys into the signer runtime
// using the stored Vault token. Without this, a pod restart leaves every
// user's keys un-subscribed at the relay layer until each user re-logs-in,
// silently breaking NIP-46 signing.
func (h *Handler) RestoreVaultKeysOnStartup(ctx context.Context) {
	if h.vaultClient == nil {
		return
	}

	users, err := h.storage.ListUsers(ctx)
	if err != nil {
		slog.Error("startup vault restore: failed to list users", "error", err)
		return
	}

	usersRestored := 0
	keysRestored := 0
	for _, user := range users {
		sessions, err := h.storage.ListUserSessions(ctx, user.ID)
		if err != nil {
			slog.Warn("startup vault restore: failed to list sessions", "user_id", user.ID, "error", err)
			continue
		}

		// Sessions come back ordered by created_at DESC and filtered to
		// non-expired. Pick the newest one that actually has a Vault token.
		var vaultToken string
		for _, sess := range sessions {
			if sess.VaultToken != "" {
				vaultToken = sess.VaultToken
				break
			}
		}
		if vaultToken == "" {
			continue
		}

		loaded := h.loadUserVaultKeysCount(ctx, user.ID, vaultToken)
		if loaded > 0 {
			usersRestored++
			keysRestored += loaded
		}
	}

	slog.Info("startup vault restore complete",
		"users_restored", usersRestored,
		"keys_restored", keysRestored,
		"users_total", len(users),
	)
}

// loadUserVaultKeysCount is loadUserVaultKeys but returns the count of keys
// registered so callers can aggregate (used by RestoreVaultKeysOnStartup).
// Verifies the decrypted private key derives the expected pubkey before
// registering, so a corrupt decrypt does not silently register a key that
// will then fail every signing request.
func (h *Handler) loadUserVaultKeysCount(ctx context.Context, userID, vaultToken string) int {
	if h.vaultClient == nil || vaultToken == "" {
		return 0
	}

	keys, err := h.storage.ListKeys(ctx, userID)
	if err != nil {
		slog.Error("failed to list user keys for vault loading", "error", err, "user_id", userID)
		return 0
	}

	vaultEncryptor := crypto.NewVaultEncryptor(h.vaultClient, userID, vaultToken)
	loaded := 0
	for _, key := range keys {
		if !crypto.IsVaultEncrypted(key.EncryptedNsec) {
			continue
		}
		privateKey, ok := decryptAndVerifyVaultKey(ctx, vaultEncryptor, key)
		if !ok {
			continue
		}
		if key.IsProxy() {
			h.signer.RegisterProxyKey(key.Pubkey, privateKey, key.BunkerURI)
		} else {
			h.signer.RegisterKey(key.Pubkey, privateKey)
		}
		loaded++
	}
	if loaded > 0 {
		slog.Info("startup vault restore: loaded keys for user",
			"user_id", userID, "count", loaded)
	}
	return loaded
}

// decryptAndVerifyVaultKey decrypts a vault-encrypted key and verifies that
// the resulting private key derives the stored pubkey. A first generation of
// cmd/migrate sent the raw hex private key as Vault's `plaintext` field
// without base64-wrapping it; Vault stored and returns those keys verbatim,
// so the standard base64-decoding path produces garbage. For those keys we
// fall back to reading Vault's plaintext field directly. Returns
// (privateKeyHex, true) on success.
func decryptAndVerifyVaultKey(ctx context.Context, enc *crypto.VaultEncryptor, key *storage.Key) (string, bool) {
	// Standard path: Vault plaintext is base64-encoded.
	privateKey, err := enc.DecryptWithContext(ctx, key.EncryptedNsec)
	if err == nil {
		if derived, derr := nostr.GetPublicKey(privateKey); derr == nil && derived == key.Pubkey {
			return privateKey, true
		}
	}

	// Fallback: legacy cmd/migrate stored the raw hex string as Vault's
	// plaintext field. Read it back without base64-decoding.
	rawPrivateKey, rerr := enc.DecryptRawWithContext(ctx, key.EncryptedNsec)
	if rerr != nil {
		slog.Error("failed to decrypt vault key (raw fallback also failed)",
			"pubkey", key.Pubkey[:16]+"...", "primary_error", err, "raw_error", rerr)
		return "", false
	}
	if derived, derr := nostr.GetPublicKey(rawPrivateKey); derr == nil && derived == key.Pubkey {
		slog.Warn("recovered vault key via legacy raw-plaintext path (cmd/migrate format)",
			"pubkey", key.Pubkey[:16]+"...")
		return rawPrivateKey, true
	}

	slog.Error("decrypted vault key does not derive expected pubkey",
		"stored_pubkey", key.Pubkey[:16]+"...",
		"std_privkey_len", len(privateKey),
		"raw_privkey_len", len(rawPrivateKey),
		"std_err", err,
	)
	return "", false
}

// safeShortPrefix returns the first 16 chars of s, or "<empty>" / "<short:N>"
// when the input is too short or empty - used to safely log diagnostics
// without leaking key material.
func safeShortPrefix(s string) string {
	if s == "" {
		return "<empty>"
	}
	if len(s) < 16 {
		return fmt.Sprintf("<short:%d>", len(s))
	}
	return s[:16] + "..."
}

// unloadUserVaultKeys removes a user's Vault-encrypted keys from the signer runtime.
// This is called when a user logs out to remove their keys from memory.
func (h *Handler) unloadUserVaultKeys(ctx context.Context, userID string) {
	// Get user's keys
	keys, err := h.storage.ListKeys(ctx, userID)
	if err != nil {
		slog.Error("failed to list user keys for unloading", "error", err, "user_id", userID)
		return
	}

	unloadedCount := 0
	for _, key := range keys {
		// Only unregister Vault-encrypted keys (local keys stay in memory)
		if !crypto.IsVaultEncrypted(key.EncryptedNsec) {
			continue
		}

		h.signer.UnregisterKey(key.Pubkey)
		unloadedCount++
	}

	if unloadedCount > 0 {
		slog.Info("unloaded vault-encrypted keys for user", "user_id", userID, "count", unloadedCount)
	}
}

// Status endpoint

func (h *Handler) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	status := h.signer.GetStatus()
	h.jsonResponse(w, http.StatusOK, status)
}

// Bunker URI endpoints

type BunkerConnectResponse struct {
	BunkerURI    string   `json:"bunker_uri"`
	SignerPubkey string   `json:"signer_pubkey"`
	Relays       []string `json:"relays"`
	Secret       string   `json:"secret,omitempty"`
}

func (h *Handler) handleBunkerConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Get authenticated user for ownership check
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	// Parse key ID from path: /api/v1/bunker/{keyID}
	keyID := strings.TrimPrefix(r.URL.Path, "/api/v1/bunker/")
	if keyID == "" {
		h.errorResponse(w, http.StatusBadRequest, "missing key ID")
		return
	}

	// Get the key
	key, err := h.storage.GetKey(r.Context(), keyID)
	if err != nil {
		if err == storage.ErrKeyNotFound {
			h.errorResponse(w, http.StatusNotFound, "key not found")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to get key")
		return
	}

	// Verify ownership - only allow bunker URI generation for owned keys
	if key.OwnerID != claims.UserID {
		h.errorResponse(w, http.StatusNotFound, "key not found")
		return
	}

	// Generate secret
	secretBytes := make([]byte, 16)
	rand.Read(secretBytes)
	secret := fmt.Sprintf("%x", secretBytes)

	// Store the secret for validation on connect
	bunkerSecret := &storage.BunkerSecret{
		ID:        generateID(),
		KeyPubkey: key.Pubkey,
		Secret:    secret,
		ExpiresAt: time.Now().Add(24 * time.Hour), // Secret valid for 24 hours
		CreatedAt: time.Now(),
	}
	if err := h.storage.CreateBunkerSecret(r.Context(), bunkerSecret); err != nil {
		slog.Error("failed to store bunker secret", "error", err)
		h.errorResponse(w, http.StatusInternalServerError, "failed to generate bunker URI")
		return
	}

	// Build bunker URI
	// bunker://<pubkey>?relay=<relay>&secret=<secret>
	// Use discovery-aware relay selection
	relays := h.signer.GetRelaysForBunker(r.Context(), key)
	params := make([]string, 0, len(relays)+1)
	for _, relay := range relays {
		params = append(params, "relay="+relay)
	}
	params = append(params, "secret="+secret)

	bunkerURI := fmt.Sprintf("bunker://%s?%s", key.Pubkey, strings.Join(params, "&"))

	slog.Info("generated bunker URI", "key", keyID, "pubkey", key.Pubkey[:16]+"...")

	h.jsonResponse(w, http.StatusOK, BunkerConnectResponse{
		BunkerURI:    bunkerURI,
		SignerPubkey: key.Pubkey,
		Relays:       relays,
		Secret:       secret,
	})
}

// Nostrconnect endpoint (client-initiated connection)

type NostrConnectRequest struct {
	URI   string `json:"uri"`
	KeyID string `json:"key_id"`
}

type NostrConnectResponse struct {
	Success      bool   `json:"success"`
	AppName      string `json:"app_name,omitempty"`
	AppURL       string `json:"app_url,omitempty"`
	AppImage     string `json:"app_image,omitempty"`
	ClientPubkey string `json:"client_pubkey"`
}

func (h *Handler) handleNostrConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req NostrConnectRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.URI == "" {
		h.errorResponse(w, http.StatusBadRequest, "uri is required")
		return
	}

	if req.KeyID == "" {
		h.errorResponse(w, http.StatusBadRequest, "key_id is required")
		return
	}

	// Parse nostrconnect:// URI
	// Format: nostrconnect://<client-pubkey>?relay=<relay>&secret=<secret>&name=<name>&url=<url>&image=<image>
	// Note: bunker:// URIs are for apps to connect TO us, not for us to process
	if strings.HasPrefix(req.URI, "bunker://") {
		h.errorResponse(w, http.StatusBadRequest, "bunker:// URIs are for apps to use - paste a nostrconnect:// URI from the app instead")
		return
	}
	if !strings.HasPrefix(req.URI, "nostrconnect://") {
		h.errorResponse(w, http.StatusBadRequest, "invalid URI - must start with nostrconnect://")
		return
	}

	// Parse the URI
	uriWithoutScheme := strings.TrimPrefix(req.URI, "nostrconnect://")
	parts := strings.SplitN(uriWithoutScheme, "?", 2)
	if len(parts) == 0 || parts[0] == "" {
		h.errorResponse(w, http.StatusBadRequest, "invalid URI - missing client pubkey")
		return
	}

	clientPubkey := parts[0]
	if len(clientPubkey) != 64 {
		h.errorResponse(w, http.StatusBadRequest, "invalid client pubkey")
		return
	}

	// Parse query parameters
	var relay, secret, appName, appURL, appImage string
	if len(parts) > 1 {
		params := strings.Split(parts[1], "&")
		for _, param := range params {
			kv := strings.SplitN(param, "=", 2)
			if len(kv) != 2 {
				continue
			}
			key := kv[0]
			value := kv[1]
			// URL decode the value
			if decoded, err := urlDecode(value); err == nil {
				value = decoded
			}
			switch key {
			case "relay":
				relay = value
			case "secret":
				secret = value
			case "name":
				appName = value
			case "url":
				appURL = value
			case "image":
				appImage = value
			}
		}
	}

	if relay == "" {
		h.errorResponse(w, http.StatusBadRequest, "invalid URI - missing relay")
		return
	}

	// Get the key
	key, err := h.storage.GetKey(r.Context(), req.KeyID)
	if err != nil {
		if err == storage.ErrKeyNotFound {
			h.errorResponse(w, http.StatusNotFound, "key not found")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to get key")
		return
	}

	// Create permission for the client with basic methods
	perm := &storage.Permission{
		KeyID:      key.Pubkey,
		UserPubkey: clientPubkey,
		Methods:    []string{"connect", "sign_event", "get_public_key", "nip44_encrypt", "nip44_decrypt"},
		AppName:    appName,
		AppURL:     appURL,
		AppImage:   appImage,
	}

	if err := h.storage.SetPermission(r.Context(), perm); err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to set permission")
		return
	}

	// Send connect response via signer
	h.signer.SendNostrConnectResponse(r.Context(), key.Pubkey, clientPubkey, relay, secret)

	slog.Info("nostrconnect established",
		"app", appName,
		"client", clientPubkey[:16]+"...",
		"key", req.KeyID,
		"relay", relay,
	)

	h.jsonResponse(w, http.StatusOK, NostrConnectResponse{
		Success:      true,
		AppName:      appName,
		AppURL:       appURL,
		AppImage:     appImage,
		ClientPubkey: clientPubkey,
	})
}

// urlDecode decodes a URL-encoded string
func urlDecode(s string) (string, error) {
	s = strings.ReplaceAll(s, "+", " ")
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			var b byte
			_, err := fmt.Sscanf(s[i:i+3], "%%%02x", &b)
			if err == nil {
				result = append(result, b)
				i += 2
				continue
			}
		}
		result = append(result, s[i])
	}
	return string(result), nil
}

// NIP-05 endpoint

type NIP05Response struct {
	Names  map[string]string   `json:"names"`
	Relays map[string][]string `json:"relays,omitempty"`
}

func (h *Handler) handleNIP05(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	name := r.URL.Query().Get("name")

	response := NIP05Response{
		Names:  make(map[string]string),
		Relays: make(map[string][]string),
	}

	// Get all keys and create name mappings (NIP-05 is public discovery)
	keys, err := h.storage.ListAllKeys(r.Context())
	if err != nil {
		h.jsonResponse(w, http.StatusOK, response)
		return
	}

	for _, key := range keys {
		keyName := key.Name
		if keyName == "" {
			keyName = key.ID
		}
		// Sanitize name for NIP-05 (lowercase, no spaces)
		keyName = strings.ToLower(strings.ReplaceAll(keyName, " ", "-"))

		if name == "" || name == keyName {
			response.Names[keyName] = key.Pubkey
			// Use key-specific relays if configured, otherwise fall back to global config
			relays := key.Relays
			if len(relays) == 0 {
				relays = h.config.Relays
			}
			response.Relays[key.Pubkey] = relays
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(response)
}

// Audit log endpoint

type AuditLogEntry struct {
	ID        string                 `json:"id"`
	Timestamp string                 `json:"timestamp"`
	Type      string                 `json:"type"`
	Actor     string                 `json:"actor,omitempty"`
	Target    string                 `json:"target,omitempty"`
	Action    string                 `json:"action,omitempty"`
	Success   bool                   `json:"success"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

func (h *Handler) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Get audit logger from signer
	logger := h.signer.AuditLogger()
	if logger == nil {
		h.jsonResponse(w, http.StatusOK, []AuditLogEntry{})
		return
	}

	// Parse query parameters for filtering
	query := r.URL.Query()
	filter := &audit.Filter{
		Limit: 100, // Default limit
	}

	if actor := query.Get("actor"); actor != "" {
		filter.Actor = actor
	}
	if target := query.Get("target"); target != "" {
		filter.Target = target
	}
	if eventType := query.Get("type"); eventType != "" {
		filter.Types = []audit.EventType{audit.EventType(eventType)}
	}

	// Query audit logs
	events, err := logger.Query(r.Context(), filter)
	if err != nil {
		slog.Error("failed to query audit logs", "error", err)
		h.errorResponse(w, http.StatusInternalServerError, "failed to query audit logs")
		return
	}

	// Convert to response format
	entries := make([]AuditLogEntry, 0, len(events))
	for _, event := range events {
		entries = append(entries, AuditLogEntry{
			ID:        event.ID,
			Timestamp: event.Timestamp.Format(time.RFC3339),
			Type:      string(event.Type),
			Actor:     event.Actor,
			Target:    event.Target,
			Action:    event.Action,
			Success:   event.Success,
			Details:   event.Details,
		})
	}

	h.jsonResponse(w, http.StatusOK, entries)
}

// FROST threshold signing handlers

type CreateFrostKeyRequest struct {
	Name        string `json:"name"`
	Threshold   int    `json:"threshold"`   // t in t-of-n
	TotalShares int    `json:"total_shares"` // n in t-of-n
}

type FrostKeyResponse struct {
	ID          string    `json:"id"`
	Name        string    `json:"name,omitempty"`
	Pubkey      string    `json:"pubkey"`
	Threshold   int       `json:"threshold"`
	TotalShares int       `json:"total_shares"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by,omitempty"`
}

type FrostShareResponse struct {
	ID              string    `json:"id"`
	FrostKeyID      string    `json:"frost_key_id"`
	ShareIndex      int       `json:"share_index"`
	HolderPubkey    string    `json:"holder_pubkey,omitempty"`
	HolderBunkerURI string    `json:"holder_bunker_uri,omitempty"`
	IsLocal         bool      `json:"is_local"`
	CreatedAt       time.Time `json:"created_at"`
}

type FrostKeyDetailResponse struct {
	FrostKeyResponse
	Shares   []FrostShareResponse `json:"shares"`
	CanSign  bool                 `json:"can_sign"`
	LocalShares int              `json:"local_shares"`
}

func (h *Handler) handleFrostKeys(w http.ResponseWriter, r *http.Request) {
	if h.frostKeyGen == nil || h.frostCoordinator == nil {
		h.errorResponse(w, http.StatusServiceUnavailable, "FROST not enabled (encryption key required)")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.handleListFrostKeys(w, r)
	case http.MethodPost:
		h.handleCreateFrostKey(w, r)
	default:
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) handleListFrostKeys(w http.ResponseWriter, r *http.Request) {
	// Get authenticated user for ownership filtering
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	// List only user's FROST keys
	keys, err := h.storage.ListFrostKeysByOwner(r.Context(), claims.UserID)
	if err != nil {
		slog.Error("failed to list FROST keys", "error", err)
		h.errorResponse(w, http.StatusInternalServerError, "failed to list FROST keys")
		return
	}

	response := make([]FrostKeyResponse, len(keys))
	for i, key := range keys {
		response[i] = FrostKeyResponse{
			ID:          key.ID,
			Name:        key.Name,
			Pubkey:      key.Pubkey,
			Threshold:   key.Threshold,
			TotalShares: key.TotalShares,
			CreatedAt:   key.CreatedAt,
			CreatedBy:   key.CreatedBy,
		}
	}
	h.jsonResponse(w, http.StatusOK, response)
}

func (h *Handler) handleCreateFrostKey(w http.ResponseWriter, r *http.Request) {
	// Get authenticated user for ownership
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	var input CreateFrostKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if input.Threshold < 1 {
		h.errorResponse(w, http.StatusBadRequest, "threshold must be at least 1")
		return
	}
	if input.TotalShares < input.Threshold {
		h.errorResponse(w, http.StatusBadRequest, "total_shares must be >= threshold")
		return
	}

	// Generate FROST key and shares
	config := &frost.KeyGenConfig{
		Name:        input.Name,
		Threshold:   input.Threshold,
		TotalShares: input.TotalShares,
	}

	result, err := h.frostKeyGen.GenerateKey(config)
	if err != nil {
		slog.Error("failed to generate FROST key", "error", err)
		h.errorResponse(w, http.StatusInternalServerError, "failed to generate FROST key")
		return
	}

	// Set owner from authenticated user
	result.FrostKey.OwnerID = claims.UserID

	// Store the key
	if err := h.storage.CreateFrostKey(r.Context(), result.FrostKey); err != nil {
		slog.Error("failed to store FROST key", "error", err)
		h.errorResponse(w, http.StatusInternalServerError, "failed to store FROST key")
		return
	}

	// Store all shares
	for _, share := range result.Shares {
		if err := h.storage.CreateFrostShare(r.Context(), share); err != nil {
			slog.Error("failed to store FROST share", "error", err, "share_index", share.ShareIndex)
			// Continue storing other shares
		}
	}

	slog.Info("created FROST key",
		"id", result.FrostKey.ID,
		"name", result.FrostKey.Name,
		"pubkey", result.FrostKey.Pubkey,
		"threshold", result.FrostKey.Threshold,
		"total_shares", result.FrostKey.TotalShares,
	)

	h.jsonResponse(w, http.StatusCreated, FrostKeyResponse{
		ID:          result.FrostKey.ID,
		Name:        result.FrostKey.Name,
		Pubkey:      result.FrostKey.Pubkey,
		Threshold:   result.FrostKey.Threshold,
		TotalShares: result.FrostKey.TotalShares,
		CreatedAt:   result.FrostKey.CreatedAt,
		CreatedBy:   result.FrostKey.CreatedBy,
	})
}

func (h *Handler) handleFrostKeyByID(w http.ResponseWriter, r *http.Request) {
	if h.frostKeyGen == nil || h.frostCoordinator == nil {
		h.errorResponse(w, http.StatusServiceUnavailable, "FROST not enabled (encryption key required)")
		return
	}

	// Parse key ID from URL
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/frost/keys/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		h.errorResponse(w, http.StatusBadRequest, "key ID required")
		return
	}
	keyID := parts[0]

	// Check for sub-resources (shares, export)
	if len(parts) > 1 {
		switch parts[1] {
		case "shares":
			h.handleFrostKeyShares(w, r, keyID)
			return
		case "export":
			if len(parts) > 2 {
				shareIndex := parts[2]
				h.handleExportFrostShare(w, r, keyID, shareIndex)
				return
			}
		case "sign":
			h.handleFrostSign(w, r, keyID)
			return
		}
	}

	switch r.Method {
	case http.MethodGet:
		h.handleGetFrostKey(w, r, keyID)
	case http.MethodDelete:
		h.handleDeleteFrostKey(w, r, keyID)
	default:
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) handleGetFrostKey(w http.ResponseWriter, r *http.Request, id string) {
	// Get authenticated user for ownership verification
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	key, err := h.storage.GetFrostKey(r.Context(), id)
	if err != nil {
		if err == storage.ErrFrostKeyNotFound {
			h.errorResponse(w, http.StatusNotFound, "FROST key not found")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to get FROST key")
		return
	}

	// Verify ownership
	if key.OwnerID != "" && key.OwnerID != claims.UserID {
		h.errorResponse(w, http.StatusForbidden, "not authorized to access this FROST key")
		return
	}

	// Get shares
	shares, err := h.storage.ListFrostShares(r.Context(), id)
	if err != nil {
		slog.Error("failed to list FROST shares", "error", err)
		shares = []*storage.FrostShare{}
	}

	// Check if we can sign
	canSign, _ := h.frostCoordinator.CanSign(r.Context(), id)
	localShareCount, _ := h.frostCoordinator.GetAvailableShareCount(r.Context(), id)

	shareResponses := make([]FrostShareResponse, len(shares))
	for i, share := range shares {
		shareResponses[i] = FrostShareResponse{
			ID:              share.ID,
			FrostKeyID:      share.FrostKeyID,
			ShareIndex:      share.ShareIndex,
			HolderPubkey:    share.HolderPubkey,
			HolderBunkerURI: share.HolderBunkerURI,
			IsLocal:         share.IsLocal,
			CreatedAt:       share.CreatedAt,
		}
	}

	h.jsonResponse(w, http.StatusOK, FrostKeyDetailResponse{
		FrostKeyResponse: FrostKeyResponse{
			ID:          key.ID,
			Name:        key.Name,
			Pubkey:      key.Pubkey,
			Threshold:   key.Threshold,
			TotalShares: key.TotalShares,
			CreatedAt:   key.CreatedAt,
			CreatedBy:   key.CreatedBy,
		},
		Shares:      shareResponses,
		CanSign:     canSign,
		LocalShares: localShareCount,
	})
}

func (h *Handler) handleDeleteFrostKey(w http.ResponseWriter, r *http.Request, id string) {
	// Get authenticated user for ownership verification
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	// Get key to verify ownership
	key, err := h.storage.GetFrostKey(r.Context(), id)
	if err != nil {
		if err == storage.ErrFrostKeyNotFound {
			h.errorResponse(w, http.StatusNotFound, "FROST key not found")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to get FROST key")
		return
	}

	// Verify ownership
	if key.OwnerID != "" && key.OwnerID != claims.UserID {
		h.errorResponse(w, http.StatusForbidden, "not authorized to delete this FROST key")
		return
	}

	err = h.storage.DeleteFrostKey(r.Context(), id)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to delete FROST key")
		return
	}

	slog.Info("deleted FROST key", "id", id, "user_id", claims.UserID)
	h.jsonResponse(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *Handler) handleFrostKeyShares(w http.ResponseWriter, r *http.Request, keyID string) {
	shares, err := h.storage.ListFrostShares(r.Context(), keyID)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to list shares")
		return
	}

	response := make([]FrostShareResponse, len(shares))
	for i, share := range shares {
		response[i] = FrostShareResponse{
			ID:              share.ID,
			FrostKeyID:      share.FrostKeyID,
			ShareIndex:      share.ShareIndex,
			HolderPubkey:    share.HolderPubkey,
			HolderBunkerURI: share.HolderBunkerURI,
			IsLocal:         share.IsLocal,
			CreatedAt:       share.CreatedAt,
		}
	}
	h.jsonResponse(w, http.StatusOK, response)
}

func (h *Handler) handleExportFrostShare(w http.ResponseWriter, r *http.Request, keyID string, shareIndexStr string) {
	if r.Method != http.MethodGet {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if h.frostKeyGen == nil {
		h.errorResponse(w, http.StatusServiceUnavailable, "FROST not enabled")
		return
	}

	// Parse share index
	shareIndex, err := strconv.Atoi(shareIndexStr)
	if err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid share index")
		return
	}

	// Get the FROST key
	key, err := h.storage.GetFrostKey(r.Context(), keyID)
	if err != nil {
		if err == storage.ErrFrostKeyNotFound {
			h.errorResponse(w, http.StatusNotFound, "FROST key not found")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to get key")
		return
	}

	// Get the specific share
	share, err := h.storage.GetFrostShareByKeyAndIndex(r.Context(), keyID, shareIndex)
	if err != nil {
		if err == storage.ErrFrostShareNotFound {
			h.errorResponse(w, http.StatusNotFound, "share not found")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to get share")
		return
	}

	// Create the bundle
	bundle, err := h.frostKeyGen.CreateShareBundle(key, share)
	if err != nil {
		slog.Error("failed to create share bundle", "error", err, "key_id", keyID, "share_index", shareIndex)
		h.errorResponse(w, http.StatusInternalServerError, "failed to create share bundle")
		return
	}

	slog.Info("exported FROST share", "key_id", keyID, "share_index", shareIndex)
	h.jsonResponse(w, http.StatusOK, bundle)
}

type FrostSignRequest struct {
	Message string `json:"message"` // Hex-encoded message to sign (32 bytes)
}

type FrostSignResponse struct {
	Signature string `json:"signature"` // Hex-encoded signature
	Pubkey    string `json:"pubkey"`    // The FROST key's public key
}

func (h *Handler) handleFrostSign(w http.ResponseWriter, r *http.Request, keyID string) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var input FrostSignRequest
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Decode hex message
	message, err := hex.DecodeString(input.Message)
	if err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid message: must be hex encoded")
		return
	}

	if len(message) != 32 {
		h.errorResponse(w, http.StatusBadRequest, "message must be 32 bytes (event hash)")
		return
	}

	var signature string

	// First try local signing (fast path - all shares local)
	canSignLocal, _ := h.frostCoordinator.CanSign(r.Context(), keyID)
	if canSignLocal {
		signature, err = h.frostCoordinator.SignEvent(r.Context(), keyID, message)
		if err != nil {
			slog.Error("FROST local signing failed", "error", err, "key_id", keyID)
			h.errorResponse(w, http.StatusInternalServerError, "signing failed")
			return
		}
	} else {
		// Need remote signing - check if RemoteSigner is available
		if h.remoteSigner == nil {
			h.errorResponse(w, http.StatusPreconditionFailed, "insufficient local shares and remote signing not enabled")
			return
		}

		// Build remote holders map from non-local shares
		shares, err := h.storage.ListFrostShares(r.Context(), keyID)
		if err != nil {
			h.errorResponse(w, http.StatusInternalServerError, "failed to list shares")
			return
		}

		remoteHolders := make(map[int]string)
		for _, share := range shares {
			if !share.IsLocal && share.HolderPubkey != "" {
				remoteHolders[share.ShareIndex] = share.HolderPubkey
			}
		}

		if len(remoteHolders) == 0 {
			h.errorResponse(w, http.StatusPreconditionFailed, "no remote share holders configured")
			return
		}

		slog.Info("initiating distributed FROST signing", "key_id", keyID, "remote_holders", len(remoteHolders))

		sigBytes, err := h.remoteSigner.SignWithRemoteShares(r.Context(), keyID, message, remoteHolders)
		if err != nil {
			slog.Error("FROST distributed signing failed", "error", err, "key_id", keyID)
			h.errorResponse(w, http.StatusInternalServerError, "distributed signing failed: "+err.Error())
			return
		}
		signature = hex.EncodeToString(sigBytes)
	}

	// Get the key to return the pubkey
	key, err := h.storage.GetFrostKey(r.Context(), keyID)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to get key")
		return
	}

	h.jsonResponse(w, http.StatusOK, FrostSignResponse{
		Signature: signature,
		Pubkey:    key.Pubkey,
	})
}

func (h *Handler) handleFrostShares(w http.ResponseWriter, r *http.Request) {
	// Handle share import
	if r.Method == http.MethodPost {
		h.handleImportFrostShare(w, r)
		return
	}
	h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
}

func (h *Handler) handleImportFrostShare(w http.ResponseWriter, r *http.Request) {
	if h.frostKeyGen == nil {
		h.errorResponse(w, http.StatusServiceUnavailable, "FROST not enabled")
		return
	}

	var bundle frost.ShareBundle
	if err := json.NewDecoder(r.Body).Decode(&bundle); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid share bundle")
		return
	}

	// Validate required fields
	if bundle.ShareData == "" {
		h.errorResponse(w, http.StatusBadRequest, "share_data is required")
		return
	}
	if bundle.GroupPublicKey == "" {
		h.errorResponse(w, http.StatusBadRequest, "group_public_key is required")
		return
	}
	if bundle.Threshold < 1 || bundle.TotalShares < bundle.Threshold {
		h.errorResponse(w, http.StatusBadRequest, "invalid threshold configuration")
		return
	}
	if bundle.ShareIndex < 1 || bundle.ShareIndex > bundle.TotalShares {
		h.errorResponse(w, http.StatusBadRequest, "invalid share_index")
		return
	}

	// Decode share data
	shareData, err := hex.DecodeString(bundle.ShareData)
	if err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid share_data: must be hex encoded")
		return
	}

	// Decode group public key
	groupPubKey, err := hex.DecodeString(bundle.GroupPublicKey)
	if err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid group_public_key: must be hex encoded")
		return
	}

	// Decode verification shares
	var verificationShares []byte
	if bundle.VerificationShares != "" {
		verificationShares, err = hex.DecodeString(bundle.VerificationShares)
		if err != nil {
			h.errorResponse(w, http.StatusBadRequest, "invalid verification_shares: must be hex encoded")
			return
		}
	}

	// Calculate the Nostr pubkey from the group public key
	pubkey := frost.HexEncode(groupPubKey)
	if len(groupPubKey) == 33 {
		// Compressed format - extract x-coordinate
		pubkey = hex.EncodeToString(groupPubKey[1:])
	}

	// Check if the FROST key already exists (by pubkey)
	existingKey, err := h.storage.GetFrostKeyByPubkey(r.Context(), pubkey)
	var frostKeyID string

	if err == nil && existingKey != nil {
		// Key exists - use its ID
		frostKeyID = existingKey.ID

		// Check if share already exists
		existingShare, err := h.storage.GetFrostShareByKeyAndIndex(r.Context(), frostKeyID, bundle.ShareIndex)
		if err == nil && existingShare != nil {
			h.errorResponse(w, http.StatusConflict, "share already exists for this key and index")
			return
		}
	} else {
		// Key doesn't exist - create it
		frostKeyID = generateAPIID()
		newKey := &storage.FrostKey{
			ID:                 frostKeyID,
			Name:               fmt.Sprintf("Imported %s", pubkey[:8]),
			Pubkey:             pubkey,
			Threshold:          bundle.Threshold,
			TotalShares:        bundle.TotalShares,
			GroupPublicKey:     groupPubKey,
			VerificationShares: verificationShares,
			CreatedAt:          time.Now(),
			CreatedBy:          "import",
		}

		if err := h.storage.CreateFrostKey(r.Context(), newKey); err != nil {
			slog.Error("failed to create FROST key", "error", err)
			h.errorResponse(w, http.StatusInternalServerError, "failed to create FROST key")
			return
		}
		slog.Info("created FROST key from import", "key_id", frostKeyID, "pubkey", pubkey[:16]+"...")
	}

	// Import the share
	share, err := h.frostKeyGen.ImportShare(frostKeyID, bundle.ShareIndex, shareData, true)
	if err != nil {
		slog.Error("failed to import share", "error", err, "key_id", frostKeyID)
		h.errorResponse(w, http.StatusInternalServerError, "failed to import share: "+err.Error())
		return
	}

	// Store the share
	if err := h.storage.CreateFrostShare(r.Context(), share); err != nil {
		slog.Error("failed to store share", "error", err, "key_id", frostKeyID)
		h.errorResponse(w, http.StatusInternalServerError, "failed to store share")
		return
	}

	slog.Info("imported FROST share", "key_id", frostKeyID, "share_index", bundle.ShareIndex)
	h.jsonResponse(w, http.StatusOK, FrostShareResponse{
		ID:         share.ID,
		FrostKeyID: frostKeyID,
		ShareIndex: share.ShareIndex,
		IsLocal:    share.IsLocal,
		CreatedAt:  share.CreatedAt,
	})
}

// generateAPIID creates a random 16-byte hex ID for API resources
func generateAPIID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Helper function for hex decoding
func hex_DecodeString(s string) ([]byte, error) {
	return hex.DecodeString(s)
}

// Admin - Platform user management handlers

// handleAdminUsers handles GET /api/v1/admin/users (list platform users)
func (h *Handler) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Validate auth and admin role
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Check admin role (get user from storage if not config-based admin)
	if !strings.HasPrefix(claims.Username, "admin:") {
		user, err := h.storage.GetUser(r.Context(), claims.UserID)
		if err != nil || !user.IsAdmin() {
			h.errorResponse(w, http.StatusForbidden, "admin access required")
			return
		}
	}

	// Parse pagination
	limit := 50
	offset := 0
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	users, total, err := h.storage.ListPlatformUsers(r.Context(), limit, offset)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to list users")
		return
	}

	h.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"users":  users,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// handleAdminUserByPubkey handles /api/v1/admin/users/{pubkey}/services/{service}
func (h *Handler) handleAdminUserByPubkey(w http.ResponseWriter, r *http.Request) {
	// Validate auth and admin role
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Check admin role
	if !strings.HasPrefix(claims.Username, "admin:") {
		user, err := h.storage.GetUser(r.Context(), claims.UserID)
		if err != nil || !user.IsAdmin() {
			h.errorResponse(w, http.StatusForbidden, "admin access required")
			return
		}
	}

	// Parse path: /api/v1/admin/users/{pubkey}/services/{service}
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/admin/users/")
	parts := strings.Split(path, "/")

	if len(parts) < 1 || parts[0] == "" {
		h.errorResponse(w, http.StatusBadRequest, "pubkey required")
		return
	}

	pubkey := parts[0]

	// GET /api/v1/admin/users/{pubkey} - get user details
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		user, err := h.storage.GetPlatformUserAccess(r.Context(), pubkey)
		if err != nil {
			h.errorResponse(w, http.StatusNotFound, "user not found")
			return
		}

		h.jsonResponse(w, http.StatusOK, user)
		return
	}

	// /api/v1/admin/users/{pubkey}/services/{service}
	if len(parts) == 3 && parts[1] == "services" {
		serviceSlug := parts[2]

		switch r.Method {
		case http.MethodPut:
			// Grant service access
			if err := h.storage.GrantServiceAccess(r.Context(), pubkey, serviceSlug); err != nil {
				h.errorResponse(w, http.StatusInternalServerError, "failed to grant access")
				return
			}
			slog.Info("service access granted", "pubkey", pubkey[:16]+"...", "service", serviceSlug)
			h.jsonResponse(w, http.StatusOK, map[string]string{"status": "granted"})

		case http.MethodDelete:
			// Revoke service access
			if err := h.storage.RevokeServiceAccess(r.Context(), pubkey, serviceSlug); err != nil {
				h.errorResponse(w, http.StatusInternalServerError, "failed to revoke access")
				return
			}
			slog.Info("service access revoked", "pubkey", pubkey[:16]+"...", "service", serviceSlug)
			h.jsonResponse(w, http.StatusOK, map[string]string{"status": "revoked"})

		default:
			h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		}
		return
	}

	h.errorResponse(w, http.StatusNotFound, "endpoint not found")
}

// handleAdminServices handles GET /api/v1/admin/services (list available services)
func (h *Handler) handleAdminServices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Validate auth and admin role
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	// Check admin role
	if !strings.HasPrefix(claims.Username, "admin:") {
		user, err := h.storage.GetUser(r.Context(), claims.UserID)
		if err != nil || !user.IsAdmin() {
			h.errorResponse(w, http.StatusForbidden, "admin access required")
			return
		}
	}

	services, err := h.storage.ListServices(r.Context())
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to list services")
		return
	}

	h.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"services": services,
	})
}

// ============================================================================
// FROST Distributed DKG API
// ============================================================================

// DKGSessionResponse represents a DKG session in API responses
type DKGSessionResponse struct {
	ID           string     `json:"id"`
	Initiator    string     `json:"initiator"`
	Participants []string   `json:"participants"`
	Threshold    int        `json:"threshold"`
	TotalShares  int        `json:"total_shares"`
	Status       string     `json:"status"`
	Round        int        `json:"round"`
	StartedAt    time.Time  `json:"started_at"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	FrostKeyID   string     `json:"frost_key_id,omitempty"`
	GroupPubkey  string     `json:"group_pubkey,omitempty"`
	Error        string     `json:"error,omitempty"`
}

// InitDKGRequest is the request body for initiating a DKG session
type InitDKGRequest struct {
	Participants []string `json:"participants"` // Nostr pubkeys of participants (including self)
	Threshold    int      `json:"threshold"`    // Minimum shares required to sign
	KeyName      string   `json:"key_name,omitempty"` // Optional name for the resulting key
}

func (h *Handler) handleFrostDKG(w http.ResponseWriter, r *http.Request) {
	if h.distributedDKG == nil {
		h.errorResponse(w, http.StatusServiceUnavailable, "distributed DKG not enabled")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.handleListDKGSessions(w, r)
	case http.MethodPost:
		h.handleInitDKGSession(w, r)
	default:
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) handleListDKGSessions(w http.ResponseWriter, r *http.Request) {
	sessions := h.distributedDKG.ListSessions()

	response := make([]DKGSessionResponse, len(sessions))
	for i, s := range sessions {
		response[i] = DKGSessionResponse{
			ID:           s.ID,
			Initiator:    s.Initiator,
			Participants: s.Participants,
			Threshold:    s.Threshold,
			TotalShares:  s.TotalShares,
			Status:       string(s.Status),
			Round:        s.Round,
			StartedAt:    s.StartedAt,
			CompletedAt:  s.CompletedAt,
			FrostKeyID:   s.FrostKeyID,
			GroupPubkey:  s.GroupPubkey,
			Error:        s.Error,
		}
	}

	h.jsonResponse(w, http.StatusOK, response)
}

func (h *Handler) handleInitDKGSession(w http.ResponseWriter, r *http.Request) {
	var req InitDKGRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.Participants) < 2 {
		h.errorResponse(w, http.StatusBadRequest, "at least 2 participants required for distributed DKG")
		return
	}

	if req.Threshold < 2 {
		h.errorResponse(w, http.StatusBadRequest, "threshold must be at least 2 for distributed DKG")
		return
	}

	if req.Threshold > len(req.Participants) {
		h.errorResponse(w, http.StatusBadRequest, "threshold cannot exceed number of participants")
		return
	}

	// Validate pubkeys
	for _, p := range req.Participants {
		if len(p) != 64 {
			h.errorResponse(w, http.StatusBadRequest, fmt.Sprintf("invalid pubkey length: %s", p))
			return
		}
	}

	session, err := h.distributedDKG.InitiateSession(r.Context(), req.Participants, req.Threshold, req.KeyName)
	if err != nil {
		slog.Error("failed to initiate DKG session", "error", err)
		h.errorResponse(w, http.StatusInternalServerError, "failed to initiate DKG session: "+err.Error())
		return
	}

	slog.Info("initiated distributed DKG session",
		"session_id", session.ID,
		"participants", len(req.Participants),
		"threshold", req.Threshold,
	)

	h.jsonResponse(w, http.StatusCreated, DKGSessionResponse{
		ID:           session.ID,
		Initiator:    session.Initiator,
		Participants: session.Participants,
		Threshold:    session.Threshold,
		TotalShares:  session.TotalShares,
		Status:       string(session.Status),
		Round:        session.Round,
		StartedAt:    session.StartedAt,
	})
}

func (h *Handler) handleFrostDKGByID(w http.ResponseWriter, r *http.Request) {
	if h.distributedDKG == nil {
		h.errorResponse(w, http.StatusServiceUnavailable, "distributed DKG not enabled")
		return
	}

	// Parse session ID from URL
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/frost/dkg/")
	sessionID := strings.TrimSuffix(path, "/")
	if sessionID == "" {
		h.errorResponse(w, http.StatusBadRequest, "session ID required")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.handleGetDKGSession(w, r, sessionID)
	default:
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *Handler) handleGetDKGSession(w http.ResponseWriter, r *http.Request, sessionID string) {
	session := h.distributedDKG.GetSession(sessionID)
	if session == nil {
		h.errorResponse(w, http.StatusNotFound, "DKG session not found")
		return
	}

	h.jsonResponse(w, http.StatusOK, DKGSessionResponse{
		ID:           session.ID,
		Initiator:    session.Initiator,
		Participants: session.Participants,
		Threshold:    session.Threshold,
		TotalShares:  session.TotalShares,
		Status:       string(session.Status),
		Round:        session.Round,
		StartedAt:    session.StartedAt,
		CompletedAt:  session.CompletedAt,
		FrostKeyID:   session.FrostKeyID,
		GroupPubkey:  session.GroupPubkey,
		Error:        session.Error,
	})
}

// Helper methods

func (h *Handler) jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *Handler) errorResponse(w http.ResponseWriter, status int, message string) {
	h.jsonResponse(w, status, map[string]string{"error": message})
}
