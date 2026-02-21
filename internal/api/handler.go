package api

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"git.coldforge.xyz/coldforge/cloistr-signer/internal/auth"
	"git.coldforge.xyz/coldforge/cloistr-signer/internal/config"
	"git.coldforge.xyz/coldforge/cloistr-signer/internal/crypto"
	"git.coldforge.xyz/coldforge/cloistr-signer/internal/signer"
	"git.coldforge.xyz/coldforge/cloistr-signer/internal/storage"
)

// Handler manages HTTP API endpoints
type Handler struct {
	config     *config.Config
	signer     *signer.Signer
	storage    storage.Storage
	authConfig *auth.Config
	encryptor  *crypto.Encryptor
}

// NewHandler creates a new API handler
func NewHandler(cfg *config.Config, signer *signer.Signer, store storage.Storage, encryptor *crypto.Encryptor) *Handler {
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
		encryptor: encryptor,
	}
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
	PrivateKey string `json:"private_key,omitempty"` // Optional - generate if not provided
}

type KeyResponse struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Pubkey          string    `json:"pubkey"`
	RequireApproval bool      `json:"require_approval"`
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
	keys, err := h.storage.ListKeys(r.Context())
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
			RequireApproval: key.RequireApproval,
			CreatedAt:       key.CreatedAt,
		}
	}

	h.jsonResponse(w, http.StatusOK, response)
}

func (h *Handler) handleCreateKey(w http.ResponseWriter, r *http.Request) {
	var req CreateKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
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

	// Encrypt the private key if encryptor is configured
	encryptedKey := privateKey
	if h.encryptor != nil {
		encrypted, err := h.encryptor.Encrypt(privateKey)
		if err != nil {
			slog.Error("failed to encrypt private key", "error", err)
			h.errorResponse(w, http.StatusInternalServerError, "failed to encrypt key")
			return
		}
		encryptedKey = encrypted
	}

	key := &storage.Key{
		ID:            pubkey[:16],
		Name:          req.Name,
		Pubkey:        pubkey,
		EncryptedNsec: encryptedKey,
		CreatedAt:     time.Now(),
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
		ID:        key.ID,
		Name:      key.Name,
		Pubkey:    key.Pubkey,
		CreatedAt: key.CreatedAt,
	})
}

func (h *Handler) handleGetKey(w http.ResponseWriter, r *http.Request, id string) {
	key, err := h.storage.GetKey(r.Context(), id)
	if err != nil {
		if err == storage.ErrKeyNotFound {
			h.errorResponse(w, http.StatusNotFound, "key not found")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to get key")
		return
	}

	h.jsonResponse(w, http.StatusOK, KeyResponse{
		ID:        key.ID,
		Name:      key.Name,
		Pubkey:    key.Pubkey,
		CreatedAt: key.CreatedAt,
	})
}

type UpdateKeyRequest struct {
	Name            *string `json:"name,omitempty"`
	RequireApproval *bool   `json:"require_approval,omitempty"`
}

func (h *Handler) handleUpdateKey(w http.ResponseWriter, r *http.Request, id string) {
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

	// Apply updates
	if req.Name != nil {
		key.Name = *req.Name
	}
	if req.RequireApproval != nil {
		key.RequireApproval = *req.RequireApproval
	}

	// Save updates
	if err := h.storage.UpdateKey(r.Context(), key); err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to update key")
		return
	}

	slog.Info("updated key", "id", id, "require_approval", key.RequireApproval)

	h.jsonResponse(w, http.StatusOK, KeyResponse{
		ID:              key.ID,
		Name:            key.Name,
		Pubkey:          key.Pubkey,
		RequireApproval: key.RequireApproval,
		CreatedAt:       key.CreatedAt,
	})
}

func (h *Handler) handleDeleteKey(w http.ResponseWriter, r *http.Request, id string) {
	if err := h.storage.DeleteKey(r.Context(), id); err != nil {
		if err == storage.ErrKeyNotFound {
			h.errorResponse(w, http.StatusNotFound, "key not found")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to delete key")
		return
	}

	slog.Info("deleted key", "id", id)
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

	if err := h.storage.DeletePermission(r.Context(), key.Pubkey, pubkey); err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to delete permission")
		return
	}

	slog.Info("deleted permission", "key", keyID, "user", pubkey[:16]+"...")
	w.WriteHeader(http.StatusNoContent)
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

	// Create user
	now := time.Now()
	user := &storage.User{
		ID:           userID,
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: passwordHash,
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

	slog.Info("user registered", "username", req.Username, "user_id", userID)

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

	// Generate JWT
	token, expiresAt, err := auth.GenerateJWT(h.authConfig, user.ID, user.Username)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	// Create session
	sessionID, _ := auth.GenerateSessionID()
	session := &storage.UserSession{
		ID:        sessionID,
		UserID:    user.ID,
		Token:     token[:16], // Store prefix for revocation check
		UserAgent: r.UserAgent(),
		IPAddress: r.RemoteAddr,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
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

	// Delete all sessions for this user (or just the current one based on token)
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

// validateAuthHeader validates the Authorization header and returns JWT claims
func (h *Handler) validateAuthHeader(r *http.Request) (*auth.JWTClaims, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, auth.ErrInvalidToken
	}

	// Expect "Bearer <token>"
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return nil, auth.ErrInvalidToken
	}

	return auth.ValidateJWT(h.authConfig, parts[1])
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
	relays := h.config.Relays
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
	Success     bool   `json:"success"`
	AppName     string `json:"app_name,omitempty"`
	AppURL      string `json:"app_url,omitempty"`
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
	var relay, secret, appName, appURL string
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

	// Get all keys and create name mappings
	keys, err := h.storage.ListKeys(r.Context())
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
			response.Relays[key.Pubkey] = h.config.Relays
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

	// For now, return empty list - audit logs will be added when audit logger is integrated
	h.jsonResponse(w, http.StatusOK, []AuditLogEntry{})
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
