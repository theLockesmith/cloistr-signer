package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"gitlab.coldforge.xyz/coldforge/coldforge-signer/internal/config"
	"gitlab.coldforge.xyz/coldforge/coldforge-signer/internal/signer"
	"gitlab.coldforge.xyz/coldforge/coldforge-signer/internal/storage"
)

// Handler manages HTTP API endpoints
type Handler struct {
	config  *config.Config
	signer  *signer.Signer
	storage storage.Storage
}

// NewHandler creates a new API handler
func NewHandler(cfg *config.Config, signer *signer.Signer, store storage.Storage) *Handler {
	return &Handler{
		config:  cfg,
		signer:  signer,
		storage: store,
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

	// Status
	mux.HandleFunc("/api/v1/status", h.handleStatus)
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
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Pubkey    string    `json:"pubkey"`
	CreatedAt time.Time `json:"created_at"`
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
			ID:        key.ID,
			Name:      key.Name,
			Pubkey:    key.Pubkey,
			CreatedAt: key.CreatedAt,
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
		// Use provided private key
		privateKey = req.PrivateKey
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

	key := &storage.Key{
		ID:            pubkey[:16],
		Name:          req.Name,
		Pubkey:        pubkey,
		EncryptedNsec: privateKey, // TODO: Encrypt with Vault
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
}

func (h *Handler) handleListPermissions(w http.ResponseWriter, r *http.Request, keyID string) {
	perms, err := h.storage.ListPermissions(r.Context(), keyID)
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

// Status endpoint

func (h *Handler) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	status := h.signer.GetStatus()
	h.jsonResponse(w, http.StatusOK, status)
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
