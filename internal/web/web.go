package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"gitlab.coldforge.xyz/coldforge/coldforge-signer/internal/auth"
	"gitlab.coldforge.xyz/coldforge/coldforge-signer/internal/config"
	"gitlab.coldforge.xyz/coldforge/coldforge-signer/internal/storage"
)

//go:embed templates/*.html static/*
var content embed.FS

// StatusProvider provides signer status
type StatusProvider interface {
	GetStatus() map[string]interface{}
}

// RequestHandler handles pending request approvals
type RequestHandler interface {
	ApproveRequest(requestID string, pendingReq *storage.PendingRequest)
	DenyRequest(requestID string, pendingReq *storage.PendingRequest)
}

// Handler serves web UI pages
type Handler struct {
	config     *config.Config
	storage    storage.Storage
	authConfig *auth.Config
	templates  *template.Template
	status     StatusProvider
	reqHandler RequestHandler
}

// New creates a new web handler
func New(cfg *config.Config, store storage.Storage, status StatusProvider, reqHandler RequestHandler) (*Handler, error) {
	// Parse templates
	tmpl, err := template.New("").Funcs(template.FuncMap{
		"formatTime": func(t time.Time) string {
			return t.Format("2006-01-02 15:04:05")
		},
		"truncate": func(s string, n int) string {
			if len(s) <= n {
				return s
			}
			return s[:n] + "..."
		},
		"json": func(v interface{}) template.JS {
			b, _ := json.Marshal(v)
			return template.JS(b)
		},
	}).ParseFS(content, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse templates: %w", err)
	}

	return &Handler{
		config:  cfg,
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
		templates:  tmpl,
		status:     status,
		reqHandler: reqHandler,
	}, nil
}

// RegisterRoutes registers web UI routes
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Static files
	mux.HandleFunc("/static/", h.handleStatic)

	// Public pages
	mux.HandleFunc("/", h.handleHome)
	mux.HandleFunc("/login", h.handleLogin)
	mux.HandleFunc("/register", h.handleRegister)

	// Authorization pages (can be accessed via link)
	mux.HandleFunc("/approve/", h.handleApproval)

	// Protected pages (require auth)
	mux.HandleFunc("/dashboard", h.requireAuth(h.handleDashboard))
	mux.HandleFunc("/keys", h.requireAuth(h.handleKeys))
	mux.HandleFunc("/requests", h.requireAuth(h.handleRequests))
	mux.HandleFunc("/users", h.requireAuth(h.handleUsers))

	// API endpoints for web UI
	mux.HandleFunc("/web/api/login", h.handleAPILogin)
	mux.HandleFunc("/web/api/login/nip07", h.handleAPINIP07Login)
	mux.HandleFunc("/web/api/register", h.handleAPIRegister)
	mux.HandleFunc("/web/api/approve", h.handleAPIApprove)
	mux.HandleFunc("/web/api/deny", h.handleAPIDeny)
}

// handleStatic serves static files
func (h *Handler) handleStatic(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/")
	data, err := content.ReadFile(path)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// Set content type based on extension
	if strings.HasSuffix(path, ".css") {
		w.Header().Set("Content-Type", "text/css")
	} else if strings.HasSuffix(path, ".js") {
		w.Header().Set("Content-Type", "application/javascript")
	}

	w.Write(data)
}

// handleHome serves the home/landing page
func (h *Handler) handleHome(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	// Check if user is logged in
	user := h.getCurrentUser(r)
	if user != nil {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	h.render(w, "home.html", map[string]interface{}{
		"Title": "Coldforge Signer",
	})
}

// handleLogin serves the login page
func (h *Handler) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Check if already logged in
	user := h.getCurrentUser(r)
	if user != nil {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	h.render(w, "login.html", map[string]interface{}{
		"Title": "Login - Coldforge Signer",
	})
}

// handleRegister serves the registration page
func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	h.render(w, "register.html", map[string]interface{}{
		"Title": "Register - Coldforge Signer",
	})
}

// handleApproval serves the authorization approval page
func (h *Handler) handleApproval(w http.ResponseWriter, r *http.Request) {
	// Extract request ID from path: /approve/{id}
	requestID := strings.TrimPrefix(r.URL.Path, "/approve/")
	if requestID == "" {
		http.Error(w, "Missing request ID", http.StatusBadRequest)
		return
	}

	// Get the pending request
	req, err := h.storage.GetPendingRequest(r.Context(), requestID)
	if err != nil {
		if err == storage.ErrRequestNotFound || err == storage.ErrRequestExpired {
			h.render(w, "approval.html", map[string]interface{}{
				"Title":   "Request Not Found",
				"Error":   "This authorization request was not found or has expired.",
				"Expired": true,
			})
			return
		}
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}

	// Check if request is expired
	if time.Now().After(req.ExpiresAt) {
		h.render(w, "approval.html", map[string]interface{}{
			"Title":   "Request Expired",
			"Error":   "This authorization request has expired.",
			"Expired": true,
		})
		return
	}

	h.render(w, "approval.html", map[string]interface{}{
		"Title":     "Authorize Request - Coldforge Signer",
		"Request":   req,
		"RequestID": requestID,
		"ExpiresIn": time.Until(req.ExpiresAt).Round(time.Second).String(),
	})
}

// handleDashboard serves the admin dashboard
func (h *Handler) handleDashboard(w http.ResponseWriter, r *http.Request) {
	user := h.getCurrentUser(r)
	status := h.status.GetStatus()

	// Get counts
	keys, _ := h.storage.ListKeys(r.Context())
	users, _ := h.storage.ListUsers(r.Context())
	policies, _ := h.storage.ListPolicies(r.Context())

	// Count pending requests
	pendingCount := 0
	for _, key := range keys {
		pending, _ := h.storage.ListPendingRequests(r.Context(), key.Pubkey)
		pendingCount += len(pending)
	}

	h.render(w, "dashboard.html", map[string]interface{}{
		"Title":           "Dashboard - Coldforge Signer",
		"User":            user,
		"Status":          status,
		"KeyCount":        len(keys),
		"UserCount":       len(users),
		"PolicyCount":     len(policies),
		"PendingCount":    pendingCount,
		"ConnectedRelays": status["connected_relays"],
	})
}

// handleKeys serves the keys management page
func (h *Handler) handleKeys(w http.ResponseWriter, r *http.Request) {
	user := h.getCurrentUser(r)
	keys, _ := h.storage.ListKeys(r.Context())

	h.render(w, "keys.html", map[string]interface{}{
		"Title": "Keys - Coldforge Signer",
		"User":  user,
		"Keys":  keys,
	})
}

// handleRequests serves the pending requests page
func (h *Handler) handleRequests(w http.ResponseWriter, r *http.Request) {
	user := h.getCurrentUser(r)
	keys, _ := h.storage.ListKeys(r.Context())

	var allPending []*storage.PendingRequest
	for _, key := range keys {
		pending, _ := h.storage.ListPendingRequests(r.Context(), key.Pubkey)
		allPending = append(allPending, pending...)
	}

	h.render(w, "requests.html", map[string]interface{}{
		"Title":    "Pending Requests - Coldforge Signer",
		"User":     user,
		"Requests": allPending,
	})
}

// handleUsers serves the users management page
func (h *Handler) handleUsers(w http.ResponseWriter, r *http.Request) {
	user := h.getCurrentUser(r)
	users, _ := h.storage.ListUsers(r.Context())

	h.render(w, "users.html", map[string]interface{}{
		"Title": "Users - Coldforge Signer",
		"User":  user,
		"Users": users,
	})
}

// API handlers

// handleAPILogin handles login form submission
func (h *Handler) handleAPILogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.jsonError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		MFACode  string `json:"mfa_code"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	// Get user
	user, err := h.storage.GetUserByUsername(r.Context(), req.Username)
	if err != nil {
		h.jsonError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Check lockout
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		h.jsonError(w, http.StatusForbidden, "Account locked")
		return
	}

	// Verify password
	if !auth.VerifyPassword(req.Password, user.PasswordHash) {
		h.storage.IncrementFailedLogins(r.Context(), user.ID)
		h.jsonError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Check MFA
	if user.MFAEnabled {
		if req.MFACode == "" {
			h.jsonResponse(w, http.StatusOK, map[string]interface{}{
				"mfa_required": true,
			})
			return
		}
		if !auth.ValidateMFACode(user.MFASecret, req.MFACode) {
			// Check backup codes
			if idx := auth.ValidateBackupCode(req.MFACode, user.BackupCodes); idx < 0 {
				h.jsonError(w, http.StatusUnauthorized, "Invalid MFA code")
				return
			}
		}
	}

	// Reset failed logins and generate token
	h.storage.ResetFailedLogins(r.Context(), user.ID)
	token, expiresAt, err := auth.GenerateJWT(h.authConfig, user.ID, user.Username)
	if err != nil {
		h.jsonError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	// Set cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	h.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"redirect": "/dashboard",
	})
}

// handleAPINIP07Login handles NIP-07 login
func (h *Handler) handleAPINIP07Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.jsonError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Pubkey    string `json:"pubkey"`
		Signature string `json:"signature"`
		Challenge string `json:"challenge"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	// Verify pubkey is an admin
	isAdmin := false
	for _, admin := range h.config.Auth.AdminPubkeys {
		if admin == req.Pubkey {
			isAdmin = true
			break
		}
	}

	if !isAdmin {
		h.jsonError(w, http.StatusForbidden, "Not an admin pubkey")
		return
	}

	// TODO: Verify signature against challenge
	// For now, we trust that the signature was verified client-side
	// In production, we should verify the signature server-side

	// Generate a session token for the admin
	token, expiresAt, err := auth.GenerateJWT(h.authConfig, req.Pubkey, "admin:"+req.Pubkey[:8])
	if err != nil {
		h.jsonError(w, http.StatusInternalServerError, "Failed to generate token")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})

	slog.Info("admin logged in via NIP-07", "pubkey", req.Pubkey[:16]+"...")

	h.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"redirect": "/dashboard",
	})
}

// handleAPIRegister handles registration form submission
func (h *Handler) handleAPIRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.jsonError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Username string `json:"username"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	// Validate
	if len(req.Username) < 3 {
		h.jsonError(w, http.StatusBadRequest, "Username must be at least 3 characters")
		return
	}
	if len(req.Password) < 8 {
		h.jsonError(w, http.StatusBadRequest, "Password must be at least 8 characters")
		return
	}

	// Check if exists
	if _, err := h.storage.GetUserByUsername(r.Context(), req.Username); err == nil {
		h.jsonError(w, http.StatusConflict, "Username already exists")
		return
	}

	// Hash password
	hash, err := auth.HashPassword(req.Password, h.authConfig.BcryptCost)
	if err != nil {
		h.jsonError(w, http.StatusInternalServerError, "Failed to hash password")
		return
	}

	// Create user
	userID, _ := auth.GenerateUserID()
	now := time.Now()
	user := &storage.User{
		ID:           userID,
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: hash,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := h.storage.CreateUser(r.Context(), user); err != nil {
		h.jsonError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}

	slog.Info("user registered via web", "username", req.Username)

	h.jsonResponse(w, http.StatusCreated, map[string]interface{}{
		"success":  true,
		"redirect": "/login",
	})
}

// handleAPIApprove handles request approval
func (h *Handler) handleAPIApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.jsonError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		RequestID string `json:"request_id"`
		Remember  bool   `json:"remember"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	// Get pending request
	pendingReq, err := h.storage.GetPendingRequest(r.Context(), req.RequestID)
	if err != nil {
		h.jsonError(w, http.StatusNotFound, "Request not found or expired")
		return
	}

	// If remember, create a persistent permission
	if req.Remember {
		perm := &storage.Permission{
			KeyID:      pendingReq.KeyPubkey,
			UserPubkey: pendingReq.ClientPubkey,
			Methods:    []string{pendingReq.Method, "connect"},
		}
		h.storage.SetPermission(r.Context(), perm)
	}

	// Delete and notify signer
	h.storage.DeletePendingRequest(r.Context(), req.RequestID)
	h.reqHandler.ApproveRequest(req.RequestID, pendingReq)

	slog.Info("request approved via web", "id", req.RequestID, "method", pendingReq.Method)

	h.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Request approved",
	})
}

// handleAPIDeny handles request denial
func (h *Handler) handleAPIDeny(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.jsonError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		RequestID string `json:"request_id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.jsonError(w, http.StatusBadRequest, "Invalid request")
		return
	}

	pendingReq, err := h.storage.GetPendingRequest(r.Context(), req.RequestID)
	if err != nil {
		h.jsonError(w, http.StatusNotFound, "Request not found or expired")
		return
	}

	h.storage.DeletePendingRequest(r.Context(), req.RequestID)
	h.reqHandler.DenyRequest(req.RequestID, pendingReq)

	slog.Info("request denied via web", "id", req.RequestID, "method", pendingReq.Method)

	h.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Request denied",
	})
}

// Helper methods

func (h *Handler) render(w http.ResponseWriter, name string, data map[string]interface{}) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, name, data); err != nil {
		slog.Error("template error", "template", name, "error", err)
		http.Error(w, "Internal error", http.StatusInternalServerError)
	}
}

func (h *Handler) jsonResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (h *Handler) jsonError(w http.ResponseWriter, status int, message string) {
	h.jsonResponse(w, status, map[string]string{"error": message})
}

func (h *Handler) getCurrentUser(r *http.Request) *storage.User {
	cookie, err := r.Cookie("auth_token")
	if err != nil {
		return nil
	}

	claims, err := auth.ValidateJWT(h.authConfig, cookie.Value)
	if err != nil {
		return nil
	}

	// Check if this is an admin login (NIP-07)
	if strings.HasPrefix(claims.Username, "admin:") {
		return &storage.User{
			ID:       claims.UserID,
			Username: claims.Username,
		}
	}

	user, err := h.storage.GetUser(r.Context(), claims.UserID)
	if err != nil {
		return nil
	}

	return user
}

func (h *Handler) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user := h.getCurrentUser(r)
		if user == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next(w, r)
	}
}
