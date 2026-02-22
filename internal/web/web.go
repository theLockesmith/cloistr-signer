package web

import (
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"

	"git.coldforge.xyz/coldforge/cloistr-signer/internal/auth"
	"git.coldforge.xyz/coldforge/cloistr-signer/internal/config"
	"git.coldforge.xyz/coldforge/cloistr-signer/internal/storage"
)

// EventPreview contains parsed event data for display in approval UI
type EventPreview struct {
	Kind        int      `json:"kind"`
	KindName    string   `json:"kind_name"`
	Content     string   `json:"content"`
	ContentFull string   `json:"content_full"`
	Tags        []string `json:"tags"`       // Human-readable tag summary
	Mentions    []string `json:"mentions"`   // npubs mentioned
	CreatedAt   string   `json:"created_at"`
	HasContent  bool     `json:"has_content"`
}

// kindName returns a human-readable name for a Nostr event kind
func kindName(kind int) string {
	names := map[int]string{
		0:     "Metadata",
		1:     "Short Text Note",
		2:     "Recommend Relay",
		3:     "Follows",
		4:     "Encrypted DM",
		5:     "Event Deletion",
		6:     "Repost",
		7:     "Reaction",
		8:     "Badge Award",
		9:     "Group Chat Message",
		10:    "Group Chat Threaded Reply",
		11:    "Group Thread",
		12:    "Group Thread Reply",
		13:    "Seal",
		14:    "Direct Message",
		16:    "Generic Repost",
		17:    "Reaction to Website",
		40:    "Channel Creation",
		41:    "Channel Metadata",
		42:    "Channel Message",
		43:    "Channel Hide Message",
		44:    "Channel Mute User",
		1021:  "Bid",
		1022:  "Bid Confirmation",
		1040:  "OpenTimestamps",
		1059:  "Gift Wrap",
		1063:  "File Metadata",
		1311:  "Live Chat Message",
		1617:  "Patches",
		1621:  "Issues",
		1622:  "Replies",
		1971:  "Problem Tracker",
		1984:  "Reporting",
		1985:  "Label",
		4550:  "Community Post Approval",
		5000:  "Job Request",
		6000:  "Job Result",
		7000:  "Job Feedback",
		9041:  "Zap Goal",
		9734:  "Zap Request",
		9735:  "Zap",
		10000: "Mute List",
		10001: "Pin List",
		10002: "Relay List",
		10003: "Bookmark List",
		10004: "Communities List",
		10005: "Public Chats List",
		10006: "Blocked Relays List",
		10007: "Search Relays List",
		10009: "User Groups",
		10015: "Interests List",
		10030: "Emoji List",
		10096: "File Storage Servers",
		13194: "Wallet Info",
		21000: "Lightning Pub RPC",
		22242: "Client Authentication",
		23194: "Wallet Request",
		23195: "Wallet Response",
		24133: "NIP-46 Request",
		27235: "HTTP Auth",
		30000: "Follow Sets",
		30001: "Generic Lists",
		30002: "Relay Sets",
		30003: "Bookmark Sets",
		30004: "Curation Sets",
		30008: "Profile Badges",
		30009: "Badge Definition",
		30015: "Interest Sets",
		30017: "Create/Update Stall",
		30018: "Create/Update Product",
		30019: "Marketplace UI/UX",
		30020: "Product Sold as Auction",
		30023: "Long-form Content",
		30024: "Draft Long-form Content",
		30030: "Emoji Sets",
		30063: "Release Artifact Sets",
		30078: "App-specific Data",
		30311: "Live Event",
		30315: "User Statuses",
		30402: "Classified Listing",
		30403: "Draft Classified Listing",
		31922: "Date-Based Calendar Event",
		31923: "Time-Based Calendar Event",
		31924: "Calendar",
		31925: "Calendar Event RSVP",
		31989: "Handler Recommendation",
		31990: "Handler Information",
		34235: "Video Event",
		34236: "Short-form Portrait Video",
		34237: "Video View",
		34550: "Community Definition",
	}

	if name, ok := names[kind]; ok {
		return name
	}
	if kind >= 5000 && kind < 6000 {
		return "Job Request"
	}
	if kind >= 6000 && kind < 7000 {
		return "Job Result"
	}
	if kind >= 7000 && kind < 8000 {
		return "Job Feedback"
	}
	return fmt.Sprintf("Kind %d", kind)
}

// parseEventPreview parses a Nostr event JSON string into an EventPreview
func parseEventPreview(eventJSON string) *EventPreview {
	var event nostr.Event
	if err := json.Unmarshal([]byte(eventJSON), &event); err != nil {
		return nil
	}

	preview := &EventPreview{
		Kind:       event.Kind,
		KindName:   kindName(event.Kind),
		HasContent: len(event.Content) > 0,
	}

	// Truncate content for preview
	if len(event.Content) > 200 {
		preview.Content = event.Content[:200] + "..."
	} else {
		preview.Content = event.Content
	}
	preview.ContentFull = event.Content

	// Format created_at if present
	if event.CreatedAt > 0 {
		preview.CreatedAt = time.Unix(int64(event.CreatedAt), 0).Format("2006-01-02 15:04:05")
	}

	// Parse tags for context
	for _, tag := range event.Tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "p":
			// Mention
			if len(tag[1]) == 64 {
				npub, _ := nip19.EncodePublicKey(tag[1])
				if npub != "" {
					preview.Mentions = append(preview.Mentions, npub[:16]+"...")
				}
			}
		case "e":
			preview.Tags = append(preview.Tags, "replies to event")
		case "t":
			preview.Tags = append(preview.Tags, "#"+tag[1])
		case "a":
			preview.Tags = append(preview.Tags, "references article")
		}
	}

	return preview
}

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
	config        *config.Config
	storage       storage.Storage
	authConfig    *auth.Config
	pageTemplates map[string]*template.Template
	status        StatusProvider
	reqHandler    RequestHandler
}

// New creates a new web handler
func New(cfg *config.Config, store storage.Storage, status StatusProvider, reqHandler RequestHandler) (*Handler, error) {
	// Create base template with functions
	funcs := template.FuncMap{
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
		"kindName": kindName,
		"npubShort": func(pubkey string) string {
			if len(pubkey) != 64 {
				return pubkey
			}
			npub, err := nip19.EncodePublicKey(pubkey)
			if err != nil {
				return pubkey[:12] + "..."
			}
			return npub[:12] + "..." + npub[len(npub)-4:]
		},
	}

	// Parse base template
	baseTmpl, err := template.New("base.html").Funcs(funcs).ParseFS(content, "templates/base.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse base template: %w", err)
	}

	// Create a map of page templates, each inheriting from base
	templates := make(map[string]*template.Template)
	pageFiles := []string{"home.html", "login.html", "register.html", "approval.html", "dashboard.html", "keys.html", "apps.html", "requests.html", "users.html"}

	for _, page := range pageFiles {
		// Clone base template
		tmpl, err := baseTmpl.Clone()
		if err != nil {
			return nil, fmt.Errorf("failed to clone base template: %w", err)
		}
		// Parse the page template
		tmpl, err = tmpl.ParseFS(content, "templates/"+page)
		if err != nil {
			return nil, fmt.Errorf("failed to parse template %s: %w", page, err)
		}
		templates[page] = tmpl
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
		pageTemplates: templates,
		status:        status,
		reqHandler:    reqHandler,
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
	mux.HandleFunc("/apps", h.requireAuth(h.handleApps))
	mux.HandleFunc("/requests", h.requireAuth(h.handleRequests))
	mux.HandleFunc("/users", h.requireAuth(h.handleUsers))

	// Logout (GET - simple redirect)
	mux.HandleFunc("/logout", h.handleLogout)

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
	} else if strings.HasSuffix(path, ".svg") {
		w.Header().Set("Content-Type", "image/svg+xml")
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
		"Title": "Cloistr Signer",
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
		"Title": "Login - Cloistr Signer",
	})
}

// handleRegister serves the registration page
func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request) {
	h.render(w, "register.html", map[string]interface{}{
		"Title": "Register - Cloistr Signer",
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

	// Parse event preview if this is a sign_event request
	var eventPreview *EventPreview
	if req.Method == "sign_event" {
		if eventJSON, ok := req.Params["0"].(string); ok {
			eventPreview = parseEventPreview(eventJSON)
		}
	}

	// Get key name for display
	var keyName string
	keys, _ := h.storage.ListKeys(r.Context())
	for _, key := range keys {
		if key.Pubkey == req.KeyPubkey {
			keyName = key.Name
			break
		}
	}

	h.render(w, "approval.html", map[string]interface{}{
		"Title":        "Authorize Request - Cloistr Signer",
		"Request":      req,
		"RequestID":    requestID,
		"ExpiresIn":    time.Until(req.ExpiresAt).Round(time.Second).String(),
		"EventPreview": eventPreview,
		"KeyName":      keyName,
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
		"Title":           "Dashboard - Cloistr Signer",
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
		"Title": "Keys - Cloistr Signer",
		"User":  user,
		"Keys":  keys,
	})
}

// AppPermissions groups permissions by key for display
type AppPermissions struct {
	KeyID       string
	KeyName     string
	KeyPubkey   string
	Permissions []*storage.Permission
}

// handleApps serves the connected apps management page
func (h *Handler) handleApps(w http.ResponseWriter, r *http.Request) {
	user := h.getCurrentUser(r)
	keys, _ := h.storage.ListKeys(r.Context())

	var apps []AppPermissions
	for _, key := range keys {
		perms, _ := h.storage.ListPermissions(r.Context(), key.Pubkey)
		if len(perms) > 0 {
			apps = append(apps, AppPermissions{
				KeyID:       key.ID,
				KeyName:     key.Name,
				KeyPubkey:   key.Pubkey,
				Permissions: perms,
			})
		}
	}

	h.render(w, "apps.html", map[string]interface{}{
		"Title": "Connected Apps - Cloistr Signer",
		"User":  user,
		"Apps":  apps,
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
		"Title":    "Pending Requests - Cloistr Signer",
		"User":     user,
		"Requests": allPending,
	})
}

// handleUsers serves the users management page (admin only)
func (h *Handler) handleUsers(w http.ResponseWriter, r *http.Request) {
	user := h.getCurrentUser(r)
	if user == nil || !user.IsAdmin() {
		http.Redirect(w, r, "/dashboard", http.StatusFound)
		return
	}

	users, _ := h.storage.ListUsers(r.Context())

	h.render(w, "users.html", map[string]interface{}{
		"Title": "Users - Cloistr Signer",
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
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
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

	// TODO: Verify signature against challenge
	// For now, we trust that the signature was verified client-side
	// In production, we should verify the signature server-side

	// Check if pubkey belongs to a registered user
	user, err := h.storage.GetUserByPubkey(r.Context(), req.Pubkey)
	if err != nil {
		// Fall back to admin pubkeys config for backwards compatibility
		isAdmin := false
		for _, admin := range h.config.Auth.AdminPubkeys {
			if admin == req.Pubkey {
				isAdmin = true
				break
			}
		}
		if !isAdmin {
			h.jsonError(w, http.StatusForbidden, "No account linked to this pubkey")
			return
		}
		// Config-based admin login
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
			Secure:   true,
			SameSite: http.SameSiteLaxMode,
		})
		slog.Info("admin logged in via NIP-07 (config)", "pubkey", req.Pubkey[:16]+"...")
		h.jsonResponse(w, http.StatusOK, map[string]interface{}{
			"success":  true,
			"redirect": "/dashboard",
		})
		return
	}

	// User found by pubkey - generate session token
	token, expiresAt, err := auth.GenerateJWT(h.authConfig, user.ID, user.Username)
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
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})

	slog.Info("user logged in via NIP-07", "username", user.Username, "pubkey", req.Pubkey[:16]+"...")

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
		Pubkey   string `json:"pubkey"`
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

	// Parse pubkey (npub bech32 or hex)
	pubkeyHex := ""
	if req.Pubkey != "" {
		if strings.HasPrefix(req.Pubkey, "npub1") {
			_, val, err := nip19.Decode(req.Pubkey)
			if err != nil {
				h.jsonError(w, http.StatusBadRequest, "Invalid npub format")
				return
			}
			pubkeyHex = val.(string)
		} else {
			// Validate hex format
			if len(req.Pubkey) != 64 {
				h.jsonError(w, http.StatusBadRequest, "Public key must be 64 hex characters or npub format")
				return
			}
			if _, err := hex.DecodeString(req.Pubkey); err != nil {
				h.jsonError(w, http.StatusBadRequest, "Invalid hex public key")
				return
			}
			pubkeyHex = req.Pubkey
		}
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

	// Determine role: first user gets admin
	role := "user"
	existingUsers, _ := h.storage.ListUsers(r.Context())
	if len(existingUsers) == 0 {
		role = "admin"
	}

	// Create user
	userID, _ := auth.GenerateUserID()
	now := time.Now()
	user := &storage.User{
		ID:           userID,
		Username:     req.Username,
		Email:        req.Email,
		Pubkey:       pubkeyHex,
		Role:         role,
		PasswordHash: hash,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := h.storage.CreateUser(r.Context(), user); err != nil {
		h.jsonError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}

	slog.Info("user registered via web", "username", req.Username, "role", role)

	h.jsonResponse(w, http.StatusCreated, map[string]interface{}{
		"success":  true,
		"redirect": "/login",
	})
}

// handleLogout clears the auth cookie and redirects to login
func (h *Handler) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Clear the auth cookie by setting it to expire in the past
	http.SetCookie(w, &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

// handleAPIApprove handles request approval
func (h *Handler) handleAPIApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.jsonError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		RequestID    string `json:"request_id"`
		Remember     bool   `json:"remember"`
		AllowedKinds []int  `json:"allowed_kinds,omitempty"`
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
			KeyID:        pendingReq.KeyPubkey,
			UserPubkey:   pendingReq.ClientPubkey,
			Methods:      []string{pendingReq.Method, "connect"},
			AllowedKinds: req.AllowedKinds,
		}
		h.storage.SetPermission(r.Context(), perm)

		if len(req.AllowedKinds) > 0 {
			slog.Info("request approved via web with kind restriction",
				"id", req.RequestID,
				"method", pendingReq.Method,
				"allowed_kinds", req.AllowedKinds)
		} else {
			slog.Info("request approved via web with full access",
				"id", req.RequestID,
				"method", pendingReq.Method)
		}
	} else {
		slog.Info("request approved via web (one-time)", "id", req.RequestID, "method", pendingReq.Method)
	}

	// Delete and notify signer
	h.storage.DeletePendingRequest(r.Context(), req.RequestID)
	h.reqHandler.ApproveRequest(req.RequestID, pendingReq)

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
	tmpl, ok := h.pageTemplates[name]
	if !ok {
		slog.Error("template not found", "template", name)
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	if err := tmpl.ExecuteTemplate(w, "base", data); err != nil {
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

	// Check if this is a config-based admin login (NIP-07 via AdminPubkeys)
	if strings.HasPrefix(claims.Username, "admin:") {
		return &storage.User{
			ID:       claims.UserID,
			Username: claims.Username,
			Role:     "admin",
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
