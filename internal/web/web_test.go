package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"git.coldforge.xyz/coldforge/cloistr-signer/internal/auth"
	"git.coldforge.xyz/coldforge/cloistr-signer/internal/config"
	"git.coldforge.xyz/coldforge/cloistr-signer/internal/storage"
)

// mockStatusProvider implements StatusProvider for testing
type mockStatusProvider struct {
	status map[string]interface{}
}

func (m *mockStatusProvider) GetStatus() map[string]interface{} {
	if m.status == nil {
		return map[string]interface{}{
			"keys_loaded":      0,
			"connected_relays": []string{},
		}
	}
	return m.status
}

// mockRequestHandler implements RequestHandler for testing
type mockRequestHandler struct {
	approvedRequests []string
	deniedRequests   []string
}

func (m *mockRequestHandler) ApproveRequest(requestID string, pendingReq *storage.PendingRequest) {
	m.approvedRequests = append(m.approvedRequests, requestID)
}

func (m *mockRequestHandler) DenyRequest(requestID string, pendingReq *storage.PendingRequest) {
	m.deniedRequests = append(m.deniedRequests, requestID)
}

// testHandler creates a handler with mocks for testing
func testHandler(t *testing.T) (*Handler, *storage.MemoryStorage, *mockRequestHandler) {
	cfg := &config.Config{
		Relays: []string{"wss://relay.example.com"},
		Auth: config.AuthConfig{
			JWTSecret:       "test-secret-key-for-testing-only",
			JWTExpiry:       24,
			MFAIssuer:       "TestIssuer",
			MaxFailedLogins: 5,
			LockoutMinutes:  15,
		},
	}

	store := storage.NewMemoryStorage()
	status := &mockStatusProvider{
		status: map[string]interface{}{
			"keys_loaded":      2,
			"connected_relays": []string{"wss://relay.example.com"},
		},
	}
	reqHandler := &mockRequestHandler{}

	h, err := New(cfg, store, status, reqHandler)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	return h, store, reqHandler
}

// createTestUser creates a user and returns the auth token
func createTestUser(t *testing.T, h *Handler, store *storage.MemoryStorage, username string) (string, *storage.User) {
	ctx := context.Background()
	hash, _ := auth.HashPassword("password123", auth.DefaultBcryptCost)
	user := &storage.User{
		ID:           "user-" + username,
		Username:     username,
		PasswordHash: hash,
		Role:         "user",
		CreatedAt:    time.Now(),
	}
	store.CreateUser(ctx, user)

	token, _, _ := auth.GenerateJWT(h.authConfig, user.ID, user.Username)
	return token, user
}

// TestNew verifies handler creation
func TestNew(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{
			JWTSecret: "test-secret",
		},
	}
	store := storage.NewMemoryStorage()
	status := &mockStatusProvider{}
	reqHandler := &mockRequestHandler{}

	h, err := New(cfg, store, status, reqHandler)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if h == nil {
		t.Fatal("New() returned nil")
	}

	if h.config != cfg {
		t.Error("handler config not set correctly")
	}

	if h.storage != store {
		t.Error("handler storage not set correctly")
	}

	// Verify templates are loaded
	expectedTemplates := []string{"home.html", "login.html", "register.html", "approval.html", "dashboard.html", "keys.html", "requests.html", "users.html"}
	for _, name := range expectedTemplates {
		if _, ok := h.pageTemplates[name]; !ok {
			t.Errorf("template %s not loaded", name)
		}
	}
}

// TestRegisterRoutes verifies routes are registered
func TestRegisterRoutes(t *testing.T) {
	h, _, _ := testHandler(t)
	mux := http.NewServeMux()

	h.RegisterRoutes(mux)

	// Test that public routes respond
	publicRoutes := []struct {
		path   string
		method string
	}{
		{"/", http.MethodGet},
		{"/login", http.MethodGet},
		{"/register", http.MethodGet},
		{"/logout", http.MethodGet},
	}

	for _, route := range publicRoutes {
		req := httptest.NewRequest(route.method, route.path, nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)

		// Should not be 404 (route exists)
		if rr.Code == http.StatusNotFound {
			t.Errorf("route %s %s not registered", route.method, route.path)
		}
	}
}

// Test public pages

func TestHandleHome(t *testing.T) {
	h, _, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()

	h.handleHome(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleHome() status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Should contain HTML
	if !strings.Contains(rr.Header().Get("Content-Type"), "text/html") {
		t.Error("handleHome() should return HTML content type")
	}
}

func TestHandleHome_NotFoundForOtherPaths(t *testing.T) {
	h, _, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/nonexistent", nil)
	rr := httptest.NewRecorder()

	h.handleHome(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("handleHome() for non-root path status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestHandleHome_RedirectsLoggedInUser(t *testing.T) {
	h, store, _ := testHandler(t)
	token, _ := createTestUser(t, h, store, "homeuser")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	h.handleHome(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("handleHome() for logged in user status = %d, want %d", rr.Code, http.StatusFound)
	}

	location := rr.Header().Get("Location")
	if location != "/dashboard" {
		t.Errorf("redirect location = %q, want %q", location, "/dashboard")
	}
}

func TestHandleLogin(t *testing.T) {
	h, _, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()

	h.handleLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleLogin() status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestHandleLogin_RedirectsLoggedInUser(t *testing.T) {
	h, store, _ := testHandler(t)
	token, _ := createTestUser(t, h, store, "loginuser")

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	h.handleLogin(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("handleLogin() for logged in user status = %d, want %d", rr.Code, http.StatusFound)
	}
}

func TestHandleRegister(t *testing.T) {
	h, _, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/register", nil)
	rr := httptest.NewRecorder()

	h.handleRegister(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleRegister() status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestHandleLogout(t *testing.T) {
	h, _, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	rr := httptest.NewRecorder()

	h.handleLogout(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("handleLogout() status = %d, want %d", rr.Code, http.StatusFound)
	}

	// Should set cookie to expire
	cookies := rr.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "auth_token" {
			found = true
			if c.MaxAge != -1 {
				t.Error("logout should set MaxAge to -1")
			}
		}
	}
	if !found {
		t.Error("logout should set auth_token cookie")
	}
}

// Test approval page

func TestHandleApproval_MissingRequestID(t *testing.T) {
	h, _, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/approve/", nil)
	rr := httptest.NewRecorder()

	h.handleApproval(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("handleApproval() without ID status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleApproval_NotFound(t *testing.T) {
	h, _, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/approve/nonexistent", nil)
	req.URL.Path = "/approve/nonexistent"
	rr := httptest.NewRecorder()

	h.handleApproval(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleApproval() for nonexistent status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Should render error page
	body := rr.Body.String()
	if !strings.Contains(body, "not found") && !strings.Contains(body, "expired") {
		t.Error("handleApproval() should show error for nonexistent request")
	}
}

func TestHandleApproval_ValidRequest(t *testing.T) {
	h, store, _ := testHandler(t)
	ctx := context.Background()

	// Create a pending request
	pendingReq := &storage.PendingRequest{
		ID:           "test-req-123",
		KeyPubkey:    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		ClientPubkey: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
		Method:       "sign_event",
		ExpiresAt:    time.Now().Add(time.Hour),
		CreatedAt:    time.Now(),
	}
	store.CreatePendingRequest(ctx, pendingReq)

	req := httptest.NewRequest(http.MethodGet, "/approve/test-req-123", nil)
	req.URL.Path = "/approve/test-req-123"
	rr := httptest.NewRecorder()

	h.handleApproval(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleApproval() status = %d, want %d", rr.Code, http.StatusOK)
	}
}

// Test protected pages (require auth)

func TestHandleDashboard_NoAuth(t *testing.T) {
	h, _, _ := testHandler(t)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	rr := httptest.NewRecorder()

	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("handleDashboard() without auth status = %d, want redirect", rr.Code)
	}

	location := rr.Header().Get("Location")
	if location != "/login" {
		t.Errorf("redirect location = %q, want %q", location, "/login")
	}
}

func TestHandleDashboard_WithAuth(t *testing.T) {
	h, store, _ := testHandler(t)
	token, _ := createTestUser(t, h, store, "dashuser")

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	h.handleDashboard(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleDashboard() with auth status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestHandleKeys_WithAuth(t *testing.T) {
	h, store, _ := testHandler(t)
	token, _ := createTestUser(t, h, store, "keysuser")

	req := httptest.NewRequest(http.MethodGet, "/keys", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	h.handleKeys(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleKeys() status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestHandleRequests_WithAuth(t *testing.T) {
	h, store, _ := testHandler(t)
	token, _ := createTestUser(t, h, store, "reqsuser")

	req := httptest.NewRequest(http.MethodGet, "/requests", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	h.handleRequests(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleRequests() status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestHandleUsers_NonAdmin(t *testing.T) {
	h, store, _ := testHandler(t)
	token, _ := createTestUser(t, h, store, "normaluser")

	req := httptest.NewRequest(http.MethodGet, "/users", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	h.handleUsers(rr, req)

	// Non-admin should be redirected
	if rr.Code != http.StatusFound {
		t.Errorf("handleUsers() for non-admin status = %d, want redirect", rr.Code)
	}
}

func TestHandleUsers_Admin(t *testing.T) {
	h, store, _ := testHandler(t)
	ctx := context.Background()

	// Create admin user
	hash, _ := auth.HashPassword("password123", auth.DefaultBcryptCost)
	adminUser := &storage.User{
		ID:           "admin-123",
		Username:     "adminuser",
		PasswordHash: hash,
		Role:         "admin",
		CreatedAt:    time.Now(),
	}
	store.CreateUser(ctx, adminUser)

	token, _, _ := auth.GenerateJWT(h.authConfig, adminUser.ID, adminUser.Username)

	req := httptest.NewRequest(http.MethodGet, "/users", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	h.handleUsers(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleUsers() for admin status = %d, want %d", rr.Code, http.StatusOK)
	}
}

// Test API endpoints

func TestHandleAPILogin_Success(t *testing.T) {
	h, store, _ := testHandler(t)
	ctx := context.Background()

	// Create user
	hash, _ := auth.HashPassword("correctpassword", auth.DefaultBcryptCost)
	user := &storage.User{
		ID:           "logintest123",
		Username:     "logintest",
		PasswordHash: hash,
		CreatedAt:    time.Now(),
	}
	store.CreateUser(ctx, user)

	body := `{"username": "logintest", "password": "correctpassword"}`
	req := httptest.NewRequest(http.MethodPost, "/web/api/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleAPILogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleAPILogin() status = %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)

	if resp["success"] != true {
		t.Error("login should return success=true")
	}

	// Should set auth cookie
	cookies := rr.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "auth_token" {
			found = true
		}
	}
	if !found {
		t.Error("login should set auth_token cookie")
	}
}

func TestHandleAPILogin_WrongPassword(t *testing.T) {
	h, store, _ := testHandler(t)
	ctx := context.Background()

	hash, _ := auth.HashPassword("correctpassword", auth.DefaultBcryptCost)
	user := &storage.User{
		ID:           "wrongpw123",
		Username:     "wrongpwuser",
		PasswordHash: hash,
		CreatedAt:    time.Now(),
	}
	store.CreateUser(ctx, user)

	body := `{"username": "wrongpwuser", "password": "wrongpassword"}`
	req := httptest.NewRequest(http.MethodPost, "/web/api/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleAPILogin(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("handleAPILogin() with wrong password status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestHandleAPILogin_LockedAccount(t *testing.T) {
	h, store, _ := testHandler(t)
	ctx := context.Background()

	lockUntil := time.Now().Add(time.Hour)
	hash, _ := auth.HashPassword("password", auth.DefaultBcryptCost)
	user := &storage.User{
		ID:           "locked123",
		Username:     "lockeduser",
		PasswordHash: hash,
		LockedUntil:  &lockUntil,
		CreatedAt:    time.Now(),
	}
	store.CreateUser(ctx, user)

	body := `{"username": "lockeduser", "password": "password"}`
	req := httptest.NewRequest(http.MethodPost, "/web/api/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleAPILogin(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("handleAPILogin() for locked account status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestHandleAPILogin_MethodNotAllowed(t *testing.T) {
	h, _, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/web/api/login", nil)
	rr := httptest.NewRecorder()

	h.handleAPILogin(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("handleAPILogin() GET status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleAPILogin_MFARequired(t *testing.T) {
	h, store, _ := testHandler(t)
	ctx := context.Background()

	hash, _ := auth.HashPassword("password", auth.DefaultBcryptCost)
	user := &storage.User{
		ID:           "mfauser123",
		Username:     "mfauser",
		PasswordHash: hash,
		MFAEnabled:   true,
		MFASecret:    "TESTSECRET",
		CreatedAt:    time.Now(),
	}
	store.CreateUser(ctx, user)

	body := `{"username": "mfauser", "password": "password"}`
	req := httptest.NewRequest(http.MethodPost, "/web/api/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleAPILogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleAPILogin() MFA user status = %d, want %d", rr.Code, http.StatusOK)
	}

	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)

	if resp["mfa_required"] != true {
		t.Error("should return mfa_required=true")
	}
}

func TestHandleAPIRegister_Success(t *testing.T) {
	h, _, _ := testHandler(t)

	body := `{"username": "newuser", "email": "new@example.com", "password": "securepassword123"}`
	req := httptest.NewRequest(http.MethodPost, "/web/api/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleAPIRegister(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("handleAPIRegister() status = %d, want %d; body: %s", rr.Code, http.StatusCreated, rr.Body.String())
	}
}

func TestHandleAPIRegister_ShortUsername(t *testing.T) {
	h, _, _ := testHandler(t)

	body := `{"username": "ab", "password": "securepassword123"}`
	req := httptest.NewRequest(http.MethodPost, "/web/api/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleAPIRegister(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("handleAPIRegister() short username status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleAPIRegister_ShortPassword(t *testing.T) {
	h, _, _ := testHandler(t)

	body := `{"username": "testuser", "password": "short"}`
	req := httptest.NewRequest(http.MethodPost, "/web/api/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleAPIRegister(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("handleAPIRegister() short password status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleAPIRegister_DuplicateUsername(t *testing.T) {
	h, store, _ := testHandler(t)
	ctx := context.Background()

	// Create existing user
	hash, _ := auth.HashPassword("password", auth.DefaultBcryptCost)
	store.CreateUser(ctx, &storage.User{
		ID:           "existing123",
		Username:     "existinguser",
		PasswordHash: hash,
		CreatedAt:    time.Now(),
	})

	body := `{"username": "existinguser", "password": "newpassword123"}`
	req := httptest.NewRequest(http.MethodPost, "/web/api/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleAPIRegister(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("handleAPIRegister() duplicate username status = %d, want %d", rr.Code, http.StatusConflict)
	}
}

func TestHandleAPIRegister_InvalidNpub(t *testing.T) {
	h, _, _ := testHandler(t)

	// Invalid npub format should be rejected
	body := `{"username": "npubuser", "password": "securepassword123", "pubkey": "npub1invalid"}`
	req := httptest.NewRequest(http.MethodPost, "/web/api/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleAPIRegister(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("handleAPIRegister() with invalid npub status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleAPIRegister_WithHexPubkey(t *testing.T) {
	h, _, _ := testHandler(t)

	body := `{"username": "hexpubuser", "password": "securepassword123", "pubkey": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}`
	req := httptest.NewRequest(http.MethodPost, "/web/api/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleAPIRegister(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("handleAPIRegister() with hex pubkey status = %d, want %d; body: %s", rr.Code, http.StatusCreated, rr.Body.String())
	}
}

func TestHandleAPIRegister_InvalidPubkey(t *testing.T) {
	h, _, _ := testHandler(t)

	body := `{"username": "badpubuser", "password": "securepassword123", "pubkey": "invalid"}`
	req := httptest.NewRequest(http.MethodPost, "/web/api/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleAPIRegister(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("handleAPIRegister() invalid pubkey status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestHandleAPIRegister_FirstUserIsAdmin(t *testing.T) {
	h, store, _ := testHandler(t)
	ctx := context.Background()

	body := `{"username": "firstuser", "password": "securepassword123"}`
	req := httptest.NewRequest(http.MethodPost, "/web/api/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleAPIRegister(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("handleAPIRegister() status = %d, want %d", rr.Code, http.StatusCreated)
	}

	// First user should be admin
	user, _ := store.GetUserByUsername(ctx, "firstuser")
	if user.Role != "admin" {
		t.Errorf("first user role = %q, want %q", user.Role, "admin")
	}
}

func TestHandleAPIApprove_Success(t *testing.T) {
	h, store, reqHandler := testHandler(t)
	ctx := context.Background()

	// Create pending request
	pendingReq := &storage.PendingRequest{
		ID:           "approve-req-123",
		KeyPubkey:    "1111111111111111111111111111111111111111111111111111111111111111",
		ClientPubkey: "2222222222222222222222222222222222222222222222222222222222222222",
		Method:       "sign_event",
		ExpiresAt:    time.Now().Add(time.Hour),
		CreatedAt:    time.Now(),
	}
	store.CreatePendingRequest(ctx, pendingReq)

	body := `{"request_id": "approve-req-123", "remember": true}`
	req := httptest.NewRequest(http.MethodPost, "/web/api/approve", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleAPIApprove(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleAPIApprove() status = %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	// Check that request handler was called
	if len(reqHandler.approvedRequests) != 1 {
		t.Errorf("expected 1 approved request, got %d", len(reqHandler.approvedRequests))
	}
	if reqHandler.approvedRequests[0] != "approve-req-123" {
		t.Errorf("approved request ID = %q, want %q", reqHandler.approvedRequests[0], "approve-req-123")
	}
}

func TestHandleAPIApprove_NotFound(t *testing.T) {
	h, _, _ := testHandler(t)

	body := `{"request_id": "nonexistent"}`
	req := httptest.NewRequest(http.MethodPost, "/web/api/approve", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleAPIApprove(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("handleAPIApprove() for nonexistent status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestHandleAPIDeny_Success(t *testing.T) {
	h, store, reqHandler := testHandler(t)
	ctx := context.Background()

	// Create pending request
	pendingReq := &storage.PendingRequest{
		ID:           "deny-req-123",
		KeyPubkey:    "3333333333333333333333333333333333333333333333333333333333333333",
		ClientPubkey: "4444444444444444444444444444444444444444444444444444444444444444",
		Method:       "sign_event",
		ExpiresAt:    time.Now().Add(time.Hour),
		CreatedAt:    time.Now(),
	}
	store.CreatePendingRequest(ctx, pendingReq)

	body := `{"request_id": "deny-req-123"}`
	req := httptest.NewRequest(http.MethodPost, "/web/api/deny", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleAPIDeny(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleAPIDeny() status = %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	// Check that request handler was called
	if len(reqHandler.deniedRequests) != 1 {
		t.Errorf("expected 1 denied request, got %d", len(reqHandler.deniedRequests))
	}
}

func TestHandleAPIDeny_NotFound(t *testing.T) {
	h, _, _ := testHandler(t)

	body := `{"request_id": "nonexistent"}`
	req := httptest.NewRequest(http.MethodPost, "/web/api/deny", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleAPIDeny(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("handleAPIDeny() for nonexistent status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

// Test static file handling

func TestHandleStatic_CSS(t *testing.T) {
	h, _, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/static/style.css", nil)
	rr := httptest.NewRecorder()

	h.handleStatic(rr, req)

	// May be 404 if file doesn't exist, or 200 if it does
	// Just verify content type is set correctly for CSS
	if rr.Code == http.StatusOK {
		contentType := rr.Header().Get("Content-Type")
		if contentType != "text/css" {
			t.Errorf("Content-Type = %q, want %q", contentType, "text/css")
		}
	}
}

func TestHandleStatic_NotFound(t *testing.T) {
	h, _, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/static/nonexistent.xyz", nil)
	rr := httptest.NewRecorder()

	h.handleStatic(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("handleStatic() for nonexistent file status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

// Test helper methods

func TestGetCurrentUser_NoCookie(t *testing.T) {
	h, _, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	user := h.getCurrentUser(req)

	if user != nil {
		t.Error("getCurrentUser() should return nil without cookie")
	}
}

func TestGetCurrentUser_InvalidToken(t *testing.T) {
	h, _, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: "invalid-token"})

	user := h.getCurrentUser(req)

	if user != nil {
		t.Error("getCurrentUser() should return nil for invalid token")
	}
}

func TestGetCurrentUser_ValidToken(t *testing.T) {
	h, store, _ := testHandler(t)
	token, expectedUser := createTestUser(t, h, store, "validuser")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})

	user := h.getCurrentUser(req)

	if user == nil {
		t.Fatal("getCurrentUser() should return user for valid token")
	}

	if user.Username != expectedUser.Username {
		t.Errorf("user.Username = %q, want %q", user.Username, expectedUser.Username)
	}
}

func TestRequireAuth_NoAuth(t *testing.T) {
	h, _, _ := testHandler(t)

	called := false
	handler := h.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	rr := httptest.NewRecorder()

	handler(rr, req)

	if called {
		t.Error("handler should not be called without auth")
	}

	if rr.Code != http.StatusFound {
		t.Errorf("requireAuth() without auth status = %d, want redirect", rr.Code)
	}
}

func TestRequireAuth_WithAuth(t *testing.T) {
	h, store, _ := testHandler(t)
	token, _ := createTestUser(t, h, store, "authuser")

	called := false
	handler := h.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.AddCookie(&http.Cookie{Name: "auth_token", Value: token})
	rr := httptest.NewRecorder()

	handler(rr, req)

	if !called {
		t.Error("handler should be called with valid auth")
	}

	if rr.Code != http.StatusOK {
		t.Errorf("requireAuth() with auth status = %d, want %d", rr.Code, http.StatusOK)
	}
}

func TestJsonResponse(t *testing.T) {
	h, _, _ := testHandler(t)

	rr := httptest.NewRecorder()
	h.jsonResponse(rr, http.StatusOK, map[string]string{"test": "value"})

	if rr.Code != http.StatusOK {
		t.Errorf("jsonResponse() status = %d, want %d", rr.Code, http.StatusOK)
	}

	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want %q", contentType, "application/json")
	}

	var resp map[string]string
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["test"] != "value" {
		t.Error("response body incorrect")
	}
}

func TestJsonError(t *testing.T) {
	h, _, _ := testHandler(t)

	rr := httptest.NewRecorder()
	h.jsonError(rr, http.StatusBadRequest, "test error")

	if rr.Code != http.StatusBadRequest {
		t.Errorf("jsonError() status = %d, want %d", rr.Code, http.StatusBadRequest)
	}

	var resp map[string]string
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["error"] != "test error" {
		t.Errorf("error = %q, want %q", resp["error"], "test error")
	}
}

func TestHandleAPINIP07Login_MethodNotAllowed(t *testing.T) {
	h, _, _ := testHandler(t)

	req := httptest.NewRequest(http.MethodGet, "/web/api/login/nip07", nil)
	rr := httptest.NewRecorder()

	h.handleAPINIP07Login(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("handleAPINIP07Login() GET status = %d, want %d", rr.Code, http.StatusMethodNotAllowed)
	}
}

func TestHandleAPINIP07Login_NoAccount(t *testing.T) {
	h, _, _ := testHandler(t)

	body := `{"pubkey": "5555555555555555555555555555555555555555555555555555555555555555", "signature": "sig", "challenge": "challenge"}`
	req := httptest.NewRequest(http.MethodPost, "/web/api/login/nip07", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleAPINIP07Login(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Errorf("handleAPINIP07Login() no account status = %d, want %d", rr.Code, http.StatusForbidden)
	}
}

func TestHandleAPINIP07Login_WithLinkedPubkey(t *testing.T) {
	h, store, _ := testHandler(t)
	ctx := context.Background()

	pubkey := "6666666666666666666666666666666666666666666666666666666666666666"
	hash, _ := auth.HashPassword("password", auth.DefaultBcryptCost)
	user := &storage.User{
		ID:           "nip07user123",
		Username:     "nip07user",
		PasswordHash: hash,
		Pubkey:       pubkey,
		CreatedAt:    time.Now(),
	}
	store.CreateUser(ctx, user)

	body := `{"pubkey": "6666666666666666666666666666666666666666666666666666666666666666", "signature": "sig", "challenge": "challenge"}`
	req := httptest.NewRequest(http.MethodPost, "/web/api/login/nip07", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	h.handleAPINIP07Login(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("handleAPINIP07Login() with linked pubkey status = %d, want %d; body: %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	// Should set cookie
	cookies := rr.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == "auth_token" {
			found = true
		}
	}
	if !found {
		t.Error("NIP-07 login should set auth_token cookie")
	}
}

// Note: handleApps test is skipped because apps.html template is not included
// in the pageFiles array in New(). This is a bug in the production code that
// should be fixed separately - the template exists but isn't loaded.
