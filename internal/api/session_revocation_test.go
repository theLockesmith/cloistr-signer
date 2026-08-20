package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/auth"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// Signing out must actually revoke. Before ensureSessionLive existed,
// handleUserLogout deleted every session server-side and the JWT it had issued
// kept working for the rest of its 24h life, because validateAuthHeader only
// checked the signature and expiry. That is why signing out of one app left you
// signed in at signer.cloistr.xyz.

func newSessionTestHandler(store storage.Storage) *Handler {
	return &Handler{
		storage: store,
		authConfig: &auth.Config{
			JWTSecret:   "test-secret-not-a-real-key",
			JWTIssuer:   "test",
			TokenExpiry: time.Hour,
		},
	}
}

// issueSession creates a live session and a JWT bound to it, the way a real
// login does.
func issueSession(t *testing.T, h *Handler, store storage.Storage) (token, sessionID string) {
	t.Helper()
	sessionID, err := auth.GenerateSessionID()
	if err != nil {
		t.Fatalf("GenerateSessionID: %v", err)
	}
	token, expiresAt, err := auth.GenerateJWTWithSession(h.authConfig, "user-1", "alice", sessionID)
	if err != nil {
		t.Fatalf("GenerateJWTWithSession: %v", err)
	}
	if err := store.CreateUserSession(context.Background(), &storage.UserSession{
		ID:        sessionID,
		UserID:    "user-1",
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatalf("CreateUserSession: %v", err)
	}
	return token, sessionID
}

func requestWithToken(token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

func TestValidateAuthHeader_AcceptsLiveSession(t *testing.T) {
	store := storage.NewMemoryStorage()
	h := newSessionTestHandler(store)
	token, _ := issueSession(t, h, store)

	claims, err := h.validateAuthHeader(requestWithToken(token))
	if err != nil {
		t.Fatalf("expected a live session to authenticate, got %v", err)
	}
	if claims.UserID != "user-1" {
		t.Errorf("UserID = %q, want user-1", claims.UserID)
	}
}

// The actual bug: after logout deletes the sessions, the SAME token must stop
// working immediately rather than lingering until it expires.
func TestValidateAuthHeader_RejectsAfterSessionsDeleted(t *testing.T) {
	store := storage.NewMemoryStorage()
	h := newSessionTestHandler(store)
	token, _ := issueSession(t, h, store)

	if _, err := h.validateAuthHeader(requestWithToken(token)); err != nil {
		t.Fatalf("precondition: token should be valid before logout, got %v", err)
	}

	// What handleUserLogout does.
	if err := store.DeleteUserSessions(context.Background(), "user-1"); err != nil {
		t.Fatalf("DeleteUserSessions: %v", err)
	}

	if _, err := h.validateAuthHeader(requestWithToken(token)); err == nil {
		t.Fatal("token still authenticated after its session was deleted — logout does not revoke")
	}
}

// Admin pubkey logins (auth.GenerateJWT) carry no SessionID and have no session
// row. They must keep working, or the admin console locks itself out.
func TestValidateAuthHeader_AllowsTokenWithoutSessionID(t *testing.T) {
	store := storage.NewMemoryStorage()
	h := newSessionTestHandler(store)

	token, _, err := auth.GenerateJWT(h.authConfig, "admin-1", "admin:abcd1234")
	if err != nil {
		t.Fatalf("GenerateJWT: %v", err)
	}

	if _, err := h.validateAuthHeader(requestWithToken(token)); err != nil {
		t.Fatalf("session-less admin token must still authenticate, got %v", err)
	}
}

// failingSessionStore reports an INFRASTRUCTURE failure (not "not found") for
// session lookups.
type failingSessionStore struct {
	storage.Storage
	err error
}

func (f *failingSessionStore) GetUserSession(ctx context.Context, id string) (*storage.UserSession, error) {
	return nil, f.err
}

// Sessions live in Dragonfly. If an unreachable session store counted as
// "logged out", a cache blip would sign out every user of every Cloistr service
// at once — the identity service is what they all authenticate against. A
// transport error must therefore fail OPEN.
func TestValidateAuthHeader_FailsOpenWhenSessionStoreErrors(t *testing.T) {
	base := storage.NewMemoryStorage()
	h := newSessionTestHandler(base)
	token, _ := issueSession(t, h, base)

	h.storage = &failingSessionStore{Storage: base, err: errors.New("dial tcp: connection refused")}

	if _, err := h.validateAuthHeader(requestWithToken(token)); err != nil {
		t.Fatalf("infrastructure error must not log users out, got %v", err)
	}
}

// ...but a definitive not-found must still reject, or the fail-open path would
// swallow real revocations too.
func TestValidateAuthHeader_RejectsOnDefinitiveNotFound(t *testing.T) {
	base := storage.NewMemoryStorage()
	h := newSessionTestHandler(base)
	token, _ := issueSession(t, h, base)

	h.storage = &failingSessionStore{Storage: base, err: storage.ErrSessionNotFound}

	if _, err := h.validateAuthHeader(requestWithToken(token)); err == nil {
		t.Fatal("ErrSessionNotFound must reject the token")
	}
}

// A tampered or unsigned token must fail before any session lookup happens.
func TestValidateAuthHeader_RejectsInvalidSignature(t *testing.T) {
	store := storage.NewMemoryStorage()
	h := newSessionTestHandler(store)

	if _, err := h.validateAuthHeader(requestWithToken("not.a.jwt")); err == nil {
		t.Fatal("expected a malformed token to be rejected")
	}
}
