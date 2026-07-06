package api

// WebAuthn / passkey endpoints for cloistr-signer.
//
// RPID is "cloistr.xyz" (the registrable parent domain) so a single passkey
// can be exercised from every *.cloistr.xyz origin without re-registering.
//
// Ceremony flow:
//   Registration (authenticated):
//     POST /api/v1/users/passkey/register/begin   → CredentialCreation JSON
//     POST /api/v1/users/passkey/register/finish  → {success:true}
//
//   Discoverable login (unauthenticated):
//     POST /api/v1/users/passkey/login/begin      → {publicKey, session_id}
//     POST /api/v1/users/passkey/login/finish     → sets auth_token cookie, {success, username}

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/auth"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// ---- webauthn.User adapter ----

// signerWebAuthnUser wraps storage.User to implement the webauthn.User interface.
// WebAuthnID uses the raw user ID string bytes (not a UUID, just text bytes),
// which is stable and opaque to the authenticator.
type signerWebAuthnUser struct {
	user  *storage.User
	creds []webauthn.Credential
}

func (u *signerWebAuthnUser) WebAuthnID() []byte                         { return []byte(u.user.ID) }
func (u *signerWebAuthnUser) WebAuthnName() string                       { return u.user.Username }
func (u *signerWebAuthnUser) WebAuthnDisplayName() string                { return u.user.Username }
func (u *signerWebAuthnUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }
func (u *signerWebAuthnUser) WebAuthnIcon() string                       { return "" }

// ---- helpers ----

// passkeySessionID returns a 32-byte hex string for use as a session ID.
func passkeySessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// encodeWebAuthnSession gob-encodes a webauthn.SessionData to bytes.
func encodeWebAuthnSession(s *webauthn.SessionData) ([]byte, error) {
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(s); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decodeWebAuthnSession gob-decodes bytes back to webauthn.SessionData.
func decodeWebAuthnSession(b []byte) (*webauthn.SessionData, error) {
	var s webauthn.SessionData
	if err := gob.NewDecoder(bytes.NewReader(b)).Decode(&s); err != nil {
		return nil, err
	}
	return &s, nil
}

// loadWebAuthnUser fetches the user and maps their stored passkey credentials
// into a webauthn.User adapter.
func (h *Handler) loadWebAuthnUser(r *http.Request, userID string) (*signerWebAuthnUser, error) {
	user, err := h.storage.GetUser(r.Context(), userID)
	if err != nil {
		return nil, err
	}

	rawCreds, err := h.storage.ListPasskeyCredentials(r.Context(), userID)
	if err != nil {
		return nil, err
	}

	var creds []webauthn.Credential
	for _, rc := range rawCreds {
		c := webauthn.Credential{
			ID:        rc.CredentialID,
			PublicKey: rc.PublicKey,
			Authenticator: webauthn.Authenticator{
				SignCount: rc.SignCount,
			},
		}
		for _, t := range rc.Transport {
			c.Transport = append(c.Transport, protocol.AuthenticatorTransport(t))
		}
		if len(rc.AAGUID) == 16 {
			copy(c.Authenticator.AAGUID[:], rc.AAGUID)
		}
		creds = append(creds, c)
	}

	return &signerWebAuthnUser{user: user, creds: creds}, nil
}

// webauthnUnavailable writes a 503 in the signer's standard error shape.
func (h *Handler) webauthnUnavailable(w http.ResponseWriter) {
	h.errorResponse(w, http.StatusServiceUnavailable, "passkeys not configured")
}

// ---- Registration ----

// POST /api/v1/users/passkey/register/begin
// AUTH REQUIRED. Returns CredentialCreation options JSON and persists the
// challenge session keyed by "reg-<userID>" so /finish can retrieve it.
func (h *Handler) handlePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if h.webauthn == nil {
		h.webauthnUnavailable(w)
		return
	}

	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	waUser, err := h.loadWebAuthnUser(r, claims.UserID)
	if err != nil {
		h.errorResponse(w, http.StatusNotFound, "user not found")
		return
	}

	options, session, err := h.webauthn.BeginRegistration(waUser)
	if err != nil {
		slog.Error("webauthn begin registration failed", "user_id", claims.UserID, "error", err)
		h.errorResponse(w, http.StatusInternalServerError, "failed to begin registration")
		return
	}

	data, err := encodeWebAuthnSession(session)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to encode session")
		return
	}

	// Key registration sessions by "reg-<userID>". One outstanding registration
	// per user; we delete any previous one before inserting the new one.
	sessionID := "reg-" + claims.UserID
	_ = h.storage.DeleteWebAuthnSession(r.Context(), sessionID)

	ws := &storage.WebAuthnSession{
		ID:        sessionID,
		UserID:    claims.UserID,
		Data:      data,
		ExpiresAt: time.Now().Add(5 * time.Minute),
		CreatedAt: time.Now(),
	}
	if err := h.storage.CreateWebAuthnSession(r.Context(), ws); err != nil {
		slog.Error("webauthn store registration session failed", "user_id", claims.UserID, "error", err)
		h.errorResponse(w, http.StatusInternalServerError, "failed to store session")
		return
	}

	h.jsonResponse(w, http.StatusOK, options)
}

// POST /api/v1/users/passkey/register/finish
// AUTH REQUIRED. Optional ?name= query param for credential label.
func (h *Handler) handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if h.webauthn == nil {
		h.webauthnUnavailable(w)
		return
	}

	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	credName := r.URL.Query().Get("name")
	if credName == "" {
		credName = "Passkey"
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(r.Body)
	if err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid credential response: "+err.Error())
		return
	}

	sessionID := "reg-" + claims.UserID
	ws, err := h.storage.GetWebAuthnSession(r.Context(), sessionID)
	if err != nil {
		h.errorResponse(w, http.StatusBadRequest, "registration session not found — please start again")
		return
	}
	// Always clean up the session, whether the ceremony succeeds or fails.
	defer h.storage.DeleteWebAuthnSession(r.Context(), sessionID)

	if time.Now().After(ws.ExpiresAt) {
		h.errorResponse(w, http.StatusBadRequest, "registration session expired — please start again")
		return
	}

	storedSession, err := decodeWebAuthnSession(ws.Data)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to decode session")
		return
	}

	waUser, err := h.loadWebAuthnUser(r, claims.UserID)
	if err != nil {
		h.errorResponse(w, http.StatusNotFound, "user not found")
		return
	}

	credential, err := h.webauthn.CreateCredential(waUser, *storedSession, parsedResponse)
	if err != nil {
		h.errorResponse(w, http.StatusBadRequest, "registration failed: "+err.Error())
		return
	}

	credID, err := passkeySessionID()
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to generate credential ID")
		return
	}

	var transports []string
	for _, t := range credential.Transport {
		transports = append(transports, string(t))
	}

	aaguid := make([]byte, 16)
	copy(aaguid, credential.Authenticator.AAGUID[:])

	pc := &storage.PasskeyCredential{
		ID:           credID,
		UserID:       claims.UserID,
		CredentialID: credential.ID,
		PublicKey:    credential.PublicKey,
		AAGUID:       aaguid,
		SignCount:    credential.Authenticator.SignCount,
		Transport:    transports,
		Name:         credName,
		CreatedAt:    time.Now(),
	}
	if err := h.storage.CreatePasskeyCredential(r.Context(), pc); err != nil {
		slog.Error("webauthn store credential failed", "user_id", claims.UserID, "error", err)
		h.errorResponse(w, http.StatusInternalServerError, "failed to store credential")
		return
	}

	slog.Info("passkey registered", "user_id", claims.UserID, "cred_name", credName)
	h.jsonResponse(w, http.StatusOK, map[string]interface{}{"success": true})
}

// ---- Discoverable login ----

// POST /api/v1/users/passkey/login/begin
// NO AUTH. Returns CredentialAssertion options and a session_id the client
// must include in the /login/finish request body.
func (h *Handler) handlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if h.webauthn == nil {
		h.webauthnUnavailable(w)
		return
	}

	options, session, err := h.webauthn.BeginDiscoverableLogin()
	if err != nil {
		slog.Error("webauthn begin discoverable login failed", "error", err)
		h.errorResponse(w, http.StatusInternalServerError, "failed to begin login")
		return
	}

	sessionID, err := passkeySessionID()
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to generate session")
		return
	}

	data, err := encodeWebAuthnSession(session)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to encode session")
		return
	}

	ws := &storage.WebAuthnSession{
		ID:        sessionID,
		UserID:    "", // discoverable — user unknown at this stage
		Data:      data,
		ExpiresAt: time.Now().Add(5 * time.Minute),
		CreatedAt: time.Now(),
	}
	if err := h.storage.CreateWebAuthnSession(r.Context(), ws); err != nil {
		slog.Error("webauthn store login session failed", "error", err)
		h.errorResponse(w, http.StatusInternalServerError, "failed to store session")
		return
	}

	h.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"publicKey":  options.Response,
		"session_id": sessionID,
	})
}

// POST /api/v1/users/passkey/login/finish
// NO AUTH.
// Body: flat JSON object with "session_id" (string) alongside the standard
// WebAuthn assertion fields (id, rawId, response, type, clientExtensionResults).
// On success: issues auth_token JWT cookie (same helper as password login)
// and returns {success:true, username}.
func (h *Handler) handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if h.webauthn == nil {
		h.webauthnUnavailable(w)
		return
	}

	// Buffer the request body so we can extract session_id and then re-feed
	// the full body to the WebAuthn parser (which also reads from the body).
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		h.errorResponse(w, http.StatusBadRequest, "failed to read request body")
		return
	}
	r.Body.Close()

	// Extract session_id from the flat JSON envelope.
	var envelope struct {
		SessionID string `json:"session_id"`
	}
	if err := json.Unmarshal(bodyBytes, &envelope); err != nil || envelope.SessionID == "" {
		h.errorResponse(w, http.StatusBadRequest, "session_id required")
		return
	}

	sessionID := envelope.SessionID

	ws, err := h.storage.GetWebAuthnSession(r.Context(), sessionID)
	if err != nil {
		h.errorResponse(w, http.StatusBadRequest, "login session not found — please start again")
		return
	}
	// Always delete the session after use (prevents replay).
	defer h.storage.DeleteWebAuthnSession(r.Context(), sessionID)

	if time.Now().After(ws.ExpiresAt) {
		h.errorResponse(w, http.StatusBadRequest, "login session expired — please start again")
		return
	}

	storedSession, err := decodeWebAuthnSession(ws.Data)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to decode session")
		return
	}

	// Re-expose the buffered body for the WebAuthn parser.
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))

	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(r.Body)
	if err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid credential response: "+err.Error())
		return
	}

	// userHandler is called by go-webauthn with the raw credential ID extracted
	// from the assertion. Look up user by credential ID.
	userHandler := func(rawID, _ []byte) (webauthn.User, error) {
		pc, err := h.storage.GetPasskeyCredentialByCredentialID(r.Context(), rawID)
		if err != nil {
			return nil, storage.ErrUserNotFound
		}
		return h.loadWebAuthnUser(r, pc.UserID)
	}

	credential, err := h.webauthn.ValidateDiscoverableLogin(userHandler, *storedSession, parsedResponse)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "authentication failed: "+err.Error())
		return
	}

	// Resolve the user from the presented credential ID (parsedResponse.RawID
	// is the base64url-decoded credential ID bytes).
	pc, err := h.storage.GetPasskeyCredentialByCredentialID(r.Context(), parsedResponse.RawID)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "credential not recognized")
		return
	}

	// Update sign count (clone detection) and last-used timestamp.
	// Non-fatal: a failure here must not block the user from logging in.
	if err := h.storage.UpdatePasskeyCredentialUsage(r.Context(), credential.ID, credential.Authenticator.SignCount); err != nil {
		slog.Warn("webauthn update passkey usage failed", "error", err, "user_id", pc.UserID)
	}

	user, err := h.storage.GetUser(r.Context(), pc.UserID)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "user not found")
		return
	}

	// Create a database session identical to the password-login flow.
	dbSessionID, _ := auth.GenerateSessionID()
	token, expiresAt, err := auth.GenerateJWTWithSession(h.authConfig, user.ID, user.Username, dbSessionID)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	dbSession := &storage.UserSession{
		ID:        dbSessionID,
		UserID:    user.ID,
		Token:     token[:16], // prefix stored for revocation tracking
		UserAgent: r.UserAgent(),
		ExpiresAt: expiresAt,
		CreatedAt: time.Now(),
	}
	if err := h.storage.CreateUserSession(r.Context(), dbSession); err != nil {
		// Non-fatal — the JWT is still valid.
		slog.Warn("webauthn create db session failed", "user_id", user.ID, "error", err)
	}

	// Stamp last login time.
	now := time.Now()
	user.LastLoginAt = &now
	_ = h.storage.UpdateUser(r.Context(), user)

	slog.Info("passkey login successful", "user_id", user.ID, "username", user.Username)

	// Issue the SAME .cloistr.xyz parent-domain cookie as password login so the
	// auth session is shared across all *.cloistr.xyz subdomains.
	http.SetCookie(w, h.newAuthCookie(token, expiresAt))

	h.jsonResponse(w, http.StatusOK, map[string]interface{}{
		"success":  true,
		"username": user.Username,
	})
}
