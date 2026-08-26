package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/audit"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/auth"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/bunker"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/config"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/crypto"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/frost"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/ratelimit"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/signer"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/vault"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
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
	userDKG          *frost.UserDKG      // FROST 2-of-N user-cosigner DKG (docs/frost-2-of-n-design.md)
	webauthn         *webauthn.WebAuthn  // nil when WebAuthn config is incomplete (e.g. no RPID)
	limiter          ratelimit.Limiter   // rate limiter for unauthenticated endpoints (nil = no limiting)
	ipHasher         *ratelimit.IPHasher // rotating HMAC hasher for per-IP keys (nil = IP limiting disabled)
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

// isVaultForbidden reports whether an error from the Vault client came from a
// 403 permission-denied response. Used by the login handler to distinguish
// "user record missing → try to provision" (retriable) from "user is
// locked-out or ACL-denied" (not retriable — provisioning cannot fix it and
// costs 3-5s of raft-write latency on the current cluster). Vault surfaces
// these as errors of the form: `authentication failed (status 403): ...` or
// `vault error (status 403): ...`, formatted by the client wrappers in
// internal/vault/vault.go. String match is sufficient — the wrapper is the
// only source of that text.
func isVaultForbidden(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "status 403")
}

// getUserSessionAwaitingVaultToken fetches a session, polling briefly if its
// VaultToken is still empty. Used by the on-demand key-load path to bridge
// the race between async-login's response and its background Vault userpass
// call finishing. Poll interval 200ms, max ~15s (matches the observed Vault
// userpass upper bound). Returns as soon as VaultToken is non-empty, or when
// the timeout is exceeded / ctx is cancelled — the caller distinguishes
// "still empty after wait" from "session missing" via session.VaultToken.
func (h *Handler) getUserSessionAwaitingVaultToken(ctx context.Context, sessionID string) (*storage.UserSession, error) {
	const (
		pollInterval = 200 * time.Millisecond
		maxWait      = 15 * time.Second
	)
	deadline := time.Now().Add(maxWait)
	for {
		session, err := h.storage.GetUserSession(ctx, sessionID)
		if err != nil || session == nil {
			return session, err
		}
		if session.VaultToken != "" || time.Now().After(deadline) {
			return session, nil
		}
		select {
		case <-ctx.Done():
			return session, ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

// populateVaultTokenAsync runs off the login critical path. It authenticates
// the user to Vault userpass, applies the same "provision on drift, skip on
// 403" logic the sync path used, and writes the resulting token to the
// existing session record. Non-fatal: any failure just leaves the session's
// VaultToken empty and lets on-demand key-load surface the problem when the
// user actually tries to sign.
//
// 30s ceiling: 15s AuthenticateUserpass + optional 15s ProvisionUser + retry.
// Vault userpass raft-consensus writes on the current cluster peak around 9s
// on success; the ceiling is a runaway backstop, not the expected duration.
func (h *Handler) populateVaultTokenAsync(sessionID, userID, username, password string) {
	// Fully off the login critical path (login already responded), so we can
	// afford to be patient: userpass login mints a token, which is a Vault
	// raft-consensus write, and under write contention a single attempt can
	// exceed the per-request timeout. A one-shot attempt that times out would
	// poison this session's VaultToken for its entire lifetime — the password
	// isn't retained, so nothing can re-mint the token until the next login,
	// and every sign attempt on this session then fails (nostrconnect 30s
	// timeout). The generous ceiling bounds the retry loop below.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var vaultToken string
	vaultAuth, err := h.authenticateUserpassWithRetry(ctx, userID, password)
	if err != nil {
		if isVaultForbidden(err) {
			slog.Info("async vault auth returned 403; skipping provision fallback", "user_id", userID)
			return
		}
		// A timeout is transient Vault slowness, NOT a missing user. Do not
		// provision on timeout: ProvisionUser issues several more raft writes
		// (transit key + policy + userpass account) and re-auths, piling load
		// onto an already-slow Vault and making the contention worse. Leave the
		// token empty; the next login retries cleanly.
		if vault.IsTimeout(err) {
			slog.Warn("async vault auth kept timing out after retries; leaving session token empty", "user_id", userID)
			return
		}
		slog.Info("async vault auth failed, attempting to provision", "user_id", userID, "error", err)
		if provisionErr := h.vaultClient.ProvisionUser(ctx, userID, username, password); provisionErr != nil {
			slog.Warn("async provision vault user failed", "error", provisionErr, "user_id", userID)
			return
		}
		vaultAuth, err = h.vaultClient.AuthenticateUserpass(ctx, userID, password)
		if err != nil {
			slog.Warn("async vault auth still failed after provisioning", "error", err, "user_id", userID)
			return
		}
		slog.Info("async vault auth successful after provisioning", "user_id", userID)
	} else {
		slog.Debug("async vault authentication successful", "user_id", userID, "lease_duration", vaultAuth.LeaseDuration)
	}
	vaultToken = vaultAuth.Token

	// Persist the token on the session that the login response already issued.
	// If the session was deleted (user logged out mid-goroutine) or expired,
	// UpdateUserSessionVaultToken returns ErrSessionNotFound — non-fatal.
	if err := h.storage.UpdateUserSessionVaultToken(ctx, sessionID, vaultToken); err != nil {
		slog.Warn("async vault token persist failed", "error", err, "session_id", sessionID)
		return
	}

	// Eager pre-load of the user's Vault-encrypted signing keys into the
	// signer runtime. Uses context.Background() so a subsequent request
	// context cancellation can't wipe the load partway through. Keys still
	// lazy-load on demand if this hasn't finished before the first sign
	// request arrives.
	go h.loadUserVaultKeys(context.Background(), userID, vaultToken)
}

// authenticateUserpassWithRetry authenticates to Vault userpass, retrying with
// exponential backoff on transient timeouts. Userpass login is a raft-consensus
// write; a single attempt can exceed the per-request timeout under write
// contention, which is the observed cause of account-specific intermittent
// login failures. Because the only caller runs off the login critical path,
// retrying costs the user nothing and turns a poisoned session (no Vault token
// for its whole life) into an eventual success.
//
// Only timeouts are retried. A 403 or any other non-timeout error is returned
// immediately so the caller's skip/provision logic runs without extra delay.
func (h *Handler) authenticateUserpassWithRetry(ctx context.Context, userID, password string) (*vault.AuthResponse, error) {
	const maxAttempts = 4
	backoff := 500 * time.Millisecond
	var lastErr error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		auth, err := h.vaultClient.AuthenticateUserpass(ctx, userID, password)
		if err == nil {
			if attempt > 1 {
				slog.Info("async vault auth succeeded on retry", "user_id", userID, "attempt", attempt)
			}
			return auth, nil
		}
		lastErr = err
		if !vault.IsTimeout(err) {
			return nil, err // 403 / bad-creds / missing-user: don't spin, let caller decide
		}
		select {
		case <-ctx.Done():
			return nil, lastErr
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	return nil, lastErr
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

	// Initialize WebAuthn. RPID and at least one origin are required; skip
	// gracefully if not configured (e.g. unit tests with in-memory storage).
	var wa *webauthn.WebAuthn
	if cfg.WebAuthn.RPID != "" && len(cfg.WebAuthn.RPOrigins) > 0 {
		waCfg := &webauthn.Config{
			RPID:                  cfg.WebAuthn.RPID,
			RPDisplayName:         cfg.WebAuthn.RPDisplayName,
			RPOrigins:             cfg.WebAuthn.RPOrigins,
			AttestationPreference: protocol.PreferNoAttestation,
			AuthenticatorSelection: protocol.AuthenticatorSelection{
				ResidentKey:      protocol.ResidentKeyRequirementPreferred,
				UserVerification: protocol.VerificationPreferred,
			},
			Timeouts: webauthn.TimeoutsConfig{
				Login: webauthn.TimeoutConfig{
					Enforce: true,
					Timeout: 5 * time.Minute,
				},
				Registration: webauthn.TimeoutConfig{
					Enforce: true,
					Timeout: 5 * time.Minute,
				},
			},
		}
		var err error
		wa, err = webauthn.New(waCfg)
		if err != nil {
			slog.Error("failed to initialize WebAuthn — passkey endpoints will be unavailable", "error", err)
			wa = nil
		} else {
			slog.Info("WebAuthn initialized", "rpid", cfg.WebAuthn.RPID, "origins", len(cfg.WebAuthn.RPOrigins))
		}
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
		userDKG:          frost.NewUserDKG(),
		webauthn:         wa,
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

// SetLimiter wires in a rate limiter for unauthenticated endpoints.
// Called from main after the handler is constructed so existing call sites
// need no changes. A nil limiter (the zero value) skips all rate limiting.
func (h *Handler) SetLimiter(l ratelimit.Limiter) { h.limiter = l }

// SetIPHasher wires in the rotating HMAC hasher used for per-IP rate limiting.
// Only meaningful when cfg.Recovery.TrustedProxyHeader is set; the handler
// checks that field before consulting the hasher.
func (h *Handler) SetIPHasher(ih *ratelimit.IPHasher) { h.ipHasher = ih }

// RegisterRoutes registers all HTTP routes
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// Health endpoints
	mux.HandleFunc("/health", h.handleHealth)
	mux.HandleFunc("/health/live", h.handleLive)
	mux.HandleFunc("/health/ready", h.handleReady)

	// Key management. The /api/v1/keys/ handler is registered below with a
	// wrapper that also handles the P7 Path A migration path.
	mux.HandleFunc("/api/v1/keys", h.handleKeys)

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
	mux.HandleFunc("/api/v1/users/password", h.handleUserChangePassword)

	// Account recovery by nsec proof of possession. Unauthenticated by necessity —
	// the whole point is that the caller has lost the password. Authority comes
	// from a signature over a server-issued single-use challenge (see recovery.go).
	mux.HandleFunc("/api/v1/recovery/challenge", h.handleRecoveryChallenge)
	mux.HandleFunc("/api/v1/recovery/complete", h.handleRecoveryComplete)
	// Opt-out lives behind normal auth: only the account holder changes their own
	// posture, and re-enabling recovery must not be reachable from a recovery.
	mux.HandleFunc("/api/v1/users/recovery", h.handleRecoverySettings)
	mux.HandleFunc("/api/v1/users/mfa/setup", h.handleMFASetup)
	mux.HandleFunc("/api/v1/users/mfa/verify", h.handleMFAVerify)
	mux.HandleFunc("/api/v1/users/mfa/disable", h.handleMFADisable)
	mux.HandleFunc("/api/v1/users/sessions", h.handleUserSessions)

	// Passkey (WebAuthn) — registration requires an active session;
	// discoverable login (/login/begin + /login/finish) is unauthenticated.
	mux.HandleFunc("/api/v1/users/passkey/register/begin", h.handlePasskeyRegisterBegin)
	mux.HandleFunc("/api/v1/users/passkey/register/finish", h.handlePasskeyRegisterFinish)
	mux.HandleFunc("/api/v1/users/passkey/login/begin", h.handlePasskeyLoginBegin)
	mux.HandleFunc("/api/v1/users/passkey/login/finish", h.handlePasskeyLoginFinish)

	// Lightning / LNURL-auth (LUD-04).
	// challenge + status + callback: unauthenticated (wallet and poller endpoints).
	// link/challenge + keys: authentication required.
	mux.HandleFunc("/api/v1/users/lightning/challenge", h.handleLightningChallenge)
	mux.HandleFunc("/api/v1/lnurl-auth/callback", h.handleLNURLAuthCallback)
	mux.HandleFunc("/api/v1/users/lightning/status", h.handleLightningStatus)
	mux.HandleFunc("/api/v1/users/lightning/link/challenge", h.handleLightningLinkChallenge)
	mux.HandleFunc("/api/v1/users/lightning/keys", h.handleLightningKeys)
	mux.HandleFunc("/api/v1/users/lightning/keys/", h.handleLightningKeyByID)

	// Status
	mux.HandleFunc("/api/v1/status", h.handleStatus)

	// Bunker URI
	mux.HandleFunc("/api/v1/bunker/", h.handleBunkerConnect)

	// Nostrconnect (client-initiated connection)
	mux.HandleFunc("/api/v1/nostrconnect", h.handleNostrConnect)
	// SSO: auto-approve nostrconnect with stored consent (unified-auth-design §5)
	mux.HandleFunc("/api/v1/nostrconnect/session", h.handleNostrConnectSession)
	// SSO: revoke all app consents and NIP-46 permissions for the caller
	mux.HandleFunc("/api/v1/nostrconnect/revoke", h.handleNostrConnectRevoke)

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

	// FROST 2-of-N user-cosigner DKG (docs/frost-2-of-n-design.md §4.2)
	mux.HandleFunc("/api/v1/frost/user-dkg/round1", h.handleFrostUserDKGRound1)
	mux.HandleFunc("/api/v1/frost/user-dkg/round2", h.handleFrostUserDKGRound2)
	mux.HandleFunc("/api/v1/frost/user-dkg/finalize", h.handleFrostUserDKGFinalize)
	// FROST lost-device recovery (design doc §6.4) - returns the at-DKG
	// signer_share_for_user (decrypted server-side via the user's Vault
	// token) plus the user-reported verification share for client-side
	// reconstruction validation.
	mux.HandleFunc("/api/v1/frost/user-dkg/recovery/", h.handleFrostUserDKGRecovery)

	// P4e: browser-side cosign listener registers its ephemeral pubkey
	// so the signer knows where to p-tag kind:24135 cosign requests.
	mux.HandleFunc("/api/v1/frost/cosign-listener/register", h.handleFrostCosignListenerRegister)

	// FROST direct-sign for the SPA's own admin ops (P7 Path C +
	// admin sign flow). Two-round HTTP handshake keyed by user
	// auth + key_id; reuses UserSignerCoordinator internals.
	mux.HandleFunc("/api/v1/frost/sign/round1", h.handleFrostSignRound1)
	mux.HandleFunc("/api/v1/frost/sign/round2", h.handleFrostSignRound2)

	// FROST P5: cross-device share transfer for keys that lack a
	// phrase-derived share (Path A/B migrations). Upload the share
	// AES-GCM-encrypted under a pairing-password-derived KEK; the
	// signer relays the ciphertext to the destination device.
	mux.HandleFunc("/api/v1/frost/share-transfer/upload", h.handleFrostShareTransferUpload)
	mux.HandleFunc("/api/v1/frost/share-transfer/", h.handleFrostShareTransferDownload)

	// P7 Path A: convert an existing user-owned local (Vault-encrypted-
	// nsec) key to FROST-user (2-of-2) shape without changing the pubkey.
	// See docs/frost-2-of-n-design.md §13.2.
	// Route pattern: POST /api/v1/keys/{keyId}/frost-migrate
	mux.HandleFunc("/api/v1/keys/", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/frost-migrate") {
			h.handleFrostMigratePathA(w, r)
			return
		}
		h.handleKeyByID(w, r)
	})

	// P7 Path B: interactive additive split for keys NOT currently in
	// the signer. Two-round protocol; nsec never leaves the browser.
	// See docs/frost-2-of-n-design.md §13.2 Path B.
	mux.HandleFunc("/api/v1/keys/frost-migrate-b/init", h.handleFrostMigrateBInit)
	mux.HandleFunc("/api/v1/keys/frost-migrate-b/finalize", h.handleFrostMigrateBFinalize)
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
	KeyType         string    `json:"key_type,omitempty"`        // "local" or "proxy"
	UpstreamPubkey  string    `json:"upstream_pubkey,omitempty"` // For proxy keys
	RequireApproval bool      `json:"require_approval"`
	DisposableMode  bool      `json:"disposable_mode"`
	CoverTraffic    bool      `json:"cover_traffic"`
	TorEgress       bool      `json:"tor_egress"`
	Relays          []string  `json:"relays,omitempty"` // Custom relays for this key
	CreatedAt       time.Time `json:"created_at"`
	IsPrimary       bool      `json:"is_primary"`
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

	if len(parts) == 2 && parts[1] == "primary" {
		// /api/v1/keys/{id}/primary
		switch r.Method {
		case http.MethodPut:
			h.handleSetPrimaryKey(w, r, keyID)
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
			DisposableMode:  key.DisposableMode,
			CoverTraffic:    key.CoverTraffic,
			TorEgress:       key.TorEgress,
			Relays:          key.Relays,
			CreatedAt:       key.CreatedAt,
			IsPrimary:       key.IsPrimary,
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
		DisposableMode:  key.DisposableMode,
		CoverTraffic:    key.CoverTraffic,
		TorEgress:       key.TorEgress,
		Relays:          key.Relays,
		CreatedAt:       key.CreatedAt,
		IsPrimary:       key.IsPrimary,
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
		DisposableMode:  key.DisposableMode,
		CoverTraffic:    key.CoverTraffic,
		TorEgress:       key.TorEgress,
		Relays:          key.Relays,
		CreatedAt:       key.CreatedAt,
		IsPrimary:       key.IsPrimary,
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
		DisposableMode:  key.DisposableMode,
		CoverTraffic:    key.CoverTraffic,
		TorEgress:       key.TorEgress,
		Relays:          key.Relays,
		CreatedAt:       key.CreatedAt,
		IsPrimary:       key.IsPrimary,
	})
}

type UpdateKeyRequest struct {
	Name            *string  `json:"name,omitempty"`
	RequireApproval *bool    `json:"require_approval,omitempty"`
	DisposableMode  *bool    `json:"disposable_mode,omitempty"`
	CoverTraffic    *bool    `json:"cover_traffic,omitempty"`
	TorEgress       *bool    `json:"tor_egress,omitempty"`
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
	if req.DisposableMode != nil {
		key.DisposableMode = *req.DisposableMode
	}
	if req.CoverTraffic != nil {
		key.CoverTraffic = *req.CoverTraffic
	}
	if req.TorEgress != nil {
		key.TorEgress = *req.TorEgress
	}
	if req.Relays != nil {
		key.Relays = req.Relays
	}

	// Save updates
	if err := h.storage.UpdateKey(r.Context(), key); err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to update key")
		return
	}

	slog.Info("updated key", "id", id, "require_approval", key.RequireApproval, "disposable_mode", key.DisposableMode, "relays", len(key.Relays))

	h.jsonResponse(w, http.StatusOK, KeyResponse{
		ID:              key.ID,
		Name:            key.Name,
		Pubkey:          key.Pubkey,
		RequireApproval: key.RequireApproval,
		DisposableMode:  key.DisposableMode,
		CoverTraffic:    key.CoverTraffic,
		TorEgress:       key.TorEgress,
		Relays:          key.Relays,
		CreatedAt:       key.CreatedAt,
		IsPrimary:       key.IsPrimary,
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

// handleSetPrimaryKey makes a key the account's identity key.
//
// PUT /api/v1/keys/{id}/primary
//
// This is deliberately its own endpoint rather than a field on PATCH
// /api/v1/keys/{id}. Promoting a key changes the pubkey that IS the user on the
// platform and the only key that can authorise an nsec password recovery, so it
// should not be something a client can do by accident while renaming a key or
// editing its relay list. handleUpdateKey does not touch IsPrimary.
//
// Proxy keys are refused: the signer does not hold their nsec, so the user could
// not produce the recovery proof their own identity key is supposed to give
// them, and reconcilePlatformIdentity would register an identity this signer
// cannot sign for.
func (h *Handler) handleSetPrimaryKey(w http.ResponseWriter, r *http.Request, id string) {
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

	// Not-found rather than forbidden: do not confirm the key exists to
	// someone who does not own it.
	if key.OwnerID != claims.UserID {
		h.errorResponse(w, http.StatusNotFound, "key not found")
		return
	}

	if key.IsProxy() {
		h.errorResponse(w, http.StatusBadRequest, "a proxy key cannot be the identity key: this signer does not hold its private key")
		return
	}

	if err := h.storage.SetPrimaryKey(r.Context(), claims.UserID, id); err != nil {
		if err == storage.ErrKeyNotFound {
			h.errorResponse(w, http.StatusNotFound, "key not found")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to set primary key")
		return
	}

	// The platform identity follows the primary key, so re-register it now
	// rather than leaving the old pubkey authoritative until the next login.
	if user, err := h.storage.GetUser(r.Context(), claims.UserID); err == nil && user != nil {
		h.reconcilePlatformIdentity(r.Context(), user)
	}

	slog.Info("primary key changed", "key_id", id, "pubkey", key.Pubkey, "owner", claims.UserID)
	h.jsonResponse(w, http.StatusOK, map[string]any{
		"id":         key.ID,
		"pubkey":     key.Pubkey,
		"is_primary": true,
	})
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
	Name        string            `json:"name"`
	Description string            `json:"description,omitempty"`
	Rules       []PolicyRuleInput `json:"rules"`
	ExpiresAt   *time.Time        `json:"expires_at,omitempty"`
}

type PolicyRuleInput struct {
	Method       string `json:"method"`
	AllowedKinds []int  `json:"allowed_kinds,omitempty"`
	MaxUsage     int    `json:"max_usage,omitempty"`
}

type PolicyResponse struct {
	ID          string                `json:"id"`
	Name        string                `json:"name"`
	Description string                `json:"description,omitempty"`
	Rules       []*storage.PolicyRule `json:"rules"`
	ExpiresAt   *time.Time            `json:"expires_at,omitempty"`
	CreatedAt   time.Time             `json:"created_at"`
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
	ID         string     `json:"id"`
	PolicyID   string     `json:"policy_id"`
	KeyID      string     `json:"key_id"`
	ClientName string     `json:"client_name,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RedeemedAt *time.Time `json:"redeemed_at,omitempty"`
	RedeemedBy string     `json:"redeemed_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
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
		"message":    "token redeemed successfully",
		"key_pubkey": key.Pubkey,
		"methods":    methods,
		"expires_at": policy.ExpiresAt,
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

	var requests []*storage.PendingRequest
	if keyPubkey != "" {
		reqs, err := h.storage.ListPendingRequests(r.Context(), keyPubkey)
		if err != nil {
			h.errorResponse(w, http.StatusInternalServerError, "failed to list requests")
			return
		}
		requests = reqs
	} else {
		// No explicit key_pubkey: scope to the authenticated user's own keys.
		// The signer UI (Dashboard/Requests) polls /requests with no param — return
		// pending requests across every key this session owns instead of a 400.
		// (The explicit-key path above is unchanged; this branch is purely additive.)
		claims, err := h.validateAuthHeader(r)
		if err != nil {
			h.errorResponse(w, http.StatusUnauthorized, "key_pubkey query parameter or a valid session required")
			return
		}
		keys, err := h.storage.ListKeys(r.Context(), claims.UserID)
		if err != nil {
			h.errorResponse(w, http.StatusInternalServerError, "failed to list keys")
			return
		}
		for _, key := range keys {
			reqs, err := h.storage.ListPendingRequests(r.Context(), key.Pubkey)
			if err != nil {
				h.errorResponse(w, http.StatusInternalServerError, "failed to list requests")
				return
			}
			requests = append(requests, reqs...)
		}
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
	Methods      []string   `json:"methods,omitempty"`       // Methods to allow (default: requested method only)
	AllowedKinds []int      `json:"allowed_kinds,omitempty"` // Kinds to allow for sign_event
	Remember     bool       `json:"remember"`                // Create persistent permission
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`    // Permission expiration (if remember=true)
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
	// ImportNsec optionally imports an existing key (nsec or hex) as the user's
	// initial signing key. When empty, a fresh keypair is generated so the new
	// account can sign immediately (no "account with zero keys" dead end).
	ImportNsec string `json:"import_nsec,omitempty"`
}

// createInitialSigningKey provisions a signing key for a newly registered user
// so they aren't left with an account that can't sign anything. importPriv may
// be an nsec/hex private key to import, or "" to generate a fresh keypair. The
// key is local-encrypted: registration runs before the user has a session, so
// no per-user Vault encryptor is available yet.
func (h *Handler) createInitialSigningKey(ctx context.Context, ownerID, name, importPriv, passphrase string) (*storage.Key, error) {
	var privateKey, pubkey string
	if strings.TrimSpace(importPriv) != "" {
		privateKey = strings.TrimSpace(importPriv)
		if strings.HasPrefix(privateKey, "nsec1") {
			prefix, value, err := nip19.Decode(privateKey)
			if err != nil || prefix != "nsec" {
				return nil, fmt.Errorf("invalid nsec format")
			}
			privateKey = value.(string)
		}
		pk, err := nostr.GetPublicKey(privateKey)
		if err != nil {
			return nil, fmt.Errorf("invalid private key")
		}
		pubkey = pk
	} else {
		privateKey = nostr.GeneratePrivateKey()
		pk, err := nostr.GetPublicKey(privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to generate key: %w", err)
		}
		pubkey = pk
	}

	// Wrap under the registrant's passphrase, not the server key.
	//
	// There is no per-user Vault encryptor at this point in registration -- the
	// account was provisioned moments ago and no userpass token has been minted --
	// so the passphrase KEK is the only user-held option available here. It is
	// also the only one that ever applies to this key: loadUserVaultKeys skips
	// anything that isn't already Vault ciphertext, so nothing migrates a
	// registration key into Vault later. A key written under the server's
	// ENCRYPTION_KEY here stays server-decryptable for its entire life.
	//
	// This does not introduce a new recovery cliff. The password is already
	// cryptographically load-bearing: it is the Vault userpass credential, so a
	// user who forgets it loses access to Vault-wrapped keys just the same. See
	// crypto/passphrase_encryptor.go and cloistr-password-reset-recovery-gap.
	//
	// The server-held encryptor remains only as a last resort for callers with no
	// passphrase in hand, and is loud about it.
	encryptedKey := privateKey
	encryptionMethod := string(crypto.EncryptionMethodLocal)
	switch {
	case passphrase != "":
		pe, err := crypto.NewPassphraseEncryptor(passphrase)
		if err != nil {
			return nil, fmt.Errorf("failed to derive key encryptor: %w", err)
		}
		enc, err := pe.Encrypt(privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt key: %w", err)
		}
		encryptedKey = enc
		encryptionMethod = string(crypto.EncryptionMethodPassphrase)
	case h.encryptor != nil:
		slog.Warn("initial signing key wrapped with the server-held key: no passphrase supplied",
			"owner_id", ownerID, "note", "server can decrypt this key")
		enc, err := h.encryptor.Encrypt(privateKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt key: %w", err)
		}
		encryptedKey = enc
	}

	key := &storage.Key{
		ID:               pubkey[:16],
		Name:             name,
		Pubkey:           pubkey,
		KeyType:          storage.KeyTypeLocal,
		EncryptedNsec:    encryptedKey,
		EncryptionMethod: encryptionMethod,
		CreatedAt:        time.Now(),
		OwnerID:          ownerID,
	}
	if err := h.storage.CreateKey(ctx, key); err != nil {
		return nil, err
	}
	h.signer.RegisterKey(pubkey, privateKey)
	return key, nil
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	MFACode  string `json:"mfa_code,omitempty"`
}

type LoginResponse struct {
	Token       string       `json:"token"`
	ExpiresAt   time.Time    `json:"expires_at"`
	User        UserResponse `json:"user"`
	MFARequired bool         `json:"mfa_required,omitempty"`
}

type UserResponse struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Email    string `json:"email,omitempty"`
	// Pubkey is the user's canonical Nostr identity: their Primary signing key's
	// pubkey (Option A identity model). Falls back to the derived platform pubkey
	// only when the user has zero signing keys. The HKDF-derived platform pubkey is
	// no longer surfaced to clients — once a signing key exists it is the sole
	// identity and the derived pubkey is de-registered (see reconcilePlatformIdentity).
	Pubkey     string     `json:"pubkey,omitempty"`
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

	// Provision an initial signing key so the new account can actually sign
	// (an account with zero signing keys is a dead end). Best-effort: on failure
	// we log and still return success — the user can create a key later.
	// The Primary key is the user's identity under the Option A model.
	var primaryKey *storage.Key
	if key, err := h.createInitialSigningKey(r.Context(), userID, "Primary", req.ImportNsec, req.Password); err != nil {
		slog.Warn("failed to create initial signing key", "error", err, "user_id", userID)
	} else {
		primaryKey = key
		// "Primary" above is only a default display name the user may rename.
		// What actually makes this the identity key is the attribute, set here.
		if err := h.storage.SetPrimaryKey(r.Context(), userID, key.ID); err != nil {
			slog.Warn("failed to flag initial key as primary", "error", err, "user_id", userID, "key_id", key.ID)
		} else {
			key.IsPrimary = true
		}
		slog.Info("created initial signing key", "user_id", userID, "pubkey", key.Pubkey[:16]+"...")
	}

	// Register the platform identity for cross-service authorization (Option A).
	// With a signing key, reconcile makes that key the sole platform identity and
	// de-registers the derived platform pubkey. Without one (key creation failed
	// above), fall back to registering the derived pubkey so the account still has
	// a usable platform identity until a key is created. Best-effort: platform
	// linking is supplementary and never fails registration.
	if primaryKey != nil {
		h.reconcilePlatformIdentity(r.Context(), user)
	} else if err := h.storage.EnsurePlatformUser(r.Context(), user.Pubkey); err != nil {
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

	// Reset failed login attempts. Non-critical bookkeeping against camelot, so
	// it runs off the login critical path: a camelot write-latency spike here
	// otherwise stalls the login response (measured up to ~11s even after
	// sessions moved to Dragonfly). Detached context; failure is logged and
	// self-heals on the next successful login.
	go func(userID string) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := h.storage.ResetFailedLogins(ctx, userID); err != nil {
			slog.Warn("async reset failed-logins failed", "error", err, "user_id", userID)
		}
	}(user.ID)

	// Lazily migrate the platform identity to the signing key (Option A): retires
	// the derived platform pubkey for pre-Option-A / fallback accounts on their
	// next login. Runs OFF the login critical path: it does idempotent bookkeeping
	// on the shared platform users/user_service_access tables (contended by other
	// services), so under load its latency must not land on the login response —
	// synchronously it turned slow shared-table writes into 10-20s logins and edge
	// 502s. Detached context (r.Context() is canceled once we respond) and a
	// snapshot of user (the handler mutates the original below via UpdateUser).
	reconcileUser := *user
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		h.reconcilePlatformIdentity(ctx, &reconcileUser)
	}()

	// Generate session ID first (needed for JWT)
	sessionID, _ := auth.GenerateSessionID()

	// Generate JWT with session ID (so we can retrieve Vault token later)
	token, expiresAt, err := auth.GenerateJWTWithSession(h.authConfig, user.ID, user.Username, sessionID)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	// Create session WITHOUT the Vault token — it will be populated by the
	// async goroutine below. Async login (2026-07-11 unified-auth §10.4 revisit):
	// userpass login on the OpenBao cluster takes 1-9s (raft-consensus writes
	// on the success path), which made synchronous logins user-visibly slow
	// and edge-gateway-borderline. The Vault token is only used for later
	// key operations; on-demand key-load (57878d4) already handles a
	// missing-token window on the NIP-46 sign path, and ensureNostrConnectKeyLoaded
	// now does a bounded wait so a key request that arrives WHILE the goroutine
	// is still running does not silently fail.
	//
	// Privacy-architecture §3.6: we do not retain per-session or per-login IPs.
	// IPAddress and LastLoginIP intentionally left empty; if/when we need
	// session-location UX, it'll be derived from short-window encrypted
	// telemetry the user can decrypt, not from operator-readable retention.
	session := &storage.UserSession{
		ID:         sessionID,
		UserID:     user.ID,
		Token:      token[:16], // Store prefix for revocation check
		VaultToken: "",         // Filled by populateVaultTokenAsync
		UserAgent:  r.UserAgent(),
		ExpiresAt:  expiresAt,
		CreatedAt:  time.Now(),
	}
	h.storage.CreateUserSession(r.Context(), session)

	// Kick off Vault userpass auth in the background. Uses context.Background()
	// (not r.Context()) because r.Context() is cancelled when the response is
	// sent; we need the goroutine to keep running independently. Password
	// captured in closure — same lifetime as the sync-flow local var was.
	if h.vaultClient != nil && h.config.Vault.Enabled {
		go h.populateVaultTokenAsync(sessionID, user.ID, user.Username, req.Password)
	}

	// Load passphrase-wrapped ("pbk:") keys. Independent of Vault: this is the
	// only path that makes a registration key usable, since createInitialSigningKey
	// wraps under the passphrase and nothing migrates those into Vault. Detached
	// context for the same reason as above -- r.Context() dies with the response --
	// and off the critical path because PBKDF2 at 600k iterations is not something
	// to put in front of a login response.
	// Drain any legacy server-held keys first, then load the passphrase-wrapped
	// set. Order matters: re-wrapping turns an "enc:" key into a "pbk:" one, and
	// the re-wrap hands it to the runtime itself, so the load pass that follows
	// simply finds nothing left to do for it.
	go func(userID, passphrase string) {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if n := h.rewrapLegacyLocalKeys(ctx, userID, passphrase); n > 0 {
			slog.Info("migrated legacy server-held keys at login", "user_id", userID, "count", n)
		}
		h.loadUserPassphraseKeys(ctx, userID, passphrase)
	}(user.ID, req.Password)

	// Update last login. LastLoginIP intentionally not set (see above). Like the
	// failed-login reset, this is non-critical bookkeeping against camelot and
	// must not sit on the login critical path — it was the last remaining
	// synchronous camelot write there. Snapshot user because the goroutine
	// outlives this handler.
	now := time.Now()
	user.LastLoginAt = &now
	lastLoginUser := *user
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := h.storage.UpdateUser(ctx, &lastLoginUser); err != nil {
			slog.Warn("async last-login update failed", "error", err, "user_id", lastLoginUser.ID)
		}
	}()

	slog.Info("user logged in", "username", req.Username, "user_id", user.ID)

	// Set parent-domain session cookie so other *.cloistr.xyz subdomains share
	// the auth session (cross-subdomain SSO, unified-auth-design §5).
	// When CookieDomain is empty (dev/localhost) the Domain attribute is omitted
	// and the browser scopes the cookie to the issuing host only.
	http.SetCookie(w, h.newAuthCookie(token, expiresAt))

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

	// The eager Vault-key pre-load that used to live here is now the tail of
	// populateVaultTokenAsync — it needs the async-fetched token, and running
	// it there keeps the login response fast. Keys still lazy-load on demand
	// via ensureNostrConnectKeyLoaded if the pre-load hasn't finished yet.
}

func (h *Handler) handleUserLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// Logout is idempotent: always clear the parent-domain cookie, even if the
	// caller has no signer session (e.g. logged in via nostrconnect, not password).
	// Returning 401 here would leave the .cloistr.xyz cookie set and make "sign out"
	// appear not to work. Server-side cleanup runs only when a session exists.
	http.SetCookie(w, h.clearAuthCookie())

	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.jsonResponse(w, http.StatusOK, map[string]string{"message": "logged out"})
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

	// Revoke all SSO app consents so cross-subdomain apps must re-consent
	// after next login (unified-auth-design §5 central logout).
	h.storage.RevokeAllAppConsents(r.Context(), claims.UserID)

	h.jsonResponse(w, http.StatusOK, map[string]string{"message": "logged out successfully"})
}

// resolveSigningPubkey returns the user's canonical signing pubkey under the
// Option A identity model: the key flagged IsPrimary. The bool is false when the
// user has no signing keys, in which case the caller should fall back to the
// derived platform pubkey (user.Pubkey) so the identity is never empty.
//
// This used to mean "the key whose Name is 'Primary', else the oldest key".
// Name is a display string the user can edit, so a rename silently moved both
// the account identity and the nsec-recovery anchor, and two keys could claim
// the title at once. It is now an attribute the user sets deliberately
// (PUT /api/v1/keys/{id}/primary), with at most one per owner enforced by a
// partial unique index.
//
// The oldest-key fallback is retained ONLY for rows the backfill could not
// reach — a key with no owner_id, or a storage backend that has not run the
// migration. It is a safety net, not the selection rule.
func (h *Handler) resolveSigningPubkey(ctx context.Context, userID string) (string, bool) {
	keys, err := h.storage.ListKeys(ctx, userID)
	if err != nil || len(keys) == 0 {
		return "", false
	}
	chosen := keys[len(keys)-1] // oldest key (last in DESC list)
	for _, k := range keys {
		if k.IsPrimary {
			chosen = k
			break
		}
	}
	if chosen.Pubkey == "" {
		return "", false
	}
	return chosen.Pubkey, true
}

// reconcilePlatformIdentity makes the user's signing key the sole platform
// identity (Option A). Once a real signing key exists it is registered for
// cross-service authorization and the HKDF-derived platform pubkey
// (user.Pubkey) is de-registered from the platform users table. The derived
// pubkey is retained on the signer_web_accounts row as the zero-keys bootstrap
// fallback. Best-effort and idempotent: a no-op when the user has no signing
// keys, and RemovePlatformUser is guarded against removing a pubkey that still
// holds service grants.
func (h *Handler) reconcilePlatformIdentity(ctx context.Context, user *storage.User) {
	signingPubkey, hasKey := h.resolveSigningPubkey(ctx, user.ID)
	if !hasKey {
		return
	}
	if err := h.storage.EnsurePlatformUser(ctx, signingPubkey); err != nil {
		slog.Warn("reconcile: failed to ensure signing platform user", "error", err, "user_id", user.ID)
	}
	if user.Pubkey != "" && user.Pubkey != signingPubkey {
		if err := h.storage.RemovePlatformUser(ctx, user.Pubkey); err != nil {
			slog.Warn("reconcile: failed to de-register derived platform pubkey", "error", err, "user_id", user.ID)
		}
	}
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

	// Option A identity model: the canonical pubkey is the user's signing key.
	// Fall back to the derived platform pubkey only when the user has no keys.
	signingPubkey := user.Pubkey
	if pk, ok := h.resolveSigningPubkey(r.Context(), user.ID); ok {
		signingPubkey = pk
	}

	h.jsonResponse(w, http.StatusOK, UserResponse{
		ID:         user.ID,
		Username:   user.Username,
		Email:      user.Email,
		Pubkey:     signingPubkey,
		MFAEnabled: user.MFAEnabled,
		CreatedAt:  user.CreatedAt,
		LastLogin:  user.LastLoginAt,
	})
}

// ChangePasswordRequest is the body for PUT /api/v1/users/password.
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// handleUserChangePassword changes the authenticated user's password. It
// verifies the current password before applying the new one, mirroring the
// register handler's validation (new password must be >= 8 chars).
func (h *Handler) handleUserChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	var req ChangePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if len(req.NewPassword) < 8 {
		h.errorResponse(w, http.StatusBadRequest, "new password must be at least 8 characters")
		return
	}

	user, err := h.storage.GetUser(r.Context(), claims.UserID)
	if err != nil {
		h.errorResponse(w, http.StatusNotFound, "user not found")
		return
	}

	// Verify the current password before allowing a change.
	if !auth.VerifyPassword(req.CurrentPassword, user.PasswordHash) {
		h.errorResponse(w, http.StatusUnauthorized, "current password is incorrect")
		return
	}

	hash, err := auth.HashPassword(req.NewPassword, h.authConfig.BcryptCost)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to hash password")
		return
	}

	// Re-wrap any passphrase-encrypted key material BEFORE committing the new password.
	// The KEK for those keys is derived from the passphrase, so changing the password
	// without re-wrapping would render the user's own keys permanently unreadable.
	// Ordering matters: on failure here the password is left unchanged, so the account
	// and its keys stay consistent under the old passphrase.
	rollbackKeys, rewrapped, err := h.rewrapPassphraseKeys(r.Context(), user.ID, req.CurrentPassword, req.NewPassword)
	if err != nil {
		slog.Error("password change aborted: key re-wrap failed",
			"user_id", user.ID, "error", err)
		h.errorResponse(w, http.StatusInternalServerError, "failed to re-encrypt key material; password unchanged")
		return
	}

	user.PasswordHash = hash
	if err := h.storage.UpdateUser(r.Context(), user); err != nil {
		// Keys are already re-wrapped under the NEW passphrase but the account still
		// has the OLD one. Roll the keys back or the user loses access to them.
		if rollbackKeys != nil {
			if rbErr := rollbackKeys(); rbErr != nil {
				slog.Error("CRITICAL: password update failed AND key rollback failed; "+
					"keys are wrapped under a passphrase the account does not have",
					"user_id", user.ID, "rollback_error", rbErr)
			}
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to update password")
		return
	}

	// Vault's userpass copy has to follow the change. Without this the account
	// authenticates to the signer with the new password and to Vault with the old
	// one, so populateVaultTokenAsync fails on every subsequent login and every
	// vault:-wrapped key silently stops loading. Reported, not fatal: the password
	// and the passphrase-wrapped keys are already consistent at this point, and
	// failing the request would leave the caller unsure which half applied.
	if !h.resetVaultCredential(r.Context(), user.ID, req.NewPassword) && h.vaultClient != nil && h.config.Vault.Enabled {
		slog.Error("password changed but vault credential update failed; vault-wrapped keys will not load until this is fixed",
			"user_id", user.ID)
	}

	slog.Info("password changed", "username", user.Username, "user_id", user.ID, "keys_rewrapped", rewrapped)

	h.jsonResponse(w, http.StatusOK, map[string]string{"message": "password changed successfully"})
}

// rewrapPassphraseKeys re-encrypts every passphrase-wrapped key this user owns from the
// old passphrase to the new one, and returns a rollback func restoring the previous
// ciphertext.
//
// Keys encrypted with a passphrase-derived KEK (crypto.PassphraseEncryptor, "pbk:") are
// readable only via the user's passphrase -- by design, the server cannot decrypt them
// alone. That means a password change MUST re-wrap them or the material is lost for
// good, with no operator recovery path.
//
// Vault- and local-encrypted keys are untouched: Vault holds its own wrapping key, and
// the local encryptor uses a server-held key. Neither is tied to the passphrase.
//
// Semantics are all-or-nothing. Every re-encryption is computed in memory first, so a
// bad passphrase or corrupt ciphertext aborts before anything is persisted. If a write
// fails partway, already-written keys are restored before returning.
func (h *Handler) rewrapPassphraseKeys(ctx context.Context, userID, oldPassphrase, newPassphrase string) (rollback func() error, count int, err error) {
	keys, err := h.storage.ListKeys(ctx, userID)
	if err != nil {
		return nil, 0, fmt.Errorf("list keys: %w", err)
	}

	// Compute every re-wrap before persisting any of it.
	type pending struct {
		key   *storage.Key
		oldCT string
		newCT string
	}
	var todo []pending
	for _, k := range keys {
		if k == nil || !crypto.IsPassphraseEncrypted(k.EncryptedNsec) {
			continue
		}
		newCT, err := crypto.ReWrap(oldPassphrase, newPassphrase, k.EncryptedNsec)
		if err != nil {
			return nil, 0, fmt.Errorf("re-wrap key %s: %w", k.ID, err)
		}
		todo = append(todo, pending{key: k, oldCT: k.EncryptedNsec, newCT: newCT})
	}
	if len(todo) == 0 {
		return nil, 0, nil
	}

	// Persist, tracking what has been written so it can be undone.
	var written []pending
	restore := func() error {
		var firstErr error
		for _, p := range written {
			p.key.EncryptedNsec = p.oldCT
			if err := h.storage.UpdateKey(ctx, p.key); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	}

	for _, p := range todo {
		p.key.EncryptedNsec = p.newCT
		if err := h.storage.UpdateKey(ctx, p.key); err != nil {
			if rbErr := restore(); rbErr != nil {
				slog.Error("key re-wrap rollback failed; some keys may be wrapped under the new passphrase",
					"user_id", userID, "rollback_error", rbErr)
			}
			return nil, 0, fmt.Errorf("persist re-wrapped key %s: %w", p.key.ID, err)
		}
		written = append(written, p)
	}

	return restore, len(written), nil
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

	claims, err := auth.ValidateJWT(h.authConfig, token)
	if err != nil {
		return nil, err
	}

	if err := h.ensureSessionLive(r.Context(), claims); err != nil {
		return nil, err
	}
	return claims, nil
}

// ensureSessionLive rejects a JWT whose server-side session has been deleted.
//
// WHY THIS EXISTS
//
// JWT validation is stateless: signature plus expiry, nothing else. So until
// this check existed, SIGNING OUT DID NOT REVOKE ANYTHING. handleUserLogout
// does the right things — deletes every session, revokes Vault tokens, revokes
// SSO app consents — but a token already issued kept working for the remainder
// of its 24h life (auth.DefaultTokenExpiry) because nothing ever asked whether
// its session still existed.
//
// The visible symptom: sign out of mail.cloistr.xyz, open signer.cloistr.xyz,
// and you are still signed in. Each origin holds its own JWT in its own
// localStorage, which no other origin can clear, and the signer's initAuth
// trusts that local token first. Clearing the shared .cloistr.xyz cookie could
// never reach it. Revocation has to be server-side; there is no client-side fix.
//
// The session row is created at login with ExpiresAt set to the JWT's OWN
// expiry, so this can never log anyone out earlier than the token would have
// died anyway. It only closes the gap between "logged out" and "token expired".
//
// FAILS OPEN on infrastructure errors, deliberately. Sessions live in
// Dragonfly; treating an unreachable session store as "everyone is logged out"
// would turn a cache blip into a total outage of the identity service every
// other Cloistr service authenticates against. Only a definitive
// ErrSessionNotFound — the record is gone or expired — rejects.
//
// A token with no SessionID is allowed through: auth.GenerateJWT issues those
// for the admin pubkey path (internal/web), which has no session row to check.
// Every real user login path uses GenerateJWTWithSession.
func (h *Handler) ensureSessionLive(ctx context.Context, claims *auth.JWTClaims) error {
	if claims == nil || claims.SessionID == "" {
		return nil
	}

	_, err := h.storage.GetUserSession(ctx, claims.SessionID)
	if err == nil {
		return nil
	}
	if errors.Is(err, storage.ErrSessionNotFound) {
		slog.Debug("rejecting token for revoked session",
			"session_id", claims.SessionID, "user_id", claims.UserID)
		return auth.ErrInvalidToken
	}

	slog.Warn("session liveness check failed; allowing request",
		"error", err, "session_id", claims.SessionID)
	return nil
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
// ensureNostrConnectKeyLoaded loads a single Vault-encrypted signing key into
// the signer runtime ON DEMAND when it isn't already present. This is the
// durable fix for cookie-SSO and post-restart nostrconnect: Vault-encrypted
// keys aren't loaded at startup and are wiped on pod restart, and the cookie
// SSO path has no password login to trigger a load — so SendNostrConnectResponse
// would hit "key not found" and the client would time out. Uses the
// authenticated user's session-stored Vault token to decrypt just this key.
// Returns true if the key is (now) loaded. No-op for already-loaded or
// non-Vault keys.
func (h *Handler) ensureNostrConnectKeyLoaded(ctx context.Context, sessionID, userID string, key *storage.Key) bool {
	if h.signer.IsKeyLoaded(key.Pubkey) {
		return true
	}
	if h.vaultClient == nil || !crypto.IsVaultEncrypted(key.EncryptedNsec) {
		return h.signer.IsKeyLoaded(key.Pubkey)
	}
	if sessionID == "" {
		return false
	}
	// Wait up to ~15s for the async login goroutine (populateVaultTokenAsync)
	// to populate the session's VaultToken. This handles the race between the
	// login response and a very-fast follow-up sign request. In steady state
	// the token is already there and the loop exits on the first read;
	// polling only matters when we caught the sub-second window between login
	// return and Vault userpass completion.
	session, err := h.getUserSessionAwaitingVaultToken(ctx, sessionID)
	if err != nil || session == nil || session.VaultToken == "" {
		slog.Warn("on-demand key load: no usable session Vault token", "user_id", userID, "error", err)
		return false
	}
	vaultEncryptor := crypto.NewVaultEncryptor(h.vaultClient, userID, session.VaultToken)
	privateKey, ok := decryptAndVerifyVaultKey(ctx, vaultEncryptor, key)
	if !ok {
		slog.Warn("on-demand key load: decrypt failed", "user_id", userID, "pubkey", key.Pubkey[:16]+"...")
		return false
	}
	if key.IsProxy() {
		h.signer.RegisterProxyKey(key.Pubkey, privateKey, key.BunkerURI)
	} else {
		h.signer.RegisterKey(key.Pubkey, privateKey)
	}
	slog.Info("on-demand loaded vault key for nostrconnect", "user_id", userID, "pubkey", key.Pubkey[:16]+"...")
	return true
}

// rewrapLegacyLocalKeys drains the server-held ("enc:") keys that predate
// passphrase wrapping, re-wrapping each under the user's passphrase on their next
// login. It returns the number of keys migrated.
//
// This is the only workable shape for the migration: re-wrapping needs the user's
// passphrase, and the server never holds it outside an authenticated request. So
// it cannot be a batch job -- it has to ride the login that supplies the secret.
// Accounts that never log in keep their legacy ciphertext, which is exactly the
// status quo for them and no worse.
//
// Safety properties, in order of how badly each would hurt:
//
//   - The stored ciphertext is replaced only after the new wrapping has been
//     produced, so a failure anywhere leaves the original intact and the next
//     login simply retries.
//   - The decrypted key is verified to derive the pubkey it is filed under before
//     anything is written. A key that fails that check is left alone and reported
//     rather than "migrated" into unreadable material.
//   - Idempotent by construction: a migrated key is "pbk:" and no longer matches
//     the legacy filter.
//
// The key is registered in the signer runtime here because it is about to stop
// being loadable at boot: "enc:" keys are server-decryptable and so are loaded by
// signer.Start(), while "pbk:" keys are user-held and deliberately skipped. This
// call is the handover.
func (h *Handler) rewrapLegacyLocalKeys(ctx context.Context, userID, passphrase string) int {
	if h.encryptor == nil || passphrase == "" {
		return 0
	}

	keys, err := h.storage.ListKeys(ctx, userID)
	if err != nil {
		slog.Error("failed to list user keys for legacy re-wrap", "error", err, "user_id", userID)
		return 0
	}

	pe, err := crypto.NewPassphraseEncryptor(passphrase)
	if err != nil {
		return 0
	}

	migrated := 0
	for _, key := range keys {
		// Legacy server-held ciphertext only. Vault and passphrase keys are
		// user-held already; unprefixed values are not ours to touch.
		if !crypto.IsEncrypted(key.EncryptedNsec) {
			continue
		}

		privateKey, err := h.encryptor.Decrypt(key.EncryptedNsec)
		if err != nil {
			slog.Error("legacy re-wrap: decrypt failed, leaving key as-is",
				"user_id", userID, "pubkey", key.Pubkey[:16]+"...", "error", err)
			continue
		}
		if derived, derr := nostr.GetPublicKey(privateKey); derr != nil || derived != key.Pubkey {
			slog.Error("legacy re-wrap: decrypted key does not derive its stored pubkey, leaving key as-is",
				"user_id", userID, "pubkey", key.Pubkey[:16]+"...")
			continue
		}

		newCiphertext, err := pe.Encrypt(privateKey)
		if err != nil {
			slog.Error("legacy re-wrap: re-encrypt failed, leaving key as-is",
				"user_id", userID, "pubkey", key.Pubkey[:16]+"...", "error", err)
			continue
		}
		if err := h.storage.UpdateKeyEncryption(ctx, key.ID, newCiphertext, string(crypto.EncryptionMethodPassphrase)); err != nil {
			slog.Error("legacy re-wrap: persisting new ciphertext failed, original retained",
				"user_id", userID, "pubkey", key.Pubkey[:16]+"...", "error", err)
			continue
		}

		// Now user-held, so no longer loaded at boot -- hand it to the runtime.
		if key.IsProxy() {
			h.signer.RegisterProxyKey(key.Pubkey, privateKey, key.BunkerURI)
		} else {
			h.signer.RegisterKey(key.Pubkey, privateKey)
		}
		migrated++
		slog.Info("re-wrapped legacy server-held key under the user's passphrase",
			"user_id", userID, "pubkey", key.Pubkey[:16]+"...")
	}

	return migrated
}

// loadUserPassphraseKeys decrypts the user's passphrase-wrapped ("pbk:") keys and
// registers them in the signer runtime. It is the passphrase-KEK counterpart of
// loadUserVaultKeys, and exists for the same reason: user-held key material is
// undecryptable at boot by design, so it has to be loaded at login.
//
// Residency is bounded exactly as the Vault path already is. The passphrase lives
// only for this call -- it is not stored on the session, and nothing persists a
// derived KEK -- so this adds no key-material lifetime beyond what a login already
// has. The decrypted private key lands in the same runtime map as every other
// loaded key and is evicted on logout.
func (h *Handler) loadUserPassphraseKeys(ctx context.Context, userID, passphrase string) {
	if passphrase == "" {
		return
	}

	keys, err := h.storage.ListKeys(ctx, userID)
	if err != nil {
		slog.Error("failed to list user keys for passphrase loading", "error", err, "user_id", userID)
		return
	}

	// Built once: PBKDF2 at 600k iterations is deliberately expensive, and the
	// encryptor caches nothing across instances.
	pe, err := crypto.NewPassphraseEncryptor(passphrase)
	if err != nil {
		return
	}

	loadedCount := 0
	for _, key := range keys {
		if !crypto.IsPassphraseEncrypted(key.EncryptedNsec) {
			continue
		}
		privateKey, err := pe.Decrypt(key.EncryptedNsec)
		if err != nil {
			// Expected for keys wrapped under a previous passphrase that a
			// password change failed to re-wrap; not fatal for the others.
			slog.Warn("failed to decrypt passphrase-wrapped key",
				"user_id", userID, "pubkey", key.Pubkey[:16]+"...", "error", err)
			continue
		}
		if key.IsProxy() {
			h.signer.RegisterProxyKey(key.Pubkey, privateKey, key.BunkerURI)
		} else {
			h.signer.RegisterKey(key.Pubkey, privateKey)
		}
		loadedCount++
	}

	if loadedCount > 0 {
		slog.Info("loaded passphrase-wrapped keys for user", "user_id", userID, "count", loadedCount)
	}
}

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

// userTokenRenewInterval is how often live sessions' Vault tokens are renewed.
// Comfortably inside the 24h token period so a renewal can fail three times
// running and the token still survives.
const userTokenRenewInterval = 6 * time.Hour

// StartUserTokenRenewal keeps every live session's per-user Vault token alive.
//
// Without it a user's Vault token expired long before their session did — the
// session runs for JWT_EXPIRY hours (720 = 30 days in production) while the
// token was capped at 72h — and nothing could re-mint it, because minting needs
// the PASSWORD and only the login handler ever has one. The user stayed signed
// in on a perfectly valid cookie while every key decrypt 403'd, so signing
// failed and the client retried forever.
//
// Intended to run in a goroutine; returns when ctx is cancelled. The first pass
// is deferred by one interval because RestoreVaultKeysOnStartup already runs
// one at boot.
func (h *Handler) StartUserTokenRenewal(ctx context.Context) {
	if h.vaultClient == nil {
		return
	}
	slog.Info("user vault token renewal started", "interval", userTokenRenewInterval)

	ticker := time.NewTicker(userTokenRenewInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		h.refreshUserVaultTokens(ctx)
	}
}

// refreshUserVaultTokens migrates userpass roles to periodic tokens and renews
// the Vault token on every live session. Safe to call repeatedly: the migration
// short-circuits once a role is already periodic, and renewing a healthy token
// just extends its lease.
//
// A token that has ALREADY lapsed cannot be revived here — Vault answers 403.
// That session's keys stay undecryptable until the user logs in again, which is
// the one path that holds a password. The 403 is logged per user so the
// condition is visible in logs rather than only as a failed sign.
func (h *Handler) refreshUserVaultTokens(ctx context.Context) {
	if h.vaultClient == nil {
		return
	}

	users, err := h.storage.ListUsers(ctx)
	if err != nil {
		slog.Error("user vault token refresh: failed to list users", "error", err)
		return
	}

	var migrated, renewed, expired, failed int
	for _, user := range users {
		// Migrate the role first so the NEXT token this user is issued is
		// periodic. Existing tokens keep the ceiling they were minted with.
		changed, err := h.vaultClient.EnsureUserpassPeriodic(ctx, user.ID)
		if err != nil {
			slog.Warn("userpass periodic migration failed", "user_id", user.ID, "error", err)
		} else if changed {
			migrated++
			slog.Info("userpass role migrated to periodic token", "user_id", user.ID)
		}

		sessions, err := h.storage.ListUserSessions(ctx, user.ID)
		if err != nil {
			slog.Warn("user vault token refresh: failed to list sessions", "user_id", user.ID, "error", err)
			continue
		}

		// Several live sessions can carry the same token; renew each distinct
		// one once rather than per session.
		seen := make(map[string]bool, len(sessions))
		for _, sess := range sessions {
			if sess.VaultToken == "" || seen[sess.VaultToken] {
				continue
			}
			seen[sess.VaultToken] = true

			lease, err := h.vaultClient.RenewToken(ctx, sess.VaultToken)
			if err != nil {
				if isVaultForbidden(err) {
					expired++
					slog.Warn("user vault token has expired and cannot be renewed; user must log in again to restore signing",
						"user_id", user.ID, "session_id", sess.ID)
				} else {
					failed++
					slog.Warn("user vault token renewal failed", "user_id", user.ID, "session_id", sess.ID, "error", err)
				}
				continue
			}
			renewed++
			slog.Debug("user vault token renewed", "user_id", user.ID, "session_id", sess.ID, "lease_seconds", lease)
		}
	}

	slog.Info("user vault token refresh complete",
		"users", len(users),
		"roles_migrated", migrated,
		"tokens_renewed", renewed,
		"tokens_expired", expired,
		"renew_failures", failed,
	)
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

	// Renew before restoring. After a long pod downtime a session's token can
	// be alive but close to its TTL; renewing first turns a restore that would
	// have 403'd into one that succeeds. This also performs the one-time
	// migration of each userpass role to periodic tokens.
	h.refreshUserVaultTokens(ctx)

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
	// Status exposes keys_loaded count and connected_relays. Privacy-architecture
	// §3.10 forbids unauthenticated enumeration of signer holdings, so require
	// auth: unauthenticated callers get a minimal "alive" response that doesn't
	// leak counts or relay identities. Use /health for unauthenticated probes.
	if _, err := h.validateAuthHeader(r); err != nil {
		h.jsonResponse(w, http.StatusOK, map[string]interface{}{"ok": true})
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

	// Approving a nostrconnect:// URI grants an app signing authority over a
	// key, so the caller must be authenticated (Bearer token or auth_token
	// cookie) and — verified after the key is loaded — must own that key.
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
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

	// Ownership check: the authenticated user must own the key they are
	// authorizing an app to sign with. Without this, any caller who knows a
	// key_id (pubkey[:16]) could grant a client signing authority over it.
	if key.OwnerID != claims.UserID {
		h.errorResponse(w, http.StatusForbidden, "key does not belong to the authenticated user")
		return
	}

	// Load the signing key on-demand if it isn't already in the runtime map, so
	// SendNostrConnectResponse can sign + publish the ack (else the client times out).
	h.ensureNostrConnectKeyLoaded(r.Context(), claims.SessionID, claims.UserID, key)

	if err := h.approveNostrConnect(r.Context(), key, clientPubkey, relay, secret, appName, appURL, appImage); err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to set permission")
		return
	}

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

// approveNostrConnect stores permission and sends the NIP-46 connect response.
// It is the shared approval path used by both the manual nostrconnect handler
// and the SSO auto-approval handler (handleNostrConnectSession).
func (h *Handler) approveNostrConnect(ctx context.Context, key *storage.Key, clientPubkey, relay, secret, appName, appURL, appImage string) error {
	perm := &storage.Permission{
		KeyID:      key.Pubkey,
		UserPubkey: clientPubkey,
		Methods:    []string{"connect", "sign_event", "get_public_key", "nip44_encrypt", "nip44_decrypt"},
		AppName:    appName,
		AppURL:     appURL,
		AppImage:   appImage,
	}
	if err := h.storage.SetPermission(ctx, perm); err != nil {
		return err
	}
	h.signer.SendNostrConnectResponse(ctx, key.Pubkey, clientPubkey, relay, secret)
	return nil
}

// NostrConnectSessionRequest is the body for POST /api/v1/nostrconnect/session.
// The caller must hold a valid session (Bearer token or auth_token cookie).
type NostrConnectSessionRequest struct {
	URI     string `json:"uri"`               // nostrconnect:// URI from the connecting app
	KeyID   string `json:"key_id"`            // ID of the signing key to authorize
	Consent bool   `json:"consent,omitempty"` // If true, record consent and approve on first-time connections
}

// NostrConnectSessionResponse is returned when consent_required is false (auto-approved).
type NostrConnectSessionResponse struct {
	Success         bool   `json:"success,omitempty"`
	ConsentRequired bool   `json:"consent_required,omitempty"`
	AppID           string `json:"app_id,omitempty"` // client pubkey; present when consent_required
	AppName         string `json:"app_name,omitempty"`
	AppURL          string `json:"app_url,omitempty"`
	AppImage        string `json:"app_image,omitempty"`
	ClientPubkey    string `json:"client_pubkey,omitempty"`
}

// handleNostrConnectSession handles POST /api/v1/nostrconnect/session.
//
// Flow (unified-auth-design §5):
//  1. Authenticated user posts a nostrconnect:// URI + key_id.
//  2. Parse the URI, verify key ownership.
//  3. HasAppConsent(user, clientPubkey)?
//     - Yes → approve immediately (silent re-auth).
//     - No + consent==true → record consent, then approve.
//     - No + consent==false → return 200 {consent_required:true, app_id, app_name}
//     so the client can display a consent prompt and re-POST with consent=true.
func (h *Handler) handleNostrConnectSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	var req NostrConnectSessionRequest
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

	// Only nostrconnect:// URIs are accepted here; bunker:// is for outbound use.
	if strings.HasPrefix(req.URI, "bunker://") {
		h.errorResponse(w, http.StatusBadRequest, "bunker:// URIs are for apps to use; paste a nostrconnect:// URI")
		return
	}
	if !strings.HasPrefix(req.URI, "nostrconnect://") {
		h.errorResponse(w, http.StatusBadRequest, "invalid URI — must start with nostrconnect://")
		return
	}

	// Parse nostrconnect:// URI (same logic as handleNostrConnect).
	uriWithoutScheme := strings.TrimPrefix(req.URI, "nostrconnect://")
	parts := strings.SplitN(uriWithoutScheme, "?", 2)
	if len(parts) == 0 || parts[0] == "" {
		h.errorResponse(w, http.StatusBadRequest, "invalid URI — missing client pubkey")
		return
	}
	clientPubkey := parts[0]
	if len(clientPubkey) != 64 {
		h.errorResponse(w, http.StatusBadRequest, "invalid client pubkey")
		return
	}

	var relay, secret, appName, appURL, appImage string
	if len(parts) > 1 {
		for _, param := range strings.Split(parts[1], "&") {
			kv := strings.SplitN(param, "=", 2)
			if len(kv) != 2 {
				continue
			}
			val := kv[1]
			if decoded, err := urlDecode(val); err == nil {
				val = decoded
			}
			switch kv[0] {
			case "relay":
				relay = val
			case "secret":
				secret = val
			case "name":
				appName = val
			case "url":
				appURL = val
			case "image":
				appImage = val
			}
		}
	}
	if relay == "" {
		h.errorResponse(w, http.StatusBadRequest, "invalid URI — missing relay")
		return
	}

	// Verify key ownership — the caller must own the key they are authorizing.
	key, err := h.storage.GetKey(r.Context(), req.KeyID)
	if err != nil {
		if err == storage.ErrKeyNotFound {
			h.errorResponse(w, http.StatusNotFound, "key not found")
			return
		}
		h.errorResponse(w, http.StatusInternalServerError, "failed to get key")
		return
	}
	if key.OwnerID != claims.UserID {
		h.errorResponse(w, http.StatusForbidden, "key does not belong to the authenticated user")
		return
	}

	// Load the signing key on-demand (cookie-SSO / post-restart have no password
	// login to have loaded it), so the approval below can actually sign+publish.
	h.ensureNostrConnectKeyLoaded(r.Context(), claims.SessionID, claims.UserID, key)

	// Check consent: does this user already trust this app?
	hasConsent, err := h.storage.HasAppConsent(r.Context(), claims.UserID, clientPubkey)
	if err != nil {
		slog.Warn("failed to check app consent", "error", err)
		// Treat storage error as no-consent to avoid silent approval on failure.
		hasConsent = false
	}

	switch {
	case hasConsent:
		// Silent re-auth: prior consent exists, approve immediately.
		if err := h.approveNostrConnect(r.Context(), key, clientPubkey, relay, secret, appName, appURL, appImage); err != nil {
			h.errorResponse(w, http.StatusInternalServerError, "failed to set permission")
			return
		}
		slog.Info("nostrconnect auto-approved (prior consent)",
			"app", appName, "client", clientPubkey[:16]+"...", "key", req.KeyID)
		h.jsonResponse(w, http.StatusOK, NostrConnectSessionResponse{
			Success:      true,
			AppName:      appName,
			AppURL:       appURL,
			AppImage:     appImage,
			ClientPubkey: clientPubkey,
		})

	case req.Consent:
		// First-time approval: user explicitly consented in the request.
		if err := h.storage.RecordAppConsent(r.Context(), claims.UserID, clientPubkey, appName); err != nil {
			slog.Warn("failed to record app consent", "error", err)
			// Non-fatal: approve anyway so the user is not blocked.
		}
		if err := h.approveNostrConnect(r.Context(), key, clientPubkey, relay, secret, appName, appURL, appImage); err != nil {
			h.errorResponse(w, http.StatusInternalServerError, "failed to set permission")
			return
		}
		slog.Info("nostrconnect approved with first-time consent",
			"app", appName, "client", clientPubkey[:16]+"...", "key", req.KeyID)
		h.jsonResponse(w, http.StatusOK, NostrConnectSessionResponse{
			Success:      true,
			AppName:      appName,
			AppURL:       appURL,
			AppImage:     appImage,
			ClientPubkey: clientPubkey,
		})

	case key.RequireApproval:
		// Opt-IN friction (unified-auth-design §9): this key is configured to
		// require explicit approval for new app connections. Ask the client to
		// show a consent prompt, then re-POST with consent=true.
		slog.Info("nostrconnect consent required (key requires approval)",
			"app", appName, "client", clientPubkey[:16]+"...", "user", claims.UserID)
		h.jsonResponse(w, http.StatusOK, NostrConnectSessionResponse{
			ConsentRequired: true,
			AppID:           clientPubkey,
			AppName:         appName,
		})

	default:
		// GATE: refuse a session this process cannot actually serve.
		//
		// Every key here is USER-HELD (measured 2026-08-25: 6 vault, 2
		// passphrase, 1 vault proxy — zero server-decryptable), so a key lives
		// only in the memory of the replica that handled that user's login.
		// Without this check the handler approved the session, answered 200,
		// and then SendNostrConnectResponse found no key and returned
		// silently — leaving the browser waiting 30 seconds for an ack that
		// was never coming, and finally showing "Could not reach your signer"
		// about a signer that was healthy the whole time.
		//
		// A 409 with a machine-readable code lets the client do the honest
		// thing immediately: ask for the passphrase that unlocks the key,
		// rather than blaming the network after half a minute.
		if !h.signer.IsKeyLoaded(key.Pubkey) {
			slog.Warn("nostrconnect refused: key not unlocked on this replica",
				"client", clientPubkey[:16]+"...", "key", req.KeyID, "user", claims.UserID)
			h.errorResponseCode(w, http.StatusConflict, "key_locked",
				"Your signing key is locked on this server. Sign in with your password to unlock it.")
			return
		}

		// Opt-OUT default (unified-auth-design §9): a valid signer session is
		// the first-party gate, so auto-approve first-time connects silently
		// (zero friction for normies) and record consent so the app is listed
		// and revocable in Connected Apps. Users who want friction set
		// RequireApproval on their key (handled by the case above).
		if err := h.storage.RecordAppConsent(r.Context(), claims.UserID, clientPubkey, appName); err != nil {
			slog.Warn("failed to record app consent", "error", err)
			// Non-fatal: approve anyway so the user is not blocked.
		}
		if err := h.approveNostrConnect(r.Context(), key, clientPubkey, relay, secret, appName, appURL, appImage); err != nil {
			h.errorResponse(w, http.StatusInternalServerError, "failed to set permission")
			return
		}
		slog.Info("nostrconnect auto-approved (opt-out default)",
			"app", appName, "client", clientPubkey[:16]+"...", "key", req.KeyID)
		h.jsonResponse(w, http.StatusOK, NostrConnectSessionResponse{
			Success:      true,
			AppName:      appName,
			AppURL:       appURL,
			AppImage:     appImage,
			ClientPubkey: clientPubkey,
		})
	}
}

// handleNostrConnectRevoke handles POST /api/v1/nostrconnect/revoke.
//
// Revokes all SSO app consents for the authenticated user and removes all
// NIP-46 signing permissions for that user's keys. The caller stays logged
// in; this only ends active app connections.
//
// Optional body: {"app_id": "<client_pubkey>"}  — if present, revokes a
// single app; if absent (or empty string), revokes all apps.
func (h *Handler) handleNostrConnectRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	var body struct {
		AppID string `json:"app_id,omitempty"`
	}
	// Body is optional; ignore decode errors (empty body = revoke all).
	json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck

	userKeys, err := h.storage.ListKeys(r.Context(), claims.UserID)
	if err != nil {
		slog.Warn("revoke: failed to list user keys", "error", err, "user_id", claims.UserID)
		userKeys = nil
	}

	if body.AppID != "" {
		// Revoke a specific app.
		if rErr := h.storage.RevokeAppConsent(r.Context(), claims.UserID, body.AppID); rErr != nil && rErr != storage.ErrConsentNotFound {
			slog.Warn("revoke: failed to revoke app consent", "error", rErr, "app_id", body.AppID)
		}
		for _, k := range userKeys {
			if dErr := h.storage.DeletePermission(r.Context(), k.Pubkey, body.AppID); dErr != nil {
				slog.Debug("revoke: delete permission", "error", dErr, "key", k.Pubkey[:16]+"...", "app", body.AppID[:16]+"...")
			}
		}
		slog.Info("nostrconnect revoked for app", "app_id", body.AppID[:16]+"...", "user_id", claims.UserID)
		h.jsonResponse(w, http.StatusOK, map[string]string{"message": "app connection revoked"})
		return
	}

	// Revoke all apps.
	if rErr := h.storage.RevokeAllAppConsents(r.Context(), claims.UserID); rErr != nil {
		slog.Warn("revoke: failed to revoke all app consents", "error", rErr)
	}
	for _, k := range userKeys {
		perms, err := h.storage.ListPermissions(r.Context(), k.Pubkey)
		if err != nil {
			continue
		}
		for _, p := range perms {
			if dErr := h.storage.DeletePermission(r.Context(), k.Pubkey, p.UserPubkey); dErr != nil {
				slog.Debug("revoke: delete permission", "error", dErr)
			}
		}
	}
	slog.Info("all nostrconnect apps revoked", "user_id", claims.UserID)
	h.jsonResponse(w, http.StatusOK, map[string]string{"message": "all app connections revoked"})
}

// newAuthCookie builds a Secure HttpOnly Lax auth_token cookie.
// When cfg.Auth.CookieDomain is non-empty (e.g. ".cloistr.xyz" in prod), the
// Domain attribute is set so the cookie is shared across all *.cloistr.xyz
// subdomains (cross-subdomain SSO). When empty (dev/localhost), the Domain
// attribute is omitted and the browser scopes the cookie to the issuing host.
func (h *Handler) newAuthCookie(token string, expiresAt time.Time) *http.Cookie {
	c := &http.Cookie{
		Name:     "auth_token",
		Value:    token,
		Path:     "/",
		Expires:  expiresAt,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	if h.config.Auth.CookieDomain != "" {
		c.Domain = h.config.Auth.CookieDomain
	}
	return c
}

// clearAuthCookie returns a cookie that immediately expires auth_token.
// The Domain attribute must match the one used when the cookie was set so that
// the browser actually removes the parent-domain cookie and not just a
// host-scoped shadow.
func (h *Handler) clearAuthCookie() *http.Cookie {
	c := &http.Cookie{
		Name:     "auth_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
	if h.config.Auth.CookieDomain != "" {
		c.Domain = h.config.Auth.CookieDomain
	}
	return c
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

	// Privacy hardening (privacy-architecture §3.10):
	// - Reject empty name queries. NIP-05 clients always query a specific
	//   name; the bulk-list form leaks the full set of users on this signer
	//   to anyone who can fetch /.well-known/nostr.json.
	// - Skip disposable-mode keys. Disposable keys are explicitly off the
	//   public discovery channel; surfacing them via NIP-05 would defeat
	//   their purpose.
	// - Skip keys with no user-set name. Falling back to the random key ID
	//   used to enumerate every key here, even unnamed ones. A key is only
	//   discoverable via NIP-05 if the owner named it.
	if name == "" {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		json.NewEncoder(w).Encode(response)
		return
	}

	keys, err := h.storage.ListAllKeys(r.Context())
	if err != nil {
		h.jsonResponse(w, http.StatusOK, response)
		return
	}

	for _, key := range keys {
		if key.DisposableMode {
			continue
		}
		if key.Name == "" {
			continue
		}
		// Sanitize name for NIP-05 (lowercase, no spaces)
		keyName := strings.ToLower(strings.ReplaceAll(key.Name, " ", "-"))
		if name != keyName {
			continue
		}

		response.Names[keyName] = key.Pubkey
		// Use key-specific relays if configured, otherwise fall back to global config
		relays := key.Relays
		if len(relays) == 0 {
			relays = h.config.Relays
		}
		response.Relays[key.Pubkey] = relays
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
	Threshold   int    `json:"threshold"`    // t in t-of-n
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
	Shares      []FrostShareResponse `json:"shares"`
	CanSign     bool                 `json:"can_sign"`
	LocalShares int                  `json:"local_shares"`
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
	Participants []string `json:"participants"`       // Nostr pubkeys of participants (including self)
	Threshold    int      `json:"threshold"`          // Minimum shares required to sign
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

// errorResponseCode is errorResponse plus a stable machine-readable code, so a
// client can act on WHICH failure it was instead of pattern-matching prose.
//
// Added for "key_locked": a locked user-held key and an unreachable relay look
// identical to a browser otherwise, and conflating them is what showed a
// network error over a healthy signer.
func (h *Handler) errorResponseCode(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message, "code": code})
}

func (h *Handler) errorResponse(w http.ResponseWriter, status int, message string) {
	h.jsonResponse(w, status, map[string]string{"error": message})
}
