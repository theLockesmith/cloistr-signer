package signer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip44"
	"git.coldforge.xyz/coldforge/cloistr-signer/internal/config"
	"git.coldforge.xyz/coldforge/cloistr-signer/internal/crypto"
	"git.coldforge.xyz/coldforge/cloistr-signer/internal/metrics"
	relay "git.coldforge.xyz/coldforge/cloistr-signer/internal/nostr"
	"git.coldforge.xyz/coldforge/cloistr-signer/internal/proxy"
	"git.coldforge.xyz/coldforge/cloistr-signer/internal/storage"
)

const (
	KindNIP46Request  = 24133
	KindNIP46Response = 24133 // Same kind, differentiated by tags
)

// normalizePubkey converts a compressed pubkey (33 bytes with 02/03 prefix) to x-only format (32 bytes)
// NIP-44 requires x-only pubkeys, but some clients send compressed SEC1 format
func normalizePubkey(pubkey string) string {
	// If it's 66 chars (33 bytes hex) and starts with 02 or 03, strip the prefix
	if len(pubkey) == 66 && (pubkey[:2] == "02" || pubkey[:2] == "03") {
		return pubkey[2:]
	}
	return pubkey
}

// NIP46Request represents a NIP-46 JSON-RPC request
type NIP46Request struct {
	ID     string   `json:"id"`
	Method string   `json:"method"`
	Params []string `json:"params"`
}

// NIP46Response represents a NIP-46 JSON-RPC response
type NIP46Response struct {
	ID     string `json:"id"`
	Result string `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

// pendingRequestContext stores the context needed to process a request after authorization
type pendingRequestContext struct {
	targetPubkey string
	privateKey   string
	clientPubkey string
	request      *NIP46Request
	perm         *storage.Permission
	resultChan   chan authResult
}

// authResult contains the result of an authorization decision
type authResult struct {
	approved bool
	perm     *storage.Permission // Permission to use (may be from token redemption)
}

// Signer handles NIP-46 remote signing requests
type Signer struct {
	config         *config.Config
	storage        storage.Storage
	relayClient    *relay.Client
	encryptor      *crypto.Encryptor
	proxyClient    *proxy.Client                      // Client for upstream signer connections
	keys           map[string]string                  // pubkey -> private key (hex)
	proxyKeys      map[string]string                  // pubkey -> bunker URI (for proxy keys)
	pendingCtx     map[string]*pendingRequestContext  // requestID -> context
	pendingCtxLock sync.RWMutex
	cancel         context.CancelFunc
}

// New creates a new NIP-46 signer
func New(cfg *config.Config, store storage.Storage, relayClient *relay.Client, encryptor *crypto.Encryptor) *Signer {
	return &Signer{
		config:      cfg,
		storage:     store,
		relayClient: relayClient,
		encryptor:   encryptor,
		proxyClient: proxy.NewClient(cfg),
		keys:        make(map[string]string),
		proxyKeys:   make(map[string]string),
		pendingCtx:  make(map[string]*pendingRequestContext),
	}
}

// Start begins listening for NIP-46 requests
func (s *Signer) Start(ctx context.Context) error {
	ctx, s.cancel = context.WithCancel(ctx)

	// Connect to relays
	if err := s.relayClient.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect to relays: %w", err)
	}

	// Load keys from storage
	keys, err := s.storage.ListKeys(ctx)
	if err != nil {
		return fmt.Errorf("failed to load keys: %w", err)
	}

	// Load any existing keys into runtime map
	for _, key := range keys {
		// Decrypt the local private key if needed (both local and proxy keys have this)
		privateKey := key.EncryptedNsec
		if privateKey != "" {
			if crypto.IsEncrypted(privateKey) && s.encryptor != nil {
				decrypted, err := s.encryptor.Decrypt(privateKey)
				if err != nil {
					slog.Error("failed to decrypt key", "pubkey", key.Pubkey[:16]+"...", "error", err)
					continue
				}
				privateKey = decrypted
			}
			s.keys[key.Pubkey] = privateKey
		}

		// Track proxy keys separately for forwarding
		if key.IsProxy() {
			s.proxyKeys[key.Pubkey] = key.BunkerURI
			upstreamShort := "unknown"
			if key.UpstreamPubkey != "" && len(key.UpstreamPubkey) >= 16 {
				upstreamShort = key.UpstreamPubkey[:16] + "..."
			}
			slog.Info("loaded proxy key", "pubkey", key.Pubkey[:16]+"...", "upstream", upstreamShort)
		}
	}

	if len(keys) == 0 {
		slog.Warn("no keys configured yet, will respond once keys are added via API")
	} else {
		slog.Info("loaded keys from storage", "count", len(keys))
	}
	metrics.SetKeysManaged(len(keys))

	// Subscribe to ALL kind:24133 events - we filter by our keys in handleEvent
	// This allows dynamic key addition via the HTTP API
	filters := nostr.Filters{{
		Kinds: []int{KindNIP46Request},
	}}

	slog.Info("subscribing to NIP-46 requests")

	go s.relayClient.SubscribeWithReconnect(ctx, filters, s.handleEvent)

	return nil
}

// Stop stops the signer
func (s *Signer) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
	s.relayClient.Disconnect()
}

// RegisterKey registers a key for signing (runtime, not persisted)
func (s *Signer) RegisterKey(pubkey, privateKeyHex string) {
	s.keys[pubkey] = privateKeyHex
}

// RegisterProxyKey registers a proxy key that forwards to an upstream signer (runtime, not persisted)
func (s *Signer) RegisterProxyKey(pubkey, privateKeyHex, bunkerURI string) {
	s.keys[pubkey] = privateKeyHex
	s.proxyKeys[pubkey] = bunkerURI
}

func (s *Signer) handleEvent(event *nostr.Event) {
	if event.Kind != KindNIP46Request {
		return
	}

	// Find which of our keys this is addressed to
	targetPubkey := ""
	for _, tag := range event.Tags {
		if len(tag) >= 2 && tag[0] == "p" {
			if _, exists := s.keys[tag[1]]; exists {
				targetPubkey = tag[1]
				break
			}
		}
	}

	if targetPubkey == "" {
		slog.Debug("event not addressed to any of our keys", "event_id", event.ID)
		return
	}

	privateKey := s.keys[targetPubkey]
	clientPubkey := event.PubKey

	slog.Info("received NIP-46 request",
		"from", clientPubkey[:16]+"...",
		"to", targetPubkey[:16]+"...",
		"event_id", event.ID,
		"client_pubkey_len", len(clientPubkey),
	)

	// Try NIP-44 decryption first (newer standard), fall back to NIP-04
	var decrypted string
	var useNIP44 bool
	var nip44Err, nip04Err error

	// Try NIP-44 first (normalize pubkey in case it has 02/03 prefix)
	normalizedClientPubkey := normalizePubkey(clientPubkey)
	slog.Debug("NIP-44 key normalization",
		"original", clientPubkey,
		"normalized", normalizedClientPubkey,
		"original_len", len(clientPubkey),
		"normalized_len", len(normalizedClientPubkey),
	)
	conversationKey, err := nip44.GenerateConversationKey(normalizedClientPubkey, privateKey)
	if err != nil {
		nip44Err = fmt.Errorf("conversation key: %w", err)
	} else {
		decrypted, nip44Err = nip44.Decrypt(event.Content, conversationKey)
		if nip44Err == nil {
			useNIP44 = true
			slog.Info("decrypted with NIP-44")
		}
	}

	// Fall back to NIP-04 if NIP-44 failed
	if !useNIP44 {
		slog.Debug("NIP-44 decryption failed, trying NIP-04", "nip44_error", nip44Err)
		sharedSecret, err := nip04.ComputeSharedSecret(clientPubkey, privateKey)
		if err != nil {
			slog.Error("failed to compute shared secret", "error", err)
			return
		}
		decrypted, nip04Err = nip04.Decrypt(event.Content, sharedSecret)
		if nip04Err != nil {
			slog.Error("failed to decrypt request",
				"nip44_error", nip44Err,
				"nip04_error", nip04Err,
			)
			return
		}
		slog.Info("decrypted with NIP-04")
	}

	var request NIP46Request
	if err := json.Unmarshal([]byte(decrypted), &request); err != nil {
		slog.Error("failed to parse request", "error", err)
		return
	}

	slog.Info("processing request", "method", request.Method, "request_id", request.ID)

	// Check permissions
	ctx := context.Background()
	perm, err := s.storage.GetPermission(ctx, targetPubkey, clientPubkey)

	// Handle request in a goroutine to avoid blocking the event loop
	// This is especially important for authorization callbacks which may take time
	go s.processRequest(ctx, targetPubkey, privateKey, clientPubkey, &request, perm, err, useNIP44)
}

// processRequest handles a NIP-46 request, potentially waiting for authorization
func (s *Signer) processRequest(ctx context.Context, targetPubkey, privateKey, clientPubkey string, request *NIP46Request, perm *storage.Permission, permErr error, useNIP44 bool) {
	// If we have a valid permission
	if permErr == nil {
		// Check if method is allowed
		if !s.isMethodAllowed(perm, request.Method) {
			slog.Warn("method not allowed", "method", request.Method, "client", clientPubkey[:16]+"...")
			s.sendError(ctx, targetPubkey, privateKey, clientPubkey, request.ID, "method not allowed", useNIP44)
			return
		}

		// Check if this permission requires approval (hybrid mode)
		if s.shouldRequireApproval(ctx, targetPubkey, perm) {
			slog.Info("permission requires approval", "client", clientPubkey[:16]+"...", "method", request.Method)
			s.handlePendingApproval(ctx, targetPubkey, privateKey, clientPubkey, request, perm, useNIP44)
			return
		}

		// Handle the request
		result, err := s.handleRequest(ctx, targetPubkey, privateKey, clientPubkey, request, perm)
		if err != nil {
			slog.Error("request handling failed", "method", request.Method, "error", err)
			s.sendError(ctx, targetPubkey, privateKey, clientPubkey, request.ID, err.Error(), useNIP44)
			return
		}

		s.sendResult(ctx, targetPubkey, privateKey, clientPubkey, request.ID, result, useNIP44)
		return
	}

	// No permission - check for bunker secret on connect requests
	// NIP-46 connect params: [pubkey, secret?]
	if request.Method == "connect" && len(request.Params) >= 2 {
		secret := request.Params[1]
		if secret != "" {
			// Validate the bunker secret
			_, err := s.storage.ValidateBunkerSecret(ctx, targetPubkey, secret)
			if err == nil {
				// Valid secret - auto-approve and create persistent permission
				slog.Info("auto-approving connect with valid bunker secret", "client", clientPubkey[:16]+"...")
				fullPerm := &storage.Permission{
					KeyID:      targetPubkey,
					UserPubkey: clientPubkey,
					Methods:    []string{"*"}, // Allow all methods
				}
				// Save the permission for future requests
				if err := s.storage.SetPermission(ctx, fullPerm); err != nil {
					slog.Error("failed to save permission from bunker secret", "error", err)
				}
				result, err := s.handleRequest(ctx, targetPubkey, privateKey, clientPubkey, request, fullPerm)
				if err != nil {
					slog.Error("request handling failed", "method", request.Method, "error", err)
					s.sendError(ctx, targetPubkey, privateKey, clientPubkey, request.ID, err.Error(), useNIP44)
					return
				}
				s.sendResult(ctx, targetPubkey, privateKey, clientPubkey, request.ID, result, useNIP44)
				return
			}
			// Invalid secret - log but continue to normal flow
			slog.Warn("invalid bunker secret provided", "client", clientPubkey[:16]+"...")
		}
	}

	// No permission - check if we should auto-approve or wait for authorization
	// Use hybrid approval check: permission (nil here) -> key -> global config
	if !s.shouldRequireApproval(ctx, targetPubkey, nil) {
		// Auto-approve: create a temporary permission with full access
		slog.Info("auto-approving request (approval not required)", "client", clientPubkey[:16]+"...", "method", request.Method)
		tempPerm := &storage.Permission{
			KeyID:      targetPubkey,
			UserPubkey: clientPubkey,
			Methods:    []string{"*"}, // Allow all methods
		}
		result, err := s.handleRequest(ctx, targetPubkey, privateKey, clientPubkey, request, tempPerm)
		if err != nil {
			slog.Error("request handling failed", "method", request.Method, "error", err)
			s.sendError(ctx, targetPubkey, privateKey, clientPubkey, request.ID, err.Error(), useNIP44)
			return
		}
		s.sendResult(ctx, targetPubkey, privateKey, clientPubkey, request.ID, result, useNIP44)
		return
	}

	// Approval required - handle pending approval flow
	s.handlePendingApproval(ctx, targetPubkey, privateKey, clientPubkey, request, nil, useNIP44)
}

// handlePendingApproval handles the approval workflow for requests that need manual authorization
func (s *Signer) handlePendingApproval(ctx context.Context, targetPubkey, privateKey, clientPubkey string, request *NIP46Request, perm *storage.Permission, useNIP44 bool) {
	// Create pending request context
	reqCtx := &pendingRequestContext{
		targetPubkey: targetPubkey,
		privateKey:   privateKey,
		clientPubkey: clientPubkey,
		request:      request,
		perm:         perm,
	}

	// Notify admins if enabled
	if s.config.Auth.NotifyAdmins && len(s.config.Auth.AdminPubkeys) > 0 {
		s.notifyAdminsOfPendingRequest(ctx, targetPubkey, privateKey, clientPubkey, request)
	}

	// Wait for authorization
	timeout := time.Duration(s.config.Auth.AuthorizationTimeout) * time.Second
	approved, approvedPerm, err := s.waitForAuthorization(ctx, reqCtx, timeout)
	if err != nil {
		slog.Warn("authorization failed", "client", clientPubkey[:16]+"...", "error", err)
		s.sendError(ctx, targetPubkey, privateKey, clientPubkey, request.ID, "authorization timeout", useNIP44)
		return
	}

	if !approved {
		slog.Info("request denied by admin", "client", clientPubkey[:16]+"...", "method", request.Method)
		s.sendError(ctx, targetPubkey, privateKey, clientPubkey, request.ID, "request denied", useNIP44)
		return
	}

	// Request was approved - use the approved permission, existing permission, or create a temporary one
	permToUse := approvedPerm
	if permToUse == nil {
		permToUse = perm
	}
	if permToUse == nil {
		// Create a temporary permission for this request only
		permToUse = &storage.Permission{
			KeyID:      targetPubkey,
			UserPubkey: clientPubkey,
			Methods:    []string{request.Method},
		}
	}

	// Handle the request
	result, err := s.handleRequest(ctx, targetPubkey, privateKey, clientPubkey, request, permToUse)
	if err != nil {
		slog.Error("request handling failed after approval", "method", request.Method, "error", err)
		s.sendError(ctx, targetPubkey, privateKey, clientPubkey, request.ID, err.Error(), useNIP44)
		return
	}

	slog.Info("request approved and processed", "method", request.Method, "client", clientPubkey[:16]+"...")
	s.sendResult(ctx, targetPubkey, privateKey, clientPubkey, request.ID, result, useNIP44)
}

func (s *Signer) isMethodAllowed(perm *storage.Permission, method string) bool {
	for _, m := range perm.Methods {
		if m == method || m == "*" || m == "all" {
			return true
		}
	}
	return false
}

// shouldRequireApproval determines if manual approval is needed for a request.
// Priority: permission setting -> key setting -> global config
func (s *Signer) shouldRequireApproval(ctx context.Context, targetPubkey string, perm *storage.Permission) bool {
	// 1. Check permission-level override (if permission exists and has explicit setting)
	if perm != nil && perm.RequireApproval != nil {
		return *perm.RequireApproval
	}

	// 2. Check key-level setting
	key, err := s.storage.GetKeyByPubkey(ctx, targetPubkey)
	if err == nil && key.RequireApproval {
		return true
	}

	// 3. Fall back to global config
	return s.config.Auth.RequireApproval
}

// checkPolicyUsage checks if a method can be used based on policy usage limits
// Returns (allowed, ruleID, error) - ruleID is used to increment usage after successful request
func (s *Signer) checkPolicyUsage(ctx context.Context, policyID, method string) (bool, string, error) {
	policy, err := s.storage.GetPolicy(ctx, policyID)
	if err != nil {
		// Policy not found or expired - allow (graceful degradation)
		slog.Warn("policy not found for usage check, allowing request", "policy_id", policyID)
		return true, "", nil
	}

	// Find matching rule
	for _, rule := range policy.Rules {
		if rule.Method == method || rule.Method == "*" {
			// Check usage limit
			if rule.MaxUsage > 0 && rule.CurrentUsage >= rule.MaxUsage {
				slog.Warn("policy usage limit exceeded",
					"policy_id", policyID,
					"method", method,
					"current", rule.CurrentUsage,
					"max", rule.MaxUsage,
				)
				return false, "", nil
			}
			return true, rule.ID, nil
		}
	}

	// No matching rule - this shouldn't happen if permission was created correctly
	// Allow to avoid breaking existing functionality
	return true, "", nil
}

func (s *Signer) handleRequest(ctx context.Context, targetPubkey, privateKey, clientPubkey string, req *NIP46Request, perm *storage.Permission) (result string, err error) {
	// Record metrics on completion
	defer func() {
		metrics.RecordSigningRequest(req.Method, err == nil)
	}()

	// Check policy usage limits if permission is policy-based
	if perm.PolicyID != "" {
		allowed, ruleID, err := s.checkPolicyUsage(ctx, perm.PolicyID, req.Method)
		if err != nil {
			return "", fmt.Errorf("failed to check policy usage: %w", err)
		}
		if !allowed {
			return "", fmt.Errorf("usage limit exceeded for method %s", req.Method)
		}
		// Increment usage after we confirm the method is valid
		if ruleID != "" {
			defer func() {
				if err := s.storage.IncrementRuleUsage(ctx, ruleID); err != nil {
					slog.Warn("failed to increment rule usage", "rule_id", ruleID, "error", err)
				}
			}()
		}
	}

	// Check if this is a proxy key - forward certain methods to upstream
	bunkerURI, isProxy := s.proxyKeys[targetPubkey]
	if isProxy && s.shouldProxyMethod(req.Method) {
		return s.handleProxyRequest(ctx, targetPubkey, privateKey, bunkerURI, req)
	}

	switch req.Method {
	case "connect":
		return s.handleConnect(ctx, targetPubkey, clientPubkey, req.Params, perm)
	case "ping":
		return "pong", nil
	case "get_public_key":
		// For proxy keys, return the upstream pubkey
		if isProxy {
			return s.getUpstreamPubkey(ctx, targetPubkey, privateKey, bunkerURI)
		}
		return targetPubkey, nil
	case "get_relays":
		return s.handleGetRelays()
	case "sign_event":
		return s.handleSignEvent(ctx, targetPubkey, privateKey, req.Params, perm)
	case "nip04_encrypt":
		return s.handleNIP04Encrypt(privateKey, req.Params)
	case "nip04_decrypt":
		return s.handleNIP04Decrypt(privateKey, req.Params)
	case "nip44_encrypt":
		return s.handleNIP44Encrypt(privateKey, req.Params)
	case "nip44_decrypt":
		return s.handleNIP44Decrypt(privateKey, req.Params)
	default:
		return "", fmt.Errorf("unknown method: %s", req.Method)
	}
}

func (s *Signer) handleConnect(ctx context.Context, targetPubkey, clientPubkey string, params []string, perm *storage.Permission) (string, error) {
	// Create or refresh session
	session := &storage.Session{
		ID:           fmt.Sprintf("%s:%s", targetPubkey[:8], clientPubkey[:8]),
		KeyID:        targetPubkey,
		ClientPubkey: clientPubkey,
		Permissions:  perm.Methods,
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
	}

	if err := s.storage.CreateSession(ctx, session); err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}

	return "ack", nil
}

func (s *Signer) handleGetRelays() (string, error) {
	relays := s.relayClient.GetConnectedRelays()
	data, err := json.Marshal(relays)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// shouldProxyMethod returns true if the method should be forwarded to the upstream signer
func (s *Signer) shouldProxyMethod(method string) bool {
	switch method {
	case "sign_event", "nip04_encrypt", "nip04_decrypt", "nip44_encrypt", "nip44_decrypt":
		return true
	default:
		return false
	}
}

// handleProxyRequest forwards a request to the upstream signer
func (s *Signer) handleProxyRequest(ctx context.Context, targetPubkey, privateKey, bunkerURI string, req *NIP46Request) (string, error) {
	// Check proxy mode - internal mode would handle this differently
	// For now, we always use external (relay-based) proxying
	if s.config.Proxy.Mode == "internal" {
		// For internal mode, check if the upstream pubkey matches one of our local keys
		// If so, we can handle it locally without a relay round-trip
		// This is a future optimization
		slog.Debug("internal proxy mode - checking for local key")
	}

	// Get or create connection to upstream using the proxy key's persistent keypair
	// This ensures permissions persist across restarts
	conn, err := s.proxyClient.GetConnection(ctx, bunkerURI, privateKey, targetPubkey)
	if err != nil {
		return "", fmt.Errorf("failed to connect to upstream: %w", err)
	}

	// Forward the request
	slog.Info("forwarding request to upstream",
		"method", req.Method,
		"upstream", conn.URI.SignerPubkey[:16]+"...",
	)

	response, err := conn.SendRequest(ctx, req.Method, req.Params)
	if err != nil {
		return "", fmt.Errorf("upstream request failed: %w", err)
	}

	return response.Result, nil
}

// getUpstreamPubkey retrieves the public key from the upstream signer
func (s *Signer) getUpstreamPubkey(ctx context.Context, targetPubkey, privateKey, bunkerURI string) (string, error) {
	conn, err := s.proxyClient.GetConnection(ctx, bunkerURI, privateKey, targetPubkey)
	if err != nil {
		return "", fmt.Errorf("failed to connect to upstream: %w", err)
	}

	return conn.GetPublicKey(ctx)
}

func (s *Signer) handleSignEvent(ctx context.Context, targetPubkey, privateKey string, params []string, perm *storage.Permission) (string, error) {
	if len(params) < 1 {
		return "", errors.New("missing event parameter")
	}

	var event nostr.Event
	if err := json.Unmarshal([]byte(params[0]), &event); err != nil {
		return "", fmt.Errorf("invalid event: %w", err)
	}

	// Check if kind is allowed
	if len(perm.AllowedKinds) > 0 {
		allowed := false
		for _, k := range perm.AllowedKinds {
			if k == event.Kind {
				allowed = true
				break
			}
		}
		if !allowed {
			return "", fmt.Errorf("kind %d not allowed", event.Kind)
		}
	}

	// Set pubkey and sign
	event.PubKey = targetPubkey
	if err := event.Sign(privateKey); err != nil {
		return "", fmt.Errorf("signing failed: %w", err)
	}

	// Return signed event as JSON
	data, err := json.Marshal(event)
	if err != nil {
		return "", err
	}

	slog.Info("signed event", "kind", event.Kind, "id", event.ID[:16]+"...")
	return string(data), nil
}

func (s *Signer) handleNIP04Encrypt(privateKey string, params []string) (string, error) {
	if len(params) < 2 {
		return "", errors.New("missing parameters (need pubkey and plaintext)")
	}

	thirdPartyPubkey := params[0]
	plaintext := params[1]

	sharedSecret, err := nip04.ComputeSharedSecret(thirdPartyPubkey, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to compute shared secret: %w", err)
	}

	ciphertext, err := nip04.Encrypt(plaintext, sharedSecret)
	if err != nil {
		return "", fmt.Errorf("encryption failed: %w", err)
	}

	return ciphertext, nil
}

func (s *Signer) handleNIP04Decrypt(privateKey string, params []string) (string, error) {
	if len(params) < 2 {
		return "", errors.New("missing parameters (need pubkey and ciphertext)")
	}

	thirdPartyPubkey := params[0]
	ciphertext := params[1]

	sharedSecret, err := nip04.ComputeSharedSecret(thirdPartyPubkey, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to compute shared secret: %w", err)
	}

	plaintext, err := nip04.Decrypt(ciphertext, sharedSecret)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

func (s *Signer) handleNIP44Encrypt(privateKey string, params []string) (string, error) {
	if len(params) < 2 {
		return "", errors.New("missing parameters (need pubkey and plaintext)")
	}

	thirdPartyPubkey := normalizePubkey(params[0])
	plaintext := params[1]

	conversationKey, err := nip44.GenerateConversationKey(thirdPartyPubkey, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to generate conversation key: %w", err)
	}

	ciphertext, err := nip44.Encrypt(plaintext, conversationKey)
	if err != nil {
		return "", fmt.Errorf("encryption failed: %w", err)
	}

	return ciphertext, nil
}

func (s *Signer) handleNIP44Decrypt(privateKey string, params []string) (string, error) {
	if len(params) < 2 {
		return "", errors.New("missing parameters (need pubkey and ciphertext)")
	}

	thirdPartyPubkey := normalizePubkey(params[0])
	ciphertext := params[1]

	conversationKey, err := nip44.GenerateConversationKey(thirdPartyPubkey, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to generate conversation key: %w", err)
	}

	plaintext, err := nip44.Decrypt(ciphertext, conversationKey)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

func (s *Signer) sendResult(ctx context.Context, signerPubkey, privateKey, clientPubkey, requestID, result string, useNIP44 bool) {
	response := NIP46Response{
		ID:     requestID,
		Result: result,
	}
	s.sendResponse(ctx, signerPubkey, privateKey, clientPubkey, response, useNIP44)
}

func (s *Signer) sendError(ctx context.Context, signerPubkey, privateKey, clientPubkey, requestID, errMsg string, useNIP44 bool) {
	response := NIP46Response{
		ID:    requestID,
		Error: errMsg,
	}
	s.sendResponse(ctx, signerPubkey, privateKey, clientPubkey, response, useNIP44)
}

func (s *Signer) sendResponse(ctx context.Context, signerPubkey, privateKey, clientPubkey string, response NIP46Response, useNIP44 bool) {
	data, err := json.Marshal(response)
	if err != nil {
		slog.Error("failed to marshal response", "error", err)
		return
	}

	var encrypted string
	if useNIP44 {
		// Use NIP-44 encryption (normalize pubkey in case it has 02/03 prefix)
		conversationKey, err := nip44.GenerateConversationKey(normalizePubkey(clientPubkey), privateKey)
		if err != nil {
			slog.Error("failed to generate conversation key", "error", err)
			return
		}
		encrypted, err = nip44.Encrypt(string(data), conversationKey)
		if err != nil {
			slog.Error("failed to encrypt response with NIP-44", "error", err)
			return
		}
	} else {
		// Use NIP-04 encryption
		sharedSecret, err := nip04.ComputeSharedSecret(clientPubkey, privateKey)
		if err != nil {
			slog.Error("failed to compute shared secret", "error", err)
			return
		}
		encrypted, err = nip04.Encrypt(string(data), sharedSecret)
		if err != nil {
			slog.Error("failed to encrypt response with NIP-04", "error", err)
			return
		}
	}

	// Create response event
	event := nostr.Event{
		Kind:      KindNIP46Response,
		Content:   encrypted,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags:      nostr.Tags{{"p", clientPubkey}},
		PubKey:    signerPubkey,
	}

	if err := event.Sign(privateKey); err != nil {
		slog.Error("failed to sign response", "error", err)
		return
	}

	// Publish response
	if err := s.relayClient.Publish(ctx, &event); err != nil {
		slog.Error("failed to publish response", "error", err)
		return
	}

	slog.Info("sent response",
		"request_id", response.ID,
		"to", clientPubkey[:16]+"...",
		"has_error", response.Error != "",
		"nip44", useNIP44,
	)
}

// SendNostrConnectResponse sends a connect response to a client for nostrconnect:// flow
func (s *Signer) SendNostrConnectResponse(ctx context.Context, signerPubkey, clientPubkey, relayURL, secret string) {
	privateKey, ok := s.keys[signerPubkey]
	if !ok {
		slog.Error("key not found for nostrconnect", "pubkey", signerPubkey[:16]+"...")
		return
	}

	// Build connect response
	// Per NIP-46/nostr-tools: result MUST be the secret for validation
	// The client checks: response.result === uri.searchParams.get('secret')
	response := NIP46Response{
		ID:     secret,
		Result: secret,
	}

	data, err := json.Marshal(response)
	if err != nil {
		slog.Error("failed to marshal nostrconnect response", "error", err)
		return
	}

	// Use NIP-44 encryption (modern standard per NIP-46 spec)
	// Primal and other modern clients expect NIP-44
	conversationKey, err := nip44.GenerateConversationKey(clientPubkey, privateKey)
	if err != nil {
		slog.Error("failed to generate conversation key for nostrconnect", "error", err)
		return
	}

	encrypted, err := nip44.Encrypt(string(data), conversationKey)
	if err != nil {
		slog.Error("failed to encrypt nostrconnect response", "error", err)
		return
	}

	// Create response event
	event := nostr.Event{
		Kind:      KindNIP46Response,
		Content:   encrypted,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags:      nostr.Tags{{"p", clientPubkey}},
		PubKey:    signerPubkey,
	}

	if err := event.Sign(privateKey); err != nil {
		slog.Error("failed to sign nostrconnect response", "error", err)
		return
	}

	// Publish to the specified relay
	if err := s.relayClient.PublishToRelay(ctx, relayURL, &event); err != nil {
		slog.Error("failed to publish nostrconnect response", "relay", relayURL, "error", err)
		return
	}

	slog.Info("sent nostrconnect response",
		"to", clientPubkey[:16]+"...",
		"relay", relayURL,
		"event_id", event.ID,
		"response_json", string(data),
		"signer_pubkey", signerPubkey,
	)
}

// GetStatus returns the current signer status
func (s *Signer) GetStatus() map[string]interface{} {
	return map[string]interface{}{
		"keys_loaded":      len(s.keys),
		"connected_relays": s.relayClient.GetConnectedRelays(),
	}
}

// notifyAdminsOfPendingRequest sends a DM to all admins about a pending authorization request
func (s *Signer) notifyAdminsOfPendingRequest(ctx context.Context, targetPubkey, privateKey, clientPubkey string, request *NIP46Request) {
	// Build notification message
	var eventKindInfo string
	if request.Method == "sign_event" && len(request.Params) > 0 {
		var event nostr.Event
		if err := json.Unmarshal([]byte(request.Params[0]), &event); err == nil {
			eventKindInfo = fmt.Sprintf(" (kind: %d)", event.Kind)
		}
	}

	message := fmt.Sprintf(`🔐 Authorization Request

Client: %s
Key: %s
Method: %s%s
Time: %s

To approve this request, use the API:
POST /api/v1/requests/{id}/approve

To deny:
POST /api/v1/requests/{id}/deny`,
		clientPubkey,
		targetPubkey,
		request.Method,
		eventKindInfo,
		time.Now().UTC().Format(time.RFC3339),
	)

	// Send DM to each admin
	for _, adminPubkey := range s.config.Auth.AdminPubkeys {
		if adminPubkey == "" {
			continue
		}

		// Compute shared secret for NIP-04 encryption
		sharedSecret, err := nip04.ComputeSharedSecret(adminPubkey, privateKey)
		if err != nil {
			slog.Error("failed to compute shared secret for admin notification",
				"admin", adminPubkey[:16]+"...",
				"error", err,
			)
			continue
		}

		// Encrypt the message
		encrypted, err := nip04.Encrypt(message, sharedSecret)
		if err != nil {
			slog.Error("failed to encrypt admin notification",
				"admin", adminPubkey[:16]+"...",
				"error", err,
			)
			continue
		}

		// Create DM event (kind:4)
		event := nostr.Event{
			Kind:      4, // Encrypted Direct Message
			Content:   encrypted,
			CreatedAt: nostr.Timestamp(time.Now().Unix()),
			Tags:      nostr.Tags{{"p", adminPubkey}},
			PubKey:    targetPubkey,
		}

		if err := event.Sign(privateKey); err != nil {
			slog.Error("failed to sign admin notification",
				"admin", adminPubkey[:16]+"...",
				"error", err,
			)
			continue
		}

		// Publish the DM
		if err := s.relayClient.Publish(ctx, &event); err != nil {
			slog.Error("failed to publish admin notification",
				"admin", adminPubkey[:16]+"...",
				"error", err,
			)
			continue
		}

		slog.Info("sent authorization notification to admin",
			"admin", adminPubkey[:16]+"...",
			"method", request.Method,
			"client", clientPubkey[:16]+"...",
		)
	}
}

// ApproveRequest processes an approved pending authorization request
func (s *Signer) ApproveRequest(requestID string, pendingReq *storage.PendingRequest) {
	s.pendingCtxLock.RLock()
	reqCtx, exists := s.pendingCtx[requestID]
	s.pendingCtxLock.RUnlock()

	if !exists {
		slog.Warn("approve request: context not found, request may have expired", "request_id", requestID)
		return
	}

	// Signal approval
	select {
	case reqCtx.resultChan <- authResult{approved: true, perm: reqCtx.perm}:
		slog.Info("request approved", "request_id", requestID, "method", pendingReq.Method)
	default:
		slog.Warn("approve request: could not send result, channel may be closed", "request_id", requestID)
	}
}

// DenyRequest sends a denial response for a pending authorization request
func (s *Signer) DenyRequest(requestID string, pendingReq *storage.PendingRequest) {
	s.pendingCtxLock.RLock()
	reqCtx, exists := s.pendingCtx[requestID]
	s.pendingCtxLock.RUnlock()

	if !exists {
		slog.Warn("deny request: context not found, request may have expired", "request_id", requestID)
		return
	}

	// Signal denial
	select {
	case reqCtx.resultChan <- authResult{approved: false}:
		slog.Info("request denied", "request_id", requestID, "method", pendingReq.Method)
	default:
		slog.Warn("deny request: could not send result, channel may be closed", "request_id", requestID)
	}
}

// storePendingContext stores the context for a pending authorization request
func (s *Signer) storePendingContext(requestID string, ctx *pendingRequestContext) {
	s.pendingCtxLock.Lock()
	defer s.pendingCtxLock.Unlock()
	s.pendingCtx[requestID] = ctx
}

// removePendingContext removes the context for a pending authorization request
func (s *Signer) removePendingContext(requestID string) {
	s.pendingCtxLock.Lock()
	defer s.pendingCtxLock.Unlock()
	delete(s.pendingCtx, requestID)
}

// waitForAuthorization creates a pending request and waits for approval/denial
func (s *Signer) waitForAuthorization(ctx context.Context, reqCtx *pendingRequestContext, timeout time.Duration) (bool, *storage.Permission, error) {
	// Generate a unique request ID
	requestID := fmt.Sprintf("%s:%s:%d", reqCtx.targetPubkey[:8], reqCtx.clientPubkey[:8], time.Now().UnixNano())

	// Extract event kind if this is a sign_event request
	var eventKind *int
	if reqCtx.request.Method == "sign_event" && len(reqCtx.request.Params) > 0 {
		var event nostr.Event
		if err := json.Unmarshal([]byte(reqCtx.request.Params[0]), &event); err == nil {
			kind := event.Kind
			eventKind = &kind
		}
	}

	// Create pending request in storage
	pendingReq := &storage.PendingRequest{
		ID:           requestID,
		KeyPubkey:    reqCtx.targetPubkey,
		ClientPubkey: reqCtx.clientPubkey,
		Method:       reqCtx.request.Method,
		Params:       make(map[string]interface{}),
		EventKind:    eventKind,
		ExpiresAt:    time.Now().Add(timeout),
		CreatedAt:    time.Now(),
	}

	// Store params (first param if present)
	if len(reqCtx.request.Params) > 0 {
		pendingReq.Params["0"] = reqCtx.request.Params[0]
	}

	if err := s.storage.CreatePendingRequest(ctx, pendingReq); err != nil {
		return false, nil, fmt.Errorf("failed to create pending request: %w", err)
	}

	// Create result channel
	reqCtx.resultChan = make(chan authResult, 1)

	// Store context for later retrieval
	s.storePendingContext(requestID, reqCtx)
	defer func() {
		s.removePendingContext(requestID)
		// Clean up storage
		_ = s.storage.DeletePendingRequest(ctx, requestID)
	}()

	slog.Info("waiting for authorization",
		"request_id", requestID,
		"method", reqCtx.request.Method,
		"client", reqCtx.clientPubkey[:16]+"...",
		"timeout", timeout,
	)

	// Wait for result or timeout
	select {
	case result := <-reqCtx.resultChan:
		return result.approved, result.perm, nil
	case <-time.After(timeout):
		return false, nil, fmt.Errorf("authorization timeout")
	case <-ctx.Done():
		return false, nil, ctx.Err()
	}
}
