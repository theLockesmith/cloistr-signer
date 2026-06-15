package signer

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip44"
	"git.aegis-hq.xyz/coldforge/cloistr-common/relayprefs"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/audit"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/bunker"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/config"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/crypto"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/discovery"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/frost"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/metrics"
	relay "git.aegis-hq.xyz/coldforge/cloistr-signer/internal/nostr"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/proxy"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
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
	sourceRelay  string // The relay the request came from (for targeted responses)
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
	config          *config.Config
	storage         storage.Storage
	relayClient     *relay.Client
	keyRelayManager *relay.KeyRelayManager              // Per-key relay connections for scalability
	encryptor       *crypto.Encryptor
	auditLogger     audit.Logger                        // Audit logging for compliance and security
	proxyClient     *proxy.Client                       // Client for upstream signer connections
	relaySelector   *discovery.Selector                 // Relay selection with optional discovery
	relayPrefs      *relayprefs.Client                  // Relay preferences for user data delivery
	frostCoordinator *frost.Coordinator                 // FROST threshold signing coordinator
	keys            map[string]string                   // pubkey -> private key (hex)
	keysLock        sync.RWMutex                        // Protects keys map for concurrent access
	keyRelays       map[string][]string                 // pubkey -> configured relays (from storage)
	proxyKeys       map[string]string                   // pubkey -> bunker URI (for proxy keys)
	frostKeys       map[string]string                   // pubkey -> frost key ID (for FROST keys)
	pendingCtx      map[string]*pendingRequestContext   // requestID -> context
	pendingCtxLock  sync.RWMutex
	seenEvents      map[string]time.Time                // event ID -> first seen time (deduplication)
	seenEventsLock  sync.RWMutex
	ctx             context.Context                     // Main context for subscription management
	cancel          context.CancelFunc
	subCancels      map[string]context.CancelFunc       // Per-key subscription cancel functions (pubkey -> cancel)
	subLock         sync.Mutex                          // Protects subscription refresh
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

// New creates a new NIP-46 signer
func New(cfg *config.Config, store storage.Storage, relayClient *relay.Client, encryptor *crypto.Encryptor, relaySelector *discovery.Selector, relayPrefs *relayprefs.Client, auditLogger audit.Logger) *Signer {
	// Create FROST coordinator if encryptor is available
	var frostCoord *frost.Coordinator
	if encryptor != nil {
		adapter := &frostEncryptorAdapter{enc: encryptor}
		frostCoord = frost.NewCoordinator(store, adapter)
	}

	return &Signer{
		config:           cfg,
		storage:          store,
		relayClient:      relayClient,
		keyRelayManager:  relay.NewKeyRelayManager(cfg.Relays, cfg.RelayPublicMappings),
		encryptor:        encryptor,
		auditLogger:      auditLogger,
		proxyClient:      proxy.NewClient(cfg),
		relaySelector:    relaySelector,
		relayPrefs:       relayPrefs,
		frostCoordinator: frostCoord,
		keys:             make(map[string]string),
		keyRelays:        make(map[string][]string),
		proxyKeys:        make(map[string]string),
		frostKeys:        make(map[string]string),
		pendingCtx:       make(map[string]*pendingRequestContext),
		seenEvents:       make(map[string]time.Time),
		subCancels:       make(map[string]context.CancelFunc),
	}
}

// Start begins listening for NIP-46 requests
func (s *Signer) Start(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(ctx)

	// Connect to relays
	if err := s.relayClient.Connect(s.ctx); err != nil {
		return fmt.Errorf("failed to connect to relays: %w", err)
	}

	// Load keys from storage (all keys for internal signer operations)
	keys, err := s.storage.ListAllKeys(s.ctx)
	if err != nil {
		return fmt.Errorf("failed to load keys: %w", err)
	}

	// Load any existing keys into runtime map
	// Note: Only locally-encrypted keys are loaded at startup
	// Vault-encrypted keys require user login to decrypt
	s.keysLock.Lock()
	vaultKeyCount := 0
	for _, key := range keys {
		// Decrypt the local private key if needed (both local and proxy keys have this)
		privateKey := key.EncryptedNsec
		if privateKey != "" {
			// Skip Vault-encrypted keys at startup - they're loaded when user logs in
			if crypto.IsVaultEncrypted(privateKey) {
				vaultKeyCount++
				slog.Debug("skipping vault-encrypted key at startup", "pubkey", key.Pubkey[:16]+"...")
				continue
			}
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

		// Store per-key relay configuration
		if len(key.Relays) > 0 {
			s.keyRelays[key.Pubkey] = key.Relays
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
	s.keysLock.Unlock()

	if len(keys) == 0 {
		slog.Warn("no keys configured yet, will subscribe once keys are added via API")
	} else {
		loadedCount := len(keys) - vaultKeyCount
		slog.Info("loaded keys from storage",
			"total", len(keys),
			"loaded", loadedCount,
			"vault_pending", vaultKeyCount,
		)
		if vaultKeyCount > 0 {
			slog.Info("vault-encrypted keys will be loaded when users log in", "count", vaultKeyCount)
		}
	}
	metrics.SetKeysManaged(len(keys))

	// Load FROST keys from storage
	frostKeys, err := s.storage.ListFrostKeys(s.ctx)
	if err != nil {
		slog.Error("failed to load FROST keys", "error", err)
	} else {
		s.keysLock.Lock()
		for _, fk := range frostKeys {
			s.frostKeys[fk.Pubkey] = fk.ID
			slog.Info("loaded FROST key", "pubkey", fk.Pubkey[:16]+"...", "threshold", fk.Threshold, "total", fk.TotalShares)
		}
		s.keysLock.Unlock()
		if len(frostKeys) > 0 {
			slog.Info("loaded FROST keys from storage", "count", len(frostKeys))
		}
	}

	// Pre-warm per-key relay clients in background
	// This establishes connections before the first request, avoiding timeout on first connect
	go s.prewarmKeyRelayClients()

	// Start subscription with #p filter for our keys
	s.refreshSubscription()

	return nil
}

// prewarmKeyRelayClients establishes per-key relay connections for all loaded keys.
// This runs in the background so startup isn't blocked.
func (s *Signer) prewarmKeyRelayClients() {
	s.keysLock.RLock()
	keysToWarm := make(map[string]string)
	for pubkey, privateKey := range s.keys {
		keysToWarm[pubkey] = privateKey
	}
	keyRelaysCopy := make(map[string][]string)
	for pubkey, relays := range s.keyRelays {
		keyRelaysCopy[pubkey] = relays
	}
	s.keysLock.RUnlock()

	for pubkey, privateKey := range keysToWarm {
		relays := keyRelaysCopy[pubkey]
		slog.Info("pre-warming relay client", "pubkey", pubkey[:16]+"...")
		s.keyRelayManager.GetClient(s.ctx, pubkey, privateKey, relays)
	}
	slog.Info("finished pre-warming relay clients", "count", len(keysToWarm))
}

// refreshSubscription updates per-key relay subscriptions.
// Each key gets its own authenticated subscription to support HAVEN inbox access.
// Call this when keys are added or removed.
func (s *Signer) refreshSubscription() {
	s.subLock.Lock()
	defer s.subLock.Unlock()

	// If Start() hasn't been called yet, skip subscription refresh
	if s.ctx == nil {
		return
	}

	// Get current pubkeys and their private keys (regular keys + FROST keys)
	s.keysLock.RLock()
	currentKeys := make(map[string]string) // pubkey -> privateKey
	keyRelaysCopy := make(map[string][]string)
	for pubkey, privateKey := range s.keys {
		currentKeys[pubkey] = privateKey
	}
	for pubkey, relays := range s.keyRelays {
		keyRelaysCopy[pubkey] = relays
	}
	// FROST keys don't have private keys here, they use the coordinator
	frostPubkeys := make(map[string]bool)
	for pubkey := range s.frostKeys {
		frostPubkeys[pubkey] = true
	}
	s.keysLock.RUnlock()

	// Cancel subscriptions for keys that were removed
	for pubkey, cancel := range s.subCancels {
		_, hasRegular := currentKeys[pubkey]
		_, hasFrost := frostPubkeys[pubkey]
		if !hasRegular && !hasFrost {
			slog.Info("canceling subscription for removed key", "pubkey", pubkey[:16]+"...")
			cancel()
			delete(s.subCancels, pubkey)
		}
	}

	if len(currentKeys) == 0 && len(frostPubkeys) == 0 {
		slog.Info("no keys to subscribe for, waiting for keys to be added")
		return
	}

	// Start subscriptions for regular keys that don't have one yet
	for pubkey, privateKey := range currentKeys {
		if _, exists := s.subCancels[pubkey]; exists {
			continue // Already has subscription
		}

		// Create per-key subscription context
		subCtx, cancel := context.WithCancel(s.ctx)
		s.subCancels[pubkey] = cancel

		// Get or create per-key relay client (will connect and be ready for auth)
		relays := keyRelaysCopy[pubkey]
		keyClient := s.keyRelayManager.GetClient(s.ctx, pubkey, privateKey, relays)

		// Create filter for just this key's pubkey
		filters := nostr.Filters{{
			Kinds: []int{KindNIP46Request},
			Tags:  nostr.TagMap{"p": []string{pubkey}},
		}}

		slog.Info("starting per-key authenticated subscription", "pubkey", pubkey[:16]+"...", "relays", len(keyClient.GetConnectedRelays()))

		// Subscribe with authentication (required for HAVEN inbox access)
		go keyClient.SubscribeWithAuth(subCtx, filters, s.handleEventWithRelay)
	}

	// For FROST keys, we still need to receive events but don't have the private key here
	// Use the main relay client for FROST keys (they may not need auth if on different relays)
	// TODO: FROST keys may need a different approach for HAVEN-enabled relays
	for pubkey := range frostPubkeys {
		if _, exists := s.subCancels[pubkey]; exists {
			continue // Already has subscription
		}
		if _, hasRegular := currentKeys[pubkey]; hasRegular {
			continue // Handled by regular key subscription above
		}

		// Create subscription context
		subCtx, cancel := context.WithCancel(s.ctx)
		s.subCancels[pubkey] = cancel

		filters := nostr.Filters{{
			Kinds: []int{KindNIP46Request},
			Tags:  nostr.TagMap{"p": []string{pubkey}},
		}}

		slog.Info("starting FROST key subscription (unauthenticated)", "pubkey", pubkey[:16]+"...")

		// FROST keys use main relay client (may not work on HAVEN relays without auth)
		go s.relayClient.SubscribeWithRelayInfoReconnect(subCtx, filters, s.handleEventWithRelay)
	}

	slog.Info("subscription refresh complete", "regular_keys", len(currentKeys), "frost_keys", len(frostPubkeys))
}

// RefreshSubscription is the public method to trigger subscription refresh.
// Call this after adding or removing keys via the API.
func (s *Signer) RefreshSubscription() {
	s.refreshSubscription()
}

// Stop stops the signer
func (s *Signer) Stop() {
	// Cancel all per-key subscriptions
	s.subLock.Lock()
	for pubkey, cancel := range s.subCancels {
		cancel()
		delete(s.subCancels, pubkey)
	}
	s.subLock.Unlock()

	// Cancel main context (also cancels any remaining child contexts)
	if s.cancel != nil {
		s.cancel()
	}
	s.relayClient.Disconnect()
}

// AuditLogger returns the audit logger for querying audit logs
func (s *Signer) AuditLogger() audit.Logger {
	return s.auditLogger
}

// GetRelaysForBunker returns the relays to include in a bunker:// URI for a key.
// Uses the discovery-aware relay selector if available, otherwise falls back to
// key-specific relays or global config.
// Internal relay URLs are mapped to public URLs for bunker URIs.
func (s *Signer) GetRelaysForBunker(ctx context.Context, key *storage.Key) []string {
	var relays []string

	// If we have a relay selector, use it
	if s.relaySelector != nil {
		input := discovery.SelectionInput{
			KeyRelays:     key.Relays,
			Mode:          discovery.RelayMode(key.RelayMode),
			DiscoveryHint: key.Pubkey, // Use the signing key's pubkey for discovery
		}
		relays = s.relaySelector.SelectRelays(ctx, input)
	} else {
		// Fallback: use key relays if set, otherwise global config
		if len(key.Relays) > 0 {
			relays = key.Relays
		} else {
			relays = s.config.Relays
		}
	}

	// Map internal URLs to public URLs for bunker URIs
	// Key-specific and discovery relays pass through unchanged (not in mapping)
	return s.config.MapRelaysToPublic(relays)
}

// RegisterKey registers a key for signing (runtime, not persisted)
// Also refreshes the relay subscription to include the new key.
func (s *Signer) RegisterKey(pubkey, privateKeyHex string) {
	s.keysLock.Lock()
	s.keys[pubkey] = privateKeyHex
	s.keysLock.Unlock()
	s.refreshSubscription()
}

// RegisterProxyKey registers a proxy key that forwards to an upstream signer (runtime, not persisted)
// Also refreshes the relay subscription to include the new key.
func (s *Signer) RegisterProxyKey(pubkey, privateKeyHex, bunkerURI string) {
	s.keysLock.Lock()
	s.keys[pubkey] = privateKeyHex
	s.proxyKeys[pubkey] = bunkerURI
	s.keysLock.Unlock()
	s.refreshSubscription()
}

// UnregisterKey removes a key from the signer (runtime only).
// Also refreshes the relay subscription to remove the key.
func (s *Signer) UnregisterKey(pubkey string) {
	s.keysLock.Lock()
	delete(s.keys, pubkey)
	delete(s.proxyKeys, pubkey)
	delete(s.keyRelays, pubkey)
	delete(s.frostKeys, pubkey)
	s.keysLock.Unlock()
	s.keyRelayManager.RemoveClient(pubkey)
	s.refreshSubscription()
}

// RegisterFrostKey registers a FROST threshold signing key (runtime, not persisted).
// Also refreshes the relay subscription to include the new key.
func (s *Signer) RegisterFrostKey(pubkey, frostKeyID string) {
	s.keysLock.Lock()
	s.frostKeys[pubkey] = frostKeyID
	s.keysLock.Unlock()
	s.refreshSubscription()
}

// UnregisterFrostKey removes a FROST key from the signer (runtime only).
// Also refreshes the relay subscription to remove the key.
func (s *Signer) UnregisterFrostKey(pubkey string) {
	s.keysLock.Lock()
	delete(s.frostKeys, pubkey)
	s.keysLock.Unlock()
	s.refreshSubscription()
}

// handleEventWithRelay wraps event handling with source relay tracking for targeted responses
func (s *Signer) handleEventWithRelay(event *nostr.Event, sourceRelay string) {
	if event.Kind != KindNIP46Request {
		return
	}

	// Deduplicate events - same event may arrive from multiple relays
	// We only want to process it once (from the first relay that delivers it)
	s.seenEventsLock.Lock()
	if _, seen := s.seenEvents[event.ID]; seen {
		s.seenEventsLock.Unlock()
		slog.Debug("skipping duplicate event", "event_id", event.ID, "relay", sourceRelay)
		return
	}
	s.seenEvents[event.ID] = time.Now()
	// Cleanup old entries (keep last 5 minutes)
	for id, t := range s.seenEvents {
		if time.Since(t) > 5*time.Minute {
			delete(s.seenEvents, id)
		}
	}
	s.seenEventsLock.Unlock()

	// Lock keys for reading during event handling
	s.keysLock.RLock()

	// Ignore events authored by our own keys (these are responses, not requests)
	// This prevents the signer from trying to process its own responses
	// when using same-instance proxy keys
	if _, isOurKey := s.keys[event.PubKey]; isOurKey {
		s.keysLock.RUnlock()
		slog.Debug("ignoring event from our own key", "event_id", event.ID, "author", event.PubKey[:16]+"...")
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
		s.keysLock.RUnlock()
		slog.Debug("event not addressed to any of our keys", "event_id", event.ID)
		return
	}

	privateKey := s.keys[targetPubkey]
	s.keysLock.RUnlock()

	clientPubkey := event.PubKey
	requestStart := time.Now()

	slog.Info("received NIP-46 request",
		"from", clientPubkey[:16]+"...",
		"to", targetPubkey[:16]+"...",
		"event_id", event.ID,
		"source_relay", sourceRelay,
		"event_created", time.Unix(int64(event.CreatedAt), 0).Format(time.RFC3339),
		"latency_ms", time.Since(time.Unix(int64(event.CreatedAt), 0)).Milliseconds(),
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
		slog.Error("failed to parse request", "error", err, "event_id", event.ID)
		return
	}

	decryptDuration := time.Since(requestStart)
	slog.Info("processing request",
		"method", request.Method,
		"request_id", request.ID,
		"event_id", event.ID,
		"decrypt_ms", decryptDuration.Milliseconds(),
	)

	// Check permissions
	ctx := context.Background()
	perm, err := s.storage.GetPermission(ctx, targetPubkey, clientPubkey)

	// Handle request in a goroutine to avoid blocking the event loop
	// This is especially important for authorization callbacks which may take time
	go s.processRequest(ctx, targetPubkey, privateKey, clientPubkey, sourceRelay, &request, perm, err, useNIP44, requestStart)
}

// processRequest handles a NIP-46 request, potentially waiting for authorization
func (s *Signer) processRequest(ctx context.Context, targetPubkey, privateKey, clientPubkey, sourceRelay string, request *NIP46Request, perm *storage.Permission, permErr error, useNIP44 bool, requestStart time.Time) {
	// Log timing at the end
	defer func() {
		slog.Info("request completed",
			"request_id", request.ID,
			"method", request.Method,
			"total_ms", time.Since(requestStart).Milliseconds(),
		)
	}()

	// If we have a valid permission
	if permErr == nil {
		// Check if method is allowed
		if !s.isMethodAllowed(perm, request.Method) {
			slog.Warn("method not allowed", "method", request.Method, "client", clientPubkey[:16]+"...")
			s.sendError(ctx, targetPubkey, privateKey, clientPubkey, sourceRelay, request.ID, "method not allowed", useNIP44)
			return
		}

		// Check if this permission requires approval (hybrid mode)
		if s.shouldRequireApproval(ctx, targetPubkey, perm) {
			slog.Info("permission requires approval", "client", clientPubkey[:16]+"...", "method", request.Method)
			s.handlePendingApproval(ctx, targetPubkey, privateKey, clientPubkey, sourceRelay, request, perm, useNIP44)
			return
		}

		// Handle the request
		result, err := s.handleRequest(ctx, targetPubkey, privateKey, clientPubkey, request, perm)
		if err != nil {
			slog.Error("request handling failed", "method", request.Method, "error", err)
			s.sendError(ctx, targetPubkey, privateKey, clientPubkey, sourceRelay, request.ID, err.Error(), useNIP44)
			return
		}

		// Update last used timestamp (async, don't block on this)
		go func() {
			if err := s.storage.UpdatePermissionLastUsed(ctx, targetPubkey, clientPubkey); err != nil {
				slog.Debug("failed to update last used timestamp", "error", err)
			}
		}()

		s.sendResult(ctx, targetPubkey, privateKey, clientPubkey, sourceRelay, request.ID, result, useNIP44)
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
					s.sendError(ctx, targetPubkey, privateKey, clientPubkey, sourceRelay, request.ID, err.Error(), useNIP44)
					return
				}
				// Update last used timestamp (async)
				go func() {
					if err := s.storage.UpdatePermissionLastUsed(ctx, targetPubkey, clientPubkey); err != nil {
						slog.Debug("failed to update last used timestamp", "error", err)
					}
				}()
				s.sendResult(ctx, targetPubkey, privateKey, clientPubkey, sourceRelay, request.ID, result, useNIP44)
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
			s.sendError(ctx, targetPubkey, privateKey, clientPubkey, sourceRelay, request.ID, err.Error(), useNIP44)
			return
		}
		s.sendResult(ctx, targetPubkey, privateKey, clientPubkey, sourceRelay, request.ID, result, useNIP44)
		return
	}

	// Approval required - handle pending approval flow
	s.handlePendingApproval(ctx, targetPubkey, privateKey, clientPubkey, sourceRelay, request, nil, useNIP44)
}

// handlePendingApproval handles the approval workflow for requests that need manual authorization
func (s *Signer) handlePendingApproval(ctx context.Context, targetPubkey, privateKey, clientPubkey, sourceRelay string, request *NIP46Request, perm *storage.Permission, useNIP44 bool) {
	// Create pending request context
	reqCtx := &pendingRequestContext{
		targetPubkey: targetPubkey,
		privateKey:   privateKey,
		clientPubkey: clientPubkey,
		sourceRelay:  sourceRelay,
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
		s.sendError(ctx, targetPubkey, privateKey, clientPubkey, sourceRelay, request.ID, "authorization timeout", useNIP44)
		return
	}

	if !approved {
		slog.Info("request denied by admin", "client", clientPubkey[:16]+"...", "method", request.Method)
		s.sendError(ctx, targetPubkey, privateKey, clientPubkey, sourceRelay, request.ID, "request denied", useNIP44)
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
		s.sendError(ctx, targetPubkey, privateKey, clientPubkey, sourceRelay, request.ID, err.Error(), useNIP44)
		return
	}

	slog.Info("request approved and processed", "method", request.Method, "client", clientPubkey[:16]+"...")
	s.sendResult(ctx, targetPubkey, privateKey, clientPubkey, sourceRelay, request.ID, result, useNIP44)
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
	// Record timing for latency metrics
	start := time.Now()

	// Record metrics on completion
	defer func() {
		metrics.RecordSigningRequest(req.Method, err == nil)
		// Record latency for methods that do actual work
		switch req.Method {
		case "sign_event", "batch_sign", "nip04_encrypt", "nip04_decrypt", "nip44_encrypt", "nip44_decrypt":
			metrics.RecordSigningLatency(req.Method, time.Since(start))
		}
	}()

	// Audit logging on completion (for methods that warrant it)
	defer func() {
		if s.auditLogger != nil && s.shouldAuditMethod(req.Method) {
			eventKind := s.extractEventKind(req)
			var eventType audit.EventType
			var errReason string
			if err != nil {
				eventType = audit.EventSignFailed
				errReason = err.Error()
			} else {
				eventType = audit.EventSignCompleted
			}

			auditEvent := audit.NewSignEvent(eventType, clientPubkey, targetPubkey, req.Method, eventKind, err == nil, errReason)

			// Add proxy/delegate info if this is a proxy key
			if bunkerURI, isProxy := s.proxyKeys[targetPubkey]; isProxy {
				if uri, parseErr := bunker.Parse(bunkerURI); parseErr == nil {
					auditEvent.Details["proxy_key"] = targetPubkey
					auditEvent.Details["upstream_pubkey"] = uri.SignerPubkey
					auditEvent.Details["is_chained"] = true
				}
			}

			// Add delegate pubkey if set on permission
			if perm.DelegatePubkey != "" {
				auditEvent.Details["delegate_pubkey"] = perm.DelegatePubkey
			}

			if logErr := s.auditLogger.Log(ctx, auditEvent); logErr != nil {
				slog.Warn("failed to log audit event", "error", logErr)
			}
		}
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
		return s.handleProxyRequest(ctx, targetPubkey, privateKey, bunkerURI, req, clientPubkey)
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
	case "batch_sign":
		// Cloistr extension: sign multiple events in one request to reduce round-trips
		return s.handleBatchSign(ctx, targetPubkey, privateKey, req.Params, perm)
	case "nip04_encrypt":
		return s.handleNIP04Encrypt(ctx, targetPubkey, privateKey, req.Params)
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

// shouldAuditMethod returns true if the method should be audit logged
func (s *Signer) shouldAuditMethod(method string) bool {
	switch method {
	case "sign_event", "nip04_encrypt", "nip04_decrypt", "nip44_encrypt", "nip44_decrypt":
		return true
	default:
		return false
	}
}

// extractEventKind extracts the event kind from sign_event params
func (s *Signer) extractEventKind(req *NIP46Request) int {
	if req.Method != "sign_event" || len(req.Params) < 1 {
		return 0
	}
	var event struct {
		Kind int `json:"kind"`
	}
	if err := json.Unmarshal([]byte(req.Params[0]), &event); err != nil {
		return 0
	}
	return event.Kind
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

	// Return pubkey in connect response to save a round-trip on rate-limited relays
	// Cloistr extension: clients that understand this skip the get_public_key call
	// Standard NIP-46 clients will receive this as the "ack" and still work
	// (they typically just check for non-error response)
	return fmt.Sprintf(`{"pubkey":"%s"}`, targetPubkey), nil
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
// clientPubkey is the original client that initiated the request (for audit trail)
func (s *Signer) handleProxyRequest(ctx context.Context, targetPubkey, privateKey, bunkerURI string, req *NIP46Request, clientPubkey string) (string, error) {
	// Parse the bunker URI to get the upstream pubkey
	uri, err := bunker.Parse(bunkerURI)
	if err != nil {
		return "", fmt.Errorf("failed to parse bunker URI: %w", err)
	}

	// Check if the upstream key is local (same signer instance)
	// If so, handle directly without a relay round-trip
	if upstreamPrivkey, isLocal := s.keys[uri.SignerPubkey]; isLocal {
		slog.Info("internal proxy: handling locally",
			"method", req.Method,
			"proxy", targetPubkey[:16]+"...",
			"upstream", uri.SignerPubkey[:16]+"...",
			"original_client", clientPubkey[:16]+"...",
		)
		return s.handleInternalProxy(ctx, uri.SignerPubkey, upstreamPrivkey, targetPubkey, req, clientPubkey)
	}

	// Check if the upstream key is a FROST key (local threshold signing)
	if frostKeyID, isFrost := s.frostKeys[uri.SignerPubkey]; isFrost {
		slog.Info("internal proxy: handling via FROST",
			"method", req.Method,
			"proxy", targetPubkey[:16]+"...",
			"upstream_frost", uri.SignerPubkey[:16]+"...",
			"frost_key_id", frostKeyID[:16]+"...",
			"original_client", clientPubkey[:16]+"...",
		)
		return s.handleFrostProxy(ctx, uri.SignerPubkey, frostKeyID, targetPubkey, req, clientPubkey)
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
		"original_client", clientPubkey[:16]+"...",
	)

	response, err := conn.SendRequest(ctx, req.Method, req.Params)
	if err != nil {
		return "", fmt.Errorf("upstream request failed: %w", err)
	}

	return response.Result, nil
}

// handleInternalProxy handles proxy requests when the upstream key is on the same signer instance.
// This avoids the relay round-trip and handles requests directly.
// originalClient is the original requester (for audit trail through the proxy chain)
func (s *Signer) handleInternalProxy(ctx context.Context, upstreamPubkey, upstreamPrivkey, proxyPubkey string, req *NIP46Request, originalClient string) (string, error) {
	// Create a "virtual" permission for the proxy key accessing the upstream key
	// The proxy key is pre-authorized with full access to the upstream
	// DelegatePubkey tracks the original client through the proxy chain
	perm := &storage.Permission{
		KeyID:          upstreamPubkey,
		UserPubkey:     proxyPubkey,
		Methods:        []string{"sign_event", "nip04_encrypt", "nip04_decrypt", "nip44_encrypt", "nip44_decrypt", "get_public_key"},
		DelegatePubkey: originalClient, // Track original requester for audit
	}

	// Handle the request directly using the upstream key
	switch req.Method {
	case "sign_event":
		return s.handleSignEvent(ctx, upstreamPubkey, upstreamPrivkey, req.Params, perm)
	case "nip04_encrypt":
		return s.handleNIP04Encrypt(ctx, upstreamPubkey, upstreamPrivkey, req.Params)
	case "nip04_decrypt":
		return s.handleNIP04Decrypt(upstreamPrivkey, req.Params)
	case "nip44_encrypt":
		return s.handleNIP44Encrypt(upstreamPrivkey, req.Params)
	case "nip44_decrypt":
		return s.handleNIP44Decrypt(upstreamPrivkey, req.Params)
	case "get_public_key":
		return upstreamPubkey, nil
	default:
		return "", fmt.Errorf("method %s not supported for internal proxy", req.Method)
	}
}

// handleFrostProxy handles proxy requests when the upstream key is a FROST threshold key.
// FROST keys support signing but not encryption (no single private key for NIP-04/44).
func (s *Signer) handleFrostProxy(ctx context.Context, upstreamPubkey, frostKeyID, proxyPubkey string, req *NIP46Request, originalClient string) (string, error) {
	if s.frostCoordinator == nil {
		return "", errors.New("FROST coordinator not available")
	}

	switch req.Method {
	case "sign_event":
		return s.handleFrostSignEvent(ctx, upstreamPubkey, frostKeyID, req.Params, originalClient)
	case "get_public_key":
		return upstreamPubkey, nil
	default:
		// FROST keys don't support encryption methods - no single private key
		return "", fmt.Errorf("method %s not supported for FROST keys (no private key for encryption)", req.Method)
	}
}

// handleFrostSignEvent signs an event using FROST threshold signatures
func (s *Signer) handleFrostSignEvent(ctx context.Context, targetPubkey, frostKeyID string, params []string, originalClient string) (string, error) {
	if len(params) < 1 {
		return "", errors.New("missing event parameter")
	}

	var event nostr.Event
	if err := json.Unmarshal([]byte(params[0]), &event); err != nil {
		return "", fmt.Errorf("invalid event: %w", err)
	}

	// Set the pubkey
	event.PubKey = targetPubkey

	// Generate event ID (SHA256 hash of serialized event)
	eventHash := event.GetID()
	hashBytes, err := hex.DecodeString(eventHash)
	if err != nil {
		return "", fmt.Errorf("failed to decode event hash: %w", err)
	}

	// Sign using FROST coordinator
	signature, err := s.frostCoordinator.SignEvent(ctx, frostKeyID, hashBytes)
	if err != nil {
		slog.Error("FROST signing failed via proxy",
			"error", err,
			"frost_key_id", frostKeyID[:16]+"...",
			"original_client", originalClient[:16]+"...",
		)
		return "", fmt.Errorf("FROST signing failed: %w", err)
	}

	// Set the signature on the event
	event.ID = eventHash
	event.Sig = signature

	slog.Info("FROST signed event via proxy",
		"event_id", eventHash[:16]+"...",
		"kind", event.Kind,
		"frost_key", targetPubkey[:16]+"...",
		"original_client", originalClient[:16]+"...",
	)

	// Return signed event as JSON
	data, err := json.Marshal(event)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// getUpstreamPubkey retrieves the public key from the upstream signer
func (s *Signer) getUpstreamPubkey(ctx context.Context, targetPubkey, privateKey, bunkerURI string) (string, error) {
	// Parse the bunker URI to get the upstream pubkey
	uri, err := bunker.Parse(bunkerURI)
	if err != nil {
		return "", fmt.Errorf("failed to parse bunker URI: %w", err)
	}

	// If upstream is local (regular key), return the pubkey directly
	if _, isLocal := s.keys[uri.SignerPubkey]; isLocal {
		slog.Debug("internal proxy: returning local upstream pubkey", "upstream", uri.SignerPubkey[:16]+"...")
		return uri.SignerPubkey, nil
	}

	// If upstream is a FROST key, return the pubkey directly
	if _, isFrost := s.frostKeys[uri.SignerPubkey]; isFrost {
		slog.Debug("internal proxy: returning FROST upstream pubkey", "upstream", uri.SignerPubkey[:16]+"...")
		return uri.SignerPubkey, nil
	}

	// Otherwise connect to the upstream signer
	conn, err := s.proxyClient.GetConnection(ctx, bunkerURI, privateKey, targetPubkey)
	if err != nil {
		return "", fmt.Errorf("failed to connect to upstream: %w", err)
	}

	return conn.GetPublicKey(ctx)
}

// disposableKindRefusal maps event kinds that disposable-mode keys refuse to sign.
// Kind 0 (profile metadata), 3 (contact list), 10002 (relay list metadata) trivially
// link a disposable identity to the operator: a disposable npub posting the same
// profile, following the same contacts, or pinning the same relay set as the master
// re-correlates them. Kind 4 (NIP-04 DM) names the recipient in cleartext via a
// `p` tag; refused in favor of NIP-17 gift-wrap (kind:1059 with NIP-44-encrypted
// inner) which hides the recipient.
var disposableKindRefusal = map[int]string{
	0:     "disposable-mode key refuses kind:0 (profile metadata reveals identity)",
	3:     "disposable-mode key refuses kind:3 (contact list reveals social graph)",
	10002: "disposable-mode key refuses kind:10002 (relay list metadata reveals relay set)",
	4:     "disposable-mode key refuses kind:4 (NIP-04 leaks recipient via p-tag); use NIP-17 (kind:1059) for stronger metadata privacy",
}

// keyIsDisposable returns true if the key with the given pubkey has DisposableMode
// set. Graceful: returns false on lookup error so signing proceeds normally if the
// key cannot be loaded (consistent with the existing graceful-degradation pattern
// elsewhere in this file).
func (s *Signer) keyIsDisposable(ctx context.Context, targetPubkey string) bool {
	key, err := s.storage.GetKeyByPubkey(ctx, targetPubkey)
	if err != nil || key == nil {
		return false
	}
	return key.DisposableMode
}

// stripFingerprintTags removes tags that fingerprint the signing software. Called
// for events signed by disposable-mode keys to defeat cross-identity correlation
// via signer-software tells.
func stripFingerprintTags(event *nostr.Event) {
	filtered := event.Tags[:0]
	for _, tag := range event.Tags {
		if len(tag) > 0 && tag[0] == "client" {
			continue
		}
		filtered = append(filtered, tag)
	}
	event.Tags = filtered
}

// applyDisposableJitter introduces a short random response delay for disposable-mode
// keys to break per-request timing correlation between the disposable identity and
// the master identity. 0-150ms window: small enough to be human-imperceptible,
// large enough to obscure sub-millisecond timing tells.
func applyDisposableJitter() {
	const maxJitterMs = 150
	var b [2]byte
	if _, err := cryptorand.Read(b[:]); err != nil {
		return
	}
	n := (int(b[0])<<8 | int(b[1])) % maxJitterMs
	time.Sleep(time.Duration(n) * time.Millisecond)
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

	disposable := s.keyIsDisposable(ctx, targetPubkey)
	if disposable {
		if reason, blocked := disposableKindRefusal[event.Kind]; blocked {
			return "", errors.New(reason)
		}
		stripFingerprintTags(&event)
		defer applyDisposableJitter()
	} else if event.Kind == 4 {
		slog.Warn("kind:4 (NIP-04 DM) signed on non-disposable key; consider NIP-17 (kind:1059) for stronger metadata privacy",
			"key_pubkey", targetPubkey[:16]+"...")
	}

	// Set pubkey and sign
	// NOTE: FROST keys are not supported via NIP-46 because NIP-46 requires decryption
	// of incoming requests using the target key's private key. FROST keys don't have
	// a single private key - they have distributed shares. FROST signing is available
	// via the HTTP API at /api/v1/frost/keys/{id}/sign instead.
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

// handleBatchSign signs multiple events in one request to reduce round-trips on rate-limited relays
// Cloistr extension: params is an array of JSON-encoded events
// Returns a JSON array of signed events in the same order
func (s *Signer) handleBatchSign(ctx context.Context, targetPubkey, privateKey string, params []string, perm *storage.Permission) (string, error) {
	if len(params) < 1 {
		return "", errors.New("missing events parameter")
	}

	signedEvents := make([]json.RawMessage, 0, len(params))

	disposable := s.keyIsDisposable(ctx, targetPubkey)
	if disposable {
		defer applyDisposableJitter()
	}

	for i, param := range params {
		var event nostr.Event
		if err := json.Unmarshal([]byte(param), &event); err != nil {
			return "", fmt.Errorf("invalid event at index %d: %w", i, err)
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
				return "", fmt.Errorf("kind %d not allowed at index %d", event.Kind, i)
			}
		}

		if disposable {
			if reason, blocked := disposableKindRefusal[event.Kind]; blocked {
				return "", fmt.Errorf("event at index %d: %s", i, reason)
			}
			stripFingerprintTags(&event)
		} else if event.Kind == 4 {
			slog.Warn("kind:4 (NIP-04 DM) signed on non-disposable key in batch; consider NIP-17 (kind:1059) for stronger metadata privacy",
				"key_pubkey", targetPubkey[:16]+"...",
				"index", i)
		}

		// Set pubkey and sign
		event.PubKey = targetPubkey
		if err := event.Sign(privateKey); err != nil {
			return "", fmt.Errorf("signing failed at index %d: %w", i, err)
		}

		data, err := json.Marshal(event)
		if err != nil {
			return "", fmt.Errorf("failed to marshal signed event at index %d: %w", i, err)
		}
		signedEvents = append(signedEvents, data)
	}

	// Return array of signed events
	result, err := json.Marshal(signedEvents)
	if err != nil {
		return "", err
	}

	// Record batch size for performance metrics
	metrics.RecordBatchSignSize(len(signedEvents))

	slog.Info("batch signed events", "count", len(signedEvents))
	return string(result), nil
}

func (s *Signer) handleNIP04Encrypt(ctx context.Context, targetPubkey, privateKey string, params []string) (string, error) {
	if len(params) < 2 {
		return "", errors.New("missing parameters (need pubkey and plaintext)")
	}

	if s.keyIsDisposable(ctx, targetPubkey) {
		return "", errors.New("disposable-mode key refuses nip04_encrypt (NIP-04 leaks recipient via p-tag); use nip44_encrypt with NIP-17 gift-wrap instead")
	}

	slog.Warn("nip04_encrypt called; consider nip44_encrypt with NIP-17 gift-wrap for stronger metadata privacy",
		"key_pubkey", targetPubkey[:16]+"...")

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

func (s *Signer) sendResult(ctx context.Context, signerPubkey, privateKey, clientPubkey, sourceRelay, requestID, result string, useNIP44 bool) {
	response := NIP46Response{
		ID:     requestID,
		Result: result,
	}
	s.sendResponse(ctx, signerPubkey, privateKey, clientPubkey, sourceRelay, response, useNIP44)
}

func (s *Signer) sendError(ctx context.Context, signerPubkey, privateKey, clientPubkey, sourceRelay, requestID, errMsg string, useNIP44 bool) {
	response := NIP46Response{
		ID:    requestID,
		Error: errMsg,
	}
	s.sendResponse(ctx, signerPubkey, privateKey, clientPubkey, sourceRelay, response, useNIP44)
}

func (s *Signer) sendResponse(ctx context.Context, signerPubkey, privateKey, clientPubkey, sourceRelay string, response NIP46Response, useNIP44 bool) {
	sendStart := time.Now()

	data, err := json.Marshal(response)
	if err != nil {
		slog.Error("failed to marshal response", "error", err, "request_id", response.ID)
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

	// Get or create per-key relay client for this signer key
	// This provides isolated rate limits per key
	keyRelays := s.keyRelays[signerPubkey]
	keyClient := s.keyRelayManager.GetClient(ctx, signerPubkey, privateKey, keyRelays)

	// Build list of relays to try for response
	// Respect user choice: if key has custom relays, use those; otherwise use config defaults
	var preferredRelays []string
	if len(keyRelays) > 0 {
		// User configured custom relays for this key - respect their choice
		preferredRelays = keyRelays
	} else {
		// Key uses defaults - we can prefer our relay (no rate limiting for kind:24133)
		preferredRelays = s.config.Relays
	}

	// Build final list: preferred relays first, source relay as fallback
	relaysToTry := make([]string, 0, len(preferredRelays)+1)
	sourceInPreferred := false
	for _, r := range preferredRelays {
		relaysToTry = append(relaysToTry, r)
		if r == sourceRelay {
			sourceInPreferred = true
		}
	}
	// Add source relay as fallback if not already in preferred list
	if !sourceInPreferred {
		relaysToTry = append(relaysToTry, sourceRelay)
	}

	// Try each relay until one succeeds
	publishStart := time.Now()
	var lastErr error
	var successRelay string
	for _, relay := range relaysToTry {
		if err := keyClient.PublishToRelay(ctx, relay, &event); err != nil {
			slog.Debug("publish attempt to relay failed",
				"request_id", response.ID,
				"relay", relay,
				"error", err,
			)
			lastErr = err
			continue
		}
		successRelay = relay
		break
	}

	if successRelay == "" {
		slog.Error("failed to publish response to any relay",
			"request_id", response.ID,
			"relays_tried", relaysToTry,
			"last_error", lastErr,
			"publish_ms", time.Since(publishStart).Milliseconds(),
		)
		return
	}

	slog.Info("sent response",
		"request_id", response.ID,
		"to", clientPubkey[:16]+"...",
		"relay", successRelay,
		"event_id", event.ID,
		"has_error", response.Error != "",
		"nip44", useNIP44,
		"encrypt_ms", publishStart.Sub(sendStart).Milliseconds(),
		"publish_ms", time.Since(publishStart).Milliseconds(),
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
	// Map internal relay URLs to public URLs for display
	connectedRelays := s.config.MapRelaysToPublic(s.relayClient.GetConnectedRelays())
	return map[string]interface{}{
		"keys_loaded":      len(s.keys),
		"connected_relays": connectedRelays,
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

		// Get admin's relay preferences for DM delivery
		var relaysToPublish []string
		if s.relayPrefs != nil {
			prefs, err := s.relayPrefs.GetRelayPrefs(ctx, adminPubkey)
			if err == nil && prefs.HasRelays() {
				// For DMs, publish to admin's all relays (both read and write)
				// This ensures the DM reaches their inbox regardless of read/write split
				relaysToPublish = prefs.AllRelays()
				slog.Debug("using admin relay preferences",
					"admin", adminPubkey[:16]+"...",
					"relays", relaysToPublish,
					"source", prefs.Source,
				)
			}
		}

		// Publish the DM to admin's preferred relays, or fall back to configured relays
		var published bool
		if len(relaysToPublish) > 0 {
			for _, relayURL := range relaysToPublish {
				if err := s.relayClient.PublishToRelay(ctx, relayURL, &event); err != nil {
					slog.Debug("failed to publish to admin relay",
						"admin", adminPubkey[:16]+"...",
						"relay", relayURL,
						"error", err,
					)
					continue
				}
				published = true
			}
		}

		// Fall back to configured relays if admin relay prefs failed or weren't available
		if !published {
			if err := s.relayClient.Publish(ctx, &event); err != nil {
				slog.Error("failed to publish admin notification",
					"admin", adminPubkey[:16]+"...",
					"error", err,
				)
				continue
			}
		}

		slog.Info("sent authorization notification to admin",
			"admin", adminPubkey[:16]+"...",
			"method", request.Method,
			"client", clientPubkey[:16]+"...",
			"used_prefs", len(relaysToPublish) > 0 && published,
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
