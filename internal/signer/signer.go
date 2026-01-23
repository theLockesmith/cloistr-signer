package signer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip44"
	"gitlab.coldforge.xyz/coldforge/coldforge-signer/internal/config"
	relay "gitlab.coldforge.xyz/coldforge/coldforge-signer/internal/nostr"
	"gitlab.coldforge.xyz/coldforge/coldforge-signer/internal/storage"
)

const (
	KindNIP46Request  = 24133
	KindNIP46Response = 24133 // Same kind, differentiated by tags
)

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

// Signer handles NIP-46 remote signing requests
type Signer struct {
	config      *config.Config
	storage     storage.Storage
	relayClient *relay.Client
	keys        map[string]string // pubkey -> private key (hex)
	cancel      context.CancelFunc
}

// New creates a new NIP-46 signer
func New(cfg *config.Config, store storage.Storage, relayClient *relay.Client) *Signer {
	return &Signer{
		config:      cfg,
		storage:     store,
		relayClient: relayClient,
		keys:        make(map[string]string),
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
		s.keys[key.Pubkey] = key.EncryptedNsec
	}

	if len(keys) == 0 {
		slog.Warn("no keys configured yet, will respond once keys are added via API")
	} else {
		slog.Info("loaded keys from storage", "count", len(keys))
	}

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
	)

	// Compute shared secret and decrypt the request content
	sharedSecret, err := nip04.ComputeSharedSecret(clientPubkey, privateKey)
	if err != nil {
		slog.Error("failed to compute shared secret", "error", err)
		return
	}

	decrypted, err := nip04.Decrypt(event.Content, sharedSecret)
	if err != nil {
		slog.Error("failed to decrypt request", "error", err)
		return
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
	if err != nil {
		slog.Warn("permission denied", "client", clientPubkey[:16]+"...", "error", err)
		s.sendError(ctx, targetPubkey, privateKey, clientPubkey, request.ID, "not authorized")
		return
	}

	// Check if method is allowed
	if !s.isMethodAllowed(perm, request.Method) {
		slog.Warn("method not allowed", "method", request.Method, "client", clientPubkey[:16]+"...")
		s.sendError(ctx, targetPubkey, privateKey, clientPubkey, request.ID, "method not allowed")
		return
	}

	// Handle the request
	result, err := s.handleRequest(ctx, targetPubkey, privateKey, clientPubkey, &request, perm)
	if err != nil {
		slog.Error("request handling failed", "method", request.Method, "error", err)
		s.sendError(ctx, targetPubkey, privateKey, clientPubkey, request.ID, err.Error())
		return
	}

	s.sendResult(ctx, targetPubkey, privateKey, clientPubkey, request.ID, result)
}

func (s *Signer) isMethodAllowed(perm *storage.Permission, method string) bool {
	for _, m := range perm.Methods {
		if m == method || m == "*" || m == "all" {
			return true
		}
	}
	return false
}

func (s *Signer) handleRequest(ctx context.Context, targetPubkey, privateKey, clientPubkey string, req *NIP46Request, perm *storage.Permission) (string, error) {
	switch req.Method {
	case "connect":
		return s.handleConnect(ctx, targetPubkey, clientPubkey, req.Params, perm)
	case "ping":
		return "pong", nil
	case "get_public_key":
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

	thirdPartyPubkey := params[0]
	plaintext := params[1]

	conversationKey, err := nip44.GenerateConversationKey(privateKey, thirdPartyPubkey)
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

	thirdPartyPubkey := params[0]
	ciphertext := params[1]

	conversationKey, err := nip44.GenerateConversationKey(privateKey, thirdPartyPubkey)
	if err != nil {
		return "", fmt.Errorf("failed to generate conversation key: %w", err)
	}

	plaintext, err := nip44.Decrypt(ciphertext, conversationKey)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

func (s *Signer) sendResult(ctx context.Context, signerPubkey, privateKey, clientPubkey, requestID, result string) {
	response := NIP46Response{
		ID:     requestID,
		Result: result,
	}
	s.sendResponse(ctx, signerPubkey, privateKey, clientPubkey, response)
}

func (s *Signer) sendError(ctx context.Context, signerPubkey, privateKey, clientPubkey, requestID, errMsg string) {
	response := NIP46Response{
		ID:    requestID,
		Error: errMsg,
	}
	s.sendResponse(ctx, signerPubkey, privateKey, clientPubkey, response)
}

func (s *Signer) sendResponse(ctx context.Context, signerPubkey, privateKey, clientPubkey string, response NIP46Response) {
	data, err := json.Marshal(response)
	if err != nil {
		slog.Error("failed to marshal response", "error", err)
		return
	}

	// Compute shared secret and encrypt response with NIP-04
	sharedSecret, err := nip04.ComputeSharedSecret(clientPubkey, privateKey)
	if err != nil {
		slog.Error("failed to compute shared secret", "error", err)
		return
	}

	encrypted, err := nip04.Encrypt(string(data), sharedSecret)
	if err != nil {
		slog.Error("failed to encrypt response", "error", err)
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
	)
}

// GetStatus returns the current signer status
func (s *Signer) GetStatus() map[string]interface{} {
	return map[string]interface{}{
		"keys_loaded":      len(s.keys),
		"connected_relays": s.relayClient.GetConnectedRelays(),
	}
}
