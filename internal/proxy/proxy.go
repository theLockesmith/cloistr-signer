// Package proxy implements NIP-46 client functionality for connecting to upstream signers.
// This enables signer chaining where this signer acts as a client to another signer.
package proxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip44"

	"git.coldforge.xyz/coldforge/cloistr-signer/internal/bunker"
	"git.coldforge.xyz/coldforge/cloistr-signer/internal/config"
)

const (
	KindNIP46Request  = 24133
	KindNIP46Response = 24133
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

// pendingResponse tracks a response we're waiting for
type pendingResponse struct {
	respChan chan *NIP46Response
}

// UpstreamConnection represents a connection to an upstream signer
type UpstreamConnection struct {
	URI            *bunker.URI
	LocalPrivkey   string       // Our ephemeral private key for this connection
	LocalPubkey    string       // Our ephemeral public key
	relay          *nostr.Relay
	pendingMu      sync.RWMutex
	pending        map[string]*pendingResponse // requestID -> pending response
	ctx            context.Context
	cancel         context.CancelFunc
	connected      bool
	useNIP44       bool // Whether upstream supports NIP-44
}

// Client manages connections to upstream signers
type Client struct {
	config      *config.Config
	connections map[string]*UpstreamConnection // upstream pubkey -> connection
	connMu      sync.RWMutex
}

// NewClient creates a new proxy client
func NewClient(cfg *config.Config) *Client {
	return &Client{
		config:      cfg,
		connections: make(map[string]*UpstreamConnection),
	}
}

// Connect establishes a connection to an upstream signer
func (c *Client) Connect(ctx context.Context, bunkerURI string) (*UpstreamConnection, error) {
	// Parse the bunker URI
	uri, err := bunker.Parse(bunkerURI)
	if err != nil {
		return nil, fmt.Errorf("failed to parse bunker URI: %w", err)
	}

	// Check if we already have a connection
	c.connMu.RLock()
	existing, exists := c.connections[uri.SignerPubkey]
	c.connMu.RUnlock()
	if exists && existing.connected {
		return existing, nil
	}

	// Generate an ephemeral keypair for this connection
	localPrivkey := nostr.GeneratePrivateKey()
	localPubkey, err := nostr.GetPublicKey(localPrivkey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	if len(uri.Relays) == 0 {
		return nil, fmt.Errorf("bunker URI has no relays specified")
	}

	// Create connection context
	connCtx, cancel := context.WithCancel(ctx)

	conn := &UpstreamConnection{
		URI:          uri,
		LocalPrivkey: localPrivkey,
		LocalPubkey:  localPubkey,
		pending:      make(map[string]*pendingResponse),
		ctx:          connCtx,
		cancel:       cancel,
		useNIP44:     true, // Try NIP-44 first (modern standard)
	}

	// Connect to the first available relay
	var lastErr error
	for _, relayURL := range uri.Relays {
		relay, err := nostr.RelayConnect(connCtx, relayURL)
		if err != nil {
			lastErr = err
			slog.Warn("failed to connect to upstream relay", "relay", relayURL, "error", err)
			continue
		}
		conn.relay = relay
		break
	}

	if conn.relay == nil {
		cancel()
		return nil, fmt.Errorf("failed to connect to any upstream relay: %w", lastErr)
	}

	// Subscribe to responses from the upstream signer
	go conn.subscribeToResponses()

	conn.connected = true

	// Store the connection
	c.connMu.Lock()
	c.connections[uri.SignerPubkey] = conn
	c.connMu.Unlock()

	slog.Info("connected to upstream signer",
		"signer", uri.SignerPubkey[:16]+"...",
		"relay", conn.relay.URL,
		"local_pubkey", localPubkey[:16]+"...",
	)

	// Send connect request if we have a secret
	if uri.Secret != "" {
		_, err := conn.SendRequest(connCtx, "connect", []string{localPubkey, uri.Secret})
		if err != nil {
			slog.Warn("failed to send connect request", "error", err)
			// Don't fail - some signers don't require connect
		}
	}

	return conn, nil
}

// GetConnection returns an existing connection or creates a new one
func (c *Client) GetConnection(ctx context.Context, bunkerURI string) (*UpstreamConnection, error) {
	// Parse to get the pubkey
	uri, err := bunker.Parse(bunkerURI)
	if err != nil {
		return nil, err
	}

	c.connMu.RLock()
	conn, exists := c.connections[uri.SignerPubkey]
	c.connMu.RUnlock()

	if exists && conn.connected {
		return conn, nil
	}

	return c.Connect(ctx, bunkerURI)
}

// Disconnect closes a connection to an upstream signer
func (c *Client) Disconnect(upstreamPubkey string) {
	c.connMu.Lock()
	conn, exists := c.connections[upstreamPubkey]
	if exists {
		conn.Close()
		delete(c.connections, upstreamPubkey)
	}
	c.connMu.Unlock()
}

// Close closes all upstream connections
func (c *Client) Close() {
	c.connMu.Lock()
	defer c.connMu.Unlock()

	for _, conn := range c.connections {
		conn.Close()
	}
	c.connections = make(map[string]*UpstreamConnection)
}

// subscribeToResponses listens for NIP-46 responses from the upstream signer
func (conn *UpstreamConnection) subscribeToResponses() {
	filters := nostr.Filters{{
		Kinds:   []int{KindNIP46Response},
		Authors: []string{conn.URI.SignerPubkey},
		Tags:    nostr.TagMap{"p": []string{conn.LocalPubkey}},
	}}

	sub, err := conn.relay.Subscribe(conn.ctx, filters)
	if err != nil {
		slog.Error("failed to subscribe to upstream responses", "error", err)
		return
	}

	for {
		select {
		case event := <-sub.Events:
			conn.handleResponse(event)
		case <-conn.ctx.Done():
			sub.Unsub()
			return
		}
	}
}

// handleResponse processes a response from the upstream signer
func (conn *UpstreamConnection) handleResponse(event *nostr.Event) {
	// Try to decrypt the response
	var decrypted string
	var err error

	// Try NIP-44 first
	if conn.useNIP44 {
		conversationKey, kerr := nip44.GenerateConversationKey(conn.URI.SignerPubkey, conn.LocalPrivkey)
		if kerr == nil {
			decrypted, err = nip44.Decrypt(event.Content, conversationKey)
		}
	}

	// Fall back to NIP-04 if NIP-44 failed
	if decrypted == "" || err != nil {
		sharedSecret, serr := nip04.ComputeSharedSecret(conn.URI.SignerPubkey, conn.LocalPrivkey)
		if serr != nil {
			slog.Error("failed to compute shared secret for upstream response", "error", serr)
			return
		}
		decrypted, err = nip04.Decrypt(event.Content, sharedSecret)
		if err != nil {
			slog.Error("failed to decrypt upstream response", "error", err)
			return
		}
		// Mark that upstream uses NIP-04
		conn.useNIP44 = false
	}

	var response NIP46Response
	if err := json.Unmarshal([]byte(decrypted), &response); err != nil {
		slog.Error("failed to parse upstream response", "error", err)
		return
	}

	slog.Debug("received upstream response",
		"request_id", response.ID,
		"has_result", response.Result != "",
		"has_error", response.Error != "",
	)

	// Find and notify the waiting request
	conn.pendingMu.RLock()
	pending, exists := conn.pending[response.ID]
	conn.pendingMu.RUnlock()

	if exists {
		select {
		case pending.respChan <- &response:
		default:
			slog.Warn("response channel full", "request_id", response.ID)
		}
	} else {
		slog.Debug("no pending request for response", "request_id", response.ID)
	}
}

// SendRequest sends a NIP-46 request to the upstream signer and waits for a response
func (conn *UpstreamConnection) SendRequest(ctx context.Context, method string, params []string) (*NIP46Response, error) {
	timeout := 30 * time.Second // Default timeout

	// Generate a unique request ID
	requestID := generateRequestID()

	request := NIP46Request{
		ID:     requestID,
		Method: method,
		Params: params,
	}

	requestJSON, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Encrypt the request
	var encrypted string
	if conn.useNIP44 {
		conversationKey, err := nip44.GenerateConversationKey(conn.URI.SignerPubkey, conn.LocalPrivkey)
		if err != nil {
			return nil, fmt.Errorf("failed to generate conversation key: %w", err)
		}
		encrypted, err = nip44.Encrypt(string(requestJSON), conversationKey)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt request: %w", err)
		}
	} else {
		sharedSecret, err := nip04.ComputeSharedSecret(conn.URI.SignerPubkey, conn.LocalPrivkey)
		if err != nil {
			return nil, fmt.Errorf("failed to compute shared secret: %w", err)
		}
		encrypted, err = nip04.Encrypt(string(requestJSON), sharedSecret)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt request: %w", err)
		}
	}

	// Create the request event
	event := nostr.Event{
		Kind:      KindNIP46Request,
		Content:   encrypted,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags:      nostr.Tags{{"p", conn.URI.SignerPubkey}},
		PubKey:    conn.LocalPubkey,
	}

	if err := event.Sign(conn.LocalPrivkey); err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	// Register pending response
	pending := &pendingResponse{
		respChan: make(chan *NIP46Response, 1),
	}

	conn.pendingMu.Lock()
	conn.pending[requestID] = pending
	conn.pendingMu.Unlock()

	defer func() {
		conn.pendingMu.Lock()
		delete(conn.pending, requestID)
		conn.pendingMu.Unlock()
	}()

	// Publish the request
	if err := conn.relay.Publish(ctx, event); err != nil {
		return nil, fmt.Errorf("failed to publish request: %w", err)
	}

	slog.Info("sent request to upstream",
		"method", method,
		"request_id", requestID,
		"upstream", conn.URI.SignerPubkey[:16]+"...",
	)

	// Wait for response
	select {
	case response := <-pending.respChan:
		if response.Error != "" {
			return nil, fmt.Errorf("upstream error: %s", response.Error)
		}
		return response, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("upstream request timeout after %v", timeout)
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// SignEvent sends a sign_event request to the upstream signer
func (conn *UpstreamConnection) SignEvent(ctx context.Context, eventJSON string) (string, error) {
	response, err := conn.SendRequest(ctx, "sign_event", []string{eventJSON})
	if err != nil {
		return "", err
	}
	return response.Result, nil
}

// Encrypt sends an encryption request to the upstream signer (NIP-04 or NIP-44)
func (conn *UpstreamConnection) Encrypt(ctx context.Context, method, thirdPartyPubkey, plaintext string) (string, error) {
	response, err := conn.SendRequest(ctx, method, []string{thirdPartyPubkey, plaintext})
	if err != nil {
		return "", err
	}
	return response.Result, nil
}

// Decrypt sends a decryption request to the upstream signer (NIP-04 or NIP-44)
func (conn *UpstreamConnection) Decrypt(ctx context.Context, method, thirdPartyPubkey, ciphertext string) (string, error) {
	response, err := conn.SendRequest(ctx, method, []string{thirdPartyPubkey, ciphertext})
	if err != nil {
		return "", err
	}
	return response.Result, nil
}

// GetPublicKey gets the public key from the upstream signer
func (conn *UpstreamConnection) GetPublicKey(ctx context.Context) (string, error) {
	response, err := conn.SendRequest(ctx, "get_public_key", nil)
	if err != nil {
		return "", err
	}
	return response.Result, nil
}

// Close closes the connection to the upstream signer
func (conn *UpstreamConnection) Close() {
	if conn.cancel != nil {
		conn.cancel()
	}
	if conn.relay != nil {
		conn.relay.Close()
	}
	conn.connected = false
}

// generateRequestID generates a random request ID
func generateRequestID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
