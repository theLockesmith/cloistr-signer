package admin

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"git.coldforge.xyz/coldforge/cloistr-signer/internal/config"
	relay "git.coldforge.xyz/coldforge/cloistr-signer/internal/nostr"
	"git.coldforge.xyz/coldforge/cloistr-signer/internal/storage"
)

const (
	KindEncryptedDM = 4
)

// KeyCreator is an interface for creating and registering keys
type KeyCreator interface {
	RegisterKey(pubkey, privateKeyHex string)
}

// RequestHandler is an interface for handling pending requests
type RequestHandler interface {
	ApproveRequest(requestID string, pendingReq *storage.PendingRequest)
	DenyRequest(requestID string, pendingReq *storage.PendingRequest)
	GetStatus() map[string]interface{}
}

// Handler processes admin commands received via Nostr DMs
type Handler struct {
	config       *config.Config
	storage      storage.Storage
	relayClient  *relay.Client
	keyCreator   KeyCreator
	reqHandler   RequestHandler
	signerPubkey string // The pubkey to use for sending DMs
	signerPriv   string // The private key for signing/encrypting
}

// New creates a new admin handler
func New(cfg *config.Config, store storage.Storage, relayClient *relay.Client, keyCreator KeyCreator, reqHandler RequestHandler) *Handler {
	return &Handler{
		config:      cfg,
		storage:     store,
		relayClient: relayClient,
		keyCreator:  keyCreator,
		reqHandler:  reqHandler,
	}
}

// SetSignerKey sets the key to use for admin communications
func (h *Handler) SetSignerKey(pubkey, privateKey string) {
	h.signerPubkey = pubkey
	h.signerPriv = privateKey
}

// Start begins listening for admin DM commands
func (h *Handler) Start(ctx context.Context) error {
	if len(h.config.Auth.AdminPubkeys) == 0 {
		slog.Info("no admin pubkeys configured, admin DM interface disabled")
		return nil
	}

	if h.signerPubkey == "" {
		slog.Warn("no signer key set for admin handler, will use first available key")
	}

	// Subscribe to DMs addressed to our keys from admin pubkeys
	filters := nostr.Filters{{
		Kinds:   []int{KindEncryptedDM},
		Authors: h.config.Auth.AdminPubkeys,
	}}

	slog.Info("subscribing to admin DM commands", "admin_count", len(h.config.Auth.AdminPubkeys))

	go h.relayClient.SubscribeWithReconnect(ctx, filters, h.handleEvent)

	return nil
}

// SendBootNotification sends a notification to all admins that the signer has started
func (h *Handler) SendBootNotification(ctx context.Context) {
	if len(h.config.Auth.AdminPubkeys) == 0 || h.signerPubkey == "" {
		return
	}

	// Get status info
	status := h.reqHandler.GetStatus()
	keysLoaded := 0
	if kl, ok := status["keys_loaded"].(int); ok {
		keysLoaded = kl
	}
	relays := []string{}
	if rl, ok := status["connected_relays"].([]string); ok {
		relays = rl
	}

	message := fmt.Sprintf(`🚀 Coldforge Signer Started

Time: %s
Keys Loaded: %d
Connected Relays: %d
%s

Available commands:
• help - Show all commands
• status - Get current status
• get_keys - List all keys
• list_pending - Show pending requests`,
		time.Now().UTC().Format(time.RFC3339),
		keysLoaded,
		len(relays),
		strings.Join(relays, "\n"),
	)

	h.broadcastToAdmins(ctx, message)
}

// handleEvent processes incoming DM events from admins
func (h *Handler) handleEvent(event *nostr.Event) {
	if event.Kind != KindEncryptedDM {
		return
	}

	// Ignore messages from our own pubkey (prevents loops)
	if event.PubKey == h.signerPubkey {
		return
	}

	// Verify sender is an admin
	if !h.isAdmin(event.PubKey) {
		slog.Debug("ignoring DM from non-admin", "pubkey", event.PubKey[:16]+"...")
		return
	}

	// Find which of our keys this is addressed to
	targetPubkey := ""
	for _, tag := range event.Tags {
		if len(tag) >= 2 && tag[0] == "p" {
			targetPubkey = tag[1]
			break
		}
	}

	if targetPubkey == "" {
		return
	}

	// Use the signer key if set, otherwise we need to find the key
	privateKey := h.signerPriv
	signerPubkey := h.signerPubkey

	if privateKey == "" {
		slog.Warn("no private key available for admin response")
		return
	}

	// Decrypt the message
	sharedSecret, err := nip04.ComputeSharedSecret(event.PubKey, privateKey)
	if err != nil {
		slog.Error("failed to compute shared secret for admin DM", "error", err)
		return
	}

	decrypted, err := nip04.Decrypt(event.Content, sharedSecret)
	if err != nil {
		slog.Error("failed to decrypt admin DM", "error", err)
		return
	}

	slog.Info("received admin command",
		"from", event.PubKey[:16]+"...",
		"command", truncate(decrypted, 50),
	)

	// Process command
	ctx := context.Background()
	response := h.processCommand(ctx, decrypted)

	// Send response
	h.sendDM(ctx, signerPubkey, privateKey, event.PubKey, response)
}

// processCommand parses and executes an admin command
func (h *Handler) processCommand(ctx context.Context, command string) string {
	command = strings.TrimSpace(command)
	parts := strings.Fields(command)

	if len(parts) == 0 {
		return h.helpMessage()
	}

	cmd := strings.ToLower(parts[0])
	args := parts[1:]

	switch cmd {
	case "help", "?":
		return h.helpMessage()

	case "status":
		return h.cmdStatus(ctx)

	case "get_keys", "keys", "list_keys":
		return h.cmdGetKeys(ctx)

	case "get_key":
		if len(args) < 1 {
			return "Usage: get_key <id>"
		}
		return h.cmdGetKey(ctx, args[0])

	case "create_key":
		name := "admin-created"
		if len(args) > 0 {
			name = strings.Join(args, " ")
		}
		return h.cmdCreateKey(ctx, name)

	case "delete_key":
		if len(args) < 1 {
			return "Usage: delete_key <id>"
		}
		return h.cmdDeleteKey(ctx, args[0])

	case "list_pending", "pending":
		return h.cmdListPending(ctx)

	case "approve":
		if len(args) < 1 {
			return "Usage: approve <request_id>"
		}
		return h.cmdApprove(ctx, args[0])

	case "deny":
		if len(args) < 1 {
			return "Usage: deny <request_id>"
		}
		return h.cmdDeny(ctx, args[0])

	case "list_users", "users":
		return h.cmdListUsers(ctx)

	case "list_policies", "policies":
		return h.cmdListPolicies(ctx)

	default:
		return fmt.Sprintf("Unknown command: %s\n\nType 'help' for available commands.", cmd)
	}
}

func (h *Handler) helpMessage() string {
	return `📋 Coldforge Signer Admin Commands

Key Management:
  get_keys         - List all signing keys
  get_key <id>     - Get key details
  create_key [name] - Create a new key
  delete_key <id>  - Delete a key

Authorization:
  list_pending     - List pending authorization requests
  approve <id>     - Approve a pending request
  deny <id>        - Deny a pending request

Users & Policies:
  list_users       - List registered users
  list_policies    - List permission policies

System:
  status           - Get signer status
  help             - Show this message`
}

func (h *Handler) cmdStatus(ctx context.Context) string {
	status := h.reqHandler.GetStatus()

	keysLoaded := 0
	if kl, ok := status["keys_loaded"].(int); ok {
		keysLoaded = kl
	}

	relays := []string{}
	if rl, ok := status["connected_relays"].([]string); ok {
		relays = rl
	}

	// Get counts from storage
	keys, _ := h.storage.ListKeys(ctx)
	users, _ := h.storage.ListUsers(ctx)
	policies, _ := h.storage.ListPolicies(ctx)

	return fmt.Sprintf(`📊 Signer Status

Keys: %d loaded / %d stored
Users: %d registered
Policies: %d defined
Relays: %d connected

Connected Relays:
%s`,
		keysLoaded, len(keys),
		len(users),
		len(policies),
		len(relays),
		"• "+strings.Join(relays, "\n• "),
	)
}

func (h *Handler) cmdGetKeys(ctx context.Context) string {
	keys, err := h.storage.ListKeys(ctx)
	if err != nil {
		return fmt.Sprintf("Error: %v", err)
	}

	if len(keys) == 0 {
		return "No keys found. Use 'create_key <name>' to create one."
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("🔑 Keys (%d):\n\n", len(keys)))

	for _, key := range keys {
		sb.WriteString(fmt.Sprintf("• %s\n  ID: %s\n  Pubkey: %s\n  Created: %s\n\n",
			key.Name,
			key.ID,
			key.Pubkey[:16]+"..."+key.Pubkey[len(key.Pubkey)-8:],
			key.CreatedAt.Format("2006-01-02 15:04"),
		))
	}

	return sb.String()
}

func (h *Handler) cmdGetKey(ctx context.Context, id string) string {
	key, err := h.storage.GetKey(ctx, id)
	if err != nil {
		if err == storage.ErrKeyNotFound {
			return fmt.Sprintf("Key not found: %s", id)
		}
		return fmt.Sprintf("Error: %v", err)
	}

	// Get permissions for this key
	perms, _ := h.storage.ListPermissions(ctx, key.Pubkey)

	return fmt.Sprintf(`🔑 Key: %s

ID: %s
Pubkey: %s
Created: %s
Permissions: %d clients authorized`,
		key.Name,
		key.ID,
		key.Pubkey,
		key.CreatedAt.Format("2006-01-02 15:04:05"),
		len(perms),
	)
}

func (h *Handler) cmdCreateKey(ctx context.Context, name string) string {
	// Generate new keypair
	privateKey := nostr.GeneratePrivateKey()
	pubkey, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		return fmt.Sprintf("Error generating key: %v", err)
	}

	key := &storage.Key{
		ID:            pubkey[:16],
		Name:          name,
		Pubkey:        pubkey,
		EncryptedNsec: privateKey, // TODO: Encrypt with Vault
		CreatedAt:     time.Now(),
	}

	if err := h.storage.CreateKey(ctx, key); err != nil {
		return fmt.Sprintf("Error creating key: %v", err)
	}

	// Register with signer for immediate use
	h.keyCreator.RegisterKey(pubkey, privateKey)

	slog.Info("admin created key", "name", name, "pubkey", pubkey[:16]+"...")

	return fmt.Sprintf(`✅ Key Created

Name: %s
ID: %s
Pubkey: %s

The key is now active and ready for NIP-46 requests.`,
		name,
		key.ID,
		pubkey,
	)
}

func (h *Handler) cmdDeleteKey(ctx context.Context, id string) string {
	// Get key first to confirm it exists
	key, err := h.storage.GetKey(ctx, id)
	if err != nil {
		if err == storage.ErrKeyNotFound {
			return fmt.Sprintf("Key not found: %s", id)
		}
		return fmt.Sprintf("Error: %v", err)
	}

	if err := h.storage.DeleteKey(ctx, id); err != nil {
		return fmt.Sprintf("Error deleting key: %v", err)
	}

	slog.Info("admin deleted key", "id", id, "name", key.Name)

	return fmt.Sprintf("✅ Key deleted: %s (%s)", key.Name, id)
}

func (h *Handler) cmdListPending(ctx context.Context) string {
	// Get all keys and list pending requests for each
	keys, err := h.storage.ListKeys(ctx)
	if err != nil {
		return fmt.Sprintf("Error: %v", err)
	}

	var allPending []*storage.PendingRequest
	for _, key := range keys {
		pending, _ := h.storage.ListPendingRequests(ctx, key.Pubkey)
		allPending = append(allPending, pending...)
	}

	if len(allPending) == 0 {
		return "No pending authorization requests."
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("⏳ Pending Requests (%d):\n\n", len(allPending)))

	for _, req := range allPending {
		kindInfo := ""
		if req.EventKind != nil {
			kindInfo = fmt.Sprintf(" (kind:%d)", *req.EventKind)
		}

		sb.WriteString(fmt.Sprintf("• ID: %s\n  Method: %s%s\n  Client: %s\n  Key: %s\n  Expires: %s\n\n",
			req.ID,
			req.Method,
			kindInfo,
			req.ClientPubkey[:16]+"...",
			req.KeyPubkey[:16]+"...",
			req.ExpiresAt.Format("15:04:05"),
		))
	}

	sb.WriteString("Use 'approve <id>' or 'deny <id>' to respond.")

	return sb.String()
}

func (h *Handler) cmdApprove(ctx context.Context, requestID string) string {
	req, err := h.storage.GetPendingRequest(ctx, requestID)
	if err != nil {
		if err == storage.ErrRequestNotFound || err == storage.ErrRequestExpired {
			return fmt.Sprintf("Request not found or expired: %s", requestID)
		}
		return fmt.Sprintf("Error: %v", err)
	}

	// Delete from storage
	_ = h.storage.DeletePendingRequest(ctx, requestID)

	// Notify the signer to process approval
	h.reqHandler.ApproveRequest(requestID, req)

	slog.Info("admin approved request", "id", requestID, "method", req.Method)

	return fmt.Sprintf("✅ Request approved: %s\nMethod: %s\nClient: %s",
		requestID,
		req.Method,
		req.ClientPubkey[:16]+"...",
	)
}

func (h *Handler) cmdDeny(ctx context.Context, requestID string) string {
	req, err := h.storage.GetPendingRequest(ctx, requestID)
	if err != nil {
		if err == storage.ErrRequestNotFound || err == storage.ErrRequestExpired {
			return fmt.Sprintf("Request not found or expired: %s", requestID)
		}
		return fmt.Sprintf("Error: %v", err)
	}

	// Delete from storage
	_ = h.storage.DeletePendingRequest(ctx, requestID)

	// Notify the signer to deny
	h.reqHandler.DenyRequest(requestID, req)

	slog.Info("admin denied request", "id", requestID, "method", req.Method)

	return fmt.Sprintf("❌ Request denied: %s\nMethod: %s\nClient: %s",
		requestID,
		req.Method,
		req.ClientPubkey[:16]+"...",
	)
}

func (h *Handler) cmdListUsers(ctx context.Context) string {
	users, err := h.storage.ListUsers(ctx)
	if err != nil {
		return fmt.Sprintf("Error: %v", err)
	}

	if len(users) == 0 {
		return "No users registered."
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("👥 Users (%d):\n\n", len(users)))

	for _, user := range users {
		mfaStatus := "❌"
		if user.MFAEnabled {
			mfaStatus = "✅"
		}

		sb.WriteString(fmt.Sprintf("• %s\n  ID: %s\n  Email: %s\n  MFA: %s\n  Created: %s\n\n",
			user.Username,
			user.ID[:16]+"...",
			user.Email,
			mfaStatus,
			user.CreatedAt.Format("2006-01-02"),
		))
	}

	return sb.String()
}

func (h *Handler) cmdListPolicies(ctx context.Context) string {
	policies, err := h.storage.ListPolicies(ctx)
	if err != nil {
		return fmt.Sprintf("Error: %v", err)
	}

	if len(policies) == 0 {
		return "No policies defined."
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("📜 Policies (%d):\n\n", len(policies)))

	for _, p := range policies {
		methods := make([]string, len(p.Rules))
		for i, r := range p.Rules {
			methods[i] = r.Method
		}

		sb.WriteString(fmt.Sprintf("• %s\n  ID: %s\n  Methods: %s\n  Created: %s\n\n",
			p.Name,
			p.ID,
			strings.Join(methods, ", "),
			p.CreatedAt.Format("2006-01-02"),
		))
	}

	return sb.String()
}

// sendDM sends an encrypted DM to a pubkey
func (h *Handler) sendDM(ctx context.Context, signerPubkey, privateKey, recipientPubkey, message string) {
	sharedSecret, err := nip04.ComputeSharedSecret(recipientPubkey, privateKey)
	if err != nil {
		slog.Error("failed to compute shared secret for DM", "error", err)
		return
	}

	encrypted, err := nip04.Encrypt(message, sharedSecret)
	if err != nil {
		slog.Error("failed to encrypt DM", "error", err)
		return
	}

	event := nostr.Event{
		Kind:      KindEncryptedDM,
		Content:   encrypted,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Tags:      nostr.Tags{{"p", recipientPubkey}},
		PubKey:    signerPubkey,
	}

	if err := event.Sign(privateKey); err != nil {
		slog.Error("failed to sign DM", "error", err)
		return
	}

	// Use adaptive POW in case relay requires it
	if err := h.relayClient.PublishWithAdaptivePow(ctx, &event, privateKey); err != nil {
		slog.Error("failed to publish DM", "error", err)
		return
	}

	slog.Debug("sent admin DM response", "to", recipientPubkey[:16]+"...")
}

// broadcastToAdmins sends a message to all admin pubkeys
func (h *Handler) broadcastToAdmins(ctx context.Context, message string) {
	if h.signerPubkey == "" || h.signerPriv == "" {
		slog.Warn("cannot broadcast to admins: no signer key configured")
		return
	}

	for _, adminPubkey := range h.config.Auth.AdminPubkeys {
		if adminPubkey == "" {
			continue
		}
		h.sendDM(ctx, h.signerPubkey, h.signerPriv, adminPubkey, message)
	}
}

// isAdmin checks if a pubkey is in the admin list
func (h *Handler) isAdmin(pubkey string) bool {
	for _, admin := range h.config.Auth.AdminPubkeys {
		if admin == pubkey {
			return true
		}
	}
	return false
}

// truncate truncates a string to maxLen characters
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// AdminResponse is returned when processing commands via HTTP
type AdminResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// ProcessCommandHTTP processes a command and returns structured response
func (h *Handler) ProcessCommandHTTP(ctx context.Context, command string) AdminResponse {
	response := h.processCommand(ctx, command)
	return AdminResponse{
		Success: !strings.HasPrefix(response, "Error") && !strings.HasPrefix(response, "Unknown"),
		Message: response,
	}
}

// GetAdminStats returns admin-level statistics
func (h *Handler) GetAdminStats(ctx context.Context) (map[string]interface{}, error) {
	keys, err := h.storage.ListKeys(ctx)
	if err != nil {
		return nil, err
	}

	users, err := h.storage.ListUsers(ctx)
	if err != nil {
		return nil, err
	}

	policies, err := h.storage.ListPolicies(ctx)
	if err != nil {
		return nil, err
	}

	// Count pending requests
	pendingCount := 0
	for _, key := range keys {
		pending, _ := h.storage.ListPendingRequests(ctx, key.Pubkey)
		pendingCount += len(pending)
	}

	status := h.reqHandler.GetStatus()

	stats := map[string]interface{}{
		"keys_count":            len(keys),
		"users_count":           len(users),
		"policies_count":        len(policies),
		"pending_requests":      pendingCount,
		"admin_pubkeys":         len(h.config.Auth.AdminPubkeys),
		"connected_relays":      status["connected_relays"],
		"keys_loaded":           status["keys_loaded"],
		"require_approval":      h.config.Auth.RequireApproval,
		"authorization_timeout": h.config.Auth.AuthorizationTimeout,
	}

	return stats, nil
}
