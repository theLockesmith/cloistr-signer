package storage

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"git.coldforge.xyz/coldforge/cloistr-signer/internal/config"
)

var (
	ErrKeyNotFound      = errors.New("key not found")
	ErrKeyExists        = errors.New("key already exists")
	ErrNotAuthorized    = errors.New("not authorized")
	ErrSessionNotFound  = errors.New("session not found")
	ErrPolicyNotFound   = errors.New("policy not found")
	ErrTokenNotFound    = errors.New("token not found")
	ErrTokenExpired     = errors.New("token expired")
	ErrTokenRedeemed    = errors.New("token already redeemed")
	ErrRequestNotFound  = errors.New("request not found")
	ErrRequestExpired   = errors.New("request expired")
	ErrUserNotFound     = errors.New("user not found")
	ErrUserExists       = errors.New("user already exists")
	ErrInvalidPassword  = errors.New("invalid password")
	ErrAccountLocked    = errors.New("account locked")
	ErrMFARequired        = errors.New("MFA verification required")
	ErrInvalidMFACode     = errors.New("invalid MFA code")
	ErrBunkerSecretInvalid = errors.New("invalid bunker secret")
)

// Key represents a stored signing key
type Key struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	Pubkey          string    `json:"pubkey"`
	EncryptedNsec   string    `json:"-"` // Never exposed in JSON
	RequireApproval bool      `json:"require_approval"` // If true, requests need manual approval
	CreatedAt       time.Time `json:"created_at"`
	CreatedBy       string    `json:"created_by"`
}

// Permission defines what a user can do with a key
type Permission struct {
	KeyID           string     `json:"key_id"`
	UserPubkey      string     `json:"user_pubkey"`
	Methods         []string   `json:"methods"` // "sign_event", "encrypt", "decrypt", "ping", etc.
	AllowedKinds    []int      `json:"allowed_kinds,omitempty"` // Empty = all kinds
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	PolicyID        string     `json:"policy_id,omitempty"`        // Source policy for usage tracking
	RequireApproval *bool      `json:"require_approval,omitempty"` // Override key's default (nil = use key default)
}

// Session represents an active NIP-46 session
type Session struct {
	ID           string    `json:"id"`
	KeyID        string    `json:"key_id"`
	ClientPubkey string    `json:"client_pubkey"`
	Permissions  []string  `json:"permissions"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Policy defines a reusable permission template
type Policy struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description,omitempty"`
	Rules       []*PolicyRule `json:"rules"`
	ExpiresAt   *time.Time    `json:"expires_at,omitempty"`
	CreatedAt   time.Time     `json:"created_at"`
	CreatedBy   string        `json:"created_by,omitempty"`
}

// PolicyRule defines a single permission rule within a policy
type PolicyRule struct {
	ID           string `json:"id"`
	PolicyID     string `json:"policy_id"`
	Method       string `json:"method"` // "sign_event", "encrypt", "decrypt", "ping", "*"
	AllowedKinds []int  `json:"allowed_kinds,omitempty"`
	MaxUsage     int    `json:"max_usage,omitempty"`  // 0 = unlimited
	CurrentUsage int    `json:"current_usage"`
}

// Token represents a one-time redeemable access token
type Token struct {
	ID          string     `json:"id"`
	PolicyID    string     `json:"policy_id"`
	KeyID       string     `json:"key_id"` // Which key this token grants access to
	ClientName  string     `json:"client_name,omitempty"`
	CreatedBy   string     `json:"created_by,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	RedeemedAt  *time.Time `json:"redeemed_at,omitempty"`
	RedeemedBy  string     `json:"redeemed_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// PendingRequest represents a NIP-46 request awaiting authorization
type PendingRequest struct {
	ID           string                 `json:"id"`
	KeyPubkey    string                 `json:"key_pubkey"`
	ClientPubkey string                 `json:"client_pubkey"`
	Method       string                 `json:"method"`
	Params       map[string]interface{} `json:"params,omitempty"`
	EventKind    *int                   `json:"event_kind,omitempty"` // For sign_event requests
	ExpiresAt    time.Time              `json:"expires_at"`
	CreatedAt    time.Time              `json:"created_at"`
}

// User represents a registered user account
type User struct {
	ID                  string     `json:"id"`
	Username            string     `json:"username"`
	Email               string     `json:"email,omitempty"`
	Pubkey              string     `json:"pubkey,omitempty"`  // Nostr public key (hex)
	Role                string     `json:"role"`              // "admin" or "user"
	PasswordHash        string     `json:"-"`                 // Never exposed in JSON
	MFASecret           string     `json:"-"`                 // TOTP secret, never exposed
	MFAEnabled          bool       `json:"mfa_enabled"`
	BackupCodes         []string   `json:"-"`                 // Hashed backup codes
	BackupCodesUsed     int        `json:"backup_codes_used"`
	FailedLoginAttempts int        `json:"failed_login_attempts"`
	LockedUntil         *time.Time `json:"locked_until,omitempty"`
	LastLoginAt         *time.Time `json:"last_login_at,omitempty"`
	LastLoginIP         string     `json:"last_login_ip,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

// IsAdmin returns true if the user has admin role
func (u *User) IsAdmin() bool {
	return u.Role == "admin"
}

// UserSession represents an authenticated user session (JWT-based)
type UserSession struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Token     string    `json:"-"` // JWT token hash for revocation check
	UserAgent string    `json:"user_agent,omitempty"`
	IPAddress string    `json:"ip_address,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// BunkerSecret represents a secret for bunker:// URI validation
type BunkerSecret struct {
	ID        string    `json:"id"`
	KeyPubkey string    `json:"key_pubkey"` // The signer key this secret is for
	Secret    string    `json:"-"`          // The secret value (never exposed in JSON)
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"` // When the secret was used (one-time use)
}

// Storage interface for key and session management
type Storage interface {
	// Key management
	CreateKey(ctx context.Context, key *Key) error
	GetKey(ctx context.Context, id string) (*Key, error)
	GetKeyByPubkey(ctx context.Context, pubkey string) (*Key, error)
	GetKeyByName(ctx context.Context, name string) (*Key, error)
	ListKeys(ctx context.Context) ([]*Key, error)
	UpdateKey(ctx context.Context, key *Key) error
	DeleteKey(ctx context.Context, id string) error

	// Permission management
	SetPermission(ctx context.Context, perm *Permission) error
	GetPermission(ctx context.Context, keyID, userPubkey string) (*Permission, error)
	ListPermissions(ctx context.Context, keyID string) ([]*Permission, error)
	DeletePermission(ctx context.Context, keyID, userPubkey string) error

	// Session management
	CreateSession(ctx context.Context, session *Session) error
	GetSession(ctx context.Context, id string) (*Session, error)
	GetSessionByClient(ctx context.Context, keyID, clientPubkey string) (*Session, error)
	DeleteSession(ctx context.Context, id string) error
	CleanExpiredSessions(ctx context.Context) error

	// Policy management
	CreatePolicy(ctx context.Context, policy *Policy) error
	GetPolicy(ctx context.Context, id string) (*Policy, error)
	ListPolicies(ctx context.Context) ([]*Policy, error)
	DeletePolicy(ctx context.Context, id string) error
	IncrementRuleUsage(ctx context.Context, ruleID string) error

	// Token management
	CreateToken(ctx context.Context, token *Token) error
	GetToken(ctx context.Context, id string) (*Token, error)
	ListTokens(ctx context.Context, keyID string) ([]*Token, error)
	RedeemToken(ctx context.Context, tokenID, redeemerPubkey string) (*Token, error)
	DeleteToken(ctx context.Context, id string) error

	// Pending request management
	CreatePendingRequest(ctx context.Context, req *PendingRequest) error
	GetPendingRequest(ctx context.Context, id string) (*PendingRequest, error)
	ListPendingRequests(ctx context.Context, keyPubkey string) ([]*PendingRequest, error)
	DeletePendingRequest(ctx context.Context, id string) error
	CleanExpiredRequests(ctx context.Context) error

	// User management
	CreateUser(ctx context.Context, user *User) error
	GetUser(ctx context.Context, id string) (*User, error)
	GetUserByUsername(ctx context.Context, username string) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	GetUserByPubkey(ctx context.Context, pubkey string) (*User, error)
	ListUsers(ctx context.Context) ([]*User, error)
	UpdateUser(ctx context.Context, user *User) error
	DeleteUser(ctx context.Context, id string) error
	IncrementFailedLogins(ctx context.Context, userID string) error
	ResetFailedLogins(ctx context.Context, userID string) error
	LockUser(ctx context.Context, userID string, until time.Time) error
	UnlockUser(ctx context.Context, userID string) error

	// User session management
	CreateUserSession(ctx context.Context, session *UserSession) error
	GetUserSession(ctx context.Context, id string) (*UserSession, error)
	ListUserSessions(ctx context.Context, userID string) ([]*UserSession, error)
	DeleteUserSession(ctx context.Context, id string) error
	DeleteUserSessions(ctx context.Context, userID string) error
	CleanExpiredUserSessions(ctx context.Context) error

	// Bunker secret management
	CreateBunkerSecret(ctx context.Context, secret *BunkerSecret) error
	ValidateBunkerSecret(ctx context.Context, keyPubkey, secret string) (*BunkerSecret, error)
	DeleteBunkerSecret(ctx context.Context, id string) error
	CleanExpiredBunkerSecrets(ctx context.Context) error

	// Lifecycle
	Close() error
}

// New creates a new storage backend based on configuration
func New(cfg config.StorageConfig) (Storage, error) {
	switch cfg.Type {
	case "memory", "":
		return NewMemoryStorage(), nil
	case "postgres":
		if cfg.DSN == "" {
			return nil, fmt.Errorf("postgres storage requires DSN (DATABASE_URL)")
		}
		return NewPostgresStorage(cfg.DSN)
	case "sqlite":
		return nil, fmt.Errorf("sqlite storage not yet implemented")
	default:
		return nil, fmt.Errorf("unknown storage type: %s", cfg.Type)
	}
}

// MemoryStorage is an in-memory implementation for development/testing
type MemoryStorage struct {
	mu              sync.RWMutex
	keys            map[string]*Key
	keysByPubkey    map[string]*Key
	keysByName      map[string]*Key
	permissions     map[string]map[string]*Permission // keyID -> userPubkey -> Permission
	sessions        map[string]*Session
	policies        map[string]*Policy
	policyRules     map[string]*PolicyRule // ruleID -> PolicyRule
	tokens          map[string]*Token
	tokensByKey     map[string]map[string]*Token // keyID -> tokenID -> Token
	pendingRequests map[string]*PendingRequest
	users           map[string]*User
	usersByUsername map[string]*User
	usersByEmail    map[string]*User
	userSessions    map[string]*UserSession
	userSessionsByUser map[string]map[string]*UserSession // userID -> sessionID -> UserSession
	bunkerSecrets   map[string]*BunkerSecret              // secret value -> BunkerSecret
}

// NewMemoryStorage creates a new in-memory storage
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		keys:               make(map[string]*Key),
		keysByPubkey:       make(map[string]*Key),
		keysByName:         make(map[string]*Key),
		permissions:        make(map[string]map[string]*Permission),
		sessions:           make(map[string]*Session),
		policies:           make(map[string]*Policy),
		policyRules:        make(map[string]*PolicyRule),
		tokens:             make(map[string]*Token),
		tokensByKey:        make(map[string]map[string]*Token),
		pendingRequests:    make(map[string]*PendingRequest),
		users:              make(map[string]*User),
		usersByUsername:    make(map[string]*User),
		usersByEmail:       make(map[string]*User),
		userSessions:       make(map[string]*UserSession),
		userSessionsByUser: make(map[string]map[string]*UserSession),
		bunkerSecrets:      make(map[string]*BunkerSecret),
	}
}

func (m *MemoryStorage) CreateKey(ctx context.Context, key *Key) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.keys[key.ID]; exists {
		return ErrKeyExists
	}
	if _, exists := m.keysByPubkey[key.Pubkey]; exists {
		return ErrKeyExists
	}

	m.keys[key.ID] = key
	m.keysByPubkey[key.Pubkey] = key
	if key.Name != "" {
		m.keysByName[key.Name] = key
	}
	return nil
}

func (m *MemoryStorage) GetKey(ctx context.Context, id string) (*Key, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key, exists := m.keys[id]
	if !exists {
		return nil, ErrKeyNotFound
	}
	return key, nil
}

func (m *MemoryStorage) GetKeyByPubkey(ctx context.Context, pubkey string) (*Key, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key, exists := m.keysByPubkey[pubkey]
	if !exists {
		return nil, ErrKeyNotFound
	}
	return key, nil
}

func (m *MemoryStorage) GetKeyByName(ctx context.Context, name string) (*Key, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key, exists := m.keysByName[name]
	if !exists {
		return nil, ErrKeyNotFound
	}
	return key, nil
}

func (m *MemoryStorage) ListKeys(ctx context.Context) ([]*Key, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keys := make([]*Key, 0, len(m.keys))
	for _, key := range m.keys {
		keys = append(keys, key)
	}
	return keys, nil
}

func (m *MemoryStorage) UpdateKey(ctx context.Context, key *Key) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, exists := m.keys[key.ID]
	if !exists {
		return ErrKeyNotFound
	}

	// Handle name change
	if existing.Name != key.Name {
		if existing.Name != "" {
			delete(m.keysByName, existing.Name)
		}
		if key.Name != "" {
			m.keysByName[key.Name] = key
		}
	}

	m.keys[key.ID] = key
	m.keysByPubkey[key.Pubkey] = key
	return nil
}

func (m *MemoryStorage) DeleteKey(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key, exists := m.keys[id]
	if !exists {
		return ErrKeyNotFound
	}

	delete(m.keys, id)
	delete(m.keysByPubkey, key.Pubkey)
	if key.Name != "" {
		delete(m.keysByName, key.Name)
	}
	delete(m.permissions, id)
	return nil
}

func (m *MemoryStorage) SetPermission(ctx context.Context, perm *Permission) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// KeyID is the full pubkey, so check keysByPubkey
	if _, exists := m.keysByPubkey[perm.KeyID]; !exists {
		return ErrKeyNotFound
	}

	if m.permissions[perm.KeyID] == nil {
		m.permissions[perm.KeyID] = make(map[string]*Permission)
	}
	m.permissions[perm.KeyID][perm.UserPubkey] = perm
	return nil
}

func (m *MemoryStorage) GetPermission(ctx context.Context, keyID, userPubkey string) (*Permission, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	perms, exists := m.permissions[keyID]
	if !exists {
		return nil, ErrNotAuthorized
	}

	perm, exists := perms[userPubkey]
	if !exists {
		return nil, ErrNotAuthorized
	}

	if perm.ExpiresAt != nil && time.Now().After(*perm.ExpiresAt) {
		return nil, ErrNotAuthorized
	}

	return perm, nil
}

func (m *MemoryStorage) ListPermissions(ctx context.Context, keyID string) ([]*Permission, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	perms, exists := m.permissions[keyID]
	if !exists {
		return []*Permission{}, nil
	}

	result := make([]*Permission, 0, len(perms))
	for _, perm := range perms {
		result = append(result, perm)
	}
	return result, nil
}

func (m *MemoryStorage) DeletePermission(ctx context.Context, keyID, userPubkey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	perms, exists := m.permissions[keyID]
	if !exists {
		return nil
	}

	delete(perms, userPubkey)
	return nil
}

func (m *MemoryStorage) CreateSession(ctx context.Context, session *Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sessions[session.ID] = session
	return nil
}

func (m *MemoryStorage) GetSession(ctx context.Context, id string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.sessions[id]
	if !exists {
		return nil, ErrSessionNotFound
	}

	if time.Now().After(session.ExpiresAt) {
		return nil, ErrSessionNotFound
	}

	return session, nil
}

func (m *MemoryStorage) GetSessionByClient(ctx context.Context, keyID, clientPubkey string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, session := range m.sessions {
		if session.KeyID == keyID && session.ClientPubkey == clientPubkey {
			if time.Now().After(session.ExpiresAt) {
				continue
			}
			return session, nil
		}
	}
	return nil, ErrSessionNotFound
}

func (m *MemoryStorage) DeleteSession(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.sessions, id)
	return nil
}

func (m *MemoryStorage) CleanExpiredSessions(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for id, session := range m.sessions {
		if now.After(session.ExpiresAt) {
			delete(m.sessions, id)
		}
	}
	return nil
}

// Policy management

func (m *MemoryStorage) CreatePolicy(ctx context.Context, policy *Policy) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.policies[policy.ID] = policy
	for _, rule := range policy.Rules {
		m.policyRules[rule.ID] = rule
	}
	return nil
}

func (m *MemoryStorage) GetPolicy(ctx context.Context, id string) (*Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	policy, exists := m.policies[id]
	if !exists {
		return nil, ErrPolicyNotFound
	}

	if policy.ExpiresAt != nil && time.Now().After(*policy.ExpiresAt) {
		return nil, ErrPolicyNotFound
	}

	return policy, nil
}

func (m *MemoryStorage) ListPolicies(ctx context.Context) ([]*Policy, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	policies := make([]*Policy, 0, len(m.policies))
	now := time.Now()
	for _, policy := range m.policies {
		if policy.ExpiresAt == nil || now.Before(*policy.ExpiresAt) {
			policies = append(policies, policy)
		}
	}
	return policies, nil
}

func (m *MemoryStorage) DeletePolicy(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	policy, exists := m.policies[id]
	if !exists {
		return ErrPolicyNotFound
	}

	// Delete associated rules
	for _, rule := range policy.Rules {
		delete(m.policyRules, rule.ID)
	}
	delete(m.policies, id)
	return nil
}

func (m *MemoryStorage) IncrementRuleUsage(ctx context.Context, ruleID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	rule, exists := m.policyRules[ruleID]
	if !exists {
		return ErrPolicyNotFound
	}

	rule.CurrentUsage++
	return nil
}

// Token management

func (m *MemoryStorage) CreateToken(ctx context.Context, token *Token) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.tokens[token.ID] = token
	if m.tokensByKey[token.KeyID] == nil {
		m.tokensByKey[token.KeyID] = make(map[string]*Token)
	}
	m.tokensByKey[token.KeyID][token.ID] = token
	return nil
}

func (m *MemoryStorage) GetToken(ctx context.Context, id string) (*Token, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	token, exists := m.tokens[id]
	if !exists {
		return nil, ErrTokenNotFound
	}
	return token, nil
}

func (m *MemoryStorage) ListTokens(ctx context.Context, keyID string) ([]*Token, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keyTokens, exists := m.tokensByKey[keyID]
	if !exists {
		return []*Token{}, nil
	}

	tokens := make([]*Token, 0, len(keyTokens))
	for _, token := range keyTokens {
		tokens = append(tokens, token)
	}
	return tokens, nil
}

func (m *MemoryStorage) RedeemToken(ctx context.Context, tokenID, redeemerPubkey string) (*Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	token, exists := m.tokens[tokenID]
	if !exists {
		return nil, ErrTokenNotFound
	}

	if token.RedeemedAt != nil {
		return nil, ErrTokenRedeemed
	}

	if token.ExpiresAt != nil && time.Now().After(*token.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	now := time.Now()
	token.RedeemedAt = &now
	token.RedeemedBy = redeemerPubkey
	return token, nil
}

func (m *MemoryStorage) DeleteToken(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	token, exists := m.tokens[id]
	if !exists {
		return ErrTokenNotFound
	}

	delete(m.tokens, id)
	if keyTokens, exists := m.tokensByKey[token.KeyID]; exists {
		delete(keyTokens, id)
	}
	return nil
}

// Pending request management

func (m *MemoryStorage) CreatePendingRequest(ctx context.Context, req *PendingRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.pendingRequests[req.ID] = req
	return nil
}

func (m *MemoryStorage) GetPendingRequest(ctx context.Context, id string) (*PendingRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	req, exists := m.pendingRequests[id]
	if !exists {
		return nil, ErrRequestNotFound
	}

	if time.Now().After(req.ExpiresAt) {
		return nil, ErrRequestExpired
	}

	return req, nil
}

func (m *MemoryStorage) ListPendingRequests(ctx context.Context, keyPubkey string) ([]*PendingRequest, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	requests := make([]*PendingRequest, 0)
	now := time.Now()
	for _, req := range m.pendingRequests {
		if req.KeyPubkey == keyPubkey && now.Before(req.ExpiresAt) {
			requests = append(requests, req)
		}
	}
	return requests, nil
}

func (m *MemoryStorage) DeletePendingRequest(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	delete(m.pendingRequests, id)
	return nil
}

func (m *MemoryStorage) CleanExpiredRequests(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for id, req := range m.pendingRequests {
		if now.After(req.ExpiresAt) {
			delete(m.pendingRequests, id)
		}
	}
	return nil
}

// User management

func (m *MemoryStorage) CreateUser(ctx context.Context, user *User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.users[user.ID]; exists {
		return ErrUserExists
	}
	if _, exists := m.usersByUsername[user.Username]; exists {
		return ErrUserExists
	}
	if user.Email != "" {
		if _, exists := m.usersByEmail[user.Email]; exists {
			return ErrUserExists
		}
	}

	m.users[user.ID] = user
	m.usersByUsername[user.Username] = user
	if user.Email != "" {
		m.usersByEmail[user.Email] = user
	}
	return nil
}

func (m *MemoryStorage) GetUser(ctx context.Context, id string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	user, exists := m.users[id]
	if !exists {
		return nil, ErrUserNotFound
	}
	return user, nil
}

func (m *MemoryStorage) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	user, exists := m.usersByUsername[username]
	if !exists {
		return nil, ErrUserNotFound
	}
	return user, nil
}

func (m *MemoryStorage) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	user, exists := m.usersByEmail[email]
	if !exists {
		return nil, ErrUserNotFound
	}
	return user, nil
}

func (m *MemoryStorage) GetUserByPubkey(ctx context.Context, pubkey string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, user := range m.users {
		if user.Pubkey == pubkey {
			return user, nil
		}
	}
	return nil, ErrUserNotFound
}

func (m *MemoryStorage) ListUsers(ctx context.Context) ([]*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	users := make([]*User, 0, len(m.users))
	for _, user := range m.users {
		users = append(users, user)
	}
	return users, nil
}

func (m *MemoryStorage) UpdateUser(ctx context.Context, user *User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, exists := m.users[user.ID]
	if !exists {
		return ErrUserNotFound
	}

	// Handle username change
	if existing.Username != user.Username {
		delete(m.usersByUsername, existing.Username)
		m.usersByUsername[user.Username] = user
	}

	// Handle email change
	if existing.Email != user.Email {
		if existing.Email != "" {
			delete(m.usersByEmail, existing.Email)
		}
		if user.Email != "" {
			m.usersByEmail[user.Email] = user
		}
	}

	user.UpdatedAt = time.Now()
	m.users[user.ID] = user
	return nil
}

func (m *MemoryStorage) DeleteUser(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	user, exists := m.users[id]
	if !exists {
		return ErrUserNotFound
	}

	delete(m.users, id)
	delete(m.usersByUsername, user.Username)
	if user.Email != "" {
		delete(m.usersByEmail, user.Email)
	}

	// Delete user sessions
	if sessions, exists := m.userSessionsByUser[id]; exists {
		for sessionID := range sessions {
			delete(m.userSessions, sessionID)
		}
		delete(m.userSessionsByUser, id)
	}

	return nil
}

func (m *MemoryStorage) IncrementFailedLogins(ctx context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	user, exists := m.users[userID]
	if !exists {
		return ErrUserNotFound
	}

	user.FailedLoginAttempts++
	user.UpdatedAt = time.Now()
	return nil
}

func (m *MemoryStorage) ResetFailedLogins(ctx context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	user, exists := m.users[userID]
	if !exists {
		return ErrUserNotFound
	}

	user.FailedLoginAttempts = 0
	user.UpdatedAt = time.Now()
	return nil
}

func (m *MemoryStorage) LockUser(ctx context.Context, userID string, until time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	user, exists := m.users[userID]
	if !exists {
		return ErrUserNotFound
	}

	user.LockedUntil = &until
	user.UpdatedAt = time.Now()
	return nil
}

func (m *MemoryStorage) UnlockUser(ctx context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	user, exists := m.users[userID]
	if !exists {
		return ErrUserNotFound
	}

	user.LockedUntil = nil
	user.FailedLoginAttempts = 0
	user.UpdatedAt = time.Now()
	return nil
}

// User session management

func (m *MemoryStorage) CreateUserSession(ctx context.Context, session *UserSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.userSessions[session.ID] = session
	if m.userSessionsByUser[session.UserID] == nil {
		m.userSessionsByUser[session.UserID] = make(map[string]*UserSession)
	}
	m.userSessionsByUser[session.UserID][session.ID] = session
	return nil
}

func (m *MemoryStorage) GetUserSession(ctx context.Context, id string) (*UserSession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	session, exists := m.userSessions[id]
	if !exists {
		return nil, ErrSessionNotFound
	}

	if time.Now().After(session.ExpiresAt) {
		return nil, ErrSessionNotFound
	}

	return session, nil
}

func (m *MemoryStorage) ListUserSessions(ctx context.Context, userID string) ([]*UserSession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sessions := make([]*UserSession, 0)
	now := time.Now()
	if userSessions, exists := m.userSessionsByUser[userID]; exists {
		for _, session := range userSessions {
			if now.Before(session.ExpiresAt) {
				sessions = append(sessions, session)
			}
		}
	}
	return sessions, nil
}

func (m *MemoryStorage) DeleteUserSession(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.userSessions[id]
	if !exists {
		return nil
	}

	delete(m.userSessions, id)
	if userSessions, exists := m.userSessionsByUser[session.UserID]; exists {
		delete(userSessions, id)
	}
	return nil
}

func (m *MemoryStorage) DeleteUserSessions(ctx context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if sessions, exists := m.userSessionsByUser[userID]; exists {
		for sessionID := range sessions {
			delete(m.userSessions, sessionID)
		}
		delete(m.userSessionsByUser, userID)
	}
	return nil
}

func (m *MemoryStorage) CleanExpiredUserSessions(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for id, session := range m.userSessions {
		if now.After(session.ExpiresAt) {
			delete(m.userSessions, id)
			if userSessions, exists := m.userSessionsByUser[session.UserID]; exists {
				delete(userSessions, id)
			}
		}
	}
	return nil
}

// Bunker secret management

func (m *MemoryStorage) CreateBunkerSecret(ctx context.Context, secret *BunkerSecret) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.bunkerSecrets[secret.Secret] = secret
	return nil
}

func (m *MemoryStorage) ValidateBunkerSecret(ctx context.Context, keyPubkey, secret string) (*BunkerSecret, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	bs, exists := m.bunkerSecrets[secret]
	if !exists {
		return nil, ErrBunkerSecretInvalid
	}

	// Check if it's for the right key
	if bs.KeyPubkey != keyPubkey {
		return nil, ErrBunkerSecretInvalid
	}

	// Check if expired
	if time.Now().After(bs.ExpiresAt) {
		delete(m.bunkerSecrets, secret)
		return nil, ErrBunkerSecretInvalid
	}

	// Check if already used
	if bs.UsedAt != nil {
		return nil, ErrBunkerSecretInvalid
	}

	// Mark as used
	now := time.Now()
	bs.UsedAt = &now

	return bs, nil
}

func (m *MemoryStorage) DeleteBunkerSecret(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Find and delete by ID
	for secret, bs := range m.bunkerSecrets {
		if bs.ID == id {
			delete(m.bunkerSecrets, secret)
			return nil
		}
	}
	return nil
}

func (m *MemoryStorage) CleanExpiredBunkerSecrets(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for secret, bs := range m.bunkerSecrets {
		if now.After(bs.ExpiresAt) {
			delete(m.bunkerSecrets, secret)
		}
	}
	return nil
}

func (m *MemoryStorage) Close() error {
	return nil
}
