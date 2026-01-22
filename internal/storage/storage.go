package storage

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"gitlab.coldforge.xyz/coldforge/coldforge-signer/internal/config"
)

var (
	ErrKeyNotFound     = errors.New("key not found")
	ErrKeyExists       = errors.New("key already exists")
	ErrNotAuthorized   = errors.New("not authorized")
	ErrSessionNotFound = errors.New("session not found")
)

// Key represents a stored signing key
type Key struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Pubkey      string    `json:"pubkey"`
	EncryptedNsec string  `json:"-"` // Never exposed in JSON
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"`
}

// Permission defines what a user can do with a key
type Permission struct {
	KeyID       string   `json:"key_id"`
	UserPubkey  string   `json:"user_pubkey"`
	Methods     []string `json:"methods"` // "sign_event", "encrypt", "decrypt", "ping", etc.
	AllowedKinds []int   `json:"allowed_kinds,omitempty"` // Empty = all kinds
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// Session represents an active NIP-46 session
type Session struct {
	ID          string    `json:"id"`
	KeyID       string    `json:"key_id"`
	ClientPubkey string   `json:"client_pubkey"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

// Storage interface for key and session management
type Storage interface {
	// Key management
	CreateKey(ctx context.Context, key *Key) error
	GetKey(ctx context.Context, id string) (*Key, error)
	GetKeyByPubkey(ctx context.Context, pubkey string) (*Key, error)
	GetKeyByName(ctx context.Context, name string) (*Key, error)
	ListKeys(ctx context.Context) ([]*Key, error)
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

	// Lifecycle
	Close() error
}

// New creates a new storage backend based on configuration
func New(cfg config.StorageConfig) (Storage, error) {
	switch cfg.Type {
	case "memory", "":
		return NewMemoryStorage(), nil
	case "postgres":
		return nil, fmt.Errorf("postgres storage not yet implemented")
	case "sqlite":
		return nil, fmt.Errorf("sqlite storage not yet implemented")
	default:
		return nil, fmt.Errorf("unknown storage type: %s", cfg.Type)
	}
}

// MemoryStorage is an in-memory implementation for development/testing
type MemoryStorage struct {
	mu          sync.RWMutex
	keys        map[string]*Key
	keysByPubkey map[string]*Key
	keysByName  map[string]*Key
	permissions map[string]map[string]*Permission // keyID -> userPubkey -> Permission
	sessions    map[string]*Session
}

// NewMemoryStorage creates a new in-memory storage
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		keys:        make(map[string]*Key),
		keysByPubkey: make(map[string]*Key),
		keysByName:  make(map[string]*Key),
		permissions: make(map[string]map[string]*Permission),
		sessions:    make(map[string]*Session),
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

	if _, exists := m.keys[perm.KeyID]; !exists {
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

func (m *MemoryStorage) Close() error {
	return nil
}
