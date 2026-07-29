package storage

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/config"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/crypto"
	"github.com/nbd-wtf/go-nostr"
)

var (
	ErrKeyNotFound          = errors.New("key not found")
	ErrKeyExists            = errors.New("key already exists")
	ErrNotAuthorized        = errors.New("not authorized")
	ErrSessionNotFound      = errors.New("session not found")
	ErrPolicyNotFound       = errors.New("policy not found")
	ErrTokenNotFound        = errors.New("token not found")
	ErrTokenExpired         = errors.New("token expired")
	ErrTokenRedeemed        = errors.New("token already redeemed")
	ErrRequestNotFound      = errors.New("request not found")
	ErrRequestExpired       = errors.New("request expired")
	ErrUserNotFound         = errors.New("user not found")
	ErrUserExists           = errors.New("user already exists")
	ErrInvalidPassword      = errors.New("invalid password")
	ErrAccountLocked        = errors.New("account locked")
	ErrMFARequired          = errors.New("MFA verification required")
	ErrInvalidMFACode       = errors.New("invalid MFA code")
	ErrBunkerSecretInvalid  = errors.New("invalid bunker secret")
	ErrSettingNotFound      = errors.New("setting not found")
	ErrConsentNotFound      = errors.New("app consent not found")
	ErrLightningKeyNotFound = errors.New("lightning key not found")
	ErrLightningKeyExists   = errors.New("lightning key already exists")
)

// KeyType represents the type of key storage
const (
	KeyTypeLocal     = "local"      // Key is stored locally (has EncryptedNsec)
	KeyTypeProxy     = "proxy"      // Key is proxied to upstream signer (has BunkerURI)
	KeyTypeFrostUser = "frost-user" // Key is FROST 2-of-N: signer holds one share, user device(s) hold the others. No full nsec exists anywhere. See docs/frost-2-of-n-design.md.
)

// Key represents a stored signing key
type Key struct {
	ID               string    `json:"id"`
	Name             string    `json:"name"`
	Pubkey           string    `json:"pubkey"`
	KeyType          string    `json:"key_type"`                  // "local" or "proxy" (default: local)
	EncryptedNsec    string    `json:"-"`                         // For local keys: never exposed in JSON
	EncryptionMethod string    `json:"-"`                         // "local" (AES-GCM) or "vault" (Vault transit)
	BunkerURI        string    `json:"-"`                         // For proxy keys: bunker:// URI to upstream signer
	UpstreamPubkey   string    `json:"upstream_pubkey,omitempty"` // For proxy keys: pubkey of the upstream signer
	RequireApproval  bool      `json:"require_approval"`          // If true, requests need manual approval
	DisposableMode   bool      `json:"disposable_mode"`           // If true, signer enforces privacy guardrails: refuses identity-linking kinds (0/3/10002), refuses NIP-04 encrypt, strips client tags, jitters response timing
	CoverTraffic     bool      `json:"cover_traffic"`             // If true, signer emits ephemeral NIP-17 gift-wrap decoys to this key's relays at randomized intervals to mask online/offline presence (privacy-architecture §3.11 paid-tier behavior)
	TorEgress        bool      `json:"tor_egress"`                // If true, signer routes outbound relay connections for this key through the configured Tor SOCKS5 proxy (privacy-architecture §3.10)
	Relays           []string  `json:"relays,omitempty"`          // Custom relays for this key (nil = use global config)
	RelayMode        string    `json:"relay_mode,omitempty"`      // Relay selection: "auto", "manual", "discovery"
	CreatedAt        time.Time `json:"created_at"`
	CreatedBy        string    `json:"created_by"`
	OwnerID          string    `json:"owner_id"` // User who owns this key (for multi-user isolation)

	// IsPrimary marks this key as the account's identity key: the pubkey that
	// IS the user on the platform (Option A), and the only key accepted as
	// proof in nsec password recovery.
	//
	// This used to be inferred from Name == "Primary". Name is a display
	// string the user can edit freely, so renaming a key silently moved the
	// account identity and the recovery anchor, and nothing stopped two keys
	// from claiming it. At most one key per owner may have this set --
	// enforced by a partial unique index, not just by convention.
	IsPrimary bool `json:"is_primary"`
}

// IsProxy returns true if this is a proxy key
func (k *Key) IsProxy() bool {
	return k.KeyType == KeyTypeProxy
}

// Permission defines what a user can do with a key
type Permission struct {
	KeyID           string     `json:"key_id"`
	UserPubkey      string     `json:"user_pubkey"`
	Methods         []string   `json:"methods"`                 // "sign_event", "encrypt", "decrypt", "ping", etc.
	AllowedKinds    []int      `json:"allowed_kinds,omitempty"` // Empty = all kinds
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	PolicyID        string     `json:"policy_id,omitempty"`        // Source policy for usage tracking
	RequireApproval *bool      `json:"require_approval,omitempty"` // Override key's default (nil = use key default)
	DelegatePubkey  string     `json:"delegate_pubkey,omitempty"`  // Original requester in proxy chain (for audit)
	// App metadata - populated from nostrconnect:// URI or connect request
	AppName    string     `json:"app_name,omitempty"`
	AppURL     string     `json:"app_url,omitempty"`
	AppImage   string     `json:"app_image,omitempty"`
	CustomName string     `json:"custom_name,omitempty"` // User-defined label (overrides AppName in display)
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// Session represents an active NIP-46 session
type Session struct {
	ID           string    `json:"id"`
	KeyID        string    `json:"key_id"`
	ClientPubkey string    `json:"client_pubkey"`
	Permissions  []string  `json:"permissions"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	// VaultToken (P4d) is the user's Vault transit token, copied from
	// their web-UI session at NIP-46 connection time. Needed to
	// decrypt FROST shares when a FROST-key sign_event arrives on
	// this session. Empty for sessions created without an active
	// web-UI login (e.g. bunker URI flow); FROST-key sign requests on
	// such sessions error with "connect via web UI for FROST".
	VaultToken string `json:"-"`
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
	MaxUsage     int    `json:"max_usage,omitempty"` // 0 = unlimited
	CurrentUsage int    `json:"current_usage"`
}

// Token represents a one-time redeemable access token
type Token struct {
	ID         string     `json:"id"`
	PolicyID   string     `json:"policy_id"`
	KeyID      string     `json:"key_id"` // Which key this token grants access to
	ClientName string     `json:"client_name,omitempty"`
	CreatedBy  string     `json:"created_by,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	RedeemedAt *time.Time `json:"redeemed_at,omitempty"`
	RedeemedBy string     `json:"redeemed_by,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
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
	Pubkey              string     `json:"pubkey,omitempty"` // Nostr public key (hex)
	Role                string     `json:"role"`             // "admin" or "user"
	PasswordHash        string     `json:"-"`                // Never exposed in JSON
	MFASecret           string     `json:"-"`                // TOTP secret, never exposed
	MFAEnabled          bool       `json:"mfa_enabled"`
	BackupCodes         []string   `json:"-"` // Hashed backup codes
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

// PlatformUser represents a user in the cloistr platform with service access info
type PlatformUser struct {
	Pubkey    string          `json:"pubkey"`
	Enabled   bool            `json:"enabled"`
	Services  []ServiceAccess `json:"services"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// ServiceAccess represents a user's access to a service
type ServiceAccess struct {
	ServiceID   string    `json:"service_id"`
	ServiceSlug string    `json:"service_slug"`
	ServiceName string    `json:"service_name"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
}

// Service represents a service in the platform
type Service struct {
	ID          string `json:"id"`
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	IsFree      bool   `json:"is_free"`
}

// UserSession represents an authenticated user session (JWT-based)
type UserSession struct {
	ID         string `json:"id"`
	UserID     string `json:"user_id"`
	Token      string `json:"-"` // JWT token hash for revocation check
	VaultToken string `json:"-"` // User's Vault token for key operations (encrypted at rest)
	// P4e: browser-side cosign listener's ephemeral pubkey. Populated
	// via POST /api/v1/frost/cosign-listener/register when the SPA
	// starts up. Read at FROST-key sign_event time to determine the
	// p-tag on outgoing kind:24135 requests. Empty for sessions that
	// haven't registered yet.
	CosignListenerPubkey string     `json:"-"`
	UserAgent            string     `json:"user_agent,omitempty"`
	IPAddress            string     `json:"ip_address,omitempty"`
	RememberDevice       bool       `json:"remember_device"`         // If true, use extended expiry instead of inactivity timeout
	LastActivity         *time.Time `json:"last_activity,omitempty"` // Last request time for inactivity tracking
	ExpiresAt            time.Time  `json:"expires_at"`              // Absolute expiry (30 days for remember, or max session length)
	CreatedAt            time.Time  `json:"created_at"`
}

// AppConsent records that a user has approved a cross-subdomain nostrconnect
// from a specific app (identified by its client pubkey). Once recorded, the
// signer auto-approves subsequent connections without prompting the user again.
// See unified-auth-design §5 ("first-time consent then silent").
type AppConsent struct {
	UserID     string    `json:"user_id"`
	AppID      string    `json:"app_id"` // nostrconnect client pubkey
	AppName    string    `json:"app_name,omitempty"`
	ApprovedAt time.Time `json:"approved_at"`
}

// PasskeyCredential represents a stored WebAuthn/passkey credential for a user.
// Corresponds to the signer_passkey_credentials table.
type PasskeyCredential struct {
	ID           string     `json:"id"`
	UserID       string     `json:"user_id"`
	CredentialID []byte     `json:"-"`
	PublicKey    []byte     `json:"-"`
	AAGUID       []byte     `json:"-"`
	SignCount    uint32     `json:"sign_count"`
	Transport    []string   `json:"transport,omitempty"`
	Name         string     `json:"name"`
	CreatedAt    time.Time  `json:"created_at"`
	LastUsedAt   *time.Time `json:"last_used_at,omitempty"`
}

// WebAuthnSession holds gob-encoded go-webauthn SessionData for an in-flight
// ceremony. user_id is NULL for discoverable (usernameless) login sessions.
// Corresponds to the signer_webauthn_sessions table.
type WebAuthnSession struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id,omitempty"` // empty for discoverable sessions
	Data      []byte    `json:"-"`                 // gob-encoded webauthn.SessionData
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// RecoveryChallenge is a single-use, expiring nonce the user signs with their
// Nostr key to prove key possession during account recovery.
//
// The challenge is server-issued rather than client-supplied on purpose. The
// NIP-07 login path lets the client pick its own challenge, which is tolerable
// there because a replayed proof only re-establishes a session the holder could
// obtain anyway. Recovery resets a credential, so a captured signature must not
// be replayable: the nonce is minted here, bound to one account, expires quickly,
// and is consumed atomically on first use.
//
// ID is the challenge value itself -- there is no separate handle, so a caller
// cannot present a challenge it did not receive.
type RecoveryChallenge struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	ExpiresAt time.Time  `json:"expires_at"`
	CreatedAt time.Time  `json:"created_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
}

// ErrChallengeNotFound is returned when a recovery challenge is unknown, already
// consumed, or expired. Deliberately one error for all three: distinguishing them
// would tell an attacker whether a guessed nonce ever existed.
var ErrChallengeNotFound = errors.New("recovery challenge not found, already used, or expired")

// LightningKey represents a linked LNURL-auth linking key for a user.
// The linking key is a secp256k1 pubkey (33 bytes, hex-encoded) derived
// deterministically by the wallet from the domain per LUD-04 §4.
type LightningKey struct {
	ID         string     `json:"id"`
	UserID     string     `json:"user_id"`
	LinkingKey string     `json:"linking_key"` // 33-byte compressed secp256k1 pubkey hex
	Name       string     `json:"name,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// BunkerSecret represents a secret for bunker:// URI validation
type BunkerSecret struct {
	ID        string     `json:"id"`
	KeyPubkey string     `json:"key_pubkey"` // The signer key this secret is for
	Secret    string     `json:"-"`          // The secret value (never exposed in JSON)
	ExpiresAt time.Time  `json:"expires_at"`
	CreatedAt time.Time  `json:"created_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"` // When the secret was used (one-time use)
}

// FrostKey represents a FROST threshold signing key
// The group public key is what gets used as the Nostr identity (npub)
type FrostKey struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name,omitempty"`
	Pubkey             string    `json:"pubkey"`       // Group public key (hex) - the Nostr identity
	Threshold          int       `json:"threshold"`    // t in t-of-n
	TotalShares        int       `json:"total_shares"` // n in t-of-n
	GroupPublicKey     []byte    `json:"-"`            // Encoded group public key (for FROST operations)
	VerificationShares []byte    `json:"-"`            // Encoded verification shares (for verifying partial sigs)
	CreatedAt          time.Time `json:"created_at"`
	CreatedBy          string    `json:"created_by,omitempty"`
	OwnerID            string    `json:"owner_id,omitempty"` // User who owns this FROST key (for per-user encryption)
}

// FrostUserShare is the signer-side share of a 2-of-N user-cosigner FROST
// identity. Distinct from FrostShare (which is for signer-to-signer DKG).
// One row per Key with KeyType == KeyTypeFrostUser. See
// docs/frost-2-of-n-design.md §3.1 for the storage shape and §3.3 for the
// share derivation.
//
// EncryptedShare is the signer's share scalar encrypted via the user's
// Vault transit key. The signer cannot decrypt without the user's Vault
// token (live session), and the share alone is useless without the user
// device's share - that's the "We Cannot Comply" inversion.
//
// VerificationShare is public material used to verify a user device's
// partial signature before combining. Safe to store unencrypted.
//
// RotationGeneration increments on share refresh (privacy-architecture
// §3.7 + FROST design §6.3). Lets the signer detect stale shares.
type FrostUserShare struct {
	ID                 string    `json:"id"`
	KeyID              string    `json:"key_id"`              // FK to Key.ID
	OwnerID            string    `json:"owner_id"`            // User who owns this identity (denormalized from Key for fast lookup)
	ShareIndex         int       `json:"share_index"`         // Signer's participant index (usually 2 for 2-of-N)
	EncryptedShare     []byte    `json:"-"`                   // Signer's share scalar, Vault-encrypted
	VerificationShare  []byte    `json:"-"`                   // Public verification material for the signer's partial sigs
	Threshold          int       `json:"threshold"`           // t in t-of-n (2 in the v1 design)
	TotalShares        int       `json:"total_shares"`        // n in t-of-n (>= 2; grows when user adds devices)
	RotationGeneration int       `json:"rotation_generation"` // Increments on share refresh
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
	// Recovery materials (docs/frost-2-of-n-design.md §6.4). Populated at
	// DKG finalize for keys created post-P3e-b; older rows have them NULL
	// and cannot be recovered without re-DKG.
	//
	// EncryptedUserShareAtDkg: g(UserIndex) at DKG time, encrypted under
	// the user's Vault transit key. The signer wrote it, the user reads
	// it back during recovery via the user's Vault token. Operator alone
	// cannot decrypt it (consistent with We-Cannot-Comply §1.1).
	//
	// UserVerificationShareHex: the user's final-share·G computed by
	// the user at DKG time and reported to the signer. Public. Used
	// during recovery to verify that the reconstructed share is the
	// same one the joint pubkey was anchored to.
	EncryptedUserShareAtDkg  []byte `json:"-"`
	UserVerificationShareHex string `json:"-"`
}

// FrostShare represents a single share of a FROST key
// Shares can be local (stored encrypted) or remote (held by another signer)
type FrostShare struct {
	ID              string    `json:"id"`
	FrostKeyID      string    `json:"frost_key_id"`
	ShareIndex      int       `json:"share_index"`                 // 1 to n
	EncryptedShare  []byte    `json:"-"`                           // Local share (encrypted with AES-256-GCM)
	HolderPubkey    string    `json:"holder_pubkey,omitempty"`     // Remote holder's Nostr pubkey
	HolderBunkerURI string    `json:"holder_bunker_uri,omitempty"` // Remote holder's bunker:// URI
	IsLocal         bool      `json:"is_local"`
	PublicShare     []byte    `json:"-"` // Public key share for this participant
	CreatedAt       time.Time `json:"created_at"`
}

// Storage interface for key and session management
type Storage interface {
	// Key management
	CreateKey(ctx context.Context, key *Key) error
	GetKey(ctx context.Context, id string) (*Key, error)
	GetKeyByPubkey(ctx context.Context, pubkey string) (*Key, error)
	GetKeyByName(ctx context.Context, name string) (*Key, error)
	ListKeys(ctx context.Context, ownerID string) ([]*Key, error) // Filter by owner for user isolation
	ListAllKeys(ctx context.Context) ([]*Key, error)              // Admin only - no owner filter
	UpdateKey(ctx context.Context, key *Key) error
	UpdateKeyEncryption(ctx context.Context, keyID, encryptedNsec, encryptionMethod string) error // For migration
	DeleteKey(ctx context.Context, id string) error

	// SetPrimaryKey makes keyID the owner's identity key and clears the flag
	// from every other key they own, atomically. UpdateKey deliberately does
	// not touch is_primary, so this is the only way it changes -- which keeps
	// a routine rename or relay edit from moving the account identity.
	SetPrimaryKey(ctx context.Context, ownerID, keyID string) error

	// Permission management
	SetPermission(ctx context.Context, perm *Permission) error
	GetPermission(ctx context.Context, keyID, userPubkey string) (*Permission, error)
	ListPermissions(ctx context.Context, keyID string) ([]*Permission, error)
	DeletePermission(ctx context.Context, keyID, userPubkey string) error
	UpdatePermissionLastUsed(ctx context.Context, keyID, userPubkey string) error
	UpdatePermissionName(ctx context.Context, keyID, userPubkey, customName string) error

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

	// Platform user management (cross-service authorization)
	EnsurePlatformUser(ctx context.Context, pubkey string) error
	// RemovePlatformUser de-registers a pubkey from the platform users table.
	// Used to retire the HKDF-derived platform pubkey once a real signing key
	// has become the user's identity (Option A). Must not remove a pubkey that
	// still holds service access grants.
	RemovePlatformUser(ctx context.Context, pubkey string) error
	DeriveUserPubkey(ctx context.Context, userID string) (string, error)
	ListPlatformUsers(ctx context.Context, limit, offset int) ([]*PlatformUser, int, error)
	GetPlatformUserAccess(ctx context.Context, pubkey string) (*PlatformUser, error)
	GrantServiceAccess(ctx context.Context, pubkey, serviceSlug string) error
	RevokeServiceAccess(ctx context.Context, pubkey, serviceSlug string) error
	ListServices(ctx context.Context) ([]*Service, error)

	// User session management
	CreateUserSession(ctx context.Context, session *UserSession) error
	GetUserSession(ctx context.Context, id string) (*UserSession, error)
	ListUserSessions(ctx context.Context, userID string) ([]*UserSession, error)
	UpdateUserSessionActivity(ctx context.Context, id string) error
	// UpdateUserSessionVaultToken populates the Vault token on an existing
	// session after an async login completes. Called from the login handler's
	// background goroutine (unified-auth-design async login) — the login
	// response is issued before Vault userpass finishes, so the session starts
	// with an empty VaultToken and this method fills it in when Vault answers.
	UpdateUserSessionVaultToken(ctx context.Context, id, vaultToken string) error
	DeleteUserSession(ctx context.Context, id string) error
	DeleteUserSessions(ctx context.Context, userID string) error
	CleanExpiredUserSessions(ctx context.Context) error

	// App consent management for cross-subdomain SSO (unified-auth-design §5).
	// AppID is the nostrconnect client pubkey from the nostrconnect:// URI.
	// First-time connections require consent; subsequent ones auto-approve.
	RecordAppConsent(ctx context.Context, userID, appID, appName string) error
	HasAppConsent(ctx context.Context, userID, appID string) (bool, error)
	ListAppConsents(ctx context.Context, userID string) ([]*AppConsent, error)
	RevokeAppConsent(ctx context.Context, userID, appID string) error
	RevokeAllAppConsents(ctx context.Context, userID string) error

	// Bunker secret management
	CreateBunkerSecret(ctx context.Context, secret *BunkerSecret) error
	ValidateBunkerSecret(ctx context.Context, keyPubkey, secret string) (*BunkerSecret, error)
	DeleteBunkerSecret(ctx context.Context, id string) error
	CleanExpiredBunkerSecrets(ctx context.Context) error

	// Settings management (for signer identity, etc.)
	GetSetting(ctx context.Context, key string) (string, error)
	SetSetting(ctx context.Context, key, value string) error

	// FROST key management
	CreateFrostKey(ctx context.Context, key *FrostKey) error
	GetFrostKey(ctx context.Context, id string) (*FrostKey, error)
	GetFrostKeyByPubkey(ctx context.Context, pubkey string) (*FrostKey, error)
	ListFrostKeys(ctx context.Context) ([]*FrostKey, error)
	ListFrostKeysByOwner(ctx context.Context, ownerID string) ([]*FrostKey, error)
	DeleteFrostKey(ctx context.Context, id string) error

	// FROST share management
	CreateFrostShare(ctx context.Context, share *FrostShare) error
	GetFrostShare(ctx context.Context, id string) (*FrostShare, error)
	GetFrostShareByKeyAndIndex(ctx context.Context, keyID string, index int) (*FrostShare, error)
	ListFrostShares(ctx context.Context, keyID string) ([]*FrostShare, error)
	ListLocalFrostShares(ctx context.Context, keyID string) ([]*FrostShare, error)
	DeleteFrostShare(ctx context.Context, id string) error

	// FROST 2-of-N user-cosigner share management (docs/frost-2-of-n-design.md).
	// One signer-held share per FROST-user Key; UpdateFrostUserShare is used
	// for share refresh / rotation.
	CreateFrostUserShare(ctx context.Context, share *FrostUserShare) error
	GetFrostUserShare(ctx context.Context, id string) (*FrostUserShare, error)
	GetFrostUserShareByKeyID(ctx context.Context, keyID string) (*FrostUserShare, error)
	ListFrostUserSharesByOwner(ctx context.Context, ownerID string) ([]*FrostUserShare, error)
	UpdateFrostUserShare(ctx context.Context, share *FrostUserShare) error
	DeleteFrostUserShare(ctx context.Context, id string) error

	// Passkey (WebAuthn) credential management
	CreatePasskeyCredential(ctx context.Context, cred *PasskeyCredential) error
	GetPasskeyCredentialByCredentialID(ctx context.Context, credentialID []byte) (*PasskeyCredential, error)
	ListPasskeyCredentials(ctx context.Context, userID string) ([]*PasskeyCredential, error)
	UpdatePasskeyCredentialUsage(ctx context.Context, credentialID []byte, signCount uint32) error
	DeletePasskeyCredential(ctx context.Context, id string) error

	// WebAuthn session management (short-lived ceremony state)
	CreateWebAuthnSession(ctx context.Context, session *WebAuthnSession) error
	GetWebAuthnSession(ctx context.Context, id string) (*WebAuthnSession, error)
	DeleteWebAuthnSession(ctx context.Context, id string) error

	// Account-recovery challenges (nsec proof-of-possession).
	// ConsumeRecoveryChallenge MUST be atomic: it marks the challenge used and
	// returns it only if it was unused and unexpired, so two concurrent attempts
	// on one challenge cannot both succeed.
	CreateRecoveryChallenge(ctx context.Context, challenge *RecoveryChallenge) error
	ConsumeRecoveryChallenge(ctx context.Context, id string) (*RecoveryChallenge, error)
	DeleteExpiredRecoveryChallenges(ctx context.Context) (int, error)

	// Lightning key management (LNURL-auth LUD-04)
	CreateLightningKey(ctx context.Context, key *LightningKey) error
	GetLightningKeyByLinkingKey(ctx context.Context, linkingKey string) (*LightningKey, error)
	ListLightningKeys(ctx context.Context, userID string) ([]*LightningKey, error)
	UpdateLightningKeyLastUsed(ctx context.Context, id string) error
	DeleteLightningKey(ctx context.Context, id string) error

	// Lifecycle
	Close() error
}

// New creates a new storage backend based on configuration
func New(cfg config.StorageConfig) (Storage, error) {
	switch cfg.Type {
	case "memory", "":
		slog.Info("using in-memory storage (data will not persist across restarts)")
		return NewMemoryStorage(), nil
	case "postgres":
		if cfg.DSN == "" {
			return nil, fmt.Errorf("postgres storage requires DSN (DATABASE_URL)")
		}
		slog.Info("using PostgreSQL storage")
		return NewPostgresStorage(cfg.DSN)
	case "sqlite":
		path := cfg.DSN
		if path == "" {
			path = "cloistr-signer.db"
		}
		slog.Info("using SQLite storage", "path", path)
		return NewSQLiteStorage(path)
	default:
		return nil, fmt.Errorf("unknown storage type: %s", cfg.Type)
	}
}

// MemoryStorage is an in-memory implementation for development/testing
type MemoryStorage struct {
	mu                 sync.RWMutex
	keys               map[string]*Key
	keysByPubkey       map[string]*Key
	keysByName         map[string]*Key
	permissions        map[string]map[string]*Permission // keyID -> userPubkey -> Permission
	sessions           map[string]*Session
	policies           map[string]*Policy
	policyRules        map[string]*PolicyRule // ruleID -> PolicyRule
	tokens             map[string]*Token
	tokensByKey        map[string]map[string]*Token // keyID -> tokenID -> Token
	pendingRequests    map[string]*PendingRequest
	users              map[string]*User
	usersByUsername    map[string]*User
	usersByEmail       map[string]*User
	userSessions       map[string]*UserSession
	userSessionsByUser map[string]map[string]*UserSession // userID -> sessionID -> UserSession
	bunkerSecrets      map[string]*BunkerSecret           // secret value -> BunkerSecret
	settings           map[string]string                  // key -> value
	// FROST threshold signing
	frostKeys           map[string]*FrostKey           // id -> FrostKey
	frostKeysByPubkey   map[string]*FrostKey           // pubkey -> FrostKey
	frostShares         map[string]*FrostShare         // id -> FrostShare
	frostSharesByKey    map[string]map[int]*FrostShare // keyID -> index -> FrostShare
	frostUserShares     map[string]*FrostUserShare     // id -> FrostUserShare
	frostUserShareByKey map[string]*FrostUserShare     // key_id -> FrostUserShare (one signer-held share per key)
	// App consents for cross-subdomain SSO (unified-auth-design §5)
	appConsents map[string]map[string]*AppConsent // userID -> appID -> AppConsent

	// WebAuthn / passkey storage
	passkeyCredentials   map[string]*PasskeyCredential   // id -> cred
	passkeyCredsByCredID map[string]*PasskeyCredential   // base64(credentialID) -> cred
	passkeyCredsByUser   map[string][]*PasskeyCredential // userID -> []cred
	webauthnSessions     map[string]*WebAuthnSession     // id -> session
	recoveryChallenges   map[string]*RecoveryChallenge   // challenge -> record

	// Lightning key storage (LNURL-auth LUD-04)
	lightningKeys             map[string]*LightningKey // id -> key
	lightningKeysByLinkingKey map[string]*LightningKey // linkingKey -> key
}

// NewMemoryStorage creates a new in-memory storage
func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		keys:                make(map[string]*Key),
		keysByPubkey:        make(map[string]*Key),
		keysByName:          make(map[string]*Key),
		permissions:         make(map[string]map[string]*Permission),
		sessions:            make(map[string]*Session),
		policies:            make(map[string]*Policy),
		policyRules:         make(map[string]*PolicyRule),
		tokens:              make(map[string]*Token),
		tokensByKey:         make(map[string]map[string]*Token),
		pendingRequests:     make(map[string]*PendingRequest),
		users:               make(map[string]*User),
		usersByUsername:     make(map[string]*User),
		usersByEmail:        make(map[string]*User),
		userSessions:        make(map[string]*UserSession),
		userSessionsByUser:  make(map[string]map[string]*UserSession),
		bunkerSecrets:       make(map[string]*BunkerSecret),
		settings:            make(map[string]string),
		frostKeys:           make(map[string]*FrostKey),
		frostKeysByPubkey:   make(map[string]*FrostKey),
		frostShares:         make(map[string]*FrostShare),
		frostSharesByKey:    make(map[string]map[int]*FrostShare),
		frostUserShares:     make(map[string]*FrostUserShare),
		frostUserShareByKey: make(map[string]*FrostUserShare),
		appConsents:         make(map[string]map[string]*AppConsent),

		passkeyCredentials:   make(map[string]*PasskeyCredential),
		passkeyCredsByCredID: make(map[string]*PasskeyCredential),
		passkeyCredsByUser:   make(map[string][]*PasskeyCredential),
		webauthnSessions:     make(map[string]*WebAuthnSession),
		recoveryChallenges:   make(map[string]*RecoveryChallenge),

		lightningKeys:             make(map[string]*LightningKey),
		lightningKeysByLinkingKey: make(map[string]*LightningKey),
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

func (m *MemoryStorage) ListKeys(ctx context.Context, ownerID string) ([]*Key, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keys := make([]*Key, 0)
	for _, key := range m.keys {
		if key.OwnerID == ownerID {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func (m *MemoryStorage) ListAllKeys(ctx context.Context) ([]*Key, error) {
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

func (m *MemoryStorage) UpdateKeyEncryption(ctx context.Context, keyID, encryptedNsec, encryptionMethod string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key, exists := m.keys[keyID]
	if !exists {
		return ErrKeyNotFound
	}

	key.EncryptedNsec = encryptedNsec
	key.EncryptionMethod = encryptionMethod
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

// SetPrimaryKey makes keyID the owner's identity key, clearing the flag from
// their other keys. The SQL backends get atomicity from a transaction; here the
// write lock provides it.
func (m *MemoryStorage) SetPrimaryKey(ctx context.Context, ownerID, keyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	target, exists := m.keys[keyID]
	if !exists || target.OwnerID != ownerID {
		return ErrKeyNotFound
	}
	for _, k := range m.keys {
		if k.OwnerID == ownerID {
			k.IsPrimary = k.ID == keyID
		}
	}
	return nil
}

func (m *MemoryStorage) SetPermission(ctx context.Context, perm *Permission) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// KeyID is the full pubkey, so check keysByPubkey
	if _, exists := m.keysByPubkey[perm.KeyID]; !exists {
		return ErrKeyNotFound
	}

	// Set CreatedAt if not already set
	if perm.CreatedAt.IsZero() {
		perm.CreatedAt = time.Now()
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

func (m *MemoryStorage) UpdatePermissionLastUsed(ctx context.Context, keyID, userPubkey string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	perms, exists := m.permissions[keyID]
	if !exists {
		return nil
	}

	perm, exists := perms[userPubkey]
	if !exists {
		return nil
	}

	now := time.Now()
	perm.LastUsedAt = &now
	return nil
}

func (m *MemoryStorage) UpdatePermissionName(ctx context.Context, keyID, userPubkey, customName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	perms, exists := m.permissions[keyID]
	if !exists {
		return ErrKeyNotFound
	}

	perm, exists := perms[userPubkey]
	if !exists {
		return ErrKeyNotFound
	}

	perm.CustomName = customName
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

// cloneUser returns an independent copy of u. MemoryStorage must never hand a
// caller a pointer into its own maps, and must never adopt a caller's pointer
// into them: the mutators below (ResetFailedLogins, LockUser, ...) write to the
// stored struct while holding m.mu, but a caller holding the same pointer reads
// it without the lock, which is a genuine data race.
//
// The concrete failure this fixes: handleUserLogin fires ResetFailedLogins in a
// goroutine and then snapshots the user (`reconcileUser := *user`) on the
// handler goroutine. With a shared pointer those are a concurrent write and
// read of the same User, and `go test -race` fails TestIntegration_UserIsolation.
//
// Reference fields are cloned too, so a caller appending to BackupCodes (the MFA
// backup-code path does exactly that) cannot reach into stored state.
func cloneUser(u *User) *User {
	if u == nil {
		return nil
	}
	c := *u
	if u.BackupCodes != nil {
		c.BackupCodes = append([]string(nil), u.BackupCodes...)
	}
	if u.LockedUntil != nil {
		t := *u.LockedUntil
		c.LockedUntil = &t
	}
	if u.LastLoginAt != nil {
		t := *u.LastLoginAt
		c.LastLoginAt = &t
	}
	return &c
}

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

	stored := cloneUser(user)
	m.users[stored.ID] = stored
	m.usersByUsername[stored.Username] = stored
	if stored.Email != "" {
		m.usersByEmail[stored.Email] = stored
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
	return cloneUser(user), nil
}

func (m *MemoryStorage) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	user, exists := m.usersByUsername[username]
	if !exists {
		return nil, ErrUserNotFound
	}
	return cloneUser(user), nil
}

func (m *MemoryStorage) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	user, exists := m.usersByEmail[email]
	if !exists {
		return nil, ErrUserNotFound
	}
	return cloneUser(user), nil
}

func (m *MemoryStorage) GetUserByPubkey(ctx context.Context, pubkey string) (*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, user := range m.users {
		if user.Pubkey == pubkey {
			return cloneUser(user), nil
		}
	}
	return nil, ErrUserNotFound
}

func (m *MemoryStorage) ListUsers(ctx context.Context) ([]*User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	users := make([]*User, 0, len(m.users))
	for _, user := range m.users {
		users = append(users, cloneUser(user))
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

	user.UpdatedAt = time.Now()
	stored := cloneUser(user)

	// Re-point every index at the new stored copy. The by-username/by-email maps
	// have to be rewritten even when the value is unchanged: they previously kept
	// the pointer from the last write, so a rename-less update left them serving
	// a stale struct.
	if existing.Username != stored.Username {
		delete(m.usersByUsername, existing.Username)
	}
	m.usersByUsername[stored.Username] = stored

	if existing.Email != stored.Email && existing.Email != "" {
		delete(m.usersByEmail, existing.Email)
	}
	if stored.Email != "" {
		m.usersByEmail[stored.Email] = stored
	}

	m.users[stored.ID] = stored
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

// EnsurePlatformUser is a no-op for in-memory storage (no platform DB)
func (m *MemoryStorage) EnsurePlatformUser(ctx context.Context, pubkey string) error {
	// In-memory storage doesn't have platform integration
	slog.Debug("EnsurePlatformUser skipped (in-memory storage)", "pubkey", pubkey[:16]+"...")
	return nil
}

// RemovePlatformUser is a no-op for in-memory storage (no platform DB)
func (m *MemoryStorage) RemovePlatformUser(ctx context.Context, pubkey string) error {
	// In-memory storage doesn't have platform integration
	slog.Debug("RemovePlatformUser skipped (in-memory storage)", "pubkey", pubkey[:16]+"...")
	return nil
}

// DeriveUserPubkey generates a deterministic pubkey for testing
// In production (PostgresStorage), this uses HKDF with a persistent seed
func (m *MemoryStorage) DeriveUserPubkey(ctx context.Context, userID string) (string, error) {
	// For in-memory/testing: use a fixed test seed + HKDF
	// This is deterministic within a test run
	testSeed := "0000000000000000000000000000000000000000000000000000000000000000"
	pubkey, err := derivePubkeyFromSeed(testSeed, userID)
	if err != nil {
		return "", err
	}
	return pubkey, nil
}

// derivePubkeyFromSeed derives a pubkey from seed and user ID using HKDF
func derivePubkeyFromSeed(seedHex, userID string) (string, error) {
	privateKey, err := crypto.DeriveNostrKey(seedHex, userID, "cloistr-platform-identity")
	if err != nil {
		return "", err
	}
	return nostr.GetPublicKey(privateKey)
}

// ListPlatformUsers returns empty list for in-memory storage (no platform integration)
func (m *MemoryStorage) ListPlatformUsers(ctx context.Context, limit, offset int) ([]*PlatformUser, int, error) {
	return nil, 0, nil
}

// GetPlatformUserAccess returns nil for in-memory storage (no platform integration)
func (m *MemoryStorage) GetPlatformUserAccess(ctx context.Context, pubkey string) (*PlatformUser, error) {
	return nil, fmt.Errorf("platform not available in memory storage")
}

// GrantServiceAccess is a no-op for in-memory storage
func (m *MemoryStorage) GrantServiceAccess(ctx context.Context, pubkey, serviceSlug string) error {
	slog.Debug("GrantServiceAccess skipped (in-memory storage)", "pubkey", pubkey[:16]+"...", "service", serviceSlug)
	return nil
}

// RevokeServiceAccess is a no-op for in-memory storage
func (m *MemoryStorage) RevokeServiceAccess(ctx context.Context, pubkey, serviceSlug string) error {
	slog.Debug("RevokeServiceAccess skipped (in-memory storage)", "pubkey", pubkey[:16]+"...", "service", serviceSlug)
	return nil
}

// ListServices returns empty list for in-memory storage
func (m *MemoryStorage) ListServices(ctx context.Context) ([]*Service, error) {
	return nil, nil
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

	// Return a snapshot copy, not the shared pointer: the update methods mutate
	// the stored struct in place under the write lock, so handing out the live
	// pointer would let callers read a field concurrently with a write (data
	// race). Postgres already returns a fresh struct per query — this matches it.
	sessionCopy := *session
	return &sessionCopy, nil
}

func (m *MemoryStorage) ListUserSessions(ctx context.Context, userID string) ([]*UserSession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sessions := make([]*UserSession, 0)
	now := time.Now()
	if userSessions, exists := m.userSessionsByUser[userID]; exists {
		for _, session := range userSessions {
			if now.Before(session.ExpiresAt) {
				// Snapshot copy — see GetUserSession for why the live pointer is
				// not returned.
				sessionCopy := *session
				sessions = append(sessions, &sessionCopy)
			}
		}
	}
	return sessions, nil
}

func (m *MemoryStorage) UpdateUserSessionActivity(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.userSessions[id]
	if !exists {
		return ErrSessionNotFound
	}

	now := time.Now()
	session.LastActivity = &now
	return nil
}

func (m *MemoryStorage) UpdateUserSessionVaultToken(ctx context.Context, id, vaultToken string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.userSessions[id]
	if !exists {
		return ErrSessionNotFound
	}

	session.VaultToken = vaultToken
	return nil
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

func (m *MemoryStorage) GetSetting(ctx context.Context, key string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	value, exists := m.settings[key]
	if !exists {
		return "", ErrSettingNotFound
	}
	return value, nil
}

func (m *MemoryStorage) SetSetting(ctx context.Context, key, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.settings[key] = value
	return nil
}

// FROST key management

var ErrFrostKeyNotFound = errors.New("frost key not found")
var ErrFrostShareNotFound = errors.New("frost share not found")
var ErrFrostUserShareNotFound = errors.New("frost user share not found")
var ErrFrostUserShareExists = errors.New("frost user share already exists for this key")

func (m *MemoryStorage) CreateFrostKey(ctx context.Context, key *FrostKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.frostKeys[key.ID]; exists {
		return errors.New("frost key already exists")
	}
	if _, exists := m.frostKeysByPubkey[key.Pubkey]; exists {
		return errors.New("frost key with this pubkey already exists")
	}

	m.frostKeys[key.ID] = key
	m.frostKeysByPubkey[key.Pubkey] = key
	return nil
}

func (m *MemoryStorage) GetFrostKey(ctx context.Context, id string) (*FrostKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key, exists := m.frostKeys[id]
	if !exists {
		return nil, ErrFrostKeyNotFound
	}
	return key, nil
}

func (m *MemoryStorage) GetFrostKeyByPubkey(ctx context.Context, pubkey string) (*FrostKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key, exists := m.frostKeysByPubkey[pubkey]
	if !exists {
		return nil, ErrFrostKeyNotFound
	}
	return key, nil
}

func (m *MemoryStorage) ListFrostKeys(ctx context.Context) ([]*FrostKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keys := make([]*FrostKey, 0, len(m.frostKeys))
	for _, key := range m.frostKeys {
		keys = append(keys, key)
	}
	return keys, nil
}

func (m *MemoryStorage) ListFrostKeysByOwner(ctx context.Context, ownerID string) ([]*FrostKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	keys := make([]*FrostKey, 0)
	for _, key := range m.frostKeys {
		if key.OwnerID == ownerID {
			keys = append(keys, key)
		}
	}
	return keys, nil
}

func (m *MemoryStorage) DeleteFrostKey(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key, exists := m.frostKeys[id]
	if !exists {
		return ErrFrostKeyNotFound
	}

	delete(m.frostKeys, id)
	delete(m.frostKeysByPubkey, key.Pubkey)
	delete(m.frostSharesByKey, id)
	return nil
}

// FROST share management

func (m *MemoryStorage) CreateFrostShare(ctx context.Context, share *FrostShare) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.frostShares[share.ID]; exists {
		return errors.New("frost share already exists")
	}

	// Check if a share with this index already exists for this key
	if shares, exists := m.frostSharesByKey[share.FrostKeyID]; exists {
		if _, exists := shares[share.ShareIndex]; exists {
			return errors.New("frost share with this index already exists for this key")
		}
	}

	m.frostShares[share.ID] = share
	if m.frostSharesByKey[share.FrostKeyID] == nil {
		m.frostSharesByKey[share.FrostKeyID] = make(map[int]*FrostShare)
	}
	m.frostSharesByKey[share.FrostKeyID][share.ShareIndex] = share
	return nil
}

func (m *MemoryStorage) GetFrostShare(ctx context.Context, id string) (*FrostShare, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	share, exists := m.frostShares[id]
	if !exists {
		return nil, ErrFrostShareNotFound
	}
	return share, nil
}

func (m *MemoryStorage) GetFrostShareByKeyAndIndex(ctx context.Context, keyID string, index int) (*FrostShare, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	shares, exists := m.frostSharesByKey[keyID]
	if !exists {
		return nil, ErrFrostShareNotFound
	}

	share, exists := shares[index]
	if !exists {
		return nil, ErrFrostShareNotFound
	}
	return share, nil
}

func (m *MemoryStorage) ListFrostShares(ctx context.Context, keyID string) ([]*FrostShare, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	shares, exists := m.frostSharesByKey[keyID]
	if !exists {
		return []*FrostShare{}, nil
	}

	result := make([]*FrostShare, 0, len(shares))
	for _, share := range shares {
		result = append(result, share)
	}
	return result, nil
}

func (m *MemoryStorage) ListLocalFrostShares(ctx context.Context, keyID string) ([]*FrostShare, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	shares, exists := m.frostSharesByKey[keyID]
	if !exists {
		return []*FrostShare{}, nil
	}

	result := make([]*FrostShare, 0)
	for _, share := range shares {
		if share.IsLocal {
			result = append(result, share)
		}
	}
	return result, nil
}

func (m *MemoryStorage) DeleteFrostShare(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	share, exists := m.frostShares[id]
	if !exists {
		return ErrFrostShareNotFound
	}

	delete(m.frostShares, id)
	if shares, exists := m.frostSharesByKey[share.FrostKeyID]; exists {
		delete(shares, share.ShareIndex)
	}
	return nil
}

// FROST 2-of-N user-cosigner share management (in-memory backend).

func (m *MemoryStorage) CreateFrostUserShare(ctx context.Context, share *FrostUserShare) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.frostUserShares[share.ID]; exists {
		return ErrFrostUserShareExists
	}
	if _, exists := m.frostUserShareByKey[share.KeyID]; exists {
		return ErrFrostUserShareExists
	}

	now := time.Now()
	if share.CreatedAt.IsZero() {
		share.CreatedAt = now
	}
	share.UpdatedAt = now

	m.frostUserShares[share.ID] = share
	m.frostUserShareByKey[share.KeyID] = share
	return nil
}

func (m *MemoryStorage) GetFrostUserShare(ctx context.Context, id string) (*FrostUserShare, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	share, exists := m.frostUserShares[id]
	if !exists {
		return nil, ErrFrostUserShareNotFound
	}
	return share, nil
}

func (m *MemoryStorage) GetFrostUserShareByKeyID(ctx context.Context, keyID string) (*FrostUserShare, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	share, exists := m.frostUserShareByKey[keyID]
	if !exists {
		return nil, ErrFrostUserShareNotFound
	}
	return share, nil
}

func (m *MemoryStorage) ListFrostUserSharesByOwner(ctx context.Context, ownerID string) ([]*FrostUserShare, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*FrostUserShare, 0)
	for _, share := range m.frostUserShares {
		if share.OwnerID == ownerID {
			result = append(result, share)
		}
	}
	return result, nil
}

func (m *MemoryStorage) UpdateFrostUserShare(ctx context.Context, share *FrostUserShare) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, exists := m.frostUserShares[share.ID]
	if !exists {
		return ErrFrostUserShareNotFound
	}

	// Preserve CreatedAt; refresh UpdatedAt.
	share.CreatedAt = existing.CreatedAt
	share.UpdatedAt = time.Now()

	m.frostUserShares[share.ID] = share
	m.frostUserShareByKey[share.KeyID] = share
	return nil
}

func (m *MemoryStorage) DeleteFrostUserShare(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	share, exists := m.frostUserShares[id]
	if !exists {
		return ErrFrostUserShareNotFound
	}

	delete(m.frostUserShares, id)
	delete(m.frostUserShareByKey, share.KeyID)
	return nil
}

// App consent management (MemoryStorage implementation).

func (m *MemoryStorage) RecordAppConsent(ctx context.Context, userID, appID, appName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.appConsents[userID]; !ok {
		m.appConsents[userID] = make(map[string]*AppConsent)
	}
	m.appConsents[userID][appID] = &AppConsent{
		UserID:     userID,
		AppID:      appID,
		AppName:    appName,
		ApprovedAt: time.Now(),
	}
	return nil
}

func (m *MemoryStorage) HasAppConsent(ctx context.Context, userID, appID string) (bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if byApp, ok := m.appConsents[userID]; ok {
		_, ok := byApp[appID]
		return ok, nil
	}
	return false, nil
}

func (m *MemoryStorage) ListAppConsents(ctx context.Context, userID string) ([]*AppConsent, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	byApp, ok := m.appConsents[userID]
	if !ok {
		return []*AppConsent{}, nil
	}
	result := make([]*AppConsent, 0, len(byApp))
	for _, c := range byApp {
		result = append(result, c)
	}
	return result, nil
}

func (m *MemoryStorage) RevokeAppConsent(ctx context.Context, userID, appID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	byApp, ok := m.appConsents[userID]
	if !ok || byApp[appID] == nil {
		return ErrConsentNotFound
	}
	delete(byApp, appID)
	return nil
}

func (m *MemoryStorage) RevokeAllAppConsents(ctx context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.appConsents, userID)
	return nil
}

// ---- Passkey / WebAuthn memory implementations ----

func (m *MemoryStorage) CreatePasskeyCredential(ctx context.Context, cred *PasskeyCredential) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := credKey(cred.CredentialID)
	m.passkeyCredentials[cred.ID] = cred
	m.passkeyCredsByCredID[key] = cred
	m.passkeyCredsByUser[cred.UserID] = append(m.passkeyCredsByUser[cred.UserID], cred)
	return nil
}

func (m *MemoryStorage) GetPasskeyCredentialByCredentialID(ctx context.Context, credentialID []byte) (*PasskeyCredential, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	cred, ok := m.passkeyCredsByCredID[credKey(credentialID)]
	if !ok {
		return nil, ErrUserNotFound // reuse sentinel; caller checks
	}
	return cred, nil
}

func (m *MemoryStorage) ListPasskeyCredentials(ctx context.Context, userID string) ([]*PasskeyCredential, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	creds := m.passkeyCredsByUser[userID]
	result := make([]*PasskeyCredential, len(creds))
	copy(result, creds)
	return result, nil
}

func (m *MemoryStorage) UpdatePasskeyCredentialUsage(ctx context.Context, credentialID []byte, signCount uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cred, ok := m.passkeyCredsByCredID[credKey(credentialID)]
	if !ok {
		return ErrUserNotFound
	}
	cred.SignCount = signCount
	now := time.Now()
	cred.LastUsedAt = &now
	return nil
}

func (m *MemoryStorage) DeletePasskeyCredential(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	cred, ok := m.passkeyCredentials[id]
	if !ok {
		return nil
	}
	delete(m.passkeyCredentials, id)
	delete(m.passkeyCredsByCredID, credKey(cred.CredentialID))

	// Remove from user slice
	slice := m.passkeyCredsByUser[cred.UserID]
	updated := slice[:0]
	for _, c := range slice {
		if c.ID != id {
			updated = append(updated, c)
		}
	}
	m.passkeyCredsByUser[cred.UserID] = updated
	return nil
}

func (m *MemoryStorage) CreateWebAuthnSession(ctx context.Context, session *WebAuthnSession) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.webauthnSessions[session.ID] = session
	return nil
}

func (m *MemoryStorage) GetWebAuthnSession(ctx context.Context, id string) (*WebAuthnSession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	s, ok := m.webauthnSessions[id]
	if !ok {
		return nil, ErrSessionNotFound
	}
	return s, nil
}

func (m *MemoryStorage) DeleteWebAuthnSession(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.webauthnSessions, id)
	return nil
}

// ---- Recovery challenge memory implementations ----

func (m *MemoryStorage) CreateRecoveryChallenge(ctx context.Context, c *RecoveryChallenge) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	stored := *c
	m.recoveryChallenges[stored.ID] = &stored
	return nil
}

// ConsumeRecoveryChallenge marks the challenge used and returns it, but only if it
// was unused and unexpired. The check and the mark happen under one lock hold, so
// two concurrent attempts on the same challenge cannot both succeed.
func (m *MemoryStorage) ConsumeRecoveryChallenge(ctx context.Context, id string) (*RecoveryChallenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	c, ok := m.recoveryChallenges[id]
	if !ok || c.UsedAt != nil || time.Now().After(c.ExpiresAt) {
		return nil, ErrChallengeNotFound
	}
	now := time.Now()
	c.UsedAt = &now

	out := *c
	return &out, nil
}

func (m *MemoryStorage) DeleteExpiredRecoveryChallenges(ctx context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	removed := 0
	for id, c := range m.recoveryChallenges {
		if now.After(c.ExpiresAt) {
			delete(m.recoveryChallenges, id)
			removed++
		}
	}
	return removed, nil
}

// ---- Lightning key memory implementations ----

func (m *MemoryStorage) CreateLightningKey(ctx context.Context, key *LightningKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.lightningKeysByLinkingKey[key.LinkingKey]; exists {
		return ErrLightningKeyExists
	}
	m.lightningKeys[key.ID] = key
	m.lightningKeysByLinkingKey[key.LinkingKey] = key
	return nil
}

func (m *MemoryStorage) GetLightningKeyByLinkingKey(ctx context.Context, linkingKey string) (*LightningKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key, ok := m.lightningKeysByLinkingKey[linkingKey]
	if !ok {
		return nil, ErrLightningKeyNotFound
	}
	return key, nil
}

func (m *MemoryStorage) ListLightningKeys(ctx context.Context, userID string) ([]*LightningKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*LightningKey, 0)
	for _, key := range m.lightningKeys {
		if key.UserID == userID {
			result = append(result, key)
		}
	}
	return result, nil
}

func (m *MemoryStorage) UpdateLightningKeyLastUsed(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key, ok := m.lightningKeys[id]
	if !ok {
		return ErrLightningKeyNotFound
	}
	now := time.Now()
	key.LastUsedAt = &now
	return nil
}

func (m *MemoryStorage) DeleteLightningKey(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	key, ok := m.lightningKeys[id]
	if !ok {
		return ErrLightningKeyNotFound
	}
	delete(m.lightningKeys, id)
	delete(m.lightningKeysByLinkingKey, key.LinkingKey)
	return nil
}

// credKey converts raw credential ID bytes to a map key string.
func credKey(b []byte) string {
	const hex = "0123456789abcdef"
	s := make([]byte, len(b)*2)
	for i, c := range b {
		s[i*2] = hex[c>>4]
		s[i*2+1] = hex[c&0xf]
	}
	return string(s)
}

func (m *MemoryStorage) Close() error {
	return nil
}
