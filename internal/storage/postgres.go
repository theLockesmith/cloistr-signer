package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/lib/pq"
	"github.com/nbd-wtf/go-nostr"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/crypto"
)

// PostgresStorage implements Storage interface using PostgreSQL
type PostgresStorage struct {
	db *sql.DB
}

// NewPostgresStorage creates a new PostgreSQL storage backend
func NewPostgresStorage(dsn string) (*PostgresStorage, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	ps := &PostgresStorage{db: db}

	// Run migrations
	if err := ps.migrate(); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	// Backfill platform users for existing web accounts
	if err := ps.backfillPlatformUsers(context.Background()); err != nil {
		slog.Warn("failed to backfill platform users", "error", err)
		// Non-fatal - continue anyway
	}

	return ps, nil
}

// migrate runs database migrations
// Table names are prefixed with 'signer_' to avoid conflicts with the cloistr platform schema
func (ps *PostgresStorage) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS signer_keys (
		id TEXT PRIMARY KEY,
		name TEXT,
		pubkey TEXT UNIQUE NOT NULL,
		encrypted_nsec TEXT NOT NULL,
		require_approval BOOLEAN NOT NULL DEFAULT FALSE,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		created_by TEXT
	);

	-- Add require_approval column if it doesn't exist (migration)
	ALTER TABLE signer_keys ADD COLUMN IF NOT EXISTS require_approval BOOLEAN NOT NULL DEFAULT FALSE;

	-- Add relays column if it doesn't exist (migration for per-key relay config)
	ALTER TABLE signer_keys ADD COLUMN IF NOT EXISTS relays TEXT[] DEFAULT '{}';

	-- Add proxy key columns (Phase 12 - Signer Chaining)
	ALTER TABLE signer_keys ADD COLUMN IF NOT EXISTS key_type TEXT NOT NULL DEFAULT 'local';
	ALTER TABLE signer_keys ADD COLUMN IF NOT EXISTS bunker_uri TEXT DEFAULT '';
	ALTER TABLE signer_keys ADD COLUMN IF NOT EXISTS upstream_pubkey TEXT DEFAULT '';

	-- Make encrypted_nsec nullable for proxy keys
	ALTER TABLE signer_keys ALTER COLUMN encrypted_nsec DROP NOT NULL;

	CREATE INDEX IF NOT EXISTS idx_signer_keys_pubkey ON signer_keys(pubkey);
	CREATE INDEX IF NOT EXISTS idx_signer_keys_name ON signer_keys(name);

	CREATE TABLE IF NOT EXISTS signer_permissions (
		key_id TEXT NOT NULL,
		user_pubkey TEXT NOT NULL,
		methods TEXT[] NOT NULL DEFAULT '{}',
		allowed_kinds INTEGER[] DEFAULT '{}',
		expires_at TIMESTAMPTZ,
		policy_id TEXT,
		require_approval BOOLEAN,
		PRIMARY KEY (key_id, user_pubkey)
	);

	-- Add require_approval column if it doesn't exist (migration)
	ALTER TABLE signer_permissions ADD COLUMN IF NOT EXISTS require_approval BOOLEAN;

	-- Add app metadata columns (migration for grouped apps UI)
	ALTER TABLE signer_permissions ADD COLUMN IF NOT EXISTS app_name TEXT;
	ALTER TABLE signer_permissions ADD COLUMN IF NOT EXISTS app_url TEXT;
	ALTER TABLE signer_permissions ADD COLUMN IF NOT EXISTS app_image TEXT;
	ALTER TABLE signer_permissions ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();
	ALTER TABLE signer_permissions ADD COLUMN IF NOT EXISTS last_used_at TIMESTAMPTZ;

	-- Add custom_name column for user-defined session labels
	ALTER TABLE signer_permissions ADD COLUMN IF NOT EXISTS custom_name TEXT;

	-- Add delegate_pubkey column for tracking original requester in proxy chains (Phase 12)
	ALTER TABLE signer_permissions ADD COLUMN IF NOT EXISTS delegate_pubkey TEXT;

	CREATE INDEX IF NOT EXISTS idx_signer_permissions_key_id ON signer_permissions(key_id);

	CREATE TABLE IF NOT EXISTS signer_sessions (
		id TEXT PRIMARY KEY,
		key_id TEXT NOT NULL,
		client_pubkey TEXT NOT NULL,
		permissions TEXT[] NOT NULL DEFAULT '{}',
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		expires_at TIMESTAMPTZ NOT NULL,
		UNIQUE (key_id, client_pubkey)
	);

	CREATE INDEX IF NOT EXISTS idx_signer_sessions_key_client ON signer_sessions(key_id, client_pubkey);
	CREATE INDEX IF NOT EXISTS idx_signer_sessions_expires ON signer_sessions(expires_at);

	CREATE TABLE IF NOT EXISTS signer_policies (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		description TEXT,
		expires_at TIMESTAMPTZ,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		created_by TEXT
	);

	CREATE TABLE IF NOT EXISTS signer_policy_rules (
		id TEXT PRIMARY KEY,
		policy_id TEXT NOT NULL REFERENCES signer_policies(id) ON DELETE CASCADE,
		method TEXT NOT NULL,
		allowed_kinds INTEGER[] DEFAULT '{}',
		max_usage INTEGER DEFAULT 0,
		current_usage INTEGER DEFAULT 0
	);

	CREATE INDEX IF NOT EXISTS idx_signer_policy_rules_policy ON signer_policy_rules(policy_id);

	CREATE TABLE IF NOT EXISTS signer_tokens (
		id TEXT PRIMARY KEY,
		policy_id TEXT NOT NULL,
		key_id TEXT NOT NULL,
		client_name TEXT,
		created_by TEXT,
		expires_at TIMESTAMPTZ,
		redeemed_at TIMESTAMPTZ,
		redeemed_by TEXT,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE INDEX IF NOT EXISTS idx_signer_tokens_key_id ON signer_tokens(key_id);

	CREATE TABLE IF NOT EXISTS signer_pending_requests (
		id TEXT PRIMARY KEY,
		key_pubkey TEXT NOT NULL,
		client_pubkey TEXT NOT NULL,
		method TEXT NOT NULL,
		params JSONB,
		event_kind INTEGER,
		expires_at TIMESTAMPTZ NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE INDEX IF NOT EXISTS idx_signer_pending_requests_key ON signer_pending_requests(key_pubkey);
	CREATE INDEX IF NOT EXISTS idx_signer_pending_requests_expires ON signer_pending_requests(expires_at);

	CREATE TABLE IF NOT EXISTS signer_web_accounts (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		email TEXT UNIQUE,
		pubkey TEXT,
		role TEXT NOT NULL DEFAULT 'user',
		password_hash TEXT NOT NULL,
		mfa_secret TEXT,
		mfa_enabled BOOLEAN DEFAULT FALSE,
		backup_codes TEXT[] DEFAULT '{}',
		backup_codes_used INTEGER DEFAULT 0,
		failed_login_attempts INTEGER DEFAULT 0,
		locked_until TIMESTAMPTZ,
		last_login_at TIMESTAMPTZ,
		last_login_ip TEXT,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	CREATE INDEX IF NOT EXISTS idx_signer_web_accounts_username ON signer_web_accounts(username);
	CREATE INDEX IF NOT EXISTS idx_signer_web_accounts_email ON signer_web_accounts(email);
	CREATE INDEX IF NOT EXISTS idx_signer_web_accounts_pubkey ON signer_web_accounts(pubkey);

	CREATE TABLE IF NOT EXISTS signer_web_sessions (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES signer_web_accounts(id) ON DELETE CASCADE,
		token_hash TEXT,
		user_agent TEXT,
		ip_address TEXT,
		remember_device BOOLEAN NOT NULL DEFAULT FALSE,
		last_activity TIMESTAMPTZ,
		expires_at TIMESTAMPTZ NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	-- Add remember_device and last_activity columns if they don't exist (migration)
	ALTER TABLE signer_web_sessions ADD COLUMN IF NOT EXISTS remember_device BOOLEAN NOT NULL DEFAULT FALSE;
	ALTER TABLE signer_web_sessions ADD COLUMN IF NOT EXISTS last_activity TIMESTAMPTZ;

	CREATE INDEX IF NOT EXISTS idx_signer_web_sessions_user ON signer_web_sessions(user_id);
	CREATE INDEX IF NOT EXISTS idx_signer_web_sessions_expires ON signer_web_sessions(expires_at);

	CREATE TABLE IF NOT EXISTS signer_bunker_secrets (
		id TEXT PRIMARY KEY,
		key_pubkey TEXT NOT NULL,
		secret TEXT NOT NULL UNIQUE,
		expires_at TIMESTAMPTZ NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		used_at TIMESTAMPTZ
	);

	CREATE INDEX IF NOT EXISTS idx_signer_bunker_secrets_key_pubkey ON signer_bunker_secrets(key_pubkey);
	CREATE INDEX IF NOT EXISTS idx_signer_bunker_secrets_secret ON signer_bunker_secrets(secret);
	CREATE INDEX IF NOT EXISTS idx_signer_bunker_secrets_expires ON signer_bunker_secrets(expires_at);

	CREATE TABLE IF NOT EXISTS signer_settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

	-- FROST threshold signing tables
	CREATE TABLE IF NOT EXISTS signer_frost_keys (
		id TEXT PRIMARY KEY,
		name TEXT,
		pubkey TEXT UNIQUE NOT NULL,
		threshold INTEGER NOT NULL,
		total_shares INTEGER NOT NULL,
		group_public_key BYTEA NOT NULL,
		verification_shares BYTEA NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		created_by TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_signer_frost_keys_pubkey ON signer_frost_keys(pubkey);

	CREATE TABLE IF NOT EXISTS signer_frost_shares (
		id TEXT PRIMARY KEY,
		frost_key_id TEXT NOT NULL REFERENCES signer_frost_keys(id) ON DELETE CASCADE,
		share_index INTEGER NOT NULL,
		encrypted_share BYTEA,
		holder_pubkey TEXT,
		holder_bunker_uri TEXT,
		is_local BOOLEAN NOT NULL DEFAULT TRUE,
		public_share BYTEA,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
		UNIQUE(frost_key_id, share_index)
	);

	CREATE INDEX IF NOT EXISTS idx_signer_frost_shares_key ON signer_frost_shares(frost_key_id);
	`

	_, err := ps.db.Exec(schema)
	return err
}

// Key management

func (ps *PostgresStorage) CreateKey(ctx context.Context, key *Key) error {
	// Ensure the pubkey exists in the platform users table
	// The signer is a FREE service, so we just ensure the user exists
	if err := ps.EnsurePlatformUser(ctx, key.Pubkey); err != nil {
		// Log but don't fail - platform table might not exist in standalone mode
		// The signer should work independently of the platform
	}

	// Default to local key type if not specified
	keyType := key.KeyType
	if keyType == "" {
		keyType = KeyTypeLocal
	}

	_, err := ps.db.ExecContext(ctx, `
		INSERT INTO signer_keys (id, name, pubkey, key_type, encrypted_nsec, bunker_uri, upstream_pubkey, relays, created_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
		key.ID, key.Name, key.Pubkey, keyType, nullString(key.EncryptedNsec), nullString(key.BunkerURI),
		nullString(key.UpstreamPubkey), pq.Array(key.Relays), key.CreatedAt, key.CreatedBy)
	if err != nil {
		if isDuplicateError(err) {
			return ErrKeyExists
		}
		return err
	}
	return nil
}

func (ps *PostgresStorage) GetKey(ctx context.Context, id string) (*Key, error) {
	key := &Key{}
	var encryptedNsec, bunkerURI, upstreamPubkey sql.NullString
	err := ps.db.QueryRowContext(ctx, `
		SELECT id, name, pubkey, key_type, encrypted_nsec, bunker_uri, upstream_pubkey, require_approval, relays, created_at, created_by
		FROM signer_keys WHERE id = $1`, id).
		Scan(&key.ID, &key.Name, &key.Pubkey, &key.KeyType, &encryptedNsec, &bunkerURI, &upstreamPubkey,
			&key.RequireApproval, pq.Array(&key.Relays), &key.CreatedAt, &key.CreatedBy)
	if err == sql.ErrNoRows {
		return nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	if encryptedNsec.Valid {
		key.EncryptedNsec = encryptedNsec.String
	}
	if bunkerURI.Valid {
		key.BunkerURI = bunkerURI.String
	}
	if upstreamPubkey.Valid {
		key.UpstreamPubkey = upstreamPubkey.String
	}
	return key, nil
}

func (ps *PostgresStorage) GetKeyByPubkey(ctx context.Context, pubkey string) (*Key, error) {
	key := &Key{}
	var encryptedNsec, bunkerURI, upstreamPubkey sql.NullString
	err := ps.db.QueryRowContext(ctx, `
		SELECT id, name, pubkey, key_type, encrypted_nsec, bunker_uri, upstream_pubkey, require_approval, relays, created_at, created_by
		FROM signer_keys WHERE pubkey = $1`, pubkey).
		Scan(&key.ID, &key.Name, &key.Pubkey, &key.KeyType, &encryptedNsec, &bunkerURI, &upstreamPubkey,
			&key.RequireApproval, pq.Array(&key.Relays), &key.CreatedAt, &key.CreatedBy)
	if err == sql.ErrNoRows {
		return nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	if encryptedNsec.Valid {
		key.EncryptedNsec = encryptedNsec.String
	}
	if bunkerURI.Valid {
		key.BunkerURI = bunkerURI.String
	}
	if upstreamPubkey.Valid {
		key.UpstreamPubkey = upstreamPubkey.String
	}
	return key, nil
}

func (ps *PostgresStorage) GetKeyByName(ctx context.Context, name string) (*Key, error) {
	key := &Key{}
	var encryptedNsec, bunkerURI, upstreamPubkey sql.NullString
	err := ps.db.QueryRowContext(ctx, `
		SELECT id, name, pubkey, key_type, encrypted_nsec, bunker_uri, upstream_pubkey, require_approval, relays, created_at, created_by
		FROM signer_keys WHERE name = $1`, name).
		Scan(&key.ID, &key.Name, &key.Pubkey, &key.KeyType, &encryptedNsec, &bunkerURI, &upstreamPubkey,
			&key.RequireApproval, pq.Array(&key.Relays), &key.CreatedAt, &key.CreatedBy)
	if err == sql.ErrNoRows {
		return nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	if encryptedNsec.Valid {
		key.EncryptedNsec = encryptedNsec.String
	}
	if bunkerURI.Valid {
		key.BunkerURI = bunkerURI.String
	}
	if upstreamPubkey.Valid {
		key.UpstreamPubkey = upstreamPubkey.String
	}
	return key, nil
}

func (ps *PostgresStorage) ListKeys(ctx context.Context) ([]*Key, error) {
	rows, err := ps.db.QueryContext(ctx, `
		SELECT id, name, pubkey, key_type, encrypted_nsec, bunker_uri, upstream_pubkey, require_approval, relays, created_at, created_by
		FROM signer_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*Key
	for rows.Next() {
		key := &Key{}
		var encryptedNsec, bunkerURI, upstreamPubkey sql.NullString
		if err := rows.Scan(&key.ID, &key.Name, &key.Pubkey, &key.KeyType, &encryptedNsec, &bunkerURI, &upstreamPubkey,
			&key.RequireApproval, pq.Array(&key.Relays), &key.CreatedAt, &key.CreatedBy); err != nil {
			return nil, err
		}
		if encryptedNsec.Valid {
			key.EncryptedNsec = encryptedNsec.String
		}
		if bunkerURI.Valid {
			key.BunkerURI = bunkerURI.String
		}
		if upstreamPubkey.Valid {
			key.UpstreamPubkey = upstreamPubkey.String
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (ps *PostgresStorage) UpdateKey(ctx context.Context, key *Key) error {
	result, err := ps.db.ExecContext(ctx, `
		UPDATE signer_keys SET name = $1, require_approval = $2, relays = $3,
			key_type = $4, bunker_uri = $5, upstream_pubkey = $6
		WHERE id = $7`,
		key.Name, key.RequireApproval, pq.Array(key.Relays),
		key.KeyType, nullString(key.BunkerURI), nullString(key.UpstreamPubkey), key.ID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrKeyNotFound
	}
	return nil
}

func (ps *PostgresStorage) DeleteKey(ctx context.Context, id string) error {
	result, err := ps.db.ExecContext(ctx, `DELETE FROM signer_keys WHERE id = $1`, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrKeyNotFound
	}
	// Also delete related permissions
	_, _ = ps.db.ExecContext(ctx, `DELETE FROM signer_permissions WHERE key_id = $1`, id)
	return nil
}

// Permission management

func (ps *PostgresStorage) SetPermission(ctx context.Context, perm *Permission) error {
	// Set created_at if not set
	if perm.CreatedAt.IsZero() {
		perm.CreatedAt = time.Now()
	}
	_, err := ps.db.ExecContext(ctx, `
		INSERT INTO signer_permissions (key_id, user_pubkey, methods, allowed_kinds, expires_at, policy_id, require_approval, app_name, app_url, app_image, custom_name, created_at, last_used_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (key_id, user_pubkey) DO UPDATE SET
			methods = EXCLUDED.methods,
			allowed_kinds = EXCLUDED.allowed_kinds,
			expires_at = EXCLUDED.expires_at,
			policy_id = EXCLUDED.policy_id,
			require_approval = EXCLUDED.require_approval,
			app_name = COALESCE(EXCLUDED.app_name, signer_permissions.app_name),
			app_url = COALESCE(EXCLUDED.app_url, signer_permissions.app_url),
			app_image = COALESCE(EXCLUDED.app_image, signer_permissions.app_image),
			custom_name = COALESCE(EXCLUDED.custom_name, signer_permissions.custom_name)`,
		perm.KeyID, perm.UserPubkey, pq.Array(perm.Methods), intArrayToInt64(perm.AllowedKinds), perm.ExpiresAt, perm.PolicyID, perm.RequireApproval,
		nullString(perm.AppName), nullString(perm.AppURL), nullString(perm.AppImage), nullString(perm.CustomName), perm.CreatedAt, perm.LastUsedAt)
	return err
}

func (ps *PostgresStorage) GetPermission(ctx context.Context, keyID, userPubkey string) (*Permission, error) {
	perm := &Permission{}
	var expiresAt, lastUsedAt sql.NullTime
	var policyID, appName, appURL, appImage, customName sql.NullString
	var allowedKinds pq.Int64Array
	var requireApproval sql.NullBool
	err := ps.db.QueryRowContext(ctx, `
		SELECT key_id, user_pubkey, methods, allowed_kinds, expires_at, policy_id, require_approval,
		       app_name, app_url, app_image, custom_name, created_at, last_used_at
		FROM signer_permissions WHERE key_id = $1 AND user_pubkey = $2`, keyID, userPubkey).
		Scan(&perm.KeyID, &perm.UserPubkey, pq.Array(&perm.Methods), &allowedKinds, &expiresAt, &policyID, &requireApproval,
			&appName, &appURL, &appImage, &customName, &perm.CreatedAt, &lastUsedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotAuthorized
	}
	if err != nil {
		return nil, err
	}

	perm.AllowedKinds = int64ArrayToInt(allowedKinds)
	if expiresAt.Valid {
		perm.ExpiresAt = &expiresAt.Time
		if time.Now().After(*perm.ExpiresAt) {
			return nil, ErrNotAuthorized
		}
	}
	if policyID.Valid {
		perm.PolicyID = policyID.String
	}
	if requireApproval.Valid {
		perm.RequireApproval = &requireApproval.Bool
	}
	if appName.Valid {
		perm.AppName = appName.String
	}
	if appURL.Valid {
		perm.AppURL = appURL.String
	}
	if appImage.Valid {
		perm.AppImage = appImage.String
	}
	if customName.Valid {
		perm.CustomName = customName.String
	}
	if lastUsedAt.Valid {
		perm.LastUsedAt = &lastUsedAt.Time
	}
	return perm, nil
}

func (ps *PostgresStorage) ListPermissions(ctx context.Context, keyID string) ([]*Permission, error) {
	rows, err := ps.db.QueryContext(ctx, `
		SELECT key_id, user_pubkey, methods, allowed_kinds, expires_at, policy_id, require_approval,
		       app_name, app_url, app_image, custom_name, created_at, last_used_at
		FROM signer_permissions WHERE key_id = $1`, keyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []*Permission
	for rows.Next() {
		perm := &Permission{}
		var expiresAt, lastUsedAt sql.NullTime
		var policyID, appName, appURL, appImage, customName sql.NullString
		var allowedKinds pq.Int64Array
		var requireApproval sql.NullBool
		if err := rows.Scan(&perm.KeyID, &perm.UserPubkey, pq.Array(&perm.Methods), &allowedKinds, &expiresAt, &policyID, &requireApproval,
			&appName, &appURL, &appImage, &customName, &perm.CreatedAt, &lastUsedAt); err != nil {
			return nil, err
		}
		perm.AllowedKinds = int64ArrayToInt(allowedKinds)
		if expiresAt.Valid {
			perm.ExpiresAt = &expiresAt.Time
		}
		if policyID.Valid {
			perm.PolicyID = policyID.String
		}
		if requireApproval.Valid {
			perm.RequireApproval = &requireApproval.Bool
		}
		if appName.Valid {
			perm.AppName = appName.String
		}
		if appURL.Valid {
			perm.AppURL = appURL.String
		}
		if appImage.Valid {
			perm.AppImage = appImage.String
		}
		if customName.Valid {
			perm.CustomName = customName.String
		}
		if lastUsedAt.Valid {
			perm.LastUsedAt = &lastUsedAt.Time
		}
		perms = append(perms, perm)
	}
	return perms, rows.Err()
}

func (ps *PostgresStorage) DeletePermission(ctx context.Context, keyID, userPubkey string) error {
	_, err := ps.db.ExecContext(ctx, `
		DELETE FROM signer_permissions WHERE key_id = $1 AND user_pubkey = $2`, keyID, userPubkey)
	return err
}

func (ps *PostgresStorage) UpdatePermissionLastUsed(ctx context.Context, keyID, userPubkey string) error {
	_, err := ps.db.ExecContext(ctx, `
		UPDATE signer_permissions SET last_used_at = NOW() WHERE key_id = $1 AND user_pubkey = $2`, keyID, userPubkey)
	return err
}

func (ps *PostgresStorage) UpdatePermissionName(ctx context.Context, keyID, userPubkey, customName string) error {
	result, err := ps.db.ExecContext(ctx, `
		UPDATE signer_permissions SET custom_name = $3 WHERE key_id = $1 AND user_pubkey = $2`, keyID, userPubkey, nullString(customName))
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrKeyNotFound
	}
	return nil
}

// Session management

func (ps *PostgresStorage) CreateSession(ctx context.Context, session *Session) error {
	_, err := ps.db.ExecContext(ctx, `
		INSERT INTO signer_sessions (id, key_id, client_pubkey, permissions, created_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (key_id, client_pubkey) DO UPDATE SET
			id = EXCLUDED.id,
			permissions = EXCLUDED.permissions,
			created_at = EXCLUDED.created_at,
			expires_at = EXCLUDED.expires_at`,
		session.ID, session.KeyID, session.ClientPubkey, pq.Array(session.Permissions), session.CreatedAt, session.ExpiresAt)
	return err
}

func (ps *PostgresStorage) GetSession(ctx context.Context, id string) (*Session, error) {
	session := &Session{}
	err := ps.db.QueryRowContext(ctx, `
		SELECT id, key_id, client_pubkey, permissions, created_at, expires_at
		FROM signer_sessions WHERE id = $1 AND expires_at > NOW()`, id).
		Scan(&session.ID, &session.KeyID, &session.ClientPubkey, pq.Array(&session.Permissions), &session.CreatedAt, &session.ExpiresAt)
	if err == sql.ErrNoRows {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	return session, nil
}

func (ps *PostgresStorage) GetSessionByClient(ctx context.Context, keyID, clientPubkey string) (*Session, error) {
	session := &Session{}
	err := ps.db.QueryRowContext(ctx, `
		SELECT id, key_id, client_pubkey, permissions, created_at, expires_at
		FROM signer_sessions WHERE key_id = $1 AND client_pubkey = $2 AND expires_at > NOW()`, keyID, clientPubkey).
		Scan(&session.ID, &session.KeyID, &session.ClientPubkey, pq.Array(&session.Permissions), &session.CreatedAt, &session.ExpiresAt)
	if err == sql.ErrNoRows {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}
	return session, nil
}

func (ps *PostgresStorage) DeleteSession(ctx context.Context, id string) error {
	_, err := ps.db.ExecContext(ctx, `DELETE FROM signer_sessions WHERE id = $1`, id)
	return err
}

func (ps *PostgresStorage) CleanExpiredSessions(ctx context.Context) error {
	_, err := ps.db.ExecContext(ctx, `DELETE FROM signer_sessions WHERE expires_at < NOW()`)
	return err
}

// Policy management

func (ps *PostgresStorage) CreatePolicy(ctx context.Context, policy *Policy) error {
	tx, err := ps.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `
		INSERT INTO signer_policies (id, name, description, expires_at, created_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		policy.ID, policy.Name, policy.Description, policy.ExpiresAt, policy.CreatedAt, policy.CreatedBy)
	if err != nil {
		return err
	}

	for _, rule := range policy.Rules {
		_, err = tx.ExecContext(ctx, `
			INSERT INTO signer_policy_rules (id, policy_id, method, allowed_kinds, max_usage, current_usage)
			VALUES ($1, $2, $3, $4, $5, $6)`,
			rule.ID, policy.ID, rule.Method, intArrayToInt64(rule.AllowedKinds), rule.MaxUsage, rule.CurrentUsage)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (ps *PostgresStorage) GetPolicy(ctx context.Context, id string) (*Policy, error) {
	policy := &Policy{}
	var expiresAt sql.NullTime
	var description, createdBy sql.NullString
	err := ps.db.QueryRowContext(ctx, `
		SELECT id, name, description, expires_at, created_at, created_by
		FROM signer_policies WHERE id = $1`, id).
		Scan(&policy.ID, &policy.Name, &description, &expiresAt, &policy.CreatedAt, &createdBy)
	if err == sql.ErrNoRows {
		return nil, ErrPolicyNotFound
	}
	if err != nil {
		return nil, err
	}

	if expiresAt.Valid {
		policy.ExpiresAt = &expiresAt.Time
		if time.Now().After(*policy.ExpiresAt) {
			return nil, ErrPolicyNotFound
		}
	}
	if description.Valid {
		policy.Description = description.String
	}
	if createdBy.Valid {
		policy.CreatedBy = createdBy.String
	}

	// Load rules
	rows, err := ps.db.QueryContext(ctx, `
		SELECT id, policy_id, method, allowed_kinds, max_usage, current_usage
		FROM signer_policy_rules WHERE policy_id = $1`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		rule := &PolicyRule{}
		var allowedKinds pq.Int64Array
		if err := rows.Scan(&rule.ID, &rule.PolicyID, &rule.Method, &allowedKinds, &rule.MaxUsage, &rule.CurrentUsage); err != nil {
			return nil, err
		}
		rule.AllowedKinds = int64ArrayToInt(allowedKinds)
		policy.Rules = append(policy.Rules, rule)
	}

	return policy, rows.Err()
}

func (ps *PostgresStorage) ListPolicies(ctx context.Context) ([]*Policy, error) {
	rows, err := ps.db.QueryContext(ctx, `
		SELECT id, name, description, expires_at, created_at, created_by
		FROM signer_policies WHERE expires_at IS NULL OR expires_at > NOW()
		ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []*Policy
	for rows.Next() {
		policy := &Policy{}
		var expiresAt sql.NullTime
		var description, createdBy sql.NullString
		if err := rows.Scan(&policy.ID, &policy.Name, &description, &expiresAt, &policy.CreatedAt, &createdBy); err != nil {
			return nil, err
		}
		if expiresAt.Valid {
			policy.ExpiresAt = &expiresAt.Time
		}
		if description.Valid {
			policy.Description = description.String
		}
		if createdBy.Valid {
			policy.CreatedBy = createdBy.String
		}
		policies = append(policies, policy)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Load rules for each policy
	for _, policy := range policies {
		ruleRows, err := ps.db.QueryContext(ctx, `
			SELECT id, policy_id, method, allowed_kinds, max_usage, current_usage
			FROM signer_policy_rules WHERE policy_id = $1`, policy.ID)
		if err != nil {
			return nil, err
		}
		for ruleRows.Next() {
			rule := &PolicyRule{}
			var allowedKinds pq.Int64Array
			if err := ruleRows.Scan(&rule.ID, &rule.PolicyID, &rule.Method, &allowedKinds, &rule.MaxUsage, &rule.CurrentUsage); err != nil {
				ruleRows.Close()
				return nil, err
			}
			rule.AllowedKinds = int64ArrayToInt(allowedKinds)
			policy.Rules = append(policy.Rules, rule)
		}
		ruleRows.Close()
	}

	return policies, nil
}

func (ps *PostgresStorage) DeletePolicy(ctx context.Context, id string) error {
	result, err := ps.db.ExecContext(ctx, `DELETE FROM signer_policies WHERE id = $1`, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrPolicyNotFound
	}
	return nil
}

func (ps *PostgresStorage) IncrementRuleUsage(ctx context.Context, ruleID string) error {
	result, err := ps.db.ExecContext(ctx, `
		UPDATE signer_policy_rules SET current_usage = current_usage + 1 WHERE id = $1`, ruleID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrPolicyNotFound
	}
	return nil
}

// Token management

func (ps *PostgresStorage) CreateToken(ctx context.Context, token *Token) error {
	_, err := ps.db.ExecContext(ctx, `
		INSERT INTO signer_tokens (id, policy_id, key_id, client_name, created_by, expires_at, redeemed_at, redeemed_by, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		token.ID, token.PolicyID, token.KeyID, token.ClientName, token.CreatedBy,
		token.ExpiresAt, token.RedeemedAt, token.RedeemedBy, token.CreatedAt)
	return err
}

func (ps *PostgresStorage) GetToken(ctx context.Context, id string) (*Token, error) {
	token := &Token{}
	var clientName, createdBy, redeemedBy sql.NullString
	var expiresAt, redeemedAt sql.NullTime
	err := ps.db.QueryRowContext(ctx, `
		SELECT id, policy_id, key_id, client_name, created_by, expires_at, redeemed_at, redeemed_by, created_at
		FROM signer_tokens WHERE id = $1`, id).
		Scan(&token.ID, &token.PolicyID, &token.KeyID, &clientName, &createdBy,
			&expiresAt, &redeemedAt, &redeemedBy, &token.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrTokenNotFound
	}
	if err != nil {
		return nil, err
	}

	if clientName.Valid {
		token.ClientName = clientName.String
	}
	if createdBy.Valid {
		token.CreatedBy = createdBy.String
	}
	if expiresAt.Valid {
		token.ExpiresAt = &expiresAt.Time
	}
	if redeemedAt.Valid {
		token.RedeemedAt = &redeemedAt.Time
	}
	if redeemedBy.Valid {
		token.RedeemedBy = redeemedBy.String
	}
	return token, nil
}

func (ps *PostgresStorage) ListTokens(ctx context.Context, keyID string) ([]*Token, error) {
	rows, err := ps.db.QueryContext(ctx, `
		SELECT id, policy_id, key_id, client_name, created_by, expires_at, redeemed_at, redeemed_by, created_at
		FROM signer_tokens WHERE key_id = $1 ORDER BY created_at DESC`, keyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []*Token
	for rows.Next() {
		token := &Token{}
		var clientName, createdBy, redeemedBy sql.NullString
		var expiresAt, redeemedAt sql.NullTime
		if err := rows.Scan(&token.ID, &token.PolicyID, &token.KeyID, &clientName, &createdBy,
			&expiresAt, &redeemedAt, &redeemedBy, &token.CreatedAt); err != nil {
			return nil, err
		}
		if clientName.Valid {
			token.ClientName = clientName.String
		}
		if createdBy.Valid {
			token.CreatedBy = createdBy.String
		}
		if expiresAt.Valid {
			token.ExpiresAt = &expiresAt.Time
		}
		if redeemedAt.Valid {
			token.RedeemedAt = &redeemedAt.Time
		}
		if redeemedBy.Valid {
			token.RedeemedBy = redeemedBy.String
		}
		tokens = append(tokens, token)
	}
	return tokens, rows.Err()
}

func (ps *PostgresStorage) RedeemToken(ctx context.Context, tokenID, redeemerPubkey string) (*Token, error) {
	token, err := ps.GetToken(ctx, tokenID)
	if err != nil {
		return nil, err
	}

	if token.RedeemedAt != nil {
		return nil, ErrTokenRedeemed
	}

	if token.ExpiresAt != nil && time.Now().After(*token.ExpiresAt) {
		return nil, ErrTokenExpired
	}

	now := time.Now()
	_, err = ps.db.ExecContext(ctx, `
		UPDATE signer_tokens SET redeemed_at = $1, redeemed_by = $2 WHERE id = $3`,
		now, redeemerPubkey, tokenID)
	if err != nil {
		return nil, err
	}

	token.RedeemedAt = &now
	token.RedeemedBy = redeemerPubkey
	return token, nil
}

func (ps *PostgresStorage) DeleteToken(ctx context.Context, id string) error {
	result, err := ps.db.ExecContext(ctx, `DELETE FROM signer_tokens WHERE id = $1`, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrTokenNotFound
	}
	return nil
}

// Pending request management

func (ps *PostgresStorage) CreatePendingRequest(ctx context.Context, req *PendingRequest) error {
	paramsJSON, err := json.Marshal(req.Params)
	if err != nil {
		return err
	}
	_, err = ps.db.ExecContext(ctx, `
		INSERT INTO signer_pending_requests (id, key_pubkey, client_pubkey, method, params, event_kind, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		req.ID, req.KeyPubkey, req.ClientPubkey, req.Method, paramsJSON, req.EventKind, req.ExpiresAt, req.CreatedAt)
	return err
}

func (ps *PostgresStorage) GetPendingRequest(ctx context.Context, id string) (*PendingRequest, error) {
	req := &PendingRequest{}
	var paramsJSON []byte
	var eventKind sql.NullInt64
	err := ps.db.QueryRowContext(ctx, `
		SELECT id, key_pubkey, client_pubkey, method, params, event_kind, expires_at, created_at
		FROM signer_pending_requests WHERE id = $1 AND expires_at > NOW()`, id).
		Scan(&req.ID, &req.KeyPubkey, &req.ClientPubkey, &req.Method, &paramsJSON, &eventKind, &req.ExpiresAt, &req.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrRequestNotFound
	}
	if err != nil {
		return nil, err
	}

	if paramsJSON != nil {
		if err := json.Unmarshal(paramsJSON, &req.Params); err != nil {
			return nil, err
		}
	}
	if eventKind.Valid {
		kind := int(eventKind.Int64)
		req.EventKind = &kind
	}
	return req, nil
}

func (ps *PostgresStorage) ListPendingRequests(ctx context.Context, keyPubkey string) ([]*PendingRequest, error) {
	rows, err := ps.db.QueryContext(ctx, `
		SELECT id, key_pubkey, client_pubkey, method, params, event_kind, expires_at, created_at
		FROM signer_pending_requests WHERE key_pubkey = $1 AND expires_at > NOW()
		ORDER BY created_at DESC`, keyPubkey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var requests []*PendingRequest
	for rows.Next() {
		req := &PendingRequest{}
		var paramsJSON []byte
		var eventKind sql.NullInt64
		if err := rows.Scan(&req.ID, &req.KeyPubkey, &req.ClientPubkey, &req.Method, &paramsJSON, &eventKind, &req.ExpiresAt, &req.CreatedAt); err != nil {
			return nil, err
		}
		if paramsJSON != nil {
			if err := json.Unmarshal(paramsJSON, &req.Params); err != nil {
				return nil, err
			}
		}
		if eventKind.Valid {
			kind := int(eventKind.Int64)
			req.EventKind = &kind
		}
		requests = append(requests, req)
	}
	return requests, rows.Err()
}

func (ps *PostgresStorage) DeletePendingRequest(ctx context.Context, id string) error {
	_, err := ps.db.ExecContext(ctx, `DELETE FROM signer_pending_requests WHERE id = $1`, id)
	return err
}

func (ps *PostgresStorage) CleanExpiredRequests(ctx context.Context) error {
	_, err := ps.db.ExecContext(ctx, `DELETE FROM signer_pending_requests WHERE expires_at < NOW()`)
	return err
}

// User management

func (ps *PostgresStorage) CreateUser(ctx context.Context, user *User) error {
	if user.Role == "" {
		user.Role = "user"
	}
	_, err := ps.db.ExecContext(ctx, `
		INSERT INTO signer_web_accounts (id, username, email, pubkey, role, password_hash, mfa_secret, mfa_enabled, backup_codes, backup_codes_used,
			failed_login_attempts, locked_until, last_login_at, last_login_ip, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
		user.ID, user.Username, nullString(user.Email), nullString(user.Pubkey), user.Role,
		user.PasswordHash, nullString(user.MFASecret),
		user.MFAEnabled, pq.Array(user.BackupCodes), user.BackupCodesUsed, user.FailedLoginAttempts,
		user.LockedUntil, user.LastLoginAt, nullString(user.LastLoginIP), user.CreatedAt, user.UpdatedAt)
	if err != nil {
		if isDuplicateError(err) {
			return ErrUserExists
		}
		return err
	}
	return nil
}

func (ps *PostgresStorage) GetUser(ctx context.Context, id string) (*User, error) {
	return ps.scanUser(ps.db.QueryRowContext(ctx, `
		SELECT id, username, email, pubkey, role, password_hash, mfa_secret, mfa_enabled, backup_codes, backup_codes_used,
			failed_login_attempts, locked_until, last_login_at, last_login_ip, created_at, updated_at
		FROM signer_web_accounts WHERE id = $1`, id))
}

func (ps *PostgresStorage) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	return ps.scanUser(ps.db.QueryRowContext(ctx, `
		SELECT id, username, email, pubkey, role, password_hash, mfa_secret, mfa_enabled, backup_codes, backup_codes_used,
			failed_login_attempts, locked_until, last_login_at, last_login_ip, created_at, updated_at
		FROM signer_web_accounts WHERE username = $1`, username))
}

func (ps *PostgresStorage) GetUserByPubkey(ctx context.Context, pubkey string) (*User, error) {
	return ps.scanUser(ps.db.QueryRowContext(ctx, `
		SELECT id, username, email, pubkey, role, password_hash, mfa_secret, mfa_enabled, backup_codes, backup_codes_used,
			failed_login_attempts, locked_until, last_login_at, last_login_ip, created_at, updated_at
		FROM signer_web_accounts WHERE pubkey = $1`, pubkey))
}

func (ps *PostgresStorage) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	return ps.scanUser(ps.db.QueryRowContext(ctx, `
		SELECT id, username, email, pubkey, role, password_hash, mfa_secret, mfa_enabled, backup_codes, backup_codes_used,
			failed_login_attempts, locked_until, last_login_at, last_login_ip, created_at, updated_at
		FROM signer_web_accounts WHERE email = $1`, email))
}

func (ps *PostgresStorage) scanUser(row *sql.Row) (*User, error) {
	user := &User{}
	var email, pubkey, mfaSecret, lastLoginIP sql.NullString
	var lockedUntil, lastLoginAt sql.NullTime
	err := row.Scan(&user.ID, &user.Username, &email, &pubkey, &user.Role, &user.PasswordHash, &mfaSecret,
		&user.MFAEnabled, pq.Array(&user.BackupCodes), &user.BackupCodesUsed, &user.FailedLoginAttempts,
		&lockedUntil, &lastLoginAt, &lastLoginIP, &user.CreatedAt, &user.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}

	if email.Valid {
		user.Email = email.String
	}
	if pubkey.Valid {
		user.Pubkey = pubkey.String
	}
	if mfaSecret.Valid {
		user.MFASecret = mfaSecret.String
	}
	if lastLoginIP.Valid {
		user.LastLoginIP = lastLoginIP.String
	}
	if lockedUntil.Valid {
		user.LockedUntil = &lockedUntil.Time
	}
	if lastLoginAt.Valid {
		user.LastLoginAt = &lastLoginAt.Time
	}
	return user, nil
}

func (ps *PostgresStorage) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := ps.db.QueryContext(ctx, `
		SELECT id, username, email, pubkey, role, password_hash, mfa_secret, mfa_enabled, backup_codes, backup_codes_used,
			failed_login_attempts, locked_until, last_login_at, last_login_ip, created_at, updated_at
		FROM signer_web_accounts ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		user := &User{}
		var email, pubkey, mfaSecret, lastLoginIP sql.NullString
		var lockedUntil, lastLoginAt sql.NullTime
		if err := rows.Scan(&user.ID, &user.Username, &email, &pubkey, &user.Role, &user.PasswordHash, &mfaSecret,
			&user.MFAEnabled, pq.Array(&user.BackupCodes), &user.BackupCodesUsed, &user.FailedLoginAttempts,
			&lockedUntil, &lastLoginAt, &lastLoginIP, &user.CreatedAt, &user.UpdatedAt); err != nil {
			return nil, err
		}
		if email.Valid {
			user.Email = email.String
		}
		if pubkey.Valid {
			user.Pubkey = pubkey.String
		}
		if mfaSecret.Valid {
			user.MFASecret = mfaSecret.String
		}
		if lastLoginIP.Valid {
			user.LastLoginIP = lastLoginIP.String
		}
		if lockedUntil.Valid {
			user.LockedUntil = &lockedUntil.Time
		}
		if lastLoginAt.Valid {
			user.LastLoginAt = &lastLoginAt.Time
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

func (ps *PostgresStorage) UpdateUser(ctx context.Context, user *User) error {
	user.UpdatedAt = time.Now()
	result, err := ps.db.ExecContext(ctx, `
		UPDATE signer_web_accounts SET username = $1, email = $2, pubkey = $3, role = $4, password_hash = $5, mfa_secret = $6, mfa_enabled = $7,
			backup_codes = $8, backup_codes_used = $9, failed_login_attempts = $10, locked_until = $11,
			last_login_at = $12, last_login_ip = $13, updated_at = $14
		WHERE id = $15`,
		user.Username, nullString(user.Email), nullString(user.Pubkey), user.Role,
		user.PasswordHash, nullString(user.MFASecret),
		user.MFAEnabled, pq.Array(user.BackupCodes), user.BackupCodesUsed, user.FailedLoginAttempts,
		user.LockedUntil, user.LastLoginAt, nullString(user.LastLoginIP), user.UpdatedAt, user.ID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (ps *PostgresStorage) DeleteUser(ctx context.Context, id string) error {
	result, err := ps.db.ExecContext(ctx, `DELETE FROM signer_web_accounts WHERE id = $1`, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (ps *PostgresStorage) IncrementFailedLogins(ctx context.Context, userID string) error {
	result, err := ps.db.ExecContext(ctx, `
		UPDATE signer_web_accounts SET failed_login_attempts = failed_login_attempts + 1, updated_at = NOW()
		WHERE id = $1`, userID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (ps *PostgresStorage) ResetFailedLogins(ctx context.Context, userID string) error {
	result, err := ps.db.ExecContext(ctx, `
		UPDATE signer_web_accounts SET failed_login_attempts = 0, updated_at = NOW()
		WHERE id = $1`, userID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (ps *PostgresStorage) LockUser(ctx context.Context, userID string, until time.Time) error {
	result, err := ps.db.ExecContext(ctx, `
		UPDATE signer_web_accounts SET locked_until = $1, updated_at = NOW()
		WHERE id = $2`, until, userID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrUserNotFound
	}
	return nil
}

func (ps *PostgresStorage) UnlockUser(ctx context.Context, userID string) error {
	result, err := ps.db.ExecContext(ctx, `
		UPDATE signer_web_accounts SET locked_until = NULL, failed_login_attempts = 0, updated_at = NOW()
		WHERE id = $1`, userID)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrUserNotFound
	}
	return nil
}

// User session management

func (ps *PostgresStorage) CreateUserSession(ctx context.Context, session *UserSession) error {
	_, err := ps.db.ExecContext(ctx, `
		INSERT INTO signer_web_sessions (id, user_id, token_hash, user_agent, ip_address, remember_device, last_activity, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		session.ID, session.UserID, nullString(session.Token), nullString(session.UserAgent),
		nullString(session.IPAddress), session.RememberDevice, session.LastActivity, session.ExpiresAt, session.CreatedAt)
	return err
}

func (ps *PostgresStorage) GetUserSession(ctx context.Context, id string) (*UserSession, error) {
	session := &UserSession{}
	var tokenHash, userAgent, ipAddress sql.NullString
	var lastActivity sql.NullTime
	err := ps.db.QueryRowContext(ctx, `
		SELECT id, user_id, token_hash, user_agent, ip_address, remember_device, last_activity, expires_at, created_at
		FROM signer_web_sessions WHERE id = $1 AND expires_at > NOW()`, id).
		Scan(&session.ID, &session.UserID, &tokenHash, &userAgent, &ipAddress, &session.RememberDevice, &lastActivity, &session.ExpiresAt, &session.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}

	if tokenHash.Valid {
		session.Token = tokenHash.String
	}
	if userAgent.Valid {
		session.UserAgent = userAgent.String
	}
	if ipAddress.Valid {
		session.IPAddress = ipAddress.String
	}
	if lastActivity.Valid {
		session.LastActivity = &lastActivity.Time
	}
	return session, nil
}

func (ps *PostgresStorage) ListUserSessions(ctx context.Context, userID string) ([]*UserSession, error) {
	rows, err := ps.db.QueryContext(ctx, `
		SELECT id, user_id, token_hash, user_agent, ip_address, remember_device, last_activity, expires_at, created_at
		FROM signer_web_sessions WHERE user_id = $1 AND expires_at > NOW()
		ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*UserSession
	for rows.Next() {
		session := &UserSession{}
		var tokenHash, userAgent, ipAddress sql.NullString
		var lastActivity sql.NullTime
		if err := rows.Scan(&session.ID, &session.UserID, &tokenHash, &userAgent, &ipAddress, &session.RememberDevice, &lastActivity, &session.ExpiresAt, &session.CreatedAt); err != nil {
			return nil, err
		}
		if tokenHash.Valid {
			session.Token = tokenHash.String
		}
		if userAgent.Valid {
			session.UserAgent = userAgent.String
		}
		if ipAddress.Valid {
			session.IPAddress = ipAddress.String
		}
		if lastActivity.Valid {
			session.LastActivity = &lastActivity.Time
		}
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

func (ps *PostgresStorage) UpdateUserSessionActivity(ctx context.Context, id string) error {
	result, err := ps.db.ExecContext(ctx, `
		UPDATE signer_web_sessions SET last_activity = NOW() WHERE id = $1 AND expires_at > NOW()`, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrSessionNotFound
	}
	return nil
}

func (ps *PostgresStorage) DeleteUserSession(ctx context.Context, id string) error {
	_, err := ps.db.ExecContext(ctx, `DELETE FROM signer_web_sessions WHERE id = $1`, id)
	return err
}

func (ps *PostgresStorage) DeleteUserSessions(ctx context.Context, userID string) error {
	_, err := ps.db.ExecContext(ctx, `DELETE FROM signer_web_sessions WHERE user_id = $1`, userID)
	return err
}

func (ps *PostgresStorage) CleanExpiredUserSessions(ctx context.Context) error {
	_, err := ps.db.ExecContext(ctx, `DELETE FROM signer_web_sessions WHERE expires_at < NOW()`)
	return err
}

// Bunker secret management

func (ps *PostgresStorage) CreateBunkerSecret(ctx context.Context, secret *BunkerSecret) error {
	_, err := ps.db.ExecContext(ctx, `
		INSERT INTO signer_bunker_secrets (id, key_pubkey, secret, expires_at, created_at, used_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		secret.ID, secret.KeyPubkey, secret.Secret, secret.ExpiresAt, secret.CreatedAt, secret.UsedAt)
	return err
}

func (ps *PostgresStorage) ValidateBunkerSecret(ctx context.Context, keyPubkey, secret string) (*BunkerSecret, error) {
	bs := &BunkerSecret{}
	var usedAt sql.NullTime
	err := ps.db.QueryRowContext(ctx, `
		SELECT id, key_pubkey, secret, expires_at, created_at, used_at
		FROM signer_bunker_secrets WHERE secret = $1 AND key_pubkey = $2`, secret, keyPubkey).
		Scan(&bs.ID, &bs.KeyPubkey, &bs.Secret, &bs.ExpiresAt, &bs.CreatedAt, &usedAt)
	if err == sql.ErrNoRows {
		return nil, ErrBunkerSecretInvalid
	}
	if err != nil {
		return nil, err
	}

	// Check if expired
	if time.Now().After(bs.ExpiresAt) {
		// Clean up expired secret
		_, _ = ps.db.ExecContext(ctx, `DELETE FROM signer_bunker_secrets WHERE id = $1`, bs.ID)
		return nil, ErrBunkerSecretInvalid
	}

	// Check if already used
	if usedAt.Valid {
		return nil, ErrBunkerSecretInvalid
	}

	// Mark as used
	now := time.Now()
	_, err = ps.db.ExecContext(ctx, `UPDATE signer_bunker_secrets SET used_at = $1 WHERE id = $2`, now, bs.ID)
	if err != nil {
		return nil, err
	}

	bs.UsedAt = &now
	return bs, nil
}

func (ps *PostgresStorage) DeleteBunkerSecret(ctx context.Context, id string) error {
	_, err := ps.db.ExecContext(ctx, `DELETE FROM signer_bunker_secrets WHERE id = $1`, id)
	return err
}

func (ps *PostgresStorage) CleanExpiredBunkerSecrets(ctx context.Context) error {
	_, err := ps.db.ExecContext(ctx, `DELETE FROM signer_bunker_secrets WHERE expires_at < NOW()`)
	return err
}

// EnsurePlatformUser upserts a pubkey into the platform users table.
// This integrates with the cloistr platform's unified user management.
// The signer is a FREE service, so we just ensure the user exists - no access checks needed.
func (ps *PostgresStorage) EnsurePlatformUser(ctx context.Context, pubkey string) error {
	_, err := ps.db.ExecContext(ctx, `
		INSERT INTO users (pubkey, enabled, created_at, updated_at)
		VALUES ($1, TRUE, NOW(), NOW())
		ON CONFLICT (pubkey) DO NOTHING`,
		pubkey)
	return err
}

// GrantServiceAccess grants a user access to a service in the platform.
// Used when a user signs up for a service.
func (ps *PostgresStorage) GrantServiceAccess(ctx context.Context, pubkey string, serviceSlug string) error {
	_, err := ps.db.ExecContext(ctx, `
		INSERT INTO user_service_access (pubkey, service_id, enabled, created_at)
		SELECT $1, id, TRUE, NOW()
		FROM services WHERE slug = $2
		ON CONFLICT (pubkey, service_id) DO UPDATE SET enabled = TRUE`,
		pubkey, serviceSlug)
	return err
}

// RevokeServiceAccess revokes a user's access to a service in the platform.
func (ps *PostgresStorage) RevokeServiceAccess(ctx context.Context, pubkey string, serviceSlug string) error {
	_, err := ps.db.ExecContext(ctx, `
		UPDATE user_service_access usa
		SET enabled = FALSE
		FROM services s
		WHERE usa.service_id = s.id
		  AND usa.pubkey = $1
		  AND s.slug = $2`,
		pubkey, serviceSlug)
	return err
}

// ListPlatformUsers returns all platform users with their service access.
// Returns users, total count, and error.
func (ps *PostgresStorage) ListPlatformUsers(ctx context.Context, limit, offset int) ([]*PlatformUser, int, error) {
	// Get total count
	var total int
	err := ps.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&total)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to count users: %w", err)
	}

	// Get users with pagination
	rows, err := ps.db.QueryContext(ctx, `
		SELECT pubkey, enabled, created_at, updated_at
		FROM users
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2`,
		limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query users: %w", err)
	}
	defer rows.Close()

	var users []*PlatformUser
	for rows.Next() {
		user := &PlatformUser{}
		if err := rows.Scan(&user.Pubkey, &user.Enabled, &user.CreatedAt, &user.UpdatedAt); err != nil {
			return nil, 0, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, user)
	}

	// Get service access for each user
	for _, user := range users {
		services, err := ps.getUserServices(ctx, user.Pubkey)
		if err != nil {
			slog.Warn("failed to get user services", "pubkey", user.Pubkey[:16]+"...", "error", err)
			continue
		}
		user.Services = services
	}

	return users, total, nil
}

// getUserServices returns service access for a user
func (ps *PostgresStorage) getUserServices(ctx context.Context, pubkey string) ([]ServiceAccess, error) {
	rows, err := ps.db.QueryContext(ctx, `
		SELECT s.id, s.slug, s.name, usa.enabled, usa.created_at
		FROM user_service_access usa
		JOIN services s ON usa.service_id = s.id
		WHERE usa.pubkey = $1
		ORDER BY s.name`,
		pubkey)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var services []ServiceAccess
	for rows.Next() {
		var sa ServiceAccess
		if err := rows.Scan(&sa.ServiceID, &sa.ServiceSlug, &sa.ServiceName, &sa.Enabled, &sa.CreatedAt); err != nil {
			return nil, err
		}
		services = append(services, sa)
	}

	return services, nil
}

// GetPlatformUserAccess returns a single platform user with service access
func (ps *PostgresStorage) GetPlatformUserAccess(ctx context.Context, pubkey string) (*PlatformUser, error) {
	user := &PlatformUser{}
	err := ps.db.QueryRowContext(ctx, `
		SELECT pubkey, enabled, created_at, updated_at
		FROM users
		WHERE pubkey = $1`,
		pubkey).Scan(&user.Pubkey, &user.Enabled, &user.CreatedAt, &user.UpdatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to query user: %w", err)
	}

	services, err := ps.getUserServices(ctx, pubkey)
	if err != nil {
		return nil, fmt.Errorf("failed to get user services: %w", err)
	}
	user.Services = services

	return user, nil
}

// ListServices returns all available services in the platform
func (ps *PostgresStorage) ListServices(ctx context.Context) ([]*Service, error) {
	rows, err := ps.db.QueryContext(ctx, `
		SELECT id, slug, name, COALESCE(description, ''), is_free
		FROM services
		ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("failed to query services: %w", err)
	}
	defer rows.Close()

	var services []*Service
	for rows.Next() {
		s := &Service{}
		if err := rows.Scan(&s.ID, &s.Slug, &s.Name, &s.Description, &s.IsFree); err != nil {
			return nil, fmt.Errorf("failed to scan service: %w", err)
		}
		services = append(services, s)
	}

	return services, nil
}

// getPlatformIdentitySeed returns the seed used for deriving user identity keys.
// Creates the seed on first access (stored in signer_settings).
func (ps *PostgresStorage) getPlatformIdentitySeed(ctx context.Context) (string, error) {
	const seedKey = "platform_identity_seed"

	// Try to get existing seed
	var seed string
	err := ps.db.QueryRowContext(ctx,
		`SELECT value FROM signer_settings WHERE key = $1`, seedKey).Scan(&seed)
	if err == nil {
		return seed, nil
	}
	if err != sql.ErrNoRows {
		return "", fmt.Errorf("failed to query seed: %w", err)
	}

	// Generate new seed (32 bytes, hex-encoded)
	seedBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, seedBytes); err != nil {
		return "", fmt.Errorf("failed to generate seed: %w", err)
	}
	seed = hex.EncodeToString(seedBytes)

	// Store it (race-safe: ON CONFLICT returns existing value)
	err = ps.db.QueryRowContext(ctx, `
		INSERT INTO signer_settings (key, value, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (key) DO UPDATE SET key = signer_settings.key
		RETURNING value`, seedKey, seed).Scan(&seed)
	if err != nil {
		return "", fmt.Errorf("failed to store seed: %w", err)
	}

	slog.Info("platform identity seed initialized")
	return seed, nil
}

// DeriveUserPubkey deterministically derives a pubkey for a user ID.
// Same user ID always produces the same pubkey.
func (ps *PostgresStorage) DeriveUserPubkey(ctx context.Context, userID string) (string, error) {
	seed, err := ps.getPlatformIdentitySeed(ctx)
	if err != nil {
		return "", err
	}

	privateKey, err := crypto.DeriveNostrKey(seed, userID, "cloistr-platform-identity")
	if err != nil {
		return "", fmt.Errorf("key derivation failed: %w", err)
	}

	pubkey, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("pubkey derivation failed: %w", err)
	}

	return pubkey, nil
}

// backfillPlatformUsers ensures all existing signer web accounts have:
// 1. A pubkey (derives one deterministically if missing)
// 2. A corresponding platform user record
// This runs on startup to catch accounts created before platform integration.
func (ps *PostgresStorage) backfillPlatformUsers(ctx context.Context) error {
	// Find users without pubkeys and derive them deterministically
	rows, err := ps.db.QueryContext(ctx, `
		SELECT id FROM signer_web_accounts WHERE pubkey IS NULL OR pubkey = ''`)
	if err != nil {
		return fmt.Errorf("failed to query users without pubkeys: %w", err)
	}
	defer rows.Close()

	var usersWithoutPubkey []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("failed to scan user id: %w", err)
		}
		usersWithoutPubkey = append(usersWithoutPubkey, id)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating users: %w", err)
	}

	// Derive pubkeys for users without them (deterministic from user ID)
	for _, userID := range usersWithoutPubkey {
		pubkey, err := ps.DeriveUserPubkey(ctx, userID)
		if err != nil {
			slog.Warn("failed to derive pubkey for user", "user_id", userID, "error", err)
			continue
		}

		_, err = ps.db.ExecContext(ctx, `
			UPDATE signer_web_accounts SET pubkey = $1, updated_at = NOW() WHERE id = $2`,
			pubkey, userID)
		if err != nil {
			slog.Warn("failed to update user pubkey", "user_id", userID, "error", err)
			continue
		}
		slog.Info("derived pubkey for existing user", "user_id", userID, "pubkey", pubkey[:16]+"...")
	}

	// Ensure all users with pubkeys have platform records
	_, err = ps.db.ExecContext(ctx, `
		INSERT INTO users (pubkey, enabled, created_at, updated_at)
		SELECT pubkey, TRUE, NOW(), NOW()
		FROM signer_web_accounts
		WHERE pubkey IS NOT NULL AND pubkey != ''
		ON CONFLICT (pubkey) DO NOTHING`)
	if err != nil {
		return fmt.Errorf("failed to backfill platform users: %w", err)
	}

	slog.Info("platform user backfill complete", "users_without_pubkey", len(usersWithoutPubkey))
	return nil
}

func (ps *PostgresStorage) GetSetting(ctx context.Context, key string) (string, error) {
	var value string
	err := ps.db.QueryRowContext(ctx,
		`SELECT value FROM signer_settings WHERE key = $1`, key).Scan(&value)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", ErrSettingNotFound
		}
		return "", err
	}
	return value, nil
}

func (ps *PostgresStorage) SetSetting(ctx context.Context, key, value string) error {
	_, err := ps.db.ExecContext(ctx, `
		INSERT INTO signer_settings (key, value, updated_at)
		VALUES ($1, $2, NOW())
		ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`,
		key, value)
	return err
}

// FROST key management

func (ps *PostgresStorage) CreateFrostKey(ctx context.Context, key *FrostKey) error {
	_, err := ps.db.ExecContext(ctx, `
		INSERT INTO signer_frost_keys (id, name, pubkey, threshold, total_shares, group_public_key, verification_shares, created_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		key.ID, nullString(key.Name), key.Pubkey, key.Threshold, key.TotalShares,
		key.GroupPublicKey, key.VerificationShares, key.CreatedAt, nullString(key.CreatedBy))
	if err != nil {
		if isDuplicateError(err) {
			return ErrKeyExists
		}
		return err
	}
	return nil
}

func (ps *PostgresStorage) GetFrostKey(ctx context.Context, id string) (*FrostKey, error) {
	key := &FrostKey{}
	var name, createdBy sql.NullString
	err := ps.db.QueryRowContext(ctx, `
		SELECT id, name, pubkey, threshold, total_shares, group_public_key, verification_shares, created_at, created_by
		FROM signer_frost_keys WHERE id = $1`, id).
		Scan(&key.ID, &name, &key.Pubkey, &key.Threshold, &key.TotalShares,
			&key.GroupPublicKey, &key.VerificationShares, &key.CreatedAt, &createdBy)
	if err == sql.ErrNoRows {
		return nil, ErrFrostKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	if name.Valid {
		key.Name = name.String
	}
	if createdBy.Valid {
		key.CreatedBy = createdBy.String
	}
	return key, nil
}

func (ps *PostgresStorage) GetFrostKeyByPubkey(ctx context.Context, pubkey string) (*FrostKey, error) {
	key := &FrostKey{}
	var name, createdBy sql.NullString
	err := ps.db.QueryRowContext(ctx, `
		SELECT id, name, pubkey, threshold, total_shares, group_public_key, verification_shares, created_at, created_by
		FROM signer_frost_keys WHERE pubkey = $1`, pubkey).
		Scan(&key.ID, &name, &key.Pubkey, &key.Threshold, &key.TotalShares,
			&key.GroupPublicKey, &key.VerificationShares, &key.CreatedAt, &createdBy)
	if err == sql.ErrNoRows {
		return nil, ErrFrostKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	if name.Valid {
		key.Name = name.String
	}
	if createdBy.Valid {
		key.CreatedBy = createdBy.String
	}
	return key, nil
}

func (ps *PostgresStorage) ListFrostKeys(ctx context.Context) ([]*FrostKey, error) {
	rows, err := ps.db.QueryContext(ctx, `
		SELECT id, name, pubkey, threshold, total_shares, group_public_key, verification_shares, created_at, created_by
		FROM signer_frost_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*FrostKey
	for rows.Next() {
		key := &FrostKey{}
		var name, createdBy sql.NullString
		if err := rows.Scan(&key.ID, &name, &key.Pubkey, &key.Threshold, &key.TotalShares,
			&key.GroupPublicKey, &key.VerificationShares, &key.CreatedAt, &createdBy); err != nil {
			return nil, err
		}
		if name.Valid {
			key.Name = name.String
		}
		if createdBy.Valid {
			key.CreatedBy = createdBy.String
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (ps *PostgresStorage) DeleteFrostKey(ctx context.Context, id string) error {
	result, err := ps.db.ExecContext(ctx, `DELETE FROM signer_frost_keys WHERE id = $1`, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrFrostKeyNotFound
	}
	return nil
}

// FROST share management

func (ps *PostgresStorage) CreateFrostShare(ctx context.Context, share *FrostShare) error {
	_, err := ps.db.ExecContext(ctx, `
		INSERT INTO signer_frost_shares (id, frost_key_id, share_index, encrypted_share, holder_pubkey, holder_bunker_uri, is_local, public_share, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		share.ID, share.FrostKeyID, share.ShareIndex, share.EncryptedShare,
		nullString(share.HolderPubkey), nullString(share.HolderBunkerURI),
		share.IsLocal, share.PublicShare, share.CreatedAt)
	if err != nil {
		if isDuplicateError(err) {
			return ErrFrostShareNotFound // Share with this index already exists
		}
		return err
	}
	return nil
}

func (ps *PostgresStorage) GetFrostShare(ctx context.Context, id string) (*FrostShare, error) {
	share := &FrostShare{}
	var holderPubkey, holderBunkerURI sql.NullString
	err := ps.db.QueryRowContext(ctx, `
		SELECT id, frost_key_id, share_index, encrypted_share, holder_pubkey, holder_bunker_uri, is_local, public_share, created_at
		FROM signer_frost_shares WHERE id = $1`, id).
		Scan(&share.ID, &share.FrostKeyID, &share.ShareIndex, &share.EncryptedShare,
			&holderPubkey, &holderBunkerURI, &share.IsLocal, &share.PublicShare, &share.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrFrostShareNotFound
	}
	if err != nil {
		return nil, err
	}
	if holderPubkey.Valid {
		share.HolderPubkey = holderPubkey.String
	}
	if holderBunkerURI.Valid {
		share.HolderBunkerURI = holderBunkerURI.String
	}
	return share, nil
}

func (ps *PostgresStorage) GetFrostShareByKeyAndIndex(ctx context.Context, keyID string, index int) (*FrostShare, error) {
	share := &FrostShare{}
	var holderPubkey, holderBunkerURI sql.NullString
	err := ps.db.QueryRowContext(ctx, `
		SELECT id, frost_key_id, share_index, encrypted_share, holder_pubkey, holder_bunker_uri, is_local, public_share, created_at
		FROM signer_frost_shares WHERE frost_key_id = $1 AND share_index = $2`, keyID, index).
		Scan(&share.ID, &share.FrostKeyID, &share.ShareIndex, &share.EncryptedShare,
			&holderPubkey, &holderBunkerURI, &share.IsLocal, &share.PublicShare, &share.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrFrostShareNotFound
	}
	if err != nil {
		return nil, err
	}
	if holderPubkey.Valid {
		share.HolderPubkey = holderPubkey.String
	}
	if holderBunkerURI.Valid {
		share.HolderBunkerURI = holderBunkerURI.String
	}
	return share, nil
}

func (ps *PostgresStorage) ListFrostShares(ctx context.Context, keyID string) ([]*FrostShare, error) {
	rows, err := ps.db.QueryContext(ctx, `
		SELECT id, frost_key_id, share_index, encrypted_share, holder_pubkey, holder_bunker_uri, is_local, public_share, created_at
		FROM signer_frost_shares WHERE frost_key_id = $1 ORDER BY share_index`, keyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var shares []*FrostShare
	for rows.Next() {
		share := &FrostShare{}
		var holderPubkey, holderBunkerURI sql.NullString
		if err := rows.Scan(&share.ID, &share.FrostKeyID, &share.ShareIndex, &share.EncryptedShare,
			&holderPubkey, &holderBunkerURI, &share.IsLocal, &share.PublicShare, &share.CreatedAt); err != nil {
			return nil, err
		}
		if holderPubkey.Valid {
			share.HolderPubkey = holderPubkey.String
		}
		if holderBunkerURI.Valid {
			share.HolderBunkerURI = holderBunkerURI.String
		}
		shares = append(shares, share)
	}
	return shares, rows.Err()
}

func (ps *PostgresStorage) ListLocalFrostShares(ctx context.Context, keyID string) ([]*FrostShare, error) {
	rows, err := ps.db.QueryContext(ctx, `
		SELECT id, frost_key_id, share_index, encrypted_share, holder_pubkey, holder_bunker_uri, is_local, public_share, created_at
		FROM signer_frost_shares WHERE frost_key_id = $1 AND is_local = TRUE ORDER BY share_index`, keyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var shares []*FrostShare
	for rows.Next() {
		share := &FrostShare{}
		var holderPubkey, holderBunkerURI sql.NullString
		if err := rows.Scan(&share.ID, &share.FrostKeyID, &share.ShareIndex, &share.EncryptedShare,
			&holderPubkey, &holderBunkerURI, &share.IsLocal, &share.PublicShare, &share.CreatedAt); err != nil {
			return nil, err
		}
		if holderPubkey.Valid {
			share.HolderPubkey = holderPubkey.String
		}
		if holderBunkerURI.Valid {
			share.HolderBunkerURI = holderBunkerURI.String
		}
		shares = append(shares, share)
	}
	return shares, rows.Err()
}

func (ps *PostgresStorage) DeleteFrostShare(ctx context.Context, id string) error {
	result, err := ps.db.ExecContext(ctx, `DELETE FROM signer_frost_shares WHERE id = $1`, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return ErrFrostShareNotFound
	}
	return nil
}

func (ps *PostgresStorage) Close() error {
	return ps.db.Close()
}

// Helper functions

func isDuplicateError(err error) bool {
	if err == nil {
		return false
	}
	// Check for PostgreSQL unique violation error code 23505
	if pqErr, ok := err.(*pq.Error); ok {
		return pqErr.Code == "23505"
	}
	return false
}

func nullString(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

func int64ArrayToInt(arr pq.Int64Array) []int {
	if arr == nil {
		return nil
	}
	result := make([]int, len(arr))
	for i, v := range arr {
		result[i] = int(v)
	}
	return result
}

func intArrayToInt64(arr []int) pq.Int64Array {
	if arr == nil {
		return nil
	}
	result := make(pq.Int64Array, len(arr))
	for i, v := range arr {
		result[i] = int64(v)
	}
	return result
}
