package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// SQLiteStorage implements Storage using SQLite
type SQLiteStorage struct {
	db *sql.DB
}

// NewSQLiteStorage creates a new SQLite-backed storage
func NewSQLiteStorage(path string) (*SQLiteStorage, error) {
	// Enable foreign keys, WAL mode, and busy timeout for better concurrency
	// _busy_timeout=5000 waits up to 5 seconds when the database is locked
	dsn := path + "?_foreign_keys=on&_journal_mode=WAL&_busy_timeout=5000"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	// Limit connections to 1 for SQLite (it handles concurrency via locking)
	db.SetMaxOpenConns(1)

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping sqlite database: %w", err)
	}

	ss := &SQLiteStorage{db: db}

	// Initialize schema
	if err := ss.initSchema(); err != nil {
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return ss, nil
}

func (ss *SQLiteStorage) Close() error {
	return ss.db.Close()
}

func (ss *SQLiteStorage) initSchema() error {
	// SQLite schema - uses TEXT for timestamps and JSON for arrays
	schema := `
	-- Web accounts for authentication
	CREATE TABLE IF NOT EXISTS signer_web_accounts (
		id TEXT PRIMARY KEY,
		username TEXT UNIQUE NOT NULL,
		email TEXT,
		password_hash TEXT NOT NULL,
		mfa_enabled INTEGER NOT NULL DEFAULT 0,
		mfa_secret TEXT,
		backup_codes TEXT,  -- JSON array
		backup_codes_used INTEGER DEFAULT 0,
		failed_login_attempts INTEGER DEFAULT 0,
		locked_until TEXT,
		created_at TEXT NOT NULL DEFAULT (datetime('now')),
		last_login_at TEXT,
		last_login_ip TEXT
	);

	-- Web sessions
	CREATE TABLE IF NOT EXISTS signer_web_sessions (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL REFERENCES signer_web_accounts(id) ON DELETE CASCADE,
		token TEXT NOT NULL,
		vault_token TEXT,
		user_agent TEXT,
		ip_address TEXT,
		remember_device INTEGER NOT NULL DEFAULT 0,
		last_activity TEXT,
		expires_at TEXT NOT NULL,
		created_at TEXT NOT NULL DEFAULT (datetime('now'))
	);

	CREATE INDEX IF NOT EXISTS idx_signer_web_sessions_user ON signer_web_sessions(user_id);
	CREATE INDEX IF NOT EXISTS idx_signer_web_sessions_expires ON signer_web_sessions(expires_at);

	-- Keys table
	CREATE TABLE IF NOT EXISTS signer_keys (
		id TEXT PRIMARY KEY,
		name TEXT,
		pubkey TEXT UNIQUE NOT NULL,
		key_type TEXT NOT NULL DEFAULT 'local',
		encrypted_nsec TEXT,
		encryption_method TEXT DEFAULT 'local',
		bunker_uri TEXT,
		upstream_pubkey TEXT,
		require_approval INTEGER NOT NULL DEFAULT 0,
		disposable_mode INTEGER NOT NULL DEFAULT 0,
		cover_traffic INTEGER NOT NULL DEFAULT 0,
		relays TEXT,  -- JSON array
		created_at TEXT NOT NULL DEFAULT (datetime('now')),
		created_by TEXT,
		owner_id TEXT REFERENCES signer_web_accounts(id)
	);

	CREATE INDEX IF NOT EXISTS idx_signer_keys_pubkey ON signer_keys(pubkey);
	CREATE INDEX IF NOT EXISTS idx_signer_keys_owner ON signer_keys(owner_id);

	-- Permissions table
	CREATE TABLE IF NOT EXISTS signer_permissions (
		key_id TEXT NOT NULL,
		user_pubkey TEXT NOT NULL,
		methods TEXT,  -- JSON array
		allowed_kinds TEXT,  -- JSON array
		expires_at TEXT,
		policy_id TEXT,
		require_approval INTEGER NOT NULL DEFAULT 0,
		app_name TEXT,
		app_url TEXT,
		app_image TEXT,
		custom_name TEXT,
		created_at TEXT NOT NULL DEFAULT (datetime('now')),
		last_used_at TEXT,
		PRIMARY KEY (key_id, user_pubkey),
		FOREIGN KEY (key_id) REFERENCES signer_keys(id) ON DELETE CASCADE
	);

	-- Pending requests
	CREATE TABLE IF NOT EXISTS signer_pending_requests (
		id TEXT PRIMARY KEY,
		key_pubkey TEXT NOT NULL,
		client_pubkey TEXT NOT NULL,
		method TEXT NOT NULL,
		params TEXT,  -- JSON object
		event_kind INTEGER,
		created_at TEXT NOT NULL DEFAULT (datetime('now')),
		expires_at TEXT NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_pending_requests_key_pubkey ON signer_pending_requests(key_pubkey);
	CREATE INDEX IF NOT EXISTS idx_pending_requests_expires ON signer_pending_requests(expires_at);

	-- Policies
	CREATE TABLE IF NOT EXISTS signer_policies (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		description TEXT,
		expires_at TEXT,
		created_at TEXT NOT NULL DEFAULT (datetime('now')),
		created_by TEXT
	);

	-- Policy rules
	CREATE TABLE IF NOT EXISTS signer_policy_rules (
		id TEXT PRIMARY KEY,
		policy_id TEXT NOT NULL REFERENCES signer_policies(id) ON DELETE CASCADE,
		method TEXT NOT NULL,
		allowed_kinds TEXT,  -- JSON array
		max_usage INTEGER DEFAULT 0,
		current_usage INTEGER DEFAULT 0
	);

	CREATE INDEX IF NOT EXISTS idx_policy_rules_policy ON signer_policy_rules(policy_id);

	-- NIP-46 sessions
	CREATE TABLE IF NOT EXISTS signer_nip46_sessions (
		id TEXT PRIMARY KEY,
		key_id TEXT NOT NULL,
		client_pubkey TEXT NOT NULL,
		permissions TEXT,  -- JSON array
		created_at TEXT NOT NULL DEFAULT (datetime('now')),
		expires_at TEXT NOT NULL
	);

	CREATE INDEX IF NOT EXISTS idx_nip46_sessions_key ON signer_nip46_sessions(key_id);
	CREATE INDEX IF NOT EXISTS idx_nip46_sessions_expires ON signer_nip46_sessions(expires_at);

	-- Tokens
	CREATE TABLE IF NOT EXISTS signer_tokens (
		id TEXT PRIMARY KEY,
		policy_id TEXT NOT NULL,
		key_id TEXT NOT NULL,
		client_name TEXT,
		created_by TEXT,
		expires_at TEXT,
		redeemed_at TEXT,
		redeemed_by TEXT,
		created_at TEXT NOT NULL DEFAULT (datetime('now'))
	);

	CREATE INDEX IF NOT EXISTS idx_tokens_key ON signer_tokens(key_id);

	-- Bunker secrets
	CREATE TABLE IF NOT EXISTS signer_bunker_secrets (
		id TEXT PRIMARY KEY,
		key_pubkey TEXT NOT NULL,
		secret TEXT NOT NULL,
		expires_at TEXT NOT NULL,
		created_at TEXT NOT NULL DEFAULT (datetime('now')),
		used_at TEXT
	);

	CREATE INDEX IF NOT EXISTS idx_bunker_secrets_key_pubkey ON signer_bunker_secrets(key_pubkey);
	CREATE INDEX IF NOT EXISTS idx_bunker_secrets_secret ON signer_bunker_secrets(secret);

	-- Settings
	CREATE TABLE IF NOT EXISTS signer_settings (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at TEXT NOT NULL DEFAULT (datetime('now'))
	);

	-- FROST threshold signing tables
	CREATE TABLE IF NOT EXISTS signer_frost_keys (
		id TEXT PRIMARY KEY,
		name TEXT,
		pubkey TEXT UNIQUE NOT NULL,
		threshold INTEGER NOT NULL,
		total_shares INTEGER NOT NULL,
		group_public_key BLOB NOT NULL,
		verification_shares BLOB NOT NULL,
		created_at TEXT NOT NULL DEFAULT (datetime('now')),
		created_by TEXT,
		owner_id TEXT REFERENCES signer_web_accounts(id)
	);

	CREATE INDEX IF NOT EXISTS idx_signer_frost_keys_pubkey ON signer_frost_keys(pubkey);

	CREATE TABLE IF NOT EXISTS signer_frost_shares (
		id TEXT PRIMARY KEY,
		frost_key_id TEXT NOT NULL REFERENCES signer_frost_keys(id) ON DELETE CASCADE,
		share_index INTEGER NOT NULL,
		encrypted_share BLOB,
		holder_pubkey TEXT,
		holder_bunker_uri TEXT,
		is_local INTEGER NOT NULL DEFAULT 1,
		public_share BLOB,
		created_at TEXT NOT NULL DEFAULT (datetime('now')),
		UNIQUE(frost_key_id, share_index)
	);

	CREATE INDEX IF NOT EXISTS idx_signer_frost_shares_key ON signer_frost_shares(frost_key_id);
	`

	_, err := ss.db.Exec(schema)
	return err
}

// Helper functions for JSON encoding/decoding arrays
func jsonArrayToStrings(data string) []string {
	if data == "" || data == "null" {
		return nil
	}
	var result []string
	if err := json.Unmarshal([]byte(data), &result); err != nil {
		return nil
	}
	return result
}

func stringsToJSONArray(arr []string) string {
	if arr == nil {
		return "[]"
	}
	data, _ := json.Marshal(arr)
	return string(data)
}

func jsonArrayToInts(data string) []int {
	if data == "" || data == "null" {
		return nil
	}
	var result []int
	if err := json.Unmarshal([]byte(data), &result); err != nil {
		return nil
	}
	return result
}

func intsToJSONArray(arr []int) string {
	if arr == nil {
		return "[]"
	}
	data, _ := json.Marshal(arr)
	return string(data)
}

func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	// Try multiple formats
	formats := []string{
		time.RFC3339,
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05Z",
	}
	for _, format := range formats {
		if t, err := time.Parse(format, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

// Key management

func (ss *SQLiteStorage) CreateKey(ctx context.Context, key *Key) error {
	keyType := key.KeyType
	if keyType == "" {
		keyType = KeyTypeLocal
	}
	encryptionMethod := key.EncryptionMethod
	if encryptionMethod == "" {
		encryptionMethod = "local"
	}

	_, err := ss.db.ExecContext(ctx, `
		INSERT INTO signer_keys (id, name, pubkey, key_type, encrypted_nsec, encryption_method, bunker_uri, upstream_pubkey, require_approval, disposable_mode, cover_traffic, relays, created_at, created_by, owner_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		key.ID, nullStr(key.Name), key.Pubkey, keyType, nullStr(key.EncryptedNsec), encryptionMethod,
		nullStr(key.BunkerURI), nullStr(key.UpstreamPubkey), boolToInt(key.RequireApproval),
		boolToInt(key.DisposableMode), boolToInt(key.CoverTraffic),
		stringsToJSONArray(key.Relays), formatTime(key.CreatedAt), nullStr(key.CreatedBy), nullStr(key.OwnerID))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return ErrKeyExists
		}
		return err
	}
	return nil
}

func (ss *SQLiteStorage) GetKey(ctx context.Context, id string) (*Key, error) {
	key := &Key{}
	var name, encryptedNsec, encryptionMethod, bunkerURI, upstreamPubkey, ownerID, relays, createdAt, createdBy sql.NullString
	var requireApproval, disposableMode, coverTraffic int

	err := ss.db.QueryRowContext(ctx, `
		SELECT id, name, pubkey, key_type, encrypted_nsec, encryption_method, bunker_uri, upstream_pubkey, require_approval, disposable_mode, cover_traffic, relays, created_at, created_by, owner_id
		FROM signer_keys WHERE id = ?`, id).
		Scan(&key.ID, &name, &key.Pubkey, &key.KeyType, &encryptedNsec, &encryptionMethod, &bunkerURI, &upstreamPubkey,
			&requireApproval, &disposableMode, &coverTraffic, &relays, &createdAt, &createdBy, &ownerID)
	if err == sql.ErrNoRows {
		return nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}

	if name.Valid {
		key.Name = name.String
	}
	if encryptedNsec.Valid {
		key.EncryptedNsec = encryptedNsec.String
	}
	if encryptionMethod.Valid {
		key.EncryptionMethod = encryptionMethod.String
	} else {
		key.EncryptionMethod = "local"
	}
	if bunkerURI.Valid {
		key.BunkerURI = bunkerURI.String
	}
	if upstreamPubkey.Valid {
		key.UpstreamPubkey = upstreamPubkey.String
	}
	if ownerID.Valid {
		key.OwnerID = ownerID.String
	}
	if relays.Valid {
		key.Relays = jsonArrayToStrings(relays.String)
	}
	if createdAt.Valid {
		key.CreatedAt = parseTime(createdAt.String)
	}
	if createdBy.Valid {
		key.CreatedBy = createdBy.String
	}
	key.RequireApproval = requireApproval != 0
	key.DisposableMode = disposableMode != 0
	key.CoverTraffic = coverTraffic != 0

	return key, nil
}

func (ss *SQLiteStorage) GetKeyByPubkey(ctx context.Context, pubkey string) (*Key, error) {
	key := &Key{}
	var name, encryptedNsec, encryptionMethod, bunkerURI, upstreamPubkey, ownerID, relays, createdAt, createdBy sql.NullString
	var requireApproval, disposableMode, coverTraffic int

	err := ss.db.QueryRowContext(ctx, `
		SELECT id, name, pubkey, key_type, encrypted_nsec, encryption_method, bunker_uri, upstream_pubkey, require_approval, disposable_mode, cover_traffic, relays, created_at, created_by, owner_id
		FROM signer_keys WHERE pubkey = ?`, pubkey).
		Scan(&key.ID, &name, &key.Pubkey, &key.KeyType, &encryptedNsec, &encryptionMethod, &bunkerURI, &upstreamPubkey,
			&requireApproval, &disposableMode, &coverTraffic, &relays, &createdAt, &createdBy, &ownerID)
	if err == sql.ErrNoRows {
		return nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}

	if name.Valid {
		key.Name = name.String
	}
	if encryptedNsec.Valid {
		key.EncryptedNsec = encryptedNsec.String
	}
	if encryptionMethod.Valid {
		key.EncryptionMethod = encryptionMethod.String
	} else {
		key.EncryptionMethod = "local"
	}
	if bunkerURI.Valid {
		key.BunkerURI = bunkerURI.String
	}
	if upstreamPubkey.Valid {
		key.UpstreamPubkey = upstreamPubkey.String
	}
	if ownerID.Valid {
		key.OwnerID = ownerID.String
	}
	if relays.Valid {
		key.Relays = jsonArrayToStrings(relays.String)
	}
	if createdAt.Valid {
		key.CreatedAt = parseTime(createdAt.String)
	}
	if createdBy.Valid {
		key.CreatedBy = createdBy.String
	}
	key.RequireApproval = requireApproval != 0
	key.DisposableMode = disposableMode != 0
	key.CoverTraffic = coverTraffic != 0

	return key, nil
}

func (ss *SQLiteStorage) GetKeyByName(ctx context.Context, name string) (*Key, error) {
	key := &Key{}
	var keyName, encryptedNsec, encryptionMethod, bunkerURI, upstreamPubkey, ownerID, relays, createdAt, createdBy sql.NullString
	var requireApproval, disposableMode, coverTraffic int

	err := ss.db.QueryRowContext(ctx, `
		SELECT id, name, pubkey, key_type, encrypted_nsec, encryption_method, bunker_uri, upstream_pubkey, require_approval, disposable_mode, cover_traffic, relays, created_at, created_by, owner_id
		FROM signer_keys WHERE name = ?`, name).
		Scan(&key.ID, &keyName, &key.Pubkey, &key.KeyType, &encryptedNsec, &encryptionMethod, &bunkerURI, &upstreamPubkey,
			&requireApproval, &disposableMode, &coverTraffic, &relays, &createdAt, &createdBy, &ownerID)
	if err == sql.ErrNoRows {
		return nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}

	if keyName.Valid {
		key.Name = keyName.String
	}
	if encryptedNsec.Valid {
		key.EncryptedNsec = encryptedNsec.String
	}
	if encryptionMethod.Valid {
		key.EncryptionMethod = encryptionMethod.String
	} else {
		key.EncryptionMethod = "local"
	}
	if bunkerURI.Valid {
		key.BunkerURI = bunkerURI.String
	}
	if upstreamPubkey.Valid {
		key.UpstreamPubkey = upstreamPubkey.String
	}
	if ownerID.Valid {
		key.OwnerID = ownerID.String
	}
	if relays.Valid {
		key.Relays = jsonArrayToStrings(relays.String)
	}
	if createdAt.Valid {
		key.CreatedAt = parseTime(createdAt.String)
	}
	if createdBy.Valid {
		key.CreatedBy = createdBy.String
	}
	key.RequireApproval = requireApproval != 0
	key.DisposableMode = disposableMode != 0
	key.CoverTraffic = coverTraffic != 0

	return key, nil
}

func (ss *SQLiteStorage) ListKeys(ctx context.Context, ownerID string) ([]*Key, error) {
	rows, err := ss.db.QueryContext(ctx, `
		SELECT id, name, pubkey, key_type, encrypted_nsec, encryption_method, bunker_uri, upstream_pubkey, require_approval, disposable_mode, cover_traffic, relays, created_at, created_by, owner_id
		FROM signer_keys WHERE owner_id = ? ORDER BY created_at DESC`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return ss.scanKeys(rows)
}

func (ss *SQLiteStorage) ListAllKeys(ctx context.Context) ([]*Key, error) {
	rows, err := ss.db.QueryContext(ctx, `
		SELECT id, name, pubkey, key_type, encrypted_nsec, encryption_method, bunker_uri, upstream_pubkey, require_approval, disposable_mode, cover_traffic, relays, created_at, created_by, owner_id
		FROM signer_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return ss.scanKeys(rows)
}

func (ss *SQLiteStorage) scanKeys(rows *sql.Rows) ([]*Key, error) {
	var keys []*Key
	for rows.Next() {
		key := &Key{}
		var name, encryptedNsec, encryptionMethod, bunkerURI, upstreamPubkey, ownerID, relays, createdAt, createdBy sql.NullString
		var requireApproval, disposableMode, coverTraffic int

		if err := rows.Scan(&key.ID, &name, &key.Pubkey, &key.KeyType, &encryptedNsec, &encryptionMethod, &bunkerURI, &upstreamPubkey,
			&requireApproval, &disposableMode, &coverTraffic, &relays, &createdAt, &createdBy, &ownerID); err != nil {
			return nil, err
		}

		if name.Valid {
			key.Name = name.String
		}
		if encryptedNsec.Valid {
			key.EncryptedNsec = encryptedNsec.String
		}
		if encryptionMethod.Valid {
			key.EncryptionMethod = encryptionMethod.String
		} else {
			key.EncryptionMethod = "local"
		}
		if bunkerURI.Valid {
			key.BunkerURI = bunkerURI.String
		}
		if upstreamPubkey.Valid {
			key.UpstreamPubkey = upstreamPubkey.String
		}
		if ownerID.Valid {
			key.OwnerID = ownerID.String
		}
		if relays.Valid {
			key.Relays = jsonArrayToStrings(relays.String)
		}
		if createdAt.Valid {
			key.CreatedAt = parseTime(createdAt.String)
		}
		if createdBy.Valid {
			key.CreatedBy = createdBy.String
		}
		key.RequireApproval = requireApproval != 0
		key.DisposableMode = disposableMode != 0
	key.CoverTraffic = coverTraffic != 0

		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (ss *SQLiteStorage) UpdateKey(ctx context.Context, key *Key) error {
	result, err := ss.db.ExecContext(ctx, `
		UPDATE signer_keys SET name = ?, require_approval = ?, disposable_mode = ?, cover_traffic = ?, relays = ?,
			key_type = ?, bunker_uri = ?, upstream_pubkey = ?
		WHERE id = ?`,
		nullStr(key.Name), boolToInt(key.RequireApproval), boolToInt(key.DisposableMode), boolToInt(key.CoverTraffic), stringsToJSONArray(key.Relays),
		key.KeyType, nullStr(key.BunkerURI), nullStr(key.UpstreamPubkey), key.ID)
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

func (ss *SQLiteStorage) UpdateKeyEncryption(ctx context.Context, keyID, encryptedNsec, encryptionMethod string) error {
	result, err := ss.db.ExecContext(ctx, `
		UPDATE signer_keys SET encrypted_nsec = ?, encryption_method = ?
		WHERE id = ?`,
		encryptedNsec, encryptionMethod, keyID)
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

func (ss *SQLiteStorage) DeleteKey(ctx context.Context, id string) error {
	result, err := ss.db.ExecContext(ctx, `DELETE FROM signer_keys WHERE id = ?`, id)
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

// Helper functions
func nullStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func boolPtrToInt(b *bool) int {
	if b == nil || !*b {
		return 0
	}
	return 1
}

func intToBoolPtr(i int) *bool {
	b := i != 0
	return &b
}

// Permission management

func (ss *SQLiteStorage) SetPermission(ctx context.Context, perm *Permission) error {
	if perm.CreatedAt.IsZero() {
		perm.CreatedAt = time.Now()
	}
	_, err := ss.db.ExecContext(ctx, `
		INSERT INTO signer_permissions (key_id, user_pubkey, methods, allowed_kinds, expires_at, policy_id, require_approval, app_name, app_url, app_image, custom_name, created_at, last_used_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (key_id, user_pubkey) DO UPDATE SET
			methods = excluded.methods,
			allowed_kinds = excluded.allowed_kinds,
			expires_at = excluded.expires_at,
			policy_id = excluded.policy_id,
			require_approval = excluded.require_approval,
			app_name = COALESCE(excluded.app_name, signer_permissions.app_name),
			app_url = COALESCE(excluded.app_url, signer_permissions.app_url),
			app_image = COALESCE(excluded.app_image, signer_permissions.app_image),
			custom_name = COALESCE(excluded.custom_name, signer_permissions.custom_name)`,
		perm.KeyID, perm.UserPubkey, stringsToJSONArray(perm.Methods), intsToJSONArray(perm.AllowedKinds),
		nullTimeStr(perm.ExpiresAt), nullStr(perm.PolicyID), boolPtrToInt(perm.RequireApproval),
		nullStr(perm.AppName), nullStr(perm.AppURL), nullStr(perm.AppImage), nullStr(perm.CustomName),
		formatTime(perm.CreatedAt), nullTimeStr(perm.LastUsedAt))
	return err
}

func (ss *SQLiteStorage) GetPermission(ctx context.Context, keyID, userPubkey string) (*Permission, error) {
	perm := &Permission{}
	var expiresAt, lastUsedAt, policyID, appName, appURL, appImage, customName, methods, allowedKinds, createdAt sql.NullString
	var requireApproval int

	err := ss.db.QueryRowContext(ctx, `
		SELECT key_id, user_pubkey, methods, allowed_kinds, expires_at, policy_id, require_approval, app_name, app_url, app_image, custom_name, created_at, last_used_at
		FROM signer_permissions WHERE key_id = ? AND user_pubkey = ?`, keyID, userPubkey).
		Scan(&perm.KeyID, &perm.UserPubkey, &methods, &allowedKinds, &expiresAt, &policyID, &requireApproval,
			&appName, &appURL, &appImage, &customName, &createdAt, &lastUsedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotAuthorized
	}
	if err != nil {
		return nil, err
	}

	if methods.Valid {
		perm.Methods = jsonArrayToStrings(methods.String)
	}
	if allowedKinds.Valid {
		perm.AllowedKinds = jsonArrayToInts(allowedKinds.String)
	}
	if expiresAt.Valid {
		t := parseTime(expiresAt.String)
		perm.ExpiresAt = &t
	}
	if policyID.Valid {
		perm.PolicyID = policyID.String
	}
	perm.RequireApproval = intToBoolPtr(requireApproval)
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
	if createdAt.Valid {
		perm.CreatedAt = parseTime(createdAt.String)
	}
	if lastUsedAt.Valid {
		t := parseTime(lastUsedAt.String)
		perm.LastUsedAt = &t
	}

	return perm, nil
}

func (ss *SQLiteStorage) ListPermissions(ctx context.Context, keyID string) ([]*Permission, error) {
	rows, err := ss.db.QueryContext(ctx, `
		SELECT key_id, user_pubkey, methods, allowed_kinds, expires_at, policy_id, require_approval, app_name, app_url, app_image, custom_name, created_at, last_used_at
		FROM signer_permissions WHERE key_id = ?`, keyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []*Permission
	for rows.Next() {
		perm := &Permission{}
		var expiresAt, lastUsedAt, policyID, appName, appURL, appImage, customName, methods, allowedKinds, createdAt sql.NullString
		var requireApproval int

		if err := rows.Scan(&perm.KeyID, &perm.UserPubkey, &methods, &allowedKinds, &expiresAt, &policyID, &requireApproval,
			&appName, &appURL, &appImage, &customName, &createdAt, &lastUsedAt); err != nil {
			return nil, err
		}

		if methods.Valid {
			perm.Methods = jsonArrayToStrings(methods.String)
		}
		if allowedKinds.Valid {
			perm.AllowedKinds = jsonArrayToInts(allowedKinds.String)
		}
		if expiresAt.Valid {
			t := parseTime(expiresAt.String)
			perm.ExpiresAt = &t
		}
		if policyID.Valid {
			perm.PolicyID = policyID.String
		}
		perm.RequireApproval = intToBoolPtr(requireApproval)
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
		if createdAt.Valid {
			perm.CreatedAt = parseTime(createdAt.String)
		}
		if lastUsedAt.Valid {
			t := parseTime(lastUsedAt.String)
			perm.LastUsedAt = &t
		}

		perms = append(perms, perm)
	}
	return perms, rows.Err()
}

func (ss *SQLiteStorage) DeletePermission(ctx context.Context, keyID, userPubkey string) error {
	_, err := ss.db.ExecContext(ctx, `DELETE FROM signer_permissions WHERE key_id = ? AND user_pubkey = ?`, keyID, userPubkey)
	return err
}

func (ss *SQLiteStorage) UpdatePermissionLastUsed(ctx context.Context, keyID, userPubkey string) error {
	_, err := ss.db.ExecContext(ctx, `
		UPDATE signer_permissions SET last_used_at = ? WHERE key_id = ? AND user_pubkey = ?`,
		formatTime(time.Now()), keyID, userPubkey)
	return err
}

func (ss *SQLiteStorage) UpdatePermissionName(ctx context.Context, keyID, userPubkey, customName string) error {
	_, err := ss.db.ExecContext(ctx, `
		UPDATE signer_permissions SET custom_name = ? WHERE key_id = ? AND user_pubkey = ?`,
		customName, keyID, userPubkey)
	return err
}

func nullTimeStr(t *time.Time) interface{} {
	if t == nil {
		return nil
	}
	return formatTime(*t)
}

// Session management

func (ss *SQLiteStorage) CreateUserSession(ctx context.Context, session *UserSession) error {
	_, err := ss.db.ExecContext(ctx, `
		INSERT INTO signer_web_sessions (id, user_id, token, vault_token, user_agent, ip_address, remember_device, last_activity, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		session.ID, session.UserID, session.Token, nullStr(session.VaultToken),
		session.UserAgent, session.IPAddress, boolToInt(session.RememberDevice),
		nullTimeStr(session.LastActivity), formatTime(session.ExpiresAt), formatTime(session.CreatedAt))
	return err
}

func (ss *SQLiteStorage) GetUserSession(ctx context.Context, id string) (*UserSession, error) {
	session := &UserSession{}
	var vaultToken, lastActivity, expiresAt, createdAt sql.NullString
	var rememberDevice int

	err := ss.db.QueryRowContext(ctx, `
		SELECT id, user_id, token, vault_token, user_agent, ip_address, remember_device, last_activity, expires_at, created_at
		FROM signer_web_sessions WHERE id = ?`, id).
		Scan(&session.ID, &session.UserID, &session.Token, &vaultToken,
			&session.UserAgent, &session.IPAddress, &rememberDevice, &lastActivity, &expiresAt, &createdAt)
	if err == sql.ErrNoRows {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}

	if vaultToken.Valid {
		session.VaultToken = vaultToken.String
	}
	session.RememberDevice = rememberDevice != 0
	if lastActivity.Valid {
		t := parseTime(lastActivity.String)
		session.LastActivity = &t
	}
	if expiresAt.Valid {
		session.ExpiresAt = parseTime(expiresAt.String)
	}
	if createdAt.Valid {
		session.CreatedAt = parseTime(createdAt.String)
	}

	if time.Now().After(session.ExpiresAt) {
		return nil, ErrSessionNotFound
	}

	return session, nil
}

func (ss *SQLiteStorage) ListUserSessions(ctx context.Context, userID string) ([]*UserSession, error) {
	now := time.Now()
	rows, err := ss.db.QueryContext(ctx, `
		SELECT id, user_id, token, vault_token, user_agent, ip_address, remember_device, last_activity, expires_at, created_at
		FROM signer_web_sessions WHERE user_id = ? AND expires_at > ? ORDER BY created_at DESC`,
		userID, formatTime(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var sessions []*UserSession
	for rows.Next() {
		session := &UserSession{}
		var vaultToken, lastActivity, expiresAt, createdAt sql.NullString
		var rememberDevice int

		if err := rows.Scan(&session.ID, &session.UserID, &session.Token, &vaultToken,
			&session.UserAgent, &session.IPAddress, &rememberDevice, &lastActivity, &expiresAt, &createdAt); err != nil {
			return nil, err
		}

		if vaultToken.Valid {
			session.VaultToken = vaultToken.String
		}
		session.RememberDevice = rememberDevice != 0
		if lastActivity.Valid {
			t := parseTime(lastActivity.String)
			session.LastActivity = &t
		}
		if expiresAt.Valid {
			session.ExpiresAt = parseTime(expiresAt.String)
		}
		if createdAt.Valid {
			session.CreatedAt = parseTime(createdAt.String)
		}

		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
}

func (ss *SQLiteStorage) DeleteUserSession(ctx context.Context, id string) error {
	_, err := ss.db.ExecContext(ctx, `DELETE FROM signer_web_sessions WHERE id = ?`, id)
	return err
}

func (ss *SQLiteStorage) DeleteUserSessions(ctx context.Context, userID string) error {
	_, err := ss.db.ExecContext(ctx, `DELETE FROM signer_web_sessions WHERE user_id = ?`, userID)
	return err
}

func (ss *SQLiteStorage) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	result, err := ss.db.ExecContext(ctx, `DELETE FROM signer_web_sessions WHERE expires_at < ?`, formatTime(time.Now()))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// User management

func (ss *SQLiteStorage) CreateUser(ctx context.Context, user *User) error {
	backupCodes, _ := json.Marshal(user.BackupCodes)

	_, err := ss.db.ExecContext(ctx, `
		INSERT INTO signer_web_accounts (id, username, email, password_hash, mfa_enabled, mfa_secret, backup_codes, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		user.ID, user.Username, nullStr(user.Email), user.PasswordHash,
		boolToInt(user.MFAEnabled), nullStr(user.MFASecret), string(backupCodes), formatTime(user.CreatedAt))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return errors.New("user already exists")
		}
		return err
	}
	return nil
}

func (ss *SQLiteStorage) GetUser(ctx context.Context, id string) (*User, error) {
	user := &User{}
	var email, mfaSecret, lockedUntil, lastLoginAt, lastLoginIP, backupCodes, createdAt sql.NullString
	var mfaEnabled, failedAttempts, backupCodesUsed int

	err := ss.db.QueryRowContext(ctx, `
		SELECT id, username, email, password_hash, mfa_enabled, mfa_secret, backup_codes, backup_codes_used,
		       failed_login_attempts, locked_until, created_at, last_login_at, last_login_ip
		FROM signer_web_accounts WHERE id = ?`, id).
		Scan(&user.ID, &user.Username, &email, &user.PasswordHash, &mfaEnabled, &mfaSecret, &backupCodes, &backupCodesUsed,
			&failedAttempts, &lockedUntil, &createdAt, &lastLoginAt, &lastLoginIP)
	if err == sql.ErrNoRows {
		return nil, errors.New("user not found")
	}
	if err != nil {
		return nil, err
	}

	if email.Valid {
		user.Email = email.String
	}
	user.MFAEnabled = mfaEnabled != 0
	if mfaSecret.Valid {
		user.MFASecret = mfaSecret.String
	}
	if backupCodes.Valid {
		json.Unmarshal([]byte(backupCodes.String), &user.BackupCodes)
	}
	user.BackupCodesUsed = backupCodesUsed
	user.FailedLoginAttempts = failedAttempts
	if lockedUntil.Valid {
		t := parseTime(lockedUntil.String)
		user.LockedUntil = &t
	}
	if createdAt.Valid {
		user.CreatedAt = parseTime(createdAt.String)
	}
	if lastLoginAt.Valid {
		t := parseTime(lastLoginAt.String)
		user.LastLoginAt = &t
	}
	if lastLoginIP.Valid {
		user.LastLoginIP = lastLoginIP.String
	}

	return user, nil
}

func (ss *SQLiteStorage) GetUserByUsername(ctx context.Context, username string) (*User, error) {
	user := &User{}
	var email, mfaSecret, lockedUntil, lastLoginAt, lastLoginIP, backupCodes, createdAt sql.NullString
	var mfaEnabled, failedAttempts, backupCodesUsed int

	err := ss.db.QueryRowContext(ctx, `
		SELECT id, username, email, password_hash, mfa_enabled, mfa_secret, backup_codes, backup_codes_used,
		       failed_login_attempts, locked_until, created_at, last_login_at, last_login_ip
		FROM signer_web_accounts WHERE username = ?`, username).
		Scan(&user.ID, &user.Username, &email, &user.PasswordHash, &mfaEnabled, &mfaSecret, &backupCodes, &backupCodesUsed,
			&failedAttempts, &lockedUntil, &createdAt, &lastLoginAt, &lastLoginIP)
	if err == sql.ErrNoRows {
		return nil, errors.New("user not found")
	}
	if err != nil {
		return nil, err
	}

	if email.Valid {
		user.Email = email.String
	}
	user.MFAEnabled = mfaEnabled != 0
	if mfaSecret.Valid {
		user.MFASecret = mfaSecret.String
	}
	if backupCodes.Valid {
		json.Unmarshal([]byte(backupCodes.String), &user.BackupCodes)
	}
	user.BackupCodesUsed = backupCodesUsed
	user.FailedLoginAttempts = failedAttempts
	if lockedUntil.Valid {
		t := parseTime(lockedUntil.String)
		user.LockedUntil = &t
	}
	if createdAt.Valid {
		user.CreatedAt = parseTime(createdAt.String)
	}
	if lastLoginAt.Valid {
		t := parseTime(lastLoginAt.String)
		user.LastLoginAt = &t
	}
	if lastLoginIP.Valid {
		user.LastLoginIP = lastLoginIP.String
	}

	return user, nil
}

func (ss *SQLiteStorage) ListUsers(ctx context.Context) ([]*User, error) {
	rows, err := ss.db.QueryContext(ctx, `
		SELECT id, username, email, password_hash, mfa_enabled, mfa_secret, backup_codes, backup_codes_used,
		       failed_login_attempts, locked_until, created_at, last_login_at, last_login_ip
		FROM signer_web_accounts ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		user := &User{}
		var email, mfaSecret, lockedUntil, lastLoginAt, lastLoginIP, backupCodes, createdAt sql.NullString
		var mfaEnabled, failedAttempts, backupCodesUsed int

		if err := rows.Scan(&user.ID, &user.Username, &email, &user.PasswordHash, &mfaEnabled, &mfaSecret, &backupCodes, &backupCodesUsed,
			&failedAttempts, &lockedUntil, &createdAt, &lastLoginAt, &lastLoginIP); err != nil {
			return nil, err
		}

		if email.Valid {
			user.Email = email.String
		}
		user.MFAEnabled = mfaEnabled != 0
		if mfaSecret.Valid {
			user.MFASecret = mfaSecret.String
		}
		if backupCodes.Valid {
			json.Unmarshal([]byte(backupCodes.String), &user.BackupCodes)
		}
		user.BackupCodesUsed = backupCodesUsed
		user.FailedLoginAttempts = failedAttempts
		if lockedUntil.Valid {
			t := parseTime(lockedUntil.String)
			user.LockedUntil = &t
		}
		if createdAt.Valid {
			user.CreatedAt = parseTime(createdAt.String)
		}
		if lastLoginAt.Valid {
			t := parseTime(lastLoginAt.String)
			user.LastLoginAt = &t
		}
		if lastLoginIP.Valid {
			user.LastLoginIP = lastLoginIP.String
		}

		users = append(users, user)
	}
	return users, rows.Err()
}

func (ss *SQLiteStorage) UpdateUser(ctx context.Context, user *User) error {
	backupCodes, _ := json.Marshal(user.BackupCodes)

	_, err := ss.db.ExecContext(ctx, `
		UPDATE signer_web_accounts SET
			email = ?, password_hash = ?, mfa_enabled = ?, mfa_secret = ?,
			backup_codes = ?, backup_codes_used = ?, failed_login_attempts = ?,
			locked_until = ?, last_login_at = ?, last_login_ip = ?
		WHERE id = ?`,
		nullStr(user.Email), user.PasswordHash, boolToInt(user.MFAEnabled), nullStr(user.MFASecret),
		string(backupCodes), user.BackupCodesUsed, user.FailedLoginAttempts,
		nullTimeStr(user.LockedUntil), nullTimeStr(user.LastLoginAt), nullStr(user.LastLoginIP), user.ID)
	return err
}

func (ss *SQLiteStorage) DeleteUser(ctx context.Context, id string) error {
	_, err := ss.db.ExecContext(ctx, `DELETE FROM signer_web_accounts WHERE id = ?`, id)
	return err
}

func (ss *SQLiteStorage) IncrementFailedLogins(ctx context.Context, userID string) error {
	_, err := ss.db.ExecContext(ctx, `
		UPDATE signer_web_accounts SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?`, userID)
	return err
}

func (ss *SQLiteStorage) ResetFailedLogins(ctx context.Context, userID string) error {
	_, err := ss.db.ExecContext(ctx, `
		UPDATE signer_web_accounts SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?`, userID)
	return err
}

func (ss *SQLiteStorage) LockUser(ctx context.Context, userID string, until time.Time) error {
	_, err := ss.db.ExecContext(ctx, `
		UPDATE signer_web_accounts SET locked_until = ? WHERE id = ?`, formatTime(until), userID)
	return err
}

// Settings

func (ss *SQLiteStorage) GetSetting(ctx context.Context, key string) (string, error) {
	var value string
	err := ss.db.QueryRowContext(ctx, `SELECT value FROM signer_settings WHERE key = ?`, key).Scan(&value)
	if err == sql.ErrNoRows {
		return "", errors.New("setting not found")
	}
	return value, err
}

func (ss *SQLiteStorage) SetSetting(ctx context.Context, key, value string) error {
	_, err := ss.db.ExecContext(ctx, `
		INSERT INTO signer_settings (key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, formatTime(time.Now()))
	return err
}

// Pending requests

func (ss *SQLiteStorage) CreatePendingRequest(ctx context.Context, req *PendingRequest) error {
	params, _ := json.Marshal(req.Params)
	var eventKind interface{}
	if req.EventKind != nil {
		eventKind = *req.EventKind
	}
	_, err := ss.db.ExecContext(ctx, `
		INSERT INTO signer_pending_requests (id, key_pubkey, client_pubkey, method, params, event_kind, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		req.ID, req.KeyPubkey, req.ClientPubkey, req.Method, string(params), eventKind,
		formatTime(req.CreatedAt), formatTime(req.ExpiresAt))
	return err
}

func (ss *SQLiteStorage) GetPendingRequest(ctx context.Context, id string) (*PendingRequest, error) {
	req := &PendingRequest{}
	var params, createdAt, expiresAt sql.NullString
	var eventKind sql.NullInt64

	err := ss.db.QueryRowContext(ctx, `
		SELECT id, key_pubkey, client_pubkey, method, params, event_kind, created_at, expires_at
		FROM signer_pending_requests WHERE id = ?`, id).
		Scan(&req.ID, &req.KeyPubkey, &req.ClientPubkey, &req.Method, &params, &eventKind,
			&createdAt, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, ErrRequestNotFound
	}
	if err != nil {
		return nil, err
	}

	if params.Valid {
		json.Unmarshal([]byte(params.String), &req.Params)
	}
	if eventKind.Valid {
		ek := int(eventKind.Int64)
		req.EventKind = &ek
	}
	if createdAt.Valid {
		req.CreatedAt = parseTime(createdAt.String)
	}
	if expiresAt.Valid {
		req.ExpiresAt = parseTime(expiresAt.String)
	}

	// Check if expired
	if time.Now().After(req.ExpiresAt) {
		return nil, ErrRequestExpired
	}

	return req, nil
}

func (ss *SQLiteStorage) ListPendingRequests(ctx context.Context, keyPubkey string) ([]*PendingRequest, error) {
	rows, err := ss.db.QueryContext(ctx, `
		SELECT id, key_pubkey, client_pubkey, method, params, event_kind, created_at, expires_at
		FROM signer_pending_requests WHERE key_pubkey = ? AND expires_at > ? ORDER BY created_at DESC`,
		keyPubkey, formatTime(time.Now()))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var reqs []*PendingRequest
	for rows.Next() {
		req := &PendingRequest{}
		var params, createdAt, expiresAt sql.NullString
		var eventKind sql.NullInt64

		if err := rows.Scan(&req.ID, &req.KeyPubkey, &req.ClientPubkey, &req.Method, &params, &eventKind,
			&createdAt, &expiresAt); err != nil {
			return nil, err
		}

		if params.Valid {
			json.Unmarshal([]byte(params.String), &req.Params)
		}
		if eventKind.Valid {
			ek := int(eventKind.Int64)
			req.EventKind = &ek
		}
		if createdAt.Valid {
			req.CreatedAt = parseTime(createdAt.String)
		}
		if expiresAt.Valid {
			req.ExpiresAt = parseTime(expiresAt.String)
		}

		reqs = append(reqs, req)
	}
	return reqs, rows.Err()
}

func (ss *SQLiteStorage) DeletePendingRequest(ctx context.Context, id string) error {
	_, err := ss.db.ExecContext(ctx, `DELETE FROM signer_pending_requests WHERE id = ?`, id)
	return err
}

func (ss *SQLiteStorage) CleanExpiredRequests(ctx context.Context) error {
	_, err := ss.db.ExecContext(ctx, `
		DELETE FROM signer_pending_requests WHERE expires_at < ?`, formatTime(time.Now()))
	return err
}

// Policy management

func (ss *SQLiteStorage) CreatePolicy(ctx context.Context, policy *Policy) error {
	tx, err := ss.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.ExecContext(ctx, `
		INSERT INTO signer_policies (id, name, description, expires_at, created_at, created_by)
		VALUES (?, ?, ?, ?, ?, ?)`,
		policy.ID, policy.Name, nullStr(policy.Description), nullTimeStr(policy.ExpiresAt),
		formatTime(policy.CreatedAt), nullStr(policy.CreatedBy))
	if err != nil {
		return err
	}

	// Insert rules
	for _, rule := range policy.Rules {
		_, err = tx.ExecContext(ctx, `
			INSERT INTO signer_policy_rules (id, policy_id, method, allowed_kinds, max_usage, current_usage)
			VALUES (?, ?, ?, ?, ?, ?)`,
			rule.ID, policy.ID, rule.Method, intsToJSONArray(rule.AllowedKinds), rule.MaxUsage, rule.CurrentUsage)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (ss *SQLiteStorage) GetPolicy(ctx context.Context, id string) (*Policy, error) {
	policy := &Policy{}
	var description, expiresAt, createdAt, createdBy sql.NullString

	err := ss.db.QueryRowContext(ctx, `
		SELECT id, name, description, expires_at, created_at, created_by
		FROM signer_policies WHERE id = ?`, id).
		Scan(&policy.ID, &policy.Name, &description, &expiresAt, &createdAt, &createdBy)
	if err == sql.ErrNoRows {
		return nil, ErrPolicyNotFound
	}
	if err != nil {
		return nil, err
	}

	if description.Valid {
		policy.Description = description.String
	}
	if expiresAt.Valid {
		t := parseTime(expiresAt.String)
		policy.ExpiresAt = &t
	}
	if createdAt.Valid {
		policy.CreatedAt = parseTime(createdAt.String)
	}
	if createdBy.Valid {
		policy.CreatedBy = createdBy.String
	}

	// Check if expired
	if policy.ExpiresAt != nil && time.Now().After(*policy.ExpiresAt) {
		return nil, ErrPolicyNotFound
	}

	// Load rules
	rows, err := ss.db.QueryContext(ctx, `
		SELECT id, policy_id, method, allowed_kinds, max_usage, current_usage
		FROM signer_policy_rules WHERE policy_id = ?`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		rule := &PolicyRule{}
		var allowedKinds sql.NullString

		if err := rows.Scan(&rule.ID, &rule.PolicyID, &rule.Method, &allowedKinds, &rule.MaxUsage, &rule.CurrentUsage); err != nil {
			return nil, err
		}

		if allowedKinds.Valid {
			rule.AllowedKinds = jsonArrayToInts(allowedKinds.String)
		}

		policy.Rules = append(policy.Rules, rule)
	}

	return policy, rows.Err()
}

func (ss *SQLiteStorage) ListPolicies(ctx context.Context) ([]*Policy, error) {
	rows, err := ss.db.QueryContext(ctx, `
		SELECT id, name, description, expires_at, created_at, created_by
		FROM signer_policies ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []*Policy
	now := time.Now()
	for rows.Next() {
		policy := &Policy{}
		var description, expiresAt, createdAt, createdBy sql.NullString

		if err := rows.Scan(&policy.ID, &policy.Name, &description, &expiresAt, &createdAt, &createdBy); err != nil {
			return nil, err
		}

		if description.Valid {
			policy.Description = description.String
		}
		if expiresAt.Valid {
			t := parseTime(expiresAt.String)
			policy.ExpiresAt = &t
			// Skip expired
			if now.After(t) {
				continue
			}
		}
		if createdAt.Valid {
			policy.CreatedAt = parseTime(createdAt.String)
		}
		if createdBy.Valid {
			policy.CreatedBy = createdBy.String
		}

		policies = append(policies, policy)
	}

	// Load rules for each policy
	for _, policy := range policies {
		ruleRows, err := ss.db.QueryContext(ctx, `
			SELECT id, policy_id, method, allowed_kinds, max_usage, current_usage
			FROM signer_policy_rules WHERE policy_id = ?`, policy.ID)
		if err != nil {
			return nil, err
		}

		for ruleRows.Next() {
			rule := &PolicyRule{}
			var allowedKinds sql.NullString

			if err := ruleRows.Scan(&rule.ID, &rule.PolicyID, &rule.Method, &allowedKinds, &rule.MaxUsage, &rule.CurrentUsage); err != nil {
				ruleRows.Close()
				return nil, err
			}

			if allowedKinds.Valid {
				rule.AllowedKinds = jsonArrayToInts(allowedKinds.String)
			}

			policy.Rules = append(policy.Rules, rule)
		}
		ruleRows.Close()
	}

	return policies, rows.Err()
}

func (ss *SQLiteStorage) DeletePolicy(ctx context.Context, id string) error {
	result, err := ss.db.ExecContext(ctx, `DELETE FROM signer_policies WHERE id = ?`, id)
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

func (ss *SQLiteStorage) IncrementRuleUsage(ctx context.Context, ruleID string) error {
	result, err := ss.db.ExecContext(ctx, `
		UPDATE signer_policy_rules SET current_usage = current_usage + 1 WHERE id = ?`, ruleID)
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

// FROST key management

func (ss *SQLiteStorage) CreateFrostKey(ctx context.Context, key *FrostKey) error {
	_, err := ss.db.ExecContext(ctx, `
		INSERT INTO signer_frost_keys (id, name, pubkey, threshold, total_shares, group_public_key, verification_shares, created_at, created_by, owner_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		key.ID, nullStr(key.Name), key.Pubkey, key.Threshold, key.TotalShares,
		key.GroupPublicKey, key.VerificationShares, formatTime(key.CreatedAt), nullStr(key.CreatedBy), nullStr(key.OwnerID))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return ErrKeyExists
		}
		return err
	}
	return nil
}

func (ss *SQLiteStorage) GetFrostKey(ctx context.Context, id string) (*FrostKey, error) {
	key := &FrostKey{}
	var name, createdBy, ownerID, createdAt sql.NullString

	err := ss.db.QueryRowContext(ctx, `
		SELECT id, name, pubkey, threshold, total_shares, group_public_key, verification_shares, created_at, created_by, owner_id
		FROM signer_frost_keys WHERE id = ?`, id).
		Scan(&key.ID, &name, &key.Pubkey, &key.Threshold, &key.TotalShares,
			&key.GroupPublicKey, &key.VerificationShares, &createdAt, &createdBy, &ownerID)
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
	if ownerID.Valid {
		key.OwnerID = ownerID.String
	}
	if createdAt.Valid {
		key.CreatedAt = parseTime(createdAt.String)
	}

	return key, nil
}

func (ss *SQLiteStorage) GetFrostKeyByPubkey(ctx context.Context, pubkey string) (*FrostKey, error) {
	key := &FrostKey{}
	var name, createdBy, ownerID, createdAt sql.NullString

	err := ss.db.QueryRowContext(ctx, `
		SELECT id, name, pubkey, threshold, total_shares, group_public_key, verification_shares, created_at, created_by, owner_id
		FROM signer_frost_keys WHERE pubkey = ?`, pubkey).
		Scan(&key.ID, &name, &key.Pubkey, &key.Threshold, &key.TotalShares,
			&key.GroupPublicKey, &key.VerificationShares, &createdAt, &createdBy, &ownerID)
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
	if ownerID.Valid {
		key.OwnerID = ownerID.String
	}
	if createdAt.Valid {
		key.CreatedAt = parseTime(createdAt.String)
	}

	return key, nil
}

func (ss *SQLiteStorage) ListFrostKeys(ctx context.Context) ([]*FrostKey, error) {
	rows, err := ss.db.QueryContext(ctx, `
		SELECT id, name, pubkey, threshold, total_shares, group_public_key, verification_shares, created_at, created_by, owner_id
		FROM signer_frost_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return ss.scanFrostKeys(rows)
}

func (ss *SQLiteStorage) ListFrostKeysByOwner(ctx context.Context, ownerID string) ([]*FrostKey, error) {
	rows, err := ss.db.QueryContext(ctx, `
		SELECT id, name, pubkey, threshold, total_shares, group_public_key, verification_shares, created_at, created_by, owner_id
		FROM signer_frost_keys WHERE owner_id = ? ORDER BY created_at DESC`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return ss.scanFrostKeys(rows)
}

func (ss *SQLiteStorage) scanFrostKeys(rows *sql.Rows) ([]*FrostKey, error) {
	var keys []*FrostKey
	for rows.Next() {
		key := &FrostKey{}
		var name, createdBy, ownerID, createdAt sql.NullString

		if err := rows.Scan(&key.ID, &name, &key.Pubkey, &key.Threshold, &key.TotalShares,
			&key.GroupPublicKey, &key.VerificationShares, &createdAt, &createdBy, &ownerID); err != nil {
			return nil, err
		}

		if name.Valid {
			key.Name = name.String
		}
		if createdBy.Valid {
			key.CreatedBy = createdBy.String
		}
		if ownerID.Valid {
			key.OwnerID = ownerID.String
		}
		if createdAt.Valid {
			key.CreatedAt = parseTime(createdAt.String)
		}

		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (ss *SQLiteStorage) DeleteFrostKey(ctx context.Context, id string) error {
	result, err := ss.db.ExecContext(ctx, `DELETE FROM signer_frost_keys WHERE id = ?`, id)
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

func (ss *SQLiteStorage) CreateFrostShare(ctx context.Context, share *FrostShare) error {
	_, err := ss.db.ExecContext(ctx, `
		INSERT INTO signer_frost_shares (id, frost_key_id, share_index, encrypted_share, holder_pubkey, holder_bunker_uri, is_local, public_share, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		share.ID, share.FrostKeyID, share.ShareIndex, share.EncryptedShare, nullStr(share.HolderPubkey),
		nullStr(share.HolderBunkerURI), boolToInt(share.IsLocal), share.PublicShare, formatTime(share.CreatedAt))
	return err
}

func (ss *SQLiteStorage) GetFrostShare(ctx context.Context, id string) (*FrostShare, error) {
	share := &FrostShare{}
	var holderPubkey, holderBunkerURI, createdAt sql.NullString
	var isLocal int

	err := ss.db.QueryRowContext(ctx, `
		SELECT id, frost_key_id, share_index, encrypted_share, holder_pubkey, holder_bunker_uri, is_local, public_share, created_at
		FROM signer_frost_shares WHERE id = ?`, id).
		Scan(&share.ID, &share.FrostKeyID, &share.ShareIndex, &share.EncryptedShare, &holderPubkey,
			&holderBunkerURI, &isLocal, &share.PublicShare, &createdAt)
	if err == sql.ErrNoRows {
		return nil, errors.New("frost share not found")
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
	share.IsLocal = isLocal != 0
	if createdAt.Valid {
		share.CreatedAt = parseTime(createdAt.String)
	}

	return share, nil
}

func (ss *SQLiteStorage) GetFrostShareByKeyAndIndex(ctx context.Context, keyID string, index int) (*FrostShare, error) {
	share := &FrostShare{}
	var holderPubkey, holderBunkerURI, createdAt sql.NullString
	var isLocal int

	err := ss.db.QueryRowContext(ctx, `
		SELECT id, frost_key_id, share_index, encrypted_share, holder_pubkey, holder_bunker_uri, is_local, public_share, created_at
		FROM signer_frost_shares WHERE frost_key_id = ? AND share_index = ?`, keyID, index).
		Scan(&share.ID, &share.FrostKeyID, &share.ShareIndex, &share.EncryptedShare, &holderPubkey,
			&holderBunkerURI, &isLocal, &share.PublicShare, &createdAt)
	if err == sql.ErrNoRows {
		return nil, errors.New("frost share not found")
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
	share.IsLocal = isLocal != 0
	if createdAt.Valid {
		share.CreatedAt = parseTime(createdAt.String)
	}

	return share, nil
}

func (ss *SQLiteStorage) ListFrostShares(ctx context.Context, keyID string) ([]*FrostShare, error) {
	rows, err := ss.db.QueryContext(ctx, `
		SELECT id, frost_key_id, share_index, encrypted_share, holder_pubkey, holder_bunker_uri, is_local, public_share, created_at
		FROM signer_frost_shares WHERE frost_key_id = ? ORDER BY share_index`, keyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return ss.scanFrostShares(rows)
}

func (ss *SQLiteStorage) ListLocalFrostShares(ctx context.Context, keyID string) ([]*FrostShare, error) {
	rows, err := ss.db.QueryContext(ctx, `
		SELECT id, frost_key_id, share_index, encrypted_share, holder_pubkey, holder_bunker_uri, is_local, public_share, created_at
		FROM signer_frost_shares WHERE frost_key_id = ? AND is_local = 1 ORDER BY share_index`, keyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return ss.scanFrostShares(rows)
}

func (ss *SQLiteStorage) scanFrostShares(rows *sql.Rows) ([]*FrostShare, error) {
	var shares []*FrostShare
	for rows.Next() {
		share := &FrostShare{}
		var holderPubkey, holderBunkerURI, createdAt sql.NullString
		var isLocal int

		if err := rows.Scan(&share.ID, &share.FrostKeyID, &share.ShareIndex, &share.EncryptedShare, &holderPubkey,
			&holderBunkerURI, &isLocal, &share.PublicShare, &createdAt); err != nil {
			return nil, err
		}

		if holderPubkey.Valid {
			share.HolderPubkey = holderPubkey.String
		}
		if holderBunkerURI.Valid {
			share.HolderBunkerURI = holderBunkerURI.String
		}
		share.IsLocal = isLocal != 0
		if createdAt.Valid {
			share.CreatedAt = parseTime(createdAt.String)
		}

		shares = append(shares, share)
	}
	return shares, rows.Err()
}

func (ss *SQLiteStorage) DeleteFrostShare(ctx context.Context, id string) error {
	result, err := ss.db.ExecContext(ctx, `DELETE FROM signer_frost_shares WHERE id = ?`, id)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows == 0 {
		return errors.New("frost share not found")
	}
	return nil
}

// NIP-46 Session management (separate from UserSession)

func (ss *SQLiteStorage) CreateSession(ctx context.Context, session *Session) error {
	_, err := ss.db.ExecContext(ctx, `
		INSERT INTO signer_nip46_sessions (id, key_id, client_pubkey, permissions, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		session.ID, session.KeyID, session.ClientPubkey, stringsToJSONArray(session.Permissions),
		formatTime(session.CreatedAt), formatTime(session.ExpiresAt))
	return err
}

func (ss *SQLiteStorage) GetSession(ctx context.Context, id string) (*Session, error) {
	session := &Session{}
	var permissions, createdAt, expiresAt sql.NullString

	err := ss.db.QueryRowContext(ctx, `
		SELECT id, key_id, client_pubkey, permissions, created_at, expires_at
		FROM signer_nip46_sessions WHERE id = ?`, id).
		Scan(&session.ID, &session.KeyID, &session.ClientPubkey, &permissions, &createdAt, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}

	if permissions.Valid {
		session.Permissions = jsonArrayToStrings(permissions.String)
	}
	if createdAt.Valid {
		session.CreatedAt = parseTime(createdAt.String)
	}
	if expiresAt.Valid {
		session.ExpiresAt = parseTime(expiresAt.String)
	}

	if time.Now().After(session.ExpiresAt) {
		return nil, ErrSessionNotFound
	}

	return session, nil
}

func (ss *SQLiteStorage) GetSessionByClient(ctx context.Context, keyID, clientPubkey string) (*Session, error) {
	session := &Session{}
	var permissions, createdAt, expiresAt sql.NullString

	err := ss.db.QueryRowContext(ctx, `
		SELECT id, key_id, client_pubkey, permissions, created_at, expires_at
		FROM signer_nip46_sessions WHERE key_id = ? AND client_pubkey = ? AND expires_at > ?`,
		keyID, clientPubkey, formatTime(time.Now())).
		Scan(&session.ID, &session.KeyID, &session.ClientPubkey, &permissions, &createdAt, &expiresAt)
	if err == sql.ErrNoRows {
		return nil, ErrSessionNotFound
	}
	if err != nil {
		return nil, err
	}

	if permissions.Valid {
		session.Permissions = jsonArrayToStrings(permissions.String)
	}
	if createdAt.Valid {
		session.CreatedAt = parseTime(createdAt.String)
	}
	if expiresAt.Valid {
		session.ExpiresAt = parseTime(expiresAt.String)
	}

	return session, nil
}

func (ss *SQLiteStorage) DeleteSession(ctx context.Context, id string) error {
	_, err := ss.db.ExecContext(ctx, `DELETE FROM signer_nip46_sessions WHERE id = ?`, id)
	return err
}

func (ss *SQLiteStorage) CleanExpiredSessions(ctx context.Context) error {
	_, err := ss.db.ExecContext(ctx, `DELETE FROM signer_nip46_sessions WHERE expires_at < ?`, formatTime(time.Now()))
	return err
}

// Token management

func (ss *SQLiteStorage) CreateToken(ctx context.Context, token *Token) error {
	_, err := ss.db.ExecContext(ctx, `
		INSERT INTO signer_tokens (id, policy_id, key_id, client_name, created_by, expires_at, redeemed_at, redeemed_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		token.ID, token.PolicyID, token.KeyID, nullStr(token.ClientName), nullStr(token.CreatedBy),
		nullTimeStr(token.ExpiresAt), nullTimeStr(token.RedeemedAt), nullStr(token.RedeemedBy), formatTime(token.CreatedAt))
	return err
}

func (ss *SQLiteStorage) GetToken(ctx context.Context, id string) (*Token, error) {
	token := &Token{}
	var clientName, createdBy, expiresAt, redeemedAt, redeemedBy, createdAt sql.NullString

	err := ss.db.QueryRowContext(ctx, `
		SELECT id, policy_id, key_id, client_name, created_by, expires_at, redeemed_at, redeemed_by, created_at
		FROM signer_tokens WHERE id = ?`, id).
		Scan(&token.ID, &token.PolicyID, &token.KeyID, &clientName, &createdBy, &expiresAt, &redeemedAt, &redeemedBy, &createdAt)
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
		t := parseTime(expiresAt.String)
		token.ExpiresAt = &t
	}
	if redeemedAt.Valid {
		t := parseTime(redeemedAt.String)
		token.RedeemedAt = &t
	}
	if redeemedBy.Valid {
		token.RedeemedBy = redeemedBy.String
	}
	if createdAt.Valid {
		token.CreatedAt = parseTime(createdAt.String)
	}

	return token, nil
}

func (ss *SQLiteStorage) ListTokens(ctx context.Context, keyID string) ([]*Token, error) {
	rows, err := ss.db.QueryContext(ctx, `
		SELECT id, policy_id, key_id, client_name, created_by, expires_at, redeemed_at, redeemed_by, created_at
		FROM signer_tokens WHERE key_id = ? ORDER BY created_at DESC`, keyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tokens []*Token
	for rows.Next() {
		token := &Token{}
		var clientName, createdBy, expiresAt, redeemedAt, redeemedBy, createdAt sql.NullString

		if err := rows.Scan(&token.ID, &token.PolicyID, &token.KeyID, &clientName, &createdBy, &expiresAt, &redeemedAt, &redeemedBy, &createdAt); err != nil {
			return nil, err
		}

		if clientName.Valid {
			token.ClientName = clientName.String
		}
		if createdBy.Valid {
			token.CreatedBy = createdBy.String
		}
		if expiresAt.Valid {
			t := parseTime(expiresAt.String)
			token.ExpiresAt = &t
		}
		if redeemedAt.Valid {
			t := parseTime(redeemedAt.String)
			token.RedeemedAt = &t
		}
		if redeemedBy.Valid {
			token.RedeemedBy = redeemedBy.String
		}
		if createdAt.Valid {
			token.CreatedAt = parseTime(createdAt.String)
		}

		tokens = append(tokens, token)
	}
	return tokens, rows.Err()
}

func (ss *SQLiteStorage) RedeemToken(ctx context.Context, tokenID, redeemerPubkey string) (*Token, error) {
	token, err := ss.GetToken(ctx, tokenID)
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
	_, err = ss.db.ExecContext(ctx, `
		UPDATE signer_tokens SET redeemed_at = ?, redeemed_by = ? WHERE id = ?`,
		formatTime(now), redeemerPubkey, tokenID)
	if err != nil {
		return nil, err
	}

	token.RedeemedAt = &now
	token.RedeemedBy = redeemerPubkey
	return token, nil
}

func (ss *SQLiteStorage) DeleteToken(ctx context.Context, id string) error {
	result, err := ss.db.ExecContext(ctx, `DELETE FROM signer_tokens WHERE id = ?`, id)
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

// Bunker secret management

func (ss *SQLiteStorage) CreateBunkerSecret(ctx context.Context, secret *BunkerSecret) error {
	_, err := ss.db.ExecContext(ctx, `
		INSERT INTO signer_bunker_secrets (id, key_pubkey, secret, expires_at, created_at, used_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		secret.ID, secret.KeyPubkey, secret.Secret, formatTime(secret.ExpiresAt), formatTime(secret.CreatedAt), nullTimeStr(secret.UsedAt))
	return err
}

func (ss *SQLiteStorage) ValidateBunkerSecret(ctx context.Context, keyPubkey, secret string) (*BunkerSecret, error) {
	bs := &BunkerSecret{}
	var expiresAt, createdAt, usedAt sql.NullString

	err := ss.db.QueryRowContext(ctx, `
		SELECT id, key_pubkey, secret, expires_at, created_at, used_at
		FROM signer_bunker_secrets WHERE key_pubkey = ? AND secret = ?`, keyPubkey, secret).
		Scan(&bs.ID, &bs.KeyPubkey, &bs.Secret, &expiresAt, &createdAt, &usedAt)
	if err == sql.ErrNoRows {
		return nil, ErrBunkerSecretInvalid
	}
	if err != nil {
		return nil, err
	}

	if expiresAt.Valid {
		bs.ExpiresAt = parseTime(expiresAt.String)
	}
	if createdAt.Valid {
		bs.CreatedAt = parseTime(createdAt.String)
	}
	if usedAt.Valid {
		t := parseTime(usedAt.String)
		bs.UsedAt = &t
	}

	// Check if expired
	if time.Now().After(bs.ExpiresAt) {
		return nil, ErrBunkerSecretInvalid
	}

	// Check if already used
	if bs.UsedAt != nil {
		return nil, ErrBunkerSecretInvalid
	}

	// Mark as used
	now := time.Now()
	_, err = ss.db.ExecContext(ctx, `UPDATE signer_bunker_secrets SET used_at = ? WHERE id = ?`, formatTime(now), bs.ID)
	if err != nil {
		return nil, err
	}
	bs.UsedAt = &now

	return bs, nil
}

func (ss *SQLiteStorage) DeleteBunkerSecret(ctx context.Context, id string) error {
	_, err := ss.db.ExecContext(ctx, `DELETE FROM signer_bunker_secrets WHERE id = ?`, id)
	return err
}

func (ss *SQLiteStorage) CleanExpiredBunkerSecrets(ctx context.Context) error {
	_, err := ss.db.ExecContext(ctx, `DELETE FROM signer_bunker_secrets WHERE expires_at < ?`, formatTime(time.Now()))
	return err
}

// More user management

func (ss *SQLiteStorage) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	user := &User{}
	var userEmail, mfaSecret, lockedUntil, lastLoginAt, lastLoginIP, backupCodes, createdAt sql.NullString
	var mfaEnabled, failedAttempts, backupCodesUsed int

	err := ss.db.QueryRowContext(ctx, `
		SELECT id, username, email, password_hash, mfa_enabled, mfa_secret, backup_codes, backup_codes_used,
		       failed_login_attempts, locked_until, created_at, last_login_at, last_login_ip
		FROM signer_web_accounts WHERE email = ?`, email).
		Scan(&user.ID, &user.Username, &userEmail, &user.PasswordHash, &mfaEnabled, &mfaSecret, &backupCodes, &backupCodesUsed,
			&failedAttempts, &lockedUntil, &createdAt, &lastLoginAt, &lastLoginIP)
	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}

	if userEmail.Valid {
		user.Email = userEmail.String
	}
	user.MFAEnabled = mfaEnabled != 0
	if mfaSecret.Valid {
		user.MFASecret = mfaSecret.String
	}
	if backupCodes.Valid {
		json.Unmarshal([]byte(backupCodes.String), &user.BackupCodes)
	}
	user.BackupCodesUsed = backupCodesUsed
	user.FailedLoginAttempts = failedAttempts
	if lockedUntil.Valid {
		t := parseTime(lockedUntil.String)
		user.LockedUntil = &t
	}
	if createdAt.Valid {
		user.CreatedAt = parseTime(createdAt.String)
	}
	if lastLoginAt.Valid {
		t := parseTime(lastLoginAt.String)
		user.LastLoginAt = &t
	}
	if lastLoginIP.Valid {
		user.LastLoginIP = lastLoginIP.String
	}

	return user, nil
}

func (ss *SQLiteStorage) GetUserByPubkey(ctx context.Context, pubkey string) (*User, error) {
	// SQLite version doesn't have pubkey column - return not found
	return nil, ErrUserNotFound
}

func (ss *SQLiteStorage) UnlockUser(ctx context.Context, userID string) error {
	_, err := ss.db.ExecContext(ctx, `
		UPDATE signer_web_accounts SET locked_until = NULL, failed_login_attempts = 0 WHERE id = ?`, userID)
	return err
}

func (ss *SQLiteStorage) UpdateUserSessionActivity(ctx context.Context, id string) error {
	_, err := ss.db.ExecContext(ctx, `
		UPDATE signer_web_sessions SET last_activity = ? WHERE id = ?`, formatTime(time.Now()), id)
	return err
}

func (ss *SQLiteStorage) CleanExpiredUserSessions(ctx context.Context) error {
	_, err := ss.db.ExecContext(ctx, `DELETE FROM signer_web_sessions WHERE expires_at < ?`, formatTime(time.Now()))
	return err
}

// Platform user (not used in SQLite mode but needed for interface)

func (ss *SQLiteStorage) EnsurePlatformUser(ctx context.Context, pubkey string) error {
	// No-op for SQLite - platform users table is not used in standalone mode
	return nil
}

func (ss *SQLiteStorage) DeriveUserPubkey(ctx context.Context, userID string) (string, error) {
	// For SQLite/self-hosted mode: use a fixed seed - this is deterministic
	testSeed := "0000000000000000000000000000000000000000000000000000000000000000"
	return derivePubkeyFromSeed(testSeed, userID)
}

func (ss *SQLiteStorage) ListPlatformUsers(ctx context.Context, limit, offset int) ([]*PlatformUser, int, error) {
	// Not available in SQLite mode
	return nil, 0, nil
}

func (ss *SQLiteStorage) GetPlatformUserAccess(ctx context.Context, pubkey string) (*PlatformUser, error) {
	// Not available in SQLite mode
	return nil, fmt.Errorf("platform not available in SQLite storage")
}

func (ss *SQLiteStorage) GrantServiceAccess(ctx context.Context, pubkey, serviceSlug string) error {
	// No-op for SQLite
	return nil
}

func (ss *SQLiteStorage) RevokeServiceAccess(ctx context.Context, pubkey, serviceSlug string) error {
	// No-op for SQLite
	return nil
}

func (ss *SQLiteStorage) ListServices(ctx context.Context) ([]*Service, error) {
	// Not available in SQLite mode
	return nil, nil
}
