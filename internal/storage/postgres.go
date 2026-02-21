package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/lib/pq"
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
		expires_at TIMESTAMPTZ NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
	);

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

	_, err := ps.db.ExecContext(ctx, `
		INSERT INTO signer_keys (id, name, pubkey, encrypted_nsec, created_at, created_by)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		key.ID, key.Name, key.Pubkey, key.EncryptedNsec, key.CreatedAt, key.CreatedBy)
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
	err := ps.db.QueryRowContext(ctx, `
		SELECT id, name, pubkey, encrypted_nsec, require_approval, created_at, created_by
		FROM signer_keys WHERE id = $1`, id).
		Scan(&key.ID, &key.Name, &key.Pubkey, &key.EncryptedNsec, &key.RequireApproval, &key.CreatedAt, &key.CreatedBy)
	if err == sql.ErrNoRows {
		return nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (ps *PostgresStorage) GetKeyByPubkey(ctx context.Context, pubkey string) (*Key, error) {
	key := &Key{}
	err := ps.db.QueryRowContext(ctx, `
		SELECT id, name, pubkey, encrypted_nsec, require_approval, created_at, created_by
		FROM signer_keys WHERE pubkey = $1`, pubkey).
		Scan(&key.ID, &key.Name, &key.Pubkey, &key.EncryptedNsec, &key.RequireApproval, &key.CreatedAt, &key.CreatedBy)
	if err == sql.ErrNoRows {
		return nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (ps *PostgresStorage) GetKeyByName(ctx context.Context, name string) (*Key, error) {
	key := &Key{}
	err := ps.db.QueryRowContext(ctx, `
		SELECT id, name, pubkey, encrypted_nsec, require_approval, created_at, created_by
		FROM signer_keys WHERE name = $1`, name).
		Scan(&key.ID, &key.Name, &key.Pubkey, &key.EncryptedNsec, &key.RequireApproval, &key.CreatedAt, &key.CreatedBy)
	if err == sql.ErrNoRows {
		return nil, ErrKeyNotFound
	}
	if err != nil {
		return nil, err
	}
	return key, nil
}

func (ps *PostgresStorage) ListKeys(ctx context.Context) ([]*Key, error) {
	rows, err := ps.db.QueryContext(ctx, `
		SELECT id, name, pubkey, encrypted_nsec, require_approval, created_at, created_by
		FROM signer_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []*Key
	for rows.Next() {
		key := &Key{}
		if err := rows.Scan(&key.ID, &key.Name, &key.Pubkey, &key.EncryptedNsec, &key.RequireApproval, &key.CreatedAt, &key.CreatedBy); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (ps *PostgresStorage) UpdateKey(ctx context.Context, key *Key) error {
	result, err := ps.db.ExecContext(ctx, `
		UPDATE signer_keys SET name = $1, require_approval = $2
		WHERE id = $3`,
		key.Name, key.RequireApproval, key.ID)
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
	_, err := ps.db.ExecContext(ctx, `
		INSERT INTO signer_permissions (key_id, user_pubkey, methods, allowed_kinds, expires_at, policy_id, require_approval)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (key_id, user_pubkey) DO UPDATE SET
			methods = EXCLUDED.methods,
			allowed_kinds = EXCLUDED.allowed_kinds,
			expires_at = EXCLUDED.expires_at,
			policy_id = EXCLUDED.policy_id,
			require_approval = EXCLUDED.require_approval`,
		perm.KeyID, perm.UserPubkey, pq.Array(perm.Methods), intArrayToInt64(perm.AllowedKinds), perm.ExpiresAt, perm.PolicyID, perm.RequireApproval)
	return err
}

func (ps *PostgresStorage) GetPermission(ctx context.Context, keyID, userPubkey string) (*Permission, error) {
	perm := &Permission{}
	var expiresAt sql.NullTime
	var policyID sql.NullString
	var allowedKinds pq.Int64Array
	var requireApproval sql.NullBool
	err := ps.db.QueryRowContext(ctx, `
		SELECT key_id, user_pubkey, methods, allowed_kinds, expires_at, policy_id, require_approval
		FROM signer_permissions WHERE key_id = $1 AND user_pubkey = $2`, keyID, userPubkey).
		Scan(&perm.KeyID, &perm.UserPubkey, pq.Array(&perm.Methods), &allowedKinds, &expiresAt, &policyID, &requireApproval)
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
	return perm, nil
}

func (ps *PostgresStorage) ListPermissions(ctx context.Context, keyID string) ([]*Permission, error) {
	rows, err := ps.db.QueryContext(ctx, `
		SELECT key_id, user_pubkey, methods, allowed_kinds, expires_at, policy_id, require_approval
		FROM signer_permissions WHERE key_id = $1`, keyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var perms []*Permission
	for rows.Next() {
		perm := &Permission{}
		var expiresAt sql.NullTime
		var policyID sql.NullString
		var allowedKinds pq.Int64Array
		var requireApproval sql.NullBool
		if err := rows.Scan(&perm.KeyID, &perm.UserPubkey, pq.Array(&perm.Methods), &allowedKinds, &expiresAt, &policyID, &requireApproval); err != nil {
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
		perms = append(perms, perm)
	}
	return perms, rows.Err()
}

func (ps *PostgresStorage) DeletePermission(ctx context.Context, keyID, userPubkey string) error {
	_, err := ps.db.ExecContext(ctx, `
		DELETE FROM signer_permissions WHERE key_id = $1 AND user_pubkey = $2`, keyID, userPubkey)
	return err
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
		INSERT INTO signer_web_sessions (id, user_id, token_hash, user_agent, ip_address, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		session.ID, session.UserID, nullString(session.Token), nullString(session.UserAgent),
		nullString(session.IPAddress), session.ExpiresAt, session.CreatedAt)
	return err
}

func (ps *PostgresStorage) GetUserSession(ctx context.Context, id string) (*UserSession, error) {
	session := &UserSession{}
	var tokenHash, userAgent, ipAddress sql.NullString
	err := ps.db.QueryRowContext(ctx, `
		SELECT id, user_id, token_hash, user_agent, ip_address, expires_at, created_at
		FROM signer_web_sessions WHERE id = $1 AND expires_at > NOW()`, id).
		Scan(&session.ID, &session.UserID, &tokenHash, &userAgent, &ipAddress, &session.ExpiresAt, &session.CreatedAt)
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
	return session, nil
}

func (ps *PostgresStorage) ListUserSessions(ctx context.Context, userID string) ([]*UserSession, error) {
	rows, err := ps.db.QueryContext(ctx, `
		SELECT id, user_id, token_hash, user_agent, ip_address, expires_at, created_at
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
		if err := rows.Scan(&session.ID, &session.UserID, &tokenHash, &userAgent, &ipAddress, &session.ExpiresAt, &session.CreatedAt); err != nil {
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
		sessions = append(sessions, session)
	}
	return sessions, rows.Err()
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
		ON CONFLICT (pubkey, service_id) DO NOTHING`,
		pubkey, serviceSlug)
	return err
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
