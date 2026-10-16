
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
	
