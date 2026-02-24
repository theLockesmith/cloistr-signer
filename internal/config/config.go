package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config holds all configuration for the signer service
type Config struct {
	Server           ServerConfig    `yaml:"server"`
	Relays           []string        `yaml:"relays"`
	RelayAuthKey     string          `yaml:"relay_auth_key"`     // Private key for NIP-42 relay auth (hex)
	MinPowDifficulty int             `yaml:"min_pow_difficulty"` // Minimum POW difficulty for publishing (0 = disabled)
	Storage          StorageConfig   `yaml:"storage"`
	Auth             AuthConfig      `yaml:"auth"`
	Vault            VaultConfig     `yaml:"vault"`
	Audit            AuditConfig     `yaml:"audit"`
	Service          ServiceConfig   `yaml:"service"`
	Proxy            ProxyConfig     `yaml:"proxy"`
	Discovery        DiscoveryConfig `yaml:"discovery"`
}

// DiscoveryConfig holds optional discovery service configuration
type DiscoveryConfig struct {
	URL             string `yaml:"url"`               // Discovery service URL (empty = disabled)
	Timeout         int    `yaml:"timeout"`           // Query timeout in seconds (default: 5)
	MaxRelays       int    `yaml:"max_relays"`        // Max relays from discovery (default: 3)
	IncludeInBunker bool   `yaml:"include_in_bunker"` // Include discovered relays in bunker URI (default: true)
}

// ProxyConfig holds proxy/chaining configuration
type ProxyConfig struct {
	Mode    string `yaml:"mode"`    // "internal" or "external" (default: internal)
	Timeout int    `yaml:"timeout"` // Timeout for upstream requests in seconds (default: 30)
}

// ServerConfig holds HTTP server configuration
type ServerConfig struct {
	Address string `yaml:"address"`
}

// StorageConfig holds storage backend configuration
type StorageConfig struct {
	Type          string `yaml:"type"` // "memory", "postgres", "sqlite"
	DSN           string `yaml:"dsn"`
	VaultURL      string `yaml:"vault_url"`
	EncryptionKey string `yaml:"encryption_key"` // 32-byte hex key for AES-256-GCM encryption
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	AdminPubkeys             []string `yaml:"admin_pubkeys"`
	RequireApproval          bool     `yaml:"require_approval"`           // Require manual approval for unknown clients (default: false, opt-in for security)
	AuthorizationTimeout     int      `yaml:"authorization_timeout"`      // Timeout in seconds for authorization requests (default: 60)
	NotifyAdmins             bool     `yaml:"notify_admins"`              // Send DM to admins for pending requests (default: true)
	JWTSecret                string   `yaml:"jwt_secret"`                 // Secret for JWT signing (required for user auth)
	JWTExpiry                int      `yaml:"jwt_expiry"`                 // JWT expiry in hours (default: 24) - max session length
	SessionInactivityMinutes int      `yaml:"session_inactivity_minutes"` // Session expires after inactivity (default: 1440 = 24h)
	RememberDeviceDays       int      `yaml:"remember_device_days"`       // "Remember this device" session length (default: 30)
	MFAIssuer                string   `yaml:"mfa_issuer"`                 // Issuer name for TOTP (default: Cloistr)
	MaxFailedLogins          int      `yaml:"max_failed_logins"`          // Max failed logins before lockout (default: 5)
	LockoutMinutes           int      `yaml:"lockout_minutes"`            // Lockout duration in minutes (default: 15)
}

// VaultConfig holds HashiCorp Vault configuration
type VaultConfig struct {
	Enabled   bool   `yaml:"enabled"`
	Address   string `yaml:"address"`    // Vault address (e.g., http://vault:8200)
	Token     string `yaml:"token"`      // Vault token
	MountPath string `yaml:"mount_path"` // KV secrets mount path (default: secret)
}

// AuditConfig holds audit logging configuration
type AuditConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Backend  string `yaml:"backend"`   // "memory", "file", "json"
	FilePath string `yaml:"file_path"` // Path for file/json backend
	MaxEvents int   `yaml:"max_events"` // Max events to retain (memory backend)
}

// ServiceConfig holds service metadata for NIP-89 and NIP-05
type ServiceConfig struct {
	Name        string `yaml:"name"`         // Service name
	Description string `yaml:"description"`  // Service description
	Website     string `yaml:"website"`      // Public URL
	NIP05Domain string `yaml:"nip05_domain"` // Domain for NIP-05 (e.g., coldforge.xyz)
	PublishNIP89 bool  `yaml:"publish_nip89"` // Publish NIP-89 announcements
}

// Load loads configuration from environment variables and optional YAML file
func Load() (*Config, error) {
	cfg := &Config{
		Server: ServerConfig{
			Address: ":7777",
		},
		Relays: []string{
			"wss://relay.coldforge.xyz",
		},
		Storage: StorageConfig{
			Type: "memory",
		},
		Auth: AuthConfig{
			AdminPubkeys:             []string{},
			RequireApproval:          false, // Default to auto-approve for simpler UX
			AuthorizationTimeout:     60,
			NotifyAdmins:             true,
			JWTSecret:                "",
			JWTExpiry:                24,
			SessionInactivityMinutes: 1440, // 24 hours - session expires if inactive
			RememberDeviceDays:       30,   // 30 days for "remember this device"
			MFAIssuer:                "Cloistr",
			MaxFailedLogins:          5,
			LockoutMinutes:           15,
		},
		Vault: VaultConfig{
			Enabled:   false,
			MountPath: "secret",
		},
		Audit: AuditConfig{
			Enabled:   true,
			Backend:   "memory",
			MaxEvents: 10000,
		},
		Service: ServiceConfig{
			Name:         "Cloistr Signer",
			Description:  "NIP-46 Remote Signing Service",
			PublishNIP89: false,
		},
		Proxy: ProxyConfig{
			Mode:    "internal",
			Timeout: 30,
		},
		Discovery: DiscoveryConfig{
			URL:             "",    // Disabled by default
			Timeout:         5,     // 5 seconds
			MaxRelays:       3,     // Max 3 relays from discovery
			IncludeInBunker: true,  // Include in bunker URI by default
		},
	}

	// Try to load from YAML file
	configPath := getEnv("CONFIG_PATH", "config.yaml")
	if data, err := os.ReadFile(configPath); err == nil {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	// Environment variables override YAML
	if addr := os.Getenv("SERVER_ADDRESS"); addr != "" {
		cfg.Server.Address = addr
	}

	if relays := os.Getenv("RELAYS"); relays != "" {
		cfg.Relays = strings.Split(relays, ",")
	}

	if authKey := os.Getenv("RELAY_AUTH_KEY"); authKey != "" {
		cfg.RelayAuthKey = authKey
	}

	if powStr := os.Getenv("MIN_POW_DIFFICULTY"); powStr != "" {
		pow, err := strconv.Atoi(powStr)
		if err != nil {
			return nil, fmt.Errorf("invalid MIN_POW_DIFFICULTY: %w", err)
		}
		cfg.MinPowDifficulty = pow
	}

	if storageType := os.Getenv("STORAGE_TYPE"); storageType != "" {
		cfg.Storage.Type = storageType
	}

	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		cfg.Storage.DSN = dsn
		// Auto-select postgres if DATABASE_URL is set and STORAGE_TYPE wasn't explicit
		if os.Getenv("STORAGE_TYPE") == "" {
			cfg.Storage.Type = "postgres"
		}
	}

	if vaultURL := os.Getenv("VAULT_URL"); vaultURL != "" {
		cfg.Storage.VaultURL = vaultURL
	}

	if encryptionKey := os.Getenv("ENCRYPTION_KEY"); encryptionKey != "" {
		cfg.Storage.EncryptionKey = encryptionKey
	}

	if adminPubkeys := os.Getenv("ADMIN_PUBKEYS"); adminPubkeys != "" {
		cfg.Auth.AdminPubkeys = strings.Split(adminPubkeys, ",")
	}

	if requireApproval := os.Getenv("REQUIRE_APPROVAL"); requireApproval != "" {
		cfg.Auth.RequireApproval = requireApproval == "true" || requireApproval == "1"
	}

	if timeout := os.Getenv("AUTHORIZATION_TIMEOUT"); timeout != "" {
		cfg.Auth.AuthorizationTimeout = getEnvInt("AUTHORIZATION_TIMEOUT", 60)
	}

	if notifyAdmins := os.Getenv("NOTIFY_ADMINS"); notifyAdmins != "" {
		cfg.Auth.NotifyAdmins = notifyAdmins == "true" || notifyAdmins == "1"
	}

	if jwtSecret := os.Getenv("JWT_SECRET"); jwtSecret != "" {
		cfg.Auth.JWTSecret = jwtSecret
	}

	if jwtExpiry := os.Getenv("JWT_EXPIRY"); jwtExpiry != "" {
		cfg.Auth.JWTExpiry = getEnvInt("JWT_EXPIRY", 24)
	}

	if mfaIssuer := os.Getenv("MFA_ISSUER"); mfaIssuer != "" {
		cfg.Auth.MFAIssuer = mfaIssuer
	}

	if maxFailed := os.Getenv("MAX_FAILED_LOGINS"); maxFailed != "" {
		cfg.Auth.MaxFailedLogins = getEnvInt("MAX_FAILED_LOGINS", 5)
	}

	if lockout := os.Getenv("LOCKOUT_MINUTES"); lockout != "" {
		cfg.Auth.LockoutMinutes = getEnvInt("LOCKOUT_MINUTES", 15)
	}

	if sessionInactivity := os.Getenv("SESSION_INACTIVITY_MINUTES"); sessionInactivity != "" {
		cfg.Auth.SessionInactivityMinutes = getEnvInt("SESSION_INACTIVITY_MINUTES", 1440)
	}

	if rememberDays := os.Getenv("REMEMBER_DEVICE_DAYS"); rememberDays != "" {
		cfg.Auth.RememberDeviceDays = getEnvInt("REMEMBER_DEVICE_DAYS", 30)
	}

	// Vault configuration
	if vaultEnabled := os.Getenv("VAULT_ENABLED"); vaultEnabled == "true" || vaultEnabled == "1" {
		cfg.Vault.Enabled = true
	}
	if vaultAddr := os.Getenv("VAULT_ADDR"); vaultAddr != "" {
		cfg.Vault.Address = vaultAddr
	}
	if vaultToken := os.Getenv("VAULT_TOKEN"); vaultToken != "" {
		cfg.Vault.Token = vaultToken
	}
	if vaultMount := os.Getenv("VAULT_MOUNT_PATH"); vaultMount != "" {
		cfg.Vault.MountPath = vaultMount
	}

	// Audit configuration
	if auditEnabled := os.Getenv("AUDIT_ENABLED"); auditEnabled != "" {
		cfg.Audit.Enabled = auditEnabled == "true" || auditEnabled == "1"
	}
	if auditBackend := os.Getenv("AUDIT_BACKEND"); auditBackend != "" {
		cfg.Audit.Backend = auditBackend
	}
	if auditPath := os.Getenv("AUDIT_FILE_PATH"); auditPath != "" {
		cfg.Audit.FilePath = auditPath
	}

	// Service configuration
	if serviceName := os.Getenv("SERVICE_NAME"); serviceName != "" {
		cfg.Service.Name = serviceName
	}
	if serviceDesc := os.Getenv("SERVICE_DESCRIPTION"); serviceDesc != "" {
		cfg.Service.Description = serviceDesc
	}
	if serviceURL := os.Getenv("SERVICE_URL"); serviceURL != "" {
		cfg.Service.Website = serviceURL
	}
	if nip05Domain := os.Getenv("NIP05_DOMAIN"); nip05Domain != "" {
		cfg.Service.NIP05Domain = nip05Domain
	}
	if publishNIP89 := os.Getenv("PUBLISH_NIP89"); publishNIP89 == "true" || publishNIP89 == "1" {
		cfg.Service.PublishNIP89 = true
	}

	// Proxy configuration
	if proxyMode := os.Getenv("PROXY_MODE"); proxyMode != "" {
		cfg.Proxy.Mode = proxyMode
	}
	if proxyTimeout := os.Getenv("PROXY_TIMEOUT"); proxyTimeout != "" {
		cfg.Proxy.Timeout = getEnvInt("PROXY_TIMEOUT", 30)
	}

	// Discovery configuration (optional - disabled if URL is empty)
	if discoveryURL := os.Getenv("DISCOVERY_URL"); discoveryURL != "" {
		cfg.Discovery.URL = discoveryURL
	}
	if discoveryTimeout := os.Getenv("DISCOVERY_TIMEOUT"); discoveryTimeout != "" {
		cfg.Discovery.Timeout = getEnvInt("DISCOVERY_TIMEOUT", 5)
	}
	if discoveryMaxRelays := os.Getenv("DISCOVERY_MAX_RELAYS"); discoveryMaxRelays != "" {
		cfg.Discovery.MaxRelays = getEnvInt("DISCOVERY_MAX_RELAYS", 3)
	}
	if discoveryInclude := os.Getenv("DISCOVERY_INCLUDE_IN_BUNKER"); discoveryInclude != "" {
		cfg.Discovery.IncludeInBunker = discoveryInclude == "true" || discoveryInclude == "1"
	}

	return cfg, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if i, err := strconv.Atoi(value); err == nil {
			return i
		}
	}
	return defaultValue
}
