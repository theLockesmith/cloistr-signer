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
	Server       ServerConfig  `yaml:"server"`
	Relays       []string      `yaml:"relays"`
	RelayAuthKey string        `yaml:"relay_auth_key"` // Private key for NIP-42 relay auth (hex)
	Storage      StorageConfig `yaml:"storage"`
	Auth         AuthConfig    `yaml:"auth"`
	Vault        VaultConfig   `yaml:"vault"`
	Audit        AuditConfig   `yaml:"audit"`
	Service      ServiceConfig `yaml:"service"`
}

// ServerConfig holds HTTP server configuration
type ServerConfig struct {
	Address string `yaml:"address"`
}

// StorageConfig holds storage backend configuration
type StorageConfig struct {
	Type     string `yaml:"type"` // "memory", "postgres", "sqlite"
	DSN      string `yaml:"dsn"`
	VaultURL string `yaml:"vault_url"`
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	AdminPubkeys         []string `yaml:"admin_pubkeys"`
	RequireApproval      bool     `yaml:"require_approval"`       // Require approval for unknown clients (default: true)
	AuthorizationTimeout int      `yaml:"authorization_timeout"`  // Timeout in seconds for authorization requests (default: 60)
	NotifyAdmins         bool     `yaml:"notify_admins"`          // Send DM to admins for pending requests (default: true)
	JWTSecret            string   `yaml:"jwt_secret"`             // Secret for JWT signing (required for user auth)
	JWTExpiry            int      `yaml:"jwt_expiry"`             // JWT expiry in hours (default: 24)
	MFAIssuer            string   `yaml:"mfa_issuer"`             // Issuer name for TOTP (default: Coldforge)
	MaxFailedLogins      int      `yaml:"max_failed_logins"`      // Max failed logins before lockout (default: 5)
	LockoutMinutes       int      `yaml:"lockout_minutes"`        // Lockout duration in minutes (default: 15)
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
			AdminPubkeys:         []string{},
			RequireApproval:      true,
			AuthorizationTimeout: 60,
			NotifyAdmins:         true,
			JWTSecret:            "",
			JWTExpiry:            24,
			MFAIssuer:            "Coldforge",
			MaxFailedLogins:      5,
			LockoutMinutes:       15,
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
			Name:         "Coldforge Signer",
			Description:  "NIP-46 Remote Signing Service",
			PublishNIP89: false,
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

	if storageType := os.Getenv("STORAGE_TYPE"); storageType != "" {
		cfg.Storage.Type = storageType
	}

	if dsn := os.Getenv("DATABASE_URL"); dsn != "" {
		cfg.Storage.DSN = dsn
	}

	if vaultURL := os.Getenv("VAULT_URL"); vaultURL != "" {
		cfg.Storage.VaultURL = vaultURL
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
