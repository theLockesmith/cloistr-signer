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
	Server  ServerConfig  `yaml:"server"`
	Relays  []string      `yaml:"relays"`
	Storage StorageConfig `yaml:"storage"`
	Auth    AuthConfig    `yaml:"auth"`
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
	AdminPubkeys []string `yaml:"admin_pubkeys"`
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
			AdminPubkeys: []string{},
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
