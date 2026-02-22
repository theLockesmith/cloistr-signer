package config

import (
	"os"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	// Clear any environment variables that might interfere
	envVars := []string{
		"CONFIG_PATH", "SERVER_ADDRESS", "RELAYS", "RELAY_AUTH_KEY",
		"STORAGE_TYPE", "DATABASE_URL", "ADMIN_PUBKEYS", "REQUIRE_APPROVAL",
		"JWT_SECRET", "VAULT_ENABLED", "AUDIT_ENABLED",
	}
	for _, v := range envVars {
		os.Unsetenv(v)
	}

	// Set CONFIG_PATH to nonexistent file to skip YAML loading
	os.Setenv("CONFIG_PATH", "/nonexistent/config.yaml")
	defer os.Unsetenv("CONFIG_PATH")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Check defaults
	if cfg.Server.Address != ":7777" {
		t.Errorf("Server.Address = %q, want %q", cfg.Server.Address, ":7777")
	}
	if len(cfg.Relays) != 1 || cfg.Relays[0] != "wss://relay.coldforge.xyz" {
		t.Errorf("Relays = %v, want [wss://relay.coldforge.xyz]", cfg.Relays)
	}
	if cfg.Storage.Type != "memory" {
		t.Errorf("Storage.Type = %q, want %q", cfg.Storage.Type, "memory")
	}
	if cfg.Auth.RequireApproval != false {
		t.Errorf("Auth.RequireApproval = %v, want false", cfg.Auth.RequireApproval)
	}
	if cfg.Auth.AuthorizationTimeout != 60 {
		t.Errorf("Auth.AuthorizationTimeout = %d, want 60", cfg.Auth.AuthorizationTimeout)
	}
	if cfg.Auth.NotifyAdmins != true {
		t.Errorf("Auth.NotifyAdmins = %v, want true", cfg.Auth.NotifyAdmins)
	}
	if cfg.Auth.JWTExpiry != 24 {
		t.Errorf("Auth.JWTExpiry = %d, want 24", cfg.Auth.JWTExpiry)
	}
	if cfg.Auth.MFAIssuer != "Cloistr" {
		t.Errorf("Auth.MFAIssuer = %q, want %q", cfg.Auth.MFAIssuer, "Cloistr")
	}
	if cfg.Auth.MaxFailedLogins != 5 {
		t.Errorf("Auth.MaxFailedLogins = %d, want 5", cfg.Auth.MaxFailedLogins)
	}
	if cfg.Auth.LockoutMinutes != 15 {
		t.Errorf("Auth.LockoutMinutes = %d, want 15", cfg.Auth.LockoutMinutes)
	}
	if cfg.Vault.Enabled != false {
		t.Errorf("Vault.Enabled = %v, want false", cfg.Vault.Enabled)
	}
	if cfg.Vault.MountPath != "secret" {
		t.Errorf("Vault.MountPath = %q, want %q", cfg.Vault.MountPath, "secret")
	}
	if cfg.Audit.Enabled != true {
		t.Errorf("Audit.Enabled = %v, want true", cfg.Audit.Enabled)
	}
	if cfg.Audit.Backend != "memory" {
		t.Errorf("Audit.Backend = %q, want %q", cfg.Audit.Backend, "memory")
	}
	if cfg.Service.Name != "Cloistr Signer" {
		t.Errorf("Service.Name = %q, want %q", cfg.Service.Name, "Cloistr Signer")
	}
	if cfg.Service.PublishNIP89 != false {
		t.Errorf("Service.PublishNIP89 = %v, want false", cfg.Service.PublishNIP89)
	}
}

func TestLoadEnvOverrides(t *testing.T) {
	// Set CONFIG_PATH to nonexistent file to skip YAML loading
	os.Setenv("CONFIG_PATH", "/nonexistent/config.yaml")
	defer os.Unsetenv("CONFIG_PATH")

	// Set environment variables
	envSettings := map[string]string{
		"SERVER_ADDRESS":        ":8888",
		"RELAYS":                "wss://relay1.example.com,wss://relay2.example.com",
		"RELAY_AUTH_KEY":        "abc123",
		"STORAGE_TYPE":          "postgres",
		"DATABASE_URL":          "postgres://localhost/test",
		"ADMIN_PUBKEYS":         "pubkey1,pubkey2",
		"REQUIRE_APPROVAL":      "true",
		"AUTHORIZATION_TIMEOUT": "120",
		"NOTIFY_ADMINS":         "false",
		"JWT_SECRET":            "supersecret",
		"JWT_EXPIRY":            "48",
		"MFA_ISSUER":            "TestApp",
		"MAX_FAILED_LOGINS":     "10",
		"LOCKOUT_MINUTES":       "30",
		"VAULT_ENABLED":         "true",
		"VAULT_ADDR":            "http://vault:8200",
		"VAULT_TOKEN":           "vault-token",
		"VAULT_MOUNT_PATH":      "kv",
		"AUDIT_ENABLED":         "false",
		"AUDIT_BACKEND":         "json",
		"AUDIT_FILE_PATH":       "/var/log/audit.json",
		"SERVICE_NAME":          "Test Signer",
		"SERVICE_DESCRIPTION":   "Test Description",
		"SERVICE_URL":           "https://test.example.com",
		"NIP05_DOMAIN":          "test.example.com",
		"PUBLISH_NIP89":         "true",
	}

	for k, v := range envSettings {
		os.Setenv(k, v)
		defer os.Unsetenv(k)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Verify overrides
	if cfg.Server.Address != ":8888" {
		t.Errorf("Server.Address = %q, want %q", cfg.Server.Address, ":8888")
	}
	if len(cfg.Relays) != 2 {
		t.Errorf("Relays length = %d, want 2", len(cfg.Relays))
	}
	if cfg.RelayAuthKey != "abc123" {
		t.Errorf("RelayAuthKey = %q, want %q", cfg.RelayAuthKey, "abc123")
	}
	if cfg.Storage.Type != "postgres" {
		t.Errorf("Storage.Type = %q, want %q", cfg.Storage.Type, "postgres")
	}
	if cfg.Storage.DSN != "postgres://localhost/test" {
		t.Errorf("Storage.DSN = %q, want %q", cfg.Storage.DSN, "postgres://localhost/test")
	}
	if len(cfg.Auth.AdminPubkeys) != 2 {
		t.Errorf("AdminPubkeys length = %d, want 2", len(cfg.Auth.AdminPubkeys))
	}
	if cfg.Auth.RequireApproval != true {
		t.Errorf("Auth.RequireApproval = %v, want true", cfg.Auth.RequireApproval)
	}
	if cfg.Auth.AuthorizationTimeout != 120 {
		t.Errorf("Auth.AuthorizationTimeout = %d, want 120", cfg.Auth.AuthorizationTimeout)
	}
	if cfg.Auth.NotifyAdmins != false {
		t.Errorf("Auth.NotifyAdmins = %v, want false", cfg.Auth.NotifyAdmins)
	}
	if cfg.Auth.JWTSecret != "supersecret" {
		t.Errorf("Auth.JWTSecret = %q, want %q", cfg.Auth.JWTSecret, "supersecret")
	}
	if cfg.Auth.JWTExpiry != 48 {
		t.Errorf("Auth.JWTExpiry = %d, want 48", cfg.Auth.JWTExpiry)
	}
	if cfg.Auth.MFAIssuer != "TestApp" {
		t.Errorf("Auth.MFAIssuer = %q, want %q", cfg.Auth.MFAIssuer, "TestApp")
	}
	if cfg.Auth.MaxFailedLogins != 10 {
		t.Errorf("Auth.MaxFailedLogins = %d, want 10", cfg.Auth.MaxFailedLogins)
	}
	if cfg.Auth.LockoutMinutes != 30 {
		t.Errorf("Auth.LockoutMinutes = %d, want 30", cfg.Auth.LockoutMinutes)
	}
	if cfg.Vault.Enabled != true {
		t.Errorf("Vault.Enabled = %v, want true", cfg.Vault.Enabled)
	}
	if cfg.Vault.Address != "http://vault:8200" {
		t.Errorf("Vault.Address = %q, want %q", cfg.Vault.Address, "http://vault:8200")
	}
	if cfg.Vault.Token != "vault-token" {
		t.Errorf("Vault.Token = %q, want %q", cfg.Vault.Token, "vault-token")
	}
	if cfg.Vault.MountPath != "kv" {
		t.Errorf("Vault.MountPath = %q, want %q", cfg.Vault.MountPath, "kv")
	}
	if cfg.Audit.Enabled != false {
		t.Errorf("Audit.Enabled = %v, want false", cfg.Audit.Enabled)
	}
	if cfg.Audit.Backend != "json" {
		t.Errorf("Audit.Backend = %q, want %q", cfg.Audit.Backend, "json")
	}
	if cfg.Audit.FilePath != "/var/log/audit.json" {
		t.Errorf("Audit.FilePath = %q, want %q", cfg.Audit.FilePath, "/var/log/audit.json")
	}
	if cfg.Service.Name != "Test Signer" {
		t.Errorf("Service.Name = %q, want %q", cfg.Service.Name, "Test Signer")
	}
	if cfg.Service.Description != "Test Description" {
		t.Errorf("Service.Description = %q, want %q", cfg.Service.Description, "Test Description")
	}
	if cfg.Service.Website != "https://test.example.com" {
		t.Errorf("Service.Website = %q, want %q", cfg.Service.Website, "https://test.example.com")
	}
	if cfg.Service.NIP05Domain != "test.example.com" {
		t.Errorf("Service.NIP05Domain = %q, want %q", cfg.Service.NIP05Domain, "test.example.com")
	}
	if cfg.Service.PublishNIP89 != true {
		t.Errorf("Service.PublishNIP89 = %v, want true", cfg.Service.PublishNIP89)
	}
}

func TestGetEnv(t *testing.T) {
	key := "TEST_GETENV_VAR"
	os.Unsetenv(key)

	// Test default value
	result := getEnv(key, "default")
	if result != "default" {
		t.Errorf("getEnv() = %q, want %q", result, "default")
	}

	// Test with set value
	os.Setenv(key, "custom")
	defer os.Unsetenv(key)
	result = getEnv(key, "default")
	if result != "custom" {
		t.Errorf("getEnv() = %q, want %q", result, "custom")
	}
}

func TestGetEnvInt(t *testing.T) {
	key := "TEST_GETENVINT_VAR"
	os.Unsetenv(key)

	// Test default value
	result := getEnvInt(key, 42)
	if result != 42 {
		t.Errorf("getEnvInt() = %d, want %d", result, 42)
	}

	// Test with valid integer
	os.Setenv(key, "100")
	defer os.Unsetenv(key)
	result = getEnvInt(key, 42)
	if result != 100 {
		t.Errorf("getEnvInt() = %d, want %d", result, 100)
	}

	// Test with invalid integer (should return default)
	os.Setenv(key, "notanumber")
	result = getEnvInt(key, 42)
	if result != 42 {
		t.Errorf("getEnvInt() = %d, want %d (default)", result, 42)
	}
}

func TestRequireApprovalValues(t *testing.T) {
	os.Setenv("CONFIG_PATH", "/nonexistent/config.yaml")
	defer os.Unsetenv("CONFIG_PATH")

	tests := []struct {
		value string
		want  bool
	}{
		{"true", true},
		{"1", true},
		{"false", false},
		{"0", false},
		{"yes", false}, // Only "true" and "1" are truthy
	}

	for _, tt := range tests {
		os.Setenv("REQUIRE_APPROVAL", tt.value)
		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.Auth.RequireApproval != tt.want {
			t.Errorf("REQUIRE_APPROVAL=%q: Auth.RequireApproval = %v, want %v",
				tt.value, cfg.Auth.RequireApproval, tt.want)
		}
	}
	os.Unsetenv("REQUIRE_APPROVAL")
}
