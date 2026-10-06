package config

import (
	"os"
	"strings"
	"testing"
)

// The WebAuthn RP ID and origins are environment-specific. With no built-in
// default, an environment that forgets them must refuse to start instead of
// silently registering passkeys against production.

func loadWithWebAuthnEnv(t *testing.T, rpid, origins string) *Config {
	t.Helper()
	t.Setenv("CONFIG_PATH", "/nonexistent/config.yaml")
	t.Setenv("WEBAUTHN_RPID", rpid)
	t.Setenv("WEBAUTHN_ORIGINS", origins)
	if rpid == "" {
		os.Unsetenv("WEBAUTHN_RPID")
	}
	if origins == "" {
		os.Unsetenv("WEBAUTHN_ORIGINS")
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	return cfg
}

func TestWebAuthn_NoProductionDefaults(t *testing.T) {
	cfg := loadWithWebAuthnEnv(t, "", "")
	if cfg.WebAuthn.RPID != "" {
		t.Errorf("RPID default = %q, want empty (no production default)", cfg.WebAuthn.RPID)
	}
	if len(cfg.WebAuthn.RPOrigins) != 0 {
		t.Errorf("RPOrigins default = %v, want empty (no production default)", cfg.WebAuthn.RPOrigins)
	}
}

func TestValidate_WebAuthnRPIDUnset(t *testing.T) {
	cfg := loadWithWebAuthnEnv(t, "", "https://signer.example.test")
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "WEBAUTHN_RPID") {
		t.Fatalf("Validate() = %v, want error naming WEBAUTHN_RPID", err)
	}
}

func TestValidate_WebAuthnOriginsUnset(t *testing.T) {
	cfg := loadWithWebAuthnEnv(t, "example.test", "")
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "WEBAUTHN_ORIGINS") {
		t.Fatalf("Validate() = %v, want error naming WEBAUTHN_ORIGINS", err)
	}
}

func TestValidate_WebAuthnBothUnsetNamesBoth(t *testing.T) {
	cfg := loadWithWebAuthnEnv(t, "", "")
	err := cfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "WEBAUTHN_RPID") || !strings.Contains(err.Error(), "WEBAUTHN_ORIGINS") {
		t.Fatalf("Validate() = %v, want error naming both variables", err)
	}
}

func TestValidate_WebAuthnSet(t *testing.T) {
	cfg := loadWithWebAuthnEnv(t, "example.test", "https://signer.example.test,https://example.test")
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
	if len(cfg.WebAuthn.RPOrigins) != 2 {
		t.Errorf("RPOrigins = %v, want 2 entries", cfg.WebAuthn.RPOrigins)
	}
}
