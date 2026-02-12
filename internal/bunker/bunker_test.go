package bunker

import (
	"strings"
	"testing"
)

func TestGenerateSecret(t *testing.T) {
	secret1, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret() error = %v", err)
	}

	// Should be 32 hex characters (16 bytes)
	if len(secret1) != 32 {
		t.Errorf("GenerateSecret() length = %d, want 32", len(secret1))
	}

	// Should be valid hex
	for _, c := range secret1 {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("GenerateSecret() contains invalid hex character: %c", c)
		}
	}

	// Should generate unique secrets
	secret2, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret() error = %v", err)
	}
	if secret1 == secret2 {
		t.Error("GenerateSecret() generated duplicate secrets")
	}
}

func TestNewURI(t *testing.T) {
	pubkey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	relays := []string{"wss://relay1.example.com", "wss://relay2.example.com"}
	secret := "abc123"

	uri := NewURI(pubkey, relays, secret)

	if uri.SignerPubkey != pubkey {
		t.Errorf("NewURI().SignerPubkey = %q, want %q", uri.SignerPubkey, pubkey)
	}
	if len(uri.Relays) != 2 {
		t.Errorf("NewURI().Relays length = %d, want 2", len(uri.Relays))
	}
	if uri.Secret != secret {
		t.Errorf("NewURI().Secret = %q, want %q", uri.Secret, secret)
	}
}

func TestURIString(t *testing.T) {
	tests := []struct {
		name     string
		uri      *URI
		contains []string
	}{
		{
			name: "with relays and secret",
			uri: &URI{
				SignerPubkey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				Relays:       []string{"wss://relay1.example.com", "wss://relay2.example.com"},
				Secret:       "abc123",
			},
			contains: []string{
				"bunker://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				"relay=wss%3A%2F%2Frelay1.example.com",
				"relay=wss%3A%2F%2Frelay2.example.com",
				"secret=abc123",
			},
		},
		{
			name: "without secret",
			uri: &URI{
				SignerPubkey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				Relays:       []string{"wss://relay.example.com"},
				Secret:       "",
			},
			contains: []string{
				"bunker://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				"relay=",
			},
		},
		{
			name: "empty relays",
			uri: &URI{
				SignerPubkey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				Relays:       []string{},
				Secret:       "secret123",
			},
			contains: []string{
				"bunker://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
				"secret=secret123",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.uri.String()
			for _, substr := range tt.contains {
				if !strings.Contains(result, substr) {
					t.Errorf("URI.String() = %q, should contain %q", result, substr)
				}
			}
		})
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		name        string
		uri         string
		wantPubkey  string
		wantRelays  int
		wantSecret  string
		wantErr     bool
		errContains string
	}{
		{
			name:       "valid URI with relays and secret",
			uri:        "bunker://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef?relay=wss%3A%2F%2Frelay.example.com&secret=abc123",
			wantPubkey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			wantRelays: 1,
			wantSecret: "abc123",
			wantErr:    false,
		},
		{
			name:       "valid URI with multiple relays",
			uri:        "bunker://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef?relay=wss%3A%2F%2Frelay1.example.com&relay=wss%3A%2F%2Frelay2.example.com",
			wantPubkey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			wantRelays: 2,
			wantSecret: "",
			wantErr:    false,
		},
		{
			name:       "valid URI without query params",
			uri:        "bunker://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			wantPubkey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			wantRelays: 0,
			wantSecret: "",
			wantErr:    false,
		},
		{
			name:        "invalid scheme",
			uri:         "nostrconnect://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			wantErr:     true,
			errContains: "must start with bunker://",
		},
		{
			name:        "invalid pubkey length",
			uri:         "bunker://0123456789abcdef",
			wantErr:     true,
			errContains: "pubkey must be 64 hex characters",
		},
		{
			name:        "invalid pubkey hex",
			uri:         "bunker://ghijklmnopqrstuv0123456789abcdef0123456789abcdef0123456789abcdef",
			wantErr:     true,
			errContains: "pubkey must be valid hex",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.uri)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Parse() error = nil, want error containing %q", tt.errContains)
				} else if !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("Parse() error = %q, want error containing %q", err.Error(), tt.errContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("Parse() unexpected error = %v", err)
			}
			if got.SignerPubkey != tt.wantPubkey {
				t.Errorf("Parse().SignerPubkey = %q, want %q", got.SignerPubkey, tt.wantPubkey)
			}
			if len(got.Relays) != tt.wantRelays {
				t.Errorf("Parse().Relays length = %d, want %d", len(got.Relays), tt.wantRelays)
			}
			if got.Secret != tt.wantSecret {
				t.Errorf("Parse().Secret = %q, want %q", got.Secret, tt.wantSecret)
			}
		})
	}
}

func TestParseRoundtrip(t *testing.T) {
	original := &URI{
		SignerPubkey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Relays:       []string{"wss://relay1.example.com", "wss://relay2.example.com"},
		Secret:       "testsecret123",
	}

	uriStr := original.String()
	parsed, err := Parse(uriStr)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}

	if parsed.SignerPubkey != original.SignerPubkey {
		t.Errorf("Roundtrip pubkey = %q, want %q", parsed.SignerPubkey, original.SignerPubkey)
	}
	if len(parsed.Relays) != len(original.Relays) {
		t.Errorf("Roundtrip relays length = %d, want %d", len(parsed.Relays), len(original.Relays))
	}
	if parsed.Secret != original.Secret {
		t.Errorf("Roundtrip secret = %q, want %q", parsed.Secret, original.Secret)
	}
}

func TestGenerateConnectionInfo(t *testing.T) {
	pubkey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	relays := []string{"wss://relay.example.com"}

	t.Run("with secret", func(t *testing.T) {
		info, err := GenerateConnectionInfo(pubkey, relays, true)
		if err != nil {
			t.Fatalf("GenerateConnectionInfo() error = %v", err)
		}
		if info.SignerPubkey != pubkey {
			t.Errorf("SignerPubkey = %q, want %q", info.SignerPubkey, pubkey)
		}
		if len(info.Relays) != 1 {
			t.Errorf("Relays length = %d, want 1", len(info.Relays))
		}
		if info.Secret == "" {
			t.Error("Secret should not be empty when includeSecret=true")
		}
		if !strings.HasPrefix(info.BunkerURI, "bunker://") {
			t.Errorf("BunkerURI = %q, should start with bunker://", info.BunkerURI)
		}
	})

	t.Run("without secret", func(t *testing.T) {
		info, err := GenerateConnectionInfo(pubkey, relays, false)
		if err != nil {
			t.Fatalf("GenerateConnectionInfo() error = %v", err)
		}
		if info.Secret != "" {
			t.Errorf("Secret = %q, want empty when includeSecret=false", info.Secret)
		}
	})
}
