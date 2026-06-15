package crypto

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/vault"
)

// mockVaultServer creates a test server that simulates Vault transit operations
func mockVaultServer(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify token in all requests
		token := r.Header.Get("X-Vault-Token")
		if token == "" {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"errors": []string{"missing client token"},
			})
			return
		}

		// Check for unauthorized token
		if token == "invalid-token" {
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"errors": []string{"permission denied"},
			})
			return
		}

		path := r.URL.Path

		// Transit encrypt
		if strings.Contains(path, "/transit/encrypt/") && r.Method == http.MethodPost {
			var payload map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			// Return mock ciphertext
			response := map[string]interface{}{
				"data": map[string]interface{}{
					"ciphertext": "vault:v1:" + base64.StdEncoding.EncodeToString([]byte(payload["plaintext"])),
				},
			}
			json.NewEncoder(w).Encode(response)
			return
		}

		// Transit rewrap - returns ciphertext bumped to a new version (v2)
		// to simulate Vault re-encrypting under the current key version.
		if strings.Contains(path, "/transit/rewrap/") && r.Method == http.MethodPost {
			var payload map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			ciphertext := payload["ciphertext"]
			if !strings.HasPrefix(ciphertext, "vault:v") {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"errors": []string{"invalid ciphertext"},
				})
				return
			}

			// Strip the version prefix (e.g. "vault:v1:") and re-emit at v2 so
			// the test can observe that a rewrap happened. Real Vault would do
			// the actual cryptographic operation here.
			rest := ciphertext
			if idx := strings.Index(rest[len("vault:v"):], ":"); idx >= 0 {
				rest = rest[len("vault:v")+idx+1:]
			}

			response := map[string]interface{}{
				"data": map[string]interface{}{
					"ciphertext": "vault:v2:" + rest,
				},
			}
			json.NewEncoder(w).Encode(response)
			return
		}

		// Transit decrypt
		if strings.Contains(path, "/transit/decrypt/") && r.Method == http.MethodPost {
			var payload map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			ciphertext := payload["ciphertext"]
			if !strings.HasPrefix(ciphertext, "vault:v1:") {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"errors": []string{"invalid ciphertext"},
				})
				return
			}

			// Extract and return the "plaintext" (base64 encoded original)
			encoded := strings.TrimPrefix(ciphertext, "vault:v1:")
			decoded, _ := base64.StdEncoding.DecodeString(encoded)

			response := map[string]interface{}{
				"data": map[string]interface{}{
					"plaintext": string(decoded),
				},
			}
			json.NewEncoder(w).Encode(response)
			return
		}

		w.WriteHeader(http.StatusNotFound)
	}))
}

func TestVaultEncryptor_EncryptDecrypt(t *testing.T) {
	server := mockVaultServer(t)
	defer server.Close()

	client, err := vault.NewClient(&vault.Config{
		Address: server.URL,
		Token:   "service-token",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	enc := NewVaultEncryptor(client, "user123", "user-vault-token")

	tests := []struct {
		name      string
		plaintext string
	}{
		{"simple string", "hello world"},
		{"nsec key", "nsec1abc123def456"},
		{"empty string", ""},
		{"unicode", "key with unicode: \u0048\u0065\u006C\u006C\u006F"},
		{"special chars", "key!@#$%^&*()_+{}[]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := enc.Encrypt(tt.plaintext)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			// Verify ciphertext has vault prefix
			if !strings.HasPrefix(ciphertext, "vault:v1:") {
				t.Errorf("Encrypt() ciphertext should have 'vault:v1:' prefix, got %q", ciphertext)
			}

			// Decrypt and verify
			decrypted, err := enc.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}

			if decrypted != tt.plaintext {
				t.Errorf("Decrypt() = %q, want %q", decrypted, tt.plaintext)
			}
		})
	}
}

func TestVaultEncryptor_EncryptDecryptBytes(t *testing.T) {
	server := mockVaultServer(t)
	defer server.Close()

	client, _ := vault.NewClient(&vault.Config{
		Address: server.URL,
		Token:   "service-token",
	})

	enc := NewVaultEncryptor(client, "user123", "user-vault-token")

	plaintext := []byte{0x00, 0x01, 0x02, 0xFE, 0xFF}

	ciphertext, err := enc.EncryptBytes(plaintext)
	if err != nil {
		t.Fatalf("EncryptBytes() error = %v", err)
	}

	decrypted, err := enc.DecryptBytes(ciphertext)
	if err != nil {
		t.Fatalf("DecryptBytes() error = %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("DecryptBytes() = %v, want %v", decrypted, plaintext)
	}
}

func TestVaultEncryptor_InvalidToken(t *testing.T) {
	server := mockVaultServer(t)
	defer server.Close()

	client, _ := vault.NewClient(&vault.Config{
		Address: server.URL,
		Token:   "service-token",
	})

	// Create encryptor with invalid token
	enc := NewVaultEncryptor(client, "user123", "invalid-token")

	_, err := enc.Encrypt("test data")
	if err == nil {
		t.Error("Encrypt() should fail with invalid token")
	}
}

func TestVaultEncryptor_Rewrap(t *testing.T) {
	server := mockVaultServer(t)
	defer server.Close()

	client, err := vault.NewClient(&vault.Config{
		Address: server.URL,
		Token:   "service-token",
	})
	if err != nil {
		t.Fatalf("NewClient() error = %v", err)
	}

	enc := NewVaultEncryptor(client, "user123", "user-token")

	plaintext := "secret nsec material"
	ciphertext, err := enc.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}
	if !strings.HasPrefix(ciphertext, "vault:v1:") {
		t.Fatalf("expected v1 ciphertext, got %s", ciphertext)
	}

	rewrapped, err := enc.Rewrap(ciphertext)
	if err != nil {
		t.Fatalf("Rewrap() error = %v", err)
	}
	if !strings.HasPrefix(rewrapped, "vault:v2:") {
		t.Errorf("expected v2 ciphertext after rewrap, got %s", rewrapped)
	}
	if rewrapped == ciphertext {
		t.Errorf("Rewrap() returned identical ciphertext; expected version bump")
	}
}

func TestVaultEncryptor_RewrapInvalidToken(t *testing.T) {
	server := mockVaultServer(t)
	defer server.Close()

	client, _ := vault.NewClient(&vault.Config{
		Address: server.URL,
		Token:   "service-token",
	})

	enc := NewVaultEncryptor(client, "user123", "invalid-token")
	if _, err := enc.Rewrap("vault:v1:fake"); err == nil {
		t.Error("Rewrap() should fail with invalid token")
	}
}

func TestVaultEncryptor_UserID(t *testing.T) {
	client, _ := vault.NewClient(&vault.Config{
		Address: "http://vault:8200",
		Token:   "test",
	})

	enc := NewVaultEncryptor(client, "user-abc-123", "token")

	if enc.UserID() != "user-abc-123" {
		t.Errorf("UserID() = %q, want %q", enc.UserID(), "user-abc-123")
	}
}

func TestVaultEncryptor_Context(t *testing.T) {
	server := mockVaultServer(t)
	defer server.Close()

	client, _ := vault.NewClient(&vault.Config{
		Address: server.URL,
		Token:   "service-token",
	})

	enc := NewVaultEncryptor(client, "user123", "user-vault-token")
	ctx := context.Background()

	// Test with context
	ciphertext, err := enc.EncryptWithContext(ctx, "test data")
	if err != nil {
		t.Fatalf("EncryptWithContext() error = %v", err)
	}

	decrypted, err := enc.DecryptWithContext(ctx, ciphertext)
	if err != nil {
		t.Fatalf("DecryptWithContext() error = %v", err)
	}

	if decrypted != "test data" {
		t.Errorf("DecryptWithContext() = %q, want %q", decrypted, "test data")
	}
}

func TestVaultEncryptor_DifferentUsers(t *testing.T) {
	server := mockVaultServer(t)
	defer server.Close()

	client, _ := vault.NewClient(&vault.Config{
		Address: server.URL,
		Token:   "service-token",
	})

	enc1 := NewVaultEncryptor(client, "user1", "token1")
	enc2 := NewVaultEncryptor(client, "user2", "token2")

	plaintext := "shared secret"

	// Each user encrypts the same plaintext
	ciphertext1, _ := enc1.Encrypt(plaintext)
	ciphertext2, _ := enc2.Encrypt(plaintext)

	// Ciphertexts should be different (different keys used)
	// In real Vault, they would be completely different
	// In our mock, the key name is different in the path
	if ciphertext1 == ciphertext2 {
		t.Log("Note: In a real Vault, different user keys would produce different ciphertexts")
	}

	// Each user can decrypt their own ciphertext
	decrypted1, err := enc1.Decrypt(ciphertext1)
	if err != nil {
		t.Fatalf("enc1.Decrypt() error = %v", err)
	}
	if decrypted1 != plaintext {
		t.Errorf("enc1.Decrypt() = %q, want %q", decrypted1, plaintext)
	}

	decrypted2, err := enc2.Decrypt(ciphertext2)
	if err != nil {
		t.Fatalf("enc2.Decrypt() error = %v", err)
	}
	if decrypted2 != plaintext {
		t.Errorf("enc2.Decrypt() = %q, want %q", decrypted2, plaintext)
	}
}

func TestIsVaultEncrypted(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"vault:v1:abc123", true},
		{"vault:v2:abc123", true},
		{"vault:v1:", true},
		{"vault:", true},  // Any vault: prefix is considered vault-encrypted
		{"vault:abc", true},
		{"enc:abc123", false},
		{"plaintext", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.value, func(t *testing.T) {
			if got := IsVaultEncrypted(tt.value); got != tt.want {
				t.Errorf("IsVaultEncrypted(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestKeyEncryptor_Interface(t *testing.T) {
	// Verify both types implement KeyEncryptor
	server := mockVaultServer(t)
	defer server.Close()

	client, _ := vault.NewClient(&vault.Config{
		Address: server.URL,
		Token:   "service-token",
	})

	var _ KeyEncryptor = (*Encryptor)(nil)
	var _ KeyEncryptor = (*VaultEncryptor)(nil)

	// Create instances and use through interface
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	localEnc, _ := NewEncryptor(key)
	vaultEnc := NewVaultEncryptor(client, "user123", "user-vault-token")

	encryptors := []KeyEncryptor{localEnc, vaultEnc}

	for i, enc := range encryptors {
		plaintext := "test data"

		ciphertext, err := enc.Encrypt(plaintext)
		if err != nil {
			t.Errorf("encryptor[%d].Encrypt() error = %v", i, err)
			continue
		}

		decrypted, err := enc.Decrypt(ciphertext)
		if err != nil {
			t.Errorf("encryptor[%d].Decrypt() error = %v", i, err)
			continue
		}

		if decrypted != plaintext {
			t.Errorf("encryptor[%d].Decrypt() = %q, want %q", i, decrypted, plaintext)
		}
	}
}
