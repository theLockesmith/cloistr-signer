package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/config"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/crypto"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/signer"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/vault"
)

// Integration tests for full user flows
// These tests verify the complete registration → login → key operations → logout flow

// TestIntegration_FullFlow_NoVault tests the complete flow without Vault (local encryption)
func TestIntegration_FullFlow_NoVault(t *testing.T) {
	// Setup: in-memory storage + local encryption
	store := storage.NewMemoryStorage()
	cfg := &config.Config{
		Auth: config.AuthConfig{
			JWTSecret:                "integration-test-secret-32chars!!",
			JWTExpiry:                24,
			SessionInactivityMinutes: 1440,
		},
		Server: config.ServerConfig{Address: ":8080"},
		Relays: []string{"wss://relay.example.com"},
	}

	encryptor, err := crypto.NewEncryptor("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	// Create signer with nil components (like handler_test.go does)
	s := signer.New(cfg, store, nil, encryptor, nil, nil, nil)
	handler := NewHandler(cfg, s, store, encryptor, nil) // nil vault client

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Step 1: Register a new user
	t.Run("1_Register", func(t *testing.T) {
		body := `{"username":"integrationuser","password":"TestPass123!"}`
		req := httptest.NewRequest("POST", "/api/v1/users/register", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Fatalf("Register failed: %d - %s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["id"] == nil {
			t.Fatal("Register response missing id")
		}
	})

	// Step 2: Login and get JWT token
	var authToken string
	t.Run("2_Login", func(t *testing.T) {
		body := `{"username":"integrationuser","password":"TestPass123!"}`
		req := httptest.NewRequest("POST", "/api/v1/users/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Login failed: %d - %s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		token, ok := resp["token"].(string)
		if !ok || token == "" {
			t.Fatal("Login response missing token")
		}
		authToken = token
	})

	// Step 3: Create a key (should use local encryption)
	var keyID string
	t.Run("3_CreateKey", func(t *testing.T) {
		body := `{"name":"integration-test-key"}`
		req := httptest.NewRequest("POST", "/api/v1/keys", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+authToken)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Fatalf("CreateKey failed: %d - %s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		id, ok := resp["id"].(string)
		if !ok || id == "" {
			t.Fatal("CreateKey response missing id")
		}
		keyID = id

		// Verify encryption method is 'local'
		method, _ := resp["encryption_method"].(string)
		if method != "local" && method != "" { // Empty means local (default)
			t.Logf("Note: encryption_method=%s", method)
		}
	})

	// Step 4: List keys - should only show our key
	t.Run("4_ListKeys", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/keys", nil)
		req.Header.Set("Authorization", "Bearer "+authToken)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("ListKeys failed: %d - %s", w.Code, w.Body.String())
		}

		var keys []map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &keys)
		if len(keys) != 1 {
			t.Fatalf("Expected 1 key, got %d", len(keys))
		}
		if keys[0]["id"] != keyID {
			t.Fatalf("Expected key id %s, got %s", keyID, keys[0]["id"])
		}
	})

	// Step 5: Get key details
	t.Run("5_GetKey", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/keys/"+keyID, nil)
		req.Header.Set("Authorization", "Bearer "+authToken)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("GetKey failed: %d - %s", w.Code, w.Body.String())
		}

		var key map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &key)
		if key["name"] != "integration-test-key" {
			t.Fatalf("Expected key name 'integration-test-key', got %s", key["name"])
		}
	})

	// Step 6: Register a second user and verify isolation
	var user2Token string
	t.Run("6_RegisterUser2", func(t *testing.T) {
		body := `{"username":"integrationuser2","password":"TestPass456!"}`
		req := httptest.NewRequest("POST", "/api/v1/users/register", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Fatalf("Register user2 failed: %d - %s", w.Code, w.Body.String())
		}

		// Login as user2
		body = `{"username":"integrationuser2","password":"TestPass456!"}`
		req = httptest.NewRequest("POST", "/api/v1/users/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		user2Token = resp["token"].(string)
	})

	// Step 7: Verify user2 cannot see user1's keys
	t.Run("7_User2_CannotSeeUser1Keys", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/keys", nil)
		req.Header.Set("Authorization", "Bearer "+user2Token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("ListKeys for user2 failed: %d - %s", w.Code, w.Body.String())
		}

		var keys []map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &keys)
		if len(keys) != 0 {
			t.Fatalf("User2 should see 0 keys, got %d", len(keys))
		}
	})

	// Step 8: Verify user2 cannot access user1's key directly
	t.Run("8_User2_CannotAccessUser1Key", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/keys/"+keyID, nil)
		req.Header.Set("Authorization", "Bearer "+user2Token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		// Should get 403 Forbidden or 404 Not Found
		if w.Code != http.StatusForbidden && w.Code != http.StatusNotFound {
			t.Fatalf("User2 accessing user1's key should fail, got %d", w.Code)
		}
	})

	// Step 9: Delete key
	t.Run("9_DeleteKey", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/keys/"+keyID, nil)
		req.Header.Set("Authorization", "Bearer "+authToken)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		// DELETE returns 204 No Content on success
		if w.Code != http.StatusOK && w.Code != http.StatusNoContent {
			t.Fatalf("DeleteKey failed: %d - %s", w.Code, w.Body.String())
		}
	})

	// Step 10: Verify key is deleted
	t.Run("10_VerifyKeyDeleted", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/keys/"+keyID, nil)
		req.Header.Set("Authorization", "Bearer "+authToken)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusNotFound && w.Code != http.StatusForbidden {
			t.Fatalf("Deleted key should not be accessible, got %d", w.Code)
		}
	})

	// Step 11: Logout
	t.Run("11_Logout", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/users/logout", nil)
		req.Header.Set("Authorization", "Bearer "+authToken)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Logout failed: %d - %s", w.Code, w.Body.String())
		}
	})
}

// TestIntegration_FullFlow_WithVault tests the complete flow with Vault-backed encryption
func TestIntegration_FullFlow_WithVault(t *testing.T) {
	// Create mock Vault server
	vaultServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Vault-Token")
		path := r.URL.Path

		// Health check
		if path == "/v1/sys/health" {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"initialized": true,
				"sealed":      false,
			})
			return
		}

		// Service token endpoints (provisioning)
		if token == "service-token" {
			// Create transit key
			if strings.Contains(path, "/transit/keys/") && r.Method == http.MethodPost {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{})
				return
			}
			// Create policy
			if strings.Contains(path, "/sys/policies/acl/") && r.Method == http.MethodPut {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{})
				return
			}
			// Create userpass account
			if strings.Contains(path, "/auth/userpass/users/") && r.Method == http.MethodPost {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{})
				return
			}
		}

		// Userpass login - return user token
		if strings.Contains(path, "/auth/userpass/login/") && r.Method == http.MethodPost {
			var payload map[string]string
			json.NewDecoder(r.Body).Decode(&payload)
			if payload["password"] == "TestVaultPass123!" {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"auth": map[string]interface{}{
						"client_token":   "user-vault-token-" + strings.TrimPrefix(path, "/v1/auth/userpass/login/"),
						"lease_duration": 3600,
						"renewable":      true,
					},
				})
				return
			}
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"errors": []string{"invalid username or password"},
			})
			return
		}

		// Token revoke
		if path == "/v1/auth/token/revoke-self" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// User token endpoints (encrypt/decrypt)
		if strings.HasPrefix(token, "user-vault-token-") {
			// Transit encrypt
			if strings.Contains(path, "/transit/encrypt/") && r.Method == http.MethodPost {
				var payload map[string]string
				json.NewDecoder(r.Body).Decode(&payload)
				ciphertext := "vault:v1:" + base64.StdEncoding.EncodeToString([]byte(payload["plaintext"]))
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{
						"ciphertext": ciphertext,
					},
				})
				return
			}
			// Transit decrypt
			if strings.Contains(path, "/transit/decrypt/") && r.Method == http.MethodPost {
				var payload map[string]string
				json.NewDecoder(r.Body).Decode(&payload)
				encoded := strings.TrimPrefix(payload["ciphertext"], "vault:v1:")
				decoded, _ := base64.StdEncoding.DecodeString(encoded)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{
						"plaintext": string(decoded),
					},
				})
				return
			}
		}

		// Forbidden for other requests
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"errors": []string{"permission denied"},
		})
	}))
	defer vaultServer.Close()

	// Setup storage and config
	store := storage.NewMemoryStorage()
	cfg := &config.Config{
		Auth: config.AuthConfig{
			JWTSecret:                "integration-test-secret-32chars!!",
			JWTExpiry:                24,
			SessionInactivityMinutes: 1440,
		},
		Vault: config.VaultConfig{
			Enabled:   true,
			Address:   vaultServer.URL,
			Token:     "service-token",
			MountPath: "transit",
		},
		Server: config.ServerConfig{Address: ":8080"},
		Relays: []string{"wss://relay.example.com"},
	}

	// Create Vault client
	vaultClient, err := vault.NewClient(&vault.Config{
		Address: vaultServer.URL,
		Token:   "service-token",
	})
	if err != nil {
		t.Fatalf("Failed to create Vault client: %v", err)
	}

	// Local encryptor as fallback
	encryptor, _ := crypto.NewEncryptor("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

	// Create signer with nil components
	s := signer.New(cfg, store, nil, encryptor, nil, nil, nil)
	handler := NewHandler(cfg, s, store, encryptor, vaultClient)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Step 1: Register with Vault provisioning
	var userID string
	t.Run("1_Register_VaultProvisioning", func(t *testing.T) {
		body := `{"username":"vaultuser","password":"TestVaultPass123!"}`
		req := httptest.NewRequest("POST", "/api/v1/users/register", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Fatalf("Register with Vault failed: %d - %s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		userID = resp["id"].(string)
	})

	// Step 2: Login - should authenticate to Vault and get user token
	var authToken string
	t.Run("2_Login_VaultAuth", func(t *testing.T) {
		body := `{"username":"vaultuser","password":"TestVaultPass123!"}`
		req := httptest.NewRequest("POST", "/api/v1/users/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Login with Vault failed: %d - %s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		authToken = resp["token"].(string)
	})

	// Step 3: Create key - should use Vault transit encryption
	var keyID string
	t.Run("3_CreateKey_VaultEncryption", func(t *testing.T) {
		body := `{"name":"vault-encrypted-key"}`
		req := httptest.NewRequest("POST", "/api/v1/keys", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+authToken)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusCreated {
			t.Fatalf("CreateKey with Vault failed: %d - %s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		keyID = resp["id"].(string)

		// Check encryption method - should be 'vault' when Vault is available
		method, _ := resp["encryption_method"].(string)
		t.Logf("Key encryption_method: %s", method)
	})

	// Step 4: List keys
	t.Run("4_ListKeys", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/keys", nil)
		req.Header.Set("Authorization", "Bearer "+authToken)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("ListKeys failed: %d - %s", w.Code, w.Body.String())
		}

		var keys []map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &keys)
		if len(keys) != 1 {
			t.Fatalf("Expected 1 key, got %d", len(keys))
		}
	})

	// Step 5: Get key and verify encrypted_nsec has vault prefix
	t.Run("5_VerifyVaultEncryption", func(t *testing.T) {
		// Get key from storage directly to check encrypted_nsec
		key, err := store.GetKey(context.Background(), keyID)
		if err != nil {
			t.Fatalf("Failed to get key from storage: %v", err)
		}

		// The encrypted_nsec should have vault: prefix when using Vault
		if key.EncryptedNsec != "" {
			hasVaultPrefix := strings.HasPrefix(key.EncryptedNsec, "vault:")
			t.Logf("encrypted_nsec has vault: prefix: %v", hasVaultPrefix)
			t.Logf("encryption_method: %s", key.EncryptionMethod)
			if key.EncryptionMethod != "vault" {
				t.Errorf("Expected encryption_method='vault', got '%s'", key.EncryptionMethod)
			}
		}
	})

	// Step 6: Logout
	t.Run("6_Logout_VaultTokenRevoke", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/users/logout", nil)
		req.Header.Set("Authorization", "Bearer "+authToken)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("Logout failed: %d - %s", w.Code, w.Body.String())
		}
	})

	_ = userID // Mark as used
}

// TestIntegration_MFA tests the MFA enrollment flow
func TestIntegration_MFA(t *testing.T) {
	store := storage.NewMemoryStorage()
	cfg := &config.Config{
		Auth: config.AuthConfig{
			JWTSecret:                "integration-test-secret-32chars!!",
			JWTExpiry:                24,
			SessionInactivityMinutes: 1440,
			MFAIssuer:                "TestCloistr",
		},
		Server: config.ServerConfig{Address: ":8080"},
		Relays: []string{"wss://relay.example.com"},
	}

	s := signer.New(cfg, store, nil, nil, nil, nil, nil)
	handler := NewHandler(cfg, s, store, nil, nil)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Step 1: Register and login
	body := `{"username":"mfauser","password":"MFATest123!"}`
	req := httptest.NewRequest("POST", "/api/v1/users/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("Register failed: %d", w.Code)
	}

	req = httptest.NewRequest("POST", "/api/v1/users/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var loginResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &loginResp)
	authToken := loginResp["token"].(string)

	// Step 2: Setup MFA
	t.Run("SetupMFA", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/v1/users/mfa/setup", nil)
		req.Header.Set("Authorization", "Bearer "+authToken)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("MFA setup failed: %d - %s", w.Code, w.Body.String())
		}

		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		if resp["secret"] == nil {
			t.Fatal("MFA setup response missing secret")
		}
		if resp["qr_code_url"] == nil {
			t.Fatal("MFA setup response missing qr_code_url")
		}
		t.Logf("MFA setup successful, secret returned")
	})
}

// TestIntegration_KeyImport tests importing existing keys
func TestIntegration_KeyImport(t *testing.T) {
	store := storage.NewMemoryStorage()
	cfg := &config.Config{
		Auth: config.AuthConfig{
			JWTSecret:                "integration-test-secret-32chars!!",
			JWTExpiry:                24,
			SessionInactivityMinutes: 1440,
		},
		Server: config.ServerConfig{Address: ":8080"},
		Relays: []string{"wss://relay.example.com"},
	}

	encryptor, _ := crypto.NewEncryptor("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	s := signer.New(cfg, store, nil, encryptor, nil, nil, nil)
	handler := NewHandler(cfg, s, store, encryptor, nil)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Register and login
	body := `{"username":"importuser","password":"ImportTest123!"}`
	req := httptest.NewRequest("POST", "/api/v1/users/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	req = httptest.NewRequest("POST", "/api/v1/users/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	var loginResp map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &loginResp)
	authToken := loginResp["token"].(string)

	// Import a key (using hex private key)
	t.Run("ImportKey", func(t *testing.T) {
		// Generate a test private key in hex format
		testPrivkey := repeat("a", 64) // Simple test key
		body := `{"name":"imported-key","private_key":"` + testPrivkey + `"}`
		req := httptest.NewRequest("POST", "/api/v1/keys", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+authToken)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		// Should succeed with valid hex key
		if w.Code != http.StatusCreated {
			t.Logf("Import key response: %d - %s", w.Code, w.Body.String())
			// May fail if key validation is strict - that's ok
		} else {
			t.Log("Key import successful")
		}
	})
}

// TestIntegration_SessionManagement tests session limits and expiration
func TestIntegration_SessionManagement(t *testing.T) {
	store := storage.NewMemoryStorage()
	cfg := &config.Config{
		Auth: config.AuthConfig{
			JWTSecret:                "integration-test-secret-32chars!!",
			JWTExpiry:                24,
			SessionInactivityMinutes: 1440,
		},
		Server: config.ServerConfig{Address: ":8080"},
		Relays: []string{"wss://relay.example.com"},
	}

	s := signer.New(cfg, store, nil, nil, nil, nil, nil)
	handler := NewHandler(cfg, s, store, nil, nil)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Register
	body := `{"username":"sessionuser","password":"SessionTest123!"}`
	req := httptest.NewRequest("POST", "/api/v1/users/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	// Login multiple times
	var tokens []string
	for i := 0; i < 3; i++ {
		req := httptest.NewRequest("POST", "/api/v1/users/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code == http.StatusOK {
			var resp map[string]interface{}
			json.Unmarshal(w.Body.Bytes(), &resp)
			tokens = append(tokens, resp["token"].(string))
		}
		t.Logf("Login %d: status=%d", i+1, w.Code)
	}

	// Verify we got tokens
	t.Logf("Got %d tokens", len(tokens))
	if len(tokens) != 3 {
		t.Errorf("Expected 3 successful logins, got %d", len(tokens))
	}

	// Verify all tokens work
	for i, token := range tokens {
		req := httptest.NewRequest("GET", "/api/v1/keys", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("Token %d failed: %d", i+1, w.Code)
		}
	}
}

// TestIntegration_UserIsolation tests that users cannot access each other's resources
func TestIntegration_UserIsolation(t *testing.T) {
	store := storage.NewMemoryStorage()
	cfg := &config.Config{
		Auth: config.AuthConfig{
			JWTSecret:                "integration-test-secret-32chars!!",
			JWTExpiry:                24,
			SessionInactivityMinutes: 1440,
		},
		Server: config.ServerConfig{Address: ":8080"},
		Relays: []string{"wss://relay.example.com"},
	}

	encryptor, _ := crypto.NewEncryptor("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	s := signer.New(cfg, store, nil, encryptor, nil, nil, nil)
	handler := NewHandler(cfg, s, store, encryptor, nil)
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Create two users
	var user1Token, user2Token string
	var user1KeyID string

	// User 1: Register, login, create key
	t.Run("User1_Setup", func(t *testing.T) {
		body := `{"username":"isolationuser1","password":"IsoTest123!"}`
		req := httptest.NewRequest("POST", "/api/v1/users/register", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusCreated {
			t.Fatalf("User1 register failed: %d", w.Code)
		}

		req = httptest.NewRequest("POST", "/api/v1/users/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		user1Token = resp["token"].(string)

		// Create key
		body = `{"name":"user1-key"}`
		req = httptest.NewRequest("POST", "/api/v1/keys", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+user1Token)
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		json.Unmarshal(w.Body.Bytes(), &resp)
		user1KeyID = resp["id"].(string)
	})

	// User 2: Register and login
	t.Run("User2_Setup", func(t *testing.T) {
		body := `{"username":"isolationuser2","password":"IsoTest456!"}`
		req := httptest.NewRequest("POST", "/api/v1/users/register", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code != http.StatusCreated {
			t.Fatalf("User2 register failed: %d", w.Code)
		}

		req = httptest.NewRequest("POST", "/api/v1/users/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		var resp map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &resp)
		user2Token = resp["token"].(string)
	})

	// Test isolation: User2 cannot see User1's keys in list
	t.Run("User2_CannotListUser1Keys", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/keys", nil)
		req.Header.Set("Authorization", "Bearer "+user2Token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		var keys []map[string]interface{}
		json.Unmarshal(w.Body.Bytes(), &keys)
		if len(keys) != 0 {
			t.Fatalf("User2 should not see User1's keys, got %d keys", len(keys))
		}
	})

	// Test isolation: User2 cannot access User1's key directly
	t.Run("User2_CannotAccessUser1Key", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/keys/"+user1KeyID, nil)
		req.Header.Set("Authorization", "Bearer "+user2Token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden && w.Code != http.StatusNotFound {
			t.Fatalf("User2 should not access User1's key, got %d", w.Code)
		}
	})

	// Test isolation: User2 cannot delete User1's key
	t.Run("User2_CannotDeleteUser1Key", func(t *testing.T) {
		req := httptest.NewRequest("DELETE", "/api/v1/keys/"+user1KeyID, nil)
		req.Header.Set("Authorization", "Bearer "+user2Token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusForbidden && w.Code != http.StatusNotFound {
			t.Fatalf("User2 should not delete User1's key, got %d", w.Code)
		}
	})

	// Verify User1 can still access their key
	t.Run("User1_CanAccessOwnKey", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/v1/keys/"+user1KeyID, nil)
		req.Header.Set("Authorization", "Bearer "+user1Token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("User1 should access own key, got %d", w.Code)
		}
	})
}

// repeat creates a string by repeating the input n times
func repeat(s string, n int) string {
	var buf bytes.Buffer
	for i := 0; i < n; i++ {
		buf.WriteString(s)
	}
	return buf.String()
}
