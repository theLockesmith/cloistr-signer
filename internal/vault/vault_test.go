package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClient(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		cfg := &Config{
			Address:   "http://vault:8200",
			Token:     "test-token",
			MountPath: "kv",
		}

		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("NewClient() error = %v", err)
		}

		if client.address != "http://vault:8200" {
			t.Errorf("address = %q, want %q", client.address, "http://vault:8200")
		}
		if client.token != "test-token" {
			t.Errorf("token = %q, want %q", client.token, "test-token")
		}
		if client.mountPath != "kv" {
			t.Errorf("mountPath = %q, want %q", client.mountPath, "kv")
		}
	})

	t.Run("default mount path", func(t *testing.T) {
		cfg := &Config{
			Address: "http://vault:8200",
			Token:   "test-token",
		}

		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("NewClient() error = %v", err)
		}

		if client.mountPath != "secret" {
			t.Errorf("mountPath = %q, want %q", client.mountPath, "secret")
		}
	})

	t.Run("strips trailing slash", func(t *testing.T) {
		cfg := &Config{
			Address: "http://vault:8200/",
		}

		client, err := NewClient(cfg)
		if err != nil {
			t.Fatalf("NewClient() error = %v", err)
		}

		if client.address != "http://vault:8200" {
			t.Errorf("address = %q, want %q", client.address, "http://vault:8200")
		}
	})

	t.Run("missing address", func(t *testing.T) {
		cfg := &Config{
			Token: "test-token",
		}

		_, err := NewClient(cfg)
		if err == nil {
			t.Error("NewClient() should return error when address is missing")
		}
	})
}

func TestClient_StoreKey(t *testing.T) {
	// Create mock Vault server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		if r.Header.Get("X-Vault-Token") != "test-token" {
			t.Errorf("missing or invalid X-Vault-Token header")
		}

		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q, want %q", r.Header.Get("Content-Type"), "application/json")
		}

		// Verify the request body structure
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}

		if _, ok := payload["data"]; !ok {
			t.Error("payload should contain 'data' field")
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client, _ := NewClient(&Config{
		Address: server.URL,
		Token:   "test-token",
	})

	ctx := context.Background()
	data := map[string]interface{}{
		"nsec": "encrypted-nsec-value",
		"name": "test-key",
	}

	err := client.StoreKey(ctx, "key123", data)
	if err != nil {
		t.Fatalf("StoreKey() error = %v", err)
	}
}

func TestClient_StoreKey_Error(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"errors": ["permission denied"]}`))
	}))
	defer server.Close()

	client, _ := NewClient(&Config{
		Address: server.URL,
		Token:   "test-token",
	})

	ctx := context.Background()
	err := client.StoreKey(ctx, "key123", map[string]interface{}{"nsec": "value"})
	if err == nil {
		t.Error("StoreKey() should return error on 403")
	}
}

func TestClient_GetKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}

		response := map[string]interface{}{
			"data": map[string]interface{}{
				"data": map[string]interface{}{
					"nsec": "encrypted-nsec-value",
					"name": "test-key",
				},
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, _ := NewClient(&Config{
		Address: server.URL,
		Token:   "test-token",
	})

	ctx := context.Background()
	data, err := client.GetKey(ctx, "key123")
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}

	if data["nsec"] != "encrypted-nsec-value" {
		t.Errorf("data[nsec] = %v, want %q", data["nsec"], "encrypted-nsec-value")
	}
}

func TestClient_GetKey_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client, _ := NewClient(&Config{
		Address: server.URL,
		Token:   "test-token",
	})

	ctx := context.Background()
	_, err := client.GetKey(ctx, "nonexistent")
	if err == nil {
		t.Error("GetKey() should return error for not found")
	}
}

func TestClient_DeleteKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, _ := NewClient(&Config{
		Address: server.URL,
		Token:   "test-token",
	})

	ctx := context.Background()
	err := client.DeleteKey(ctx, "key123")
	if err != nil {
		t.Fatalf("DeleteKey() error = %v", err)
	}
}

func TestClient_ListKeys(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "LIST" {
			t.Errorf("expected LIST, got %s", r.Method)
		}

		response := map[string]interface{}{
			"data": map[string]interface{}{
				"keys": []string{"key1", "key2", "key3"},
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, _ := NewClient(&Config{
		Address: server.URL,
		Token:   "test-token",
	})

	ctx := context.Background()
	keys, err := client.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}

	if len(keys) != 3 {
		t.Errorf("ListKeys() = %d keys, want 3", len(keys))
	}
}

func TestClient_ListKeys_Empty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client, _ := NewClient(&Config{
		Address: server.URL,
		Token:   "test-token",
	})

	ctx := context.Background()
	keys, err := client.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}

	if len(keys) != 0 {
		t.Errorf("ListKeys() = %d keys, want 0 for empty", len(keys))
	}
}

func TestClient_HealthCheck(t *testing.T) {
	t.Run("healthy", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/sys/health" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := NewClient(&Config{Address: server.URL})

		ctx := context.Background()
		err := client.HealthCheck(ctx)
		if err != nil {
			t.Errorf("HealthCheck() error = %v", err)
		}
	})

	t.Run("standby (429)", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(429)
		}))
		defer server.Close()

		client, _ := NewClient(&Config{Address: server.URL})

		ctx := context.Background()
		err := client.HealthCheck(ctx)
		if err != nil {
			t.Errorf("HealthCheck() should not error on standby: %v", err)
		}
	})

	t.Run("sealed (503)", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()

		client, _ := NewClient(&Config{Address: server.URL})

		ctx := context.Background()
		err := client.HealthCheck(ctx)
		if err == nil {
			t.Error("HealthCheck() should return error when sealed")
		}
	})
}

func TestClient_TransitEncrypt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		response := map[string]interface{}{
			"data": map[string]interface{}{
				"ciphertext": "vault:v1:encrypted-data",
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, _ := NewClient(&Config{
		Address: server.URL,
		Token:   "test-token",
	})

	ctx := context.Background()
	ciphertext, err := client.TransitEncrypt(ctx, "mykey", "base64-plaintext")
	if err != nil {
		t.Fatalf("TransitEncrypt() error = %v", err)
	}

	if ciphertext != "vault:v1:encrypted-data" {
		t.Errorf("ciphertext = %q, want %q", ciphertext, "vault:v1:encrypted-data")
	}
}

func TestClient_TransitDecrypt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}

		response := map[string]interface{}{
			"data": map[string]interface{}{
				"plaintext": "decrypted-base64-data",
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, _ := NewClient(&Config{
		Address: server.URL,
		Token:   "test-token",
	})

	ctx := context.Background()
	plaintext, err := client.TransitDecrypt(ctx, "mykey", "vault:v1:encrypted-data")
	if err != nil {
		t.Fatalf("TransitDecrypt() error = %v", err)
	}

	if plaintext != "decrypted-base64-data" {
		t.Errorf("plaintext = %q, want %q", plaintext, "decrypted-base64-data")
	}
}

func TestConfig_Fields(t *testing.T) {
	cfg := Config{
		Address:   "http://vault:8200",
		Token:     "my-token",
		MountPath: "secret-v2",
	}

	if cfg.Address != "http://vault:8200" {
		t.Errorf("Address = %q", cfg.Address)
	}
	if cfg.Token != "my-token" {
		t.Errorf("Token = %q", cfg.Token)
	}
	if cfg.MountPath != "secret-v2" {
		t.Errorf("MountPath = %q", cfg.MountPath)
	}
}

// Tests for auth flow functions

func TestClient_CreateTransitKey(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("expected POST, got %s", r.Method)
			}
			if r.URL.Path != "/v1/transit/keys/mykey" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			if r.Header.Get("X-Vault-Token") != "service-token" {
				t.Errorf("missing or invalid X-Vault-Token header")
			}

			// Verify request body
			var payload map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("failed to decode request body: %v", err)
			}
			if payload["type"] != "aes256-gcm96" {
				t.Errorf("type = %v, want aes256-gcm96", payload["type"])
			}
			if payload["exportable"] != false {
				t.Errorf("exportable = %v, want false", payload["exportable"])
			}

			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		client, _ := NewClient(&Config{
			Address: server.URL,
			Token:   "service-token",
		})

		err := client.CreateTransitKey(context.Background(), "mykey")
		if err != nil {
			t.Fatalf("CreateTransitKey() error = %v", err)
		}
	})

	t.Run("error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"errors": ["permission denied"]}`))
		}))
		defer server.Close()

		client, _ := NewClient(&Config{
			Address: server.URL,
			Token:   "bad-token",
		})

		err := client.CreateTransitKey(context.Background(), "mykey")
		if err == nil {
			t.Error("CreateTransitKey() should return error on 403")
		}
	})
}

func TestClient_CreateUserpassAccount(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("expected POST, got %s", r.Method)
			}
			if r.URL.Path != "/v1/auth/userpass/users/user123" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			if r.Header.Get("X-Vault-Token") != "service-token" {
				t.Errorf("missing or invalid X-Vault-Token header")
			}

			// Verify request body
			var payload map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("failed to decode request body: %v", err)
			}
			if payload["password"] != "userpass123" {
				t.Errorf("password = %v", payload["password"])
			}
			if payload["token_ttl"] != "24h" {
				t.Errorf("token_ttl = %v", payload["token_ttl"])
			}
			if payload["token_max_ttl"] != "72h" {
				t.Errorf("token_max_ttl = %v", payload["token_max_ttl"])
			}

			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		client, _ := NewClient(&Config{
			Address: server.URL,
			Token:   "service-token",
		})

		err := client.CreateUserpassAccount(context.Background(), "user123", "userpass123", []string{"user-policy"})
		if err != nil {
			t.Fatalf("CreateUserpassAccount() error = %v", err)
		}
	})

	t.Run("error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"errors": ["permission denied"]}`))
		}))
		defer server.Close()

		client, _ := NewClient(&Config{
			Address: server.URL,
			Token:   "bad-token",
		})

		err := client.CreateUserpassAccount(context.Background(), "user123", "pass", []string{})
		if err == nil {
			t.Error("CreateUserpassAccount() should return error on 403")
		}
	})
}

func TestClient_UpdateUserpassPassword(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/auth/userpass/users/user123/password" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}

		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}
		if payload["password"] != "newpassword" {
			t.Errorf("password = %v, want newpassword", payload["password"])
		}

		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, _ := NewClient(&Config{
		Address: server.URL,
		Token:   "service-token",
	})

	err := client.UpdateUserpassPassword(context.Background(), "user123", "newpassword")
	if err != nil {
		t.Fatalf("UpdateUserpassPassword() error = %v", err)
	}
}

func TestClient_AuthenticateUserpass(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("expected POST, got %s", r.Method)
			}
			if r.URL.Path != "/v1/auth/userpass/login/user123" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			// Auth endpoint should NOT require X-Vault-Token
			if r.Header.Get("X-Vault-Token") != "" {
				t.Log("Note: X-Vault-Token not required for userpass login")
			}

			var payload map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("failed to decode request body: %v", err)
			}
			if payload["password"] != "mypassword" {
				t.Errorf("password = %v", payload["password"])
			}

			response := map[string]interface{}{
				"auth": map[string]interface{}{
					"client_token":   "user-token-abc123",
					"accessor":       "accessor-xyz789",
					"policies":       []string{"default", "user-policy"},
					"token_policies": []string{"default", "user-policy"},
					"lease_duration": 86400,
					"renewable":      true,
				},
			}
			json.NewEncoder(w).Encode(response)
		}))
		defer server.Close()

		client, _ := NewClient(&Config{
			Address: server.URL,
			Token:   "service-token",
		})

		auth, err := client.AuthenticateUserpass(context.Background(), "user123", "mypassword")
		if err != nil {
			t.Fatalf("AuthenticateUserpass() error = %v", err)
		}

		if auth.Token != "user-token-abc123" {
			t.Errorf("Token = %q, want %q", auth.Token, "user-token-abc123")
		}
		if auth.Accessor != "accessor-xyz789" {
			t.Errorf("Accessor = %q, want %q", auth.Accessor, "accessor-xyz789")
		}
		if auth.LeaseDuration != 86400 {
			t.Errorf("LeaseDuration = %d, want 86400", auth.LeaseDuration)
		}
		if !auth.Renewable {
			t.Error("Renewable should be true")
		}
		if len(auth.Policies) != 2 {
			t.Errorf("Policies = %v, want 2 policies", auth.Policies)
		}
	})

	t.Run("invalid credentials", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"errors": ["invalid username or password"]}`))
		}))
		defer server.Close()

		client, _ := NewClient(&Config{
			Address: server.URL,
			Token:   "service-token",
		})

		_, err := client.AuthenticateUserpass(context.Background(), "user123", "wrongpassword")
		if err == nil {
			t.Error("AuthenticateUserpass() should return error for invalid credentials")
		}
	})
}

func TestClient_RevokeToken(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Errorf("expected POST, got %s", r.Method)
			}
			if r.URL.Path != "/v1/auth/token/revoke" {
				t.Errorf("unexpected path: %s", r.URL.Path)
			}
			if r.Header.Get("X-Vault-Token") != "service-token" {
				t.Errorf("missing or invalid X-Vault-Token header")
			}

			var payload map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("failed to decode request body: %v", err)
			}
			if payload["token"] != "token-to-revoke" {
				t.Errorf("token = %v", payload["token"])
			}

			w.WriteHeader(http.StatusNoContent)
		}))
		defer server.Close()

		client, _ := NewClient(&Config{
			Address: server.URL,
			Token:   "service-token",
		})

		err := client.RevokeToken(context.Background(), "token-to-revoke")
		if err != nil {
			t.Fatalf("RevokeToken() error = %v", err)
		}
	})

	t.Run("error", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			w.Write([]byte(`{"errors": ["permission denied"]}`))
		}))
		defer server.Close()

		client, _ := NewClient(&Config{
			Address: server.URL,
			Token:   "bad-token",
		})

		err := client.RevokeToken(context.Background(), "some-token")
		if err == nil {
			t.Error("RevokeToken() should return error on 403")
		}
	})
}

func TestClient_CreatePolicy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		if r.URL.Path != "/v1/sys/policies/acl/my-policy" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("X-Vault-Token") != "service-token" {
			t.Errorf("missing or invalid X-Vault-Token header")
		}

		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("failed to decode request body: %v", err)
		}
		if _, ok := payload["policy"]; !ok {
			t.Error("payload should contain 'policy' field")
		}

		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	client, _ := NewClient(&Config{
		Address: server.URL,
		Token:   "service-token",
	})

	policy := `path "transit/encrypt/mykey" { capabilities = ["update"] }`
	err := client.CreatePolicy(context.Background(), "my-policy", policy)
	if err != nil {
		t.Fatalf("CreatePolicy() error = %v", err)
	}
}

func TestClient_TransitEncryptWithToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/transit/encrypt/user-key" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		// Should use the user's token, not service token
		if r.Header.Get("X-Vault-Token") != "user-vault-token" {
			t.Errorf("X-Vault-Token = %q, want user-vault-token", r.Header.Get("X-Vault-Token"))
		}

		response := map[string]interface{}{
			"data": map[string]interface{}{
				"ciphertext": "vault:v1:user-encrypted-data",
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, _ := NewClient(&Config{
		Address: server.URL,
		Token:   "service-token", // Service token should NOT be used
	})

	ciphertext, err := client.TransitEncryptWithToken(context.Background(), "user-vault-token", "user-key", "plaintext")
	if err != nil {
		t.Fatalf("TransitEncryptWithToken() error = %v", err)
	}

	if ciphertext != "vault:v1:user-encrypted-data" {
		t.Errorf("ciphertext = %q, want %q", ciphertext, "vault:v1:user-encrypted-data")
	}
}

func TestClient_TransitDecryptWithToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/transit/decrypt/user-key" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		// Should use the user's token, not service token
		if r.Header.Get("X-Vault-Token") != "user-vault-token" {
			t.Errorf("X-Vault-Token = %q, want user-vault-token", r.Header.Get("X-Vault-Token"))
		}

		response := map[string]interface{}{
			"data": map[string]interface{}{
				"plaintext": "decrypted-user-data",
			},
		}
		json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	client, _ := NewClient(&Config{
		Address: server.URL,
		Token:   "service-token", // Service token should NOT be used
	})

	plaintext, err := client.TransitDecryptWithToken(context.Background(), "user-vault-token", "user-key", "vault:v1:encrypted")
	if err != nil {
		t.Fatalf("TransitDecryptWithToken() error = %v", err)
	}

	if plaintext != "decrypted-user-data" {
		t.Errorf("plaintext = %q, want %q", plaintext, "decrypted-user-data")
	}
}

func TestClient_TransitDecryptWithToken_WrongToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate Vault rejecting wrong token
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"errors": ["permission denied"]}`))
	}))
	defer server.Close()

	client, _ := NewClient(&Config{
		Address: server.URL,
		Token:   "service-token",
	})

	_, err := client.TransitDecryptWithToken(context.Background(), "wrong-user-token", "user-key", "vault:v1:encrypted")
	if err == nil {
		t.Error("TransitDecryptWithToken() should return error for wrong token")
	}
}

func TestClient_ProvisionUser(t *testing.T) {
	callOrder := []string{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		case r.Method == http.MethodPost && path == "/v1/transit/keys/cloistr-user-user123":
			callOrder = append(callOrder, "create_transit_key")
			w.WriteHeader(http.StatusOK)

		case r.Method == http.MethodPut && path == "/v1/sys/policies/acl/cloistr-user-user123":
			callOrder = append(callOrder, "create_policy")
			w.WriteHeader(http.StatusNoContent)

		case r.Method == http.MethodPost && path == "/v1/auth/userpass/users/user123":
			callOrder = append(callOrder, "create_userpass")
			// Verify policies are attached
			var payload map[string]interface{}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Errorf("failed to decode request body: %v", err)
			}
			policies, ok := payload["policies"].([]interface{})
			if !ok || len(policies) == 0 {
				t.Error("userpass account should have policies attached")
			}
			w.WriteHeader(http.StatusNoContent)

		default:
			t.Errorf("unexpected request: %s %s", r.Method, path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	client, _ := NewClient(&Config{
		Address: server.URL,
		Token:   "service-token",
	})

	err := client.ProvisionUser(context.Background(), "user123", "testuser", "password123")
	if err != nil {
		t.Fatalf("ProvisionUser() error = %v", err)
	}

	// Verify call order: transit key → policy → userpass
	expected := []string{"create_transit_key", "create_policy", "create_userpass"}
	if len(callOrder) != len(expected) {
		t.Errorf("call order = %v, want %v", callOrder, expected)
	}
	for i, call := range callOrder {
		if call != expected[i] {
			t.Errorf("call[%d] = %q, want %q", i, call, expected[i])
		}
	}
}

func TestClient_ProvisionUser_TransitKeyError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// All requests fail
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"errors": ["permission denied"]}`))
	}))
	defer server.Close()

	client, _ := NewClient(&Config{
		Address: server.URL,
		Token:   "bad-token",
	})

	err := client.ProvisionUser(context.Background(), "user123", "testuser", "password123")
	if err == nil {
		t.Error("ProvisionUser() should return error when transit key creation fails")
	}
}

func TestUserTransitKeyName(t *testing.T) {
	tests := []struct {
		userID string
		want   string
	}{
		{"user123", "cloistr-user-user123"},
		{"abc-def-ghi", "cloistr-user-abc-def-ghi"},
		{"", "cloistr-user-"},
	}

	for _, tt := range tests {
		t.Run(tt.userID, func(t *testing.T) {
			got := UserTransitKeyName(tt.userID)
			if got != tt.want {
				t.Errorf("UserTransitKeyName(%q) = %q, want %q", tt.userID, got, tt.want)
			}
		})
	}
}

func TestUserPolicyName(t *testing.T) {
	tests := []struct {
		userID string
		want   string
	}{
		{"user123", "cloistr-user-user123"},
		{"abc-def-ghi", "cloistr-user-abc-def-ghi"},
	}

	for _, tt := range tests {
		t.Run(tt.userID, func(t *testing.T) {
			got := UserPolicyName(tt.userID)
			if got != tt.want {
				t.Errorf("UserPolicyName(%q) = %q, want %q", tt.userID, got, tt.want)
			}
		})
	}
}

func TestGenerateUserPolicy(t *testing.T) {
	userID := "user123"
	policy := GenerateUserPolicy(userID)

	// Should contain encrypt and decrypt paths for user's key
	expectedKeyName := "cloistr-user-user123"
	if !contains(policy, "transit/encrypt/"+expectedKeyName) {
		t.Error("policy should contain encrypt path for user's transit key")
	}
	if !contains(policy, "transit/decrypt/"+expectedKeyName) {
		t.Error("policy should contain decrypt path for user's transit key")
	}
	if !contains(policy, `capabilities = ["update"]`) {
		t.Error("policy should have update capability")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestAuthResponse_Fields(t *testing.T) {
	auth := AuthResponse{
		Token:         "token123",
		Accessor:      "accessor456",
		LeaseDuration: 3600,
		Renewable:     true,
		Policies:      []string{"default", "user-policy"},
	}

	if auth.Token != "token123" {
		t.Errorf("Token = %q", auth.Token)
	}
	if auth.Accessor != "accessor456" {
		t.Errorf("Accessor = %q", auth.Accessor)
	}
	if auth.LeaseDuration != 3600 {
		t.Errorf("LeaseDuration = %d", auth.LeaseDuration)
	}
	if !auth.Renewable {
		t.Error("Renewable should be true")
	}
	if len(auth.Policies) != 2 {
		t.Errorf("Policies = %v", auth.Policies)
	}
}
