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
