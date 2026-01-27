package vault

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is a HashiCorp Vault client for key storage
type Client struct {
	address    string
	token      string
	mountPath  string
	httpClient *http.Client
}

// Config holds Vault configuration
type Config struct {
	Address   string // Vault address (e.g., http://vault:8200)
	Token     string // Vault token for authentication
	MountPath string // KV secrets engine mount path (default: secret)
}

// NewClient creates a new Vault client
func NewClient(cfg *Config) (*Client, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("vault address is required")
	}

	mountPath := cfg.MountPath
	if mountPath == "" {
		mountPath = "secret"
	}

	return &Client{
		address:   strings.TrimSuffix(cfg.Address, "/"),
		token:     cfg.Token,
		mountPath: mountPath,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// StoreKey stores an encrypted key in Vault
func (c *Client) StoreKey(ctx context.Context, keyID string, data map[string]interface{}) error {
	path := fmt.Sprintf("%s/data/coldforge-signer/keys/%s", c.mountPath, keyID)

	payload := map[string]interface{}{
		"data": data,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.address+"/v1/"+path, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Vault-Token", c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to store key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("vault error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// GetKey retrieves a key from Vault
func (c *Client) GetKey(ctx context.Context, keyID string) (map[string]interface{}, error) {
	path := fmt.Sprintf("%s/data/coldforge-signer/keys/%s", c.mountPath, keyID)

	req, err := http.NewRequestWithContext(ctx, "GET", c.address+"/v1/"+path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("key not found")
	}

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("vault error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	var result struct {
		Data struct {
			Data map[string]interface{} `json:"data"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result.Data.Data, nil
}

// DeleteKey deletes a key from Vault
func (c *Client) DeleteKey(ctx context.Context, keyID string) error {
	path := fmt.Sprintf("%s/metadata/coldforge-signer/keys/%s", c.mountPath, keyID)

	req, err := http.NewRequestWithContext(ctx, "DELETE", c.address+"/v1/"+path, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to delete key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("vault error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// ListKeys lists all key IDs in Vault
func (c *Client) ListKeys(ctx context.Context) ([]string, error) {
	path := fmt.Sprintf("%s/metadata/coldforge-signer/keys", c.mountPath)

	req, err := http.NewRequestWithContext(ctx, "LIST", c.address+"/v1/"+path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return []string{}, nil
	}

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("vault error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	var result struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result.Data.Keys, nil
}

// HealthCheck checks if Vault is accessible
func (c *Client) HealthCheck(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.address+"/v1/sys/health", nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("vault not reachable: %w", err)
	}
	defer resp.Body.Close()

	// 200 = initialized, unsealed, active
	// 429 = standby
	// 472 = disaster recovery standby
	// 473 = performance standby
	// 501 = not initialized
	// 503 = sealed
	if resp.StatusCode != http.StatusOK && resp.StatusCode != 429 &&
		resp.StatusCode != 472 && resp.StatusCode != 473 {
		return fmt.Errorf("vault unhealthy: status %d", resp.StatusCode)
	}

	return nil
}

// TransitEncrypt encrypts data using Vault's transit secrets engine
func (c *Client) TransitEncrypt(ctx context.Context, keyName, plaintext string) (string, error) {
	path := fmt.Sprintf("transit/encrypt/%s", keyName)

	payload := map[string]interface{}{
		"plaintext": plaintext, // Should be base64 encoded
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.address+"/v1/"+path, strings.NewReader(string(body)))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Vault-Token", c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("vault error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	var result struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return result.Data.Ciphertext, nil
}

// TransitDecrypt decrypts data using Vault's transit secrets engine
func (c *Client) TransitDecrypt(ctx context.Context, keyName, ciphertext string) (string, error) {
	path := fmt.Sprintf("transit/decrypt/%s", keyName)

	payload := map[string]interface{}{
		"ciphertext": ciphertext,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.address+"/v1/"+path, strings.NewReader(string(body)))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Vault-Token", c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("vault error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	var result struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return result.Data.Plaintext, nil
}
