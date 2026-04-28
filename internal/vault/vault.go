package vault

import (
	"context"
	"crypto/tls"
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
	Address    string // Vault address (e.g., http://vault:8200)
	Token      string // Vault token for authentication
	MountPath  string // KV secrets engine mount path (default: secret)
	SkipVerify bool   // Skip TLS certificate verification
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

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	if cfg.SkipVerify {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // User explicitly requested TLS skip verify
			},
		}
	}

	return &Client{
		address:    strings.TrimSuffix(cfg.Address, "/"),
		token:      cfg.Token,
		mountPath:  mountPath,
		httpClient: httpClient,
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

// TransitDecryptWithToken decrypts using a specific user's Vault token
func (c *Client) TransitDecryptWithToken(ctx context.Context, token, keyName, ciphertext string) (string, error) {
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

	req.Header.Set("X-Vault-Token", token)
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

// TransitEncryptWithToken encrypts using a specific user's Vault token
func (c *Client) TransitEncryptWithToken(ctx context.Context, token, keyName, plaintext string) (string, error) {
	path := fmt.Sprintf("transit/encrypt/%s", keyName)

	payload := map[string]interface{}{
		"plaintext": plaintext,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.address+"/v1/"+path, strings.NewReader(string(body)))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Vault-Token", token)
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

// CreateTransitKey creates a new transit encryption key for a user
func (c *Client) CreateTransitKey(ctx context.Context, keyName string) error {
	path := fmt.Sprintf("transit/keys/%s", keyName)

	payload := map[string]interface{}{
		"type":       "aes256-gcm96",
		"exportable": false, // Keys cannot be exported - security requirement
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
		return fmt.Errorf("failed to create transit key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("vault error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// CreateUserpassAccount creates a new userpass auth account for a user
func (c *Client) CreateUserpassAccount(ctx context.Context, username, password string, policies []string) error {
	path := fmt.Sprintf("auth/userpass/users/%s", username)

	payload := map[string]interface{}{
		"password":       password,
		"policies":       policies,
		"token_ttl":      "24h",
		"token_max_ttl":  "72h",
		"token_policies": policies,
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
		return fmt.Errorf("failed to create userpass account: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("vault error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// UpdateUserpassPassword updates a user's password in Vault
func (c *Client) UpdateUserpassPassword(ctx context.Context, username, password string) error {
	path := fmt.Sprintf("auth/userpass/users/%s/password", username)

	payload := map[string]interface{}{
		"password": password,
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
		return fmt.Errorf("failed to update password: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("vault error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// AuthenticateUserpass authenticates a user and returns a Vault token
func (c *Client) AuthenticateUserpass(ctx context.Context, username, password string) (*AuthResponse, error) {
	path := fmt.Sprintf("auth/userpass/login/%s", username)

	payload := map[string]interface{}{
		"password": password,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.address+"/v1/"+path, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("authentication failed (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	var result struct {
		Auth struct {
			ClientToken   string   `json:"client_token"`
			Accessor      string   `json:"accessor"`
			Policies      []string `json:"policies"`
			TokenPolicies []string `json:"token_policies"`
			LeaseDuration int      `json:"lease_duration"`
			Renewable     bool     `json:"renewable"`
		} `json:"auth"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &AuthResponse{
		Token:         result.Auth.ClientToken,
		Accessor:      result.Auth.Accessor,
		LeaseDuration: result.Auth.LeaseDuration,
		Renewable:     result.Auth.Renewable,
		Policies:      result.Auth.Policies,
	}, nil
}

// AuthResponse contains authentication response data
type AuthResponse struct {
	Token         string
	Accessor      string
	LeaseDuration int
	Renewable     bool
	Policies      []string
}

// RevokeToken revokes a Vault token
func (c *Client) RevokeToken(ctx context.Context, token string) error {
	path := "auth/token/revoke"

	payload := map[string]interface{}{
		"token": token,
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
		return fmt.Errorf("failed to revoke token: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("vault error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// CreatePolicy creates a Vault policy
func (c *Client) CreatePolicy(ctx context.Context, name, policy string) error {
	path := fmt.Sprintf("sys/policies/acl/%s", name)

	payload := map[string]interface{}{
		"policy": policy,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", c.address+"/v1/"+path, strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Vault-Token", c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create policy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("vault error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// UserTransitKeyName returns the transit key name for a user
func UserTransitKeyName(userID string) string {
	return fmt.Sprintf("cloistr-user-%s", userID)
}

// UserPolicyName returns the policy name for a user
func UserPolicyName(userID string) string {
	return fmt.Sprintf("cloistr-user-%s", userID)
}

// GenerateUserPolicy generates a Vault policy for a user that only allows
// access to their own transit key
func GenerateUserPolicy(userID string) string {
	keyName := UserTransitKeyName(userID)
	return fmt.Sprintf(`
# Policy for user %s
# Allows encrypt/decrypt with their own transit key only

path "transit/encrypt/%s" {
  capabilities = ["update"]
}

path "transit/decrypt/%s" {
  capabilities = ["update"]
}
`, userID, keyName, keyName)
}

// ProvisionUser creates all Vault resources for a new user:
// 1. Transit key for encryption
// 2. Policy restricting access to their key only
// 3. Userpass account with the policy attached
func (c *Client) ProvisionUser(ctx context.Context, userID, username, password string) error {
	// Create transit key
	keyName := UserTransitKeyName(userID)
	if err := c.CreateTransitKey(ctx, keyName); err != nil {
		return fmt.Errorf("failed to create transit key: %w", err)
	}

	// Create policy
	policyName := UserPolicyName(userID)
	policy := GenerateUserPolicy(userID)
	if err := c.CreatePolicy(ctx, policyName, policy); err != nil {
		return fmt.Errorf("failed to create policy: %w", err)
	}

	// Create userpass account with policy
	// Use userID as username to ensure uniqueness
	if err := c.CreateUserpassAccount(ctx, userID, password, []string{policyName}); err != nil {
		return fmt.Errorf("failed to create userpass account: %w", err)
	}

	return nil
}
