package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/metrics"
)

// Derived-key transit calls, made with the signer's own (service) token. Used by
// "stay signed in" session seals (internal/seal): the transit key is created with
// derived=true, so every call carries a base64 derivation context, and a ciphertext
// only decrypts under the context it was made with.

// TransitEncryptDerived encrypts base64 plaintext under a derived transit key.
func (c *Client) TransitEncryptDerived(ctx context.Context, keyName, plaintextB64, contextB64 string) (string, error) {
	var out struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	err := c.transitCall(ctx, "transit_encrypt", http.MethodPost, "transit/encrypt/"+keyName,
		map[string]any{"plaintext": plaintextB64, "context": contextB64}, &out)
	return out.Data.Ciphertext, err
}

// TransitDecryptDerived decrypts a derived-key ciphertext; returns base64 plaintext.
func (c *Client) TransitDecryptDerived(ctx context.Context, keyName, ciphertext, contextB64 string) (string, error) {
	var out struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	err := c.transitCall(ctx, "transit_decrypt", http.MethodPost, "transit/decrypt/"+keyName,
		map[string]any{"ciphertext": ciphertext, "context": contextB64}, &out)
	return out.Data.Plaintext, err
}

// TransitRewrapDerived re-encrypts a derived-key ciphertext under the key's latest
// version, inside Vault (the plaintext is never returned).
func (c *Client) TransitRewrapDerived(ctx context.Context, keyName, ciphertext, contextB64 string) (string, error) {
	var out struct {
		Data struct {
			Ciphertext string `json:"ciphertext"`
		} `json:"data"`
	}
	err := c.transitCall(ctx, "transit_rewrap", http.MethodPost, "transit/rewrap/"+keyName,
		map[string]any{"ciphertext": ciphertext, "context": contextB64}, &out)
	return out.Data.Ciphertext, err
}

// TransitKeyVersions reads a transit key's latest and minimum decryption versions.
func (c *Client) TransitKeyVersions(ctx context.Context, keyName string) (latest, minDecryption int, err error) {
	var out struct {
		Data struct {
			LatestVersion        int `json:"latest_version"`
			MinDecryptionVersion int `json:"min_decryption_version"`
		} `json:"data"`
	}
	err = c.transitCall(ctx, "transit_read_key", http.MethodGet, "transit/keys/"+keyName, nil, &out)
	return out.Data.LatestVersion, out.Data.MinDecryptionVersion, err
}

// TransitSetMinDecryptionVersion stops the key decrypting (or rewrapping) any
// ciphertext older than version v. Irreversible in effect for those ciphertexts
// unless the setting is lowered again.
func (c *Client) TransitSetMinDecryptionVersion(ctx context.Context, keyName string, v int) error {
	return c.transitCall(ctx, "transit_key_config", http.MethodPost, "transit/keys/"+keyName+"/config",
		map[string]any{"min_decryption_version": v}, nil)
}

// transitCall sends one request with the service token. Non-2xx answers become an
// error of the form "vault error (status N): body", like the other transit helpers.
func (c *Client) transitCall(ctx context.Context, op, method, path string, payload any, out any) error {
	start := time.Now()
	defer func() { metrics.RecordVaultLatency(op, time.Since(start)) }()

	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("failed to marshal payload: %w", err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.address+"/v1/"+path, body)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("vault error (status %d): %s", resp.StatusCode, string(b))
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("failed to decode response: %w", err)
	}
	return nil
}
