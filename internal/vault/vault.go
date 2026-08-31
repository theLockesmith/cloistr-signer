package vault

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/textproto"
	"os"
	"strings"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/metrics"
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
	Address    string        // Vault address (e.g., http://vault:8200)
	Token      string        // Vault token for authentication
	MountPath  string        // KV secrets engine mount path (default: secret)
	SkipVerify bool          // Skip TLS certificate verification
	Timeout    time.Duration // Per-request timeout; default 5s. Fail fast so a Vault outage can't hang login/register into a browser NetworkError.
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

	// Fail fast: a Vault outage must NOT hang login/register (each does 1-2 Vault
	// calls; a 30s timeout × multiple calls stacked into >50s hangs → browser
	// NetworkError). Bound connect, TLS handshake, AND total request time so an
	// unreachable-but-healthy Vault surfaces as a prompt error, not a hang.
	// Total per-request budget must accommodate a slow-but-healthy Vault userpass
	// auth (server-side bcrypt, ~5s). A 5s cap sat right on that latency and got
	// tripped intermittently, and do()'s retry then DOUBLED it → 10s+ logins and
	// gateway 502s. Give the whole request 12s. Connect + TLS handshake stay short
	// so an UNREACHABLE Vault still fails fast (a few seconds), not a 12s hang.
	reqTimeout := cfg.Timeout
	if reqTimeout <= 0 {
		reqTimeout = 12 * time.Second
	}
	connectTimeout := 3 * time.Second
	if reqTimeout < connectTimeout {
		connectTimeout = reqTimeout
	}

	transport := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: connectTimeout}).DialContext,
		TLSHandshakeTimeout: connectTimeout,
		// Force HTTP/1.1 on the Vault client. httptrace evidence 2026-07-11
		// showed every POST /v1/auth/userpass/login/* wrote the request in
		// ~15ms and then hung 5s to context deadline with first_byte_at_ms=0,
		// while wget (HTTP/1.1) from the same pod hit the same endpoint in
		// ~200ms. Go's default Transport auto-upgrades to HTTP/2 when the
		// server offers h2 via ALPN; OpenBao's HTTP/2 handler stalls on this
		// path. Passing an empty TLSNextProto map disables that upgrade for
		// THIS transport only (relay/Nostr paths are unaffected).
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	if cfg.SkipVerify {
		transport.TLSClientConfig = &tls.Config{
			InsecureSkipVerify: true, //nolint:gosec // User explicitly requested TLS skip verify
		}
	}

	httpClient := &http.Client{
		Timeout:   reqTimeout,
		Transport: transport,
	}

	return &Client{
		address:    strings.TrimSuffix(cfg.Address, "/"),
		token:      cfg.Token,
		mountPath:  mountPath,
		httpClient: httpClient,
	}, nil
}

// do issues the request and retries ONCE on a timeout. A single transient Vault
// slow moment (OpenBao hiccup) should not fail an interactive login: the fail-fast
// per-request timeout is deliberately short (5s), so without a retry a brief blip
// becomes a user-visible failure (observed 2026-07-09: one login hit a ~30s Vault
// slowness and got context.DeadlineExceeded). All Vault endpoints used here
// (transit encrypt/decrypt, kv, policy, userpass) are idempotent, so re-sending a
// timed-out request is safe. Worst case is 2×timeout; non-timeout errors (4xx/5xx,
// connection refused) are returned immediately without a retry.
func (c *Client) do(req *http.Request) (*http.Response, error) {
	req, timings := maybeTraceRequest(req)
	resp, err := c.httpClient.Do(req)
	timings.log(req, err)
	if err == nil || !isTimeout(err) {
		return resp, err
	}
	slog.Warn("vault request timed out, retrying once", "method", req.Method, "path", req.URL.Path)
	retry := req.Clone(req.Context())
	if req.GetBody != nil {
		if body, berr := req.GetBody(); berr == nil {
			retry.Body = body
		}
	}
	retry, retryTimings := maybeTraceRequest(retry)
	resp, err = c.httpClient.Do(retry)
	retryTimings.log(retry, err)
	return resp, err
}

// vaultHttpTrace is toggled by env VAULT_HTTPTRACE=1. When on, do() attaches an
// httptrace.ClientTrace to every Vault request and logs per-phase durations
// (DNS, dial, TLS handshake, wrote-request, first-response-byte). Diagnostic
// tool for the 2026-07-10 "5s Go client timeout while wget sees 200ms" issue.
// Off by default because it fires on every Vault call and would spam logs.
var vaultHttpTrace = os.Getenv("VAULT_HTTPTRACE") == "1"

// phaseTimings records monotonic timestamps for the httptrace phases. nil when
// tracing is disabled — the log() method is nil-safe so hot paths pay nothing.
type phaseTimings struct {
	start           time.Time
	dnsStart        time.Time
	dnsDone         time.Time
	connectStart    time.Time
	connectDone     time.Time
	tlsStart        time.Time
	tlsDone         time.Time
	wroteHeaders    time.Time
	wroteRequest    time.Time
	got1xxResponse  time.Time
	got1xxCode      int
	wait100Continue time.Time
	firstByte       time.Time
	connReused      bool
	connWasIdle     bool
	remoteAddr      string
}

// maybeTraceRequest returns the request unchanged (and a nil timings) when
// VAULT_HTTPTRACE isn't set; otherwise it clones the request onto a context
// carrying an httptrace.ClientTrace that fills a fresh phaseTimings.
func maybeTraceRequest(req *http.Request) (*http.Request, *phaseTimings) {
	if !vaultHttpTrace {
		return req, nil
	}
	t := &phaseTimings{start: time.Now()}
	trace := &httptrace.ClientTrace{
		DNSStart:          func(httptrace.DNSStartInfo) { t.dnsStart = time.Now() },
		DNSDone:           func(httptrace.DNSDoneInfo) { t.dnsDone = time.Now() },
		ConnectStart:      func(string, string) { t.connectStart = time.Now() },
		ConnectDone:       func(string, string, error) { t.connectDone = time.Now() },
		TLSHandshakeStart: func() { t.tlsStart = time.Now() },
		TLSHandshakeDone:  func(tls.ConnectionState, error) { t.tlsDone = time.Now() },
		WroteHeaders:      func() { t.wroteHeaders = time.Now() },
		Wait100Continue:   func() { t.wait100Continue = time.Now() },
		Got1xxResponse: func(code int, _ textproto.MIMEHeader) error {
			t.got1xxResponse = time.Now()
			t.got1xxCode = code
			return nil
		},
		WroteRequest:         func(httptrace.WroteRequestInfo) { t.wroteRequest = time.Now() },
		GotFirstResponseByte: func() { t.firstByte = time.Now() },
		GotConn: func(info httptrace.GotConnInfo) {
			t.connReused = info.Reused
			t.connWasIdle = info.WasIdle
			if info.Conn != nil {
				t.remoteAddr = info.Conn.RemoteAddr().String()
			}
		},
	}
	return req.WithContext(httptrace.WithClientTrace(req.Context(), trace)), t
}

// log emits one INFO line summarizing the per-phase durations. Any phase that
// didn't fire (e.g. TLS on a reused conn) reports 0 so operators see which
// phases were skipped.
func (t *phaseTimings) log(req *http.Request, reqErr error) {
	if t == nil {
		return
	}
	dur := func(a, b time.Time) time.Duration {
		if a.IsZero() || b.IsZero() {
			return 0
		}
		return b.Sub(a)
	}
	total := time.Since(t.start)
	slog.Info("vault httptrace",
		"method", req.Method,
		"path", req.URL.Path,
		"remote", t.remoteAddr,
		"conn_reused", t.connReused,
		"conn_was_idle", t.connWasIdle,
		"dns_ms", dur(t.dnsStart, t.dnsDone).Milliseconds(),
		"dial_ms", dur(t.connectStart, t.connectDone).Milliseconds(),
		"tls_ms", dur(t.tlsStart, t.tlsDone).Milliseconds(),
		"wrote_headers_at_ms", dur(t.start, t.wroteHeaders).Milliseconds(),
		"wait_100_at_ms", dur(t.start, t.wait100Continue).Milliseconds(),
		"got_1xx_at_ms", dur(t.start, t.got1xxResponse).Milliseconds(),
		"got_1xx_code", t.got1xxCode,
		"wrote_request_at_ms", dur(t.start, t.wroteRequest).Milliseconds(),
		"first_byte_at_ms", dur(t.start, t.firstByte).Milliseconds(),
		"total_ms", total.Milliseconds(),
		"err", reqErr,
	)
}

// isTimeout reports whether err is a request timeout (context deadline or a
// net.Error timeout), i.e. safe-to-retry transient slowness.
func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// IsTimeout reports whether err (possibly wrapped) is a request timeout, i.e.
// transient Vault slowness that is safe to retry rather than a genuine auth
// failure. Exported so callers can distinguish "Vault was slow" from "the user
// doesn't exist / bad credentials" and avoid reprovisioning on a mere timeout.
func IsTimeout(err error) bool {
	return isTimeout(err)
}

// StoreKey stores an encrypted key in Vault
func (c *Client) StoreKey(ctx context.Context, keyID string, data map[string]interface{}) error {
	start := time.Now()
	defer func() {
		metrics.RecordVaultLatency("store_key", time.Since(start))
	}()

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

	resp, err := c.do(req)
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
	start := time.Now()
	defer func() {
		metrics.RecordVaultLatency("get_key", time.Since(start))
	}()

	path := fmt.Sprintf("%s/data/coldforge-signer/keys/%s", c.mountPath, keyID)

	req, err := http.NewRequestWithContext(ctx, "GET", c.address+"/v1/"+path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.do(req)
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
	start := time.Now()
	defer func() {
		metrics.RecordVaultLatency("delete_key", time.Since(start))
	}()

	path := fmt.Sprintf("%s/metadata/coldforge-signer/keys/%s", c.mountPath, keyID)

	req, err := http.NewRequestWithContext(ctx, "DELETE", c.address+"/v1/"+path, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.do(req)
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
	start := time.Now()
	defer func() {
		metrics.RecordVaultLatency("list_keys", time.Since(start))
	}()

	path := fmt.Sprintf("%s/metadata/coldforge-signer/keys", c.mountPath)

	req, err := http.NewRequestWithContext(ctx, "LIST", c.address+"/v1/"+path, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.do(req)
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

	resp, err := c.do(req)
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
	start := time.Now()
	defer func() {
		metrics.RecordVaultLatency("transit_encrypt", time.Since(start))
	}()

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

	resp, err := c.do(req)
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
	start := time.Now()
	defer func() {
		metrics.RecordVaultLatency("transit_decrypt", time.Since(start))
	}()

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

	resp, err := c.do(req)
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
	start := time.Now()
	defer func() {
		metrics.RecordVaultLatency("transit_decrypt", time.Since(start))
	}()

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

	resp, err := c.do(req)
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
	start := time.Now()
	defer func() {
		metrics.RecordVaultLatency("transit_encrypt", time.Since(start))
	}()

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

	resp, err := c.do(req)
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

// TransitRotateKey rotates a transit key, creating a new version. Existing
// ciphertext continues to decrypt with its embedded version; subsequent
// encrypts use the new version. Pair with TransitRewrap (or
// TransitRewrapWithToken) to bring existing ciphertext forward without
// exposing plaintext to the caller.
//
// Uses the admin token (c.token). Requires update capability on
// `transit/keys/{name}/rotate`.
func (c *Client) TransitRotateKey(ctx context.Context, keyName string) error {
	start := time.Now()
	defer func() {
		metrics.RecordVaultLatency("transit_rotate", time.Since(start))
	}()

	path := fmt.Sprintf("transit/keys/%s/rotate", keyName)

	req, err := http.NewRequestWithContext(ctx, "POST", c.address+"/v1/"+path, nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.do(req)
	if err != nil {
		return fmt.Errorf("failed to rotate transit key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("vault error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	return nil
}

// TransitRewrap re-encrypts ciphertext using the current version of the
// transit key. Used after TransitRotateKey to migrate ciphertext to the
// new key version. Plaintext is never exposed to the caller (the operation
// happens entirely inside Vault).
//
// Uses the admin token (c.token). Requires update capability on
// `transit/rewrap/{name}`.
func (c *Client) TransitRewrap(ctx context.Context, keyName, ciphertext string) (string, error) {
	return c.TransitRewrapWithToken(ctx, c.token, keyName, ciphertext)
}

// TransitRewrapWithToken re-encrypts ciphertext using the supplied token's
// access to the transit key. Lets a user rewrap their own ciphertext using
// their user token, without ever exposing plaintext.
func (c *Client) TransitRewrapWithToken(ctx context.Context, token, keyName, ciphertext string) (string, error) {
	start := time.Now()
	defer func() {
		metrics.RecordVaultLatency("transit_rewrap", time.Since(start))
	}()

	path := fmt.Sprintf("transit/rewrap/%s", keyName)

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

	resp, err := c.do(req)
	if err != nil {
		return "", fmt.Errorf("failed to rewrap: %w", err)
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

	resp, err := c.do(req)
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

// userpassTokenPeriod makes tokens minted by this role PERIODIC. A periodic
// token has no max TTL: it lives forever as long as something renews it inside
// each period, which is what StartUserTokenRenewal does.
//
// The previous role used token_max_ttl 72h, which Vault enforces as a hard
// ceiling regardless of renewal. User SESSIONS run for JWT_EXPIRY hours (720 =
// 30 days in production), so the Vault token died roughly ten times over
// inside a single session, and nothing could re-mint it: populateVaultTokenAsync
// needs the PASSWORD, and the only caller that has one is the login handler.
// The user stayed signed in on a valid cookie while every key decrypt 403'd —
// observed as "startup vault restore complete users_restored=0" with 8 users.
const userpassTokenPeriod = "24h"

// CreateUserpassAccount creates a new userpass auth account for a user
func (c *Client) CreateUserpassAccount(ctx context.Context, username, password string, policies []string) error {
	path := fmt.Sprintf("auth/userpass/users/%s", username)

	payload := map[string]interface{}{
		"password":       password,
		"policies":       policies,
		"token_ttl":      userpassTokenPeriod,
		"token_period":   userpassTokenPeriod,
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

	resp, err := c.do(req)
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

// EnsureUserpassPeriodic migrates an EXISTING userpass role to periodic tokens.
// Roles created before userpassTokenPeriod carry token_max_ttl 72h, a hard
// ceiling Vault applies no matter how often a token is renewed, so renewal
// alone cannot keep those users' tokens alive for a 30-day session.
//
// It reads the current role first and writes every field back, because Vault's
// userpass write is a full replace of the token_* tunables — a partial write
// would silently reset the user's policies and lock them out of their own
// transit key. The password is NOT sent: Vault's userpass handler only rehashes
// a password when the field is present, so omitting it leaves the credential
// untouched.
//
// Returns true when the role was actually changed. Note this only affects
// tokens minted from now on; a token already issued keeps the ceiling it was
// born with, so existing users still need one more login to get a periodic one.
func (c *Client) EnsureUserpassPeriodic(ctx context.Context, username string) (bool, error) {
	path := fmt.Sprintf("auth/userpass/users/%s", username)

	req, err := http.NewRequestWithContext(ctx, "GET", c.address+"/v1/"+path, nil)
	if err != nil {
		return false, fmt.Errorf("failed to create read request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.do(req)
	if err != nil {
		return false, fmt.Errorf("failed to read userpass account: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// No role yet — nothing to migrate. The user provisions on next login.
		return false, nil
	}
	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return false, fmt.Errorf("vault error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	var read struct {
		Data struct {
			TokenPolicies []string `json:"token_policies"`
			Policies      []string `json:"policies"`
			TokenPeriod   int      `json:"token_period"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&read); err != nil {
		return false, fmt.Errorf("failed to decode userpass account: %w", err)
	}

	if read.Data.TokenPeriod > 0 {
		return false, nil // already periodic
	}

	policies := read.Data.TokenPolicies
	if len(policies) == 0 {
		policies = read.Data.Policies
	}
	if len(policies) == 0 {
		// Writing back an empty policy set would strip the user's access to
		// their own transit key. Refuse rather than break them.
		return false, fmt.Errorf("userpass role %q has no policies; refusing to rewrite", username)
	}

	payload := map[string]interface{}{
		"policies":       policies,
		"token_policies": policies,
		"token_ttl":      userpassTokenPeriod,
		"token_period":   userpassTokenPeriod,
		"token_max_ttl":  0, // clear the 72h ceiling; the period supersedes it
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("failed to marshal payload: %w", err)
	}

	wreq, err := http.NewRequestWithContext(ctx, "POST", c.address+"/v1/"+path, strings.NewReader(string(body)))
	if err != nil {
		return false, fmt.Errorf("failed to create write request: %w", err)
	}
	wreq.Header.Set("X-Vault-Token", c.token)
	wreq.Header.Set("Content-Type", "application/json")

	wresp, err := c.do(wreq)
	if err != nil {
		return false, fmt.Errorf("failed to update userpass account: %w", err)
	}
	defer wresp.Body.Close()

	if wresp.StatusCode != http.StatusOK && wresp.StatusCode != http.StatusNoContent {
		bodyBytes, _ := io.ReadAll(wresp.Body)
		return false, fmt.Errorf("vault error (status %d): %s", wresp.StatusCode, string(bodyBytes))
	}

	return true, nil
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

	resp, err := c.do(req)
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

	resp, err := c.do(req)
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

	resp, err := c.do(req)
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

	resp, err := c.do(req)
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
# Allows encrypt/decrypt/rewrap with their own transit key only.
# Rewrap lets the user refresh their own ciphertext to the latest key
# version after an admin-driven rotation, without ever exposing plaintext.

path "transit/encrypt/%s" {
  capabilities = ["update"]
}

path "transit/decrypt/%s" {
  capabilities = ["update"]
}

path "transit/rewrap/%s" {
  capabilities = ["update"]
}
`, userID, keyName, keyName, keyName)
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

// RenewSelf renews the client's own Vault token and returns the new lease
// duration in seconds. The signer's service token has a finite lease; without
// renewal it expires and every transit-key operation 403s ("invalid token"),
// silently breaking per-user key provisioning.
func (c *Client) RenewSelf(ctx context.Context) (int, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", c.address+"/v1/auth/token/renew-self", strings.NewReader("{}"))
	if err != nil {
		return 0, fmt.Errorf("failed to create renew request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.do(req)
	if err != nil {
		return 0, fmt.Errorf("token renew request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("vault renew error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	var result struct {
		Auth struct {
			LeaseDuration int `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("failed to decode renew response: %w", err)
	}
	return result.Auth.LeaseDuration, nil
}

// RenewToken renews an arbitrary Vault token (a per-user token held on a
// session) rather than the signer's own, and returns the new lease duration in
// seconds. renew-self acts on whatever token authenticates the request, so this
// is RenewSelf with a caller-supplied token.
//
// A token that has already lapsed cannot be revived — Vault answers 403 and the
// caller must treat that session's Vault access as gone.
func (c *Client) RenewToken(ctx context.Context, token string) (int, error) {
	if token == "" {
		return 0, fmt.Errorf("empty token")
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.address+"/v1/auth/token/renew-self", strings.NewReader("{}"))
	if err != nil {
		return 0, fmt.Errorf("failed to create renew request: %w", err)
	}
	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.do(req)
	if err != nil {
		return 0, fmt.Errorf("token renew request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return 0, fmt.Errorf("vault renew error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	var result struct {
		Auth struct {
			LeaseDuration int `json:"lease_duration"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("failed to decode renew response: %w", err)
	}
	return result.Auth.LeaseDuration, nil
}

// StartTokenRenewal keeps the signer's Vault token alive for the life of the
// process. It renews at roughly half the lease each cycle (floored at 1m,
// capped at 12h) so a periodic token never lapses. Intended to run in a
// goroutine; returns when ctx is cancelled. This is the fix for the token
// silently expiring at its TTL and 403-ing all key operations.
func (c *Client) StartTokenRenewal(ctx context.Context) {
	// Initial renew confirms the token is valid + reveals the lease duration.
	lease, err := c.RenewSelf(ctx)
	if err != nil {
		// A root/non-renewable/already-dead token can't be renewed. Log loudly
		// and fall back to a conservative interval so we keep re-checking
		// (e.g. after an operator re-mints) without spinning hot.
		slog.Warn("initial vault token renewal failed — token may be expired, root, or non-renewable", "error", err)
		lease = 3600
	} else {
		slog.Info("vault token auto-renewal started", "lease_seconds", lease)
	}

	for {
		wait := time.Duration(lease/2) * time.Second
		if wait < time.Minute {
			wait = time.Minute
		}
		if wait > 12*time.Hour {
			wait = 12 * time.Hour
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}

		newLease, err := c.RenewSelf(ctx)
		if err != nil {
			slog.Error("vault token renewal failed", "error", err)
			lease = 300 // retry sooner on failure
			continue
		}
		lease = newLease
		slog.Debug("vault token renewed", "lease_seconds", lease)
	}
}
