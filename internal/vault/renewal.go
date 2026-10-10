package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/metrics"
)

// ErrTokenInvalid means Vault refused the signer's own token (403): it has
// expired, been revoked, or was never valid. Renewal cannot revive it.
var ErrTokenInvalid = errors.New("vault token invalid")

const (
	renewalFloor     = time.Second
	renewalCap       = 12 * time.Hour
	renewalJitter    = 0.1             // +/-10% so replicas sharing a token don't renew in lockstep
	renewalRetryCap  = 5 * time.Minute // after a failure, retry at least this often
	unknownLeaseWait = time.Hour       // no lease known at all: re-check hourly
)

// TokenStatus is what the signer knows about its own Vault token.
type TokenStatus struct {
	Known   bool          // an expiry has been learned from Vault
	TTL     time.Duration // time left; meaningful only when Known
	Invalid bool          // Vault refused the token, or the tracked expiry has passed
}

// TokenStatus reports the tracked state of the signer's own token.
func (c *Client) TokenStatus() TokenStatus {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	st := TokenStatus{Known: !c.tokenExpiry.IsZero(), Invalid: c.tokenInvalid}
	if st.Known {
		st.TTL = time.Until(c.tokenExpiry)
		if st.TTL <= 0 {
			st.Invalid = true
		}
	}
	return st
}

func (c *Client) setTokenExpiry(t time.Time) {
	c.tokenMu.Lock()
	c.tokenExpiry = t
	c.tokenInvalid = false
	c.tokenMu.Unlock()
	metrics.SetVaultTokenExpiry(t)
}

func (c *Client) markTokenInvalid() {
	c.tokenMu.Lock()
	c.tokenInvalid = true
	c.tokenMu.Unlock()
}

// renewalWait is how long to sleep before the next renewal: half the lease,
// jittered by up to +/-10% (jitter in [-1, 1]), then clamped to [1s, 12h].
func renewalWait(lease time.Duration, jitter float64) time.Duration {
	wait := time.Duration(float64(lease/2) * (1 + renewalJitter*jitter))
	if wait < renewalFloor {
		wait = renewalFloor
	}
	if wait > renewalCap {
		wait = renewalCap
	}
	return wait
}

// LookupSelfTTL returns the remaining TTL of the client's own token.
func (c *Client) LookupSelfTTL(ctx context.Context) (time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", c.address+"/v1/auth/token/lookup-self", nil)
	if err != nil {
		return 0, fmt.Errorf("failed to create lookup request: %w", err)
	}
	req.Header.Set("X-Vault-Token", c.token)

	resp, err := c.do(req)
	if err != nil {
		return 0, fmt.Errorf("token lookup request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == http.StatusForbidden {
			return 0, fmt.Errorf("%w (status %d): %s", ErrTokenInvalid, resp.StatusCode, string(bodyBytes))
		}
		return 0, fmt.Errorf("vault lookup error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	var result struct {
		Data struct {
			TTL int `json:"ttl"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, fmt.Errorf("failed to decode lookup response: %w", err)
	}
	return time.Duration(result.Data.TTL) * time.Second, nil
}

// renewOnce renews the token, updates the tracked expiry, and returns the
// lease to schedule the next renewal from. On failure it falls back to
// lookup-self so the tracked TTL stays truthful, and returns a lease that
// brings the retry forward.
func (c *Client) renewOnce(ctx context.Context) time.Duration {
	secs, err := c.RenewSelf(ctx)
	if err == nil && secs == 0 {
		// Vault reports no lease (e.g. a root token): nothing to expire.
		slog.Info("vault token renewed; token has no expiry")
		return 2 * unknownLeaseWait
	}
	if err == nil {
		lease := time.Duration(secs) * time.Second
		expiry := time.Now().Add(lease)
		c.setTokenExpiry(expiry)
		slog.Info("vault token renewed", "lease_seconds", secs, "expires_at", expiry.UTC().Format(time.RFC3339))
		return lease
	}

	if errors.Is(err, ErrTokenInvalid) {
		c.markTokenInvalid()
		slog.Error("vault token renewal refused: token expired, revoked or invalid", "error", err)
		return 2 * renewalRetryCap
	}

	slog.Error("vault token renewal failed", "error", err)
	ttl, lerr := c.LookupSelfTTL(ctx)
	switch {
	case lerr == nil:
		c.setTokenExpiry(time.Now().Add(ttl))
		slog.Warn("vault token not renewed; current ttl from lookup", "ttl_seconds", int(ttl.Seconds()))
		if ttl > 2*renewalRetryCap {
			return 2 * renewalRetryCap
		}
		return ttl
	case errors.Is(lerr, ErrTokenInvalid):
		c.markTokenInvalid()
	default:
		slog.Warn("vault token lookup failed", "error", lerr)
	}
	if st := c.TokenStatus(); st.Known && st.TTL > 0 && st.TTL < 2*renewalRetryCap {
		return st.TTL
	}
	return 2 * renewalRetryCap
}

// StartTokenRenewal keeps the signer's Vault token alive for the life of the
// process and keeps its expiry visible (TokenStatus, the
// coldforge_signer_vault_token_ttl_seconds gauge, an info log per renewal).
// Intended to run in a goroutine; returns when ctx is cancelled.
func (c *Client) StartTokenRenewal(ctx context.Context) {
	lease := c.renewOnce(ctx)
	if !c.TokenStatus().Known {
		lease = 2 * unknownLeaseWait
	}
	slog.Info("vault token auto-renewal started", "lease_seconds", int(lease.Seconds()))

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(renewalWait(lease, rand.Float64()*2-1)):
		}
		lease = c.renewOnce(ctx)
	}
}
