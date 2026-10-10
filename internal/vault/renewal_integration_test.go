package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// Runs against a real dev Vault with short-TTL tokens (card #288):
//
//	docker run -d --rm --name vault-dev -p 18200:8200 -e VAULT_DEV_ROOT_TOKEN_ID=dev-root hashicorp/vault
//	VAULT_DEV_ADDR=http://127.0.0.1:18200 VAULT_DEV_ROOT_TOKEN=dev-root go test ./internal/vault/ -run Integration -v
func devVault(t *testing.T) (addr, root string) {
	addr, root = os.Getenv("VAULT_DEV_ADDR"), os.Getenv("VAULT_DEV_ROOT_TOKEN")
	if addr == "" || root == "" {
		t.Skip("VAULT_DEV_ADDR / VAULT_DEV_ROOT_TOKEN not set")
	}
	return addr, root
}

func mintToken(t *testing.T, addr, root, body string) string {
	t.Helper()
	req, _ := http.NewRequest("POST", addr+"/v1/auth/token/create-orphan", strings.NewReader(body))
	req.Header.Set("X-Vault-Token", root)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Auth struct {
			ClientToken string `json:"client_token"`
		} `json:"auth"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.Auth.ClientToken == "" {
		t.Fatalf("mint token: status %d, err %v", resp.StatusCode, err)
	}
	return out.Auth.ClientToken
}

// A periodic token with a 20s period outlives several periods while the
// renewal loop runs; an identical token without the loop dies.
func TestIntegration_ShortPeriodTokenStaysAlive(t *testing.T) {
	addr, root := devVault(t)
	renewed := mintToken(t, addr, root, `{"period":"20s","policies":["default"]}`)
	control := mintToken(t, addr, root, `{"period":"20s","policies":["default"]}`)

	c, err := NewClient(&Config{Address: addr, Token: renewed})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.StartTokenRenewal(ctx)

	time.Sleep(65 * time.Second) // more than three periods

	if _, err := c.LookupSelfTTL(context.Background()); err != nil {
		t.Fatalf("renewed token died: %v", err)
	}
	if st := c.TokenStatus(); !st.Known || st.Invalid || st.TTL <= 0 {
		t.Fatalf("status = %+v, want known, valid, positive ttl", st)
	}
	ctrl, _ := NewClient(&Config{Address: addr, Token: control})
	if _, err := ctrl.LookupSelfTTL(context.Background()); err == nil {
		t.Fatal("control token without renewal is still alive; the test proves nothing")
	}
}

// A token with a hard max TTL cannot be renewed past it; the loop must notice
// and report the token invalid rather than keep claiming it is healthy.
func TestIntegration_MaxTTLTokenReportedInvalid(t *testing.T) {
	addr, root := devVault(t)
	tok := mintToken(t, addr, root, `{"ttl":"10s","explicit_max_ttl":"25s","policies":["default"]}`)

	c, err := NewClient(&Config{Address: addr, Token: tok})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.StartTokenRenewal(ctx)

	start := time.Now()
	for time.Since(start) < 60*time.Second {
		if c.TokenStatus().Invalid {
			// Renewal must have carried it past its 10s TTL; only the 25s max ends it.
			if took := time.Since(start); took < 20*time.Second {
				t.Fatalf("token went invalid after %v, before its max TTL: renewal did not keep it alive", took)
			}
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("token past its max TTL still reported as %+v", c.TokenStatus())
}
