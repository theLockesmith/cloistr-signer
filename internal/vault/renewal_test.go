package vault

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRenewalWait(t *testing.T) {
	cases := []struct {
		name   string
		lease  time.Duration
		jitter float64 // in [-1, 1]
		want   time.Duration
	}{
		{"half the lease", 2 * time.Hour, 0, time.Hour},
		{"jitter shortens by up to 10%", 2 * time.Hour, -1, 54 * time.Minute},
		{"jitter lengthens by up to 10%", 2 * time.Hour, 1, 66 * time.Minute},
		{"capped at 12h", 768 * time.Hour, 0, 12 * time.Hour},
		{"cap holds with jitter", 768 * time.Hour, 1, 12 * time.Hour},
		{"short lease goes below a minute", 40 * time.Second, 0, 20 * time.Second},
		{"short lease halves", 4 * time.Second, 0, 2 * time.Second},
		{"floored at 1s", time.Second, 0, time.Second},
		{"zero lease floored", 0, 0, time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := renewalWait(tc.lease, tc.jitter); got != tc.want {
				t.Fatalf("renewalWait(%v, %v) = %v, want %v", tc.lease, tc.jitter, got, tc.want)
			}
		})
	}
}

func renewServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/token/renew-self":
			w.WriteHeader(status)
			_, _ = w.Write([]byte(body))
		case "/v1/auth/token/lookup-self":
			if status == http.StatusForbidden {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"errors":["permission denied"]}`))
				return
			}
			_, _ = w.Write([]byte(`{"data":{"ttl":7200}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestClient(t *testing.T, addr string) *Client {
	t.Helper()
	c, err := NewClient(&Config{Address: addr, Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestTokenStatus_UnknownBeforeFirstRenewal(t *testing.T) {
	c := newTestClient(t, "http://127.0.0.1:1")
	if st := c.TokenStatus(); st.Known || st.Invalid {
		t.Fatalf("status before any renewal = %+v, want unknown and not invalid", st)
	}
}

func TestRenewOnce_TracksExpiry(t *testing.T) {
	srv := renewServer(t, http.StatusOK, `{"auth":{"lease_duration":3600}}`)
	c := newTestClient(t, srv.URL)

	lease := c.renewOnce(context.Background())
	if lease != time.Hour {
		t.Fatalf("lease = %v, want 1h", lease)
	}
	st := c.TokenStatus()
	if !st.Known || st.Invalid {
		t.Fatalf("status = %+v, want known and valid", st)
	}
	if st.TTL < 59*time.Minute || st.TTL > time.Hour {
		t.Fatalf("ttl = %v, want about 1h", st.TTL)
	}
}

// A failed renewal must not reset the tracked expiry; it falls back to
// lookup-self so the TTL keeps reflecting the real token.
func TestRenewOnce_FailureFallsBackToLookup(t *testing.T) {
	srv := renewServer(t, http.StatusInternalServerError, `{"errors":["boom"]}`)
	c := newTestClient(t, srv.URL)

	c.renewOnce(context.Background())
	st := c.TokenStatus()
	if !st.Known || st.Invalid {
		t.Fatalf("status = %+v, want known (from lookup-self) and valid", st)
	}
	if st.TTL < 119*time.Minute || st.TTL > 2*time.Hour {
		t.Fatalf("ttl = %v, want about 2h from lookup-self", st.TTL)
	}
}

func TestRenewOnce_ForbiddenMarksInvalid(t *testing.T) {
	srv := renewServer(t, http.StatusForbidden, `{"errors":["permission denied"]}`)
	c := newTestClient(t, srv.URL)

	c.renewOnce(context.Background())
	if st := c.TokenStatus(); !st.Invalid {
		t.Fatalf("status = %+v, want invalid after a 403", st)
	}
}

func TestTokenStatus_ExpiredIsInvalid(t *testing.T) {
	c := newTestClient(t, "http://127.0.0.1:1")
	c.setTokenExpiry(time.Now().Add(-time.Second))
	if st := c.TokenStatus(); !st.Invalid || st.TTL > 0 {
		t.Fatalf("status = %+v, want invalid with ttl <= 0", st)
	}
}

func TestRenewOnce_RecoveryClearsInvalid(t *testing.T) {
	c := newTestClient(t, "http://127.0.0.1:1")
	c.markTokenInvalid()
	srv := renewServer(t, http.StatusOK, `{"auth":{"lease_duration":3600}}`)
	c.address = srv.URL
	c.renewOnce(context.Background())
	if st := c.TokenStatus(); st.Invalid {
		t.Fatalf("status = %+v, want valid after a successful renewal", st)
	}
}

func TestRenewOnce_ZeroLeaseLeavesExpiryUnknown(t *testing.T) {
	srv := renewServer(t, http.StatusOK, `{"auth":{"lease_duration":0}}`)
	c := newTestClient(t, srv.URL)
	if lease := c.renewOnce(context.Background()); lease < time.Hour {
		t.Fatalf("lease = %v, want a long re-check for a token with no expiry", lease)
	}
	if st := c.TokenStatus(); st.Known || st.Invalid {
		t.Fatalf("status = %+v, want unknown and valid for a token with no expiry", st)
	}
}
