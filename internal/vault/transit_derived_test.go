package vault

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// derivedServer records the last request and answers like Vault's transit engine.
func derivedServer(t *testing.T, status int, reply string) (*Client, *map[string]any, *string) {
	t.Helper()
	var body map[string]any
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.Method + " " + r.URL.Path
		if r.Header.Get("X-Vault-Token") != "svc-token" {
			t.Errorf("request used token %q, want the service token", r.Header.Get("X-Vault-Token"))
		}
		body = nil
		if r.Body != nil {
			_ = json.NewDecoder(r.Body).Decode(&body)
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(reply))
	}))
	t.Cleanup(srv.Close)
	c, err := NewClient(&Config{Address: srv.URL, Token: "svc-token"})
	if err != nil {
		t.Fatal(err)
	}
	return c, &body, &path
}

func TestTransitEncryptDerivedSendsContext(t *testing.T) {
	c, body, path := derivedServer(t, 200, `{"data":{"ciphertext":"vault:v3:abc"}}`)
	ct, err := c.TransitEncryptDerived(context.Background(), "seal-key", "cHQ=", "Y3R4")
	if err != nil {
		t.Fatal(err)
	}
	if ct != "vault:v3:abc" {
		t.Fatalf("ciphertext = %q", ct)
	}
	if *path != "POST /v1/transit/encrypt/seal-key" {
		t.Fatalf("path = %q", *path)
	}
	if (*body)["plaintext"] != "cHQ=" || (*body)["context"] != "Y3R4" {
		t.Fatalf("body = %v, want plaintext and context", *body)
	}
}

func TestTransitDecryptDerivedSendsContext(t *testing.T) {
	c, body, path := derivedServer(t, 200, `{"data":{"plaintext":"cHQ="}}`)
	pt, err := c.TransitDecryptDerived(context.Background(), "seal-key", "vault:v3:abc", "Y3R4")
	if err != nil || pt != "cHQ=" {
		t.Fatalf("pt=%q err=%v", pt, err)
	}
	if *path != "POST /v1/transit/decrypt/seal-key" || (*body)["context"] != "Y3R4" || (*body)["ciphertext"] != "vault:v3:abc" {
		t.Fatalf("path=%q body=%v", *path, *body)
	}
}

func TestTransitDecryptDerivedErrorCarriesStatus(t *testing.T) {
	c, _, _ := derivedServer(t, 400, `{"errors":["cipher: message authentication failed"]}`)
	_, err := c.TransitDecryptDerived(context.Background(), "k", "vault:v1:x", "Y3R4")
	if err == nil || !strings.Contains(err.Error(), "status 400") {
		t.Fatalf("err = %v, want one naming status 400", err)
	}
}

func TestTransitRewrapDerived(t *testing.T) {
	c, body, path := derivedServer(t, 200, `{"data":{"ciphertext":"vault:v4:new"}}`)
	ct, err := c.TransitRewrapDerived(context.Background(), "seal-key", "vault:v3:abc", "Y3R4")
	if err != nil || ct != "vault:v4:new" {
		t.Fatalf("ct=%q err=%v", ct, err)
	}
	if *path != "POST /v1/transit/rewrap/seal-key" || (*body)["context"] != "Y3R4" {
		t.Fatalf("path=%q body=%v", *path, *body)
	}
}

func TestTransitKeyVersions(t *testing.T) {
	c, _, path := derivedServer(t, 200, `{"data":{"latest_version":5,"min_decryption_version":3,"derived":true}}`)
	latest, minDec, err := c.TransitKeyVersions(context.Background(), "seal-key")
	if err != nil || latest != 5 || minDec != 3 {
		t.Fatalf("latest=%d min=%d err=%v", latest, minDec, err)
	}
	if *path != "GET /v1/transit/keys/seal-key" {
		t.Fatalf("path = %q", *path)
	}
}

func TestTransitSetMinDecryptionVersion(t *testing.T) {
	c, body, path := derivedServer(t, 204, ``)
	if err := c.TransitSetMinDecryptionVersion(context.Background(), "seal-key", 5); err != nil {
		t.Fatal(err)
	}
	if *path != "POST /v1/transit/keys/seal-key/config" || (*body)["min_decryption_version"] != float64(5) {
		t.Fatalf("path=%q body=%v", *path, *body)
	}
}
