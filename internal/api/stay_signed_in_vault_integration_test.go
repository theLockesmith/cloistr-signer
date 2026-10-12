package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/seal"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/vault"
)

// Runs the vault sealer against a real dev Vault, with the signer token limited to
// exactly the policy proposed for production (Atlas playbooks/vault-cloistr-signer.yml):
//
//	docker run -d --rm --name vault-dev -p 18200:8200 -e VAULT_DEV_ROOT_TOKEN_ID=dev-root hashicorp/vault
//	VAULT_DEV_ADDR=http://127.0.0.1:18200 VAULT_DEV_ROOT_TOKEN=dev-root go test ./internal/api/ -run VaultIntegration -v

const sessionSealPolicy = `
path "transit/encrypt/cloistr-signer-session-seal" { capabilities = ["update"] }
path "transit/decrypt/cloistr-signer-session-seal" { capabilities = ["update"] }
path "transit/rewrap/cloistr-signer-session-seal" { capabilities = ["update"] }
path "transit/keys/cloistr-signer-session-seal" { capabilities = ["read"] }
path "transit/keys/cloistr-signer-session-seal/rotate" { capabilities = ["update"] }
path "transit/keys/cloistr-signer-session-seal/config" { capabilities = ["update"] }
`

func vaultDo(t *testing.T, addr, token, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, addr+"/v1/"+path, rd)
	req.Header.Set("X-Vault-Token", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestStaySignedIn_VaultIntegration(t *testing.T) {
	addr, root := os.Getenv("VAULT_DEV_ADDR"), os.Getenv("VAULT_DEV_ROOT_TOKEN")
	if addr == "" || root == "" {
		t.Skip("VAULT_DEV_ADDR / VAULT_DEV_ROOT_TOKEN not set")
	}
	// Transit + the key, as the Atlas task creates it.
	vaultDo(t, addr, root, "POST", "sys/mounts/transit", map[string]any{"type": "transit"})
	vaultDo(t, addr, root, "DELETE", "transit/keys/cloistr-signer-session-seal", nil)
	if code, out := vaultDo(t, addr, root, "POST", "transit/keys/cloistr-signer-session-seal", map[string]any{
		"type": "aes256-gcm96", "derived": true, "exportable": false, "allow_plaintext_backup": false, "auto_rotate_period": "720h",
	}); code != 200 && code != 204 {
		t.Fatalf("create key: %d %v", code, out)
	}
	if code, out := vaultDo(t, addr, root, "PUT", "sys/policies/acl/seal-test", map[string]any{"policy": sessionSealPolicy}); code != 204 {
		t.Fatalf("policy: %d %v", code, out)
	}
	code, out := vaultDo(t, addr, root, "POST", "auth/token/create-orphan", map[string]any{"policies": []string{"seal-test"}, "no_default_policy": true, "ttl": "10m"})
	if code != 200 {
		t.Fatalf("mint token: %d %v", code, out)
	}
	tok := out["auth"].(map[string]any)["client_token"].(string)

	vc, err := vault.NewClient(&vault.Config{Address: addr, Token: tok})
	if err != nil {
		t.Fatal(err)
	}
	s, err := seal.NewVault(vc, "")
	if err != nil {
		t.Fatal(err)
	}

	f := newStayFixture(t)
	f.h.SetSealer(s)
	f.h.SetSealRotator(vc)
	resp, rr := f.loginWith(t, f.h, "30d", false)
	if rr.Code != 200 || resp.StaySignedIn == nil || resp.StaySignedIn.Mode != seal.ModeVault {
		t.Fatalf("login: %d %+v", rr.Code, resp.StaySignedIn)
	}
	rows := sealsFor(t, f.store)
	if len(rows) != 1 || !strings.HasPrefix(string(rows[0].Sealed), "vt1:vault:v1:") {
		t.Fatalf("seal rows = %+v", rows)
	}
	backup := bytes.Clone(rows[0].Sealed)
	b := seal.Binding{Pubkey: rows[0].Pubkey, SessionID: rows[0].SessionID}

	// Deploy: a fresh replica restores with only the signer token.
	after := f.replica(t, s)
	after.reconcileSeals(context.Background())
	if priv, ok := after.signer.LoadedPrivateKey(f.key.Pubkey); !ok || priv != f.priv {
		t.Fatal("fresh replica did not restore from Vault")
	}
	// A swapped binding fails inside Vault (derived key + context).
	if _, err := s.Open(context.Background(), backup, seal.Binding{Pubkey: b.Pubkey, SessionID: "other"}); !errors.Is(err, seal.ErrOpen) {
		t.Fatalf("swapped session: %v, want ErrOpen", err)
	}

	// Rotation with the signer token: rotate, rewrap, raise min_decryption_version.
	if code, out := vaultDo(t, addr, tok, "POST", "transit/keys/cloistr-signer-session-seal/rotate", nil); code != 200 && code != 204 {
		t.Fatalf("rotate with signer token: %d %v", code, out)
	}
	if err := f.h.rotateVaultSeals(context.Background()); err != nil {
		t.Fatalf("rotation pass: %v", err)
	}
	latest, minDec, err := vc.TransitKeyVersions(context.Background(), seal.DefaultVaultKey)
	if err != nil || latest != 2 || minDec != 2 {
		t.Fatalf("versions after rotation: latest=%d min=%d err=%v", latest, minDec, err)
	}
	rows = sealsFor(t, f.store)
	if !strings.HasPrefix(string(rows[0].Sealed), "vt1:vault:v2:") {
		t.Fatalf("live seal not rewrapped: %.20s", rows[0].Sealed)
	}
	if _, err := s.Open(context.Background(), backup, b); !errors.Is(err, seal.ErrOpen) {
		t.Fatalf("old backup after rotation: %v, want ErrOpen", err)
	}
	fresh := f.replica(t, s)
	fresh.reconcileSeals(context.Background())
	if !fresh.signer.IsKeyLoaded(f.key.Pubkey) {
		t.Fatal("rewrapped seal did not restore")
	}

	// The token can't touch anything else.
	vaultDo(t, addr, root, "POST", "transit/keys/cloistr-user-x", map[string]any{"type": "aes256-gcm96"})
	if code, _ := vaultDo(t, addr, tok, "POST", "transit/encrypt/cloistr-user-x", map[string]any{"plaintext": "aGk="}); code != 403 {
		t.Fatalf("signer token on another key: %d, want 403", code)
	}
	if code, _ := vaultDo(t, addr, tok, "DELETE", "transit/keys/cloistr-signer-session-seal", nil); code != 403 {
		t.Fatalf("signer token deleting the seal key: %d, want 403", code)
	}
}
