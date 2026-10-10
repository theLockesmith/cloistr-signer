package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/audit"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/auth"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/config"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/crypto"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/signer"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/vault"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/nbd-wtf/go-nostr/nip49"
	"github.com/pquerna/otp/totp"
)

const (
	exportUserID   = "user-export-001"
	exportUsername = "exporter"
	exportPassword = "correct horse battery staple"
)

type exportFixture struct {
	h      *Handler
	store  *storage.MemoryStorage
	logger *audit.MemoryLogger
	priv   string
	key    *storage.Key
	logs   *bytes.Buffer
}

// newExportFixture builds a handler with an audit logger, a user, and one
// passphrase-wrapped key owned by that user. vaultClient may be nil.
func newExportFixture(t *testing.T, vaultClient *vault.Client) *exportFixture {
	t.Helper()
	cfg := &config.Config{
		Relays: []string{"wss://relay.example.com"},
		Auth: config.AuthConfig{
			JWTSecret: "test-secret-key-for-testing-only", JWTExpiry: 24, MFAIssuer: "TestIssuer",
			MaxFailedLogins: 5, LockoutMinutes: 15,
		},
	}
	if vaultClient != nil {
		cfg.Vault.Enabled = true
	}
	store := storage.NewMemoryStorage()
	logger := audit.NewMemoryLogger(100)
	h := NewHandler(cfg, signer.New(cfg, store, nil, nil, nil, nil, logger), store, nil, vaultClient)

	hash, err := auth.HashPassword(exportPassword, 4)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateUser(context.Background(), &storage.User{
		ID: exportUserID, Username: exportUsername, PasswordHash: hash, Role: "user",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}

	priv := nostr.GeneratePrivateKey()
	pub, _ := nostr.GetPublicKey(priv)
	pe, _ := crypto.NewPassphraseEncryptor(exportPassword)
	ct, err := pe.Encrypt(priv)
	if err != nil {
		t.Fatal(err)
	}
	key := &storage.Key{ID: "key-export-001", Name: "main", Pubkey: pub, OwnerID: exportUserID, EncryptedNsec: ct, CreatedAt: time.Now()}
	if err := store.CreateKey(context.Background(), key); err != nil {
		t.Fatal(err)
	}

	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	return &exportFixture{h: h, store: store, logger: logger, priv: priv, key: key, logs: &logs}
}

func (f *exportFixture) export(t *testing.T, keyID string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/"+keyID+"/export", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+makeSessionToken(t, f.h, exportUserID))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	f.h.handleKeyExport(rr, req)
	return rr
}

func validExport(format string) map[string]any {
	b := map[string]any{"password": exportPassword, "confirm": exportUsername, "format": format}
	if format == "ncryptsec" {
		b["export_password"] = "a different export passphrase"
	}
	return b
}

// The key must never reach a log line or an audit record.
func (f *exportFixture) assertNoKeyMaterialLeaked(t *testing.T, exported string) {
	t.Helper()
	nsec, _ := nip19.EncodePrivateKey(f.priv)
	for _, secret := range []string{f.priv, nsec, exported} {
		if secret != "" && strings.Contains(f.logs.String(), secret) {
			t.Fatal("key material appeared in the logs")
		}
	}
	events, _ := f.logger.Query(context.Background(), &audit.Filter{})
	raw, _ := json.Marshal(events)
	for _, secret := range []string{f.priv, nsec, exported} {
		if secret != "" && strings.Contains(string(raw), secret) {
			t.Fatal("key material appeared in an audit record")
		}
	}
}

func (f *exportFixture) exportedEvents(t *testing.T) []*audit.Event {
	t.Helper()
	ev, _ := f.logger.Query(context.Background(), &audit.Filter{Types: []audit.EventType{audit.EventKeyExported}})
	return ev
}

func TestKeyExport_NsecFromPassphraseKey(t *testing.T) {
	f := newExportFixture(t, nil)
	rr := f.export(t, f.key.ID, validExport("nsec"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if cc := rr.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	var resp KeyExportResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	prefix, decoded, err := nip19.Decode(resp.Value)
	if err != nil || prefix != "nsec" || decoded.(string) != f.priv {
		t.Fatalf("exported value does not decode to the key: prefix=%q err=%v", prefix, err)
	}
	if resp.Pubkey != f.key.Pubkey || resp.Format != "nsec" {
		t.Errorf("response = %+v", resp)
	}

	ev := f.exportedEvents(t)
	if len(ev) != 1 || ev[0].Actor != exportUserID || ev[0].Target != f.key.Pubkey || ev[0].Details["format"] != "nsec" {
		t.Fatalf("key.exported audit events = %+v, want one naming the user, key and format", ev)
	}
	f.assertNoKeyMaterialLeaked(t, resp.Value)
}

func TestKeyExport_Ncryptsec(t *testing.T) {
	f := newExportFixture(t, nil)
	rr := f.export(t, f.key.ID, validExport("ncryptsec"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp KeyExportResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if !strings.HasPrefix(resp.Value, "ncryptsec1") {
		t.Fatalf("value %q is not an ncryptsec", resp.Value[:12])
	}
	got, err := nip49.Decrypt(resp.Value, "a different export passphrase")
	if err != nil || got != f.priv {
		t.Fatalf("ncryptsec does not decrypt to the key with the export password: %v", err)
	}
	f.assertNoKeyMaterialLeaked(t, resp.Value)
}

func TestKeyExport_NcryptsecNeedsExportPassword(t *testing.T) {
	f := newExportFixture(t, nil)
	b := validExport("ncryptsec")
	delete(b, "export_password")
	if rr := f.export(t, f.key.ID, b); rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rr.Code)
	}
}

func TestKeyExport_Refusals(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(f *exportFixture, b map[string]any) string // returns key ID
		want   int
	}{
		{"wrong password", func(f *exportFixture, b map[string]any) string { b["password"] = "nope"; return f.key.ID }, http.StatusUnauthorized},
		{"wrong confirmation", func(f *exportFixture, b map[string]any) string { b["confirm"] = "exporterr"; return f.key.ID }, http.StatusBadRequest},
		{"unknown format", func(f *exportFixture, b map[string]any) string { b["format"] = "hex"; return f.key.ID }, http.StatusBadRequest},
		{"someone else's key", func(f *exportFixture, b map[string]any) string {
			other := &storage.Key{ID: "key-other", Pubkey: strings.Repeat("c", 64), OwnerID: "user-other", EncryptedNsec: f.key.EncryptedNsec, CreatedAt: time.Now()}
			_ = f.store.CreateKey(context.Background(), other)
			return other.ID
		}, http.StatusNotFound},
		{"split FROST key has no single secret", func(f *exportFixture, b map[string]any) string {
			split := &storage.Key{ID: "key-frost", Pubkey: strings.Repeat("d", 64), OwnerID: exportUserID, CreatedAt: time.Now()}
			_ = f.store.CreateKey(context.Background(), split)
			return split.ID
		}, http.StatusConflict},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newExportFixture(t, nil)
			b := validExport("nsec")
			id := tc.mutate(f, b)
			rr := f.export(t, id, b)
			if rr.Code != tc.want {
				t.Fatalf("status = %d, want %d: %s", rr.Code, tc.want, rr.Body.String())
			}
			if strings.Contains(rr.Body.String(), "nsec1") {
				t.Fatal("a refused export returned key material")
			}
			if len(f.exportedEvents(t)) != 0 {
				t.Fatal("a refused export left a key.exported record")
			}
		})
	}
}

func TestKeyExport_WrongPasswordCountsAsFailedLogin(t *testing.T) {
	f := newExportFixture(t, nil)
	b := validExport("nsec")
	b["password"] = "nope"
	f.export(t, f.key.ID, b)
	u, _ := f.store.GetUser(context.Background(), exportUserID)
	if u.FailedLoginAttempts != 1 {
		t.Fatalf("failed attempts = %d, want 1", u.FailedLoginAttempts)
	}
}

func TestKeyExport_MFA(t *testing.T) {
	f := newExportFixture(t, nil)
	secret, _, _ := auth.GenerateMFASecret("TestIssuer", exportUsername)
	u, _ := f.store.GetUser(context.Background(), exportUserID)
	u.MFAEnabled, u.MFASecret = true, secret
	_ = f.store.UpdateUser(context.Background(), u)

	if rr := f.export(t, f.key.ID, validExport("nsec")); rr.Code != http.StatusUnauthorized || !strings.Contains(rr.Body.String(), "mfa_required") {
		t.Fatalf("without a code: status = %d body = %s, want 401 mfa_required", rr.Code, rr.Body.String())
	}
	b := validExport("nsec")
	b["mfa_code"] = "000000"
	if rr := f.export(t, f.key.ID, b); rr.Code != http.StatusUnauthorized {
		t.Fatalf("with a wrong code: status = %d, want 401", rr.Code)
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	b["mfa_code"] = code
	if rr := f.export(t, f.key.ID, b); rr.Code != http.StatusOK {
		t.Fatalf("with a valid code: status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
}

// Vault-wrapped keys are decrypted with a fresh userpass login, so export
// does not depend on which replica holds the key in memory.
func TestKeyExport_VaultKey(t *testing.T) {
	priv := nostr.GeneratePrivateKey()
	pub, _ := nostr.GetPublicKey(priv)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/auth/userpass/login/" + exportUserID:
			var body struct{ Password string }
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.Password != exportPassword {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"auth":{"client_token":"user-token","lease_duration":600}}`))
		case "/v1/transit/decrypt/" + vault.UserTransitKeyName(exportUserID):
			if r.Header.Get("X-Vault-Token") != "user-token" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte(`{"data":{"plaintext":"` + base64.StdEncoding.EncodeToString([]byte(priv)) + `"}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	vc, err := vault.NewClient(&vault.Config{Address: srv.URL, Token: "signer-token"})
	if err != nil {
		t.Fatal(err)
	}

	f := newExportFixture(t, vc)
	f.priv = priv
	vk := &storage.Key{ID: "key-vault", Pubkey: pub, OwnerID: exportUserID, EncryptedNsec: "vault:v1:abc", CreatedAt: time.Now()}
	if err := f.store.CreateKey(context.Background(), vk); err != nil {
		t.Fatal(err)
	}
	rr := f.export(t, vk.ID, validExport("nsec"))
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp KeyExportResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if _, decoded, err := nip19.Decode(resp.Value); err != nil || decoded.(string) != priv {
		t.Fatal("vault key export does not decode to the key")
	}
	f.assertNoKeyMaterialLeaked(t, resp.Value)
}
