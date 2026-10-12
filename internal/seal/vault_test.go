package seal

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// fakeTransit mimics a derived transit key: the derivation context must match on
// decrypt, and the key version is part of the ciphertext.
type fakeTransit struct {
	ikm     []byte
	version int
	minDec  int
	gotKey  string
}

func (f *fakeTransit) TransitEncryptDerived(_ context.Context, key, plaintextB64, contextB64 string) (string, error) {
	f.gotKey = key
	pt, err := base64.StdEncoding.DecodeString(plaintextB64)
	if err != nil {
		return "", err
	}
	ctxb, _ := base64.StdEncoding.DecodeString(contextB64)
	b := Binding{Pubkey: string(ctxb), SessionID: "ctx"}
	ct, err := aeadSeal(append(f.ikm, byte(f.version)), "fake", pt, b)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("vault:v%d:%s", f.version, base64.StdEncoding.EncodeToString(ct)), nil
}

func (f *fakeTransit) TransitDecryptDerived(_ context.Context, key, ciphertext, contextB64 string) (string, error) {
	var v int
	var body string
	if _, err := fmt.Sscanf(ciphertext, "vault:v%d:", &v); err != nil {
		return "", err
	}
	if v < f.minDec {
		return "", errors.New("vault error (status 400): ciphertext version is disallowed by policy (too old)")
	}
	body = ciphertext[strings.LastIndex(ciphertext, ":")+1:]
	ct, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return "", err
	}
	ctxb, _ := base64.StdEncoding.DecodeString(contextB64)
	pt, err := aeadOpen(append(f.ikm, byte(v)), "fake", ct, Binding{Pubkey: string(ctxb), SessionID: "ctx"})
	if err != nil {
		return "", errors.New("vault error (status 400): cipher: message authentication failed")
	}
	return base64.StdEncoding.EncodeToString(pt), nil
}

func newVaultSealer(t *testing.T) (*Vault, *fakeTransit) {
	t.Helper()
	ft := &fakeTransit{ikm: []byte("fake transit key material 32byte"), version: 1}
	v, err := NewVault(ft, "")
	if err != nil {
		t.Fatal(err)
	}
	return v, ft
}

func TestVaultRoundTripAndKeyName(t *testing.T) {
	v, ft := newVaultSealer(t)
	if !v.Enabled() || v.Mode() != ModeVault {
		t.Fatal("vault sealer must be enabled, mode vault")
	}
	blob, err := v.Seal(context.Background(), secret, alice)
	if err != nil {
		t.Fatal(err)
	}
	if ft.gotKey != DefaultVaultKey {
		t.Fatalf("transit key = %q, want %q", ft.gotKey, DefaultVaultKey)
	}
	if DetectMode(blob) != ModeVault {
		t.Fatalf("blob %q not detected as vault", blob)
	}
	if got := VaultKeyVersion(blob); got != 1 {
		t.Fatalf("VaultKeyVersion = %d, want 1", got)
	}
	got, err := v.Open(context.Background(), blob, alice)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("Open: %v", err)
	}
}

func TestVaultSwappedBlobFails(t *testing.T) {
	v, _ := newVaultSealer(t)
	blob, _ := v.Seal(context.Background(), secret, alice)
	for _, b := range []Binding{
		{Pubkey: "bb22", SessionID: alice.SessionID},
		{Pubkey: alice.Pubkey, SessionID: "sess-2"},
	} {
		if _, err := v.Open(context.Background(), blob, b); !errors.Is(err, ErrOpen) {
			t.Fatalf("binding %+v: err = %v, want ErrOpen", b, err)
		}
	}
	if _, err := v.Open(context.Background(), []byte("kf1junk"), alice); !errors.Is(err, ErrOpen) {
		t.Fatalf("non-vault blob: err = %v, want ErrOpen", err)
	}
}

// After rotation + min_decryption_version, an old ciphertext (an old DB backup) no
// longer opens.
func TestVaultOldVersionRefusedAfterMinDecryption(t *testing.T) {
	v, ft := newVaultSealer(t)
	old, _ := v.Seal(context.Background(), secret, alice)
	ft.version, ft.minDec = 2, 2
	if _, err := v.Open(context.Background(), old, alice); !errors.Is(err, ErrOpen) {
		t.Fatalf("old version: err = %v, want ErrOpen", err)
	}
	fresh, _ := v.Seal(context.Background(), secret, alice)
	if VaultKeyVersion(fresh) != 2 {
		t.Fatalf("fresh seal version = %d, want 2", VaultKeyVersion(fresh))
	}
	if _, err := v.Open(context.Background(), fresh, alice); err != nil {
		t.Fatalf("fresh seal: %v", err)
	}
}

func TestVaultKeyVersionJunk(t *testing.T) {
	for _, s := range []string{"", "vt1:", "vt1:vault:vx:abc", "kf1...."} {
		if VaultKeyVersion([]byte(s)) != 0 {
			t.Errorf("VaultKeyVersion(%q) != 0", s)
		}
	}
}

func TestNewVaultNeedsClient(t *testing.T) {
	if _, err := NewVault(nil, ""); err == nil {
		t.Fatal("NewVault(nil) should fail")
	}
}
