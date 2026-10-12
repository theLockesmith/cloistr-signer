package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/seal"
)

// fakeVault is a derived transit key with versions and min_decryption_version.
// Its "ciphertext" is not encrypted (the seal package tests cover real crypto);
// it records the version and context so rotation logic can be checked exactly.
type fakeVault struct {
	mu            sync.Mutex
	latest, min   int
	rewraps       int
	failRewrap    bool
	failSetMinErr error
}

func (v *fakeVault) TransitEncryptDerived(_ context.Context, _, pt, ctx string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return fmt.Sprintf("vault:v%d:%s.%s", v.latest, ctx, pt), nil
}

func (v *fakeVault) TransitDecryptDerived(_ context.Context, _, ct, ctx string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	var ver int
	if _, err := fmt.Sscanf(ct, "vault:v%d:", &ver); err != nil {
		return "", err
	}
	if ver < v.min {
		return "", errors.New("vault error (status 400): ciphertext version is disallowed by policy (too old)")
	}
	body := ct[strings.Index(ct[6:], ":")+7:]
	gotCtx, pt, _ := strings.Cut(body, ".")
	if gotCtx != ctx {
		return "", errors.New("vault error (status 400): cipher: message authentication failed")
	}
	return pt, nil
}

func (v *fakeVault) TransitRewrapDerived(ctx context.Context, key, ct, c string) (string, error) {
	if v.failRewrap {
		return "", errors.New("vault error (status 500): boom")
	}
	pt, err := v.TransitDecryptDerived(ctx, key, ct, c)
	if err != nil {
		return "", err
	}
	v.mu.Lock()
	v.rewraps++
	v.mu.Unlock()
	return v.TransitEncryptDerived(ctx, key, pt, c)
}

func (v *fakeVault) TransitKeyVersions(context.Context, string) (int, int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.latest, v.min, nil
}

func (v *fakeVault) TransitSetMinDecryptionVersion(_ context.Context, _ string, m int) error {
	if v.failSetMinErr != nil {
		return v.failSetMinErr
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.min = m
	return nil
}

func vaultFixture(t *testing.T) (*staySignedInFixture, *fakeVault, seal.Sealer) {
	t.Helper()
	f := newStayFixture(t)
	fv := &fakeVault{latest: 1, min: 1}
	s, err := seal.NewVault(fv, "")
	if err != nil {
		t.Fatal(err)
	}
	f.h.SetSealer(s)
	f.h.SetSealRotator(fv)
	return f, fv, s
}

// Rotation re-wraps live seals to the newest key version and only then raises
// min_decryption_version, so live sign-ins survive and an old DB backup does not
// open any more.
func TestStaySignedIn_VaultRotationStrandsOldBackups(t *testing.T) {
	f, fv, s := vaultFixture(t)
	resp, _ := f.loginWith(t, f.h, "until_signout", false)
	if resp.StaySignedIn == nil || resp.StaySignedIn.Mode != seal.ModeVault {
		t.Fatalf("grant = %+v, want vault", resp.StaySignedIn)
	}
	backup := sealsFor(t, f.store)[0] // "an old DB backup" taken now
	backupBlob := bytes.Clone(backup.Sealed)
	if seal.VaultKeyVersion(backupBlob) != 1 {
		t.Fatalf("seal made at version %d, want 1", seal.VaultKeyVersion(backupBlob))
	}

	fv.latest = 2 // Vault's scheduled rotation (auto_rotate_period)
	if err := f.h.rotateVaultSeals(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fv.min != 2 || fv.rewraps != 1 {
		t.Fatalf("after rotation min=%d rewraps=%d, want 2 and 1", fv.min, fv.rewraps)
	}
	live := sealsFor(t, f.store)[0]
	if seal.VaultKeyVersion(live.Sealed) != 2 {
		t.Fatalf("live seal at version %d, want 2", seal.VaultKeyVersion(live.Sealed))
	}

	// The live seal still restores after a deploy...
	after := f.replica(t, s)
	after.reconcileSeals(context.Background())
	if !after.signer.IsKeyLoaded(f.key.Pubkey) {
		t.Fatal("live seal did not restore after rotation")
	}
	// ...but the backup copy no longer opens, even with Vault access.
	b := seal.Binding{Pubkey: backup.Pubkey, SessionID: backup.SessionID}
	if _, err := s.Open(context.Background(), backupBlob, b); !errors.Is(err, seal.ErrOpen) {
		t.Fatalf("old backup blob: err = %v, want ErrOpen", err)
	}

	// Nothing to do on a second pass.
	if err := f.h.rotateVaultSeals(context.Background()); err != nil || fv.rewraps != 1 {
		t.Fatalf("second pass: err=%v rewraps=%d", err, fv.rewraps)
	}
}

// If any live seal fails to rewrap, min_decryption_version is NOT raised: raising
// it would lock that user out.
func TestStaySignedIn_VaultRotationHoldsMinOnFailure(t *testing.T) {
	f, fv, _ := vaultFixture(t)
	f.loginWith(t, f.h, "30d", false)
	fv.latest, fv.failRewrap = 2, true
	if err := f.h.rotateVaultSeals(context.Background()); err == nil {
		t.Fatal("rotation reported success with a failed rewrap")
	}
	if fv.min != 1 {
		t.Fatalf("min raised to %d despite a failed rewrap", fv.min)
	}
}

func TestStaySignedIn_VaultRotationNoopForOtherSealers(t *testing.T) {
	f := newStayFixture(t) // keyfile
	if err := f.h.rotateVaultSeals(context.Background()); err != nil {
		t.Fatal(err)
	}
}

var _ = base64.StdEncoding
