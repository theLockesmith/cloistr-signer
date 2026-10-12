package signer

import (
	"context"
	"testing"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/config"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

const restorePub = "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11"

// A user-held key that isn't in memory is offered to the restorer (stay signed
// in) before resolveSigningKey gives up.
func TestResolveSigningKeyAsksRestorer(t *testing.T) {
	store := storage.NewMemoryStorage()
	ctx := context.Background()
	if err := store.CreateKey(ctx, &storage.Key{ID: "k1", Pubkey: restorePub, EncryptedNsec: "pbk:AAAA"}); err != nil {
		t.Fatal(err)
	}
	s := New(&config.Config{}, store, nil, nil, nil, nil, nil)

	if _, ok := s.resolveSigningKey(ctx, restorePub); ok {
		t.Fatal("resolved a locked user-held key with no restorer")
	}

	asked := 0
	s.SetKeyRestorer(func(_ context.Context, pubkey string) bool {
		asked++
		if pubkey != restorePub {
			t.Errorf("restorer asked for %q", pubkey)
		}
		s.keysLock.Lock()
		s.keys[pubkey] = "secret-hex"
		s.keysLock.Unlock()
		return true
	})
	priv, ok := s.resolveSigningKey(ctx, restorePub)
	if !ok || priv != "secret-hex" || asked != 1 {
		t.Fatalf("resolve = %q, %v (asked %d); want the restored key", priv, ok, asked)
	}
	// Now in memory: the restorer isn't asked again.
	if _, ok := s.resolveSigningKey(ctx, restorePub); !ok || asked != 1 {
		t.Fatalf("second resolve asked the restorer again (asked %d)", asked)
	}
}

func TestResolveSigningKeyRestorerDeclines(t *testing.T) {
	store := storage.NewMemoryStorage()
	ctx := context.Background()
	_ = store.CreateKey(ctx, &storage.Key{ID: "k1", Pubkey: restorePub, EncryptedNsec: "vault:v1:xyz"})
	s := New(&config.Config{}, store, nil, nil, nil, nil, nil)
	s.SetKeyRestorer(func(context.Context, string) bool { return false })
	if _, ok := s.resolveSigningKey(ctx, restorePub); ok {
		t.Fatal("resolved although the restorer declined")
	}
}

func TestLoadedPrivateKey(t *testing.T) {
	s := New(&config.Config{}, storage.NewMemoryStorage(), nil, nil, nil, nil, nil)
	if _, ok := s.LoadedPrivateKey(restorePub); ok {
		t.Fatal("reported a key that was never loaded")
	}
	s.keysLock.Lock()
	s.keys[restorePub] = "secret-hex"
	s.keysLock.Unlock()
	if priv, ok := s.LoadedPrivateKey(restorePub); !ok || priv != "secret-hex" {
		t.Fatalf("LoadedPrivateKey = %q, %v", priv, ok)
	}
}
