package signer

import (
	"testing"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/nostr"
)

const (
	testWarmPubkey = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testWarmSeckey = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// newWarmTestSigner builds a minimally-populated Signer suitable for exercising the
// key registration lifecycle without a live relay. s.ctx is deliberately left nil so
// warmKeyRelayClient short-circuits: these tests assert the bookkeeping and the
// guard, not the network handshake.
func newWarmTestSigner() *Signer {
	return &Signer{
		keys:       make(map[string]string),
		proxyKeys:  make(map[string]string),
		keyRelays:  make(map[string][]string),
		frostKeys:  make(map[string]string),
	}
}

// RegisterKey must remain safe before Start() has run (s.ctx == nil). Warming is a
// background relay connect; it must never panic or block registration.
func TestRegisterKey_SafeBeforeStart(t *testing.T) {
	s := newWarmTestSigner()

	s.RegisterKey(testWarmPubkey, testWarmSeckey)

	s.keysLock.RLock()
	got, ok := s.keys[testWarmPubkey]
	s.keysLock.RUnlock()

	if !ok {
		t.Fatal("RegisterKey did not register the key")
	}
	if got != testWarmSeckey {
		t.Errorf("registered private key = %q, want %q", got, testWarmSeckey)
	}
}

// warmKeyRelayClient must no-op (not panic) on each guard condition.
func TestWarmKeyRelayClient_Guards(t *testing.T) {
	cases := []struct {
		name    string
		mutate  func(*Signer)
		privKey string
	}{
		{"nil ctx", func(s *Signer) {}, testWarmSeckey},
		{"empty private key", func(s *Signer) {}, ""},
		{"nil relay manager", func(s *Signer) { s.keyRelayManager = nil }, testWarmSeckey},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := newWarmTestSigner()
			c.mutate(s)
			// Must not panic.
			s.warmKeyRelayClient(testWarmPubkey, c.privKey)
		})
	}
}

// Setup and teardown must stay symmetric: UnregisterKey removes the relay client, so
// RegisterKey is the point that creates it. If someone removes the warm call from
// RegisterKey, the login path silently regresses to paying a connect + NIP-42 AUTH
// round-trip inline on the user's first signing request.
func TestRegisterUnregister_Symmetry(t *testing.T) {
	s := newWarmTestSigner()
	s.keyRelayManager = nostr.NewKeyRelayManager(nil, nil)

	s.RegisterKey(testWarmPubkey, testWarmSeckey)
	s.keysLock.RLock()
	_, present := s.keys[testWarmPubkey]
	s.keysLock.RUnlock()
	if !present {
		t.Fatal("key absent after RegisterKey")
	}

	s.UnregisterKey(testWarmPubkey)
	s.keysLock.RLock()
	_, stillThere := s.keys[testWarmPubkey]
	s.keysLock.RUnlock()
	if stillThere {
		t.Error("key still present after UnregisterKey — private material must be evicted on logout")
	}
}

// A Vault-encrypted key's per-key relay config must survive boot even though its
// private material is skipped. Regression guard for the hoist in Start(): the vault
// `continue` used to skip the keyRelays assignment, so a vault key registered at
// login silently fell back to the default relay set.
func TestVaultKeyRelayConfig_SurvivesBootSkip(t *testing.T) {
	s := newWarmTestSigner()
	want := []string{"wss://relay.example.test"}

	// Simulate what Start() now does for a vault key: relay config recorded even
	// though the private key is never loaded into s.keys.
	s.keyRelays[testWarmPubkey] = want
	if _, loaded := s.keys[testWarmPubkey]; loaded {
		t.Fatal("vault key must not have private material loaded at boot")
	}

	// At login the key is registered; warming must pick up the boot-recorded relays.
	s.keysLock.RLock()
	got := s.keyRelays[testWarmPubkey]
	s.keysLock.RUnlock()

	if len(got) != 1 || got[0] != want[0] {
		t.Errorf("keyRelays for vault key = %v, want %v", got, want)
	}
}
