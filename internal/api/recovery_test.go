package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/auth"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/config"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/crypto"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/signer"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// Account recovery hands out a password reset to whoever can sign a challenge, so
// the tests below are mostly about what must NOT work: a stale challenge, a
// replayed one, a signature from an unrelated key, a proof over a different nonce.

type recoveryFixture struct {
	h        *Handler
	store    storage.Storage
	mux      *http.ServeMux
	user     *storage.User
	priv     string
	pub      string
	password string
}

func newRecoveryFixture(t *testing.T) *recoveryFixture {
	t.Helper()
	store := storage.NewMemoryStorage()
	cfg := &config.Config{Relays: []string{"wss://relay.example.com"}}
	authCfg := &auth.Config{
		JWTSecret:   "test-secret-that-is-long-enough-1234",
		TokenExpiry: 24 * time.Hour,
		BcryptCost:  4,
	}

	s := signer.New(cfg, store, nil, nil, nil, nil, nil)
	h := &Handler{config: cfg, storage: store, signer: s, authConfig: authCfg}

	const password = "original-password"
	hash, err := auth.HashPassword(password, authCfg.BcryptCost)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	user := &storage.User{
		ID: "user-1", Username: "alice", Role: "user", PasswordHash: hash,
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	if err := store.CreateUser(context.Background(), user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	priv := nostr.GeneratePrivateKey()
	pub, err := nostr.GetPublicKey(priv)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	pe, _ := crypto.NewPassphraseEncryptor(password)
	ct, _ := pe.Encrypt(priv)
	key := &storage.Key{
		ID: pub[:16], Name: "Primary", Pubkey: pub, KeyType: storage.KeyTypeLocal,
		EncryptedNsec: ct, EncryptionMethod: string(crypto.EncryptionMethodPassphrase),
		CreatedAt: time.Now(), OwnerID: user.ID,
	}
	if err := store.CreateKey(context.Background(), key); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/recovery/challenge", h.handleRecoveryChallenge)
	mux.HandleFunc("/api/v1/recovery/complete", h.handleRecoveryComplete)

	return &recoveryFixture{h: h, store: store, mux: mux, user: user, priv: priv, pub: pub, password: password}
}

func (f *recoveryFixture) post(t *testing.T, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "http://signer.cloistr.xyz"+path, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, req)
	return w
}

func (f *recoveryFixture) requestChallenge(t *testing.T, username string) string {
	t.Helper()
	w := f.post(t, "/api/v1/recovery/challenge", map[string]string{"username": username})
	if w.Code != http.StatusOK {
		t.Fatalf("challenge: status %d, body %s", w.Code, w.Body.String())
	}
	var resp recoveryChallengeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("challenge decode: %v", err)
	}
	return resp.Challenge
}

// signChallenge produces the kind-27235 proof the client would send.
func signChallenge(t *testing.T, priv, challenge string, createdAt time.Time) string {
	t.Helper()
	ev := nostr.Event{
		Kind:      recoveryAuthKind,
		CreatedAt: nostr.Timestamp(createdAt.Unix()),
		Tags:      nostr.Tags{{"challenge", challenge}},
		Content:   "cloistr account recovery",
	}
	if err := ev.Sign(priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	raw, _ := json.Marshal(ev)
	return string(raw)
}

func TestRecovery_HappyPathResetsPasswordAndRestoresKey(t *testing.T) {
	f := newRecoveryFixture(t)
	challenge := f.requestChallenge(t, "alice")

	const newPassword = "a-brand-new-password"
	w := f.post(t, "/api/v1/recovery/complete", recoveryCompleteRequest{
		Challenge:   challenge,
		SignedEvent: signChallenge(t, f.priv, challenge, time.Now()),
		NewPassword: newPassword,
		Nsec:        f.priv,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("complete: status %d, body %s", w.Code, w.Body.String())
	}

	var resp recoveryCompleteResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.KeysRecovered != 1 {
		t.Errorf("KeysRecovered = %d, want 1", resp.KeysRecovered)
	}
	if len(resp.KeysNeedingReimport) != 0 {
		t.Errorf("KeysNeedingReimport = %v, want none", resp.KeysNeedingReimport)
	}

	user, err := f.store.GetUser(context.Background(), f.user.ID)
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if !auth.VerifyPassword(newPassword, user.PasswordHash) {
		t.Error("new password does not verify")
	}
	if auth.VerifyPassword(f.password, user.PasswordHash) {
		t.Error("old password still verifies")
	}

	// The restored key must be readable under the NEW passphrase, which is the
	// whole point — a reset that leaves the key sealed is not a recovery.
	key, err := f.store.GetKey(context.Background(), f.pub[:16])
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	pe, _ := crypto.NewPassphraseEncryptor(newPassword)
	got, err := pe.Decrypt(key.EncryptedNsec)
	if err != nil || got != f.priv {
		t.Errorf("key not re-wrapped under the new passphrase (err=%v)", err)
	}
	if !f.h.signer.IsKeyLoaded(f.pub) {
		t.Error("recovered key was not loaded into the signer runtime")
	}
}

// Without the nsec, recovery still restores account access but must say plainly
// that the passphrase-wrapped key is stranded.
func TestRecovery_WithoutNsecReportsStrandedKeys(t *testing.T) {
	f := newRecoveryFixture(t)
	challenge := f.requestChallenge(t, "alice")

	w := f.post(t, "/api/v1/recovery/complete", recoveryCompleteRequest{
		Challenge:   challenge,
		SignedEvent: signChallenge(t, f.priv, challenge, time.Now()),
		NewPassword: "a-brand-new-password",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}
	var resp recoveryCompleteResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.KeysRecovered != 0 {
		t.Errorf("KeysRecovered = %d, want 0", resp.KeysRecovered)
	}
	if len(resp.KeysNeedingReimport) != 1 || resp.KeysNeedingReimport[0] != f.pub {
		t.Errorf("KeysNeedingReimport = %v, want [%s]", resp.KeysNeedingReimport, f.pub)
	}
}

// A challenge is spent by the attempt, not by the attempt succeeding.
func TestRecovery_ChallengeIsSingleUse(t *testing.T) {
	f := newRecoveryFixture(t)
	challenge := f.requestChallenge(t, "alice")
	signed := signChallenge(t, f.priv, challenge, time.Now())

	first := f.post(t, "/api/v1/recovery/complete", recoveryCompleteRequest{
		Challenge: challenge, SignedEvent: signed, NewPassword: "first-new-password",
	})
	if first.Code != http.StatusOK {
		t.Fatalf("first attempt: status %d", first.Code)
	}

	// Replaying the exact same proof must not reset the password again.
	second := f.post(t, "/api/v1/recovery/complete", recoveryCompleteRequest{
		Challenge: challenge, SignedEvent: signed, NewPassword: "attacker-password",
	})
	if second.Code != http.StatusUnauthorized {
		t.Errorf("replayed challenge: status %d, want 401", second.Code)
	}
	user, _ := f.store.GetUser(context.Background(), f.user.ID)
	if auth.VerifyPassword("attacker-password", user.PasswordHash) {
		t.Error("a replayed proof reset the password")
	}
}

// Someone else's valid nsec proves possession of *a* key, but not of one on this
// account. This is the check that stops any Nostr user resetting any account.
func TestRecovery_RejectsProofFromUnrelatedKey(t *testing.T) {
	f := newRecoveryFixture(t)
	challenge := f.requestChallenge(t, "alice")

	attackerPriv := nostr.GeneratePrivateKey()
	w := f.post(t, "/api/v1/recovery/complete", recoveryCompleteRequest{
		Challenge:   challenge,
		SignedEvent: signChallenge(t, attackerPriv, challenge, time.Now()),
		NewPassword: "attacker-password",
	})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401", w.Code)
	}
	user, _ := f.store.GetUser(context.Background(), f.user.ID)
	if !auth.VerifyPassword(f.password, user.PasswordHash) {
		t.Error("password changed despite an unrelated proving key")
	}
}

// A proof over a different nonce must not be accepted for this one, or a
// signature captured anywhere becomes a universal reset token.
func TestRecovery_RejectsProofOverDifferentChallenge(t *testing.T) {
	f := newRecoveryFixture(t)
	challenge := f.requestChallenge(t, "alice")
	other := f.requestChallenge(t, "alice")

	w := f.post(t, "/api/v1/recovery/complete", recoveryCompleteRequest{
		Challenge:   challenge,
		SignedEvent: signChallenge(t, f.priv, other, time.Now()),
		NewPassword: "attacker-password",
	})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401", w.Code)
	}
}

func TestRecovery_RejectsUnknownAndExpiredChallenges(t *testing.T) {
	f := newRecoveryFixture(t)

	// Never issued.
	w := f.post(t, "/api/v1/recovery/complete", recoveryCompleteRequest{
		Challenge:   strings.Repeat("ab", 32),
		SignedEvent: signChallenge(t, f.priv, strings.Repeat("ab", 32), time.Now()),
		NewPassword: "attacker-password",
	})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("unknown challenge: status %d, want 401", w.Code)
	}

	// Issued but past its TTL.
	expired := &storage.RecoveryChallenge{
		ID: strings.Repeat("cd", 32), UserID: f.user.ID,
		ExpiresAt: time.Now().Add(-time.Minute), CreatedAt: time.Now().Add(-10 * time.Minute),
	}
	if err := f.store.CreateRecoveryChallenge(context.Background(), expired); err != nil {
		t.Fatalf("CreateRecoveryChallenge: %v", err)
	}
	w = f.post(t, "/api/v1/recovery/complete", recoveryCompleteRequest{
		Challenge:   expired.ID,
		SignedEvent: signChallenge(t, f.priv, expired.ID, time.Now()),
		NewPassword: "attacker-password",
	})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expired challenge: status %d, want 401", w.Code)
	}
}

// The signed event's own timestamp is checked too, so a proof minted long before
// the challenge could have existed is refused.
func TestRecovery_RejectsStaleSignedEvent(t *testing.T) {
	f := newRecoveryFixture(t)
	challenge := f.requestChallenge(t, "alice")

	w := f.post(t, "/api/v1/recovery/complete", recoveryCompleteRequest{
		Challenge:   challenge,
		SignedEvent: signChallenge(t, f.priv, challenge, time.Now().Add(-2*time.Hour)),
		NewPassword: "attacker-password",
	})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status %d, want 401", w.Code)
	}
}

// An nsec that isn't the key just proven must be refused, so the proof cannot be
// used as cover for installing a different key on the account.
func TestRecovery_RejectsMismatchedNsec(t *testing.T) {
	f := newRecoveryFixture(t)
	challenge := f.requestChallenge(t, "alice")

	w := f.post(t, "/api/v1/recovery/complete", recoveryCompleteRequest{
		Challenge:   challenge,
		SignedEvent: signChallenge(t, f.priv, challenge, time.Now()),
		NewPassword: "a-brand-new-password",
		Nsec:        nostr.GeneratePrivateKey(),
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400", w.Code)
	}
	user, _ := f.store.GetUser(context.Background(), f.user.ID)
	if !auth.VerifyPassword(f.password, user.PasswordHash) {
		t.Error("password changed despite a mismatched nsec; the reset must abort first")
	}
}

// The challenge endpoint must not confirm whether an account exists.
func TestRecovery_ChallengeDoesNotLeakAccountExistence(t *testing.T) {
	f := newRecoveryFixture(t)

	known := f.post(t, "/api/v1/recovery/challenge", map[string]string{"username": "alice"})
	unknown := f.post(t, "/api/v1/recovery/challenge", map[string]string{"username": "nobody-here"})

	if known.Code != unknown.Code {
		t.Errorf("status differs: known=%d unknown=%d", known.Code, unknown.Code)
	}
	var a, b recoveryChallengeResponse
	if err := json.Unmarshal(known.Body.Bytes(), &a); err != nil {
		t.Fatalf("decode known: %v", err)
	}
	if err := json.Unmarshal(unknown.Body.Bytes(), &b); err != nil {
		t.Fatalf("decode unknown: %v", err)
	}
	if len(a.Challenge) != len(b.Challenge) {
		t.Errorf("challenge length differs: %d vs %d", len(a.Challenge), len(b.Challenge))
	}
	if b.Challenge == "" {
		t.Error("no challenge issued for an unknown account — that is an existence oracle")
	}

	// And the unknown-account challenge must be inert.
	w := f.post(t, "/api/v1/recovery/complete", recoveryCompleteRequest{
		Challenge:   b.Challenge,
		SignedEvent: signChallenge(t, f.priv, b.Challenge, time.Now()),
		NewPassword: "attacker-password",
	})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("unknown-account challenge was usable: status %d", w.Code)
	}
}

// Recovery is also the end of a lockout — otherwise the user proves themselves
// and is locked straight back out.
func TestRecovery_ClearsLockout(t *testing.T) {
	f := newRecoveryFixture(t)

	user, _ := f.store.GetUser(context.Background(), f.user.ID)
	until := time.Now().Add(time.Hour)
	user.FailedLoginAttempts = 9
	user.LockedUntil = &until
	if err := f.store.UpdateUser(context.Background(), user); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}

	challenge := f.requestChallenge(t, "alice")
	w := f.post(t, "/api/v1/recovery/complete", recoveryCompleteRequest{
		Challenge:   challenge,
		SignedEvent: signChallenge(t, f.priv, challenge, time.Now()),
		NewPassword: "a-brand-new-password",
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", w.Code, w.Body.String())
	}

	after, _ := f.store.GetUser(context.Background(), f.user.ID)
	if after.FailedLoginAttempts != 0 {
		t.Errorf("FailedLoginAttempts = %d, want 0", after.FailedLoginAttempts)
	}
	if after.LockedUntil != nil {
		t.Error("LockedUntil was not cleared")
	}
}

func TestRecovery_RejectsShortPassword(t *testing.T) {
	f := newRecoveryFixture(t)
	challenge := f.requestChallenge(t, "alice")

	w := f.post(t, "/api/v1/recovery/complete", recoveryCompleteRequest{
		Challenge:   challenge,
		SignedEvent: signChallenge(t, f.priv, challenge, time.Now()),
		NewPassword: "short",
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("status %d, want 400", w.Code)
	}
	// The challenge must survive a request rejected before it was consumed, or a
	// typo in the new password would cost the user their one proof.
	ok := f.post(t, "/api/v1/recovery/complete", recoveryCompleteRequest{
		Challenge:   challenge,
		SignedEvent: signChallenge(t, f.priv, challenge, time.Now()),
		NewPassword: "a-brand-new-password",
	})
	if ok.Code != http.StatusOK {
		t.Errorf("retry after validation failure: status %d, want 200", ok.Code)
	}
}

// addSecondaryKey registers another key on the same account, of the kind a user
// might add for a single app.
func (f *recoveryFixture) addSecondaryKey(t *testing.T, name string) (priv, pub string) {
	t.Helper()
	priv = nostr.GeneratePrivateKey()
	pub, err := nostr.GetPublicKey(priv)
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	pe, _ := crypto.NewPassphraseEncryptor(f.password)
	ct, _ := pe.Encrypt(priv)
	key := &storage.Key{
		ID: pub[:16], Name: name, Pubkey: pub, KeyType: storage.KeyTypeLocal,
		EncryptedNsec: ct, EncryptionMethod: string(crypto.EncryptionMethodPassphrase),
		CreatedAt: time.Now(), OwnerID: f.user.ID,
	}
	if err := f.store.CreateKey(context.Background(), key); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	return priv, pub
}

// The property that bounds the blast radius: an account is NOT only as strong as
// its weakest key. A secondary key proves possession of itself and nothing more —
// otherwise compromising a throwaway app key would reset the password, which
// resets the Vault credential, which hands over every vault:-wrapped key.
func TestRecovery_RejectsProofFromNonIdentityKeyOnSameAccount(t *testing.T) {
	f := newRecoveryFixture(t)
	secondaryPriv, secondaryPub := f.addSecondaryKey(t, "App key")

	challenge := f.requestChallenge(t, "alice")
	w := f.post(t, "/api/v1/recovery/complete", recoveryCompleteRequest{
		Challenge:   challenge,
		SignedEvent: signChallenge(t, secondaryPriv, challenge, time.Now()),
		NewPassword: "attacker-password",
	})
	if w.Code != http.StatusUnauthorized {
		t.Errorf("secondary key was accepted: status %d, want 401", w.Code)
	}
	user, _ := f.store.GetUser(context.Background(), f.user.ID)
	if !auth.VerifyPassword(f.password, user.PasswordHash) {
		t.Error("password was reset by a non-identity key")
	}

	// Sanity: the secondary key really does belong to the account, so the
	// rejection is about which key it is, not about ownership.
	keys, _ := f.store.ListKeys(context.Background(), f.user.ID)
	if !ownsPubkey(keys, secondaryPub) {
		t.Fatal("precondition failed: secondary key is not on the account")
	}
	// And the identity key still works.
	challenge2 := f.requestChallenge(t, "alice")
	ok := f.post(t, "/api/v1/recovery/complete", recoveryCompleteRequest{
		Challenge:   challenge2,
		SignedEvent: signChallenge(t, f.priv, challenge2, time.Now()),
		NewPassword: "a-brand-new-password",
	})
	if ok.Code != http.StatusOK {
		t.Errorf("identity key rejected: status %d, body %s", ok.Code, ok.Body.String())
	}
}

func TestRecovery_OptOutBlocksRecovery(t *testing.T) {
	f := newRecoveryFixture(t)
	if err := f.store.SetSetting(context.Background(), recoveryOptOutKey(f.user.ID), "true"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}

	challenge := f.requestChallenge(t, "alice")
	w := f.post(t, "/api/v1/recovery/complete", recoveryCompleteRequest{
		Challenge:   challenge,
		SignedEvent: signChallenge(t, f.priv, challenge, time.Now()),
		NewPassword: "a-brand-new-password",
	})
	if w.Code != http.StatusForbidden {
		t.Errorf("status %d, want 403", w.Code)
	}
	user, _ := f.store.GetUser(context.Background(), f.user.ID)
	if !auth.VerifyPassword(f.password, user.PasswordHash) {
		t.Error("password was reset despite opt-out")
	}
}

// Opting out must not become an oracle: the challenge endpoint has to look the
// same for an opted-out account as for any other, because it is unauthenticated.
func TestRecovery_OptOutIsNotVisibleBeforeProof(t *testing.T) {
	f := newRecoveryFixture(t)

	before := f.post(t, "/api/v1/recovery/challenge", map[string]string{"username": "alice"})
	if err := f.store.SetSetting(context.Background(), recoveryOptOutKey(f.user.ID), "true"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	after := f.post(t, "/api/v1/recovery/challenge", map[string]string{"username": "alice"})

	if before.Code != after.Code {
		t.Errorf("challenge status differs once opted out: %d vs %d", before.Code, after.Code)
	}
	var a, b recoveryChallengeResponse
	_ = json.Unmarshal(before.Body.Bytes(), &a)
	_ = json.Unmarshal(after.Body.Bytes(), &b)
	if len(a.Challenge) != len(b.Challenge) || b.Challenge == "" {
		t.Error("challenge shape differs once opted out; that is an opt-out oracle")
	}
}

// Default posture is enabled, and a storage read failure must not silently
// disable recovery for someone who never opted out.
func TestRecovery_DefaultIsEnabled(t *testing.T) {
	f := newRecoveryFixture(t)
	if f.h.recoveryDisabled(context.Background(), f.user.ID) {
		t.Error("recovery is disabled by default; it must be opt-OUT, not opt-in")
	}
	if f.h.recoveryDisabled(context.Background(), "no-such-user") {
		t.Error("an unknown/unreadable setting must read as enabled, not disabled")
	}
}

func TestRecovery_OptOutRoundTripsThroughSettings(t *testing.T) {
	f := newRecoveryFixture(t)
	ctx := context.Background()

	for _, enabled := range []bool{false, true, false} {
		value := "false"
		if !enabled {
			value = "true"
		}
		if err := f.store.SetSetting(ctx, recoveryOptOutKey(f.user.ID), value); err != nil {
			t.Fatalf("SetSetting: %v", err)
		}
		if got := !f.h.recoveryDisabled(ctx, f.user.ID); got != enabled {
			t.Errorf("enabled = %v, want %v", got, enabled)
		}
	}
}
