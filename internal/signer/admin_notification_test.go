package signer

import (
	"testing"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/config"
	gonostr "github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
)

// Audit finding #31, 2026-09-06.
//
// notifyAdminsOfPendingRequest used to set PubKey to the requesting USER's
// pubkey and sign with that user's custody key -- the key this service holds
// only in order to remote-sign what the user's own client asks for. The result
// was an activity log of a user's signing session, authored as that user and
// published to relays chosen by the admin. The user's client never asked for
// the event and never saw it.
//
// These tests pin the property that was wrong: whose key signs this.

func newTestSignerWithServiceKey(t *testing.T) (*Signer, string, string) {
	t.Helper()
	servicePriv := gonostr.GeneratePrivateKey()
	servicePub, err := gonostr.GetPublicKey(servicePriv)
	if err != nil {
		t.Fatalf("service key: %v", err)
	}
	s := &Signer{config: &config.Config{}}
	s.SetServiceKey(servicePub, servicePriv)
	return s, servicePub, servicePriv
}

func TestAdminNotificationIsSignedByTheServiceNotTheUser(t *testing.T) {
	s, servicePub, _ := newTestSignerWithServiceKey(t)

	// A user whose key the bunker holds in custody. Nothing this test does may
	// end up attributed to them.
	userPriv := gonostr.GeneratePrivateKey()
	userPub, err := gonostr.GetPublicKey(userPriv)
	if err != nil {
		t.Fatalf("user key: %v", err)
	}
	s.keysLock.Lock()
	s.keys = map[string]string{userPub: userPriv}
	s.keysLock.Unlock()

	adminPriv := gonostr.GeneratePrivateKey()
	adminPub, err := gonostr.GetPublicKey(adminPriv)
	if err != nil {
		t.Fatalf("admin key: %v", err)
	}

	event, err := s.buildAdminNotification(adminPub, "Authorization Request for "+userPub)
	if err != nil {
		t.Fatalf("buildAdminNotification: %v", err)
	}

	if event.PubKey == userPub {
		t.Fatal("the notification is authored by the USER -- this is finding #31")
	}
	if event.PubKey != servicePub {
		t.Fatalf("author = %s, want the service key %s", event.PubKey, servicePub)
	}

	// Authorship is a signature claim, not a field. Check the signature too:
	// setting PubKey without signing correspondingly would still be a forgery
	// of the service's identity.
	ok, err := event.CheckSignature()
	if err != nil || !ok {
		t.Fatalf("signature does not verify against the stated author: ok=%v err=%v", ok, err)
	}

	// And the admin must still be able to read it, which only works if the
	// shared secret was derived from the same key that signed.
	secret, err := nip04.ComputeSharedSecret(event.PubKey, adminPriv)
	if err != nil {
		t.Fatalf("admin shared secret: %v", err)
	}
	plaintext, err := nip04.Decrypt(event.Content, secret)
	if err != nil {
		t.Fatalf("admin cannot decrypt the notification: %v", err)
	}

	// The user's pubkey belongs in the encrypted body -- the admin needs it to
	// act on the request. It must not be the author.
	if want := "Authorization Request for " + userPub; plaintext != want {
		t.Fatalf("body = %q, want %q", plaintext, want)
	}
}

func TestWithNoServiceKeyNothingIsBuiltRatherThanFallingBackToTheUser(t *testing.T) {
	s := &Signer{config: &config.Config{}}

	adminPriv := gonostr.GeneratePrivateKey()
	adminPub, err := gonostr.GetPublicKey(adminPriv)
	if err != nil {
		t.Fatalf("admin key: %v", err)
	}

	event, err := s.buildAdminNotification(adminPub, "anything")
	if err == nil {
		t.Fatalf("built a notification with no service key: author=%s", event.PubKey)
	}
	if event != nil {
		t.Fatal("returned an event alongside an error")
	}

	// Assert the REASON, not just that something failed. Without an explicit
	// guard this call still errors, because an empty private key cannot derive
	// a shared secret -- so a test that only checks err != nil passes whether
	// the fail-closed check exists or not. Measured: removing the guard left
	// the loose version of this test green.
	if got := err.Error(); got != "no service key configured" {
		t.Fatalf("failed for the wrong reason: %q -- the explicit fail-closed "+
			"guard is what must stop this, not an incidental crypto error", got)
	}
}
