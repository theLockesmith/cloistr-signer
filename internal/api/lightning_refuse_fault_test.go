package api

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// Reviewer's note on !254: refuseLightningChallenge answered 400 "unlinked"
// even when consuming the challenge FAILED. That reports a server fault as a
// user-facing refusal, and hides that the challenge may still be live. A
// failed consume must be a 500.

// consumeFailStore fails ConsumeLightningChallenge with a storage fault and
// passes everything else through.
type consumeFailStore struct {
	storage.Storage
}

func (s *consumeFailStore) ConsumeLightningChallenge(ctx context.Context, sessionID string) (string, error) {
	return "", errors.New("connection reset by peer")
}

func TestLightningRefusal_ConsumeFault_Status500(t *testing.T) {
	a, _, store, wallet := lightningReplicas(t)
	a.config.Lightning.ConfirmFirstLogin = true

	sid, code, body, _ := lnLoginUntilStatus(t, a, wallet)
	if code != http.StatusOK || body["status"] != "confirm_account" {
		t.Fatalf("setup: first poll should ask for confirmation: %d %v", code, body)
	}
	if err := store.DeleteLightningKey(context.Background(), "lk1"); err != nil {
		t.Fatal(err)
	}
	a.storage = &consumeFailStore{Storage: store}

	code, body, cookies := lnStatus(t, a, sid)
	if body["success"] == true || len(cookies) != 0 {
		t.Fatalf("BYPASS: status signed in while refusing: %d %v cookies=%d", code, body, len(cookies))
	}
	if code != http.StatusInternalServerError {
		t.Fatalf("status with a failed consume: %d %v, want 500 (a server fault, not a user refusal)", code, body)
	}
}

func TestLightningRefusal_ConsumeFault_Confirm500(t *testing.T) {
	a, _, store, wallet := lightningReplicas(t)
	a.config.Lightning.ConfirmFirstLogin = true

	sid, code, body, _ := lnLoginUntilStatus(t, a, wallet)
	if code != http.StatusOK || body["status"] != "confirm_account" {
		t.Fatalf("setup: first poll should ask for confirmation: %d %v", code, body)
	}
	if err := store.DeleteLightningKey(context.Background(), "lk1"); err != nil {
		t.Fatal(err)
	}
	a.storage = &consumeFailStore{Storage: store}

	code, body, cookies := lnConfirm(t, a, sid, false)
	if body["success"] == true || len(cookies) != 0 {
		t.Fatalf("BYPASS: confirm signed in while refusing: %d %v cookies=%d", code, body, len(cookies))
	}
	if code != http.StatusInternalServerError {
		t.Fatalf("confirm with a failed consume: %d %v, want 500 (a server fault, not a user refusal)", code, body)
	}
}
