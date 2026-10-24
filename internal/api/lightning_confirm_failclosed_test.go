package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// cloistr-audit, review of !241 (note 20285): the first-login confirmation
// gate FAILS OPEN. lightningKeyNeedsConfirm collapses three different
// situations into one boolean:
//   - the linking key no longer exists (deleted)
//   - the linking key now belongs to a different account
//   - this browser already confirmed it (confirmation genuinely not needed)
//
// Callers can't tell "refuse" apart from "proceed", so a missing or
// reassigned key falls through to a sign-in (status) or a 409 "not_required"
// that the UI treats as "keep polling" (confirm), and the next poll signs in.
//
// Attack: attacker starts a login challenge with the victim's wallet,
// deletes the linking key the instant the wallet signs (or between the
// confirm_account prompt and the victim's "No"), and the victim's browser
// gets signed into the attacker's account anyway.
//
// These tests reproduce the two failing cases from that review (#5 and #6)
// plus an account-mismatch variant, and pin down what "fail closed" means:
// consume the challenge and refuse, never 409, never a sign-in.

// Race #5: the wallet signs, the attacker deletes the key before the
// victim's next status poll. The poll must refuse, not sign in, and the
// challenge must be consumed so a retried poll is refused too (not stuck
// "pending" for another race attempt).
func TestLightningConfirm_KeyDeletedBeforePoll_StatusRefuses(t *testing.T) {
	a, _, store, wallet := lightningReplicas(t)
	a.config.Lightning.ConfirmFirstLogin = true

	sid, code, body, cookies := lnLoginUntilStatus(t, a, wallet)
	if code != http.StatusOK || body["status"] != "confirm_account" || len(cookies) != 0 {
		t.Fatalf("setup: first poll should ask for confirmation: %d %v cookies=%d", code, body, len(cookies))
	}

	// Attacker deletes the linking key before the victim's next poll.
	if err := store.DeleteLightningKey(context.Background(), "lk1"); err != nil {
		t.Fatal(err)
	}

	code, body, cookies = lnStatus(t, a, sid)
	if body["success"] == true || len(cookies) != 0 {
		t.Fatalf("BYPASS: status signed in after the key was deleted: %d %v cookies=%d, want a refusal", code, body, len(cookies))
	}
	if code == http.StatusConflict {
		t.Fatalf("status returned 409 for a deleted key: %d %v, want a refusal that is NOT 409 (409 must mean only \"wallet hasn't signed yet\")", code, body)
	}

	// Retry: the challenge must already be consumed, so a repeated poll is
	// refused too, not left "pending" for another attempt at the race.
	code, body, cookies = lnStatus(t, a, sid)
	if body["success"] == true || len(cookies) != 0 {
		t.Fatalf("BYPASS on retry: status signed in on a second poll after refusal: %d %v cookies=%d", code, body, len(cookies))
	}
}

// Race #6: the victim sees the confirm_account prompt and answers "No", but
// the attacker deleted the key in between. The current code's 409
// "not_required" makes the UI keep polling /status, which then signs in.
// Confirm must refuse outright (never 409) and consume the challenge; the
// account must never end up signed in.
func TestLightningConfirm_KeyDeletedBetweenPromptAndNo_ConfirmRefuses(t *testing.T) {
	a, _, store, wallet := lightningReplicas(t)
	a.config.Lightning.ConfirmFirstLogin = true

	sid, code, body, _ := lnLoginUntilStatus(t, a, wallet)
	if code != http.StatusOK || body["status"] != "confirm_account" {
		t.Fatalf("setup: first poll should ask for confirmation: %d %v", code, body)
	}

	// Attacker deletes the key between the prompt and the victim's answer.
	if err := store.DeleteLightningKey(context.Background(), "lk1"); err != nil {
		t.Fatal(err)
	}

	code, body, cookies := lnConfirm(t, a, sid, false) // victim clicks "No"
	if code == http.StatusConflict && body["status"] == "not_required" {
		t.Fatalf("BYPASS: confirm answered 409 not_required for a deleted key; the UI treats that as \"keep polling\" and the next poll signs in: %d %v", code, body)
	}
	if body["success"] == true || len(cookies) != 0 {
		t.Fatalf("BYPASS: confirm signed in after the key was deleted: %d %v cookies=%d", code, body, len(cookies))
	}

	// Whatever /confirm answered, the challenge must now be consumed: the
	// account must never be reachable through a follow-up poll.
	code, body, cookies = lnStatus(t, a, sid)
	if body["success"] == true || len(cookies) != 0 {
		t.Fatalf("BYPASS: the victim was signed in on the poll AFTER clicking No: %d %v cookies=%d", code, body, len(cookies))
	}
}

// reassignKeyToAttacker simulates the linking key being reassigned to a
// different account between authentication and the poll/confirm (e.g. a
// delete + relink), without consuming the challenge or polling status.
func reassignKeyToAttacker(t *testing.T, store *storage.MemoryStorage, wallet lnWallet) {
	t.Helper()
	ctx := context.Background()
	if err := store.CreateUser(ctx, &storage.User{ID: "attacker-b", Username: "attacker-b", PasswordHash: "x", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteLightningKey(ctx, "lk1"); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateLightningKey(ctx, &storage.LightningKey{ID: "lk1", UserID: "attacker-b", LinkingKey: wallet.key(), CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
}

// Account-mismatch variant, /status: between authentication and the poll,
// the same linking key gets reassigned to a different account. lk.UserID no
// longer matches the challenge's authenticated UserID, and that must refuse
// exactly like a missing key — never a sign-in into either account.
func TestLightningConfirm_AccountMismatch_StatusRefuses(t *testing.T) {
	a, _, store, wallet := lightningReplicas(t)
	a.config.Lightning.ConfirmFirstLogin = true

	k1, sid := lnChallenge(t, a)
	if cb := lnCallback(t, a, wallet.callbackQuery(t, k1)); cb["status"] != "OK" {
		t.Fatalf("login callback: %v", cb)
	}
	reassignKeyToAttacker(t, store, wallet)

	code, body, cookies := lnStatus(t, a, sid)
	if body["success"] == true || len(cookies) != 0 {
		t.Fatalf("BYPASS: status signed into the reassigned account: %d %v cookies=%d", code, body, len(cookies))
	}
}

// Account-mismatch variant, /confirm: same setup, but the browser reaches
// /confirm directly (as it would right after the prompt). Must refuse, never
// 409 not_required.
func TestLightningConfirm_AccountMismatch_ConfirmRefuses(t *testing.T) {
	a, _, store, wallet := lightningReplicas(t)
	a.config.Lightning.ConfirmFirstLogin = true

	k1, sid := lnChallenge(t, a)
	if cb := lnCallback(t, a, wallet.callbackQuery(t, k1)); cb["status"] != "OK" {
		t.Fatalf("login callback: %v", cb)
	}
	reassignKeyToAttacker(t, store, wallet)

	code, body, cookies := lnConfirm(t, a, sid, true)
	if code == http.StatusConflict && body["status"] == "not_required" {
		t.Fatalf("BYPASS: confirm answered 409 not_required for a reassigned key: %d %v", code, body)
	}
	if body["success"] == true || len(cookies) != 0 {
		t.Fatalf("BYPASS: confirm signed into the reassigned account: %d %v cookies=%d", code, body, len(cookies))
	}
}

// Consuming the challenge on refusal is what makes the refusal permanent:
// even if the key is put back exactly as it was (the attacker "undoes" the
// deletion), the SAME challenge must never become completable again.
func TestLightningConfirm_RefusalConsumesChallenge(t *testing.T) {
	a, _, store, wallet := lightningReplicas(t)
	a.config.Lightning.ConfirmFirstLogin = true
	ctx := context.Background()

	sid, code, body, _ := lnLoginUntilStatus(t, a, wallet)
	if code != http.StatusOK || body["status"] != "confirm_account" {
		t.Fatalf("setup: first poll should ask for confirmation: %d %v", code, body)
	}
	if err := store.DeleteLightningKey(ctx, "lk1"); err != nil {
		t.Fatal(err)
	}
	if code, body, _ := lnStatus(t, a, sid); code != http.StatusBadRequest || body["status"] != "unlinked" {
		t.Fatalf("refusal: %d %v, want 400 unlinked", code, body)
	}

	// Restore the exact same key, correctly, as if the deletion never
	// happened.
	if err := store.CreateLightningKey(ctx, &storage.LightningKey{ID: "lk1", UserID: "ln-user", LinkingKey: wallet.key(), CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	code, body, cookies := lnStatus(t, a, sid)
	if body["status"] == "confirm_account" || body["success"] == true {
		t.Fatalf("BYPASS: the refused challenge came back to life once the key was restored: %d %v cookies=%d, want it to stay consumed", code, body, len(cookies))
	}
	if code != http.StatusBadRequest || body["status"] != "expired" {
		t.Fatalf("poll after refusal, key restored: %d %v, want 400 expired", code, body)
	}
}

// Control: with the key still intact and matching, the normal first-login
// confirmation flow is unaffected by the fail-closed fix.
func TestLightningConfirm_HappyPathStillWorks(t *testing.T) {
	a, _, _, wallet := lightningReplicas(t)
	a.config.Lightning.ConfirmFirstLogin = true

	sid, code, body, cookies := lnLoginUntilStatus(t, a, wallet)
	if code != http.StatusOK || body["status"] != "confirm_account" || body["username"] != "ln-user" || len(cookies) != 0 {
		t.Fatalf("first login: %d %v cookies=%d, want confirm_account for ln-user", code, body, len(cookies))
	}
	code, body, cookies = lnConfirm(t, a, sid, true)
	if code != http.StatusOK || body["success"] != true || len(cookies) == 0 {
		t.Fatalf("confirm=true: %d %v cookies=%d, want a sign-in", code, body, len(cookies))
	}
}
