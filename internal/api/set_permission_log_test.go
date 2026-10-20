package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// permWriteFails: every grant write fails with a recognisable cause.
type permWriteFails struct{ storage.Storage }

var errGrantWrite = errors.New("grant-write-cause-1d7f")

func (s permWriteFails) SetPermission(context.Context, *storage.Permission) error {
	return errGrantWrite
}

func (s permWriteFails) SetPermissionIfSlotFree(context.Context, *storage.Permission) error {
	return errGrantWrite
}

func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &logs
}

// A failed grant write answers "failed to set permission" and logs why. The
// cause used to be dropped, so a production 500 at sign-in left no trace of
// what the database said.
func TestSetPermissionFailure_LogsCause(t *testing.T) {
	t.Run("set-permission endpoint", func(t *testing.T) {
		h, store, _ := slottedRoleKey(t)
		h.storage = permWriteFails{store}
		logs := captureLogs(t)
		rr := postPermission(t, h, `{"user_pubkey":"`+newcomerCli+`","methods":["sign_event"],"slot":"default","replace":true}`)
		assertLoggedPermissionFailure(t, rr, logs)
	})
	t.Run("nostrconnect session", func(t *testing.T) {
		h, store := testHandler(t)
		key := seedUserAndKey(t, store)
		unlockKey(h, key)
		h.storage = permWriteFails{store}
		logs := captureLogs(t)
		body, _ := json.Marshal(map[string]interface{}{
			"uri":    validNostrConnectURI(testClientPubkey, "wss://relay.cloistr.xyz", "TestApp"),
			"key_id": key.ID,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/nostrconnect/session", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+makeSessionToken(t, h, testUserIDSess))
		rr := httptest.NewRecorder()
		h.handleNostrConnectSession(rr, req)
		assertLoggedPermissionFailure(t, rr, logs)
	})
}

func assertLoggedPermissionFailure(t *testing.T, rr *httptest.ResponseRecorder, logs *bytes.Buffer) {
	t.Helper()
	if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), "failed to set permission") {
		t.Fatalf("response %d %s, want 500 failed to set permission", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), errGrantWrite.Error()) {
		t.Fatal("the storage error leaked into the response body")
	}
	if !strings.Contains(logs.String(), errGrantWrite.Error()) {
		t.Fatalf("cause not logged; logs:\n%s", logs.String())
	}
}
