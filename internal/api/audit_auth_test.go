package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/audit"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/auth"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/signer"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// GET /api/v1/audit answered anyone, signed in or not, with every account's
// events (found on production 2026-10-19). It now requires sign-in and returns
// only the caller's own events; an admin sees all.

const (
	auditCallerKey = "aa00000000000000000000000000000000000000000000000000000000000001"
	auditOtherKey  = "bb00000000000000000000000000000000000000000000000000000000000002"
	auditOtherUser = "other-user-456"
)

// auditFixture returns a handler whose audit log holds events of the caller
// (testUserID) and of another account, labelled by Action.
func auditFixture(t *testing.T) *Handler {
	t.Helper()
	base, store := testHandler(t)
	logger := audit.NewMemoryLogger(100)
	h := NewHandler(base.config, signer.New(base.config, store, nil, nil, nil, nil, logger), store, nil, nil)
	ctx := context.Background()
	for _, u := range []struct{ id, name string }{{testUserID, "testuser"}, {auditOtherUser, "other"}} {
		if err := store.CreateUser(ctx, &storage.User{ID: u.id, Username: u.name, PasswordHash: "x", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	for _, k := range []struct{ id, pub, owner string }{{"k-caller", auditCallerKey, testUserID}, {"k-other", auditOtherKey, auditOtherUser}} {
		if err := store.CreateKey(ctx, &storage.Key{ID: k.id, Pubkey: k.pub, OwnerID: k.owner, CreatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	for _, ev := range []*audit.Event{
		{Type: audit.EventUserLogin, Actor: testUserID, ActorType: "user", Action: "caller-login"},
		{Type: audit.EventSignCompleted, Actor: "client-1", ActorType: "client", Target: auditCallerKey, TargetType: "key", Action: "caller-sign"},
		{Type: audit.EventUserLogin, Actor: auditOtherUser, ActorType: "user", Action: "other-login"},
		{Type: audit.EventSignCompleted, Actor: "client-2", ActorType: "client", Target: auditOtherKey, TargetType: "key", Action: "other-sign"},
		{Type: audit.EventType("lightning_key.linked"), Actor: auditOtherUser, ActorType: "user", Target: "02wallet", TargetType: "lightning_key", Action: "other-ln-link"},
	} {
		if err := logger.Log(ctx, ev); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func auditGet(t *testing.T, h *Handler, query, token string) (int, []string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/audit"+query, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	h.handleAuditLogs(rr, req)
	var entries []AuditLogEntry
	_ = json.Unmarshal(rr.Body.Bytes(), &entries)
	actions := make([]string, 0, len(entries))
	for _, e := range entries {
		actions = append(actions, e.Action)
	}
	sort.Strings(actions)
	return rr.Code, actions
}

func TestAuditLogs_RequiresSignIn(t *testing.T) {
	h := auditFixture(t)
	if code, got := auditGet(t, h, "", ""); code != http.StatusUnauthorized || len(got) != 0 {
		t.Fatalf("unauthenticated: %d %v, want 401 and no events", code, got)
	}
	if code, got := auditGet(t, h, "?actor="+auditOtherUser, "not-a-token"); code != http.StatusUnauthorized || len(got) != 0 {
		t.Fatalf("bad token: %d %v, want 401 and no events", code, got)
	}
}

func TestAuditLogs_OnlyCallersOwnEvents(t *testing.T) {
	h := auditFixture(t)
	tok := testAuthToken(t, h)
	if code, got := auditGet(t, h, "", tok); code != http.StatusOK || len(got) != 2 || got[0] != "caller-login" || got[1] != "caller-sign" {
		t.Fatalf("own events: %d %v, want 200 [caller-login caller-sign]", code, got)
	}
	for _, q := range []string{"?actor=" + auditOtherUser, "?target=" + auditOtherKey, "?type=" + string(audit.EventType("lightning_key.linked"))} {
		if code, got := auditGet(t, h, q, tok); code != http.StatusOK || len(got) != 0 {
			t.Fatalf("%s from a signed-in non-admin: %d %v, want 200 and none of the other account's events", q, code, got)
		}
	}
}

func TestAuditLogs_AdminSeesAll(t *testing.T) {
	h := auditFixture(t)
	// A real config admin: the token's user id is a configured admin pubkey.
	// The "admin:" username alone proves nothing (see admin_prefix_test.go).
	const adminPK = "ad00000000000000000000000000000000000000000000000000000000000009"
	h.config.Auth.AdminPubkeys = []string{adminPK}
	tok, _, err := auth.GenerateJWT(h.authConfig, adminPK, "admin:"+adminPK[:8])
	if err != nil {
		t.Fatal(err)
	}
	if code, got := auditGet(t, h, "", tok); code != http.StatusOK || len(got) != 5 {
		t.Fatalf("admin: %d %v, want 200 and all 5 events", code, got)
	}
	forged, _, _ := auth.GenerateJWT(h.authConfig, "admin-1", "admin:abcd1234")
	if code, got := auditGet(t, h, "", forged); code != http.StatusOK || len(got) != 0 {
		t.Fatalf("forged admin: username: %d %v, want only its own (no) events", code, got)
	}
	if code, got := auditGet(t, h, "?actor="+auditOtherUser, tok); code != http.StatusOK || len(got) != 2 {
		t.Fatalf("admin ?actor=other: %d %v, want 2 events", code, got)
	}
}
