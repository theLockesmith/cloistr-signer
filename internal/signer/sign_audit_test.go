package signer

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/audit"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/config"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
	"github.com/nbd-wtf/go-nostr"
)

func signReq(t *testing.T, method string, kinds ...int) *NIP46Request {
	t.Helper()
	params := make([]string, 0, len(kinds))
	for i, k := range kinds {
		ev, _ := json.Marshal(map[string]any{
			"kind": k, "content": fmt.Sprintf("secret content %d", i), "created_at": time.Now().Unix(), "tags": [][]string{},
		})
		params = append(params, string(ev))
	}
	return &NIP46Request{ID: "r", Method: method, Params: params}
}

// Every signature leaves exactly one sign.completed record naming the account,
// the client, the kind and the signed event id; failures leave sign.failed.
func TestSignAudit_OneRecordPerSignature(t *testing.T) {
	logger := audit.NewMemoryLogger(100)
	s := New(&config.Config{}, storage.NewMemoryStorage(), nil, nil, nil, nil, logger)
	priv := nostr.GeneratePrivateKey()
	account, _ := nostr.GetPublicKey(priv)
	s.RegisterKey(account, priv)
	client, _ := nostr.GetPublicKey(nostr.GeneratePrivateKey())
	perm := &storage.Permission{KeyID: account, UserPubkey: client, Methods: []string{"sign_event", "batch_sign"}, AllowedKinds: []int{1, 7}}
	ctx := context.Background()

	var wantIDs []string
	for i := 0; i < 3; i++ {
		res, err := s.handleRequest(ctx, account, priv, client, signReq(t, "sign_event", 1), perm)
		if err != nil {
			t.Fatal(err)
		}
		var ev nostr.Event
		_ = json.Unmarshal([]byte(res), &ev)
		wantIDs = append(wantIDs, ev.ID)
	}
	res, err := s.handleRequest(ctx, account, priv, client, signReq(t, "batch_sign", 1, 7), perm)
	if err != nil {
		t.Fatal(err)
	}
	var batch []nostr.Event
	_ = json.Unmarshal([]byte(res), &batch)
	for _, ev := range batch {
		wantIDs = append(wantIDs, ev.ID)
	}
	if _, err := s.handleRequest(ctx, account, priv, client, signReq(t, "sign_event", 4), perm); err == nil {
		t.Fatal("kind 4 should be refused by the permission")
	}

	completed, _ := logger.Query(ctx, &audit.Filter{Types: []audit.EventType{audit.EventSignCompleted}})
	if len(completed) != len(wantIDs) {
		t.Fatalf("sign.completed records = %d, want %d (one per signature)", len(completed), len(wantIDs))
	}
	got := map[string]bool{}
	for _, e := range completed {
		if e.Actor != client || e.Target != account {
			t.Errorf("record actor/target = %s/%s, want client %s / account %s", e.Actor, e.Target, client, account)
		}
		id, _ := e.Details["event_id"].(string)
		got[id] = true
		if _, ok := e.Details["event_kind"]; !ok {
			t.Errorf("record %s has no event_kind", id)
		}
		if _, ok := e.Details["content"]; ok {
			t.Error("record carries event content")
		}
	}
	for _, id := range wantIDs {
		if !got[id] {
			t.Errorf("no sign.completed record for signed event %s", id)
		}
	}

	failed, _ := logger.Query(ctx, &audit.Filter{Types: []audit.EventType{audit.EventSignFailed}})
	if len(failed) != 1 || failed[0].ErrorReason == "" || failed[0].Details["event_kind"] != 4 {
		t.Fatalf("sign.failed records = %+v, want one with a reason and kind 4", failed)
	}
}

func addressableReq(t *testing.T, kind int, d string) *NIP46Request {
	t.Helper()
	ev, _ := json.Marshal(map[string]any{
		"kind": kind, "content": "page body that must never be logged", "created_at": time.Now().Unix(),
		"tags": [][]string{{"title", "x"}, {"d", d}},
	})
	return &NIP46Request{ID: "r", Method: "sign_event", Params: []string{string(ev)}}
}

// An addressable event's record carries its d tag, signed or refused, so a stray
// publication can be traced to the page it touched with one grep.
func TestSignAudit_RecordsDTag(t *testing.T) {
	logger := audit.NewMemoryLogger(100)
	s := New(&config.Config{}, storage.NewMemoryStorage(), nil, nil, nil, nil, logger)
	priv := nostr.GeneratePrivateKey()
	account, _ := nostr.GetPublicKey(priv)
	s.RegisterKey(account, priv)
	client, _ := nostr.GetPublicKey(nostr.GeneratePrivateKey())
	perm := &storage.Permission{KeyID: account, UserPubkey: client, Methods: []string{"sign_event"}, AllowedKinds: []int{30023, 1}}
	ctx := context.Background()

	if _, err := s.handleRequest(ctx, account, priv, client, addressableReq(t, 30023, "my-page"), perm); err != nil {
		t.Fatal(err)
	}
	if _, err := s.handleRequest(ctx, account, priv, client, addressableReq(t, 30024, "draft-page"), perm); err == nil {
		t.Fatal("kind 30024 should be refused by the permission")
	}
	if _, err := s.handleRequest(ctx, account, priv, client, signReq(t, "sign_event", 1), perm); err != nil {
		t.Fatal(err)
	}

	completed, _ := logger.Query(ctx, &audit.Filter{Types: []audit.EventType{audit.EventSignCompleted}})
	byKind := map[any]*audit.Event{}
	for _, e := range completed {
		byKind[e.Details["event_kind"]] = e
	}
	if e := byKind[30023]; e == nil || e.Details["d_tag"] != "my-page" {
		t.Fatalf("kind 30023 record = %+v, want d_tag my-page", e)
	}
	if e := byKind[1]; e == nil {
		t.Fatal("no record for the kind 1 signature")
	} else if _, ok := e.Details["d_tag"]; ok {
		t.Fatalf("kind 1 record has a d_tag it never carried: %+v", e.Details)
	}
	failed, _ := logger.Query(ctx, &audit.Filter{Types: []audit.EventType{audit.EventSignFailed}})
	if len(failed) != 1 || failed[0].Details["d_tag"] != "draft-page" {
		t.Fatalf("sign.failed records = %+v, want one with d_tag draft-page", failed)
	}
	for _, e := range append(completed, failed...) {
		b, _ := json.Marshal(e)
		if strings.Contains(string(b), "must never be logged") {
			t.Fatalf("record carries event content: %s", b)
		}
	}
}
