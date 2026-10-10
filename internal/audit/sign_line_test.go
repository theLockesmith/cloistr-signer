package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

const (
	acct   = "041a7196234085aaa0b6c0ffee00000000000000000000000000000000000001"
	client = "4ae29c0ba74316541d7c0ffee000000000000000000000000000000000000002"
)

// The sign.completed log line is the durable accountability record: it must
// carry full pubkeys, kind, event id, method, pod, time and outcome.
func TestSignLine_CarriesAccountabilityFields(t *testing.T) {
	buf := captureSlog(t)
	e := NewSignEvent(EventSignCompleted, client, acct, "sign_event", 1, true, "")
	e.Details["event_id"] = "eeee"
	if err := NewMemoryLogger(10).Log(context.Background(), e); err != nil {
		t.Fatal(err)
	}

	var line map[string]any
	if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
		t.Fatalf("log line not JSON: %v: %s", err, buf.String())
	}
	want := map[string]any{
		"type": "sign.completed", "account_pubkey": acct, "client_pubkey": client,
		"method": "sign_event", "event_kind": float64(1), "event_id": "eeee", "outcome": "signed",
	}
	for k, v := range want {
		if line[k] != v {
			t.Errorf("%s = %v, want %v", k, line[k], v)
		}
	}
	for _, k := range []string{"pod", "at"} {
		if s, _ := line[k].(string); s == "" {
			t.Errorf("%s missing", k)
		}
	}
}

func TestSignLine_FailureCarriesReason(t *testing.T) {
	buf := captureSlog(t)
	e := NewSignEvent(EventSignFailed, client, acct, "sign_event", 4, false, "kind 4 not allowed")
	_ = NewMemoryLogger(10).Log(context.Background(), e)

	var line map[string]any
	_ = json.Unmarshal(buf.Bytes(), &line)
	if line["outcome"] != "failed" || line["reason"] != "kind 4 not allowed" {
		t.Fatalf("outcome/reason = %v/%v, want failed/\"kind 4 not allowed\"", line["outcome"], line["reason"])
	}
}

// Non-sign events keep the short form.
func TestNonSignLine_Unchanged(t *testing.T) {
	buf := captureSlog(t)
	_ = NewMemoryLogger(10).Log(context.Background(), NewUserEvent("user.login", "u1", "alice", "login", true, "", ""))
	if strings.Contains(buf.String(), "account_pubkey") {
		t.Fatalf("user event got sign fields: %s", buf.String())
	}
}
