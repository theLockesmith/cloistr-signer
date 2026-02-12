package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestNewMemoryLogger(t *testing.T) {
	tests := []struct {
		name      string
		maxEvents int
		wantMax   int
	}{
		{"default max", 0, 10000},
		{"negative max", -1, 10000},
		{"custom max", 500, 500},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := NewMemoryLogger(tt.maxEvents)
			if logger.maxLen != tt.wantMax {
				t.Errorf("NewMemoryLogger(%d).maxLen = %d, want %d", tt.maxEvents, logger.maxLen, tt.wantMax)
			}
		})
	}
}

func TestMemoryLogger_Log(t *testing.T) {
	ctx := context.Background()
	logger := NewMemoryLogger(100)

	event := &Event{
		Type:    EventUserLogin,
		Actor:   "user123",
		Action:  "logged in",
		Success: true,
	}

	err := logger.Log(ctx, event)
	if err != nil {
		t.Fatalf("Log() error = %v", err)
	}

	// Should have generated an ID
	if event.ID == "" {
		t.Error("Log() should generate ID if not set")
	}

	// Should have set timestamp
	if event.Timestamp.IsZero() {
		t.Error("Log() should set timestamp if not set")
	}

	if len(logger.events) != 1 {
		t.Errorf("events length = %d, want 1", len(logger.events))
	}
}

func TestMemoryLogger_LogWithExistingID(t *testing.T) {
	ctx := context.Background()
	logger := NewMemoryLogger(100)

	ts := time.Now().Add(-time.Hour)
	event := &Event{
		ID:        "existing-id",
		Timestamp: ts,
		Type:      EventKeyCreated,
		Success:   true,
	}

	err := logger.Log(ctx, event)
	if err != nil {
		t.Fatalf("Log() error = %v", err)
	}

	if event.ID != "existing-id" {
		t.Errorf("Log() should not overwrite existing ID")
	}

	if event.Timestamp != ts {
		t.Errorf("Log() should not overwrite existing timestamp")
	}
}

func TestMemoryLogger_LogTruncation(t *testing.T) {
	ctx := context.Background()
	maxEvents := 5
	logger := NewMemoryLogger(maxEvents)

	// Add more events than max
	for i := 0; i < 10; i++ {
		logger.Log(ctx, &Event{
			Type:    EventUserLogin,
			Success: true,
		})
	}

	if len(logger.events) != maxEvents {
		t.Errorf("events length = %d, want %d (should truncate)", len(logger.events), maxEvents)
	}
}

func TestMemoryLogger_Query(t *testing.T) {
	ctx := context.Background()
	logger := NewMemoryLogger(100)

	// Add various events
	now := time.Now()
	events := []*Event{
		{Type: EventUserLogin, Actor: "user1", Timestamp: now.Add(-3 * time.Hour), Success: true},
		{Type: EventUserLogin, Actor: "user2", Timestamp: now.Add(-2 * time.Hour), Success: true},
		{Type: EventKeyCreated, Actor: "admin1", Target: "key1", Timestamp: now.Add(-1 * time.Hour), Success: true},
		{Type: EventSignRequest, Actor: "client1", Target: "key1", Timestamp: now, Success: true},
	}

	for _, e := range events {
		logger.Log(ctx, e)
	}

	t.Run("filter by type", func(t *testing.T) {
		results, err := logger.Query(ctx, &Filter{Types: []EventType{EventUserLogin}})
		if err != nil {
			t.Fatalf("Query() error = %v", err)
		}
		if len(results) != 2 {
			t.Errorf("Query(type=UserLogin) = %d events, want 2", len(results))
		}
	})

	t.Run("filter by actor", func(t *testing.T) {
		results, err := logger.Query(ctx, &Filter{Actor: "user1"})
		if err != nil {
			t.Fatalf("Query() error = %v", err)
		}
		if len(results) != 1 {
			t.Errorf("Query(actor=user1) = %d events, want 1", len(results))
		}
	})

	t.Run("filter by target", func(t *testing.T) {
		results, err := logger.Query(ctx, &Filter{Target: "key1"})
		if err != nil {
			t.Fatalf("Query() error = %v", err)
		}
		if len(results) != 2 {
			t.Errorf("Query(target=key1) = %d events, want 2", len(results))
		}
	})

	t.Run("filter by time range", func(t *testing.T) {
		results, err := logger.Query(ctx, &Filter{
			StartTime: now.Add(-90 * time.Minute),
			EndTime:   now.Add(time.Minute),
		})
		if err != nil {
			t.Fatalf("Query() error = %v", err)
		}
		if len(results) != 2 {
			t.Errorf("Query(time range) = %d events, want 2", len(results))
		}
	})

	t.Run("with limit", func(t *testing.T) {
		results, err := logger.Query(ctx, &Filter{Limit: 2})
		if err != nil {
			t.Fatalf("Query() error = %v", err)
		}
		if len(results) != 2 {
			t.Errorf("Query(limit=2) = %d events, want 2", len(results))
		}
	})

	t.Run("with offset", func(t *testing.T) {
		results, err := logger.Query(ctx, &Filter{Offset: 2, Limit: 10})
		if err != nil {
			t.Fatalf("Query() error = %v", err)
		}
		if len(results) != 2 {
			t.Errorf("Query(offset=2) = %d events, want 2", len(results))
		}
	})

	t.Run("offset beyond results", func(t *testing.T) {
		results, err := logger.Query(ctx, &Filter{Offset: 100})
		if err != nil {
			t.Fatalf("Query() error = %v", err)
		}
		if len(results) != 0 {
			t.Errorf("Query(offset=100) = %d events, want 0", len(results))
		}
	})
}

func TestMemoryLogger_Close(t *testing.T) {
	logger := NewMemoryLogger(100)
	err := logger.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestJSONLogger_Log(t *testing.T) {
	var buf bytes.Buffer
	logger := NewJSONLogger(&buf)

	ctx := context.Background()
	event := &Event{
		Type:    EventUserLogin,
		Actor:   "user123",
		Action:  "logged in",
		Success: true,
	}

	err := logger.Log(ctx, event)
	if err != nil {
		t.Fatalf("Log() error = %v", err)
	}

	// Verify JSON output
	var logged Event
	if err := json.Unmarshal(buf.Bytes(), &logged); err != nil {
		t.Fatalf("failed to unmarshal logged event: %v", err)
	}

	if logged.Type != EventUserLogin {
		t.Errorf("logged Type = %q, want %q", logged.Type, EventUserLogin)
	}
	if logged.Actor != "user123" {
		t.Errorf("logged Actor = %q, want %q", logged.Actor, "user123")
	}
	if logged.ID == "" {
		t.Error("logged ID should not be empty")
	}
}

func TestJSONLogger_Query(t *testing.T) {
	var buf bytes.Buffer
	logger := NewJSONLogger(&buf)

	ctx := context.Background()
	_, err := logger.Query(ctx, &Filter{})
	if err == nil {
		t.Error("Query() should return error for JSON logger")
	}
}

func TestJSONLogger_Close(t *testing.T) {
	var buf bytes.Buffer
	logger := NewJSONLogger(&buf)
	err := logger.Close()
	if err != nil {
		t.Errorf("Close() error = %v", err)
	}
}

func TestNewSignEvent(t *testing.T) {
	// Use 64-char pubkeys to avoid truncation issues in NewSignEvent
	clientPubkey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	keyPubkey := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	event := NewSignEvent(EventSignRequest, clientPubkey, keyPubkey, "sign_event", 1, true, "")

	if event.Type != EventSignRequest {
		t.Errorf("Type = %q, want %q", event.Type, EventSignRequest)
	}
	if event.Actor != clientPubkey {
		t.Errorf("Actor = %q, want %q", event.Actor, clientPubkey)
	}
	if event.Target != keyPubkey {
		t.Errorf("Target = %q, want %q", event.Target, keyPubkey)
	}
	if event.ActorType != "client" {
		t.Errorf("ActorType = %q, want %q", event.ActorType, "client")
	}
	if event.TargetType != "key" {
		t.Errorf("TargetType = %q, want %q", event.TargetType, "key")
	}
	if !event.Success {
		t.Error("Success should be true")
	}
	if event.Details["method"] != "sign_event" {
		t.Errorf("Details[method] = %v, want %q", event.Details["method"], "sign_event")
	}
	if event.Details["event_kind"] != 1 {
		t.Errorf("Details[event_kind] = %v, want %d", event.Details["event_kind"], 1)
	}
}

func TestNewSignEventNoKind(t *testing.T) {
	// Use 64-char pubkeys to avoid truncation issues
	clientPubkey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	keyPubkey := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	event := NewSignEvent(EventSignRequest, clientPubkey, keyPubkey, "ping", 0, true, "")

	if _, ok := event.Details["event_kind"]; ok {
		t.Error("event_kind should not be set when kind is 0")
	}
}

func TestNewSignEventWithError(t *testing.T) {
	// Use 64-char pubkeys to avoid truncation issues
	clientPubkey := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	keyPubkey := "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
	event := NewSignEvent(EventSignFailed, clientPubkey, keyPubkey, "sign_event", 1, false, "permission denied")

	if event.Success {
		t.Error("Success should be false")
	}
	if event.ErrorReason != "permission denied" {
		t.Errorf("ErrorReason = %q, want %q", event.ErrorReason, "permission denied")
	}
}

func TestNewUserEvent(t *testing.T) {
	event := NewUserEvent(EventUserLogin, "user123", "testuser", "logged in", true, "192.168.1.1", "Mozilla/5.0")

	if event.Type != EventUserLogin {
		t.Errorf("Type = %q, want %q", event.Type, EventUserLogin)
	}
	if event.Actor != "user123" {
		t.Errorf("Actor = %q, want %q", event.Actor, "user123")
	}
	if event.Target != "testuser" {
		t.Errorf("Target = %q, want %q", event.Target, "testuser")
	}
	if event.ActorType != "user" {
		t.Errorf("ActorType = %q, want %q", event.ActorType, "user")
	}
	if event.IPAddress != "192.168.1.1" {
		t.Errorf("IPAddress = %q, want %q", event.IPAddress, "192.168.1.1")
	}
	if event.UserAgent != "Mozilla/5.0" {
		t.Errorf("UserAgent = %q, want %q", event.UserAgent, "Mozilla/5.0")
	}
}

func TestNewKeyEvent(t *testing.T) {
	event := NewKeyEvent(EventKeyCreated, "admin123", "key456", "created key", true)

	if event.Type != EventKeyCreated {
		t.Errorf("Type = %q, want %q", event.Type, EventKeyCreated)
	}
	if event.Actor != "admin123" {
		t.Errorf("Actor = %q, want %q", event.Actor, "admin123")
	}
	if event.Target != "key456" {
		t.Errorf("Target = %q, want %q", event.Target, "key456")
	}
	if event.ActorType != "admin" {
		t.Errorf("ActorType = %q, want %q", event.ActorType, "admin")
	}
	if event.TargetType != "key" {
		t.Errorf("TargetType = %q, want %q", event.TargetType, "key")
	}
}

func TestNewAdminEvent(t *testing.T) {
	event := NewAdminEvent("adminpub123", "get_keys", true)

	if event.Type != EventAdminCommand {
		t.Errorf("Type = %q, want %q", event.Type, EventAdminCommand)
	}
	if event.Actor != "adminpub123" {
		t.Errorf("Actor = %q, want %q", event.Actor, "adminpub123")
	}
	if event.ActorType != "admin" {
		t.Errorf("ActorType = %q, want %q", event.ActorType, "admin")
	}
	if event.Action != "get_keys" {
		t.Errorf("Action = %q, want %q", event.Action, "get_keys")
	}
	if event.Details["command"] != "get_keys" {
		t.Errorf("Details[command] = %v, want %q", event.Details["command"], "get_keys")
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		input string
		n     int
		want  string
	}{
		{"hello", 10, "hello"},
		{"hello world", 5, "hello..."},
		{"abc", 3, "abc"},
		{"", 5, ""},
	}

	for _, tt := range tests {
		got := truncate(tt.input, tt.n)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.n, got, tt.want)
		}
	}
}

func TestEventTypes(t *testing.T) {
	// Verify event type constants are defined
	types := []EventType{
		EventKeyCreated,
		EventKeyDeleted,
		EventKeyAccessed,
		EventSignRequest,
		EventSignApproved,
		EventSignDenied,
		EventSignCompleted,
		EventSignFailed,
		EventUserLogin,
		EventUserLoginFailed,
		EventUserLogout,
		EventUserCreated,
		EventUserMFAEnabled,
		EventUserMFADisabled,
		EventUserLocked,
		EventPermissionGranted,
		EventPermissionRevoked,
		EventAdminCommand,
	}

	for _, et := range types {
		if et == "" {
			t.Errorf("EventType should not be empty")
		}
	}
}
