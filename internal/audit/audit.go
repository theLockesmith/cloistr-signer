package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// EventType represents the type of audit event
type EventType string

const (
	// Key events
	EventKeyCreated  EventType = "key.created"
	EventKeyDeleted  EventType = "key.deleted"
	EventKeyAccessed EventType = "key.accessed"

	// Signing events
	EventSignRequest   EventType = "sign.request"
	EventSignApproved  EventType = "sign.approved"
	EventSignDenied    EventType = "sign.denied"
	EventSignCompleted EventType = "sign.completed"
	EventSignFailed    EventType = "sign.failed"

	// Auth events
	EventUserLogin       EventType = "user.login"
	EventUserLoginFailed EventType = "user.login_failed"
	EventUserLogout      EventType = "user.logout"
	EventUserCreated     EventType = "user.created"
	EventUserMFAEnabled  EventType = "user.mfa_enabled"
	EventUserMFADisabled EventType = "user.mfa_disabled"
	EventUserLocked      EventType = "user.locked"

	// Permission events
	EventPermissionGranted EventType = "permission.granted"
	EventPermissionRevoked EventType = "permission.revoked"

	// Admin events
	EventAdminCommand EventType = "admin.command"
)

// Event represents an audit log entry
type Event struct {
	ID          string                 `json:"id"`
	Timestamp   time.Time              `json:"timestamp"`
	Type        EventType              `json:"type"`
	Actor       string                 `json:"actor,omitempty"`       // Who performed the action (pubkey or user ID)
	ActorType   string                 `json:"actor_type,omitempty"`  // "user", "client", "admin", "system"
	Target      string                 `json:"target,omitempty"`      // What was affected (key pubkey, user ID, etc)
	TargetType  string                 `json:"target_type,omitempty"` // "key", "user", "permission", etc
	Action      string                 `json:"action,omitempty"`      // Human-readable action description
	Details     map[string]interface{} `json:"details,omitempty"`     // Additional context
	IPAddress   string                 `json:"ip_address,omitempty"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	Success     bool                   `json:"success"`
	ErrorReason string                 `json:"error_reason,omitempty"`
}

// Logger is the audit logger interface
type Logger interface {
	Log(ctx context.Context, event *Event) error
	Query(ctx context.Context, filter *Filter) ([]*Event, error)
	Close() error
}

// Filter for querying audit logs
type Filter struct {
	Types     []EventType
	Actor     string
	Target    string
	StartTime time.Time
	EndTime   time.Time
	Limit     int
	Offset    int
}

// MemoryLogger stores audit logs in memory (for development/testing)
type MemoryLogger struct {
	mu     sync.RWMutex
	events []*Event
	maxLen int
}

// NewMemoryLogger creates a new in-memory audit logger
func NewMemoryLogger(maxEvents int) *MemoryLogger {
	if maxEvents <= 0 {
		maxEvents = 10000
	}
	return &MemoryLogger{
		events: make([]*Event, 0),
		maxLen: maxEvents,
	}
}

// Log records an audit event
func (l *MemoryLogger) Log(ctx context.Context, event *Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	// Generate ID if not set
	if event.ID == "" {
		event.ID = fmt.Sprintf("%d-%d", time.Now().UnixNano(), len(l.events))
	}

	// Set timestamp if not set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Append event
	l.events = append(l.events, event)

	// Trim if too long (keep most recent)
	if len(l.events) > l.maxLen {
		l.events = l.events[len(l.events)-l.maxLen:]
	}

	// Also log to slog for observability
	logEvent(event)

	return nil
}

// Query retrieves audit events matching the filter
func (l *MemoryLogger) Query(ctx context.Context, filter *Filter) ([]*Event, error) {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var results []*Event

	for i := len(l.events) - 1; i >= 0; i-- {
		event := l.events[i]

		// Apply filters
		if len(filter.Types) > 0 {
			found := false
			for _, t := range filter.Types {
				if event.Type == t {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		if filter.Actor != "" && event.Actor != filter.Actor {
			continue
		}

		if filter.Target != "" && event.Target != filter.Target {
			continue
		}

		if !filter.StartTime.IsZero() && event.Timestamp.Before(filter.StartTime) {
			continue
		}

		if !filter.EndTime.IsZero() && event.Timestamp.After(filter.EndTime) {
			continue
		}

		results = append(results, event)

		if filter.Limit > 0 && len(results) >= filter.Limit+filter.Offset {
			break
		}
	}

	// Apply offset
	if filter.Offset > 0 && filter.Offset < len(results) {
		results = results[filter.Offset:]
	} else if filter.Offset >= len(results) {
		results = []*Event{}
	}

	// Apply limit
	if filter.Limit > 0 && len(results) > filter.Limit {
		results = results[:filter.Limit]
	}

	return results, nil
}

// Close closes the logger
func (l *MemoryLogger) Close() error {
	return nil
}

// Helper to log to slog
func logEvent(event *Event) {
	attrs := []any{
		"audit_id", event.ID,
		"type", event.Type,
		"success", event.Success,
	}

	if event.Actor != "" {
		attrs = append(attrs, "actor", truncate(event.Actor, 20))
	}
	if event.Target != "" {
		attrs = append(attrs, "target", truncate(event.Target, 20))
	}
	if event.Action != "" {
		attrs = append(attrs, "action", event.Action)
	}
	if event.ErrorReason != "" {
		attrs = append(attrs, "error", event.ErrorReason)
	}

	if event.Success {
		slog.Info("audit", attrs...)
	} else {
		slog.Warn("audit", attrs...)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// JSONLogger writes audit logs as JSON to an io.Writer
type JSONLogger struct {
	mu      sync.Mutex
	encoder *json.Encoder
}

// NewJSONLogger creates a JSON logger
func NewJSONLogger(w interface{ Write([]byte) (int, error) }) *JSONLogger {
	return &JSONLogger{
		encoder: json.NewEncoder(w),
	}
}

// Log records an audit event as JSON
func (l *JSONLogger) Log(ctx context.Context, event *Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if event.ID == "" {
		event.ID = fmt.Sprintf("%d", time.Now().UnixNano())
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	return l.encoder.Encode(event)
}

// Query is not supported for JSON logger
func (l *JSONLogger) Query(ctx context.Context, filter *Filter) ([]*Event, error) {
	return nil, fmt.Errorf("query not supported for JSON logger")
}

// Close closes the logger
func (l *JSONLogger) Close() error {
	return nil
}

// Helper functions to create common audit events

// NewSignEvent creates a signing-related audit event
func NewSignEvent(eventType EventType, clientPubkey, keyPubkey, method string, eventKind int, success bool, errReason string) *Event {
	details := map[string]interface{}{
		"method": method,
	}
	if eventKind > 0 {
		details["event_kind"] = eventKind
	}

	return &Event{
		Type:        eventType,
		Actor:       clientPubkey,
		ActorType:   "client",
		Target:      keyPubkey,
		TargetType:  "key",
		Action:      fmt.Sprintf("%s request for %s", method, keyPubkey[:16]+"..."),
		Details:     details,
		Success:     success,
		ErrorReason: errReason,
	}
}

// NewUserEvent creates a user-related audit event
func NewUserEvent(eventType EventType, userID, username, action string, success bool, ip, ua string) *Event {
	return &Event{
		Type:       eventType,
		Actor:      userID,
		ActorType:  "user",
		Target:     username,
		TargetType: "user",
		Action:     action,
		Success:    success,
		IPAddress:  ip,
		UserAgent:  ua,
	}
}

// NewKeyEvent creates a key-related audit event
func NewKeyEvent(eventType EventType, actor, keyPubkey, action string, success bool) *Event {
	return &Event{
		Type:       eventType,
		Actor:      actor,
		ActorType:  "admin",
		Target:     keyPubkey,
		TargetType: "key",
		Action:     action,
		Success:    success,
	}
}

// NewAdminEvent creates an admin command audit event
func NewAdminEvent(adminPubkey, command string, success bool) *Event {
	return &Event{
		Type:       EventAdminCommand,
		Actor:      adminPubkey,
		ActorType:  "admin",
		Action:     command,
		Success:    success,
		Details: map[string]interface{}{
			"command": command,
		},
	}
}
