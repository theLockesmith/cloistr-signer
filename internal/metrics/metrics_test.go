package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// Helper to get metric value from a counter vec
func getCounterValue(cv *prometheus.CounterVec, labels ...string) float64 {
	m := &dto.Metric{}
	if err := cv.WithLabelValues(labels...).Write(m); err != nil {
		return 0
	}
	return m.Counter.GetValue()
}

// Helper to get metric value from a gauge
func getGaugeValue(g prometheus.Gauge) float64 {
	m := &dto.Metric{}
	if err := g.Write(m); err != nil {
		return 0
	}
	return m.Gauge.GetValue()
}

// Handler Tests

func TestHandler(t *testing.T) {
	handler := Handler()
	if handler == nil {
		t.Fatal("Handler() returned nil")
	}

	// Verify it responds to requests
	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Handler() status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Should contain prometheus metrics format
	body := rr.Body.String()
	if !strings.Contains(body, "coldforge_signer") {
		t.Error("Handler() response should contain coldforge_signer metrics")
	}
}

// responseWriter Tests

func TestResponseWriter_WriteHeader(t *testing.T) {
	rr := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: rr, status: http.StatusOK}

	rw.WriteHeader(http.StatusNotFound)

	if rw.status != http.StatusNotFound {
		t.Errorf("WriteHeader() status = %d, want %d", rw.status, http.StatusNotFound)
	}
	if !rw.wroteHeader {
		t.Error("WriteHeader() should set wroteHeader to true")
	}
	if rr.Code != http.StatusNotFound {
		t.Errorf("WriteHeader() underlying status = %d, want %d", rr.Code, http.StatusNotFound)
	}
}

func TestResponseWriter_WriteHeaderOnlyOnce(t *testing.T) {
	rr := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: rr, status: http.StatusOK}

	rw.WriteHeader(http.StatusNotFound)
	rw.WriteHeader(http.StatusInternalServerError) // Should be ignored

	if rw.status != http.StatusNotFound {
		t.Errorf("WriteHeader() called twice, status = %d, want %d", rw.status, http.StatusNotFound)
	}
}

func TestResponseWriter_Write(t *testing.T) {
	rr := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: rr, status: http.StatusOK}

	n, err := rw.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n != 5 {
		t.Errorf("Write() = %d bytes, want 5", n)
	}
	if !rw.wroteHeader {
		t.Error("Write() should set wroteHeader to true")
	}
	if rw.status != http.StatusOK {
		t.Errorf("Write() should default status to 200, got %d", rw.status)
	}
}

func TestResponseWriter_WriteAfterWriteHeader(t *testing.T) {
	rr := httptest.NewRecorder()
	rw := &responseWriter{ResponseWriter: rr, status: http.StatusOK}

	rw.WriteHeader(http.StatusCreated)
	rw.Write([]byte("created"))

	if rw.status != http.StatusCreated {
		t.Errorf("Write() after WriteHeader() status = %d, want %d", rw.status, http.StatusCreated)
	}
}

// Middleware Tests

func TestMiddleware_RecordsMetrics(t *testing.T) {
	// Create a simple handler
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Wrap with middleware
	wrapped := Middleware(handler)

	// Make a request
	req := httptest.NewRequest("GET", "/api/v1/keys", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Middleware() status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Verify metrics were recorded (check counter increased)
	value := getCounterValue(RequestsTotal, "GET", "/api/v1/keys", "200")
	if value < 1 {
		t.Error("Middleware() should increment RequestsTotal counter")
	}
}

func TestMiddleware_SkipsMetricsEndpoint(t *testing.T) {
	callCount := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)
	})

	wrapped := Middleware(handler)

	// Request to /metrics should still be served but not recorded
	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()

	// Get initial counter value
	initialValue := getCounterValue(RequestsTotal, "GET", "/metrics", "200")

	wrapped.ServeHTTP(rr, req)

	if callCount != 1 {
		t.Error("Middleware() should still call handler for /metrics")
	}

	// Counter should not increase for /metrics endpoint
	finalValue := getCounterValue(RequestsTotal, "GET", "/metrics", "200")
	if finalValue != initialValue {
		t.Error("Middleware() should not record metrics for /metrics endpoint")
	}
}

func TestMiddleware_RecordsErrorStatus(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	wrapped := Middleware(handler)

	req := httptest.NewRequest("POST", "/api/v1/keys", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Middleware() status = %d, want %d", rr.Code, http.StatusInternalServerError)
	}

	value := getCounterValue(RequestsTotal, "POST", "/api/v1/keys", "500")
	if value < 1 {
		t.Error("Middleware() should record 500 status")
	}
}

func TestMiddleware_NormalizesPath(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := Middleware(handler)

	// Request with ID in path
	req := httptest.NewRequest("GET", "/api/v1/keys/abc123-def456", nil)
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	// Should be normalized to /api/v1/keys/:id
	value := getCounterValue(RequestsTotal, "GET", "/api/v1/keys/:id", "200")
	if value < 1 {
		t.Error("Middleware() should normalize path with ID")
	}
}

// normalizePath Tests

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		// Keys endpoints
		{"/api/v1/keys", "/api/v1/keys"},
		{"/api/v1/keys/abc123", "/api/v1/keys/:id"},
		{"/api/v1/keys/abc123/permissions", "/api/v1/keys/:id/permissions"},

		// Requests endpoints
		{"/api/v1/requests", "/api/v1/requests"},
		{"/api/v1/requests/req-123", "/api/v1/requests/:id"},

		// Bunker endpoints
		{"/api/v1/bunker/key-456", "/api/v1/bunker/:id"},

		// Tokens endpoints
		{"/api/v1/tokens/tok-789", "/api/v1/tokens/:id"},

		// Policies endpoints
		{"/api/v1/policies/pol-abc", "/api/v1/policies/:id"},

		// Approve endpoints
		{"/approve/req-123", "/approve/:id"},

		// Other paths (unchanged)
		{"/health", "/health"},
		{"/health/live", "/health/live"},
		{"/api/v1/users/login", "/api/v1/users/login"},
		{"/", "/"},
		{"/dashboard", "/dashboard"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizePath(tt.input)
			if got != tt.expected {
				t.Errorf("normalizePath(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// indexOf Tests

func TestIndexOf(t *testing.T) {
	tests := []struct {
		s        string
		c        byte
		expected int
	}{
		{"hello", 'e', 1},
		{"hello", 'l', 2},
		{"hello", 'o', 4},
		{"hello", 'x', -1},
		{"", 'a', -1},
		{"abc/def", '/', 3},
		{"/path/to/file", '/', 0},
	}

	for _, tt := range tests {
		t.Run(tt.s, func(t *testing.T) {
			got := indexOf(tt.s, tt.c)
			if got != tt.expected {
				t.Errorf("indexOf(%q, %q) = %d, want %d", tt.s, tt.c, got, tt.expected)
			}
		})
	}
}

// RecordSigningRequest Tests

func TestRecordSigningRequest_Success(t *testing.T) {
	initialValue := getCounterValue(SigningRequestsTotal, "sign_event", "success")

	RecordSigningRequest("sign_event", true)

	finalValue := getCounterValue(SigningRequestsTotal, "sign_event", "success")
	if finalValue != initialValue+1 {
		t.Errorf("RecordSigningRequest(success) did not increment counter, got %f, want %f", finalValue, initialValue+1)
	}
}

func TestRecordSigningRequest_Error(t *testing.T) {
	initialValue := getCounterValue(SigningRequestsTotal, "sign_event", "error")

	RecordSigningRequest("sign_event", false)

	finalValue := getCounterValue(SigningRequestsTotal, "sign_event", "error")
	if finalValue != initialValue+1 {
		t.Errorf("RecordSigningRequest(error) did not increment counter, got %f, want %f", finalValue, initialValue+1)
	}
}

func TestRecordSigningRequest_DifferentMethods(t *testing.T) {
	methods := []string{"ping", "get_public_key", "nip04_encrypt", "nip44_decrypt"}

	for _, method := range methods {
		initialValue := getCounterValue(SigningRequestsTotal, method, "success")
		RecordSigningRequest(method, true)
		finalValue := getCounterValue(SigningRequestsTotal, method, "success")

		if finalValue != initialValue+1 {
			t.Errorf("RecordSigningRequest(%s) did not increment counter", method)
		}
	}
}

// RecordError Tests

func TestRecordError(t *testing.T) {
	errorTypes := []string{"auth_failed", "invalid_request", "storage_error", "relay_error"}

	for _, errorType := range errorTypes {
		initialValue := getCounterValue(ErrorsTotal, errorType)
		RecordError(errorType)
		finalValue := getCounterValue(ErrorsTotal, errorType)

		if finalValue != initialValue+1 {
			t.Errorf("RecordError(%s) did not increment counter", errorType)
		}
	}
}

// Gauge Setter Tests

func TestSetRelayConnections(t *testing.T) {
	SetRelayConnections(5)

	value := getGaugeValue(ActiveRelayConnections)
	if value != 5 {
		t.Errorf("SetRelayConnections(5) = %f, want 5", value)
	}

	SetRelayConnections(0)
	value = getGaugeValue(ActiveRelayConnections)
	if value != 0 {
		t.Errorf("SetRelayConnections(0) = %f, want 0", value)
	}
}

func TestSetKeysManaged(t *testing.T) {
	SetKeysManaged(10)

	value := getGaugeValue(KeysManaged)
	if value != 10 {
		t.Errorf("SetKeysManaged(10) = %f, want 10", value)
	}

	SetKeysManaged(3)
	value = getGaugeValue(KeysManaged)
	if value != 3 {
		t.Errorf("SetKeysManaged(3) = %f, want 3", value)
	}
}

func TestSetPendingRequests(t *testing.T) {
	SetPendingRequests(7)

	value := getGaugeValue(PendingRequests)
	if value != 7 {
		t.Errorf("SetPendingRequests(7) = %f, want 7", value)
	}

	SetPendingRequests(0)
	value = getGaugeValue(PendingRequests)
	if value != 0 {
		t.Errorf("SetPendingRequests(0) = %f, want 0", value)
	}
}

// Integration test - verify all metrics are properly registered

func TestMetricsRegistered(t *testing.T) {
	// These should not panic if metrics are properly registered
	RequestsTotal.WithLabelValues("GET", "/test", "200").Inc()
	RequestDuration.WithLabelValues("GET", "/test").Observe(0.1)
	ErrorsTotal.WithLabelValues("test_error").Inc()
	SigningRequestsTotal.WithLabelValues("test_method", "success").Inc()
	ActiveRelayConnections.Set(1)
	KeysManaged.Set(1)
	PendingRequests.Set(1)
	ActiveSessions.Set(1)

	// If we get here without panic, metrics are registered
}
