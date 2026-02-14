package metrics

import (
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	// Standard HTTP metrics (required for all services)
	RequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "coldforge_signer_requests_total",
			Help: "Total HTTP requests processed",
		},
		[]string{"method", "path", "status"},
	)

	RequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "coldforge_signer_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{"method", "path"},
	)

	ErrorsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "coldforge_signer_errors_total",
			Help: "Total errors by type",
		},
		[]string{"type"},
	)

	// Signer-specific metrics
	SigningRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "coldforge_signer_signing_requests_total",
			Help: "Total NIP-46 signing requests",
		},
		[]string{"method", "status"},
	)

	ActiveRelayConnections = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "coldforge_signer_relay_connections_active",
			Help: "Number of active relay connections",
		},
	)

	KeysManaged = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "coldforge_signer_keys_managed",
			Help: "Number of keys being managed",
		},
	)

	PendingRequests = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "coldforge_signer_pending_requests",
			Help: "Number of pending authorization requests",
		},
	)

	ActiveSessions = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "coldforge_signer_sessions_active",
			Help: "Number of active user sessions",
		},
	)
)

// Handler returns the Prometheus metrics handler
func Handler() http.Handler {
	return promhttp.Handler()
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

func (rw *responseWriter) WriteHeader(code int) {
	if !rw.wroteHeader {
		rw.status = code
		rw.wroteHeader = true
	}
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	return rw.ResponseWriter.Write(b)
}

// Middleware wraps an http.Handler to record metrics
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip metrics endpoint itself to avoid recursion
		if r.URL.Path == "/metrics" {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		duration := time.Since(start)

		// Normalize path for metrics (avoid high cardinality)
		path := normalizePath(r.URL.Path)

		RequestsTotal.WithLabelValues(r.Method, path, strconv.Itoa(wrapped.status)).Inc()
		RequestDuration.WithLabelValues(r.Method, path).Observe(duration.Seconds())
	})
}

// normalizePath normalizes URL paths to avoid high cardinality metrics
func normalizePath(path string) string {
	// Replace UUIDs and IDs with placeholders
	// Common patterns: /api/v1/keys/{id}, /api/v1/requests/{id}, etc.
	switch {
	case len(path) > 13 && path[:13] == "/api/v1/keys/":
		if len(path) > 13 {
			rest := path[13:]
			if idx := indexOf(rest, '/'); idx > 0 {
				return "/api/v1/keys/:id/" + rest[idx+1:]
			}
			return "/api/v1/keys/:id"
		}
	case len(path) > 17 && path[:17] == "/api/v1/requests/":
		return "/api/v1/requests/:id"
	case len(path) > 15 && path[:15] == "/api/v1/bunker/":
		return "/api/v1/bunker/:id"
	case len(path) > 15 && path[:15] == "/api/v1/tokens/":
		return "/api/v1/tokens/:id"
	case len(path) > 17 && path[:17] == "/api/v1/policies/":
		return "/api/v1/policies/:id"
	case len(path) > 9 && path[:9] == "/approve/":
		return "/approve/:id"
	}
	return path
}

func indexOf(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// RecordSigningRequest records a NIP-46 signing request
func RecordSigningRequest(method string, success bool) {
	status := "success"
	if !success {
		status = "error"
	}
	SigningRequestsTotal.WithLabelValues(method, status).Inc()
}

// RecordError records an error by type
func RecordError(errorType string) {
	ErrorsTotal.WithLabelValues(errorType).Inc()
}

// SetRelayConnections sets the number of active relay connections
func SetRelayConnections(count int) {
	ActiveRelayConnections.Set(float64(count))
}

// SetKeysManaged sets the number of managed keys
func SetKeysManaged(count int) {
	KeysManaged.Set(float64(count))
}

// SetPendingRequests sets the number of pending requests
func SetPendingRequests(count int) {
	PendingRequests.Set(float64(count))
}
