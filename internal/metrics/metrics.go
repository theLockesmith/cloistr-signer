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

	// Phase 13: Performance metrics

	// SigningLatency measures NIP-46 operation latency by method
	SigningLatency = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "coldforge_signer_signing_latency_seconds",
			Help:    "NIP-46 signing operation latency",
			Buckets: []float64{.01, .025, .05, .1, .25, .5, 1, 2.5},
		},
		[]string{"method"},
	)

	// VaultLatency measures Vault API call latency by operation
	VaultLatency = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "coldforge_signer_vault_latency_seconds",
			Help:    "Vault API call latency",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5},
		},
		[]string{"operation"},
	)

	// BatchSignSize tracks the number of events per batch_sign request
	BatchSignSize = promauto.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "coldforge_signer_batch_sign_size",
			Help:    "Number of events per batch_sign request",
			Buckets: []float64{1, 2, 5, 10, 25, 50, 100},
		},
	)

	// VaultCacheHits tracks Vault cache hit/miss rates
	VaultCacheHits = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "coldforge_signer_vault_cache_total",
			Help: "Vault cache hits and misses",
		},
		[]string{"result"}, // "hit" or "miss"
	)

	// ActiveNIP46Sessions tracks active NIP-46 client sessions
	ActiveNIP46Sessions = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "coldforge_signer_nip46_sessions_active",
			Help: "Active NIP-46 client sessions",
		},
	)

	// RelayConnectionsPerKey tracks relay connections per signing key
	RelayConnectionsPerKey = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "coldforge_signer_relay_connections_per_key",
			Help: "Number of per-key relay clients",
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

// RecordSigningLatency records the latency of a NIP-46 operation
func RecordSigningLatency(method string, duration time.Duration) {
	SigningLatency.WithLabelValues(method).Observe(duration.Seconds())
}

// RecordVaultLatency records the latency of a Vault API call
func RecordVaultLatency(operation string, duration time.Duration) {
	VaultLatency.WithLabelValues(operation).Observe(duration.Seconds())
}

// RecordBatchSignSize records the number of events in a batch_sign request
func RecordBatchSignSize(count int) {
	BatchSignSize.Observe(float64(count))
}

// RecordVaultCacheHit records a Vault cache hit
func RecordVaultCacheHit() {
	VaultCacheHits.WithLabelValues("hit").Inc()
}

// RecordVaultCacheMiss records a Vault cache miss
func RecordVaultCacheMiss() {
	VaultCacheHits.WithLabelValues("miss").Inc()
}

// SetActiveNIP46Sessions sets the number of active NIP-46 sessions
func SetActiveNIP46Sessions(count int) {
	ActiveNIP46Sessions.Set(float64(count))
}

// SetRelayConnectionsPerKey sets the number of per-key relay clients
func SetRelayConnectionsPerKey(count int) {
	RelayConnectionsPerKey.Set(float64(count))
}
