package metrics

import (
	"net/http"
	"time"
)

// Setup decides where /metrics is served. With addr empty it is mounted on the
// public mux, as before. With addr set (METRICS_ADDRESS, e.g. ":9100") it is
// served only by the returned server on that separate listener, which the
// public route never reaches, so request counts and gauges stay in-cluster.
func Setup(public *http.ServeMux, addr string) *http.Server {
	if addr == "" {
		public.Handle("/metrics", Handler())
		return nil
	}
	m := http.NewServeMux()
	m.Handle("/metrics", Handler())
	return &http.Server{
		Addr:         addr,
		Handler:      m,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
}
