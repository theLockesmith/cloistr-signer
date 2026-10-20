package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// /metrics was served on the public port, so anyone on the internet could read
// per-path request counts, key and session gauges (found 2026-10-19). With a
// metrics address set it is served only on that separate, in-cluster listener.

func publicMux() *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("spa")) })
	return m
}

func get(h http.Handler, path string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
	return rr
}

func TestSetup_SeparateListenerKeepsMetricsOffThePublicMux(t *testing.T) {
	public := publicMux()
	srv := Setup(public, ":9100")
	if srv == nil || srv.Addr != ":9100" {
		t.Fatalf("Setup returned %+v, want a server on :9100", srv)
	}
	if body := get(public, "/metrics").Body.String(); strings.Contains(body, "coldforge_signer_") {
		t.Fatalf("public mux still serves metrics")
	}
	rr := get(srv.Handler, "/metrics")
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "coldforge_signer_") {
		t.Fatalf("metrics listener: %d, want 200 with signer metrics", rr.Code)
	}
	if rr := get(srv.Handler, "/api/v1/keys"); rr.Code != http.StatusNotFound {
		t.Fatalf("metrics listener serves other paths: %d, want 404", rr.Code)
	}
}

// Unset keeps today's behaviour, so the signer can roll before the config
// that moves the scrape to the new port.
func TestSetup_NoAddressKeepsMetricsOnThePublicMux(t *testing.T) {
	public := publicMux()
	if srv := Setup(public, ""); srv != nil {
		t.Fatalf("Setup with no address returned a server")
	}
	if body := get(public, "/metrics").Body.String(); !strings.Contains(body, "coldforge_signer_") {
		t.Fatalf("public mux lost metrics with no metrics address set")
	}
}
