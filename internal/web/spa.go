package web

import (
	"embed"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

//go:embed dist
var spaContent embed.FS

// forceTemplateMode can be set to true in tests to bypass SPA detection
var forceTemplateMode = false

// SetForceTemplateMode enables/disables forced template mode (for testing)
func SetForceTemplateMode(enabled bool) {
	forceTemplateMode = enabled
}

// SPAHandler serves the React SPA with fallback to index.html for client-side routing
type SPAHandler struct {
	staticFS http.FileSystem
	devMode  bool // If true, serve from filesystem instead of embed
	devPath  string
}

// NewSPAHandler creates a new SPA handler
// If devPath is non-empty, serves from filesystem (dev mode)
// Otherwise serves from embedded dist/
func NewSPAHandler(devPath string) *SPAHandler {
	h := &SPAHandler{
		devMode: devPath != "",
		devPath: devPath,
	}

	if h.devMode {
		h.staticFS = http.Dir(devPath)
	} else {
		// Create a sub-filesystem rooted at "dist"
		subFS, err := fs.Sub(spaContent, "dist")
		if err != nil {
			panic("failed to create SPA filesystem: " + err.Error())
		}
		h.staticFS = http.FS(subFS)
	}

	return h
}

// ServeHTTP implements http.Handler
func (h *SPAHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path

	// Try to serve the file directly
	f, err := h.staticFS.Open(path)
	if err == nil {
		defer f.Close()

		stat, err := f.Stat()
		if err == nil && !stat.IsDir() {
			// Set content type based on extension
			h.setContentType(w, path)

			// Serve the file
			http.ServeContent(w, r, path, stat.ModTime(), f.(fs.File).(interface {
				Read([]byte) (int, error)
				Seek(int64, int) (int64, error)
			}).(http.File))
			return
		}
	}

	// File not found - serve index.html for SPA routing
	h.serveIndex(w, r)
}

// serveIndex serves the index.html file
func (h *SPAHandler) serveIndex(w http.ResponseWriter, r *http.Request) {
	f, err := h.staticFS.Open("index.html")
	if err != nil {
		http.Error(w, "SPA not found", http.StatusNotFound)
		return
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		http.Error(w, "SPA error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	http.ServeContent(w, r, "index.html", stat.ModTime(), f.(http.File))
}

// setContentType sets the Content-Type header based on file extension
func (h *SPAHandler) setContentType(w http.ResponseWriter, path string) {
	ext := filepath.Ext(path)
	switch ext {
	case ".html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	case ".css":
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	case ".js":
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
	case ".json":
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
	case ".svg":
		w.Header().Set("Content-Type", "image/svg+xml")
	case ".png":
		w.Header().Set("Content-Type", "image/png")
	case ".ico":
		w.Header().Set("Content-Type", "image/x-icon")
	case ".woff":
		w.Header().Set("Content-Type", "font/woff")
	case ".woff2":
		w.Header().Set("Content-Type", "font/woff2")
	case ".map":
		w.Header().Set("Content-Type", "application/json")
	}
}

// IsSPAEnabled checks if the SPA build exists
func IsSPAEnabled() bool {
	// Allow tests to force template mode
	if forceTemplateMode {
		return false
	}

	// Check if embedded dist has content
	entries, err := spaContent.ReadDir("dist")
	if err != nil {
		return false
	}
	// Look for index.html
	for _, entry := range entries {
		if entry.Name() == "index.html" {
			return true
		}
	}
	return false
}

// IsSPAPath returns true if the path should be handled by the SPA
// (i.e., not an API path, not a web API path, and not the approval path)
func IsSPAPath(path string) bool {
	// API paths are handled by the API handler
	if strings.HasPrefix(path, "/api/") {
		return false
	}
	// Web API paths (legacy) are handled by web handler
	if strings.HasPrefix(path, "/web/api/") {
		return false
	}
	// Health checks
	if strings.HasPrefix(path, "/health") {
		return false
	}
	// Well-known paths
	if strings.HasPrefix(path, "/.well-known/") {
		return false
	}
	// Approval deep-links can be either:
	// - Served by SPA if SPA handles it
	// - Served by Go templates if legacy mode
	// For now, let SPA handle /approve/* since it will redirect to login if needed
	return true
}

// SPAMiddleware creates a middleware that serves the SPA for appropriate paths
func SPAMiddleware(spa *SPAHandler, fallback http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if IsSPAPath(r.URL.Path) {
			spa.ServeHTTP(w, r)
			return
		}
		fallback.ServeHTTP(w, r)
	})
}

// DevSPAPath returns the path to serve SPA from in development mode
// Returns empty string if SPA_DEV_PATH env var is not set
func DevSPAPath() string {
	return os.Getenv("SPA_DEV_PATH")
}
