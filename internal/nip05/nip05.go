package nip05

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// WellKnownResponse represents the .well-known/nostr.json response
type WellKnownResponse struct {
	Names  map[string]string   `json:"names"`
	Relays map[string][]string `json:"relays,omitempty"`
}

// VerificationResult contains the result of NIP-05 verification
type VerificationResult struct {
	Valid    bool     `json:"valid"`
	Pubkey   string   `json:"pubkey,omitempty"`
	Relays   []string `json:"relays,omitempty"`
	Error    string   `json:"error,omitempty"`
	Verified time.Time `json:"verified_at,omitempty"`
}

// Verify verifies a NIP-05 identifier and returns the associated pubkey
// Format: name@domain.com
func Verify(ctx context.Context, identifier string) (*VerificationResult, error) {
	result := &VerificationResult{
		Valid:    false,
		Verified: time.Now(),
	}

	// Parse identifier
	parts := strings.SplitN(identifier, "@", 2)
	if len(parts) != 2 {
		result.Error = "invalid NIP-05 format: expected name@domain"
		return result, nil
	}

	name := parts[0]
	domain := parts[1]

	// Handle _ as root name
	if name == "" {
		name = "_"
	}

	// Build URL
	url := fmt.Sprintf("https://%s/.well-known/nostr.json?name=%s", domain, name)

	// Create request with timeout
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		result.Error = fmt.Sprintf("failed to create request: %v", err)
		return result, nil
	}

	req.Header.Set("Accept", "application/json")

	// Make request
	resp, err := client.Do(req)
	if err != nil {
		result.Error = fmt.Sprintf("failed to fetch: %v", err)
		return result, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		result.Error = fmt.Sprintf("HTTP %d", resp.StatusCode)
		return result, nil
	}

	// Parse response
	var wellKnown WellKnownResponse
	if err := json.NewDecoder(resp.Body).Decode(&wellKnown); err != nil {
		result.Error = fmt.Sprintf("failed to parse response: %v", err)
		return result, nil
	}

	// Look up name
	pubkey, exists := wellKnown.Names[name]
	if !exists {
		result.Error = "name not found"
		return result, nil
	}

	// Validate pubkey format
	if len(pubkey) != 64 {
		result.Error = "invalid pubkey in response"
		return result, nil
	}

	result.Valid = true
	result.Pubkey = pubkey

	// Get relays if available
	if relays, ok := wellKnown.Relays[pubkey]; ok {
		result.Relays = relays
	}

	return result, nil
}

// Handler serves NIP-05 .well-known/nostr.json responses
type Handler struct {
	names  map[string]string   // name -> pubkey
	relays map[string][]string // pubkey -> relays
}

// NewHandler creates a new NIP-05 handler
func NewHandler() *Handler {
	return &Handler{
		names:  make(map[string]string),
		relays: make(map[string][]string),
	}
}

// AddName adds a name -> pubkey mapping
func (h *Handler) AddName(name, pubkey string) {
	h.names[name] = pubkey
}

// AddRelays adds relays for a pubkey
func (h *Handler) AddRelays(pubkey string, relays []string) {
	h.relays[pubkey] = relays
}

// RemoveName removes a name mapping
func (h *Handler) RemoveName(name string) {
	delete(h.names, name)
}

// ServeHTTP handles .well-known/nostr.json requests
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get name query param
	name := r.URL.Query().Get("name")

	response := WellKnownResponse{
		Names:  make(map[string]string),
		Relays: make(map[string][]string),
	}

	if name != "" {
		// Return only the requested name
		if pubkey, exists := h.names[name]; exists {
			response.Names[name] = pubkey
			if relays, ok := h.relays[pubkey]; ok {
				response.Relays[pubkey] = relays
			}
		}
	} else {
		// Return all names
		response.Names = h.names
		response.Relays = h.relays
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	json.NewEncoder(w).Encode(response)
}
