package bunker

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
)

// URI represents a bunker:// connection URI
// Format: bunker://<signer-pubkey>?relay=<relay-url>&relay=<relay-url>&secret=<secret>
type URI struct {
	SignerPubkey string   // The signer's public key
	Relays       []string // Relay URLs for communication
	Secret       string   // Optional shared secret for initial connection
}

// GenerateSecret generates a random secret for bunker connections
func GenerateSecret() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate secret: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// NewURI creates a new bunker URI
func NewURI(signerPubkey string, relays []string, secret string) *URI {
	return &URI{
		SignerPubkey: signerPubkey,
		Relays:       relays,
		Secret:       secret,
	}
}

// String returns the bunker:// URI string
func (u *URI) String() string {
	// bunker://<pubkey>?relay=<url>&relay=<url>&secret=<secret>
	uri := fmt.Sprintf("bunker://%s", u.SignerPubkey)

	params := url.Values{}
	for _, relay := range u.Relays {
		params.Add("relay", relay)
	}
	if u.Secret != "" {
		params.Set("secret", u.Secret)
	}

	if len(params) > 0 {
		uri += "?" + params.Encode()
	}

	return uri
}

// Parse parses a bunker:// URI string
func Parse(uriStr string) (*URI, error) {
	if !strings.HasPrefix(uriStr, "bunker://") {
		return nil, fmt.Errorf("invalid bunker URI: must start with bunker://")
	}

	// Parse as URL
	parsed, err := url.Parse(uriStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse bunker URI: %w", err)
	}

	// Extract pubkey from host
	pubkey := parsed.Host
	if len(pubkey) != 64 {
		return nil, fmt.Errorf("invalid bunker URI: pubkey must be 64 hex characters")
	}

	// Validate hex
	if _, err := hex.DecodeString(pubkey); err != nil {
		return nil, fmt.Errorf("invalid bunker URI: pubkey must be valid hex")
	}

	uri := &URI{
		SignerPubkey: pubkey,
	}

	// Parse query params
	query := parsed.Query()

	// Get relays
	uri.Relays = query["relay"]

	// Get secret
	uri.Secret = query.Get("secret")

	return uri, nil
}

// ConnectionInfo holds information needed for a client to connect
type ConnectionInfo struct {
	BunkerURI    string   `json:"bunker_uri"`
	SignerPubkey string   `json:"signer_pubkey"`
	Relays       []string `json:"relays"`
	Secret       string   `json:"secret,omitempty"`
	ExpiresAt    string   `json:"expires_at,omitempty"`
}

// GenerateConnectionInfo creates connection info for a key
func GenerateConnectionInfo(signerPubkey string, relays []string, includeSecret bool) (*ConnectionInfo, error) {
	var secret string
	var err error

	if includeSecret {
		secret, err = GenerateSecret()
		if err != nil {
			return nil, err
		}
	}

	uri := NewURI(signerPubkey, relays, secret)

	return &ConnectionInfo{
		BunkerURI:    uri.String(),
		SignerPubkey: signerPubkey,
		Relays:       relays,
		Secret:       secret,
	}, nil
}
