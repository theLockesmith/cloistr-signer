// Package frost implements FROST (Flexible Round-Optimized Schnorr Threshold) signatures
// for distributed key custody. This allows t-of-n threshold signing where no single
// party holds the complete private key.
//
// This package uses the bytemare/frost library which implements RFC 9591.
// For Nostr compatibility, we use the secp256k1 ciphersuite.
package frost

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	frostlib "github.com/bytemare/frost"
	"github.com/bytemare/secret-sharing/keys"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/nostr"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

var (
	// ErrInsufficientShares is returned when not enough shares are available for signing
	ErrInsufficientShares = errors.New("insufficient shares for signing")
	// ErrInvalidThreshold is returned when threshold parameters are invalid
	ErrInvalidThreshold = errors.New("invalid threshold: must be > 0 and <= total shares")
	// ErrSigningFailed is returned when FROST signing fails
	ErrSigningFailed = errors.New("frost signing failed")
	// ErrShareAlreadyExists is returned when trying to create a duplicate share
	ErrShareAlreadyExists = errors.New("frost share already exists")
	// ErrInvalidShare is returned when a share fails validation
	ErrInvalidShare = errors.New("invalid frost share")
	// ErrCoordinatorBusy is returned when the coordinator is already processing a request
	ErrCoordinatorBusy = errors.New("frost coordinator is busy")
)

// DefaultCiphersuite is secp256k1 for Nostr compatibility
// Nostr uses secp256k1 Schnorr signatures (BIP-340 compatible)
var DefaultCiphersuite = frostlib.Secp256k1

// Type aliases for convenience - use storage types directly
type FrostKey = storage.FrostKey
type FrostShare = storage.FrostShare

// ShareHolder represents a participant that holds a FROST share
type ShareHolder struct {
	Index       int    `json:"index"`       // Share index (1 to n)
	Pubkey      string `json:"pubkey"`      // Holder's Nostr pubkey
	IsLocal     bool   `json:"is_local"`    // True if share is stored locally
	IsOnline    bool   `json:"is_online"`   // True if holder is reachable (for remote shares)
	LastSeenAt  *time.Time `json:"last_seen_at,omitempty"`
}

// SigningSession represents an in-progress FROST signing operation
type SigningSession struct {
	ID           string
	FrostKeyID   string
	Message      []byte
	Participants []int              // Share indices participating
	Commitments  frostlib.CommitmentList
	Shares       []*frostlib.SignatureShare
	mu           sync.Mutex
	done         chan struct{}
	result       []byte             // Final signature
	err          error
}

// KeyGenConfig holds configuration for FROST key generation
type KeyGenConfig struct {
	Name        string   // Optional name for the key
	Threshold   int      // t - minimum shares needed to sign
	TotalShares int      // n - total number of shares
	// For trusted dealer mode, we can optionally import an existing secret
	ExistingSecret []byte // If set, split this secret instead of generating new
}

// KeyGenResult holds the result of FROST key generation
type KeyGenResult struct {
	FrostKey    *FrostKey      // The generated FROST key
	Shares      []*FrostShare  // The generated shares (unencrypted)
	SecretData  [][]byte       // Raw secret share data (for export/distribution)
}

// Validate checks if the KeyGenConfig is valid
func (c *KeyGenConfig) Validate() error {
	if c.Threshold < 1 {
		return fmt.Errorf("%w: threshold must be at least 1", ErrInvalidThreshold)
	}
	if c.TotalShares < c.Threshold {
		return fmt.Errorf("%w: total shares must be >= threshold", ErrInvalidThreshold)
	}
	if c.Threshold > 255 || c.TotalShares > 255 {
		return fmt.Errorf("%w: threshold and total shares must be <= 255", ErrInvalidThreshold)
	}
	return nil
}

// FrostStorage defines the minimal storage interface needed by the frost package
// This allows for easy testing and decoupling from the full storage interface
type FrostStorage interface {
	GetFrostKey(ctx context.Context, id string) (*storage.FrostKey, error)
	GetFrostKeyByPubkey(ctx context.Context, pubkey string) (*storage.FrostKey, error)
	ListFrostKeys(ctx context.Context) ([]*storage.FrostKey, error)
	CreateFrostKey(ctx context.Context, key *storage.FrostKey) error
	DeleteFrostKey(ctx context.Context, id string) error
	GetFrostShare(ctx context.Context, id string) (*storage.FrostShare, error)
	GetFrostShareByKeyAndIndex(ctx context.Context, frostKeyID string, index int) (*storage.FrostShare, error)
	ListFrostShares(ctx context.Context, frostKeyID string) ([]*storage.FrostShare, error)
	ListLocalFrostShares(ctx context.Context, frostKeyID string) ([]*storage.FrostShare, error)
	CreateFrostShare(ctx context.Context, share *storage.FrostShare) error
	DeleteFrostShare(ctx context.Context, id string) error
}

// Encryptor defines the interface for share encryption/decryption
type Encryptor interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

// NostrClient defines the interface for Nostr communication
// This allows for testing without a real Nostr client
type NostrClient interface {
	SendEphemeralDM(ctx context.Context, privateKey, recipientPubkey string, message *nostr.DMMessage) error
	SubscribeDMs(ctx context.Context, privateKey string, handler nostr.DMHandler) error
}

// pubkeyToHex converts a FROST group public key to hex string for Nostr
// For secp256k1, the public key needs to be in the 32-byte x-coordinate only format (BIP-340)
func pubkeyToHex(pubkeyBytes []byte) string {
	// FROST secp256k1 public keys are 33 bytes (compressed) or 65 bytes (uncompressed)
	// Nostr uses 32-byte x-only pubkeys (BIP-340)
	// For now, we'll use the full compressed key and extract x-coordinate as needed
	if len(pubkeyBytes) == 33 {
		// Compressed format: first byte is 0x02 or 0x03, followed by 32-byte x
		return hex.EncodeToString(pubkeyBytes[1:])
	}
	if len(pubkeyBytes) == 65 {
		// Uncompressed format: 0x04 + 32-byte x + 32-byte y
		return hex.EncodeToString(pubkeyBytes[1:33])
	}
	if len(pubkeyBytes) == 32 {
		// Already x-only
		return hex.EncodeToString(pubkeyBytes)
	}
	// Fallback: return full hex
	return hex.EncodeToString(pubkeyBytes)
}

// GetFrostConfiguration creates a FROST Configuration from stored key data
func GetFrostConfiguration(key *FrostKey, publicShares []*keys.PublicKeyShare) (*frostlib.Configuration, error) {
	group := DefaultCiphersuite.Group()

	// Decode group public key
	verificationKey := group.NewElement()
	if err := verificationKey.Decode(key.GroupPublicKey); err != nil {
		return nil, fmt.Errorf("failed to decode group public key: %w", err)
	}

	config := &frostlib.Configuration{
		Ciphersuite:           DefaultCiphersuite,
		Threshold:             uint16(key.Threshold),
		MaxSigners:            uint16(key.TotalShares),
		VerificationKey:       verificationKey,
		SignerPublicKeyShares: publicShares,
	}

	if err := config.Init(); err != nil {
		return nil, fmt.Errorf("failed to initialize FROST configuration: %w", err)
	}

	return config, nil
}
