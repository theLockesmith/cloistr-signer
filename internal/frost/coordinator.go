package frost

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/bytemare/ecc"
	frostlib "github.com/bytemare/frost"
	"github.com/bytemare/secret-sharing/keys"
)

// Coordinator orchestrates FROST signing operations
// For local shares, it handles the entire signing process internally.
// For remote shares, it would coordinate via Nostr DMs (future enhancement).
type Coordinator struct {
	storage   FrostStorage
	encryptor Encryptor
	mu        sync.Mutex
}

// NewCoordinator creates a new FROST signing coordinator
func NewCoordinator(storage FrostStorage, encryptor Encryptor) *Coordinator {
	return &Coordinator{
		storage:   storage,
		encryptor: encryptor,
	}
}

// SignMessage signs a message using FROST threshold signatures
// This requires at least t local shares to be available for the given key.
// Returns the signature as a 64-byte array (32-byte R + 32-byte s) compatible with Nostr/BIP-340.
func (c *Coordinator) SignMessage(ctx context.Context, frostKeyID string, message []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Get the FROST key
	frostKey, err := c.storage.GetFrostKey(ctx, frostKeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get FROST key: %w", err)
	}

	// Get all local shares
	localShares, err := c.storage.ListLocalFrostShares(ctx, frostKeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to list local shares: %w", err)
	}

	// Check if we have enough shares
	if len(localShares) < frostKey.Threshold {
		return nil, fmt.Errorf("%w: have %d, need %d", ErrInsufficientShares, len(localShares), frostKey.Threshold)
	}

	// Use exactly threshold shares (first t available)
	sharesToUse := localShares[:frostKey.Threshold]

	// Decrypt shares and build key shares
	group := DefaultCiphersuite.Group()
	keyShares := make([]*keys.KeyShare, len(sharesToUse))
	publicKeyShares := make([]*keys.PublicKeyShare, frostKey.TotalShares)

	// First, decode all public key shares from verification data
	verificationPubKeys, err := decodeVerificationShares(frostKey.VerificationShares, group)
	if err != nil {
		return nil, fmt.Errorf("failed to decode verification shares: %w", err)
	}

	// Build PublicKeyShare array for configuration
	for i := 0; i < frostKey.TotalShares; i++ {
		publicKeyShares[i] = &keys.PublicKeyShare{
			PublicKey: verificationPubKeys[i],
			ID:        uint16(i + 1),
			Group:     group,
		}
	}

	// Decrypt and decode the key shares we'll use for signing
	for i, share := range sharesToUse {
		var shareData []byte
		if c.encryptor != nil && len(share.EncryptedShare) > 0 {
			decrypted, err := c.encryptor.Decrypt(share.EncryptedShare)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt share %d: %w", share.ShareIndex, err)
			}
			shareData = decrypted
		} else {
			shareData = share.EncryptedShare
		}

		ks, err := decodeKeyShare(shareData, group)
		if err != nil {
			return nil, fmt.Errorf("failed to decode key share %d: %w", share.ShareIndex, err)
		}
		keyShares[i] = ks
	}

	// Build FROST configuration
	config, err := GetFrostConfiguration(frostKey, publicKeyShares)
	if err != nil {
		return nil, fmt.Errorf("failed to create FROST configuration: %w", err)
	}

	// Create signers for each share
	signers := make([]*frostlib.Signer, len(keyShares))
	for i, ks := range keyShares {
		signer, err := config.Signer(ks)
		if err != nil {
			return nil, fmt.Errorf("failed to create signer for share %d: %w", sharesToUse[i].ShareIndex, err)
		}
		signers[i] = signer
	}

	// Round 1: Generate commitments
	commitments := make(frostlib.CommitmentList, len(signers))
	for i, signer := range signers {
		commitment := signer.Commit()
		commitments[i] = commitment
	}

	// Sort commitments by signer ID (required by FROST protocol)
	commitments.Sort()

	// Round 2: Generate signature shares
	sigShares := make([]*frostlib.SignatureShare, len(signers))
	for i, signer := range signers {
		sigShare, err := signer.Sign(message, commitments)
		if err != nil {
			return nil, fmt.Errorf("failed to sign with share %d: %w", sharesToUse[i].ShareIndex, err)
		}
		sigShares[i] = sigShare
	}

	// Aggregate signatures
	signature, err := config.AggregateSignatures(message, sigShares, commitments, true)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate signatures: %w", err)
	}

	// Encode signature to bytes
	// FROST signature is R (element) + z (scalar)
	// For Nostr/BIP-340, we need 32-byte R + 32-byte s format
	sigBytes := signature.Encode()

	return sigBytes, nil
}

// SignEvent signs a Nostr event hash using FROST
// The eventHash should be the 32-byte SHA256 hash of the serialized event.
// Returns the hex-encoded signature.
func (c *Coordinator) SignEvent(ctx context.Context, frostKeyID string, eventHash []byte) (string, error) {
	if len(eventHash) != 32 {
		return "", fmt.Errorf("event hash must be 32 bytes, got %d", len(eventHash))
	}

	sigBytes, err := c.SignMessage(ctx, frostKeyID, eventHash)
	if err != nil {
		return "", err
	}

	return hex.EncodeToString(sigBytes), nil
}

// VerifySignature verifies a FROST signature against the group public key
func (c *Coordinator) VerifySignature(ctx context.Context, frostKeyID string, message, signatureBytes []byte) (bool, error) {
	// Get the FROST key
	frostKey, err := c.storage.GetFrostKey(ctx, frostKeyID)
	if err != nil {
		return false, fmt.Errorf("failed to get FROST key: %w", err)
	}

	group := DefaultCiphersuite.Group()

	// Decode the group public key
	verificationKey := group.NewElement()
	if err := verificationKey.Decode(frostKey.GroupPublicKey); err != nil {
		return false, fmt.Errorf("failed to decode verification key: %w", err)
	}

	// Decode the signature
	signature := new(frostlib.Signature)
	if err := signature.Decode(signatureBytes); err != nil {
		return false, fmt.Errorf("failed to decode signature: %w", err)
	}

	// Verify
	err = frostlib.VerifySignature(DefaultCiphersuite, message, signature, verificationKey)
	if err != nil {
		return false, nil // Verification failed but no error
	}

	return true, nil
}

// GetAvailableShareCount returns the number of local shares available for a key
func (c *Coordinator) GetAvailableShareCount(ctx context.Context, frostKeyID string) (int, error) {
	shares, err := c.storage.ListLocalFrostShares(ctx, frostKeyID)
	if err != nil {
		return 0, err
	}
	return len(shares), nil
}

// CanSign returns true if enough local shares are available to sign
func (c *Coordinator) CanSign(ctx context.Context, frostKeyID string) (bool, error) {
	frostKey, err := c.storage.GetFrostKey(ctx, frostKeyID)
	if err != nil {
		return false, err
	}

	count, err := c.GetAvailableShareCount(ctx, frostKeyID)
	if err != nil {
		return false, err
	}

	return count >= frostKey.Threshold, nil
}

// GetShareHolders returns information about all share holders for a key
func (c *Coordinator) GetShareHolders(ctx context.Context, frostKeyID string) ([]*ShareHolder, error) {
	shares, err := c.storage.ListFrostShares(ctx, frostKeyID)
	if err != nil {
		return nil, err
	}

	holders := make([]*ShareHolder, len(shares))
	for i, share := range shares {
		holders[i] = &ShareHolder{
			Index:   share.ShareIndex,
			Pubkey:  share.HolderPubkey,
			IsLocal: share.IsLocal,
			// IsOnline would be set by checking remote share connectivity (future)
			IsOnline: share.IsLocal, // Local shares are always "online"
		}
	}

	return holders, nil
}

// ConvertToNostrSignature converts a FROST signature to Nostr-compatible format
// FROST secp256k1 signatures may need conversion to BIP-340 format
func ConvertToNostrSignature(sigBytes []byte) (string, error) {
	// FROST signature format for secp256k1: R (33 bytes compressed) + s (32 bytes)
	// Nostr/BIP-340 format: r (32 bytes x-only) + s (32 bytes)

	// The bytemare/frost library should output in a format we can work with
	// For now, if the signature is already 64 bytes, assume it's in the right format
	if len(sigBytes) == 64 {
		return hex.EncodeToString(sigBytes), nil
	}

	// If it's 65 bytes (33 + 32), extract x-coordinate of R
	if len(sigBytes) == 65 {
		// First byte is 0x02 or 0x03 (compression prefix)
		// Next 32 bytes are x-coordinate of R
		// Last 32 bytes are s
		r := sigBytes[1:33]
		s := sigBytes[33:65]
		result := make([]byte, 64)
		copy(result[:32], r)
		copy(result[32:], s)
		return hex.EncodeToString(result), nil
	}

	return "", fmt.Errorf("unexpected signature length: %d bytes", len(sigBytes))
}

// decodePublicKeyShare decodes a public key share from bytes
func decodePublicKeyShare(data []byte, group ecc.Group, index int) (*keys.PublicKeyShare, error) {
	pk := group.NewElement()
	if err := pk.Decode(data); err != nil {
		return nil, err
	}
	return &keys.PublicKeyShare{
		PublicKey: pk,
		ID:        uint16(index),
		Group:     group,
	}, nil
}
