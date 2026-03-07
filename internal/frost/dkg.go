package frost

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/bytemare/ecc"
	"github.com/bytemare/frost/debug"
	"github.com/bytemare/secret-sharing/keys"
)

// KeyGenerator handles FROST key generation
type KeyGenerator struct {
	encryptor Encryptor
}

// NewKeyGenerator creates a new FROST key generator
func NewKeyGenerator(encryptor Encryptor) *KeyGenerator {
	return &KeyGenerator{
		encryptor: encryptor,
	}
}

// GenerateKey creates a new FROST key using trusted dealer mode
// In trusted dealer mode, the dealer generates all shares from a single secret.
// This is simpler but requires trusting the dealer (who briefly sees the full secret).
// For high-security scenarios, use distributed DKG instead.
func (kg *KeyGenerator) GenerateKey(config *KeyGenConfig) (*KeyGenResult, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	// Get the FROST ciphersuite group
	group := DefaultCiphersuite.Group()

	// Prepare the secret scalar
	var secret = group.NewScalar()
	if len(config.ExistingSecret) > 0 {
		// Import existing secret
		if err := secret.Decode(config.ExistingSecret); err != nil {
			return nil, fmt.Errorf("failed to decode existing secret: %w", err)
		}
	} else {
		// Generate random secret - the dealer will see this temporarily
		secret.Random()
	}

	// Generate shares using trusted dealer key generation
	// This creates a t-of-n threshold scheme
	keyShares, groupPubKey, _ := debug.TrustedDealerKeygen(
		DefaultCiphersuite,
		secret,
		uint16(config.Threshold),
		uint16(config.TotalShares),
	)

	// Clear the secret from memory (it's been split into shares)
	secret.Zero()

	// Generate a unique ID for this FROST key
	keyID := generateID()

	// Encode the group public key
	groupPubKeyBytes := groupPubKey.Encode()

	// Derive public keys from each key share (the returned participantPubKeys
	// from TrustedDealerKeygen only has threshold elements, not all shares)
	allPublicKeys := make([]*ecc.Element, len(keyShares))
	for i, ks := range keyShares {
		allPublicKeys[i] = ks.Public().PublicKey
	}

	// Build verification shares data (all participant public keys)
	// We store these for verifying partial signatures during signing
	verificationSharesData, err := encodeVerificationShares(allPublicKeys, group)
	if err != nil {
		return nil, fmt.Errorf("failed to encode verification shares: %w", err)
	}

	// Create the FROST key record
	frostKey := &FrostKey{
		ID:                 keyID,
		Name:               config.Name,
		Pubkey:             pubkeyToHex(groupPubKeyBytes),
		Threshold:          config.Threshold,
		TotalShares:        config.TotalShares,
		GroupPublicKey:     groupPubKeyBytes,
		VerificationShares: verificationSharesData,
		CreatedAt:          time.Now(),
	}

	// Create share records
	shares := make([]*FrostShare, len(keyShares))
	secretData := make([][]byte, len(keyShares))

	for i, ks := range keyShares {
		shareID := generateID()

		// Encode the key share for storage
		shareBytes := ks.Encode()
		secretData[i] = shareBytes

		// Encode the public key share (derived from key share above)
		pubShareBytes := allPublicKeys[i].Encode()

		// Encrypt the share if we have an encryptor
		var encryptedShare []byte
		if kg.encryptor != nil {
			encrypted, err := kg.encryptor.Encrypt(shareBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to encrypt share %d: %w", i+1, err)
			}
			encryptedShare = encrypted
		} else {
			// Store unencrypted (not recommended for production)
			encryptedShare = shareBytes
		}

		shares[i] = &FrostShare{
			ID:             shareID,
			FrostKeyID:     keyID,
			ShareIndex:     i + 1, // 1-indexed
			EncryptedShare: encryptedShare,
			IsLocal:        true,
			PublicShare:    pubShareBytes,
			CreatedAt:      time.Now(),
		}
	}

	return &KeyGenResult{
		FrostKey:   frostKey,
		Shares:     shares,
		SecretData: secretData,
	}, nil
}

// ImportShare imports an existing share (e.g., from another signer)
func (kg *KeyGenerator) ImportShare(frostKeyID string, shareIndex int, shareData []byte, isLocal bool) (*FrostShare, error) {
	shareID := generateID()

	var encryptedShare []byte
	var publicShare []byte

	if isLocal {
		// For local shares, we need to decrypt to extract the public share, then re-encrypt
		group := DefaultCiphersuite.Group()

		// Decode the key share to get the public key
		ks, err := decodeKeyShare(shareData, group)
		if err != nil {
			return nil, fmt.Errorf("failed to decode share: %w", err)
		}

		// Get public key share
		publicShare = ks.Public().Encode()

		// Encrypt for storage
		if kg.encryptor != nil {
			encrypted, err := kg.encryptor.Encrypt(shareData)
			if err != nil {
				return nil, fmt.Errorf("failed to encrypt share: %w", err)
			}
			encryptedShare = encrypted
		} else {
			encryptedShare = shareData
		}
	}

	return &FrostShare{
		ID:             shareID,
		FrostKeyID:     frostKeyID,
		ShareIndex:     shareIndex,
		EncryptedShare: encryptedShare,
		IsLocal:        isLocal,
		PublicShare:    publicShare,
		CreatedAt:      time.Now(),
	}, nil
}

// ExportShareBundle creates an exportable bundle for a share
// This can be used to transfer a share to another signer
type ShareBundle struct {
	FrostKeyID         string `json:"frost_key_id"`
	ShareIndex         int    `json:"share_index"`
	ShareData          string `json:"share_data"`      // Hex-encoded share
	GroupPublicKey     string `json:"group_public_key"` // Hex-encoded group public key
	Threshold          int    `json:"threshold"`
	TotalShares        int    `json:"total_shares"`
	VerificationShares string `json:"verification_shares"` // Hex-encoded verification data
}

// CreateShareBundle creates an exportable bundle from a share
func (kg *KeyGenerator) CreateShareBundle(key *FrostKey, share *FrostShare) (*ShareBundle, error) {
	// Decrypt the share data
	var shareData []byte
	if kg.encryptor != nil && share.IsLocal && len(share.EncryptedShare) > 0 {
		decrypted, err := kg.encryptor.Decrypt(share.EncryptedShare)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt share: %w", err)
		}
		shareData = decrypted
	} else {
		shareData = share.EncryptedShare
	}

	return &ShareBundle{
		FrostKeyID:         key.ID,
		ShareIndex:         share.ShareIndex,
		ShareData:          hex.EncodeToString(shareData),
		GroupPublicKey:     hex.EncodeToString(key.GroupPublicKey),
		Threshold:          key.Threshold,
		TotalShares:        key.TotalShares,
		VerificationShares: hex.EncodeToString(key.VerificationShares),
	}, nil
}

// generateID creates a random 16-byte hex ID
func generateID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// encodeVerificationShares encodes all participant public keys for storage
func encodeVerificationShares(pubKeys []*ecc.Element, group ecc.Group) ([]byte, error) {
	// Simple format: 2-byte count + concatenated encoded public keys
	if len(pubKeys) > 65535 {
		return nil, fmt.Errorf("too many public keys")
	}

	// Calculate total size
	elemSize := group.ElementLength()
	totalSize := 2 + len(pubKeys)*elemSize

	data := make([]byte, totalSize)
	data[0] = byte(len(pubKeys) >> 8)
	data[1] = byte(len(pubKeys))

	offset := 2
	for _, pk := range pubKeys {
		encoded := pk.Encode()
		copy(data[offset:offset+elemSize], encoded)
		offset += elemSize
	}

	return data, nil
}

// decodeVerificationShares decodes participant public keys from storage
func decodeVerificationShares(data []byte, group ecc.Group) ([]*ecc.Element, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("verification shares data too short")
	}

	count := int(data[0])<<8 | int(data[1])
	elemSize := group.ElementLength()
	expectedSize := 2 + count*elemSize

	if len(data) != expectedSize {
		return nil, fmt.Errorf("verification shares data size mismatch: got %d, expected %d", len(data), expectedSize)
	}

	pubKeys := make([]*ecc.Element, count)
	offset := 2
	for i := 0; i < count; i++ {
		pk := group.NewElement()
		if err := pk.Decode(data[offset : offset+elemSize]); err != nil {
			return nil, fmt.Errorf("failed to decode public key %d: %w", i, err)
		}
		pubKeys[i] = pk
		offset += elemSize
	}

	return pubKeys, nil
}

// decodeKeyShare decodes a key share from bytes
func decodeKeyShare(data []byte, group ecc.Group) (*keys.KeyShare, error) {
	ks := new(keys.KeyShare)
	if err := ks.Decode(data); err != nil {
		return nil, err
	}
	return ks, nil
}
