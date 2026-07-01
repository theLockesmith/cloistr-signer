package frost

import (
	"context"
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/bytemare/ecc"
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

// SignMessage signs a 32-byte digest using BIP-340-mode FROST threshold
// signatures. Requires at least t local shares. Returns a canonical 64-byte
// BIP-340 signature that verifies under btcec/schnorr — the same verifier
// Nostr relays use.
//
// P4a'/2026-07-01: replaced bytemare/frost.Signer + AggregateSignatures
// with the BIP-340-native primitives from bip340_frost.go. The prior
// implementation produced FROST-secp256k1-SHA256-v1 signatures which
// Nostr relays would have rejected. See docs/frost-cosigning-design.md §9.
func (c *Coordinator) SignMessage(ctx context.Context, frostKeyID string, message []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(message) != 32 {
		return nil, fmt.Errorf("message must be 32 bytes (Nostr event id), got %d", len(message))
	}

	frostKey, err := c.storage.GetFrostKey(ctx, frostKeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get FROST key: %w", err)
	}

	localShares, err := c.storage.ListLocalFrostShares(ctx, frostKeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to list local shares: %w", err)
	}
	if len(localShares) < frostKey.Threshold {
		return nil, fmt.Errorf("%w: have %d, need %d", ErrInsufficientShares, len(localShares), frostKey.Threshold)
	}
	sharesToUse := localShares[:frostKey.Threshold]

	group := DefaultCiphersuite.Group()

	// Decode the joint pubkey.
	jointPubkey := group.NewElement()
	if err := jointPubkey.Decode(frostKey.GroupPublicKey); err != nil {
		return nil, fmt.Errorf("decode group public key: %w", err)
	}

	// Decode all verification shares. Indexed by participant ID.
	verificationPubKeys, err := decodeVerificationShares(frostKey.VerificationShares, group)
	if err != nil {
		return nil, fmt.Errorf("failed to decode verification shares: %w", err)
	}
	verificationByID := make(map[uint16]*ecc.Element, len(verificationPubKeys))
	for i, v := range verificationPubKeys {
		verificationByID[uint16(i+1)] = v
	}

	// Decrypt each local share, extract raw secret scalar + participant ID.
	type localShareMaterial struct {
		id     uint16
		secret *ecc.Scalar
	}
	locals := make([]localShareMaterial, len(sharesToUse))
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
		locals[i] = localShareMaterial{
			id:     ks.ID,
			secret: ks.Secret,
		}
	}

	// Generate a fresh nonce pair per participant. In-process signing —
	// all t signers are local, so all nonces stay in this function.
	participants := make([]signParticipant, len(locals))
	commitments := make([]NonceCommitmentPair, len(locals))
	allIDs := make([]uint16, len(locals))
	for i, l := range locals {
		d := group.NewScalar().Random()
		e := group.NewScalar().Random()
		D := group.Base().Multiply(d)
		E := group.Base().Multiply(e)
		participants[i] = signParticipant{id: l.id, d: d, e: e, D: D, E: E, secret: l.secret}
		commitments[i] = NonceCommitmentPair{ParticipantID: l.id, Hiding: D, Binding: E}
		allIDs[i] = l.id
	}
	// Sort by ID ascending — required by ComputeBindingFactors + all BIP-340
	// FROST helpers.
	sortByParticipantID(commitments, allIDs, participants)

	// Prepare shared signable state (binding factors, R aggregation +
	// even-Y normalization, BIP-340 challenge).
	signable, err := PrepareSignable(&SessionForSigning{
		Group:         group,
		ParticipantID: participants[0].id, // placeholder; PrepareSignable also computes lambda but we recompute per-participant below
		AllIDs:        allIDs,
		Commitments:   commitments,
		JointPubkey:   jointPubkey,
		Message:       message,
	})
	if err != nil {
		return nil, fmt.Errorf("prepare signable: %w", err)
	}

	// Compute each participant's partial sig.
	partials := make([]*ecc.Scalar, len(participants))
	for i, p := range participants {
		lambda := LagrangeCoefficient(group, p.id, allIDs)
		rho := signable.BindingFactors[p.id]
		partials[i] = ComputePartialSignature(
			group,
			p.d, p.e, rho, signable.REvenY,
			p.secret, signable.PubkeyEvenY,
			lambda, signable.Challenge,
		)
	}

	// Aggregate into canonical 64-byte BIP-340 signature.
	sigBytes, err := AggregateFullSignature(group, signable, partials)
	if err != nil {
		return nil, fmt.Errorf("aggregate: %w", err)
	}

	// Belt-and-braces: verify under btcec/schnorr before returning. If
	// this fails, something is wrong with the local math or share
	// material and we do NOT want to publish an invalid Nostr sig.
	if err := VerifyBIP340(sigBytes, message, jointPubkey); err != nil {
		return nil, fmt.Errorf("assembled signature failed BIP-340 verification: %w", err)
	}

	return sigBytes, nil
}

// signParticipant is the in-process state for one FROST participant during
// a single-shot local-shares-only signing ceremony.
type signParticipant struct {
	id     uint16
	d, e   *ecc.Scalar
	D, E   *ecc.Element
	secret *ecc.Scalar
}

// sortByParticipantID sorts three parallel slices by the commitment
// list's participant ID ascending. Used because Go's sort.Slice can't
// swap parallel slices atomically without a wrapper struct.
func sortByParticipantID(commitments []NonceCommitmentPair, allIDs []uint16, participants []signParticipant) {
	// Simple insertion sort — for small n (typically 2-5), avoids the
	// wrapper struct overhead.
	for i := 1; i < len(commitments); i++ {
		for j := i; j > 0 && commitments[j-1].ParticipantID > commitments[j].ParticipantID; j-- {
			commitments[j-1], commitments[j] = commitments[j], commitments[j-1]
			allIDs[j-1], allIDs[j] = allIDs[j], allIDs[j-1]
			participants[j-1], participants[j] = participants[j], participants[j-1]
		}
	}
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

// VerifySignature verifies a BIP-340 Schnorr signature against the joint
// public key via btcec/schnorr — the same verifier real Nostr relays run.
// signatureBytes must be a canonical 64-byte (R_x || s) sig.
func (c *Coordinator) VerifySignature(ctx context.Context, frostKeyID string, message, signatureBytes []byte) (bool, error) {
	frostKey, err := c.storage.GetFrostKey(ctx, frostKeyID)
	if err != nil {
		return false, fmt.Errorf("failed to get FROST key: %w", err)
	}

	group := DefaultCiphersuite.Group()

	verificationKey := group.NewElement()
	if err := verificationKey.Decode(frostKey.GroupPublicKey); err != nil {
		return false, fmt.Errorf("failed to decode verification key: %w", err)
	}

	// Length + format errors are reported as errors; only the actual
	// "signature does not verify" case returns (false, nil).
	if len(signatureBytes) != 64 {
		return false, fmt.Errorf("signature must be 64 bytes, got %d", len(signatureBytes))
	}
	if err := VerifyBIP340(signatureBytes, message, verificationKey); err != nil {
		if err.Error() == "BIP-340 verification failed" {
			return false, nil
		}
		return false, err
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
