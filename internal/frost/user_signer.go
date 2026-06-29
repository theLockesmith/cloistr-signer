// Package frost user_signer: signer-side implementation of the 2-of-N
// user-cosigner per-signature ceremony described in
// docs/frost-cosigning-design.md.
//
// This is the Go protocol-only piece (P4a) - no HTTP endpoints, no
// relay traffic, no WASM. The user's contribution arrives as
// pre-encoded bytemare/frost commitment + signature-share bytes; this
// layer combines them with the signer's contribution to produce a
// BIP-340 Schnorr signature.

package frost

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	frostlib "github.com/bytemare/frost"
	"github.com/bytemare/secret-sharing/keys"
)

// UserCosignTTL is how long a half-completed cosign session lives in the
// coordinator's memory before GC. Aligned with the DKG session TTL.
const UserCosignTTL = 60 * time.Second

// Errors returned by the cosign coordinator.
var (
	ErrCosignSessionNotFound = errors.New("cosign session not found or expired")
	ErrCosignBadSignature    = errors.New("aggregated signature failed BIP-340 verification")
	ErrCosignBadInput        = errors.New("malformed cosign input")
)

// UserCosignSetup is the material the caller assembles from storage +
// Vault for a single sign request. The coordinator does not retain
// plaintext share material across sessions - this is passed by value
// and discarded after BeginCosign.
type UserCosignSetup struct {
	KeyID                    string
	JointPubkeyHex           string // compressed-SEC1 hex (33 bytes)
	SignerShareScalar        []byte // 32-byte secp256k1 scalar (signer's secret share)
	SignerVerificationShare  []byte // 33-byte compressed-SEC1 (signer_share*G)
	UserVerificationShareHex string // 33-byte compressed-SEC1 hex (user_share*G)
	EventHash                []byte // 32-byte sha256 of the event being signed
}

// BeginCosignResult is what BeginCosign returns. SignerCommitment*Hex
// are the values sent to the user device on the wire.
type BeginCosignResult struct {
	SessionID                  string
	SignerCommitmentHidingHex  string // 33-byte SEC1 hex (D_signer)
	SignerCommitmentBindingHex string // 33-byte SEC1 hex (E_signer)
}

// userCosignSession is the in-memory state for one in-flight cosign.
// Nonces are NOT serialized; lose this struct mid-session and the
// cosign aborts (user retries).
type userCosignSession struct {
	id            string
	keyID         string
	eventHash     []byte
	signer        *frostlib.Signer
	signerCommit  *frostlib.Commitment
	configuration *frostlib.Configuration
	createdAt     time.Time
	expiresAt     time.Time
}

// UserSignerCoordinator drives the signer side of the 2-of-2
// per-signature ceremony.
type UserSignerCoordinator struct {
	mu       sync.Mutex
	sessions map[string]*userCosignSession
}

// NewUserSignerCoordinator returns a fresh coordinator. Call GC
// periodically to drop expired sessions.
func NewUserSignerCoordinator() *UserSignerCoordinator {
	return &UserSignerCoordinator{
		sessions: make(map[string]*userCosignSession),
	}
}

// BeginCosign generates the signer's commitment and opens a session.
// The setup.SignerShareScalar must already be Vault-decrypted by the
// caller.
func (c *UserSignerCoordinator) BeginCosign(setup UserCosignSetup) (*BeginCosignResult, error) {
	if len(setup.EventHash) != 32 {
		return nil, fmt.Errorf("%w: event_hash must be 32 bytes, got %d", ErrCosignBadInput, len(setup.EventHash))
	}
	if len(setup.SignerShareScalar) == 0 {
		return nil, fmt.Errorf("%w: signer share scalar is empty", ErrCosignBadInput)
	}

	group := DefaultCiphersuite.Group()

	jointPubkey := group.NewElement()
	if err := jointPubkey.DecodeHex(setup.JointPubkeyHex); err != nil {
		return nil, fmt.Errorf("%w: decode joint pubkey: %v", ErrCosignBadInput, err)
	}

	signerVerification := group.NewElement()
	if err := signerVerification.Decode(setup.SignerVerificationShare); err != nil {
		return nil, fmt.Errorf("%w: decode signer verification share: %v", ErrCosignBadInput, err)
	}
	userVerification := group.NewElement()
	if err := userVerification.DecodeHex(setup.UserVerificationShareHex); err != nil {
		return nil, fmt.Errorf("%w: decode user verification share: %v", ErrCosignBadInput, err)
	}

	signerSecret := group.NewScalar()
	if err := signerSecret.Decode(setup.SignerShareScalar); err != nil {
		return nil, fmt.Errorf("%w: decode signer share: %v", ErrCosignBadInput, err)
	}

	// Build bytemare/frost Configuration. IDs: 1=user, 2=signer
	// (matches docs/frost-2-of-n-design.md and user_dkg.go constants).
	signerKeyShare := &keys.KeyShare{
		Secret:          signerSecret,
		VerificationKey: jointPubkey,
		PublicKeyShare: keys.PublicKeyShare{
			PublicKey: signerVerification,
			ID:        uint16(SignerIndex),
			Group:     group,
		},
	}
	userPublicKeyShare := &keys.PublicKeyShare{
		PublicKey: userVerification,
		ID:        uint16(UserIndex),
		Group:     group,
	}
	config := &frostlib.Configuration{
		Ciphersuite:           DefaultCiphersuite,
		Threshold:             2,
		MaxSigners:            2,
		VerificationKey:       jointPubkey,
		SignerPublicKeyShares: []*keys.PublicKeyShare{userPublicKeyShare, &signerKeyShare.PublicKeyShare},
	}
	if err := config.Init(); err != nil {
		return nil, fmt.Errorf("frost configuration: %w", err)
	}

	signer, err := config.Signer(signerKeyShare)
	if err != nil {
		return nil, fmt.Errorf("frost signer: %w", err)
	}
	commitment := signer.Commit()

	sessionID, err := newCosignSessionID()
	if err != nil {
		return nil, fmt.Errorf("session id: %w", err)
	}
	now := time.Now()
	session := &userCosignSession{
		id:            sessionID,
		keyID:         setup.KeyID,
		eventHash:     append([]byte(nil), setup.EventHash...),
		signer:        signer,
		signerCommit:  commitment,
		configuration: config,
		createdAt:     now,
		expiresAt:     now.Add(UserCosignTTL),
	}

	c.mu.Lock()
	c.sessions[sessionID] = session
	c.mu.Unlock()

	return &BeginCosignResult{
		SessionID:                  sessionID,
		SignerCommitmentHidingHex:  commitment.HidingNonceCommitment.Hex(),
		SignerCommitmentBindingHex: commitment.BindingNonceCommitment.Hex(),
	}, nil
}

// CompleteCosignInput is the user-supplied half of round 2.
type CompleteCosignInput struct {
	SessionID                string
	UserCommitmentHidingHex  string
	UserCommitmentBindingHex string
	UserPartialSignatureHex  string
}

// CompleteCosign verifies the user's contribution against the user's
// verification share, runs the signer's Sign(), and aggregates to
// produce a 64-byte BIP-340 signature. The session is dropped on any
// outcome.
func (c *UserSignerCoordinator) CompleteCosign(in CompleteCosignInput) ([]byte, error) {
	c.mu.Lock()
	session, ok := c.sessions[in.SessionID]
	if !ok {
		c.mu.Unlock()
		return nil, ErrCosignSessionNotFound
	}
	if time.Now().After(session.expiresAt) {
		delete(c.sessions, in.SessionID)
		c.mu.Unlock()
		return nil, ErrCosignSessionNotFound
	}
	c.mu.Unlock()

	defer c.dropSession(in.SessionID)

	group := DefaultCiphersuite.Group()

	userHiding := group.NewElement()
	if err := userHiding.DecodeHex(in.UserCommitmentHidingHex); err != nil {
		return nil, fmt.Errorf("%w: decode user hiding commitment: %v", ErrCosignBadInput, err)
	}
	userBinding := group.NewElement()
	if err := userBinding.DecodeHex(in.UserCommitmentBindingHex); err != nil {
		return nil, fmt.Errorf("%w: decode user binding commitment: %v", ErrCosignBadInput, err)
	}
	userCommitment := &frostlib.Commitment{
		HidingNonceCommitment:  userHiding,
		BindingNonceCommitment: userBinding,
		SignerID:               uint16(UserIndex),
		Group:                  group,
	}

	// Sort commitments by ID ascending - binding factor depends on
	// canonical ordering; both sides MUST agree.
	commitments := frostlib.CommitmentList{userCommitment, session.signerCommit}
	commitments.Sort()

	userSigShare := &frostlib.SignatureShare{
		SignerIdentifier: uint16(UserIndex),
		SignatureShare:   group.NewScalar(),
		Group:            group,
	}
	userZ, err := hex.DecodeString(in.UserPartialSignatureHex)
	if err != nil {
		return nil, fmt.Errorf("%w: decode user partial sig hex: %v", ErrCosignBadInput, err)
	}
	if err := userSigShare.SignatureShare.Decode(userZ); err != nil {
		return nil, fmt.Errorf("%w: decode user partial sig scalar: %v", ErrCosignBadInput, err)
	}

	// Verify the user's partial sig BEFORE invoking the signer's
	// secret. A malformed/lying user is rejected without ever
	// touching the signer's private scalar.
	if err := session.configuration.VerifySignatureShare(userSigShare, session.eventHash, commitments); err != nil {
		return nil, fmt.Errorf("user partial sig failed verification: %w", err)
	}

	signerSigShare, err := session.signer.Sign(session.eventHash, commitments)
	if err != nil {
		return nil, fmt.Errorf("signer Sign: %w", err)
	}

	// Aggregate with verify=true: bytemare/frost runs BIP-340
	// verification internally and errors on any divergence.
	signature, err := session.configuration.AggregateSignatures(
		session.eventHash,
		[]*frostlib.SignatureShare{userSigShare, signerSigShare},
		commitments,
		true,
	)
	if err != nil {
		return nil, fmt.Errorf("aggregate: %w", err)
	}

	encoded := signature.Encode()
	// Belt-and-braces re-verification under the free function.
	if err := frostlib.VerifySignature(DefaultCiphersuite, session.eventHash, signature, session.configuration.VerificationKey); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCosignBadSignature, err)
	}
	return encoded, nil
}

// GC drops expired sessions. Returns the number dropped.
func (c *UserSignerCoordinator) GC() int {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	dropped := 0
	for id, session := range c.sessions {
		if now.After(session.expiresAt) {
			delete(c.sessions, id)
			dropped++
		}
	}
	return dropped
}

// SessionCount returns the number of in-memory cosign sessions.
func (c *UserSignerCoordinator) SessionCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.sessions)
}

func (c *UserSignerCoordinator) dropSession(sessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.sessions, sessionID)
}

func newCosignSessionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// HelperBuildKeyShareForTest constructs a *keys.KeyShare from raw
// secret-scalar bytes + the public material the coordinator accepts.
// Used by user_signer_test.go to simulate the user side via
// bytemare/frost.Signer. NOT for production use.
func HelperBuildKeyShareForTest(
	secretScalar []byte,
	verificationShareHex string,
	jointPubkeyHex string,
	id int,
) (*keys.KeyShare, error) {
	group := DefaultCiphersuite.Group()
	secret := group.NewScalar()
	if err := secret.Decode(secretScalar); err != nil {
		return nil, fmt.Errorf("decode secret: %w", err)
	}
	verification := group.NewElement()
	if err := verification.DecodeHex(verificationShareHex); err != nil {
		return nil, fmt.Errorf("decode verification share: %w", err)
	}
	jointPub := group.NewElement()
	if err := jointPub.DecodeHex(jointPubkeyHex); err != nil {
		return nil, fmt.Errorf("decode joint pubkey: %w", err)
	}
	return &keys.KeyShare{
		Secret:          secret,
		VerificationKey: jointPub,
		PublicKeyShare: keys.PublicKeyShare{
			PublicKey: verification,
			ID:        uint16(id),
			Group:     group,
		},
	}, nil
}
