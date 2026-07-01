// Package frost user_signer: signer-side implementation of the 2-of-N
// user-cosigner per-signature ceremony described in
// docs/frost-cosigning-design.md.
//
// P4a' (2026-07-01): replaced bytemare/frost.Signer internals with
// hand-rolled BIP-340-mode FROST math from bip340_frost.go. The prior
// implementation produced FROST-secp256k1-SHA256-v1 signatures which
// don't verify under BIP-340 (Nostr's verification scheme). See
// docs/frost-cosigning-design.md §9.

package frost

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/bytemare/ecc"
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
	JointPubkeyHex           string // 33-byte compressed-SEC1 hex
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
	id           string
	keyID        string
	eventHash    []byte
	d            *ecc.Scalar // hiding nonce
	e            *ecc.Scalar // binding nonce
	dCommit      *ecc.Element
	eCommit      *ecc.Element
	signerShare  *ecc.Scalar // s_signer (plaintext)
	jointPubkey  *ecc.Element
	userVerify   *ecc.Element
	signerVerify *ecc.Element
	createdAt    time.Time
	expiresAt    time.Time
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

// BeginCosign generates the signer's nonce commitment and opens a session.
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

	// Fresh nonce pair. d and e must be independent random scalars.
	d := group.NewScalar().Random()
	e := group.NewScalar().Random()
	dCommit := group.Base().Multiply(d)
	eCommit := group.Base().Multiply(e)

	sessionID, err := newCosignSessionID()
	if err != nil {
		return nil, fmt.Errorf("session id: %w", err)
	}
	now := time.Now()
	session := &userCosignSession{
		id:           sessionID,
		keyID:        setup.KeyID,
		eventHash:    append([]byte(nil), setup.EventHash...),
		d:            d,
		e:            e,
		dCommit:      dCommit,
		eCommit:      eCommit,
		signerShare:  signerSecret,
		jointPubkey:  jointPubkey,
		userVerify:   userVerification,
		signerVerify: signerVerification,
		createdAt:    now,
		expiresAt:    now.Add(UserCosignTTL),
	}

	c.mu.Lock()
	c.sessions[sessionID] = session
	c.mu.Unlock()

	return &BeginCosignResult{
		SessionID:                  sessionID,
		SignerCommitmentHidingHex:  HelperEncodeCompressed(dCommit),
		SignerCommitmentBindingHex: HelperEncodeCompressed(eCommit),
	}, nil
}

// CompleteCosignInput is the user-supplied half of round 2.
type CompleteCosignInput struct {
	SessionID                string
	UserCommitmentHidingHex  string
	UserCommitmentBindingHex string
	UserPartialSignatureHex  string
}

// CompleteCosign verifies the user's contribution, runs the signer's
// partial sig math, and aggregates into a canonical 64-byte BIP-340
// signature. The session is dropped on any outcome.
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

	// Decode user's commitment.
	userHiding := group.NewElement()
	if err := userHiding.DecodeHex(in.UserCommitmentHidingHex); err != nil {
		return nil, fmt.Errorf("%w: decode user hiding: %v", ErrCosignBadInput, err)
	}
	userBinding := group.NewElement()
	if err := userBinding.DecodeHex(in.UserCommitmentBindingHex); err != nil {
		return nil, fmt.Errorf("%w: decode user binding: %v", ErrCosignBadInput, err)
	}

	// Sorted commitment list: [user (id=1), signer (id=2)]
	commitments := []NonceCommitmentPair{
		{ParticipantID: uint16(UserIndex), Hiding: userHiding, Binding: userBinding},
		{ParticipantID: uint16(SignerIndex), Hiding: session.dCommit, Binding: session.eCommit},
	}
	allIDs := []uint16{uint16(UserIndex), uint16(SignerIndex)}

	// Build the signable state (deterministic given inputs).
	signable, err := PrepareSignable(&SessionForSigning{
		Group:         group,
		ParticipantID: uint16(SignerIndex),
		AllIDs:        allIDs,
		Commitments:   commitments,
		JointPubkey:   session.jointPubkey,
		Message:       session.eventHash,
	})
	if err != nil {
		return nil, fmt.Errorf("prepare signable: %w", err)
	}

	// Decode user's partial signature.
	userZBytes, err := hex.DecodeString(in.UserPartialSignatureHex)
	if err != nil {
		return nil, fmt.Errorf("%w: decode user partial hex: %v", ErrCosignBadInput, err)
	}
	userZ := group.NewScalar()
	if err := userZ.Decode(userZBytes); err != nil {
		return nil, fmt.Errorf("%w: decode user partial scalar: %v", ErrCosignBadInput, err)
	}

	// Verify user's partial BEFORE invoking the signer's secret. The
	// user's lambda differs from the signer's (it depends on
	// participant ID), so recompute for the user rather than using
	// signable.Lambda which was prepared for the signer.
	userLambda := LagrangeCoefficient(group, uint16(UserIndex), allIDs)
	if err := verifyPartialSignature(group, userZ, uint16(UserIndex), commitments, signable, userLambda, session.userVerify); err != nil {
		return nil, fmt.Errorf("user partial sig verification failed: %w", err)
	}

	// Signer computes its own partial.
	signerSession := &SessionForSigning{
		Group:         group,
		ParticipantID: uint16(SignerIndex),
		AllIDs:        allIDs,
		Commitments:   commitments,
		JointPubkey:   session.jointPubkey,
		Message:       session.eventHash,
		NonceHiding:   session.d,
		NonceBinding:  session.e,
		Share:         session.signerShare,
	}
	signerZ := signerSession.Sign(signable)

	// Aggregate.
	sigBytes, err := AggregateFullSignature(group, signable, []*ecc.Scalar{userZ, signerZ})
	if err != nil {
		return nil, fmt.Errorf("aggregate: %w", err)
	}

	// Defense-in-depth: verify the assembled signature under
	// btcec/schnorr before returning.
	if err := VerifyBIP340(sigBytes, session.eventHash, session.jointPubkey); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCosignBadSignature, err)
	}

	return sigBytes, nil
}

// verifyPartialSignature checks that z_i*G matches what the participant
// should produce. Rearranged from the signing equation:
//   z_i*G = nonce_contrib_point + lambda_i * c * verification_share_eff
func verifyPartialSignature(
	group ecc.Group,
	z *ecc.Scalar,
	participantID uint16,
	commitments []NonceCommitmentPair,
	signable *Signable,
	participantLambda *ecc.Scalar,
	verificationShare *ecc.Element,
) error {
	lhs := group.Base().Multiply(z.Copy())

	var c NonceCommitmentPair
	found := false
	for _, cp := range commitments {
		if cp.ParticipantID == participantID {
			c = cp
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("no commitment for participant %d", participantID)
	}
	rho := signable.BindingFactors[participantID]

	nonceContribPt := c.Hiding.Copy().Add(c.Binding.Copy().Multiply(rho.Copy()))
	if !signable.REvenY {
		nonceContribPt = nonceContribPt.Negate()
	}

	scalar := participantLambda.Copy().Multiply(signable.Challenge.Copy())
	verifyContribPt := verificationShare.Copy().Multiply(scalar)
	if !signable.PubkeyEvenY {
		verifyContribPt = verifyContribPt.Negate()
	}

	rhs := nonceContribPt.Copy().Add(verifyContribPt)

	if !lhs.Equal(rhs) {
		return errors.New("partial signature does not match expected value")
	}
	return nil
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

// HelperBuildUserSessionForTest builds a SessionForSigning representing
// the user role, for use in tests. NOT for production use.
func HelperBuildUserSessionForTest(
	userShareBytes []byte,
	userNonceHidingBytes []byte,
	userNonceBindingBytes []byte,
	userCommitHiding string,
	userCommitBinding string,
	signerCommitHiding string,
	signerCommitBinding string,
	jointPubkeyHex string,
	eventHash []byte,
) (*SessionForSigning, error) {
	group := DefaultCiphersuite.Group()

	share := group.NewScalar()
	if err := share.Decode(userShareBytes); err != nil {
		return nil, fmt.Errorf("decode user share: %w", err)
	}
	d := group.NewScalar()
	if err := d.Decode(userNonceHidingBytes); err != nil {
		return nil, fmt.Errorf("decode user d: %w", err)
	}
	e := group.NewScalar()
	if err := e.Decode(userNonceBindingBytes); err != nil {
		return nil, fmt.Errorf("decode user e: %w", err)
	}

	userD := group.NewElement()
	if err := userD.DecodeHex(userCommitHiding); err != nil {
		return nil, fmt.Errorf("decode user D: %w", err)
	}
	userE := group.NewElement()
	if err := userE.DecodeHex(userCommitBinding); err != nil {
		return nil, fmt.Errorf("decode user E: %w", err)
	}
	signerD := group.NewElement()
	if err := signerD.DecodeHex(signerCommitHiding); err != nil {
		return nil, fmt.Errorf("decode signer D: %w", err)
	}
	signerE := group.NewElement()
	if err := signerE.DecodeHex(signerCommitBinding); err != nil {
		return nil, fmt.Errorf("decode signer E: %w", err)
	}
	jointPubkey := group.NewElement()
	if err := jointPubkey.DecodeHex(jointPubkeyHex); err != nil {
		return nil, fmt.Errorf("decode joint pubkey: %w", err)
	}

	commitments := []NonceCommitmentPair{
		{ParticipantID: uint16(UserIndex), Hiding: userD, Binding: userE},
		{ParticipantID: uint16(SignerIndex), Hiding: signerD, Binding: signerE},
	}
	allIDs := []uint16{uint16(UserIndex), uint16(SignerIndex)}

	return &SessionForSigning{
		Group:         group,
		ParticipantID: uint16(UserIndex),
		AllIDs:        allIDs,
		Commitments:   commitments,
		JointPubkey:   jointPubkey,
		Message:       eventHash,
		NonceHiding:   d,
		NonceBinding:  e,
		Share:         share,
	}, nil
}
