// Package frost user_dkg: signer-side implementation of the 2-of-N
// user-cosigner DKG defined in docs/frost-2-of-n-design.md §4.2.
//
// The ceremony is a 3-round protocol between the signer (this code) and the
// user's device. Each round is one HTTPS request/response. State for a DKG
// session lives in-memory on the signer with a short TTL (60s per §4.3);
// half-committed sessions are GC'd on timeout.
//
// Math, for threshold t=2, N=2 (extensible to N>2 in §6.1):
//
//   Each party generates a degree-(t-1)=1 polynomial:
//     User:   f(x) = a0 + a1·x
//     Signer: g(x) = b0 + b1·x
//
//   Each party commits to its coefficients:
//     User:   A0 = a0·G,  A1 = a1·G
//     Signer: B0 = b0·G,  B1 = b1·G
//
//   Each party evaluates its polynomial at the other party's index and
//   sends the resulting scalar:
//     User → Signer:  f(2) = a0 + 2·a1
//     Signer → User:  g(1) = b0 + b1
//
//   Each party verifies the received scalar against the sender's commitment:
//     User-share-for-signer·G == A0 + A1·2
//     Signer-share-for-user·G == B0 + B1·1
//
//   Each party's final share is the sum of evaluations received:
//     signer_share = f(2) + g(2)   (signer evaluates its own polynomial too)
//     user_share   = f(1) + g(1)
//
//   Joint pubkey = A0 + B0 = (a0 + b0)·G = master_secret·G
//   (where master_secret = a0 + b0 is never reconstructed by either party.)
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

// Signer's participant index in 2-of-N. Users get index 1, signer index 2.
// Both indices must be non-zero scalars (the polynomial constant term is
// evaluated at index, and 0 would expose the secret directly).
const (
	UserIndex   = 1
	SignerIndex = 2
)

// DKGSessionTTL is how long a half-committed DKG session lives before GC.
// Aligned with docs/frost-2-of-n-design.md §4.3.
const DKGSessionTTL = 60 * time.Second

// Errors returned by the DKG protocol.
var (
	ErrDKGSessionNotFound  = errors.New("dkg session not found or expired")
	ErrDKGWrongPhase       = errors.New("dkg session is in the wrong phase for this request")
	ErrDKGVerificationFail = errors.New("dkg share verification failed against received commitments")
	ErrDKGPubkeyMismatch   = errors.New("dkg finalize: joint pubkey reported by user does not match signer-computed value")
)

// UserDKGPhase tracks where a session is in the 3-round protocol.
type UserDKGPhase int

const (
	PhaseAwaitingRound1 UserDKGPhase = iota // initial state, never persisted
	PhaseAwaitingRound2                     // signer has both parties' commitments; awaiting user's encrypted share
	PhaseAwaitingFinalize                   // both shares exchanged + verified; awaiting user's pubkey confirmation
	PhaseComplete                           // finalize succeeded; session can be GC'd
)

// userDKGState holds the signer's view of one DKG session.
type userDKGState struct {
	SessionID string
	UserID    string
	Phase     UserDKGPhase

	// Signer's polynomial g(x) = b0 + b1·x. b0 IS the signer's contribution
	// to the master secret; never leaves this struct, never written to disk,
	// dropped on session close.
	signerCoeffs []*ecc.Scalar // [b0, b1]

	// Signer's commitments B0, B1.
	signerCommits []*ecc.Element

	// User's commitments A0, A1, received in round 1.
	userCommits []*ecc.Element

	// Signer's final aggregated share = f(SignerIndex) + g(SignerIndex).
	// Populated in round 2 after the user's share-for-signer is verified.
	signerShare *ecc.Scalar

	// Joint pubkey = A0 + B0. Computed in round 2 (signer side); user computes
	// independently and confirms in finalize.
	jointPubkey *ecc.Element

	CreatedAt time.Time
	ExpiresAt time.Time
}

// UserDKG drives the signer side of the 2-of-N user-cosigner DKG.
type UserDKG struct {
	mu       sync.Mutex
	sessions map[string]*userDKGState
}

// NewUserDKG creates a fresh DKG coordinator with an empty session store.
// Call GC periodically (or wire to a janitor goroutine) to drop expired
// sessions; sessions also self-expire on access.
func NewUserDKG() *UserDKG {
	return &UserDKG{
		sessions: make(map[string]*userDKGState),
	}
}

// Round1Request is what the user device sends in round 1.
type Round1Request struct {
	UserID         string   `json:"user_id"`          // taken from auth context in the HTTP handler; included here for the in-process path
	UserCommitsHex []string `json:"user_commits_hex"` // [A0_hex, A1_hex]
}

// Round1Response is what the signer returns in round 1.
type Round1Response struct {
	SessionID        string   `json:"session_id"`
	SignerCommitsHex []string `json:"signer_commits_hex"` // [B0_hex, B1_hex]
}

// Round2Request is what the user device sends in round 2.
type Round2Request struct {
	SessionID             string `json:"session_id"`
	UserShareForSignerHex string `json:"user_share_for_signer_hex"` // f(SignerIndex)
}

// Round2Response is what the signer returns in round 2.
type Round2Response struct {
	SignerShareForUserHex string `json:"signer_share_for_user_hex"` // g(UserIndex)
}

// FinalizeRequest is what the user device sends in round 3.
type FinalizeRequest struct {
	SessionID             string `json:"session_id"`
	ConfirmJointPubkeyHex string `json:"confirm_joint_pubkey_hex"` // user-computed P, signer verifies it matches its own computation
}

// FinalizeResult is what Finalize returns to the HTTP handler. The handler
// is responsible for persisting the Key + FrostUserShare via the storage
// layer; UserDKG itself is storage-agnostic.
type FinalizeResult struct {
	SessionID         string
	UserID            string
	JointPubkey       []byte // encoded element (caller chooses storage encoding)
	SignerShare       []byte // encoded scalar - caller MUST Vault-encrypt before persisting
	VerificationShare []byte // encoded element - public, safe to store unencrypted
	Threshold         int
	TotalShares       int
}

// Round1 processes the user's commitments and returns the signer's.
// Side effect: creates a new session in PhaseAwaitingRound2.
func (d *UserDKG) Round1(req *Round1Request) (*Round1Response, error) {
	if req.UserID == "" {
		return nil, errors.New("user_id is required")
	}
	if len(req.UserCommitsHex) != 2 {
		return nil, fmt.Errorf("expected 2 user commitments (degree-1 polynomial), got %d", len(req.UserCommitsHex))
	}

	group := DefaultCiphersuite.Group()

	// Decode user's commitments.
	userCommits := make([]*ecc.Element, 2)
	for i, h := range req.UserCommitsHex {
		el := group.NewElement()
		if err := el.DecodeHex(h); err != nil {
			return nil, fmt.Errorf("decode user commit %d: %w", i, err)
		}
		userCommits[i] = el
	}

	// Generate signer's polynomial g(x) = b0 + b1·x with fresh randomness.
	// b0 is the signer's secret contribution to the master.
	b0 := group.NewScalar().Random()
	b1 := group.NewScalar().Random()

	// Compute signer's commitments B0 = b0·G, B1 = b1·G.
	B0 := group.Base().Multiply(b0)
	B1 := group.Base().Multiply(b1)

	sessionID, err := newSessionID()
	if err != nil {
		return nil, fmt.Errorf("session id: %w", err)
	}

	now := time.Now()
	state := &userDKGState{
		SessionID:     sessionID,
		UserID:        req.UserID,
		Phase:         PhaseAwaitingRound2,
		signerCoeffs:  []*ecc.Scalar{b0, b1},
		signerCommits: []*ecc.Element{B0, B1},
		userCommits:   userCommits,
		CreatedAt:     now,
		ExpiresAt:     now.Add(DKGSessionTTL),
	}

	d.mu.Lock()
	d.sessions[sessionID] = state
	d.mu.Unlock()

	return &Round1Response{
		SessionID:        sessionID,
		SignerCommitsHex: []string{B0.Hex(), B1.Hex()},
	}, nil
}

// Round2 verifies the user's share-for-signer, computes the signer's own
// aggregated share, and returns the signer's share-for-user.
func (d *UserDKG) Round2(req *Round2Request) (*Round2Response, error) {
	state, err := d.getSession(req.SessionID, PhaseAwaitingRound2)
	if err != nil {
		return nil, err
	}

	group := DefaultCiphersuite.Group()

	// Decode user's share-for-signer.
	userShareForSigner := group.NewScalar()
	rawShare, err := hex.DecodeString(req.UserShareForSignerHex)
	if err != nil {
		return nil, fmt.Errorf("decode user_share_for_signer hex: %w", err)
	}
	if err := userShareForSigner.Decode(rawShare); err != nil {
		return nil, fmt.Errorf("decode user_share_for_signer scalar: %w", err)
	}

	// Verify f(SignerIndex)·G == A0 + SignerIndex·A1.
	if !verifyShareAgainstCommitment(userShareForSigner, SignerIndex, state.userCommits, group) {
		d.dropSession(state.SessionID)
		return nil, ErrDKGVerificationFail
	}

	// Compute signer's evaluation of its own polynomial at SignerIndex.
	// g(SignerIndex) = b0 + b1·SignerIndex.
	signerShareSelf := evaluatePolynomial(state.signerCoeffs, SignerIndex, group)

	// Compute signer's evaluation at UserIndex - this is what we send to the user.
	signerShareForUser := evaluatePolynomial(state.signerCoeffs, UserIndex, group)

	// Compute signer's final aggregated share: f(SignerIndex) + g(SignerIndex).
	finalSignerShare := group.NewScalar().Set(userShareForSigner)
	finalSignerShare.Add(signerShareSelf)

	// Compute joint pubkey = A0 + B0.
	jointPubkey := group.NewElement().Set(state.userCommits[0])
	jointPubkey.Add(state.signerCommits[0])

	d.mu.Lock()
	state.signerShare = finalSignerShare
	state.jointPubkey = jointPubkey
	state.Phase = PhaseAwaitingFinalize
	d.mu.Unlock()

	return &Round2Response{
		SignerShareForUserHex: hex.EncodeToString(signerShareForUser.Encode()),
	}, nil
}

// Finalize verifies the user-reported joint pubkey matches the signer's
// computation and returns the materials the handler needs to persist.
// The session is dropped immediately on success.
//
// FinalizeResult.SignerShare is plaintext scalar bytes - the HTTP handler
// MUST Vault-encrypt before writing to storage. UserDKG keeps no
// persistent state.
func (d *UserDKG) Finalize(req *FinalizeRequest) (*FinalizeResult, error) {
	state, err := d.getSession(req.SessionID, PhaseAwaitingFinalize)
	if err != nil {
		return nil, err
	}

	group := DefaultCiphersuite.Group()

	confirmPubkey := group.NewElement()
	if err := confirmPubkey.DecodeHex(req.ConfirmJointPubkeyHex); err != nil {
		return nil, fmt.Errorf("decode confirm_joint_pubkey_hex: %w", err)
	}

	if !confirmPubkey.Equal(state.jointPubkey) {
		d.dropSession(state.SessionID)
		return nil, ErrDKGPubkeyMismatch
	}

	// signer_share·G - public material used to verify the signer's partial
	// signatures during signing.
	verificationShare := group.Base().Multiply(state.signerShare)

	result := &FinalizeResult{
		SessionID:         state.SessionID,
		UserID:            state.UserID,
		JointPubkey:       state.jointPubkey.Encode(),
		SignerShare:       state.signerShare.Encode(),
		VerificationShare: verificationShare.Encode(),
		Threshold:         2,
		TotalShares:       2,
	}

	d.dropSession(state.SessionID)
	return result, nil
}

// GC drops expired sessions. Call periodically.
func (d *UserDKG) GC() int {
	now := time.Now()
	d.mu.Lock()
	defer d.mu.Unlock()
	dropped := 0
	for id, state := range d.sessions {
		if now.After(state.ExpiresAt) {
			delete(d.sessions, id)
			dropped++
		}
	}
	return dropped
}

// SessionCount returns the number of in-memory sessions. Useful for tests
// and observability.
func (d *UserDKG) SessionCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.sessions)
}

func (d *UserDKG) getSession(sessionID string, expectedPhase UserDKGPhase) (*userDKGState, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	state, ok := d.sessions[sessionID]
	if !ok {
		return nil, ErrDKGSessionNotFound
	}
	if time.Now().After(state.ExpiresAt) {
		delete(d.sessions, sessionID)
		return nil, ErrDKGSessionNotFound
	}
	if state.Phase != expectedPhase {
		return nil, ErrDKGWrongPhase
	}
	return state, nil
}

func (d *UserDKG) dropSession(sessionID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.sessions, sessionID)
}

// (evaluatePolynomial and verifyShareAgainstCommitment are defined in
// dkg_distributed.go and reused here. Both handle the general polynomial
// case; for 2-of-N the degree is 1 but the same math applies.)

func newSessionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}
