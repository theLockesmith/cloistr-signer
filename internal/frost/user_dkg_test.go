package frost

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/bytemare/ecc"
)

// End-to-end driver for the 2-of-N user-cosigner DKG. The signer is the
// real UserDKG implementation; the "user device" half is simulated in-test
// using the same primitives a browser WASM module would use.
//
// This test is the contract that the P3 browser implementation has to
// satisfy. Anything the test does, the browser does.

// userPartyState mirrors what the browser holds during DKG.
type userPartyState struct {
	coeffs  []*ecc.Scalar  // [a0, a1]
	commits []*ecc.Element // [A0, A1]
}

func newUserParty(t *testing.T) *userPartyState {
	t.Helper()
	group := DefaultCiphersuite.Group()
	a0 := group.NewScalar().Random()
	a1 := group.NewScalar().Random()
	return &userPartyState{
		coeffs:  []*ecc.Scalar{a0, a1},
		commits: []*ecc.Element{group.Base().Multiply(a0), group.Base().Multiply(a1)},
	}
}

func (u *userPartyState) commitsHex() []string {
	return []string{u.commits[0].Hex(), u.commits[1].Hex()}
}

// shareForSigner evaluates f(SignerIndex) and returns the scalar bytes.
func (u *userPartyState) shareForSigner() string {
	share := evaluatePolynomial(u.coeffs, SignerIndex, DefaultCiphersuite.Group())
	return hex.EncodeToString(share.Encode())
}

// finalize_aggregate computes the user's final share = f(UserIndex) + g(UserIndex)
// given the signer's share-for-user.
func (u *userPartyState) finalShare(t *testing.T, signerShareForUserHex string) *ecc.Scalar {
	t.Helper()
	group := DefaultCiphersuite.Group()
	signerShare := group.NewScalar()
	rawShare, err := hex.DecodeString(signerShareForUserHex)
	if err != nil {
		t.Fatalf("decode signer share hex: %v", err)
	}
	if err := signerShare.Decode(rawShare); err != nil {
		t.Fatalf("decode signer share scalar: %v", err)
	}

	userSelf := evaluatePolynomial(u.coeffs, UserIndex, group)
	final := group.NewScalar().Set(userSelf)
	final.Add(signerShare)
	return final
}

func TestUserDKG_EndToEnd(t *testing.T) {
	d := NewUserDKG()
	user := newUserParty(t)

	// Round 1
	r1Resp, err := d.Round1(&Round1Request{
		UserID:         "user-test-1",
		UserCommitsHex: user.commitsHex(),
	})
	if err != nil {
		t.Fatalf("Round1: %v", err)
	}
	if r1Resp.SessionID == "" {
		t.Fatal("Round1 returned empty session_id")
	}
	if len(r1Resp.SignerCommitsHex) != 2 {
		t.Fatalf("Round1 returned %d commits, want 2", len(r1Resp.SignerCommitsHex))
	}
	if d.SessionCount() != 1 {
		t.Errorf("expected 1 active session after Round1, got %d", d.SessionCount())
	}

	// Round 2: user verifies signer's commits structurally (decode succeeds), then sends share.
	group := DefaultCiphersuite.Group()
	signerCommits := make([]*ecc.Element, 2)
	for i, h := range r1Resp.SignerCommitsHex {
		signerCommits[i] = group.NewElement()
		if err := signerCommits[i].DecodeHex(h); err != nil {
			t.Fatalf("decode signer commit %d: %v", i, err)
		}
	}

	r2Resp, err := d.Round2(&Round2Request{
		SessionID:             r1Resp.SessionID,
		UserShareForSignerHex: user.shareForSigner(),
	})
	if err != nil {
		t.Fatalf("Round2: %v", err)
	}
	if r2Resp.SignerShareForUserHex == "" {
		t.Fatal("Round2 returned empty signer share")
	}

	// User verifies the received share against signer's commitments.
	signerShareForUser := group.NewScalar()
	rawShare, err := hex.DecodeString(r2Resp.SignerShareForUserHex)
	if err != nil {
		t.Fatalf("decode signer share hex: %v", err)
	}
	if err := signerShareForUser.Decode(rawShare); err != nil {
		t.Fatalf("decode signer share scalar: %v", err)
	}
	if !verifyShareAgainstCommitment(signerShareForUser, UserIndex, signerCommits, group) {
		t.Fatal("signer's share-for-user did not verify against signer's commitments")
	}

	// User computes the joint pubkey: A0 + B0.
	userJointPubkey := group.NewElement().Set(user.commits[0])
	userJointPubkey.Add(signerCommits[0])

	// User computes its final share.
	userShare := user.finalShare(t, r2Resp.SignerShareForUserHex)

	// Finalize: user reports its computed pubkey; signer verifies + persists.
	finalizeResult, err := d.Finalize(&FinalizeRequest{
		SessionID:             r1Resp.SessionID,
		ConfirmJointPubkeyHex: userJointPubkey.Hex(),
	})
	if err != nil {
		t.Fatalf("Finalize: %v", err)
	}

	if d.SessionCount() != 0 {
		t.Errorf("expected 0 sessions after Finalize (session should be dropped), got %d", d.SessionCount())
	}

	// Pubkey returned to handler must match what user computed.
	finalizePubkey := group.NewElement()
	if err := finalizePubkey.Decode(finalizeResult.JointPubkey); err != nil {
		t.Fatalf("decode finalize pubkey: %v", err)
	}
	if !finalizePubkey.Equal(userJointPubkey) {
		t.Error("finalize result pubkey does not match user-computed pubkey")
	}

	// The two final shares must be a valid Shamir 2-of-2 reconstruction of
	// the joint secret. We verify this by reconstructing via Lagrange and
	// checking master_secret·G == joint pubkey.
	signerShare := group.NewScalar()
	if err := signerShare.Decode(finalizeResult.SignerShare); err != nil {
		t.Fatalf("decode signer share from finalize: %v", err)
	}

	masterSecret := lagrangeReconstruct(t, group, []*ecc.Scalar{userShare, signerShare}, []int{UserIndex, SignerIndex})
	reconstructedPubkey := group.Base().Multiply(masterSecret)
	if !reconstructedPubkey.Equal(userJointPubkey) {
		t.Error("reconstructed master·G does not equal joint pubkey - shares do not form a valid 2-of-2")
	}

	// Verification share returned to handler must equal signer_share·G.
	expectedVS := group.Base().Multiply(signerShare)
	actualVS := group.NewElement()
	if err := actualVS.Decode(finalizeResult.VerificationShare); err != nil {
		t.Fatalf("decode verification share: %v", err)
	}
	if !actualVS.Equal(expectedVS) {
		t.Error("verification share != signer_share·G")
	}

	if finalizeResult.Threshold != 2 || finalizeResult.TotalShares != 2 {
		t.Errorf("threshold/total = %d/%d, want 2/2", finalizeResult.Threshold, finalizeResult.TotalShares)
	}
}

func TestUserDKG_Round1RejectsBadCommitments(t *testing.T) {
	d := NewUserDKG()

	cases := []struct {
		name string
		req  *Round1Request
	}{
		{"no user id", &Round1Request{UserID: "", UserCommitsHex: []string{"00", "00"}}},
		{"wrong commit count", &Round1Request{UserID: "u", UserCommitsHex: []string{"00"}}},
		{"undecodable commit", &Round1Request{UserID: "u", UserCommitsHex: []string{"not-hex", "00"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := d.Round1(tc.req); err == nil {
				t.Error("expected error")
			}
		})
	}
}

func TestUserDKG_Round2DetectsBadShare(t *testing.T) {
	// Adversarial user sends a share that does NOT match its committed
	// polynomial. The signer must detect via the commitment check and abort.
	d := NewUserDKG()
	user := newUserParty(t)

	r1Resp, err := d.Round1(&Round1Request{
		UserID:         "user-test-attack",
		UserCommitsHex: user.commitsHex(),
	})
	if err != nil {
		t.Fatalf("Round1: %v", err)
	}

	// Send a random scalar instead of the correct f(SignerIndex).
	group := DefaultCiphersuite.Group()
	bogus := group.NewScalar().Random()
	_, err = d.Round2(&Round2Request{
		SessionID:             r1Resp.SessionID,
		UserShareForSignerHex: hex.EncodeToString(bogus.Encode()),
	})
	if err != ErrDKGVerificationFail {
		t.Errorf("expected ErrDKGVerificationFail, got %v", err)
	}
	if d.SessionCount() != 0 {
		t.Error("session should be dropped after verification failure")
	}
}

func TestUserDKG_FinalizeDetectsPubkeyMismatch(t *testing.T) {
	// Adversarial user reports a pubkey that doesn't match the signer's
	// computation. Signer must reject finalize.
	d := NewUserDKG()
	user := newUserParty(t)

	r1Resp, _ := d.Round1(&Round1Request{
		UserID:         "user-mismatch",
		UserCommitsHex: user.commitsHex(),
	})
	_, _ = d.Round2(&Round2Request{
		SessionID:             r1Resp.SessionID,
		UserShareForSignerHex: user.shareForSigner(),
	})

	group := DefaultCiphersuite.Group()
	bogusPubkey := group.Base().Multiply(group.NewScalar().Random())
	_, err := d.Finalize(&FinalizeRequest{
		SessionID:             r1Resp.SessionID,
		ConfirmJointPubkeyHex: bogusPubkey.Hex(),
	})
	if err != ErrDKGPubkeyMismatch {
		t.Errorf("expected ErrDKGPubkeyMismatch, got %v", err)
	}
}

func TestUserDKG_WrongPhaseRejection(t *testing.T) {
	d := NewUserDKG()
	user := newUserParty(t)

	r1Resp, _ := d.Round1(&Round1Request{
		UserID:         "user-phase",
		UserCommitsHex: user.commitsHex(),
	})

	// Calling Finalize before Round2 must fail with wrong-phase.
	group := DefaultCiphersuite.Group()
	someElement := group.Base().Multiply(group.NewScalar().Random())
	_, err := d.Finalize(&FinalizeRequest{
		SessionID:             r1Resp.SessionID,
		ConfirmJointPubkeyHex: someElement.Hex(),
	})
	if err != ErrDKGWrongPhase {
		t.Errorf("expected ErrDKGWrongPhase, got %v", err)
	}
}

func TestUserDKG_SessionNotFound(t *testing.T) {
	d := NewUserDKG()
	_, err := d.Round2(&Round2Request{
		SessionID:             "deadbeef",
		UserShareForSignerHex: "00",
	})
	if err != ErrDKGSessionNotFound {
		t.Errorf("expected ErrDKGSessionNotFound, got %v", err)
	}
}

func TestUserDKG_SessionExpiry(t *testing.T) {
	d := NewUserDKG()
	user := newUserParty(t)
	r1Resp, err := d.Round1(&Round1Request{
		UserID:         "user-expire",
		UserCommitsHex: user.commitsHex(),
	})
	if err != nil {
		t.Fatalf("Round1: %v", err)
	}

	// Manually expire the session by mutating ExpiresAt.
	d.mu.Lock()
	state := d.sessions[r1Resp.SessionID]
	state.ExpiresAt = time.Now().Add(-1 * time.Minute)
	d.mu.Unlock()

	_, err = d.Round2(&Round2Request{
		SessionID:             r1Resp.SessionID,
		UserShareForSignerHex: user.shareForSigner(),
	})
	if err != ErrDKGSessionNotFound {
		t.Errorf("expired session should return ErrDKGSessionNotFound, got %v", err)
	}

	dropped := d.GC()
	if dropped != 0 {
		t.Errorf("session was already self-expired on access; GC found %d to drop", dropped)
	}
}

func TestUserDKG_GCExpired(t *testing.T) {
	d := NewUserDKG()
	user := newUserParty(t)

	for i := 0; i < 3; i++ {
		_, err := d.Round1(&Round1Request{
			UserID:         "user-gc-" + strings.Repeat("x", i+1),
			UserCommitsHex: user.commitsHex(),
		})
		if err != nil {
			t.Fatalf("Round1: %v", err)
		}
	}
	if d.SessionCount() != 3 {
		t.Fatalf("expected 3 sessions, got %d", d.SessionCount())
	}

	d.mu.Lock()
	past := time.Now().Add(-1 * time.Minute)
	for _, state := range d.sessions {
		state.ExpiresAt = past
	}
	d.mu.Unlock()

	dropped := d.GC()
	if dropped != 3 {
		t.Errorf("GC dropped %d, want 3", dropped)
	}
	if d.SessionCount() != 0 {
		t.Errorf("expected 0 sessions post-GC, got %d", d.SessionCount())
	}
}

// lagrangeReconstruct interpolates the polynomial at x=0 given shares at the
// supplied indices. Used in the end-to-end test to verify the two shares
// reconstruct a master secret whose scalar·G equals the joint pubkey - i.e.,
// the DKG produced a valid 2-of-2 sharing.
func lagrangeReconstruct(t *testing.T, group ecc.Group, shares []*ecc.Scalar, indices []int) *ecc.Scalar {
	t.Helper()
	if len(shares) != len(indices) {
		t.Fatalf("share count %d != index count %d", len(shares), len(indices))
	}

	result := group.NewScalar()

	for i, share := range shares {
		// Compute Lagrange coefficient l_i(0) = prod_{j != i} (-x_j) / (x_i - x_j)
		lambda := group.NewScalar().One()
		xi := group.NewScalar().SetUInt64(uint64(indices[i]))

		for j, idx := range indices {
			if i == j {
				continue
			}
			xj := group.NewScalar().SetUInt64(uint64(idx))

			// numerator: -x_j  (which is 0 - x_j in scalar field)
			numerator := group.NewScalar().Zero()
			numerator.Subtract(xj)

			// denominator: x_i - x_j
			denominator := group.NewScalar().Set(xi)
			denominator.Subtract(xj)

			// numerator / denominator
			invDenominator := denominator.Invert()
			term := group.NewScalar().Set(numerator)
			term.Multiply(invDenominator)

			lambda.Multiply(term)
		}

		// result += share * lambda
		contribution := group.NewScalar().Set(share)
		contribution.Multiply(lambda)
		result.Add(contribution)
	}

	return result
}
