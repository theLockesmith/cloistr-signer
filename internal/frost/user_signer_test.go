package frost

import (
	"crypto/sha256"
	"testing"

	"github.com/bytemare/ecc"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// userSignerFixture is a 2-of-2 FROST key setup produced in-test via the
// DKG polynomial math. Both parties' final shares and the joint pubkey
// are derived so we can exercise the BIP-340 cosigning path end-to-end.
type userSignerFixture struct {
	jointPubkeyHex          string
	signerShareScalar       []byte
	signerVerificationShare []byte // 33-byte compressed (signer_share*G)
	userShareScalar         []byte
	userVerificationShare   string // 33-byte compressed hex (user_share*G)
}

func newUserSignerFixture(t *testing.T) userSignerFixture {
	t.Helper()

	group := DefaultCiphersuite.Group()

	a0 := group.NewScalar().Random()
	a1 := group.NewScalar().Random()
	b0 := group.NewScalar().Random()
	b1 := group.NewScalar().Random()

	A0 := group.Base().Multiply(a0)
	B0 := group.Base().Multiply(b0)
	jointPubkey := A0.Copy().Add(B0)

	idxSigner := group.NewScalar().SetUInt64(uint64(SignerIndex))
	idxUser := group.NewScalar().SetUInt64(uint64(UserIndex))

	fSigner := a0.Copy().Add(group.NewScalar().Set(a1).Multiply(idxSigner))
	gUser := b0.Copy().Add(group.NewScalar().Set(b1).Multiply(idxUser))
	fUser := a0.Copy().Add(group.NewScalar().Set(a1).Multiply(idxUser))
	gSigner := b0.Copy().Add(group.NewScalar().Set(b1).Multiply(idxSigner))

	signerFinal := fSigner.Copy().Add(gSigner)
	userFinal := fUser.Copy().Add(gUser)

	signerVerification := group.Base().Multiply(signerFinal)
	userVerification := group.Base().Multiply(userFinal)

	return userSignerFixture{
		jointPubkeyHex:          jointPubkey.Hex(),
		signerShareScalar:       signerFinal.Encode(),
		signerVerificationShare: signerVerification.Encode(),
		userShareScalar:         userFinal.Encode(),
		userVerificationShare:   userVerification.Hex(),
	}
}

// simulateUserPartial runs the user side of the cosign ceremony using
// the BIP-340 FROST primitives, given the signer's advertised
// commitment. Returns the user's commitment and partial sig.
func simulateUserPartial(t *testing.T, fx userSignerFixture, signerHiding, signerBinding string, eventHash []byte) (dCommitHex, eCommitHex, partialHex string) {
	t.Helper()
	group := DefaultCiphersuite.Group()

	dUser := group.NewScalar().Random()
	eUser := group.NewScalar().Random()
	dUserCommit := group.Base().Multiply(dUser)
	eUserCommit := group.Base().Multiply(eUser)

	sess, err := HelperBuildUserSessionForTest(
		fx.userShareScalar,
		dUser.Encode(),
		eUser.Encode(),
		dUserCommit.Hex(),
		eUserCommit.Hex(),
		signerHiding,
		signerBinding,
		fx.jointPubkeyHex,
		eventHash,
	)
	if err != nil {
		t.Fatalf("build user session: %v", err)
	}
	signable, err := PrepareSignable(sess)
	if err != nil {
		t.Fatalf("PrepareSignable: %v", err)
	}
	z := sess.Sign(signable)
	return dUserCommit.Hex(), eUserCommit.Hex(), z.Hex()
}

// Full end-to-end cosigning test. Both parties use hand-rolled
// BIP-340-mode FROST. Result MUST verify as a real BIP-340 signature
// under btcec/schnorr - the same verifier Nostr relays use.
func TestUserSignerCoordinator_FullFlow(t *testing.T) {
	fx := newUserSignerFixture(t)
	coord := NewUserSignerCoordinator()
	eventHash := sha256.Sum256([]byte("the post the user is about to send"))

	begin, err := coord.BeginCosign(UserCosignSetup{
		KeyID:                    "test-key",
		JointPubkeyHex:           fx.jointPubkeyHex,
		SignerShareScalar:        fx.signerShareScalar,
		SignerVerificationShare:  fx.signerVerificationShare,
		UserVerificationShareHex: fx.userVerificationShare,
		EventHash:                eventHash[:],
	})
	if err != nil {
		t.Fatalf("BeginCosign: %v", err)
	}
	if coord.SessionCount() != 1 {
		t.Errorf("SessionCount = %d, want 1", coord.SessionCount())
	}

	dUserHex, eUserHex, partialHex := simulateUserPartial(
		t, fx,
		begin.SignerCommitmentHidingHex,
		begin.SignerCommitmentBindingHex,
		eventHash[:],
	)

	sigBytes, err := coord.CompleteCosign(CompleteCosignInput{
		SessionID:                begin.SessionID,
		UserCommitmentHidingHex:  dUserHex,
		UserCommitmentBindingHex: eUserHex,
		UserPartialSignatureHex:  partialHex,
	})
	if err != nil {
		t.Fatalf("CompleteCosign: %v", err)
	}
	if len(sigBytes) != 64 {
		t.Errorf("sig length = %d, want 64 (BIP-340 canonical)", len(sigBytes))
	}
	if coord.SessionCount() != 0 {
		t.Errorf("SessionCount after CompleteCosign = %d, want 0", coord.SessionCount())
	}

	// ACCEPTANCE CRITERION: verify under btcec/schnorr (BIP-340).
	sig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		t.Fatalf("schnorr.ParseSignature: %v", err)
	}
	jointPub := parseElement(t, fx.jointPubkeyHex)
	pEncoded := jointPub.Encode()
	pk, err := schnorr.ParsePubKey(pEncoded[1:])
	if err != nil {
		t.Fatalf("schnorr.ParsePubKey: %v", err)
	}
	if !sig.Verify(eventHash[:], pk) {
		t.Fatal("BIP-340 signature did NOT verify under btcec/schnorr - P4a' math is wrong")
	}
}

// Unknown session must surface ErrCosignSessionNotFound.
func TestUserSignerCoordinator_CompleteCosignUnknownSession(t *testing.T) {
	coord := NewUserSignerCoordinator()
	_, err := coord.CompleteCosign(CompleteCosignInput{
		SessionID:                "nonexistent",
		UserCommitmentHidingHex:  "02" + zeroHex(32),
		UserCommitmentBindingHex: "02" + zeroHex(32),
		UserPartialSignatureHex:  zeroHex(32),
	})
	if err != ErrCosignSessionNotFound {
		t.Errorf("got %v, want ErrCosignSessionNotFound", err)
	}
}

// Random scalar as user partial sig must be rejected without invoking
// the signer's secret material.
func TestUserSignerCoordinator_RejectsBadUserPartialSig(t *testing.T) {
	fx := newUserSignerFixture(t)
	coord := NewUserSignerCoordinator()
	eventHash := sha256.Sum256([]byte("x"))

	begin, err := coord.BeginCosign(UserCosignSetup{
		KeyID:                    "test-key",
		JointPubkeyHex:           fx.jointPubkeyHex,
		SignerShareScalar:        fx.signerShareScalar,
		SignerVerificationShare:  fx.signerVerificationShare,
		UserVerificationShareHex: fx.userVerificationShare,
		EventHash:                eventHash[:],
	})
	if err != nil {
		t.Fatalf("BeginCosign: %v", err)
	}

	group := DefaultCiphersuite.Group()
	bogusHiding := group.Base().Multiply(group.NewScalar().Random())
	bogusBinding := group.Base().Multiply(group.NewScalar().Random())
	bogusZ := group.NewScalar().Random()

	_, err = coord.CompleteCosign(CompleteCosignInput{
		SessionID:                begin.SessionID,
		UserCommitmentHidingHex:  bogusHiding.Hex(),
		UserCommitmentBindingHex: bogusBinding.Hex(),
		UserPartialSignatureHex:  bogusZ.Hex(),
	})
	if err == nil {
		t.Fatal("expected error for bogus user partial sig, got nil")
	}
	if coord.SessionCount() != 0 {
		t.Errorf("SessionCount = %d after rejection, want 0", coord.SessionCount())
	}
}

// GC drops expired sessions.
func TestUserSignerCoordinator_GC(t *testing.T) {
	fx := newUserSignerFixture(t)
	coord := NewUserSignerCoordinator()
	eventHash := sha256.Sum256([]byte("x"))

	begin, err := coord.BeginCosign(UserCosignSetup{
		KeyID:                    "test-key",
		JointPubkeyHex:           fx.jointPubkeyHex,
		SignerShareScalar:        fx.signerShareScalar,
		SignerVerificationShare:  fx.signerVerificationShare,
		UserVerificationShareHex: fx.userVerificationShare,
		EventHash:                eventHash[:],
	})
	if err != nil {
		t.Fatalf("BeginCosign: %v", err)
	}
	coord.mu.Lock()
	coord.sessions[begin.SessionID].expiresAt = coord.sessions[begin.SessionID].expiresAt.Add(-UserCosignTTL * 2)
	coord.mu.Unlock()

	dropped := coord.GC()
	if dropped != 1 {
		t.Errorf("GC dropped %d, want 1", dropped)
	}
	if coord.SessionCount() != 0 {
		t.Errorf("SessionCount = %d after GC, want 0", coord.SessionCount())
	}
}

// P4a' merge gate: the BIP-340 KnownIssue test flips to positive. If
// this test EVER fails after P4a', the BIP-340 signing math has
// regressed and no downstream FROST work should proceed.
func TestUserSignerCoordinator_SignatureVerifiesAsBIP340(t *testing.T) {
	fx := newUserSignerFixture(t)
	coord := NewUserSignerCoordinator()
	eventHash := sha256.Sum256([]byte("nostr event body for a real relay"))

	begin, err := coord.BeginCosign(UserCosignSetup{
		KeyID:                    "test-key",
		JointPubkeyHex:           fx.jointPubkeyHex,
		SignerShareScalar:        fx.signerShareScalar,
		SignerVerificationShare:  fx.signerVerificationShare,
		UserVerificationShareHex: fx.userVerificationShare,
		EventHash:                eventHash[:],
	})
	if err != nil {
		t.Fatalf("BeginCosign: %v", err)
	}

	dUserHex, eUserHex, partialHex := simulateUserPartial(
		t, fx,
		begin.SignerCommitmentHidingHex,
		begin.SignerCommitmentBindingHex,
		eventHash[:],
	)

	sigBytes, err := coord.CompleteCosign(CompleteCosignInput{
		SessionID:                begin.SessionID,
		UserCommitmentHidingHex:  dUserHex,
		UserCommitmentBindingHex: eUserHex,
		UserPartialSignatureHex:  partialHex,
	})
	if err != nil {
		t.Fatalf("CompleteCosign: %v", err)
	}

	if err := VerifyBIP340(sigBytes, eventHash[:], parseElement(t, fx.jointPubkeyHex)); err != nil {
		t.Fatalf("VerifyBIP340: %v", err)
	}

	sig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		t.Fatalf("schnorr.ParseSignature: %v", err)
	}
	jointPub := parseElement(t, fx.jointPubkeyHex)
	pEncoded := jointPub.Encode()
	pk, err := schnorr.ParsePubKey(pEncoded[1:])
	if err != nil {
		t.Fatalf("schnorr.ParsePubKey: %v", err)
	}
	if !sig.Verify(eventHash[:], pk) {
		t.Fatal("BIP-340 signature does not verify under btcec/schnorr")
	}
	t.Log("BIP-340 signature verifies via btcec/schnorr - Nostr-compatible")
}

// --- test helpers ---

func parseElement(t *testing.T, hexStr string) *ecc.Element {
	t.Helper()
	group := DefaultCiphersuite.Group()
	e := group.NewElement()
	if err := e.DecodeHex(hexStr); err != nil {
		t.Fatalf("decode element hex: %v", err)
	}
	return e
}

func zeroHex(n int) string {
	out := make([]byte, n*2)
	for i := range out {
		out[i] = '0'
	}
	return string(out)
}
