package frost

import (
	"crypto/sha256"
	"testing"

	"github.com/bytemare/ecc"
	frostlib "github.com/bytemare/frost"
	"github.com/bytemare/secret-sharing/keys"
)

// userSignerFixture runs the user-cosigner DKG in-process, returns the
// material on both sides plus the joint pubkey. Bridges from the DKG
// world (raw scalars) to the bytemare/frost world (KeyShare structs)
// so the cosign tests can exercise the protocol end-to-end without
// needing HTTP or persistence.
type userSignerFixture struct {
	jointPubkeyHex          string
	signerShareScalar       []byte
	signerVerificationShare []byte // 33-byte SEC1 compressed (signer_share*G)
	userKeyShare            interface{}
	userVerificationShare   string // 33-byte SEC1 hex (user_share*G)
}

// newUserSignerFixture drives the existing UserDKG to produce a 2-of-2
// share split, then post-processes both halves into bytemare/frost-
// compatible KeyShare material. Both parties speak bytemare/frost
// after this; the WASM module (P4b) will replace the user side later.
func newUserSignerFixture(t *testing.T) userSignerFixture {
	t.Helper()

	group := DefaultCiphersuite.Group()

	// User-side polynomial f(x) = a0 + a1*x. Random coefficients.
	a0 := group.NewScalar().Random()
	a1 := group.NewScalar().Random()
	// Signer-side polynomial g(x) = b0 + b1*x.
	b0 := group.NewScalar().Random()
	b1 := group.NewScalar().Random()

	// Joint pubkey P = A0 + B0
	A0 := group.Base().Multiply(a0)
	B0 := group.Base().Multiply(b0)
	jointPubkey := A0.Copy().Add(B0)

	// f(SignerIndex=2) = a0 + 2*a1
	idxSigner := group.NewScalar().SetUInt64(uint64(SignerIndex))
	idxUser := group.NewScalar().SetUInt64(uint64(UserIndex))

	fSigner := a0.Copy().Add(group.NewScalar().Set(a1).Multiply(idxSigner))
	// g(UserIndex=1) = b0 + 1*b1
	gUser := b0.Copy().Add(group.NewScalar().Set(b1).Multiply(idxUser))
	// f(UserIndex=1) = a0 + 1*a1
	fUser := a0.Copy().Add(group.NewScalar().Set(a1).Multiply(idxUser))
	// g(SignerIndex=2) = b0 + 2*b1
	gSigner := b0.Copy().Add(group.NewScalar().Set(b1).Multiply(idxSigner))

	// Final shares: each party adds their own polynomial's
	// self-evaluation to the counterpart's share-for-them.
	signerFinal := fSigner.Copy().Add(gSigner)
	userFinal := fUser.Copy().Add(gUser)

	// Verification shares (public).
	signerVerification := group.Base().Multiply(signerFinal)
	userVerification := group.Base().Multiply(userFinal)

	// Build the user-side KeyShare for the simulated user role.
	userKeyShare, err := HelperBuildKeyShareForTest(
		userFinal.Encode(),
		userVerification.Hex(),
		jointPubkey.Hex(),
		UserIndex,
	)
	if err != nil {
		t.Fatalf("build user key share: %v", err)
	}

	return userSignerFixture{
		jointPubkeyHex:          jointPubkey.Hex(),
		signerShareScalar:       signerFinal.Encode(),
		signerVerificationShare: signerVerification.Encode(),
		userKeyShare:            userKeyShare,
		userVerificationShare:   userVerification.Hex(),
	}
}

// Full end-to-end: simulate both parties, prove the aggregate signature
// verifies under bytemare/frost AND would have been accepted by the
// joint pubkey.
//
// This is the protocol reference. In P4b the user side moves to WASM;
// the WIRE FORMAT must produce bytes that drop into this same
// CompleteCosign call unchanged.
func TestUserSignerCoordinator_FullFlow(t *testing.T) {
	fx := newUserSignerFixture(t)
	coord := NewUserSignerCoordinator()

	// Event-to-sign hash. Real callers pass the BIP-340 sighash; for
	// the protocol test any 32-byte digest is fine.
	eventHash := sha256.Sum256([]byte("the post the user is about to send"))

	// Signer round 1
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
	if begin.SessionID == "" {
		t.Fatal("empty session id")
	}
	if coord.SessionCount() != 1 {
		t.Errorf("SessionCount = %d after BeginCosign, want 1", coord.SessionCount())
	}

	// User side (simulated via bytemare/frost). The user has its own
	// KeyShare and the configuration is reconstructed from the same
	// public material the signer assembled.
	userConfig := buildUserConfig(t, fx)
	userKS := fx.userKeyShare.(interface {
		Identifier() uint16
	})
	_ = userKS
	userSigner, err := userConfig.Signer(toKeyShare(t, fx.userKeyShare))
	if err != nil {
		t.Fatalf("user-side signer: %v", err)
	}
	userCommit := userSigner.Commit()

	// Build the commitment list the user would form: their own
	// commit + the signer's commit (received in begin.*Hex).
	signerCommit := decodeCommitment(t, begin.SignerCommitmentHidingHex, begin.SignerCommitmentBindingHex, SignerIndex)
	commitments := frostlib.CommitmentList{userCommit, signerCommit}
	commitments.Sort()

	// User computes their partial sig.
	userSigShare, err := userSigner.Sign(eventHash[:], commitments)
	if err != nil {
		t.Fatalf("user Sign: %v", err)
	}

	// User sends commit + partial to signer.
	sigBytes, err := coord.CompleteCosign(CompleteCosignInput{
		SessionID:                begin.SessionID,
		UserCommitmentHidingHex:  userCommit.HidingNonceCommitment.Hex(),
		UserCommitmentBindingHex: userCommit.BindingNonceCommitment.Hex(),
		UserPartialSignatureHex:  userSigShare.SignatureShare.Hex(),
	})
	if err != nil {
		t.Fatalf("CompleteCosign: %v", err)
	}
	// bytemare/frost.Signature.Encode() returns [group_id(1) || R(33) || z(32)] = 66 bytes.
	// NIP-46 conversion to 64-byte BIP-340 format happens at the dispatch boundary (P4d), not here.
	if len(sigBytes) != 66 {
		t.Errorf("signature length = %d, want 66 (1+33+32 from bytemare/frost.Signature.Encode)", len(sigBytes))
	}

	// Session must be dropped after CompleteCosign.
	if coord.SessionCount() != 0 {
		t.Errorf("SessionCount = %d after CompleteCosign, want 0", coord.SessionCount())
	}

	// Final BIP-340 verification through bytemare/frost's free function.
	group := DefaultCiphersuite.Group()
	jointPub := group.NewElement()
	if err := jointPub.DecodeHex(fx.jointPubkeyHex); err != nil {
		t.Fatalf("decode joint pubkey: %v", err)
	}
	sig := &frostlib.Signature{Group: group}
	if err := sig.Decode(sigBytes); err != nil {
		t.Fatalf("decode aggregated sig: %v", err)
	}
	if err := frostlib.VerifySignature(DefaultCiphersuite, eventHash[:], sig, jointPub); err != nil {
		t.Errorf("aggregated signature does NOT verify under BIP-340: %v", err)
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

// User partial sig from the WRONG share must fail verification, and
// the signer's secret must NOT be invoked. We can't directly assert
// "the signer's Sign was not called" without instrumentation, but if
// the user-side verification gate works the rejection comes before
// session.signer.Sign in the code path.
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

	// Build a bogus user commitment + partial sig. The commitment is
	// valid SEC1 (so we get past the decode), but the partial sig is
	// just a random scalar that won't verify against the user's
	// verification share.
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
	// Session must still be dropped on rejection.
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
	// Force-expire by mutating the session through the coordinator.
	coord.mu.Lock()
	coord.sessions[begin.SessionID].expiresAt = coord.sessions[begin.SessionID].expiresAt.Add(-UserCosignTTL * 2)
	coord.mu.Unlock()

	dropped := coord.GC()
	if dropped != 1 {
		t.Errorf("GC dropped %d sessions, want 1", dropped)
	}
	if coord.SessionCount() != 0 {
		t.Errorf("SessionCount = %d after GC, want 0", coord.SessionCount())
	}
}

// --- test helpers ---

func buildUserConfig(t *testing.T, fx userSignerFixture) *frostlib.Configuration {
	t.Helper()
	group := DefaultCiphersuite.Group()

	jointPub := group.NewElement()
	if err := jointPub.DecodeHex(fx.jointPubkeyHex); err != nil {
		t.Fatalf("decode joint pubkey: %v", err)
	}
	userVer := group.NewElement()
	if err := userVer.DecodeHex(fx.userVerificationShare); err != nil {
		t.Fatalf("decode user verification share: %v", err)
	}
	signerVer := group.NewElement()
	if err := signerVer.Decode(fx.signerVerificationShare); err != nil {
		t.Fatalf("decode signer verification share: %v", err)
	}

	cfg := &frostlib.Configuration{
		Ciphersuite:     DefaultCiphersuite,
		Threshold:       2,
		MaxSigners:      2,
		VerificationKey: jointPub,
		SignerPublicKeyShares: []*keys.PublicKeyShare{
			{PublicKey: userVer, ID: uint16(UserIndex), Group: group},
			{PublicKey: signerVer, ID: uint16(SignerIndex), Group: group},
		},
	}
	if err := cfg.Init(); err != nil {
		t.Fatalf("user config Init: %v", err)
	}
	return cfg
}

func toKeyShare(t *testing.T, v interface{}) *keys.KeyShare {
	t.Helper()
	ks, ok := v.(*keys.KeyShare)
	if !ok {
		t.Fatalf("fixture user key share is not *keys.KeyShare: %T", v)
	}
	return ks
}

func decodeCommitment(t *testing.T, hidingHex, bindingHex string, signerID int) *frostlib.Commitment {
	t.Helper()
	group := DefaultCiphersuite.Group()
	hiding := group.NewElement()
	if err := hiding.DecodeHex(hidingHex); err != nil {
		t.Fatalf("decode hiding: %v", err)
	}
	binding := group.NewElement()
	if err := binding.DecodeHex(bindingHex); err != nil {
		t.Fatalf("decode binding: %v", err)
	}
	return &frostlib.Commitment{
		HidingNonceCommitment:  hiding,
		BindingNonceCommitment: binding,
		SignerID:               uint16(signerID),
		Group:                  group,
	}
}

func zeroHex(n int) string {
	out := make([]byte, n*2)
	for i := range out {
		out[i] = '0'
	}
	return string(out)
}

// Compile-time guard against the keys import being unused if helpers
// move around.
var _ ecc.Group = DefaultCiphersuite.Group()

// Make the keys package importable at the test scope without a
// distinct import line by name-binding to it via the helper.
var _ = (*keysPlaceholder)(nil)

type keysPlaceholder struct{}
