// bip340_frost.go: BIP-340-mode FROST math for 2-of-N user-cosigner
// signing (and reusable by the Phase 13 signer-to-signer coordinator).
//
// This is a hand-rolled implementation because neither bytemare/frost
// (Go) nor frost-secp256k1 (Rust) produce byte-identical BIP-340
// signatures — bytemare/frost uses its own IRTF-standard challenge
// hash which is not BIP-340. See docs/frost-cosigning-design.md §9.
//
// The math (concrete):
//
//   Binding factor per participant i:
//     rho_input = "cloistr-frost-v1/binding" || P_x(32) || msg(32) ||
//                 [for each c in sorted_commitments: id(2) || D(33) || E(33)] ||
//                 target_id(2)
//     rho_i = int(SHA256(rho_input)) mod n
//
//   Aggregated nonce:
//     R = sum_i (D_i + rho_i * E_i)
//
//   Even-Y normalization (BIP-340 requires R_y even):
//     if R.y is odd: work with R' = -R, and flip every participant's
//     nonce contribution scalar (d_i + rho_i * e_i → -(d_i + rho_i*e_i)).
//
//   Joint pubkey normalization (BIP-340 requires P_y even):
//     if P.y is odd: flip every participant's share scalar during signing
//     (s_i → -s_i). Not persisted; applied at cosign time only.
//
//   Challenge:
//     c = int(tagged_hash("BIP0340/challenge", R_x || P_x || msg)) mod n
//
//   Partial signature:
//     nonce_contrib_i = d_i + rho_i * e_i  (negated if R had odd Y)
//     share_i_eff     = s_i                (negated if P had odd Y)
//     z_i = nonce_contrib_i + lambda_i * share_i_eff * c
//
//   Aggregate:
//     z = sum_i z_i mod n
//
//   Final signature:
//     64 bytes = R_effective_x(32) || z(32) — directly parseable by
//     btcec/schnorr.ParseSignature.

package frost

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/bytemare/ecc"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// Domain-separation tag for our custom BIP-340-mode FROST binding
// factor. Versioned so a future scheme can coexist without breaking
// existing keys.
const bip340FrostBindingDomain = "cloistr-frost-v1/binding"

// NonceCommitmentPair is a participant's (D_i, E_i) commitments.
type NonceCommitmentPair struct {
	ParticipantID uint16
	Hiding        *ecc.Element // D_i, 33-byte compressed on the wire
	Binding       *ecc.Element // E_i, 33-byte compressed on the wire
}

// Sort commitments by ParticipantID ascending. Both parties must
// agree on the canonical order for binding factors to match.
type nonceCommitmentList []NonceCommitmentPair

func (l nonceCommitmentList) Len() int      { return len(l) }
func (l nonceCommitmentList) Swap(i, j int) { l[i], l[j] = l[j], l[i] }
func (l nonceCommitmentList) Less(i, j int) bool {
	return l[i].ParticipantID < l[j].ParticipantID
}

// LagrangeCoefficient computes lambda_i = product over j != i of x_j / (x_j - x_i)
// evaluated at x = 0. All arithmetic mod n.
// For 2-of-2 with {1, 2}: lambda_1 = 2/(2-1) = 2, lambda_2 = 1/(1-2) = -1.
func LagrangeCoefficient(group ecc.Group, targetID uint16, allIDs []uint16) *ecc.Scalar {
	num := group.NewScalar().SetUInt64(1)
	den := group.NewScalar().SetUInt64(1)
	xi := group.NewScalar().SetUInt64(uint64(targetID))
	for _, otherID := range allIDs {
		if otherID == targetID {
			continue
		}
		xj := group.NewScalar().SetUInt64(uint64(otherID))
		num.Multiply(xj)
		diff := xj.Copy().Subtract(xi)
		den.Multiply(diff)
	}
	return num.Multiply(den.Invert())
}

// xOnlyPubkey returns the 32-byte x-coordinate of a compressed pubkey
// and whether the y-coordinate is even.
func xOnlyPubkey(compressed []byte) (xOnly []byte, yEven bool, err error) {
	if len(compressed) != 33 {
		return nil, false, fmt.Errorf("expected 33-byte compressed pubkey, got %d", len(compressed))
	}
	yEven = compressed[0] == 0x02
	return compressed[1:], yEven, nil
}

// ComputeBindingFactors computes rho_i for each participant.
//
// Both parties must call this with the SAME sorted commitment list
// and joint pubkey and message. If any input differs the resulting
// scalars diverge and the partial signatures won't aggregate correctly.
func ComputeBindingFactors(
	group ecc.Group,
	jointPubkey *ecc.Element,
	message []byte,
	commitments []NonceCommitmentPair,
) (map[uint16]*ecc.Scalar, error) {
	if len(message) != 32 {
		return nil, fmt.Errorf("message must be 32 bytes, got %d", len(message))
	}
	// The list must be sorted; we don't sort here so callers see any
	// mismatches immediately in tests.
	for i := 1; i < len(commitments); i++ {
		if commitments[i-1].ParticipantID >= commitments[i].ParticipantID {
			return nil, fmt.Errorf("commitments must be sorted ascending by ParticipantID")
		}
	}

	pubkeyEncoded := jointPubkey.Encode() // 33-byte compressed
	pubkeyXOnly, _, err := xOnlyPubkey(pubkeyEncoded)
	if err != nil {
		return nil, err
	}

	// Precompute the common prefix.
	var prefix []byte
	prefix = append(prefix, []byte(bip340FrostBindingDomain)...)
	prefix = append(prefix, pubkeyXOnly...)
	prefix = append(prefix, message...)
	for _, c := range commitments {
		var idBytes [2]byte
		binary.BigEndian.PutUint16(idBytes[:], c.ParticipantID)
		prefix = append(prefix, idBytes[:]...)
		prefix = append(prefix, c.Hiding.Encode()...)
		prefix = append(prefix, c.Binding.Encode()...)
	}

	out := make(map[uint16]*ecc.Scalar, len(commitments))
	for _, c := range commitments {
		var idBytes [2]byte
		binary.BigEndian.PutUint16(idBytes[:], c.ParticipantID)
		input := make([]byte, 0, len(prefix)+2)
		input = append(input, prefix...)
		input = append(input, idBytes[:]...)
		digest := sha256.Sum256(input)
		// Interpret digest as scalar mod n. bytemare/ecc's Decode()
		// requires the value to be < n, which is not guaranteed for
		// a random 32-byte string. Reduce via BIP-340's "int(bytes) mod n"
		// approach using btcec's ModNScalar and then bridging back.
		var mns btcec.ModNScalar
		mns.SetByteSlice(digest[:])
		reduced := scalarFromModN(&mns)
		s := group.NewScalar()
		if err := s.Decode(reduced); err != nil {
			return nil, fmt.Errorf("decode reduced binding factor: %w", err)
		}
		out[c.ParticipantID] = s
	}
	return out, nil
}

// scalarFromModN produces a 32-byte big-endian encoding of a
// btcec.ModNScalar, suitable for feeding into bytemare/ecc's
// Scalar.Decode. The output is guaranteed < n because ModNScalar
// stores reduced values.
func scalarFromModN(m *btcec.ModNScalar) []byte {
	var b [32]byte
	m.PutBytesUnchecked(b[:])
	return b[:]
}

// AggregateNonceCommitment computes R = sum(D_i + rho_i * E_i).
// Also reports whether R has even Y — callers use this to negate
// their nonce contributions if false.
func AggregateNonceCommitment(
	group ecc.Group,
	commitments []NonceCommitmentPair,
	bindingFactors map[uint16]*ecc.Scalar,
) (r *ecc.Element, yEven bool, err error) {
	R := group.NewElement() // identity
	for _, c := range commitments {
		rho, ok := bindingFactors[c.ParticipantID]
		if !ok {
			return nil, false, fmt.Errorf("missing binding factor for participant %d", c.ParticipantID)
		}
		contrib := c.Hiding.Copy().Add(c.Binding.Copy().Multiply(rho))
		R.Add(contrib)
	}
	encoded := R.Encode()
	if len(encoded) != 33 {
		return nil, false, fmt.Errorf("expected 33-byte compressed R, got %d", len(encoded))
	}
	yEven = encoded[0] == 0x02

	// Normalize: if R has odd Y, flip to even-Y variant. The caller's
	// partial-sig math handles the corresponding scalar negation.
	if !yEven {
		R = R.Negate()
	}
	return R, yEven, nil
}

// ComputeBIP340Challenge = int(tagged_hash("BIP0340/challenge",
// R_x || P_x || msg)) mod n. Both R and P are treated as even-Y.
func ComputeBIP340Challenge(
	group ecc.Group,
	rEvenY *ecc.Element,
	jointPubkey *ecc.Element,
	message []byte,
) (*ecc.Scalar, error) {
	rEncoded := rEvenY.Encode()
	if len(rEncoded) != 33 || rEncoded[0] != 0x02 {
		return nil, fmt.Errorf("R must be even-Y compressed encoding")
	}
	pEncoded := jointPubkey.Encode()
	if len(pEncoded) != 33 {
		return nil, fmt.Errorf("expected 33-byte compressed P")
	}
	// P must also be treated as even-Y for BIP-340. The x-coordinate
	// is the same regardless of parity.
	pXOnly := pEncoded[1:]
	rXOnly := rEncoded[1:]

	digest := chainhash.TaggedHash(chainhash.TagBIP0340Challenge, rXOnly, pXOnly, message)

	var mns btcec.ModNScalar
	mns.SetByteSlice(digest[:])
	reduced := scalarFromModN(&mns)
	c := group.NewScalar()
	if err := c.Decode(reduced); err != nil {
		return nil, fmt.Errorf("decode challenge: %w", err)
	}
	return c, nil
}

// ComputePartialSignature computes participant i's z_i for BIP-340 FROST.
//
// nonceHiding + rho_i * nonceBinding is the "k contribution" from
// this participant. If R had odd Y (i.e., rEvenY == false), the
// contribution must be negated.
//
// share is s_i. If the joint pubkey has odd Y (pubkeyEvenY == false),
// the share must be negated for this signing.
//
// The returned z_i is a scalar mod n, ready for aggregation.
func ComputePartialSignature(
	group ecc.Group,
	nonceHiding *ecc.Scalar, // d_i
	nonceBinding *ecc.Scalar, // e_i
	rho *ecc.Scalar,          // rho_i
	rEvenY bool,
	share *ecc.Scalar,        // s_i
	pubkeyEvenY bool,
	lambda *ecc.Scalar,       // lambda_i
	challenge *ecc.Scalar,    // c
) *ecc.Scalar {
	// nonce_contrib = d_i + rho_i * e_i
	nonceContrib := nonceHiding.Copy().Add(rho.Copy().Multiply(nonceBinding))
	if !rEvenY {
		nonceContrib = negateScalar(group, nonceContrib)
	}

	// share_eff = s_i (negated if joint pubkey has odd Y)
	shareEff := share.Copy()
	if !pubkeyEvenY {
		shareEff = negateScalar(group, shareEff)
	}

	// z_i = nonce_contrib + lambda * share_eff * c
	term := lambda.Copy().Multiply(shareEff).Multiply(challenge)
	return nonceContrib.Add(term)
}

// negateScalar returns -s mod n.
func negateScalar(group ecc.Group, s *ecc.Scalar) *ecc.Scalar {
	zero := group.NewScalar()
	return zero.Subtract(s)
}

// AggregatePartialSignatures sums the z_i values. Returns the final
// z scalar as 32-byte big-endian bytes.
func AggregatePartialSignatures(group ecc.Group, partials []*ecc.Scalar) []byte {
	z := group.NewScalar()
	for _, p := range partials {
		z.Add(p)
	}
	return z.Encode()
}

// EncodeBIP340Signature produces the canonical 64-byte BIP-340 signature
// from the (even-Y) R and the aggregate z.
func EncodeBIP340Signature(rEvenY *ecc.Element, zBytes []byte) ([]byte, error) {
	rEncoded := rEvenY.Encode()
	if len(rEncoded) != 33 || rEncoded[0] != 0x02 {
		return nil, fmt.Errorf("R must be even-Y compressed encoding")
	}
	if len(zBytes) != 32 {
		return nil, fmt.Errorf("z must be 32 bytes, got %d", len(zBytes))
	}
	sig := make([]byte, 64)
	copy(sig[:32], rEncoded[1:])
	copy(sig[32:], zBytes)
	return sig, nil
}

// VerifyBIP340 wraps btcec/schnorr for a self-check pass.
func VerifyBIP340(sigBytes, msgHash []byte, jointPubkey *ecc.Element) error {
	if len(sigBytes) != 64 {
		return fmt.Errorf("sig must be 64 bytes, got %d", len(sigBytes))
	}
	if len(msgHash) != 32 {
		return fmt.Errorf("msg must be 32 bytes, got %d", len(msgHash))
	}
	sig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("parse sig: %w", err)
	}
	pEncoded := jointPubkey.Encode()
	if len(pEncoded) != 33 {
		return fmt.Errorf("expected 33-byte compressed P")
	}
	pk, err := schnorr.ParsePubKey(pEncoded[1:]) // x-only
	if err != nil {
		return fmt.Errorf("parse pubkey: %w", err)
	}
	if !sig.Verify(msgHash, pk) {
		return errors.New("BIP-340 verification failed")
	}
	return nil
}

// SessionForSigning encapsulates the per-session state a single
// participant needs to produce their partial sig. Both the coordinator
// (signer side) and the WASM interop test (user side simulation) use
// this same struct.
type SessionForSigning struct {
	Group           ecc.Group
	ParticipantID   uint16
	AllIDs          []uint16                     // sorted ascending
	Commitments     []NonceCommitmentPair        // sorted ascending
	JointPubkey     *ecc.Element
	Message         []byte
	NonceHiding     *ecc.Scalar // d_i (secret)
	NonceBinding    *ecc.Scalar // e_i (secret)
	Share           *ecc.Scalar // s_i (secret)
}

// Signable derives all public quantities (binding factors, R, R-even-Y,
// challenge, lambda) from the session and returns them. The returned
// values are what a caller needs to (a) sign and (b) verify their
// partial sig locally before releasing it.
type Signable struct {
	BindingFactors map[uint16]*ecc.Scalar
	R              *ecc.Element // even-Y form
	REvenY         bool         // whether the pre-normalization R had even Y (i.e. no flip needed)
	Challenge      *ecc.Scalar
	Lambda         *ecc.Scalar // for this participant
	PubkeyEvenY    bool         // whether the joint pubkey has even Y
}

// PrepareSignable does the deterministic setup: binding factors, R
// aggregation and Y normalization, challenge, lambda. Deterministic
// given (message, joint pubkey, sorted commitments, all IDs).
func PrepareSignable(s *SessionForSigning) (*Signable, error) {
	bindingFactors, err := ComputeBindingFactors(s.Group, s.JointPubkey, s.Message, s.Commitments)
	if err != nil {
		return nil, err
	}
	R, rEvenY, err := AggregateNonceCommitment(s.Group, s.Commitments, bindingFactors)
	if err != nil {
		return nil, err
	}
	challenge, err := ComputeBIP340Challenge(s.Group, R, s.JointPubkey, s.Message)
	if err != nil {
		return nil, err
	}
	lambda := LagrangeCoefficient(s.Group, s.ParticipantID, s.AllIDs)

	pEncoded := s.JointPubkey.Encode()
	pubkeyEvenY := pEncoded[0] == 0x02

	return &Signable{
		BindingFactors: bindingFactors,
		R:              R,
		REvenY:         rEvenY,
		Challenge:      challenge,
		Lambda:         lambda,
		PubkeyEvenY:    pubkeyEvenY,
	}, nil
}

// Sign produces this participant's partial signature.
func (s *SessionForSigning) Sign(sig *Signable) *ecc.Scalar {
	rho := sig.BindingFactors[s.ParticipantID]
	return ComputePartialSignature(
		s.Group,
		s.NonceHiding, s.NonceBinding, rho, sig.REvenY,
		s.Share, sig.PubkeyEvenY,
		sig.Lambda, sig.Challenge,
	)
}

// AggregateFullSignature combines partials into a BIP-340 signature.
func AggregateFullSignature(
	group ecc.Group,
	sig *Signable,
	partials []*ecc.Scalar,
) ([]byte, error) {
	zBytes := AggregatePartialSignatures(group, partials)
	return EncodeBIP340Signature(sig.R, zBytes)
}

// HelperEncodeCompressed encodes an ecc.Element as 33-byte compressed
// SEC1 hex — reusable by tests + WASM interop.
func HelperEncodeCompressed(e *ecc.Element) string {
	return hex.EncodeToString(e.Encode())
}
