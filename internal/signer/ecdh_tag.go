package signer

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// handleECDHTag computes a handoff bucket tag for the blind-mailbox thread
// design without exposing the raw ECDH shared key.
//
// Params: [peer_pubkey, window_id]
//
//	peer_pubkey: hex-encoded secp256k1 x-only pubkey of the other party
//	window_id:   decimal string of the epoch-day window number
//
// Returns: 2-char lowercase hex string (the first byte of the bucket hash).
//
// Algorithm (must match the kit's handoff_bucket / _ecdh_hex):
//
//	ecdh_x      = secp256k1_scalar_mult(sk, lift_x(peer_pubkey)).x   (32 bytes BE)
//	ecdh_hex    = lowercase_hex( SHA-256(ecdh_x) )                    (64-char string)
//	bucket_hash = SHA-256( UTF-8( ecdh_hex + "handoff" + decimal(window_id) ) )
//	tag         = hex( bucket_hash[0] )
func (s *Signer) handleECDHTag(privateKey string, params []string) (string, error) {
	if len(params) < 2 {
		return "", errors.New("missing parameters (need peer_pubkey and window_id)")
	}

	peerPubkey := normalizePubkey(params[0])
	windowIDStr := params[1]

	if _, err := strconv.ParseUint(windowIDStr, 10, 64); err != nil {
		return "", fmt.Errorf("invalid window_id: %w", err)
	}

	privKeyBytes, err := hex.DecodeString(privateKey)
	if err != nil {
		return "", fmt.Errorf("invalid private key: %w", err)
	}
	privKey, _ := btcec.PrivKeyFromBytes(privKeyBytes)

	pubKeyBytes, err := hex.DecodeString("02" + peerPubkey)
	if err != nil {
		return "", fmt.Errorf("invalid peer pubkey: %w", err)
	}
	pubKey, err := btcec.ParsePubKey(pubKeyBytes)
	if err != nil {
		return "", fmt.Errorf("invalid peer pubkey: %w", err)
	}

	var point, result secp256k1.JacobianPoint
	pubKey.AsJacobian(&point)
	secp256k1.ScalarMultNonConst(&privKey.Key, &point, &result)
	result.ToAffine()

	var xBytes [32]byte
	result.X.PutBytesUnchecked(xBytes[:])

	ecdhHash := sha256.Sum256(xBytes[:])
	ecdhHex := hex.EncodeToString(ecdhHash[:])

	input := ecdhHex + "handoff" + windowIDStr
	hash := sha256.Sum256([]byte(input))
	return fmt.Sprintf("%02x", hash[0]), nil
}
