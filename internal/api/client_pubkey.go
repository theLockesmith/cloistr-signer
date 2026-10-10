package api

import (
	"encoding/hex"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
)

// validClientPubkey reports whether pk is a 64-char hex x-only public key that
// lies on secp256k1. An off-curve key passes a length check but can never
// receive an encrypted reply, so a session for it would be dead on arrival.
func validClientPubkey(pk string) bool {
	if len(pk) != 64 {
		return false
	}
	b, err := hex.DecodeString(pk)
	if err != nil {
		return false
	}
	_, err = schnorr.ParsePubKey(b)
	return err == nil
}
