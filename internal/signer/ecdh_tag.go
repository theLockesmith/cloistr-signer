package signer

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	"github.com/nbd-wtf/go-nostr/nip44"
)

// handleECDHTag computes a handoff bucket tag for the blind-mailbox thread
// design without exposing the raw ECDH shared key.
//
// Params: [peer_pubkey, window_id]
//
//	peer_pubkey: hex-encoded secp256k1 pubkey of the other party
//	window_id:   decimal string of the epoch-day window number
//
// Returns: 2-char hex string, the first byte of
//
//	SHA-256(ECDH_shared || "handoff" || BE32(window_id))
//
// where ECDH_shared is the NIP-44 conversation key between privateKey and
// peer_pubkey. Both sides of the pair compute the same tag; nobody else can.
func (s *Signer) handleECDHTag(privateKey string, params []string) (string, error) {
	if len(params) < 2 {
		return "", errors.New("missing parameters (need peer_pubkey and window_id)")
	}

	peerPubkey := normalizePubkey(params[0])
	windowIDStr := params[1]

	windowID, err := strconv.ParseUint(windowIDStr, 10, 32)
	if err != nil {
		return "", fmt.Errorf("invalid window_id: %w", err)
	}

	convKey, err := nip44.GenerateConversationKey(peerPubkey, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to compute ECDH shared key: %w", err)
	}

	wBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(wBytes, uint32(windowID))

	label := []byte("handoff")
	input := make([]byte, 0, 32+len(label)+4)
	input = append(input, convKey[:]...)
	input = append(input, label...)
	input = append(input, wBytes...)

	hash := sha256.Sum256(input)
	return hex.EncodeToString(hash[:1]), nil
}
