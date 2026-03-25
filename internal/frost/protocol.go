// Package frost implements FROST threshold signatures and distributed key generation.
package frost

import (
	"encoding/hex"
	"encoding/json"
	"time"
)

// DKG Protocol Message Types
const (
	// DKG Round messages
	MsgTypeDKGInit     = "dkg_init"     // Initiate a new DKG session
	MsgTypeDKGAccept   = "dkg_accept"   // Accept participation in DKG
	MsgTypeDKGCommit   = "dkg_commit"   // Round 1: Broadcast commitment
	MsgTypeDKGShare    = "dkg_share"    // Round 2: Send encrypted share
	MsgTypeDKGVerify   = "dkg_verify"   // Round 3: Report verification result
	MsgTypeDKGComplete = "dkg_complete" // DKG completed successfully
	MsgTypeDKGAbort    = "dkg_abort"    // DKG aborted (with reason)

	// Signing messages
	MsgTypeSignRequest    = "sign_request"    // Request partial signature
	MsgTypeSignCommitment = "sign_commitment" // Round 1: Signing commitment
	MsgTypeSignShare      = "sign_share"      // Round 2: Signature share
)

// DKGSession represents an ongoing DKG session
type DKGSession struct {
	ID           string         `json:"id"`
	Initiator    string         `json:"initiator"`     // Initiator's pubkey
	Participants []string       `json:"participants"`  // All participants' pubkeys (ordered by index)
	Threshold    int            `json:"threshold"`     // t - minimum shares for signing
	TotalShares  int            `json:"total_shares"`  // n - total number of shares
	Status       DKGStatus      `json:"status"`
	StartedAt    time.Time      `json:"started_at"`
	CompletedAt  *time.Time     `json:"completed_at,omitempty"`
	FrostKeyID   string         `json:"frost_key_id,omitempty"` // Set when complete
	GroupPubkey  string         `json:"group_pubkey,omitempty"` // Set when complete
	Round        int            `json:"round"`                  // Current round (1, 2, or 3)
	Error        string         `json:"error,omitempty"`        // Error message if aborted
}

// DKGStatus represents the state of a DKG session
type DKGStatus string

const (
	DKGStatusPending    DKGStatus = "pending"    // Waiting for participants to accept
	DKGStatusRound1     DKGStatus = "round1"     // Collecting commitments
	DKGStatusRound2     DKGStatus = "round2"     // Distributing shares
	DKGStatusRound3     DKGStatus = "round3"     // Verifying shares
	DKGStatusComplete   DKGStatus = "complete"   // DKG completed successfully
	DKGStatusAborted    DKGStatus = "aborted"    // DKG was aborted
)

// DKGInitPayload is sent by the initiator to start a DKG session
type DKGInitPayload struct {
	SessionID    string   `json:"session_id"`
	Participants []string `json:"participants"` // Pubkeys of all participants (including initiator)
	Threshold    int      `json:"threshold"`
	TotalShares  int      `json:"total_shares"`
	KeyName      string   `json:"key_name,omitempty"` // Optional name for the key
	ExpiresAt    int64    `json:"expires_at"`         // Unix timestamp when invitation expires
}

// DKGAcceptPayload is sent by participants to accept the DKG invitation
type DKGAcceptPayload struct {
	SessionID string `json:"session_id"`
	Index     int    `json:"index"` // Participant's index (1-based, derived from position in participants list)
}

// DKGCommitPayload contains a participant's commitment for Round 1
// In FROST DKG, each participant generates a random polynomial and broadcasts
// commitments to the polynomial coefficients (VSS commitment)
type DKGCommitPayload struct {
	SessionID   string `json:"session_id"`
	Index       int    `json:"index"`      // Participant index (1-based)
	Commitment  string `json:"commitment"` // Hex-encoded commitment (concatenated group elements)
}

// DKGSharePayload contains an encrypted share for a specific participant (Round 2)
// Each participant evaluates their polynomial at each other participant's index
// and sends the result encrypted
type DKGSharePayload struct {
	SessionID    string `json:"session_id"`
	FromIndex    int    `json:"from_index"`    // Sender's participant index
	ToIndex      int    `json:"to_index"`      // Recipient's participant index
	Share        string `json:"share"`         // Hex-encoded encrypted share
	PublicShare  string `json:"public_share"`  // Hex-encoded public key share (for verification)
}

// DKGVerifyPayload reports the verification result for received shares
type DKGVerifyPayload struct {
	SessionID  string `json:"session_id"`
	Index      int    `json:"index"`       // Verifier's participant index
	Success    bool   `json:"success"`     // True if all shares verified
	FailedFrom []int  `json:"failed_from"` // Indices of participants whose shares failed verification
}

// DKGCompletePayload is broadcast when DKG completes successfully
type DKGCompletePayload struct {
	SessionID    string `json:"session_id"`
	Index        int    `json:"index"`        // Participant index
	GroupPubkey  string `json:"group_pubkey"` // The generated group public key (hex)
}

// DKGAbortPayload is sent when DKG must be aborted
type DKGAbortPayload struct {
	SessionID string `json:"session_id"`
	Index     int    `json:"index"`  // Aborting participant index
	Reason    string `json:"reason"` // Human-readable reason
}

// SignRequestPayload requests a partial signature from a share holder
type SignRequestPayload struct {
	SessionID   string `json:"session_id"`
	FrostKeyID  string `json:"frost_key_id"` // ID of the FROST key to sign with
	Message     string `json:"message"`      // Hex-encoded message to sign
	Commitments string `json:"commitments"`  // Hex-encoded commitment list from all participants
}

// SignCommitmentPayload contains a signer's commitment for a signing session
type SignCommitmentPayload struct {
	SessionID   string `json:"session_id"`
	Index       int    `json:"index"`       // Signer's share index
	Commitment  string `json:"commitment"`  // Hex-encoded signing commitment
}

// SignSharePayload contains a partial signature share
type SignSharePayload struct {
	SessionID string `json:"session_id"`
	Index     int    `json:"index"` // Signer's share index
	Share     string `json:"share"` // Hex-encoded signature share
}

// MarshalDKGInit creates a DKG init message
func MarshalDKGInit(payload *DKGInitPayload) ([]byte, error) {
	return json.Marshal(payload)
}

// UnmarshalDKGInit parses a DKG init payload
func UnmarshalDKGInit(data json.RawMessage) (*DKGInitPayload, error) {
	var p DKGInitPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// MarshalDKGCommit creates a DKG commit message
func MarshalDKGCommit(payload *DKGCommitPayload) ([]byte, error) {
	return json.Marshal(payload)
}

// UnmarshalDKGCommit parses a DKG commit payload
func UnmarshalDKGCommit(data json.RawMessage) (*DKGCommitPayload, error) {
	var p DKGCommitPayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// MarshalDKGShare creates a DKG share message
func MarshalDKGShare(payload *DKGSharePayload) ([]byte, error) {
	return json.Marshal(payload)
}

// UnmarshalDKGShare parses a DKG share payload
func UnmarshalDKGShare(data json.RawMessage) (*DKGSharePayload, error) {
	var p DKGSharePayload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

// HexEncode encodes bytes to hex string
func HexEncode(data []byte) string {
	return hex.EncodeToString(data)
}

// HexDecode decodes a hex string to bytes
func HexDecode(s string) ([]byte, error) {
	return hex.DecodeString(s)
}
