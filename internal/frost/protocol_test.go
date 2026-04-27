package frost

import (
	"encoding/json"
	"testing"
	"time"
)

func TestDKGStatus_Values(t *testing.T) {
	// Verify all DKG status constants are defined correctly
	statuses := []DKGStatus{
		DKGStatusPending,
		DKGStatusRound1,
		DKGStatusRound2,
		DKGStatusRound3,
		DKGStatusComplete,
		DKGStatusAborted,
	}

	expected := []string{"pending", "round1", "round2", "round3", "complete", "aborted"}

	for i, status := range statuses {
		if string(status) != expected[i] {
			t.Errorf("status %d = %q, want %q", i, status, expected[i])
		}
	}
}

func TestMessageTypes(t *testing.T) {
	// Verify message type constants
	tests := []struct {
		constant string
		expected string
	}{
		{MsgTypeDKGInit, "dkg_init"},
		{MsgTypeDKGAccept, "dkg_accept"},
		{MsgTypeDKGCommit, "dkg_commit"},
		{MsgTypeDKGShare, "dkg_share"},
		{MsgTypeDKGVerify, "dkg_verify"},
		{MsgTypeDKGComplete, "dkg_complete"},
		{MsgTypeDKGAbort, "dkg_abort"},
		{MsgTypeSignRequest, "sign_request"},
		{MsgTypeSignCommitment, "sign_commitment"},
		{MsgTypeSignShare, "sign_share"},
	}

	for _, tt := range tests {
		if tt.constant != tt.expected {
			t.Errorf("message type = %q, want %q", tt.constant, tt.expected)
		}
	}
}

func TestDKGSession_JSON(t *testing.T) {
	now := time.Now()
	completed := now.Add(time.Minute)

	session := &DKGSession{
		ID:           "test-session-123",
		Initiator:    "pubkey1",
		Participants: []string{"pubkey1", "pubkey2", "pubkey3"},
		Threshold:    2,
		TotalShares:  3,
		Status:       DKGStatusComplete,
		StartedAt:    now,
		CompletedAt:  &completed,
		FrostKeyID:   "frost-key-456",
		GroupPubkey:  "abcd1234",
		Round:        3,
	}

	// Marshal
	data, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	// Unmarshal
	var decoded DKGSession
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	// Verify fields
	if decoded.ID != session.ID {
		t.Errorf("ID = %q, want %q", decoded.ID, session.ID)
	}
	if decoded.Threshold != session.Threshold {
		t.Errorf("Threshold = %d, want %d", decoded.Threshold, session.Threshold)
	}
	if decoded.Status != session.Status {
		t.Errorf("Status = %q, want %q", decoded.Status, session.Status)
	}
	if len(decoded.Participants) != len(session.Participants) {
		t.Errorf("Participants count = %d, want %d", len(decoded.Participants), len(session.Participants))
	}
}

func TestMarshalUnmarshalDKGInit(t *testing.T) {
	payload := &DKGInitPayload{
		SessionID:    "session-abc",
		Participants: []string{"pub1", "pub2", "pub3"},
		Threshold:    2,
		TotalShares:  3,
		KeyName:      "My FROST Key",
		ExpiresAt:    1234567890,
	}

	data, err := MarshalDKGInit(payload)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	decoded, err := UnmarshalDKGInit(data)
	if err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.SessionID != payload.SessionID {
		t.Errorf("SessionID = %q, want %q", decoded.SessionID, payload.SessionID)
	}
	if decoded.Threshold != payload.Threshold {
		t.Errorf("Threshold = %d, want %d", decoded.Threshold, payload.Threshold)
	}
	if decoded.KeyName != payload.KeyName {
		t.Errorf("KeyName = %q, want %q", decoded.KeyName, payload.KeyName)
	}
	if len(decoded.Participants) != len(payload.Participants) {
		t.Errorf("Participants count = %d, want %d", len(decoded.Participants), len(payload.Participants))
	}
}

func TestMarshalUnmarshalDKGCommit(t *testing.T) {
	payload := &DKGCommitPayload{
		SessionID:  "session-xyz",
		Index:      1,
		Commitment: "deadbeef1234",
	}

	data, err := MarshalDKGCommit(payload)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	decoded, err := UnmarshalDKGCommit(data)
	if err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.SessionID != payload.SessionID {
		t.Errorf("SessionID = %q, want %q", decoded.SessionID, payload.SessionID)
	}
	if decoded.Index != payload.Index {
		t.Errorf("Index = %d, want %d", decoded.Index, payload.Index)
	}
	if decoded.Commitment != payload.Commitment {
		t.Errorf("Commitment = %q, want %q", decoded.Commitment, payload.Commitment)
	}
}

func TestMarshalUnmarshalDKGShare(t *testing.T) {
	payload := &DKGSharePayload{
		SessionID:   "session-share",
		FromIndex:   1,
		ToIndex:     2,
		Share:       "encrypted-share-hex",
		PublicShare: "public-share-hex",
	}

	data, err := MarshalDKGShare(payload)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	decoded, err := UnmarshalDKGShare(data)
	if err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.FromIndex != payload.FromIndex {
		t.Errorf("FromIndex = %d, want %d", decoded.FromIndex, payload.FromIndex)
	}
	if decoded.ToIndex != payload.ToIndex {
		t.Errorf("ToIndex = %d, want %d", decoded.ToIndex, payload.ToIndex)
	}
	if decoded.Share != payload.Share {
		t.Errorf("Share = %q, want %q", decoded.Share, payload.Share)
	}
}

func TestUnmarshalDKGInit_InvalidJSON(t *testing.T) {
	_, err := UnmarshalDKGInit([]byte("invalid json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestUnmarshalDKGCommit_InvalidJSON(t *testing.T) {
	_, err := UnmarshalDKGCommit([]byte("{invalid}"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestUnmarshalDKGShare_InvalidJSON(t *testing.T) {
	_, err := UnmarshalDKGShare([]byte("not json"))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestHexEncodeDecode(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"empty", []byte{}},
		{"single byte", []byte{0x42}},
		{"multiple bytes", []byte{0xde, 0xad, 0xbe, 0xef}},
		{"32 bytes", make([]byte, 32)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := HexEncode(tt.input)
			decoded, err := HexDecode(encoded)
			if err != nil {
				t.Fatalf("decode error: %v", err)
			}

			if len(decoded) != len(tt.input) {
				t.Errorf("decoded length = %d, want %d", len(decoded), len(tt.input))
			}

			for i := range tt.input {
				if decoded[i] != tt.input[i] {
					t.Errorf("byte %d = %x, want %x", i, decoded[i], tt.input[i])
				}
			}
		})
	}
}

func TestHexDecode_Invalid(t *testing.T) {
	tests := []string{
		"xyz",      // Invalid hex chars
		"deadbee",  // Odd length
		"GHIJ",     // More invalid chars
	}

	for _, tt := range tests {
		_, err := HexDecode(tt)
		if err == nil {
			t.Errorf("expected error for %q", tt)
		}
	}
}

func TestDKGVerifyPayload_JSON(t *testing.T) {
	payload := &DKGVerifyPayload{
		SessionID:  "verify-session",
		Index:      2,
		Success:    false,
		FailedFrom: []int{1, 3},
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded DKGVerifyPayload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.Success != payload.Success {
		t.Errorf("Success = %v, want %v", decoded.Success, payload.Success)
	}
	if len(decoded.FailedFrom) != 2 {
		t.Errorf("FailedFrom length = %d, want 2", len(decoded.FailedFrom))
	}
}

func TestDKGCompletePayload_JSON(t *testing.T) {
	payload := &DKGCompletePayload{
		SessionID:   "complete-session",
		Index:       1,
		GroupPubkey: "abcdef123456",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded DKGCompletePayload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.GroupPubkey != payload.GroupPubkey {
		t.Errorf("GroupPubkey = %q, want %q", decoded.GroupPubkey, payload.GroupPubkey)
	}
}

func TestDKGAbortPayload_JSON(t *testing.T) {
	payload := &DKGAbortPayload{
		SessionID: "abort-session",
		Index:     2,
		Reason:    "Share verification failed",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded DKGAbortPayload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.Reason != payload.Reason {
		t.Errorf("Reason = %q, want %q", decoded.Reason, payload.Reason)
	}
}

func TestSignRequestPayload_JSON(t *testing.T) {
	payload := &SignRequestPayload{
		SessionID:   "sign-session",
		FrostKeyID:  "frost-key-123",
		Message:     "deadbeefcafe",
		Commitments: "commitment-data",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded SignRequestPayload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.FrostKeyID != payload.FrostKeyID {
		t.Errorf("FrostKeyID = %q, want %q", decoded.FrostKeyID, payload.FrostKeyID)
	}
	if decoded.Message != payload.Message {
		t.Errorf("Message = %q, want %q", decoded.Message, payload.Message)
	}
}

func TestSignCommitmentPayload_JSON(t *testing.T) {
	payload := &SignCommitmentPayload{
		SessionID:  "sign-commit-session",
		Index:      3,
		Commitment: "sign-commitment-hex",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded SignCommitmentPayload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.Index != payload.Index {
		t.Errorf("Index = %d, want %d", decoded.Index, payload.Index)
	}
}

func TestSignSharePayload_JSON(t *testing.T) {
	payload := &SignSharePayload{
		SessionID: "sign-share-session",
		Index:     2,
		Share:     "signature-share-hex",
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded SignSharePayload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.Share != payload.Share {
		t.Errorf("Share = %q, want %q", decoded.Share, payload.Share)
	}
}

func TestDKGAcceptPayload_JSON(t *testing.T) {
	payload := &DKGAcceptPayload{
		SessionID: "accept-session",
		Index:     1,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var decoded DKGAcceptPayload
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if decoded.SessionID != payload.SessionID {
		t.Errorf("SessionID = %q, want %q", decoded.SessionID, payload.SessionID)
	}
	if decoded.Index != payload.Index {
		t.Errorf("Index = %d, want %d", decoded.Index, payload.Index)
	}
}
