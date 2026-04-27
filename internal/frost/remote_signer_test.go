package frost

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/bytemare/ecc"
	frostlib "github.com/bytemare/frost"
	"github.com/bytemare/secret-sharing/keys"
	"github.com/nbd-wtf/go-nostr"

	internalNostr "git.aegis-hq.xyz/coldforge/cloistr-signer/internal/nostr"
)

// mockNostrClientRS implements NostrClient for RemoteSigner testing
type mockNostrClientRS struct {
	sentMessages   []sentDMRS
	subscribeCalls int
	sendError      error
	mu             sync.Mutex
}

type sentDMRS struct {
	recipient string
	message   *internalNostr.DMMessage
}

func newMockNostrClientRS() *mockNostrClientRS {
	return &mockNostrClientRS{
		sentMessages: make([]sentDMRS, 0),
	}
}

func (m *mockNostrClientRS) SendEphemeralDM(ctx context.Context, privateKey, recipientPubkey string, message *internalNostr.DMMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sendError != nil {
		return m.sendError
	}
	m.sentMessages = append(m.sentMessages, sentDMRS{recipient: recipientPubkey, message: message})
	return nil
}

func (m *mockNostrClientRS) SubscribeDMs(ctx context.Context, privateKey string, handler internalNostr.DMHandler) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.subscribeCalls++
	return nil
}

func TestNewRemoteSigner(t *testing.T) {
	store := newTestStorage()
	encryptor := &testEncryptor{}

	t.Run("valid private key", func(t *testing.T) {
		privkey := nostr.GeneratePrivateKey()

		rs, err := NewRemoteSigner(store, encryptor, nil, privkey)
		if err != nil {
			t.Fatalf("NewRemoteSigner error: %v", err)
		}

		if rs == nil {
			t.Fatal("RemoteSigner is nil")
		}
		if rs.storage != store {
			t.Error("storage not set correctly")
		}
		if rs.encryptor != encryptor {
			t.Error("encryptor not set correctly")
		}
		if rs.privateKey != privkey {
			t.Error("privateKey not set correctly")
		}
		if rs.pubkey == "" {
			t.Error("pubkey not derived")
		}
		if rs.sessions == nil {
			t.Error("sessions map not initialized")
		}
	})

	t.Run("invalid private key", func(t *testing.T) {
		_, err := NewRemoteSigner(store, encryptor, nil, "invalid-key")
		if err == nil {
			t.Error("expected error for invalid private key")
		}
	})

	t.Run("empty private key", func(t *testing.T) {
		_, err := NewRemoteSigner(store, encryptor, nil, "")
		if err == nil {
			t.Error("expected error for empty private key")
		}
	})
}

func TestSigningSession_Fields(t *testing.T) {
	session := &signingSession{
		ID:                 "test-session",
		FrostKeyID:         "frost-key-123",
		Message:            []byte("test message"),
		Participants:       []int{1, 2, 3},
		ParticipantPubkeys: map[int]string{1: "pub1", 2: "pub2", 3: "pub3"},
		Commitments:        make(map[int]*frostlib.Commitment),
		Shares:             make(map[int]*frostlib.SignatureShare),
		Done:               make(chan struct{}),
	}

	if session.ID != "test-session" {
		t.Error("ID not set")
	}
	if len(session.Participants) != 3 {
		t.Error("Participants not set")
	}
	if session.ParticipantPubkeys[2] != "pub2" {
		t.Error("ParticipantPubkeys not set correctly")
	}
}

func TestRemoteSigner_HandleMessage_Routing(t *testing.T) {
	store := newTestStorage()
	encryptor := &testEncryptor{}
	privkey := nostr.GeneratePrivateKey()

	rs, err := NewRemoteSigner(store, encryptor, nil, privkey)
	if err != nil {
		t.Fatalf("NewRemoteSigner error: %v", err)
	}

	// Add a test session
	session := &signingSession{
		ID:                 "test-session",
		FrostKeyID:         "frost-key",
		ParticipantPubkeys: map[int]string{1: "sender-pubkey"},
		Commitments:        make(map[int]*frostlib.Commitment),
		Shares:             make(map[int]*frostlib.SignatureShare),
		Done:               make(chan struct{}),
	}
	rs.mu.Lock()
	rs.sessions["test-session"] = session
	rs.mu.Unlock()

	t.Run("unknown message type is ignored", func(t *testing.T) {
		msg := &internalNostr.DMMessage{
			Type:    "unknown_type",
			Payload: json.RawMessage(`{}`),
		}
		// Should not panic
		rs.handleMessage("sender-pubkey", msg)
	})

	t.Run("sign commitment message", func(t *testing.T) {
		// Create a test commitment (using a random point)
		group := DefaultCiphersuite.Group()
		scalar := group.NewScalar().Random()
		commitment := group.Base().Multiply(scalar)
		encodedCommitment := hex.EncodeToString(commitment.Encode())

		payload := &SignCommitmentPayload{
			SessionID:  "test-session",
			Index:      1,
			Commitment: encodedCommitment,
		}
		payloadBytes, _ := json.Marshal(payload)

		msg := &internalNostr.DMMessage{
			Type:    MsgTypeSignCommitment,
			Payload: payloadBytes,
		}

		// Call handleMessage
		rs.handleMessage("sender-pubkey", msg)

		// Commitment should NOT be added because it's malformed for FROST
		// (need proper FROST commitment encoding, not just a random element)
	})

	t.Run("sign share message with wrong sender", func(t *testing.T) {
		payload := &SignSharePayload{
			SessionID: "test-session",
			Index:     1,
			Share:     "deadbeef",
		}
		payloadBytes, _ := json.Marshal(payload)

		msg := &internalNostr.DMMessage{
			Type:    MsgTypeSignShare,
			Payload: payloadBytes,
		}

		// Wrong sender - should be ignored
		rs.handleMessage("wrong-pubkey", msg)

		session.mu.Lock()
		shareCount := len(session.Shares)
		session.mu.Unlock()

		if shareCount != 0 {
			t.Error("share should not be added from wrong sender")
		}
	})

	t.Run("sign share for nonexistent session", func(t *testing.T) {
		payload := &SignSharePayload{
			SessionID: "nonexistent-session",
			Index:     1,
			Share:     "deadbeef",
		}
		payloadBytes, _ := json.Marshal(payload)

		msg := &internalNostr.DMMessage{
			Type:    MsgTypeSignShare,
			Payload: payloadBytes,
		}

		// Should not panic - just ignore
		rs.handleMessage("sender-pubkey", msg)
	})
}

func TestRemoteSigner_HandleSignCommitment(t *testing.T) {
	store := newTestStorage()
	encryptor := &testEncryptor{}
	privkey := nostr.GeneratePrivateKey()

	rs, err := NewRemoteSigner(store, encryptor, nil, privkey)
	if err != nil {
		t.Fatalf("NewRemoteSigner error: %v", err)
	}

	senderPubkey := "sender-pubkey-123"

	// Create a session with the sender as a participant
	session := &signingSession{
		ID:                 "commit-test-session",
		FrostKeyID:         "frost-key",
		ParticipantPubkeys: map[int]string{2: senderPubkey},
		Commitments:        make(map[int]*frostlib.Commitment),
		Shares:             make(map[int]*frostlib.SignatureShare),
		Done:               make(chan struct{}),
	}
	rs.mu.Lock()
	rs.sessions["commit-test-session"] = session
	rs.mu.Unlock()

	t.Run("invalid json payload", func(t *testing.T) {
		rs.handleSignCommitment(senderPubkey, json.RawMessage(`invalid`))
		// Should not panic
	})

	t.Run("session not found", func(t *testing.T) {
		payload := &SignCommitmentPayload{
			SessionID:  "nonexistent",
			Index:      2,
			Commitment: "deadbeef",
		}
		payloadBytes, _ := json.Marshal(payload)

		rs.handleSignCommitment(senderPubkey, payloadBytes)
		// Should not panic
	})

	t.Run("wrong sender pubkey", func(t *testing.T) {
		payload := &SignCommitmentPayload{
			SessionID:  "commit-test-session",
			Index:      2,
			Commitment: "deadbeef",
		}
		payloadBytes, _ := json.Marshal(payload)

		rs.handleSignCommitment("wrong-sender", payloadBytes)

		session.mu.Lock()
		_, exists := session.Commitments[2]
		session.mu.Unlock()

		if exists {
			t.Error("commitment should not be added from wrong sender")
		}
	})

	t.Run("invalid hex commitment", func(t *testing.T) {
		payload := &SignCommitmentPayload{
			SessionID:  "commit-test-session",
			Index:      2,
			Commitment: "not-valid-hex!",
		}
		payloadBytes, _ := json.Marshal(payload)

		rs.handleSignCommitment(senderPubkey, payloadBytes)

		session.mu.Lock()
		_, exists := session.Commitments[2]
		session.mu.Unlock()

		if exists {
			t.Error("commitment should not be added with invalid hex")
		}
	})
}

func TestRemoteSigner_HandleSignShare(t *testing.T) {
	store := newTestStorage()
	encryptor := &testEncryptor{}
	privkey := nostr.GeneratePrivateKey()

	rs, err := NewRemoteSigner(store, encryptor, nil, privkey)
	if err != nil {
		t.Fatalf("NewRemoteSigner error: %v", err)
	}

	senderPubkey := "share-sender-pubkey"

	session := &signingSession{
		ID:                 "share-test-session",
		FrostKeyID:         "frost-key",
		ParticipantPubkeys: map[int]string{3: senderPubkey},
		Commitments:        make(map[int]*frostlib.Commitment),
		Shares:             make(map[int]*frostlib.SignatureShare),
		Done:               make(chan struct{}),
	}
	rs.mu.Lock()
	rs.sessions["share-test-session"] = session
	rs.mu.Unlock()

	t.Run("invalid json payload", func(t *testing.T) {
		rs.handleSignShare(senderPubkey, json.RawMessage(`{broken`))
		// Should not panic
	})

	t.Run("session not found", func(t *testing.T) {
		payload := &SignSharePayload{
			SessionID: "missing-session",
			Index:     3,
			Share:     "deadbeef",
		}
		payloadBytes, _ := json.Marshal(payload)

		rs.handleSignShare(senderPubkey, payloadBytes)
		// Should not panic
	})

	t.Run("wrong sender pubkey", func(t *testing.T) {
		payload := &SignSharePayload{
			SessionID: "share-test-session",
			Index:     3,
			Share:     "deadbeef",
		}
		payloadBytes, _ := json.Marshal(payload)

		rs.handleSignShare("wrong-sender", payloadBytes)

		session.mu.Lock()
		_, exists := session.Shares[3]
		session.mu.Unlock()

		if exists {
			t.Error("share should not be added from wrong sender")
		}
	})

	t.Run("wrong participant index", func(t *testing.T) {
		payload := &SignSharePayload{
			SessionID: "share-test-session",
			Index:     99, // Not in ParticipantPubkeys
			Share:     "deadbeef",
		}
		payloadBytes, _ := json.Marshal(payload)

		rs.handleSignShare(senderPubkey, payloadBytes)

		session.mu.Lock()
		_, exists := session.Shares[99]
		session.mu.Unlock()

		if exists {
			t.Error("share should not be added for wrong index")
		}
	})

	t.Run("invalid hex share", func(t *testing.T) {
		payload := &SignSharePayload{
			SessionID: "share-test-session",
			Index:     3,
			Share:     "not-valid-hex!!!",
		}
		payloadBytes, _ := json.Marshal(payload)

		rs.handleSignShare(senderPubkey, payloadBytes)

		session.mu.Lock()
		_, exists := session.Shares[3]
		session.mu.Unlock()

		if exists {
			t.Error("share should not be added with invalid hex")
		}
	})
}

func TestRemoteSigner_SessionConcurrency(t *testing.T) {
	store := newTestStorage()
	encryptor := &testEncryptor{}
	privkey := nostr.GeneratePrivateKey()

	rs, err := NewRemoteSigner(store, encryptor, nil, privkey)
	if err != nil {
		t.Fatalf("NewRemoteSigner error: %v", err)
	}

	// Test concurrent session access
	done := make(chan bool)

	go func() {
		for i := 0; i < 100; i++ {
			session := &signingSession{
				ID:          generateID(),
				Commitments: make(map[int]*frostlib.Commitment),
				Shares:      make(map[int]*frostlib.SignatureShare),
			}
			rs.mu.Lock()
			rs.sessions[session.ID] = session
			rs.mu.Unlock()
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			rs.mu.RLock()
			_ = len(rs.sessions)
			rs.mu.RUnlock()
		}
		done <- true
	}()

	<-done
	<-done
}

func TestRemoteSigner_HandleSignRequest_EdgeCases(t *testing.T) {
	store := newTestStorage()
	encryptor := &testEncryptor{}
	privkey := nostr.GeneratePrivateKey()
	senderPubkey, _ := nostr.GetPublicKey(nostr.GeneratePrivateKey())

	rs, err := NewRemoteSigner(store, encryptor, nil, privkey)
	if err != nil {
		t.Fatalf("NewRemoteSigner error: %v", err)
	}

	t.Run("invalid json", func(t *testing.T) {
		// Should not panic
		rs.handleSignRequest(senderPubkey, json.RawMessage(`invalid json`))
	})

	t.Run("unknown frost key", func(t *testing.T) {
		payload := &SignRequestPayload{
			SessionID:   "test-session",
			FrostKeyID:  "nonexistent-key-id",
			Message:     "deadbeef",
			Commitments: "cafebabe",
		}
		payloadBytes, _ := json.Marshal(payload)
		// Should not panic
		rs.handleSignRequest(senderPubkey, payloadBytes)
	})

	t.Run("no local share", func(t *testing.T) {
		// Create a frost key but no shares
		kg := NewKeyGenerator(encryptor)
		config := &KeyGenConfig{
			Threshold:   2,
			TotalShares: 3,
		}
		result, _ := kg.GenerateKey(config)
		store.CreateFrostKey(nil, result.FrostKey)
		// Don't create any shares

		payload := &SignRequestPayload{
			SessionID:   "test-session",
			FrostKeyID:  result.FrostKey.ID,
			Message:     "deadbeef",
			Commitments: "cafebabe",
		}
		payloadBytes, _ := json.Marshal(payload)
		// Should not panic
		rs.handleSignRequest(senderPubkey, payloadBytes)
	})

	t.Run("invalid message hex", func(t *testing.T) {
		// Create frost key with shares
		kg := NewKeyGenerator(encryptor)
		config := &KeyGenConfig{
			Threshold:   2,
			TotalShares: 3,
		}
		result, _ := kg.GenerateKey(config)
		store.CreateFrostKey(nil, result.FrostKey)
		for _, share := range result.Shares {
			store.CreateFrostShare(nil, share)
		}

		payload := &SignRequestPayload{
			SessionID:   "test-session",
			FrostKeyID:  result.FrostKey.ID,
			Message:     "not-valid-hex!!!",
			Commitments: "cafebabe",
		}
		payloadBytes, _ := json.Marshal(payload)
		// Should not panic
		rs.handleSignRequest(senderPubkey, payloadBytes)
	})

	t.Run("invalid commitments hex", func(t *testing.T) {
		// Create frost key with shares
		kg := NewKeyGenerator(encryptor)
		config := &KeyGenConfig{
			Threshold:   2,
			TotalShares: 3,
		}
		result, _ := kg.GenerateKey(config)
		store.CreateFrostKey(nil, result.FrostKey)
		for _, share := range result.Shares {
			store.CreateFrostShare(nil, share)
		}

		// Create valid message
		message := make([]byte, 32)
		messageHex := hex.EncodeToString(message)

		payload := &SignRequestPayload{
			SessionID:   "test-session",
			FrostKeyID:  result.FrostKey.ID,
			Message:     messageHex,
			Commitments: "not-valid-hex!!!",
		}
		payloadBytes, _ := json.Marshal(payload)
		// Should not panic
		rs.handleSignRequest(senderPubkey, payloadBytes)
	})

	t.Run("invalid commitments format", func(t *testing.T) {
		// Create frost key with shares
		kg := NewKeyGenerator(encryptor)
		config := &KeyGenConfig{
			Threshold:   2,
			TotalShares: 3,
		}
		result, _ := kg.GenerateKey(config)
		store.CreateFrostKey(nil, result.FrostKey)
		for _, share := range result.Shares {
			store.CreateFrostShare(nil, share)
		}

		// Create valid message
		message := make([]byte, 32)
		messageHex := hex.EncodeToString(message)

		payload := &SignRequestPayload{
			SessionID:   "test-session",
			FrostKeyID:  result.FrostKey.ID,
			Message:     messageHex,
			Commitments: "abcd1234", // Valid hex but invalid commitment format
		}
		payloadBytes, _ := json.Marshal(payload)
		// Should not panic
		rs.handleSignRequest(senderPubkey, payloadBytes)
	})

	t.Run("invalid verification shares in key", func(t *testing.T) {
		// Create frost key with invalid verification shares
		invalidKey := &FrostKey{
			ID:                 "invalid-verification-key",
			Name:               "test",
			Pubkey:             "deadbeef",
			Threshold:          2,
			TotalShares:        3,
			GroupPublicKey:     make([]byte, 33),
			VerificationShares: []byte{0x00, 0x01}, // Invalid
		}
		store.CreateFrostKey(nil, invalidKey)

		// Create a share for this key
		share := &FrostShare{
			ID:             "test-share-invalid",
			FrostKeyID:     invalidKey.ID,
			ShareIndex:     1,
			EncryptedShare: make([]byte, 32),
			IsLocal:        true,
		}
		store.CreateFrostShare(nil, share)

		message := make([]byte, 32)
		messageHex := hex.EncodeToString(message)

		payload := &SignRequestPayload{
			SessionID:   "test-session-invalid",
			FrostKeyID:  invalidKey.ID,
			Message:     messageHex,
			Commitments: "abcd1234",
		}
		payloadBytes, _ := json.Marshal(payload)
		// Should not panic
		rs.handleSignRequest(senderPubkey, payloadBytes)
	})

	t.Run("decryption error", func(t *testing.T) {
		// Create a RemoteSigner with failing encryptor
		failStore := newTestStorage()
		failingEnc := &failingEncryptor{failDecrypt: true}
		rsWithFailingEnc, _ := NewRemoteSigner(failStore, failingEnc, nil, nostr.GeneratePrivateKey())

		// Create frost key with shares
		kg := NewKeyGenerator(encryptor)
		config := &KeyGenConfig{
			Threshold:   2,
			TotalShares: 3,
		}
		result, _ := kg.GenerateKey(config)
		failStore.CreateFrostKey(nil, result.FrostKey)
		for _, share := range result.Shares {
			failStore.CreateFrostShare(nil, share)
		}

		// Create valid message and empty commitment list
		message := make([]byte, 32)
		messageHex := hex.EncodeToString(message)

		// Create a valid empty commitment list
		emptyList := frostlib.CommitmentList{}
		commitBytes := emptyList.Encode()

		payload := &SignRequestPayload{
			SessionID:   "test-decrypt-error",
			FrostKeyID:  result.FrostKey.ID,
			Message:     messageHex,
			Commitments: hex.EncodeToString(commitBytes),
		}
		payloadBytes, _ := json.Marshal(payload)
		// Should not panic - will fail at decryption
		rsWithFailingEnc.handleSignRequest(senderPubkey, payloadBytes)
	})

	t.Run("invalid share data", func(t *testing.T) {
		// Create frost key with invalid share data
		invalidShareKey := &FrostKey{
			ID:                 "invalid-share-data-key",
			Name:               "test",
			Pubkey:             "deadbeef",
			Threshold:          2,
			TotalShares:        3,
			GroupPublicKey:     make([]byte, 33),
			VerificationShares: nil, // Will be set below
		}

		// Create valid verification shares
		group := DefaultCiphersuite.Group()
		verShares := make([]*ecc.Element, 3)
		for i := 0; i < 3; i++ {
			scalar := group.NewScalar().Random()
			verShares[i] = group.Base().Multiply(scalar)
		}
		vs, _ := encodeVerificationShares(verShares, group)
		invalidShareKey.VerificationShares = vs
		store.CreateFrostKey(nil, invalidShareKey)

		// Create a share with invalid encrypted data (too short to decode)
		invalidShare := &FrostShare{
			ID:             "invalid-share-data",
			FrostKeyID:     invalidShareKey.ID,
			ShareIndex:     1,
			EncryptedShare: []byte{0x01, 0x02, 0x03}, // Too short
			IsLocal:        true,
		}
		store.CreateFrostShare(nil, invalidShare)

		message := make([]byte, 32)
		messageHex := hex.EncodeToString(message)

		// Create empty commitment list
		emptyList := frostlib.CommitmentList{}
		commitBytes := emptyList.Encode()

		payload := &SignRequestPayload{
			SessionID:   "test-invalid-share",
			FrostKeyID:  invalidShareKey.ID,
			Message:     messageHex,
			Commitments: hex.EncodeToString(commitBytes),
		}
		payloadBytes, _ := json.Marshal(payload)
		// Should not panic - will fail at decodeKeyShare
		rs.handleSignRequest(senderPubkey, payloadBytes)
	})

	t.Run("config creation error - zero threshold", func(t *testing.T) {
		// Create frost key with invalid threshold
		zeroThresholdKey := &FrostKey{
			ID:                 "zero-threshold-key",
			Name:               "test",
			Pubkey:             "deadbeef",
			Threshold:          0, // Invalid
			TotalShares:        3,
			GroupPublicKey:     make([]byte, 33),
			VerificationShares: nil, // Will be set below
		}

		// Create valid verification shares
		group := DefaultCiphersuite.Group()
		verShares := make([]*ecc.Element, 3)
		for i := 0; i < 3; i++ {
			scalar := group.NewScalar().Random()
			verShares[i] = group.Base().Multiply(scalar)
		}
		vs, _ := encodeVerificationShares(verShares, group)
		zeroThresholdKey.VerificationShares = vs
		store.CreateFrostKey(nil, zeroThresholdKey)

		// We need a valid share here
		kg := NewKeyGenerator(encryptor)
		goodConfig := &KeyGenConfig{
			Threshold:   2,
			TotalShares: 3,
		}
		goodResult, _ := kg.GenerateKey(goodConfig)

		// Create share pointing to the zero-threshold key but with valid share data
		validShare := &FrostShare{
			ID:             "valid-share-zero-threshold",
			FrostKeyID:     zeroThresholdKey.ID,
			ShareIndex:     1,
			EncryptedShare: goodResult.SecretData[0],
			IsLocal:        true,
		}
		store.CreateFrostShare(nil, validShare)

		message := make([]byte, 32)
		messageHex := hex.EncodeToString(message)

		// Create empty commitment list
		emptyList := frostlib.CommitmentList{}
		commitBytes := emptyList.Encode()

		payload := &SignRequestPayload{
			SessionID:   "test-zero-threshold",
			FrostKeyID:  zeroThresholdKey.ID,
			Message:     messageHex,
			Commitments: hex.EncodeToString(commitBytes),
		}
		payloadBytes, _ := json.Marshal(payload)
		// Should not panic - will fail at GetFrostConfiguration
		rs.handleSignRequest(senderPubkey, payloadBytes)
	})
}

func TestRemoteSigner_HandleMessage_AllTypes(t *testing.T) {
	store := newTestStorage()
	encryptor := &testEncryptor{}
	privkey := nostr.GeneratePrivateKey()
	senderPubkey, _ := nostr.GetPublicKey(nostr.GeneratePrivateKey())

	rs, err := NewRemoteSigner(store, encryptor, nil, privkey)
	if err != nil {
		t.Fatalf("NewRemoteSigner error: %v", err)
	}

	// Test all message type routing
	messageTypes := []string{
		MsgTypeSignRequest,
		MsgTypeSignCommitment,
		MsgTypeSignShare,
		"unknown_type",
	}

	for _, msgType := range messageTypes {
		t.Run(msgType, func(t *testing.T) {
			msg := &internalNostr.DMMessage{
				Type:    msgType,
				Payload: json.RawMessage(`{}`),
			}
			// Should not panic
			rs.handleMessage(senderPubkey, msg)
		})
	}
}

func TestSigningSession_Complete(t *testing.T) {
	// Test session completion detection
	group := DefaultCiphersuite.Group()

	session := &signingSession{
		ID:           "complete-test",
		FrostKeyID:   "key-123",
		Message:      make([]byte, 32),
		Participants: []int{1, 2, 3},
		ParticipantPubkeys: map[int]string{
			1: "pub1",
			2: "pub2",
			3: "pub3",
		},
		Commitments: make(map[int]*frostlib.Commitment),
		Shares:      make(map[int]*frostlib.SignatureShare),
		Done:        make(chan struct{}),
	}

	// Initially not complete
	session.mu.Lock()
	commitCount := len(session.Commitments)
	shareCount := len(session.Shares)
	session.mu.Unlock()

	if commitCount != 0 {
		t.Errorf("expected 0 commits, got %d", commitCount)
	}
	if shareCount != 0 {
		t.Errorf("expected 0 shares, got %d", shareCount)
	}

	// Add commitments
	for i := 1; i <= 3; i++ {
		scalar := group.NewScalar().Random()
		hidingNonce := group.Base().Multiply(scalar)
		bindingNonce := group.Base().Multiply(group.NewScalar().Random())
		commit := &frostlib.Commitment{
			HidingNonceCommitment:  hidingNonce,
			BindingNonceCommitment: bindingNonce,
			CommitmentID:           uint64(i),
			SignerID:               uint16(i),
			Group:                  group,
		}
		session.mu.Lock()
		session.Commitments[i] = commit
		session.mu.Unlock()
	}

	session.mu.Lock()
	commitCount = len(session.Commitments)
	session.mu.Unlock()

	if commitCount != 3 {
		t.Errorf("expected 3 commits, got %d", commitCount)
	}
}

func TestRemoteSigner_HandleSignCommitment_ValidCommitment(t *testing.T) {
	store := newTestStorage()
	encryptor := &testEncryptor{}
	privkey := nostr.GeneratePrivateKey()
	senderPubkey, _ := nostr.GetPublicKey(nostr.GeneratePrivateKey())

	rs, err := NewRemoteSigner(store, encryptor, nil, privkey)
	if err != nil {
		t.Fatalf("NewRemoteSigner error: %v", err)
	}

	group := DefaultCiphersuite.Group()

	// Create a session with the sender as a participant
	session := &signingSession{
		ID:                 "valid-commit-session",
		FrostKeyID:         "frost-key",
		ParticipantPubkeys: map[int]string{2: senderPubkey},
		Commitments:        make(map[int]*frostlib.Commitment),
		Shares:             make(map[int]*frostlib.SignatureShare),
		Done:               make(chan struct{}),
	}
	rs.mu.Lock()
	rs.sessions["valid-commit-session"] = session
	rs.mu.Unlock()

	// Create a valid FROST commitment
	hidingNonce := group.Base().Multiply(group.NewScalar().Random())
	bindingNonce := group.Base().Multiply(group.NewScalar().Random())
	commitment := &frostlib.Commitment{
		HidingNonceCommitment:  hidingNonce,
		BindingNonceCommitment: bindingNonce,
		CommitmentID:           2,
		SignerID:               2,
		Group:                  group,
	}
	commitmentHex := hex.EncodeToString(commitment.Encode())

	payload := &SignCommitmentPayload{
		SessionID:  "valid-commit-session",
		Index:      2,
		Commitment: commitmentHex,
	}
	payloadBytes, _ := json.Marshal(payload)

	rs.handleSignCommitment(senderPubkey, payloadBytes)

	// Check if commitment was added
	session.mu.Lock()
	_, exists := session.Commitments[2]
	session.mu.Unlock()

	if !exists {
		t.Error("valid commitment should be added to session")
	}
}

func TestRemoteSigner_HandleSignShare_ValidShare(t *testing.T) {
	store := newTestStorage()
	encryptor := &testEncryptor{}
	privkey := nostr.GeneratePrivateKey()
	senderPubkey, _ := nostr.GetPublicKey(nostr.GeneratePrivateKey())

	rs, err := NewRemoteSigner(store, encryptor, nil, privkey)
	if err != nil {
		t.Fatalf("NewRemoteSigner error: %v", err)
	}

	group := DefaultCiphersuite.Group()

	// Create a session with the sender as a participant
	session := &signingSession{
		ID:                 "valid-share-session",
		FrostKeyID:         "frost-key",
		ParticipantPubkeys: map[int]string{2: senderPubkey},
		Commitments:        make(map[int]*frostlib.Commitment),
		Shares:             make(map[int]*frostlib.SignatureShare),
		Done:               make(chan struct{}),
	}
	rs.mu.Lock()
	rs.sessions["valid-share-session"] = session
	rs.mu.Unlock()

	// Create a valid FROST signature share
	sigShare := &frostlib.SignatureShare{
		SignatureShare:   group.NewScalar().Random(),
		SignerIdentifier: 2,
		Group:            group,
	}
	shareHex := hex.EncodeToString(sigShare.Encode())

	payload := &SignSharePayload{
		SessionID: "valid-share-session",
		Index:     2,
		Share:     shareHex,
	}
	payloadBytes, _ := json.Marshal(payload)

	rs.handleSignShare(senderPubkey, payloadBytes)

	// Check if share was added
	session.mu.Lock()
	_, exists := session.Shares[2]
	session.mu.Unlock()

	if !exists {
		t.Error("valid share should be added to session")
	}
}

func TestRemoteSigner_HandleSignShare_InvalidShareDecode(t *testing.T) {
	store := newTestStorage()
	encryptor := &testEncryptor{}
	privkey := nostr.GeneratePrivateKey()
	senderPubkey, _ := nostr.GetPublicKey(nostr.GeneratePrivateKey())

	rs, err := NewRemoteSigner(store, encryptor, nil, privkey)
	if err != nil {
		t.Fatalf("NewRemoteSigner error: %v", err)
	}

	// Create a session with the sender as a participant
	session := &signingSession{
		ID:                 "invalid-decode-session",
		FrostKeyID:         "frost-key",
		ParticipantPubkeys: map[int]string{2: senderPubkey},
		Commitments:        make(map[int]*frostlib.Commitment),
		Shares:             make(map[int]*frostlib.SignatureShare),
		Done:               make(chan struct{}),
	}
	rs.mu.Lock()
	rs.sessions["invalid-decode-session"] = session
	rs.mu.Unlock()

	// Use valid hex but invalid share data (too short)
	payload := &SignSharePayload{
		SessionID: "invalid-decode-session",
		Index:     2,
		Share:     "abcd1234", // Valid hex but too short to be a valid signature share
	}
	payloadBytes, _ := json.Marshal(payload)

	// Should not panic, but share should not be added
	rs.handleSignShare(senderPubkey, payloadBytes)

	// Check that share was NOT added
	session.mu.Lock()
	_, exists := session.Shares[2]
	session.mu.Unlock()

	if exists {
		t.Error("invalid share should not be added to session")
	}
}

func TestRemoteSigner_StartListener(t *testing.T) {
	store := newTestStorage()
	encryptor := &testEncryptor{}
	privkey := nostr.GeneratePrivateKey()
	mockClient := newMockNostrClientRS()

	// Create RemoteSigner with mock client - need to manually set nostrClient
	rs, err := NewRemoteSigner(store, encryptor, nil, privkey)
	if err != nil {
		t.Fatalf("NewRemoteSigner error: %v", err)
	}
	rs.nostrClient = mockClient

	t.Run("calls SubscribeDMs", func(t *testing.T) {
		ctx := context.Background()
		err := rs.StartListener(ctx)
		if err != nil {
			t.Errorf("StartListener error: %v", err)
		}

		mockClient.mu.Lock()
		calls := mockClient.subscribeCalls
		mockClient.mu.Unlock()

		if calls != 1 {
			t.Errorf("expected 1 SubscribeDMs call, got %d", calls)
		}
	})
}

func TestRemoteSigner_SignWithRemoteShares(t *testing.T) {
	encryptor := &testEncryptor{}
	privkey := nostr.GeneratePrivateKey()
	ctx := context.Background()

	t.Run("frost key not found", func(t *testing.T) {
		store := newTestStorage()
		mockClient := newMockNostrClientRS()

		rs, _ := NewRemoteSigner(store, encryptor, nil, privkey)
		rs.nostrClient = mockClient

		_, err := rs.SignWithRemoteShares(ctx, "nonexistent-key", []byte("message"), nil)
		if err == nil {
			t.Error("expected error for nonexistent frost key")
		}
		if err != nil && err.Error() != "failed to get FROST key: key not found" {
			// Accept any error about getting FROST key
			if !contains(err.Error(), "FROST key") {
				t.Errorf("unexpected error: %v", err)
			}
		}
	})

	t.Run("no local shares", func(t *testing.T) {
		store := newTestStorage()
		mockClient := newMockNostrClientRS()

		// Create FROST key but no shares
		kg := NewKeyGenerator(encryptor)
		config := &KeyGenConfig{Threshold: 2, TotalShares: 3}
		result, _ := kg.GenerateKey(config)
		store.CreateFrostKey(ctx, result.FrostKey)

		rs, _ := NewRemoteSigner(store, encryptor, nil, privkey)
		rs.nostrClient = mockClient

		_, err := rs.SignWithRemoteShares(ctx, result.FrostKey.ID, []byte("message"), nil)
		if err == nil {
			t.Error("expected error when no local shares")
		}
		if err != nil && !contains(err.Error(), "no local shares") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("insufficient shares total", func(t *testing.T) {
		store := newTestStorage()
		mockClient := newMockNostrClientRS()

		// Create FROST key with threshold=3
		kg := NewKeyGenerator(encryptor)
		config := &KeyGenConfig{Threshold: 3, TotalShares: 5}
		result, _ := kg.GenerateKey(config)
		store.CreateFrostKey(ctx, result.FrostKey)

		// Only add 1 local share (need 3 for threshold)
		share := result.Shares[0]
		share.IsLocal = true
		store.CreateFrostShare(ctx, share)

		rs, _ := NewRemoteSigner(store, encryptor, nil, privkey)
		rs.nostrClient = mockClient

		// Only 1 local + 0 remote = 1 total, but threshold is 3
		_, err := rs.SignWithRemoteShares(ctx, result.FrostKey.ID, []byte("message"), nil)
		if err == nil {
			t.Error("expected error for insufficient shares")
		}
		if err != nil && !contains(err.Error(), "insufficient shares") {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("local-only signing success", func(t *testing.T) {
		store := newTestStorage()
		mockClient := newMockNostrClientRS()

		// Create FROST key with threshold=2
		kg := NewKeyGenerator(encryptor)
		config := &KeyGenConfig{Threshold: 2, TotalShares: 3}
		result, _ := kg.GenerateKey(config)
		store.CreateFrostKey(ctx, result.FrostKey)

		// Add 2 local shares (meets threshold)
		for i := 0; i < 2; i++ {
			share := result.Shares[i]
			share.IsLocal = true
			store.CreateFrostShare(ctx, share)
		}

		rs, _ := NewRemoteSigner(store, encryptor, nil, privkey)
		rs.nostrClient = mockClient

		message := []byte("test message to sign")
		signature, err := rs.SignWithRemoteShares(ctx, result.FrostKey.ID, message, nil)
		if err != nil {
			t.Fatalf("SignWithRemoteShares error: %v", err)
		}

		if len(signature) == 0 {
			t.Error("expected non-empty signature")
		}

		// No DMs should be sent for local-only signing
		mockClient.mu.Lock()
		sentCount := len(mockClient.sentMessages)
		mockClient.mu.Unlock()

		if sentCount != 0 {
			t.Errorf("expected 0 DMs sent for local-only signing, got %d", sentCount)
		}
	})

	t.Run("decryption error", func(t *testing.T) {
		store := newTestStorage()
		mockClient := newMockNostrClientRS()
		failingEnc := &failingEncryptor{failDecrypt: true}

		// Create FROST key with working encryptor
		kg := NewKeyGenerator(encryptor)
		config := &KeyGenConfig{Threshold: 2, TotalShares: 3}
		result, _ := kg.GenerateKey(config)
		store.CreateFrostKey(ctx, result.FrostKey)

		// Add 2 local shares
		for i := 0; i < 2; i++ {
			share := result.Shares[i]
			share.IsLocal = true
			store.CreateFrostShare(ctx, share)
		}

		// Use failing encryptor for the signer
		rs, _ := NewRemoteSigner(store, failingEnc, nil, privkey)
		rs.nostrClient = mockClient

		_, err := rs.SignWithRemoteShares(ctx, result.FrostKey.ID, []byte("message"), nil)
		if err == nil {
			t.Error("expected decryption error")
		}
		if err != nil && !contains(err.Error(), "decrypt") {
			t.Errorf("unexpected error (expected decrypt): %v", err)
		}
	})

	t.Run("verification shares decode error", func(t *testing.T) {
		store := newTestStorage()
		mockClient := newMockNostrClientRS()

		// Create FROST key with invalid verification shares
		invalidKey := &FrostKey{
			ID:                 "invalid-ver-key",
			Name:               "test",
			Pubkey:             "deadbeef",
			Threshold:          2,
			TotalShares:        3,
			GroupPublicKey:     make([]byte, 33),
			VerificationShares: []byte{0x00, 0x01}, // Invalid
		}
		store.CreateFrostKey(ctx, invalidKey)

		// Create valid-looking shares
		kg := NewKeyGenerator(encryptor)
		kgConfig := &KeyGenConfig{Threshold: 2, TotalShares: 3}
		kgResult, _ := kg.GenerateKey(kgConfig)

		for i := 0; i < 2; i++ {
			share := &FrostShare{
				ID:             generateID(),
				FrostKeyID:     invalidKey.ID,
				ShareIndex:     i + 1,
				EncryptedShare: kgResult.SecretData[i],
				IsLocal:        true,
			}
			store.CreateFrostShare(ctx, share)
		}

		rs, _ := NewRemoteSigner(store, encryptor, nil, privkey)
		rs.nostrClient = mockClient

		_, err := rs.SignWithRemoteShares(ctx, invalidKey.ID, []byte("message"), nil)
		if err == nil {
			t.Error("expected error for invalid verification shares")
		}
	})

	t.Run("invalid key share data", func(t *testing.T) {
		store := newTestStorage()
		mockClient := newMockNostrClientRS()

		// Create FROST key with valid verification shares
		kg := NewKeyGenerator(encryptor)
		config := &KeyGenConfig{Threshold: 2, TotalShares: 3}
		result, _ := kg.GenerateKey(config)
		store.CreateFrostKey(ctx, result.FrostKey)

		// Create shares with invalid encrypted data
		for i := 0; i < 2; i++ {
			share := &FrostShare{
				ID:             generateID(),
				FrostKeyID:     result.FrostKey.ID,
				ShareIndex:     i + 1,
				EncryptedShare: []byte{0x01, 0x02}, // Too short
				IsLocal:        true,
			}
			store.CreateFrostShare(ctx, share)
		}

		rs, _ := NewRemoteSigner(store, encryptor, nil, privkey)
		rs.nostrClient = mockClient

		_, err := rs.SignWithRemoteShares(ctx, result.FrostKey.ID, []byte("message"), nil)
		if err == nil {
			t.Error("expected error for invalid key share data")
		}
	})

	t.Run("with remote holders sends DMs", func(t *testing.T) {
		store := newTestStorage()
		mockClient := newMockNostrClientRS()

		// Create FROST key with threshold=2
		kg := NewKeyGenerator(encryptor)
		config := &KeyGenConfig{Threshold: 2, TotalShares: 3}
		result, _ := kg.GenerateKey(config)
		store.CreateFrostKey(ctx, result.FrostKey)

		// Add 1 local share only
		share := result.Shares[0]
		share.IsLocal = true
		store.CreateFrostShare(ctx, share)

		rs, _ := NewRemoteSigner(store, encryptor, nil, privkey)
		rs.nostrClient = mockClient

		remotePubkey := "remote-participant-pubkey"
		remoteHolders := map[int]string{2: remotePubkey}

		// This will timeout waiting for remote response, but should still send the DM
		timeoutCtx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()

		_, err := rs.SignWithRemoteShares(timeoutCtx, result.FrostKey.ID, []byte("message"), remoteHolders)
		// Expect timeout error
		if err == nil {
			t.Error("expected timeout error when waiting for remote response")
		}

		// But a DM should have been sent
		mockClient.mu.Lock()
		sentCount := len(mockClient.sentMessages)
		mockClient.mu.Unlock()

		if sentCount == 0 {
			t.Error("expected at least 1 DM to be sent to remote holder")
		}
	})
}

// contains is a simple helper for checking substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestRemoteSigner_HandleSignRequest_SuccessPath(t *testing.T) {
	store := newTestStorage()
	encryptor := &testEncryptor{}
	privkey := nostr.GeneratePrivateKey()
	senderPubkey, _ := nostr.GetPublicKey(nostr.GeneratePrivateKey())
	mockClient := newMockNostrClientRS()

	// Create RemoteSigner with mock
	rs, err := NewRemoteSigner(store, encryptor, nil, privkey)
	if err != nil {
		t.Fatalf("NewRemoteSigner error: %v", err)
	}
	rs.nostrClient = mockClient

	// Generate FROST key with proper shares
	kg := NewKeyGenerator(encryptor)
	kgConfig := &KeyGenConfig{Threshold: 2, TotalShares: 3}
	result, err := kg.GenerateKey(kgConfig)
	if err != nil {
		t.Fatalf("GenerateKey error: %v", err)
	}

	// Store the key
	store.CreateFrostKey(nil, result.FrostKey)

	// Store one share as local (the one the signer will use)
	share := result.Shares[0]
	share.IsLocal = true
	store.CreateFrostShare(nil, share)

	// Create a signer from another share to generate valid commitments
	group := DefaultCiphersuite.Group()
	verificationPubKeys, err := decodeVerificationShares(result.FrostKey.VerificationShares, group)
	if err != nil {
		t.Fatalf("decodeVerificationShares error: %v", err)
	}

	publicKeyShares := make([]*keys.PublicKeyShare, result.FrostKey.TotalShares)
	for i := 0; i < result.FrostKey.TotalShares; i++ {
		publicKeyShares[i] = &keys.PublicKeyShare{
			PublicKey: verificationPubKeys[i],
			ID:        uint16(i + 1),
			Group:     group,
		}
	}

	frostConfig, err := GetFrostConfiguration(result.FrostKey, publicKeyShares)
	if err != nil {
		t.Fatalf("GetFrostConfiguration error: %v", err)
	}

	// Decode second share to create commitments
	otherShareData := result.SecretData[1]
	otherKS, err := decodeKeyShare(otherShareData, group)
	if err != nil {
		t.Fatalf("decodeKeyShare error: %v", err)
	}

	otherSigner, err := frostConfig.Signer(otherKS)
	if err != nil {
		t.Fatalf("Signer error: %v", err)
	}

	// Generate commitment from the other signer
	commitment := otherSigner.Commit()
	commitmentList := frostlib.CommitmentList{commitment}
	commitmentList.Sort()
	commitmentsHex := hex.EncodeToString(commitmentList.Encode())

	// Create the sign request
	message := []byte("test message to sign")
	messageHex := hex.EncodeToString(message)

	payload := &SignRequestPayload{
		SessionID:   "test-success-session",
		FrostKeyID:  result.FrostKey.ID,
		Message:     messageHex,
		Commitments: commitmentsHex,
	}
	payloadBytes, _ := json.Marshal(payload)

	// Call handleSignRequest
	rs.handleSignRequest(senderPubkey, payloadBytes)

	// Verify DMs were sent (commitment + signature share)
	mockClient.mu.Lock()
	sentCount := len(mockClient.sentMessages)
	messages := mockClient.sentMessages
	mockClient.mu.Unlock()

	if sentCount != 2 {
		t.Errorf("expected 2 DMs sent (commitment + share), got %d", sentCount)
	}

	// Verify message types
	hasCommitment := false
	hasShare := false
	for _, msg := range messages {
		if msg.message.Type == MsgTypeSignCommitment {
			hasCommitment = true
		}
		if msg.message.Type == MsgTypeSignShare {
			hasShare = true
		}
	}

	if !hasCommitment {
		t.Error("expected a commitment message to be sent")
	}
	if !hasShare {
		t.Error("expected a signature share message to be sent")
	}
}

func TestRemoteSigner_HandleSignRequest_SendCommitmentError(t *testing.T) {
	store := newTestStorage()
	encryptor := &testEncryptor{}
	privkey := nostr.GeneratePrivateKey()
	senderPubkey, _ := nostr.GetPublicKey(nostr.GeneratePrivateKey())
	mockClient := newMockNostrClientRS()
	mockClient.sendError = fmt.Errorf("simulated send error")

	rs, err := NewRemoteSigner(store, encryptor, nil, privkey)
	if err != nil {
		t.Fatalf("NewRemoteSigner error: %v", err)
	}
	rs.nostrClient = mockClient

	// Generate FROST key with proper shares
	kg := NewKeyGenerator(encryptor)
	kgConfig := &KeyGenConfig{Threshold: 2, TotalShares: 3}
	result, _ := kg.GenerateKey(kgConfig)
	store.CreateFrostKey(nil, result.FrostKey)

	share := result.Shares[0]
	share.IsLocal = true
	store.CreateFrostShare(nil, share)

	// Create valid commitments
	group := DefaultCiphersuite.Group()
	verificationPubKeys, _ := decodeVerificationShares(result.FrostKey.VerificationShares, group)

	publicKeyShares := make([]*keys.PublicKeyShare, result.FrostKey.TotalShares)
	for i := 0; i < result.FrostKey.TotalShares; i++ {
		publicKeyShares[i] = &keys.PublicKeyShare{
			PublicKey: verificationPubKeys[i],
			ID:        uint16(i + 1),
			Group:     group,
		}
	}

	frostConfig, _ := GetFrostConfiguration(result.FrostKey, publicKeyShares)
	otherShareData := result.SecretData[1]
	otherKS, _ := decodeKeyShare(otherShareData, group)
	otherSigner, _ := frostConfig.Signer(otherKS)

	commitment := otherSigner.Commit()
	commitmentList := frostlib.CommitmentList{commitment}
	commitmentList.Sort()
	commitmentsHex := hex.EncodeToString(commitmentList.Encode())

	message := []byte("test message")
	messageHex := hex.EncodeToString(message)

	payload := &SignRequestPayload{
		SessionID:   "test-send-error",
		FrostKeyID:  result.FrostKey.ID,
		Message:     messageHex,
		Commitments: commitmentsHex,
	}
	payloadBytes, _ := json.Marshal(payload)

	// Should not panic - returns early on send error
	rs.handleSignRequest(senderPubkey, payloadBytes)
}

func TestRemoteSigner_HandleSignRequest_NoEncryptor(t *testing.T) {
	store := newTestStorage()
	encryptor := &testEncryptor{}
	privkey := nostr.GeneratePrivateKey()
	senderPubkey, _ := nostr.GetPublicKey(nostr.GeneratePrivateKey())
	mockClient := newMockNostrClientRS()

	// Create RemoteSigner WITHOUT encryptor (nil)
	rs, err := NewRemoteSigner(store, nil, nil, privkey)
	if err != nil {
		t.Fatalf("NewRemoteSigner error: %v", err)
	}
	rs.nostrClient = mockClient

	// Generate FROST key - shares won't be encrypted
	kg := NewKeyGenerator(encryptor)
	kgConfig := &KeyGenConfig{Threshold: 2, TotalShares: 3}
	result, _ := kg.GenerateKey(kgConfig)
	store.CreateFrostKey(nil, result.FrostKey)

	share := result.Shares[0]
	share.IsLocal = true
	store.CreateFrostShare(nil, share)

	// Create valid commitments
	group := DefaultCiphersuite.Group()
	verificationPubKeys, _ := decodeVerificationShares(result.FrostKey.VerificationShares, group)

	publicKeyShares := make([]*keys.PublicKeyShare, result.FrostKey.TotalShares)
	for i := 0; i < result.FrostKey.TotalShares; i++ {
		publicKeyShares[i] = &keys.PublicKeyShare{
			PublicKey: verificationPubKeys[i],
			ID:        uint16(i + 1),
			Group:     group,
		}
	}

	frostConfig, _ := GetFrostConfiguration(result.FrostKey, publicKeyShares)
	otherShareData := result.SecretData[1]
	otherKS, _ := decodeKeyShare(otherShareData, group)
	otherSigner, _ := frostConfig.Signer(otherKS)

	commitment := otherSigner.Commit()
	commitmentList := frostlib.CommitmentList{commitment}
	commitmentList.Sort()
	commitmentsHex := hex.EncodeToString(commitmentList.Encode())

	message := []byte("test message no encryptor")
	messageHex := hex.EncodeToString(message)

	payload := &SignRequestPayload{
		SessionID:   "test-no-enc",
		FrostKeyID:  result.FrostKey.ID,
		Message:     messageHex,
		Commitments: commitmentsHex,
	}
	payloadBytes, _ := json.Marshal(payload)

	// Should work - share data used directly without decryption
	rs.handleSignRequest(senderPubkey, payloadBytes)

	// Verify DMs were sent
	mockClient.mu.Lock()
	sentCount := len(mockClient.sentMessages)
	mockClient.mu.Unlock()

	if sentCount != 2 {
		t.Errorf("expected 2 DMs sent, got %d", sentCount)
	}
}
