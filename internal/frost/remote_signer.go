package frost

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	frostlib "github.com/bytemare/frost"
	"github.com/bytemare/secret-sharing/keys"

	"git.coldforge.xyz/coldforge/cloistr-signer/internal/nostr"
)

// RemoteSigner coordinates FROST signing with remote share holders
type RemoteSigner struct {
	storage     FrostStorage
	encryptor   Encryptor
	nostrClient *nostr.Client
	privateKey  string
	pubkey      string

	// Active signing sessions
	sessions map[string]*signingSession
	mu       sync.RWMutex
}

// signingSession tracks an in-progress distributed signing operation
type signingSession struct {
	ID            string
	FrostKeyID    string
	Message       []byte
	Participants  []int                           // Share indices participating
	ParticipantPubkeys map[int]string             // Index -> pubkey mapping
	Commitments   map[int]*frostlib.Commitment    // Collected commitments
	Shares        map[int]*frostlib.SignatureShare // Collected signature shares
	LocalShare    *frostlib.SignatureShare        // Our signature share
	Result        []byte                          // Final signature
	Error         error
	Done          chan struct{}
	mu            sync.Mutex
}

// NewRemoteSigner creates a new remote signing coordinator
func NewRemoteSigner(storage FrostStorage, encryptor Encryptor, nostrClient *nostr.Client, privateKey string) (*RemoteSigner, error) {
	pubkey, err := getPublicKeyFromPrivate(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive pubkey: %w", err)
	}

	return &RemoteSigner{
		storage:     storage,
		encryptor:   encryptor,
		nostrClient: nostrClient,
		privateKey:  privateKey,
		pubkey:      pubkey,
		sessions:    make(map[string]*signingSession),
	}, nil
}

// StartListener starts listening for signing-related messages
func (r *RemoteSigner) StartListener(ctx context.Context) error {
	return r.nostrClient.SubscribeDMs(ctx, r.privateKey, r.handleMessage)
}

// handleMessage routes incoming signing messages
func (r *RemoteSigner) handleMessage(senderPubkey string, message *nostr.DMMessage) {
	switch message.Type {
	case MsgTypeSignRequest:
		r.handleSignRequest(senderPubkey, message.Payload)
	case MsgTypeSignCommitment:
		r.handleSignCommitment(senderPubkey, message.Payload)
	case MsgTypeSignShare:
		r.handleSignShare(senderPubkey, message.Payload)
	}
}

// SignWithRemoteShares signs a message using both local and remote shares
func (r *RemoteSigner) SignWithRemoteShares(ctx context.Context, frostKeyID string, message []byte, remoteHolders map[int]string) ([]byte, error) {
	// Get the FROST key
	frostKey, err := r.storage.GetFrostKey(ctx, frostKeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to get FROST key: %w", err)
	}

	// Get our local shares
	localShares, err := r.storage.ListLocalFrostShares(ctx, frostKeyID)
	if err != nil {
		return nil, fmt.Errorf("failed to list local shares: %w", err)
	}

	if len(localShares) == 0 {
		return nil, fmt.Errorf("no local shares available")
	}

	// Calculate total available shares
	totalAvailable := len(localShares) + len(remoteHolders)
	if totalAvailable < frostKey.Threshold {
		return nil, fmt.Errorf("insufficient shares: have %d (local: %d, remote: %d), need %d",
			totalAvailable, len(localShares), len(remoteHolders), frostKey.Threshold)
	}

	// Create signing session
	sessionID := generateID()
	session := &signingSession{
		ID:                 sessionID,
		FrostKeyID:         frostKeyID,
		Message:            message,
		ParticipantPubkeys: remoteHolders,
		Commitments:        make(map[int]*frostlib.Commitment),
		Shares:             make(map[int]*frostlib.SignatureShare),
		Done:               make(chan struct{}),
	}

	// Determine which shares to use
	// Use all local shares first, then add remote shares as needed
	neededRemote := frostKey.Threshold - len(localShares)
	if neededRemote < 0 {
		neededRemote = 0
	}

	// Collect participant indices
	participants := make([]int, 0, frostKey.Threshold)
	for _, share := range localShares {
		participants = append(participants, share.ShareIndex)
		if len(participants) >= frostKey.Threshold && neededRemote == 0 {
			break
		}
	}

	remoteCount := 0
	for idx := range remoteHolders {
		if remoteCount >= neededRemote {
			break
		}
		participants = append(participants, idx)
		remoteCount++
	}

	session.Participants = participants

	r.mu.Lock()
	r.sessions[sessionID] = session
	r.mu.Unlock()

	// Start local signing process
	group := DefaultCiphersuite.Group()

	// Decode key shares and create signers
	publicKeyShares := make([]*keys.PublicKeyShare, frostKey.TotalShares)
	verificationPubKeys, err := decodeVerificationShares(frostKey.VerificationShares, group)
	if err != nil {
		return nil, fmt.Errorf("failed to decode verification shares: %w", err)
	}

	for i := 0; i < frostKey.TotalShares; i++ {
		publicKeyShares[i] = &keys.PublicKeyShare{
			PublicKey: verificationPubKeys[i],
			ID:        uint16(i + 1),
			Group:     group,
		}
	}

	config, err := GetFrostConfiguration(frostKey, publicKeyShares)
	if err != nil {
		return nil, fmt.Errorf("failed to create configuration: %w", err)
	}

	// Generate commitments for local shares
	localSigners := make(map[int]*frostlib.Signer)
	for _, share := range localShares {
		// Check if this share is a participant
		isParticipant := false
		for _, idx := range participants {
			if idx == share.ShareIndex {
				isParticipant = true
				break
			}
		}
		if !isParticipant {
			continue
		}

		// Decrypt share
		var shareData []byte
		if r.encryptor != nil && len(share.EncryptedShare) > 0 {
			decrypted, err := r.encryptor.Decrypt(share.EncryptedShare)
			if err != nil {
				return nil, fmt.Errorf("failed to decrypt share %d: %w", share.ShareIndex, err)
			}
			shareData = decrypted
		} else {
			shareData = share.EncryptedShare
		}

		ks, err := decodeKeyShare(shareData, group)
		if err != nil {
			return nil, fmt.Errorf("failed to decode key share %d: %w", share.ShareIndex, err)
		}

		signer, err := config.Signer(ks)
		if err != nil {
			return nil, fmt.Errorf("failed to create signer for share %d: %w", share.ShareIndex, err)
		}

		localSigners[share.ShareIndex] = signer

		// Generate commitment
		commitment := signer.Commit()
		session.mu.Lock()
		session.Commitments[share.ShareIndex] = commitment
		session.mu.Unlock()
	}

	// If we have remote participants, send signing request with our commitments
	if len(remoteHolders) > 0 && neededRemote > 0 {
		// Encode our commitments
		var commitmentList frostlib.CommitmentList
		for _, idx := range participants {
			if c, ok := session.Commitments[idx]; ok {
				commitmentList = append(commitmentList, c)
			}
		}
		commitmentList.Sort()
		commitmentsHex := hex.EncodeToString(commitmentList.Encode())

		signRequest := &SignRequestPayload{
			SessionID:   sessionID,
			FrostKeyID:  frostKeyID,
			Message:     hex.EncodeToString(message),
			Commitments: commitmentsHex,
		}

		payloadBytes, _ := json.Marshal(signRequest)
		msg := &nostr.DMMessage{
			Type:    MsgTypeSignRequest,
			Payload: payloadBytes,
		}

		// Send to remote participants
		for idx, pubkey := range remoteHolders {
			isParticipant := false
			for _, pIdx := range participants {
				if pIdx == idx {
					isParticipant = true
					break
				}
			}
			if !isParticipant {
				continue
			}

			if err := r.nostrClient.SendEphemeralDM(ctx, r.privateKey, pubkey, msg); err != nil {
				slog.Warn("failed to send sign request", "to_index", idx, "error", err)
			}
		}

		// Wait for remote commitments (with timeout)
		waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		for {
			session.mu.Lock()
			if len(session.Commitments) >= frostKey.Threshold {
				session.mu.Unlock()
				break
			}
			session.mu.Unlock()

			select {
			case <-waitCtx.Done():
				return nil, fmt.Errorf("timeout waiting for remote commitments")
			case <-time.After(100 * time.Millisecond):
				continue
			}
		}
	}

	// Build commitment list
	session.mu.Lock()
	var commitmentList frostlib.CommitmentList
	for _, idx := range participants {
		if c, ok := session.Commitments[idx]; ok {
			commitmentList = append(commitmentList, c)
		}
	}
	session.mu.Unlock()

	if len(commitmentList) < frostKey.Threshold {
		return nil, fmt.Errorf("insufficient commitments: have %d, need %d", len(commitmentList), frostKey.Threshold)
	}

	commitmentList.Sort()

	// Generate local signature shares
	for idx, signer := range localSigners {
		sigShare, err := signer.Sign(message, commitmentList)
		if err != nil {
			return nil, fmt.Errorf("failed to sign with share %d: %w", idx, err)
		}
		session.mu.Lock()
		session.Shares[idx] = sigShare
		session.mu.Unlock()
	}

	// If we need remote shares, wait for them
	if neededRemote > 0 {
		waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()

		for {
			session.mu.Lock()
			if len(session.Shares) >= frostKey.Threshold {
				session.mu.Unlock()
				break
			}
			session.mu.Unlock()

			select {
			case <-waitCtx.Done():
				return nil, fmt.Errorf("timeout waiting for remote signature shares")
			case <-time.After(100 * time.Millisecond):
				continue
			}
		}
	}

	// Aggregate signatures
	session.mu.Lock()
	var sigShares []*frostlib.SignatureShare
	for _, idx := range participants[:frostKey.Threshold] {
		if s, ok := session.Shares[idx]; ok {
			sigShares = append(sigShares, s)
		}
	}
	session.mu.Unlock()

	signature, err := config.AggregateSignatures(message, sigShares, commitmentList, true)
	if err != nil {
		return nil, fmt.Errorf("failed to aggregate signatures: %w", err)
	}

	sigBytes := signature.Encode()

	// Cleanup session
	r.mu.Lock()
	delete(r.sessions, sessionID)
	r.mu.Unlock()

	return sigBytes, nil
}

// handleSignRequest processes an incoming signing request (as a remote participant)
func (r *RemoteSigner) handleSignRequest(senderPubkey string, payload json.RawMessage) {
	var req SignRequestPayload
	if err := json.Unmarshal(payload, &req); err != nil {
		return
	}

	ctx := context.Background()

	// Check if we have a share for this key
	frostKey, err := r.storage.GetFrostKey(ctx, req.FrostKeyID)
	if err != nil {
		slog.Debug("sign request for unknown key", "key_id", req.FrostKeyID)
		return
	}

	localShares, err := r.storage.ListLocalFrostShares(ctx, req.FrostKeyID)
	if err != nil || len(localShares) == 0 {
		slog.Debug("no local share for signing request", "key_id", req.FrostKeyID)
		return
	}

	message, err := hex.DecodeString(req.Message)
	if err != nil {
		return
	}

	slog.Info("received signing request", "session_id", req.SessionID, "key_id", req.FrostKeyID[:8])

	// Decode incoming commitments
	commitmentsBytes, err := hex.DecodeString(req.Commitments)
	if err != nil {
		return
	}

	commitmentList, err := frostlib.DecodeList(commitmentsBytes)
	if err != nil {
		slog.Warn("failed to decode commitments", "error", err)
		return
	}

	// Set up FROST configuration
	group := DefaultCiphersuite.Group()
	publicKeyShares := make([]*keys.PublicKeyShare, frostKey.TotalShares)
	verificationPubKeys, err := decodeVerificationShares(frostKey.VerificationShares, group)
	if err != nil {
		return
	}

	for i := 0; i < frostKey.TotalShares; i++ {
		publicKeyShares[i] = &keys.PublicKeyShare{
			PublicKey: verificationPubKeys[i],
			ID:        uint16(i + 1),
			Group:     group,
		}
	}

	config, err := GetFrostConfiguration(frostKey, publicKeyShares)
	if err != nil {
		return
	}

	// Use first local share
	share := localShares[0]
	var shareData []byte
	if r.encryptor != nil && len(share.EncryptedShare) > 0 {
		decrypted, err := r.encryptor.Decrypt(share.EncryptedShare)
		if err != nil {
			return
		}
		shareData = decrypted
	} else {
		shareData = share.EncryptedShare
	}

	ks, err := decodeKeyShare(shareData, group)
	if err != nil {
		return
	}

	signer, err := config.Signer(ks)
	if err != nil {
		return
	}

	// Generate our commitment and add to list
	ourCommitment := signer.Commit()
	commitmentList = append(commitmentList, ourCommitment)
	commitmentList.Sort()

	// Send our commitment back
	commitPayload := &SignCommitmentPayload{
		SessionID:  req.SessionID,
		Index:      share.ShareIndex,
		Commitment: hex.EncodeToString(ourCommitment.Encode()),
	}

	payloadBytes, _ := json.Marshal(commitPayload)
	msg := &nostr.DMMessage{
		Type:    MsgTypeSignCommitment,
		Payload: payloadBytes,
	}

	if err := r.nostrClient.SendEphemeralDM(ctx, r.privateKey, senderPubkey, msg); err != nil {
		slog.Warn("failed to send commitment", "error", err)
		return
	}

	// Generate signature share
	sigShare, err := signer.Sign(message, commitmentList)
	if err != nil {
		slog.Warn("failed to sign", "error", err)
		return
	}

	// Send signature share
	sharePayload := &SignSharePayload{
		SessionID: req.SessionID,
		Index:     share.ShareIndex,
		Share:     hex.EncodeToString(sigShare.Encode()),
	}

	payloadBytes, _ = json.Marshal(sharePayload)
	msg = &nostr.DMMessage{
		Type:    MsgTypeSignShare,
		Payload: payloadBytes,
	}

	if err := r.nostrClient.SendEphemeralDM(ctx, r.privateKey, senderPubkey, msg); err != nil {
		slog.Warn("failed to send signature share", "error", err)
	}

	slog.Info("sent signature share", "session_id", req.SessionID)
}

// handleSignCommitment processes an incoming commitment from a remote participant
func (r *RemoteSigner) handleSignCommitment(senderPubkey string, payload json.RawMessage) {
	var commit SignCommitmentPayload
	if err := json.Unmarshal(payload, &commit); err != nil {
		return
	}

	r.mu.RLock()
	session, exists := r.sessions[commit.SessionID]
	r.mu.RUnlock()

	if !exists {
		return
	}

	// Verify sender
	expectedPubkey, ok := session.ParticipantPubkeys[commit.Index]
	if !ok || expectedPubkey != senderPubkey {
		return
	}

	// Decode commitment
	commitBytes, err := hex.DecodeString(commit.Commitment)
	if err != nil {
		return
	}

	commitment := new(frostlib.Commitment)
	if err := commitment.Decode(commitBytes); err != nil {
		return
	}

	session.mu.Lock()
	session.Commitments[commit.Index] = commitment
	session.mu.Unlock()

	slog.Debug("received commitment", "session_id", commit.SessionID, "index", commit.Index)
}

// handleSignShare processes an incoming signature share from a remote participant
func (r *RemoteSigner) handleSignShare(senderPubkey string, payload json.RawMessage) {
	var shareMsg SignSharePayload
	if err := json.Unmarshal(payload, &shareMsg); err != nil {
		return
	}

	r.mu.RLock()
	session, exists := r.sessions[shareMsg.SessionID]
	r.mu.RUnlock()

	if !exists {
		return
	}

	// Verify sender
	expectedPubkey, ok := session.ParticipantPubkeys[shareMsg.Index]
	if !ok || expectedPubkey != senderPubkey {
		return
	}

	// Decode signature share
	shareBytes, err := hex.DecodeString(shareMsg.Share)
	if err != nil {
		return
	}

	sigShare := new(frostlib.SignatureShare)
	if err := sigShare.Decode(shareBytes); err != nil {
		return
	}

	session.mu.Lock()
	session.Shares[shareMsg.Index] = sigShare
	session.mu.Unlock()

	slog.Debug("received signature share", "session_id", shareMsg.SessionID, "index", shareMsg.Index)
}
