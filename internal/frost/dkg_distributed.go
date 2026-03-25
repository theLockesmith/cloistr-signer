package frost

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/bytemare/ecc"

	"git.coldforge.xyz/coldforge/cloistr-signer/internal/nostr"
)

// DistributedDKG coordinates distributed key generation across multiple signers
type DistributedDKG struct {
	storage      FrostStorage
	encryptor    Encryptor
	nostrClient  *nostr.Client
	privateKey   string // Our Nostr identity key (hex)
	pubkey       string // Our Nostr pubkey (hex)

	sessions     map[string]*localDKGState
	mu           sync.RWMutex

	// Callbacks
	onSessionComplete func(sessionID string, frostKeyID string, groupPubkey string)
	onSessionFailed   func(sessionID string, reason string)
}

// localDKGState holds local state for a DKG session
type localDKGState struct {
	Session       *DKGSession
	MyIndex       int                          // Our participant index (1-based)
	Polynomial    []*ecc.Scalar                // Our secret polynomial coefficients
	Commitment    []*ecc.Element               // Our commitment (public polynomial)
	ReceivedCommits map[int][]*ecc.Element     // Commitments from other participants
	ReceivedShares  map[int]*ecc.Scalar        // Shares received from others
	MyShare       *ecc.Scalar                  // Our aggregated share
	Accepted      map[string]bool              // Which participants have accepted
	Verified      map[int]bool                 // Which participants have verified
	mu            sync.Mutex
}

// NewDistributedDKG creates a new distributed DKG coordinator
func NewDistributedDKG(storage FrostStorage, encryptor Encryptor, nostrClient *nostr.Client, privateKey string) (*DistributedDKG, error) {
	pubkey, err := getPublicKeyFromPrivate(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive pubkey: %w", err)
	}

	dkg := &DistributedDKG{
		storage:     storage,
		encryptor:   encryptor,
		nostrClient: nostrClient,
		privateKey:  privateKey,
		pubkey:      pubkey,
		sessions:    make(map[string]*localDKGState),
	}

	return dkg, nil
}

// SetCallbacks sets completion/failure callbacks
func (d *DistributedDKG) SetCallbacks(onComplete func(string, string, string), onFailed func(string, string)) {
	d.onSessionComplete = onComplete
	d.onSessionFailed = onFailed
}

// StartDMListener starts listening for DKG messages
func (d *DistributedDKG) StartDMListener(ctx context.Context) error {
	return d.nostrClient.SubscribeDMs(ctx, d.privateKey, d.handleDM)
}

// handleDM processes incoming DKG messages
func (d *DistributedDKG) handleDM(senderPubkey string, message *nostr.DMMessage) {
	switch message.Type {
	case MsgTypeDKGInit:
		d.handleDKGInit(senderPubkey, message.Payload)
	case MsgTypeDKGAccept:
		d.handleDKGAccept(senderPubkey, message.Payload)
	case MsgTypeDKGCommit:
		d.handleDKGCommit(senderPubkey, message.Payload)
	case MsgTypeDKGShare:
		d.handleDKGShare(senderPubkey, message.Payload)
	case MsgTypeDKGVerify:
		d.handleDKGVerify(senderPubkey, message.Payload)
	case MsgTypeDKGComplete:
		d.handleDKGComplete(senderPubkey, message.Payload)
	case MsgTypeDKGAbort:
		d.handleDKGAbort(senderPubkey, message.Payload)
	default:
		slog.Debug("unknown DKG message type", "type", message.Type, "from", senderPubkey)
	}
}

// InitiateSession starts a new distributed DKG session
func (d *DistributedDKG) InitiateSession(ctx context.Context, participants []string, threshold int, keyName string) (*DKGSession, error) {
	if threshold < 2 {
		return nil, fmt.Errorf("threshold must be at least 2 for distributed DKG")
	}
	if len(participants) < threshold {
		return nil, fmt.Errorf("need at least %d participants for threshold %d", threshold, threshold)
	}

	// Ensure we're in the participants list
	myIndex := -1
	for i, p := range participants {
		if p == d.pubkey {
			myIndex = i + 1 // 1-based index
			break
		}
	}
	if myIndex == -1 {
		return nil, fmt.Errorf("initiator must be a participant")
	}

	sessionID := generateID()
	now := time.Now()
	expiresAt := now.Add(5 * time.Minute)

	session := &DKGSession{
		ID:           sessionID,
		Initiator:    d.pubkey,
		Participants: participants,
		Threshold:    threshold,
		TotalShares:  len(participants),
		Status:       DKGStatusPending,
		StartedAt:    now,
		Round:        0,
	}

	// Create local state
	state := &localDKGState{
		Session:         session,
		MyIndex:         myIndex,
		ReceivedCommits: make(map[int][]*ecc.Element),
		ReceivedShares:  make(map[int]*ecc.Scalar),
		Accepted:        make(map[string]bool),
		Verified:        make(map[int]bool),
	}
	// We implicitly accept our own invitation
	state.Accepted[d.pubkey] = true

	d.mu.Lock()
	d.sessions[sessionID] = state
	d.mu.Unlock()

	// Send DKG init to all other participants
	initPayload := &DKGInitPayload{
		SessionID:    sessionID,
		Participants: participants,
		Threshold:    threshold,
		TotalShares:  len(participants),
		KeyName:      keyName,
		ExpiresAt:    expiresAt.Unix(),
	}

	payloadBytes, err := json.Marshal(initPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal init payload: %w", err)
	}

	msg := &nostr.DMMessage{
		Type:    MsgTypeDKGInit,
		Payload: payloadBytes,
	}

	// Send to all other participants
	for _, participant := range participants {
		if participant == d.pubkey {
			continue // Don't send to ourselves
		}
		if err := d.nostrClient.SendEphemeralDM(ctx, d.privateKey, participant, msg); err != nil {
			slog.Warn("failed to send DKG init", "to", participant, "error", err)
			// Continue anyway - they might come online later
		}
	}

	slog.Info("initiated DKG session", "session_id", sessionID, "participants", len(participants), "threshold", threshold)
	return session, nil
}

// handleDKGInit processes a DKG initialization request
func (d *DistributedDKG) handleDKGInit(senderPubkey string, payload json.RawMessage) {
	var init DKGInitPayload
	if err := json.Unmarshal(payload, &init); err != nil {
		slog.Warn("failed to unmarshal DKG init", "error", err)
		return
	}

	// Check if invitation has expired
	if time.Now().Unix() > init.ExpiresAt {
		slog.Info("DKG invitation expired", "session_id", init.SessionID)
		return
	}

	// Find our index
	myIndex := -1
	for i, p := range init.Participants {
		if p == d.pubkey {
			myIndex = i + 1
			break
		}
	}
	if myIndex == -1 {
		slog.Debug("not a participant in DKG session", "session_id", init.SessionID)
		return
	}

	// Verify sender is the first participant (initiator)
	if len(init.Participants) == 0 || senderPubkey != init.Participants[0] {
		// Allow any participant to forward the init
		found := false
		for _, p := range init.Participants {
			if p == senderPubkey {
				found = true
				break
			}
		}
		if !found {
			slog.Warn("DKG init from non-participant", "from", senderPubkey)
			return
		}
	}

	// Check if we already have this session
	d.mu.Lock()
	if _, exists := d.sessions[init.SessionID]; exists {
		d.mu.Unlock()
		return
	}

	// Create session state
	session := &DKGSession{
		ID:           init.SessionID,
		Initiator:    init.Participants[0],
		Participants: init.Participants,
		Threshold:    init.Threshold,
		TotalShares:  init.TotalShares,
		Status:       DKGStatusPending,
		StartedAt:    time.Now(),
		Round:        0,
	}

	state := &localDKGState{
		Session:         session,
		MyIndex:         myIndex,
		ReceivedCommits: make(map[int][]*ecc.Element),
		ReceivedShares:  make(map[int]*ecc.Scalar),
		Accepted:        make(map[string]bool),
		Verified:        make(map[int]bool),
	}

	d.sessions[init.SessionID] = state
	d.mu.Unlock()

	slog.Info("received DKG invitation", "session_id", init.SessionID, "my_index", myIndex, "threshold", init.Threshold)

	// Auto-accept for now (in production, might want user confirmation)
	d.acceptSession(context.Background(), init.SessionID)
}

// acceptSession accepts participation in a DKG session
func (d *DistributedDKG) acceptSession(ctx context.Context, sessionID string) error {
	d.mu.RLock()
	state, exists := d.sessions[sessionID]
	d.mu.RUnlock()

	if !exists {
		return fmt.Errorf("session not found: %s", sessionID)
	}

	acceptPayload := &DKGAcceptPayload{
		SessionID: sessionID,
		Index:     state.MyIndex,
	}

	payloadBytes, err := json.Marshal(acceptPayload)
	if err != nil {
		return err
	}

	msg := &nostr.DMMessage{
		Type:    MsgTypeDKGAccept,
		Payload: payloadBytes,
	}

	// Send accept to initiator
	initiator := state.Session.Initiator
	if err := d.nostrClient.SendEphemeralDM(ctx, d.privateKey, initiator, msg); err != nil {
		return fmt.Errorf("failed to send accept: %w", err)
	}

	state.mu.Lock()
	state.Accepted[d.pubkey] = true
	state.mu.Unlock()

	slog.Info("accepted DKG session", "session_id", sessionID)
	return nil
}

// handleDKGAccept processes a DKG accept message
func (d *DistributedDKG) handleDKGAccept(senderPubkey string, payload json.RawMessage) {
	var accept DKGAcceptPayload
	if err := json.Unmarshal(payload, &accept); err != nil {
		return
	}

	d.mu.RLock()
	state, exists := d.sessions[accept.SessionID]
	d.mu.RUnlock()

	if !exists {
		return
	}

	// Verify sender is a valid participant
	valid := false
	for _, p := range state.Session.Participants {
		if p == senderPubkey {
			valid = true
			break
		}
	}
	if !valid {
		return
	}

	state.mu.Lock()
	state.Accepted[senderPubkey] = true
	acceptedCount := len(state.Accepted)
	state.mu.Unlock()

	slog.Info("participant accepted DKG", "session_id", accept.SessionID, "from", senderPubkey[:8], "accepted", acceptedCount, "total", state.Session.TotalShares)

	// If all participants have accepted, start Round 1
	if acceptedCount == state.Session.TotalShares && state.Session.Status == DKGStatusPending {
		d.startRound1(context.Background(), accept.SessionID)
	}
}

// startRound1 initiates Round 1: commitment generation and broadcast
func (d *DistributedDKG) startRound1(ctx context.Context, sessionID string) {
	d.mu.RLock()
	state, exists := d.sessions[sessionID]
	d.mu.RUnlock()

	if !exists {
		return
	}

	state.mu.Lock()
	if state.Session.Status != DKGStatusPending {
		state.mu.Unlock()
		return
	}
	state.Session.Status = DKGStatusRound1
	state.Session.Round = 1
	state.mu.Unlock()

	slog.Info("starting DKG Round 1", "session_id", sessionID)

	group := DefaultCiphersuite.Group()
	threshold := state.Session.Threshold

	// Generate random polynomial of degree threshold-1
	// f(x) = a_0 + a_1*x + ... + a_{t-1}*x^{t-1}
	polynomial := make([]*ecc.Scalar, threshold)
	commitment := make([]*ecc.Element, threshold)

	for i := 0; i < threshold; i++ {
		polynomial[i] = group.NewScalar().Random()
		commitment[i] = group.Base().Multiply(polynomial[i])
	}

	state.mu.Lock()
	state.Polynomial = polynomial
	state.Commitment = commitment
	// Store our own commitment
	state.ReceivedCommits[state.MyIndex] = commitment
	state.mu.Unlock()

	// Encode commitment
	commitBytes := encodeCommitmentList(commitment)
	commitHex := hex.EncodeToString(commitBytes)

	commitPayload := &DKGCommitPayload{
		SessionID:  sessionID,
		Index:      state.MyIndex,
		Commitment: commitHex,
	}

	payloadBytes, err := json.Marshal(commitPayload)
	if err != nil {
		slog.Error("failed to marshal commit payload", "error", err)
		return
	}

	msg := &nostr.DMMessage{
		Type:    MsgTypeDKGCommit,
		Payload: payloadBytes,
	}

	// Broadcast to all participants
	for _, participant := range state.Session.Participants {
		if participant == d.pubkey {
			continue
		}
		if err := d.nostrClient.SendEphemeralDM(ctx, d.privateKey, participant, msg); err != nil {
			slog.Warn("failed to send commitment", "to", participant[:8], "error", err)
		}
	}

	slog.Info("broadcasted Round 1 commitment", "session_id", sessionID)

	// Check if we can proceed to Round 2
	d.checkRound1Complete(ctx, sessionID)
}

// handleDKGCommit processes a commitment from another participant
func (d *DistributedDKG) handleDKGCommit(senderPubkey string, payload json.RawMessage) {
	var commit DKGCommitPayload
	if err := json.Unmarshal(payload, &commit); err != nil {
		return
	}

	d.mu.RLock()
	state, exists := d.sessions[commit.SessionID]
	d.mu.RUnlock()

	if !exists {
		return
	}

	// Verify sender matches claimed index
	if commit.Index < 1 || commit.Index > len(state.Session.Participants) {
		return
	}
	if state.Session.Participants[commit.Index-1] != senderPubkey {
		slog.Warn("commitment index mismatch", "claimed", commit.Index, "sender", senderPubkey[:8])
		return
	}

	// Decode commitment
	commitBytes, err := hex.DecodeString(commit.Commitment)
	if err != nil {
		return
	}

	group := DefaultCiphersuite.Group()
	commitList, err := decodeCommitmentList(commitBytes, group, state.Session.Threshold)
	if err != nil {
		slog.Warn("failed to decode commitment", "error", err)
		return
	}

	state.mu.Lock()
	state.ReceivedCommits[commit.Index] = commitList
	receivedCount := len(state.ReceivedCommits)
	state.mu.Unlock()

	slog.Info("received commitment", "session_id", commit.SessionID, "from_index", commit.Index, "received", receivedCount, "total", state.Session.TotalShares)

	d.checkRound1Complete(context.Background(), commit.SessionID)
}

// checkRound1Complete checks if all commitments received and starts Round 2
func (d *DistributedDKG) checkRound1Complete(ctx context.Context, sessionID string) {
	d.mu.RLock()
	state, exists := d.sessions[sessionID]
	d.mu.RUnlock()

	if !exists {
		return
	}

	state.mu.Lock()
	if len(state.ReceivedCommits) < state.Session.TotalShares || state.Session.Round != 1 {
		state.mu.Unlock()
		return
	}
	state.Session.Status = DKGStatusRound2
	state.Session.Round = 2
	state.mu.Unlock()

	slog.Info("Round 1 complete, starting Round 2", "session_id", sessionID)
	d.startRound2(ctx, sessionID)
}

// startRound2 sends encrypted shares to each participant
func (d *DistributedDKG) startRound2(ctx context.Context, sessionID string) {
	d.mu.RLock()
	state, exists := d.sessions[sessionID]
	d.mu.RUnlock()

	if !exists {
		return
	}

	group := DefaultCiphersuite.Group()

	// Evaluate our polynomial at each participant's index and send the share
	for i := 1; i <= state.Session.TotalShares; i++ {
		if i == state.MyIndex {
			// Store our own share contribution
			share := evaluatePolynomial(state.Polynomial, i, group)
			state.mu.Lock()
			if state.ReceivedShares[state.MyIndex] == nil {
				state.ReceivedShares[state.MyIndex] = share
			} else {
				state.ReceivedShares[state.MyIndex] = state.ReceivedShares[state.MyIndex].Add(share)
			}
			state.mu.Unlock()
			continue
		}

		// Evaluate polynomial at participant i's index
		share := evaluatePolynomial(state.Polynomial, i, group)
		shareBytes := share.Encode()

		// Compute public share (g^share)
		publicShare := group.Base().Multiply(share)
		publicShareBytes := publicShare.Encode()

		sharePayload := &DKGSharePayload{
			SessionID:   sessionID,
			FromIndex:   state.MyIndex,
			ToIndex:     i,
			Share:       hex.EncodeToString(shareBytes),
			PublicShare: hex.EncodeToString(publicShareBytes),
		}

		payloadBytes, err := json.Marshal(sharePayload)
		if err != nil {
			continue
		}

		msg := &nostr.DMMessage{
			Type:    MsgTypeDKGShare,
			Payload: payloadBytes,
		}

		recipient := state.Session.Participants[i-1]
		if err := d.nostrClient.SendEphemeralDM(ctx, d.privateKey, recipient, msg); err != nil {
			slog.Warn("failed to send share", "to_index", i, "error", err)
		}
	}

	slog.Info("sent Round 2 shares", "session_id", sessionID)
	d.checkRound2Complete(ctx, sessionID)
}

// handleDKGShare processes a share from another participant
func (d *DistributedDKG) handleDKGShare(senderPubkey string, payload json.RawMessage) {
	var shareMsg DKGSharePayload
	if err := json.Unmarshal(payload, &shareMsg); err != nil {
		return
	}

	d.mu.RLock()
	state, exists := d.sessions[shareMsg.SessionID]
	d.mu.RUnlock()

	if !exists {
		return
	}

	// Verify this share is for us
	if shareMsg.ToIndex != state.MyIndex {
		return
	}

	// Verify sender matches claimed from_index
	if shareMsg.FromIndex < 1 || shareMsg.FromIndex > len(state.Session.Participants) {
		return
	}
	if state.Session.Participants[shareMsg.FromIndex-1] != senderPubkey {
		return
	}

	// Decode share
	shareBytes, err := hex.DecodeString(shareMsg.Share)
	if err != nil {
		return
	}

	group := DefaultCiphersuite.Group()
	share := group.NewScalar()
	if err := share.Decode(shareBytes); err != nil {
		return
	}

	// Verify share against sender's commitment using VSS
	state.mu.Lock()
	senderCommit := state.ReceivedCommits[shareMsg.FromIndex]
	state.mu.Unlock()

	if senderCommit != nil {
		if !verifyShareAgainstCommitment(share, shareMsg.ToIndex, senderCommit, group) {
			slog.Warn("share verification failed", "from_index", shareMsg.FromIndex, "session_id", shareMsg.SessionID)
			// TODO: Report verification failure and possibly abort
			return
		}
	}

	// Aggregate share
	state.mu.Lock()
	if state.ReceivedShares[shareMsg.FromIndex] != nil {
		// Already have this share
		state.mu.Unlock()
		return
	}
	state.ReceivedShares[shareMsg.FromIndex] = share
	receivedCount := len(state.ReceivedShares)
	state.mu.Unlock()

	slog.Info("received share", "session_id", shareMsg.SessionID, "from_index", shareMsg.FromIndex, "received", receivedCount, "total", state.Session.TotalShares)

	d.checkRound2Complete(context.Background(), shareMsg.SessionID)
}

// checkRound2Complete checks if all shares received and finalizes
func (d *DistributedDKG) checkRound2Complete(ctx context.Context, sessionID string) {
	d.mu.RLock()
	state, exists := d.sessions[sessionID]
	d.mu.RUnlock()

	if !exists {
		return
	}

	state.mu.Lock()
	if len(state.ReceivedShares) < state.Session.TotalShares || state.Session.Round != 2 {
		state.mu.Unlock()
		return
	}

	// Aggregate all received shares into our final share
	group := DefaultCiphersuite.Group()
	myShare := group.NewScalar()
	for _, share := range state.ReceivedShares {
		myShare = myShare.Add(share)
	}
	state.MyShare = myShare

	// Compute group public key from commitments
	// GroupPubKey = sum of all a_0 commitments (first element of each commitment)
	groupPubKey := group.NewElement().Identity()
	for _, commit := range state.ReceivedCommits {
		if len(commit) > 0 {
			groupPubKey = groupPubKey.Add(commit[0])
		}
	}

	state.Session.Status = DKGStatusRound3
	state.Session.Round = 3
	state.mu.Unlock()

	slog.Info("Round 2 complete, verifying", "session_id", sessionID)

	// Verify and complete
	d.finalizeDKG(ctx, sessionID, myShare, groupPubKey)
}

// finalizeDKG completes the DKG and stores the resulting key share
func (d *DistributedDKG) finalizeDKG(ctx context.Context, sessionID string, myShare *ecc.Scalar, groupPubKey *ecc.Element) {
	d.mu.RLock()
	state, exists := d.sessions[sessionID]
	d.mu.RUnlock()

	if !exists {
		return
	}

	group := DefaultCiphersuite.Group()

	// Create FROST key share using library function
	groupPubKeyBytes := groupPubKey.Encode()
	myShareBytes := myShare.Encode()

	// Compute our public key share
	myPubKey := group.Base().Multiply(myShare)
	myPubKeyBytes := myPubKey.Encode()

	// Build verification shares from commitments
	// For each participant, their public key share is computed from the commitments
	allPublicKeys := make([]*ecc.Element, state.Session.TotalShares)
	for i := 1; i <= state.Session.TotalShares; i++ {
		pubKey := group.NewElement().Identity()
		for j, commit := range state.ReceivedCommits {
			// Compute the contribution from participant j to participant i's public key
			contribution := computePublicShareContribution(i, commit, group)
			if j == 1 { // First participant's contribution
				pubKey = contribution
			} else {
				pubKey = pubKey.Add(contribution)
			}
		}
		allPublicKeys[i-1] = pubKey
	}

	verificationSharesData, err := encodeVerificationShares(allPublicKeys, group)
	if err != nil {
		slog.Error("failed to encode verification shares", "error", err)
		return
	}

	// Create FROST key record
	frostKeyID := generateID()
	groupPubkeyHex := pubkeyToHex(groupPubKeyBytes)

	frostKey := &FrostKey{
		ID:                 frostKeyID,
		Name:               fmt.Sprintf("DKG-%s", sessionID[:8]),
		Pubkey:             groupPubkeyHex,
		Threshold:          state.Session.Threshold,
		TotalShares:        state.Session.TotalShares,
		GroupPublicKey:     groupPubKeyBytes,
		VerificationShares: verificationSharesData,
		CreatedAt:          time.Now(),
	}

	// Store FROST key
	if err := d.storage.CreateFrostKey(ctx, frostKey); err != nil {
		slog.Error("failed to store FROST key", "error", err)
		return
	}

	// Encrypt and store our share
	var encryptedShare []byte
	if d.encryptor != nil {
		var err error
		encryptedShare, err = d.encryptor.Encrypt(myShareBytes)
		if err != nil {
			slog.Error("failed to encrypt share", "error", err)
			return
		}
	} else {
		encryptedShare = myShareBytes
	}

	// Build key share in library format for storage
	keyShareData := buildKeyShareData(uint16(state.MyIndex), myShareBytes, myPubKeyBytes, groupPubKeyBytes, group)

	// Re-encrypt the proper key share format
	if d.encryptor != nil {
		var err error
		encryptedShare, err = d.encryptor.Encrypt(keyShareData)
		if err != nil {
			slog.Error("failed to encrypt key share", "error", err)
			return
		}
	} else {
		encryptedShare = keyShareData
	}

	frostShare := &FrostShare{
		ID:             generateID(),
		FrostKeyID:     frostKeyID,
		ShareIndex:     state.MyIndex,
		EncryptedShare: encryptedShare,
		IsLocal:        true,
		PublicShare:    myPubKeyBytes,
		CreatedAt:      time.Now(),
	}

	if err := d.storage.CreateFrostShare(ctx, frostShare); err != nil {
		slog.Error("failed to store FROST share", "error", err)
		return
	}

	// Update session state
	now := time.Now()
	state.mu.Lock()
	state.Session.Status = DKGStatusComplete
	state.Session.CompletedAt = &now
	state.Session.FrostKeyID = frostKeyID
	state.Session.GroupPubkey = groupPubkeyHex
	state.mu.Unlock()

	slog.Info("DKG complete", "session_id", sessionID, "frost_key_id", frostKeyID, "group_pubkey", groupPubkeyHex[:16]+"...")

	// Send completion message
	completePayload := &DKGCompletePayload{
		SessionID:   sessionID,
		Index:       state.MyIndex,
		GroupPubkey: groupPubkeyHex,
	}

	payloadBytes, _ := json.Marshal(completePayload)
	msg := &nostr.DMMessage{
		Type:    MsgTypeDKGComplete,
		Payload: payloadBytes,
	}

	for _, participant := range state.Session.Participants {
		if participant == d.pubkey {
			continue
		}
		d.nostrClient.SendEphemeralDM(ctx, d.privateKey, participant, msg)
	}

	// Notify callback
	if d.onSessionComplete != nil {
		d.onSessionComplete(sessionID, frostKeyID, groupPubkeyHex)
	}
}

// handleDKGVerify processes verification result (currently unused as we verify inline)
func (d *DistributedDKG) handleDKGVerify(senderPubkey string, payload json.RawMessage) {
	// Verification is done inline during share processing
	slog.Debug("received verify message", "from", senderPubkey[:8])
}

// handleDKGComplete processes completion notification
func (d *DistributedDKG) handleDKGComplete(senderPubkey string, payload json.RawMessage) {
	var complete DKGCompletePayload
	if err := json.Unmarshal(payload, &complete); err != nil {
		return
	}

	d.mu.RLock()
	state, exists := d.sessions[complete.SessionID]
	d.mu.RUnlock()

	if !exists {
		return
	}

	slog.Info("received DKG completion", "session_id", complete.SessionID, "from_index", complete.Index, "group_pubkey", complete.GroupPubkey[:16]+"...")

	// Verify group pubkey matches ours
	state.mu.Lock()
	if state.Session.GroupPubkey != "" && state.Session.GroupPubkey != complete.GroupPubkey {
		slog.Warn("group pubkey mismatch", "ours", state.Session.GroupPubkey[:16], "theirs", complete.GroupPubkey[:16])
	}
	state.mu.Unlock()
}

// handleDKGAbort processes abort notification
func (d *DistributedDKG) handleDKGAbort(senderPubkey string, payload json.RawMessage) {
	var abort DKGAbortPayload
	if err := json.Unmarshal(payload, &abort); err != nil {
		return
	}

	d.mu.Lock()
	state, exists := d.sessions[abort.SessionID]
	if exists {
		state.Session.Status = DKGStatusAborted
		state.Session.Error = abort.Reason
	}
	d.mu.Unlock()

	slog.Warn("DKG aborted", "session_id", abort.SessionID, "reason", abort.Reason)

	if d.onSessionFailed != nil && exists {
		d.onSessionFailed(abort.SessionID, abort.Reason)
	}
}

// GetSession returns the current state of a DKG session
func (d *DistributedDKG) GetSession(sessionID string) *DKGSession {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if state, exists := d.sessions[sessionID]; exists {
		return state.Session
	}
	return nil
}

// ListSessions returns all known DKG sessions
func (d *DistributedDKG) ListSessions() []*DKGSession {
	d.mu.RLock()
	defer d.mu.RUnlock()

	sessions := make([]*DKGSession, 0, len(d.sessions))
	for _, state := range d.sessions {
		sessions = append(sessions, state.Session)
	}
	return sessions
}

// Helper functions

func getPublicKeyFromPrivate(privateKeyHex string) (string, error) {
	privBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", err
	}
	if len(privBytes) != 32 {
		return "", fmt.Errorf("invalid private key length")
	}

	group := DefaultCiphersuite.Group()
	priv := group.NewScalar()
	if err := priv.Decode(privBytes); err != nil {
		return "", err
	}

	pub := group.Base().Multiply(priv)
	pubBytes := pub.Encode()
	return pubkeyToHex(pubBytes), nil
}

func evaluatePolynomial(coeffs []*ecc.Scalar, x int, group ecc.Group) *ecc.Scalar {
	// f(x) = a_0 + a_1*x + a_2*x^2 + ...
	result := group.NewScalar()
	xScalar := group.NewScalar()
	xBytes := make([]byte, 32)
	xBytes[31] = byte(x)
	xScalar.Decode(xBytes)

	xPower := group.NewScalar()
	oneBytes := make([]byte, 32)
	oneBytes[31] = 1
	xPower.Decode(oneBytes)

	for _, coeff := range coeffs {
		term := coeff.Copy().Multiply(xPower)
		result = result.Add(term)
		xPower = xPower.Multiply(xScalar)
	}

	return result
}

func verifyShareAgainstCommitment(share *ecc.Scalar, index int, commitment []*ecc.Element, group ecc.Group) bool {
	// Verify: g^share = prod(C_j^(i^j)) for j = 0..t-1
	// Where C_j is the j-th commitment element

	// Compute g^share
	expected := group.Base().Multiply(share)

	// Compute product of C_j^(i^j)
	computed := group.NewElement().Identity()

	xScalar := group.NewScalar()
	xBytes := make([]byte, 32)
	xBytes[31] = byte(index)
	xScalar.Decode(xBytes)

	xPower := group.NewScalar()
	oneBytes := make([]byte, 32)
	oneBytes[31] = 1
	xPower.Decode(oneBytes)

	for _, C := range commitment {
		term := C.Copy().Multiply(xPower)
		computed = computed.Add(term)
		xPower = xPower.Multiply(xScalar)
	}

	return expected.Equal(computed)
}

func computePublicShareContribution(index int, commitment []*ecc.Element, group ecc.Group) *ecc.Element {
	// Compute sum(C_j * i^j) for a participant's public key contribution
	result := group.NewElement().Identity()

	xScalar := group.NewScalar()
	xBytes := make([]byte, 32)
	xBytes[31] = byte(index)
	xScalar.Decode(xBytes)

	xPower := group.NewScalar()
	oneBytes := make([]byte, 32)
	oneBytes[31] = 1
	xPower.Decode(oneBytes)

	for _, C := range commitment {
		term := C.Copy().Multiply(xPower)
		result = result.Add(term)
		xPower = xPower.Multiply(xScalar)
	}

	return result
}

func encodeCommitmentList(commitments []*ecc.Element) []byte {
	if len(commitments) == 0 {
		return nil
	}
	elemLen := len(commitments[0].Encode())
	result := make([]byte, len(commitments)*elemLen)
	for i, c := range commitments {
		copy(result[i*elemLen:(i+1)*elemLen], c.Encode())
	}
	return result
}

func decodeCommitmentList(data []byte, group ecc.Group, count int) ([]*ecc.Element, error) {
	elemLen := group.ElementLength()
	if len(data) != count*elemLen {
		return nil, fmt.Errorf("invalid commitment data length")
	}

	result := make([]*ecc.Element, count)
	for i := 0; i < count; i++ {
		elem := group.NewElement()
		if err := elem.Decode(data[i*elemLen : (i+1)*elemLen]); err != nil {
			return nil, err
		}
		result[i] = elem
	}
	return result, nil
}

func buildKeyShareData(index uint16, secretShare, publicKey, groupPublicKey []byte, group ecc.Group) []byte {
	// Build a key share that can be decoded by the frost library
	// Use the frost library's NewKeyShare function via the debug package

	// For now, use a simple format that our coordinator can decode
	// Format: [index(2)] [secret(32)] [public(33)]
	result := make([]byte, 2+len(secretShare)+len(publicKey))
	result[0] = byte(index >> 8)
	result[1] = byte(index)
	copy(result[2:], secretShare)
	copy(result[2+len(secretShare):], publicKey)
	return result
}
