package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/auth"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/crypto"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/seal"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// "Stay signed in": at sign-in the user picks how long their unlocked key should
// outlive a signer restart. For anything but "this session only", the decrypted key
// is sealed (internal/seal) and stored with its expiry. Every replica restores every
// live seal it can open, at start and then every sealReconcileInterval, so the key
// is subscribed on the relays again after a deploy and outside NIP-46 apps keep
// working with no client involvement. Expiry and revocation are enforced the same
// way: a replica drops a key whose seal is gone, expired, or whose sign-in session
// has ended.
//
// A replica restores a key only from a seal; it never hands keys to another replica.

// sealReconcileInterval bounds how long an expired or revoked seal's key can stay
// usable on a replica that didn't handle the revocation itself.
const sealReconcileInterval = 15 * time.Second

// lazyRestoreBackoff stops a burst of requests for a locked key from each hitting
// the database.
const lazyRestoreBackoff = 5 * time.Second

// Stay-signed-in choices, in the order the UI offers them.
const (
	stayChoiceSession      = "session"
	stayChoiceDay          = "1d"
	stayChoiceMonth        = "30d"
	stayChoiceUntilSignOut = "until_signout"
)

var stayChoices = []string{stayChoiceSession, stayChoiceDay, stayChoiceMonth, stayChoiceUntilSignOut}

func validStayChoice(c string) bool {
	if c == "" {
		return true
	}
	for _, v := range stayChoices {
		if c == v {
			return true
		}
	}
	return false
}

// staySignedIn is the per-replica state. A nil *staySignedIn on the Handler means
// the feature is not wired (tests that build a bare Handler).
type staySignedIn struct {
	sealer  seal.Sealer
	rotator sealRotator // vault mode only (stay_signed_in_rotation.go)

	mu        sync.Mutex
	leases    map[string]sealLease // pubkey -> why this replica holds it
	missUntil map[string]time.Time // pubkey -> no lazy restore before this
}

// sealLease records that this replica holds a key because of a seal (made here at
// sign-in, or restored). Leased keys are dropped when no live seal remains.
type sealLease struct {
	userID string
	at     time.Time // when this replica (re)acquired it
}

// SetSealer turns stay-signed-in on with the given sealer (seal.None{} offers only
// split sealing, if enabled). Call before serving.
func (h *Handler) SetSealer(s seal.Sealer) {
	if s == nil {
		s = seal.None{}
	}
	h.stay = &staySignedIn{sealer: s, leases: map[string]sealLease{}, missUntil: map[string]time.Time{}}
	if h.signer != nil {
		h.signer.SetKeyRestorer(h.restoreSealedKey)
	}
}

// stayGrant is what a sign-in was granted. The sign-in session, its token and its
// seals all share expiresAt.
type stayGrant struct {
	choice    string
	mode      string
	expiresAt time.Time
	sliding   bool   // until_signout: renewed on use, up to the idle cap
	half      []byte // split mode only
}

func (h *Handler) now() time.Time {
	if h.stayNow != nil {
		return h.stayNow()
	}
	return time.Now()
}

// StaySignedInGrant is returned in the login response.
type StaySignedInGrant struct {
	Granted   string     `json:"granted"`              // session, 1d, 30d, until_signout
	Mode      string     `json:"mode,omitempty"`       // vault, keyfile or split; empty for session
	ExpiresAt *time.Time `json:"expires_at,omitempty"` // when the key locks again
	// SplitHalf is the browser half (base64url, 32 bytes) for split mode. The
	// server does not keep it. Store it for this sign-in and hand it back to
	// POST /api/v1/users/session/unseal when the session reports key_locked.
	SplitHalf string `json:"split_half,omitempty"`
}

// grantStaySignedIn decides what a sign-in gets. A granted choice also sets the
// sign-in session's lifetime: 1d and 30d are fixed; until_signout slides (renewed
// on use, ends after SESSION_IDLE_DAYS idle). SESSION_SEAL_MAX_DAYS caps all of
// them. Session-only (nil grant) keeps the default sign-in lifetime.
func (h *Handler) grantStaySignedIn(choice string, split bool) (*stayGrant, *StaySignedInGrant) {
	if choice == "" {
		return nil, nil
	}
	sessionOnly := &StaySignedInGrant{Granted: stayChoiceSession}
	if choice == stayChoiceSession || h.stay == nil {
		return nil, sessionOnly
	}
	g := &stayGrant{choice: choice}
	now := h.now()
	switch {
	case split && h.config.StaySignedIn.Split:
		half, err := seal.NewSplitHalf()
		if err != nil {
			slog.Error("stay signed in: cannot make a split half; granting session only", "error", err)
			return nil, sessionOnly
		}
		g.mode, g.half = seal.ModeSplit, half
	case !split && h.stay.sealer.Enabled():
		g.mode = h.stay.sealer.Mode()
	default:
		return nil, sessionOnly
	}

	var exp time.Time
	switch choice {
	case stayChoiceDay:
		exp = now.Add(24 * time.Hour)
	case stayChoiceMonth:
		exp = now.Add(30 * 24 * time.Hour)
	case stayChoiceUntilSignOut:
		exp, g.sliding = now.Add(h.idleWindow()), true
	}
	g.expiresAt = h.capAtMaxDays(now, exp).Truncate(time.Second)

	resp := &StaySignedInGrant{Granted: choice, Mode: g.mode, ExpiresAt: &g.expiresAt}
	if g.half != nil {
		resp.SplitHalf = base64.RawURLEncoding.EncodeToString(g.half)
	}
	return g, resp
}

// sealSessionKeys seals every user-held key of userID that this replica now holds,
// bound to the sign-in session. Called at the end of the login unlock.
func (h *Handler) sealSessionKeys(ctx context.Context, userID, sessionID string, g *stayGrant) {
	if g == nil || h.stay == nil {
		return
	}
	keys, err := h.storage.ListKeys(ctx, userID)
	if err != nil {
		slog.Error("stay signed in: list keys", "user_id", userID, "error", err)
		return
	}
	sealed := 0
	for _, key := range keys {
		if !crypto.DetectEncryptionMethod(key.EncryptedNsec).UserHeld() {
			continue // server-held keys are loaded at start anyway
		}
		priv, ok := h.signer.LoadedPrivateKey(key.Pubkey)
		if !ok {
			continue
		}
		b := seal.Binding{Pubkey: key.Pubkey, SessionID: sessionID}
		var blob []byte
		if g.mode == seal.ModeSplit {
			blob, err = seal.SplitSeal([]byte(priv), g.half, b)
		} else {
			blob, err = h.stay.sealer.Seal(ctx, []byte(priv), b)
		}
		if err != nil {
			slog.Error("stay signed in: seal failed; this key will need a sign-in after a restart",
				"user_id", userID, "pubkey", shortPK(key.Pubkey), "mode", g.mode, "error", err)
			continue
		}
		row := &storage.SessionSeal{
			ID: newSealID(), UserID: userID, KeyID: key.ID, Pubkey: key.Pubkey, SessionID: sessionID,
			Mode: g.mode, Sealed: blob, ExpiresAt: g.expiresAt, CreatedAt: time.Now(), Sliding: g.sliding,
		}
		if err := h.storage.UpsertSessionSeal(ctx, row); err != nil {
			slog.Error("stay signed in: store seal", "user_id", userID, "pubkey", shortPK(key.Pubkey), "error", err)
			continue
		}
		h.stay.lease(key.Pubkey, userID)
		sealed++
	}
	if sealed > 0 {
		slog.Info("stay signed in: sealed keys", "user_id", userID, "count", sealed,
			"mode", g.mode, "choice", g.choice, "expires_at", g.expiresAt.UTC().Format(time.RFC3339))
	}
}

func (s *staySignedIn) lease(pubkey, userID string) {
	s.mu.Lock()
	s.leases[pubkey] = sealLease{userID: userID, at: time.Now()}
	delete(s.missUntil, pubkey)
	s.mu.Unlock()
}

// liveSeals lists seals whose sign-in session is still live, grouped by pubkey.
// unsure holds pubkeys whose session could not be checked (session store error):
// they are neither restored nor dropped this pass.
func (h *Handler) liveSeals(ctx context.Context) (live map[string][]*storage.SessionSeal, unsure map[string]bool, err error) {
	rows, err := h.storage.ListLiveSessionSeals(ctx)
	if err != nil {
		return nil, nil, err
	}
	live, unsure = map[string][]*storage.SessionSeal{}, map[string]bool{}
	sessionLive := map[string]*bool{}
	for _, sl := range rows {
		ok, seen := sessionLive[sl.SessionID]
		if !seen {
			_, gerr := h.storage.GetUserSession(ctx, sl.SessionID)
			switch {
			case gerr == nil:
				v := true
				ok = &v
			case errors.Is(gerr, storage.ErrSessionNotFound):
				v := false
				ok = &v
				if _, derr := h.storage.DeleteSessionSealsBySession(ctx, sl.SessionID); derr != nil {
					slog.Warn("stay signed in: delete seals of an ended session", "error", derr)
				}
			default:
				slog.Warn("stay signed in: session check failed; leaving this seal for the next pass", "error", gerr)
			}
			sessionLive[sl.SessionID] = ok
		}
		switch {
		case ok == nil:
			unsure[sl.Pubkey] = true
		case *ok:
			live[sl.Pubkey] = append(live[sl.Pubkey], sl)
		}
	}
	return live, unsure, nil
}

// reconcileSeals is one pass: drop keys whose seals are gone, restore keys with a
// live seal this replica can open, and sweep expired rows.
func (h *Handler) reconcileSeals(ctx context.Context) {
	if h.stay == nil {
		return
	}
	passStart := time.Now()
	live, unsure, err := h.liveSeals(ctx)
	if err != nil {
		slog.Warn("stay signed in: list seals failed; holding current state", "error", err)
		return
	}

	h.stay.mu.Lock()
	var drop []string
	for pk, l := range h.stay.leases {
		// A lease taken after this pass read the table (a sign-in that just
		// sealed) is newer than what we saw: leave it for the next pass.
		if len(live[pk]) == 0 && !unsure[pk] && l.at.Before(passStart) {
			drop = append(drop, pk)
		}
	}
	h.stay.mu.Unlock()
	for _, pk := range drop {
		h.lockSealedKeyIfStale(ctx, pk, passStart, "seal expired or revoked")
	}

	restored := 0
	for pk, seals := range live {
		if h.signer.IsKeyLoaded(pk) {
			continue
		}
		if h.restoreFromSeals(ctx, pk, seals) {
			restored++
		}
	}
	if restored > 0 {
		h.publishLoadedKeys(ctx)
	}
	if n, err := h.storage.DeleteExpiredSessionSeals(ctx); err == nil && n > 0 {
		slog.Info("stay signed in: swept expired seals", "count", n)
	}
}

// restoreFromSeals opens the first seal of pubkey this replica can open and
// installs the key. Split seals need the browser half and are skipped.
func (h *Handler) restoreFromSeals(ctx context.Context, pubkey string, seals []*storage.SessionSeal) bool {
	for _, sl := range seals {
		if sl.Mode == seal.ModeSplit {
			continue
		}
		if sl.Mode != h.stay.sealer.Mode() {
			slog.Warn("stay signed in: seal made in another mode; cannot open it here",
				"pubkey", shortPK(pubkey), "seal_mode", sl.Mode, "sealer", h.stay.sealer.Mode())
			continue
		}
		pt, err := h.stay.sealer.Open(ctx, sl.Sealed, seal.Binding{Pubkey: sl.Pubkey, SessionID: sl.SessionID})
		if err != nil {
			slog.Warn("stay signed in: seal did not open", "pubkey", shortPK(pubkey), "seal_id", sl.ID, "error", err)
			continue
		}
		if h.installSealedKey(ctx, sl, string(pt)) {
			slog.Info("stay signed in: restored key from seal", "user_id", sl.UserID, "pubkey", shortPK(pubkey), "mode", sl.Mode)
			return true
		}
	}
	return false
}

// installSealedKey checks the opened key really is pubkey's and registers it.
func (h *Handler) installSealedKey(ctx context.Context, sl *storage.SessionSeal, priv string) bool {
	if pub, err := nostr.GetPublicKey(priv); err != nil || pub != sl.Pubkey {
		slog.Error("stay signed in: opened seal does not match its pubkey; refusing it", "seal_id", sl.ID, "pubkey", shortPK(sl.Pubkey))
		return false
	}
	key, err := h.storage.GetKeyByPubkey(ctx, sl.Pubkey)
	if err != nil {
		return false
	}
	if key.IsProxy() {
		h.signer.RegisterProxyKey(key.Pubkey, priv, key.BunkerURI)
	} else {
		h.signer.RegisterKey(key.Pubkey, priv)
	}
	h.stay.lease(sl.Pubkey, sl.UserID)
	return true
}

// restoreSealedKey is the lazy path: a request needs a locked key now. Installed
// as the signer's KeyRestorer and called from ensureNostrConnectKeyLoaded.
func (h *Handler) restoreSealedKey(ctx context.Context, pubkey string) bool {
	if h.stay == nil {
		return false
	}
	h.stay.mu.Lock()
	until, backoff := h.stay.missUntil[pubkey]
	h.stay.mu.Unlock()
	if backoff && time.Now().Before(until) {
		return false
	}
	live, _, err := h.liveSeals(ctx)
	if err == nil && h.restoreFromSeals(ctx, pubkey, live[pubkey]) {
		h.publishLoadedKeys(ctx)
		return true
	}
	h.stay.mu.Lock()
	h.stay.missUntil[pubkey] = time.Now().Add(lazyRestoreBackoff)
	h.stay.mu.Unlock()
	return false
}

// lockSealedKeyIfStale is lockSealedKey for the reconcile pass: it re-checks under
// the lock that the lease wasn't renewed since the pass began.
// The check and the delete happen under one lock hold, so a lease renewed in
// between is never dropped.
func (h *Handler) lockSealedKeyIfStale(ctx context.Context, pubkey string, passStart time.Time, why string) {
	h.stay.mu.Lock()
	l, ok := h.stay.leases[pubkey]
	if !ok || !l.at.Before(passStart) {
		h.stay.mu.Unlock()
		return
	}
	delete(h.stay.leases, pubkey)
	h.stay.mu.Unlock()
	h.unloadSealedKey(ctx, pubkey, l.userID, why)
}

func (h *Handler) lockSealedKey(ctx context.Context, pubkey, why string) {
	h.stay.mu.Lock()
	l := h.stay.leases[pubkey]
	delete(h.stay.leases, pubkey)
	h.stay.mu.Unlock()
	h.unloadSealedKey(ctx, pubkey, l.userID, why)
}

func (h *Handler) unloadSealedKey(ctx context.Context, pubkey, userID, why string) {
	if h.signer.IsKeyLoaded(pubkey) {
		h.signer.UnregisterKey(pubkey)
		h.forgetKeyLocation(ctx, pubkey)
		slog.Info("stay signed in: key locked", "user_id", userID, "pubkey", shortPK(pubkey), "reason", why)
	}
}

// revokeUserSeals deletes every seal of userID and locks those keys here and on
// the replica the location registry names; other replicas follow within
// sealReconcileInterval. Returns how many seals were deleted.
func (h *Handler) revokeUserSeals(ctx context.Context, userID, why string) int {
	if h.stay == nil {
		return 0
	}
	seals, _ := h.storage.ListSessionSealsByUser(ctx, userID)
	n, err := h.storage.DeleteSessionSealsByUser(ctx, userID)
	if err != nil {
		slog.Error("stay signed in: revoke seals", "user_id", userID, "error", err)
	}
	pks := map[string]bool{}
	for _, sl := range seals {
		pks[sl.Pubkey] = true
	}
	h.stay.mu.Lock()
	for pk, l := range h.stay.leases {
		if l.userID == userID {
			pks[pk] = true
		}
	}
	h.stay.mu.Unlock()
	var list []string
	for pk := range pks {
		h.lockSealedKey(ctx, pk, why)
		list = append(list, pk)
	}
	if h.forward != nil && len(list) > 0 {
		h.forward.evictRemote(ctx, list)
	}
	if n > 0 {
		slog.Info("stay signed in: seals revoked", "user_id", userID, "count", n, "reason", why)
	}
	return n
}

// RunStaySignedIn restores sealed keys now and keeps reconciling until ctx ends.
func (h *Handler) RunStaySignedIn(ctx context.Context) {
	if h.stay == nil {
		return
	}
	h.reconcileSeals(ctx)
	t := time.NewTicker(sealReconcileInterval)
	defer t.Stop()
	rot := time.NewTicker(sealRotationInterval)
	defer rot.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			h.reconcileSeals(ctx)
		case <-rot.C:
			if err := h.rotateVaultSeals(ctx); err != nil {
				slog.Warn("stay signed in: seal rotation pass failed", "error", err)
			}
		}
	}
}

// ---- HTTP ----

// StaySignedInOptions tells the sign-in UI what to offer.
type StaySignedInOptions struct {
	Sealer       string   `json:"sealer"`                  // vault, keyfile or none
	Choices      []string `json:"choices"`                 // without split; ["session"] when the sealer is none
	Split        bool     `json:"split"`                   // split (browser-held half) available
	SplitChoices []string `json:"split_choices,omitempty"` // choices with split
	MaxDays      int      `json:"max_days,omitempty"`      // server cap; 0 = up to the session's own expiry
}

// GET /api/v1/users/stay-signed-in/options (no auth: the sign-in form needs it).
func (h *Handler) handleStaySignedInOptions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	o := StaySignedInOptions{Sealer: seal.ModeNone, Choices: []string{stayChoiceSession}, MaxDays: h.config.StaySignedIn.MaxDays}
	if h.stay != nil {
		o.Sealer = h.stay.sealer.Mode()
		if h.stay.sealer.Enabled() {
			o.Choices = stayChoices
		}
		if h.config.StaySignedIn.Split {
			o.Split, o.SplitChoices = true, stayChoices
		}
	}
	h.jsonResponse(w, http.StatusOK, o)
}

// StaySignedInEntry is one active seal, as listed to its owner.
type StaySignedInEntry struct {
	ID        string    `json:"id"`
	Pubkey    string    `json:"pubkey"`
	Mode      string    `json:"mode"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	Current   bool      `json:"current"` // made by the session asking
}

// GET    /api/v1/users/stay-signed-in  lists the caller's active seals.
// DELETE /api/v1/users/stay-signed-in  revokes all of them (keeps the web sign-in).
func (h *Handler) handleStaySignedIn(w http.ResponseWriter, r *http.Request) {
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	switch r.Method {
	case http.MethodGet:
		seals, err := h.storage.ListSessionSealsByUser(r.Context(), claims.UserID)
		if err != nil {
			h.errorResponse(w, http.StatusInternalServerError, "failed to list")
			return
		}
		out := make([]StaySignedInEntry, 0, len(seals))
		for _, sl := range seals {
			out = append(out, StaySignedInEntry{ID: sl.ID, Pubkey: sl.Pubkey, Mode: sl.Mode,
				ExpiresAt: sl.ExpiresAt, CreatedAt: sl.CreatedAt, Current: sl.SessionID == claims.SessionID})
		}
		h.jsonResponse(w, http.StatusOK, out)
	case http.MethodDelete:
		n := h.revokeUserSeals(r.Context(), claims.UserID, "revoked by user")
		http.SetCookie(w, clearSplitHalfCookie())
		h.jsonResponse(w, http.StatusOK, map[string]int{"revoked": n})
	default:
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// POST /api/v1/users/session/unseal  {"split_half": "<base64url>"}
//
// Split mode: restores the caller's session's split-sealed keys on this replica.
// 200 {"restored": n}; 400 bad half; 404 no_split_seal (nothing to restore for this
// session: sign in again); 403 seal_mismatch (wrong half).
func (h *Handler) handleSessionUnseal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	// The half comes from the body (non-browser clients) or, for browsers, from
	// the HttpOnly cookie set at sign-in; the body may then be empty.
	var body struct {
		SplitHalf string `json:"split_half"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.SplitHalf == "" {
		c, cerr := r.Cookie(splitHalfCookieName)
		if cerr != nil || c.Value == "" {
			h.errorResponseCode(w, http.StatusNotFound, "no_split_seal", "no browser half for this session; sign in again")
			return
		}
		body.SplitHalf = c.Value
	}
	half, err := base64.RawURLEncoding.DecodeString(body.SplitHalf)
	if err != nil {
		half, err = base64.URLEncoding.DecodeString(body.SplitHalf)
	}
	if err != nil || len(half) != seal.SplitHalfLen {
		h.errorResponseCode(w, http.StatusBadRequest, "bad_split_half", "split_half must be 32 bytes, base64url")
		return
	}
	if h.stay == nil || claims.SessionID == "" {
		h.errorResponseCode(w, http.StatusNotFound, "no_split_seal", "nothing to unseal for this session; sign in again")
		return
	}
	seals, err := h.storage.ListSessionSealsBySession(r.Context(), claims.SessionID)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to read seals")
		return
	}
	found, restored := 0, 0
	for _, sl := range seals {
		if sl.Mode != seal.ModeSplit || sl.UserID != claims.UserID {
			continue
		}
		found++
		// Always verify the half, even if the key is already loaded here: a
		// 200 must mean "this half opens this session's seal".
		pt, err := seal.SplitOpen(sl.Sealed, half, seal.Binding{Pubkey: sl.Pubkey, SessionID: sl.SessionID})
		if err != nil {
			continue
		}
		if h.signer.IsKeyLoaded(sl.Pubkey) {
			h.stay.lease(sl.Pubkey, sl.UserID)
			restored++
			continue
		}
		if h.installSealedKey(r.Context(), sl, string(pt)) {
			restored++
		}
	}
	switch {
	case found == 0:
		h.errorResponseCode(w, http.StatusNotFound, "no_split_seal", "nothing to unseal for this session; sign in again")
	case restored == 0:
		slog.Warn("stay signed in: split unseal refused (wrong half)", "user_id", claims.UserID)
		h.errorResponseCode(w, http.StatusForbidden, "seal_mismatch", "that browser half does not open this session's seal")
	default:
		h.publishLoadedKeys(r.Context())
		slog.Info("stay signed in: restored keys with the browser half", "user_id", claims.UserID, "count", restored)
		h.jsonResponse(w, http.StatusOK, map[string]int{"restored": restored})
	}
}

func newSealID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func shortPK(pk string) string {
	if len(pk) > 16 {
		return pk[:16] + "..."
	}
	return pk
}

// ---- Sliding sessions ("until I sign out") ----

// slideRenewEvery throttles renewal writes: a session is extended only once its
// expiry has fallen this far behind now + idle window.
const slideRenewEvery = time.Hour

func (h *Handler) idleWindow() time.Duration {
	d := h.config.StaySignedIn.IdleDays
	if d < 1 {
		d = 90
	}
	return time.Duration(d) * 24 * time.Hour
}

// capAtMaxDays applies the operator ceiling, counted from the sign-in.
func (h *Handler) capAtMaxDays(signedInAt, exp time.Time) time.Time {
	if max := h.config.StaySignedIn.MaxDays; max > 0 {
		if ceiling := signedInAt.Add(time.Duration(max) * 24 * time.Hour); exp.After(ceiling) {
			return ceiling
		}
	}
	return exp
}

// slideSession renews an "until I sign out" session: its expiry, its seals'
// expiry and a fresh token all move to now + idle window (capped by max days).
// Returns ok=false for sessions that don't slide. With force, a token is issued
// even when the renewal itself is throttled (the explicit refresh call).
func (h *Handler) slideSession(ctx context.Context, claims *auth.JWTClaims, force bool) (token string, exp time.Time, ok bool) {
	if h.stay == nil || claims == nil || claims.SessionID == "" {
		return "", time.Time{}, false
	}
	seals, err := h.storage.ListSessionSealsBySession(ctx, claims.SessionID)
	if err != nil {
		return "", time.Time{}, false
	}
	sliding := false
	for _, sl := range seals {
		sliding = sliding || sl.Sliding
	}
	if !sliding {
		return "", time.Time{}, false
	}
	sess, err := h.storage.GetUserSession(ctx, claims.SessionID)
	if err != nil {
		return "", time.Time{}, false
	}
	exp = sess.ExpiresAt
	next := h.capAtMaxDays(sess.CreatedAt, h.now().Add(h.idleWindow())).Truncate(time.Second)
	if next.Sub(sess.ExpiresAt) >= slideRenewEvery {
		if err := h.storage.ExtendUserSession(ctx, sess.ID, next); err != nil {
			slog.Warn("stay signed in: session renewal failed", "error", err)
			return "", time.Time{}, false
		}
		if _, err := h.storage.ExtendSessionSeals(ctx, sess.ID, next); err != nil {
			slog.Warn("stay signed in: seal renewal failed", "error", err)
		}
		exp = next
	} else if !force {
		return "", time.Time{}, false
	}
	token, exp, err = auth.GenerateJWTWithSessionUntil(h.authConfig, claims.UserID, claims.Username, sess.ID, exp)
	if err != nil {
		return "", time.Time{}, false
	}
	return token, exp, true
}

// POST /api/v1/users/session/refresh -> {"token","expires_at"} for an "until I sign
// out" session (renewing it); 409 not_sliding for any other session.
func (h *Handler) handleSessionRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	tok, exp, ok := h.slideSession(r.Context(), claims, true)
	if !ok {
		h.errorResponseCode(w, http.StatusConflict, "not_sliding", "this sign-in has a fixed lifetime; sign in again when it ends")
		return
	}
	http.SetCookie(w, h.newAuthCookie(tok, exp))
	h.jsonResponse(w, http.StatusOK, map[string]any{"token": tok, "expires_at": exp})
}

// ---- Split half cookie (browsers) ----

// The browser half lives in an HttpOnly cookie scoped to the unseal endpoint, so
// page scripts never see it. Host-only, Strict (the other Cloistr apps are
// same-site). Its Max-Age is the seal's expiry; for until_signout it can't be
// re-issued as the session slides (the server never keeps the half, and
// /users/me doesn't receive the cookie), so it lives as long as browsers allow,
// or until SESSION_SEAL_MAX_DAYS. The server-side seal expiry governs either way.
const (
	splitHalfCookieName = "cloistr_seal_half"
	splitHalfCookiePath = "/api/v1/users/session/unseal"
	browserCookieMax    = 400 * 24 * time.Hour // browsers cap cookie lifetimes at 400 days
)

// isBrowserRequest: browsers send Sec-Fetch-Mode (and Origin on CORS/POST);
// plain HTTP clients don't. Browser split sign-ins get the half as a cookie only.
func isBrowserRequest(r *http.Request) bool {
	return r.Header.Get("Sec-Fetch-Mode") != "" || r.Header.Get("Origin") != ""
}

func (h *Handler) splitHalfCookie(g *stayGrant) *http.Cookie {
	life := time.Until(g.expiresAt)
	if g.sliding {
		life = h.capAtMaxDays(time.Now(), time.Now().Add(browserCookieMax)).Sub(time.Now())
	}
	return &http.Cookie{
		Name:     splitHalfCookieName,
		Value:    base64.RawURLEncoding.EncodeToString(g.half),
		Path:     splitHalfCookiePath,
		MaxAge:   int(life.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}
}

func clearSplitHalfCookie() *http.Cookie {
	return &http.Cookie{Name: splitHalfCookieName, Value: "", Path: splitHalfCookiePath, MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode}
}
