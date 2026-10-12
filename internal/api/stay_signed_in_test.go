package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/auth"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/config"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/seal"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/signer"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// Two handlers on one database stand in for two replicas; a handler created after
// the login stands in for a pod that started after a deploy. Nothing carries over
// between handlers except the database (and, in keyfile mode, the key file).

type staySignedInFixture struct {
	*exportFixture
	keyfile string
}

func newStayFixture(t *testing.T) *staySignedInFixture {
	t.Helper()
	f := &staySignedInFixture{exportFixture: newExportFixture(t, nil), keyfile: filepath.Join(t.TempDir(), "seal.key")}
	// Production signs sessions in for 30 days (JWT_EXPIRY=720); give the fixture
	// longer so the 30-day choice isn't capped by the session itself.
	f.h.config.Auth.JWTExpiry = 40 * 24
	f.h.authConfig.TokenExpiry = 40 * 24 * time.Hour
	f.h.config.StaySignedIn.Split = true
	f.h.SetSealer(f.keyfileSealer(t))
	return f
}

func (f *staySignedInFixture) keyfileSealer(t *testing.T) seal.Sealer {
	t.Helper()
	k, err := seal.LoadKeyfile(f.keyfile, true)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// replica starts a fresh replica on the shared database with the given sealer.
func (f *staySignedInFixture) replica(t *testing.T, s seal.Sealer) *Handler {
	t.Helper()
	cfg := f.h.config
	h := NewHandler(cfg, signer.New(cfg, f.store, nil, nil, nil, nil, nil), f.store, nil, nil)
	h.authConfig.TokenExpiry = f.h.authConfig.TokenExpiry
	h.SetSealer(s)
	return h
}

func (f *staySignedInFixture) loginWith(t *testing.T, h *Handler, choice string, split bool) (LoginResponse, *httptest.ResponseRecorder) {
	t.Helper()
	b, _ := json.Marshal(LoginRequest{Username: exportUsername, Password: exportPassword, StaySignedIn: choice, StaySignedInSplit: split})
	rr := httptest.NewRecorder()
	h.handleUserLogin(rr, httptest.NewRequest(http.MethodPost, "/api/v1/users/login", bytes.NewReader(b)))
	var resp LoginResponse
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	// The unlock (and the seal) finish in the background; wait for them.
	h.keyLoads.wait(context.Background(), exportUserID, 10*time.Second)
	return resp, rr
}

func sealsFor(t *testing.T, store storage.Storage) []*storage.SessionSeal {
	t.Helper()
	s, err := store.ListLiveSessionSeals(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func claimsOf(t *testing.T, h *Handler, token string) *auth.JWTClaims {
	t.Helper()
	c, err := auth.ValidateJWT(h.authConfig, token)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The headline: sign in with 30 days, "roll the signer" (a new replica that never
// saw the login), and the key is usable there with no re-login.
func TestStaySignedIn_SurvivesDeploy(t *testing.T) {
	f := newStayFixture(t)
	resp, rr := f.loginWith(t, f.h, "30d", false)
	if rr.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rr.Code, rr.Body.String())
	}
	g := resp.StaySignedIn
	if g == nil || g.Granted != "30d" || g.Mode != seal.ModeKeyfile || g.ExpiresAt == nil || g.SplitHalf != "" {
		t.Fatalf("grant = %+v, want 30d keyfile with an expiry and no split half", g)
	}
	if d := time.Until(*g.ExpiresAt); d < 29*24*time.Hour || d > 31*24*time.Hour {
		t.Fatalf("grant expires in %v, want ~30 days", d)
	}
	seals := sealsFor(t, f.store)
	if len(seals) != 1 || seals[0].Pubkey != f.key.Pubkey || seals[0].SessionID != claimsOf(t, f.h, resp.Token).SessionID {
		t.Fatalf("seals = %+v, want one for the key, bound to the login session", seals)
	}
	if bytes.Contains(seals[0].Sealed, []byte(f.priv)) {
		t.Fatal("seal row holds the private key in the clear")
	}

	after := f.replica(t, f.keyfileSealer(t))
	if after.signer.IsKeyLoaded(f.key.Pubkey) {
		t.Fatal("fresh replica had the key before restoring")
	}
	after.reconcileSeals(context.Background())
	priv, ok := after.signer.LoadedPrivateKey(f.key.Pubkey)
	if !ok || priv != f.priv {
		t.Fatal("fresh replica did not restore the sealed key")
	}
}

// A request for the key on a replica that hasn't reconciled yet restores it lazily
// (the signer's restorer hook), with no client involvement.
func TestStaySignedIn_LazyRestore(t *testing.T) {
	f := newStayFixture(t)
	f.loginWith(t, f.h, "1d", false)
	after := f.replica(t, f.keyfileSealer(t))
	key, _ := f.store.GetKeyByPubkey(context.Background(), f.key.Pubkey)
	if !after.ensureNostrConnectKeyLoaded(context.Background(), "", exportUserID, key) {
		t.Fatal("on-demand load did not restore from the seal")
	}
}

// Session-only behaves exactly as before: no seal, and a new replica has nothing.
func TestStaySignedIn_SessionOnlyUnchanged(t *testing.T) {
	f := newStayFixture(t)
	for _, choice := range []string{"", "session"} {
		resp, rr := f.loginWith(t, f.h, choice, false)
		if rr.Code != http.StatusOK {
			t.Fatalf("login %q: %d", choice, rr.Code)
		}
		if !f.h.signer.IsKeyLoaded(f.key.Pubkey) {
			t.Fatalf("login %q did not unlock the key on the login replica", choice)
		}
		if resp.StaySignedIn != nil && resp.StaySignedIn.Granted != "session" {
			t.Fatalf("login %q granted %+v", choice, resp.StaySignedIn)
		}
	}
	if s := sealsFor(t, f.store); len(s) != 0 {
		t.Fatalf("session-only logins left %d seals", len(s))
	}
	after := f.replica(t, f.keyfileSealer(t))
	after.reconcileSeals(context.Background())
	if after.signer.IsKeyLoaded(f.key.Pubkey) {
		t.Fatal("a session-only key appeared on a new replica")
	}
}

func TestStaySignedIn_UnknownChoiceRejected(t *testing.T) {
	f := newStayFixture(t)
	_, rr := f.loginWith(t, f.h, "forever-and-ever", false)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("unknown choice: %d, want 400", rr.Code)
	}
}

// A seal row moved onto another session (or account) does not open.
func TestStaySignedIn_SwappedBlobFails(t *testing.T) {
	f := newStayFixture(t)
	f.loginWith(t, f.h, "30d", false)
	sl := sealsFor(t, f.store)[0]
	// Re-home the blob onto a different live session of the same user.
	other := &storage.UserSession{ID: "other-session", UserID: exportUserID, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()}
	_ = f.store.CreateUserSession(context.Background(), other)
	_, _ = f.store.DeleteSessionSealsBySession(context.Background(), sl.SessionID)
	moved := *sl
	moved.ID, moved.SessionID = "moved", other.ID
	if err := f.store.UpsertSessionSeal(context.Background(), &moved); err != nil {
		t.Fatal(err)
	}
	after := f.replica(t, f.keyfileSealer(t))
	after.reconcileSeals(context.Background())
	if after.signer.IsKeyLoaded(f.key.Pubkey) {
		t.Fatal("a seal moved to another session opened")
	}
}

// The DB alone cannot unseal: a replica with a different key file gets nothing.
func TestStaySignedIn_DBCopyAloneCannotUnseal(t *testing.T) {
	f := newStayFixture(t)
	f.loginWith(t, f.h, "30d", false)
	stranger, err := seal.LoadKeyfile(filepath.Join(t.TempDir(), "other.key"), true)
	if err != nil {
		t.Fatal(err)
	}
	after := f.replica(t, stranger)
	after.reconcileSeals(context.Background())
	if after.signer.IsKeyLoaded(f.key.Pubkey) {
		t.Fatal("a replica without the sealing key restored the key")
	}
}

// Expiry is enforced server-side: an expired seal is not restored, and a replica
// holding the key because of it drops it.
func TestStaySignedIn_ExpiredIsRefusedAndUnloaded(t *testing.T) {
	f := newStayFixture(t)
	f.loginWith(t, f.h, "1d", false)
	other := f.replica(t, f.keyfileSealer(t))
	other.reconcileSeals(context.Background())
	if !other.signer.IsKeyLoaded(f.key.Pubkey) {
		t.Fatal("setup: second replica did not restore")
	}
	sl := sealsFor(t, f.store)[0]
	sl.ExpiresAt = time.Now().Add(-time.Second)
	if err := f.store.UpsertSessionSeal(context.Background(), sl); err != nil {
		t.Fatal(err)
	}
	for name, h := range map[string]*Handler{"login replica": f.h, "restored replica": other} {
		h.reconcileSeals(context.Background())
		if h.signer.IsKeyLoaded(f.key.Pubkey) {
			t.Fatalf("%s still holds the key after its seal expired", name)
		}
	}
	fresh := f.replica(t, f.keyfileSealer(t))
	fresh.reconcileSeals(context.Background())
	key, _ := f.store.GetKeyByPubkey(context.Background(), f.key.Pubkey)
	if fresh.signer.IsKeyLoaded(f.key.Pubkey) || fresh.ensureNostrConnectKeyLoaded(context.Background(), "", exportUserID, key) {
		t.Fatal("an expired seal was restored")
	}
	if n := len(sealsFor(t, f.store)); n != 0 {
		t.Fatalf("%d live seals after expiry", n)
	}
}

// Sign-out deletes the seals and locks the key on every replica.
func TestStaySignedIn_SignOutRevokes(t *testing.T) {
	f := newStayFixture(t)
	resp, _ := f.loginWith(t, f.h, "until_signout", false)
	if resp.StaySignedIn == nil || resp.StaySignedIn.Granted != "until_signout" {
		t.Fatalf("grant = %+v", resp.StaySignedIn)
	}
	other := f.replica(t, f.keyfileSealer(t))
	other.reconcileSeals(context.Background())

	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/logout", nil)
	req.Header.Set("Authorization", "Bearer "+resp.Token)
	rr := httptest.NewRecorder()
	f.h.handleUserLogout(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("logout: %d", rr.Code)
	}
	if n := len(sealsFor(t, f.store)); n != 0 {
		t.Fatalf("%d seals survive sign-out", n)
	}
	if f.h.signer.IsKeyLoaded(f.key.Pubkey) {
		t.Fatal("login replica still holds the key after sign-out")
	}
	other.reconcileSeals(context.Background())
	if other.signer.IsKeyLoaded(f.key.Pubkey) {
		t.Fatal("other replica still holds the key after sign-out")
	}
}

// Revoking all sessions (and the session behind a seal disappearing any other
// way) makes the seal unusable.
func TestStaySignedIn_SessionGoneRevokes(t *testing.T) {
	f := newStayFixture(t)
	f.loginWith(t, f.h, "30d", false)
	_ = f.store.DeleteUserSessions(context.Background(), exportUserID)
	after := f.replica(t, f.keyfileSealer(t))
	after.reconcileSeals(context.Background())
	if after.signer.IsKeyLoaded(f.key.Pubkey) {
		t.Fatal("restored a seal whose session is gone")
	}
	f.h.reconcileSeals(context.Background())
	if f.h.signer.IsKeyLoaded(f.key.Pubkey) {
		t.Fatal("login replica kept a key whose seal's session is gone")
	}
}

// Revoke-all: DELETE /api/v1/users/stay-signed-in drops every seal but keeps the
// user signed in to the web UI.
func TestStaySignedIn_RevokeAllEndpoint(t *testing.T) {
	f := newStayFixture(t)
	resp, _ := f.loginWith(t, f.h, "30d", false)

	get := httptest.NewRequest(http.MethodGet, "/api/v1/users/stay-signed-in", nil)
	get.Header.Set("Authorization", "Bearer "+resp.Token)
	rr := httptest.NewRecorder()
	f.h.handleStaySignedIn(rr, get)
	var list []StaySignedInEntry
	if err := json.Unmarshal(rr.Body.Bytes(), &list); err != nil || rr.Code != 200 || len(list) != 1 || !list[0].Current {
		t.Fatalf("list: %d %s", rr.Code, rr.Body.String())
	}

	del := httptest.NewRequest(http.MethodDelete, "/api/v1/users/stay-signed-in", nil)
	del.Header.Set("Authorization", "Bearer "+resp.Token)
	rr = httptest.NewRecorder()
	f.h.handleStaySignedIn(rr, del)
	if rr.Code != http.StatusOK {
		t.Fatalf("revoke-all: %d %s", rr.Code, rr.Body.String())
	}
	if n := len(sealsFor(t, f.store)); n != 0 {
		t.Fatalf("%d seals after revoke-all", n)
	}
	if f.h.signer.IsKeyLoaded(f.key.Pubkey) {
		t.Fatal("key still loaded after revoke-all")
	}
	if _, err := f.h.validateAuthHeader(requestWithToken(resp.Token)); err != nil {
		t.Fatalf("revoke-all signed the user out of the web UI: %v", err)
	}
}

// none mode: durable choices are not granted; session-only still works.
func TestStaySignedIn_NoneMode(t *testing.T) {
	f := newStayFixture(t)
	f.h.SetSealer(seal.None{})
	resp, rr := f.loginWith(t, f.h, "30d", false)
	if rr.Code != http.StatusOK {
		t.Fatalf("login: %d", rr.Code)
	}
	if resp.StaySignedIn == nil || resp.StaySignedIn.Granted != "session" {
		t.Fatalf("none mode granted %+v, want session", resp.StaySignedIn)
	}
	if !f.h.signer.IsKeyLoaded(f.key.Pubkey) {
		t.Fatal("none mode broke the normal unlock")
	}
	if n := len(sealsFor(t, f.store)); n != 0 {
		t.Fatalf("none mode stored %d seals", n)
	}
}

// Split mode: only the browser half unseals. A new replica can't restore it on its
// own; handing the half back over the session restores it; a wrong half is refused.
func TestStaySignedIn_SplitOnlyWithBrowserHalf(t *testing.T) {
	f := newStayFixture(t)
	f.h.SetSealer(seal.None{}) // split needs no Vault or key file
	resp, rr := f.loginWith(t, f.h, "30d", true)
	if rr.Code != http.StatusOK {
		t.Fatalf("login: %d %s", rr.Code, rr.Body.String())
	}
	g := resp.StaySignedIn
	if g == nil || g.Granted != "30d" || g.Mode != seal.ModeSplit || g.SplitHalf == "" {
		t.Fatalf("grant = %+v, want 30d split with a browser half", g)
	}
	half, err := base64.RawURLEncoding.DecodeString(g.SplitHalf)
	if err != nil || len(half) != seal.SplitHalfLen {
		t.Fatalf("split half %q not 32 bytes of base64url", g.SplitHalf)
	}
	if s := sealsFor(t, f.store); len(s) != 1 || s[0].Mode != seal.ModeSplit || bytes.Contains(s[0].Sealed, half) {
		t.Fatalf("seal row wrong: %+v", s)
	}

	after := f.replica(t, seal.None{})
	after.reconcileSeals(context.Background())
	key, _ := f.store.GetKeyByPubkey(context.Background(), f.key.Pubkey)
	if after.signer.IsKeyLoaded(f.key.Pubkey) || after.ensureNostrConnectKeyLoaded(context.Background(), "", exportUserID, key) {
		t.Fatal("split seal restored without the browser half")
	}

	unseal := func(h string) *httptest.ResponseRecorder {
		b, _ := json.Marshal(map[string]string{"split_half": h})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/users/session/unseal", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+resp.Token)
		rr := httptest.NewRecorder()
		after.handleSessionUnseal(rr, req)
		return rr
	}
	wrong := bytes.Clone(half)
	wrong[0] ^= 1
	if rr := unseal(base64.RawURLEncoding.EncodeToString(wrong)); rr.Code != http.StatusForbidden || after.signer.IsKeyLoaded(f.key.Pubkey) {
		t.Fatalf("wrong half: %d %s", rr.Code, rr.Body.String())
	}
	if rr := unseal("not base64!"); rr.Code != http.StatusBadRequest {
		t.Fatalf("garbage half: %d", rr.Code)
	}
	rr = unseal(g.SplitHalf)
	if rr.Code != http.StatusOK {
		t.Fatalf("right half: %d %s", rr.Code, rr.Body.String())
	}
	if priv, ok := after.signer.LoadedPrivateKey(f.key.Pubkey); !ok || priv != f.priv {
		t.Fatal("unseal with the right half did not restore the key")
	}
}

func TestStaySignedIn_SplitRefusedWhenDisabled(t *testing.T) {
	f := newStayFixture(t)
	f.h.config.StaySignedIn.Split = false
	f.h.SetSealer(seal.None{})
	resp, _ := f.loginWith(t, f.h, "30d", true)
	if resp.StaySignedIn == nil || resp.StaySignedIn.Granted != "session" || resp.StaySignedIn.SplitHalf != "" {
		t.Fatalf("split disabled but granted %+v", resp.StaySignedIn)
	}
}

// A seal never outlives its sign-in session.
func TestStaySignedIn_CappedBySession(t *testing.T) {
	f := newStayFixture(t)
	f.h.authConfig.TokenExpiry = 24 * time.Hour
	resp, _ := f.loginWith(t, f.h, "30d", false)
	if g := resp.StaySignedIn; g == nil || g.ExpiresAt == nil || g.ExpiresAt.After(resp.ExpiresAt) {
		t.Fatalf("grant %+v outlives the session (%v)", g, resp.ExpiresAt)
	}
}

// The server-side maximum caps the choice.
func TestStaySignedIn_MaxDaysCaps(t *testing.T) {
	f := newStayFixture(t)
	f.h.config.StaySignedIn.MaxDays = 2
	resp, _ := f.loginWith(t, f.h, "30d", false)
	g := resp.StaySignedIn
	if g == nil || g.ExpiresAt == nil || time.Until(*g.ExpiresAt) > 2*24*time.Hour+time.Minute {
		t.Fatalf("grant %+v not capped at 2 days", g)
	}
	sl := sealsFor(t, f.store)[0]
	if time.Until(sl.ExpiresAt) > 2*24*time.Hour+time.Minute {
		t.Fatalf("seal row expires %v, past the 2-day cap", sl.ExpiresAt)
	}
}

func TestStaySignedIn_Options(t *testing.T) {
	f := newStayFixture(t)
	get := func() StaySignedInOptions {
		rr := httptest.NewRecorder()
		f.h.handleStaySignedInOptions(rr, httptest.NewRequest(http.MethodGet, "/api/v1/users/stay-signed-in/options", nil))
		var o StaySignedInOptions
		if err := json.Unmarshal(rr.Body.Bytes(), &o); err != nil || rr.Code != 200 {
			t.Fatalf("options: %d %s", rr.Code, rr.Body.String())
		}
		return o
	}
	o := get()
	if o.Sealer != seal.ModeKeyfile || len(o.Choices) != 4 || !o.Split {
		t.Fatalf("keyfile options = %+v", o)
	}
	f.h.SetSealer(seal.None{})
	o = get()
	if o.Sealer != seal.ModeNone || len(o.Choices) != 1 || o.Choices[0] != "session" || len(o.SplitChoices) != 4 {
		t.Fatalf("none options = %+v", o)
	}
}

var _ = config.Config{}

func (f *staySignedInFixture) me(t *testing.T, h *Handler, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	h.handleUserMe(rr, req)
	return rr
}

func near(a, b time.Time) bool { return a.Sub(b).Abs() < time.Minute }

// The web session's lifetime follows the choice: 1d and 30d are fixed.
func TestStaySignedIn_SessionFollowsChoice(t *testing.T) {
	f := newStayFixture(t)
	resp, _ := f.loginWith(t, f.h, "1d", false)
	if !near(resp.ExpiresAt, time.Now().Add(24*time.Hour)) {
		t.Fatalf("1d sign-in expires %v, want ~1 day", resp.ExpiresAt)
	}
	sess, _ := f.store.GetUserSession(context.Background(), claimsOf(t, f.h, resp.Token).SessionID)
	if !near(sess.ExpiresAt, resp.ExpiresAt) || sealsFor(t, f.store)[0].Sliding {
		t.Fatalf("1d: session %v, seal sliding %v", sess.ExpiresAt, sealsFor(t, f.store)[0].Sliding)
	}
	// Fixed choices do not slide.
	f.me(t, f.h, resp.Token)
	again, _ := f.store.GetUserSession(context.Background(), sess.ID)
	if !again.ExpiresAt.Equal(sess.ExpiresAt) {
		t.Fatal("a fixed 1d session was extended")
	}
}

// until_signout slides: each use pushes the session (and its seal) to now + idle
// cap, and hands back a fresh token (cookie, or POST /session/refresh).
func TestStaySignedIn_UntilSignOutSlides(t *testing.T) {
	f := newStayFixture(t)
	f.h.config.StaySignedIn.IdleDays = 90
	resp, _ := f.loginWith(t, f.h, "until_signout", false)
	idle := 90 * 24 * time.Hour
	if !near(resp.ExpiresAt, time.Now().Add(idle)) {
		t.Fatalf("until_signout sign-in expires %v, want ~90 days", resp.ExpiresAt)
	}
	sid := claimsOf(t, f.h, resp.Token).SessionID
	if sl := sealsFor(t, f.store)[0]; !sl.Sliding || !near(sl.ExpiresAt, resp.ExpiresAt) {
		t.Fatalf("seal %+v, want sliding with the session's expiry", sl)
	}

	// 80 days later: 10 days of idle budget left.
	soon := time.Now().Add(10 * 24 * time.Hour)
	_ = f.store.ExtendUserSession(context.Background(), sid, soon)
	_, _ = f.store.ExtendSessionSeals(context.Background(), sid, soon)

	rr := f.me(t, f.h, resp.Token)
	if rr.Code != http.StatusOK {
		t.Fatalf("me: %d", rr.Code)
	}
	sess, _ := f.store.GetUserSession(context.Background(), sid)
	if !near(sess.ExpiresAt, time.Now().Add(idle)) {
		t.Fatalf("session not slid: expires %v", sess.ExpiresAt)
	}
	if sl := sealsFor(t, f.store)[0]; !near(sl.ExpiresAt, sess.ExpiresAt) {
		t.Fatalf("seal did not move with the session: %v", sl.ExpiresAt)
	}
	var cookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == "auth_token" {
			cookie = c
		}
	}
	if cookie == nil || !near(claimsOf(t, f.h, cookie.Value).ExpiresAt.Time, sess.ExpiresAt) {
		t.Fatal("me did not re-issue the cookie with the new expiry")
	}

	// Bearer holders refresh explicitly.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/session/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+resp.Token)
	rr = httptest.NewRecorder()
	f.h.handleSessionRefresh(rr, req)
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil || rr.Code != 200 || !near(out.ExpiresAt, sess.ExpiresAt) {
		t.Fatalf("refresh: %d %s", rr.Code, rr.Body.String())
	}
	if c := claimsOf(t, f.h, out.Token); c.SessionID != sid {
		t.Fatalf("refreshed token is for session %q, want %q", c.SessionID, sid)
	}
}

func TestStaySignedIn_RefreshRefusesFixedSessions(t *testing.T) {
	f := newStayFixture(t)
	resp, _ := f.loginWith(t, f.h, "30d", false)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/session/refresh", nil)
	req.Header.Set("Authorization", "Bearer "+resp.Token)
	rr := httptest.NewRecorder()
	f.h.handleSessionRefresh(rr, req)
	if rr.Code != http.StatusConflict {
		t.Fatalf("refresh of a fixed session: %d, want 409", rr.Code)
	}
}

// max_days stays the operator ceiling, even for sliding sessions.
func TestStaySignedIn_SlidingStopsAtMaxDays(t *testing.T) {
	f := newStayFixture(t)
	f.h.config.StaySignedIn.IdleDays = 90
	f.h.config.StaySignedIn.MaxDays = 100
	resp, _ := f.loginWith(t, f.h, "until_signout", false)
	sid := claimsOf(t, f.h, resp.Token).SessionID
	sess, _ := f.store.GetUserSession(context.Background(), sid)
	created := sess.CreatedAt
	// Pretend the sign-in was 95 days ago.
	f.h.stayNow = func() time.Time { return time.Now().Add(95 * 24 * time.Hour) }
	defer func() { f.h.stayNow = nil }()
	_ = f.store.ExtendUserSession(context.Background(), sid, time.Now().Add(96*24*time.Hour))
	f.me(t, f.h, resp.Token)
	sess, _ = f.store.GetUserSession(context.Background(), sid)
	if ceiling := created.Add(100 * 24 * time.Hour); sess.ExpiresAt.After(ceiling.Add(time.Minute)) {
		t.Fatalf("slid to %v, past the 100-day ceiling %v", sess.ExpiresAt, ceiling)
	}
}
