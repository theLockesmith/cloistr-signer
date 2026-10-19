package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/audit"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/signer"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
	"github.com/btcsuite/btcd/btcutil/bech32"
)

// Login CSRF through link mode (reproduced on production by cloistr-pr):
// attacker B starts a link challenge in B's own session and gets victim A's
// wallet to sign it (a swapped QR). A's wallet key is now linked to B's
// account, so A's later, honest Lightning logins land A in B's account.
//
// A key's first Lightning login must therefore stop and show which account it
// opens, and set no cookie until the user confirms it is theirs.
func TestLightningLink_CSRFVictimLoginStopsAtConfirm(t *testing.T) {
	a, _, store, _ := lightningReplicas(t)
	a.config.Lightning.ConfirmFirstLogin = true
	ctx := context.Background()
	// testUserID is the attacker (addAuthHeader signs requests as testUserID).
	if err := store.CreateUser(ctx, &storage.User{ID: testUserID, Username: "attacker-b", PasswordHash: "x", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	victimWallet := newLNWallet(t) // A's wallet, linked nowhere yet

	// B starts a link challenge; A's wallet signs it.
	k1, sid := linkChallenge(t, a)
	if cb := lnCallback(t, a, victimWallet.callbackQuery(t, k1)); cb["status"] != "OK" {
		t.Fatalf("link callback: %v", cb)
	}
	lnStatus(t, a, sid)

	// A, later, signs in honestly with their own wallet.
	k1, sid = lnChallenge(t, a)
	if cb := lnCallback(t, a, victimWallet.callbackQuery(t, k1)); cb["status"] != "OK" {
		t.Fatalf("login callback: %v", cb)
	}
	code, body, cookies := lnStatus(t, a, sid)
	if body["success"] == true || len(cookies) != 0 {
		t.Fatalf("victim's first Lightning login signed straight in: %d %v cookies=%d; want it stopped at the account check", code, body, len(cookies))
	}
	if code != http.StatusOK || body["status"] != "confirm_account" || body["username"] != "attacker-b" {
		t.Fatalf("victim's first login: %d %v, want 200 status=confirm_account username=attacker-b", code, body)
	}
}

// csrfBound returns a handler where the attacker (testUserID, "attacker-b")
// has linked the victim's wallet key, plus that wallet.
func csrfBound(t *testing.T, confirmOn bool) (*Handler, *storage.MemoryStorage, lnWallet) {
	t.Helper()
	a, _, store, _ := lightningReplicas(t)
	a.config.Lightning.ConfirmFirstLogin = confirmOn
	if err := store.CreateUser(context.Background(), &storage.User{ID: testUserID, Username: "attacker-b", PasswordHash: "x", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	victim := newLNWallet(t)
	k1, sid := linkChallenge(t, a)
	if cb := lnCallback(t, a, victim.callbackQuery(t, k1)); cb["status"] != "OK" {
		t.Fatalf("link callback: %v", cb)
	}
	lnStatus(t, a, sid)
	return a, store, victim
}

// lnLoginUntilStatus runs a login up to the first status poll, from a browser
// holding the given cookies (none by default).
func lnLoginUntilStatus(t *testing.T, h *Handler, w lnWallet, browser ...*http.Cookie) (sid string, code int, body map[string]any, cookies []*http.Cookie) {
	t.Helper()
	k1, sid := lnChallenge(t, h)
	if cb := lnCallback(t, h, w.callbackQuery(t, k1)); cb["status"] != "OK" {
		t.Fatalf("login callback: %v", cb)
	}
	code, body, cookies = lnStatus(t, h, sid, browser...)
	return sid, code, body, cookies
}

// lnMarkers keeps the confirmation markers from a response's cookies.
func lnMarkers(cookies []*http.Cookie) []*http.Cookie {
	var out []*http.Cookie
	for _, c := range cookies {
		if strings.HasPrefix(c.Name, lightningConfirmCookiePrefix) {
			out = append(out, c)
		}
	}
	return out
}

func lnConfirm(t *testing.T, h *Handler, sid string, yes bool) (int, map[string]any, []*http.Cookie) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{"session_id": sid, "confirm": yes})
	rr := httptest.NewRecorder()
	h.handleLightningConfirm(rr, httptest.NewRequest(http.MethodPost, "/api/v1/users/lightning/confirm", bytes.NewReader(b)))
	var body map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &body)
	return rr.Code, body, rr.Result().Cookies()
}

// Flag off (the default until the login UI handles the prompt): today's
// behaviour, the first login signs straight in.
func TestLightningLink_CSRFFlagOffKeepsTodaysBehaviour(t *testing.T) {
	h, _, victim := csrfBound(t, false)
	_, code, body, cookies := lnLoginUntilStatus(t, h, victim)
	if code != http.StatusOK || body["success"] != true || len(cookies) == 0 {
		t.Fatalf("flag off: %d %v cookies=%d, want today's direct sign-in", code, body, len(cookies))
	}
}

// "No, not my account": the key is unlinked from the attacker's account, no
// cookie, and the wallet no longer signs in anywhere.
func TestLightningLink_CSRFVictimSaysNoUnlinks(t *testing.T) {
	h, store, victim := csrfBound(t, true)
	sid, _, body, _ := lnLoginUntilStatus(t, h, victim)
	if body["status"] != "confirm_account" {
		t.Fatalf("first login: %v", body)
	}
	code, body, cookies := lnConfirm(t, h, sid, false)
	if code != http.StatusOK || body["status"] != "unlinked" || len(cookies) != 0 {
		t.Fatalf("confirm=false: %d %v cookies=%d, want 200 unlinked and no cookie", code, body, len(cookies))
	}
	if keys, _ := store.ListLightningKeys(context.Background(), testUserID); len(keys) != 0 {
		t.Fatalf("attacker still has %d Lightning keys", len(keys))
	}
	if code, body, cookies := lnStatus(t, h, sid); body["success"] == true || len(cookies) != 0 {
		t.Fatalf("poll after 'no': %d %v, want no sign-in", code, body)
	}
	k1, _ := lnChallenge(t, h)
	if cb := lnCallback(t, h, victim.callbackQuery(t, k1)); cb["status"] != "ERROR" {
		t.Fatalf("wallet still signs in after unlinking: %v", cb)
	}
}

// "Yes": the login completes with a cookie, and the key's later logins in the
// same browser no longer ask (once per browser, not every time). A browser
// that never answered still asks.
func TestLightningLink_ConfirmYesOnceThenDirect(t *testing.T) {
	a, _, _, wallet := lightningReplicas(t) // ln-user's own key, linked before confirmation existed
	a.config.Lightning.ConfirmFirstLogin = true
	sid, _, body, cookies := lnLoginUntilStatus(t, a, wallet)
	if body["status"] != "confirm_account" || body["username"] != "ln-user" || len(cookies) != 0 {
		t.Fatalf("existing key's first login: %v cookies=%d, want confirm_account for ln-user", body, len(cookies))
	}
	code, body, cookies := lnConfirm(t, a, sid, true)
	if code != http.StatusOK || body["success"] != true || len(cookies) == 0 {
		t.Fatalf("confirm=true: %d %v cookies=%d, want a sign-in", code, body, len(cookies))
	}
	browser := lnMarkers(cookies)
	if len(browser) != 1 {
		t.Fatalf("confirm=true set %d confirmation markers, want 1", len(browser))
	}
	if code, body, _ := lnConfirm(t, a, sid, true); code != http.StatusBadRequest || body["status"] != "expired" {
		t.Fatalf("second confirm: %d %v, want 400 expired", code, body)
	}
	_, code, body, cookies = lnLoginUntilStatus(t, a, wallet, browser...)
	if code != http.StatusOK || body["success"] != true || len(cookies) == 0 {
		t.Fatalf("login after confirming, same browser: %d %v, want a direct sign-in", code, body)
	}
	_, code, body, cookies = lnLoginUntilStatus(t, a, wallet)
	if code != http.StatusOK || body["status"] != "confirm_account" || len(cookies) != 0 {
		t.Fatalf("login after confirming, another browser: %d %v cookies=%d, want confirm_account", code, body, len(cookies))
	}
}

// The marker is HttpOnly, Secure, SameSite=Strict, host-only, and sent only to
// the Lightning endpoints.
func TestLightningConfirm_MarkerCookieAttributes(t *testing.T) {
	a, _, _, wallet := lightningReplicas(t)
	a.config.Lightning.ConfirmFirstLogin = true
	a.config.Auth.CookieDomain = ".example.test"
	sid, _, _, _ := lnLoginUntilStatus(t, a, wallet)
	_, _, cookies := lnConfirm(t, a, sid, true)
	m := lnMarkers(cookies)
	if len(m) != 1 {
		t.Fatalf("markers = %d, want 1", len(m))
	}
	c := m[0]
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode || c.Path != lightningConfirmCookiePath || c.Domain != "" || c.MaxAge <= 0 {
		t.Fatalf("marker cookie = %+v, want HttpOnly Secure Strict host-only path %s with a max age", c, lightningConfirmCookiePath)
	}
}

// A marker covers the key AND the account it opened when the browser said
// yes: if the same key now opens another account, or the marker is altered,
// the browser is asked again.
func TestLightningConfirm_MarkerBoundToAccount(t *testing.T) {
	a, _, store, wallet := lightningReplicas(t)
	a.config.Lightning.ConfirmFirstLogin = true
	ctx := context.Background()
	sid, _, _, _ := lnLoginUntilStatus(t, a, wallet)
	_, _, cookies := lnConfirm(t, a, sid, true)
	browser := lnMarkers(cookies)

	tampered := *browser[0]
	tampered.Value = "A" + tampered.Value[1:]
	if tampered.Value == browser[0].Value {
		tampered.Value = "B" + tampered.Value[1:]
	}
	if _, code, body, _ := lnLoginUntilStatus(t, a, wallet, &tampered); body["status"] != "confirm_account" {
		t.Fatalf("altered marker: %d %v, want confirm_account", code, body)
	}

	// Same key id and wallet key, now on the attacker's account.
	if err := store.CreateUser(ctx, &storage.User{ID: testUserID, Username: "attacker-b", PasswordHash: "x", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := store.DeleteLightningKey(ctx, "lk1"); err != nil {
		t.Fatal(err)
	}
	if err := store.CreateLightningKey(ctx, &storage.LightningKey{ID: "lk1", UserID: testUserID, LinkingKey: wallet.key(), CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, code, body, cookies := lnLoginUntilStatus(t, a, wallet, browser...); body["status"] != "confirm_account" || body["username"] != "attacker-b" || len(cookies) != 0 {
		t.Fatalf("marker for ln-user, key now opens attacker-b: %d %v cookies=%d, want confirm_account for attacker-b", code, body, len(cookies))
	}
}

// Confirm is refused before the wallet has signed, and for unknown sessions.
func TestLightningLink_ConfirmRefusals(t *testing.T) {
	a, _, _, _ := lightningReplicas(t)
	a.config.Lightning.ConfirmFirstLogin = true
	_, sid := lnChallenge(t, a)
	if code, body, _ := lnConfirm(t, a, sid, true); code != http.StatusConflict || body["status"] != "pending" {
		t.Fatalf("before the wallet signed: %d %v, want 409 pending", code, body)
	}
	if code, body, _ := lnConfirm(t, a, "no-such-session", true); code != http.StatusBadRequest || body["status"] != "expired" {
		t.Fatalf("unknown session: %d %v, want 400 expired", code, body)
	}
}

// (a) A link challenge tells the wallet it is a link (LUD-04 action=link); a
// login challenge says login.
func TestLightningChallenge_ActionParam(t *testing.T) {
	a, _, _, _ := lightningReplicas(t)
	for _, tc := range []struct {
		name, want string
		do         func() *httptest.ResponseRecorder
	}{
		{"login", "action=login", func() *httptest.ResponseRecorder {
			rr := httptest.NewRecorder()
			a.handleLightningChallenge(rr, httptest.NewRequest(http.MethodPost, "/api/v1/users/lightning/challenge", nil))
			return rr
		}},
		{"link", "action=link", func() *httptest.ResponseRecorder {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/users/lightning/link/challenge", nil)
			addAuthHeader(t, a, req)
			rr := httptest.NewRecorder()
			a.handleLightningLinkChallenge(rr, req)
			return rr
		}},
	} {
		var body map[string]string
		_ = json.Unmarshal(tc.do().Body.Bytes(), &body)
		_, data5, err := bech32.DecodeNoLimit(strings.ToLower(body["lnurl"]))
		if err != nil {
			t.Fatalf("%s: decode lnurl: %v", tc.name, err)
		}
		data, err := bech32.ConvertBits(data5, 5, 8, false)
		if err != nil {
			t.Fatalf("%s: decode lnurl: %v", tc.name, err)
		}
		if !strings.Contains(string(data), tc.want) {
			t.Fatalf("%s challenge URL %q lacks %s", tc.name, data, tc.want)
		}
	}
}

// (c) Every link, and every "not my account", leaves an audit event naming
// the account and the wallet key.
func TestLightningLink_AuditEvents(t *testing.T) {
	base, _, store, _ := lightningReplicas(t)
	logger := audit.NewMemoryLogger(50)
	h := NewHandler(base.config, signer.New(base.config, store, nil, nil, nil, nil, logger), store, nil, nil)
	h.config.Lightning.ConfirmFirstLogin = true
	if err := store.CreateUser(context.Background(), &storage.User{ID: testUserID, Username: "attacker-b", PasswordHash: "x", CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	victim := newLNWallet(t)
	k1, sid := linkChallenge(t, h)
	lnCallback(t, h, victim.callbackQuery(t, k1))
	lnStatus(t, h, sid)
	sid, _, _, _ = lnLoginUntilStatus(t, h, victim)
	lnConfirm(t, h, sid, false)

	for _, typ := range []audit.EventType{audit.EventLightningKeyLinked, audit.EventLightningKeyRejected} {
		evs, _ := logger.Query(context.Background(), &audit.Filter{Types: []audit.EventType{typ}})
		if len(evs) != 1 || evs[0].Actor != testUserID || evs[0].Target != victim.key() {
			t.Fatalf("%s events = %+v, want one for %s / the victim's key", typ, evs, testUserID)
		}
	}
}

// Review !241 (cloistr-pr): the attacker gets the victim's wallet to sign one
// attacker-started LOGIN challenge too, answers "yes" in the attacker's own
// browser, and the key is confirmed. The victim's later honest login, from
// the victim's own browser, must still stop at the account check: a "yes" only
// covers the browser that gave it.
func TestReview241_AttackerPreConfirmsVictimKey(t *testing.T) {
	h, _, victim := csrfBound(t, true)
	sid, _, body, _ := lnLoginUntilStatus(t, h, victim) // attacker's login challenge, victim's wallet signs
	if body["status"] != "confirm_account" {
		t.Fatalf("attacker's login: %v", body)
	}
	if code, body, _ := lnConfirm(t, h, sid, true); code != http.StatusOK || body["success"] != true {
		t.Fatalf("attacker confirm: %d %v", code, body)
	}
	_, code, body, cookies := lnLoginUntilStatus(t, h, victim) // victim, later, honestly
	if body["success"] == true || len(cookies) != 0 {
		t.Fatalf("BYPASS: victim's honest login after the attacker's pre-confirm: %d %v cookies=%d, want it stopped at the account check", code, body, len(cookies))
	}
	if code != http.StatusOK || body["status"] != "confirm_account" || body["username"] != "attacker-b" {
		t.Fatalf("victim's login: %d %v, want 200 status=confirm_account username=attacker-b", code, body)
	}
}
