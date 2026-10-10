package web

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/auth"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/ratelimit"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
	"github.com/pquerna/otp/totp"
)

// The legacy /web/api/login must apply the same protections as
// /api/v1/users/login: lockout on wrong passwords and wrong MFA codes,
// attempt limits, and single-use backup codes.

func webLoginUser(t *testing.T, store storage.Storage, mfa bool) (secret string, backup []string) {
	t.Helper()
	hash, _ := auth.HashPassword("correctpassword", auth.TestingBcryptCost)
	u := &storage.User{ID: "weblogin1", Username: "weblogin", PasswordHash: hash, CreatedAt: time.Now()}
	if mfa {
		secret, _, _ = auth.GenerateMFASecret("Test", "weblogin")
		plain, hashed, _ := auth.GenerateBackupCodes(2)
		u.MFAEnabled, u.MFASecret, u.BackupCodes = true, secret, hashed
		backup = plain
	}
	if err := store.CreateUser(context.Background(), u); err != nil {
		t.Fatal(err)
	}
	return secret, backup
}

func webLogin(h *Handler, password, mfa string) *httptest.ResponseRecorder {
	body := fmt.Sprintf(`{"username":"weblogin","password":%q,"mfa_code":%q}`, password, mfa)
	req := httptest.NewRequest(http.MethodPost, "/web/api/login", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.handleAPILogin(rr, req)
	return rr
}

func failedAttempts(t *testing.T, store storage.Storage) int {
	u, _ := store.GetUser(context.Background(), "weblogin1")
	return u.FailedLoginAttempts
}

func TestWebLogin_WrongPasswordsLockTheAccount(t *testing.T) {
	h, store, _ := testHandler(t)
	webLoginUser(t, store, false)
	for i := 0; i < 5; i++ {
		webLogin(h, "wrong", "")
	}
	if rr := webLogin(h, "correctpassword", ""); rr.Code != http.StatusForbidden {
		t.Fatalf("after 5 wrong passwords the right one got %d, want 403 account locked", rr.Code)
	}
}

func TestWebLogin_WrongMFACodeCountsTowardLockout(t *testing.T) {
	h, store, _ := testHandler(t)
	secret, _ := webLoginUser(t, store, true)
	webLogin(h, "correctpassword", "000000")
	if n := failedAttempts(t, store); n != 1 {
		t.Fatalf("failed attempts after one wrong MFA code = %d, want 1", n)
	}
	for i := 0; i < 4; i++ {
		webLogin(h, "correctpassword", "000000")
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	if rr := webLogin(h, "correctpassword", code); rr.Code != http.StatusForbidden {
		t.Fatalf("after 5 wrong MFA codes a valid code got %d, want 403", rr.Code)
	}
}

func TestWebLogin_BackupCodeIsSingleUse(t *testing.T) {
	h, store, _ := testHandler(t)
	_, backup := webLoginUser(t, store, true)
	if rr := webLogin(h, "correctpassword", backup[0]); rr.Code != http.StatusOK {
		t.Fatalf("first use of a backup code: status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
	if rr := webLogin(h, "correctpassword", backup[0]); rr.Code != http.StatusUnauthorized {
		t.Fatalf("second use of the same backup code: status = %d, want 401", rr.Code)
	}
}

func TestWebLogin_AttemptLimit(t *testing.T) {
	h, store, _ := testHandler(t)
	webLoginUser(t, store, false)
	h.SetAuthLimits(ratelimit.NewMemory(), nil)
	h.config.Auth.AttemptsPerAccount = 3
	h.config.Auth.AttemptWindowMinutes = 15
	h.authConfig.MaxFailedAttempts = 1000
	for i := 0; i < 3; i++ {
		webLogin(h, "wrong", "")
	}
	if rr := webLogin(h, "correctpassword", ""); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("4th attempt: status = %d, want 429", rr.Code)
	}
}
