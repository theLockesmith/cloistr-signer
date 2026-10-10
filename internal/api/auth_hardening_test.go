package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/auth"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/ratelimit"
	"github.com/pquerna/otp/totp"
)

// enableMFA turns MFA on for the fixture user and returns the TOTP secret.
func (f *exportFixture) enableMFA(t *testing.T) string {
	t.Helper()
	secret, _, _ := auth.GenerateMFASecret("TestIssuer", exportUsername)
	u, _ := f.store.GetUser(context.Background(), exportUserID)
	u.MFAEnabled, u.MFASecret = true, secret
	_ = f.store.UpdateUser(context.Background(), u)
	return secret
}

func (f *exportFixture) failedAttempts(t *testing.T) int {
	t.Helper()
	u, _ := f.store.GetUser(context.Background(), exportUserID)
	return u.FailedLoginAttempts
}

func (f *exportFixture) login(t *testing.T, username, password, mfa, ip string) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(LoginRequest{Username: username, Password: password, MFACode: mfa})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users/login", bytes.NewReader(b))
	if ip != "" {
		req.Header.Set("X-Real-IP", ip)
	}
	rr := httptest.NewRecorder()
	f.h.handleUserLogin(rr, req)
	return rr
}

func (f *exportFixture) selfDelete(t *testing.T, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/me", bytes.NewReader(b))
	rr := httptest.NewRecorder()
	f.h.handleSelfDelete(rr, req, &auth.JWTClaims{UserID: exportUserID, Username: exportUsername})
	return rr
}

// (a) A wrong MFA code counts toward the same lockout as a wrong password.

func TestLogin_WrongMFACodeCountsTowardLockout(t *testing.T) {
	f := newExportFixture(t, nil)
	secret := f.enableMFA(t)

	if rr := f.login(t, exportUsername, exportPassword, "000000", ""); rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong code: status = %d, want 401", rr.Code)
	}
	if n := f.failedAttempts(t); n != 1 {
		t.Fatalf("failed attempts after one wrong MFA code = %d, want 1", n)
	}
	for i := 0; i < 4; i++ {
		f.login(t, exportUsername, exportPassword, "000000", "")
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	if rr := f.login(t, exportUsername, exportPassword, code, ""); rr.Code != http.StatusForbidden {
		t.Fatalf("after 5 wrong MFA codes a valid code got %d, want 403 account locked", rr.Code)
	}
}

func TestExport_WrongMFACodeCountsTowardLockout(t *testing.T) {
	f := newExportFixture(t, nil)
	secret := f.enableMFA(t)
	b := validExport("nsec")
	b["mfa_code"] = "000000"
	f.export(t, f.key.ID, b)
	if n := f.failedAttempts(t); n != 1 {
		t.Fatalf("failed attempts after one wrong MFA code on export = %d, want 1", n)
	}
	for i := 0; i < 4; i++ {
		f.export(t, f.key.ID, b)
	}
	b["mfa_code"], _ = totp.GenerateCode(secret, time.Now())
	if rr := f.export(t, f.key.ID, b); rr.Code != http.StatusForbidden {
		t.Fatalf("after 5 wrong MFA codes a valid code got %d, want 403 account locked", rr.Code)
	}
}

func TestSelfDelete_WrongMFACodeCountsTowardLockout(t *testing.T) {
	f := newExportFixture(t, nil)
	f.enableMFA(t)
	rr := f.selfDelete(t, map[string]any{"password": exportPassword, "confirm": exportUsername, "mfa_code": "000000"})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	if n := f.failedAttempts(t); n != 1 {
		t.Fatalf("failed attempts after one wrong MFA code on self-delete = %d, want 1", n)
	}
}

// (b) Per-account and per-IP attempt limits on sign-in, self-delete and export.

func (f *exportFixture) limitAttempts(t *testing.T, perAccount, perIP int) {
	t.Helper()
	f.h.SetLimiter(ratelimit.NewMemory())
	ih, err := ratelimit.NewIPHasher(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.h.SetIPHasher(ih)
	f.h.config.Recovery.TrustedProxyHeader = "X-Real-IP"
	f.h.config.Auth.AttemptsPerAccount = perAccount
	f.h.config.Auth.AttemptsPerIP = perIP
	f.h.config.Auth.AttemptWindowMinutes = 15
	// Keep the lockout out of the way so only the rate limit can refuse.
	f.h.authConfig.MaxFailedAttempts = 1000
}

func TestLogin_PerAccountLimit(t *testing.T) {
	f := newExportFixture(t, nil)
	f.limitAttempts(t, 3, 1000)
	for i := 0; i < 3; i++ {
		if rr := f.login(t, exportUsername, "wrong", "", fmt.Sprintf("10.0.0.%d", i)); rr.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status = %d, want 401", i+1, rr.Code)
		}
	}
	// Even the right password is refused once the account's budget is spent,
	// and from a fresh IP: the limit is on the account, not the address.
	if rr := f.login(t, exportUsername, exportPassword, "", "10.0.0.99"); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("4th attempt: status = %d, want 429", rr.Code)
	}
}

func TestLogin_PerIPLimit(t *testing.T) {
	f := newExportFixture(t, nil)
	f.limitAttempts(t, 1000, 3)
	for i := 0; i < 3; i++ {
		f.login(t, fmt.Sprintf("someone%d", i), "wrong", "", "203.0.113.7")
	}
	if rr := f.login(t, exportUsername, exportPassword, "", "203.0.113.7"); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("4th attempt from one IP across accounts: status = %d, want 429", rr.Code)
	}
}

func TestExport_PerAccountLimit(t *testing.T) {
	f := newExportFixture(t, nil)
	f.limitAttempts(t, 3, 1000)
	b := validExport("nsec")
	b["password"] = "wrong"
	for i := 0; i < 3; i++ {
		f.export(t, f.key.ID, b)
	}
	if rr := f.export(t, f.key.ID, validExport("nsec")); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("4th export attempt: status = %d, want 429", rr.Code)
	}
}

func TestSelfDelete_PerAccountLimit(t *testing.T) {
	f := newExportFixture(t, nil)
	f.limitAttempts(t, 3, 1000)
	for i := 0; i < 3; i++ {
		f.selfDelete(t, map[string]any{"password": "wrong", "confirm": exportUsername})
	}
	if rr := f.selfDelete(t, map[string]any{"password": exportPassword, "confirm": exportUsername}); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("4th self-delete attempt: status = %d, want 429", rr.Code)
	}
}

// Sign-in, self-delete and export draw on one per-account budget, so an
// attacker cannot multiply guesses by switching endpoints.
func TestAttemptBudgetSharedAcrossEndpoints(t *testing.T) {
	f := newExportFixture(t, nil)
	f.limitAttempts(t, 3, 1000)
	f.login(t, exportUsername, "wrong", "", "")
	b := validExport("nsec")
	b["password"] = "wrong"
	f.export(t, f.key.ID, b)
	f.selfDelete(t, map[string]any{"password": "wrong", "confirm": exportUsername})
	if rr := f.login(t, exportUsername, exportPassword, "", ""); rr.Code != http.StatusTooManyRequests {
		t.Fatalf("4th attempt across endpoints: status = %d, want 429", rr.Code)
	}
}

// (c) The ncryptsec export password has a minimum length.
func TestExport_NcryptsecPasswordMinimumLength(t *testing.T) {
	f := newExportFixture(t, nil)
	b := validExport("ncryptsec")
	b["export_password"] = "short12" // 7 characters
	if rr := f.export(t, f.key.ID, b); rr.Code != http.StatusBadRequest {
		t.Fatalf("7-char export password: status = %d, want 400", rr.Code)
	}
	b["export_password"] = "long1234" // 8 characters
	if rr := f.export(t, f.key.ID, b); rr.Code != http.StatusOK {
		t.Fatalf("8-char export password: status = %d, want 200: %s", rr.Code, rr.Body.String())
	}
}
