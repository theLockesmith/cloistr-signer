package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/auth"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// fakeAccountVault records the order of Vault deletions and can fail any step.
type fakeAccountVault struct {
	calls []string
	fail  map[string]error
}

func (f *fakeAccountVault) DeleteUserpassAccount(_ context.Context, username string) error {
	f.calls = append(f.calls, "userpass:"+username)
	return f.fail["userpass"]
}

func (f *fakeAccountVault) DeletePolicy(_ context.Context, name string) error {
	f.calls = append(f.calls, "policy:"+name)
	return f.fail["policy"]
}

func (f *fakeAccountVault) DeleteTransitKey(_ context.Context, name string) error {
	f.calls = append(f.calls, "transit:"+name)
	return f.fail["transit"]
}

// failingStore injects failures into the storage steps of the deletion path.
type failingStore struct {
	storage.Storage
	fail map[string]error
}

func (s *failingStore) DeleteUserSessions(ctx context.Context, userID string) error {
	if err := s.fail["sessions"]; err != nil {
		return err
	}
	return s.Storage.DeleteUserSessions(ctx, userID)
}

func (s *failingStore) DeletePermission(ctx context.Context, keyID, userPubkey string) error {
	if err := s.fail["permission"]; err != nil {
		return err
	}
	return s.Storage.DeletePermission(ctx, keyID, userPubkey)
}

func (s *failingStore) DeleteUser(ctx context.Context, id string) error {
	if err := s.fail["user"]; err != nil {
		return err
	}
	return s.Storage.DeleteUser(ctx, id)
}

const delPassword = "correct horse battery staple"

// deletionFixture: a user with one unlocked key, one grant, one app consent
// and one session, a fake Vault, and a store that can fail on demand.
func deletionFixture(t *testing.T) (*Handler, *failingStore, *fakeAccountVault, *storage.Key) {
	t.Helper()
	h, mem := testHandler(t)
	key := seedUserAndKey(t, mem)
	ctx := context.Background()

	user, _ := mem.GetUser(ctx, testUserIDSess)
	hash, err := auth.HashPassword(delPassword, 4)
	if err != nil {
		t.Fatal(err)
	}
	user.PasswordHash = hash
	if err := mem.UpdateUser(ctx, user); err != nil {
		t.Fatal(err)
	}
	unlockKey(h, key)
	if err := mem.SetPermission(ctx, &storage.Permission{KeyID: key.Pubkey, UserPubkey: testClientPubkey, Methods: []string{"sign_event"}}); err != nil {
		t.Fatal(err)
	}
	if err := mem.RecordAppConsent(ctx, testUserIDSess, testClientPubkey, "TestApp"); err != nil {
		t.Fatal(err)
	}
	if err := mem.CreateUserSession(ctx, &storage.UserSession{ID: "sess-1", UserID: testUserIDSess, ExpiresAt: time.Now().Add(time.Hour), CreatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	fs := &failingStore{Storage: mem, fail: map[string]error{}}
	h.storage = fs
	fv := &fakeAccountVault{fail: map[string]error{}}
	h.accountVault = fv
	return h, fs, fv, key
}

func assertAccountGone(t *testing.T, h *Handler, key *storage.Key) {
	t.Helper()
	ctx := context.Background()
	if _, err := h.storage.GetUser(ctx, testUserIDSess); !errors.Is(err, storage.ErrUserNotFound) {
		t.Errorf("user still present (err=%v)", err)
	}
	if keys, _ := h.storage.ListKeys(ctx, testUserIDSess); len(keys) != 0 {
		t.Errorf("keys still present: %d", len(keys))
	}
	if h.signer.IsKeyLoaded(key.Pubkey) {
		t.Error("key still unlocked in signer memory")
	}
	if sessions, _ := h.storage.ListUserSessions(ctx, testUserIDSess); len(sessions) != 0 {
		t.Errorf("sessions still present: %d", len(sessions))
	}
	if perms, _ := h.storage.ListPermissions(ctx, key.Pubkey); len(perms) != 0 {
		t.Errorf("grants still present: %d", len(perms))
	}
}

func TestDeleteAccount_RemovesEverythingInOrder(t *testing.T) {
	h, _, fv, key := deletionFixture(t)

	res, err := h.deleteAccount(context.Background(), testUserIDSess)
	if err != nil {
		t.Fatalf("deleteAccount: %v", err)
	}
	if len(res.Retained) != 0 {
		t.Errorf("retained = %v, want none", res.Retained)
	}
	assertAccountGone(t, h, key)
	want := []string{
		"userpass:" + testUserIDSess,
		"policy:cloistr-user-" + testUserIDSess,
		"transit:cloistr-user-" + testUserIDSess,
	}
	if len(fv.calls) != len(want) {
		t.Fatalf("vault calls = %v, want %v", fv.calls, want)
	}
	for i := range want {
		if fv.calls[i] != want[i] {
			t.Errorf("vault call %d = %q, want %q", i, fv.calls[i], want[i])
		}
	}
}

// Step 1 failing: nothing irreversible has happened; the DB row and the
// Vault credential are untouched, and a retry completes.
func TestDeleteAccount_SessionRevokeFailureAbortsBeforeVaultAndDB(t *testing.T) {
	h, fs, fv, key := deletionFixture(t)
	fs.fail["sessions"] = errors.New("store down")

	if _, err := h.deleteAccount(context.Background(), testUserIDSess); err == nil {
		t.Fatal("expected an error when sessions cannot be revoked")
	}
	if _, err := h.storage.GetUser(context.Background(), testUserIDSess); err != nil {
		t.Errorf("user deleted despite step-1 failure: %v", err)
	}
	if len(fv.calls) != 0 {
		t.Errorf("vault touched despite step-1 failure: %v", fv.calls)
	}

	delete(fs.fail, "sessions")
	if _, err := h.deleteAccount(context.Background(), testUserIDSess); err != nil {
		t.Fatalf("retry: %v", err)
	}
	assertAccountGone(t, h, key)
}

func TestDeleteAccount_GrantRevokeFailureAbortsBeforeVaultAndDB(t *testing.T) {
	h, fs, fv, key := deletionFixture(t)
	fs.fail["permission"] = errors.New("store down")

	if _, err := h.deleteAccount(context.Background(), testUserIDSess); err == nil {
		t.Fatal("expected an error when grants cannot be revoked")
	}
	if _, err := h.storage.GetUser(context.Background(), testUserIDSess); err != nil {
		t.Errorf("user deleted despite grant failure: %v", err)
	}
	if len(fv.calls) != 0 {
		t.Errorf("vault touched despite grant failure: %v", fv.calls)
	}

	delete(fs.fail, "permission")
	if _, err := h.deleteAccount(context.Background(), testUserIDSess); err != nil {
		t.Fatalf("retry: %v", err)
	}
	assertAccountGone(t, h, key)
}

// Step 2 failing: the Vault credential may still exist, so the DB row must
// survive too (it is how a retry finds the account again).
func TestDeleteAccount_VaultUserpassFailureAbortsBeforeDB(t *testing.T) {
	h, _, fv, key := deletionFixture(t)
	fv.fail["userpass"] = errors.New("vault 503")

	if _, err := h.deleteAccount(context.Background(), testUserIDSess); err == nil {
		t.Fatal("expected an error when the Vault login cannot be deleted")
	}
	if _, err := h.storage.GetUser(context.Background(), testUserIDSess); err != nil {
		t.Errorf("user deleted despite Vault failure: %v", err)
	}
	for _, c := range fv.calls {
		if c != "userpass:"+testUserIDSess {
			t.Errorf("continued past the failed userpass step: %v", fv.calls)
		}
	}

	delete(fv.fail, "userpass")
	if _, err := h.deleteAccount(context.Background(), testUserIDSess); err != nil {
		t.Fatalf("retry: %v", err)
	}
	assertAccountGone(t, h, key)
}

func TestDeleteAccount_VaultPolicyFailureAbortsBeforeDB(t *testing.T) {
	h, _, fv, key := deletionFixture(t)
	fv.fail["policy"] = errors.New("vault 503")

	if _, err := h.deleteAccount(context.Background(), testUserIDSess); err == nil {
		t.Fatal("expected an error when the Vault policy cannot be deleted")
	}
	if _, err := h.storage.GetUser(context.Background(), testUserIDSess); err != nil {
		t.Errorf("user deleted despite Vault policy failure: %v", err)
	}

	delete(fv.fail, "policy")
	if _, err := h.deleteAccount(context.Background(), testUserIDSess); err != nil {
		t.Fatalf("retry: %v", err)
	}
	assertAccountGone(t, h, key)
}

// Step 3 failing: credentials are already gone; the error is reported and a
// retry finishes the job.
func TestDeleteAccount_DBDeleteFailureReportedAndRetryable(t *testing.T) {
	h, fs, fv, key := deletionFixture(t)
	fs.fail["user"] = errors.New("db down")

	if _, err := h.deleteAccount(context.Background(), testUserIDSess); err == nil {
		t.Fatal("expected an error when the account row cannot be deleted")
	}
	for _, c := range fv.calls {
		if c == "transit:cloistr-user-"+testUserIDSess {
			t.Error("transit key deleted before the account row")
		}
	}

	delete(fs.fail, "user")
	if _, err := h.deleteAccount(context.Background(), testUserIDSess); err != nil {
		t.Fatalf("retry: %v", err)
	}
	assertAccountGone(t, h, key)
}

// Step 4 failing (today's case: the signer policy lacks transit delete):
// the account is deleted, the transit key is recorded as retained, and the
// sweep finishes it once deletion succeeds.
func TestDeleteAccount_TransitFailureRecordedAsRetainedThenSwept(t *testing.T) {
	h, _, fv, key := deletionFixture(t)
	fv.fail["transit"] = errors.New("vault 403 permission denied")
	ctx := context.Background()

	res, err := h.deleteAccount(ctx, testUserIDSess)
	if err != nil {
		t.Fatalf("deleteAccount: %v (a retained transit key is not a failure)", err)
	}
	wantObj := "transit/keys/cloistr-user-" + testUserIDSess
	if len(res.Retained) != 1 || res.Retained[0] != wantObj {
		t.Fatalf("retained = %v, want [%s]", res.Retained, wantObj)
	}
	assertAccountGone(t, h, key)
	pending, err := h.storage.ListRetainedDeletions(ctx)
	if err != nil || len(pending) != 1 || pending[0].UserID != testUserIDSess || pending[0].Object != wantObj {
		t.Fatalf("retained record = %+v (err %v)", pending, err)
	}

	// Still failing: the record stays.
	if n := h.sweepRetainedDeletions(ctx); n != 0 {
		t.Errorf("sweep cleared %d while still failing", n)
	}
	if pending, _ := h.storage.ListRetainedDeletions(ctx); len(pending) != 1 {
		t.Fatalf("record lost after a failed sweep: %+v", pending)
	}

	delete(fv.fail, "transit")
	if n := h.sweepRetainedDeletions(ctx); n != 1 {
		t.Errorf("sweep cleared %d, want 1", n)
	}
	if pending, _ := h.storage.ListRetainedDeletions(ctx); len(pending) != 0 {
		t.Errorf("record not cleared after a successful sweep: %+v", pending)
	}
}

func TestDeleteAccount_AlreadyDeletedIsNotAnError(t *testing.T) {
	h, _, _, _ := deletionFixture(t)
	ctx := context.Background()
	if _, err := h.deleteAccount(ctx, testUserIDSess); err != nil {
		t.Fatal(err)
	}
	if _, err := h.deleteAccount(ctx, testUserIDSess); err != nil {
		t.Fatalf("second delete: %v", err)
	}
}

// --- self-service endpoint ---

func selfDelete(t *testing.T, h *Handler, body map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/me", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+makeSessionToken(t, h, testUserIDSess))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.handleUserMe(rr, req)
	return rr
}

func TestSelfDelete_WrongPasswordRefused(t *testing.T) {
	h, _, fv, _ := deletionFixture(t)
	rr := selfDelete(t, h, map[string]string{"password": "wrong", "confirm": "ssotest"})
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rr.Code)
	}
	if len(fv.calls) != 0 {
		t.Error("deletion ran despite a wrong password")
	}
	user, _ := h.storage.GetUser(context.Background(), testUserIDSess)
	if user == nil || user.FailedLoginAttempts != 1 {
		t.Errorf("a wrong password must count toward lockout; user=%+v", user)
	}
}

func TestSelfDelete_ConfirmationMustMatchUsername(t *testing.T) {
	h, _, fv, _ := deletionFixture(t)
	for _, c := range []string{"", "SSOTEST", "ssotest "} {
		rr := selfDelete(t, h, map[string]string{"password": delPassword, "confirm": c})
		if rr.Code != http.StatusBadRequest {
			t.Errorf("confirm %q: status = %d, want 400", c, rr.Code)
		}
	}
	if len(fv.calls) != 0 {
		t.Error("deletion ran without the typed confirmation")
	}
}

func TestSelfDelete_RequiresMFAWhenEnabled(t *testing.T) {
	h, _, fv, _ := deletionFixture(t)
	ctx := context.Background()
	secret, _, err := auth.GenerateMFASecret("Test", "ssotest")
	if err != nil {
		t.Fatal(err)
	}
	user, _ := h.storage.GetUser(ctx, testUserIDSess)
	user.MFAEnabled = true
	user.MFASecret = secret
	_ = h.storage.UpdateUser(ctx, user)

	if rr := selfDelete(t, h, map[string]string{"password": delPassword, "confirm": "ssotest"}); rr.Code != http.StatusUnauthorized {
		t.Errorf("missing MFA code: status = %d, want 401", rr.Code)
	}
	if rr := selfDelete(t, h, map[string]string{"password": delPassword, "confirm": "ssotest", "mfa_code": "000000"}); rr.Code != http.StatusUnauthorized {
		t.Errorf("wrong MFA code: status = %d, want 401", rr.Code)
	}
	if len(fv.calls) != 0 {
		t.Fatal("deletion ran without a valid MFA code")
	}
	code, _ := totp.GenerateCode(secret, time.Now())
	if rr := selfDelete(t, h, map[string]string{"password": delPassword, "confirm": "ssotest", "mfa_code": code}); rr.Code != http.StatusOK {
		t.Fatalf("valid MFA code: status = %d, body %s", rr.Code, rr.Body.String())
	}
}

func TestSelfDelete_Success(t *testing.T) {
	h, _, _, key := deletionFixture(t)
	rr := selfDelete(t, h, map[string]string{"password": delPassword, "confirm": "ssotest"})
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rr.Code, rr.Body.String())
	}
	var resp map[string]interface{}
	_ = json.Unmarshal(rr.Body.Bytes(), &resp)
	if resp["deleted"] != true {
		t.Errorf("response = %v, want deleted=true", resp)
	}
	assertAccountGone(t, h, key)
}

// --- admin endpoint ---

func adminDelete(t *testing.T, h *Handler, asUserID string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/admin/users/"+testUserIDSess, nil)
	req.Header.Set("Authorization", "Bearer "+makeSessionToken(t, h, asUserID))
	rr := httptest.NewRecorder()
	h.handleAdminUserByPubkey(rr, req)
	return rr
}

func TestAdminDelete_NonAdminRefused(t *testing.T) {
	h, _, fv, _ := deletionFixture(t)
	if rr := adminDelete(t, h, testUserIDSess); rr.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rr.Code)
	}
	if len(fv.calls) != 0 {
		t.Error("deletion ran for a non-admin caller")
	}
}

func TestAdminDelete_DeletesUser(t *testing.T) {
	h, _, _, key := deletionFixture(t)
	ctx := context.Background()
	admin := &storage.User{ID: "admin-1", Username: "boss", PasswordHash: "x", Role: "admin", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := h.storage.CreateUser(ctx, admin); err != nil {
		t.Fatal(err)
	}
	if rr := adminDelete(t, h, "admin-1"); rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rr.Code, rr.Body.String())
	}
	assertAccountGone(t, h, key)
}
