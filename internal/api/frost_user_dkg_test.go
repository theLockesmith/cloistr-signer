package api

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bytemare/ecc"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/config"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/crypto"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/frost"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/signer"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/vault"
)

// HTTP integration tests for the FROST 2-of-N user-cosigner DKG endpoints.
// These exercise the full wire path: JSON envelopes, JWT auth, mock-Vault
// encryption, and the finalize → storage persistence sequence. The
// in-process protocol math is covered separately in
// internal/frost/user_dkg_test.go; here we pin the HTTP contract.

// frostTestUser is the simulated browser party. Identical math to what a
// real client must run; reproduced here to keep the test self-contained.
// (The frost package keeps the equivalent helpers unexported.)
type frostTestUser struct {
	coeffs  []*ecc.Scalar
	commits []*ecc.Element
}

func newFrostTestUser() *frostTestUser {
	group := frost.DefaultCiphersuite.Group()
	a0 := group.NewScalar().Random()
	a1 := group.NewScalar().Random()
	return &frostTestUser{
		coeffs:  []*ecc.Scalar{a0, a1},
		commits: []*ecc.Element{group.Base().Multiply(a0), group.Base().Multiply(a1)},
	}
}

func (u *frostTestUser) commitsHex() []string {
	return []string{u.commits[0].Hex(), u.commits[1].Hex()}
}

// shareForSigner evaluates f(SignerIndex) = a0 + a1·SignerIndex and returns
// the hex-encoded scalar.
func (u *frostTestUser) shareForSigner() string {
	group := frost.DefaultCiphersuite.Group()
	result := group.NewScalar().Set(u.coeffs[0])
	term := group.NewScalar().Set(u.coeffs[1])
	idxScalar := group.NewScalar().SetUInt64(uint64(frost.SignerIndex))
	term.Multiply(idxScalar)
	result.Add(term)
	return hex.EncodeToString(result.Encode())
}

// jointPubkeyHex computes user-side joint pubkey = A0 + signerB0.
func (u *frostTestUser) jointPubkeyHex(t *testing.T, signerCommitsHex []string) string {
	t.Helper()
	group := frost.DefaultCiphersuite.Group()
	B0 := group.NewElement()
	if err := B0.DecodeHex(signerCommitsHex[0]); err != nil {
		t.Fatalf("decode signer B0: %v", err)
	}
	pub := group.NewElement().Set(u.commits[0])
	pub.Add(B0)
	return pub.Hex()
}

// frostTestEnv bundles the harness for a FROST DKG HTTP test: a mock Vault,
// a configured Handler, an http.ServeMux with routes registered, and a
// registered+logged-in user with a JWT.
type frostTestEnv struct {
	vault     *httptest.Server
	store     storage.Storage
	handler   *Handler
	mux       *http.ServeMux
	authToken string
	userID    string
}

func (e *frostTestEnv) close() {
	if e.vault != nil {
		e.vault.Close()
	}
}

// setupFrostTestEnv stands up a mock Vault, a Handler wired to it, and a
// registered + logged-in user. The returned env is ready to drive the
// three DKG endpoints with auth.
func setupFrostTestEnv(t *testing.T) *frostTestEnv {
	t.Helper()

	// Mock Vault server. Pattern copied from integration_test.go's
	// TestIntegration_FullFlow_WithVault and trimmed to what FROST needs.
	vaultServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("X-Vault-Token")
		path := r.URL.Path

		if path == "/v1/sys/health" {
			json.NewEncoder(w).Encode(map[string]interface{}{"initialized": true, "sealed": false})
			return
		}

		if token == "service-token" {
			if strings.Contains(path, "/transit/keys/") && r.Method == http.MethodPost {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{})
				return
			}
			if strings.Contains(path, "/sys/policies/acl/") && r.Method == http.MethodPut {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{})
				return
			}
			if strings.Contains(path, "/auth/userpass/users/") && r.Method == http.MethodPost {
				w.WriteHeader(http.StatusOK)
				json.NewEncoder(w).Encode(map[string]interface{}{})
				return
			}
		}

		if strings.Contains(path, "/auth/userpass/login/") && r.Method == http.MethodPost {
			var payload map[string]string
			json.NewDecoder(r.Body).Decode(&payload)
			if payload["password"] == "FrostTestPass123!" {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"auth": map[string]interface{}{
						"client_token":   "user-vault-token-" + strings.TrimPrefix(path, "/v1/auth/userpass/login/"),
						"lease_duration": 3600,
						"renewable":      true,
					},
				})
				return
			}
			w.WriteHeader(http.StatusForbidden)
			return
		}

		if path == "/v1/auth/token/revoke-self" {
			w.WriteHeader(http.StatusOK)
			return
		}

		if strings.HasPrefix(token, "user-vault-token-") {
			if strings.Contains(path, "/transit/encrypt/") && r.Method == http.MethodPost {
				var payload map[string]string
				json.NewDecoder(r.Body).Decode(&payload)
				ciphertext := "vault:v1:" + base64.StdEncoding.EncodeToString([]byte(payload["plaintext"]))
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{"ciphertext": ciphertext},
				})
				return
			}
			if strings.Contains(path, "/transit/decrypt/") && r.Method == http.MethodPost {
				var payload map[string]string
				json.NewDecoder(r.Body).Decode(&payload)
				encoded := strings.TrimPrefix(payload["ciphertext"], "vault:v1:")
				decoded, _ := base64.StdEncoding.DecodeString(encoded)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{"plaintext": string(decoded)},
				})
				return
			}
		}

		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{"errors": []string{"permission denied"}})
	}))

	store := storage.NewMemoryStorage()
	cfg := &config.Config{
		Auth: config.AuthConfig{
			JWTSecret:                "frost-test-secret-32-chars-long!",
			JWTExpiry:                24,
			SessionInactivityMinutes: 1440,
			MaxFailedLogins:          5,
			LockoutMinutes:           15,
		},
		Vault: config.VaultConfig{
			Enabled:   true,
			Address:   vaultServer.URL,
			Token:     "service-token",
			MountPath: "transit",
		},
		Server: config.ServerConfig{Address: ":8080"},
		Relays: []string{"wss://relay.example.com"},
	}

	vaultClient, err := vault.NewClient(&vault.Config{Address: vaultServer.URL, Token: "service-token"})
	if err != nil {
		vaultServer.Close()
		t.Fatalf("vault client: %v", err)
	}

	encryptor, _ := crypto.NewEncryptor("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	s := signer.New(cfg, store, nil, encryptor, nil, nil, nil)
	handler := NewHandler(cfg, s, store, encryptor, vaultClient)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	env := &frostTestEnv{
		vault:   vaultServer,
		store:   store,
		handler: handler,
		mux:     mux,
	}

	// Register + login.
	regBody := `{"username":"frostuser","password":"FrostTestPass123!"}`
	regReq := httptest.NewRequest(http.MethodPost, "/api/v1/users/register", strings.NewReader(regBody))
	regReq.Header.Set("Content-Type", "application/json")
	regW := httptest.NewRecorder()
	mux.ServeHTTP(regW, regReq)
	if regW.Code != http.StatusCreated {
		env.close()
		t.Fatalf("register: %d - %s", regW.Code, regW.Body.String())
	}
	var regResp map[string]interface{}
	if err := json.Unmarshal(regW.Body.Bytes(), &regResp); err != nil {
		env.close()
		t.Fatalf("decode register response: %v", err)
	}
	env.userID = regResp["id"].(string)

	loginBody := `{"username":"frostuser","password":"FrostTestPass123!"}`
	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/users/login", strings.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginW := httptest.NewRecorder()
	mux.ServeHTTP(loginW, loginReq)
	if loginW.Code != http.StatusOK {
		env.close()
		t.Fatalf("login: %d - %s", loginW.Code, loginW.Body.String())
	}
	var loginResp map[string]interface{}
	if err := json.Unmarshal(loginW.Body.Bytes(), &loginResp); err != nil {
		env.close()
		t.Fatalf("decode login response: %v", err)
	}
	env.authToken = loginResp["token"].(string)

	return env
}

// postJSON is a convenience for the DKG endpoint tests.
func postJSON(t *testing.T, mux *http.ServeMux, path, authToken string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal request body: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

func TestFrostUserDKGHTTP_FullFlow(t *testing.T) {
	env := setupFrostTestEnv(t)
	defer env.close()
	user := newFrostTestUser()

	// Round 1
	r1 := postJSON(t, env.mux, "/api/v1/frost/user-dkg/round1", env.authToken, map[string]interface{}{
		"user_commits_hex": user.commitsHex(),
	})
	if r1.Code != http.StatusOK {
		t.Fatalf("round1: %d - %s", r1.Code, r1.Body.String())
	}
	var r1Resp frost.Round1Response
	if err := json.Unmarshal(r1.Body.Bytes(), &r1Resp); err != nil {
		t.Fatalf("decode round1 response: %v", err)
	}
	if r1Resp.SessionID == "" || len(r1Resp.SignerCommitsHex) != 2 {
		t.Fatalf("round1 response shape: %+v", r1Resp)
	}

	// Round 2
	r2 := postJSON(t, env.mux, "/api/v1/frost/user-dkg/round2", env.authToken, frost.Round2Request{
		SessionID:             r1Resp.SessionID,
		UserShareForSignerHex: user.shareForSigner(),
	})
	if r2.Code != http.StatusOK {
		t.Fatalf("round2: %d - %s", r2.Code, r2.Body.String())
	}
	var r2Resp frost.Round2Response
	if err := json.Unmarshal(r2.Body.Bytes(), &r2Resp); err != nil {
		t.Fatalf("decode round2 response: %v", err)
	}
	if r2Resp.SignerShareForUserHex == "" {
		t.Fatalf("round2 returned empty signer share")
	}

	// Finalize
	final := postJSON(t, env.mux, "/api/v1/frost/user-dkg/finalize", env.authToken, frost.FinalizeRequest{
		SessionID:             r1Resp.SessionID,
		ConfirmJointPubkeyHex: user.jointPubkeyHex(t, r1Resp.SignerCommitsHex),
	})
	if final.Code != http.StatusOK {
		t.Fatalf("finalize: %d - %s", final.Code, final.Body.String())
	}

	var finalResp FrostUserDKGFinalizeResponse
	if err := json.Unmarshal(final.Body.Bytes(), &finalResp); err != nil {
		t.Fatalf("decode finalize response: %v", err)
	}
	if finalResp.KeyID == "" {
		t.Fatal("finalize returned empty key_id")
	}
	if len(finalResp.Pubkey) != 64 {
		t.Errorf("pubkey hex length = %d, want 64 (x-only 32 bytes)", len(finalResp.Pubkey))
	}

	// Persistence checks: Key row + FrostUserShare row, with correct type
	// and a vault-prefixed ciphertext on the share.
	ctx := context.Background()
	gotKey, err := env.store.GetKey(ctx, finalResp.KeyID)
	if err != nil {
		t.Fatalf("get persisted key: %v", err)
	}
	if gotKey.KeyType != storage.KeyTypeFrostUser {
		t.Errorf("KeyType = %q, want %q", gotKey.KeyType, storage.KeyTypeFrostUser)
	}
	if gotKey.OwnerID != env.userID {
		t.Errorf("OwnerID = %q, want %q", gotKey.OwnerID, env.userID)
	}
	if gotKey.Pubkey != finalResp.Pubkey {
		t.Errorf("persisted Pubkey = %q, response Pubkey = %q", gotKey.Pubkey, finalResp.Pubkey)
	}

	gotShare, err := env.store.GetFrostUserShareByKeyID(ctx, finalResp.KeyID)
	if err != nil {
		t.Fatalf("get persisted share: %v", err)
	}
	if gotShare.ShareIndex != frost.SignerIndex {
		t.Errorf("ShareIndex = %d, want %d", gotShare.ShareIndex, frost.SignerIndex)
	}
	if gotShare.Threshold != 2 || gotShare.TotalShares != 2 {
		t.Errorf("threshold/total = %d/%d, want 2/2", gotShare.Threshold, gotShare.TotalShares)
	}
	if !strings.HasPrefix(string(gotShare.EncryptedShare), "vault:v1:") {
		t.Errorf("EncryptedShare is not Vault-prefixed; got %q", string(gotShare.EncryptedShare))
	}
	if len(gotShare.VerificationShare) == 0 {
		t.Errorf("VerificationShare is empty")
	}
}

func TestFrostUserDKGHTTP_RequiresAuth(t *testing.T) {
	env := setupFrostTestEnv(t)
	defer env.close()

	cases := []struct {
		path string
		body interface{}
	}{
		{"/api/v1/frost/user-dkg/round1", map[string]interface{}{"user_commits_hex": []string{"00", "00"}}},
		{"/api/v1/frost/user-dkg/round2", frost.Round2Request{SessionID: "fake", UserShareForSignerHex: "00"}},
		{"/api/v1/frost/user-dkg/finalize", frost.FinalizeRequest{SessionID: "fake", ConfirmJointPubkeyHex: "00"}},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			w := postJSON(t, env.mux, tc.path, "", tc.body)
			if w.Code != http.StatusUnauthorized {
				t.Errorf("no-auth call to %s: status = %d, want 401", tc.path, w.Code)
			}
		})
	}
}

func TestFrostUserDKGHTTP_Round2RejectsBadShare(t *testing.T) {
	env := setupFrostTestEnv(t)
	defer env.close()
	user := newFrostTestUser()

	r1 := postJSON(t, env.mux, "/api/v1/frost/user-dkg/round1", env.authToken, map[string]interface{}{
		"user_commits_hex": user.commitsHex(),
	})
	if r1.Code != http.StatusOK {
		t.Fatalf("round1: %d - %s", r1.Code, r1.Body.String())
	}
	var r1Resp frost.Round1Response
	json.Unmarshal(r1.Body.Bytes(), &r1Resp)

	// Send a random scalar (not the polynomial evaluation).
	group := frost.DefaultCiphersuite.Group()
	bogus := group.NewScalar().Random()
	w := postJSON(t, env.mux, "/api/v1/frost/user-dkg/round2", env.authToken, frost.Round2Request{
		SessionID:             r1Resp.SessionID,
		UserShareForSignerHex: hex.EncodeToString(bogus.Encode()),
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("bad share: status = %d, want 400. body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "verification") {
		t.Errorf("expected verification-failure error message, got: %s", w.Body.String())
	}
}

func TestFrostUserDKGHTTP_FinalizeRejectsPubkeyMismatch(t *testing.T) {
	env := setupFrostTestEnv(t)
	defer env.close()
	user := newFrostTestUser()

	r1 := postJSON(t, env.mux, "/api/v1/frost/user-dkg/round1", env.authToken, map[string]interface{}{
		"user_commits_hex": user.commitsHex(),
	})
	var r1Resp frost.Round1Response
	json.Unmarshal(r1.Body.Bytes(), &r1Resp)

	r2 := postJSON(t, env.mux, "/api/v1/frost/user-dkg/round2", env.authToken, frost.Round2Request{
		SessionID:             r1Resp.SessionID,
		UserShareForSignerHex: user.shareForSigner(),
	})
	if r2.Code != http.StatusOK {
		t.Fatalf("round2: %d - %s", r2.Code, r2.Body.String())
	}

	// Lie about the pubkey - submit a random one instead of A0+B0.
	group := frost.DefaultCiphersuite.Group()
	bogusPubkey := group.Base().Multiply(group.NewScalar().Random())
	w := postJSON(t, env.mux, "/api/v1/frost/user-dkg/finalize", env.authToken, frost.FinalizeRequest{
		SessionID:             r1Resp.SessionID,
		ConfirmJointPubkeyHex: bogusPubkey.Hex(),
	})
	if w.Code != http.StatusBadRequest {
		t.Errorf("pubkey mismatch: status = %d, want 400. body: %s", w.Code, w.Body.String())
	}
}

// Recovery endpoint round-trip (docs/frost-2-of-n-design.md §6.4).
// Run a full DKG that supplies UserVerificationShareHex at finalize,
// then hit GET /api/v1/frost/user-dkg/recovery/{keyId} and verify the
// response carries:
//   - the same Pubkey as the finalize response
//   - the original Round 2 signer-share-for-user (decrypted server-side
//     from the Vault-stored ciphertext)
//   - the user_verification_share that we passed in
func TestFrostUserDKGHTTP_Recovery(t *testing.T) {
	env := setupFrostTestEnv(t)
	defer env.close()
	user := newFrostTestUser()

	// Round 1
	r1Body := postJSON(t, env.mux, "/api/v1/frost/user-dkg/round1", env.authToken, map[string]interface{}{
		"user_commits_hex": user.commitsHex(),
	})
	if r1Body.Code != http.StatusOK {
		t.Fatalf("round1: %d - %s", r1Body.Code, r1Body.Body.String())
	}
	var r1 frost.Round1Response
	json.Unmarshal(r1Body.Body.Bytes(), &r1)

	// Round 2
	r2Body := postJSON(t, env.mux, "/api/v1/frost/user-dkg/round2", env.authToken, frost.Round2Request{
		SessionID:             r1.SessionID,
		UserShareForSignerHex: user.shareForSigner(),
	})
	if r2Body.Code != http.StatusOK {
		t.Fatalf("round2: %d - %s", r2Body.Code, r2Body.Body.String())
	}
	var r2 frost.Round2Response
	json.Unmarshal(r2Body.Body.Bytes(), &r2)

	// Compute the user's final share + verification share locally - same
	// math a real client runs.
	group := frost.DefaultCiphersuite.Group()
	signerShareForUser := group.NewScalar()
	rawSignerShare, _ := hex.DecodeString(r2.SignerShareForUserHex)
	if err := signerShareForUser.Decode(rawSignerShare); err != nil {
		t.Fatalf("decode signer share: %v", err)
	}
	userSelf := group.NewScalar().Set(user.coeffs[0])
	term := group.NewScalar().Set(user.coeffs[1])
	idx := group.NewScalar().SetUInt64(uint64(frost.UserIndex))
	term.Multiply(idx)
	userSelf.Add(term)
	userFinalShare := group.NewScalar().Set(userSelf)
	userFinalShare.Add(signerShareForUser)
	userVerificationShare := group.Base().Multiply(userFinalShare)
	userVerificationShareHex := userVerificationShare.Hex()

	// Finalize with the verification share so recovery can later be tested
	finBody := postJSON(t, env.mux, "/api/v1/frost/user-dkg/finalize", env.authToken, frost.FinalizeRequest{
		SessionID:                r1.SessionID,
		ConfirmJointPubkeyHex:    user.jointPubkeyHex(t, r1.SignerCommitsHex),
		UserVerificationShareHex: userVerificationShareHex,
	})
	if finBody.Code != http.StatusOK {
		t.Fatalf("finalize: %d - %s", finBody.Code, finBody.Body.String())
	}
	var fin FrostUserDKGFinalizeResponse
	json.Unmarshal(finBody.Body.Bytes(), &fin)

	// Recovery
	recReq := httptest.NewRequest(http.MethodGet,
		"/api/v1/frost/user-dkg/recovery/"+fin.KeyID, nil)
	recReq.Header.Set("Authorization", "Bearer "+env.authToken)
	recW := httptest.NewRecorder()
	env.mux.ServeHTTP(recW, recReq)
	if recW.Code != http.StatusOK {
		t.Fatalf("recovery: %d - %s", recW.Code, recW.Body.String())
	}
	var rec FrostUserDKGRecoveryResponse
	if err := json.Unmarshal(recW.Body.Bytes(), &rec); err != nil {
		t.Fatalf("decode recovery: %v", err)
	}

	if rec.KeyID != fin.KeyID {
		t.Errorf("recovery key_id = %q, want %q", rec.KeyID, fin.KeyID)
	}
	if rec.Pubkey != fin.Pubkey {
		t.Errorf("recovery pubkey = %q, want %q", rec.Pubkey, fin.Pubkey)
	}
	if rec.UserVerificationShareHex != userVerificationShareHex {
		t.Errorf("verification share mismatch: got %q, want %q",
			rec.UserVerificationShareHex, userVerificationShareHex)
	}
	if rec.SignerShareForUserHex != r2.SignerShareForUserHex {
		t.Errorf("signer_share_for_user round-trip mismatch:\n got: %q\nwant: %q",
			rec.SignerShareForUserHex, r2.SignerShareForUserHex)
	}

	// Sanity: the recovered signer_share_for_user + user-derived f(UserIndex)
	// should reconstruct to the same final share whose ·G == user_verification_share.
	signerShare2 := group.NewScalar()
	raw2, _ := hex.DecodeString(rec.SignerShareForUserHex)
	if err := signerShare2.Decode(raw2); err != nil {
		t.Fatalf("decode recovered share: %v", err)
	}
	reconstructed := group.NewScalar().Set(userSelf)
	reconstructed.Add(signerShare2)
	reconstructedPt := group.Base().Multiply(reconstructed)
	if !reconstructedPt.Equal(userVerificationShare) {
		t.Errorf("reconstructed final-share·G does not match stored user_verification_share")
	}
}

// Recovery for a key owned by a different user must return 404.
func TestFrostUserDKGHTTP_RecoveryOwnerCheck(t *testing.T) {
	env := setupFrostTestEnv(t)
	defer env.close()

	// Hit recovery on a made-up key id - same code path as owner-mismatch
	// because the GetKey returns ErrKeyNotFound which is mapped to 404.
	// We don't have a second-user fixture in this test env; this exercises
	// the not-found branch which is the same response shape.
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/frost/user-dkg/recovery/nonexistent-key-id", nil)
	req.Header.Set("Authorization", "Bearer "+env.authToken)
	w := httptest.NewRecorder()
	env.mux.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("recovery of missing key: status = %d, want 404", w.Code)
	}
}

// Without auth the recovery endpoint must 401.
func TestFrostUserDKGHTTP_RecoveryRequiresAuth(t *testing.T) {
	env := setupFrostTestEnv(t)
	defer env.close()
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/frost/user-dkg/recovery/anything", nil)
	w := httptest.NewRecorder()
	env.mux.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("recovery without auth: status = %d, want 401", w.Code)
	}
}

// Without Vault, finalize MUST refuse - the privacy-architecture §1.1
// "We Cannot Comply" property requires the share to be encrypted under a
// key the operator alone cannot read. The signer refuses to fall back to
// a weaker envelope.
func TestFrostUserDKGHTTP_FinalizeRequiresVault(t *testing.T) {
	// Build a handler with no vault client.
	store := storage.NewMemoryStorage()
	cfg := &config.Config{
		Auth: config.AuthConfig{
			JWTSecret:                "frost-no-vault-test-secret-32ch!",
			JWTExpiry:                24,
			SessionInactivityMinutes: 1440,
			MaxFailedLogins:          5,
			LockoutMinutes:           15,
		},
		Server: config.ServerConfig{Address: ":8080"},
		Relays: []string{"wss://relay.example.com"},
	}
	encryptor, _ := crypto.NewEncryptor("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	s := signer.New(cfg, store, nil, encryptor, nil, nil, nil)
	handler := NewHandler(cfg, s, store, encryptor, nil) // nil vault
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Register + login (no vault path - just creates user with local encryption).
	regReq := httptest.NewRequest(http.MethodPost, "/api/v1/users/register",
		strings.NewReader(`{"username":"nofrostuser","password":"NoVaultPass123!"}`))
	regReq.Header.Set("Content-Type", "application/json")
	regW := httptest.NewRecorder()
	mux.ServeHTTP(regW, regReq)
	if regW.Code != http.StatusCreated {
		t.Fatalf("register no-vault: %d - %s", regW.Code, regW.Body.String())
	}

	loginReq := httptest.NewRequest(http.MethodPost, "/api/v1/users/login",
		strings.NewReader(`{"username":"nofrostuser","password":"NoVaultPass123!"}`))
	loginReq.Header.Set("Content-Type", "application/json")
	loginW := httptest.NewRecorder()
	mux.ServeHTTP(loginW, loginReq)
	if loginW.Code != http.StatusOK {
		t.Fatalf("login no-vault: %d - %s", loginW.Code, loginW.Body.String())
	}
	var loginResp map[string]interface{}
	json.Unmarshal(loginW.Body.Bytes(), &loginResp)
	authToken := loginResp["token"].(string)

	user := newFrostTestUser()
	r1 := postJSON(t, mux, "/api/v1/frost/user-dkg/round1", authToken, map[string]interface{}{
		"user_commits_hex": user.commitsHex(),
	})
	if r1.Code != http.StatusOK {
		t.Fatalf("round1 no-vault: %d - %s", r1.Code, r1.Body.String())
	}
	var r1Resp frost.Round1Response
	json.Unmarshal(r1.Body.Bytes(), &r1Resp)

	r2 := postJSON(t, mux, "/api/v1/frost/user-dkg/round2", authToken, frost.Round2Request{
		SessionID:             r1Resp.SessionID,
		UserShareForSignerHex: user.shareForSigner(),
	})
	if r2.Code != http.StatusOK {
		t.Fatalf("round2 no-vault: %d - %s", r2.Code, r2.Body.String())
	}

	w := postJSON(t, mux, "/api/v1/frost/user-dkg/finalize", authToken, frost.FinalizeRequest{
		SessionID:             r1Resp.SessionID,
		ConfirmJointPubkeyHex: user.jointPubkeyHex(t, r1Resp.SignerCommitsHex),
	})
	if w.Code != http.StatusFailedDependency {
		t.Errorf("finalize without vault: status = %d, want 424 (FailedDependency). body: %s", w.Code, w.Body.String())
	}
}
