package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip13"
	"github.com/nbd-wtf/go-nostr/nip19"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/auth"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/crypto"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/ratelimit"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// Account recovery by Nostr-key proof of possession.
//
// The problem this solves: the password is cryptographically load-bearing. It is
// the Vault userpass credential AND the KEK for passphrase-wrapped keys, so
// overwriting a password hash does not recover an account -- it strands the key
// material behind a passphrase nobody has. There is no operator escape hatch by
// design, which is what "the server cannot decrypt without you" costs.
//
// Under the Option A identity model the user's signing key IS their identity, so
// the nsec is the one credential that outlives a forgotten password. Proving
// possession of a key already registered to the account is therefore the right
// authority for resetting that account's password.
//
// Flow:
//
//	POST /api/v1/recovery/challenge  {username}
//	  -> {challenge, expires_at}          server-issued nonce, bound to the account
//	POST /api/v1/recovery/complete   {challenge, signed_event, new_password, [nsec]}
//	  -> {keys_recovered, keys_needing_reimport}
//
// What survives the reset, and why:
//
//	vault:  survives. The transit key lives in Vault under its own wrapping key and
//	        is not derived from the password; resetting the userpass credential
//	        administratively leaves the ciphertext readable.
//	enc:    survives. Wrapped with the server-held key, which is unrelated.
//	pbk:    LOST, unless the caller supplies the nsec. The KEK came from the
//	        forgotten passphrase. This is not a defect to engineer around; it is
//	        the property working as intended.

const (
	// recoveryChallengeTTL is deliberately short. The window only has to cover a
	// human clicking through a signing prompt, and a signed proof is a
	// password-reset authority -- there is no reason for it to be long-lived.
	recoveryChallengeTTL = 5 * time.Minute

	// recoveryChallengeBytes is the nonce size. 32 bytes so a challenge cannot be
	// guessed or ground down; the value doubles as the primary key.
	recoveryChallengeBytes = 32

	// recoveryAuthKind is the NIP-98-style ephemeral event kind the client signs,
	// matching the kind already used by the NIP-07 login path.
	recoveryAuthKind = 27235
)

type recoveryChallengeRequest struct {
	Username string `json:"username"`
	// PowEvent is a JSON-serialised Nostr event that demonstrates proof of work
	// at the difficulty configured in cfg.Recovery.PoWDifficulty. Ignored when
	// that difficulty is 0 (the default — dark until a client mines it).
	PowEvent string `json:"pow_event,omitempty"`
}

type recoveryChallengeResponse struct {
	Challenge string    `json:"challenge"`
	ExpiresAt time.Time `json:"expires_at"`
}

type recoveryCompleteRequest struct {
	Challenge   string `json:"challenge"`
	SignedEvent string `json:"signed_event"`
	NewPassword string `json:"new_password"`
	// Nsec optionally restores the proven key in the same step. The caller has
	// just demonstrated possession by signing, so this reveals nothing new to the
	// server -- which already stores this key, wrapped -- but it is optional
	// because sending key material is a bigger act than signing a nonce. Without
	// it, recovery restores account access and the key is re-imported later
	// through the ordinary authenticated path.
	Nsec string `json:"nsec,omitempty"`
}

type recoveryCompleteResponse struct {
	Message              string   `json:"message"`
	KeysRecovered        int      `json:"keys_recovered"`
	KeysNeedingReimport  []string `json:"keys_needing_reimport,omitempty"`
	VaultCredentialReset bool     `json:"vault_credential_reset"`
}

// handleRecoveryChallenge issues a single-use nonce for the named account.
//
// It answers identically whether or not the account exists. An endpoint that
// only issues challenges for real usernames is a username oracle, and this one
// is unauthenticated by necessity. The unknown-account challenge is a real random
// value that simply matches no stored row, so it fails at the next step exactly
// as a wrong signature would.
//
// Four independent rate-limiting layers (see RecoveryConfig) are applied before
// any account lookup. All must pass; none is a fallback for another. Limiter
// backend failures are fail-open: they log at WARN and let the request proceed.
// A limiter that fails closed is a recovery outage for exactly the users this
// flow exists to rescue.
func (h *Handler) handleRecoveryChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req recoveryChallengeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	username := strings.TrimSpace(strings.ToLower(req.Username))
	if username == "" {
		h.errorResponse(w, http.StatusBadRequest, "username is required")
		return
	}

	// --- Layer 1: Proof of Work (skipped when PoWDifficulty == 0) ---
	if h.config.Recovery.PoWDifficulty > 0 {
		if req.PowEvent == "" {
			h.errorResponse(w, http.StatusBadRequest,
				fmt.Sprintf("pow_event is required (target difficulty: %d bits)", h.config.Recovery.PoWDifficulty))
			return
		}
		var ev nostr.Event
		if err := json.Unmarshal([]byte(req.PowEvent), &ev); err != nil {
			h.errorResponse(w, http.StatusBadRequest, "pow_event: not a valid nostr event")
			return
		}
		// Timestamp must be within ±5 minutes so a mined event cannot be reused
		// across multiple recovery windows or stockpiled far in advance.
		if age := time.Since(ev.CreatedAt.Time()); age > 5*time.Minute || age < -5*time.Minute {
			h.errorResponse(w, http.StatusBadRequest, "pow_event: timestamp outside the ±5 minute window")
			return
		}
		// The event must bind the username it was mined for.  Without this a
		// single mined event would be usable against any account.
		hasUsernameTag := false
		for _, tag := range ev.Tags {
			if len(tag) >= 2 && tag[0] == "u" && tag[1] == username {
				hasUsernameTag = true
				break
			}
		}
		if !hasUsernameTag {
			h.errorResponse(w, http.StatusBadRequest, "pow_event: missing [\"u\", <username>] tag")
			return
		}
		// CommittedDifficulty checks the nonce tag's committed target against the
		// actual leading-zero count in the event ID.  It returns 0 when the target
		// overstates the work, so an underpowered event is safely rejected.
		// Signature is intentionally NOT required: PoW is over the event ID, and
		// requiring a signature would demand a key the caller may not have loaded.
		if got := nip13.CommittedDifficulty(&ev); got < h.config.Recovery.PoWDifficulty {
			h.errorResponse(w, http.StatusBadRequest,
				fmt.Sprintf("insufficient proof of work: got %d bits, need %d", got, h.config.Recovery.PoWDifficulty))
			return
		}
	}

	ctx := r.Context()
	lim := h.limiter // may be nil in tests / single-replica deploys without CACHE_URL

	// --- Layer 2: Global limit ---
	// The absolute backstop on row growth regardless of attacker shape.
	// Deliberately generous: a tight global limit is also a global denial surface.
	if lim != nil {
		allowed, err := lim.Allow(ctx, "recovery:global", h.config.Recovery.GlobalLimit, h.config.Recovery.GlobalWindow)
		if err != nil {
			slog.Warn("recovery rate limiter error (global)", "error", err)
		}
		if !allowed {
			h.errorResponse(w, http.StatusTooManyRequests, "too many requests")
			return
		}
	}

	// --- Layer 3: Per-username limit ---
	// Counted on the requested STRING — before and regardless of whether the
	// account exists.  Counting only real accounts would make a tripped limit
	// prove the account exists, reintroducing the enumeration oracle this
	// endpoint is built to avoid.
	if lim != nil {
		allowed, err := lim.Allow(ctx,
			"recovery:user:"+ratelimit.HashKey(username),
			h.config.Recovery.PerUsernameLimit,
			h.config.Recovery.PerUsernameWindow,
		)
		if err != nil {
			slog.Warn("recovery rate limiter error (per-username)", "error", err)
		}
		if !allowed {
			h.errorResponse(w, http.StatusTooManyRequests, "too many requests")
			return
		}
	}

	// --- Layer 4: Per-IP limit ---
	// Only active when TrustedProxyHeader is set.  RemoteAddr is never used
	// as a fallback: behind the Cloudflare tunnel it is the tunnel pod, so
	// every client on earth would share one bucket.  A missing or empty header
	// value on an individual request skips this layer for that request (the
	// proxy may legitimately not forward the header for internal traffic).
	if lim != nil && h.config.Recovery.TrustedProxyHeader != "" && h.ipHasher != nil {
		rawHeader := r.Header.Get(h.config.Recovery.TrustedProxyHeader)
		if rawHeader != "" {
			ip := strings.TrimSpace(strings.SplitN(rawHeader, ",", 2)[0])
			if ip != "" {
				allowed, err := lim.Allow(ctx,
					h.ipHasher.Key(ip),
					h.config.Recovery.PerIPLimit,
					h.config.Recovery.PerIPWindow,
				)
				if err != nil {
					slog.Warn("recovery rate limiter error (per-IP)", "error", err)
				}
				if !allowed {
					h.errorResponse(w, http.StatusTooManyRequests, "too many requests")
					return
				}
			}
		}
	}

	nonce, err := randomHex(recoveryChallengeBytes)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to generate challenge")
		return
	}
	now := time.Now()
	expiresAt := now.Add(recoveryChallengeTTL)

	// Persist only for a real account. For an unknown one we still return a
	// well-formed challenge, so the response is indistinguishable.
	if user, err := h.storage.GetUserByUsername(r.Context(), username); err == nil {
		record := &storage.RecoveryChallenge{
			ID: nonce, UserID: user.ID, ExpiresAt: expiresAt, CreatedAt: now,
		}
		if err := h.storage.CreateRecoveryChallenge(r.Context(), record); err != nil {
			slog.Error("failed to store recovery challenge", "error", err, "user_id", user.ID)
			h.errorResponse(w, http.StatusInternalServerError, "failed to issue challenge")
			return
		}
		slog.Info("recovery challenge issued", "user_id", user.ID, "username", username)
	} else {
		slog.Info("recovery challenge requested for unknown account", "username", username)
	}

	h.jsonResponse(w, http.StatusOK, recoveryChallengeResponse{Challenge: nonce, ExpiresAt: expiresAt})
}

// handleRecoveryComplete verifies the signed challenge and resets the password.
func (h *Handler) handleRecoveryComplete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req recoveryCompleteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.errorResponse(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.NewPassword) < 8 {
		h.errorResponse(w, http.StatusBadRequest, "new password must be at least 8 characters")
		return
	}

	// Consume first. The challenge is spent by the attempt, not by the attempt
	// succeeding, so a failed proof cannot be retried against the same nonce.
	record, err := h.storage.ConsumeRecoveryChallenge(r.Context(), req.Challenge)
	if err != nil {
		slog.Warn("recovery attempt with unusable challenge", "error", err)
		h.errorResponse(w, http.StatusUnauthorized, "invalid or expired challenge")
		return
	}

	pubkey, err := verifyRecoveryProof(req.SignedEvent, req.Challenge)
	if err != nil {
		slog.Warn("recovery proof rejected", "user_id", record.UserID, "error", err)
		h.errorResponse(w, http.StatusUnauthorized, "invalid proof of key possession")
		return
	}

	// Opt-out is checked only AFTER a valid proof. Refusing earlier would tell an
	// unauthenticated caller which accounts have recovery disabled; by this point
	// they have already demonstrated they hold the account's identity key, so the
	// fact is worth nothing to them.
	if h.recoveryDisabled(r.Context(), record.UserID) {
		slog.Info("recovery refused: disabled on this account", "user_id", record.UserID)
		h.errorResponse(w, http.StatusForbidden, "nsec recovery is disabled for this account")
		return
	}

	// The signature proves possession of *a* key. It must be this account's
	// IDENTITY key, not merely one of its keys.
	//
	// Accepting any key would make an account only as strong as its weakest one:
	// compromise a throwaway key added for some app, and you reset the password,
	// which resets the Vault userpass credential, which hands over every
	// vault:-wrapped key on the account. Recovery authority is account authority,
	// so it belongs to the key that IS the account.
	//
	// resolveSigningPubkey is the same resolver reconcilePlatformIdentity uses to
	// pick the sole platform identity under Option A. Reusing it means recovery
	// authority and platform identity can never drift apart.
	keys, err := h.storage.ListKeys(r.Context(), record.UserID)
	if err != nil {
		slog.Error("recovery: failed to list keys", "error", err, "user_id", record.UserID)
		h.errorResponse(w, http.StatusInternalServerError, "recovery failed")
		return
	}
	identityPubkey, hasIdentity := h.resolveSigningPubkey(r.Context(), record.UserID)
	if !hasIdentity || subtle.ConstantTimeCompare([]byte(identityPubkey), []byte(pubkey)) != 1 {
		slog.Warn("recovery proof did not come from the account's identity key",
			"user_id", record.UserID, "proved", safePubkeyPrefix(pubkey),
			"owns_some_key", ownsPubkey(keys, pubkey))
		h.errorResponse(w, http.StatusUnauthorized, "invalid proof of key possession")
		return
	}

	user, err := h.storage.GetUser(r.Context(), record.UserID)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "recovery failed")
		return
	}

	// Restore the proven key first, if the caller supplied it. Doing this before
	// the password is committed keeps the failure mode boring: on error the
	// account still has its old password and nothing has been half-migrated.
	recovered := 0
	if strings.TrimSpace(req.Nsec) != "" {
		priv, err := normalizePrivateKey(req.Nsec)
		if err != nil {
			h.errorResponse(w, http.StatusBadRequest, "invalid nsec")
			return
		}
		derived, err := nostr.GetPublicKey(priv)
		if err != nil || subtle.ConstantTimeCompare([]byte(derived), []byte(pubkey)) != 1 {
			h.errorResponse(w, http.StatusBadRequest, "nsec does not match the key you proved")
			return
		}
		if err := h.rewrapKeyUnderPassphrase(r.Context(), keys, pubkey, priv, req.NewPassword); err != nil {
			slog.Error("recovery: failed to restore proven key", "error", err, "user_id", user.ID)
			h.errorResponse(w, http.StatusInternalServerError, "failed to restore key material")
			return
		}
		recovered = 1
	}

	hash, err := auth.HashPassword(req.NewPassword, h.authConfig.BcryptCost)
	if err != nil {
		h.errorResponse(w, http.StatusInternalServerError, "failed to hash password")
		return
	}
	user.PasswordHash = hash
	// A recovery is also the end of a lockout: the holder of the key has proven
	// themselves, and leaving the counter set would lock them straight back out.
	user.FailedLoginAttempts = 0
	user.LockedUntil = nil
	if err := h.storage.UpdateUser(r.Context(), user); err != nil {
		slog.Error("recovery: failed to update password", "error", err, "user_id", user.ID)
		h.errorResponse(w, http.StatusInternalServerError, "failed to update password")
		return
	}

	// Vault's userpass copy must follow, or the account authenticates to the
	// signer with the new password and to Vault with the old one -- which would
	// strand every vault: key behind a credential nobody holds.
	vaultReset := h.resetVaultCredential(r.Context(), user.ID, req.NewPassword)

	// Anything still passphrase-wrapped was sealed with the forgotten password.
	// Name those keys plainly rather than let the user discover them missing.
	var stranded []string
	for _, k := range keys {
		if k.Pubkey == pubkey && recovered == 1 {
			continue
		}
		if crypto.IsPassphraseEncrypted(k.EncryptedNsec) {
			stranded = append(stranded, k.Pubkey)
		}
	}

	slog.Info("account recovered via nsec proof",
		"user_id", user.ID, "username", user.Username,
		"proven_pubkey", safePubkeyPrefix(pubkey),
		"keys_recovered", recovered, "keys_stranded", len(stranded),
		"vault_credential_reset", vaultReset)

	h.jsonResponse(w, http.StatusOK, recoveryCompleteResponse{
		Message:              "password reset; sign in with your new password",
		KeysRecovered:        recovered,
		KeysNeedingReimport:  stranded,
		VaultCredentialReset: vaultReset,
	})
}

// verifyRecoveryProof checks the signed event and returns the pubkey it proves.
//
// Every check matters: the event must carry the challenge WE issued (binding the
// proof to this attempt), be the expected ephemeral kind, be recent, and carry a
// valid BIP-340 signature over its own id.
func verifyRecoveryProof(signedEvent, challenge string) (string, error) {
	if strings.TrimSpace(signedEvent) == "" {
		return "", fmt.Errorf("no signed event supplied")
	}
	var ev nostr.Event
	if err := json.Unmarshal([]byte(signedEvent), &ev); err != nil {
		return "", fmt.Errorf("signed_event is not a nostr event: %w", err)
	}
	if ev.Kind != recoveryAuthKind {
		return "", fmt.Errorf("unexpected event kind %d", ev.Kind)
	}

	// Constant-time so the comparison cannot be used to grind out a valid nonce.
	var matched bool
	for _, tag := range ev.Tags {
		if len(tag) >= 2 && tag[0] == "challenge" &&
			subtle.ConstantTimeCompare([]byte(tag[1]), []byte(challenge)) == 1 {
			matched = true
			break
		}
	}
	if !matched {
		return "", fmt.Errorf("signed event does not carry the issued challenge")
	}

	// The challenge already bounds replay; this rejects a signature minted long
	// before it could have been requested, which would indicate a confused client.
	if age := time.Since(ev.CreatedAt.Time()); age > recoveryChallengeTTL || age < -recoveryChallengeTTL {
		return "", fmt.Errorf("signed event timestamp is outside the acceptable window")
	}

	ok, err := ev.CheckSignature()
	if err != nil || !ok {
		return "", fmt.Errorf("invalid signature")
	}
	return ev.PubKey, nil
}

// recoveryOptOutKey namespaces the per-account opt-out in the settings table.
// A per-user boolean does not justify a column plus the six scan sites that come
// with it on signer_web_accounts; the settings row is a smaller surface with the
// same fail-open behaviour on a read error (absent == enabled), which matches the
// default every existing account already has.
func recoveryOptOutKey(userID string) string {
	return "recovery_nsec_disabled:" + userID
}

// recoveryDisabled reports whether the account has opted out of nsec recovery.
//
// Reads that fail are treated as "not disabled". That is the honest default: the
// alternative -- failing closed on a storage blip -- would deny recovery to users
// who never opted out, which is the exact lockout this whole feature exists to
// prevent. The opt-out protects against a stolen nsec; a storage error is not
// that adversary.
func (h *Handler) recoveryDisabled(ctx context.Context, userID string) bool {
	v, err := h.storage.GetSetting(ctx, recoveryOptOutKey(userID))
	if err != nil {
		return false
	}
	return v == "true"
}

// handleRecoverySettings reads or sets the caller's nsec-recovery opt-out.
// Authenticated: only the account holder can change their own posture, and
// turning recovery back ON must not be something a recovery flow can do to
// itself.
//
//	GET  /api/v1/users/recovery -> {nsec_recovery_enabled}
//	PUT  /api/v1/users/recovery {enabled: bool}
func (h *Handler) handleRecoverySettings(w http.ResponseWriter, r *http.Request) {
	claims, err := h.validateAuthHeader(r)
	if err != nil {
		h.errorResponse(w, http.StatusUnauthorized, "invalid or missing token")
		return
	}

	switch r.Method {
	case http.MethodGet:
		h.jsonResponse(w, http.StatusOK, map[string]bool{
			"nsec_recovery_enabled": !h.recoveryDisabled(r.Context(), claims.UserID),
		})
	case http.MethodPut:
		var req struct {
			Enabled *bool `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Enabled == nil {
			h.errorResponse(w, http.StatusBadRequest, "enabled (bool) is required")
			return
		}
		value := "false"
		if !*req.Enabled {
			value = "true"
		}
		if err := h.storage.SetSetting(r.Context(), recoveryOptOutKey(claims.UserID), value); err != nil {
			slog.Error("failed to persist recovery preference", "error", err, "user_id", claims.UserID)
			h.errorResponse(w, http.StatusInternalServerError, "failed to save preference")
			return
		}
		slog.Info("nsec recovery preference changed", "user_id", claims.UserID, "enabled", *req.Enabled)
		h.jsonResponse(w, http.StatusOK, map[string]bool{"nsec_recovery_enabled": *req.Enabled})
	default:
		h.errorResponse(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

// ownsPubkey reports whether the pubkey belongs to one of the account's keys.
// Retained for diagnostics: the authorization check requires the identity key
// specifically, and knowing whether a rejected proof at least belonged to the
// account distinguishes a stolen secondary key from an unrelated one.
func ownsPubkey(keys []*storage.Key, pubkey string) bool {
	for _, k := range keys {
		if subtle.ConstantTimeCompare([]byte(k.Pubkey), []byte(pubkey)) == 1 {
			return true
		}
	}
	return false
}

// rewrapKeyUnderPassphrase re-wraps one key under the new passphrase from
// plaintext the caller supplied, and loads it into the signer runtime.
func (h *Handler) rewrapKeyUnderPassphrase(ctx context.Context, keys []*storage.Key, pubkey, privateKey, passphrase string) error {
	var target *storage.Key
	for _, k := range keys {
		if k.Pubkey == pubkey {
			target = k
			break
		}
	}
	if target == nil {
		return fmt.Errorf("key not found for pubkey")
	}

	pe, err := crypto.NewPassphraseEncryptor(passphrase)
	if err != nil {
		return fmt.Errorf("build passphrase encryptor: %w", err)
	}
	ciphertext, err := pe.Encrypt(privateKey)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	if err := h.storage.UpdateKeyEncryption(ctx, target.ID, ciphertext, string(crypto.EncryptionMethodPassphrase)); err != nil {
		return fmt.Errorf("persist: %w", err)
	}

	if target.IsProxy() {
		h.signer.RegisterProxyKey(target.Pubkey, privateKey, target.BunkerURI)
	} else {
		h.signer.RegisterKey(target.Pubkey, privateKey)
	}
	return nil
}

// resetVaultCredential updates the account's Vault userpass password using the
// signer's own token. Reported rather than fatal: the password reset itself has
// already succeeded, and failing the request here would leave the caller unsure
// which half applied. A stale Vault credential surfaces as vault: keys failing to
// load at login, which the response already warns about.
func (h *Handler) resetVaultCredential(ctx context.Context, userID, newPassword string) bool {
	if h.vaultClient == nil || !h.config.Vault.Enabled {
		return false
	}
	if err := h.vaultClient.UpdateUserpassPassword(ctx, userID, newPassword); err != nil {
		slog.Error("recovery: failed to reset vault userpass credential; vault-wrapped keys will not load until this is fixed",
			"error", err, "user_id", userID)
		return false
	}
	return true
}

// normalizePrivateKey accepts an nsec or raw hex and returns 64-char hex.
func normalizePrivateKey(in string) (string, error) {
	s := strings.TrimSpace(in)
	if strings.HasPrefix(s, "nsec1") {
		prefix, value, err := nip19.Decode(s)
		if err != nil || prefix != "nsec" {
			return "", fmt.Errorf("invalid nsec")
		}
		hexKey, ok := value.(string)
		if !ok {
			return "", fmt.Errorf("invalid nsec payload")
		}
		return hexKey, nil
	}
	if len(s) != 64 {
		return "", fmt.Errorf("private key must be nsec or 64 hex characters")
	}
	if _, err := hex.DecodeString(s); err != nil {
		return "", fmt.Errorf("private key is not valid hex")
	}
	return s, nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func safePubkeyPrefix(pubkey string) string {
	if len(pubkey) >= 16 {
		return pubkey[:16] + "..."
	}
	return pubkey
}
