package api

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/seal"
)

// Vault seal rotation. The transit key rotates on Vault's own schedule
// (auto_rotate_period on cloistr-signer-session-seal). After each rotation the
// signer re-wraps every live seal to the newest version (inside Vault; the key is
// never decrypted for this) and only then raises min_decryption_version to that
// version. Live sign-ins, including "until I sign out", carry on; any older copy of
// a seal, such as one in a database backup, stops decrypting even for someone who
// can call Vault. A backup taken since the last rotation still opens until the next
// one, so the replay window is one rotation period.

const sealRotationInterval = time.Hour

// sealRotator is the Vault access rotation needs (the signer's own token).
type sealRotator interface {
	TransitKeyVersions(ctx context.Context, key string) (latest, minDecryption int, err error)
	TransitRewrapDerived(ctx context.Context, key, ciphertext, contextB64 string) (string, error)
	TransitSetMinDecryptionVersion(ctx context.Context, key string, v int) error
}

// SetSealRotator enables rotation for the vault sealer. Call after SetSealer.
func (h *Handler) SetSealRotator(r sealRotator) {
	if h.stay != nil {
		h.stay.rotator = r
	}
}

// rotateVaultSeals runs one rotation pass. A no-op unless the sealer is Vault.
// min_decryption_version is raised only when every live seal is already at the
// latest version, so a failed rewrap never locks a user out.
func (h *Handler) rotateVaultSeals(ctx context.Context) error {
	if h.stay == nil || h.stay.rotator == nil {
		return nil
	}
	v, ok := h.stay.sealer.(*seal.Vault)
	if !ok {
		return nil
	}
	// Read the versions BEFORE listing: a seal made after this read is at least
	// at `latest`, so it can't be stranded by raising the minimum to `latest`.
	latest, minDec, err := h.stay.rotator.TransitKeyVersions(ctx, v.Key())
	if err != nil {
		return fmt.Errorf("read seal key versions: %w", err)
	}
	seals, err := h.storage.ListLiveSessionSeals(ctx)
	if err != nil {
		return fmt.Errorf("list seals: %w", err)
	}
	rewrapped, failed, dead := 0, 0, 0
	for _, sl := range seals {
		if sl.Mode != seal.ModeVault {
			continue
		}
		ver := seal.VaultKeyVersion(sl.Sealed)
		if ver < minDec {
			dead++ // already unopenable; swept when it expires
			continue
		}
		if ver >= latest {
			continue
		}
		ct, _ := seal.VaultCiphertext(sl.Sealed)
		b := seal.Binding{Pubkey: sl.Pubkey, SessionID: sl.SessionID}
		nct, err := h.stay.rotator.TransitRewrapDerived(ctx, v.Key(), ct, seal.Context(b))
		if err == nil {
			err = h.storage.UpdateSessionSealBlob(ctx, sl.ID, seal.VaultBlob(nct))
		}
		if err != nil {
			failed++
			slog.Warn("stay signed in: rewrap failed", "seal_id", sl.ID, "error", err)
			continue
		}
		rewrapped++
	}
	if dead > 0 {
		slog.Warn("stay signed in: seals below min_decryption_version can no longer open", "count", dead, "min_decryption_version", minDec)
	}
	if rewrapped > 0 {
		slog.Info("stay signed in: re-wrapped seals to the latest key version", "count", rewrapped, "version", latest)
	}
	if failed > 0 {
		return fmt.Errorf("%d seals failed to rewrap; min_decryption_version left at %d", failed, minDec)
	}
	if minDec < latest {
		if err := h.stay.rotator.TransitSetMinDecryptionVersion(ctx, v.Key(), latest); err != nil {
			return fmt.Errorf("raise min_decryption_version: %w", err)
		}
		slog.Info("stay signed in: raised seal key min_decryption_version; older seal copies no longer open",
			"from", minDec, "to", latest)
	}
	return nil
}
