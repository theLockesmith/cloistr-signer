package seal

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// DefaultVaultKey is the transit key seals are made under. It is created with
// derived=true, so the binding is the key-derivation context: a ciphertext opens only
// under the exact pubkey + session it was sealed for.
const DefaultVaultKey = "cloistr-signer-session-seal"

// vaultPrefix marks Vault-sealed blobs: "vt1:" || "vault:vN:...".
var vaultPrefix = []byte("vt1:")

// Transit is the part of the Vault client the vault sealer uses. The signer's own
// token is used (not a user's), which is why the seal can be opened with no user
// present; see the package doc for the trust line.
type Transit interface {
	TransitEncryptDerived(ctx context.Context, key, plaintextB64, contextB64 string) (string, error)
	TransitDecryptDerived(ctx context.Context, key, ciphertext, contextB64 string) (string, error)
}

// Vault seals under a Vault transit key. The sealing key never leaves Vault.
type Vault struct {
	t   Transit
	key string
}

// NewVault builds a vault sealer on transit key (DefaultVaultKey if empty).
func NewVault(t Transit, key string) (*Vault, error) {
	if t == nil {
		return nil, errors.New("seal: vault mode needs a Vault client (VAULT_ADDR and a token)")
	}
	if key == "" {
		key = DefaultVaultKey
	}
	return &Vault{t: t, key: key}, nil
}

func (*Vault) Mode() string  { return ModeVault }
func (*Vault) Enabled() bool { return true }

// Key is the transit key name.
func (v *Vault) Key() string { return v.key }

// Context is the base64 derivation context for b (what transit's rewrap needs too).
func Context(b Binding) string { return base64.StdEncoding.EncodeToString(b.Bytes()) }

func (v *Vault) Seal(ctx context.Context, plaintext []byte, b Binding) ([]byte, error) {
	if err := b.validate(); err != nil {
		return nil, err
	}
	ct, err := v.t.TransitEncryptDerived(ctx, v.key, base64.StdEncoding.EncodeToString(plaintext), Context(b))
	if err != nil {
		return nil, fmt.Errorf("seal: vault encrypt: %w", err)
	}
	return append(bytes.Clone(vaultPrefix), ct...), nil
}

func (v *Vault) Open(ctx context.Context, sealed []byte, b Binding) ([]byte, error) {
	if err := b.validate(); err != nil {
		return nil, err
	}
	if !bytes.HasPrefix(sealed, vaultPrefix) {
		return nil, ErrOpen
	}
	ptB64, err := v.t.TransitDecryptDerived(ctx, v.key, string(sealed[len(vaultPrefix):]), Context(b))
	if err != nil {
		// A Vault 4xx (wrong context, too-old version, tampered) is an open failure;
		// anything else (Vault down, timeout) is reported as-is so callers can tell
		// "this seal is bad" from "try again later".
		if strings.Contains(err.Error(), "status 400") || strings.Contains(err.Error(), "status 404") {
			return nil, fmt.Errorf("%w: %v", ErrOpen, err)
		}
		return nil, fmt.Errorf("seal: vault decrypt: %w", err)
	}
	pt, err := base64.StdEncoding.DecodeString(ptB64)
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

// VaultKeyVersion returns the transit key version a vault-sealed blob was made under,
// or 0 if blob is not a vault seal. Used by rotation to find seals to rewrap.
func VaultKeyVersion(blob []byte) int {
	s, ok := strings.CutPrefix(string(blob), string(vaultPrefix))
	if !ok {
		return 0
	}
	s, ok = strings.CutPrefix(s, "vault:v")
	if !ok {
		return 0
	}
	n, _, _ := strings.Cut(s, ":")
	v, err := strconv.Atoi(n)
	if err != nil || v < 1 {
		return 0
	}
	return v
}

// VaultCiphertext strips the blob prefix, giving the raw "vault:vN:..." ciphertext.
func VaultCiphertext(blob []byte) (string, bool) {
	s, ok := strings.CutPrefix(string(blob), string(vaultPrefix))
	return s, ok
}

// VaultBlob wraps a raw transit ciphertext (e.g. from rewrap) as a stored blob.
func VaultBlob(ciphertext string) []byte {
	return append(bytes.Clone(vaultPrefix), ciphertext...)
}
