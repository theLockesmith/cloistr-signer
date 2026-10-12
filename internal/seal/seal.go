// Package seal implements "stay signed in": after a user unlocks their key, the
// signer can seal the decrypted key and store the sealed copy (in Postgres) with an
// expiry, so that any replica can restore it after a deploy without the user typing
// their password again. This is what lets outside NIP-46 apps keep working across a
// signer rollout.
//
// Trust line, stated plainly: while a seal exists and has not expired, the signer can
// recover that user's key on its own (with the sealing key: Vault transit or a key
// file). That is the operator-approved exception to "only the user can unlock". It is
// bounded by the expiry the user picked, enforced server-side, and revocable (sign-out
// deletes the seal; revoke-all deletes every seal for the user).
//
// Every seal is bound to Binding{Pubkey, SessionID}. The binding is mixed into the
// key derivation AND used as AEAD associated data, so a sealed blob copied onto
// another account's row, or another session's row, fails to open.
//
// Modes (SESSION_SEALER):
//
//	vault    Vault transit, derived key with the binding as context. The sealing key
//	         never leaves Vault, so a DB copy alone cannot unseal.
//	keyfile  a 32-byte key in a 0600 file readable only by the signer. Keep it on a
//	         different volume from the database: a DB copy alone cannot unseal.
//	none     sealing disabled; only "this session only" is offered (today's behaviour).
//
// Independently of the mode, a user can opt into split sealing (see split.go): the
// sealing key is split between the server and the user's browser, so neither the DB
// nor the server alone can unseal.
package seal

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Mode names, as configured in SESSION_SEALER and stored on each seal row.
const (
	ModeVault   = "vault"
	ModeKeyfile = "keyfile"
	ModeNone    = "none"
	ModeSplit   = "split"
)

var (
	// ErrDisabled is returned by the none sealer: stay-signed-in is off.
	ErrDisabled = errors.New("seal: sealing disabled (SESSION_SEALER=none)")
	// ErrOpen means a seal could not be opened: wrong binding, wrong key, tampered
	// or truncated blob. Deliberately one error for all of them.
	ErrOpen = errors.New("seal: cannot open sealed key")
)

// Binding is what a seal is bound to. Both fields are required.
type Binding struct {
	Pubkey    string // hex pubkey of the sealed key
	SessionID string // the sign-in session the seal belongs to
}

func (b Binding) validate() error {
	if b.Pubkey == "" || b.SessionID == "" {
		return errors.New("seal: binding needs both pubkey and session id")
	}
	return nil
}

// Bytes is the canonical, unambiguous encoding of the binding (length-prefixed, so
// ("ab","c") and ("a","bc") differ). Used as AEAD associated data, HKDF info and the
// Vault derivation context.
func (b Binding) Bytes() []byte {
	const label = "cloistr-signer/session-seal/v1"
	out := make([]byte, 0, len(label)+8+len(b.Pubkey)+len(b.SessionID))
	out = append(out, label...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(b.Pubkey)))
	out = append(out, b.Pubkey...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(b.SessionID)))
	out = append(out, b.SessionID...)
	return out
}

// Sealer seals and opens decrypted user keys.
type Sealer interface {
	// Mode is the configured mode name (vault, keyfile, none).
	Mode() string
	// Enabled reports whether durable seals can be made at all.
	Enabled() bool
	Seal(ctx context.Context, plaintext []byte, b Binding) ([]byte, error)
	Open(ctx context.Context, sealed []byte, b Binding) ([]byte, error)
}

// None is the disabled sealer.
type None struct{}

func (None) Mode() string  { return ModeNone }
func (None) Enabled() bool { return false }
func (None) Seal(context.Context, []byte, Binding) ([]byte, error) {
	return nil, ErrDisabled
}
func (None) Open(context.Context, []byte, Binding) ([]byte, error) {
	return nil, ErrDisabled
}

// DetectMode names the mode a sealed blob was made in, from its prefix ("" if
// unknown). Lets a replica open old seals after the operator changes SESSION_SEALER,
// or report clearly that it can't.
func DetectMode(blob []byte) string {
	switch {
	case bytes.HasPrefix(blob, keyfilePrefix):
		return ModeKeyfile
	case bytes.HasPrefix(blob, splitPrefix):
		return ModeSplit
	case bytes.HasPrefix(blob, vaultPrefix):
		return ModeVault
	}
	return ""
}

// aeadSeal derives a per-binding AES-256-GCM key from ikm with HKDF-SHA256 and
// encrypts plaintext with the binding as associated data. Output: nonce || ct.
func aeadSeal(ikm []byte, purpose string, plaintext []byte, b Binding) ([]byte, error) {
	gcm, err := derivedGCM(ikm, purpose, b)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("seal: nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, b.Bytes()), nil
}

func aeadOpen(ikm []byte, purpose string, blob []byte, b Binding) ([]byte, error) {
	gcm, err := derivedGCM(ikm, purpose, b)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize()+gcm.Overhead() {
		return nil, ErrOpen
	}
	nonce, ct := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, ct, b.Bytes())
	if err != nil {
		return nil, ErrOpen
	}
	return pt, nil
}

func derivedGCM(ikm []byte, purpose string, b Binding) (cipher.AEAD, error) {
	info := append([]byte(purpose+"\x00"), b.Bytes()...)
	key, err := hkdf.Key(sha256.New, ikm, nil, string(info), 32)
	if err != nil {
		return nil, fmt.Errorf("seal: hkdf: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
