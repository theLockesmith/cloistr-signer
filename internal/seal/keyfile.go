package seal

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// keyfilePrefix marks keyfile-sealed blobs: "kf1" || fingerprint[8] || nonce || ct.
// The fingerprint names the sealing key, so a seal made under a replaced key file is
// reported as such instead of as a generic open failure.
var keyfilePrefix = []byte("kf1")

const keyfilePurpose = "keyfile"

// ErrWrongKeyfile means the seal was made under a different key file.
var ErrWrongKeyfile = fmt.Errorf("%w: sealed under a different key file", ErrOpen)

// Keyfile seals under a 32-byte key read from a file. The file must not be readable
// by group or others; the docs recommend a different volume from the database,
// because DB + key file together can unseal.
type Keyfile struct {
	key [32]byte
	fp  [8]byte
}

// LoadKeyfile reads the sealing key from path. If the file does not exist and create
// is true, a new random key is written there with mode 0600. The file holds the key
// as 64 hex characters (trailing whitespace allowed).
func LoadKeyfile(path string, create bool) (*Keyfile, error) {
	if path == "" {
		return nil, errors.New("seal: keyfile mode needs SESSION_SEAL_KEYFILE")
	}
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) && create {
		if err := writeNewKeyfile(path); err != nil {
			return nil, err
		}
		f, err = os.Open(path)
	}
	if err != nil {
		return nil, fmt.Errorf("seal: open keyfile: %w", err)
	}
	defer f.Close()
	// Check the file actually opened (a Kubernetes Secret mount is a symlink to
	// it), and read from the same descriptor so it can't be swapped in between.
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("seal: stat keyfile: %w", err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("seal: keyfile %s is not a regular file", path)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("seal: keyfile %s is mode %o; it must not be readable by group or others (chmod 600, or defaultMode 0400 on a Secret volume)", path, st.Mode().Perm())
	}
	data, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return nil, fmt.Errorf("seal: read keyfile: %w", err)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("seal: keyfile %s must hold exactly 32 bytes as 64 hex characters", path)
	}
	k := &Keyfile{}
	copy(k.key[:], raw)
	sum := sha256.Sum256(append([]byte("cloistr-signer/session-seal/keyfile-fp\x00"), raw...))
	copy(k.fp[:], sum[:8])
	return k, nil
}

func writeNewKeyfile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("seal: create keyfile dir: %w", err)
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("seal: create keyfile: %w", err)
	}
	if _, err := f.WriteString(hex.EncodeToString(raw[:]) + "\n"); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func (*Keyfile) Mode() string  { return ModeKeyfile }
func (*Keyfile) Enabled() bool { return true }

// Fingerprint identifies the loaded key (safe to log).
func (k *Keyfile) Fingerprint() string { return hex.EncodeToString(k.fp[:]) }

func (k *Keyfile) Seal(_ context.Context, plaintext []byte, b Binding) ([]byte, error) {
	if err := b.validate(); err != nil {
		return nil, err
	}
	body, err := aeadSeal(k.key[:], keyfilePurpose, plaintext, b)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(keyfilePrefix)+len(k.fp)+len(body))
	out = append(out, keyfilePrefix...)
	out = append(out, k.fp[:]...)
	return append(out, body...), nil
}

func (k *Keyfile) Open(_ context.Context, sealed []byte, b Binding) ([]byte, error) {
	if err := b.validate(); err != nil {
		return nil, err
	}
	n := len(keyfilePrefix) + len(k.fp)
	if len(sealed) < n || !bytes.Equal(sealed[:len(keyfilePrefix)], keyfilePrefix) {
		return nil, ErrOpen
	}
	if !bytes.Equal(sealed[len(keyfilePrefix):n], k.fp[:]) {
		return nil, ErrWrongKeyfile
	}
	return aeadOpen(k.key[:], keyfilePurpose, sealed[n:], b)
}
