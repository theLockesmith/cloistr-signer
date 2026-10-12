package seal

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

var (
	alice  = Binding{Pubkey: "aa11", SessionID: "sess-1"}
	secret = []byte("0123456789abcdef0123456789abcdef") // stands in for a nostr secret key
)

func newKeyfile(t *testing.T) (*Keyfile, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keys", "session-seal.key")
	k, err := LoadKeyfile(path, true)
	if err != nil {
		t.Fatalf("LoadKeyfile(create): %v", err)
	}
	return k, path
}

func TestKeyfileRoundTrip(t *testing.T) {
	k, path := newKeyfile(t)
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("created keyfile mode = %o, want 600", st.Mode().Perm())
	}
	blob, err := k.Seal(context.Background(), secret, alice)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, secret) {
		t.Fatal("sealed blob contains the plaintext")
	}
	got, err := k.Open(context.Background(), blob, alice)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("round trip changed the plaintext")
	}

	// Reloading the same file opens seals made before (a restart / another replica).
	k2, err := LoadKeyfile(path, false)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := k2.Open(context.Background(), blob, alice); err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("reloaded keyfile cannot open: %v", err)
	}
}

// A blob swapped onto another account (pubkey) or another session fails to open.
func TestKeyfileSwappedBlobFails(t *testing.T) {
	k, _ := newKeyfile(t)
	blob, err := k.Seal(context.Background(), secret, alice)
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string]Binding{
		"other pubkey":  {Pubkey: "bb22", SessionID: alice.SessionID},
		"other session": {Pubkey: alice.Pubkey, SessionID: "sess-2"},
		// Length-prefixing: concatenation-equal bindings must still differ.
		"shifted boundary": {Pubkey: "aa11s", SessionID: "ess-1"},
	} {
		if _, err := k.Open(context.Background(), blob, b); !errors.Is(err, ErrOpen) {
			t.Errorf("%s: Open err = %v, want ErrOpen", name, err)
		}
	}
}

func TestKeyfileTamperAndTruncationFail(t *testing.T) {
	k, _ := newKeyfile(t)
	blob, _ := k.Seal(context.Background(), secret, alice)
	for i := range blob {
		bad := bytes.Clone(blob)
		bad[i] ^= 0x01
		if _, err := k.Open(context.Background(), bad, alice); err == nil {
			t.Fatalf("flipping byte %d still opened", i)
		}
	}
	for _, n := range []int{0, 3, 11, len(blob) - 1} {
		if _, err := k.Open(context.Background(), blob[:n], alice); err == nil {
			t.Fatalf("truncation to %d bytes still opened", n)
		}
	}
}

// A DB copy alone cannot unseal: without the key file there is nothing that opens it,
// and a different key file is refused.
func TestKeyfileDBCopyAloneCannotUnseal(t *testing.T) {
	k, _ := newKeyfile(t)
	blob, _ := k.Seal(context.Background(), secret, alice)
	other, _ := newKeyfile(t)
	if _, err := other.Open(context.Background(), blob, alice); !errors.Is(err, ErrWrongKeyfile) {
		t.Fatalf("other keyfile Open err = %v, want ErrWrongKeyfile", err)
	}
}

func TestKeyfileRefusesLoosePermissions(t *testing.T) {
	_, path := newKeyfile(t)
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyfile(path, false); err == nil {
		t.Fatal("loaded a group-readable keyfile")
	}
}

func TestKeyfileMissingWithoutCreate(t *testing.T) {
	if _, err := LoadKeyfile(filepath.Join(t.TempDir(), "nope"), false); err == nil {
		t.Fatal("missing keyfile without create should fail")
	}
	if _, err := LoadKeyfile("", true); err == nil {
		t.Fatal("empty path should fail")
	}
}

func TestBindingRequired(t *testing.T) {
	k, _ := newKeyfile(t)
	if _, err := k.Seal(context.Background(), secret, Binding{Pubkey: "aa"}); err == nil {
		t.Fatal("sealed with no session id")
	}
	if _, err := SplitSeal(secret, mustHalf(t), Binding{SessionID: "s"}); err == nil {
		t.Fatal("split-sealed with no pubkey")
	}
}

func TestNoneSealer(t *testing.T) {
	var s Sealer = None{}
	if s.Enabled() || s.Mode() != ModeNone {
		t.Fatal("none sealer must report disabled")
	}
	if _, err := s.Seal(context.Background(), secret, alice); !errors.Is(err, ErrDisabled) {
		t.Fatalf("Seal err = %v, want ErrDisabled", err)
	}
	if _, err := s.Open(context.Background(), []byte("x"), alice); !errors.Is(err, ErrDisabled) {
		t.Fatalf("Open err = %v, want ErrDisabled", err)
	}
}

// Split mode unseals only with the browser half: the DB row (which holds the server
// half) alone cannot open it, nor can a wrong half.
func TestSplitOnlyWithBrowserHalf(t *testing.T) {
	half := mustHalf(t)
	blob, err := SplitSeal(secret, half, alice)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SplitSeal(secret, half[:5], alice); err == nil {
		t.Fatal("sealed with a short browser half")
	}
	if len(half) != SplitHalfLen {
		t.Fatalf("browser half is %d bytes, want %d", len(half), SplitHalfLen)
	}
	if bytes.Contains(blob, half) {
		t.Fatal("DB blob contains the browser half")
	}
	got, err := SplitOpen(blob, half, alice)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("SplitOpen with the right half: %v", err)
	}
	if _, err := SplitOpen(blob, nil, alice); !errors.Is(err, ErrOpen) {
		t.Fatalf("no half: err = %v, want ErrOpen", err)
	}
	if _, err := SplitOpen(blob, make([]byte, SplitHalfLen), alice); !errors.Is(err, ErrOpen) {
		t.Fatalf("zero half: err = %v, want ErrOpen", err)
	}
	wrong := bytes.Clone(half)
	wrong[0] ^= 1
	if _, err := SplitOpen(blob, wrong, alice); !errors.Is(err, ErrOpen) {
		t.Fatalf("wrong half: err = %v, want ErrOpen", err)
	}
	if _, err := SplitOpen(blob, half, Binding{Pubkey: "bb22", SessionID: "sess-1"}); !errors.Is(err, ErrOpen) {
		t.Fatalf("swapped account: err = %v, want ErrOpen", err)
	}
	// One browser half can cover several keys; each seal has its own server half.
	blob2, _ := SplitSeal(secret, half, alice)
	if bytes.Equal(blob[:3+SplitHalfLen], blob2[:3+SplitHalfLen]) {
		t.Fatal("server halves repeat")
	}
	if bytes.Equal(half, mustHalf(t)) {
		t.Fatal("browser halves repeat")
	}
}

func TestDetectMode(t *testing.T) {
	k, _ := newKeyfile(t)
	kb, _ := k.Seal(context.Background(), secret, alice)
	sb, _ := SplitSeal(secret, mustHalf(t), alice)
	cases := map[string][]byte{
		ModeKeyfile: kb,
		ModeSplit:   sb,
		ModeVault:   []byte("vt1:vault:v1:abc"),
		"":          []byte("junk"),
	}
	for want, blob := range cases {
		if got := DetectMode(blob); got != want {
			t.Errorf("DetectMode(%q...) = %q, want %q", blob[:3], got, want)
		}
	}
}

func mustHalf(t *testing.T) []byte {
	t.Helper()
	h, err := NewSplitHalf()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// A symlink to a 0600 key file (how Kubernetes mounts a Secret) loads; a
// group-readable target is refused through the link too.
func TestKeyfileThroughSymlink(t *testing.T) {
	_, path := newKeyfile(t)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyfile(link, false); err != nil {
		t.Fatalf("symlinked 0600 keyfile refused: %v", err)
	}
	_ = os.Chmod(path, 0o644)
	if _, err := LoadKeyfile(link, false); err == nil {
		t.Fatal("group-readable target accepted through a symlink")
	}
}

// Each defense layer, pinned on its own.

// Every seal gets a fresh random nonce.
func TestSealNoncesAreFresh(t *testing.T) {
	ikm := bytes.Repeat([]byte{7}, 32)
	a, err := aeadSeal(ikm, "test", secret, alice)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := aeadSeal(ikm, "test", secret, alice)
	const n = 12 // GCM nonce
	if bytes.Equal(a[:n], b[:n]) || bytes.Equal(a[:n], make([]byte, n)) {
		t.Fatalf("nonce reused or zero: %x / %x", a[:n], b[:n])
	}
}

// The binding is in the HKDF info: a key derived for one binding can't open a
// blob made under another binding's key, even with matching associated data.
func TestBindingInKeyDerivation(t *testing.T) {
	ikm := bytes.Repeat([]byte{7}, 32)
	bob := Binding{Pubkey: "bb22", SessionID: "sess-1"}
	gcm, err := derivedGCM(ikm, "test", alice)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	nonce[0] = 1
	blob := gcm.Seal(bytes.Clone(nonce), nonce, secret, bob.Bytes()) // alice's key, bob's AAD
	if _, err := aeadOpen(ikm, "test", blob, bob); !errors.Is(err, ErrOpen) {
		t.Fatalf("opened with a key derived for another binding: %v", err)
	}
}

// The binding is the associated data: the right key with the wrong AAD fails.
func TestBindingInAssociatedData(t *testing.T) {
	ikm := bytes.Repeat([]byte{7}, 32)
	bob := Binding{Pubkey: "bb22", SessionID: "sess-1"}
	gcm, err := derivedGCM(ikm, "test", bob)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	nonce[0] = 1
	blob := gcm.Seal(bytes.Clone(nonce), nonce, secret, alice.Bytes()) // bob's key, alice's AAD
	if _, err := aeadOpen(ikm, "test", blob, bob); !errors.Is(err, ErrOpen) {
		t.Fatalf("opened with mismatched associated data: %v", err)
	}
}

// The server half is part of the key: change it in the blob and the right browser
// half no longer opens it.
func TestSplitServerHalfInKey(t *testing.T) {
	half := mustHalf(t)
	blob, err := SplitSeal(secret, half, alice)
	if err != nil {
		t.Fatal(err)
	}
	blob[len(splitPrefix)] ^= 1
	if _, err := SplitOpen(blob, half, alice); !errors.Is(err, ErrOpen) {
		t.Fatalf("opened with a changed server half: %v", err)
	}
}

// An all-zero browser half is refused when sealing and when opening, and short or
// truncated input is an open failure, not a panic.
func TestSplitRejectsZeroAndShortInput(t *testing.T) {
	zero := make([]byte, SplitHalfLen)
	if _, err := SplitSeal(secret, zero, alice); !errors.Is(err, ErrOpen) {
		t.Fatalf("sealed under a zero half: %v", err)
	}
	// A blob sealed under a zero half (bypassing SplitSeal) must not open with it.
	server := bytes.Repeat([]byte{9}, SplitHalfLen)
	body, err := aeadSeal(splitIKM(server, zero), splitPurpose, secret, alice)
	if err != nil {
		t.Fatal(err)
	}
	blob := append(append(append([]byte{}, splitPrefix...), server...), body...)
	if _, err := SplitOpen(blob, zero, alice); !errors.Is(err, ErrOpen) {
		t.Fatalf("opened with a zero half: %v", err)
	}
	half := mustHalf(t)
	for _, b := range [][]byte{nil, splitPrefix, blob[:len(splitPrefix)+SplitHalfLen-1], blob[:len(splitPrefix)+SplitHalfLen+3]} {
		if _, err := SplitOpen(b, half, alice); !errors.Is(err, ErrOpen) {
			t.Fatalf("short blob (%d bytes): %v", len(b), err)
		}
	}
	if _, err := SplitOpen(blob, half[:SplitHalfLen-1], alice); !errors.Is(err, ErrOpen) {
		t.Fatalf("short half: %v", err)
	}
}
