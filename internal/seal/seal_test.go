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
