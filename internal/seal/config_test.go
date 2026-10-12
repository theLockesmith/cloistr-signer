package seal

import (
	"path/filepath"
	"testing"
)

func TestFromConfig(t *testing.T) {
	kf := filepath.Join(t.TempDir(), "k")
	s, err := FromConfig(ModeKeyfile, kf, "", nil)
	if err != nil || s.Mode() != ModeKeyfile {
		t.Fatalf("keyfile: %v %v", s, err)
	}
	if s, err := FromConfig(ModeNone, "", "", nil); err != nil || s.Enabled() {
		t.Fatalf("none: %v %v", s, err)
	}
	if _, err := FromConfig(ModeVault, "", "", nil); err == nil {
		t.Fatal("vault without a client accepted")
	}
	v, err := FromConfig(ModeVault, "", "k2", &fakeTransit{})
	if err != nil || v.Mode() != ModeVault || v.(*Vault).Key() != "k2" {
		t.Fatalf("vault: %v %v", v, err)
	}
	if _, err := FromConfig("rot13", "", "", nil); err == nil {
		t.Fatal("unknown mode accepted")
	}
}
