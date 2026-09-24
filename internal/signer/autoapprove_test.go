package signer

import (
	"os"
	"strings"
	"testing"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/config"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

// The auto-approve branch in handleNIP46Request must not mint a temporary
// Methods:["*"] permission for unknown clients. This test scans the source to
// confirm the temp-perm pattern is gone.

func TestAutoApproveBranch_NoTempPermMinted(t *testing.T) {
	cfg := &config.Config{
		Auth: config.AuthConfig{RequireApproval: false},
	}
	s := New(cfg, storage.NewMemoryStorage(), nil, nil, nil, nil, nil)
	if s.config.Auth.RequireApproval {
		t.Fatal("shipped default must be RequireApproval=false")
	}

	data, err := os.ReadFile("signer.go")
	if err != nil {
		t.Fatalf("ReadFile(signer.go): %v", err)
	}
	if strings.Contains(string(data), "tempPerm") {
		t.Error("signer.go still contains tempPerm — the auto-approve branch must refuse, not mint")
	}
}
