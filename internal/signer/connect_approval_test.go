package signer

import (
	"context"
	"testing"

	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/config"
	"git.aegis-hq.xyz/coldforge/cloistr-signer/internal/storage"
)

const (
	approvalKeyPubkey    = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	approvalClientPubkey = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
)

func approvalSigner(t *testing.T, keyRequires, globalRequires bool) *Signer {
	t.Helper()
	store := storage.NewMemoryStorage()
	cfg := &config.Config{}
	cfg.Auth.RequireApproval = globalRequires
	if err := store.CreateKey(context.Background(), &storage.Key{
		ID:              approvalKeyPubkey[:16],
		Name:            "approval-key",
		Pubkey:          approvalKeyPubkey,
		RequireApproval: keyRequires,
	}); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	return New(cfg, store, nil, nil, nil, nil, nil)
}

// "Require approval" on a key (or globally) gates NEW clients. A client that
// already holds a grant was approved when the grant was made; sending each of
// its requests back to the approval queue blocks every app the person has
// already let in.
func TestShouldRequireApproval_GrantedClientIsNotReapproved(t *testing.T) {
	ctx := context.Background()
	yes, no := true, false
	grant := func(override *bool) *storage.Permission {
		return &storage.Permission{KeyID: approvalKeyPubkey, UserPubkey: approvalClientPubkey,
			Methods: []string{"*"}, RequireApproval: override}
	}

	cases := []struct {
		name                        string
		keyRequires, globalRequires bool
		perm                        *storage.Permission
		want                        bool
	}{
		{"key requires, granted client", true, false, grant(nil), false},
		{"global requires, granted client", false, true, grant(nil), false},
		{"key requires, unknown client", true, false, nil, true},
		{"global requires, unknown client", false, true, nil, true},
		{"nothing requires, unknown client", false, false, nil, false},
		{"grant asks for per-request approval", false, false, grant(&yes), true},
		{"grant opts out on an approval key", true, false, grant(&no), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := approvalSigner(t, c.keyRequires, c.globalRequires)
			if got := s.shouldRequireApproval(ctx, approvalKeyPubkey, c.perm); got != c.want {
				t.Errorf("shouldRequireApproval = %v, want %v", got, c.want)
			}
		})
	}
}

// NIP-46: a successful connect is answered with "ack". Clients that check for
// it (NDK, and Cloistr Photos' own bunker client) reject anything else, so the
// old {"pubkey":...} reply failed their connect outright.
func TestConnect_RepliesAck(t *testing.T) {
	s := approvalSigner(t, false, false)
	perm := &storage.Permission{KeyID: approvalKeyPubkey, UserPubkey: approvalClientPubkey, Methods: []string{"*"}}
	req := &NIP46Request{ID: "c1", Method: "connect", Params: []string{approvalKeyPubkey}}

	got, err := s.handleRequest(context.Background(), approvalKeyPubkey, "", approvalClientPubkey, req, perm)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if got != "ack" {
		t.Errorf("connect replied %q, want \"ack\"", got)
	}
}
