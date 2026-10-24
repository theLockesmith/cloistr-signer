package config

import (
	"reflect"
	"testing"
)

// ADMIN_USER_IDS fills AdminUserIDs (trimmed, empties dropped) and nothing
// else: it is not an admin pubkey, so it never turns on admin DMs.
func TestLoad_AdminUserIDs(t *testing.T) {
	t.Setenv("ADMIN_USER_IDS", " acct-1, ,acct-2 ")
	t.Setenv("ADMIN_PUBKEYS", "")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	v := reflect.ValueOf(cfg.Auth).FieldByName("AdminUserIDs")
	if !v.IsValid() {
		t.Fatal("no AdminUserIDs setting")
	}
	if got := v.Interface().([]string); len(got) != 2 || got[0] != "acct-1" || got[1] != "acct-2" {
		t.Fatalf("AdminUserIDs = %q, want [acct-1 acct-2]", got)
	}
	if len(cfg.Auth.AdminPubkeys) != 0 || cfg.Auth.IsAdminPubkey("acct-1") {
		t.Fatalf("AdminPubkeys = %q; an admin account ID must not become an admin pubkey", cfg.Auth.AdminPubkeys)
	}
}
