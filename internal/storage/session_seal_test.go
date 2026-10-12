package storage

import (
	"bytes"
	"context"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// The same contract runs against every backend.

func TestSessionSeals_Memory(t *testing.T) { runSessionSealContract(t, NewMemoryStorage()) }

func TestSessionSeals_SQLite(t *testing.T) {
	s, err := NewSQLiteStorage(filepath.Join(t.TempDir(), "seal.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	runSessionSealContract(t, s)
}

func TestSessionSeals_Postgres(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	_, _ = ps.db.Exec("DELETE FROM signer_session_seals")
	_, _ = ps.db.Exec("DELETE FROM signer_keys WHERE id LIKE 'sealkey-%'")
	_, _ = ps.db.Exec("DELETE FROM signer_web_accounts WHERE id LIKE 'sealuser-%'")
	runSessionSealContract(t, ps)
}

func sealIDs(seals []*SessionSeal) []string {
	out := make([]string, 0, len(seals))
	for _, s := range seals {
		out = append(out, s.ID)
	}
	sort.Strings(out)
	return out
}

func runSessionSealContract(t *testing.T, s Storage) {
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	for _, u := range []string{"sealuser-a", "sealuser-b"} {
		if err := s.CreateUser(ctx, &User{ID: u, Username: u, PasswordHash: "x", Role: "user", CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatalf("CreateUser %s: %v", u, err)
		}
	}
	for i, k := range []struct{ id, owner, pub string }{
		{"sealkey-a1", "sealuser-a", "a1a1"},
		{"sealkey-a2", "sealuser-a", "a2a2"},
		{"sealkey-b1", "sealuser-b", "b1b1"},
	} {
		if err := s.CreateKey(ctx, &Key{ID: k.id, Name: k.id, Pubkey: k.pub + string(rune('0'+i)), OwnerID: k.owner, CreatedAt: now}); err != nil {
			t.Fatalf("CreateKey %s: %v", k.id, err)
		}
	}
	mk := func(id, user, key, pub, sess string, exp time.Time) *SessionSeal {
		return &SessionSeal{ID: id, UserID: user, KeyID: key, Pubkey: pub, SessionID: sess,
			Mode: "keyfile", Sealed: []byte("blob-" + id), ExpiresAt: exp, CreatedAt: now}
	}
	seals := []*SessionSeal{
		mk("s1", "sealuser-a", "sealkey-a1", "a1a10", "sess-a1", now.Add(time.Hour)),
		mk("s2", "sealuser-a", "sealkey-a2", "a2a21", "sess-a1", now.Add(time.Hour)),
		mk("s3", "sealuser-a", "sealkey-a1", "a1a10", "sess-a2", now.Add(2*time.Hour)),
		mk("s4", "sealuser-b", "sealkey-b1", "b1b12", "sess-b1", now.Add(time.Hour)),
		mk("old", "sealuser-b", "sealkey-b1", "b1b12", "sess-b0", now.Add(-time.Minute)),
	}
	for _, sl := range seals {
		if err := s.UpsertSessionSeal(ctx, sl); err != nil {
			t.Fatalf("UpsertSessionSeal %s: %v", sl.ID, err)
		}
	}

	// Live listing excludes expired seals and returns the blob intact.
	live, err := s.ListLiveSessionSeals(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got := sealIDs(live); len(got) != 4 || got[0] != "s1" || got[3] != "s4" {
		t.Fatalf("live = %v, want s1..s4", got)
	}
	for _, sl := range live {
		if !bytes.Equal(sl.Sealed, []byte("blob-"+sl.ID)) || sl.Mode != "keyfile" || sl.Pubkey == "" || sl.SessionID == "" || sl.KeyID == "" {
			t.Fatalf("seal %s came back wrong: %+v", sl.ID, sl)
		}
		if !sl.ExpiresAt.After(now) {
			t.Fatalf("seal %s expiry %v not after now", sl.ID, sl.ExpiresAt)
		}
	}

	// Upsert on the same (session, key) replaces, keeping one row.
	re := mk("s1-new", "sealuser-a", "sealkey-a1", "a1a10", "sess-a1", now.Add(3*time.Hour))
	if err := s.UpsertSessionSeal(ctx, re); err != nil {
		t.Fatal(err)
	}
	bySess, err := s.ListSessionSealsBySession(ctx, "sess-a1")
	if err != nil {
		t.Fatal(err)
	}
	if len(bySess) != 2 {
		t.Fatalf("sess-a1 has %d seals after re-upsert, want 2", len(bySess))
	}
	for _, sl := range bySess {
		if sl.KeyID == "sealkey-a1" && !bytes.Equal(sl.Sealed, []byte("blob-s1-new")) {
			t.Fatalf("re-upsert did not replace the blob: %q", sl.Sealed)
		}
	}
	reID := ""
	for _, sl := range bySess {
		if sl.KeyID == "sealkey-a1" {
			reID = sl.ID
		}
	}

	// Rewrap updates the blob in place.
	if err := s.UpdateSessionSealBlob(ctx, reID, []byte("rewrapped")); err != nil {
		t.Fatal(err)
	}
	byUser, _ := s.ListSessionSealsByUser(ctx, "sealuser-a")
	found := false
	for _, sl := range byUser {
		if sl.ID == reID && bytes.Equal(sl.Sealed, []byte("rewrapped")) {
			found = true
		}
	}
	if !found || len(byUser) != 3 {
		t.Fatalf("user a seals = %v (rewrap found=%v), want 3 with rewrapped blob", sealIDs(byUser), found)
	}

	// Delete by session.
	if n, err := s.DeleteSessionSealsBySession(ctx, "sess-a1"); err != nil || n != 2 {
		t.Fatalf("DeleteSessionSealsBySession = %d, %v; want 2", n, err)
	}
	// Delete by user leaves other users alone.
	if n, err := s.DeleteSessionSealsByUser(ctx, "sealuser-a"); err != nil || n != 1 {
		t.Fatalf("DeleteSessionSealsByUser = %d, %v; want 1", n, err)
	}
	// Expired rows are swept.
	if n, err := s.DeleteExpiredSessionSeals(ctx); err != nil || n != 1 {
		t.Fatalf("DeleteExpiredSessionSeals = %d, %v; want 1", n, err)
	}
	live, _ = s.ListLiveSessionSeals(ctx)
	if got := sealIDs(live); len(got) != 1 || got[0] != "s4" {
		t.Fatalf("after deletes live = %v, want [s4]", got)
	}

	// Deleting the key removes its seals (no orphan seal of a deleted key).
	if err := s.DeleteKey(ctx, "sealkey-b1"); err != nil {
		t.Fatal(err)
	}
	live, _ = s.ListLiveSessionSeals(ctx)
	if len(live) != 0 {
		t.Fatalf("seal of a deleted key survived: %v", sealIDs(live))
	}
}
