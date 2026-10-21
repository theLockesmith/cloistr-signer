package storage

import (
	"context"
	"testing"
	"time"
)

// The single_grant migration on a database as it was before it: the fleet
// account's keys become single-grant, a user key's grant with no expiry gets
// a full sliding 30 days (nobody signed out), an explicit expiry and a fleet
// grant are left alone, a grant naming no key keeps the one-grant rule, and a
// second start changes nothing.
func TestPostgresMigration_SingleGrantBackfill(t *testing.T) {
	ps := getTestPostgresStorage(t)
	defer ps.Close()
	ctx := context.Background()
	const (
		fleetKey = "f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1"
		userKey  = "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2"
	)
	explicit := time.Now().Add(5 * 24 * time.Hour).Truncate(time.Second)

	// Back to the schema before this change, then data as production holds it.
	for _, q := range []string{
		`DROP INDEX idx_one_active_single_grant_per_key_slot`,
		`ALTER TABLE signer_permissions DROP COLUMN single_grant, DROP COLUMN sliding_expiry`,
		`ALTER TABLE signer_keys DROP COLUMN single_grant`,
		`CREATE UNIQUE INDEX idx_one_active_grant_per_key_slot ON signer_permissions(key_id, slot) WHERE revoked_at IS NULL`,
		`INSERT INTO signer_web_accounts (id, username, password_hash) VALUES ('acct-fleet', '` + FleetAccountUsername + `', 'x'), ('acct-user', 'someone', 'x')`,
		`INSERT INTO signer_keys (id, name, pubkey, encrypted_nsec, owner_id, created_by) VALUES
			('fleetkey', 'arbiter:role', '` + fleetKey + `', 'x', 'acct-fleet', 'test'),
			('userkey', 'Primary', '` + userKey + `', 'x', 'acct-user', 'test')`,
		`INSERT INTO signer_permissions (key_id, user_pubkey, methods) VALUES
			('` + fleetKey + `', 'fleet-agent', '{sign_event}'),
			('` + userKey + `', 'mail', '{sign_event}'),
			('no-such-key', 'orphan', '{ping}')`,
	} {
		if _, err := ps.db.Exec(q); err != nil {
			t.Fatalf("build pre-migration database: %v\n%s", err, q)
		}
	}
	if _, err := ps.db.Exec(`INSERT INTO signer_permissions (key_id, user_pubkey, methods, slot, expires_at) VALUES ($1, 'docs', '{sign_event}', 'publisher', $2)`, userKey, explicit); err != nil {
		t.Fatal(err)
	}

	if err := ps.migrate(); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	for pub, want := range map[string]bool{fleetKey: true, userKey: false} {
		k, err := ps.GetKeyByPubkey(ctx, pub)
		if err != nil || k.SingleGrant != want {
			t.Fatalf("key %s = %+v, %v; want SingleGrant %v", pub[:4], k, err, want)
		}
	}
	mail, err := ps.GetPermission(ctx, userKey, "mail")
	if err != nil || !mail.SlidingExpiry || mail.ExpiresAt == nil || !near(*mail.ExpiresAt, time.Now().Add(SlidingGrantTTL)) {
		t.Fatalf("user grant with no expiry = %+v, %v; want live, sliding, ~30 days", mail, err)
	}
	if docs, err := ps.GetPermission(ctx, userKey, "docs"); err != nil || docs.SlidingExpiry || !docs.ExpiresAt.Equal(explicit) {
		t.Fatalf("user grant with an explicit expiry = %+v, %v; want unchanged, not sliding", docs, err)
	}
	if fleet, err := ps.GetPermission(ctx, fleetKey, "fleet-agent"); err != nil || fleet.ExpiresAt != nil || fleet.SlidingExpiry {
		t.Fatalf("fleet grant = %+v, %v; want live, no expiry, not sliding", fleet, err)
	}
	var orphanSingle, fleetSingle bool
	if err := ps.db.QueryRow(`SELECT single_grant FROM signer_permissions WHERE user_pubkey = 'orphan'`).Scan(&orphanSingle); err != nil || !orphanSingle {
		t.Fatalf("orphan grant single_grant = %v, %v; want true (old rule)", orphanSingle, err)
	}
	if err := ps.db.QueryRow(`SELECT single_grant FROM signer_permissions WHERE user_pubkey = 'fleet-agent'`).Scan(&fleetSingle); err != nil || !fleetSingle {
		t.Fatalf("fleet grant single_grant = %v, %v; want true", fleetSingle, err)
	}

	// After the migration: a second app on the user key is added beside mail;
	// a second agent on the fleet key displaces the first.
	if err := ps.SetPermission(ctx, &Permission{KeyID: userKey, UserPubkey: "calendar", Methods: []string{"sign_event"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := ps.GetPermission(ctx, userKey, "mail"); err != nil {
		t.Fatalf("mail after a second app signed in: %v, want live", err)
	}
	if err := ps.SetPermission(ctx, &Permission{KeyID: fleetKey, UserPubkey: "fleet-agent-2", Methods: []string{"sign_event"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := ps.GetPermission(ctx, fleetKey, "fleet-agent"); err == nil {
		t.Fatal("first fleet agent still live after a second connected")
	}

	// A second start: nothing re-flagged, no expiry extended, nothing revoked.
	if _, err := ps.db.Exec(`UPDATE signer_keys SET single_grant = FALSE WHERE pubkey = $1`, fleetKey); err != nil {
		t.Fatal(err)
	}
	if err := ps.migrate(); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if k, _ := ps.GetKeyByPubkey(ctx, fleetKey); k.SingleGrant {
		t.Fatal("second start re-ran the fleet backfill")
	}
	if again, err := ps.GetPermission(ctx, userKey, "mail"); err != nil || !again.ExpiresAt.Equal(*mail.ExpiresAt) {
		t.Fatalf("mail after second start = %+v, %v; want expiry unchanged at %v", again, err, mail.ExpiresAt)
	}
	for _, c := range []string{"mail", "calendar", "docs"} {
		if _, err := ps.GetPermission(ctx, userKey, c); err != nil {
			t.Fatalf("%s revoked by the second start: %v", c, err)
		}
	}
}
