package storage

import (
	"database/sql"
	"net/url"
	"os"
	"testing"
)

// Only signer_test and signer_test_<suffix> pass; every name that merely
// contains "test" (or names a real database) is refused.
func TestTestDatabaseName(t *testing.T) {
	for name, want := range map[string]bool{
		"signer_test": true, "signer_test_ci": true, "signer_test_2": true,
		"signer_test_prod": false, "latest": false, "my-test-db": false, "test": false,
		"signer": false, "cloistr": false, "postgres": false, "signer_testing": false,
		"SIGNER_TEST": false, "signer_test_": false, "x_signer_test": false, "": false,
	} {
		if got := isTestDatabaseName(name); got != want {
			t.Errorf("isTestDatabaseName(%q) = %v, want %v", name, got, want)
		}
	}
}

// Pointed at a database that is not a test database, the Postgres test setup
// refuses BEFORE opening the storage: it returns an error, and no signer_
// table is created there (opening the storage runs migrate(), which would).
func TestOpenTestPostgres_RefusesWithoutTouchingTheDatabase(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL is not set in CI")
		}
		t.Skip("TEST_DATABASE_URL not set")
	}
	admin, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	const victim = "signer_guard_victim" // not an allowed test name
	_, _ = admin.Exec(`DROP DATABASE IF EXISTS ` + victim)
	if _, err := admin.Exec(`CREATE DATABASE ` + victim); err != nil {
		t.Fatalf("create %s: %v", victim, err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(`DROP DATABASE IF EXISTS ` + victim + ` WITH (FORCE)`) })

	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + victim
	if ps, err := openTestPostgres(u.String()); err == nil {
		ps.Close()
		t.Fatalf("openTestPostgres accepted database %q", victim)
	}

	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var tables int
	if err := db.QueryRow(`SELECT count(*) FROM pg_tables WHERE tablename LIKE 'signer\_%'`).Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if tables != 0 {
		t.Fatalf("refused database %q now has %d signer_ tables: the guard ran after migrations", victim, tables)
	}
}
