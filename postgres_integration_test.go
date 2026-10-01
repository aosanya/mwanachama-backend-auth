//go:build postgres

// postgres_integration_test.go exercises the GORM stores against a real
// Postgres, mirroring mwanachama-backend-actor's and
// mwanachama-backend-comm's postgres_integration_test.go. Skipped unless
// POSTGRES_URL is set; the unit tests elsewhere in this package (sqlite via
// glebarez/sqlite) already exhaustively cover business logic — this file's
// job is narrower: prove the sequence-based id minting, the
// phone_salt_one_live partial index, and the composite/natural primary keys
// all work against real Postgres, not just sqlite's more permissive dialect.
//
// Not run by this task — written for completeness, matching the sibling
// repos' convention of shipping this file without exercising it against a
// shared scratch container. See [[feedback_use_memory_backend_for_tests]].
package mwanachamaauth_test

import (
	"context"
	"os"
	"testing"

	gormpostgres "gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/aosanya/mwanachama-backend-shared/spec"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
	"github.com/aosanya/mwanachama-backend-auth/models"
)

// newPostgresDB opens POSTGRES_URL, migrates a fresh set of this repo's eight
// tables and returns the *gorm.DB plus the table names, dropping the tables
// on cleanup. Skips the calling test if POSTGRES_URL is unset.
func tableForRole(t *testing.T, s *spec.Spec, role string) string {
	t.Helper()
	o, ok := s.ByRole(role)
	if !ok {
		t.Fatalf("the declaration fills no %q role", role)
	}
	return s.TableFor(o)
}

func newPostgresDB(t *testing.T) (*gorm.DB, *spec.Spec) {
	t.Helper()
	dsn := os.Getenv("POSTGRES_URL")
	if dsn == "" {
		t.Skip("POSTGRES_URL not set; skipping Postgres integration test")
	}

	db, err := gorm.Open(gormpostgres.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("gorm.Open: %v", err)
	}

	s, err := mwanachamaauth.SpecFor("pgtest")
	if err != nil {
		t.Fatalf("SpecFor: %v", err)
	}
	if err := mwanachamaauth.Provision(db, s); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	t.Cleanup(func() {
		for _, o := range s.Objects {
			_ = db.Migrator().DropTable(s.TableFor(o))
		}
		_ = db.Migrator().DropTable(s.NameRegistryTable())
	})
	return db, s
}

// TestPostgresDeviceIDsAreSequenceMinted proves the archived migrations'
// `nextval('auth_device_seq')` convention this repo's mintID reproduces
// actually works against a real SEQUENCE, which sqlite has no equivalent of.
func TestPostgresDeviceIDsAreSequenceMinted(t *testing.T) {
	db, tables := newPostgresDB(t)
	s := mustAuthStore(t, db, tables)
	ctx := context.Background()

	a, err := s.RegisterDevice(ctx, models.Device{SubjectID: "m1", PublicKey: "pk-a"})
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}
	b, err := s.RegisterDevice(ctx, models.Device{SubjectID: "m1", PublicKey: "pk-b"})
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}
	if a.ID == b.ID {
		t.Fatalf("two devices minted the same id: %q", a.ID)
	}
}

// TestPostgresPhoneSaltOneLiveIsDatabaseEnforced proves the one-live-salt
// expression index Provision applies really refuses a second concurrent live
// salt at the database, not just at the Go-level pre-check. The index is on an
// expression rather than a column, which spec.Index has no way to declare, so
// only a Postgres run exercises what Provision adds beside spec.Migrate.
func TestPostgresPhoneSaltOneLiveIsDatabaseEnforced(t *testing.T) {
	db, s := newPostgresDB(t)
	saltTable := tableForRole(t, s, "salt")

	// Bypass the Go-level guard entirely: insert two "live" rows directly.
	if err := db.Table(saltTable).Create(map[string]any{
		"id": 1, "secret": []byte("a"), "set_at": "now()",
	}).Error; err != nil {
		t.Fatalf("first insert: %v", err)
	}
	err := db.Table(saltTable).Create(map[string]any{
		"id": 2, "secret": []byte("b"), "set_at": "now()",
	}).Error
	if err == nil {
		t.Fatal("a second live salt was accepted at the database — phone_salt_one_live did not fire")
	}
}
