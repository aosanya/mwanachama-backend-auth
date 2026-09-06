package mwanachamaauth_test

import (
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
)

// newTestDB builds a fresh in-memory sqlite database, migrated the same way
// a real deployment would via [mwanachamaauth.Migrate] — mirroring
// mwanachama-backend-actor's and mwanachama-backend-comm's identical
// testdb_test.go setup. Exercising real GORM/SQL behavior catches more than
// a Go map fake ever could, while staying fully in-process — no containers,
// no POSTGRES_URL.
func newTestDB(t *testing.T) (*gorm.DB, mwanachamaauth.TableNames) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("gorm.Open: %v", err)
	}
	tables := mwanachamaauth.DefaultTableNames()
	if err := mwanachamaauth.Migrate(db, tables); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return db, tables
}
