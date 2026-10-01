package mwanachamaauth_test

import (
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/aosanya/mwanachama-backend-shared/spec"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
)

func newTestDB(t *testing.T) (*gorm.DB, *spec.Spec) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("gorm.Open: %v", err)
	}
	s, err := mwanachamaauth.SpecFor("test")
	if err != nil {
		t.Fatalf("LoadSpec: %v", err)
	}
	if err := mwanachamaauth.Provision(db, s); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	return db, s
}

func mustAuthStore(t *testing.T, db *gorm.DB, s *spec.Spec) *mwanachamaauth.AuthStore {
	t.Helper()
	st, err := mwanachamaauth.NewAuthStore(db, s)
	if err != nil {
		t.Fatalf("NewAuthStore: %v", err)
	}
	return st
}

func mustOperatorStore(t *testing.T, db *gorm.DB, s *spec.Spec) *mwanachamaauth.OperatorStore {
	t.Helper()
	st, err := mwanachamaauth.NewOperatorStore(db, s)
	if err != nil {
		t.Fatalf("NewOperatorStore: %v", err)
	}
	return st
}

func mustVerificationStore(t *testing.T, db *gorm.DB, s *spec.Spec) *mwanachamaauth.VerificationStore {
	t.Helper()
	st, err := mwanachamaauth.NewVerificationStore(db, s)
	if err != nil {
		t.Fatalf("NewVerificationStore: %v", err)
	}
	return st
}

func mustPhoneSaltStore(t *testing.T, db *gorm.DB, s *spec.Spec) *mwanachamaauth.PhoneSaltStore {
	t.Helper()
	st, err := mwanachamaauth.NewPhoneSaltStore(db, s)
	if err != nil {
		t.Fatalf("NewPhoneSaltStore: %v", err)
	}
	return st
}
