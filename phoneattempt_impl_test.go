package mwanachamaauth_test

import (
	"context"
	"testing"
	"time"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
	"github.com/aosanya/mwanachama-backend-auth/models"
)

func TestAuthMemberIDForPhoneMintsOnce(t *testing.T) {
	db, tables := newTestDB(t)
	s := mwanachamaauth.NewAuthStore(db, tables)
	ctx := context.Background()

	mints := 0
	mint := func() string {
		mints++
		return "member-x"
	}
	id, err := s.MemberIDForPhone(ctx, "+254700000001", mint)
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	if id != "member-x" || mints != 1 {
		t.Fatalf("expected minted once, got id=%q mints=%d", id, mints)
	}
	id2, err := s.MemberIDForPhone(ctx, "+254700000001", mint)
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if id2 != "member-x" || mints != 1 {
		t.Fatalf("expected reuse, got id=%q mints=%d", id2, mints)
	}
	if _, err := s.MemberIDForPhone(ctx, "+254700000002", mint); err != nil {
		t.Fatalf("third: %v", err)
	}
	if mints != 2 {
		t.Fatalf("expected new mint for new phone, got mints=%d", mints)
	}
}

// TestAuthMemberIDForPhoneEmptyMintDoesNotBind is DEV-1263: a mintMember
// returning "" means "do not bind", not "bind the empty string".
func TestAuthMemberIDForPhoneEmptyMintDoesNotBind(t *testing.T) {
	db, tables := newTestDB(t)
	s := mwanachamaauth.NewAuthStore(db, tables)
	ctx := context.Background()

	id, err := s.MemberIDForPhone(ctx, "+254700000003", func() string { return "" })
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	if id != "" {
		t.Fatalf("expected no binding, got %q", id)
	}
	// A later call that DOES mint must still succeed for the same number.
	id2, err := s.MemberIDForPhone(ctx, "+254700000003", func() string { return "member-y" })
	if err != nil {
		t.Fatalf("second: %v", err)
	}
	if id2 != "member-y" {
		t.Fatalf("expected mint on second call, got %q", id2)
	}
}

func TestAuthPhoneAttemptLifecycle(t *testing.T) {
	db, tables := newTestDB(t)
	s := mwanachamaauth.NewAuthStore(db, tables)
	ctx := context.Background()

	zero, err := s.PhoneAttempt(ctx, "+254700000009")
	if err != nil {
		t.Fatalf("PhoneAttempt: %v", err)
	}
	if zero.Failed != 0 {
		t.Fatalf("a number nobody has failed against should be the zero value, got %+v", zero)
	}

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var last models.PhoneAttempt
	for i := 0; i < models.AuthLockAfter; i++ {
		last, err = s.RecordPhoneFailure(ctx, "+254700000009", now, 15*time.Minute)
		if err != nil {
			t.Fatalf("RecordPhoneFailure %d: %v", i, err)
		}
	}
	if !last.Locked(now) {
		t.Fatalf("after %d failures the number should be locked: %+v", models.AuthLockAfter, last)
	}

	if err := s.ClearPhoneAttempts(ctx, "+254700000009"); err != nil {
		t.Fatalf("ClearPhoneAttempts: %v", err)
	}
	cleared, err := s.PhoneAttempt(ctx, "+254700000009")
	if err != nil {
		t.Fatalf("PhoneAttempt after clear: %v", err)
	}
	if cleared.Failed != 0 || cleared.Locked(now) {
		t.Fatalf("expected a clean slate after ClearPhoneAttempts, got %+v", cleared)
	}
}
