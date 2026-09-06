package mwanachamaauth_test

import (
	"context"
	"testing"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
	"github.com/aosanya/mwanachama-backend-auth/models"
)

func TestVerificationDefaultsToUnverified(t *testing.T) {
	db, tables := newTestDB(t)
	s := mwanachamaauth.NewVerificationStore(db, tables)
	ctx := context.Background()

	r, err := s.Get(ctx, "m-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if r.MemberID != "m-1" {
		t.Fatalf("expected member id echoed, got %q", r.MemberID)
	}
	if r.Status != models.VerificationStatusUnverified {
		t.Fatalf("expected VerificationStatusUnverified, got %q", r.Status)
	}
	if r.UpdatedAt.IsZero() {
		t.Fatalf("expected UpdatedAt stamped, got zero")
	}
}

func TestVerificationSetThenGet(t *testing.T) {
	db, tables := newTestDB(t)
	s := mwanachamaauth.NewVerificationStore(db, tables)
	ctx := context.Background()

	if _, err := s.Set(ctx, models.VerificationRecord{
		MemberID: "m-2",
		Status:   models.VerificationStatusVerified,
		Note:     "ID card confirmed",
	}); err != nil {
		t.Fatalf("set: %v", err)
	}

	got, err := s.Get(ctx, "m-2")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != models.VerificationStatusVerified {
		t.Fatalf("expected VerificationStatusVerified, got %q", got.Status)
	}
	if got.Note != "ID card confirmed" {
		t.Fatalf("expected note preserved, got %q", got.Note)
	}
	firstStamp := got.UpdatedAt

	// A second Set overrides the record (upsert semantics), and the store —
	// not the caller — says when. DEV-1173: a caller-supplied UpdatedAt must
	// never be honoured.
	if _, err := s.Set(ctx, models.VerificationRecord{
		MemberID:  "m-2",
		Status:    models.VerificationStatusRejected,
		Note:      "insufficient docs",
		UpdatedAt: firstStamp.AddDate(1, 0, 0),
	}); err != nil {
		t.Fatalf("upsert: %v", err)
	}
	got, err = s.Get(ctx, "m-2")
	if err != nil {
		t.Fatalf("get after upsert: %v", err)
	}
	if got.Status != models.VerificationStatusRejected || got.Note != "insufficient docs" {
		t.Fatalf("expected upsert to replace, got %+v", got)
	}
	if got.UpdatedAt.Equal(firstStamp.AddDate(1, 0, 0)) {
		t.Fatalf("the caller's UpdatedAt was honoured: %v", got.UpdatedAt)
	}
}
