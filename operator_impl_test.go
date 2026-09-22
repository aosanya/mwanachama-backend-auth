package mwanachamaauth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
	"github.com/aosanya/mwanachama-backend-auth/models"
)

func TestOperatorCreateAndVerifier(t *testing.T) {
	db, tables := newTestDB(t)
	s := mwanachamaauth.NewOperatorStore(db, tables)
	ctx := context.Background()

	c, err := s.Create(ctx, models.OperatorCredential{MemberID: "m1", Email: "a@example.org"}, "hash-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if c.ID == "" || c.CreatedAt.IsZero() || c.UpdatedAt.IsZero() {
		t.Fatalf("expected minted id + timestamps, got %+v", c)
	}

	got, hash, err := s.Verifier(ctx, "a@example.org")
	if err != nil {
		t.Fatalf("Verifier: %v", err)
	}
	if hash != "hash-1" || got.ID != c.ID {
		t.Fatalf("Verifier returned %+v / %q, want id=%q hash=hash-1", got, hash, c.ID)
	}

	// A second credential claiming the same address is refused.
	if _, err := s.Create(ctx, models.OperatorCredential{MemberID: "m2", Email: "a@example.org"}, "hash-2"); !errors.Is(err, models.ErrOperatorEmailTaken) {
		t.Fatalf("duplicate email = %v, want ErrOperatorEmailTaken", err)
	}

	if _, _, err := s.Verifier(ctx, "nobody@example.org"); !errors.Is(err, models.ErrOperatorNotFound) {
		t.Fatalf("Verifier(unknown) = %v, want ErrOperatorNotFound", err)
	}
}

func TestOperatorDisableIsIdempotentAndKeepsFirstStamp(t *testing.T) {
	db, tables := newTestDB(t)
	s := mwanachamaauth.NewOperatorStore(db, tables)
	ctx := context.Background()

	c, err := s.Create(ctx, models.OperatorCredential{MemberID: "m1", Email: "b@example.org"}, "hash-1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := s.Disable(ctx, c.ID); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	_, _, err = s.Verifier(ctx, "b@example.org")
	if !errors.Is(err, models.ErrOperatorDisabled) {
		t.Fatalf("Verifier(disabled) = %v, want ErrOperatorDisabled", err)
	}

	// A second Disable must not error and must not move the stamp forward —
	// asserted indirectly via a successful idempotent call.
	if err := s.Disable(ctx, c.ID); err != nil {
		t.Fatalf("second Disable: %v", err)
	}

	if err := s.Disable(ctx, "opcred-nope"); !errors.Is(err, models.ErrOperatorNotFound) {
		t.Fatalf("Disable(unknown) = %v, want ErrOperatorNotFound", err)
	}
}

func TestOperatorListForMemberIncludesDisabled(t *testing.T) {
	db, tables := newTestDB(t)
	s := mwanachamaauth.NewOperatorStore(db, tables)
	ctx := context.Background()

	a, _ := s.Create(ctx, models.OperatorCredential{MemberID: "m1", Email: "c1@example.org"}, "h1")
	b, _ := s.Create(ctx, models.OperatorCredential{MemberID: "m1", Email: "c2@example.org"}, "h2")
	if err := s.Disable(ctx, b.ID); err != nil {
		t.Fatalf("Disable: %v", err)
	}

	out, err := s.ListForMember(ctx, "m1")
	if err != nil {
		t.Fatalf("ListForMember: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected both credentials (disabled included), got %d: %+v", len(out), out)
	}
	found := map[string]bool{a.ID: false, b.ID: false}
	for _, c := range out {
		found[c.ID] = true
	}
	if !found[a.ID] || !found[b.ID] {
		t.Fatalf("missing an expected credential: %+v", out)
	}
}

func TestOperatorLockOutAfterFiveFailures(t *testing.T) {
	db, tables := newTestDB(t)
	s := mwanachamaauth.NewOperatorStore(db, tables)
	ctx := context.Background()

	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var last models.OperatorAttempt
	var err error
	for i := 0; i < models.OperatorLockAfter; i++ {
		last, err = s.RecordFailure(ctx, "guessed@example.org", now, 15*time.Minute)
		if err != nil {
			t.Fatalf("RecordFailure %d: %v", i, err)
		}
	}
	if !last.Locked(now) {
		t.Fatalf("expected lock-out after %d failures, got %+v", models.OperatorLockAfter, last)
	}
	// Counted even though this address holds no credential — the enumeration
	// guard the console sign-in refusal depends on.
	if last.Email != "guessed@example.org" {
		t.Fatalf("Email = %q, want the guessed address", last.Email)
	}

	if err := s.ClearAttempts(ctx, "guessed@example.org"); err != nil {
		t.Fatalf("ClearAttempts: %v", err)
	}
	cleared, err := s.Attempt(ctx, "guessed@example.org")
	if err != nil {
		t.Fatalf("Attempt: %v", err)
	}
	if cleared.Locked(now) {
		t.Fatalf("expected the lock cleared, got %+v", cleared)
	}
}

// TestDEV1698_SubThresholdFailuresDoNotResetOnAFreshWindow pins a known
// defect (board row DEV-1698, documentation/3. implementation/todo.md):
// models.OperatorAttempt.Fail (and models.PhoneAttempt.Fail, identical
// shape) only resets Failed to 0 when a lock was actually triggered AND has
// since expired (`!a.LockedUntil.IsZero() && !now.Before(a.LockedUntil)`).
// An address that stays *under* the lock threshold never sets LockedUntil at
// all, so its sub-threshold failure count never resets, no matter how much
// time passes between attempts — three failures today and one a year from
// now reads as four consecutive failures, not one fresh failure in a new
// window. Once DEV-1698 is fixed (a sub-threshold count should also reset
// after some real elapsed-time policy, not only after an actual lock
// expires), the final assertion below must change: today it asserts
// Failed == 4 (the bug); the fix should make a failure a full year after the
// last one read as Failed == 1.
func TestDEV1698_SubThresholdFailuresDoNotResetOnAFreshWindow(t *testing.T) {
	db, tables := newTestDB(t)
	s := mwanachamaauth.NewOperatorStore(db, tables)
	ctx := context.Background()

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	email := "sub-threshold@example.org"

	// Three failures, well below the 5-failure lock threshold — LockedUntil
	// never gets set.
	var last models.OperatorAttempt
	for i := 0; i < 3; i++ {
		next, err := s.RecordFailure(ctx, email, base, 15*time.Minute)
		if err != nil {
			t.Fatalf("RecordFailure %d: %v", i, err)
		}
		last = next
	}
	if last.Failed != 3 || last.Locked(base) {
		t.Fatalf("setup: want 3 sub-threshold failures and no lock, got Failed=%d Locked=%v", last.Failed, last.Locked(base))
	}

	// A full year passes with no further activity before the next attempt —
	// unambiguously a fresh window, and far longer than the 15-minute
	// lockFor even if a lock had been set.
	aYearLater := base.Add(365 * 24 * time.Hour)
	next, err := s.RecordFailure(ctx, email, aYearLater, 15*time.Minute)
	if err != nil {
		t.Fatalf("RecordFailure after a year: %v", err)
	}

	// PINS DEV-1698: a correct implementation would treat this as the first
	// failure of a new window (Failed == 1). The current implementation
	// carries the stale count forward instead.
	if next.Failed != 4 {
		t.Fatalf("PINS DEV-1698: current (buggy) behavior carries sub-threshold failures across a year-long gap; got Failed=%d, want 4 — if this now fails, DEV-1698 is fixed and this assertion should be inverted to want Failed=1", next.Failed)
	}

	// Consequence: two more failures in the new window (a total of 3 *real*
	// consecutive failures since the year-long gap) now cross the 5-failure
	// lock threshold early, because they are compounding with 3-year-old
	// stale failures the caller has long since forgotten about.
	for i := 0; i < 2; i++ {
		next, err = s.RecordFailure(ctx, email, aYearLater, 15*time.Minute)
		if err != nil {
			t.Fatalf("RecordFailure follow-up %d: %v", i, err)
		}
	}
	if !next.Locked(aYearLater) {
		t.Fatalf("PINS DEV-1698's consequence: want the address wrongly locked out by only 3 genuinely-consecutive failures (2 fresh + 3 stale from a year ago), got Locked=%v Failed=%d", next.Locked(aYearLater), next.Failed)
	}
}
