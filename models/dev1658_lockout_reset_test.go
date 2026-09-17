package models

import (
	"testing"
	"time"
)

// TestOperatorAttempt_PinsFailuresBelowLockThresholdNeverReset pins DEV-1658:
// OperatorAttempt.Fail's own doc comment promises "the five are always
// consecutive within one window rather than cumulative over an address's
// lifetime — otherwise a credential used for a year would lock on its fifth
// typo ever." The actual reset guard only fires when the address was
// ALREADY locked (LockedUntil set) and that lock has expired — an address
// that fails fewer than OperatorLockAfter times never gets LockedUntil set
// at all, so those failures are never reset by elapsed time and simply
// accumulate for the address's lifetime.
//
// This test asserts the CURRENT (broken) behavior: four failures, one per
// calendar year, still sum to Failed=4 with no reset, and a fifth failure
// a year after that locks the address — exactly the "locks on its fifth
// typo ever" scenario the doc comment says cannot happen. Once DEV-1658 is
// fixed (either resetting on elapsed-since-last-failure, or the doc comment
// being corrected to describe the real, intentional policy), this
// assertion must be revisited: a real per-window reset would keep Failed
// at 1 for each of these widely-spaced failures, never reaching a lock at
// all.
func TestOperatorAttempt_PinsFailuresBelowLockThresholdNeverReset(t *testing.T) {
	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	lockFor := 15 * time.Minute

	var a OperatorAttempt
	for i := 0; i < OperatorLockAfter-1; i++ {
		now := base.AddDate(i, 0, 0) // one year apart each time
		a = a.Fail(now, lockFor)
		if a.Locked(now) {
			t.Fatalf("failure #%d (year %d) should not lock yet: %+v", i+1, 2020+i, a)
		}
	}
	if a.Failed != OperatorLockAfter-1 {
		t.Fatalf("after %d failures spread one year apart, want Failed=%d (no reset fired), got %d",
			OperatorLockAfter-1, OperatorLockAfter-1, a.Failed)
	}

	fifth := base.AddDate(OperatorLockAfter-1, 0, 0)
	a = a.Fail(fifth, lockFor)
	if !a.Locked(fifth) {
		t.Fatalf("want the address locked on its 5th-ever failure despite them being years apart, got %+v", a)
	}
}

// TestPhoneAttempt_PinsFailuresBelowLockThresholdNeverReset is
// TestOperatorAttempt_PinsFailuresBelowLockThresholdNeverReset's identical
// twin for PhoneAttempt.Fail (models/auth.go) — same shape, same doc
// comment promise, same gap. See DEV-1658.
func TestPhoneAttempt_PinsFailuresBelowLockThresholdNeverReset(t *testing.T) {
	base := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	lockFor := 15 * time.Minute

	var a PhoneAttempt
	for i := 0; i < AuthLockAfter-1; i++ {
		now := base.AddDate(i, 0, 0)
		a = a.Fail(now, lockFor)
		if a.Locked(now) {
			t.Fatalf("failure #%d (year %d) should not lock yet: %+v", i+1, 2020+i, a)
		}
	}
	if a.Failed != AuthLockAfter-1 {
		t.Fatalf("after %d failures spread one year apart, want Failed=%d (no reset fired), got %d",
			AuthLockAfter-1, AuthLockAfter-1, a.Failed)
	}

	fifth := base.AddDate(AuthLockAfter-1, 0, 0)
	a = a.Fail(fifth, lockFor)
	if !a.Locked(fifth) {
		t.Fatalf("want the number locked on its 5th-ever failure despite them being years apart, got %+v", a)
	}
}
