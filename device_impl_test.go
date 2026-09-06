package mwanachamaauth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
	"github.com/aosanya/mwanachama-backend-auth/models"
)

func TestAuthRegisterAndGetDevice(t *testing.T) {
	db, tables := newTestDB(t)
	s := mwanachamaauth.NewAuthStore(db, tables)
	ctx := context.Background()

	d, err := s.RegisterDevice(ctx, models.Device{MemberID: "m-1", PublicKey: "pk"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if d.ID == "" || d.CreatedAt.IsZero() {
		t.Fatalf("expected minted id + created_at, got %+v", d)
	}
	got, err := s.GetDevice(ctx, d.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.MemberID != "m-1" || got.PublicKey != "pk" {
		t.Fatalf("wrong device: %+v", got)
	}
	if _, err := s.GetDevice(ctx, "missing"); !errors.Is(err, models.ErrAuthNotFound) {
		t.Fatalf("expected ErrAuthNotFound, got %v", err)
	}
}

// TestSignOutKeepsTheFirstDate pins the idempotence the gateway's original
// Postgres store wrote as `signed_out_at = COALESCE(signed_out_at, …)`. The
// value is when the handset stopped being trusted, so a retry — a second
// tap, a client resend — must not move it forward. DEV-1272.
func TestSignOutKeepsTheFirstDate(t *testing.T) {
	db, tables := newTestDB(t)
	s := mwanachamaauth.NewAuthStore(db, tables)
	ctx := context.Background()

	dev, err := s.RegisterDevice(ctx, models.Device{MemberID: "m1", PublicKey: "pk", Name: "phone"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if dev.IsSignedOut() {
		t.Fatalf("a freshly registered handset reads as signed out: %+v", dev.SignedOutAt)
	}

	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	first, err := s.SignOutDevice(ctx, dev.ID, t0.Add(time.Hour), models.SignOutByMember)
	if err != nil {
		t.Fatalf("sign out: %v", err)
	}
	if first.SignedOutAt == nil || !first.SignedOutAt.Equal(t0.Add(time.Hour)) {
		t.Fatalf("first sign-out date = %v, want %v", first.SignedOutAt, t0.Add(time.Hour))
	}

	again, err := s.SignOutDevice(ctx, dev.ID, t0.Add(48*time.Hour), models.SignOutByRecovery)
	if err != nil {
		t.Fatalf("repeat sign out: %v", err)
	}
	if again.SignedOutAt == nil || !again.SignedOutAt.Equal(t0.Add(time.Hour)) {
		t.Errorf("a repeat sign-out moved the date to %v — the window a compromise had is "+
			"read off this value, so it must stay at the first sign-out %v",
			again.SignedOutAt, t0.Add(time.Hour))
	}
	// DEV-1347 · and it must not rewrite WHY either.
	if again.SignedOutBy != models.SignOutByMember {
		t.Errorf("a repeat sign-out rewrote the reason to %q, want %q", again.SignedOutBy, models.SignOutByMember)
	}

	if _, err := s.SignOutDevice(ctx, "device-nope", t0, models.SignOutByMember); !errors.Is(err, models.ErrAuthNotFound) {
		t.Errorf("signing out an unknown device returned %v, want models.ErrAuthNotFound", err)
	}

	if _, err := s.SignOutDevice(ctx, dev.ID, t0, ""); !errors.Is(err, models.ErrAuthSignOutReasonRequired) {
		t.Errorf("sign out with no reason = %v, want ErrAuthSignOutReasonRequired", err)
	}
}

// TestSignOutOtherDevicesEjectsEveryoneButTheKept is device.md:89's G96
// sweep: a successful recovery ejects every OTHER handset the member holds,
// stamping `recovery`, and returns exactly what it ended.
func TestSignOutOtherDevicesEjectsEveryoneButTheKept(t *testing.T) {
	db, tables := newTestDB(t)
	s := mwanachamaauth.NewAuthStore(db, tables)
	ctx := context.Background()

	a, _ := s.RegisterDevice(ctx, models.Device{MemberID: "m1", PublicKey: "pk-a"})
	b, _ := s.RegisterDevice(ctx, models.Device{MemberID: "m1", PublicKey: "pk-b"})
	c, _ := s.RegisterDevice(ctx, models.Device{MemberID: "m1", PublicKey: "pk-c"})
	// A different member's device must never be touched by m1's sweep.
	other, _ := s.RegisterDevice(ctx, models.Device{MemberID: "m2", PublicKey: "pk-other"})
	// Already signed out — must not be re-reported.
	alreadyOut, _ := s.RegisterDevice(ctx, models.Device{MemberID: "m1", PublicKey: "pk-out"})
	if _, err := s.SignOutDevice(ctx, alreadyOut.ID, time.Now(), models.SignOutByMember); err != nil {
		t.Fatalf("pre-signout: %v", err)
	}

	at := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	ended, err := s.SignOutOtherDevices(ctx, "m1", b.ID, at)
	if err != nil {
		t.Fatalf("SignOutOtherDevices: %v", err)
	}
	if len(ended) != 2 {
		t.Fatalf("ended = %d devices, want 2 (a and c): %+v", len(ended), ended)
	}
	for _, d := range ended {
		if d.ID != a.ID && d.ID != c.ID {
			t.Errorf("unexpected device ended: %+v", d)
		}
		if d.SignedOutBy != models.SignOutByRecovery {
			t.Errorf("device %s signed out by %q, want recovery", d.ID, d.SignedOutBy)
		}
		if d.SignedOutAt == nil || !d.SignedOutAt.Equal(at) {
			t.Errorf("device %s signed_out_at = %v, want %v", d.ID, d.SignedOutAt, at)
		}
	}

	kept, err := s.GetDevice(ctx, b.ID)
	if err != nil || kept.IsSignedOut() {
		t.Errorf("kept device b was signed out: %+v (err %v)", kept, err)
	}
	untouched, err := s.GetDevice(ctx, other.ID)
	if err != nil || untouched.IsSignedOut() {
		t.Errorf("a different member's device was touched: %+v (err %v)", untouched, err)
	}
}
