package mwanachamaauth_test

import (
	"context"
	"errors"
	"testing"
	"time"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
	"github.com/aosanya/mwanachama-backend-auth/models"
)

func TestAuthChallengeConsumeExpiry(t *testing.T) {
	db, tables := newTestDB(t)
	s := mwanachamaauth.NewAuthStore(db, tables)
	ctx := context.Background()

	c, err := s.CreateChallenge(ctx, models.Challenge{Kind: models.KindDevice, DeviceID: "d", Secret: "n"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if c.ID == "" {
		t.Fatal("expected minted challenge id")
	}
	if c.ExpiresAt.IsZero() {
		t.Fatal("expected a default expiry")
	}

	now := c.ExpiresAt.Add(-time.Minute) // still within the default 5m window
	got, err := s.ConsumeChallenge(ctx, c.ID, now)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	if !got.Consumed {
		t.Fatal("expected consumed=true on returned challenge")
	}
	if _, err := s.ConsumeChallenge(ctx, c.ID, now); !errors.Is(err, models.ErrAuthNotFound) {
		t.Fatalf("expected ErrAuthNotFound on second consume, got %v", err)
	}
}

func TestAuthChallengeExpired(t *testing.T) {
	db, tables := newTestDB(t)
	s := mwanachamaauth.NewAuthStore(db, tables)
	ctx := context.Background()

	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c, err := s.CreateChallenge(ctx, models.Challenge{
		Kind: models.KindPhone, Phone: "+254700000000", Secret: "999",
		ExpiresAt: t0.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := s.ConsumeChallenge(ctx, c.ID, t0.Add(2*time.Minute)); !errors.Is(err, models.ErrAuthChallengeExpired) {
		t.Fatalf("expected ErrAuthChallengeExpired, got %v", err)
	}
}

func TestAuthChallengeMissingIsNotFound(t *testing.T) {
	db, tables := newTestDB(t)
	s := mwanachamaauth.NewAuthStore(db, tables)
	ctx := context.Background()

	if _, err := s.GetChallenge(ctx, "chal-nope"); !errors.Is(err, models.ErrAuthNotFound) {
		t.Fatalf("GetChallenge(missing) = %v, want ErrAuthNotFound", err)
	}
	if _, err := s.ConsumeChallenge(ctx, "chal-nope", time.Now()); !errors.Is(err, models.ErrAuthNotFound) {
		t.Fatalf("ConsumeChallenge(missing) = %v, want ErrAuthNotFound", err)
	}
}
