package mwanachamaauth_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"
	"time"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
	"github.com/aosanya/mwanachama-backend-auth/models"
)

// TestSaltCarriesNoSecret is the structural guard the whole object rests on.
//
// phone-salt.md's select rule for `secret` is **nobody**, and this port
// enforces it by the shape of the type rather than by a view. If somebody
// adds a Secret field to models.Salt, every other test in this package still
// passes and the key starts appearing in JSON, in logs and in any handler
// that marshals a Salt. This test is the one that notices.
func TestSaltCarriesNoSecret(t *testing.T) {
	ty := reflect.TypeOf(models.Salt{})
	for i := 0; i < ty.NumField(); i++ {
		switch ty.Field(i).Name {
		case "Secret", "Key", "HMACKey", "Salt":
			t.Fatalf("models.Salt gained a %q field: the key must never be reachable "+
				"through a value any handler can marshal (phone-salt.md, select: nobody)",
				ty.Field(i).Name)
		}
	}
}

func TestHashIsHMACUnderTheLiveSalt(t *testing.T) {
	db, tables := newTestDB(t)
	s := mwanachamaauth.NewPhoneSaltStore(db, tables)
	ctx := context.Background()
	secret := []byte("organization-key-v1")
	if _, err := s.Provision(ctx, 1, secret, ""); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	got, id, err := s.Hash(ctx, "+254712445678")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if id != 1 {
		t.Fatalf("salt id = %d, want 1", id)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("+254712445678"))
	if want := mac.Sum(nil); !hmac.Equal(got, want) {
		t.Fatalf("digest = %x, want %x", got, want)
	}
}

func TestHashChangesWithTheSalt(t *testing.T) {
	db, tables := newTestDB(t)
	s := mwanachamaauth.NewPhoneSaltStore(db, tables)
	ctx := context.Background()
	if _, err := s.Provision(ctx, 1, []byte("salt-one"), ""); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	before, _, _ := s.Hash(ctx, "+254712445678")

	if _, err := s.Retire(ctx, 1, "member-1"); err != nil {
		t.Fatalf("Retire: %v", err)
	}
	if _, err := s.Provision(ctx, 2, []byte("salt-two"), "member-1"); err != nil {
		t.Fatalf("Provision successor: %v", err)
	}
	after, id, err := s.Hash(ctx, "+254712445678")
	if err != nil {
		t.Fatalf("Hash after rotation: %v", err)
	}
	if id != 2 {
		t.Fatalf("hashed under salt %d after rotation, want 2", id)
	}
	if hmac.Equal(before, after) {
		t.Fatal("the successor salt produced the same digest — the key is not being used")
	}
}

func TestHashRefusesWithNoLiveSalt(t *testing.T) {
	db, tables := newTestDB(t)
	s := mwanachamaauth.NewPhoneSaltStore(db, tables)
	ctx := context.Background()
	if _, _, err := s.Hash(ctx, "+254712445678"); !errors.Is(err, models.ErrPhoneSaltNotFound) {
		t.Fatalf("Hash with no salt = %v, want ErrPhoneSaltNotFound", err)
	}
	if _, err := s.Provision(ctx, 1, []byte("k"), ""); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if _, err := s.Retire(ctx, 1, "member-1"); err != nil {
		t.Fatalf("Retire: %v", err)
	}
	if _, _, err := s.Hash(ctx, "+254712445678"); !errors.Is(err, models.ErrPhoneSaltNotFound) {
		t.Fatalf("Hash after the only salt retired = %v, want ErrPhoneSaltNotFound", err)
	}
}

func TestProvisionRefusesASecondLiveSalt(t *testing.T) {
	db, tables := newTestDB(t)
	s := mwanachamaauth.NewPhoneSaltStore(db, tables)
	ctx := context.Background()
	if _, err := s.Provision(ctx, 1, []byte("a"), ""); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if _, err := s.Provision(ctx, 2, []byte("b"), ""); !errors.Is(err, models.ErrPhoneSaltAlreadyLive) {
		t.Fatalf("second live Provision = %v, want ErrPhoneSaltAlreadyLive", err)
	}
}

func TestRetireStampsThePairAndRefusesTwice(t *testing.T) {
	db, tables := newTestDB(t)
	s := mwanachamaauth.NewPhoneSaltStore(db, tables)
	ctx := context.Background()
	if _, err := s.Provision(ctx, 1, []byte("k"), ""); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	if _, err := s.Retire(ctx, 1, ""); !errors.Is(err, models.ErrPhoneSaltNoActor) {
		t.Fatalf("Retire with no actor = %v, want ErrPhoneSaltNoActor", err)
	}
	if live, err := s.Live(ctx); err != nil || !live.Live() {
		t.Fatalf("a refused retire left the salt at %+v (err %v); it must still be live", live, err)
	}

	got, err := s.Retire(ctx, 1, "member-1")
	if err != nil {
		t.Fatalf("Retire: %v", err)
	}
	if got.RetiredAt == nil || got.RetiredBy != "member-1" {
		t.Fatalf("retired pair = (%v, %q), want a stamp and \"member-1\"", got.RetiredAt, got.RetiredBy)
	}

	if _, err := s.Retire(ctx, 1, "member-2"); !errors.Is(err, models.ErrPhoneSaltRetired) {
		t.Fatalf("second Retire = %v, want ErrPhoneSaltRetired", err)
	}
	again, _ := s.List(ctx)
	if again[0].RetiredBy != "member-1" {
		t.Fatalf("retired_by is now %q; the refused second retire overwrote the actor", again[0].RetiredBy)
	}

	if _, err := s.Retire(ctx, 999, "member-1"); !errors.Is(err, models.ErrPhoneSaltNotFound) {
		t.Fatalf("Retire(unknown id) = %v, want ErrPhoneSaltNotFound", err)
	}
}

func TestListIsNewestFirst(t *testing.T) {
	db, tables := newTestDB(t)
	s := mwanachamaauth.NewPhoneSaltStore(db, tables)
	ctx := context.Background()
	for i := 1; i <= 3; i++ {
		if _, err := s.Provision(ctx, i, []byte{byte(i)}, ""); err != nil {
			t.Fatalf("Provision %d: %v", i, err)
		}
		if i < 3 {
			if _, err := s.Retire(ctx, i, "member-1"); err != nil {
				t.Fatalf("Retire %d: %v", i, err)
			}
		}
	}
	got, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 3 || got[0].ID != 3 || got[2].ID != 1 {
		t.Fatalf("List order wrong: %+v", got)
	}
	if !got[0].Live() || got[1].Live() || got[2].Live() {
		t.Fatalf("live flags wrong: %+v", got)
	}
}

// TestListEmptyBeforeProvisioning is routes/PhoneSaltRoutes's own refusal
// path: an empty list is a real answer meaning provisioning has not run,
// not an error.
func TestListEmptyBeforeProvisioning(t *testing.T) {
	db, tables := newTestDB(t)
	s := mwanachamaauth.NewPhoneSaltStore(db, tables)
	got, err := s.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected an empty list before provisioning, got %+v", got)
	}
}

func TestAgeDaysFreezesAtRetirement(t *testing.T) {
	set := time.Date(2026, 2, 4, 0, 0, 0, 0, time.UTC)
	read := set.AddDate(0, 0, 178)

	live := models.Salt{ID: 1, SetAt: set}
	if got := live.AgeDays(read); got != 178 {
		t.Fatalf("live AgeDays = %d, want 178", got)
	}

	retired := set.AddDate(0, 0, 30)
	dead := models.Salt{ID: 1, SetAt: set, RetiredAt: &retired, RetiredBy: "member-1"}
	if got := dead.AgeDays(read); got != 30 {
		t.Fatalf("retired AgeDays = %d, want 30 — it should freeze at retirement", got)
	}
}
