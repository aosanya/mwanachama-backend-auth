package mwanachamaauth_test

import (
	"context"
	"errors"
	"testing"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
	"github.com/aosanya/mwanachama-backend-auth/phonenumber"
)

type fakeRegionSource struct {
	region string
	err    error
}

func (f fakeRegionSource) DefaultDiallingRegion(context.Context) (string, error) {
	return f.region, f.err
}

func TestIndexerCanonicalizesThenHashes(t *testing.T) {
	db, tables := newTestDB(t)
	salts := mwanachamaauth.NewPhoneSaltStore(db, tables)
	ctx := context.Background()
	if _, err := salts.Provision(ctx, 1, []byte("org-key"), ""); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	ix := mwanachamaauth.NewIndexer(salts, fakeRegionSource{region: "KE"})

	d1, err := ix.Index(ctx, "0712 445 678")
	if err != nil {
		t.Fatalf("Index: %v", err)
	}
	if d1.Canonical != "+254712445678" {
		t.Fatalf("Canonical = %q, want +254712445678", d1.Canonical)
	}
	if d1.SaltID != 1 {
		t.Fatalf("SaltID = %d, want 1", d1.SaltID)
	}

	// A differently-spelled but identical number must land on the same
	// digest — the whole reason this type exists.
	d2, err := ix.IndexInRegion(ctx, "+254712445678", "GB")
	if err != nil {
		t.Fatalf("IndexInRegion: %v", err)
	}
	if string(d1.Hash) != string(d2.Hash) {
		t.Fatalf("two spellings of one number hashed differently: %x vs %x", d1.Hash, d2.Hash)
	}
}

func TestIndexerRefusesWithNoRegion(t *testing.T) {
	db, tables := newTestDB(t)
	salts := mwanachamaauth.NewPhoneSaltStore(db, tables)
	ix := mwanachamaauth.NewIndexer(salts, fakeRegionSource{region: ""})

	if _, err := ix.Index(context.Background(), "0712 445 678"); !errors.Is(err, mwanachamaauth.ErrNoDiallingRegion) {
		t.Fatalf("Index with no region = %v, want ErrNoDiallingRegion", err)
	}
	if _, err := ix.IndexInRegion(context.Background(), "0712 445 678", ""); !errors.Is(err, mwanachamaauth.ErrNoDiallingRegion) {
		t.Fatalf("IndexInRegion with empty region = %v, want ErrNoDiallingRegion", err)
	}
}

func TestIndexerRejectsUnparseableNumbers(t *testing.T) {
	db, tables := newTestDB(t)
	salts := mwanachamaauth.NewPhoneSaltStore(db, tables)
	ctx := context.Background()
	if _, err := salts.Provision(ctx, 1, []byte("org-key"), ""); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	ix := mwanachamaauth.NewIndexer(salts, fakeRegionSource{region: "KE"})

	if _, err := ix.Index(ctx, "not a number"); !errors.Is(err, phonenumber.ErrUnparseable) {
		t.Fatalf("Index(unparseable) = %v, want phonenumber.ErrUnparseable", err)
	}
}
