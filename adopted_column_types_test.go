package mwanachamaauth_test

import (
	"context"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/aosanya/mwanachama-backend-shared/spec"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
)

const legacySaltDDL = `create table auth_phone_salt (
	id integer primary key,
	secret blob not null,
	set_at timestamp not null,
	set_by text,
	retired_at timestamp,
	retired_by text
)`

func adoptedSaltDB(t *testing.T) (*gorm.DB, *spec.Spec, string) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("gorm.Open: %v", err)
	}
	if err := db.Exec(legacySaltDDL).Error; err != nil {
		t.Fatalf("seed the legacy table: %v", err)
	}
	s, err := mwanachamaauth.SpecFor("test")
	if err != nil {
		t.Fatalf("SpecFor: %v", err)
	}
	if err := mwanachamaauth.Provision(db, s); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	o, ok := s.ByRole("salt")
	if !ok {
		t.Fatal("the declaration fills no salt role")
	}
	return db, s, s.TableFor(o)
}

func TestAdoptedSaltKeepsItsLegacyColumnTypeSoTheIndexDropsTheEmptyStringTest(t *testing.T) {
	db, _, table := adoptedSaltDB(t)

	textual, err := spec.ColumnIsTextual(db, table, "retired_at")
	if err != nil {
		t.Fatalf("ColumnIsTextual: %v", err)
	}
	if textual {
		t.Fatal("the adopted table was expected to keep its legacy timestamp column, not be retyped to text")
	}

	var sql []string
	if err := db.Raw(`select sql from sqlite_master where type = 'index' and name = ?`, table+"_one_live").
		Scan(&sql).Error; err != nil {
		t.Fatalf("read the index: %v", err)
	}
	if len(sql) == 0 {
		t.Fatal("Provision created no one-live index")
	}
	if strings.Contains(sql[0], "= ''") {
		t.Fatalf("the one-live index compares a non-text column to the empty string, which Postgres refuses: %s", sql[0])
	}
}

func TestTheLiveSaltIsStillReachableOnAnAdoptedTable(t *testing.T) {
	db, s, _ := adoptedSaltDB(t)

	st, err := mwanachamaauth.NewPhoneSaltStore(db, s)
	if err != nil {
		t.Fatalf("NewPhoneSaltStore: %v", err)
	}
	ctx := context.Background()
	if _, err := st.Provision(ctx, 1, []byte("0123456789abcdef"), "operator-1"); err != nil {
		t.Fatalf("Provision a salt: %v", err)
	}

	live, err := st.Live(ctx)
	if err != nil {
		t.Fatalf("Live: %v", err)
	}
	if live.ID != 1 || !live.Live() {
		t.Fatalf("live salt = %+v, want id 1 and no retirement stamp", live)
	}

	if _, err := st.Retire(ctx, 1, "operator-1"); err != nil {
		t.Fatalf("Retire: %v", err)
	}
	if _, err := st.Live(ctx); err == nil {
		t.Fatal("Live still found a salt after the only one was retired")
	}
}
