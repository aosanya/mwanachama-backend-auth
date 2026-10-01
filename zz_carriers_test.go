package mwanachamaauth

import (
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func TestCarriersAgree(t *testing.T) {
	for _, p := range []string{"auth.platform.json", "auth.clinic.json"} {
		s, err := LoadSpec(p)
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := newStore(db, s, carriers()); err != nil {
			t.Errorf("%s:\n%v", p, err)
		}
	}
}
