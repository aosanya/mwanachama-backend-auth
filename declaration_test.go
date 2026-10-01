package mwanachamaauth_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/aosanya/mwanachama-backend-shared/spec"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
)

// shippedSpecs is every domain declaration this module ships, found rather
// than listed: a spec added later and not loaded by any test is exactly the
// one that drifts, because nothing fails until somebody provisions it.
func shippedSpecs(t *testing.T) []string {
	t.Helper()
	entries, err := filepath.Glob("auth.*.json")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	var out []string
	for _, p := range entries {
		base := filepath.Base(p)
		if base == "auth.blueprint.json" || base == "auth.operations.json" {
			continue
		}
		out = append(out, p)
	}
	if len(out) < 2 {
		t.Fatalf("found %v; this module ships at least two domains, or its neutrality is asserted rather than exercised", out)
	}
	return out
}

func memoryDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return db
}

func TestEveryExampleFitsTheTypes(t *testing.T) {
	for _, path := range shippedSpecs(t) {
		t.Run(path, func(t *testing.T) {
			s, err := mwanachamaauth.LoadSpec(path)
			if err != nil {
				t.Fatalf("LoadSpec: %v", err)
			}
			db := memoryDB(t)
			if err := mwanachamaauth.Provision(db, s); err != nil {
				t.Fatalf("Provision: %v", err)
			}
			if _, err := mwanachamaauth.NewAuthStore(db, s); err != nil {
				t.Errorf("NewAuthStore: %v", err)
			}
			if _, err := mwanachamaauth.NewOperatorStore(db, s); err != nil {
				t.Errorf("NewOperatorStore: %v", err)
			}
			if _, err := mwanachamaauth.NewVerificationStore(db, s); err != nil {
				t.Errorf("NewVerificationStore: %v", err)
			}
			if _, err := mwanachamaauth.NewPhoneSaltStore(db, s); err != nil {
				t.Errorf("NewPhoneSaltStore: %v", err)
			}
		})
	}
}

func TestTwoDomainsCoexist(t *testing.T) {
	db := memoryDB(t)
	seen := map[string]string{}

	for _, path := range shippedSpecs(t) {
		s, err := mwanachamaauth.LoadSpec(path)
		if err != nil {
			t.Fatalf("LoadSpec %s: %v", path, err)
		}
		if err := mwanachamaauth.Provision(db, s); err != nil {
			t.Fatalf("Provision %s into a database that already holds another domain: %v", path, err)
		}
		for _, o := range s.Objects {
			table := s.TableFor(o)
			if first, taken := seen[table]; taken {
				t.Fatalf("%s and %s both land in %s; two domains would share one table", first, path, table)
			}
			seen[table] = path
			if !db.Migrator().HasTable(table) {
				t.Errorf("%s: %s was declared but not created", path, table)
			}
		}
	}
}

// A required column must not carry a default, because the default is exactly
// what would let an omitted value pass unnoticed.
func TestRequiredFieldsHaveNoDefault(t *testing.T) {
	for _, path := range shippedSpecs(t) {
		s, err := mwanachamaauth.LoadSpec(path)
		if err != nil {
			t.Fatalf("LoadSpec %s: %v", path, err)
		}
		for _, o := range s.Objects {
			for _, f := range o.Fields {
				if (f.Required || f.Primary) && f.Default != "" {
					t.Errorf("%s: %s.%s is required and defaults to %q",
						path, o.Name, f.Name, f.Default)
				}
			}
		}
	}
	for _, path := range shippedSpecs(t) {
		s, err := mwanachamaauth.LoadSpec(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, stmt := range s.DDL("postgres") {
			for _, line := range strings.Split(stmt, "\n") {
				if strings.Contains(line, "not null") && strings.Contains(line, "default") {
					t.Errorf("%s: %q is both not null and defaulted", path, strings.TrimSpace(line))
				}
			}
		}
	}
}

// The constants Go compares against and the blueprint's declared values were
// promised to agree, and nothing checked it. Both directions matter: a value
// the blueprint permits and Go has no constant for is a state nothing can
// produce, and a constant the blueprint does not permit is a write that is
// refused at the edge.
func TestVocabularyMatchesTheBlueprint(t *testing.T) {
	b, err := mwanachamaauth.Blueprint()
	if err != nil {
		t.Fatalf("Blueprint: %v", err)
	}

	declared := map[string][]string{}
	for _, o := range b.Objects {
		for _, f := range o.Fields {
			if len(f.Values) > 0 {
				declared[o.Role+"."+f.Name] = f.Values
			}
		}
	}

	inGo := map[string][]string{
		"device.signed_out_by": {
			string(mwanachamaauth.SignOutBySelf),
			string(mwanachamaauth.SignOutByRecovery),
		},
		"challenge.kind": {
			string(mwanachamaauth.KindDevice),
			string(mwanachamaauth.KindPhone),
			string(mwanachamaauth.KindRecovery),
		},
		"verification.status": {
			string(mwanachamaauth.VerificationStatusUnverified),
			string(mwanachamaauth.VerificationStatusPending),
			string(mwanachamaauth.VerificationStatusVerified),
			string(mwanachamaauth.VerificationStatusRejected),
		},
	}

	for field, want := range declared {
		got, ok := inGo[field]
		if !ok {
			t.Errorf("the blueprint declares values for %s and this test names no Go constants for it", field)
			continue
		}
		assertSameSet(t, field, want, got)
	}
	for field := range inGo {
		if _, ok := declared[field]; !ok {
			t.Errorf("this test names Go constants for %s, which the blueprint declares no values for", field)
		}
	}
}

func assertSameSet(t *testing.T, field string, declared, inGo []string) {
	t.Helper()
	have := map[string]bool{}
	for _, v := range inGo {
		have[v] = true
	}
	for _, v := range declared {
		if !have[v] {
			t.Errorf("%s: the blueprint permits %q, which no Go constant produces", field, v)
		}
	}
	permitted := map[string]bool{}
	for _, v := range declared {
		permitted[v] = true
	}
	for _, v := range inGo {
		if !permitted[v] {
			t.Errorf("%s: a Go constant is %q, which the blueprint does not permit", field, v)
		}
	}
}

// Every exported sentinel must appear in the operations spec's errors map. An
// unmapped sentinel is redacted to a 500 "internal error", so a 400-shaped
// refusal arrives as an unexplained server fault.
func TestEverySentinelIsMappedToAStatus(t *testing.T) {
	s, err := mwanachamaauth.OperationSpec()
	if err != nil {
		t.Fatalf("OperationSpec: %v", err)
	}
	for name := range mwanachamaauth.Sentinels() {
		if _, ok := s.Errors[name]; !ok {
			t.Errorf("the sentinel %s is supplied but the declaration maps it to no status, so it would be redacted to a 500", name)
		}
	}
	for name := range s.Errors {
		if _, ok := mwanachamaauth.Sentinels()[name]; !ok {
			t.Errorf("the declaration maps %s to a status, but nothing supplies that sentinel", name)
		}
	}
}

func TestTheShippedSpecsAreNotAlsoTheTestFixture(t *testing.T) {
	// A shipped example that is also live config stops being a test of
	// anything: the one domain nobody has provisioned is what proves the
	// module runs somewhere it has never run.
	found := false
	for _, path := range shippedSpecs(t) {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var s *spec.Spec
		if s, err = mwanachamaauth.ParseSpec(raw); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if s.Instance != "platform" {
			found = true
		}
	}
	if !found {
		t.Error("every shipped domain is the one in production; add one nobody has provisioned")
	}
}
