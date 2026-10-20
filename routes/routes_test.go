package routes_test

import (
	"testing"
	"time"

	"github.com/aosanya/mwanachama-backend-auth/routes"
)

// TestRoutesAggregatorReturnsEveryGroup exercises [routes.Routes] and
// [routes.Route.Pattern] — the per-domain builders each get their own happy
// path/refusal coverage in device_test.go, recovery_test.go, operator_test.go,
// verification_test.go and phonesalt_test.go.
func TestRoutesAggregatorReturnsEveryGroup(t *testing.T) {
	db, tables := newTestDB(t)
	deps := routes.Deps{
		Auth:         mustAuthStore(t, db, tables),
		Operators:    mustOperatorStore(t, db, tables),
		Verification: mustVerificationStore(t, db, tables),
		PhoneSalts:   mustPhoneSaltStore(t, db, tables),
		Sessions:     mustSessionStore(t, db, tables),
		Minter:       &fakeMinter{},
		TTL:          time.Hour,
		Identity:     fakeIdentity("m1"),
	}
	all := routes.Routes(deps)
	if len(all) != 12 {
		t.Fatalf("Routes() returned %d routes, want 12: %+v", len(all), all)
	}
	if got := all[0].Pattern("/v1/auth"); got != "POST /v1/auth/devices/{deviceID}/challenge" {
		t.Fatalf("Pattern() = %q", got)
	}
}
