package routes_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"

	"github.com/aosanya/mwanachama-backend-shared/spec"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
	"github.com/aosanya/mwanachama-backend-auth/routes"
)

const testSpecPath = "../auth.platform.json"

func newTestDB(t *testing.T) (*gorm.DB, *spec.Spec) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("gorm.Open: %v", err)
	}
	s, err := mwanachamaauth.LoadSpec(testSpecPath)
	if err != nil {
		t.Fatalf("LoadSpec: %v", err)
	}
	if err := mwanachamaauth.Provision(db, s); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	return db, s
}

func mustAuthStore(t *testing.T, db *gorm.DB, s *spec.Spec) *mwanachamaauth.AuthStore {
	t.Helper()
	st, err := mwanachamaauth.NewAuthStore(db, s)
	if err != nil {
		t.Fatalf("NewAuthStore: %v", err)
	}
	return st
}

func mustOperatorStore(t *testing.T, db *gorm.DB, s *spec.Spec) *mwanachamaauth.OperatorStore {
	t.Helper()
	st, err := mwanachamaauth.NewOperatorStore(db, s)
	if err != nil {
		t.Fatalf("NewOperatorStore: %v", err)
	}
	return st
}

func mustVerificationStore(t *testing.T, db *gorm.DB, s *spec.Spec) *mwanachamaauth.VerificationStore {
	t.Helper()
	st, err := mwanachamaauth.NewVerificationStore(db, s)
	if err != nil {
		t.Fatalf("NewVerificationStore: %v", err)
	}
	return st
}

func mustPhoneSaltStore(t *testing.T, db *gorm.DB, s *spec.Spec) *mwanachamaauth.PhoneSaltStore {
	t.Helper()
	st, err := mwanachamaauth.NewPhoneSaltStore(db, s)
	if err != nil {
		t.Fatalf("NewPhoneSaltStore: %v", err)
	}
	return st
}

// fakeMinter is a minimal SessionMinter — the gateway supplies a real one in
// the follow-up cutover pass; this repo's own tests only need to prove the
// seam is called correctly.
type fakeMinter struct{ minted int }

func (f *fakeMinter) Mint(_ context.Context, subjectID, deviceID string, ttl time.Duration) (routes.Session, error) {
	f.minted++
	now := time.Now().UTC()
	return routes.Session{
		Token: "tok-" + subjectID, ActorID: subjectID, DeviceID: deviceID,
		IssuedAt: now, ExpiresAt: now.Add(ttl),
	}, nil
}

// fakeIdentity resolves every request to the same caller — enough to test
// ChangeOperatorPassword's identity check in both directions.
type fakeIdentity string

func (f fakeIdentity) CallerID(*http.Request) string { return string(f) }

func decodeBody(t *testing.T, rec *httptest.ResponseRecorder, v any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
		t.Fatalf("decoding response body %s: %v", rec.Body.String(), err)
	}
}
