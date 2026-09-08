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

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
	"github.com/aosanya/mwanachama-backend-auth/routes"
)

// newTestDB mirrors the root package's own testdb_test.go helper — a fresh
// in-memory sqlite database migrated via mwanachamaauth.Migrate. Shared by
// every *_test.go file in this package.
func newTestDB(t *testing.T) (*gorm.DB, mwanachamaauth.TableNames) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("gorm.Open: %v", err)
	}
	tables := mwanachamaauth.DefaultTableNames()
	if err := mwanachamaauth.Migrate(db, tables); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return db, tables
}

// fakeMinter is a minimal SessionMinter — the gateway supplies a real one in
// the follow-up cutover pass; this repo's own tests only need to prove the
// seam is called correctly.
type fakeMinter struct{ minted int }

func (f *fakeMinter) Mint(_ context.Context, memberID, deviceID string, ttl time.Duration) (routes.Session, error) {
	f.minted++
	now := time.Now().UTC()
	return routes.Session{
		Token: "tok-" + memberID, ActorID: memberID, DeviceID: deviceID,
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
