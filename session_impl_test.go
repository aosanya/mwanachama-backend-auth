package mwanachamaauth_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/aosanya/mwanachama-backend-shared/spec"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
)

const firefoxOnLinux = "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"

func mustSessionStore(t *testing.T, db *gorm.DB, s *spec.Spec) *mwanachamaauth.SessionStore {
	t.Helper()
	st, err := mwanachamaauth.NewSessionStore(db, s)
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}
	return st
}

func startSession(t *testing.T, st *mwanachamaauth.SessionStore, subject, token string, at time.Time) mwanachamaauth.SessionRecord {
	t.Helper()
	rec, err := st.Start(context.Background(), mwanachamaauth.SessionStart{
		SubjectID: subject, Token: token, UserAgent: firefoxOnLinux,
		At: at, ExpiresAt: at.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	return rec
}

var t0 = time.Date(2026, 10, 20, 9, 0, 0, 0, time.UTC)

func TestStartingASessionRecordsTheDeviceAndStoresOnlyTheTokensDigest(t *testing.T) {
	db, s := newTestDB(t)
	st := mustSessionStore(t, db, s)
	rec := startSession(t, st, "s1", "raw-token-one", t0)

	if rec.Device != "Firefox on Linux" {
		t.Errorf("device = %q, want the description and not the user agent", rec.Device)
	}
	if !rec.StartedAt.Equal(t0) || !rec.LastUsedAt.Equal(t0) {
		t.Errorf("started %v, last used %v; want both at %v", rec.StartedAt, rec.LastUsedAt, t0)
	}

	o, _ := s.ByRole(mwanachamaauth.RoleSession)
	var rows []map[string]any
	if err := db.Table(s.TableFor(o)).Find(&rows).Error; err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("want one row, got %d", len(rows))
	}
	sum := sha256.Sum256([]byte("raw-token-one"))
	for column, v := range rows[0] {
		if str, ok := v.(string); ok && str == "raw-token-one" {
			t.Errorf("the raw token is stored in %s", column)
		}
		if str, ok := v.(string); ok && str == firefoxOnLinux {
			t.Errorf("the raw user agent is stored in %s", column)
		}
	}
	if rows[0]["token_digest"] != hex.EncodeToString(sum[:]) {
		t.Errorf("token_digest = %v, want the SHA-256 hex of the token", rows[0]["token_digest"])
	}
}

func TestStartRefusesAMissingSubjectTokenOrExpiry(t *testing.T) {
	db, s := newTestDB(t)
	st := mustSessionStore(t, db, s)
	ctx := context.Background()
	for name, in := range map[string]mwanachamaauth.SessionStart{
		"no subject":        {Token: "t", At: t0, ExpiresAt: t0.Add(time.Hour)},
		"no token":          {SubjectID: "s1", At: t0, ExpiresAt: t0.Add(time.Hour)},
		"expires at start":  {SubjectID: "s1", Token: "t", At: t0, ExpiresAt: t0},
		"expires before it": {SubjectID: "s1", Token: "t", At: t0, ExpiresAt: t0.Add(-time.Hour)},
	} {
		if _, err := st.Start(ctx, in); !errors.Is(err, mwanachamaauth.ErrSessionInvalid) {
			t.Errorf("%s: err = %v, want ErrSessionInvalid", name, err)
		}
	}
}

func TestByTokenFindsALiveSessionAndNothingElse(t *testing.T) {
	db, s := newTestDB(t)
	st := mustSessionStore(t, db, s)
	ctx := context.Background()
	rec := startSession(t, st, "s1", "tok", t0)

	got, err := st.ByToken(ctx, "tok", t0.Add(time.Minute))
	if err != nil || got.ID != rec.ID || got.SubjectID != "s1" {
		t.Fatalf("ByToken = %+v, %v; want %s", got, err, rec.ID)
	}
	for name, token := range map[string]string{"unknown": "other", "empty": ""} {
		if _, err := st.ByToken(ctx, token, t0); !errors.Is(err, mwanachamaauth.ErrSessionNotFound) {
			t.Errorf("%s token: err = %v, want ErrSessionNotFound", name, err)
		}
	}
	if _, err := st.ByToken(ctx, "tok", t0.Add(25*time.Hour)); !errors.Is(err, mwanachamaauth.ErrSessionNotFound) {
		t.Errorf("expired: err = %v, want ErrSessionNotFound", err)
	}
	if err := st.End(ctx, "s1", rec.ID, t0.Add(2*time.Minute)); err != nil {
		t.Fatalf("End: %v", err)
	}
	if _, err := st.ByToken(ctx, "tok", t0.Add(3*time.Minute)); !errors.Is(err, mwanachamaauth.ErrSessionNotFound) {
		t.Errorf("ended: err = %v, want ErrSessionNotFound", err)
	}
}

func TestTouchOnlyMovesLastUsedForward(t *testing.T) {
	db, s := newTestDB(t)
	st := mustSessionStore(t, db, s)
	ctx := context.Background()
	rec := startSession(t, st, "s1", "tok", t0)

	if err := st.Touch(ctx, rec.ID, t0.Add(10*time.Minute)); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	if err := st.Touch(ctx, rec.ID, t0.Add(5*time.Minute)); err != nil {
		t.Fatalf("an older touch must be a no-op, not an error: %v", err)
	}
	got, err := st.ByToken(ctx, "tok", t0.Add(11*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if !got.LastUsedAt.Equal(t0.Add(10 * time.Minute)) {
		t.Errorf("last used = %v, want %v", got.LastUsedAt, t0.Add(10*time.Minute))
	}
	if err := st.Touch(ctx, "session-nobody", t0); !errors.Is(err, mwanachamaauth.ErrSessionNotFound) {
		t.Errorf("unknown id: err = %v, want ErrSessionNotFound", err)
	}
	if err := st.End(ctx, "s1", rec.ID, t0.Add(12*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := st.Touch(ctx, rec.ID, t0.Add(13*time.Minute)); !errors.Is(err, mwanachamaauth.ErrSessionNotFound) {
		t.Errorf("ended: err = %v, want ErrSessionNotFound", err)
	}
}

func TestListLiveIsOneSubjectsUnendedUnexpiredSessionsMostRecentlyUsedFirst(t *testing.T) {
	db, s := newTestDB(t)
	st := mustSessionStore(t, db, s)
	ctx := context.Background()
	older := startSession(t, st, "s1", "a", t0)
	newer := startSession(t, st, "s1", "b", t0.Add(time.Minute))
	ended := startSession(t, st, "s1", "c", t0.Add(2*time.Minute))
	startSession(t, st, "s2", "d", t0)
	if _, err := st.Start(ctx, mwanachamaauth.SessionStart{SubjectID: "s1", Token: "e", At: t0, ExpiresAt: t0.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := st.End(ctx, "s1", ended.ID, t0.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}

	list, err := st.ListLive(ctx, "s1", t0.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != newer.ID || list[1].ID != older.ID {
		t.Fatalf("ListLive = %+v; want %s then %s", list, newer.ID, older.ID)
	}
}

func TestEndIsScopedToTheSubjectAndKeepsTheFirstInstant(t *testing.T) {
	db, s := newTestDB(t)
	st := mustSessionStore(t, db, s)
	ctx := context.Background()
	mine := startSession(t, st, "s1", "a", t0)
	theirs := startSession(t, st, "s2", "b", t0)

	if err := st.End(ctx, "s1", theirs.ID, t0); !errors.Is(err, mwanachamaauth.ErrSessionNotFound) {
		t.Fatalf("ending another subject's session: err = %v, want ErrSessionNotFound", err)
	}
	if _, err := st.ByToken(ctx, "b", t0.Add(time.Minute)); err != nil {
		t.Fatalf("the other subject's session was ended: %v", err)
	}
	if err := st.End(ctx, "s1", "session-invented", t0); !errors.Is(err, mwanachamaauth.ErrSessionNotFound) {
		t.Fatalf("an invented id: err = %v, want ErrSessionNotFound", err)
	}

	if err := st.End(ctx, "s1", mine.ID, t0.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := st.End(ctx, "s1", mine.ID, t0.Add(time.Hour)); err != nil {
		t.Fatalf("ending twice must be idempotent: %v", err)
	}
	o, _ := s.ByRole(mwanachamaauth.RoleSession)
	var endedAt string
	if err := db.Table(s.TableFor(o)).Select("ended_at").Where("id = ?", mine.ID).Scan(&endedAt).Error; err != nil {
		t.Fatal(err)
	}
	if want := t0.Add(time.Minute).Format("2006-01-02T15:04:05.000000000Z"); endedAt != want {
		t.Errorf("ended_at = %q, want the first ending %q", endedAt, want)
	}
}

func TestCheckRefusesADigestThatIsNotSHA256Hex(t *testing.T) {
	s, err := mwanachamaauth.SpecFor("test")
	if err != nil {
		t.Fatal(err)
	}
	row := struct {
		ID          string
		SubjectID   string
		TokenDigest string
	}{ID: "x", SubjectID: "s1", TokenDigest: "raw-token"}
	if err := mwanachamaauth.Check(s, mwanachamaauth.RoleSession, row); err == nil {
		t.Error("a raw token passed as a digest was accepted")
	}
}
