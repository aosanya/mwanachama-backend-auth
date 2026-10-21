//go:build postgres

package mwanachamaauth_test

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
	"github.com/aosanya/mwanachama-backend-auth/models"
)

const identityStandIn = `
CREATE SCHEMA auth;
CREATE TABLE auth.sessions (
  id uuid PRIMARY KEY,
  user_id uuid NOT NULL,
  created_at timestamptz,
  updated_at timestamptz,
  refreshed_at timestamp,
  not_after timestamptz,
  user_agent text,
  ip inet
);
CREATE TABLE auth.refresh_tokens (
  id bigserial PRIMARY KEY,
  token text,
  user_id varchar(255),
  session_id uuid REFERENCES auth.sessions(id) ON DELETE CASCADE
);
`

func identityProjectStandIn(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("IDENTITY_SCRATCH_POSTGRES_URL")
	if dsn == "" {
		t.Skip("IDENTITY_SCRATCH_POSTGRES_URL not set; it must name a throwaway database with no auth schema")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	var exists bool
	if err := db.QueryRow(`SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'auth')`).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Skip("this database already has an auth schema; refusing to touch a real identity project")
	}
	role := "session_reader_test"
	if _, err := db.Exec(`CREATE ROLE ` + role); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Exec(`DROP FUNCTION IF EXISTS public.list_sign_in_sessions(uuid), public.end_sign_in_session(uuid, uuid), public.touch_sign_in_session(uuid, uuid)`)
		db.Exec(`DROP SCHEMA sign_in_private CASCADE`)
		db.Exec(`DROP SCHEMA auth CASCADE`)
		db.Exec(`DROP ROLE ` + role)
	})
	if _, err := db.Exec(identityStandIn); err != nil {
		t.Fatal(err)
	}
	functions, err := mwanachamaauth.IdentitySessionFunctions(role)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := db.Exec(functions); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func TestIdentitySessionsAgainstPostgres(t *testing.T) {
	db := identityProjectStandIn(t)
	ctx := context.Background()
	mine, theirs := "00000000-0000-0000-0000-00000000000a", "00000000-0000-0000-0000-00000000000b"
	if _, err := db.Exec(`
INSERT INTO auth.sessions (id, user_id, created_at, updated_at, refreshed_at, not_after, user_agent, ip) VALUES
  ('00000000-0000-0000-0000-0000000000a1', $1, now() - interval '2 days', now(), now() AT TIME ZONE 'UTC', NULL, 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) Safari/604.1', '203.0.113.7'),
  ('00000000-0000-0000-0000-0000000000a2', $1, now() - interval '9 days', now(), NULL, now() - interval '1 day', '', '203.0.113.7'),
  ('00000000-0000-0000-0000-0000000000b1', $2, now(), now(), NULL, NULL, '', '198.51.100.1');
INSERT INTO auth.refresh_tokens (token, user_id, session_id) VALUES ('t1', $1, '00000000-0000-0000-0000-0000000000a1');
`, mine, theirs); err != nil {
		t.Fatal(err)
	}
	store := mwanachamaauth.IdentitySessions{DB: db}

	got, err := store.List(ctx, mine)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "00000000-0000-0000-0000-0000000000a1" || got[0].Device.Form != models.DeviceFormPhone {
		t.Fatalf("listed %+v, want the one live session, on a phone", got)
	}

	if got[0].LastSeenAt.Before(got[0].LastRefreshedAt) {
		t.Fatalf("last seen %v before the last refresh %v", got[0].LastSeenAt, got[0].LastRefreshedAt)
	}

	if _, err := db.Exec(`UPDATE auth.sessions SET refreshed_at = (now() - interval '1 hour') AT TIME ZONE 'UTC' WHERE user_id = $1`, mine); err != nil {
		t.Fatal(err)
	}
	if err := store.Touch(ctx, theirs, got[0].ID); err != nil {
		t.Fatal(err)
	}
	var touched int
	if err := db.QueryRow(`SELECT count(*) FROM sign_in_private.session_last_seen`).Scan(&touched); err != nil || touched != 0 {
		t.Fatalf("another subject's touch was kept: %d, %v", touched, err)
	}
	if err := store.Touch(ctx, mine, got[0].ID); err != nil {
		t.Fatal(err)
	}
	if err := store.Touch(ctx, mine, "00000000-0000-0000-0000-0000000000a2"); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM sign_in_private.session_last_seen`).Scan(&touched); err != nil || touched != 1 {
		t.Fatalf("%d last-seen rows, want only the live session's, %v", touched, err)
	}
	if _, err := db.Exec(`UPDATE sign_in_private.session_last_seen SET seen_at = now() - interval '30 seconds'`); err != nil {
		t.Fatal(err)
	}
	if err := store.Touch(ctx, mine, got[0].ID); err != nil {
		t.Fatal(err)
	}
	var throttled bool
	if err := db.QueryRow(`SELECT seen_at < now() - interval '20 seconds' FROM sign_in_private.session_last_seen`).Scan(&throttled); err != nil || !throttled {
		t.Fatalf("a touch inside the throttle moved last seen: %v", err)
	}
	if got, err = store.List(ctx, mine); err != nil || len(got) != 1 {
		t.Fatalf("%+v, %v", got, err)
	}
	if !got[0].LastSeenAt.After(got[0].LastRefreshedAt) {
		t.Fatalf("last seen %v did not move past the refresh %v", got[0].LastSeenAt, got[0].LastRefreshedAt)
	}
	var reachable bool
	if err := db.QueryRow(`SELECT has_table_privilege('session_reader_test', 'sign_in_private.session_last_seen', 'SELECT')`).Scan(&reachable); err != nil || reachable {
		t.Fatalf("the host role reads the last-seen table directly: %v", err)
	}

	if err := store.End(ctx, theirs, got[0].ID); !errors.Is(err, models.ErrSessionNotFound) {
		t.Fatalf("another subject ended it: %v", err)
	}
	if err := store.End(ctx, mine, got[0].ID); err != nil {
		t.Fatal(err)
	}
	var left int
	if err := db.QueryRow(`SELECT count(*) FROM auth.refresh_tokens`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("%d refresh tokens survive the session, %v", left, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM sign_in_private.session_last_seen`).Scan(&left); err != nil || left != 0 {
		t.Fatalf("%d last-seen rows survive the session, %v", left, err)
	}
	if err := store.End(ctx, mine, got[0].ID); !errors.Is(err, models.ErrSessionNotFound) {
		t.Fatalf("ending twice: %v", err)
	}
}
