package mwanachamaauth_test

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
)

func identitySessionSQL(t *testing.T) string {
	t.Helper()
	sql, err := mwanachamaauth.IdentitySessionFunctions("host_api")
	if err != nil {
		t.Fatal(err)
	}
	return sql
}

func TestIdentitySessionFunctionsAreLockedDownToTheHostRole(t *testing.T) {
	sql := identitySessionSQL(t)
	for _, sig := range []string{"public.list_sign_in_sessions(uuid)", "public.end_sign_in_session(uuid, uuid)", "public.touch_sign_in_session(uuid, uuid)"} {
		for _, want := range []string{
			"REVOKE ALL ON FUNCTION " + sig + " FROM PUBLIC;",
			"REVOKE ALL ON FUNCTION " + sig + " FROM anon;",
			"REVOKE ALL ON FUNCTION " + sig + " FROM authenticated;",
			"REVOKE ALL ON FUNCTION " + sig + " FROM service_role;",
			"GRANT EXECUTE ON FUNCTION " + sig + " TO host_api;",
		} {
			if !strings.Contains(sql, want) {
				t.Errorf("missing %q", want)
			}
		}
	}
	if got := strings.Count(sql, "SECURITY DEFINER"); got != 3 {
		t.Errorf("%d functions are SECURITY DEFINER, want 3", got)
	}
	if got := strings.Count(sql, "SET search_path = ''"); got != 3 {
		t.Errorf("%d functions pin an empty search_path, want 3", got)
	}
	if got := strings.Count(sql, "GRANT "); got != 3 {
		t.Errorf("%d grants, want one per function", got)
	}
}

func TestIdentitySessionFunctionsNeverTouchTheNetworkAddress(t *testing.T) {
	sql := identitySessionSQL(t)
	if regexp.MustCompile(`(?i)\bip\b`).MatchString(sql) {
		t.Fatal("the session functions name the ip column")
	}
	if strings.Contains(sql, "s.*") || strings.Contains(sql, "SELECT *") {
		t.Fatal("the session functions select every column")
	}
	if regexp.MustCompile(`(?i)(INSERT INTO|UPDATE)\s+auth\.`).MatchString(sql) {
		t.Fatal("the session functions copy or change a session")
	}
	if got := strings.Count(sql, "INSERT INTO"); got != 1 || !strings.Contains(sql, "INSERT INTO sign_in_private.session_last_seen AS seen (session_id, seen_at)") {
		t.Fatal("something other than the last-seen time is written")
	}
}

func TestTheLastSeenTableIsReachableOnlyThroughTheFunctions(t *testing.T) {
	sql := identitySessionSQL(t)
	for _, want := range []string{
		"CREATE SCHEMA IF NOT EXISTS sign_in_private;",
		"session_id uuid PRIMARY KEY REFERENCES auth.sessions(id) ON DELETE CASCADE,",
		"ALTER TABLE sign_in_private.session_last_seen ENABLE ROW LEVEL SECURITY;",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %q", want)
		}
	}
	for _, object := range []string{"SCHEMA sign_in_private", "TABLE sign_in_private.session_last_seen"} {
		for _, from := range []string{"PUBLIC", "anon", "authenticated", "service_role"} {
			if want := "REVOKE ALL ON " + object + " FROM " + from + ";"; !strings.Contains(sql, want) {
				t.Errorf("missing %q", want)
			}
		}
	}
	if strings.Contains(sql, "sign_in_private TO") || strings.Contains(sql, "session_last_seen TO") {
		t.Fatal("the last-seen store is granted to a role")
	}
}

func TestTouchingMovesOnlyTheSubjectsLiveSessionAndAtMostOncePerThrottle(t *testing.T) {
	sql := identitySessionSQL(t)
	for _, want := range []string{
		"CREATE OR REPLACE FUNCTION public.touch_sign_in_session(p_subject uuid, p_session uuid)",
		"WHERE s.id = p_session\n    AND s.user_id = p_subject\n    AND (s.not_after IS NULL OR s.not_after > now())",
		"ON CONFLICT (session_id) DO UPDATE\n    SET seen_at = excluded.seen_at\n    WHERE seen.seen_at < excluded.seen_at - interval '" + strconv.Itoa(int(mwanachamaauth.LastSeenThrottle/time.Second)) + " seconds'",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %q", want)
		}
	}
	if mwanachamaauth.LastSeenThrottle < time.Minute || mwanachamaauth.LastSeenThrottle > 5*time.Minute {
		t.Fatalf("the throttle is %v; last seen is to stay within a few minutes of use", mwanachamaauth.LastSeenThrottle)
	}
}

func TestListingReadsLastSeenAsTheLaterOfUseAndRefresh(t *testing.T) {
	sql := identitySessionSQL(t)
	for _, want := range []string{
		"DROP FUNCTION IF EXISTS public.list_sign_in_sessions(uuid);",
		"LEFT JOIN sign_in_private.session_last_seen AS seen ON seen.session_id = s.id",
		"greatest(seen.seen_at, coalesce(s.refreshed_at AT TIME ZONE 'UTC', s.updated_at, s.created_at))",
		"ORDER BY 5 DESC NULLS LAST, 1",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %q", want)
		}
	}
	if !strings.HasPrefix(sql, "BEGIN;\n") || !strings.HasSuffix(sql, "COMMIT;\n") {
		t.Fatal("the script is not one transaction, so a failed replace could leave the listing dropped")
	}
}

func TestListingReadsOnlyOneSubjectsLiveSessions(t *testing.T) {
	sql := identitySessionSQL(t)
	for _, want := range []string{
		"RETURNS TABLE (session_id uuid, user_agent text, started_at timestamptz, last_refreshed_at timestamptz, last_seen_at timestamptz)",
		"FROM auth.sessions AS s",
		"WHERE s.user_id = p_subject",
		"s.not_after IS NULL OR s.not_after > now()",
	} {
		if !strings.Contains(sql, want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestEndingChecksTheSessionIsTheSubjectsBeforeDeletingAnything(t *testing.T) {
	sql := identitySessionSQL(t)
	check := strings.Index(sql, "PERFORM 1 FROM auth.sessions WHERE id = p_session AND user_id = p_subject FOR UPDATE;")
	refuse := strings.Index(sql, "IF NOT FOUND THEN\n    RETURN false;")
	tokens := strings.Index(sql, "DELETE FROM auth.refresh_tokens WHERE session_id = p_session;")
	session := strings.Index(sql, "DELETE FROM auth.sessions WHERE id = p_session AND user_id = p_subject;")
	if check < 0 || refuse < check || tokens < refuse || session < tokens {
		t.Fatalf("ownership is not settled before the deletes: check %d, refuse %d, tokens %d, session %d", check, refuse, tokens, session)
	}
	if strings.Count(sql, "DELETE FROM") != 2 {
		t.Fatal("the end function deletes from more than the session and its refresh tokens")
	}
}

func TestIdentitySessionFunctionsRefuseARoleTheyCannotSafelyGrant(t *testing.T) {
	for _, role := range []string{"", "anon", "authenticated", "service_role", "public", "Host", "x; DROP TABLE auth.sessions", "a b"} {
		if _, err := mwanachamaauth.IdentitySessionFunctions(role); err == nil {
			t.Errorf("%q was accepted", role)
		}
	}
	if _, err := mwanachamaauth.IdentitySessionFunctions("postgres"); err != nil {
		t.Errorf("postgres refused: %v", err)
	}
}
