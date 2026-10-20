package mwanachamaauth_test

import (
	"regexp"
	"strings"
	"testing"

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
	for _, sig := range []string{"public.list_sign_in_sessions(uuid)", "public.end_sign_in_session(uuid, uuid)"} {
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
	if got := strings.Count(sql, "SECURITY DEFINER"); got != 2 {
		t.Errorf("%d functions are SECURITY DEFINER, want 2", got)
	}
	if got := strings.Count(sql, "SET search_path = ''"); got != 2 {
		t.Errorf("%d functions pin an empty search_path, want 2", got)
	}
	if got := strings.Count(sql, "GRANT EXECUTE"); got != 2 {
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
	if strings.Contains(sql, "INSERT") || strings.Contains(sql, "UPDATE ") {
		t.Fatal("the session functions copy or change a session")
	}
}

func TestListingReadsOnlyOneSubjectsLiveSessions(t *testing.T) {
	sql := identitySessionSQL(t)
	for _, want := range []string{
		"RETURNS TABLE (session_id uuid, user_agent text, started_at timestamptz, last_refreshed_at timestamptz)",
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
