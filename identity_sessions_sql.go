package mwanachamaauth

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
)

const LastSeenThrottle = 2 * time.Minute

const (
	IdentitySessionSchema   = "public"
	ListSignInSessionsFunc  = IdentitySessionSchema + ".list_sign_in_sessions"
	EndSignInSessionFunc    = IdentitySessionSchema + ".end_sign_in_session"
	TouchSignInSessionFunc  = IdentitySessionSchema + ".touch_sign_in_session"
	LastSeenSchema          = "sign_in_private"
	LastSeenTable           = LastSeenSchema + ".session_last_seen"
	listSignInSessionsArgs  = "(uuid)"
	endSignInSessionArgs    = "(uuid, uuid)"
	touchSignInSessionArgs  = "(uuid, uuid)"
	identityProjectNoTzZone = "UTC"
)

var grantableRolePattern = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

var identityProjectClientRoles = []string{"anon", "authenticated", "service_role"}

func checkGrantableRole(role string) error {
	if !grantableRolePattern.MatchString(role) {
		return fmt.Errorf("identity sessions: %q is not a role name", role)
	}
	if role == "public" || slices.Contains(identityProjectClientRoles, role) {
		return fmt.Errorf("identity sessions: %q is a role the project's clients sign in as, never the host's", role)
	}
	return nil
}

func revokeFromClients(b *strings.Builder, kind, object string) {
	fmt.Fprintf(b, "REVOKE ALL ON %s %s FROM PUBLIC;\nDO $$ BEGIN", kind, object)
	for _, client := range identityProjectClientRoles {
		fmt.Fprintf(b, `
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '%[1]s') THEN
    REVOKE ALL ON %[2]s %[3]s FROM %[1]s;
  END IF;`, client, kind, object)
	}
	b.WriteString("\nEND $$;\n")
}

func lockDown(signature, role string) string {
	var b strings.Builder
	revokeFromClients(&b, "FUNCTION", signature)
	fmt.Fprintf(&b, "GRANT EXECUTE ON FUNCTION %s TO %s;\n", signature, role)
	return b.String()
}

func lastSeenStore() string {
	var b strings.Builder
	fmt.Fprintf(&b, `
CREATE SCHEMA IF NOT EXISTS %[1]s;
CREATE TABLE IF NOT EXISTS %[2]s (
  session_id uuid PRIMARY KEY REFERENCES auth.sessions(id) ON DELETE CASCADE,
  seen_at timestamptz NOT NULL
);
ALTER TABLE %[2]s ENABLE ROW LEVEL SECURITY;
`, LastSeenSchema, LastSeenTable)
	revokeFromClients(&b, "SCHEMA", LastSeenSchema)
	revokeFromClients(&b, "TABLE", LastSeenTable)
	return b.String()
}

func IdentitySessionFunctions(role string) (string, error) {
	if err := checkGrantableRole(role); err != nil {
		return "", err
	}
	refreshed := fmt.Sprintf("coalesce(s.refreshed_at AT TIME ZONE '%s', s.updated_at, s.created_at)", identityProjectNoTzZone)
	list := fmt.Sprintf(`
DROP FUNCTION IF EXISTS %[1]s%[2]s;
CREATE FUNCTION %[1]s(p_subject uuid)
RETURNS TABLE (session_id uuid, user_agent text, started_at timestamptz, last_refreshed_at timestamptz, last_seen_at timestamptz)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $fn$
  SELECT s.id,
         coalesce(s.user_agent, ''),
         coalesce(s.created_at, s.updated_at),
         %[3]s,
         greatest(seen.seen_at, %[3]s)
  FROM auth.sessions AS s
  LEFT JOIN %[4]s AS seen ON seen.session_id = s.id
  WHERE s.user_id = p_subject
    AND (s.not_after IS NULL OR s.not_after > now())
  ORDER BY 5 DESC NULLS LAST, 1
$fn$;

`, ListSignInSessionsFunc, listSignInSessionsArgs, refreshed, LastSeenTable)
	end := fmt.Sprintf(`
CREATE OR REPLACE FUNCTION %[1]s(p_subject uuid, p_session uuid)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $fn$
BEGIN
  PERFORM 1 FROM auth.sessions WHERE id = p_session AND user_id = p_subject FOR UPDATE;
  IF NOT FOUND THEN
    RETURN false;
  END IF;
  DELETE FROM auth.refresh_tokens WHERE session_id = p_session;
  DELETE FROM auth.sessions WHERE id = p_session AND user_id = p_subject;
  RETURN true;
END;
$fn$;

`, EndSignInSessionFunc)
	touch := fmt.Sprintf(`
CREATE OR REPLACE FUNCTION %[1]s(p_subject uuid, p_session uuid)
RETURNS void
LANGUAGE sql
VOLATILE
SECURITY DEFINER
SET search_path = ''
AS $fn$
  INSERT INTO %[2]s AS seen (session_id, seen_at)
  SELECT s.id, now()
  FROM auth.sessions AS s
  WHERE s.id = p_session
    AND s.user_id = p_subject
    AND (s.not_after IS NULL OR s.not_after > now())
  ON CONFLICT (session_id) DO UPDATE
    SET seen_at = excluded.seen_at
    WHERE seen.seen_at < excluded.seen_at - interval '%[3]d seconds'
$fn$;

`, TouchSignInSessionFunc, LastSeenTable, int(LastSeenThrottle/time.Second))
	return "BEGIN;\n" + lastSeenStore() +
		list + lockDown(ListSignInSessionsFunc+listSignInSessionsArgs, role) +
		end + lockDown(EndSignInSessionFunc+endSignInSessionArgs, role) +
		touch + lockDown(TouchSignInSessionFunc+touchSignInSessionArgs, role) +
		"COMMIT;\n", nil
}
