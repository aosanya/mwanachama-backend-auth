package mwanachamaauth

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

const (
	IdentitySessionSchema   = "public"
	ListSignInSessionsFunc  = IdentitySessionSchema + ".list_sign_in_sessions"
	EndSignInSessionFunc    = IdentitySessionSchema + ".end_sign_in_session"
	listSignInSessionsArgs  = "(uuid)"
	endSignInSessionArgs    = "(uuid, uuid)"
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

func lockDown(signature, role string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "REVOKE ALL ON FUNCTION %s FROM PUBLIC;\nDO $$ BEGIN", signature)
	for _, client := range identityProjectClientRoles {
		fmt.Fprintf(&b, `
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '%[1]s') THEN
    REVOKE ALL ON FUNCTION %[2]s FROM %[1]s;
  END IF;`, client, signature)
	}
	fmt.Fprintf(&b, "\nEND $$;\nGRANT EXECUTE ON FUNCTION %s TO %s;\n", signature, role)
	return b.String()
}

func IdentitySessionFunctions(role string) (string, error) {
	if err := checkGrantableRole(role); err != nil {
		return "", err
	}
	list := fmt.Sprintf(`
CREATE OR REPLACE FUNCTION %[1]s(p_subject uuid)
RETURNS TABLE (session_id uuid, user_agent text, started_at timestamptz, last_refreshed_at timestamptz)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = ''
AS $fn$
  SELECT s.id,
         coalesce(s.user_agent, ''),
         coalesce(s.created_at, s.updated_at),
         coalesce(s.refreshed_at AT TIME ZONE '%[2]s', s.updated_at, s.created_at)
  FROM auth.sessions AS s
  WHERE s.user_id = p_subject
    AND (s.not_after IS NULL OR s.not_after > now())
  ORDER BY 4 DESC NULLS LAST, 1
$fn$;

`, ListSignInSessionsFunc, identityProjectNoTzZone)
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
	return list + lockDown(ListSignInSessionsFunc+listSignInSessionsArgs, role) +
		end + lockDown(EndSignInSessionFunc+endSignInSessionArgs, role), nil
}
