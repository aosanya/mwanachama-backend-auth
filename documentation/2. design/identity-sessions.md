# Identity-project sessions

DEV-1708. The member app signs in through Supabase Auth, so a member app
session is a row in `auth.sessions` of the identity project, the one the host
verifies tokens against. This module reads and ends those rows, so a person
can see where they are signed in and end any one of them, and an agency owner
can see (not end) the sessions of the members of their agencies (member app
decisions 95–97). Who may call which is the host's: `mwanachama-wakala-api`
WK117 decides that a member reads and ends their own and an owner only reads.

This is a different thing from the [`session` role](sessions.md) (DEV-1709).
That one is a record this module keeps for the studio's own sign-ins. This
one keeps nothing: it reads the identity project's rows on demand and deletes
one when asked.

## Never a service-role key

The host holds no Supabase service-role key (wakala-api's decision 64, the
rule WK27 set). The rows are reached through two `SECURITY DEFINER` functions
an operator installs once in the identity project, the pattern
`public.invite_member` already uses (see wakala-api's
`documentation/2. design/member-invitations.md`).

```sql
public.list_sign_in_sessions(p_subject uuid)
  RETURNS TABLE (session_id uuid, user_agent text, started_at timestamptz, last_refreshed_at timestamptz)
public.end_sign_in_session(p_subject uuid, p_session uuid) RETURNS boolean
```

`IdentitySessionFunctions(role)` generates both, and `go run ./cmd/sessionsql
-role <role>` prints them. The role is required and has no default, because
the role is the host's, not this module's.

How they are locked down, the same way as `invite_member`:

- `SECURITY DEFINER`, so they run as their owner (`postgres`, whoever applies
  them) and the host's role needs no right on the `auth` schema.
- `SET search_path = ''`, and every name inside is schema-qualified.
- `REVOKE ALL ... FROM PUBLIC`, and from `anon`, `authenticated` and
  `service_role` when each exists. Supabase grants `EXECUTE` on new functions
  in `public` to those three by default, and `public` is exposed as RPC, so
  revoking from `PUBLIC` alone would let anybody with the anon key list
  anybody's sessions.
- `GRANT EXECUTE` to the one role given. The generator refuses `public`,
  `anon`, `authenticated`, `service_role` and anything that is not a plain
  lower-case identifier.

## What is read, and what never is

For one subject, each session that has not passed its `not_after`:

| Returned | From |
| --- | --- |
| `session_id` | `auth.sessions.id` |
| `user_agent` | `auth.sessions.user_agent`, `''` when absent |
| `started_at` | `created_at`, else `updated_at` |
| `last_refreshed_at` | `refreshed_at` (stored without a zone, in UTC), else `updated_at`, else `created_at` |

Most recently refreshed first.

**The `ip` column is never read, returned or copied** (decision 96). The
function names its four columns; it never selects `*`, and a test fails the
build if the generated SQL names `ip` at all. Nothing is inserted or updated.

**The user agent crosses into Go and goes no further.** `IdentitySessions.List`
classifies it and drops it: `models.IdentitySession` has no field for it, the
same rule the `session` role keeps by storing only a description.

## The device

`ClassifyUserAgent(ua)` answers a `models.DeviceClass`, pure Go:

| Field | Values | How |
| --- | --- | --- |
| `form` | `phone`, `tablet`, `computer`, `""` | iPad, `Tablet`, Kindle, or Android without `Mobile` is a tablet; iPhone, iPod, Windows Phone, `Mobile` or other Android is a phone; Windows NT, Macintosh, CrOS, X11 or Linux is a computer. |
| `client` | `app`, `browser`, `""` | An Android web view (`; wv)`), Dart, OkHttp, CFNetwork, Expo or React Native is an installed app; a recognised browser token is a browser. |
| `description` | e.g. `Chrome on Android` | `DescribeUserAgent`, the same text the `session` role stores. |

An installed web app on a phone's home screen sends its browser's user agent,
so it reads as a browser. Nothing in the user agent tells the two apart, and
this module does not guess.

## Ending one

`end_sign_in_session` locks the session row **for that subject only**
(`WHERE id = p_session AND user_id = p_subject FOR UPDATE`) and answers
`false` when there is none, before it deletes anything. Another subject's
session and an invented id are the same `false`, which `IdentitySessions.End`
turns into `models.ErrSessionNotFound`. Only then does it delete the
session's refresh tokens and the session.

GoTrue's own foreign key already cascades a session's refresh tokens; the
explicit delete is there so the function holds even on a project whose key
does not. Once the refresh tokens are gone, that device's next refresh fails
and it is signed out. An access token it already holds keeps working until it
expires unless the verifier checks that its session still exists.

## The Go side

`IdentitySessions{DB *sql.DB}`, over the host's connection to the identity
project (wakala-api's `DATABASE_URL`):

| Method | Answers |
| --- | --- |
| `List(ctx, subject)` | The subject's live sessions, classified. A subject that is not a UUID has none, and the project is not asked. |
| `End(ctx, subject, session)` | `nil`, or `ErrSessionNotFound` for another subject's, an unknown, or a non-UUID id (the project is not asked for the last). |

Both answer `models.ErrIdentitySessionFunctionsMissing` when Postgres says the
function does not exist (`42883`), the role may not call it (`42501`) or the
schema is missing (`3F000`), so a host can say what an operator has to apply
rather than answering a bare 500. Ids and the subject are bound parameters,
never spliced into the query.

There are no HTTP addresses for these in `auth.operations.json`. Which caller
reaches whose sessions is decided by the host's membership, which this module
cannot see, so the host serves them (WK117).

## What an operator applies

1. Find the role the host's connection to the identity project signs in as.
2. `go run ./cmd/sessionsql -role <that role>`.
3. Read it, then run it once as `postgres` in that project.
4. Check that `has_function_privilege('anon', 'public.list_sign_in_sessions(uuid)', 'EXECUTE')`
   and the same for `authenticated` and for `public.end_sign_in_session(uuid, uuid)`
   are all `false`, and `true` for the host's role.

Re-check and re-apply after a Supabase auth upgrade that changes
`auth.sessions`: the functions read `user_agent`, `refreshed_at` and
`not_after` by name.

## Tests

The SQL is tested as text (lock-down, ownership before delete, no `ip`), the
reader through a scripted `database/sql` driver, and the classifier as a
table. `identity_sessions_postgres_test.go` (`//go:build postgres`) runs both
functions against a stand-in `auth` schema, but only on
`IDENTITY_SCRATCH_POSTGRES_URL`, and skips a database that already has an
`auth` schema so it can never touch a real identity project.
