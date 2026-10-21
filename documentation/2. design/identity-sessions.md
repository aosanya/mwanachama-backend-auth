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
one reads the identity project's rows on demand and deletes one when asked;
the one thing it keeps is when each session was last used (DEV-1710, below),
in a table of its own beside `auth.sessions`, never in it.

## Never a service-role key

The host holds no Supabase service-role key (wakala-api's decision 64, the
rule WK27 set). The rows are reached through three `SECURITY DEFINER` functions
an operator installs once in the identity project, the pattern
`public.invite_member` already uses (see wakala-api's
`documentation/2. design/member-invitations.md`).

```sql
public.list_sign_in_sessions(p_subject uuid)
  RETURNS TABLE (session_id uuid, user_agent text, started_at timestamptz,
                 last_refreshed_at timestamptz, last_seen_at timestamptz)
public.end_sign_in_session(p_subject uuid, p_session uuid) RETURNS boolean
public.touch_sign_in_session(p_subject uuid, p_session uuid) RETURNS void
```

`IdentitySessionFunctions(role)` generates all three, with the last-seen
table they share, as one transaction (`BEGIN` … `COMMIT`), and
`go run ./cmd/sessionsql -role <role>` prints them. The role is required and has no default, because
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
| `last_seen_at` | the later of `last_refreshed_at` and the session's last-seen time, below |

Most recently seen first.

**The `ip` column is never read, returned or copied** (decision 96). The
function names its columns; it never selects `*`, and a test fails the
build if the generated SQL names `ip` at all. Nothing in the `auth` schema is
inserted or updated; the one write is the last-seen time, in its own table.

## Last seen

DEV-1710, member app decision 165: Last seen stays within a few minutes of
use. `refreshed_at` moves only when the device refreshes its token, about
hourly, so a list read from it can be an hour behind a device in use.

The host calls a touch for each verified request that carries a session, and
the list reads the touch back as `last_seen_at`. `last_refreshed_at` is still
returned, unchanged, so a reader that has not moved to `last_seen_at` keeps
working.

**The throttle is `LastSeenThrottle`, two minutes.** A touch moves a
session's last-seen time at most once per throttle, so the list is at most two
minutes behind the latest request from one host process. With several host
processes each throttling on its own, the database's guard (below) still
writes at most once per throttle, and the list can lag by up to twice the
throttle, four minutes. Two minutes keeps that worst case inside "a few
minutes"; a write per active session every two minutes is cheap.

The throttle is held twice, for two different costs:

- **`LastSeen`, in the host process**, skips the round trip. It remembers,
  per subject and session, when it last asked the project, and asks again only
  once the throttle has passed. A failed touch is forgotten, so the next
  request retries it. Old entries are swept once per throttle, so the map
  holds only sessions seen within the last throttle or two. A `LastSeen` is
  built once and shared (`&LastSeen{Sessions: identitySessions}`); `Now` is
  for tests.
- **`touch_sign_in_session`, in the project**, skips the write. Its upsert
  updates an existing row only when the stored time is older than the
  throttle (`interval '<seconds> seconds'`, generated from the same
  constant), so several host processes do not each write.

What the touch writes, and what it never does:

- It writes only `sign_in_private.session_last_seen (session_id, seen_at)`,
  one row per session. **It never writes `auth.sessions`**: `refreshed_at`
  and `updated_at` are what GoTrue's inactivity timeout reads, so moving them
  on use would quietly keep a session alive that the project would otherwise
  end. Last seen is a display fact and stays one.
- It touches a session only if that session is **the subject's own and
  live** (`user_id = p_subject`, `not_after` not passed). Another subject's
  session and an invented id write nothing, and the call does not say which.
- The row references `auth.sessions(id) ON DELETE CASCADE`, so ending a
  session, here or by GoTrue's own sign-out, removes its last-seen time. A
  touch racing an ending can fail that foreign key (`23503`);
  `IdentitySessions.Touch` answers that as success, since the session it
  would have touched is gone.

The table is locked down like the functions: it lives in its own schema,
`sign_in_private`, which the project's API does not expose; both the schema
and the table have `ALL` revoked from `PUBLIC`, `anon`, `authenticated` and
`service_role`; row-level security is on with no policy; and nothing is
granted to the host's role. Only the `SECURITY DEFINER` functions, running as
their owner, read or write it.

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
| `Touch(ctx, subject, session)` | `nil` whether or not anything moved. `ErrSessionNotFound` for a non-UUID id, without asking the project. Unthrottled; a host calls it through `LastSeen`. |

`LastSeen.Touch` has the same signature and answers, throttled. Both satisfy
`SessionToucher`, the one-method interface a host can depend on.

All three answer `models.ErrIdentitySessionFunctionsMissing` when Postgres
says the function does not exist (`42883`), the role may not call it
(`42501`), the schema is missing (`3F000`) or a column is missing (`42703`,
what the listing answers when the project still has the version without
`last_seen_at`), so a host can say what an operator has to apply rather than
answering a bare 500. A host should not fail a request because its touch
failed; the touch is a side effect of the request, not part of it. Ids and the subject are bound parameters,
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
   and `public.touch_sign_in_session(uuid, uuid)` are all `false`, and `true`
   for the host's role; and that
   `has_table_privilege(<role>, 'sign_in_private.session_last_seen', 'SELECT')`
   is `false` for `anon`, `authenticated` and the host's role alike.

The script is safe to run again. It is how a project that has DEV-1708's two
functions gains DEV-1710's: the listing's result columns changed, which
`CREATE OR REPLACE` cannot do, so the script drops and recreates it, inside
the same transaction so a failure leaves the old one in place. **Apply it
before deploying a host that reads `last_seen_at`**; the other order answers
`ErrIdentitySessionFunctionsMissing` until it is applied.

Re-check and re-apply after a Supabase auth upgrade that changes
`auth.sessions`: the functions read `user_agent`, `refreshed_at` and
`not_after` by name, and the last-seen table references `auth.sessions(id)`.

## Tests

The SQL is tested as text (lock-down of the functions, the schema and the
table; ownership before delete; no `ip`; no write to `auth`; the touch scoped
to the subject's live session and throttled by `LastSeenThrottle`), the reader
through a scripted `database/sql` driver, `LastSeen` against a recording
store and a stepped clock, and the classifier as a table.
`identity_sessions_postgres_test.go` (`//go:build postgres`) applies the
script twice and runs all three functions against a stand-in `auth` schema, but only on
`IDENTITY_SCRATCH_POSTGRES_URL`, and skips a database that already has an
`auth` schema so it can never touch a real identity project.
