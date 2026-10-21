# Sessions

DEV-1709. A signed-in browser session is a record this module keeps, so the
person holding it can see where they are signed in and end any one of them.
It serves the studio's Administration › Sessions screen, where an owner sees
their own studio sessions and ends any but the one in use (member app
requirements, decisions 95–97). The wiring into `mwanachama-wakala-api` is
its own row there, WK117; nothing here reaches into that repo.

## What is kept, and what is not

The `session` role, declared in `auth.blueprint.json`:

| Field | What it is |
| --- | --- |
| `id` | `session-<uuid>`, the handle a holder names to end it. Random rather than sequence-minted, so the ids of other people's sessions cannot be counted off one's own. It proves nothing on its own. |
| `subject_id` | Who signed in. Every read and every end is scoped to it. |
| `token_digest` | SHA-256 of the session token, lower-case hex, unique, `matches: sha256_hex`. |
| `device` | A short description such as `Firefox on Linux`, derived from the user agent. |
| `started_at` | When it was signed in. |
| `last_used_at` | When it last carried a request; only moves forward. |
| `expires_at` | When it stops being honoured whatever else happens. |
| `ended_at` | When its holder ended it; nullable, kept at the first ending. |

**No network address and no location** (decision 96). There is no column
for either, so there is nothing to forget to leave out.

**The token is never stored.** `Start` takes the raw token and writes only
its digest; `ByToken` digests what it is given and looks that up. A copy of
the table cannot be replayed as a sign-in. The `sha256_hex` pattern is what
stops a raw token being written into the digest column by mistake: `Check`
refuses anything that is not 64 lower-case hex characters.

**The user agent is never stored either.** `Start` takes it and keeps
`DescribeUserAgent`'s answer: one browser name from a fixed list and one
system name from a fixed list, or the empty string when neither is
recognised. The full string is a fingerprint and the screen only needs the
two names. The description is derived inside the module, not by the host,
so a host cannot store the raw string by passing it through.

The carrier is `sessionRow`, which holds `token_digest`;
`models.SessionRecord` does not, so the digest is never on a type a response
is built from. This is the same shape as `credentialRecord` and
`saltRecord` in [declared storage](declared-storage.md).

## The repository

`models.SessionRepository` is a fifth interface beside the four that must
not change; it changes none of them.

| Method | What it does |
| --- | --- |
| `Start(ctx, SessionStart)` | Records a new session. Refuses a missing subject, a missing token, or an expiry not after the start with `ErrSessionInvalid`. |
| `ByToken(ctx, token, now)` | The live session a token belongs to. Unknown, ended and expired all answer `ErrSessionNotFound`. |
| `Touch(ctx, id, at)` | Moves `last_used_at` forward. An older instant is a no-op, not an error, so two requests racing cannot move it back. An ended or unknown session answers `ErrSessionNotFound`. |
| `ListLive(ctx, subject, now)` | One subject's sessions that are neither ended nor expired, most recently used first. |
| `End(ctx, subject, id, at)` | Ends one session of that subject's. Another subject's and an invented id are the same `ErrSessionNotFound`. Ending one already ended is idempotent and keeps the first instant. |

How often a host calls `Touch` is the host's choice. Writing on every request
is correct but not cheap; a host may skip the write when the stored instant is
recent enough, since the screen shows "last used" at minute resolution at
best. `LastSeenThrottle` (two minutes) is the interval the member app's
sessions keep (decision 165, [identity sessions](identity-sessions.md#last-seen)),
and the natural one to reuse here.

Expiry is compared as text. Every timestamp is written in specstore's
fixed-width layout, which sorts in time order, and the table is a new one
`spec.Migrate` creates, so the adopted-column-type trap in
[adopted column types](adopted-column-types.md) does not apply. If this table
is ever adopted from an older hand-written one, that comparison has to be
revisited.

## Its own store, its own carriers

`SessionStore` builds its `specstore` over a carrier map holding only the
`session` role, not over the shared `carriers()`. A domain spec that does not
claim `session` — `mwanachama-wakala-api`'s own `wakala.auth.json`, until
WK117 adds it — still builds every other store unchanged. Adding `session`
to `carriers()` would have made every existing store refuse to construct
against that declaration.

Both shipped domains claim it: `auth.platform.json` as `console_session`,
`auth.clinic.json` as `desk_session`, each with a `by_subject` index for the
list.

## The two addresses

| Action | Address | Answers |
| --- | --- | --- |
| `auth.session.list` | `GET /sessions` | `200 {"sessions": [...]}`, the caller's own live sessions, each with `current: true` on the one making the request. |
| `auth.session.end` | `DELETE /sessions/{sessionID}` | `204`. `404` for another subject's or an unknown id, in identical words. `409` for the session making the request. |

Both are gated: neither is on `AnonymousActions`. Both are `handled`, for the
reason the [route table](routes.md) gives for the rest — the end address has
an ordering to protect (the session in use is refused before the store is
asked) and needs a fact no declared call can carry, which session the request
arrived on.

That fact is a new seam, `routes.CurrentSession`, with one method,
`CallerSessionID(r)`. The mount answers it from whatever it verified the
request with, typically the `id` `ByToken` returned. It is separate from
`Identity` so that adding it changed no interface a mount already
implements. A mount that supplies none gets no `current` flag and no refusal
of the session in use; the subject scoping still holds, because that is the
store's and keyed on `Identity.CallerID`.

Refusing the session in use is a choice about where sign-out lives, not a
security property: ending it from the list would sign the screen out from
under itself, and the mount already has a sign-out.

A mount that builds the routes without a session store gets `501` from both
addresses rather than a nil-pointer panic.

## What this does not do

- It does not mint tokens. The mount still mints and signs them; this module
  records what was minted.
- It does not let an owner end somebody else's session. Decision 95 lets an
  agency owner *see* their members' sessions and not end them; those are
  member app sessions held by Supabase Auth, which are
  [identity-project sessions](identity-sessions.md) (DEV-1708), not this
  table.
- It does not bound how many live sessions one subject holds or sweep
  expired rows. Neither was asked for; an expired row is invisible to every
  read already.
