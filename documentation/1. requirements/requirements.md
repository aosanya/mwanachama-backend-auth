# Requirements

## Why this repo exists

`mwanachama-backend-api-gateway`'s stated end state is an empty
`internal/domain` — every package either already has, or gets, a home in a
sibling repo, following the pattern `mwanachama-backend-actor` set
(see the gateway's `documentation/2. design/architecture-domain-decomposition.md`).
Five packages — `auth`, `operator`, `verification`, `phonenumber`,
`phonesalt` — had no destination decided as of that note: they cluster into
one bounded context ("proving or recording who someone is, not what they do
once identified") that did not match any existing sibling repo's scope. This
repo is that destination.

Scope confirmed by the owner (2026-09-06,
`documentation/2. design/design-register.md` in the gateway repo): full
extraction, `models/`+`gormstore/`+`routes/`, same template as actor/comm.

## What was ported

All five domains, field-for-field and (where the gateway's own comments
carried DEV-xxx/G-xxx reasoning) with that reasoning preserved verbatim in
spirit:

1. **auth** — device registration + challenge/verify sign-in, and the
   phone-number lock-out state that gates it.
2. **operator** — the console's own stored email/password credential.
3. **verification** — a member's unverified/pending/verified/rejected
   status.
4. **phonenumber** — E.164 canonicalization (pure, stateless, its own leaf
   subpackage).
5. **phonesalt** — the per-organization phone-hashing salt `phonenumber`
   already coupled to in the gateway.

## Decisions made while porting

1. **Named `auth`, not `identity`.** The gateway's own decomposition note
   proposed `mwanachama-backend-identity`; `identity` already names an
   unrelated story track in the gateway about member identity *flows*
   (`todo_identity_recover.md` etc.), so a different name was needed to
   avoid confusion between "this repo" and "that story track". See the
   gateway's `documentation/2. design/design-register.md`, 2026-09-06 entry.
2. **Naming collisions resolved by domain-of-origin prefix**, mirroring
   `mwanachama-backend-comm`'s identical resolution for chat/directmessage/
   moderation. See CLAUDE.md for the full mapping.
3. **Session-token minting stays gateway-owned.** `routes/session.go`'s
   `SessionMinter` interface is the seam; this repo never imports or
   depends on the gateway's `internal/session` package.
4. **`gorm.io/datatypes` (JSONB support) was not added as a dependency.**
   None of the five domains store a JSON-typed column — unlike
   `mwanachama-backend-actor`'s `Attributes` or
   `mwanachama-backend-assetmanager`'s `AttributesJSON` — so the dependency
   sibling repos carry for that reason was left out rather than added
   speculatively.
5. **`ConsumeChallenge` is read-then-guarded-write**, not the gateway's
   original single atomic `UPDATE ... WHERE expires_at > $now` statement —
   see CLAUDE.md's gormstore section for why (a raw SQL time comparison
   against sqlite's text-encoded timestamp column proved unreliable in this
   repo's own test suite).

## Out of scope for this repo (by design)

- Wiring into the gateway's `go.mod`/`cmd/server/stores.go` (DEV-1655),
  cutting the gateway's HTTP layer over to `routes/` (DEV-1656), and
  archiving the gateway's superseded Postgres migrations (DEV-1657) — all
  three are the gateway repo's own follow-up work, not this repo's.
- Every gateway handler that composes a domain this repo does not import
  (member, chapter, role, orgsettings, custody, comm) — see `routes/doc.go`'s
  named exclusion list.
