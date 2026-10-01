# CLAUDE.md

Guidance for Claude Code working in this repository.

## Project: mwanachama-backend-auth

Extraction of `mwanachama-backend-api-gateway`'s five identity/credential
packages — `internal/domain/{auth,operator,verification,phonenumber,
phonesalt}` — DEV-1649 through DEV-1654 on that repo's
`documentation/3. implementation/todo_auth_standup.md`. Domain logic AND
storage both live in this package, imported directly by whatever mounts it —
no separate service, no gRPC, no proto. Module path
`github.com/aosanya/mwanachama-backend-auth`.

**`mwanachama-backend-api-gateway` was retired into `dump/` on 2026-10-01, so
`mwanachama-wakala-api` is the only consumer of this repo.** Anything below
that describes the gateway as a live mount is history, not current wiring; the
gateway's own original table names survive only in this repo's legacy-adoption
map.

**Named `auth`, not `identity`** (the name
`architecture-domain-decomposition.md` proposed) — `identity` already names
an unrelated existing story track in the gateway (`todo_identity_recover.md`,
`todo_identity_leave.md`, ... about member identity *flows*, not
credentials). See the gateway's `documentation/2. design/design-register.md`,
2026-09-06.

Independent of the gateway's custody/audit cluster — no package here imports
`custody`, unlike `role`/`member`.

## Five domains, one package

- **auth** (`device_impl.go`/`challenge_impl.go`/`phoneattempt_impl.go`/
  `proof.go`) — device registration + challenge/verify sign-in. `Device`
  (`SignedOutAt`/`SignedOutBy`/`IsSignedOut()`), `Challenge`
  (`ChallengeKind`: device/phone/recovery, `Public()` projection blanking
  `SubjectID`), `PhoneAttempt` (`AuthLockAfter=5`), `AuthRepository`.
  `proof.go`'s `VerifyDeviceProof`/`IsPublicKeyMaterial` (Ed25519, three
  encodings: base64, raw base64url, hex) ports verbatim.
- **operator** (`operator_impl.go`/`operator_attempt_impl.go`/`password.go`) —
  the console's own email/password credential, the platform's only stored
  secret. `OperatorCredential`, `Normalize`/`ValidEmail`, `OperatorAttempt`,
  `OperatorRepository`, and `password.go`'s argon2id `Hash`/`Verify` (PHC
  string format, `MinPasswordLength=12`) ports verbatim.
- **verification** (`verification_impl.go`) — a subject's
  unverified/pending/verified/rejected status. `Get` synthesizes an
  "unverified" zero record for an unseen subject — ported exactly; `Set`
  upserts.
- **phonenumber** (`phonenumber/`) — pure, stateless E.164 canonicalization
  via `github.com/nyaruka/phonenumbers`. No GORM, no domain type, no import
  of anything else in this repo except being imported BY `blindindex.go`.
- **phonesalt** (`phonesalt_impl.go`/`blindindex.go`) — the per-organization
  phone-hashing salt. `models.Salt` deliberately has NO secret field — a
  load-bearing security property, preserved exactly (see `models/
  phonesalt.go`'s package doc). `blindindex.go`'s `Indexer`/`RegionSource`/
  `Digest` composes `phonenumber.Canonicalize` with
  `models.PhoneSaltRepository` — pure composition, no storage of its own,
  kept in the root package, the same placement the gateway used.

## Naming collisions, resolved by domain-of-origin prefix (comm's precedent)

Four of the five sub-domains each declared their own `ErrNotFound`/
`Repository` in the gateway; flattened into one `models` package those names
collide, so every colliding name is prefixed by the domain it came from,
mirroring `mwanachama-backend-comm`'s identical resolution for
chat/directmessage/moderation:

- `auth.ErrNotFound` -> `models.ErrAuthNotFound`; `auth.Repository` ->
  `models.AuthRepository`; similarly `ErrAuthChallengeExpired`,
  `ErrAuthDeviceSignedOut`, `ErrAuthSignOutReasonRequired`.
- `operator.ErrNotFound` -> `models.ErrOperatorNotFound`;
  `operator.Repository` -> `models.OperatorRepository`;
  `operator.Credential` -> `models.OperatorCredential`; `operator.Attempt` ->
  `models.OperatorAttempt` (auth's own lock-out type keeps the plain name
  `models.PhoneAttempt` — no collision once operator's is renamed).
- `verification.ErrNotFound` -> `models.ErrVerificationNotFound`;
  `verification.Repository` -> `models.VerificationRepository`;
  `verification.Record` -> `models.VerificationRecord`; `verification.Status`
  -> `models.VerificationStatus`.
- `phonesalt.ErrNotFound` -> `models.ErrPhoneSaltNotFound`;
  `phonesalt.Repository` -> `models.PhoneSaltRepository`; similarly
  `ErrPhoneSaltAlreadyLive`, `ErrPhoneSaltRetired`, `ErrPhoneSaltNoActor`.
  `phonesalt.Salt` stays `models.Salt` — no collision.
- `auth.Device`, `Challenge`, `ChallengeKind`, `SignOutReason`,
  `PhoneAttempt` — no collisions, kept unprefixed.
- `auth.LockAfter` and `operator.LockAfter` collide as package-scope
  constants once flattened — renamed `models.AuthLockAfter` and
  `models.OperatorLockAfter` respectively; both files carry a one-line
  comment at the constant explaining the rename.
- `phonenumber`'s own `Canonicalize`/`ErrNoRegion`/`ErrUnparseable` need no
  renaming — they live in their own leaf subpackage.

## Objects are declared, not written

The eight tables come from `auth.blueprint.json`, not from Go row structs —
see [documentation/2. design/declared-storage.md](documentation/2.%20design/declared-storage.md)
and the org-wide strategy in
`developer/documentation/2. design/architecture-spec-driven-modules.md`.

- `auth.blueprint.json` declares the module's **eight objects once**: the
  roles `device`, `challenge`, `phone_attempt`, `phone_binding`,
  `credential`, `credential_attempt`, `verification` and `salt`. Reached
  through `Blueprint()`, `LoadSpec(path)`, `ParseSpec(raw)` and
  `SpecFor(instance)`. Load a domain spec through those, never through
  `spec.Load`, or its roled objects arrive with no fields.
- `auth.platform.json` is the domain in production; `auth.clinic.json` is a
  domain nobody has provisioned, and that is the point — a shipped example
  that is also live config stops being a test of anything.
- `models/` holds the domain types and the four repository interfaces.
  **The four interfaces must not change**: `models.AuthRepository`,
  `OperatorRepository`, `VerificationRepository` and `PhoneSaltRepository`
  are what `mwanachama-wakala-api` is written against.
- `store.go` is role constants plus thin wrappers over `specstore`. The four
  constructors are `New<X>Store(db, *spec.Spec)` and each returns an error,
  because the carrier cross-check can fail: a declared column with no field,
  or a field with no column, fails at construction rather than dropping a
  value on every write.

**This module names no domain.** A word that means something in one domain
and nothing in another does not belong here — it must run a clinic's front
desk and a library's reader accounts without a line changing.
`domain_agnostic_test.go` enforces it over identifiers, over every **stored
enum value** and over the action ids. `MemberID` is `SubjectID`, and the
stored sign-out reason `"member"` is `"self"`.

**The wire names deliberately did not move.** `json:"member_id"` and the
`/members/` path segments are the published HTTP contract; the column
underneath is `subject_id`. The guard test says so in its own body.

**A column is found by field name, never by json tag.** `SubjectID` is
`subject_id`. A tag-reading codec silently stops storing any `json:"-"`
field — which is exactly where a stored secret lives.

**Every declared column is written on every write**, because a map missing a
key means "leave it alone" to an update, so omitting empty values would make
clearing a field impossible.

**Two carriers are not the models type, on purpose.** `credentialRecord`
holds `password_hash` and `saltRecord` holds the raw `secret`, neither of
which is on `models.OperatorCredential` or `models.Salt`. `models.Salt`
having no secret field is a load-bearing security property this file has
always recorded; the standard's own answer (catalog's `ShareLink.KeyHash`
with `json:"-"`) is for a *hash*, and this is live key material. **Open for
the owner** — DEV-1705.

**`nullable` is exactly where the Go field is a pointer**, which is the three
columns whose absence differs from their zero: `device.signed_out_at`,
`credential.disabled_at`, `salt.retired_at`. `specstore` refuses any other
pairing. Everything else that was SQL `NULL` is now the zero value in a
column that still accepts `NULL`, so a legacy row reads back the same.

**The "absent" predicate asks the database for the column's type** —
`st.Unset(role, field)`, never a hand-written `IS NULL OR = ''`. An adopted
table keeps the types its old hand-written SQL gave it, so on
`mwanachama-wakala-api`'s database the three nullable instants are real
`timestamptz` columns while the blueprint says `text`, and Postgres refuses to
compare one to `''` at all. See
[2. design/adopted-column-types.md](documentation/2.%20design/adopted-column-types.md).
Four sites were broken against the live database before this was found, three
of them ordinary reads, because SQLite compares across types without
complaint and every test here runs on a table `spec.Migrate` created.

**A table is `<instance>_hashOf(<mount>)_hashOf(<module>_<object>)`** — only
the instance stays readable. Assert on `spec.RawNameFor`, never on a physical
name, and exclude the per-instance `<instance>_spec_table_names` registry
from anything that counts tables.

**`Provision` is the entry point, not `Migrate`.** It adopts the legacy
tables, runs `spec.Migrate`, then applies the three things a declaration
cannot carry: the Postgres `SEQUENCE`s the id minting reads, the one-live-salt
index (unique over an *expression*, which `spec.Index` cannot say), and the
one-off rewrite of the stored sign-out reason. `ProvisionStatements` is that
list, and `cmd/ddl` prints it after the generated DDL so a spec can be read
as SQL before it is trusted.

**Legacy adoption covers two name sets**, because the deployments disagreed:
the retired api-gateway used `operator_credential`, wakala-api uses
`auth_operator_credential`. Both go through `spec.Legacy.Tables`, the shared
helper added for this (S48 there) — do not write a per-repo adoption path.
**Running adoption against a live database is an operator step.**

## Rules are declared too, where they can be

`validate.go` reads `required`, an enum's `values` and a named `matches`
pattern off the spec and applies them on the four create paths.
`patterns.go` is the registry: `e164` for the three phone columns and
`email_address` for the two address columns. A spec naming a pattern nobody
supplies is an error, not a rule that quietly never runs.

`Check(s, role, v)` is the same validation without a database, for a caller
validating what it has read before it opens a connection.

**What stays in Go is what a spec cannot say**, and each piece lives with the
type it is about: `PhoneAttempt.Fail` and `OperatorAttempt.Fail`'s lock-out
policy, `TriesLeft`, `Challenge.Public`'s redaction, `Device.IsSignedOut`,
`Salt.Live`/`AgeDays`, and `proof.go`'s Ed25519 verification.

## routes/ — HTTP surface

**The address table is declared, not written** — `auth.operations.json`
carries all ten addresses with their method, path, action id, status and
description, plus the errors map from every exported sentinel to a status.
`routes/routes.go`'s `Build` ranges over `dispatch.Handled` and binds a
handler per action id, refusing by name both a declared action with no
handler and a handler bound to an action nobody declared. See
[documentation/2. design/routes.md](documentation/2.%20design/routes.md).

**Every address is declared `handled`, meaning the module supplies the
handler, and that is not a shortcut.** Six of the ten are orchestrations
whose *ordering* is the security property — a signed-out device refused in
exactly the words an unknown one gets, a sign-in that counts a failure for an
address holding no credential so the two refusals cannot be told apart, a
recovery that ends every other device — and DEV-1701 is already filed against
one of those orderings. `dispatch.Operation` names exactly one `call`, so
declaring them as calls would mean rewriting them, which is where the property
would be lost. The remaining four *are* single calls but reach four different
stores; dispatching them needs a combined facade (DEV-1706).

**`AnonymousActions` names what is public, never what is protected.** Five
action ids, each public by necessity. An address added later and not named
there arrives gated, so the failure direction is a 401. `Split` separates the
two halves. The action ids are also the vocabulary DEV-1700 needs.

See `routes/doc.go` for the full portability classification — which of the gateway's original
`auth_device_handlers.go`/`auth_handlers.go`/`auth_operator_handlers.go`/
`auth_phone_handlers.go`/`auth_phone_region.go`/`auth_recovery_handlers.go`/
`phone_salt_handlers.go`/`orgsettings_verification_handlers.go` handlers moved
here and which stay gateway-side because they compose a domain this repo
must not depend on (member/chapter/role/orgsettings/custody/comm).

**The wire helpers and `Route` come from
`mwanachama-backend-shared/httpwire`, not from this repo (DEV-1702).**
`httpwire.WriteJSON`/`WriteErr`/`ReadJSON` replace the `writeJSON`/`writeErr`/
`readJSON` this package used to carry, and `Route` is a type alias for
`httpwire.Route` rather than a struct declared here — `httpwire.Route` is a
field-name superset (it adds `Action`) with the same `Pattern` method, so the
exported surface a mounting process sees is unchanged. `routes/wire.go` keeps
only `randHex`, which is this repo's own. Do not reintroduce a local copy of
any of the five. `mwanachama-backend-comm` carried one too and lost it inside
its own conversion; what remains of that sweep is S44 on shared's board.

**Session-token minting is gateway-owned, not a domain this repo reaches
into.** `routes/session.go`'s `SessionMinter` is the externally-supplied seam
every flow that ends in a session (`DeviceVerify`, `RecoveryVerify`,
`OperatorSignIn`) mints through — the same pattern actor's
`HierarchyChecker` and comm's `Identity` already establish. A mount adapts
its own session manager into this interface; `mwanachama-wakala-api` does.

Two mount-configured dev-only bools are threaded through as plain
parameters, never defaulted or hard-coded: `DeviceVerify`'s
`allowUnsignedProof` (false means signatures ARE checked — the original's
careful polarity, preserved) and `RecoveryRequest`'s `echoChallengeCode`
(false means the secret is withheld).

**`OperatorSignIn` drops the gateway's diagnostic-only sign-in-failure log
call** rather than threading an optional `Logger` interface through this
package for one call site — the distinction is diagnostic, never wire-visible,
so a mount can log it around whatever wraps this route.

## What is superseded

- **`gormstore/` and `tables.go`** — **deleted 2026-10-01 (DEV-1703)**. Seven
  row structs, their `*ToRow`/`*FromRow` converters, `AutoMigrate`,
  `TableNames`, `DefaultTableNames`, `PrefixedTableNames` and `Migrate`. What
  replaces them is `auth.blueprint.json` plus `store.go`'s codec, and
  `Provision(db, *spec.Spec)` is the entry point. The acceptance was that
  every behavioural test in the repo passed unchanged against hashed table
  names; the only test edit was the two harnesses.
- **The seven `*Routes` builders** — deleted 2026-10-01 (DEV-1703).
  `DeviceChallengeRoutes`, `DeviceVerifyRoutes`, `RecoveryRoutes`,
  `OperatorSignInRoutes`, `OperatorCredentialRoutes`, `VerificationRoutes` and
  `PhoneSaltRoutes` are the ladder shared's S41 tracks across six repos. The
  gate boundary they encoded is now `AnonymousActions`, an allowlist of action
  ids. `Build` and `Split` replace all seven.
- **`routes/wire.go`'s `writeJSON`/`writeErr`/`readJSON` and the local
  `Route` struct** — deleted 2026-09-30 (DEV-1702) in favour of `httpwire`.
- **An `argon2id_digest` pattern on `password_hash`** — written and removed
  the same day. Nothing in this repo ever validated the shape of a stored
  hash, so declaring it would have been a new refusal introduced inside a
  refactor; it turned three operator tests red, which is the evidence. Filed
  as DEV-1704 instead.

## Conventions

- No Go file over 300 lines; split by responsibility — `device_impl.go`/
  `challenge_impl.go`/`phoneattempt_impl.go` split auth's original single
  `Repository` implementation three ways for this reason, and
  `routes/*_test.go` is one file per domain rather than one
  `routes_test.go` for the same reason.
- `make test` (`go test ./...`, sqlite via `glebarez/sqlite`, provisioned
  through `Provision`) is the expected way to verify a change here — do not reach for
  a real Postgres. `postgres_integration_test.go` (`//go:build postgres`,
  gated on `POSTGRES_URL`) exists for real Postgres-wiring coverage sqlite
  can't fully stand in for (sequence-minted ids, the one-live-salt expression
  index) and is run by `make test-pg`, not by `make test`. The tag is
  `postgres`, matching the sibling repos, not `mwanachama-backend-catalog`'s
  `integration`. See [[feedback_use_memory_backend_for_tests]].
- The `Makefile` is `build`/`test`/`test-pg`/`vet`/`clean`, the same five
  targets catalog's has.
- Four-phase `documentation/` layout — see
  [documentation/README.md](documentation/README.md).
- There are no hand-written route builders left to name: an address is an
  entry in `auth.operations.json`, and adding one is an edit to that file plus
  a handler bound by its action id. [[feedback_routes_name_match_model]] still
  governs any repo that has not adopted the declared table.
- **The four Go interfaces that must not change** are
  `models.AuthRepository`, `models.OperatorRepository`,
  `models.VerificationRepository` and `models.PhoneSaltRepository` —
  `mwanachama-wakala-api` is written against them, and the declared statuses
  in `auth.operations.json` depend on their sentinels staying stable. The four
  **constructors** did change: each takes a `*spec.Spec` and returns an error.
- Four-phase `documentation/`, and the three pages a change here usually
  touches are
  [2. design/declared-storage.md](documentation/2.%20design/declared-storage.md),
  [2. design/adopted-column-types.md](documentation/2.%20design/adopted-column-types.md)
  and [2. design/routes.md](documentation/2.%20design/routes.md).

## Code comments

Write code with no comments. Not one-liners above a function, not section
banners, not doc comments on exported symbols, not "why" notes next to a
tricky line. A name, a type, or a smaller function carries it instead.

Anything that genuinely needs explaining goes in this repo's `documentation/`
folder, under the phase it belongs to (`1. requirements`, `2. design`,
`3. implementation`, `4. qa`) — never inline.

**Why:** inline prose drifts out of sync with the code, duplicates what
`documentation/` already owns, and buries the explanation where nobody
looking for it will search.

**How to apply:**

- New code ships without comments. If a line seems to need one, rename or
  split until it doesn't.
- Touching code that already has comments: strip the ones in the code you are
  changing. Do not sweep untouched files unless asked.
- If the reasoning matters, add or update the matching `documentation/` page
  in the same change and leave nothing behind in the source.
- Machine-read directives are not comments and stay: build tags, `//go:embed`,
  `//go:generate`, linter pragmas (`//nolint`, `// eslint-disable-next-line`,
  `// ignore:`), license headers, codegen "do not edit" banners, and generated
  files as a whole.
- Commit messages, PR descriptions, and test names carry the narration that
  used to go in comments.

This rule is repeated verbatim in every mwanachama repo's `CLAUDE.md` so that
it reaches sessions that do not load this machine's user-level config —
scheduled cloud routines, other machines, and other agent harnesses.
