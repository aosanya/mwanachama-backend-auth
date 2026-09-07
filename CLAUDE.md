# CLAUDE.md

Guidance for Claude Code working in this repository.

## Project: mwanachama-backend-auth

Extraction of `mwanachama-backend-api-gateway`'s five identity/credential
packages — `internal/domain/{auth,operator,verification,phonenumber,
phonesalt}` — DEV-1649 through DEV-1654 on that repo's
`documentation/3. implementation/todo_auth_standup.md`. Domain logic AND
storage both live in this package, imported directly by the gateway
process — no separate service, no gRPC, no proto — the same shape
`mwanachama-backend-actor` and `mwanachama-backend-comm` already took for the
same "extracted from the gateway" reason. Module path
`github.com/aosanya/mwanachama-backend-auth`.

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
  `MemberID`), `PhoneAttempt` (`AuthLockAfter=5`), `AuthRepository`.
  `proof.go`'s `VerifyDeviceProof`/`IsPublicKeyMaterial` (Ed25519, three
  encodings: base64, raw base64url, hex) ports verbatim.
- **operator** (`operator_impl.go`/`operator_attempt_impl.go`/`password.go`) —
  the console's own email/password credential, the platform's only stored
  secret. `OperatorCredential`, `Normalize`/`ValidEmail`, `OperatorAttempt`,
  `OperatorRepository`, and `password.go`'s argon2id `Hash`/`Verify` (PHC
  string format, `MinPasswordLength=12`) ports verbatim.
- **verification** (`verification_impl.go`) — a member's
  unverified/pending/verified/rejected status. `Get` synthesizes an
  "unverified" zero record for an unseen member — ported exactly; `Set`
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
  kept in the root package (not `models/`, not `gormstore/`), same
  placement the gateway used.

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

## GORM, models/+gormstore/ split

Same template `mwanachama-backend-actor` set and `mwanachama-backend-comm`
followed for the same reason: `models/` holds the domain types and the four
repository interfaces they're read and written through; `gormstore/` holds
every GORM-specific piece (row structs, row<->domain conversion, `Migrate`),
one file per entity area. The root package keeps one `*Store` per domain
(`AuthStore`, `OperatorStore`, `VerificationStore`, `PhoneSaltStore`), each
built on a `*gorm.DB`. `tables.go` wraps `gormstore.TableNames`/
`DefaultTableNames`/`Migrate`.

- **Table names are the gateway's own original production names, reused
  verbatim** (`auth_device`, `auth_challenge`, `auth_phone`,
  `auth_phone_attempt`, `operator_credential`, `operator_attempt`,
  `verification`, `phone_salt`) — see the archived migrations in the
  gateway's `internal/store/postgres/migrations_archive/`
  (000007/000009/000018/000020/000027/000029/000048). Reusing them means no
  data migration is needed if this repo ever points at the gateway's own
  database.
- Postgres `SEQUENCE`s (`auth_device_seq`, `auth_challenge_seq`,
  `operator_credential_seq`) back the three id-minting `BeforeCreate` hooks,
  matching the archived migrations' `nextval(...)` convention; sqlite (tests
  only) falls back to a uuid-suffixed id.
- **`SaltRow.Secret` is the one exported field in this repo carrying the raw
  key**, because GORM requires exported fields to map columns. Every
  conversion function that builds a `models.Salt` deliberately omits it; the
  only statement in the whole repo that reads it back is
  `phonesalt_impl.go`'s `Hash` method, which returns a digest and never the
  key — see `gormstore/phonesalt.go`'s doc comment.
- **`ConsumeChallenge` is read-then-guarded-write, not the gateway's original
  single `UPDATE ... WHERE expires_at > $now` statement** — a raw SQL
  comparison of a bound `time.Time` against sqlite's text-encoded timestamp
  column does not reliably compare chronologically on this repo's test
  dialect (discovered by the routes-level happy-path tests failing while the
  store-level tests, which derived "now" from the stored `ExpiresAt` rather
  than the real clock, passed). Expiry is checked in Go against a value GORM
  itself parsed back out of the column; the `consumed` flag still flips
  through a guarded `UPDATE ... WHERE id = ? AND consumed = false`, so two
  callers racing to consume the same still-valid challenge cannot both win.
  See `challenge_impl.go`'s doc comment.

## routes/ — HTTP surface

Mirrors `mwanachama-backend-actor/routes` and `mwanachama-backend-comm/
routes`: decode/call/encode handlers, `Route`/`Route.Pattern`, one `*Routes`
function per domain plus a `Routes(Deps)` aggregator. See `routes/doc.go` for
the full portability classification — which of the gateway's original
`auth_device_handlers.go`/`auth_handlers.go`/`auth_operator_handlers.go`/
`auth_phone_handlers.go`/`auth_phone_region.go`/`auth_recovery_handlers.go`/
`phone_salt_handlers.go`/`orgsettings_verification_handlers.go` handlers moved
here and which stay gateway-side because they compose a domain this repo
must not depend on (member/chapter/role/orgsettings/custody/comm).

**Session-token minting is gateway-owned, not a domain this repo reaches
into.** `routes/session.go`'s `SessionMinter` is the externally-supplied seam
every flow that ends in a session (`DeviceVerify`, `RecoveryVerify`,
`OperatorSignIn`) mints through — the same pattern actor's
`HierarchyChecker` and comm's `Identity` already establish. The gateway
adapts its own `internal/session.Manager.Mint` into this interface with a
two-line wrapper in the follow-up cutover pass (DEV-1656), not written here.

Two gateway-configured dev-only bools are threaded through as plain
parameters, never defaulted or hard-coded: `DeviceVerify`'s
`allowUnsignedProof` (false means signatures ARE checked — the original's
careful polarity, preserved) and `RecoveryRequest`'s `echoChallengeCode`
(false means the secret is withheld).

**`OperatorSignIn` drops the gateway's diagnostic-only sign-in-failure log
call** rather than threading an optional `Logger` interface through this
package for one call site — the gateway's own comment already says the
distinction is diagnostic, never wire-visible, so the gateway can log the
same distinction itself around whatever wraps this route. See
`routes/operator.go`'s `OperatorSignIn` doc comment.

## Conventions

- No Go file over 300 lines; split by responsibility — `device_impl.go`/
  `challenge_impl.go`/`phoneattempt_impl.go` split auth's original single
  `Repository` implementation three ways for this reason, and
  `routes/*_test.go` is one file per domain rather than one
  `routes_test.go` for the same reason.
- `go test ./...` (sqlite via `glebarez/sqlite`, migrated through
  `Migrate`) is the expected way to verify a change here — do not reach for
  a real Postgres. `postgres_integration_test.go` (`//go:build postgres`,
  gated on `POSTGRES_URL`) exists for real Postgres-wiring coverage sqlite
  can't fully stand in for (sequence-minted ids, the `phone_salt_one_live`
  partial index) but is not run by default. See
  [[feedback_use_memory_backend_for_tests]].
- Four-phase `documentation/` layout — see
  [documentation/README.md](documentation/README.md).
- Route builder functions are named `<ModelType>Routes` (e.g.
  `DeviceChallengeRoutes`, `OperatorSignInRoutes`) — see
  [[feedback_routes_name_match_model]].
- Before wiring into `mwanachama-backend-api-gateway` (DEV-1655/1656), the
  four Go interfaces that must not change are `models.AuthRepository`,
  `models.OperatorRepository`, `models.VerificationRepository` and
  `models.PhoneSaltRepository` — route request/response shapes and status
  codes in `routes/` all depend on those staying stable.
