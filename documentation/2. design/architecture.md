# Architecture

## Shape

No gRPC, no standalone service, no Supabase/RLS — a plain Go module imported
directly by the gateway process, the same template
`mwanachama-backend-actor` and `mwanachama-backend-comm` already established
for an extraction out of `mwanachama-backend-api-gateway`'s `internal/domain`.

```
mwanachama-backend-auth/
  doc.go                package doc
  errors.go             classify() driver-error mapping, ErrInvalidReference/ErrConflict
  tables.go             wraps gormstore.TableNames/DefaultTableNames/Migrate
  device_impl.go        AuthStore: RegisterDevice, GetDevice, SignOutDevice, SignOutOtherDevices
  challenge_impl.go      AuthStore: CreateChallenge, GetChallenge, ConsumeChallenge
  phoneattempt_impl.go   AuthStore: PhoneAttempt, RecordPhoneFailure, ClearPhoneAttempts, MemberIDForPhone
  proof.go               VerifyDeviceProof/IsPublicKeyMaterial (Ed25519)
  operator_impl.go        OperatorStore: Create, Verifier, Get, ListForMember, SetPassword, Disable
  operator_attempt_impl.go  OperatorStore: Attempt, RecordFailure, ClearAttempts
  password.go              Hash/Verify (argon2id)
  verification_impl.go     VerificationStore
  phonesalt_impl.go        PhoneSaltStore — the one file that ever reads gormstore's secret column
  blindindex.go            Indexer/RegionSource/Digest
  phonenumber/             E.164 canonicalization — pure, stateless, its own leaf subpackage
  models/                  domain types + the four repository interfaces
  gormstore/               GORM row structs, row<->domain conversion, Migrate
  routes/                  HTTP surface — see routes/doc.go
```

## models/ + gormstore/ split

Same split actor and comm both use: `models/` holds domain types and
repository interfaces (what a caller of this repo, or a test, ever needs to
import); `gormstore/` holds every GORM-specific piece (row structs,
`*ToRow`/`*FromRow` converters, `Migrate`). The root package's `*_impl.go`
files are the only code that calls into `gormstore/` — nothing outside this
repo needs to know GORM exists.

## Table names and id minting

Table names are the gateway's own original production names
(`gormstore.DefaultTableNames`), not instance-scoped the way actor's
member/chapter tables were — all eight already exist in the gateway's
Postgres under these exact names (see the archived migrations,
`mwanachama-backend-api-gateway/internal/store/postgres/migrations_archive/`),
and reusing them means no data migration is needed if this repo is ever
pointed at the same database.

Three tables mint a server-generated id (`auth_device`, `auth_challenge`,
`operator_credential`) via a Postgres `SEQUENCE` + `BeforeCreate` hook,
matching the archived migrations' `nextval(...)` convention; sqlite (tests
only, no `SEQUENCE` support) falls back to a uuid-suffixed id with the same
prefix. The other five tables are keyed on a natural key the caller already
supplies (phone number, email address, member id, an explicit salt version)
and mint nothing.

## The one file that reads a secret

`phonesalt_impl.go`'s `Hash` method is the only statement in this repo that
selects `gormstore.SaltRow.Secret` — the raw per-organization HMAC key.
Every other conversion function that builds a `models.Salt` omits it, and
`models.Salt` itself has no secret field at all. See `models/phonesalt.go`'s
package doc for the full reasoning (ported from the gateway's own
`phonesalt` package doc, which is itself load-bearing documentation, not
just prose).

## routes/ — HTTP surface

See `routes/doc.go` for the full "what is and is not in scope, and why"
classification. In short: a gateway handler is portable here only if its
body is a single call (or small sequence of calls) into this repo's own
domain repositories, with the one deliberate exception of session-token
minting — gateway-owned, reached through the externally-supplied
`SessionMinter` seam (`routes/session.go`), the same pattern actor's
`HierarchyChecker` and comm's `Identity` already establish.

## Naming-collision resolution

See CLAUDE.md's own section — repeated there rather than here because it is
the fact a caller porting a sixth domain into this repo would need first.
