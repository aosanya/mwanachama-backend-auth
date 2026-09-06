# mwanachama-backend-auth — completed tasks

| Task | Title | Completed | Notes |
|------|-------|-----------|-------|
| DEV-1649 | Scaffold `mwanachama-backend-auth`: `go.mod`, `CLAUDE.md`, `models/`, `gormstore/`, `routes/` — file layout copied from `mwanachama-backend-actor` | 2026-09-06 | New repo, module `github.com/aosanya/mwanachama-backend-auth`, Go 1.25.0. `git init` run with a `.gitignore` mirroring actor's/comm's; no commits made (not this pass's job). Dependency versions matched across the sibling repos (`gorm.io/gorm v1.31.2`, `gorm.io/driver/postgres v1.6.2`, `github.com/glebarez/sqlite v1.11.0`, `github.com/google/uuid v1.6.0`, `github.com/nyaruka/phonenumbers v1.8.1`, `github.com/jackc/pgx/v5 v5.10.0`, `golang.org/x/crypto v0.45.0`) — `gorm.io/datatypes` deliberately left out, since none of the five domains store a JSON-typed column. |
| DEV-1650 | Port `internal/domain/auth` (device + challenge records) into `models/`+`gormstore/` | 2026-09-06 | `models/auth.go`: `Device`, `Challenge`+`ChallengeKind`, `SignOutReason` consts, `PhoneAttempt`, `AuthLockAfter` (renamed from `auth.LockAfter` to avoid colliding with operator's own budget), `AuthRepository`, `Err*` sentinels prefixed `Auth`. `gormstore/device.go`+`challenge.go`+`phoneattempt.go`: `DeviceRow`/`ChallengeRow`/`PhoneAttemptRow`/`AuthPhoneRow` (the phone-to-member binding table), `BeforeCreate` id-minting off `auth_device_seq`/`auth_challenge_seq`. Root package: `device_impl.go`/`challenge_impl.go`/`phoneattempt_impl.go` (`AuthStore`, split three ways to stay under 300 lines per file — auth's original single `Repository` implementation does not fit in one), `proof.go` (`VerifyDeviceProof`/`IsPublicKeyMaterial`, ported verbatim). `ConsumeChallenge` deliberately reshaped to read-then-guarded-write rather than the gateway's single atomic UPDATE — see the file's own doc comment: a raw SQL `expires_at > ?` comparison against sqlite's text-encoded timestamp column proved unreliable, caught by the `routes/` happy-path tests (the store-level unit tests had derived "now" from the stored `ExpiresAt` rather than the real clock, and so did not exercise the real-clock path). |
| DEV-1651 | Port `internal/domain/operator` (console credential) into `models/`+`gormstore/` | 2026-09-06 | `models/operator.go`: `OperatorCredential`, `Normalize`/`ValidEmail`, `OperatorAttempt`, `OperatorLockAfter` (renamed from `operator.LockAfter`), `OperatorRepository`, `Err*` sentinels prefixed `Operator`. `gormstore/operator.go`: `CredentialRow` (its `PasswordHash` field is exported for GORM's sake but never copied onto a domain `OperatorCredential`), `OperatorAttemptRow`. Root package: `operator_impl.go`+`operator_attempt_impl.go` (`OperatorStore`, same two-file split as auth), `password.go` (`Hash`/`Verify`, ported verbatim). |
| DEV-1652 | Port `internal/domain/verification` into `models/`+`gormstore/` | 2026-09-06 | `models/verification.go`: `VerificationRecord`, `VerificationStatus`+4 constants, `VerificationRepository`, `ErrVerificationNotFound`. `gormstore/verification.go`: `VerificationRow`, member-id-keyed, no id-minting. Root package: `verification_impl.go` (`VerificationStore`) — `Get`'s "synthesize an unverified zero record for an unseen member" behavior ported exactly, `Set`'s "stamp `updated_at` unconditionally, never honour a caller-supplied one" (DEV-1173) ported exactly. |
| DEV-1653 | Port `internal/domain/phonenumber` then `internal/domain/phonesalt` into `models/`+`gormstore/` | 2026-09-06 | `phonenumber/phonenumber.go` ported near-verbatim (package doc trimmed of gateway-internal doc/design references that don't resolve in this repo, reasoning kept) as its own leaf subpackage, imported by nothing else in this repo except `blindindex.go`. `models/phonesalt.go`: `Salt` (no secret field — the package doc's load-bearing paragraph on why is preserved), `PhoneSaltRepository`, `Err*` sentinels prefixed `PhoneSalt`. `gormstore/phonesalt.go`: `SaltRow` — the one row struct with an exported `Secret []byte` field, documented as the only field its own conversion functions must never copy onto a `models.Salt`. Root package: `phonesalt_impl.go` (`PhoneSaltStore` — `Hash` is the one statement in the whole repo that ever selects the secret column), `blindindex.go` (`Indexer`/`RegionSource`/`Digest`, ported, kept at the repo root per the gateway's own placement). |
| DEV-1654 | Build `routes/` route builders, mirroring the gateway's `auth_device_handlers.go`/`auth_handlers.go`/`auth_operator_handlers.go`/`auth_phone_handlers.go`/`auth_phone_region.go`/`auth_recovery_handlers.go`/`phone_salt_handlers.go` and the verification slice of `orgchrome_verification_handlers.go` | 2026-09-06 | Ported: `DeviceChallengeRoutes`/`DeviceVerifyRoutes` (device.go), `RecoveryRoutes` (recovery.go), `OperatorSignInRoutes`/`OperatorCredentialRoutes` (operator.go — change-password/disable/list, not create), `VerificationRoutes` (verification.go — the PUT/set decision only, not the GET, which stays gateway-side behind `requireContactRead`), `PhoneSaltRoutes` (phonesalt.go — list only). New seams this repo needed that the gateway owns: `routes/session.go`'s `SessionMinter`+`Session` (session-token minting is gateway-owned) and `routes/identity.go`'s `Identity` (the caller's own id, for `ChangeOperatorPassword`'s ownership check). `routes/doc.go` carries the full portable/excluded classification. `routes_test.go` split into one file per domain (`device_test.go`/`recovery_test.go`/`operator_test.go`/`verification_test.go`/`phonesalt_test.go`) plus a shared `testutil_test.go`, to stay under the 300-line file limit — happy path + at least one refusal per route builder (locked-out phone/operator sign-in, wrong device signature, wrong recovery secret, forbidden password change, empty phone-salt list before provisioning, no-secret-leak assertion). `go build`/`go vet`/`gofmt -l .`/`go test ./...` all clean, sqlite-backed only — no Postgres reached. |

## Board context

DEV-1655 (gateway `go.mod`/`cmd/server/stores.go` wiring), DEV-1656 (gateway
HTTP cutover, deleting the superseded `internal/domain` packages) and
DEV-1657 (archiving the superseded Postgres migrations) were filed and
completed on the gateway's own `todo_auth_standup.md` board, in a later
pass — see that repo's `documentation/3. implementation/todo_done.md` for
the full record of that half.

### Discrepancies found against the gateway source during porting

- **`registerDevice`'s member-minting branch is gateway-only in a way the
  spec's exclusion list undersold slightly**: it composes not just
  `member.Repository.Create` but also `d.optionalCaller` (the gateway's own
  session-verification helper) to decide whether a caller-supplied
  `member_id` is legitimate. Confirms the exclusion (still correctly
  excluded), just noting the *session* dependency alongside the *member*
  dependency for whoever does the DEV-1656 cutover.
- **`getVerification`'s exclusion and the package-layout hint for
  `VerificationRoutes` read as contradictory on a first pass** — the layout
  note says "the plain Get/Set only," which could be misread as two HTTP
  routes (GET and PUT). Resolved by reading "Get" as the repository method
  `SetVerification`'s read-modify-write calls internally (to carry
  `FullName`/`Phone`/`WorkflowID` forward), not as its own HTTP route — the
  named exclusion for `getVerification` (gated by `requireContactRead`) is
  the one that actually governs the HTTP surface, and only one verification
  route (`PUT .../verification`) was built. Flagging this for whoever
  reads the spec next, since the two sentences do read as being in tension
  until resolved this way.
- Every other named exclusion (`signOutDevice`, `phoneChallenge`/
  `phoneVerify`, `createOperatorCredential`, `submitVerification`,
  `getOrgChrome`/`getOwnOrgChrome`/`putOrgChrome`) matched the actual
  gateway source exactly as described — no further entanglement or
  simplification found beyond what was already documented.
