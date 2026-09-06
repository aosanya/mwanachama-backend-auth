// Package mwanachamaauth is the identity/credential cluster extracted from
// mwanachama-backend-api-gateway's internal/domain/{auth,operator,
// verification,phonenumber,phonesalt} — DEV-1649 through DEV-1654 on that
// repo's documentation/3. implementation/todo_auth_standup.md. Domain logic
// AND storage both live in this package, imported directly by the gateway
// process — no separate service, no gRPC, no proto, the same shape
// mwanachama-backend-actor and mwanachama-backend-comm already took for the
// same "extracted from the gateway" reason. Module path
// github.com/aosanya/mwanachama-backend-auth.
//
// Named "auth", not "identity" (the name architecture-domain-decomposition.md
// proposed) — "identity" already names an unrelated existing story track in
// the gateway (todo_identity_recover.md, todo_identity_leave.md, ... about
// member identity *flows*, not credentials). See the gateway's
// documentation/2. design/design-register.md, 2026-09-06.
//
// # Five domains, one package
//
// auth (device registration + challenge/verify sign-in), operator (the
// console's stored email/password credential — the platform's only stored
// secret), verification (a member's unverified/pending/verified/rejected
// status), phonenumber (E.164 canonicalization, kept as its own leaf
// subpackage) and phonesalt (the per-organization phone-hashing salt, which
// already coupled to phonenumber in the gateway) — see each type's own doc
// comment in models/ for the reasoning ported from the gateway's originals.
//
// Session-token minting itself is explicitly gateway-owned and stays out of
// this repo entirely: routes/session.go's SessionMinter is the seam a mounting
// gateway supplies its own internal/session.Manager through.
//
// # Naming collisions, resolved by domain-of-origin prefix
//
// Four of the five sub-domains each declared their own ErrNotFound and
// Repository in the gateway; flattened into one models package those names
// collide, so — mirroring mwanachama-backend-comm's identical resolution for
// chat/directmessage/moderation — every colliding name is prefixed by the
// domain it came from: auth.ErrNotFound -> models.ErrAuthNotFound,
// operator.Repository -> models.OperatorRepository,
// verification.Record -> models.VerificationRecord,
// phonesalt.ErrNotFound -> models.ErrPhoneSaltNotFound, and so on. auth's own
// vocabulary (Device, Challenge, ChallengeKind, SignOutReason, PhoneAttempt)
// had no collisions and ports unchanged. See models/ for the full list.
//
// # Layout
//
// models/ holds the domain types and the four repository interfaces they are
// read and written through. gormstore/ holds every GORM-specific piece: row
// structs, row<->domain conversion, and Migrate — mirroring actor's and
// comm's identical split. The root package keeps one *Store per domain
// (AuthStore, OperatorStore, VerificationStore, PhoneSaltStore), each built on
// a *gorm.DB, plus proof.go (Ed25519 device-proof verification), password.go
// (argon2id verifiers) and blindindex.go (the Indexer composing phonenumber
// with a PhoneSaltRepository) at the root, since none of the three has a
// storage concern of its own. routes/ is this repo's own HTTP surface — see
// routes/doc.go for exactly which of the gateway's original handlers are
// portable here and which stay gateway-side by design.
package mwanachamaauth
