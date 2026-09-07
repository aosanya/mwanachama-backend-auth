// Package routes is mwanachama-backend-auth's own HTTP surface, mirroring
// mwanachama-backend-actor/routes and mwanachama-backend-comm/routes: decode
// a request, call one models repository method (or a small, same-domain
// sequence of them), encode the response — reachable from an HTTP mux
// without a mounting process reimplementing the request/response shape.
//
// A handler is portable into this package only if its body is a single call
// (or small sequence of calls) into this repo's own domain repositories with
// no cross-domain composition — no member/chapter/role/orgsettings/custody/comm
// call in the body — the same line actor's and comm's own doc.go draw.
// Session-token minting is the one deliberate exception: it is gateway-owned
// (see SessionMinter in session.go), not a domain this package reaches into,
// so a handler that ends by minting a session is still portable provided
// everything before that point is pure auth/operator.
//
// # Portable (built here)
//
//   - DeviceChallenge (device.go) — GetDevice + IsSignedOut check +
//     CreateChallenge + Public(). Pure auth.
//   - DeviceVerify (device.go) — GetDevice + ConsumeChallenge +
//     signature-proof check + SessionMinter.Mint. Pure auth plus the
//     SessionMinter seam.
//   - RecoveryRequest (CreateChallenge) and RecoveryVerify (ConsumeChallenge +
//     SignOutOtherDevices + Mint) — recovery.go. Pure auth plus the
//     SessionMinter seam.
//   - OperatorSignIn (operator.go) — Attempt/Verifier/Verify/RecordFailure/
//     ClearAttempts + Mint. Pure operator plus the SessionMinter seam.
//     Preserves the gateway's entire one-sentence-refusal security property
//     verbatim: the signInRefusal constant, lock-out counted against
//     addresses that hold no credential, and the distinct (here: dropped —
//     see OperatorSignIn's own doc comment) log-only signInFailure.
//   - ChangeOperatorPassword (operator.go) — pure operator plus the Identity
//     seam (`cred.MemberID != identity.CallerID(r)`).
//   - DisableOperatorCredential, ListOperatorCredentials (operator.go) — pure
//     operator, no seam needed beyond path values.
//   - SetVerification (verification.go) — pure verification, a
//     read-modify-write that preserves the exact field-carry-forward
//     behavior: a PUT only ever changes Status/Note, never FullName/Phone/
//     WorkflowID, which are read off the current record first.
//   - ListPhoneSalts (phonesalt.go) — pure phonesalt, preserving saltView's
//     shape exactly: id, set_at, age_days, live, set_by, retired_at,
//     retired_by — no secret field, ever.
//
// [Routes] returns the whole set as one list of addresses a mounting process
// can range over to build a mux from; the per-domain *Routes functions
// (DeviceChallengeRoutes, DeviceVerifyRoutes, RecoveryRoutes,
// OperatorSignInRoutes, OperatorCredentialRoutes, VerificationRoutes,
// PhoneSaltRoutes) return one group at a time for a mounting process that
// wraps different groups in different policy (the gateway does today —
// DeviceChallenge and DeviceVerify are both public but the gateway may still
// want different rate-limiting around each; sign-in carries no
// caller-identity gate at all, while credential management needs one).
//
// # Deliberately NOT here, and not a future TODO — a considered exclusion
//
//   - registerDevice — composes member.Repository.Create and the gateway's
//     own session-verification logic (optionalCaller) to decide whether a
//     supplied member_id is legitimate. Stays in gateway.
//   - signOutDevice — composes comm's DMRepository.RetireDeviceKeysForDevice
//     and the gateway's session.Manager.RevokeDevice in a specific fail-safe
//     order (keys retired, then the device marked signed out, then sessions
//     revoked last). Stays in gateway.
//   - phoneChallenge/phoneVerify — call the gateway's own canonicalPhone/
//     diallingRegion, which read orgsettings.Repository for the organization's
//     default dialling region. Stays in gateway, which imports this repo's
//     phonenumber subpackage directly for the canonicalization step once cut
//     over.
//   - createOperatorCredential — checks member.Repository.Get before minting,
//     so a credential is never bound to a member id nobody holds. Stays in
//     gateway.
//   - getVerification — gated by the gateway's own requireContactRead
//     (G341: the member themselves, or a holder of CapMemberContactRead at a
//     shared chapter — role.Repository + chapter.Repository). Stays in
//     gateway. Note: models.VerificationRepository.Get is still used
//     internally by SetVerification's read-modify-write above; what is
//     excluded is exposing Get as its own, ungated HTTP route.
//   - submitVerification — writes to the Actor row (Members.SetDisplayName)
//     and enforces an inline caller-identity check tighter than Identity's
//     shape here (a member may only submit their own application, gated at
//     the handler rather than via a supplied seam). Stays in gateway.
//   - getOrgSettings/getOwnOrgSettings/putOrgSettings — belong to orgsettings, a
//     different domain that happened to share a handler file with
//     verification in the gateway. Out of scope entirely for this repo; not
//     ported, not excluded-with-reasoning like the rows above, simply not
//     this repo's concern.
//
// A route built from this package still needs a caller-identity/capability
// gate wrapped around it before it is safe to serve — this package answers
// "what happens once that gate has passed", never "who may pass it". Every
// route that needs the caller's own id (ChangeOperatorPassword) needs an
// [Identity] supplied at construction, and every route that mints a session
// needs a [SessionMinter] and an explicit ttl — externally supplied facts,
// never lookups this package performs, the same relationship actor's
// HierarchyChecker and comm's Identity already establish.
package routes
