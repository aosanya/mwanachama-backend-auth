// Package models holds the domain types and repository interfaces for all
// five ported sub-domains (auth, operator, verification, phonesalt) — flat,
// mirroring mwanachama-backend-comm's identical "several gateway packages,
// one models package" shape. Names that collided across the originals are
// prefixed by the domain they came from; see this repo's doc.go for the full
// list.
package models

import (
	"context"
	"errors"
	"time"
)

// ErrAuthNotFound is returned when a device or challenge id has no record.
// Ported from internal/domain/auth.ErrNotFound; prefixed to avoid colliding
// with operator's, verification's and phonesalt's own not-found sentinels
// once all four share this package.
var ErrAuthNotFound = errors.New("auth: not found")

// ErrAuthSignOutReasonRequired refuses a sign-out that does not say which
// door acted (DEV-1347).
//
// A programming error rather than a caller's, and refused in both stores
// anyway: the alternative is a store defaulting the reason, and the one thing
// this column must never do is guess. M121 and M135 open with why the handset
// was ejected, and a member-initiated sign-out rendered as a recovery is G99's
// notification firing at somebody who did it themselves. The Postgres CHECK
// would catch it too — this catches it before the write as well, so every
// backend refuses the same call.
var ErrAuthSignOutReasonRequired = errors.New("auth: a sign-out must say which door ended the device")

// ErrAuthChallengeExpired is returned when a challenge is verified past its
// expiry.
var ErrAuthChallengeExpired = errors.New("auth: challenge expired")

// ErrAuthDeviceSignedOut is returned when a signed-out device tries to
// challenge or verify. It is deliberately distinct from ErrAuthNotFound at
// the domain boundary — the handlers collapse both into the same public
// answer, because a caller who can tell "this device was signed out" from
// "no such device" learns which ids were once real, which is the harvest
// DEV-1217 closed on the same two doors.
var ErrAuthDeviceSignedOut = errors.New("auth: device signed out")

// ChallengeKind distinguishes the flows a challenge can belong to.
type ChallengeKind string

const (
	KindDevice   ChallengeKind = "device"
	KindPhone    ChallengeKind = "phone"
	KindRecovery ChallengeKind = "recovery"
)

// Device is a client install bound to a member. PublicKey is the Ed25519 key
// the device's answer to a challenge is verified against — standard base64,
// raw base64url or hex, see VerifyDeviceProof in this repo's proof.go.
//
// DEV-1185 · this comment used to end "the mock store accepts any signature",
// and it was accurate: the verify handler refused an empty string and passed
// everything else, so anyone who could name a device id was minted its member's
// session. The comment described the defect for as long as the defect existed.
// A device registered before 2026-08-22 carries a placeholder here and can no
// longer sign in — that is the intended posture, not a regression.
type Device struct {
	ID        string    `json:"id"`
	MemberID  string    `json:"member_id"`
	PublicKey string    `json:"public_key"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`

	// SignedOutAt ends this device's life (DEV-1272, M143 member-sign-out).
	// A signed-out device may never challenge or verify again: its key stays on
	// the row so the record of what it was is not destroyed, but the door is
	// shut. Signing back in is the ordinary M37/M38 phone flow registering a
	// *new* device, which is what member-sign-out.md says signing out means —
	// "signing back in with the number on file is the ordinary sign-in and
	// verification survives it".
	//
	// A pointer, not a time.Time: `omitempty` does not omit a zero struct, so a
	// value type renders `"signed_out_at":"0001-01-01T00:00:00Z"` on every live
	// device — a date that reads as a sign-out and is not one.
	SignedOutAt *time.Time `json:"signed_out_at,omitempty"`

	// SignedOutBy is why (DEV-1347). Empty exactly when SignedOutAt is nil.
	//
	// **This is the fact M121 member-recovery-verify and M135
	// member-device-signed-out each open with** — "someone signed in as you on
	// a new handset, using your recovery phrase. This phone was signed out
	// then." A screen cannot write that off a date alone, and it must never
	// guess: a member-initiated sign-out rendered as a recovery is G99's
	// notification firing at somebody who signed themselves out.
	//
	// Two values, and the absent third is deliberate — device.md:60 models
	// `member` · `recovery`, and the reserved `expiry` was deleted 2026-08-21
	// (DSN-1035) against G230: a session ends on a security event, never on a
	// clock, so a reason nothing writes read as though sessions expired.
	SignedOutBy SignOutReason `json:"signed_out_by,omitempty"`
}

// SignOutReason is why a device's life ended — device.md:60's enum.
type SignOutReason string

const (
	// SignOutByMember is the handset signing itself out (DEV-1272, M143).
	// **Only ever the presenting device**: G99's rule is that a device may
	// only sign itself out, because on the branch that matters the attacker
	// holds the other phone — which is why M135 carries no control at all.
	SignOutByMember SignOutReason = "member"
	// SignOutByRecovery is a successful recovery ejecting every OTHER handset
	// the member had (device.md:89, G96 both branches). It is the only value
	// any screen currently produces, and it is written by the recovery flow —
	// never by a handset.
	SignOutByRecovery SignOutReason = "recovery"
)

// IsSignedOut reports whether this device's life has ended.
func (d Device) IsSignedOut() bool { return d.SignedOutAt != nil }

// Challenge is a short-lived nonce/code a client must answer to prove control
// of a device or phone number.
type Challenge struct {
	ID        string        `json:"id"`
	Kind      ChallengeKind `json:"kind"`
	DeviceID  string        `json:"device_id,omitempty"`
	Phone     string        `json:"phone,omitempty"`
	Secret    string        `json:"secret"` // nonce (device) or code (phone/recovery)
	MemberID  string        `json:"member_id,omitempty"`
	ExpiresAt time.Time     `json:"expires_at"`
	Consumed  bool          `json:"consumed"`
}

// Public is the projection a challenge door may write to a caller who has not
// yet proved anything.
//
// DEV-1217 · the device door is public by necessity — proving a device is how
// a session is first obtained, so there is no session to check — and it used
// to answer the whole struct, MemberID included. Device ids are sequential on
// both of the gateway's original stores, so anon walked the id space and read
// the owning member id off each 201: a device->member map built with no
// account at all, which is the input DEV-1182's takeover and DEV-1163's
// harvest both start from.
//
// MemberID is the only field a signing client has never needed. It signs the
// nonce; the session minted afterwards carries the member id, read
// server-side from the stored challenge, never from the client.
func (c Challenge) Public() Challenge {
	c.MemberID = ""
	return c
}

// AuthLockAfter is how many consecutive wrong codes lock a phone number, read
// off M38 member-signin-code:88 — "After five wrong codes this number is
// locked for 15 minutes." The duration is the caller's to choose; the count is
// here because PhoneAttempt.Fail applies it.
//
// Named AuthLockAfter rather than the original auth.LockAfter: operator's own
// identical lock-out budget (operator.LockAfter in the gateway) would collide
// with this one once both flatten into this package, so both gained a
// domain-of-origin prefix — see OperatorLockAfter in operator.go.
const AuthLockAfter = 5

// PhoneAttempt is a phone number's consecutive-wrong-code state (DEV-1264).
//
// It is keyed on the *number*, not on the challenge and not on the caller,
// because M38:96-97 says so in as many words: "attempts are counted and
// rate-limited server-side, not in the app, so retrying from another device
// does not reset the count". A per-challenge counter resets every time a wrong
// code consumes its challenge; a per-caller limiter counts the wrong thing.
type PhoneAttempt struct {
	Phone       string    `json:"phone"`
	Failed      int       `json:"failed_attempts"`
	LockedUntil time.Time `json:"locked_until,omitempty"`
}

// Locked reports whether the number is barred as of now.
func (a PhoneAttempt) Locked(now time.Time) bool {
	return !a.LockedUntil.IsZero() && now.Before(a.LockedUntil)
}

// TriesLeft is the number M38:86 renders as "3 tries left". It never goes
// below zero, and it is meaningless while Locked — the screen shows the
// lock-out instead.
func (a PhoneAttempt) TriesLeft() int {
	if n := AuthLockAfter - a.Failed; n > 0 {
		return n
	}
	return 0
}

// Fail applies one wrong code and returns the state after it. A lock that has
// already expired resets the count first, so the five are always *consecutive*
// within one window rather than cumulative over a number's lifetime.
func (a PhoneAttempt) Fail(now time.Time, lockFor time.Duration) PhoneAttempt {
	if !a.LockedUntil.IsZero() && !now.Before(a.LockedUntil) {
		a.Failed = 0
		a.LockedUntil = time.Time{}
	}
	a.Failed++
	if a.Failed >= AuthLockAfter {
		a.LockedUntil = now.Add(lockFor)
	}
	return a
}

// AuthRepository is the persistence boundary for the auth domain. Ported from
// internal/domain/auth.Repository; prefixed to avoid colliding with
// operator's, verification's and phonesalt's own Repository interfaces.
type AuthRepository interface {
	RegisterDevice(ctx context.Context, d Device) (Device, error)
	GetDevice(ctx context.Context, id string) (Device, error)

	// SignOutDevice ends a device's life and returns it as it now stands.
	// Idempotent: signing out an already-signed-out device keeps the first
	// timestamp AND the first reason, because the first sign-out is when the
	// handset stopped being trusted and a repeat call must not move that date
	// forward — nor rewrite why. A recovery sweeping a handset the member had
	// already signed out leaves it reading `member`, which is what happened.
	//
	// by is required (DEV-1347): a sign-out with no reason is a row M121 and
	// M135 cannot render, so the caller states which door acted rather than
	// leaving the store to assume one.
	SignOutDevice(ctx context.Context, id string, at time.Time, by SignOutReason) (Device, error)

	// SignOutOtherDevices ends every device the member holds EXCEPT keepID,
	// stamping SignOutByRecovery, and returns the ones this call actually
	// ended — device.md:89's "sets signed_out_at and signed_out_by =
	// 'recovery' on every other row for the member in the same transaction
	// that mints the new one" (G96, both branches).
	//
	// **Not the plural of SignOutDevice, and must not be built as one.**
	// DEV-1272's rule is that a device may only sign ITSELF out, because on
	// the branch that matters the attacker holds the other phone. This is the
	// recovery flow's act, not a handset's, and the caller is the recovery
	// route — which is why it takes a member and an exception rather than a
	// device id.
	//
	// keepID may be empty: a recovery that mints no device of its own ejects
	// every one of them. Already-signed-out devices keep their first date and
	// reason and are not returned, so the result is exactly what this recovery
	// ended and is what a notification would be built from.
	SignOutOtherDevices(ctx context.Context, memberID, keepID string, at time.Time) ([]Device, error)

	CreateChallenge(ctx context.Context, c Challenge) (Challenge, error)
	GetChallenge(ctx context.Context, id string) (Challenge, error)
	// ConsumeChallenge marks a challenge used and returns it, failing if it is
	// missing, already consumed, or expired as of now.
	ConsumeChallenge(ctx context.Context, id string, now time.Time) (Challenge, error)

	// PhoneAttempt reads the consecutive-wrong-code state for a number.
	// A number nobody has failed against returns the zero PhoneAttempt.
	PhoneAttempt(ctx context.Context, phone string) (PhoneAttempt, error)

	// RecordPhoneFailure counts one wrong code against a number and returns
	// the state after it. Implementations apply AuthLockAfter / lockFor by
	// calling PhoneAttempt.Fail, so the policy lives in one place (this
	// package) and not once per store.
	RecordPhoneFailure(ctx context.Context, phone string, now time.Time, lockFor time.Duration) (PhoneAttempt, error)

	// ClearPhoneAttempts forgets a number's failures. A correct code is the
	// only caller: the count is *consecutive* wrong codes, so it survives a
	// device change but not a success.
	ClearPhoneAttempts(ctx context.Context, phone string) error

	// MemberIDForPhone returns the member bound to a phone number, minting one
	// via mintMember on first sight.
	//
	// DEV-1263 · a mintMember that returns "" means *do not bind*: the lookup
	// answers "" with no error and writes nothing. That is how the challenge
	// door asks the question without answering it, because M37 promises
	// "Nothing exists until you confirm the code" and the mint therefore
	// belongs on the verify path. An implementation that binds "" instead of
	// skipping the write leaves a phone pointing at no member, which reads as
	// "already bound" forever after.
	MemberIDForPhone(ctx context.Context, phone string, mintMember func() string) (string, error)
}
