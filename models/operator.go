package models

// Ported from internal/domain/operator — the platform's first stored secret,
// and the deliberateness of that is the whole of this file's design.
//
// **This is the platform's first stored secret, and the deliberateness of
// that is the whole of this package's design.** Every other credential the
// gateway admits proves possession of something the member already holds — a
// device key, a code sent to a number, a recovery phrase — and none of them
// puts a reusable secret in a table. This one does, because the console needs
// an identifier an organization controls: **a phone number can be revoked by
// the carrier and reassigned to a stranger**, and a coordinator's authority
// over an organization must not follow a SIM card.
//
// So the properties below are not ceremony:
//
//   - The password is stored only as an argon2id verifier (this repo's
//     password.go), never reversibly, and no route ever reads one back.
//   - The credential is a **separate identity** from a member's own contact
//     email. That column is a contact detail an organization records about a
//     person; this is a key to a console. Keeping them apart means a
//     directory edit can never move somebody's sign-in, and a sign-in
//     address never has to appear in a roster export.
//   - It authenticates and **never authorizes**. Holding one mints an ordinary
//     session for the bound member and nothing more; what that session may do
//     comes off the member's own seats, checked per request. A stolen console
//     password is worth exactly the seats its member holds — which is why
//     there is no "console admin" flag here and must not be.

import (
	"context"
	"errors"
	"strings"
	"time"
)

// ErrOperatorNotFound is returned when no credential matches.
//
// **Every sign-in failure resolves to this or to a bare mismatch, and the
// handler answers both with one sentence.** A caller who can tell *no such
// address* from *wrong password* has an account-enumeration oracle, and an
// operator console's address list is a list of the people worth phishing.
var ErrOperatorNotFound = errors.New("operator: no such credential")

// ErrOperatorEmailTaken is returned when a second credential claims an
// address one already holds.
var ErrOperatorEmailTaken = errors.New("that email address already has a console credential")

// ErrOperatorDisabled is returned for a credential whose access has been
// withdrawn.
//
// Its own sentinel rather than a fold into ErrOperatorNotFound, because the
// two are different acts to different audiences: the store distinguishes them
// so an audit can, and the *handler* collapses them on the wire so a caller
// cannot.
var ErrOperatorDisabled = errors.New("operator: credential disabled")

// OperatorLockAfter is how many consecutive wrong passwords bar an address.
// Five, the same count the phone door uses — one policy for "somebody is
// guessing", rather than two numbers that drift.
//
// Named OperatorLockAfter rather than the original operator.LockAfter: it
// would collide with auth's own identical lock-out budget once both flatten
// into this package — see AuthLockAfter in auth.go.
const OperatorLockAfter = 5

// OperatorCredential is one console sign-in, minus its verifier. Ported from
// internal/domain/operator.Credential.
//
// The hash is never a field on this struct and never crosses a repository
// boundary in a value a handler holds: it travels as an explicit argument to
// Create/SetPassword and comes back only from Verifier, whose one caller is
// the sign-in path. A hash on the struct is a hash that eventually gets
// marshalled into a response by a handler that returned the wrong thing.
type OperatorCredential struct {
	ID       string `json:"id"`
	MemberID string `json:"member_id"`
	// Email is stored normalized — see Normalize. The address as typed is not
	// kept: two spellings of one address must not be two credentials.
	Email      string     `json:"email"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	DisabledAt *time.Time `json:"disabled_at,omitempty"`
}

// Disabled reports whether access has been withdrawn.
func (c OperatorCredential) Disabled() bool { return c.DisabledAt != nil }

// Normalize is the one spelling of an address this package stores or matches
// on: trimmed and lower-cased.
//
// Case only, and no further cleverness — no dot-stripping, no `+tag` removal.
// Those rules are one mail provider's and not the next one's, and a gateway
// that decided `a.b@example.org` and `ab@example.org` were the same person
// would be wrong for most of the world's mail servers while looking helpful.
func Normalize(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// ValidEmail is a deliberately shallow check: one `@`, something either side,
// no spaces, and a dot in the domain.
//
// It is not a validator and does not try to be. The only test that means
// anything is whether mail arrives, and an over-strict pattern here refuses
// real addresses — which, for a credential an operator cannot sign in without,
// is the more expensive failure by far.
func ValidEmail(email string) bool {
	e := Normalize(email)
	if strings.ContainsAny(e, " \t\n") {
		return false
	}
	at := strings.Index(e, "@")
	if at <= 0 || at != strings.LastIndex(e, "@") || at == len(e)-1 {
		return false
	}
	domain := e[at+1:]
	dot := strings.Index(domain, ".")
	return dot > 0 && dot < len(domain)-1
}

// OperatorAttempt is an address's consecutive-wrong-password state. Ported
// from internal/domain/operator.Attempt.
//
// Keyed on the **address**, not on the caller and not on the session, for the
// reason the phone door's counter is keyed on the number: a per-caller
// limiter counts requests, and what needs counting is guesses against one
// account. A second browser is not a second budget.
type OperatorAttempt struct {
	Email       string    `json:"email"`
	Failed      int       `json:"failed_attempts"`
	LockedUntil time.Time `json:"locked_until,omitempty"`
}

// Locked reports whether the address is barred as of now.
func (a OperatorAttempt) Locked(now time.Time) bool {
	return !a.LockedUntil.IsZero() && now.Before(a.LockedUntil)
}

// TriesLeft never goes below zero, and is meaningless while Locked — the
// screen shows the lock-out instead.
func (a OperatorAttempt) TriesLeft() int {
	if n := OperatorLockAfter - a.Failed; n > 0 {
		return n
	}
	return 0
}

// Fail applies one wrong password and returns the state after it.
//
// A lock that has already expired resets the count first, so the five are
// always *consecutive within one window* rather than cumulative over an
// address's lifetime — otherwise a credential used for a year would lock on
// its fifth typo ever.
func (a OperatorAttempt) Fail(now time.Time, lockFor time.Duration) OperatorAttempt {
	if !a.LockedUntil.IsZero() && !now.Before(a.LockedUntil) {
		a.Failed = 0
		a.LockedUntil = time.Time{}
	}
	a.Failed++
	if a.Failed >= OperatorLockAfter {
		a.LockedUntil = now.Add(lockFor)
	}
	return a
}

// OperatorRepository is the persistence boundary for console credentials.
// Ported from internal/domain/operator.Repository.
type OperatorRepository interface {
	// Create stores a credential and its verifier. Email must already be
	// normalized; hash must already be an Encode()d argon2id string.
	//
	// Returns ErrOperatorEmailTaken when the address is already claimed.
	Create(ctx context.Context, c OperatorCredential, hash string) (OperatorCredential, error)

	// Verifier returns a credential and its stored hash, by address.
	//
	// The one method that hands a hash back, named so that a reader can find
	// every use of one by searching for this word. Returns ErrOperatorNotFound
	// for an address nobody holds; a **disabled** credential is returned with
	// ErrOperatorDisabled so the caller can distinguish them for the log while
	// still answering the wire identically.
	Verifier(ctx context.Context, email string) (OperatorCredential, string, error)

	// Get returns a credential by id.
	Get(ctx context.Context, id string) (OperatorCredential, error)

	// ListForMember returns every credential bound to a member, disabled ones
	// included — a withdrawn credential is part of the record of who could
	// once sign in, and hiding it makes that record unreadable.
	ListForMember(ctx context.Context, memberID string) ([]OperatorCredential, error)

	// SetPassword replaces the verifier. It does not clear the lock-out: a
	// password change is not proof that the guesser has gone.
	SetPassword(ctx context.Context, id, hash string) error

	// Disable withdraws access, in place. There is no delete: a credential
	// that once existed is part of who could reach this console, and G222's
	// "withdrawn is never restored" is why there is no Enable beside it.
	Disable(ctx context.Context, id string) error

	// Attempt reads the consecutive-wrong-password state for an address. An
	// address nobody has failed against returns the zero OperatorAttempt.
	Attempt(ctx context.Context, email string) (OperatorAttempt, error)

	// RecordFailure counts one wrong password and returns the state after it.
	// Implementations apply the policy by calling OperatorAttempt.Fail, so
	// OperatorLockAfter lives in this package and not once per store.
	RecordFailure(ctx context.Context, email string, now time.Time, lockFor time.Duration) (OperatorAttempt, error)

	// ClearAttempts forgets an address's failures. A correct password is the
	// only caller.
	ClearAttempts(ctx context.Context, email string) error
}
