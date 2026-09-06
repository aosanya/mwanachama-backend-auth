// Ported from internal/domain/phonesalt — `phone_salt`, the per-organization
// secret every phone number is hashed under (G16), and its public facts.
//
// # The secret is absent from this package's types, on purpose
//
// phone-salt.md's select rule is "nobody, for `secret`", and its anon rule is
// "nothing at all — the salt is the one value whose leak retroactively
// de-anonymizes every phone hash in the register". Here that is enforced by
// the shape of the code: Salt below has no secret field, so no handler, no
// JSON encoder and no log line can carry it, and there is no
// PhoneSaltRepository method that returns it. The key is read by exactly one
// statement in this repo — inside PhoneSaltStore.Hash (phonesalt_impl.go) —
// and that method returns a digest.
//
// A future contributor who adds a Secret field to Salt has removed the whole
// guarantee, silently, and every other test in this package would still pass
// except the one built for precisely that (see phonesalt_impl_test.go).
//
// # What this package deliberately does NOT carry
//
//   - Rotation. Re-computing every stored hash under a successor, previewing
//     the orphan count first, needs a contribution/statement-import domain
//     that does not exist in this repo. Retire below is the half that can be
//     built honestly today — it stamps the pair, and it refuses to leave a
//     plane with no live salt.
//   - Phone normalization. Hash is a keyed hash over the bytes it is given
//     and normalizes nothing — that is not an oversight, it is the caller's
//     job (see phonenumber.Canonicalize and Indexer in blindindex.go).
package models

import (
	"context"
	"errors"
	"time"
)

// ErrPhoneSaltNotFound is returned when no salt matches — including, from
// Live, when the organization has no live salt at all.
//
// A plane with no live salt cannot hash, which means it cannot enrol and
// cannot import. That is a provisioning failure and never a normal state, so
// it is an error rather than a zero value a caller might use by accident.
var ErrPhoneSaltNotFound = errors.New("phonesalt: not found")

// ErrPhoneSaltAlreadyLive is returned by Provision when a live salt already
// exists.
//
// Two live salts are two answers to "which key do I hash under", and the
// loser's hashes match nothing while looking perfectly well-formed. The
// database refuses it too (phone_salt_one_live); this is the same refusal
// named in the domain's own words so a caller can tell it from a driver error.
var ErrPhoneSaltAlreadyLive = errors.New("phonesalt: a live salt already exists")

// ErrPhoneSaltRetired is returned when an operation names a salt that is
// already retired. Retiring twice would overwrite who actually ended it.
var ErrPhoneSaltRetired = errors.New("phonesalt: salt already retired")

// ErrPhoneSaltNoActor is returned when Retire is called without naming who
// retired the salt.
//
// The database refuses the same row (phone_salt_retired_pair), and this is
// that refusal in the domain's own words. It is a distinct sentinel rather
// than a reference error because the caller's mistake is specific and
// fixable: rotation is a custody act and the log names an actor, so a
// retirement with no actor is not a validation slip but a missing fact.
var ErrPhoneSaltNoActor = errors.New("phonesalt: a retirement must name who retired it")

// Salt is one phone salt's public facts — everything an admin-facing screen
// draws and nothing else. Fields mirror the archived migration
// 000018_phone_salt one-for-one **except `secret`, which is deliberately
// absent**; see the package doc.
type Salt struct {
	// ID is the version operators say aloud: "salt 1", "salt 2". A
	// contribution/statement-import row (outside this repo) names this
	// column, and comparing it against the live salt's ID is what makes an
	// orphan detectable.
	ID int `json:"id"`

	// SetAt is when this salt began. An admin screen draws its age off this
	// and nothing else — "set 04 Feb 2026 · 178 days".
	SetAt time.Time `json:"set_at"`

	// SetBy is who set it, or empty for the first salt, which provisioning
	// writes before any member exists to name.
	SetBy string `json:"set_by,omitempty"`

	// RetiredAt is when it stopped being the live salt, or nil while it is
	// live. A retired salt keeps its row: the contributions naming it must
	// still resolve, and their orphaned status is only legible because the
	// salt they name is still there and visibly retired.
	RetiredAt *time.Time `json:"retired_at,omitempty"`

	// RetiredBy is who retired it. Paired with RetiredAt by the database's
	// phone_salt_retired_pair CHECK: a salt cannot be retired without naming
	// who retired it, and the constraint binds the table owner too.
	RetiredBy string `json:"retired_by,omitempty"`
}

// Live reports whether this salt is the one hashes are computed under now.
func (s Salt) Live() bool { return s.RetiredAt == nil }

// AgeDays is an admin screen's "178 days", computed against the caller's
// clock rather than time.Now so a test can state the day it is reading from.
//
// Measured from SetAt for a live salt and frozen at RetiredAt for a retired
// one: a retired salt's age is how long it served, not how long ago it began,
// and a screen that kept counting would report a key nobody has used for
// months as the organization's oldest exposure.
func (s Salt) AgeDays(now time.Time) int {
	end := now
	if s.RetiredAt != nil {
		end = *s.RetiredAt
	}
	d := end.Sub(s.SetAt)
	if d < 0 {
		return 0
	}
	return int(d.Hours() / 24)
}

// PhoneSaltRepository is the persistence boundary for the phone-salt domain.
// Ported from internal/domain/phonesalt.Repository.
//
// Like every other domain in this port it carries no capability check of its
// own — authorization lives beside the handler, in whatever mounts this
// repo's routes/. What is unusual here is the *shape* of the interface
// rather than any rule in it: there is no Get returning a secret, no Secret
// method and no Key method, because phone-salt.md's select rule for that
// column is **nobody**, and an interface that could return it would put the
// enforcement back into the discipline of every call site. See the package
// doc.
type PhoneSaltRepository interface {
	// Hash computes the G16 keyed hash of one phone number under the live
	// salt and reports which salt it used, so the caller can store the pair.
	//
	// This is the only method that touches the key, and it returns a digest.
	// A caller that wants to compare two numbers hashes both and compares the
	// digests; a caller that wants to know the key cannot ask.
	//
	// **phone is used verbatim.** This method normalizes nothing — see the
	// package doc. Passing two spellings of one number yields two digests,
	// and that is a property of the undecided normalization question, not of
	// the hash.
	//
	// ErrPhoneSaltNotFound when the organization has no live salt: a plane
	// that cannot hash cannot enrol or import, and silently returning a zero
	// digest would make every member match every other.
	Hash(ctx context.Context, phone string) (digest []byte, saltID int, err error)

	// Live returns the salt hashes are currently computed under, without its
	// secret. ErrPhoneSaltNotFound when there is none.
	Live(ctx context.Context) (Salt, error)

	// List returns every salt, live and retired, newest first. Never empty on
	// a provisioned plane; an empty slice means provisioning did not run,
	// which is worth seeing rather than hiding behind an error.
	List(ctx context.Context) ([]Salt, error)

	// Provision writes the organization's first salt, or the successor a
	// rotation has already decided on, with the given id and key.
	//
	// It does NOT retire anything and does not re-hash: rotation is a
	// separate transaction over every stored hash, out of this repo's scope.
	// This method is the half that has an honest meaning today — the first
	// salt, written by provisioning before any member exists.
	//
	// ErrPhoneSaltAlreadyLive when a live salt exists. The caller cannot pass
	// that by retrying; it has to retire the incumbent first, which is the
	// sequence that makes the orphan cost visible.
	Provision(ctx context.Context, id int, secret []byte, setBy string) (Salt, error)

	// Retire stamps retired_at and retired_by on one salt, together, which is
	// the only write the schema's phone_salt_retired_pair permits.
	//
	// retiredBy must be non-empty: a salt cannot be retired without naming
	// who retired it. Retiring an already-retired salt is
	// ErrPhoneSaltRetired rather than a no-op or a re-stamp — a second retire
	// would overwrite who actually ended it, which is the fact the column
	// exists to keep.
	//
	// Note what this leaves behind: a plane whose only salt has been retired
	// can no longer hash. That is deliberate and is the shape of the real
	// act — the successor is provisioned first, in the same transaction, by
	// the rotation door.
	Retire(ctx context.Context, id int, retiredBy string) (Salt, error)
}
