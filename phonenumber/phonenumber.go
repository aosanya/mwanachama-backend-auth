// Package phonenumber canonicalizes a phone number to E.164 against a
// dialling region. Ported verbatim from
// mwanachama-backend-api-gateway's internal/domain/phonenumber (DEV-1258,
// DEV-1653), against G366's decision (DSN-1479, 2026-08-22): canonicalize to
// E.164 against the organization default dialling region (member-overridable
// at entry), reject what will not parse, hash the canonical bytes, discard
// the input.
//
// # Why this package exists rather than a helper inside phonesalt
//
// The same rule must serve every caller that ever compares two phone hashes,
// because an HMAC has no notion of "nearly" — if two call sites canonicalize
// even slightly differently, one caller's hash matches nothing the other
// caller's hash produced, and the mismatch surfaces nowhere but as a quiet,
// permanent non-match. One exported function every caller uses is what makes
// that class of bug unrepresentable; a helper copied into each caller is what
// makes it inevitable.
//
// It is deliberately NOT inside phonesalt. That package's whole guarantee is
// that its Hash normalizes nothing and hashes the bytes it is given, stated
// in its own package doc and enforced by its own tests. This function sits
// **in front of** that boundary rather than inside it, which keeps the hash
// boundary one line and keeps "what did we hash" answerable by reading one
// function. Kept as its own leaf subpackage in this repo — imported by
// nothing else here except the blind-index code in blindindex.go — for the
// same reason it was its own package in the gateway.
//
// # The parser is a library, and that was a decision
//
// github.com/nyaruka/phonenumbers, the maintained Go port of Google's
// libphonenumber. Rejecting what will not parse under the chosen region is
// per-region digit-length and prefix rules for every region the product
// might reach. A hand-rolled canonicalizer would be right for one country
// code and silently wrong for the next region, permanently, because the
// entered form is discarded and there is nothing to re-hash from. That is
// not a smaller version of the library; it is the failure mode.
package phonenumber

import (
	"errors"
	"fmt"
	"strings"

	"github.com/nyaruka/phonenumbers"
)

// ErrNoRegion is returned when Canonicalize is asked to parse a number with no
// dialling region to parse it against.
//
// This is the sentinel that makes an unprovisioned organization fail loudly
// at the first enrolment instead of quietly months later. A number
// canonicalized under the wrong region cannot be recovered — the entered form
// is discarded — so guessing a region here would trade a startup error for an
// unrecoverable one. The region is a value a person sets before the first
// member is enrolled, and this error is what enforces "before".
var ErrNoRegion = errors.New("phonenumber: no dialling region set for this organization")

// ErrUnparseable is returned when the input is not a phone number the chosen
// region can make sense of.
//
// This matters most on an import path, where the input is whatever an
// external source wrote — the one form nobody here controls — and a row that
// will not parse must be refused at import rather than hashed on a guess. A
// guess would produce a well-formed digest that matches no member and looks
// exactly like a member who has not contributed.
var ErrUnparseable = errors.New("phonenumber: not a valid number for the given region")

// Canonicalize returns input in E.164 (`+254712445678`) as parsed against
// region, an ISO-3166-1 alpha-2 code.
//
// The returned string is what gets hashed and stored; the input is discarded
// by the caller and never persisted.
//
// Both arguments are rejected rather than defaulted. An empty region is
// ErrNoRegion — see that sentinel for why a default would be the one
// unrecoverable mistake here — and anything the region cannot parse into a
// valid number is ErrUnparseable.
//
// A number already written in international form parses to itself regardless
// of region, which is what makes `0712 445 678` and `+254 712 445 678` one
// member: the first needs the region and the second does not, and both land
// on the same bytes.
func Canonicalize(input, region string) (string, error) {
	region = strings.TrimSpace(region)
	if region == "" {
		return "", ErrNoRegion
	}

	// Uppercase is not folded here for the same reason the archived
	// migration 000023's CHECK refuses it: libphonenumber's region codes are
	// case-sensitive, and a caller that reached this function with `ke` has a
	// store or a screen writing the wrong shape. Folding it would hide that.
	if region != strings.ToUpper(region) {
		return "", fmt.Errorf("%w: region %q is not uppercase ISO-3166-1 alpha-2", ErrUnparseable, region)
	}

	input = strings.TrimSpace(input)
	if input == "" {
		return "", fmt.Errorf("%w: empty", ErrUnparseable)
	}

	num, err := phonenumbers.Parse(input, region)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrUnparseable, err)
	}

	// Parse succeeding is not the same as the number being real. It accepts
	// digit strings of plausible shape that no operator in the region would
	// ever issue, so the validity check is the rule, not a nicety. Without it
	// a mistyped number would hash cleanly to a member who does not exist.
	if !phonenumbers.IsValidNumber(num) {
		return "", fmt.Errorf("%w: %q is not a valid number in %s", ErrUnparseable, input, region)
	}

	return phonenumbers.Format(num, phonenumbers.E164), nil
}
