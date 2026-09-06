package mwanachamaauth

// Indexer, ported from internal/domain/phonesalt/blindindex.go. Kept in this
// repo's root package (not models/, not gormstore/) — same placement the
// gateway used — since it is pure composition over phonenumber.Canonicalize
// and a models.PhoneSaltRepository, with no storage of its own.

import (
	"context"
	"errors"
	"fmt"

	"github.com/aosanya/mwanachama-backend-auth/models"
	"github.com/aosanya/mwanachama-backend-auth/phonenumber"
)

// Indexer is the one door every phone number goes through on its way to a
// blind index (DEV-1227, applying G366 as decided by DSN-1479 on 2026-08-22).
//
// # Why there is exactly one of these
//
// G16 matches an external record to a member by comparing HMACs, and an HMAC
// has no notion of "nearly". The two sides of that comparison are written by
// different code paths months apart — a member's own phone hash at enrolment,
// and an imported record's at ingestion — so if the two canonicalize even
// slightly differently, the imported row hashes to nothing the register
// holds and lands unclaimed, with no error raised anywhere. Nothing fails;
// the record just stops matching.
//
// One type that both callers use is what makes that class of bug
// unrepresentable rather than merely unlikely. A helper each caller invokes
// in its own order is the same code until somebody edits one of them.
//
// # What this deliberately does NOT do
//
// It does not normalize inside the hash. PhoneSaltRepository.Hash still
// hashes the bytes it is given and still says so — that guarantee is
// load-bearing, because "what exactly did we hash" has to stay answerable by
// reading one short function. This type sits strictly in front of it:
// canonicalize, then hand the canonical bytes over. The hash boundary stays
// one line.
//
// It also never stores or returns the entered form. G16's rule is that no raw
// number is stored, and Digest carries the canonical E.164 only so the caller
// can put it on screen while it is still in memory; nothing here writes it
// anywhere.
type Indexer struct {
	salts   models.PhoneSaltRepository
	regions RegionSource
}

// RegionSource supplies the organization's default dialling region — an
// ISO-3166-1 alpha-2 code.
//
// It is an interface rather than a direct dependency on any org-branding
// store, for one reason worth stating: this package must not be able to
// reach a *branding* record. The only fact it is entitled to is the region,
// so that is the only fact the seam exposes, and no future edit here can
// start reading support emails or logo URLs by accident.
type RegionSource interface {
	// DefaultDiallingRegion returns the organization's configured region, or
	// the empty string when nobody has set one. An empty string is a normal
	// return and not an error: it is the state a freshly provisioned plane
	// is in, and the refusal belongs at the point of use, where it can say
	// what the caller was trying to do.
	DefaultDiallingRegion(ctx context.Context) (string, error)
}

// NewIndexer composes the salt repository with a region source.
func NewIndexer(salts models.PhoneSaltRepository, regions RegionSource) *Indexer {
	return &Indexer{salts: salts, regions: regions}
}

// Digest is one phone number's blind index, and the facts a caller needs to
// store it correctly.
type Digest struct {
	// Hash is the HMAC the register compares on. It is what gets stored.
	Hash []byte

	// SaltID is which salt it was computed under, stored alongside Hash so a
	// rotation can tell an orphan from a match.
	SaltID int

	// Canonical is the E.164 form that was hashed. It is returned for display
	// and for error messages, never for storage — G16's rule is that no raw
	// number is stored, and this is the value that rule is about.
	Canonical string
}

// ErrNoDiallingRegion is returned when a number needs a region to be
// understood and the organization has not set one.
//
// This is a provisioning failure surfacing at the first number that needs it,
// and it is deliberately loud. A number canonicalized under the wrong region
// cannot be recovered — the entered form is discarded and there is nothing to
// re-hash from — so the alternative to this error is not "it works", it is a
// register quietly split into numbers hashed two ways.
var ErrNoDiallingRegion = errors.New("phonesalt: the organization has no default dialling region set")

// Index canonicalizes phone against the organization's default dialling
// region and returns its blind index. A number that will not parse is
// rejected here and never hashed on a guess.
func (ix *Indexer) Index(ctx context.Context, phone string) (Digest, error) {
	region, err := ix.regions.DefaultDiallingRegion(ctx)
	if err != nil {
		return Digest{}, fmt.Errorf("reading the default dialling region: %w", err)
	}
	if region == "" {
		return Digest{}, ErrNoDiallingRegion
	}
	return ix.IndexInRegion(ctx, phone, region)
}

// IndexInRegion is the same operation against a region the caller states
// explicitly.
//
// It exists because G366 makes the region *member-overridable at entry* —
// how an organization spanning a border gets two truths out of one setting,
// by asking the one actor who knows which country they are in.
//
// An empty region is refused rather than quietly falling back to the
// organization default. A caller that wants the default has Index; making
// this method fall back would mean a caller who believed they were being
// explicit, and passed an empty string by mistake, would silently get a
// different region — which is precisely the unrecoverable error.
func (ix *Indexer) IndexInRegion(ctx context.Context, phone, region string) (Digest, error) {
	if region == "" {
		return Digest{}, ErrNoDiallingRegion
	}

	canonical, err := phonenumber.Canonicalize(phone, region)
	if err != nil {
		return Digest{}, err
	}

	// The canonical bytes, and nothing else, cross the hash boundary.
	hash, saltID, err := ix.salts.Hash(ctx, canonical)
	if err != nil {
		return Digest{}, err
	}

	return Digest{Hash: hash, SaltID: saltID, Canonical: canonical}, nil
}
