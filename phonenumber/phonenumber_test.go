package phonenumber

import (
	"errors"
	"testing"
)

// TestSpellingsTheRuleCallsTheSameCollide is the reason this package exists:
// the spellings different callers actually write must land on one string,
// because the next thing that happens to that string is an HMAC and an HMAC
// has no notion of "nearly".
func TestSpellingsTheRuleCallsTheSameCollide(t *testing.T) {
	const region = "KE"
	const want = "+254712445678"

	spellings := []string{
		"0712 445 678",
		"0712445678",
		"+254712445678",
		"+254 712 445 678",
		"254712445678",
		"+254-712-445-678",
		"(0712) 445678",
	}

	for _, in := range spellings {
		got, err := Canonicalize(in, region)
		if err != nil {
			t.Fatalf("Canonicalize(%q, %q) errored: %v", in, region, err)
		}
		if got != want {
			t.Errorf("Canonicalize(%q, %q) = %q, want %q", in, region, got, want)
		}
	}
}

// TestSpellingsTheRuleCallsDifferentDoNot is the other half of the same
// assert. A canonicalizer that mapped everything to one value would pass the
// test above and be catastrophic — every member would be every other member.
func TestSpellingsTheRuleCallsDifferentDoNot(t *testing.T) {
	a, err := Canonicalize("0712 445 678", "KE")
	if err != nil {
		t.Fatalf("first number errored: %v", err)
	}
	b, err := Canonicalize("0712 445 679", "KE")
	if err != nil {
		t.Fatalf("second number errored: %v", err)
	}
	if a == b {
		t.Fatalf("two different numbers canonicalized to the same string %q", a)
	}
}

// TestSameDigitsDifferentRegionsAreDifferentNumbers asserts the accepted
// trade-off: the same national digits under two regions are two people, and
// there is nothing to re-hash from once the entered form is discarded.
func TestSameDigitsDifferentRegionsAreDifferentNumbers(t *testing.T) {
	ke, err := Canonicalize("0712 445 678", "KE")
	if err != nil {
		t.Fatalf("KE errored: %v", err)
	}
	gb, err := Canonicalize("07123 456789", "GB")
	if err != nil {
		t.Fatalf("GB errored: %v", err)
	}
	if ke == gb {
		t.Fatalf("two regions produced the same canonical form %q", ke)
	}
	if got, want := ke[:4], "+254"; got != want {
		t.Errorf("KE canonical form starts %q, want %q", got, want)
	}
	if got, want := gb[:3], "+44"; got != want {
		t.Errorf("GB canonical form starts %q, want %q", got, want)
	}
}

// TestInternationalFormIgnoresTheRegion is why an organization spanning a
// border is survivable: a number already written internationally does not
// need the region to be right.
func TestInternationalFormIgnoresTheRegion(t *testing.T) {
	for _, region := range []string{"KE", "GB", "US", "TZ"} {
		got, err := Canonicalize("+254712445678", region)
		if err != nil {
			t.Fatalf("region %q errored: %v", region, err)
		}
		if got != "+254712445678" {
			t.Errorf("region %q gave %q, want %q", region, got, "+254712445678")
		}
	}
}

// TestNoRegionIsRefusedRatherThanGuessed. An organization that has not set a
// region must not be able to hash a national number at all.
func TestNoRegionIsRefusedRatherThanGuessed(t *testing.T) {
	for _, region := range []string{"", "   "} {
		if _, err := Canonicalize("0712 445 678", region); !errors.Is(err, ErrNoRegion) {
			t.Errorf("Canonicalize with region %q: err = %v, want ErrNoRegion", region, err)
		}
	}
}

// TestUnparseableIsRejected covers the "reject what will not parse" rule.
func TestUnparseableIsRejected(t *testing.T) {
	cases := []struct{ name, in, region string }{
		{"empty", "", "KE"},
		{"not a number", "not a phone number", "KE"},
		{"too short", "0712", "KE"},
		{"too long", "07124456789012345", "KE"},
		// This case is the IsValidNumber branch and nothing else, verified
		// rather than assumed: phonenumbers.Parse *succeeds* on this input and
		// hands back a perfectly well-formed "+254912445678" — `09` is simply
		// not a prefix any Kenyan operator issues.
		{"well-formed but unissued prefix", "0912 445 678", "KE"},
		{"lowercase region", "0712 445 678", "ke"},
		{"unknown region", "0712 445 678", "ZZ"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Canonicalize(c.in, c.region)
			if !errors.Is(err, ErrUnparseable) {
				t.Fatalf("Canonicalize(%q, %q) = %q, err = %v, want ErrUnparseable", c.in, c.region, got, err)
			}
		})
	}
}

// TestNothingIsReturnedAlongsideAnError guards the shape a caller depends on:
// the canonical form is what gets hashed, so a non-empty return beside a
// non-nil error is a value a careless caller could hash.
func TestNothingIsReturnedAlongsideAnError(t *testing.T) {
	for _, c := range []struct{ in, region string }{
		{"0712 445 678", ""},
		{"nonsense", "KE"},
		{"", "KE"},
	} {
		got, err := Canonicalize(c.in, c.region)
		if err == nil {
			t.Fatalf("Canonicalize(%q, %q) unexpectedly succeeded", c.in, c.region)
		}
		if got != "" {
			t.Errorf("Canonicalize(%q, %q) returned %q alongside error %v", c.in, c.region, got, err)
		}
	}
}
