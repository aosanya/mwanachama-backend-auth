package mwanachamaauth

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestAVerifierRoundTrips(t *testing.T) {
	const pw = "correct horse battery staple"
	h, err := Hash(pw)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	ok, err := Verify(h, pw)
	if err != nil || !ok {
		t.Fatalf("Verify(correct) = %v, %v; want true, nil", ok, err)
	}
	ok, err = Verify(h, pw+"x")
	if err != nil || ok {
		t.Fatalf("Verify(wrong) = %v, %v; want false, nil", ok, err)
	}
}

// TestTwoHashesOfOnePasswordDiffer is the salt doing its job. Without it, two
// operators who chose the same password would be visibly the same row to
// anyone reading the table, and one cracked hash would open both.
func TestTwoHashesOfOnePasswordDiffer(t *testing.T) {
	const pw = "correct horse battery staple"
	a, _ := Hash(pw)
	b, _ := Hash(pw)
	if a == b {
		t.Fatal("two hashes of one password are identical — the salt is not random")
	}
}

// TestAVerifierCarriesItsOwnCost is why the parameters are in the string.
//
// They will be raised. A deployment holding a year of hashes at the old cost
// must still verify them, so the cost has to travel with the hash rather than
// be read from a constant at verification time — otherwise the day the
// constant changes, every stored password stops working at once.
func TestAVerifierCarriesItsOwnCost(t *testing.T) {
	const pw = "correct horse battery staple"

	h, err := Hash(pw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h, "$m=") || !strings.Contains(h, ",t=") || !strings.Contains(h, ",p=") {
		t.Fatalf("verifier %q does not carry m/t/p", h)
	}

	// 8 KiB / 1 pass / 1 thread — a cost Hash never emits.
	salt := []byte("sixteen-byte-slt")
	key := argon2.IDKey([]byte(pw), salt, 1, 8, 1, argonKeyLen)
	cheap := fmt.Sprintf("$argon2id$v=%d$m=8,t=1,p=1$%s$%s",
		argon2.Version,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key))

	ok, err := Verify(cheap, pw)
	if err != nil || !ok {
		t.Fatalf("a verifier written at another cost did not verify: %v %v", ok, err)
	}
	if ok, _ := Verify(cheap, pw+"x"); ok {
		t.Fatal("the low-cost verifier accepted the wrong password")
	}
}

func TestAShortPasswordIsRefused(t *testing.T) {
	// Length and nothing else: composition rules push people towards
	// `Password1!` and away from the length that actually matters.
	if _, err := Hash("short"); !errors.Is(err, ErrPasswordTooShort) {
		t.Fatalf("Hash(short) = %v, want ErrPasswordTooShort", err)
	}
	if _, err := Hash(strings.Repeat("a", MinPasswordLength)); err != nil {
		t.Fatalf("Hash at exactly the floor: %v", err)
	}
}

// TestAnUnreadableVerifierIsNotAWrongPassword separates the two for the log.
// They mean opposite things to an operator: one is "type it again", the other
// is "this row is broken and no password will ever work".
func TestAnUnreadableVerifierIsNotAWrongPassword(t *testing.T) {
	for _, bad := range []string{
		"", "not-a-hash", "$bcrypt$v=19$m=1,t=1,p=1$aaaa$bbbb",
		"$argon2id$v=1$m=1,t=1,p=1$aaaa$bbbb", // wrong version
		"$argon2id$v=19$nonsense$aaaa$bbbb",
		"$argon2id$v=19$m=1,t=1,p=1$!!!$bbbb", // unbase64able salt
	} {
		if _, err := Verify(bad, "correct horse battery staple"); !errors.Is(err, ErrBadVerifier) {
			t.Fatalf("Verify(%q) = %v, want ErrBadVerifier", bad, err)
		}
	}
}
