package mwanachamaauth

// Ported verbatim from internal/domain/operator/password.go — only the
// package name changed. Password verifiers — argon2id, encoded in the PHC
// string format so the parameters travel with the hash.
//
// **The parameters are in the string on purpose.** They will be raised, and a
// deployment holding a year of hashes at the old cost must still be able to
// verify them; a package-level constant read at verification time would
// invalidate every stored password the day it changed. Storing them means an
// old hash verifies at its own cost and a new one is written at the current
// one.
//
// argon2id rather than bcrypt: bcrypt silently truncates at 72 bytes, which
// turns a long passphrase — the thing an operator should be encouraged to use
// — into a shorter secret than it looks, and it has no memory-hardness at all.

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	// argonTime, argonMemory and argonThreads are the cost this repo writes
	// *new* hashes at. Roughly the RFC 9106 second recommended profile: 64
	// MiB and one pass is the balance for a server that must also answer
	// requests.
	argonTime    uint32 = 1
	argonMemory  uint32 = 64 * 1024 // KiB
	argonThreads uint8  = 4
	argonKeyLen  uint32 = 32
	argonSaltLen        = 16
)

// MinPasswordLength is a floor and not a policy.
//
// Twelve, with no character-class rules, because composition rules push people
// towards `Password1!` and away from the length that actually matters. The one
// thing a server can usefully insist on is that the secret be long.
const MinPasswordLength = 12

// ErrPasswordTooShort is returned by Hash for a password under the floor.
var ErrPasswordTooShort = fmt.Errorf(
	"a console password must be at least %d characters", MinPasswordLength)

// ErrBadVerifier means a stored hash could not be parsed — a corrupted row, or
// one written by a scheme this build does not know.
//
// Its own error rather than "wrong password": those two mean opposite things
// to an operator staring at a sign-in screen, and collapsing them would send
// somebody to reset a password that was never the problem. The *caller* still
// answers the wire with one sentence; this distinction is for the log.
var ErrBadVerifier = errors.New("operator: unreadable password verifier")

// Hash derives a new argon2id verifier for password.
func Hash(password string) (string, error) {
	if len([]rune(password)) < MinPasswordLength {
		return "", ErrPasswordTooShort
	}
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// Verify reports whether password matches the encoded verifier.
//
// The comparison is `subtle.ConstantTimeCompare`, which matters less here than
// it would elsewhere — argon2 already dominates the timing — but costs nothing
// and removes the question.
func Verify(encoded, password string) (bool, error) {
	parts := strings.Split(encoded, "$")
	// "", "argon2id", "v=19", "m=..,t=..,p=..", salt, key
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, ErrBadVerifier
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, ErrBadVerifier
	}
	var (
		memory  uint32
		time    uint32
		threads uint8
	)
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return false, ErrBadVerifier
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, ErrBadVerifier
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, ErrBadVerifier
	}
	// Derived at the STORED cost, not the current one — that is what lets the
	// constants above be raised without invalidating every password on disk.
	got := argon2.IDKey([]byte(password), salt, time, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}
