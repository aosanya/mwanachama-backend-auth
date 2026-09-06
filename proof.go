package mwanachamaauth

// Ported verbatim from internal/domain/auth/proof.go — only the package name
// changed.

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

// ErrProofInvalid is returned when a device's answer to a challenge is not a
// valid signature over that challenge's nonce under the device's registered
// public key. It is deliberately one error for every way the answer can be
// wrong — a caller who does not hold the key learns nothing from the shape of
// the refusal.
var ErrProofInvalid = errors.New("auth: device proof invalid")

// ErrKeyUnusable is returned when the *registered* key cannot be read as an
// Ed25519 public key at all. It is separated from ErrProofInvalid because it
// says something about the device record rather than about the caller: a
// device registered before signature verification was enforced carries a
// placeholder string and can never sign in again, and an operator reading the
// logs needs to be able to tell that apart from a failed forgery.
var ErrKeyUnusable = errors.New("auth: device public key is not an ed25519 key")

// VerifyDeviceProof checks that signature is an Ed25519 signature over the
// challenge nonce under publicKey.
//
// DEV-1185 · until 2026-08-22 the gateway asked for a signature and then
// checked only that the string was non-empty (Device.PublicKey's own comment
// said so). The challenge and verify routes are public by necessity — a device
// proving itself is how a session is first obtained, so there is no session to
// check — which made the pair a complete account takeover: anon challenged a
// device the victim already owned, answered with the literal "x", and was
// minted the victim's session. Nothing was held. This function is the proof
// those routes always claimed to ask for.
//
// The nonce is signed as the raw bytes of the string the challenge carries in
// its `secret` field, exactly as the client read it off the challenge response
// — not a decoded or re-encoded form of it. Whatever the server generated,
// the client signs that.
//
// Key and signature material are accepted as standard base64, raw (unpadded)
// base64url, or hex, because the clients that hold these keys are three
// different Flutter surfaces and a Go test suite and there is no reason to
// make the encoding a fourth thing that can be wrong. Length is what is
// checked, not the alphabet.
func VerifyDeviceProof(publicKey, nonce, signature string) error {
	pub, ok := decodeKeyMaterial(publicKey, ed25519.PublicKeySize)
	if !ok {
		return ErrKeyUnusable
	}
	sig, ok := decodeKeyMaterial(signature, ed25519.SignatureSize)
	if !ok {
		return ErrProofInvalid
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), []byte(nonce), sig) {
		return ErrProofInvalid
	}
	return nil
}

// IsPublicKeyMaterial reports whether s decodes to an Ed25519 public key, in
// any of the three encodings VerifyDeviceProof accepts.
//
// DEV-1254 · it exists for the one place a public key arrives with no
// signature to verify it against — a client-derived key with no session at
// all. That route's safety rests entirely on the key being high-entropy, but
// the gateway was accepting any non-empty string, so the premise was the
// client's to keep. A one-character key would have made the same route an
// enumeration oracle over whatever it keyed.
//
// It is a shape check and never a proof of possession: it says the caller
// presented something the right size to be a key, not that they hold the
// private half. That distinction is why this is a separate function from
// VerifyDeviceProof rather than a mode of it — a caller who wanted the second
// thing and got the first would have exactly the wrong guarantee.
func IsPublicKeyMaterial(s string) bool {
	_, ok := decodeKeyMaterial(s, ed25519.PublicKeySize)
	return ok
}

// decodeKeyMaterial decodes s as standard base64, raw base64url or hex and
// returns it only if it is exactly want bytes long. A wrong length is a
// failure rather than a truncation: an Ed25519 key or signature has one size,
// and accepting anything else would hand ed25519.Verify material it would only
// reject later for a reason harder to read.
func decodeKeyMaterial(s string, want int) ([]byte, bool) {
	if s == "" {
		return nil, false
	}
	for _, dec := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
		hex.DecodeString,
	} {
		if b, err := dec(s); err == nil && len(b) == want {
			return b, true
		}
	}
	return nil, false
}
