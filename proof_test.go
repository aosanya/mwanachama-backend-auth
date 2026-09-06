package mwanachamaauth_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
)

// The encodings a client may present its key and signature in. Three Flutter
// surfaces and a Go test suite hold these keys; making the encoding a fourth
// thing that can be wrong buys nothing, so length is what is checked.
func TestVerifyDeviceProofAcceptsEveryDocumentedEncoding(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	const nonce = "9f2c1ab4de77c0e5"
	sig := ed25519.Sign(priv, []byte(nonce))

	for name, enc := range map[string]func([]byte) string{
		"base64 std":     base64.StdEncoding.EncodeToString,
		"base64 raw url": base64.RawURLEncoding.EncodeToString,
		"hex":            hex.EncodeToString,
	} {
		t.Run(name, func(t *testing.T) {
			if err := mwanachamaauth.VerifyDeviceProof(enc(pub), nonce, enc(sig)); err != nil {
				t.Fatalf("%s-encoded proof rejected: %v", name, err)
			}
		})
	}
}

// Every way the proof can be wrong, and the one way the *record* can be wrong.
func TestVerifyDeviceProofRefusals(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, otherPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	const nonce = "9f2c1ab4de77c0e5"
	b64 := base64.StdEncoding.EncodeToString
	good := b64(ed25519.Sign(priv, []byte(nonce)))

	cases := []struct {
		name        string
		key, n, sig string
		want        error
	}{
		// The measured attack: any non-empty string used to pass.
		{"arbitrary string", b64(pub), nonce, "x", mwanachamaauth.ErrProofInvalid},
		{"empty signature", b64(pub), nonce, "", mwanachamaauth.ErrProofInvalid},
		{"nonce played back", b64(pub), nonce, nonce, mwanachamaauth.ErrProofInvalid},
		{"right length, zeroes", b64(pub), nonce, b64(make([]byte, ed25519.SignatureSize)), mwanachamaauth.ErrProofInvalid},
		{"signed by another key", b64(pub), nonce, b64(ed25519.Sign(otherPriv, []byte(nonce))), mwanachamaauth.ErrProofInvalid},
		{"good signature, wrong nonce", b64(pub), "a-different-nonce", good, mwanachamaauth.ErrProofInvalid},
		{"good signature, another device's key", b64(otherPub), nonce, good, mwanachamaauth.ErrProofInvalid},
		// A device registered before verification was enforced.
		{"placeholder key", "pk-alice", nonce, good, mwanachamaauth.ErrKeyUnusable},
		{"empty key", "", nonce, good, mwanachamaauth.ErrKeyUnusable},
		// Decodes cleanly but is the wrong size — refused rather than padded.
		{"31-byte key", b64(make([]byte, 31)), nonce, good, mwanachamaauth.ErrKeyUnusable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := mwanachamaauth.VerifyDeviceProof(c.key, c.n, c.sig)
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}

	// The positive control, so a VerifyDeviceProof that refused everything
	// would not pass this file.
	if err := mwanachamaauth.VerifyDeviceProof(b64(pub), nonce, good); err != nil {
		t.Fatalf("the honest proof was refused: %v", err)
	}
}
