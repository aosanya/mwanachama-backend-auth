package routes_test

// Pins board row DEV-1700: ConsumeChallenge is called — and permanently
// marks the challenge used — BEFORE DeviceVerify/RecoveryVerify actually
// check the proof (signature/secret). A single wrong guess against a valid,
// unexpired challenge_id burns it forever, whether or not the guesser was
// the legitimate holder. Combined with sequential, predictable "chal-N"/
// "device-N" ids in production (gormstore.mintID, Postgres sequence-backed
// — see gormstore/tables.go and gormstore/challenge.go/device.go), this lets
// a fully unauthenticated caller with no credentials at all deny every
// in-flight device-verify or account-recovery attempt fleet-wide, just by
// enumerating ids and POSTing garbage.
//
// If DEV-1700 is ever fixed (e.g. checking the proof BEFORE consuming, or
// only consuming on a successful proof and rate-limiting failed guesses
// separately), both assertions below that a same-challenge retry is
// refused must start failing — invert them alongside the fix.
import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
	"github.com/aosanya/mwanachama-backend-auth/routes"
)

func TestDEV1700_DeviceVerify_OneWrongSignatureBurnsTheChallengeForTheRealDevice(t *testing.T) {
	db, tables := newTestDB(t)
	auth := mwanachamaauth.NewAuthStore(db, tables)
	ctx := context.Background()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dev, err := auth.RegisterDevice(ctx, mwanachamaauth.Device{
		MemberID: "m1", PublicKey: base64.StdEncoding.EncodeToString(pub),
	})
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}
	challenge, err := auth.CreateChallenge(ctx, mwanachamaauth.Challenge{
		Kind: mwanachamaauth.KindDevice, DeviceID: dev.ID, MemberID: dev.MemberID, Secret: "nonce-xyz",
	})
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}

	minter := &fakeMinter{}
	handler := routes.DeviceVerify(auth, minter, time.Hour, false)

	// Attacker (or a corrupted first submission) guesses wrong — no
	// knowledge of the device's private key is needed to reach this point,
	// only the (predictable, sequential in production) deviceID and
	// challenge_id.
	badBody := strings.NewReader(`{"challenge_id":"` + challenge.ID + `","signature":"bm90LXJlYWwtc2ln"}`)
	badReq := httptest.NewRequest(http.MethodPost, "/devices/"+dev.ID+"/verify", badBody)
	badReq.SetPathValue("deviceID", dev.ID)
	badRec := httptest.NewRecorder()
	handler(badRec, badReq)
	if badRec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-signature attempt: status = %d, want 401: %s", badRec.Code, badRec.Body.String())
	}

	// BUG: the real device now retries with its genuine, correctly-signed
	// proof against the SAME challenge — and is refused, because the first
	// (bogus) attempt already consumed it. Once fixed, this should return
	// 201 and mint a session.
	sig := ed25519.Sign(priv, []byte(challenge.Secret))
	goodBody := strings.NewReader(`{"challenge_id":"` + challenge.ID + `","signature":"` +
		base64.StdEncoding.EncodeToString(sig) + `"}`)
	goodReq := httptest.NewRequest(http.MethodPost, "/devices/"+dev.ID+"/verify", goodBody)
	goodReq.SetPathValue("deviceID", dev.ID)
	goodRec := httptest.NewRecorder()
	handler(goodRec, goodReq)
	if goodRec.Code != http.StatusUnauthorized {
		t.Fatalf("pin invalidated: the real device's correctly-signed retry now succeeds (status %d) — DEV-1700 is fixed, invert this test", goodRec.Code)
	}
	if minter.minted != 0 {
		t.Fatalf("pin invalidated: a session was minted for the retry — DEV-1700 is fixed, invert this test")
	}
}

func TestDEV1700_RecoveryVerify_OneWrongGuessBurnsTheChallengeForTheRealMember(t *testing.T) {
	db, tables := newTestDB(t)
	auth := mwanachamaauth.NewAuthStore(db, tables)
	ctx := context.Background()

	challenge, err := auth.CreateChallenge(ctx, mwanachamaauth.Challenge{
		Kind: mwanachamaauth.KindRecovery, MemberID: "m1", Secret: "correct-secret",
	})
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}

	minter := &fakeMinter{}
	handler := routes.RecoveryVerify(auth, minter, time.Hour)

	// Attacker enumerates a challenge_id (sequential "chal-N" in
	// production) and submits one wrong guess — no knowledge of the
	// member's actual recovery secret is needed.
	badBody := strings.NewReader(`{"challenge_id":"` + challenge.ID + `","secret":"wrong-guess"}`)
	badReq := httptest.NewRequest(http.MethodPost, "/recovery/verify", badBody)
	badRec := httptest.NewRecorder()
	handler(badRec, badReq)
	if badRec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-secret attempt: status = %d, want 401: %s", badRec.Code, badRec.Body.String())
	}

	// BUG: the real member now submits their genuine, correct recovery
	// secret against the SAME challenge — and is refused, because the
	// attacker's earlier bogus guess already consumed it. Once fixed, this
	// should return 201 and mint a session.
	goodBody := strings.NewReader(`{"challenge_id":"` + challenge.ID + `","secret":"correct-secret"}`)
	goodReq := httptest.NewRequest(http.MethodPost, "/recovery/verify", goodBody)
	goodRec := httptest.NewRecorder()
	handler(goodRec, goodReq)
	if goodRec.Code != http.StatusUnauthorized {
		t.Fatalf("pin invalidated: the real member's correct-secret retry now succeeds (status %d) — DEV-1700 is fixed, invert this test", goodRec.Code)
	}
	if minter.minted != 0 {
		t.Fatalf("pin invalidated: a session was minted for the retry — DEV-1700 is fixed, invert this test")
	}
}
