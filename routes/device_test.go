package routes_test

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

func TestDeviceChallengeAndVerifyHappyPath(t *testing.T) {
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

	challengeHandler := routes.DeviceChallenge(auth)
	req := httptest.NewRequest(http.MethodPost, "/devices/"+dev.ID+"/challenge", nil)
	req.SetPathValue("deviceID", dev.ID)
	rec := httptest.NewRecorder()
	challengeHandler(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("challenge status = %d, body %s", rec.Code, rec.Body.String())
	}
	var challenge mwanachamaauth.Challenge
	decodeBody(t, rec, &challenge)
	if challenge.MemberID != "" {
		t.Fatalf("challenge response leaked member_id: %+v", challenge)
	}
	if challenge.Secret == "" {
		t.Fatalf("challenge response missing secret nonce")
	}

	minter := &fakeMinter{}
	verifyHandler := routes.DeviceVerify(auth, minter, 30*24*time.Hour, false)
	sig := ed25519.Sign(priv, []byte(challenge.Secret))
	body := strings.NewReader(`{"challenge_id":"` + challenge.ID + `","signature":"` +
		base64.StdEncoding.EncodeToString(sig) + `"}`)
	req = httptest.NewRequest(http.MethodPost, "/devices/"+dev.ID+"/verify", body)
	req.SetPathValue("deviceID", dev.ID)
	rec = httptest.NewRecorder()
	verifyHandler(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("verify status = %d, body %s", rec.Code, rec.Body.String())
	}
	var session routes.Session
	decodeBody(t, rec, &session)
	if session.ActorID != "m1" || session.Token == "" {
		t.Fatalf("unexpected session: %+v", session)
	}
	if minter.minted != 1 {
		t.Fatalf("expected exactly one mint, got %d", minter.minted)
	}
}

// TestDeviceVerifyRefusesWrongSignature is the DEV-1185 regression this
// route exists to close: an unsigned or wrongly-signed proof must never mint
// a session.
func TestDeviceVerifyRefusesWrongSignature(t *testing.T) {
	db, tables := newTestDB(t)
	auth := mwanachamaauth.NewAuthStore(db, tables)
	ctx := context.Background()

	pub, _, err := ed25519.GenerateKey(nil)
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
		Kind: mwanachamaauth.KindDevice, DeviceID: dev.ID, MemberID: dev.MemberID, Secret: "nonce",
	})
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}

	minter := &fakeMinter{}
	handler := routes.DeviceVerify(auth, minter, time.Hour, false)
	body := strings.NewReader(`{"challenge_id":"` + challenge.ID + `","signature":"x"}`)
	req := httptest.NewRequest(http.MethodPost, "/devices/"+dev.ID+"/verify", body)
	req.SetPathValue("deviceID", dev.ID)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for a bogus signature, got %d: %s", rec.Code, rec.Body.String())
	}
	if minter.minted != 0 {
		t.Fatalf("a session was minted for an invalid proof")
	}
}
