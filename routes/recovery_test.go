package routes_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
	"github.com/aosanya/mwanachama-backend-auth/routes"
)

func TestRecoveryRequestAndVerifyHappyPath(t *testing.T) {
	db, tables := newTestDB(t)
	auth := mwanachamaauth.NewAuthStore(db, tables)

	requestHandler := routes.RecoveryRequest(auth, true) // echo on, so the test can read the secret
	req := httptest.NewRequest(http.MethodPost, "/recovery/request", strings.NewReader(`{"member_id":"m1"}`))
	rec := httptest.NewRecorder()
	requestHandler(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("request status = %d, body %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	decodeBody(t, rec, &out)
	secret, _ := out["secret"].(string)
	id, _ := out["id"].(string)
	if secret == "" || id == "" {
		t.Fatalf("expected id + echoed secret, got %+v", out)
	}

	// Register a device for m1 first, so the sweep has something to eject.
	ctx := context.Background()
	dev, err := auth.RegisterDevice(ctx, mwanachamaauth.Device{MemberID: "m1", PublicKey: "pk"})
	if err != nil {
		t.Fatalf("RegisterDevice: %v", err)
	}

	minter := &fakeMinter{}
	verifyHandler := routes.RecoveryVerify(auth, minter, time.Hour)
	req = httptest.NewRequest(http.MethodPost, "/recovery/verify",
		strings.NewReader(`{"challenge_id":"`+id+`","secret":"`+secret+`"}`))
	rec = httptest.NewRecorder()
	verifyHandler(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("verify status = %d, body %s", rec.Code, rec.Body.String())
	}
	var session routes.Session
	decodeBody(t, rec, &session)
	if session.MemberID != "m1" {
		t.Fatalf("unexpected session: %+v", session)
	}

	swept, err := auth.GetDevice(ctx, dev.ID)
	if err != nil {
		t.Fatalf("GetDevice: %v", err)
	}
	if !swept.IsSignedOut() || swept.SignedOutBy != mwanachamaauth.SignOutByRecovery {
		t.Fatalf("expected the member's device swept by recovery, got %+v", swept)
	}
}

// TestRecoveryVerifyRefusesWrongSecret and does not mint a session.
func TestRecoveryVerifyRefusesWrongSecret(t *testing.T) {
	db, tables := newTestDB(t)
	auth := mwanachamaauth.NewAuthStore(db, tables)
	ctx := context.Background()

	c, err := auth.CreateChallenge(ctx, mwanachamaauth.Challenge{Kind: mwanachamaauth.KindRecovery, MemberID: "m1", Secret: "abc123"})
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}
	minter := &fakeMinter{}
	handler := routes.RecoveryVerify(auth, minter, time.Hour)
	req := httptest.NewRequest(http.MethodPost, "/recovery/verify",
		strings.NewReader(`{"challenge_id":"`+c.ID+`","secret":"wrong"}`))
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d: %s", rec.Code, rec.Body.String())
	}
	if minter.minted != 0 {
		t.Fatalf("a session was minted for a wrong secret")
	}
}
