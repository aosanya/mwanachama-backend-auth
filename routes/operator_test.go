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

func TestOperatorSignInHappyPath(t *testing.T) {
	db, tables := newTestDB(t)
	ops := mwanachamaauth.NewOperatorStore(db, tables)
	ctx := context.Background()

	hash, err := mwanachamaauth.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if _, err := ops.Create(ctx, mwanachamaauth.OperatorCredential{MemberID: "m1", Email: "op@example.org"}, hash); err != nil {
		t.Fatalf("Create: %v", err)
	}

	minter := &fakeMinter{}
	handler := routes.OperatorSignIn(ops, minter, time.Hour)
	req := httptest.NewRequest(http.MethodPost, "/operator/signin",
		strings.NewReader(`{"email":"op@example.org","password":"correct horse battery staple"}`))
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var session routes.Session
	decodeBody(t, rec, &session)
	if session.ActorID != "m1" {
		t.Fatalf("unexpected session: %+v", session)
	}
}

// TestOperatorSignInLocksOutAfterFiveFailures pins the whole
// enumeration-resistant refusal shape: locked out with 429, one sentence.
func TestOperatorSignInLocksOutAfterFiveFailures(t *testing.T) {
	db, tables := newTestDB(t)
	ops := mwanachamaauth.NewOperatorStore(db, tables)
	minter := &fakeMinter{}
	handler := routes.OperatorSignIn(ops, minter, time.Hour)

	var lastCode int
	for i := 0; i < mwanachamaauth.OperatorLockAfter; i++ {
		req := httptest.NewRequest(http.MethodPost, "/operator/signin",
			strings.NewReader(`{"email":"nobody@example.org","password":"whatever-wrong-1"}`))
		rec := httptest.NewRecorder()
		handler(rec, req)
		lastCode = rec.Code
	}
	if lastCode != http.StatusTooManyRequests {
		t.Fatalf("after %d failures expected 429, got %d", mwanachamaauth.OperatorLockAfter, lastCode)
	}

	// One more attempt, even with nothing else wrong, is still locked.
	req := httptest.NewRequest(http.MethodPost, "/operator/signin",
		strings.NewReader(`{"email":"nobody@example.org","password":"whatever-wrong-1"}`))
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected the lock-out to persist, got %d", rec.Code)
	}
	if minter.minted != 0 {
		t.Fatalf("a session was minted for a locked-out address")
	}
}

func TestChangeOperatorPasswordForbidsAnotherCallersCredential(t *testing.T) {
	db, tables := newTestDB(t)
	ops := mwanachamaauth.NewOperatorStore(db, tables)
	ctx := context.Background()
	hash, _ := mwanachamaauth.Hash("correct horse battery staple")
	if _, err := ops.Create(ctx, mwanachamaauth.OperatorCredential{MemberID: "m1", Email: "owner@example.org"}, hash); err != nil {
		t.Fatalf("Create: %v", err)
	}

	handler := routes.ChangeOperatorPassword(ops, fakeIdentity("someone-else"))
	req := httptest.NewRequest(http.MethodPut, "/operator/password", strings.NewReader(
		`{"email":"owner@example.org","current_password":"correct horse battery staple","new_password":"a new long enough password"}`))
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when the caller does not own the credential, got %d: %s", rec.Code, rec.Body.String())
	}

	// The rightful owner succeeds.
	handler = routes.ChangeOperatorPassword(ops, fakeIdentity("m1"))
	req = httptest.NewRequest(http.MethodPut, "/operator/password", strings.NewReader(
		`{"email":"owner@example.org","current_password":"correct horse battery staple","new_password":"a new long enough password"}`))
	rec = httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for the rightful owner, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestDisableAndListOperatorCredentials(t *testing.T) {
	db, tables := newTestDB(t)
	ops := mwanachamaauth.NewOperatorStore(db, tables)
	ctx := context.Background()
	hash, _ := mwanachamaauth.Hash("correct horse battery staple")
	cred, err := ops.Create(ctx, mwanachamaauth.OperatorCredential{MemberID: "m1", Email: "d@example.org"}, hash)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	disable := routes.DisableOperatorCredential(ops)
	req := httptest.NewRequest(http.MethodDelete, "/operator/credentials/"+cred.ID, nil)
	req.SetPathValue("credentialID", cred.ID)
	rec := httptest.NewRecorder()
	disable(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("disable status = %d, body %s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest(http.MethodDelete, "/operator/credentials/nope", nil)
	req.SetPathValue("credentialID", "nope")
	rec = httptest.NewRecorder()
	disable(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("disable(unknown) status = %d, want 404", rec.Code)
	}

	list := routes.ListOperatorCredentials(ops)
	req = httptest.NewRequest(http.MethodGet, "/members/m1/operator-credentials", nil)
	req.SetPathValue("memberID", "m1")
	rec = httptest.NewRecorder()
	list(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d", rec.Code)
	}
	var out []mwanachamaauth.OperatorCredential
	decodeBody(t, rec, &out)
	if len(out) != 1 || out[0].ID != cred.ID {
		t.Fatalf("expected the disabled credential still listed, got %+v", out)
	}
}
