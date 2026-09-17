package routes_test

// Coverage test, not a bug pin: confirms OperatorSignIn's lock-out is
// enumeration-resistant end to end through the real HTTP surface — the
// property this repo's own CLAUDE.md and the gateway's both call out by
// name ("Every failed sign-in answers one sentence and failures are counted
// against addresses holding no credential, because otherwise the lock-out
// itself becomes an enumeration oracle"). Driven by a real http.Client over
// a real httptest.NewServer + http.ServeMux built from OperatorSignInRoutes,
// never a direct handler call, per the fleet integration-test-sweep method.
//
// Investigated as part of DEV-1698's lockout probe: this property HOLDS —
// see TestOperatorSignIn_NoCredentialAddressIsIndistinguishableFromWrongPassword
// below. DEV-1698 itself is a separate, narrower finding (the reset policy,
// not this symmetry) — see models/dev1698_lockout_reset_test.go.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
	"github.com/aosanya/mwanachama-backend-auth/routes"
)

func postSignIn(t *testing.T, client *http.Client, url, email, password string) (int, map[string]any) {
	t.Helper()
	body := fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)
	resp, err := client.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// TestOperatorSignIn_NoCredentialAddressIsIndistinguishableFromWrongPassword
// drives a real credential (wrong password) and a never-registered address
// side by side through the real HTTP surface across the whole lock-out
// window, and asserts status code, tries_left and the refusal sentence are
// identical at every step — including the 429 lock-out itself.
func TestOperatorSignIn_NoCredentialAddressIsIndistinguishableFromWrongPassword(t *testing.T) {
	db, tables := newTestDB(t)
	ops := mwanachamaauth.NewOperatorStore(db, tables)
	ctx := context.Background()

	hash, err := mwanachamaauth.Hash("correct horse battery staple 12")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if _, err := ops.Create(ctx, mwanachamaauth.OperatorCredential{MemberID: "m1", Email: "real@example.org"}, hash); err != nil {
		t.Fatalf("Create: %v", err)
	}

	mux := http.NewServeMux()
	for _, rt := range routes.OperatorSignInRoutes(ops, &fakeMinter{}, time.Hour) {
		mux.HandleFunc(rt.Pattern(""), rt.Handler)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	client := srv.Client()
	url := srv.URL + "/operator/signin"

	for i := 1; i <= mwanachamaauth.OperatorLockAfter+1; i++ {
		codeReal, bodyReal := postSignIn(t, client, url, "real@example.org", "totally-wrong-password")
		codeFake, bodyFake := postSignIn(t, client, url, "nobody-ever-registered@example.org", "totally-wrong-password")

		if codeReal != codeFake {
			t.Errorf("attempt %d: status differs — real=%d fake=%d", i, codeReal, codeFake)
		}
		if fmt.Sprint(bodyReal["tries_left"]) != fmt.Sprint(bodyFake["tries_left"]) {
			t.Errorf("attempt %d: tries_left differs — real=%v fake=%v", i, bodyReal["tries_left"], bodyFake["tries_left"])
		}
		if fmt.Sprint(bodyReal["error"]) != fmt.Sprint(bodyFake["error"]) {
			t.Errorf("attempt %d: error message differs — real=%v fake=%v", i, bodyReal["error"], bodyFake["error"])
		}
		if i == mwanachamaauth.OperatorLockAfter {
			if codeReal != http.StatusTooManyRequests {
				t.Errorf("attempt %d: want both addresses locked (429), got real=%d fake=%d", i, codeReal, codeFake)
			}
		}
	}
}
