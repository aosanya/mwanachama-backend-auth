package routes_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
	"github.com/aosanya/mwanachama-backend-auth/routes"
)

func TestListPhoneSaltsEmptyBeforeProvisioning(t *testing.T) {
	db, tables := newTestDB(t)
	salts := mwanachamaauth.NewPhoneSaltStore(db, tables)

	handler := routes.ListPhoneSalts(salts)
	req := httptest.NewRequest(http.MethodGet, "/phone-salts", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Salts []map[string]any `json:"salts"`
	}
	decodeBody(t, rec, &out)
	if len(out.Salts) != 0 {
		t.Fatalf("expected an empty list before provisioning, got %+v", out.Salts)
	}
}

func TestListPhoneSaltsNeverCarriesASecretField(t *testing.T) {
	db, tables := newTestDB(t)
	salts := mwanachamaauth.NewPhoneSaltStore(db, tables)
	if _, err := salts.Provision(context.Background(), 1, []byte("org-key"), "member-1"); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	handler := routes.ListPhoneSalts(salts)
	req := httptest.NewRequest(http.MethodGet, "/phone-salts", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "org-key") {
		t.Fatalf("the phone salt list response leaked the secret: %s", rec.Body.String())
	}
	var out struct {
		Salts []map[string]any `json:"salts"`
	}
	decodeBody(t, rec, &out)
	if len(out.Salts) != 1 {
		t.Fatalf("expected one salt, got %+v", out.Salts)
	}
	for _, forbidden := range []string{"secret", "key", "hmac_key"} {
		if _, ok := out.Salts[0][forbidden]; ok {
			t.Fatalf("phone salt view carries a %q field", forbidden)
		}
	}
}
