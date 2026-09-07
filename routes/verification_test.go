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

func TestSetVerificationCarriesForwardSubmittedFields(t *testing.T) {
	db, tables := newTestDB(t)
	verification := mwanachamaauth.NewVerificationStore(db, tables)
	ctx := context.Background()

	// A prior self-submission the operator's PUT must not clobber.
	if _, err := verification.Set(ctx, mwanachamaauth.VerificationRecord{
		MemberID: "m1", Status: mwanachamaauth.VerificationStatusPending,
		FullName: "Jane Member", Phone: "+254700000000", WorkflowID: "wf-1",
	}); err != nil {
		t.Fatalf("seed Set: %v", err)
	}

	handler := routes.SetVerification(verification)
	req := httptest.NewRequest(http.MethodPut, "/members/m1/verification",
		strings.NewReader(`{"status":"verified","note":"ID confirmed"}`))
	req.SetPathValue("memberID", "m1")
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var out mwanachamaauth.VerificationRecord
	decodeBody(t, rec, &out)
	if out.Status != mwanachamaauth.VerificationStatusVerified || out.Note != "ID confirmed" {
		t.Fatalf("decision not applied: %+v", out)
	}
	if out.FullName != "Jane Member" || out.Phone != "+254700000000" || out.WorkflowID != "wf-1" {
		t.Fatalf("the member's own submission was clobbered: %+v", out)
	}
}

// TestSetVerificationOpensAnUnappliedForMemberFirst pins Get's synthesized
// default: a member with no row at all still gets a clean first decision.
func TestSetVerificationOpensAnUnappliedForMemberFirst(t *testing.T) {
	db, tables := newTestDB(t)
	verification := mwanachamaauth.NewVerificationStore(db, tables)

	handler := routes.SetVerification(verification)
	req := httptest.NewRequest(http.MethodPut, "/members/never-applied/verification",
		strings.NewReader(`{"status":"rejected","note":"no ID presented"}`))
	req.SetPathValue("memberID", "never-applied")
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body.String())
	}
	var out mwanachamaauth.VerificationRecord
	decodeBody(t, rec, &out)
	if out.Status != mwanachamaauth.VerificationStatusRejected || out.FullName != "" {
		t.Fatalf("expected a clean first decision with no prior submission, got %+v", out)
	}
}
