// verification.go — HTTP routes over the verification domain, ported from
// mwanachama-backend-api-gateway's verification_handlers.go.
// Only setVerification is portable — see doc.go: getVerification is gated
// by the gateway's own requireContactRead (role/chapter-scoped read
// authorization this package cannot reach) and submitVerification writes to
// the Actor row via a different domain entirely, so neither is here.
package routes

import (
	"net/http"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
)

// SetVerification handles PUT /members/{memberID}/verification — how an
// operator *decides* an application.
//
// DEV-1173 · updated_at is the record's own clock; models.VerificationStore.Set
// stamps it, so a caller cannot date their own decision.
//
// full_name, phone and workflow_id are the member's own submission and are
// read off the current record rather than taken from the wire, so a
// decision that does not resend those three fields cannot blank them — the
// same field-carry-forward the gateway's original setVerification enforced.
func SetVerification(verification mwanachamaauth.VerificationRepository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Status mwanachamaauth.VerificationStatus `json:"status"`
			Note   string                    `json:"note"`
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		memberID := r.PathValue("memberID")

		// Read-modify-write. Get synthesizes an "unverified" record for a
		// member with no row yet, so a first decision is still an ordinary
		// upsert and this cannot 404 a member who has never applied.
		cur, err := verification.Get(r.Context(), memberID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		cur.MemberID = memberID
		cur.Status = in.Status
		cur.Note = in.Note

		out, err := verification.Set(r.Context(), cur)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// VerificationRoutes is SetVerification alone, addressed under
// /members/{memberID}/verification.
func VerificationRoutes(verification mwanachamaauth.VerificationRepository) []Route {
	return []Route{
		{Method: http.MethodPut, Path: "/members/{memberID}/verification", Handler: SetVerification(verification)},
	}
}
