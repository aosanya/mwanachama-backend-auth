// phonesalt.go — HTTP routes over the phone-salt register, ported from
// mwanachama-backend-api-gateway's phone_salt_handlers.go. There is one
// route here and there will never be a second that returns a key — see
// models.Salt's own doc comment for why a handler in this file could not
// serialise the secret if it tried.
package routes

import (
	"net/http"
	"time"

	"github.com/aosanya/mwanachama-backend-auth/models"
)

// saltView is one row of the salt register — every field an admin screen
// draws; the key is not a field. Mirrors the gateway's original saltView
// shape exactly.
type saltView struct {
	ID    int       `json:"id"`
	SetAt time.Time `json:"set_at"`

	// AgeDays is computed server-side rather than left to the client, so two
	// surfaces cannot compute the "N days" figure two different ways.
	AgeDays int `json:"age_days"`

	Live      bool       `json:"live"`
	SetBy     string     `json:"set_by,omitempty"`
	RetiredAt *time.Time `json:"retired_at,omitempty"`
	RetiredBy string     `json:"retired_by,omitempty"`
}

func newSaltView(s models.Salt, now time.Time) saltView {
	return saltView{
		ID:        s.ID,
		SetAt:     s.SetAt,
		AgeDays:   s.AgeDays(now),
		Live:      s.Live(),
		SetBy:     s.SetBy,
		RetiredAt: s.RetiredAt,
		RetiredBy: s.RetiredBy,
	}
}

// ListPhoneSalts handles GET /phone-salts — the whole register, newest
// first. An empty list is a real answer and not an error: it means
// provisioning has not written the first salt yet.
func ListPhoneSalts(salts models.PhoneSaltRepository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := salts.List(r.Context())
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		now := time.Now().UTC()
		out := make([]saltView, 0, len(list))
		for _, s := range list {
			out = append(out, newSaltView(s, now))
		}
		writeJSON(w, http.StatusOK, map[string]any{"salts": out})
	}
}

// PhoneSaltRoutes is ListPhoneSalts alone, addressed under /phone-salts.
func PhoneSaltRoutes(salts models.PhoneSaltRepository) []Route {
	return []Route{
		{Method: http.MethodGet, Path: "/phone-salts", Handler: ListPhoneSalts(salts)},
	}
}
