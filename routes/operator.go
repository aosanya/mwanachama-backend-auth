// operator.go — HTTP routes over the console credential, ported from
// mwanachama-backend-api-gateway's auth_operator_handlers.go. createOperatorCredential
// is NOT here (checks member.Repository.Get before minting — see doc.go);
// OperatorSignIn, ChangeOperatorPassword, DisableOperatorCredential and
// ListOperatorCredentials are pure operator (plus, for sign-in and password
// change, the SessionMinter/Identity seams).
package routes

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
	"github.com/aosanya/mwanachama-backend-auth/models"
)

// operatorLockFor is how long five consecutive wrong passwords bar an
// address — fifteen minutes, the gateway's own original constant, ported
// unchanged since it is this domain's policy rather than a gateway-composed
// seam (unlike sessionTTL, which the mounting gateway owns and must supply).
const operatorLockFor = 15 * time.Minute

// signInRefusal is the ONLY thing a failed console sign-in ever says.
//
// One sentence for every cause — no such address, wrong password, disabled
// credential, unreadable verifier — because a caller who can tell them apart
// has an account-enumeration oracle, and the addresses on an operator
// console are precisely the list of people worth phishing.
const signInRefusal = "that email address and password do not match a console sign-in"

// OperatorSignIn handles POST /operator/signin.
//
// **The wire cannot distinguish a failure's cause, and neither does this
// handler's log — there is no logger here at all.** The gateway's original
// signInFailure said "the wire cannot distinguish them and must not; an
// operator diagnosing a support call has to" and logged the cause via its
// own slog.Logger. That distinction is diagnostic-only per the gateway's own
// comment (never load-bearing for the wire's one-sentence refusal, which
// this handler still enforces byte-for-byte), so it is dropped here rather
// than threading an optional Logger interface through this package for one
// call site — simpler, and the gateway can log the same distinction itself
// around whatever wraps this route, since it already has the credential and
// the error value this handler saw.
func OperatorSignIn(ops models.OperatorRepository, minter SessionMinter, ttl time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		email := models.Normalize(in.Email)
		if email == "" || in.Password == "" {
			writeErr(w, http.StatusBadRequest, "an email address and a password are required")
			return
		}
		now := time.Now()

		// The lock-out is checked BEFORE the credential is looked up, and
		// counted against addresses that hold no credential too — otherwise
		// the absence of a lock-out becomes the enumeration oracle the
		// single refusal above exists to close.
		attempt, err := ops.Attempt(r.Context(), email)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		if attempt.Locked(now) {
			writeOperatorLocked(w, attempt, now)
			return
		}

		cred, hash, credErr := ops.Verifier(r.Context(), email)
		matched := false
		if credErr == nil {
			if ok, _ := mwanachamaauth.Verify(hash, in.Password); ok {
				matched = true
			}
		}

		if !matched {
			after, ferr := ops.RecordFailure(r.Context(), email, now, operatorLockFor)
			if ferr != nil {
				writeErr(w, http.StatusInternalServerError, "internal error")
				return
			}
			if after.Locked(now) {
				writeOperatorLocked(w, after, now)
				return
			}
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error":      signInRefusal,
				"tries_left": after.TriesLeft(),
			})
			return
		}

		if err := ops.ClearAttempts(r.Context(), email); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		s, err := minter.Mint(r.Context(), cred.MemberID, "", ttl)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "could not mint a session")
			return
		}
		writeJSON(w, http.StatusCreated, s)
	}
}

// writeOperatorLocked shapes the lock-out answer in one place. 429 rather
// than 401: the credential is not wrong, the caller has run out of tries.
func writeOperatorLocked(w http.ResponseWriter, a models.OperatorAttempt, now time.Time) {
	retry := int(a.LockedUntil.Sub(now).Seconds())
	if retry < 1 {
		retry = 1
	}
	w.Header().Set("Retry-After", fmt.Sprintf("%d", retry))
	writeJSON(w, http.StatusTooManyRequests, map[string]any{
		"error":        "too many wrong passwords — this sign-in is locked",
		"locked_until": a.LockedUntil,
		"tries_left":   0,
	})
}

// ChangeOperatorPassword handles PUT /operator/password.
//
// The current password is required even though identity already proves who
// the caller is — asking is what stops somebody who walked up to an unlocked
// screen from locking the real operator out of their own console.
func ChangeOperatorPassword(ops models.OperatorRepository, identity Identity) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			Email           string `json:"email"`
			CurrentPassword string `json:"current_password"`
			NewPassword     string `json:"new_password"`
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		email := models.Normalize(in.Email)
		cred, hash, err := ops.Verifier(r.Context(), email)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, signInRefusal)
			return
		}
		// The credential must be the caller's own, taken off identity —
		// never off the body.
		if cred.MemberID != identity.CallerID(r) {
			writeErr(w, http.StatusForbidden, "that console sign-in is not yours")
			return
		}
		ok, err := mwanachamaauth.Verify(hash, in.CurrentPassword)
		if err != nil || !ok {
			writeErr(w, http.StatusUnauthorized, signInRefusal)
			return
		}
		newHash, err := mwanachamaauth.Hash(in.NewPassword)
		if errors.Is(err, mwanachamaauth.ErrPasswordTooShort) {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		if err := ops.SetPassword(r.Context(), cred.ID, newHash); err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// DisableOperatorCredential handles DELETE /operator/credentials/{credentialID}.
func DisableOperatorCredential(ops models.OperatorRepository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := ops.Disable(r.Context(), r.PathValue("credentialID"))
		if errors.Is(err, models.ErrOperatorNotFound) {
			writeErr(w, http.StatusNotFound, err.Error())
			return
		}
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// ListOperatorCredentials handles GET /members/{memberID}/operator-credentials.
func ListOperatorCredentials(ops models.OperatorRepository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		out, err := ops.ListForMember(r.Context(), r.PathValue("memberID"))
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "internal error")
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}

// OperatorSignInRoutes is OperatorSignIn alone, addressed under
// /operator/signin. Returned separately from OperatorCredentialRoutes
// because sign-in carries no caller-identity gate at all (it is how a
// session comes into being) while every credential-management route needs
// one wrapped around it.
func OperatorSignInRoutes(ops models.OperatorRepository, minter SessionMinter, ttl time.Duration) []Route {
	return []Route{
		{Method: http.MethodPost, Path: "/operator/signin", Handler: OperatorSignIn(ops, minter, ttl)},
	}
}

// OperatorCredentialRoutes is the three credential-management operations —
// change-password, disable, list — addressed under /operator/password,
// /operator/credentials/{credentialID} and
// /members/{memberID}/operator-credentials. createOperatorCredential is
// deliberately not here; see doc.go.
func OperatorCredentialRoutes(ops models.OperatorRepository, identity Identity) []Route {
	return []Route{
		{Method: http.MethodPut, Path: "/operator/password", Handler: ChangeOperatorPassword(ops, identity)},
		{Method: http.MethodDelete, Path: "/operator/credentials/{credentialID}", Handler: DisableOperatorCredential(ops)},
		{Method: http.MethodGet, Path: "/members/{memberID}/operator-credentials", Handler: ListOperatorCredentials(ops)},
	}
}
