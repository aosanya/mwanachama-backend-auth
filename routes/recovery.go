// recovery.go — HTTP routes over the recovery credential, ported from
// mwanachama-backend-api-gateway's auth_recovery_handlers.go. Both halves are
// pure auth plus (for verify) the SessionMinter seam — see doc.go.
package routes

import (
	"net/http"
	"time"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
)

// RecoveryRequest handles POST /recovery/request.
//
// echoChallengeCode is the gateway's own dev-only EchoChallengeCode flag —
// writing the OTP-equivalent secret into the response body — threaded
// through as a plain bool, zero value (false) meaning off, the same polarity
// DeviceVerify's allowUnsignedProof uses. Without a real transport to a
// member's recovery phrase holder, a rig that needs to see the secret in
// tests says so explicitly; a deployment that says nothing keeps it to
// itself, matching the gateway's own "fails closed" reasoning for this flag.
func RecoveryRequest(auth mwanachamaauth.AuthRepository, echoChallengeCode bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			MemberID string `json:"member_id"`
		}
		if err := readJSON(r, &in); err != nil || in.MemberID == "" {
			writeErr(w, http.StatusBadRequest, "member_id required")
			return
		}
		c, err := auth.CreateChallenge(r.Context(), mwanachamaauth.Challenge{
			Kind: mwanachamaauth.KindRecovery, MemberID: in.MemberID,
			Secret: randHex(8),
		})
		if err != nil {
			writeAuthErr(w, err)
			return
		}
		// DEV-1267 · the response is written out by hand rather than via
		// Challenge.Public(): Public() only blanks MemberID and leaves
		// Secret, and a recovery code is not a nonce meant to be public the
		// way the device door's is.
		body := map[string]any{
			"id":         c.ID,
			"kind":       c.Kind,
			"expires_at": c.ExpiresAt,
		}
		if echoChallengeCode {
			body["secret"] = c.Secret
		}
		writeJSON(w, http.StatusCreated, body)
	}
}

// RecoveryVerify handles POST /recovery/verify.
//
// **Before the session is minted, deliberately** — device.md:89's G96, both
// branches: a successful recovery ejects every other handset the member
// holds, stamping `recovery`, BEFORE the new session is minted. If the sweep
// fails, the caller gets no session and the old handsets keep working — a
// state a member can retry out of, rather than a live session sitting beside
// a possibly-compromised handset.
func RecoveryVerify(auth mwanachamaauth.AuthRepository, minter SessionMinter, ttl time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var in struct {
			ChallengeID string `json:"challenge_id"`
			Secret      string `json:"secret"`
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		c, err := auth.ConsumeChallenge(r.Context(), in.ChallengeID, time.Now())
		if err != nil {
			writeErr(w, http.StatusUnauthorized, err.Error())
			return
		}
		if c.Kind != mwanachamaauth.KindRecovery || c.Secret != in.Secret {
			writeErr(w, http.StatusUnauthorized, "secret mismatch")
			return
		}
		// keepID is empty: this door mints no device of its own, so every
		// device the member had is ejected.
		if _, err := auth.SignOutOtherDevices(r.Context(), c.MemberID, "", time.Now().UTC()); err != nil {
			writeAuthErr(w, err)
			return
		}
		s, err := minter.Mint(r.Context(), c.MemberID, "", ttl)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "could not mint a session")
			return
		}
		writeJSON(w, http.StatusCreated, s)
	}
}

// RecoveryRoutes is RecoveryRequest + RecoveryVerify, addressed under
// /recovery/request and /recovery/verify.
func RecoveryRoutes(auth mwanachamaauth.AuthRepository, minter SessionMinter, ttl time.Duration, echoChallengeCode bool) []Route {
	return []Route{
		{Method: http.MethodPost, Path: "/recovery/request", Handler: RecoveryRequest(auth, echoChallengeCode)},
		{Method: http.MethodPost, Path: "/recovery/verify", Handler: RecoveryVerify(auth, minter, ttl)},
	}
}
