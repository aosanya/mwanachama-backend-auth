// device.go — HTTP routes over the device credential's challenge/verify pair,
// ported from mwanachama-backend-api-gateway's auth_device_handlers.go. See
// doc.go for what is and is not in scope: registerDevice and signOutDevice
// are NOT here (both compose gateway-internal domains) — only deviceChallenge
// and deviceVerify, which are pure auth plus (for verify) the SessionMinter
// seam.
package routes

import (
	"errors"
	"net/http"
	"time"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
	"github.com/aosanya/mwanachama-backend-auth/models"
)

// authStatusFor maps this repo's auth error sentinels to a status code.
func authStatusFor(err error) int {
	switch {
	case errors.Is(err, models.ErrAuthNotFound):
		return http.StatusNotFound
	case errors.Is(err, models.ErrAuthChallengeExpired),
		errors.Is(err, models.ErrAuthDeviceSignedOut),
		errors.Is(err, models.ErrAuthSignOutReasonRequired):
		return http.StatusUnauthorized
	default:
		return http.StatusInternalServerError
	}
}

func writeAuthErr(w http.ResponseWriter, err error) {
	code := authStatusFor(err)
	if code == http.StatusInternalServerError {
		writeErr(w, code, "internal error")
		return
	}
	writeErr(w, code, err.Error())
}

// DeviceChallenge handles POST {deviceID}/challenge.
//
// DEV-1217 · public by necessity — proving a device is how a session is
// first obtained, so there is no session to check — which is why the
// response is [models.Challenge.Public], never the whole record. A
// signed-out handset is answered exactly as an unknown one (DEV-1272): the
// two are one refusal on purpose, so a caller who could tell them apart
// would learn which device ids were once real.
func DeviceChallenge(auth models.AuthRepository) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("deviceID")
		dev, err := auth.GetDevice(r.Context(), id)
		if err != nil || dev.IsSignedOut() {
			writeErr(w, http.StatusNotFound, "device not found")
			return
		}
		c, err := auth.CreateChallenge(r.Context(), models.Challenge{
			Kind: models.KindDevice, DeviceID: dev.ID, MemberID: dev.MemberID,
			Secret: randHex(16),
		})
		if err != nil {
			writeAuthErr(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, c.Public())
	}
}

// DeviceVerify handles POST {deviceID}/verify.
//
// DEV-1185 · the signature is verified as Ed25519 over the challenge nonce
// against the device's registered public key, so answering a challenge
// requires the private key the device registered with. allowUnsignedProof is
// the gateway's own dev-only bypass (AllowUnsignedDeviceProof) — a plain bool
// this package accepts as the caller's answer, never defaults: passing false
// (the Go zero value) means signatures ARE checked, preserving the original's
// careful polarity. On success, mints a session via minter and writes it with
// 201 — the reward for a security act that already happened, not a bare
// acknowledgement.
func DeviceVerify(auth models.AuthRepository, minter SessionMinter, ttl time.Duration, allowUnsignedProof bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		deviceID := r.PathValue("deviceID")
		var in struct {
			ChallengeID string `json:"challenge_id"`
			Signature   string `json:"signature"`
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		dev, err := auth.GetDevice(r.Context(), deviceID)
		// DEV-1272 · enforced here too, not only at the challenge: a
		// challenge minted a moment before the sign-out must not still be
		// spendable.
		if err != nil || dev.IsSignedOut() {
			writeErr(w, http.StatusUnauthorized, "device not found")
			return
		}
		c, err := auth.ConsumeChallenge(r.Context(), in.ChallengeID, time.Now())
		if err != nil {
			writeErr(w, http.StatusUnauthorized, err.Error())
			return
		}
		if c.DeviceID != deviceID || c.Kind != models.KindDevice {
			writeErr(w, http.StatusUnauthorized, "challenge mismatch")
			return
		}
		if in.Signature == "" {
			writeErr(w, http.StatusUnauthorized, "signature required")
			return
		}
		var proofErr error
		if allowUnsignedProof {
			proofErr = nil
		} else {
			proofErr = mwanachamaauth.VerifyDeviceProof(dev.PublicKey, c.Secret, in.Signature)
		}
		if proofErr != nil {
			// One refusal for every way the proof can be wrong — see
			// mwanachamaauth.ErrKeyUnusable/ErrProofInvalid's own doc
			// comments for why the caller is never told which.
			writeErr(w, http.StatusUnauthorized, "device proof invalid")
			return
		}
		s, err := minter.Mint(r.Context(), c.MemberID, deviceID, ttl)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "could not mint a session")
			return
		}
		writeJSON(w, http.StatusCreated, s)
	}
}

// DeviceChallengeRoutes is DeviceChallenge alone, addressed under
// /devices/{deviceID}/challenge.
func DeviceChallengeRoutes(auth models.AuthRepository) []Route {
	return []Route{
		{Method: http.MethodPost, Path: "/devices/{deviceID}/challenge", Handler: DeviceChallenge(auth)},
	}
}

// DeviceVerifyRoutes is DeviceVerify alone, addressed under
// /devices/{deviceID}/verify. Returned separately from
// DeviceChallengeRoutes because the gateway wraps the two with different
// middleware (both are public, but a mounting process's rate limiting or
// logging policy may still differ between "ask for a challenge" and "spend
// one").
func DeviceVerifyRoutes(auth models.AuthRepository, minter SessionMinter, ttl time.Duration, allowUnsignedProof bool) []Route {
	return []Route{
		{Method: http.MethodPost, Path: "/devices/{deviceID}/verify", Handler: DeviceVerify(auth, minter, ttl, allowUnsignedProof)},
	}
}
