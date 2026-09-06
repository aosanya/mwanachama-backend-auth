package routes

import (
	"net/http"
	"time"

	"github.com/aosanya/mwanachama-backend-auth/models"
)

// Route is one address this package answers, relative to wherever the
// mounting process prefixes it (e.g. "/v1/auth") — enough to build one
// *http.ServeMux entry from, without the mounting process hand-spelling
// each path/method pair itself. Mirrors mwanachama-backend-actor's and
// mwanachama-backend-comm's identical Route type.
type Route struct {
	Method  string
	Path    string
	Handler http.HandlerFunc
}

// Pattern returns the http.ServeMux registration pattern for this route once
// mounted under prefix — r.Method+" "+prefix+r.Path, net/http's own
// "METHOD /path" syntax (Go 1.22+ mux patterns).
func (r Route) Pattern(prefix string) string {
	return r.Method + " " + prefix + r.Path
}

// Deps bundles every externally-supplied fact [Routes] needs to build the
// whole set at once — the four repositories plus the gateway-owned seams
// (SessionMinter, Identity, the session ttl, and the two dev-only bools) —
// so a mounting process that wants everything in one loop does not have to
// hand-spell seven constructor calls itself. A mounting process that wants
// to wrap different domains in different policy (the gateway does, today)
// calls the per-domain *Routes functions directly instead, the same choice
// actor's and comm's own Routes aggregators leave open.
type Deps struct {
	Auth         models.AuthRepository
	Operators    models.OperatorRepository
	Verification models.VerificationRepository
	PhoneSalts   models.PhoneSaltRepository

	Minter SessionMinter
	TTL    time.Duration

	Identity Identity

	// AllowUnsignedDeviceProof is DeviceVerify's dev-only bypass. False (the
	// zero value) means signatures ARE checked.
	AllowUnsignedDeviceProof bool
	// EchoChallengeCode is RecoveryRequest's dev-only "write the secret into
	// the response body" flag. False (the zero value) means it is withheld.
	EchoChallengeCode bool
}

// Routes is every address this package answers today, built from d: device
// challenge/verify, recovery request/verify, operator sign-in and credential
// management, plain verification set, and the phone-salt list — concatenated
// in the order their own *Routes functions are documented above.
func Routes(d Deps) []Route {
	out := DeviceChallengeRoutes(d.Auth)
	out = append(out, DeviceVerifyRoutes(d.Auth, d.Minter, d.TTL, d.AllowUnsignedDeviceProof)...)
	out = append(out, RecoveryRoutes(d.Auth, d.Minter, d.TTL, d.EchoChallengeCode)...)
	out = append(out, OperatorSignInRoutes(d.Operators, d.Minter, d.TTL)...)
	out = append(out, OperatorCredentialRoutes(d.Operators, d.Identity)...)
	out = append(out, VerificationRoutes(d.Verification)...)
	out = append(out, PhoneSaltRoutes(d.PhoneSalts)...)
	return out
}
