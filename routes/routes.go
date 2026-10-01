package routes

import (
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/aosanya/mwanachama-backend-shared/dispatch"
	"github.com/aosanya/mwanachama-backend-shared/httpwire"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
)

type Route = httpwire.Route

type Deps struct {
	Auth         mwanachamaauth.AuthRepository
	Operators    mwanachamaauth.OperatorRepository
	Verification mwanachamaauth.VerificationRepository
	PhoneSalts   mwanachamaauth.PhoneSaltRepository

	Minter SessionMinter
	TTL    time.Duration

	Identity Identity

	AllowUnsignedDeviceProof bool
	EchoChallengeCode        bool
}

var AnonymousActions = []string{
	"auth.device.challenge",
	"auth.device.verify",
	"auth.recovery.request",
	"auth.recovery.verify",
	"auth.operator.signin",
}

func handlers(d Deps) map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		"auth.device.challenge":            DeviceChallenge(d.Auth),
		"auth.device.verify":               DeviceVerify(d.Auth, d.Minter, d.TTL, d.AllowUnsignedDeviceProof),
		"auth.recovery.request":            RecoveryRequest(d.Auth, d.EchoChallengeCode),
		"auth.recovery.verify":             RecoveryVerify(d.Auth, d.Minter, d.TTL),
		"auth.operator.signin":             OperatorSignIn(d.Operators, d.Minter, d.TTL),
		"auth.operator.password_change":    ChangeOperatorPassword(d.Operators, d.Identity),
		"auth.operator_credential.disable": DisableOperatorCredential(d.Operators),
		"auth.operator_credential.list":    ListOperatorCredentials(d.Operators),
		"auth.verification.set":            SetVerification(d.Verification),
		"auth.phone_salt.list":             ListPhoneSalts(d.PhoneSalts),
	}
}

func Build(d Deps) ([]Route, error) {
	s, err := mwanachamaauth.OperationSpec()
	if err != nil {
		return nil, err
	}
	bound := handlers(d)

	var problems []string
	var out []Route
	for _, op := range dispatch.Handled(s) {
		h, ok := bound[op.Action]
		if !ok {
			problems = append(problems, fmt.Sprintf("the action %q is declared but no handler is bound to it", op.Action))
			continue
		}
		out = append(out, Route{Method: op.Method, Path: s.Base + op.Path, Action: op.Action, Handler: h})
	}

	declared := map[string]bool{}
	for _, op := range dispatch.Handled(s) {
		declared[op.Action] = true
	}
	for action := range bound {
		if !declared[action] {
			problems = append(problems, fmt.Sprintf("a handler is bound to %q, which the declaration does not name", action))
		}
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, fmt.Errorf("routes: %v", problems)
	}
	return out, nil
}

func Split(all []Route) (anonymous, gated []Route) {
	open := map[string]bool{}
	for _, a := range AnonymousActions {
		open[a] = true
	}
	for _, r := range all {
		if open[r.Action] {
			anonymous = append(anonymous, r)
			continue
		}
		gated = append(gated, r)
	}
	return anonymous, gated
}

func Routes(d Deps) []Route {
	out, err := Build(d)
	if err != nil {
		panic(err)
	}
	return out
}
