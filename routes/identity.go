package routes

import "net/http"

// Identity resolves the caller's own member id from an authenticated
// request — the one gateway-session concern this package cannot own itself.
// Modeled on mwanachama-backend-comm/routes/identity.go's Identity, narrowed
// to the one fact this package's own portable routes need: changeOperatorPassword
// checks `cred.MemberID != identity.CallerID(r)` before letting a caller
// change a console credential, the same way comm's DM handlers check the
// caller's own id rather than reading it off a URL path segment. Unlike
// comm's Identity, no route in this package needs the caller's device id, so
// there is no CallerDeviceID here.
//
// The mounting process's own auth middleware is what actually authenticates
// a request; this interface only asks it what it already knows.
type Identity interface {
	// CallerID returns the authenticated caller's own member id.
	CallerID(r *http.Request) string
}
