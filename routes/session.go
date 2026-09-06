package routes

import (
	"context"
	"time"
)

// Session is this package's own minimal projection of the session a
// SessionMinter mints — deliberately shaped to match the gateway's existing
// session.Session wire fields exactly, so a client sees no difference when
// the gateway's own /v1/auth/... routes are cut over to this package in a
// follow-up pass.
type Session struct {
	Token     string    `json:"token"`
	MemberID  string    `json:"member_id"`
	DeviceID  string    `json:"device_id,omitempty"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// SessionMinter is the externally-supplied seam every flow that ends in a
// session (DeviceVerify, RecoveryRoutes' verify half, OperatorSignInRoutes)
// mints through, the same externally-supplied-interface pattern
// mwanachama-backend-actor's HierarchyChecker and
// mwanachama-backend-comm's Identity already establish.
//
// Session-token minting itself is explicitly gateway-owned (this repo's
// doc.go) — the gateway's own internal/session.Manager satisfies this with a
// two-line adapter in the follow-up cutover pass, not written here. This
// package must not know how a token is generated, signed or stored; it only
// needs to know that minting one takes a member id, an optional device id
// and a lifetime, and produces a Session.
type SessionMinter interface {
	Mint(ctx context.Context, memberID, deviceID string, ttl time.Duration) (Session, error)
}
