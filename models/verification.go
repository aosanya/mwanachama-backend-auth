// Ported from internal/domain/verification — a member's verification status
// (unverified / pending / verified / rejected).
package models

import (
	"context"
	"errors"
	"time"
)

// ErrVerificationNotFound is returned when no record exists for a member.
var ErrVerificationNotFound = errors.New("verification: not found")

// VerificationStatus is the current verification state for a member.
type VerificationStatus string

const (
	VerificationStatusUnverified VerificationStatus = "unverified"
	VerificationStatusPending    VerificationStatus = "pending"
	VerificationStatusVerified   VerificationStatus = "verified"
	VerificationStatusRejected   VerificationStatus = "rejected"
)

// VerificationRecord is one member's verification status snapshot. Ported
// from internal/domain/verification.Record.
//
// FullName/Phone/WorkflowID carry a self-submitted verification application:
// the identity a member offered for review, and the id that identifies that
// submission. They ride on the same record as the reviewer's Status/Note
// rather than a separate table because there is exactly one open application
// per member at a time — the fields are blank until a submission is first
// made, and an operator reviewing GET sees exactly what was submitted
// alongside the status they are about to set.
type VerificationRecord struct {
	MemberID   string             `json:"member_id"`
	Status     VerificationStatus `json:"status"`
	Note       string             `json:"note,omitempty"`
	FullName   string             `json:"full_name,omitempty"`
	Phone      string             `json:"phone,omitempty"`
	WorkflowID string             `json:"workflow_id,omitempty"`
	UpdatedAt  time.Time          `json:"updated_at"`
}

// VerificationRepository is the persistence boundary for the verification
// domain. Ported from internal/domain/verification.Repository.
type VerificationRepository interface {
	// Get returns the record for a member, synthesizing an "unverified" zero
	// record for a member with no row yet — see the gateway's original
	// verification.postgres/memory stores, whose Get this repo's own
	// VerificationStore ports unchanged. A caller may therefore Set the first
	// decision for any member id without a prior row ever existing.
	Get(ctx context.Context, memberID string) (VerificationRecord, error)
	// Set upserts a verification record.
	Set(ctx context.Context, r VerificationRecord) (VerificationRecord, error)
}
