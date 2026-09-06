package gormstore

import (
	"time"

	"github.com/aosanya/mwanachama-backend-auth/models"
)

// VerificationRow is the GORM row for a [models.VerificationRecord]. Schema:
// archived migrations 000007_auth_verification (base columns) and
// 000009_verification_submission (FullName/Phone/WorkflowID). Keyed on the
// member id — no id-minting, since there is exactly one verification record
// per member.
type VerificationRow struct {
	MemberID   string `gorm:"primaryKey;column:member_id"`
	Status     string
	Note       string
	FullName   string `gorm:"column:full_name"`
	Phone      string
	WorkflowID string    `gorm:"column:workflow_id"`
	UpdatedAt  time.Time `gorm:"column:updated_at"`
}

func (VerificationRow) TableName() string { return "verification" }

// VerificationToRow converts a domain VerificationRecord to its row shape.
func VerificationToRow(r models.VerificationRecord) VerificationRow {
	return VerificationRow{
		MemberID:   r.MemberID,
		Status:     string(r.Status),
		Note:       r.Note,
		FullName:   r.FullName,
		Phone:      r.Phone,
		WorkflowID: r.WorkflowID,
		UpdatedAt:  r.UpdatedAt,
	}
}

// VerificationFromRow converts a row back to the domain VerificationRecord.
func VerificationFromRow(r VerificationRow) models.VerificationRecord {
	return models.VerificationRecord{
		MemberID:   r.MemberID,
		Status:     models.VerificationStatus(r.Status),
		Note:       r.Note,
		FullName:   r.FullName,
		Phone:      r.Phone,
		WorkflowID: r.WorkflowID,
		UpdatedAt:  r.UpdatedAt,
	}
}
