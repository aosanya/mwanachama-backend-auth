package gormstore

import (
	"time"

	"github.com/aosanya/mwanachama-backend-auth/models"
)

// PhoneAttemptRow is the GORM row for a [models.PhoneAttempt]. Schema:
// archived migration 000020_auth_phone_attempt. Keyed on the phone number
// itself — no id-minting, since the number IS the identity this row tracks,
// per DEV-1264's reasoning in models.PhoneAttempt's own doc comment.
type PhoneAttemptRow struct {
	Phone          string     `gorm:"primaryKey"`
	FailedAttempts int        `gorm:"column:failed_attempts"`
	LockedUntil    *time.Time `gorm:"column:locked_until"`
	UpdatedAt      time.Time  `gorm:"column:updated_at"`
}

func (PhoneAttemptRow) TableName() string { return "auth_phone_attempt" }

// PhoneAttemptToRow converts a domain PhoneAttempt to its row shape.
func PhoneAttemptToRow(a models.PhoneAttempt, now time.Time) PhoneAttemptRow {
	var locked *time.Time
	if !a.LockedUntil.IsZero() {
		t := a.LockedUntil
		locked = &t
	}
	return PhoneAttemptRow{
		Phone:          a.Phone,
		FailedAttempts: a.Failed,
		LockedUntil:    locked,
		UpdatedAt:      now,
	}
}

// PhoneAttemptFromRow converts a row back to the domain PhoneAttempt.
func PhoneAttemptFromRow(r PhoneAttemptRow) models.PhoneAttempt {
	a := models.PhoneAttempt{Phone: r.Phone, Failed: r.FailedAttempts}
	if r.LockedUntil != nil {
		a.LockedUntil = *r.LockedUntil
	}
	return a
}

// AuthPhoneRow is the GORM row backing [models.AuthRepository.MemberIDForPhone]
// — the phone-number-to-member binding. Schema: archived migration
// 000007_auth_verification's auth_phone table. Keyed on the phone number;
// there is no domain type of its own for this row, since the whole of what it
// carries is the one mapping MemberIDForPhone reads and writes.
type AuthPhoneRow struct {
	Phone    string `gorm:"primaryKey"`
	MemberID string `gorm:"column:member_id"`
}

func (AuthPhoneRow) TableName() string { return "auth_phone" }
