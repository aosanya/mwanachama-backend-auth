package gormstore

import (
	"time"

	"gorm.io/gorm"

	"github.com/aosanya/mwanachama-backend-auth/models"
)

// CredentialRow is the GORM row for a [models.OperatorCredential]. Schema:
// archived migration 000048_operator_credential.
//
// PasswordHash must be an exported field for GORM to map the column at all,
// but [CredentialFromRow] never copies it onto a [models.OperatorCredential]
// — that domain type has no hash field, on purpose (see models/operator.go).
// The only code path that reads this field is operator_impl.go's Verifier,
// which is this repo's mirror of the gateway's own "one query in the package
// that selects password_hash" discipline.
type CredentialRow struct {
	ID           string     `gorm:"primaryKey"`
	MemberID     string     `gorm:"column:member_id;index"`
	Email        string     `gorm:"uniqueIndex:operator_credential_email_idx"`
	PasswordHash string     `gorm:"column:password_hash"`
	CreatedAt    time.Time  `gorm:"column:created_at"`
	UpdatedAt    time.Time  `gorm:"column:updated_at"`
	DisabledAt   *time.Time `gorm:"column:disabled_at"`
}

func (CredentialRow) TableName() string { return "operator_credential" }

// BeforeCreate mints a credential id (keyed off operator_credential_seq,
// "opcred" prefix) when the caller left one unset.
func (r *CredentialRow) BeforeCreate(tx *gorm.DB) error {
	if r.ID == "" {
		id, err := mintID(tx, "opcred", "operator_credential_seq")
		if err != nil {
			return err
		}
		r.ID = id
	}
	now := time.Now().UTC()
	if r.CreatedAt.IsZero() {
		r.CreatedAt = now
	}
	if r.UpdatedAt.IsZero() {
		r.UpdatedAt = now
	}
	return nil
}

// CredentialToRow converts a domain OperatorCredential and its verifier hash
// to row shape.
func CredentialToRow(c models.OperatorCredential, hash string) CredentialRow {
	return CredentialRow{
		ID:           c.ID,
		MemberID:     c.MemberID,
		Email:        c.Email,
		PasswordHash: hash,
		CreatedAt:    c.CreatedAt,
		UpdatedAt:    c.UpdatedAt,
		DisabledAt:   c.DisabledAt,
	}
}

// CredentialFromRow converts a row back to the domain OperatorCredential —
// deliberately never copying PasswordHash. See the type's own doc comment.
func CredentialFromRow(r CredentialRow) models.OperatorCredential {
	return models.OperatorCredential{
		ID:         r.ID,
		MemberID:   r.MemberID,
		Email:      r.Email,
		CreatedAt:  r.CreatedAt,
		UpdatedAt:  r.UpdatedAt,
		DisabledAt: r.DisabledAt,
	}
}

// OperatorAttemptRow is the GORM row for a [models.OperatorAttempt]. Schema:
// archived migration 000048_operator_credential. Keyed on the email address
// itself — no id-minting — including, deliberately, addresses that hold no
// credential at all: an attacker guessing at addresses that do not exist must
// be counted the same way, or the absence of a lock-out becomes the
// enumeration oracle the one-sentence sign-in refusal exists to close.
type OperatorAttemptRow struct {
	Email       string `gorm:"primaryKey"`
	Failed      int
	LockedUntil *time.Time `gorm:"column:locked_until"`
}

func (OperatorAttemptRow) TableName() string { return "operator_attempt" }

// OperatorAttemptToRow converts a domain OperatorAttempt to its row shape.
func OperatorAttemptToRow(a models.OperatorAttempt) OperatorAttemptRow {
	var locked *time.Time
	if !a.LockedUntil.IsZero() {
		t := a.LockedUntil
		locked = &t
	}
	return OperatorAttemptRow{Email: a.Email, Failed: a.Failed, LockedUntil: locked}
}

// OperatorAttemptFromRow converts a row back to the domain OperatorAttempt.
func OperatorAttemptFromRow(r OperatorAttemptRow) models.OperatorAttempt {
	a := models.OperatorAttempt{Email: r.Email, Failed: r.Failed}
	if r.LockedUntil != nil {
		a.LockedUntil = *r.LockedUntil
	}
	return a
}
