package gormstore

import (
	"time"

	"gorm.io/gorm"

	"github.com/aosanya/mwanachama-backend-auth/models"
)

// ChallengeRow is the GORM row for a [models.Challenge]. Schema: archived
// migration 000007_auth_verification. DeviceID, Phone and MemberID are all
// nullable — a challenge is a discriminated union over device/phone/recovery
// kinds and only the fields relevant to its own kind are ever set.
type ChallengeRow struct {
	ID        string `gorm:"primaryKey"`
	Kind      string
	DeviceID  *string `gorm:"column:device_id"`
	Phone     *string `gorm:"index"`
	Secret    string
	MemberID  *string   `gorm:"column:member_id"`
	ExpiresAt time.Time `gorm:"column:expires_at"`
	Consumed  bool
}

func (ChallengeRow) TableName() string { return "auth_challenge" }

// BeforeCreate mints a challenge id (keyed off auth_challenge_seq, "chal"
// prefix) when the caller left one unset, and defaults ExpiresAt to five
// minutes out — the same default the gateway's original memory and Postgres
// stores both applied when a caller left it zero.
func (r *ChallengeRow) BeforeCreate(tx *gorm.DB) error {
	if r.ID == "" {
		id, err := mintID(tx, "chal", "auth_challenge_seq")
		if err != nil {
			return err
		}
		r.ID = id
	}
	if r.ExpiresAt.IsZero() {
		r.ExpiresAt = time.Now().UTC().Add(5 * time.Minute)
	}
	return nil
}

// ChallengeToRow converts a domain Challenge to its row shape.
func ChallengeToRow(c models.Challenge) ChallengeRow {
	return ChallengeRow{
		ID:        c.ID,
		Kind:      string(c.Kind),
		DeviceID:  StringToNullable(c.DeviceID),
		Phone:     StringToNullable(c.Phone),
		Secret:    c.Secret,
		MemberID:  StringToNullable(c.MemberID),
		ExpiresAt: c.ExpiresAt,
		Consumed:  c.Consumed,
	}
}

// ChallengeFromRow converts a row back to the domain Challenge.
func ChallengeFromRow(r ChallengeRow) models.Challenge {
	return models.Challenge{
		ID:        r.ID,
		Kind:      models.ChallengeKind(r.Kind),
		DeviceID:  NullableToString(r.DeviceID),
		Phone:     NullableToString(r.Phone),
		Secret:    r.Secret,
		MemberID:  NullableToString(r.MemberID),
		ExpiresAt: r.ExpiresAt,
		Consumed:  r.Consumed,
	}
}
