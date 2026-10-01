package mwanachamaauth

import (
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/aosanya/mwanachama-backend-shared/spec"
	"github.com/aosanya/mwanachama-backend-shared/specstore"

	"github.com/aosanya/mwanachama-backend-auth/models"
)

const (
	roleDevice            = "device"
	roleChallenge         = "challenge"
	rolePhoneAttempt      = "phone_attempt"
	rolePhoneBinding      = "phone_binding"
	roleCredential        = "credential"
	roleCredentialAttempt = "credential_attempt"
	roleVerification      = "verification"
	roleSalt              = "salt"
)

type store = specstore.Store

var errNoRow = errors.New("auth: no such row")

func newStore(db *gorm.DB, s *spec.Spec, carriers map[string]any) (*store, error) {
	return specstore.New(db, s, carriers)
}

func columnName(field string) string { return specstore.ColumnName(field) }

func encode(o spec.Object, v any) (map[string]any, error) { return specstore.Encode(o, v) }

func decode(o spec.Object, row map[string]any, out any) error {
	return specstore.Decode(o, row, out)
}

func listOf[T any](st *store, q *gorm.DB, role string) ([]T, error) {
	return specstore.List[T](st, q, role)
}

func storedTime(t time.Time) string { return t.UTC().Format(specstore.TimeLayout) }

func unsetText(column string) string {
	return "(" + column + " IS NULL OR " + column + " = '')"
}

func liveDeviceClause() string { return unsetText(columnName("SignedOutAt")) }

type phoneBinding struct {
	Phone     string
	SubjectID string
}

type credentialRecord struct {
	ID           string
	SubjectID    string
	Email        string
	PasswordHash string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DisabledAt   *time.Time
}

func (c credentialRecord) credential() models.OperatorCredential {
	return models.OperatorCredential{
		ID:         c.ID,
		SubjectID:  c.SubjectID,
		Email:      c.Email,
		CreatedAt:  c.CreatedAt,
		UpdatedAt:  c.UpdatedAt,
		DisabledAt: c.DisabledAt,
	}
}

type saltRecord struct {
	ID        int
	Secret    []byte
	SetAt     time.Time
	SetBy     string
	RetiredAt *time.Time
	RetiredBy string
}

func (s saltRecord) salt() models.Salt {
	return models.Salt{
		ID:        s.ID,
		SetAt:     s.SetAt,
		SetBy:     s.SetBy,
		RetiredAt: s.RetiredAt,
		RetiredBy: s.RetiredBy,
	}
}

func carriers() map[string]any {
	return map[string]any{
		roleDevice:            models.Device{},
		roleChallenge:         models.Challenge{},
		rolePhoneAttempt:      models.PhoneAttempt{},
		rolePhoneBinding:      phoneBinding{},
		roleCredential:        credentialRecord{},
		roleCredentialAttempt: models.OperatorAttempt{},
		roleVerification:      models.VerificationRecord{},
		roleSalt:              saltRecord{},
	}
}
