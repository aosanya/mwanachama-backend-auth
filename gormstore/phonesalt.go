package gormstore

import (
	"time"

	"github.com/aosanya/mwanachama-backend-auth/models"
)

// SaltRow is the GORM row for a [models.Salt]. Schema: archived migration
// 000018_phone_salt.
//
// **Secret must be an exported field for GORM to map the column at all, and
// this is the only statement in this repo's conversion code that may ever
// read it.** Every function below that builds a [models.Salt] — SaltFromRow
// included — leaves it untouched, because models.Salt has no secret field at
// all (see models/phonesalt.go's package doc: phone-salt.md's select rule is
// "nobody, for secret"). The one place this repo reads Secret back out of a
// row is phonesalt_impl.go's Hash method, which returns a digest and never
// the key itself. A future conversion function that copies Secret onto
// anything JSON-encodable or logged has broken that guarantee.
type SaltRow struct {
	ID        int `gorm:"primaryKey;autoIncrement:false"`
	Secret    []byte
	SetAt     time.Time  `gorm:"column:set_at"`
	SetBy     *string    `gorm:"column:set_by"`
	RetiredAt *time.Time `gorm:"column:retired_at"`
	RetiredBy *string    `gorm:"column:retired_by"`
}

func (SaltRow) TableName() string { return "phone_salt" }

// SaltFromRow converts a row to its public [models.Salt] projection —
// deliberately never copying Secret. See the type's own doc comment.
func SaltFromRow(r SaltRow) models.Salt {
	return models.Salt{
		ID:        r.ID,
		SetAt:     r.SetAt,
		SetBy:     NullableToString(r.SetBy),
		RetiredAt: r.RetiredAt,
		RetiredBy: NullableToString(r.RetiredBy),
	}
}
