package gormstore

import (
	"time"

	"gorm.io/gorm"

	"github.com/aosanya/mwanachama-backend-auth/models"
)

// DeviceRow is the GORM row for a [models.Device]. Schema:
// mwanachama-backend-api-gateway's archived migrations 000007_auth_verification
// (base columns) and 000027_auth_device_sign_out /
// 000029_auth_device_signed_out_by (the two sign-out columns).
//
// SignedOutBy is a nullable string here even though [models.SignOutReason] is
// itself a defined string type, for the same reason [models.Device.SignedOutBy]
// is a plain string rather than a pointer: the domain distinguishes "no
// reason" (empty string) from a reason, and GORM maps a Go zero value to a SQL
// empty string rather than NULL unless the column is a pointer.
type DeviceRow struct {
	ID          string `gorm:"primaryKey"`
	MemberID    string `gorm:"column:member_id;index"`
	PublicKey   string `gorm:"column:public_key"`
	Name        string
	CreatedAt   time.Time  `gorm:"column:created_at"`
	SignedOutAt *time.Time `gorm:"column:signed_out_at"`
	SignedOutBy *string    `gorm:"column:signed_out_by"`
}

// TableName pins DeviceRow to no default GORM-pluralized name; the actual
// table is chosen per call by db.Table(t.AuthDevices) in Migrate and by every
// store method, so this only matters if a caller uses DeviceRow directly
// without going through db.Table first.
func (DeviceRow) TableName() string { return "auth_device" }

// BeforeCreate mints a device id (keyed off auth_device_seq, "device" prefix)
// when the caller left one unset — the archived Postgres schema's own
// `DEFAULT ('device-' || nextval('auth_device_seq'))`.
func (r *DeviceRow) BeforeCreate(tx *gorm.DB) error {
	if r.ID == "" {
		id, err := mintID(tx, "device", "auth_device_seq")
		if err != nil {
			return err
		}
		r.ID = id
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	return nil
}

// DeviceToRow converts a domain Device to its row shape.
func DeviceToRow(d models.Device) DeviceRow {
	var signedOutBy *string
	if d.SignedOutBy != "" {
		s := string(d.SignedOutBy)
		signedOutBy = &s
	}
	return DeviceRow{
		ID:          d.ID,
		MemberID:    d.MemberID,
		PublicKey:   d.PublicKey,
		Name:        d.Name,
		CreatedAt:   d.CreatedAt,
		SignedOutAt: d.SignedOutAt,
		SignedOutBy: signedOutBy,
	}
}

// DeviceFromRow converts a row back to the domain Device.
func DeviceFromRow(r DeviceRow) models.Device {
	var signedOutBy models.SignOutReason
	if r.SignedOutBy != nil {
		signedOutBy = models.SignOutReason(*r.SignedOutBy)
	}
	return models.Device{
		ID:          r.ID,
		MemberID:    r.MemberID,
		PublicKey:   r.PublicKey,
		Name:        r.Name,
		CreatedAt:   r.CreatedAt,
		SignedOutAt: r.SignedOutAt,
		SignedOutBy: signedOutBy,
	}
}
