package mwanachamaauth

// AuthStore's device methods, ported from
// mwanachama-backend-api-gateway's internal/store/{memory,postgres}
// auth_store.go / auth_signout_store.go. Challenge and phone-attempt methods
// live in challenge_impl.go and phoneattempt_impl.go respectively — the same
// three-way split comm's DM domain uses for the same reason (one GORM store
// now does the job the gateway's two backend-specific implementations used
// to split across, and the result stays under [[file-length-limit]] only by
// splitting further than the original single auth.Repository interface).

import (
	"context"
	"sort"
	"time"

	"gorm.io/gorm"

	"github.com/aosanya/mwanachama-backend-auth/gormstore"
	"github.com/aosanya/mwanachama-backend-auth/models"
)

// AuthStore is the GORM-backed implementation of [models.AuthRepository].
type AuthStore struct {
	db     *gorm.DB
	tables TableNames
}

// NewAuthStore constructs a store over db, scoped to the tables named by t.
func NewAuthStore(db *gorm.DB, t TableNames) *AuthStore {
	return &AuthStore{db: db, tables: t}
}

// RegisterDevice stores a device, minting an id + created_at when empty.
func (s *AuthStore) RegisterDevice(ctx context.Context, d models.Device) (models.Device, error) {
	row := gormstore.DeviceToRow(d)
	if err := s.db.WithContext(ctx).Table(s.tables.AuthDevices).Create(&row).Error; err != nil {
		return models.Device{}, classify(err)
	}
	return gormstore.DeviceFromRow(row), nil
}

// GetDevice returns a device by id, signed-out ones included. The caller
// decides what a signed-out device may do; the store does not hide the row,
// because a sign-out is a fact about the handset and not a deletion of it.
func (s *AuthStore) GetDevice(ctx context.Context, id string) (models.Device, error) {
	var row gormstore.DeviceRow
	err := s.db.WithContext(ctx).Table(s.tables.AuthDevices).Where("id = ?", id).First(&row).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return models.Device{}, models.ErrAuthNotFound
		}
		return models.Device{}, classify(err)
	}
	return gormstore.DeviceFromRow(row), nil
}

// SignOutDevice ends a device's life (DEV-1272) and records why (DEV-1347).
//
// Idempotent: an already signed-out device keeps its first timestamp AND its
// first reason, so a repeat call can move neither the date the handset
// stopped being trusted nor the account of what ended it. The UPDATE ...
// WHERE ... COALESCE shape mirrors the gateway's original Postgres store: one
// statement, not a read-then-write, so two racing sign-outs cannot disagree.
func (s *AuthStore) SignOutDevice(ctx context.Context, id string, at time.Time, by models.SignOutReason) (models.Device, error) {
	if by == "" {
		return models.Device{}, models.ErrAuthSignOutReasonRequired
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	table := s.tables.AuthDevices
	res := s.db.WithContext(ctx).Exec(
		"UPDATE "+table+" SET signed_out_at = COALESCE(signed_out_at, ?), "+
			"signed_out_by = COALESCE(signed_out_by, ?) WHERE id = ?",
		at, string(by), id,
	)
	if res.Error != nil {
		return models.Device{}, classify(res.Error)
	}
	if res.RowsAffected == 0 {
		return models.Device{}, models.ErrAuthNotFound
	}
	return s.GetDevice(ctx, id)
}

// SignOutOtherDevices ends every device the member holds except keepID,
// stamping SignOutByRecovery, and returns the ones this call actually ended —
// device.md:89's "sets signed_out_at and signed_out_by = 'recovery' on every
// other row for the member in the same transaction that mints the new one"
// (G96, both branches).
//
// **Not the plural of SignOutDevice, and must not be built as one.** DEV-1272's
// rule is that a device may only sign ITSELF out; this is the recovery flow's
// act. keepID may be empty: a recovery that mints no device of its own ejects
// every one of them.
func (s *AuthStore) SignOutOtherDevices(ctx context.Context, memberID, keepID string, at time.Time) ([]models.Device, error) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	var rows []gormstore.DeviceRow
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		q := tx.Table(s.tables.AuthDevices).Where("member_id = ? AND signed_out_at IS NULL", memberID)
		if keepID != "" {
			q = q.Where("id <> ?", keepID)
		}
		if err := q.Find(&rows).Error; err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		ids := make([]string, len(rows))
		for i, r := range rows {
			ids[i] = r.ID
		}
		return tx.Table(s.tables.AuthDevices).Where("id IN ?", ids).
			Updates(map[string]any{
				"signed_out_at": at,
				"signed_out_by": string(models.SignOutByRecovery),
			}).Error
	})
	if err != nil {
		return nil, classify(err)
	}
	out := make([]models.Device, 0, len(rows))
	for _, r := range rows {
		when := at
		r.SignedOutAt = &when
		by := string(models.SignOutByRecovery)
		r.SignedOutBy = &by
		out = append(out, gormstore.DeviceFromRow(r))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
