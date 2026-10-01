package mwanachamaauth

import (
	"context"
	"sort"
	"time"

	"gorm.io/gorm"

	"github.com/aosanya/mwanachama-backend-shared/spec"

	"github.com/aosanya/mwanachama-backend-auth/models"
)

type AuthStore struct {
	st *store
	db *gorm.DB
}

func NewAuthStore(db *gorm.DB, s *spec.Spec) (*AuthStore, error) {
	st, err := newStore(db, s, carriers())
	if err != nil {
		return nil, err
	}
	return &AuthStore{st: st, db: db}, nil
}

func (s *AuthStore) RegisterDevice(ctx context.Context, d models.Device) (models.Device, error) {
	if d.ID == "" {
		id, err := mintID(s.db, "device", seqDevice)
		if err != nil {
			return models.Device{}, err
		}
		d.ID = id
	}
	if d.CreatedAt.IsZero() {
		d.CreatedAt = time.Now().UTC()
	}
	if err := check(s.st.Object(roleDevice), d); err != nil {
		return models.Device{}, err
	}
	if err := s.st.Insert(ctx, roleDevice, d); err != nil {
		return models.Device{}, classify(err)
	}
	return d, nil
}

func (s *AuthStore) GetDevice(ctx context.Context, id string) (models.Device, error) {
	var out models.Device
	q := s.st.Query(ctx, roleDevice).Where(columnName("ID")+" = ?", id)
	if err := s.st.Take(q, roleDevice, &out, models.ErrAuthNotFound); err != nil {
		if err == models.ErrAuthNotFound {
			return models.Device{}, err
		}
		return models.Device{}, classify(err)
	}
	return out, nil
}

func (s *AuthStore) SignOutDevice(ctx context.Context, id string, at time.Time, by models.SignOutReason) (models.Device, error) {
	if by == "" {
		return models.Device{}, models.ErrAuthSignOutReasonRequired
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	table := s.st.Table(roleDevice)
	signedOutAt := columnName("SignedOutAt")
	signedOutBy := columnName("SignedOutBy")
	res := s.db.WithContext(ctx).Exec(
		"UPDATE "+table+" SET "+signedOutAt+" = COALESCE(NULLIF("+signedOutAt+", ''), ?), "+
			signedOutBy+" = COALESCE(NULLIF("+signedOutBy+", ''), ?) WHERE "+columnName("ID")+" = ?",
		storedTime(at), string(by), id,
	)
	if res.Error != nil {
		return models.Device{}, classify(res.Error)
	}
	if res.RowsAffected == 0 {
		return models.Device{}, models.ErrAuthNotFound
	}
	return s.GetDevice(ctx, id)
}

func (s *AuthStore) SignOutOtherDevices(ctx context.Context, subjectID, keepID string, at time.Time) ([]models.Device, error) {
	if at.IsZero() {
		at = time.Now().UTC()
	}
	var live []models.Device
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		q := tx.Table(s.st.Table(roleDevice)).
			Where(columnName("SubjectID")+" = ?", subjectID).
			Where(liveDeviceClause())
		if keepID != "" {
			q = q.Where(columnName("ID")+" <> ?", keepID)
		}
		found, err := listOf[models.Device](s.st, q, roleDevice)
		if err != nil {
			return err
		}
		live = found
		if len(live) == 0 {
			return nil
		}
		ids := make([]string, len(live))
		for i, d := range live {
			ids[i] = d.ID
		}
		return tx.Table(s.st.Table(roleDevice)).
			Where(columnName("ID")+" IN ?", ids).
			Updates(map[string]any{
				columnName("SignedOutAt"): storedTime(at),
				columnName("SignedOutBy"): string(models.SignOutByRecovery),
			}).Error
	})
	if err != nil {
		return nil, classify(err)
	}
	out := make([]models.Device, 0, len(live))
	for _, d := range live {
		when := at
		d.SignedOutAt = &when
		d.SignedOutBy = models.SignOutByRecovery
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
