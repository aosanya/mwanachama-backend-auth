package mwanachamaauth

// AuthStore's phone-attempt and phone-to-member methods — see
// device_impl.go's header for why this domain is split across three files.

import (
	"context"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/aosanya/mwanachama-backend-auth/gormstore"
	"github.com/aosanya/mwanachama-backend-auth/models"
)

// PhoneAttempt reads a number's consecutive-wrong-code state (DEV-1264). A
// number nobody has failed against returns the zero PhoneAttempt.
func (s *AuthStore) PhoneAttempt(ctx context.Context, phone string) (models.PhoneAttempt, error) {
	var row gormstore.PhoneAttemptRow
	err := s.db.WithContext(ctx).Table(s.tables.AuthPhoneAttempts).Where("phone = ?", phone).First(&row).Error
	if err == gorm.ErrRecordNotFound {
		return models.PhoneAttempt{Phone: phone}, nil
	}
	if err != nil {
		return models.PhoneAttempt{}, classify(err)
	}
	return gormstore.PhoneAttemptFromRow(row), nil
}

// RecordPhoneFailure counts one wrong code against a number.
//
// The read-modify-write is deliberate rather than an atomic increment: the
// policy (when a lock starts, and that an expired lock resets the count
// first) lives in models.PhoneAttempt.Fail so this store cannot drift from
// what the domain type itself defines.
func (s *AuthStore) RecordPhoneFailure(ctx context.Context, phone string, now time.Time, lockFor time.Duration) (models.PhoneAttempt, error) {
	current, err := s.PhoneAttempt(ctx, phone)
	if err != nil {
		return models.PhoneAttempt{}, err
	}
	next := current.Fail(now, lockFor)
	row := gormstore.PhoneAttemptToRow(next, now)
	err = s.db.WithContext(ctx).Table(s.tables.AuthPhoneAttempts).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "phone"}},
			DoUpdates: clause.AssignmentColumns([]string{"failed_attempts", "locked_until", "updated_at"}),
		}).Create(&row).Error
	if err != nil {
		return models.PhoneAttempt{}, classify(err)
	}
	return next, nil
}

// ClearPhoneAttempts forgets a number's failures, which a correct code does.
func (s *AuthStore) ClearPhoneAttempts(ctx context.Context, phone string) error {
	err := s.db.WithContext(ctx).Table(s.tables.AuthPhoneAttempts).Where("phone = ?", phone).
		Delete(&gormstore.PhoneAttemptRow{}).Error
	if err != nil {
		return classify(err)
	}
	return nil
}

// MemberIDForPhone returns the member bound to a phone, minting via
// mintMember the first time. The insert is guarded with an ON CONFLICT DO
// NOTHING so a race resolves cleanly — the losing caller reads the winning
// caller's id back, mirroring the gateway's original Postgres store.
func (s *AuthStore) MemberIDForPhone(ctx context.Context, phone string, mintMember func() string) (string, error) {
	var existing gormstore.AuthPhoneRow
	err := s.db.WithContext(ctx).Table(s.tables.AuthPhones).Where("phone = ?", phone).First(&existing).Error
	if err == nil {
		return existing.MemberID, nil
	}
	if err != gorm.ErrRecordNotFound {
		return "", classify(err)
	}

	minted := mintMember()
	// DEV-1263 · "" means the caller asked without minting (the challenge
	// door). Write nothing: a row carrying an empty string would read as
	// bound on every later call while pointing at no member at all.
	if minted == "" {
		return "", nil
	}

	row := gormstore.AuthPhoneRow{Phone: phone, MemberID: minted}
	err = s.db.WithContext(ctx).Table(s.tables.AuthPhones).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "phone"}},
			DoNothing: true,
		}).Create(&row).Error
	if err != nil {
		return "", classify(err)
	}
	var out gormstore.AuthPhoneRow
	if err := s.db.WithContext(ctx).Table(s.tables.AuthPhones).Where("phone = ?", phone).First(&out).Error; err != nil {
		return "", classify(err)
	}
	return out.MemberID, nil
}

var _ models.AuthRepository = (*AuthStore)(nil)
