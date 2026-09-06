package mwanachamaauth

// OperatorStore's lock-out methods — see operator_impl.go's header for why
// this domain is split across two files.

import (
	"context"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/aosanya/mwanachama-backend-auth/gormstore"
	"github.com/aosanya/mwanachama-backend-auth/models"
)

// Attempt reads the consecutive-wrong-password state for an address. An
// address nobody has failed against returns the zero OperatorAttempt.
func (s *OperatorStore) Attempt(ctx context.Context, email string) (models.OperatorAttempt, error) {
	var row gormstore.OperatorAttemptRow
	err := s.db.WithContext(ctx).Table(s.tables.OperatorAttempts).Where("email = ?", email).First(&row).Error
	if err == gorm.ErrRecordNotFound {
		return models.OperatorAttempt{Email: email}, nil
	}
	if err != nil {
		return models.OperatorAttempt{}, classify(err)
	}
	return gormstore.OperatorAttemptFromRow(row), nil
}

// RecordFailure counts one wrong password against an address, applying the
// policy via models.OperatorAttempt.Fail so this store cannot drift from what
// the domain type itself defines.
func (s *OperatorStore) RecordFailure(ctx context.Context, email string, now time.Time, lockFor time.Duration) (models.OperatorAttempt, error) {
	current, err := s.Attempt(ctx, email)
	if err != nil {
		return models.OperatorAttempt{}, err
	}
	next := current.Fail(now, lockFor)
	row := gormstore.OperatorAttemptToRow(next)
	err = s.db.WithContext(ctx).Table(s.tables.OperatorAttempts).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "email"}},
			DoUpdates: clause.AssignmentColumns([]string{"failed", "locked_until"}),
		}).Create(&row).Error
	if err != nil {
		return models.OperatorAttempt{}, classify(err)
	}
	return next, nil
}

// ClearAttempts forgets an address's failures. A correct password is the
// only caller.
func (s *OperatorStore) ClearAttempts(ctx context.Context, email string) error {
	err := s.db.WithContext(ctx).Table(s.tables.OperatorAttempts).Where("email = ?", email).
		Delete(&gormstore.OperatorAttemptRow{}).Error
	if err != nil {
		return classify(err)
	}
	return nil
}
