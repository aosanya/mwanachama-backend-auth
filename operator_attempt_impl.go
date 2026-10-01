package mwanachamaauth

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm/clause"

	"github.com/aosanya/mwanachama-backend-auth/models"
)

func (s *OperatorStore) Attempt(ctx context.Context, email string) (models.OperatorAttempt, error) {
	var out models.OperatorAttempt
	q := s.st.Query(ctx, roleCredentialAttempt).Where(columnName("Email")+" = ?", email)
	err := s.st.Take(q, roleCredentialAttempt, &out, errNoRow)
	if errors.Is(err, errNoRow) {
		return models.OperatorAttempt{Email: email}, nil
	}
	if err != nil {
		return models.OperatorAttempt{}, classify(err)
	}
	return out, nil
}

func (s *OperatorStore) RecordFailure(ctx context.Context, email string, now time.Time, lockFor time.Duration) (models.OperatorAttempt, error) {
	current, err := s.Attempt(ctx, email)
	if err != nil {
		return models.OperatorAttempt{}, err
	}
	next := current.Fail(now, lockFor)
	next.Email = email

	row, err := encode(s.st.Object(roleCredentialAttempt), next)
	if err != nil {
		return models.OperatorAttempt{}, err
	}
	err = s.st.Query(ctx, roleCredentialAttempt).
		Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: columnName("Email")}},
			DoUpdates: clause.AssignmentColumns([]string{
				columnName("Failed"), columnName("LockedUntil"),
			}),
		}).Create(row).Error
	if err != nil {
		return models.OperatorAttempt{}, classify(err)
	}
	return next, nil
}

func (s *OperatorStore) ClearAttempts(ctx context.Context, email string) error {
	err := s.st.Query(ctx, roleCredentialAttempt).
		Where(columnName("Email")+" = ?", email).
		Delete(nil).Error
	if err != nil {
		return classify(err)
	}
	return nil
}
