package mwanachamaauth

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm/clause"

	"github.com/aosanya/mwanachama-backend-auth/models"
)

func (s *AuthStore) PhoneAttempt(ctx context.Context, phone string) (models.PhoneAttempt, error) {
	var out models.PhoneAttempt
	q := s.st.Query(ctx, rolePhoneAttempt).Where(columnName("Phone")+" = ?", phone)
	err := s.st.Take(q, rolePhoneAttempt, &out, errNoRow)
	if errors.Is(err, errNoRow) {
		return models.PhoneAttempt{Phone: phone}, nil
	}
	if err != nil {
		return models.PhoneAttempt{}, classify(err)
	}
	return out, nil
}

func (s *AuthStore) RecordPhoneFailure(ctx context.Context, phone string, now time.Time, lockFor time.Duration) (models.PhoneAttempt, error) {
	current, err := s.PhoneAttempt(ctx, phone)
	if err != nil {
		return models.PhoneAttempt{}, err
	}
	next := current.Fail(now, lockFor)
	next.Phone = phone
	next.UpdatedAt = now

	row, err := encode(s.st.Object(rolePhoneAttempt), next)
	if err != nil {
		return models.PhoneAttempt{}, err
	}
	err = s.st.Query(ctx, rolePhoneAttempt).
		Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: columnName("Phone")}},
			DoUpdates: clause.AssignmentColumns([]string{
				columnName("Failed"), columnName("LockedUntil"), columnName("UpdatedAt"),
			}),
		}).Create(row).Error
	if err != nil {
		return models.PhoneAttempt{}, classify(err)
	}
	return next, nil
}

func (s *AuthStore) ClearPhoneAttempts(ctx context.Context, phone string) error {
	err := s.st.Query(ctx, rolePhoneAttempt).
		Where(columnName("Phone")+" = ?", phone).
		Delete(nil).Error
	if err != nil {
		return classify(err)
	}
	return nil
}

func (s *AuthStore) SubjectIDForPhone(ctx context.Context, phone string, mintSubject func() string) (string, error) {
	held, err := s.phoneBinding(ctx, phone)
	if err == nil {
		return held.SubjectID, nil
	}
	if !errors.Is(err, errNoRow) {
		return "", classify(err)
	}

	minted := mintSubject()
	if minted == "" {
		return "", nil
	}

	row, err := encode(s.st.Object(rolePhoneBinding), phoneBinding{Phone: phone, SubjectID: minted})
	if err != nil {
		return "", err
	}
	err = s.st.Query(ctx, rolePhoneBinding).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: columnName("Phone")}},
			DoNothing: true,
		}).Create(row).Error
	if err != nil {
		return "", classify(err)
	}
	out, err := s.phoneBinding(ctx, phone)
	if err != nil {
		return "", classify(err)
	}
	return out.SubjectID, nil
}

func (s *AuthStore) phoneBinding(ctx context.Context, phone string) (phoneBinding, error) {
	var out phoneBinding
	q := s.st.Query(ctx, rolePhoneBinding).Where(columnName("Phone")+" = ?", phone)
	if err := s.st.Take(q, rolePhoneBinding, &out, errNoRow); err != nil {
		return phoneBinding{}, err
	}
	return out, nil
}

var _ models.AuthRepository = (*AuthStore)(nil)
