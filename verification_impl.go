package mwanachamaauth

import (
	"context"
	"errors"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/aosanya/mwanachama-backend-shared/spec"

	"github.com/aosanya/mwanachama-backend-auth/models"
)

type VerificationStore struct {
	st *store
	db *gorm.DB
}

func NewVerificationStore(db *gorm.DB, s *spec.Spec) (*VerificationStore, error) {
	st, err := newStore(db, s, carriers())
	if err != nil {
		return nil, err
	}
	return &VerificationStore{st: st, db: db}, nil
}

func (s *VerificationStore) Get(ctx context.Context, subjectID string) (models.VerificationRecord, error) {
	var out models.VerificationRecord
	q := s.st.Query(ctx, roleVerification).Where(columnName("SubjectID")+" = ?", subjectID)
	err := s.st.Take(q, roleVerification, &out, errNoRow)
	if errors.Is(err, errNoRow) {
		return models.VerificationRecord{
			SubjectID: subjectID,
			Status:    models.VerificationStatusUnverified,
			UpdatedAt: time.Now().UTC(),
		}, nil
	}
	if err != nil {
		return models.VerificationRecord{}, classify(err)
	}
	return out, nil
}

func (s *VerificationStore) Set(ctx context.Context, r models.VerificationRecord) (models.VerificationRecord, error) {
	r.UpdatedAt = time.Now().UTC()
	row, err := encode(s.st.Object(roleVerification), r)
	if err != nil {
		return models.VerificationRecord{}, err
	}
	err = s.st.Query(ctx, roleVerification).
		Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: columnName("SubjectID")}},
			DoUpdates: clause.AssignmentColumns([]string{
				columnName("Status"), columnName("Note"), columnName("FullName"),
				columnName("Phone"), columnName("WorkflowID"), columnName("UpdatedAt"),
			}),
		}).Create(row).Error
	if err != nil {
		return models.VerificationRecord{}, classify(err)
	}
	return r, nil
}

var _ models.VerificationRepository = (*VerificationStore)(nil)
