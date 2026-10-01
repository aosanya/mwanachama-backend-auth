package mwanachamaauth

import (
	"context"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/aosanya/mwanachama-backend-shared/spec"

	"github.com/aosanya/mwanachama-backend-auth/models"
)

type OperatorStore struct {
	st *store
	db *gorm.DB
}

func NewOperatorStore(db *gorm.DB, s *spec.Spec) (*OperatorStore, error) {
	st, err := newStore(db, s, carriers())
	if err != nil {
		return nil, err
	}
	return &OperatorStore{st: st, db: db}, nil
}

func (s *OperatorStore) Create(ctx context.Context, c models.OperatorCredential, hash string) (models.OperatorCredential, error) {
	if c.ID == "" {
		id, err := mintID(s.db, "opcred", seqCredential)
		if err != nil {
			return models.OperatorCredential{}, err
		}
		c.ID = id
	}
	now := time.Now().UTC()
	if c.CreatedAt.IsZero() {
		c.CreatedAt = now
	}
	if c.UpdatedAt.IsZero() {
		c.UpdatedAt = now
	}
	rec := credentialRecord{
		ID:           c.ID,
		SubjectID:    c.SubjectID,
		Email:        c.Email,
		PasswordHash: hash,
		CreatedAt:    c.CreatedAt,
		UpdatedAt:    c.UpdatedAt,
		DisabledAt:   c.DisabledAt,
	}
	if err := s.st.Insert(ctx, roleCredential, rec); err != nil {
		mapped := classify(err)
		if isConflictOn(mapped, "email") {
			return models.OperatorCredential{}, models.ErrOperatorEmailTaken
		}
		return models.OperatorCredential{}, mapped
	}
	return rec.credential(), nil
}

func (s *OperatorStore) Verifier(ctx context.Context, email string) (models.OperatorCredential, string, error) {
	rec, err := s.record(ctx, columnName("Email"), email)
	if errors.Is(err, errNoRow) {
		return models.OperatorCredential{}, "", models.ErrOperatorNotFound
	}
	if err != nil {
		return models.OperatorCredential{}, "", classify(err)
	}
	cred := rec.credential()
	if cred.Disabled() {
		return cred, rec.PasswordHash, models.ErrOperatorDisabled
	}
	return cred, rec.PasswordHash, nil
}

func (s *OperatorStore) Get(ctx context.Context, id string) (models.OperatorCredential, error) {
	rec, err := s.record(ctx, columnName("ID"), id)
	if errors.Is(err, errNoRow) {
		return models.OperatorCredential{}, models.ErrOperatorNotFound
	}
	if err != nil {
		return models.OperatorCredential{}, classify(err)
	}
	return rec.credential(), nil
}

func (s *OperatorStore) ListForSubject(ctx context.Context, subjectID string) ([]models.OperatorCredential, error) {
	q := s.st.Query(ctx, roleCredential).
		Where(columnName("SubjectID")+" = ?", subjectID).
		Order(columnName("ID"))
	recs, err := listOf[credentialRecord](s.st, q, roleCredential)
	if err != nil {
		return nil, classify(err)
	}
	out := make([]models.OperatorCredential, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.credential())
	}
	return out, nil
}

func (s *OperatorStore) SetPassword(ctx context.Context, id, hash string) error {
	res := s.st.Query(ctx, roleCredential).
		Where(columnName("ID")+" = ?", id).
		Updates(map[string]any{
			columnName("PasswordHash"): hash,
			columnName("UpdatedAt"):    storedTime(time.Now().UTC()),
		})
	if res.Error != nil {
		return classify(res.Error)
	}
	if res.RowsAffected == 0 {
		return models.ErrOperatorNotFound
	}
	return nil
}

func (s *OperatorStore) Disable(ctx context.Context, id string) error {
	now := time.Now().UTC()
	res := s.st.Query(ctx, roleCredential).
		Where(columnName("ID")+" = ?", id).
		Where(unsetText(columnName("DisabledAt"))).
		Updates(map[string]any{
			columnName("DisabledAt"): storedTime(now),
			columnName("UpdatedAt"):  storedTime(now),
		})
	if res.Error != nil {
		return classify(res.Error)
	}
	if res.RowsAffected > 0 {
		return nil
	}
	if _, err := s.Get(ctx, id); err != nil {
		return err
	}
	return nil
}

func (s *OperatorStore) record(ctx context.Context, column, value string) (credentialRecord, error) {
	var out credentialRecord
	q := s.st.Query(ctx, roleCredential).Where(column+" = ?", value)
	if err := s.st.Take(q, roleCredential, &out, errNoRow); err != nil {
		return credentialRecord{}, err
	}
	return out, nil
}

func isConflictOn(err error, needle string) bool {
	fe, ok := err.(*fieldError)
	return ok && fe.err == ErrConflict && strings.Contains(fe.field, needle)
}

var _ models.OperatorRepository = (*OperatorStore)(nil)
