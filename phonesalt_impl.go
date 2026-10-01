package mwanachamaauth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/aosanya/mwanachama-backend-shared/spec"

	"github.com/aosanya/mwanachama-backend-auth/models"
)

type PhoneSaltStore struct {
	st *store
	db *gorm.DB
}

func NewPhoneSaltStore(db *gorm.DB, s *spec.Spec) (*PhoneSaltStore, error) {
	st, err := newStore(db, s, carriers())
	if err != nil {
		return nil, err
	}
	return &PhoneSaltStore{st: st, db: db}, nil
}

func (s *PhoneSaltStore) Hash(ctx context.Context, phone string) ([]byte, int, error) {
	rec, err := s.liveRecord(ctx)
	if errors.Is(err, errNoRow) {
		return nil, 0, models.ErrPhoneSaltNotFound
	}
	if err != nil {
		return nil, 0, classify(err)
	}
	mac := hmac.New(sha256.New, rec.Secret)
	mac.Write([]byte(phone))
	digest := mac.Sum(nil)
	for i := range rec.Secret {
		rec.Secret[i] = 0
	}
	return digest, rec.ID, nil
}

func (s *PhoneSaltStore) Live(ctx context.Context) (models.Salt, error) {
	rec, err := s.liveRecord(ctx)
	if errors.Is(err, errNoRow) {
		return models.Salt{}, models.ErrPhoneSaltNotFound
	}
	if err != nil {
		return models.Salt{}, classify(err)
	}
	return rec.salt(), nil
}

func (s *PhoneSaltStore) List(ctx context.Context) ([]models.Salt, error) {
	q := s.st.Query(ctx, roleSalt).Order(columnName("ID") + " DESC")
	recs, err := listOf[saltRecord](s.st, q, roleSalt)
	if err != nil {
		return nil, classify(err)
	}
	out := make([]models.Salt, 0, len(recs))
	for _, r := range recs {
		out = append(out, r.salt())
	}
	return out, nil
}

func (s *PhoneSaltStore) Provision(ctx context.Context, id int, secret []byte, setBy string) (models.Salt, error) {
	key := make([]byte, len(secret))
	copy(key, secret)
	rec := saltRecord{
		ID:     id,
		Secret: key,
		SetAt:  time.Now().UTC(),
		SetBy:  setBy,
	}
	if err := check(s.st.Object(roleSalt), rec); err != nil {
		return models.Salt{}, err
	}
	if err := s.st.Insert(ctx, roleSalt, rec); err != nil {
		mapped := classify(err)
		if errors.Is(mapped, ErrConflict) {
			return models.Salt{}, models.ErrPhoneSaltAlreadyLive
		}
		return models.Salt{}, mapped
	}
	return rec.salt(), nil
}

func (s *PhoneSaltStore) Retire(ctx context.Context, id int, retiredBy string) (models.Salt, error) {
	if retiredBy == "" {
		return models.Salt{}, models.ErrPhoneSaltNoActor
	}
	res := s.st.Query(ctx, roleSalt).
		Where(columnName("ID")+" = ?", id).
		Where(unsetText(columnName("RetiredAt"))).
		Updates(map[string]any{
			columnName("RetiredAt"): storedTime(time.Now().UTC()),
			columnName("RetiredBy"): retiredBy,
		})
	if res.Error != nil {
		return models.Salt{}, classify(res.Error)
	}
	if res.RowsAffected == 0 {
		var count int64
		if err := s.st.Query(ctx, roleSalt).Where(columnName("ID")+" = ?", id).Count(&count).Error; err != nil {
			return models.Salt{}, classify(err)
		}
		if count > 0 {
			return models.Salt{}, models.ErrPhoneSaltRetired
		}
		return models.Salt{}, models.ErrPhoneSaltNotFound
	}
	rec, err := s.record(ctx, id)
	if err != nil {
		return models.Salt{}, classify(err)
	}
	return rec.salt(), nil
}

func (s *PhoneSaltStore) liveRecord(ctx context.Context) (saltRecord, error) {
	var out saltRecord
	q := s.st.Query(ctx, roleSalt).Where(unsetText(columnName("RetiredAt")))
	if err := s.st.Take(q, roleSalt, &out, errNoRow); err != nil {
		return saltRecord{}, err
	}
	return out, nil
}

func (s *PhoneSaltStore) record(ctx context.Context, id int) (saltRecord, error) {
	var out saltRecord
	q := s.st.Query(ctx, roleSalt).Where(columnName("ID")+" = ?", id)
	if err := s.st.Take(q, roleSalt, &out, errNoRow); err != nil {
		return saltRecord{}, err
	}
	return out, nil
}

var _ models.PhoneSaltRepository = (*PhoneSaltStore)(nil)
