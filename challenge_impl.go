package mwanachamaauth

import (
	"context"
	"time"

	"github.com/aosanya/mwanachama-backend-auth/models"
)

func (s *AuthStore) CreateChallenge(ctx context.Context, c models.Challenge) (models.Challenge, error) {
	if c.ID == "" {
		id, err := mintID(s.db, "chal", seqChallenge)
		if err != nil {
			return models.Challenge{}, err
		}
		c.ID = id
	}
	if c.ExpiresAt.IsZero() {
		c.ExpiresAt = time.Now().UTC().Add(5 * time.Minute)
	}
	if err := check(s.st.Object(roleChallenge), c); err != nil {
		return models.Challenge{}, err
	}
	if err := s.st.Insert(ctx, roleChallenge, c); err != nil {
		return models.Challenge{}, classify(err)
	}
	return c, nil
}

func (s *AuthStore) GetChallenge(ctx context.Context, id string) (models.Challenge, error) {
	var out models.Challenge
	q := s.st.Query(ctx, roleChallenge).Where(columnName("ID")+" = ?", id)
	if err := s.st.Take(q, roleChallenge, &out, models.ErrAuthNotFound); err != nil {
		if err == models.ErrAuthNotFound {
			return models.Challenge{}, err
		}
		return models.Challenge{}, classify(err)
	}
	return out, nil
}

func (s *AuthStore) ConsumeChallenge(ctx context.Context, id string, now time.Time) (models.Challenge, error) {
	held, err := s.GetChallenge(ctx, id)
	if err != nil {
		return models.Challenge{}, err
	}
	if held.Consumed {
		return models.Challenge{}, models.ErrAuthNotFound
	}
	if !now.Before(held.ExpiresAt) {
		return models.Challenge{}, models.ErrAuthChallengeExpired
	}

	consumed := columnName("Consumed")
	res := s.st.Query(ctx, roleChallenge).
		Where(columnName("ID")+" = ? AND "+consumed+" = ?", id, false).
		Updates(map[string]any{consumed: true})
	if res.Error != nil {
		return models.Challenge{}, classify(res.Error)
	}
	if res.RowsAffected == 0 {
		return models.Challenge{}, models.ErrAuthNotFound
	}
	held.Consumed = true
	return held, nil
}
