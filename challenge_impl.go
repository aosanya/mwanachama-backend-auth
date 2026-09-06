package mwanachamaauth

// AuthStore's challenge methods — see device_impl.go's header for why this
// domain is split across three files.

import (
	"context"
	"time"

	"gorm.io/gorm"

	"github.com/aosanya/mwanachama-backend-auth/gormstore"
	"github.com/aosanya/mwanachama-backend-auth/models"
)

// CreateChallenge stores a challenge, minting id + expiry when empty.
func (s *AuthStore) CreateChallenge(ctx context.Context, c models.Challenge) (models.Challenge, error) {
	row := gormstore.ChallengeToRow(c)
	if err := s.db.WithContext(ctx).Table(s.tables.AuthChallenges).Create(&row).Error; err != nil {
		return models.Challenge{}, classify(err)
	}
	return gormstore.ChallengeFromRow(row), nil
}

// GetChallenge returns a challenge by id.
func (s *AuthStore) GetChallenge(ctx context.Context, id string) (models.Challenge, error) {
	var row gormstore.ChallengeRow
	err := s.db.WithContext(ctx).Table(s.tables.AuthChallenges).Where("id = ?", id).First(&row).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return models.Challenge{}, models.ErrAuthNotFound
		}
		return models.Challenge{}, classify(err)
	}
	return gormstore.ChallengeFromRow(row), nil
}

// ConsumeChallenge marks a challenge used, refusing missing / already-consumed
// / expired records.
//
// Deliberately a read-then-guarded-write rather than the gateway's original
// single `UPDATE ... WHERE ... expires_at > $now` statement: a raw SQL
// comparison of a bound time.Time against sqlite's text-encoded timestamp
// column does not reliably compare chronologically — the write path (GORM's
// own struct-based Create) and a hand-written comparison value do not
// provably share one text format, the same class of trap
// mwanachama-backend-comm's errors.go built flexTime to work around, one
// directory over. Expiry is therefore checked in Go, against a value GORM
// itself parsed back out of the column, which is reliable on both dialects
// this repo supports. The consumed flag still flips through a guarded
// `UPDATE ... WHERE id = ? AND consumed = false`, so two callers racing to
// consume the same still-valid challenge cannot both win — only the exact
// instant a challenge expires between the read and the write is unguarded,
// which costs nothing an attacker can use (the challenge is refused either
// way).
func (s *AuthStore) ConsumeChallenge(ctx context.Context, id string, now time.Time) (models.Challenge, error) {
	table := s.tables.AuthChallenges
	var row gormstore.ChallengeRow
	err := s.db.WithContext(ctx).Table(table).Where("id = ?", id).First(&row).Error
	if err == gorm.ErrRecordNotFound {
		return models.Challenge{}, models.ErrAuthNotFound
	}
	if err != nil {
		return models.Challenge{}, classify(err)
	}
	if row.Consumed {
		return models.Challenge{}, models.ErrAuthNotFound
	}
	if !now.Before(row.ExpiresAt) {
		return models.Challenge{}, models.ErrAuthChallengeExpired
	}

	res := s.db.WithContext(ctx).Table(table).
		Where("id = ? AND consumed = ?", id, false).
		Updates(map[string]any{"consumed": true})
	if res.Error != nil {
		return models.Challenge{}, classify(res.Error)
	}
	if res.RowsAffected == 0 {
		// Raced: consumed by another caller between our read and our write.
		return models.Challenge{}, models.ErrAuthNotFound
	}
	row.Consumed = true
	return gormstore.ChallengeFromRow(row), nil
}
