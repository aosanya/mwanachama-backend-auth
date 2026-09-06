package mwanachamaauth

// PhoneSaltStore, ported from mwanachama-backend-api-gateway's
// internal/store/{memory,postgres} phonesalt_store.go.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"time"

	"gorm.io/gorm"

	"github.com/aosanya/mwanachama-backend-auth/gormstore"
	"github.com/aosanya/mwanachama-backend-auth/models"
)

// PhoneSaltStore is the GORM-backed implementation of
// [models.PhoneSaltRepository].
type PhoneSaltStore struct {
	db     *gorm.DB
	tables TableNames
}

// NewPhoneSaltStore constructs a store over db, scoped to the tables named by
// t.
func NewPhoneSaltStore(db *gorm.DB, t TableNames) *PhoneSaltStore {
	return &PhoneSaltStore{db: db, tables: t}
}

// liveSaltSecret is the one place in this repo an exported struct field
// carries the raw key back out of the database — used by Hash below and
// nowhere else, and never returned from any method on PhoneSaltStore.
type liveSaltSecret struct {
	ID     int
	Secret []byte
}

// Hash computes HMAC-SHA256 of phone under the live salt (G16).
//
// **This is the only statement in this repo that selects the secret
// column.** It reads the live salt only, so a retired key cannot be reached
// through this path at all. phone is used verbatim; this store normalizes
// nothing (the gateway's own DSN-1479 decision, see models/phonesalt.go).
func (s *PhoneSaltStore) Hash(ctx context.Context, phone string) ([]byte, int, error) {
	var row liveSaltSecret
	err := s.db.WithContext(ctx).Table(s.tables.PhoneSalts).
		Select("id, secret").Where("retired_at IS NULL").First(&row).Error
	if err == gorm.ErrRecordNotFound {
		return nil, 0, models.ErrPhoneSaltNotFound
	}
	if err != nil {
		return nil, 0, classify(err)
	}
	mac := hmac.New(sha256.New, row.Secret)
	mac.Write([]byte(phone))
	digest := mac.Sum(nil)
	// Zero the key's backing array before it is garbage. Not a strong
	// guarantee — the driver may have copied it — but the copy this function
	// controls is the one it is responsible for.
	for i := range row.Secret {
		row.Secret[i] = 0
	}
	return digest, row.ID, nil
}

// Live returns the salt hashes are currently computed under, without its
// secret.
func (s *PhoneSaltStore) Live(ctx context.Context) (models.Salt, error) {
	var row gormstore.SaltRow
	err := s.db.WithContext(ctx).Table(s.tables.PhoneSalts).
		Where("retired_at IS NULL").First(&row).Error
	if err == gorm.ErrRecordNotFound {
		return models.Salt{}, models.ErrPhoneSaltNotFound
	}
	if err != nil {
		return models.Salt{}, classify(err)
	}
	return gormstore.SaltFromRow(row), nil
}

// List returns every salt, newest first.
func (s *PhoneSaltStore) List(ctx context.Context) ([]models.Salt, error) {
	var rows []gormstore.SaltRow
	err := s.db.WithContext(ctx).Table(s.tables.PhoneSalts).Order("id DESC").Find(&rows).Error
	if err != nil {
		return nil, classify(err)
	}
	out := make([]models.Salt, 0, len(rows))
	for _, r := range rows {
		out = append(out, gormstore.SaltFromRow(r))
	}
	return out, nil
}

// Provision writes a salt. ErrPhoneSaltAlreadyLive if one is already live —
// enforced at the database by the phone_salt_one_live partial unique index
// (see gormstore.Migrate), which a duplicate id also collides with.
func (s *PhoneSaltStore) Provision(ctx context.Context, id int, secret []byte, setBy string) (models.Salt, error) {
	// Copy the key: a caller that reuses or zeroes its buffer must not be
	// able to change what this plane hashes under after the fact.
	key := make([]byte, len(secret))
	copy(key, secret)
	row := gormstore.SaltRow{
		ID:     id,
		Secret: key,
		SetAt:  time.Now().UTC(),
		SetBy:  gormstore.StringToNullable(setBy),
	}
	err := s.db.WithContext(ctx).Table(s.tables.PhoneSalts).Create(&row).Error
	if err != nil {
		mapped := classify(err)
		if errors.Is(mapped, ErrConflict) {
			return models.Salt{}, models.ErrPhoneSaltAlreadyLive
		}
		return models.Salt{}, mapped
	}
	return gormstore.SaltFromRow(row), nil
}

// Retire stamps retired_at and retired_by together — the only write the
// schema's phone_salt_retired_pair CHECK permits.
func (s *PhoneSaltStore) Retire(ctx context.Context, id int, retiredBy string) (models.Salt, error) {
	if retiredBy == "" {
		// Refused before the statement, matching the gateway's original
		// stores: Postgres would refuse it too (phone_salt_retired_pair),
		// but as a CHECK violation, which classify maps to a reference error
		// rather than this specific sentinel.
		return models.Salt{}, models.ErrPhoneSaltNoActor
	}
	table := s.tables.PhoneSalts
	res := s.db.WithContext(ctx).Exec(
		"UPDATE "+table+" SET retired_at = ?, retired_by = ? WHERE id = ? AND retired_at IS NULL",
		time.Now().UTC(), retiredBy, id,
	)
	if res.Error != nil {
		return models.Salt{}, classify(res.Error)
	}
	if res.RowsAffected == 0 {
		// No row matched: either the id is unknown or it is already retired.
		// Told apart with a second read rather than guessed, because
		// "already retired" is the answer a rotation needs and "no such
		// salt" is the answer a typo needs.
		var count int64
		if err := s.db.WithContext(ctx).Table(table).Where("id = ?", id).Count(&count).Error; err != nil {
			return models.Salt{}, classify(err)
		}
		if count > 0 {
			return models.Salt{}, models.ErrPhoneSaltRetired
		}
		return models.Salt{}, models.ErrPhoneSaltNotFound
	}
	var row gormstore.SaltRow
	if err := s.db.WithContext(ctx).Table(table).Where("id = ?", id).First(&row).Error; err != nil {
		return models.Salt{}, classify(err)
	}
	return gormstore.SaltFromRow(row), nil
}

var _ models.PhoneSaltRepository = (*PhoneSaltStore)(nil)
