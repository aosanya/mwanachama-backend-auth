package mwanachamaauth

// VerificationStore, ported from mwanachama-backend-api-gateway's
// internal/store/{memory,postgres} verification_store.go.

import (
	"context"
	"time"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"github.com/aosanya/mwanachama-backend-auth/gormstore"
	"github.com/aosanya/mwanachama-backend-auth/models"
)

// VerificationStore is the GORM-backed implementation of
// [models.VerificationRepository].
type VerificationStore struct {
	db     *gorm.DB
	tables TableNames
}

// NewVerificationStore constructs a store over db, scoped to the tables named
// by t.
func NewVerificationStore(db *gorm.DB, t TableNames) *VerificationStore {
	return &VerificationStore{db: db, tables: t}
}

// Get returns the record for a member, synthesizing an "unverified" record
// stamped with now() when the member has no row — matching the gateway's
// original stores' identical default so a caller never needs to special-case
// a member who has not yet applied.
func (s *VerificationStore) Get(ctx context.Context, memberID string) (models.VerificationRecord, error) {
	var row gormstore.VerificationRow
	err := s.db.WithContext(ctx).Table(s.tables.Verifications).Where("member_id = ?", memberID).First(&row).Error
	if err == gorm.ErrRecordNotFound {
		return models.VerificationRecord{
			MemberID:  memberID,
			Status:    models.VerificationStatusUnverified,
			UpdatedAt: time.Now().UTC(),
		}, nil
	}
	if err != nil {
		return models.VerificationRecord{}, classify(err)
	}
	return gormstore.VerificationFromRow(row), nil
}

// Set upserts a verification record.
//
// DEV-1173 · updated_at is stamped by this store unconditionally, on both the
// insert and the conflict update. It is the only clock this record carries —
// it *is* the answer to "when was this member verified" — and a Set is by
// definition a change happening now, so there is no case where the caller's
// value is the right one.
func (s *VerificationStore) Set(ctx context.Context, r models.VerificationRecord) (models.VerificationRecord, error) {
	r.UpdatedAt = time.Now().UTC()
	row := gormstore.VerificationToRow(r)
	err := s.db.WithContext(ctx).Table(s.tables.Verifications).
		Clauses(clause.OnConflict{
			Columns: []clause.Column{{Name: "member_id"}},
			DoUpdates: clause.AssignmentColumns([]string{
				"status", "note", "full_name", "phone", "workflow_id", "updated_at",
			}),
		}).Create(&row).Error
	if err != nil {
		return models.VerificationRecord{}, classify(err)
	}
	return gormstore.VerificationFromRow(row), nil
}

var _ models.VerificationRepository = (*VerificationStore)(nil)
