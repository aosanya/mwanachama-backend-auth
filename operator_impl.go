package mwanachamaauth

// OperatorStore, ported from mwanachama-backend-api-gateway's
// internal/store/{memory,postgres} operator_store.go. Lock-out methods
// (Attempt/RecordFailure/ClearAttempts) live in operator_attempt_impl.go —
// the same split device/challenge/phone-attempt take in auth's own three
// files, for the same [[file-length-limit]] reason.

import (
	"context"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/aosanya/mwanachama-backend-auth/gormstore"
	"github.com/aosanya/mwanachama-backend-auth/models"
)

// OperatorStore is the GORM-backed implementation of
// [models.OperatorRepository].
type OperatorStore struct {
	db     *gorm.DB
	tables TableNames
}

// NewOperatorStore constructs a store over db, scoped to the tables named by
// t.
func NewOperatorStore(db *gorm.DB, t TableNames) *OperatorStore {
	return &OperatorStore{db: db, tables: t}
}

// Create stores a credential and its verifier.
func (s *OperatorStore) Create(ctx context.Context, c models.OperatorCredential, hash string) (models.OperatorCredential, error) {
	row := gormstore.CredentialToRow(c, hash)
	err := s.db.WithContext(ctx).Table(s.tables.OperatorCredentials).Create(&row).Error
	if err != nil {
		mapped := classify(err)
		if isConflictOn(mapped, "email") {
			return models.OperatorCredential{}, models.ErrOperatorEmailTaken
		}
		return models.OperatorCredential{}, mapped
	}
	return gormstore.CredentialFromRow(row), nil
}

// Verifier returns a credential and its stored hash, by address.
//
// **The one query in this package that selects password_hash.** A disabled
// credential comes back with ErrOperatorDisabled rather than being filtered
// out, so a caller can record which one it was while still answering the
// wire with the sentence a wrong password gets.
func (s *OperatorStore) Verifier(ctx context.Context, email string) (models.OperatorCredential, string, error) {
	var row gormstore.CredentialRow
	err := s.db.WithContext(ctx).Table(s.tables.OperatorCredentials).Where("email = ?", email).First(&row).Error
	if err == gorm.ErrRecordNotFound {
		return models.OperatorCredential{}, "", models.ErrOperatorNotFound
	}
	if err != nil {
		return models.OperatorCredential{}, "", classify(err)
	}
	cred := gormstore.CredentialFromRow(row)
	if cred.Disabled() {
		return cred, row.PasswordHash, models.ErrOperatorDisabled
	}
	return cred, row.PasswordHash, nil
}

// Get returns a credential by id.
func (s *OperatorStore) Get(ctx context.Context, id string) (models.OperatorCredential, error) {
	var row gormstore.CredentialRow
	err := s.db.WithContext(ctx).Table(s.tables.OperatorCredentials).Where("id = ?", id).First(&row).Error
	if err == gorm.ErrRecordNotFound {
		return models.OperatorCredential{}, models.ErrOperatorNotFound
	}
	if err != nil {
		return models.OperatorCredential{}, classify(err)
	}
	return gormstore.CredentialFromRow(row), nil
}

// ListForMember returns every credential bound to a member, disabled ones
// included — a withdrawn credential is part of the record of who could once
// sign in, and hiding it makes that record unreadable.
func (s *OperatorStore) ListForMember(ctx context.Context, memberID string) ([]models.OperatorCredential, error) {
	var rows []gormstore.CredentialRow
	err := s.db.WithContext(ctx).Table(s.tables.OperatorCredentials).
		Where("member_id = ?", memberID).Order("id").Find(&rows).Error
	if err != nil {
		return nil, classify(err)
	}
	out := make([]models.OperatorCredential, 0, len(rows))
	for _, r := range rows {
		out = append(out, gormstore.CredentialFromRow(r))
	}
	return out, nil
}

// SetPassword replaces the verifier. It does not clear the lock-out: a
// password change is not proof that the guesser has gone.
func (s *OperatorStore) SetPassword(ctx context.Context, id, hash string) error {
	res := s.db.WithContext(ctx).Table(s.tables.OperatorCredentials).Where("id = ?", id).
		Updates(map[string]any{"password_hash": hash, "updated_at": time.Now().UTC()})
	if res.Error != nil {
		return classify(res.Error)
	}
	if res.RowsAffected == 0 {
		return models.ErrOperatorNotFound
	}
	return nil
}

// Disable withdraws access in place, idempotently — `WHERE disabled_at IS
// NULL` keeps the original stamp rather than overwriting it with a later
// clock, which would lose when access actually ended.
func (s *OperatorStore) Disable(ctx context.Context, id string) error {
	now := time.Now().UTC()
	res := s.db.WithContext(ctx).Table(s.tables.OperatorCredentials).
		Where("id = ? AND disabled_at IS NULL", id).
		Updates(map[string]any{"disabled_at": now, "updated_at": now})
	if res.Error != nil {
		return classify(res.Error)
	}
	if res.RowsAffected > 0 {
		return nil
	}
	// Zero rows means either "no such credential" or "already disabled", and
	// only one of those is an error. One extra read settles it rather than
	// reporting a missing row for an act that has already happened.
	if _, err := s.Get(ctx, id); err != nil {
		return err
	}
	return nil
}

// isConflictOn reports whether err is an ErrConflict naming a field
// containing needle — used to translate a generic unique-violation into
// ErrOperatorEmailTaken without matching on every possible constraint name
// the two dialects spell differently.
func isConflictOn(err error, needle string) bool {
	fe, ok := err.(*fieldError)
	return ok && fe.err == ErrConflict && strings.Contains(fe.field, needle)
}

var _ models.OperatorRepository = (*OperatorStore)(nil)
