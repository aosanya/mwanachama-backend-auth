package mwanachamaauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"gorm.io/gorm"

	"github.com/aosanya/mwanachama-backend-shared/spec"
	"github.com/aosanya/mwanachama-backend-shared/specstore"

	"github.com/aosanya/mwanachama-backend-auth/models"
)

const roleSession = "session"

const RoleSession = roleSession

type (
	SessionRepository = models.SessionRepository
	SessionRecord     = models.SessionRecord
	SessionStart      = models.SessionStart
)

var (
	ErrSessionNotFound = models.ErrSessionNotFound
	ErrSessionInUse    = models.ErrSessionInUse
	ErrSessionInvalid  = models.ErrSessionInvalid
)

type sessionRow struct {
	ID          string
	SubjectID   string
	TokenDigest string
	Device      string
	StartedAt   time.Time
	LastUsedAt  time.Time
	ExpiresAt   time.Time
	EndedAt     *time.Time
}

func (r sessionRow) record() models.SessionRecord {
	return models.SessionRecord{
		ID:         r.ID,
		SubjectID:  r.SubjectID,
		Device:     r.Device,
		StartedAt:  r.StartedAt,
		LastUsedAt: r.LastUsedAt,
		ExpiresAt:  r.ExpiresAt,
		EndedAt:    r.EndedAt,
	}
}

func sessionCarriers() map[string]any {
	return map[string]any{roleSession: sessionRow{}}
}

type SessionStore struct {
	st *store
}

func NewSessionStore(db *gorm.DB, s *spec.Spec) (*SessionStore, error) {
	st, err := newStore(db, s, sessionCarriers())
	if err != nil {
		return nil, err
	}
	return &SessionStore{st: st}, nil
}

func tokenDigest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *SessionStore) Start(ctx context.Context, in models.SessionStart) (models.SessionRecord, error) {
	at := in.At
	if at.IsZero() {
		at = time.Now()
	}
	at = at.UTC()
	if strings.TrimSpace(in.SubjectID) == "" || in.Token == "" || !in.ExpiresAt.After(at) {
		return models.SessionRecord{}, models.ErrSessionInvalid
	}
	row := sessionRow{
		ID:          "session-" + specstore.NewID(),
		SubjectID:   in.SubjectID,
		TokenDigest: tokenDigest(in.Token),
		Device:      DescribeUserAgent(in.UserAgent),
		StartedAt:   at,
		LastUsedAt:  at,
		ExpiresAt:   in.ExpiresAt.UTC(),
	}
	if err := check(s.st.Object(roleSession), row); err != nil {
		return models.SessionRecord{}, err
	}
	if err := s.st.Insert(ctx, roleSession, row); err != nil {
		return models.SessionRecord{}, classify(err)
	}
	return row.record(), nil
}

func (s *SessionStore) ByToken(ctx context.Context, token string, now time.Time) (models.SessionRecord, error) {
	if token == "" {
		return models.SessionRecord{}, models.ErrSessionNotFound
	}
	q := s.live(ctx, now).Where(columnName("TokenDigest")+" = ?", tokenDigest(token))
	row, err := s.take(q)
	if err != nil {
		return models.SessionRecord{}, err
	}
	return row.record(), nil
}

func (s *SessionStore) Touch(ctx context.Context, id string, at time.Time) error {
	lastUsed := columnName("LastUsedAt")
	stamp := storedTime(at)
	res := s.st.Query(ctx, roleSession).
		Where(columnName("ID")+" = ?", id).
		Where(s.st.Unset(roleSession, "EndedAt")).
		Where(lastUsed+" < ?", stamp).
		Updates(map[string]any{lastUsed: stamp})
	if res.Error != nil {
		return classify(res.Error)
	}
	if res.RowsAffected > 0 {
		return nil
	}
	q := s.st.Query(ctx, roleSession).
		Where(columnName("ID")+" = ?", id).
		Where(s.st.Unset(roleSession, "EndedAt"))
	_, err := s.take(q)
	return err
}

func (s *SessionStore) ListLive(ctx context.Context, subjectID string, now time.Time) ([]models.SessionRecord, error) {
	q := s.live(ctx, now).
		Where(columnName("SubjectID")+" = ?", subjectID).
		Order(columnName("LastUsedAt") + " DESC").
		Order(columnName("ID"))
	rows, err := listOf[sessionRow](s.st, q, roleSession)
	if err != nil {
		return nil, classify(err)
	}
	out := make([]models.SessionRecord, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.record())
	}
	return out, nil
}

func (s *SessionStore) End(ctx context.Context, subjectID, id string, at time.Time) error {
	if subjectID == "" || id == "" {
		return models.ErrSessionNotFound
	}
	owned := func() *gorm.DB {
		return s.st.Query(ctx, roleSession).
			Where(columnName("ID")+" = ?", id).
			Where(columnName("SubjectID")+" = ?", subjectID)
	}
	res := owned().
		Where(s.st.Unset(roleSession, "EndedAt")).
		Updates(map[string]any{columnName("EndedAt"): storedTime(at)})
	if res.Error != nil {
		return classify(res.Error)
	}
	if res.RowsAffected > 0 {
		return nil
	}
	_, err := s.take(owned())
	return err
}

func (s *SessionStore) live(ctx context.Context, now time.Time) *gorm.DB {
	return s.st.Query(ctx, roleSession).
		Where(s.st.Unset(roleSession, "EndedAt")).
		Where(columnName("ExpiresAt")+" > ?", storedTime(now))
}

func (s *SessionStore) take(q *gorm.DB) (sessionRow, error) {
	var out sessionRow
	err := s.st.Take(q, roleSession, &out, models.ErrSessionNotFound)
	if errors.Is(err, models.ErrSessionNotFound) {
		return sessionRow{}, err
	}
	if err != nil {
		return sessionRow{}, classify(err)
	}
	return out, nil
}

var _ models.SessionRepository = (*SessionStore)(nil)
