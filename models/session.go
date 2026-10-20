package models

import (
	"context"
	"errors"
	"time"
)

var ErrSessionNotFound = errors.New("session: not found")

var ErrSessionInUse = errors.New("session: this is the session making the request; sign out to end it")

var ErrSessionInvalid = errors.New("session: a subject, a token and an expiry after the start are required")

type SessionRecord struct {
	ID         string     `json:"id"`
	SubjectID  string     `json:"subject_id"`
	Device     string     `json:"device"`
	StartedAt  time.Time  `json:"started_at"`
	LastUsedAt time.Time  `json:"last_used_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	EndedAt    *time.Time `json:"ended_at,omitempty"`
}

func (s SessionRecord) Ended() bool { return s.EndedAt != nil }

func (s SessionRecord) Live(now time.Time) bool { return !s.Ended() && now.Before(s.ExpiresAt) }

type SessionStart struct {
	SubjectID string
	Token     string
	UserAgent string
	At        time.Time
	ExpiresAt time.Time
}

type SessionRepository interface {
	Start(ctx context.Context, in SessionStart) (SessionRecord, error)
	ByToken(ctx context.Context, token string, now time.Time) (SessionRecord, error)
	Touch(ctx context.Context, id string, at time.Time) error
	ListLive(ctx context.Context, subjectID string, now time.Time) ([]SessionRecord, error)
	End(ctx context.Context, subjectID, id string, at time.Time) error
}
