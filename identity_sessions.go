package mwanachamaauth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/aosanya/mwanachama-backend-auth/models"
)

const (
	listSignInSessionsQuery = "SELECT session_id::text, user_agent, started_at, last_refreshed_at, last_seen_at FROM " + ListSignInSessionsFunc + "($1::uuid)"
	endSignInSessionQuery   = "SELECT " + EndSignInSessionFunc + "($1::uuid, $2::uuid)"
	touchSignInSessionQuery = "SELECT " + TouchSignInSessionFunc + "($1::uuid, $2::uuid)"
	sessionGoneCode         = "23503"
)

var unreachableFunctionCodes = []string{"42883", "42501", "3F000", "42703"}

type IdentitySessions struct {
	DB *sql.DB
}

func identitySessionErr(call string, err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		for _, code := range unreachableFunctionCodes {
			if pgErr.Code == code {
				return models.ErrIdentitySessionFunctionsMissing
			}
		}
	}
	return fmt.Errorf("identity sessions: %s: %w", call, err)
}

func canonicalUUID(s string) (string, bool) {
	id, err := uuid.Parse(s)
	if err != nil {
		return "", false
	}
	return id.String(), true
}

func (s IdentitySessions) List(ctx context.Context, subjectID string) ([]models.IdentitySession, error) {
	subject, ok := canonicalUUID(subjectID)
	if !ok {
		return []models.IdentitySession{}, nil
	}
	rows, err := s.DB.QueryContext(ctx, listSignInSessionsQuery, subject)
	if err != nil {
		return nil, identitySessionErr("list", err)
	}
	defer rows.Close()
	out := []models.IdentitySession{}
	for rows.Next() {
		var (
			id, userAgent            string
			started, refreshed, seen sql.NullTime
		)
		if err := rows.Scan(&id, &userAgent, &started, &refreshed, &seen); err != nil {
			return nil, identitySessionErr("list", err)
		}
		session := models.IdentitySession{
			ID:        id,
			SubjectID: subject,
			Device:    ClassifyUserAgent(userAgent),
			StartedAt: started.Time.UTC(),
		}
		session.LastRefreshedAt = session.StartedAt
		if refreshed.Valid {
			session.LastRefreshedAt = refreshed.Time.UTC()
		}
		session.LastSeenAt = session.LastRefreshedAt
		if seen.Valid && seen.Time.After(session.LastSeenAt) {
			session.LastSeenAt = seen.Time.UTC()
		}
		out = append(out, session)
	}
	if err := rows.Err(); err != nil {
		return nil, identitySessionErr("list", err)
	}
	return out, nil
}

func (s IdentitySessions) End(ctx context.Context, subjectID, sessionID string) error {
	subject, subjectOK := canonicalUUID(subjectID)
	session, sessionOK := canonicalUUID(sessionID)
	if !subjectOK || !sessionOK {
		return models.ErrSessionNotFound
	}
	var ended bool
	if err := s.DB.QueryRowContext(ctx, endSignInSessionQuery, subject, session).Scan(&ended); err != nil {
		return identitySessionErr("end", err)
	}
	if !ended {
		return models.ErrSessionNotFound
	}
	return nil
}

func (s IdentitySessions) Touch(ctx context.Context, subjectID, sessionID string) error {
	subject, subjectOK := canonicalUUID(subjectID)
	session, sessionOK := canonicalUUID(sessionID)
	if !subjectOK || !sessionOK {
		return models.ErrSessionNotFound
	}
	_, err := s.DB.ExecContext(ctx, touchSignInSessionQuery, subject, session)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == sessionGoneCode {
		return nil
	}
	if err != nil {
		return identitySessionErr("touch", err)
	}
	return nil
}
