package mwanachamaauth

import (
	"context"
	"sync"
	"time"

	"github.com/aosanya/mwanachama-backend-auth/models"
)

type SessionToucher interface {
	Touch(ctx context.Context, subjectID, sessionID string) error
}

type LastSeen struct {
	Sessions SessionToucher
	Now      func() time.Time

	mu      sync.Mutex
	touched map[string]time.Time
	swept   time.Time
}

func (l *LastSeen) Touch(ctx context.Context, subjectID, sessionID string) error {
	subject, subjectOK := canonicalUUID(subjectID)
	session, sessionOK := canonicalUUID(sessionID)
	if !subjectOK || !sessionOK {
		return models.ErrSessionNotFound
	}
	key := subject + "/" + session
	at := l.now()
	if !l.claim(key, at) {
		return nil
	}
	if err := l.Sessions.Touch(ctx, subject, session); err != nil {
		l.release(key, at)
		return err
	}
	return nil
}

func (l *LastSeen) now() time.Time {
	if l.Now != nil {
		return l.Now()
	}
	return time.Now()
}

func (l *LastSeen) claim(key string, at time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.touched == nil {
		l.touched = map[string]time.Time{}
	}
	if at.Sub(l.swept) >= LastSeenThrottle {
		for k, last := range l.touched {
			if at.Sub(last) >= LastSeenThrottle {
				delete(l.touched, k)
			}
		}
		l.swept = at
	}
	if last, ok := l.touched[key]; ok && at.Sub(last) < LastSeenThrottle {
		return false
	}
	l.touched[key] = at
	return true
}

func (l *LastSeen) release(key string, at time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if last, ok := l.touched[key]; ok && last.Equal(at) {
		delete(l.touched, key)
	}
}
