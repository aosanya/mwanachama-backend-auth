package mwanachamaauth_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
	"github.com/aosanya/mwanachama-backend-auth/models"
)

const sessionB = "00000000-0000-0000-0000-0000000000a2"

type recordedTouches struct {
	mu    sync.Mutex
	err   error
	calls []string
}

func (r *recordedTouches) Touch(_ context.Context, subjectID, sessionID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, subjectID+"/"+sessionID)
	return r.err
}

func (r *recordedTouches) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

type stepClock struct{ at time.Time }

func (c *stepClock) now() time.Time          { return c.at }
func (c *stepClock) advance(d time.Duration) { c.at = c.at.Add(d) }
func newStepClock() *stepClock               { return &stepClock{at: time.Date(2026, 10, 21, 8, 0, 0, 0, time.UTC)} }
func lastSeenOver(r *recordedTouches, c *stepClock) *mwanachamaauth.LastSeen {
	return &mwanachamaauth.LastSeen{Sessions: r, Now: c.now}
}

func TestLastSeenReachesTheProjectOncePerThrottlePerSession(t *testing.T) {
	r, clock := &recordedTouches{}, newStepClock()
	seen := lastSeenOver(r, clock)
	ctx := context.Background()
	for range 5 {
		if err := seen.Touch(ctx, subjectA, sessionA); err != nil {
			t.Fatal(err)
		}
		clock.advance(mwanachamaauth.LastSeenThrottle / 10)
	}
	if r.count() != 1 {
		t.Fatalf("%d touches inside one throttle, want 1", r.count())
	}
	clock.advance(mwanachamaauth.LastSeenThrottle)
	if err := seen.Touch(ctx, subjectA, sessionA); err != nil {
		t.Fatal(err)
	}
	if r.count() != 2 {
		t.Fatalf("%d touches after the throttle passed, want 2", r.count())
	}
}

func TestLastSeenThrottlesEachSessionOnItsOwn(t *testing.T) {
	r, clock := &recordedTouches{}, newStepClock()
	seen := lastSeenOver(r, clock)
	ctx := context.Background()
	for _, session := range []string{sessionA, sessionB, sessionA, sessionB} {
		if err := seen.Touch(ctx, subjectA, session); err != nil {
			t.Fatal(err)
		}
	}
	if r.count() != 2 {
		t.Fatalf("%d touches, want one per session", r.count())
	}
}

func TestLastSeenTreatsOneSessionSpelledTwoWaysAsOne(t *testing.T) {
	r, clock := &recordedTouches{}, newStepClock()
	seen := lastSeenOver(r, clock)
	ctx := context.Background()
	_ = seen.Touch(ctx, subjectA, sessionA)
	_ = seen.Touch(ctx, strings.ToUpper(subjectA), strings.ToUpper(sessionA))
	if r.count() != 1 || r.calls[0] != subjectA+"/"+sessionA {
		t.Fatalf("calls %v", r.calls)
	}
}

func TestAFailedTouchIsRetriedOnTheNextRequest(t *testing.T) {
	r, clock := &recordedTouches{err: errors.New("unreachable")}, newStepClock()
	seen := lastSeenOver(r, clock)
	ctx := context.Background()
	if err := seen.Touch(ctx, subjectA, sessionA); err == nil {
		t.Fatal("the failure was swallowed")
	}
	r.err = nil
	clock.advance(time.Second)
	if err := seen.Touch(ctx, subjectA, sessionA); err != nil {
		t.Fatal(err)
	}
	if r.count() != 2 {
		t.Fatalf("%d touches, want the failed one retried", r.count())
	}
}

func TestLastSeenNeverForwardsAnIdThatIsNoUUID(t *testing.T) {
	r, clock := &recordedTouches{}, newStepClock()
	seen := lastSeenOver(r, clock)
	if err := seen.Touch(context.Background(), subjectA, "session-1"); !errors.Is(err, models.ErrSessionNotFound) {
		t.Fatalf("got %v", err)
	}
	if r.count() != 0 {
		t.Fatal("the store was asked")
	}
}

func TestLastSeenIsSafeUnderConcurrentRequests(t *testing.T) {
	r := &recordedTouches{}
	seen := &mwanachamaauth.LastSeen{Sessions: r}
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = seen.Touch(context.Background(), subjectA, sessionA)
		}()
	}
	wg.Wait()
	if r.count() != 1 {
		t.Fatalf("%d touches from one burst, want 1", r.count())
	}
}

var _ mwanachamaauth.SessionToucher = mwanachamaauth.IdentitySessions{}
var _ mwanachamaauth.SessionToucher = (*mwanachamaauth.LastSeen)(nil)
