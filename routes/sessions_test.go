package routes_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gorm.io/gorm"

	"github.com/aosanya/mwanachama-backend-shared/spec"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
	"github.com/aosanya/mwanachama-backend-auth/routes"
)

type signedInKey struct{}

type signedIn struct {
	subject string
	session string
}

type contextIdentity struct{}

func (contextIdentity) CallerID(r *http.Request) string {
	who, _ := r.Context().Value(signedInKey{}).(signedIn)
	return who.subject
}

func (contextIdentity) CallerSessionID(r *http.Request) string {
	who, _ := r.Context().Value(signedInKey{}).(signedIn)
	return who.session
}

func mustSessionStore(t *testing.T, db *gorm.DB, s *spec.Spec) *mwanachamaauth.SessionStore {
	t.Helper()
	st, err := mwanachamaauth.NewSessionStore(db, s)
	if err != nil {
		t.Fatalf("NewSessionStore: %v", err)
	}
	return st
}

type sessionRig struct {
	mux      *http.ServeMux
	sessions *mwanachamaauth.SessionStore
}

func newSessionRig(t *testing.T) sessionRig {
	t.Helper()
	db, s := newTestDB(t)
	sessions := mustSessionStore(t, db, s)
	all, err := routes.Build(routes.Deps{
		Sessions:       sessions,
		Identity:       contextIdentity{},
		CurrentSession: contextIdentity{},
	})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	_, gated := routes.Split(all)
	mux := http.NewServeMux()
	for _, r := range gated {
		mux.HandleFunc(r.Pattern("/v1/auth"), func(w http.ResponseWriter, req *http.Request) {
			token := req.Header.Get("Authorization")
			held, err := sessions.ByToken(req.Context(), token, time.Now().UTC())
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(req.Context(), signedInKey{}, signedIn{subject: held.SubjectID, session: held.ID})
			r.Handler(w, req.WithContext(ctx))
		})
	}
	return sessionRig{mux: mux, sessions: sessions}
}

func (g sessionRig) signIn(t *testing.T, subject, token, userAgent string) mwanachamaauth.SessionRecord {
	t.Helper()
	rec, err := g.sessions.Start(context.Background(), mwanachamaauth.SessionStart{
		SubjectID: subject, Token: token, UserAgent: userAgent,
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	return rec
}

func (g sessionRig) call(t *testing.T, method, path, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", token)
	rec := httptest.NewRecorder()
	g.mux.ServeHTTP(rec, req)
	return rec
}

type listedSession struct {
	ID         string    `json:"id"`
	SubjectID  string    `json:"subject_id"`
	Device     string    `json:"device"`
	StartedAt  time.Time `json:"started_at"`
	LastUsedAt time.Time `json:"last_used_at"`
	Current    bool      `json:"current"`
}

func (g sessionRig) list(t *testing.T, token string) []listedSession {
	t.Helper()
	rec := g.call(t, http.MethodGet, "/v1/auth/sessions", token)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: status %d, body %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Sessions []listedSession `json:"sessions"`
	}
	decodeBody(t, rec, &out)
	return out.Sessions
}

const (
	laptop = "Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0"
	phone  = "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36"
)

func TestSessionRoutesAreGated(t *testing.T) {
	all, err := routes.Build(routes.Deps{})
	if err != nil {
		t.Fatal(err)
	}
	anonymous, _ := routes.Split(all)
	for _, r := range anonymous {
		if r.Action == "auth.session.list" || r.Action == "auth.session.end" {
			t.Errorf("%s is anonymous; a session list is only ever its holder's", r.Action)
		}
	}
}

func TestACallerListsOnlyTheirOwnSessionsAndSeesWhichIsInUse(t *testing.T) {
	g := newSessionRig(t)
	here := g.signIn(t, "alice", "alice-laptop", laptop)
	there := g.signIn(t, "alice", "alice-phone", phone)
	g.signIn(t, "bob", "bob-laptop", laptop)

	got := g.list(t, "alice-laptop")
	if len(got) != 2 {
		t.Fatalf("alice sees %d sessions, want her own 2: %+v", len(got), got)
	}
	byID := map[string]listedSession{}
	for _, s := range got {
		if s.SubjectID != "alice" {
			t.Errorf("alice's list carries %s's session %s", s.SubjectID, s.ID)
		}
		byID[s.ID] = s
	}
	if !byID[here.ID].Current || byID[there.ID].Current {
		t.Errorf("current flags = %v/%v, want only the laptop session in use", byID[here.ID].Current, byID[there.ID].Current)
	}
	if byID[there.ID].Device != "Chrome on Android" || byID[here.ID].Device != "Firefox on Linux" {
		t.Errorf("devices = %q/%q", byID[here.ID].Device, byID[there.ID].Device)
	}

	rec := g.call(t, http.MethodGet, "/v1/auth/sessions", "alice-laptop")
	for _, leak := range []string{"alice-laptop", "alice-phone", "token", "Mozilla"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("the session list carries %q: %s", leak, rec.Body.String())
		}
	}
}

func TestEndingOneSessionLeavesTheOthers(t *testing.T) {
	g := newSessionRig(t)
	g.signIn(t, "alice", "alice-laptop", laptop)
	there := g.signIn(t, "alice", "alice-phone", phone)
	tablet := g.signIn(t, "alice", "alice-tablet", phone)

	if rec := g.call(t, http.MethodDelete, "/v1/auth/sessions/"+there.ID, "alice-laptop"); rec.Code != http.StatusNoContent {
		t.Fatalf("end: status %d, body %s", rec.Code, rec.Body.String())
	}
	if rec := g.call(t, http.MethodGet, "/v1/auth/sessions", "alice-phone"); rec.Code != http.StatusUnauthorized {
		t.Errorf("the ended session still authenticates: status %d", rec.Code)
	}
	got := g.list(t, "alice-laptop")
	if len(got) != 2 {
		t.Fatalf("after ending one, %d remain; want 2", len(got))
	}
	for _, s := range got {
		if s.ID == there.ID {
			t.Errorf("the ended session is still listed")
		}
	}
	if rec := g.call(t, http.MethodGet, "/v1/auth/sessions", "alice-tablet"); rec.Code != http.StatusOK {
		t.Errorf("a session that was not ended stopped working: %d (%s)", rec.Code, tablet.ID)
	}
}

func TestACallerCannotEndAnotherSubjectsSessionAndIsAnsweredNotFound(t *testing.T) {
	g := newSessionRig(t)
	g.signIn(t, "alice", "alice-laptop", laptop)
	bobs := g.signIn(t, "bob", "bob-laptop", laptop)

	theirs := g.call(t, http.MethodDelete, "/v1/auth/sessions/"+bobs.ID, "alice-laptop")
	invented := g.call(t, http.MethodDelete, "/v1/auth/sessions/session-invented", "alice-laptop")
	if theirs.Code != http.StatusNotFound || invented.Code != http.StatusNotFound {
		t.Fatalf("another's session answered %d, an invented one %d; want 404 for both", theirs.Code, invented.Code)
	}
	if theirs.Body.String() != invented.Body.String() {
		t.Errorf("the two refusals differ:\n%s\n%s", theirs.Body.String(), invented.Body.String())
	}
	if rec := g.call(t, http.MethodGet, "/v1/auth/sessions", "bob-laptop"); rec.Code != http.StatusOK {
		t.Errorf("bob's session was ended by alice: status %d", rec.Code)
	}
}

func TestTheSessionInUseIsNotEndedFromTheList(t *testing.T) {
	g := newSessionRig(t)
	here := g.signIn(t, "alice", "alice-laptop", laptop)

	rec := g.call(t, http.MethodDelete, "/v1/auth/sessions/"+here.ID, "alice-laptop")
	if rec.Code != http.StatusConflict {
		t.Fatalf("ending the session in use: status %d, want 409", rec.Code)
	}
	if got := g.list(t, "alice-laptop"); len(got) != 1 {
		t.Errorf("the session in use was ended")
	}
}

func TestSessionRoutesWithoutAStoreAnswerNotImplemented(t *testing.T) {
	h := routes.ListOwnSessions(nil, fakeIdentity("alice"), nil)
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/sessions", nil))
	if rec.Code != http.StatusNotImplemented {
		t.Errorf("status %d, want 501", rec.Code)
	}
}
