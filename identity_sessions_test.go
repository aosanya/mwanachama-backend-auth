package mwanachamaauth_test

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	mwanachamaauth "github.com/aosanya/mwanachama-backend-auth"
	"github.com/aosanya/mwanachama-backend-auth/models"
)

const (
	subjectA = "00000000-0000-0000-0000-00000000000a"
	sessionA = "00000000-0000-0000-0000-0000000000a1"
)

type identityCall struct {
	query string
	args  []driver.Value
}

type identityProject struct {
	mu    sync.Mutex
	err   error
	cols  []string
	rows  [][]driver.Value
	calls []identityCall
}

func (p *identityProject) Open(string) (driver.Conn, error) { return &identityConn{p}, nil }

type identityConn struct{ p *identityProject }

func (c *identityConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("not prepared") }
func (c *identityConn) Close() error                        { return nil }
func (c *identityConn) Begin() (driver.Tx, error)           { return nil, errors.New("no transactions") }

func (c *identityConn) QueryContext(_ context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.p.mu.Lock()
	defer c.p.mu.Unlock()
	call := identityCall{query: query}
	for _, a := range args {
		call.args = append(call.args, a.Value)
	}
	c.p.calls = append(c.p.calls, call)
	if c.p.err != nil {
		return nil, c.p.err
	}
	return &identityRows{cols: c.p.cols, rows: c.p.rows}, nil
}

type identityRows struct {
	cols []string
	rows [][]driver.Value
}

func (r *identityRows) Columns() []string { return r.cols }
func (r *identityRows) Close() error      { return nil }
func (r *identityRows) Next(dest []driver.Value) error {
	if len(r.rows) == 0 {
		return io.EOF
	}
	copy(dest, r.rows[0])
	r.rows = r.rows[1:]
	return nil
}

var (
	registerIdentityProject sync.Once
	theIdentityProject      = &identityProject{}
)

func identitySessions(t *testing.T, err error, cols []string, rows ...[]driver.Value) mwanachamaauth.IdentitySessions {
	t.Helper()
	registerIdentityProject.Do(func() { sql.Register("auth-identity-project", theIdentityProject) })
	theIdentityProject.mu.Lock()
	theIdentityProject.err, theIdentityProject.cols, theIdentityProject.rows, theIdentityProject.calls = err, cols, rows, nil
	theIdentityProject.mu.Unlock()
	db, openErr := sql.Open("auth-identity-project", "")
	if openErr != nil {
		t.Fatal(openErr)
	}
	t.Cleanup(func() { db.Close() })
	return mwanachamaauth.IdentitySessions{DB: db}
}

var listColumns = []string{"session_id", "user_agent", "started_at", "last_refreshed_at"}

func TestListingCallsTheFunctionWithTheSubjectAsAParameterAndClassifiesEachDevice(t *testing.T) {
	started := time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC)
	refreshed := time.Date(2026, 10, 20, 9, 30, 0, 0, time.UTC)
	store := identitySessions(t, nil, listColumns,
		[]driver.Value{sessionA, "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Mobile Safari/537.36", started, refreshed},
		[]driver.Value{"00000000-0000-0000-0000-0000000000a2", "", started, nil},
	)
	got, err := store.List(context.Background(), strings.ToUpper(subjectA))
	if err != nil {
		t.Fatal(err)
	}
	call := theIdentityProject.calls[0]
	if call.query != "SELECT session_id::text, user_agent, started_at, last_refreshed_at FROM public.list_sign_in_sessions($1::uuid)" {
		t.Fatalf("query %q", call.query)
	}
	if len(call.args) != 1 || call.args[0] != subjectA {
		t.Fatalf("args %v, want the canonical subject alone", call.args)
	}
	want := []models.IdentitySession{
		{ID: sessionA, SubjectID: subjectA, StartedAt: started, LastRefreshedAt: refreshed,
			Device: models.DeviceClass{Form: models.DeviceFormPhone, Client: models.DeviceClientBrowser, Description: "Chrome on Android"}},
		{ID: "00000000-0000-0000-0000-0000000000a2", SubjectID: subjectA, StartedAt: started, LastRefreshedAt: started},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestListingAnswersAnEmptyListNotNil(t *testing.T) {
	got, err := identitySessions(t, nil, listColumns).List(context.Background(), subjectA)
	if err != nil || got == nil || len(got) != 0 {
		t.Fatalf("got %#v, %v", got, err)
	}
}

func TestListingASubjectThatIsNoAccountIdNeverReachesTheProject(t *testing.T) {
	store := identitySessions(t, nil, listColumns)
	got, err := store.List(context.Background(), "x' OR 1=1 --")
	if err != nil || len(got) != 0 {
		t.Fatalf("got %#v, %v", got, err)
	}
	if len(theIdentityProject.calls) != 0 {
		t.Fatal("the project was asked")
	}
}

func TestAListedSessionCarriesNoNetworkAddressAndNoUserAgent(t *testing.T) {
	for _, ty := range []reflect.Type{reflect.TypeOf(models.IdentitySession{}), reflect.TypeOf(models.DeviceClass{})} {
		for i := range ty.NumField() {
			name := strings.ToLower(ty.Field(i).Name + " " + ty.Field(i).Tag.Get("json"))
			for _, banned := range []string{"ip", "address", "location", "agent"} {
				for _, word := range strings.FieldsFunc(name, func(r rune) bool { return r == ' ' || r == '_' || r == ',' }) {
					if word == banned {
						t.Errorf("%s.%s carries %q", ty.Name(), ty.Field(i).Name, banned)
					}
				}
			}
		}
	}
}

func TestEndingCallsTheFunctionWithTheSubjectAndTheSession(t *testing.T) {
	store := identitySessions(t, nil, []string{"end_sign_in_session"}, []driver.Value{true})
	if err := store.End(context.Background(), subjectA, sessionA); err != nil {
		t.Fatal(err)
	}
	call := theIdentityProject.calls[0]
	if call.query != "SELECT public.end_sign_in_session($1::uuid, $2::uuid)" {
		t.Fatalf("query %q", call.query)
	}
	if len(call.args) != 2 || call.args[0] != subjectA || call.args[1] != sessionA {
		t.Fatalf("args %v", call.args)
	}
}

func TestEndingAnotherSubjectsOrAnUnknownSessionIsNotFound(t *testing.T) {
	store := identitySessions(t, nil, []string{"end_sign_in_session"}, []driver.Value{false})
	if err := store.End(context.Background(), subjectA, sessionA); !errors.Is(err, models.ErrSessionNotFound) {
		t.Fatalf("got %v", err)
	}
}

func TestEndingWithAnIdThatIsNoUUIDIsNotFoundWithoutAskingTheProject(t *testing.T) {
	for _, pair := range [][2]string{{subjectA, "session-1"}, {"someone", sessionA}, {"", ""}} {
		store := identitySessions(t, nil, []string{"end_sign_in_session"}, []driver.Value{true})
		if err := store.End(context.Background(), pair[0], pair[1]); !errors.Is(err, models.ErrSessionNotFound) {
			t.Errorf("%v: got %v", pair, err)
		}
		if len(theIdentityProject.calls) != 0 {
			t.Errorf("%v: the project was asked", pair)
		}
	}
}

func TestAProjectWithoutTheFunctionsIsNamed(t *testing.T) {
	for _, code := range []string{"42883", "42501", "3F000"} {
		store := identitySessions(t, &pgconn.PgError{Code: code}, nil)
		if _, err := store.List(context.Background(), subjectA); !errors.Is(err, models.ErrIdentitySessionFunctionsMissing) {
			t.Errorf("list %s: %v", code, err)
		}
		if err := store.End(context.Background(), subjectA, sessionA); !errors.Is(err, models.ErrIdentitySessionFunctionsMissing) {
			t.Errorf("end %s: %v", code, err)
		}
	}
	store := identitySessions(t, &pgconn.PgError{Code: "57014"}, nil)
	if _, err := store.List(context.Background(), subjectA); err == nil || errors.Is(err, models.ErrIdentitySessionFunctionsMissing) {
		t.Fatalf("a cancelled query read as %v", err)
	}
}
