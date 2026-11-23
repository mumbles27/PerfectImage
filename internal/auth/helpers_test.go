package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/config"
	"github.com/mumbles27/PerfectImage/internal/secrets"
	"github.com/mumbles27/PerfectImage/internal/store"
)

// cheapArgon keeps tests fast; production uses DefaultArgon2Params.
var cheapArgon = Argon2Params{Memory: 64, Iterations: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type events struct {
	mu sync.Mutex
	ev []audit.Event
}

func (e *events) Record(_ context.Context, ev audit.Event) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ev = append(e.ev, ev)
	return nil
}

func (e *events) has(action string, outcome audit.Outcome) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for _, ev := range e.ev {
		if ev.Action == action && ev.Outcome == outcome {
			return true
		}
	}
	return false
}

type fixture struct {
	svc   *Service
	db    *store.DB
	clock *clock
	audit *events
}

func newFixture(t *testing.T, mutate func(*Options)) *fixture {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, filepath.Join(t.TempDir(), "test.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := store.Migrate(ctx, db); err != nil {
		t.Fatal(err)
	}
	key, _ := secrets.NewKey()
	sealer, _ := secrets.NewAESGCM(key)
	clk := &clock{t: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)}
	ev := &events{}
	o := Options{
		DB: db, Sealer: sealer, Audit: ev, Argon2: &cheapArgon, Now: clk.Now,
		Config: config.AuthConfig{LoginRatePerIP: -1, LoginRatePerUser: -1},
	}
	if mutate != nil {
		mutate(&o)
	}
	svc := NewService(o)
	if err := svc.Init(ctx); err != nil {
		t.Fatal(err)
	}
	return &fixture{svc: svc, db: db, clock: clk, audit: ev}
}

// mustUser creates a local user with a known password that does not need
// changing.
func (f *fixture) mustUser(t *testing.T, name, password string, roles ...string) *User {
	t.Helper()
	ctx := context.Background()
	u, _, err := f.svc.CreateUser(ctx, nil, SystemActor, NewUser{Username: name, Roles: roles, Password: password})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.db.ExecContext(ctx, `UPDATE auth_users SET must_change_password = 0 WHERE id = ?`, u.ID); err != nil {
		t.Fatal(err)
	}
	u.MustChangePassword = false
	return u
}

// do runs r through the CSRF protector (which resolves sessions) and h,
// returning the recorder. Cookies from jar are sent and updated.
func (f *fixture) do(t *testing.T, jar map[string]string, r *http.Request, h http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	for k, v := range jar {
		r.AddCookie(&http.Cookie{Name: k, Value: v})
	}
	w := httptest.NewRecorder()
	f.svc.CSRF().Protect(h).ServeHTTP(w, r)
	for _, c := range w.Result().Cookies() {
		if c.MaxAge < 0 {
			delete(jar, c.Name)
		} else {
			jar[c.Name] = c.Value
		}
	}
	return w
}
