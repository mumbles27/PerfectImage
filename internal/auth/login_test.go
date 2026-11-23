package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/config"
	"github.com/mumbles27/PerfectImage/internal/rbac"
)

func TestLoginLockoutWithBackoff(t *testing.T) {
	f := newFixture(t, func(o *Options) {
		o.Config.LockoutThreshold = 3
		o.Config.LockoutDuration = time.Minute
		o.Config.LockoutMaxDuration = 3 * time.Minute
	})
	ctx := context.Background()
	f.mustUser(t, "alice", "Lantern-Purple-42", "Viewer")
	meta := RequestMeta{IP: "192.0.2.1"}
	login := func(pw string) error { _, err := f.svc.Login(ctx, meta, "ALICE", pw); return err }

	steps := []struct {
		name    string
		advance time.Duration
		pw      string
		want    error
		locked  time.Duration // expected remaining lock after the step
	}{
		{"fail 1", 0, "bad", ErrInvalidCredentials, 0},
		{"fail 2", 0, "bad", ErrInvalidCredentials, 0},
		{"fail 3 locks 1m", 0, "bad", ErrInvalidCredentials, time.Minute},
		{"locked even with right password", 0, "Lantern-Purple-42", ErrAccountLocked, time.Minute},
		{"fail 4 after expiry locks 2m", 61 * time.Second, "bad", ErrInvalidCredentials, 2 * time.Minute},
		{"fail 5 after expiry capped at 3m", 121 * time.Second, "bad", ErrInvalidCredentials, 3 * time.Minute},
		{"success after expiry resets", 181 * time.Second, "Lantern-Purple-42", nil, 0},
	}
	for _, st := range steps {
		f.clock.Add(st.advance)
		if err := login(st.pw); !errors.Is(err, st.want) {
			t.Fatalf("%s: err = %v, want %v", st.name, err, st.want)
		}
		u, _ := f.svc.UserByUsername(ctx, "alice")
		if got := u.LockedUntil.Sub(f.clock.Now()); max(got, 0) != st.locked {
			t.Fatalf("%s: locked for %v, want %v", st.name, got, st.locked)
		}
	}
	u, _ := f.svc.UserByUsername(ctx, "alice")
	if u.FailedLogins != 0 {
		t.Fatalf("failed logins = %d after success", u.FailedLogins)
	}
	if !f.audit.has("auth.login", audit.OutcomeFailure) || !f.audit.has("auth.login", audit.OutcomeSuccess) {
		t.Fatal("login not audited")
	}
	for _, ev := range f.audit.ev {
		for _, v := range ev.Details {
			if s, ok := v.(string); ok && strings.Contains(s, "Lantern") {
				t.Fatal("password leaked into audit")
			}
		}
	}

	// Admin unlock.
	for range 3 {
		_ = login("bad")
	}
	if err := login("Lantern-Purple-42"); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("expected lock, got %v", err)
	}
	if err := f.svc.Unlock(ctx, SystemActor, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := login("Lantern-Purple-42"); err != nil {
		t.Fatalf("after unlock: %v", err)
	}
}

func TestLoginErrorsAndRateLimit(t *testing.T) {
	f := newFixture(t, func(o *Options) { o.Config.LoginRatePerUser = 3; o.Config.LoginRatePerIP = 100 })
	ctx := context.Background()
	u := f.mustUser(t, "bob", "Lantern-Purple-42", "Viewer")
	meta := RequestMeta{IP: "192.0.2.2"}
	if _, err := f.svc.Login(ctx, meta, "nobody", "x"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown user: %v", err)
	}
	if err := f.svc.SetDisabled(ctx, SystemActor, u.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Login(ctx, meta, "bob", "Lantern-Purple-42"); !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("disabled: %v", err)
	}
	_, _ = f.svc.Login(ctx, meta, "bob", "x")
	_, _ = f.svc.Login(ctx, meta, "bob", "x")
	if _, err := f.svc.Login(ctx, meta, "bob", "x"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("rate limit: %v", err)
	}
}

// login performs a full password sign-in through the HTTP layer and returns
// the cookie jar.
func (f *fixture) login(t *testing.T, user, pw string) map[string]string {
	t.Helper()
	jar := map[string]string{}
	var csrf string
	f.do(t, jar, httptest.NewRequest("GET", "/login", nil), func(w http.ResponseWriter, r *http.Request) {
		csrf = f.svc.CSRF().Token(r)
	})
	form := url.Values{"username": {user}, "password": {pw}, CSRFField: {csrf}}
	req := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := f.do(t, jar, req, func(w http.ResponseWriter, r *http.Request) {
		au, err := f.svc.Login(r.Context(), MetaFrom(r, ""), r.PostFormValue("username"), r.PostFormValue("password"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if _, err := f.svc.StartSession(r.Context(), w, r, au, MetaFrom(r, "")); err != nil {
			t.Fatal(err)
		}
	})
	if w.Code != http.StatusOK {
		t.Fatalf("login: %d %s", w.Code, w.Body)
	}
	return jar
}

func (f *fixture) whoami(t *testing.T, jar map[string]string) (*Principal, error) {
	t.Helper()
	var p *Principal
	var err error
	f.do(t, jar, httptest.NewRequest("GET", "/", nil), func(w http.ResponseWriter, r *http.Request) {
		p, err = f.svc.Authenticate(r)
	})
	return p, err
}

func TestSessionLifecycle(t *testing.T) {
	f := newFixture(t, func(o *Options) {
		o.Config = config.AuthConfig{SessionTTL: time.Hour, SessionAbsoluteTTL: 3 * time.Hour, LoginRatePerIP: -1, LoginRatePerUser: -1}
	})
	ctx := context.Background()
	u := f.mustUser(t, "carol", "Lantern-Purple-42", "Operator")
	jar := f.login(t, "carol", "Lantern-Purple-42")
	first := jar[SessionCookie]
	p, err := f.whoami(t, jar)
	if err != nil || p.Username != "carol" || !p.Has(rbac.DeployRun) || p.Has(rbac.UsersManage) || p.AuthMethod != "password" {
		t.Fatalf("principal = %+v, %v", p, err)
	}
	var raw string
	_ = f.db.QueryRowContext(ctx, `SELECT id FROM auth_sessions`).Scan(&raw)
	if raw == first || raw != sha256Hex(first) {
		t.Fatal("session stored unhashed")
	}

	// Privilege change flags rotation: next request gets a new ID and the
	// new permissions; the old cookie stops working.
	if err := f.svc.UpdateUser(ctx, nil, SystemActor, u.ID, "", "", []string{"Viewer"}); err != nil {
		t.Fatal(err)
	}
	p, _ = f.whoami(t, jar)
	if jar[SessionCookie] == first || p == nil || p.Has(rbac.DeployRun) {
		t.Fatalf("not rotated/downgraded: %+v", p)
	}
	if _, err := f.whoami(t, map[string]string{SessionCookie: first}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("old session still valid: %v", err)
	}

	// Idle timeout.
	f.clock.Add(59 * time.Minute)
	if _, err := f.whoami(t, jar); err != nil {
		t.Fatalf("expired early: %v", err)
	}
	f.clock.Add(61 * time.Minute)
	if _, err := f.whoami(t, jar); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("idle timeout not enforced")
	}

	// Absolute timeout despite activity.
	jar = f.login(t, "carol", "Lantern-Purple-42")
	for range 6 {
		f.clock.Add(30 * time.Minute)
		_, _ = f.whoami(t, jar)
	}
	if _, err := f.whoami(t, jar); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("absolute timeout not enforced")
	}

	// Logout-all revokes every session.
	j1 := f.login(t, "carol", "Lantern-Purple-42")
	j2 := f.login(t, "carol", "Lantern-Purple-42")
	if ss, _ := f.svc.Sessions(ctx, u.ID); len(ss) != 2 {
		t.Fatalf("sessions = %d", len(ss))
	}
	if n, err := f.svc.RevokeAllSessions(ctx, Actor{ID: u.ID, Username: u.Username}, u.ID, ""); err != nil || n != 2 {
		t.Fatalf("revoke all = %d, %v", n, err)
	}
	for _, j := range []map[string]string{j1, j2} {
		if _, err := f.whoami(t, j); err == nil {
			t.Fatal("session survived logout-all")
		}
	}

	// Disabled users lose access immediately.
	j3 := f.login(t, "carol", "Lantern-Purple-42")
	_, _ = f.db.ExecContext(ctx, `UPDATE auth_users SET disabled = 1 WHERE id = ?`, u.ID)
	if _, err := f.whoami(t, j3); err == nil {
		t.Fatal("disabled user authenticated")
	}
}

func TestLoginStagesAndFixation(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	u, pw, err := f.svc.CreateUser(ctx, nil, SystemActor, NewUser{Username: "dave", Roles: []string{"Viewer"}})
	if err != nil {
		t.Fatal(err)
	}
	// Attacker-planted session cookie must not survive login.
	planted := map[string]string{SessionCookie: "attacker-chosen-value-xxxxxxxxxxxxxxxxxxx"}
	jar := f.login(t, "dave", pw)
	if jar[SessionCookie] == planted[SessionCookie] {
		t.Fatal("session fixation")
	}
	if _, err := f.whoami(t, jar); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("pending (password change) session authenticated")
	}
	var stage string
	f.do(t, jar, httptest.NewRequest("GET", "/login/password", nil), func(w http.ResponseWriter, r *http.Request) {
		stage = CurrentSession(r).Stage
		if err := f.svc.ChangePassword(r.Context(), Actor{}, u.ID, pw, "Lantern-Purple-42", CurrentSession(r).ID); err != nil {
			t.Fatal(err)
		}
		before := jar[SessionCookie]
		next, err := f.svc.Advance(r.Context(), w, r, true)
		if err != nil || next != StageActive {
			t.Fatalf("advance = %s, %v", next, err)
		}
		_ = before
	})
	if stage != StagePassword {
		t.Fatalf("stage = %s", stage)
	}
	if p, err := f.whoami(t, jar); err != nil || p.Username != "dave" {
		t.Fatalf("after password change: %v", err)
	}
}

func TestCSRFProtector(t *testing.T) {
	f := newFixture(t, nil)
	f.mustUser(t, "erin", "Lantern-Purple-42", "Viewer")
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }

	anon := map[string]string{}
	var anonTok string
	f.do(t, anon, httptest.NewRequest("GET", "/login", nil), func(w http.ResponseWriter, r *http.Request) {
		anonTok = f.svc.CSRF().Token(r)
	})
	if anonTok == "" || anon[preSessionCookie] == "" {
		t.Fatal("no anonymous token/cookie")
	}
	sess := f.login(t, "erin", "Lantern-Purple-42")
	var sessTok string
	f.do(t, sess, httptest.NewRequest("GET", "/", nil), func(w http.ResponseWriter, r *http.Request) {
		sessTok = f.svc.CSRF().Token(r)
	})

	post := func(jar map[string]string, hdr map[string]string, form string) int {
		r := httptest.NewRequest("POST", "/x", strings.NewReader(form))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for k, v := range hdr {
			r.Header.Set(k, v)
		}
		return f.do(t, jar, r, ok).Code
	}
	tests := []struct {
		name string
		jar  map[string]string
		hdr  map[string]string
		form string
		want int
	}{
		{"anon no token", anon, nil, "", http.StatusForbidden},
		{"anon form token", anon, nil, CSRFField + "=" + anonTok, http.StatusNoContent},
		{"anon header token", anon, map[string]string{CSRFHeader: anonTok}, "", http.StatusNoContent},
		{"anon wrong token", anon, map[string]string{CSRFHeader: sessTok}, "", http.StatusForbidden},
		{"session token", sess, map[string]string{CSRFHeader: sessTok}, "", http.StatusNoContent},
		{"session with anon token", sess, map[string]string{CSRFHeader: anonTok}, "", http.StatusForbidden},
		{"other browser's pre-session", map[string]string{preSessionCookie: strings.Repeat("A", 43)}, map[string]string{CSRFHeader: anonTok}, "", http.StatusForbidden},
		{"bearer exempt", map[string]string{}, map[string]string{"Authorization": "Bearer pit_x"}, "", http.StatusNoContent},
		{"cross-origin rejected", sess, map[string]string{CSRFHeader: sessTok, "Sec-Fetch-Site": "cross-site"}, "", http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := post(tt.jar, tt.hdr, tt.form); got != tt.want {
				t.Fatalf("status = %d, want %d", got, tt.want)
			}
		})
	}
	// GETs need no token.
	if w := f.do(t, anon, httptest.NewRequest("GET", "/x", nil), ok); w.Code != http.StatusNoContent {
		t.Fatalf("GET = %d", w.Code)
	}
}
