package authplugin

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"net/url"

	"github.com/mumbles27/PerfectImage/internal/auth"
)

const oidcStateCookie = "pi_oidc_state"

type loginData struct {
	Next      string
	Username  string
	Error     string
	Notice    string
	Providers []auth.OIDCProvider
}

func (m *module) loginPage(w http.ResponseWriter, r *http.Request) {
	next := auth.SafeNext(r.URL.Query().Get("next"))
	if auth.PrincipalFrom(r.Context()) != nil {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	m.renderLogin(w, r, http.StatusOK, loginData{Next: next, Notice: flash(r)})
}

func (m *module) renderLogin(w http.ResponseWriter, r *http.Request, status int, d loginData) {
	provs, err := m.svc.OIDCProviders(r.Context(), true)
	if err != nil {
		m.srv.Logger().Error("list oidc providers", "err", err)
	}
	d.Providers = provs
	m.render(w, r, status, "login.html", "Sign in", d)
}

func (m *module) loginSubmit(w http.ResponseWriter, r *http.Request) {
	next := auth.SafeNext(r.PostFormValue("next"))
	username := r.PostFormValue("username")
	au, err := m.svc.Login(r.Context(), m.meta(r), username, r.PostFormValue("password"))
	if err != nil {
		msg, status := "Invalid username or password, or the account is temporarily locked.", http.StatusUnauthorized
		if errors.Is(err, auth.ErrRateLimited) {
			msg, status = "Too many sign-in attempts. Wait a minute and try again.", http.StatusTooManyRequests
		} else if !isAuthFailure(err) {
			m.srv.Logger().Error("login", "err", err)
			msg, status = "Sign-in is temporarily unavailable.", http.StatusInternalServerError
		}
		m.renderLogin(w, r, status, loginData{Next: next, Username: username, Error: msg})
		return
	}
	m.startSession(w, r, au, next)
}

func isAuthFailure(err error) bool {
	for _, e := range []error{auth.ErrInvalidCredentials, auth.ErrAccountLocked, auth.ErrAccountDisabled,
		auth.ErrNotProvisioned, auth.ErrOIDCState, auth.ErrProviderNotFound} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

func (m *module) startSession(w http.ResponseWriter, r *http.Request, au *auth.Authenticated, next string) {
	stage, err := m.svc.StartSession(r.Context(), w, r, au, m.meta(r))
	if err != nil {
		m.srv.Logger().Error("start session", "err", err)
		m.srv.Error(w, r, http.StatusInternalServerError, "Could not start a session.")
		return
	}
	http.Redirect(w, r, stagePath(stage, next), http.StatusSeeOther)
}

func stagePath(stage, next string) string {
	q := ""
	if next != "/" {
		q = "?next=" + url.QueryEscape(next)
	}
	switch stage {
	case auth.StageMFA:
		return "/login/mfa" + q
	case auth.StagePassword:
		return "/login/password" + q
	case auth.StageMFAEnroll:
		return "/login/mfa/setup" + q
	}
	return next
}

// pending returns the user of the request's in-progress sign-in when it is
// in stage; otherwise it redirects to /login and returns nil.
func (m *module) pending(w http.ResponseWriter, r *http.Request, stage string) *auth.User {
	ss := auth.CurrentSession(r)
	if ss == nil || ss.Stage != stage {
		if ss != nil && ss.Stage == auth.StageActive {
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return nil
		}
		redirect(w, r, "/login", "")
		return nil
	}
	u, err := m.svc.UserByID(r.Context(), ss.UserID)
	if err != nil || u.Disabled {
		redirect(w, r, "/login", "")
		return nil
	}
	return u
}

func (m *module) advance(w http.ResponseWriter, r *http.Request, mfaDone bool, next string) {
	stage, err := m.svc.Advance(r.Context(), w, r, mfaDone)
	if err != nil {
		redirect(w, r, "/login", "")
		return
	}
	http.Redirect(w, r, stagePath(stage, next), http.StatusSeeOther)
}

type stageData struct {
	Next       string
	Error      string
	User       *auth.User
	Enrollment *auth.Enrollment
	Codes      []string
	MinLength  int
}

func (m *module) mfaPage(w http.ResponseWriter, r *http.Request) {
	u := m.pending(w, r, auth.StageMFA)
	if u == nil {
		return
	}
	m.render(w, r, http.StatusOK, "login_mfa.html", "Two-factor authentication",
		stageData{Next: auth.SafeNext(r.URL.Query().Get("next")), User: u})
}

func (m *module) mfaSubmit(w http.ResponseWriter, r *http.Request) {
	u := m.pending(w, r, auth.StageMFA)
	if u == nil {
		return
	}
	next := auth.SafeNext(r.PostFormValue("next"))
	a := auth.Actor{ID: u.ID, Username: u.Username, Meta: m.meta(r)}
	if err := m.svc.VerifyMFA(r.Context(), a, u, r.PostFormValue("code")); err != nil {
		m.render(w, r, http.StatusUnauthorized, "login_mfa.html", "Two-factor authentication",
			stageData{Next: next, User: u, Error: userMessage(err)})
		return
	}
	m.advance(w, r, true, next)
}

func (m *module) forcedPasswordPage(w http.ResponseWriter, r *http.Request) {
	u := m.pending(w, r, auth.StagePassword)
	if u == nil {
		return
	}
	m.render(w, r, http.StatusOK, "login_password.html", "Change password",
		stageData{Next: auth.SafeNext(r.URL.Query().Get("next")), User: u, MinLength: m.svc.Policy().MinLength})
}

func (m *module) forcedPasswordSubmit(w http.ResponseWriter, r *http.Request) {
	u := m.pending(w, r, auth.StagePassword)
	if u == nil {
		return
	}
	next := auth.SafeNext(r.PostFormValue("next"))
	fail := func(msg string) {
		m.render(w, r, http.StatusBadRequest, "login_password.html", "Change password",
			stageData{Next: next, User: u, Error: msg, MinLength: m.svc.Policy().MinLength})
	}
	if r.PostFormValue("new_password") != r.PostFormValue("confirm_password") {
		fail("The new passwords do not match.")
		return
	}
	a := auth.Actor{ID: u.ID, Username: u.Username, Meta: m.meta(r)}
	ss := auth.CurrentSession(r)
	if err := m.svc.ChangePassword(r.Context(), a, u.ID, r.PostFormValue("current_password"),
		r.PostFormValue("new_password"), ss.ID); err != nil {
		fail(userMessage(err))
		return
	}
	m.advance(w, r, true, next)
}

func (m *module) forcedEnrollPage(w http.ResponseWriter, r *http.Request) {
	u := m.pending(w, r, auth.StageMFAEnroll)
	if u == nil {
		return
	}
	enr, err := m.svc.PendingTOTP(u)
	if err != nil {
		if enr, err = m.svc.BeginTOTP(r.Context(), u); err != nil {
			m.srv.Logger().Error("begin totp", "err", err)
			m.srv.Error(w, r, http.StatusInternalServerError, "Could not start MFA enrollment.")
			return
		}
	}
	m.render(w, r, http.StatusOK, "login_mfa_setup.html", "Set up two-factor authentication",
		stageData{Next: auth.SafeNext(r.URL.Query().Get("next")), User: u, Enrollment: enr})
}

func (m *module) forcedEnrollSubmit(w http.ResponseWriter, r *http.Request) {
	u := m.pending(w, r, auth.StageMFAEnroll)
	if u == nil {
		return
	}
	next := auth.SafeNext(r.PostFormValue("next"))
	a := auth.Actor{ID: u.ID, Username: u.Username, Meta: m.meta(r)}
	codes, err := m.svc.ConfirmTOTP(r.Context(), a, u, r.PostFormValue("code"))
	if err != nil {
		enr, _ := m.svc.PendingTOTP(u)
		m.render(w, r, http.StatusBadRequest, "login_mfa_setup.html", "Set up two-factor authentication",
			stageData{Next: next, User: u, Enrollment: enr, Error: userMessage(err)})
		return
	}
	stage, err := m.svc.Advance(r.Context(), w, r, true)
	if err != nil {
		redirect(w, r, "/login", "")
		return
	}
	// Show the recovery codes once, then continue.
	m.render(w, r, http.StatusOK, "login_recovery.html", "Recovery codes",
		stageData{Next: stagePath(stage, next), User: u, Codes: codes})
}

func (m *module) logout(w http.ResponseWriter, r *http.Request) {
	m.svc.Logout(r.Context(), w, r, m.meta(r))
	redirect(w, r, "/login", "")
}

// --- OIDC -----------------------------------------------------------------

func (m *module) oidcStart(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("provider")
	next := auth.SafeNext(r.URL.Query().Get("next"))
	authURL, state, err := m.svc.OIDCBegin(r.Context(), name, m.redirectURL(r, name), next)
	if err != nil {
		m.srv.Logger().Warn("oidc begin", "provider", name, "err", err)
		m.renderLogin(w, r, http.StatusBadGateway, loginData{Next: next, Error: "Single sign-on is unavailable right now."})
		return
	}
	// Bind the flow to this browser: the callback must present this cookie.
	http.SetCookie(w, &http.Cookie{
		Name: oidcStateCookie, Value: state, Path: "/login/oidc/", MaxAge: 600, HttpOnly: true,
		Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (m *module) oidcCallback(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("provider")
	q := r.URL.Query()
	http.SetCookie(w, &http.Cookie{Name: oidcStateCookie, Value: "", Path: "/login/oidc/", MaxAge: -1, HttpOnly: true,
		Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
	fail := func(msg string) {
		m.renderLogin(w, r, http.StatusUnauthorized, loginData{Next: "/", Error: msg})
	}
	if e := q.Get("error"); e != "" {
		fail("The identity provider refused the sign-in.")
		return
	}
	ck, err := r.Cookie(oidcStateCookie)
	state := q.Get("state")
	if err != nil || state == "" || subtle.ConstantTimeCompare([]byte(ck.Value), []byte(state)) != 1 {
		fail("The sign-in request expired or was started in another browser. Try again.")
		return
	}
	au, next, err := m.svc.OIDCComplete(r.Context(), m.meta(r), name, m.redirectURL(r, name), state, q.Get("code"))
	if err != nil {
		if errors.Is(err, auth.ErrNotProvisioned) {
			fail("Your account is not provisioned in PerfectImage. Contact an administrator.")
			return
		}
		m.srv.Logger().Warn("oidc callback", "provider", name, "err", err)
		fail("Single sign-on failed. Try again or contact an administrator.")
		return
	}
	m.startSession(w, r, au, next)
}
