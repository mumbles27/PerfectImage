package authplugin

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/mumbles27/PerfectImage/internal/auth"
	"github.com/mumbles27/PerfectImage/internal/rbac"
)

type accountData struct {
	User          *auth.User
	Principal     *auth.Principal
	Sessions      []auth.Session
	CurrentID     string
	Tokens        []auth.APIToken
	Grantable     []option
	RecoveryLeft  int
	MFARequired   bool
	Enrollment    *auth.Enrollment
	Codes         []string
	NewToken      string
	MinLength     int
	MaxTokenDays  int
	Now           time.Time
	Notice, Error string
}

func (m *module) accountData(r *http.Request) (*accountData, error) {
	ctx := r.Context()
	p := auth.PrincipalFrom(ctx)
	u, err := m.svc.UserByID(ctx, p.ID)
	if err != nil {
		return nil, err
	}
	d := &accountData{User: u, Principal: p, CurrentID: p.SessionID, Grantable: permOptions(p.Permissions, nil),
		MinLength: m.svc.Policy().MinLength, Now: time.Now(), Notice: flash(r)}
	if d.Sessions, err = m.svc.Sessions(ctx, u.ID); err != nil {
		return nil, err
	}
	if d.Tokens, err = m.svc.Tokens(ctx, u.ID); err != nil {
		return nil, err
	}
	if d.RecoveryLeft, err = m.svc.RecoveryCodesLeft(ctx, u.ID); err != nil {
		return nil, err
	}
	if d.MFARequired, err = m.svc.MFARequired(ctx, u); err != nil {
		return nil, err
	}
	d.Enrollment, _ = m.svc.PendingTOTP(u)
	d.MaxTokenDays = int(m.svc.TokenMaxTTL().Hours() / 24)
	return d, nil
}

func (m *module) renderAccount(w http.ResponseWriter, r *http.Request, status int, mutate func(*accountData)) {
	d, err := m.accountData(r)
	if errors.Is(err, auth.ErrUserNotFound) {
		m.srv.Error(w, r, http.StatusNotFound, "This identity has no local account (e.g. auth.dev_allow_all).")
		return
	}
	if err != nil {
		m.srv.Logger().Error("account page", "err", err)
		m.srv.Error(w, r, http.StatusInternalServerError, "Could not load your account.")
		return
	}
	if mutate != nil {
		mutate(d)
	}
	m.render(w, r, status, "account.html", "Account", d)
}

func (m *module) accountPage(w http.ResponseWriter, r *http.Request) {
	m.renderAccount(w, r, http.StatusOK, nil)
}

func (m *module) accountError(w http.ResponseWriter, r *http.Request, err error) {
	m.renderAccount(w, r, http.StatusBadRequest, func(d *accountData) { d.Error = userMessage(err) })
}

func (m *module) currentUser(w http.ResponseWriter, r *http.Request) *auth.User {
	u, err := m.svc.UserByID(r.Context(), auth.PrincipalFrom(r.Context()).ID)
	if err != nil {
		m.srv.Error(w, r, http.StatusInternalServerError, "Could not load your account.")
		return nil
	}
	return u
}

func (m *module) accountPassword(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFrom(r.Context())
	if r.PostFormValue("new_password") != r.PostFormValue("confirm_password") {
		m.renderAccount(w, r, http.StatusBadRequest, func(d *accountData) { d.Error = "The new passwords do not match." })
		return
	}
	if err := m.svc.ChangePassword(r.Context(), m.actor(r), p.ID, r.PostFormValue("current_password"),
		r.PostFormValue("new_password"), p.SessionID); err != nil {
		m.accountError(w, r, err)
		return
	}
	_ = m.svc.RotateCurrent(r.Context(), w, r)
	redirect(w, r, "/account", "password")
}

func (m *module) accountMFABegin(w http.ResponseWriter, r *http.Request) {
	u := m.currentUser(w, r)
	if u == nil {
		return
	}
	if _, err := m.svc.BeginTOTP(r.Context(), u); err != nil {
		m.accountError(w, r, err)
		return
	}
	http.Redirect(w, r, "/account#mfa", http.StatusSeeOther)
}

func (m *module) accountMFAConfirm(w http.ResponseWriter, r *http.Request) {
	u := m.currentUser(w, r)
	if u == nil {
		return
	}
	codes, err := m.svc.ConfirmTOTP(r.Context(), m.actor(r), u, r.PostFormValue("code"))
	if err != nil {
		m.accountError(w, r, err)
		return
	}
	_ = m.svc.RotateCurrent(r.Context(), w, r)
	m.renderAccount(w, r, http.StatusOK, func(d *accountData) {
		d.Codes = codes
		d.Notice = "Two-factor authentication enabled. Store these recovery codes safely; they are shown only once."
	})
}

func (m *module) accountMFADisable(w http.ResponseWriter, r *http.Request) {
	u := m.currentUser(w, r)
	if u == nil {
		return
	}
	if err := m.svc.DisableTOTP(r.Context(), m.actor(r), u, r.PostFormValue("code")); err != nil {
		m.accountError(w, r, err)
		return
	}
	_ = m.svc.RotateCurrent(r.Context(), w, r)
	redirect(w, r, "/account", "mfa-disabled")
}

func (m *module) accountMFARecovery(w http.ResponseWriter, r *http.Request) {
	u := m.currentUser(w, r)
	if u == nil {
		return
	}
	codes, err := m.svc.RegenerateRecoveryCodes(r.Context(), m.actor(r), u, r.PostFormValue("code"))
	if err != nil {
		m.accountError(w, r, err)
		return
	}
	m.renderAccount(w, r, http.StatusOK, func(d *accountData) {
		d.Codes = codes
		d.Notice = "New recovery codes generated; the old ones no longer work."
	})
}

func (m *module) accountTokenCreate(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFrom(r.Context())
	days, err := strconv.Atoi(r.PostFormValue("days"))
	if err != nil || days < 1 {
		m.renderAccount(w, r, http.StatusBadRequest, func(d *accountData) { d.Error = "Choose a lifetime in days." })
		return
	}
	var perms []rbac.Permission
	for _, v := range r.PostForm["permissions"] {
		perms = append(perms, rbac.Permission(v))
	}
	_, raw, err := m.svc.CreateToken(r.Context(), p, m.actor(r), r.PostFormValue("name"), perms,
		time.Duration(days)*24*time.Hour)
	if err != nil {
		m.accountError(w, r, err)
		return
	}
	m.renderAccount(w, r, http.StatusOK, func(d *accountData) {
		d.NewToken = raw
		d.Notice = "Token created. Copy it now; it is shown only once."
	})
}

func (m *module) accountTokenRevoke(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFrom(r.Context())
	if err := m.svc.RevokeToken(r.Context(), m.actor(r), p.ID, r.PathValue("id")); err != nil {
		m.accountError(w, r, err)
		return
	}
	redirect(w, r, "/account#tokens", "revoked")
}

func (m *module) accountSessionRevoke(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFrom(r.Context())
	id := r.PathValue("id")
	if err := m.svc.RevokeSession(r.Context(), m.actor(r), p.ID, id); err != nil {
		m.accountError(w, r, err)
		return
	}
	if id == p.SessionID {
		redirect(w, r, "/login", "")
		return
	}
	redirect(w, r, "/account#sessions", "revoked")
}

func (m *module) accountSessionsRevokeOthers(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFrom(r.Context())
	if _, err := m.svc.RevokeAllSessions(r.Context(), m.actor(r), p.ID, p.SessionID); err != nil {
		m.accountError(w, r, err)
		return
	}
	redirect(w, r, "/account#sessions", "signed-out")
}

func (m *module) accountLogoutAll(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFrom(r.Context())
	if _, err := m.svc.RevokeAllSessions(r.Context(), m.actor(r), p.ID, ""); err != nil {
		m.accountError(w, r, err)
		return
	}
	m.svc.Logout(r.Context(), w, r, m.meta(r))
	redirect(w, r, "/login", "sessions-ended")
}
