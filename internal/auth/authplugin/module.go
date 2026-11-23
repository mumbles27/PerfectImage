package authplugin

import (
	"errors"
	"io/fs"
	"net/http"
	"net/url"
	"strings"

	"github.com/mumbles27/PerfectImage/internal/auth"
	"github.com/mumbles27/PerfectImage/internal/rbac"
	"github.com/mumbles27/PerfectImage/internal/web"
)

type module struct {
	svc       *auth.Service
	srv       *web.Server
	publicURL string
}

func (m *module) Name() string         { return "auth" }
func (m *module) Templates() fs.FS     { return templates() }
func (m *module) Nav() []web.NavItem   { return navItems }
func (m *module) static() http.Handler { return staticHandler() }

var navItems = []web.NavItem{
	{Label: "Users", Path: "/settings/users", Permission: rbac.UsersManage, Order: 71},
	{Label: "Roles", Path: "/settings/roles", Permission: rbac.RolesManage, Order: 72},
	{Label: "SSO", Path: "/settings/sso", Permission: rbac.SettingsManage, Order: 73},
	{Label: "Account", Path: "/account", Order: 90},
}

func staticHandler() http.Handler {
	sub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}
	fsrv := http.StripPrefix("/auth/static/", http.FileServerFS(sub))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		fsrv.ServeHTTP(w, r)
	})
}

func (m *module) Routes(rt *web.Router) {
	rt.HandlePublic("GET /auth/static/", m.static())

	// Sign-in flow (public; each step checks the pending session itself).
	rt.HandlePublic("GET /login", http.HandlerFunc(m.loginPage))
	rt.HandlePublic("POST /login", http.HandlerFunc(m.loginSubmit))
	rt.HandlePublic("GET /login/mfa", http.HandlerFunc(m.mfaPage))
	rt.HandlePublic("POST /login/mfa", http.HandlerFunc(m.mfaSubmit))
	rt.HandlePublic("GET /login/password", http.HandlerFunc(m.forcedPasswordPage))
	rt.HandlePublic("POST /login/password", http.HandlerFunc(m.forcedPasswordSubmit))
	rt.HandlePublic("GET /login/mfa/setup", http.HandlerFunc(m.forcedEnrollPage))
	rt.HandlePublic("POST /login/mfa/setup", http.HandlerFunc(m.forcedEnrollSubmit))
	rt.HandlePublic("GET /login/oidc/{provider}", http.HandlerFunc(m.oidcStart))
	rt.HandlePublic("GET /login/oidc/{provider}/callback", http.HandlerFunc(m.oidcCallback))
	rt.HandlePublic("POST /logout", http.HandlerFunc(m.logout))

	// Own account (any signed-in user).
	rt.HandleFunc("GET /account", "", m.accountPage)
	rt.HandleFunc("POST /account/password", "", m.sessionOnly(m.accountPassword))
	rt.HandleFunc("POST /account/mfa/begin", "", m.sessionOnly(m.accountMFABegin))
	rt.HandleFunc("POST /account/mfa/confirm", "", m.sessionOnly(m.accountMFAConfirm))
	rt.HandleFunc("POST /account/mfa/disable", "", m.sessionOnly(m.accountMFADisable))
	rt.HandleFunc("POST /account/mfa/recovery", "", m.sessionOnly(m.accountMFARecovery))
	rt.HandleFunc("POST /account/tokens", "", m.sessionOnly(m.accountTokenCreate))
	rt.HandleFunc("POST /account/tokens/{id}/revoke", "", m.sessionOnly(m.accountTokenRevoke))
	rt.HandleFunc("POST /account/sessions/{id}/revoke", "", m.sessionOnly(m.accountSessionRevoke))
	rt.HandleFunc("POST /account/sessions/revoke-others", "", m.sessionOnly(m.accountSessionsRevokeOthers))
	rt.HandleFunc("POST /account/logout-all", "", m.sessionOnly(m.accountLogoutAll))

	// User administration.
	rt.HandleFunc("GET /settings/users", rbac.UsersManage, m.usersPage)
	rt.HandleFunc("POST /settings/users", rbac.UsersManage, m.sessionOnly(m.userCreate))
	rt.HandleFunc("GET /settings/users/{id}", rbac.UsersManage, m.userPage)
	rt.HandleFunc("POST /settings/users/{id}", rbac.UsersManage, m.sessionOnly(m.userUpdate))
	rt.HandleFunc("POST /settings/users/{id}/{action}", rbac.UsersManage, m.sessionOnly(m.userAction))

	// Roles.
	rt.HandleFunc("GET /settings/roles", rbac.RolesManage, m.rolesPage)
	rt.HandleFunc("POST /settings/roles", rbac.RolesManage, m.sessionOnly(m.roleCreate))
	rt.HandleFunc("GET /settings/roles/{name}", rbac.RolesManage, m.rolePage)
	rt.HandleFunc("POST /settings/roles/{name}", rbac.RolesManage, m.sessionOnly(m.roleUpdate))
	rt.HandleFunc("POST /settings/roles/{name}/delete", rbac.RolesManage, m.sessionOnly(m.roleDelete))

	// SSO configuration.
	rt.HandleFunc("GET /settings/sso", rbac.SettingsManage, m.ssoPage)
	rt.HandleFunc("POST /settings/sso/oidc", rbac.SettingsManage, m.sessionOnly(m.oidcSave))
	rt.HandleFunc("POST /settings/sso/oidc/{name}/delete", rbac.SettingsManage, m.sessionOnly(m.oidcDelete))
	rt.HandleFunc("POST /settings/sso/oidc/{name}/test", rbac.SettingsManage, m.sessionOnly(m.oidcTest))
	rt.HandleFunc("POST /settings/sso/ldap", rbac.SettingsManage, m.sessionOnly(m.ldapSave))
	rt.HandleFunc("POST /settings/sso/ldap/test", rbac.SettingsManage, m.sessionOnly(m.ldapTest))
}

// sessionOnly refuses API-token principals for interactive account and
// administration changes (tokens cannot mint tokens, change passwords, ...).
func (m *module) sessionOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if p := auth.PrincipalFrom(r.Context()); p == nil || p.AuthMethod == "token" {
			m.srv.Error(w, r, http.StatusForbidden, "This action requires an interactive session.")
			return
		}
		h(w, r)
	}
}

func (m *module) meta(r *http.Request) auth.RequestMeta {
	return auth.MetaFrom(r, web.RequestIDFrom(r.Context()))
}

func (m *module) actor(r *http.Request) auth.Actor {
	return auth.ActorFrom(auth.PrincipalFrom(r.Context()), m.meta(r))
}

func (m *module) render(w http.ResponseWriter, r *http.Request, status int, name, title string, data any) {
	m.srv.Render(w, r, status, "auth/"+name, title, data)
}

// redirect sends a 303 to path with an optional flash message key.
func redirect(w http.ResponseWriter, r *http.Request, path, msg string) {
	if msg != "" {
		frag := ""
		if i := strings.IndexByte(path, '#'); i >= 0 {
			path, frag = path[:i], path[i:]
		}
		sep := "?"
		if strings.Contains(path, "?") {
			sep = "&"
		}
		path += sep + "msg=" + url.QueryEscape(msg) + frag
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}

// flashes maps message keys (from ?msg=) to text, so arbitrary text can't be
// injected through the URL.
var flashes = map[string]string{
	"saved":          "Changes saved.",
	"created":        "Created.",
	"deleted":        "Deleted.",
	"unlocked":       "Account unlocked.",
	"disabled":       "Account disabled and signed out.",
	"enabled":        "Account enabled.",
	"mfa-reset":      "MFA reset; the user must enroll again.",
	"revoked":        "Revoked.",
	"signed-out":     "Other sessions signed out.",
	"password":       "Password changed. Other sessions were signed out.",
	"mfa-disabled":   "Two-factor authentication disabled.",
	"sessions-ended": "All sessions were signed out.",
}

func flash(r *http.Request) string { return flashes[r.URL.Query().Get("msg")] }

// userMessage turns a service error into text safe to show.
func userMessage(err error) string {
	var pe *auth.PolicyError
	switch {
	case errors.As(err, &pe):
		return "Password " + pe.Reason + "."
	case errors.Is(err, auth.ErrEscalation):
		return "You cannot grant permissions you do not hold yourself."
	case errors.Is(err, auth.ErrLastAdmin):
		return "At least one enabled user must keep the Admin role."
	case errors.Is(err, auth.ErrSelf):
		return "You cannot do this to your own account."
	case errors.Is(err, auth.ErrRoleBuiltin):
		return "Built-in roles cannot be changed or deleted."
	case errors.Is(err, auth.ErrRoleExists):
		return "A role with that name already exists."
	case errors.Is(err, auth.ErrUserExists):
		return "That username is already taken."
	case errors.Is(err, auth.ErrInvalidCredentials):
		return "The current password is incorrect."
	case errors.Is(err, auth.ErrMFAInvalid):
		return "The verification code is not valid."
	case errors.Is(err, auth.ErrMFARequired):
		return "Two-factor authentication is required for your role and cannot be disabled."
	case errors.Is(err, auth.ErrRateLimited):
		return "Too many attempts. Wait a minute and try again."
	case errors.Is(err, auth.ErrAccountLocked):
		return "The account is temporarily locked."
	case errors.Is(err, auth.ErrNotLocal):
		return "This account is managed by an external identity provider."
	case errors.Is(err, auth.ErrTokenScope):
		return "Choose at least one permission you hold."
	case errors.Is(err, auth.ErrInvalidName), errors.Is(err, auth.ErrRoleNotFound):
		return strings.TrimPrefix(err.Error(), "auth: ")
	}
	msg := err.Error()
	if strings.HasPrefix(msg, "auth: ") {
		return strings.TrimPrefix(msg, "auth: ")
	}
	return "The operation failed. See the service log for details."
}

// redirectURL returns the OIDC callback URL for provider.
func (m *module) redirectURL(r *http.Request, provider string) string {
	base := strings.TrimRight(m.publicURL, "/")
	if base == "" {
		scheme := "https"
		if r.TLS == nil {
			scheme = "http"
		}
		base = scheme + "://" + r.Host
	}
	return base + "/login/oidc/" + url.PathEscape(provider) + "/callback"
}
