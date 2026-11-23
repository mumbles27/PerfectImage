package authplugin

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mumbles27/PerfectImage/internal/auth"
)

type providerView struct {
	auth.OIDCProvider
	Scopes       string
	RoleMap      string
	DefaultRoles string
	CallbackURL  string
}

type ssoData struct {
	Providers     []providerView
	NewCallback   string
	LDAP          *auth.LDAPConfig
	LDAPRoleMap   string
	LDAPDefaults  string
	LDAPTimeout   int
	Notice, Error string
}

func (m *module) renderSSO(w http.ResponseWriter, r *http.Request, status int, errMsg string) {
	ctx := r.Context()
	provs, err := m.svc.OIDCProviders(ctx, false)
	var ldapCfg *auth.LDAPConfig
	if err == nil {
		ldapCfg, err = m.svc.LDAPConfig(ctx)
	}
	if err != nil {
		m.srv.Logger().Error("sso page", "err", err)
		m.srv.Error(w, r, http.StatusInternalServerError, "Could not load SSO settings.")
		return
	}
	d := ssoData{
		NewCallback: m.redirectURL(r, "<name>"), LDAP: ldapCfg, LDAPRoleMap: formatRoleMap(ldapCfg.RoleMap),
		LDAPDefaults: strings.Join(ldapCfg.DefaultRoles, ", "), LDAPTimeout: int(ldapCfg.Timeout / time.Second),
		Notice: flash(r), Error: errMsg,
	}
	for _, p := range provs {
		d.Providers = append(d.Providers, providerView{
			OIDCProvider: p, Scopes: strings.Join(p.Scopes, " "), RoleMap: formatRoleMap(p.RoleMap),
			DefaultRoles: strings.Join(p.DefaultRoles, ", "), CallbackURL: m.redirectURL(r, p.Name),
		})
	}
	m.render(w, r, status, "sso.html", "Single sign-on", d)
}

func (m *module) ssoPage(w http.ResponseWriter, r *http.Request) {
	m.renderSSO(w, r, http.StatusOK, "")
}

// formatRoleMap renders a role map as "group => Role, Role" lines.
func formatRoleMap(rm map[string][]string) string {
	keys := make([]string, 0, len(rm))
	for k := range rm {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var b strings.Builder
	for _, k := range keys {
		fmt.Fprintf(&b, "%s => %s\n", k, strings.Join(rm[k], ", "))
	}
	return b.String()
}

// parseRoleMap parses "group => Role, Role" lines (group values may contain
// "=" and "," as in LDAP DNs; the last "=>" separates).
func parseRoleMap(s string) (map[string][]string, error) {
	out := map[string][]string{}
	for i, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.LastIndex(line, "=>")
		if idx < 0 {
			return nil, fmt.Errorf("role mapping line %d: expected \"group => Role, Role\"", i+1)
		}
		group := strings.TrimSpace(line[:idx])
		roles := splitList(line[idx+2:])
		if group == "" || len(roles) == 0 {
			return nil, fmt.Errorf("role mapping line %d: group and at least one role are required", i+1)
		}
		out[group] = append(out[group], roles...)
	}
	return out, nil
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

func (m *module) oidcSave(w http.ResponseWriter, r *http.Request) {
	rm, err := parseRoleMap(r.PostFormValue("role_map"))
	if err != nil {
		m.renderSSO(w, r, http.StatusBadRequest, err.Error())
		return
	}
	p := auth.OIDCProvider{
		Name: r.PostFormValue("name"), DisplayName: r.PostFormValue("display_name"),
		Issuer: strings.TrimSpace(r.PostFormValue("issuer")), ClientID: r.PostFormValue("client_id"),
		ClientSecret: r.PostFormValue("client_secret"), Scopes: strings.Fields(r.PostFormValue("scopes")),
		GroupsClaim: strings.TrimSpace(r.PostFormValue("groups_claim")), RoleMap: rm,
		DefaultRoles: splitList(r.PostFormValue("default_roles")),
		JIT:          r.PostFormValue("jit") != "", Enabled: r.PostFormValue("enabled") != "",
	}
	if err := m.svc.SaveOIDCProvider(r.Context(), m.actor(r), p); err != nil {
		m.renderSSO(w, r, http.StatusBadRequest, userMessage(err))
		return
	}
	redirect(w, r, "/settings/sso", "saved")
}

func (m *module) oidcDelete(w http.ResponseWriter, r *http.Request) {
	if err := m.svc.DeleteOIDCProvider(r.Context(), m.actor(r), r.PathValue("name")); err != nil {
		m.renderSSO(w, r, http.StatusBadRequest, userMessage(err))
		return
	}
	redirect(w, r, "/settings/sso", "deleted")
}

type testResult struct {
	OK      bool
	Message string
}

func (m *module) renderTest(w http.ResponseWriter, r *http.Request, res testResult) {
	m.srv.RenderPartial(w, r, "auth/sso.html", "test-result", res)
}

func (m *module) oidcTest(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := m.svc.TestOIDC(ctx, m.actor(r), r.PathValue("name")); err != nil {
		m.renderTest(w, r, testResult{Message: "Discovery failed: " + errText(err)})
		return
	}
	m.renderTest(w, r, testResult{OK: true, Message: "Discovery document and keys endpoint reachable."})
}

func (m *module) ldapSave(w http.ResponseWriter, r *http.Request) {
	rm, err := parseRoleMap(r.PostFormValue("role_map"))
	if err != nil {
		m.renderSSO(w, r, http.StatusBadRequest, err.Error())
		return
	}
	timeout, _ := strconv.Atoi(r.PostFormValue("timeout"))
	c := auth.LDAPConfig{
		Enabled: r.PostFormValue("enabled") != "", URL: strings.TrimSpace(r.PostFormValue("url")),
		StartTLS: r.PostFormValue("start_tls") != "", CAPEM: strings.TrimSpace(r.PostFormValue("ca_pem")),
		ServerName: strings.TrimSpace(r.PostFormValue("server_name")),
		BindDN:     strings.TrimSpace(r.PostFormValue("bind_dn")), BindPassword: r.PostFormValue("bind_password"),
		UserBaseDN: strings.TrimSpace(r.PostFormValue("user_base_dn")), UserFilter: strings.TrimSpace(r.PostFormValue("user_filter")),
		UsernameAttr: strings.TrimSpace(r.PostFormValue("username_attr")), DisplayNameAttr: strings.TrimSpace(r.PostFormValue("display_name_attr")),
		EmailAttr: strings.TrimSpace(r.PostFormValue("email_attr")), GroupBaseDN: strings.TrimSpace(r.PostFormValue("group_base_dn")),
		GroupFilter: strings.TrimSpace(r.PostFormValue("group_filter")), ADMatchingRule: r.PostFormValue("ad_matching_rule") != "",
		RoleMap: rm, DefaultRoles: splitList(r.PostFormValue("default_roles")), Timeout: time.Duration(timeout) * time.Second,
	}
	if err := m.svc.SaveLDAPConfig(r.Context(), m.actor(r), c, r.PostFormValue("clear_password") != ""); err != nil {
		m.renderSSO(w, r, http.StatusBadRequest, userMessage(err))
		return
	}
	redirect(w, r, "/settings/sso#ldap", "saved")
}

func (m *module) ldapTest(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	summary, err := m.svc.TestLDAP(ctx, m.actor(r), strings.TrimSpace(r.PostFormValue("test_username")))
	if err != nil {
		m.renderTest(w, r, testResult{Message: "LDAP test failed: " + errText(err)})
		return
	}
	m.renderTest(w, r, testResult{OK: true, Message: summary})
}

// errText shows connection errors to administrators (they contain no
// secrets: bind passwords and client secrets are never part of errors).
func errText(err error) string {
	if errors.Is(err, auth.ErrInvalidCredentials) {
		return "user not found (or not unique)"
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err.Error()
	}
	return strings.TrimPrefix(err.Error(), "auth: ")
}
