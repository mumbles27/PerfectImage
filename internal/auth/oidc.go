package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/secrets"
)

// OIDCProvider is a configured OpenID Connect identity provider.
type OIDCProvider struct {
	Name        string // URL slug
	DisplayName string
	Issuer      string
	ClientID    string
	// ClientSecret is only populated when saving; loaded providers carry
	// HasSecret instead.
	ClientSecret string
	HasSecret    bool
	Scopes       []string
	GroupsClaim  string
	// RoleMap maps an IdP group value to PerfectImage roles.
	RoleMap      map[string][]string
	DefaultRoles []string
	// JIT provisions unknown users at first sign-in.
	JIT     bool
	Enabled bool
}

// OIDC errors.
var (
	ErrProviderNotFound = errors.New("auth: identity provider not found")
	ErrOIDCState        = errors.New("auth: invalid or expired sign-in state")
	ErrNotProvisioned   = errors.New("auth: no matching account and just-in-time provisioning is disabled")
)

var slugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

const oidcStateTTL = 10 * time.Minute

func secretAAD(name string) string {
	return "auth_oidc_providers.client_secret:" + strings.ToLower(name)
}

// OIDCProviders lists configured providers (secrets omitted).
func (s *Service) OIDCProviders(ctx context.Context, enabledOnly bool) ([]OIDCProvider, error) {
	q := `SELECT name, display_name, issuer, client_id, client_secret, scopes, groups_claim, role_map, default_roles, jit, enabled
		FROM auth_oidc_providers`
	if enabledOnly {
		q += ` WHERE enabled = 1`
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY display_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OIDCProvider
	for rows.Next() {
		p, _, err := scanProvider(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

func scanProvider(sc scanner) (*OIDCProvider, string, error) {
	var p OIDCProvider
	var sealed, scopes, roleMap, defRoles string
	err := sc.Scan(&p.Name, &p.DisplayName, &p.Issuer, &p.ClientID, &sealed, &scopes, &p.GroupsClaim,
		&roleMap, &defRoles, &p.JIT, &p.Enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, "", ErrProviderNotFound
	}
	if err != nil {
		return nil, "", err
	}
	p.HasSecret = sealed != ""
	_ = json.Unmarshal([]byte(scopes), &p.Scopes)
	_ = json.Unmarshal([]byte(roleMap), &p.RoleMap)
	_ = json.Unmarshal([]byte(defRoles), &p.DefaultRoles)
	return &p, sealed, nil
}

// OIDCProvider loads one provider including its decrypted client secret.
func (s *Service) OIDCProvider(ctx context.Context, name string) (*OIDCProvider, error) {
	p, sealed, err := scanProvider(s.db.QueryRowContext(ctx, `SELECT name, display_name, issuer, client_id, client_secret,
		scopes, groups_claim, role_map, default_roles, jit, enabled FROM auth_oidc_providers WHERE name = ?`, name))
	if err != nil {
		return nil, err
	}
	if sealed != "" {
		if s.sealer == nil {
			return nil, ErrNoSealer
		}
		if p.ClientSecret, err = secrets.DecryptString(s.sealer, sealed, secretAAD(p.Name)); err != nil {
			return nil, fmt.Errorf("auth: decrypt client secret for %s: %w", p.Name, err)
		}
	}
	return p, nil
}

// SaveOIDCProvider creates or updates a provider. An empty ClientSecret on
// update keeps the stored one.
func (s *Service) SaveOIDCProvider(ctx context.Context, a Actor, p OIDCProvider) error {
	p.Name = strings.ToLower(strings.TrimSpace(p.Name))
	if !slugRE.MatchString(p.Name) {
		return fmt.Errorf("%w: provider names are 1-32 lowercase letters, digits and dashes", ErrInvalidName)
	}
	u, err := url.Parse(p.Issuer)
	if err != nil || u.Host == "" || (u.Scheme != "https" && !(u.Scheme == "http" && isLoopbackHost(u.Hostname()))) {
		return errors.New("auth: issuer must be an https:// URL")
	}
	if strings.TrimSpace(p.ClientID) == "" {
		return errors.New("auth: client ID is required")
	}
	if p.DisplayName == "" {
		p.DisplayName = p.Name
	}
	if p.GroupsClaim == "" {
		p.GroupsClaim = "groups"
	}
	if !slices.Contains(p.Scopes, oidc.ScopeOpenID) {
		p.Scopes = append([]string{oidc.ScopeOpenID}, p.Scopes...)
	}
	if err := s.checkRoleNames(ctx, p.RoleMap, p.DefaultRoles); err != nil {
		return err
	}
	scopes, _ := json.Marshal(p.Scopes)
	roleMap, _ := json.Marshal(nonNilMap(p.RoleMap))
	defRoles, _ := json.Marshal(nonNilSlice(p.DefaultRoles))
	now := s.ms(s.now())
	var sealed string
	if p.ClientSecret != "" {
		if s.sealer == nil {
			return ErrNoSealer
		}
		if sealed, err = secrets.EncryptString(s.sealer, p.ClientSecret, secretAAD(p.Name)); err != nil {
			return err
		}
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO auth_oidc_providers (name, display_name, issuer, client_id, client_secret,
		scopes, groups_claim, role_map, default_roles, jit, enabled, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET display_name = excluded.display_name, issuer = excluded.issuer,
			client_id = excluded.client_id,
			client_secret = CASE WHEN excluded.client_secret = '' THEN client_secret ELSE excluded.client_secret END,
			scopes = excluded.scopes, groups_claim = excluded.groups_claim, role_map = excluded.role_map,
			default_roles = excluded.default_roles, jit = excluded.jit, enabled = excluded.enabled,
			updated_at = excluded.updated_at`,
		p.Name, strings.TrimSpace(p.DisplayName), strings.TrimRight(strings.TrimSpace(p.Issuer), "/"),
		strings.TrimSpace(p.ClientID), sealed, string(scopes), p.GroupsClaim, string(roleMap), string(defRoles),
		p.JIT, p.Enabled, now, now)
	if err != nil {
		s.record(ctx, a, "sso.oidc.save", "oidc:"+p.Name, audit.OutcomeFailure, err.Error(), nil)
		return err
	}
	s.record(ctx, a, "sso.oidc.save", "oidc:"+p.Name, audit.OutcomeSuccess, "", map[string]any{
		"issuer": p.Issuer, "client_id": p.ClientID, "secret_changed": p.ClientSecret != "", "enabled": p.Enabled,
		"jit": p.JIT, "role_map": p.RoleMap, "default_roles": p.DefaultRoles,
	})
	return nil
}

// DeleteOIDCProvider removes a provider and its identity links.
func (s *Service) DeleteOIDCProvider(ctx context.Context, a Actor, name string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM auth_oidc_providers WHERE name = ?`, name)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrProviderNotFound
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM auth_identities WHERE provider = ?`, SourceOIDCPrefix+strings.ToLower(name))
	s.record(ctx, a, "sso.oidc.delete", "oidc:"+name, audit.OutcomeSuccess, "", nil)
	return nil
}

func (s *Service) checkRoleNames(ctx context.Context, roleMap map[string][]string, defaults []string) error {
	all := slices.Clone(defaults)
	for _, rs := range roleMap {
		all = append(all, rs...)
	}
	_, unknown, err := s.canonicalRoles(ctx, all)
	if err != nil {
		return err
	}
	if len(unknown) > 0 {
		return fmt.Errorf("%w: %s", ErrRoleNotFound, strings.Join(unknown, ", "))
	}
	return nil
}

func (s *Service) oidcContext(ctx context.Context) context.Context {
	return oidc.ClientContext(ctx, s.http)
}

func (s *Service) oauthConfig(ctx context.Context, p *OIDCProvider, redirectURL string) (*oidc.Provider, *oauth2.Config, error) {
	prov, err := oidc.NewProvider(s.oidcContext(ctx), p.Issuer)
	if err != nil {
		return nil, nil, fmt.Errorf("auth: oidc discovery for %s: %w", p.Name, err)
	}
	return prov, &oauth2.Config{
		ClientID: p.ClientID, ClientSecret: p.ClientSecret, Endpoint: prov.Endpoint(),
		RedirectURL: redirectURL, Scopes: p.Scopes,
	}, nil
}

// TestOIDC runs discovery against the provider's issuer.
func (s *Service) TestOIDC(ctx context.Context, a Actor, name string) error {
	p, err := s.OIDCProvider(ctx, name)
	if err != nil {
		return err
	}
	_, _, err = s.oauthConfig(ctx, p, "")
	outcome, reason := audit.OutcomeSuccess, ""
	if err != nil {
		outcome, reason = audit.OutcomeFailure, err.Error()
	}
	s.record(ctx, a, "sso.oidc.test", "oidc:"+name, outcome, reason, nil)
	return err
}

// OIDCBegin starts an authorization-code flow with PKCE (S256), state and
// nonce. It returns the IdP URL to redirect to and the state value, which
// the caller must also bind to the browser (cookie) and compare on return.
func (s *Service) OIDCBegin(ctx context.Context, name, redirectURL, next string) (authURL, state string, err error) {
	p, err := s.OIDCProvider(ctx, name)
	if err != nil {
		return "", "", err
	}
	if !p.Enabled {
		return "", "", ErrProviderNotFound
	}
	_, oc, err := s.oauthConfig(ctx, p, redirectURL)
	if err != nil {
		return "", "", err
	}
	state, nonce, verifier := randToken(32), randToken(32), oauth2.GenerateVerifier()
	if _, err := s.db.ExecContext(ctx, `INSERT INTO auth_oidc_states (state_hash, provider, nonce, verifier, next, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`, sha256Hex(state), p.Name, nonce, verifier, SafeNext(next),
		s.ms(s.now().Add(oidcStateTTL))); err != nil {
		return "", "", err
	}
	return oc.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), state, nil
}

// OIDCClaims are the identity attributes taken from the ID token.
type OIDCClaims struct {
	Subject           string `json:"sub"`
	Email             string `json:"email"`
	EmailVerified     *bool  `json:"email_verified"`
	PreferredUsername string `json:"preferred_username"`
	Name              string `json:"name"`
	Groups            []string
}

// OIDCComplete validates the callback (state, code exchange with PKCE, ID
// token signature/issuer/audience/expiry and nonce), then finds or
// provisions the user and syncs their roles from group claims. It returns
// the authenticated user and the post-login redirect target.
func (s *Service) OIDCComplete(ctx context.Context, meta RequestMeta, name, redirectURL, state, code string) (*Authenticated, string, error) {
	a := Actor{Username: "oidc:" + name, Meta: meta}
	fail := func(reason string, err error) (*Authenticated, string, error) {
		s.record(ctx, a, "auth.login", "oidc:"+name, audit.OutcomeFailure, reason, map[string]any{"method": "oidc"})
		return nil, "", err
	}
	if !s.ipLimit.Allow("ip:" + meta.IP) {
		return fail("rate limited", ErrRateLimited)
	}
	var provName, nonce, verifier, next string
	var exp int64
	err := s.db.QueryRowContext(ctx, `DELETE FROM auth_oidc_states WHERE state_hash = ?
		RETURNING provider, nonce, verifier, next, expires_at`, sha256Hex(state)).Scan(&provName, &nonce, &verifier, &next, &exp)
	if err != nil || !strings.EqualFold(provName, name) || s.now().After(fromMS(exp)) {
		return fail("invalid state", ErrOIDCState)
	}
	p, err := s.OIDCProvider(ctx, provName)
	if err != nil || !p.Enabled {
		return fail("provider unavailable", ErrProviderNotFound)
	}
	prov, oc, err := s.oauthConfig(ctx, p, redirectURL)
	if err != nil {
		return fail(err.Error(), err)
	}
	octx := s.oidcContext(ctx)
	tok, err := oc.Exchange(octx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return fail("code exchange failed", fmt.Errorf("auth: oidc code exchange: %w", err))
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return fail("no id_token", errors.New("auth: oidc response lacks id_token"))
	}
	idt, err := prov.VerifierContext(octx, &oidc.Config{ClientID: p.ClientID}).Verify(octx, rawID)
	if err != nil {
		return fail("id_token invalid", fmt.Errorf("auth: verify id_token: %w", err))
	}
	if idt.Nonce == "" || idt.Nonce != nonce {
		return fail("nonce mismatch", errors.New("auth: id_token nonce mismatch"))
	}
	claims, err := extractClaims(idt, p.GroupsClaim)
	if err != nil {
		return fail("bad claims", err)
	}
	u, err := s.provisionExternal(ctx, a, SourceOIDCPrefix+p.Name, externalIdentity{
		Subject: claims.Subject, Username: oidcUsername(claims), DisplayName: claims.Name, Email: claims.Email,
		Groups: claims.Groups, RoleMap: p.RoleMap, DefaultRoles: p.DefaultRoles, JIT: p.JIT,
	})
	if err != nil {
		return fail(err.Error(), err)
	}
	if u.Disabled {
		return fail("account disabled", ErrAccountDisabled)
	}
	s.loginSucceeded(ctx, u)
	s.record(ctx, Actor{ID: u.ID, Username: u.Username, Meta: meta}, "auth.login", "user:"+u.Username,
		audit.OutcomeSuccess, "", map[string]any{"method": "oidc", "provider": p.Name, "groups": claims.Groups})
	return &Authenticated{User: u, Method: "oidc:" + p.Name}, next, nil
}

func extractClaims(idt *oidc.IDToken, groupsClaim string) (*OIDCClaims, error) {
	var c OIDCClaims
	if err := idt.Claims(&c); err != nil {
		return nil, err
	}
	c.Subject = idt.Subject
	var raw map[string]any
	if err := idt.Claims(&raw); err != nil {
		return nil, err
	}
	switch g := raw[groupsClaim].(type) {
	case []any:
		for _, v := range g {
			if s, ok := v.(string); ok {
				c.Groups = append(c.Groups, s)
			}
		}
	case string:
		c.Groups = []string{g}
	}
	return &c, nil
}

func oidcUsername(c *OIDCClaims) string {
	for _, cand := range []string{c.PreferredUsername, c.Email} {
		if cand != "" && ValidUsername(cand) {
			return cand
		}
	}
	return ""
}

// externalIdentity is a user asserted by an IdP (OIDC or LDAP).
type externalIdentity struct {
	Subject, Username, DisplayName, Email string
	Groups                                []string
	RoleMap                               map[string][]string
	DefaultRoles                          []string
	JIT                                   bool
}

// mapRoles resolves group memberships to role names (case-insensitive
// group match), plus defaults.
func mapRoles(groups []string, roleMap map[string][]string, defaults []string) []string {
	out := slices.Clone(defaults)
	for g, roles := range roleMap {
		if slices.ContainsFunc(groups, func(x string) bool { return strings.EqualFold(x, g) }) {
			out = append(out, roles...)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// provisionExternal finds the user linked to (source, subject), creating it
// when JIT is enabled, and syncs profile and roles from the IdP.
func (s *Service) provisionExternal(ctx context.Context, a Actor, source string, id externalIdentity) (*User, error) {
	if id.Subject == "" {
		return nil, errors.New("auth: identity has no subject")
	}
	roles, unknown, err := s.canonicalRoles(ctx, mapRoles(id.Groups, id.RoleMap, id.DefaultRoles))
	if err != nil {
		return nil, err
	}
	if len(unknown) > 0 {
		s.log.Warn("sso role mapping references unknown roles", "source", source, "roles", unknown)
	}
	var userID string
	err = s.db.QueryRowContext(ctx, `SELECT user_id FROM auth_identities WHERE provider = ? AND subject = ?`, source, id.Subject).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		if !id.JIT {
			return nil, ErrNotProvisioned
		}
		username := id.Username
		if username == "" {
			username = "user-" + sha256Hex(source + "|" + id.Subject)[:12]
		}
		// Never attach to an existing account with the same name: that would
		// let an IdP take over a local account.
		if _, err := s.UserByUsername(ctx, username); err == nil {
			username = username + "-" + sha256Hex(source + "|" + id.Subject)[:6]
		}
		now := s.ms(s.now())
		userID = newID()
		err = s.db.Tx(ctx, func(tx *sql.Tx) error {
			if _, err := tx.ExecContext(ctx, `INSERT INTO auth_users (id, username, display_name, email, source, created_at, updated_at)
				VALUES (?, ?, ?, ?, ?, ?, ?)`, userID, username, id.DisplayName, id.Email, source, now, now); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO auth_identities (provider, subject, user_id) VALUES (?, ?, ?)`,
				source, id.Subject, userID); err != nil {
				return err
			}
			_, err := s.setUserRolesTx(ctx, tx, userID, roles)
			return err
		})
		if err != nil {
			return nil, err
		}
		s.record(ctx, a, "user.provision", "user:"+username, audit.OutcomeSuccess, "",
			map[string]any{"source": source, "roles": roles})
		return s.UserByID(ctx, userID)
	}
	if err != nil {
		return nil, err
	}
	var changed bool
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE auth_users SET display_name = CASE WHEN ? <> '' THEN ? ELSE display_name END,
			email = CASE WHEN ? <> '' THEN ? ELSE email END, updated_at = ? WHERE id = ?`,
			id.DisplayName, id.DisplayName, id.Email, id.Email, s.ms(s.now()), userID); err != nil {
			return err
		}
		changed, err = s.setUserRolesTx(ctx, tx, userID, roles)
		return err
	})
	if err != nil {
		return nil, err
	}
	u, err := s.UserByID(ctx, userID)
	if err == nil && changed {
		s.record(ctx, a, "user.roles.sync", "user:"+u.Username, audit.OutcomeSuccess, "",
			map[string]any{"source": source, "roles": roles})
	}
	return u, err
}

// SafeNext returns next if it is a local absolute path, else "/".
func SafeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") ||
		strings.ContainsAny(next, "\r\n") {
		return "/"
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" || strings.HasPrefix(u.Path, "/login") {
		return "/"
	}
	return next
}

func isLoopbackHost(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

func nonNilMap(m map[string][]string) map[string][]string {
	if m == nil {
		return map[string][]string{}
	}
	return m
}

func nonNilSlice(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
