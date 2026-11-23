package auth

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/secrets"
)

// LDAPConfig configures LDAP/Active Directory authentication
// (search-then-bind). It is stored in auth_ldap_config; BindPassword is
// sealed separately and never serialized with the rest.
type LDAPConfig struct {
	Enabled bool `json:"enabled"`
	// URL is ldaps://host:636 or ldap://host:389 (the latter requires
	// StartTLS).
	URL      string `json:"url"`
	StartTLS bool   `json:"start_tls"`
	// CAPEM optionally pins the CA bundle used to verify the server.
	CAPEM string `json:"ca_pem"`
	// ServerName overrides the TLS server name (defaults to the URL host).
	ServerName string `json:"server_name"`

	BindDN       string `json:"bind_dn"`
	BindPassword string `json:"-"`
	HasPassword  bool   `json:"-"`

	UserBaseDN string `json:"user_base_dn"`
	// UserFilter must contain {username}, e.g.
	// (&(objectClass=user)(sAMAccountName={username})).
	UserFilter      string `json:"user_filter"`
	UsernameAttr    string `json:"username_attr"`
	DisplayNameAttr string `json:"display_name_attr"`
	EmailAttr       string `json:"email_attr"`

	GroupBaseDN string `json:"group_base_dn"`
	// GroupFilter selects group objects, e.g. (objectClass=group).
	GroupFilter string `json:"group_filter"`
	// ADMatchingRule resolves nested groups in one query with
	// LDAP_MATCHING_RULE_IN_CHAIN (Active Directory only); otherwise nested
	// groups are resolved by iterative member searches.
	ADMatchingRule bool `json:"ad_matching_rule"`
	// RoleMap maps group DNs or CNs (case-insensitive) to roles.
	RoleMap      map[string][]string `json:"role_map"`
	DefaultRoles []string            `json:"default_roles"`
	// Timeout bounds dialing and each LDAP operation.
	Timeout time.Duration `json:"timeout"`
}

// maxGroupDepth bounds nested-group resolution.
const maxGroupDepth = 8

// LDAPConn is the subset of *ldap.Conn used by the service (fakeable).
type LDAPConn interface {
	Bind(username, password string) error
	Search(req *ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
}

// LDAPDialer opens an authenticated-transport (TLS) connection.
type LDAPDialer func(ctx context.Context, cfg *LDAPConfig) (LDAPConn, error)

const ldapAAD = "auth_ldap_config.bind_password"

// ErrLDAPDisabled is returned when LDAP is not configured.
var ErrLDAPDisabled = errors.New("auth: LDAP is not configured")

func (c *LDAPConfig) applyDefaults() {
	if c.UserFilter == "" {
		c.UserFilter = "(&(objectClass=person)(uid={username}))"
	}
	if c.UsernameAttr == "" {
		c.UsernameAttr = "uid"
	}
	if c.DisplayNameAttr == "" {
		c.DisplayNameAttr = "displayName"
	}
	if c.EmailAttr == "" {
		c.EmailAttr = "mail"
	}
	if c.GroupFilter == "" {
		c.GroupFilter = "(|(objectClass=group)(objectClass=groupOfNames))"
	}
	if c.Timeout <= 0 {
		c.Timeout = 10 * time.Second
	}
}

// Validate checks the configuration.
func (c *LDAPConfig) Validate() error {
	u, err := url.Parse(c.URL)
	if err != nil || u.Host == "" {
		return errors.New("auth: LDAP URL must look like ldaps://dc.example.com:636")
	}
	switch u.Scheme {
	case "ldaps":
		if c.StartTLS {
			return errors.New("auth: StartTLS is not used with ldaps://")
		}
	case "ldap":
		if !c.StartTLS {
			return errors.New("auth: plain ldap:// requires StartTLS (credentials are never sent in clear text)")
		}
	default:
		return errors.New("auth: LDAP URL scheme must be ldaps or ldap")
	}
	if c.CAPEM != "" {
		if ok := x509.NewCertPool().AppendCertsFromPEM([]byte(c.CAPEM)); !ok {
			return errors.New("auth: CA certificate is not valid PEM")
		}
	}
	if !strings.Contains(c.UserFilter, "{username}") {
		return errors.New("auth: user filter must contain {username}")
	}
	if c.UserBaseDN == "" {
		return errors.New("auth: user base DN is required")
	}
	if c.Timeout > 2*time.Minute {
		return errors.New("auth: LDAP timeout must be at most 2m")
	}
	return nil
}

// LDAPConfig loads the stored configuration (bind password omitted).
func (s *Service) LDAPConfig(ctx context.Context) (*LDAPConfig, error) {
	c, _, err := s.loadLDAP(ctx)
	return c, err
}

func (s *Service) loadLDAP(ctx context.Context) (*LDAPConfig, string, error) {
	var raw, sealed string
	err := s.db.QueryRowContext(ctx, `SELECT config, bind_password FROM auth_ldap_config WHERE id = 1`).Scan(&raw, &sealed)
	if errors.Is(err, sql.ErrNoRows) {
		c := &LDAPConfig{}
		c.applyDefaults()
		return c, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	var c LDAPConfig
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		return nil, "", err
	}
	c.applyDefaults()
	c.HasPassword = sealed != ""
	return &c, sealed, nil
}

// withPassword returns cfg with the decrypted bind password.
func (s *Service) withPassword(cfg *LDAPConfig, sealed string) (*LDAPConfig, error) {
	c := *cfg
	if sealed == "" {
		return &c, nil
	}
	if s.sealer == nil {
		return nil, ErrNoSealer
	}
	pw, err := secrets.DecryptString(s.sealer, sealed, ldapAAD)
	if err != nil {
		return nil, fmt.Errorf("auth: decrypt LDAP bind password: %w", err)
	}
	c.BindPassword = pw
	return &c, nil
}

// SaveLDAPConfig stores the configuration. An empty BindPassword keeps the
// stored one unless clearPassword is set.
func (s *Service) SaveLDAPConfig(ctx context.Context, a Actor, c LDAPConfig, clearPassword bool) error {
	c.applyDefaults()
	if c.Enabled || c.URL != "" {
		if err := c.Validate(); err != nil {
			return err
		}
	}
	if err := s.checkRoleNames(ctx, c.RoleMap, c.DefaultRoles); err != nil {
		return err
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return err
	}
	var sealed string
	if c.BindPassword != "" {
		if s.sealer == nil {
			return ErrNoSealer
		}
		if sealed, err = secrets.EncryptString(s.sealer, c.BindPassword, ldapAAD); err != nil {
			return err
		}
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO auth_ldap_config (id, config, bind_password, updated_at) VALUES (1, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET config = excluded.config,
			bind_password = CASE WHEN ? THEN '' WHEN excluded.bind_password = '' THEN bind_password ELSE excluded.bind_password END,
			updated_at = excluded.updated_at`, string(raw), sealed, s.ms(s.now()), clearPassword)
	outcome, reason := audit.OutcomeSuccess, ""
	if err != nil {
		outcome, reason = audit.OutcomeFailure, err.Error()
	}
	s.record(ctx, a, "sso.ldap.save", "ldap", outcome, reason, map[string]any{
		"enabled": c.Enabled, "url": c.URL, "bind_dn": c.BindDN, "password_changed": c.BindPassword != "" || clearPassword,
		"role_map": c.RoleMap, "default_roles": c.DefaultRoles,
	})
	return err
}

// TestLDAP dials and binds with the service account. If username is set it
// also resolves that user and their groups (no password needed) and
// returns a human-readable summary.
func (s *Service) TestLDAP(ctx context.Context, a Actor, username string) (string, error) {
	cfg, sealed, err := s.loadLDAP(ctx)
	if err != nil {
		return "", err
	}
	if cfg.URL == "" {
		return "", ErrLDAPDisabled
	}
	cfg, err = s.withPassword(cfg, sealed)
	if err != nil {
		return "", err
	}
	summary, err := s.testLDAP(ctx, cfg, username)
	outcome, reason := audit.OutcomeSuccess, ""
	if err != nil {
		outcome, reason = audit.OutcomeFailure, err.Error()
	}
	s.record(ctx, a, "sso.ldap.test", "ldap", outcome, reason, nil)
	return summary, err
}

func (s *Service) testLDAP(ctx context.Context, cfg *LDAPConfig, username string) (string, error) {
	conn, err := s.ldial(ctx, cfg)
	if err != nil {
		return "", fmt.Errorf("connect: %w", err)
	}
	defer conn.Close()
	if err := serviceBind(conn, cfg); err != nil {
		return "", err
	}
	if username == "" {
		return "Connected and bound successfully.", nil
	}
	e, err := findUser(conn, cfg, username)
	if err != nil {
		return "", err
	}
	groups, err := userGroups(conn, cfg, e.DN)
	if err != nil {
		return "", err
	}
	roles := mapRoles(groupKeys(groups), cfg.RoleMap, cfg.DefaultRoles)
	return fmt.Sprintf("Found %s; %d group(s); roles: %s", e.DN, len(groups), strings.Join(roles, ", ")), nil
}

func serviceBind(conn LDAPConn, cfg *LDAPConfig) error {
	if cfg.BindDN == "" {
		return nil // anonymous search
	}
	if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
		return fmt.Errorf("service bind failed: %w", err)
	}
	return nil
}

func findUser(conn LDAPConn, cfg *LDAPConfig, username string) (*ldap.Entry, error) {
	filter := strings.ReplaceAll(cfg.UserFilter, "{username}", ldap.EscapeFilter(username))
	res, err := conn.Search(ldap.NewSearchRequest(cfg.UserBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		2, int(cfg.Timeout.Seconds()), false, filter,
		[]string{"dn", cfg.UsernameAttr, cfg.DisplayNameAttr, cfg.EmailAttr, "memberOf"}, nil))
	if err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("user search: %w", err)
	}
	if len(res.Entries) != 1 {
		return nil, ErrInvalidCredentials
	}
	return res.Entries[0], nil
}

// ldapGroup is a resolved group.
type ldapGroup struct{ DN, CN string }

func groupKeys(gs []ldapGroup) []string {
	out := make([]string, 0, 2*len(gs))
	for _, g := range gs {
		out = append(out, g.DN)
		if g.CN != "" {
			out = append(out, g.CN)
		}
	}
	return out
}

// userGroups resolves direct and nested group memberships of userDN.
func userGroups(conn LDAPConn, cfg *LDAPConfig, userDN string) ([]ldapGroup, error) {
	base := cfg.GroupBaseDN
	if base == "" {
		base = cfg.UserBaseDN
	}
	search := func(filter string) ([]*ldap.Entry, error) {
		res, err := conn.Search(ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
			1000, int(cfg.Timeout.Seconds()), false, filter, []string{"dn", "cn"}, nil))
		if err != nil {
			return nil, fmt.Errorf("group search: %w", err)
		}
		return res.Entries, nil
	}
	var out []ldapGroup
	seen := map[string]bool{}
	if cfg.ADMatchingRule {
		es, err := search("(&" + cfg.GroupFilter + "(member:1.2.840.113556.1.4.1941:=" + ldap.EscapeFilter(userDN) + "))")
		if err != nil {
			return nil, err
		}
		for _, e := range es {
			out = append(out, ldapGroup{DN: e.DN, CN: e.GetAttributeValue("cn")})
		}
		return out, nil
	}
	frontier := []string{userDN}
	for depth := 0; depth < maxGroupDepth && len(frontier) > 0; depth++ {
		var next []string
		for _, dn := range frontier {
			filter := "(&" + cfg.GroupFilter + "(|(member=" + ldap.EscapeFilter(dn) + ")(uniqueMember=" + ldap.EscapeFilter(dn) + ")))"
			es, err := search(filter)
			if err != nil {
				return nil, err
			}
			for _, e := range es {
				k := strings.ToLower(e.DN)
				if seen[k] {
					continue
				}
				seen[k] = true
				out = append(out, ldapGroup{DN: e.DN, CN: e.GetAttributeValue("cn")})
				next = append(next, e.DN)
			}
		}
		frontier = next
	}
	return out, nil
}

// loginLDAP performs search-then-bind and provisions/syncs the user.
func (s *Service) loginLDAP(ctx context.Context, cfg *LDAPConfig, a Actor, username, password string) (*User, error) {
	if password == "" {
		return nil, ErrInvalidCredentials // never allow unauthenticated binds
	}
	_, sealed, err := s.loadLDAP(ctx)
	if err != nil {
		return nil, err
	}
	if cfg, err = s.withPassword(cfg, sealed); err != nil {
		return nil, err
	}
	conn, err := s.ldial(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("ldap connect: %w", err)
	}
	defer conn.Close()
	if err := serviceBind(conn, cfg); err != nil {
		return nil, err
	}
	e, err := findUser(conn, cfg, username)
	if err != nil {
		return nil, err
	}
	if err := conn.Bind(e.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("user bind: %w", err)
	}
	// Re-bind as the service account for group lookups (user may lack rights).
	if err := serviceBind(conn, cfg); err != nil {
		return nil, err
	}
	groups, err := userGroups(conn, cfg, e.DN)
	if err != nil {
		return nil, err
	}
	name := e.GetAttributeValue(cfg.UsernameAttr)
	if name == "" || !ValidUsername(name) {
		name = username
	}
	u, err := s.provisionExternal(ctx, a, SourceLDAP, externalIdentity{
		Subject: strings.ToLower(e.DN), Username: name, DisplayName: e.GetAttributeValue(cfg.DisplayNameAttr),
		Email: e.GetAttributeValue(cfg.EmailAttr), Groups: groupKeys(groups), RoleMap: cfg.RoleMap,
		DefaultRoles: cfg.DefaultRoles, JIT: true,
	})
	if err != nil {
		return nil, err
	}
	if u.Disabled {
		return nil, ErrAccountDisabled
	}
	return u, nil
}

// dialLDAP is the production LDAPDialer.
func dialLDAP(ctx context.Context, cfg *LDAPConfig) (LDAPConn, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: cfg.ServerName}
	if tlsCfg.ServerName == "" {
		tlsCfg.ServerName = u.Hostname()
	}
	if cfg.CAPEM != "" {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM([]byte(cfg.CAPEM))
		tlsCfg.RootCAs = pool
	}
	timeout := cfg.Timeout
	if dl, ok := ctx.Deadline(); ok {
		timeout = min(timeout, time.Until(dl))
	}
	conn, err := ldap.DialURL(cfg.URL, ldap.DialWithDialer(&net.Dialer{Timeout: timeout}), ldap.DialWithTLSConfig(tlsCfg))
	if err != nil {
		return nil, err
	}
	conn.SetTimeout(timeout)
	if cfg.StartTLS {
		if err := conn.StartTLS(tlsCfg); err != nil {
			conn.Close()
			return nil, fmt.Errorf("starttls: %w", err)
		}
	}
	return conn, nil
}
