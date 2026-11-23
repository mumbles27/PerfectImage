package auth

import (
	"context"
	"errors"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// fakeDirectory is an in-memory LDAP directory implementing LDAPConn.
type fakeDirectory struct {
	users     map[string]fakeUser // by DN (lower-case)
	groups    map[string][]string // group DN -> member DNs
	binds     []string
	searches  []string
	dialErr   error
	boundAsDN string
}

type fakeUser struct {
	dn, uid, password, name, mail string
}

func (d *fakeDirectory) dial(context.Context, *LDAPConfig) (LDAPConn, error) {
	if d.dialErr != nil {
		return nil, d.dialErr
	}
	return d, nil
}

func (d *fakeDirectory) Close() error { return nil }

func (d *fakeDirectory) Bind(dn, pw string) error {
	d.binds = append(d.binds, dn)
	if dn == "cn=svc,dc=example,dc=test" && pw == "fake-bind-pw" {
		d.boundAsDN = dn
		return nil
	}
	if u, ok := d.users[strings.ToLower(dn)]; ok && pw != "" && pw == u.password {
		d.boundAsDN = dn
		return nil
	}
	return ldap.NewError(ldap.LDAPResultInvalidCredentials, errors.New("invalid credentials"))
}

var (
	uidFilterRE    = regexp.MustCompile(`\(uid=([^)]*)\)`)
	memberFilterRE = regexp.MustCompile(`\(member=([^)]*)\)`)
)

func (d *fakeDirectory) Search(req *ldap.SearchRequest) (*ldap.SearchResult, error) {
	d.searches = append(d.searches, req.Filter)
	if d.boundAsDN == "" {
		return nil, ldap.NewError(ldap.LDAPResultInsufficientAccessRights, errors.New("bind first"))
	}
	res := &ldap.SearchResult{}
	if m := uidFilterRE.FindStringSubmatch(req.Filter); m != nil {
		for _, u := range d.users {
			if u.uid == m[1] {
				res.Entries = append(res.Entries, ldap.NewEntry(u.dn, map[string][]string{
					"uid": {u.uid}, "displayName": {u.name}, "mail": {u.mail}}))
			}
		}
		return res, nil
	}
	if m := memberFilterRE.FindStringSubmatch(req.Filter); m != nil {
		member := strings.ToLower(unescapeFilter(m[1]))
		for g, members := range d.groups {
			if slices.Contains(members, member) {
				cn := strings.TrimPrefix(strings.SplitN(g, ",", 2)[0], "cn=")
				res.Entries = append(res.Entries, ldap.NewEntry(g, map[string][]string{"cn": {cn}}))
			}
		}
		return res, nil
	}
	return res, nil
}

func unescapeFilter(s string) string {
	r := strings.NewReplacer(`\28`, "(", `\29`, ")", `\2a`, "*", `\5c`, `\`, `\00`, "\x00")
	return r.Replace(s)
}

func newFakeDirectory() *fakeDirectory {
	return &fakeDirectory{
		users: map[string]fakeUser{
			"uid=hank,ou=people,dc=example,dc=test": {dn: "uid=hank,ou=people,dc=example,dc=test", uid: "hank", password: "dir-pass-1", name: "Hank", mail: "hank@example.test"},
			"uid=ivy,ou=people,dc=example,dc=test":  {dn: "uid=ivy,ou=people,dc=example,dc=test", uid: "ivy", password: "dir-pass-2", name: "Ivy"},
		},
		groups: map[string][]string{
			// hank -> team-a -> platform (nested) -> mapped to Admin by CN.
			"cn=team-a,ou=groups,dc=example,dc=test":   {"uid=hank,ou=people,dc=example,dc=test"},
			"cn=platform,ou=groups,dc=example,dc=test": {"cn=team-a,ou=groups,dc=example,dc=test"},
			// cycle protection
			"cn=loop,ou=groups,dc=example,dc=test": {"cn=platform,ou=groups,dc=example,dc=test", "cn=loop,ou=groups,dc=example,dc=test"},
		},
	}
}

func TestLDAPConfigValidate(t *testing.T) {
	base := LDAPConfig{URL: "ldaps://dc.example.test:636", UserBaseDN: "dc=example,dc=test"}
	base.applyDefaults()
	tests := []struct {
		name   string
		mutate func(*LDAPConfig)
		ok     bool
	}{
		{"ldaps", func(*LDAPConfig) {}, true},
		{"ldap with starttls", func(c *LDAPConfig) { c.URL = "ldap://dc:389"; c.StartTLS = true }, true},
		{"plain ldap refused", func(c *LDAPConfig) { c.URL = "ldap://dc:389" }, false},
		{"starttls on ldaps", func(c *LDAPConfig) { c.StartTLS = true }, false},
		{"bad scheme", func(c *LDAPConfig) { c.URL = "http://dc" }, false},
		{"bad CA", func(c *LDAPConfig) { c.CAPEM = "not pem" }, false},
		{"filter without placeholder", func(c *LDAPConfig) { c.UserFilter = "(uid=x)" }, false},
		{"no base", func(c *LDAPConfig) { c.UserBaseDN = "" }, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := base
			tt.mutate(&c)
			if err := c.Validate(); (err == nil) != tt.ok {
				t.Fatalf("err = %v", err)
			}
		})
	}
}

func TestLDAPLogin(t *testing.T) {
	dir := newFakeDirectory()
	f := newFixture(t, func(o *Options) { o.LDAPDialer = dir.dial })
	ctx := context.Background()
	cfg := LDAPConfig{
		Enabled: true, URL: "ldaps://dc.example.test", BindDN: "cn=svc,dc=example,dc=test", BindPassword: "fake-bind-pw",
		UserBaseDN: "ou=people,dc=example,dc=test", GroupBaseDN: "ou=groups,dc=example,dc=test",
		RoleMap:      map[string][]string{"platform": {"Admin"}, "cn=team-a,ou=groups,dc=example,dc=test": {"Builder"}},
		DefaultRoles: []string{"Viewer"},
	}
	if err := f.svc.SaveLDAPConfig(ctx, SystemActor, cfg, false); err != nil {
		t.Fatal(err)
	}
	var raw, sealed string
	_ = f.db.QueryRowContext(ctx, `SELECT config, bind_password FROM auth_ldap_config`).Scan(&raw, &sealed)
	if strings.Contains(raw+sealed, "fake-bind-pw") {
		t.Fatal("bind password stored in clear")
	}
	meta := RequestMeta{IP: "203.0.113.5"}

	tests := []struct {
		name      string
		user, pw  string
		wantErr   error
		wantRoles []string
	}{
		{"nested groups map to roles", "hank", "dir-pass-1", nil, []string{"Admin", "Builder", "Viewer"}},
		{"no groups gets defaults", "ivy", "dir-pass-2", nil, []string{"Viewer"}},
		{"wrong password", "hank", "nope", ErrInvalidCredentials, nil},
		{"empty password never binds", "hank", "", ErrInvalidCredentials, nil},
		{"unknown user", "zed", "x", ErrInvalidCredentials, nil},
		{"filter injection escaped", "*)(uid=*", "x", ErrInvalidCredentials, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir.binds = nil
			au, err := f.svc.Login(ctx, meta, tt.user, tt.pw)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}
			if au.Method != "ldap" || au.User.Source != SourceLDAP || !slices.Equal(au.User.Roles, tt.wantRoles) {
				t.Fatalf("user = %+v (%s)", au.User, au.Method)
			}
			// search-then-bind: service bind, user bind, service re-bind.
			if len(dir.binds) != 3 || dir.binds[0] != cfg.BindDN || !strings.HasPrefix(dir.binds[1], "uid="+tt.user) {
				t.Fatalf("binds = %v", dir.binds)
			}
		})
	}
	// Injection attempt was escaped in the filter.
	for _, s := range dir.searches {
		if strings.Contains(s, "(uid=*)") {
			t.Fatalf("unescaped filter %q", s)
		}
	}
	// Second login reuses the account.
	a1, _ := f.svc.Login(ctx, meta, "hank", "dir-pass-1")
	a2, _ := f.svc.Login(ctx, meta, "hank", "dir-pass-1")
	if a1.User.ID != a2.User.ID {
		t.Fatal("duplicate LDAP account")
	}
	// Local accounts with the same name keep using the local password.
	f.mustUser(t, "localonly", "Lantern-Purple-42", "Viewer")
	if au, err := f.svc.Login(ctx, meta, "localonly", "Lantern-Purple-42"); err != nil || au.Method != "password" {
		t.Fatalf("local login with LDAP enabled: %v", err)
	}
	// Test connection helper.
	summary, err := f.svc.TestLDAP(ctx, SystemActor, "hank")
	if err != nil || !strings.Contains(summary, "Admin") {
		t.Fatalf("test = %q, %v", summary, err)
	}
	dir.dialErr = errors.New("connection refused")
	if _, err := f.svc.TestLDAP(ctx, SystemActor, ""); err == nil {
		t.Fatal("dial error not reported")
	}
	if _, err := f.svc.Login(ctx, meta, "hank", "dir-pass-1"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("ldap outage: %v", err)
	}
	// Keeping and clearing the stored bind password.
	cfg.BindPassword = ""
	_ = f.svc.SaveLDAPConfig(ctx, SystemActor, cfg, false)
	if c, _ := f.svc.LDAPConfig(ctx); !c.HasPassword {
		t.Fatal("password dropped on save without new value")
	}
	_ = f.svc.SaveLDAPConfig(ctx, SystemActor, cfg, true)
	if c, _ := f.svc.LDAPConfig(ctx); c.HasPassword {
		t.Fatal("password not cleared")
	}
}

func TestMapRoles(t *testing.T) {
	got := mapRoles([]string{"CN=Ops,DC=x", "devs"}, map[string][]string{"cn=ops,dc=x": {"Operator"}, "DEVS": {"Builder", "Operator"}}, []string{"Viewer"})
	if !slices.Equal(got, []string{"Builder", "Operator", "Viewer"}) {
		t.Fatalf("got %v", got)
	}
}
