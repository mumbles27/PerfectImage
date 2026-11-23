package auth

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/mumbles27/PerfectImage/internal/rbac"
)

func TestBuiltinRolesSeeded(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	roles, err := f.svc.Roles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range roles {
		names = append(names, r.Name)
		if !r.Builtin {
			t.Errorf("%s not builtin", r.Name)
		}
		if !slices.Equal(r.Permissions, rbac.Normalize(rbac.BuiltinRoles[r.Name])) {
			t.Errorf("%s permissions = %v", r.Name, r.Permissions)
		}
	}
	if !slices.Equal(names, rbac.BuiltinNames()) {
		t.Fatalf("roles = %v", names)
	}
	// Tampered built-in permissions are restored on startup.
	_, _ = f.db.ExecContext(ctx, `DELETE FROM auth_role_permissions WHERE role = 'Viewer'`)
	if err := f.svc.SeedRoles(ctx); err != nil {
		t.Fatal(err)
	}
	if r, _ := f.svc.Role(ctx, "viewer"); len(r.Permissions) != len(rbac.BuiltinRoles[rbac.RoleViewer]) {
		t.Fatal("built-in not re-seeded")
	}
}

func TestRoleManagementAndResolution(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	admin := &Principal{ID: "a", Username: "root", Permissions: rbac.All}
	limited := &Principal{ID: "l", Username: "lim", Permissions: []rbac.Permission{rbac.RolesManage, rbac.JobsView}}

	tests := []struct {
		name    string
		actor   *Principal
		role    Role
		create  bool
		wantErr error
	}{
		{"create custom", admin, Role{Name: "Auditor", Permissions: []rbac.Permission{rbac.AuditView, rbac.JobsView, rbac.AuditView}}, true, nil},
		{"duplicate (case-insensitive)", admin, Role{Name: "auditor"}, true, ErrRoleExists},
		{"builtin name", admin, Role{Name: "Admin"}, true, ErrRoleBuiltin},
		{"invalid name", admin, Role{Name: "1 bad/name"}, true, ErrInvalidName},
		{"escalation", limited, Role{Name: "Sneaky", Permissions: []rbac.Permission{rbac.UsersManage}}, true, ErrEscalation},
		{"limited may grant own perms", limited, Role{Name: "Watcher", Permissions: []rbac.Permission{rbac.JobsView}}, true, nil},
		{"limited cannot remove perms it lacks", limited, Role{Name: "Auditor", Permissions: []rbac.Permission{rbac.JobsView}}, false, ErrEscalation},
		{"update custom", admin, Role{Name: "Auditor", Description: "d", Permissions: []rbac.Permission{rbac.AuditView, rbac.DeployView}}, false, nil},
		{"update builtin", admin, Role{Name: "Viewer"}, false, ErrRoleBuiltin},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := f.svc.SaveRole(ctx, tt.actor, SystemActor, tt.role, tt.create)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
		})
	}
	r, err := f.svc.Role(ctx, "Auditor")
	if err != nil || !slices.Equal(r.Permissions, []rbac.Permission{rbac.DeployView, rbac.AuditView}) {
		t.Fatalf("Auditor = %+v, %v", r, err)
	}

	// Effective permissions are the union of all roles.
	u := f.mustUser(t, "frank", "Lantern-Purple-42", "Builder", "Auditor")
	roles, perms, err := f.svc.UserRolesAndPermissions(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(roles, []string{"Auditor", "Builder"}) {
		t.Fatalf("roles = %v", roles)
	}
	want := rbac.Normalize(append(rbac.RolePermissions(rbac.RoleBuilder), rbac.DeployView, rbac.AuditView))
	if !slices.Equal(perms, want) {
		t.Fatalf("perms = %v, want %v", perms, want)
	}

	// Deleting the custom role removes it from members.
	if err := f.svc.DeleteRole(ctx, admin, SystemActor, "Viewer"); !errors.Is(err, ErrRoleBuiltin) {
		t.Fatalf("delete builtin: %v", err)
	}
	if err := f.svc.DeleteRole(ctx, admin, SystemActor, "auditor"); err != nil {
		t.Fatal(err)
	}
	if roles, _, _ := f.svc.UserRolesAndPermissions(ctx, u.ID); !slices.Equal(roles, []string{"Builder"}) {
		t.Fatalf("roles after delete = %v", roles)
	}
}

func TestUserAdminGuards(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	root := f.mustUser(t, "root", "Lantern-Purple-42", "Admin")
	mgr := &Principal{ID: "m", Username: "mgr", Permissions: []rbac.Permission{rbac.UsersManage, rbac.ImagesView, rbac.CatalogView, rbac.DeployView, rbac.JobsView}}
	a := Actor{ID: root.ID, Username: root.Username}

	if _, _, err := f.svc.CreateUser(ctx, mgr, a, NewUser{Username: "x1", Roles: []string{"Admin"}}); !errors.Is(err, ErrEscalation) {
		t.Fatalf("manager granted Admin: %v", err)
	}
	v, pw, err := f.svc.CreateUser(ctx, mgr, a, NewUser{Username: "viewer1", Roles: []string{"Viewer"}})
	if err != nil || pw == "" || !v.MustChangePassword {
		t.Fatalf("create viewer: %v", err)
	}
	if _, _, err := f.svc.CreateUser(ctx, nil, a, NewUser{Username: "VIEWER1"}); !errors.Is(err, ErrUserExists) {
		t.Fatalf("duplicate: %v", err)
	}
	if _, _, err := f.svc.CreateUser(ctx, nil, a, NewUser{Username: "x2", Roles: []string{"Nope"}}); !errors.Is(err, ErrRoleNotFound) {
		t.Fatalf("unknown role: %v", err)
	}
	if err := f.svc.UpdateUser(ctx, mgr, a, root.ID, "", "", nil); !errors.Is(err, ErrEscalation) {
		t.Fatalf("manager demoted admin: %v", err)
	}
	if _, err := f.svc.ResetPassword(ctx, mgr, a, root.ID); !errors.Is(err, ErrEscalation) {
		t.Fatalf("manager reset admin password: %v", err)
	}
	// Last admin protection.
	if err := f.svc.UpdateUser(ctx, nil, a, root.ID, "", "", []string{"Viewer"}); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("demote last admin: %v", err)
	}
	if err := f.svc.SetDisabled(ctx, Actor{ID: "other"}, root.ID, true); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("disable last admin: %v", err)
	}
	if err := f.svc.SetDisabled(ctx, a, root.ID, true); !errors.Is(err, ErrSelf) {
		t.Fatalf("disable self: %v", err)
	}
	if err := f.svc.DeleteUser(ctx, nil, Actor{ID: "other"}, root.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("delete last admin: %v", err)
	}
	f.mustUser(t, "root2", "Lantern-Purple-42", "Admin")
	if err := f.svc.UpdateUser(ctx, nil, a, root.ID, "Root", "", []string{"Viewer"}); err != nil {
		t.Fatalf("demote with another admin: %v", err)
	}
	// Reset password: new one-time password, forced change.
	pw2, err := f.svc.ResetPassword(ctx, nil, a, v.ID)
	if err != nil || pw2 == pw {
		t.Fatalf("reset: %v", err)
	}
	if au, err := f.svc.Login(ctx, RequestMeta{}, "viewer1", pw2); err != nil || !au.User.MustChangePassword {
		t.Fatalf("login with reset password: %v", err)
	}
}

func TestAPITokens(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	u := f.mustUser(t, "gina", "Lantern-Purple-42", "Operator")
	p := &Principal{ID: u.ID, Username: u.Username, Permissions: rbac.RolePermissions(rbac.RoleOperator)}
	a := Actor{ID: u.ID, Username: u.Username}

	tests := []struct {
		name  string
		perms []rbac.Permission
		ttl   time.Duration
		ok    bool
	}{
		{"subset", []rbac.Permission{rbac.JobsView, rbac.DeployRun}, 24 * time.Hour, true},
		{"empty scope", nil, 24 * time.Hour, false},
		{"not held", []rbac.Permission{rbac.UsersManage}, 24 * time.Hour, false},
		{"too long", []rbac.Permission{rbac.JobsView}, 2 * 365 * 24 * time.Hour, false},
	}
	var raw string
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, r, err := f.svc.CreateToken(ctx, p, a, "ci", tt.perms, tt.ttl)
			if (err == nil) != tt.ok {
				t.Fatalf("err = %v", err)
			}
			if tt.ok {
				raw = r
			}
		})
	}
	bearer := func(tok string) (*Principal, error) {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		return f.svc.Authenticate(r)
	}
	tp, err := bearer(raw)
	if err != nil || tp.AuthMethod != "token" || tp.SessionID != "" ||
		!slices.Equal(tp.Permissions, []rbac.Permission{rbac.DeployRun, rbac.JobsView}) {
		t.Fatalf("token principal = %+v, %v", tp, err)
	}
	var stored string
	_ = f.db.QueryRowContext(ctx, `SELECT token_hash FROM auth_api_tokens`).Scan(&stored)
	if stored == raw || stored != sha256Hex(raw) {
		t.Fatal("token not stored hashed")
	}
	// Scope shrinks with the owner's permissions.
	if err := f.svc.UpdateUser(ctx, nil, SystemActor, u.ID, "", "", []string{"Viewer"}); err != nil {
		t.Fatal(err)
	}
	if tp, _ = bearer(raw); !slices.Equal(tp.Permissions, []rbac.Permission{rbac.JobsView}) {
		t.Fatalf("after downgrade = %v", tp.Permissions)
	}
	if _, err := bearer(raw + "x"); err == nil {
		t.Fatal("tampered token accepted")
	}
	f.clock.Add(25 * time.Hour)
	if _, err := bearer(raw); err == nil {
		t.Fatal("expired token accepted")
	}
	toks, _ := f.svc.Tokens(ctx, u.ID)
	if len(toks) != 1 {
		t.Fatalf("tokens = %d", len(toks))
	}
	if err := f.svc.RevokeToken(ctx, a, "someone-else", toks[0].ID); err == nil {
		t.Fatal("revoked another user's token")
	}
	if err := f.svc.RevokeToken(ctx, a, u.ID, toks[0].ID); err != nil {
		t.Fatal(err)
	}
}

func TestAuthorize(t *testing.T) {
	f := newFixture(t, nil)
	p := &Principal{Permissions: []rbac.Permission{rbac.JobsView}}
	tests := []struct {
		p    *Principal
		perm rbac.Permission
		want error
	}{
		{nil, rbac.JobsView, ErrUnauthenticated},
		{p, rbac.JobsView, nil},
		{p, rbac.JobsCancel, ErrForbidden},
		{&Principal{Permissions: []rbac.Permission{"made.up"}}, "made.up", ErrForbidden},
	}
	for _, tt := range tests {
		if err := f.svc.Authorize(context.Background(), tt.p, tt.perm); !errors.Is(err, tt.want) {
			t.Errorf("Authorize(%v) = %v, want %v", tt.perm, err, tt.want)
		}
	}
	_ = http.StatusOK
}

func TestBootstrapAndResetAdmin(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	dir := t.TempDir()
	var out bytes.Buffer
	if err := f.svc.Bootstrap(ctx, &out, dir); err != nil {
		t.Fatal(err)
	}
	u, err := f.svc.UserByUsername(ctx, "admin")
	if err != nil || !u.MustChangePassword || !slices.Contains(u.Roles, rbac.RoleAdmin) {
		t.Fatalf("admin = %+v, %v", u, err)
	}
	if !strings.Contains(out.String(), "One-time password") {
		t.Fatal("password not printed")
	}
	// Second run does nothing.
	out.Reset()
	if err := f.svc.Bootstrap(ctx, &out, dir); err != nil || out.Len() != 0 {
		t.Fatalf("second bootstrap printed %q, %v", out.String(), err)
	}
	// ResetAdmin clears lockout/MFA/sessions and restores Admin.
	_, _ = f.db.ExecContext(ctx, `UPDATE auth_users SET locked_until = ?, disabled = 1, totp_enabled = 1 WHERE id = ?`,
		f.svc.ms(f.clock.Now().Add(time.Hour)), u.ID)
	_, _ = f.db.ExecContext(ctx, `DELETE FROM auth_user_roles WHERE user_id = ?`, u.ID)
	pw, err := AdminResetter(f.svc).ResetAdmin(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	au, err := f.svc.Login(ctx, RequestMeta{}, "admin", pw)
	if err != nil || au.User.TOTPEnabled || !slices.Contains(au.User.Roles, rbac.RoleAdmin) {
		t.Fatalf("login after reset: %+v, %v", au, err)
	}
	// Creates a missing account.
	if _, err := f.svc.ResetAdmin(ctx, "breakglass"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.UserByUsername(ctx, "breakglass"); err != nil {
		t.Fatal(err)
	}
}
