package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/rbac"
)

// Role is a named set of permissions.
type Role struct {
	Name        string
	Description string
	Builtin     bool
	Permissions []rbac.Permission
	Members     int
}

// Role errors.
var (
	ErrRoleBuiltin  = errors.New("auth: built-in roles cannot be changed or deleted")
	ErrRoleExists   = errors.New("auth: role already exists")
	ErrRoleNotFound = errors.New("auth: role not found")
	ErrInvalidName  = errors.New("auth: invalid name")
	ErrEscalation   = errors.New("auth: cannot grant permissions you do not hold")
	ErrLastAdmin    = errors.New("auth: at least one enabled user must keep the Admin role")
)

var roleNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9 _.-]{0,63}$`)

var builtinDescriptions = map[string]string{
	rbac.RoleAdmin:    "Full access, including users, roles and settings",
	rbac.RoleOperator: "Build images and deploy VMs",
	rbac.RoleBuilder:  "Build images and manage the catalog",
	rbac.RoleViewer:   "Read-only access",
}

// SeedRoles creates the built-in roles and resets their permissions to the
// defaults in rbac.BuiltinRoles (so new permissions reach upgraded installs).
func (s *Service) SeedRoles(ctx context.Context) error {
	now := s.ms(s.now())
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		for _, name := range rbac.BuiltinNames() {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO auth_roles (name, description, builtin, created_at, updated_at) VALUES (?, ?, 1, ?, ?)
				ON CONFLICT(name) DO UPDATE SET builtin = 1, name = excluded.name, description = excluded.description`,
				name, builtinDescriptions[name], now, now); err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `DELETE FROM auth_role_permissions WHERE role = ?`, name); err != nil {
				return err
			}
			for _, p := range rbac.BuiltinRoles[name] {
				if _, err := tx.ExecContext(ctx, `INSERT INTO auth_role_permissions (role, permission) VALUES (?, ?)`, name, p); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// Roles lists all roles with their permissions, built-ins first.
func (s *Service) Roles(ctx context.Context) ([]Role, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT r.name, r.description, r.builtin,
		       (SELECT COUNT(*) FROM auth_user_roles ur WHERE ur.role = r.name)
		FROM auth_roles r ORDER BY r.builtin DESC, r.name`)
	if err != nil {
		return nil, err
	}
	var roles []Role
	for rows.Next() {
		var r Role
		if err := rows.Scan(&r.Name, &r.Description, &r.Builtin, &r.Members); err != nil {
			rows.Close()
			return nil, err
		}
		roles = append(roles, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Order built-ins as declared in rbac.
	order := rbac.BuiltinNames()
	slices.SortStableFunc(roles, func(a, b Role) int {
		ia, ib := slices.Index(order, a.Name), slices.Index(order, b.Name)
		if ia < 0 {
			ia = len(order)
		}
		if ib < 0 {
			ib = len(order)
		}
		return ia - ib
	})
	for i := range roles {
		if roles[i].Permissions, err = s.rolePermissions(ctx, roles[i].Name); err != nil {
			return nil, err
		}
	}
	return roles, nil
}

// Role returns one role.
func (s *Service) Role(ctx context.Context, name string) (*Role, error) {
	var r Role
	err := s.db.QueryRowContext(ctx, `SELECT name, description, builtin FROM auth_roles WHERE name = ?`, name).
		Scan(&r.Name, &r.Description, &r.Builtin)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrRoleNotFound
	}
	if err != nil {
		return nil, err
	}
	r.Permissions, err = s.rolePermissions(ctx, r.Name)
	return &r, err
}

func (s *Service) rolePermissions(ctx context.Context, role string) ([]rbac.Permission, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT permission FROM auth_role_permissions WHERE role = ?`, role)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []rbac.Permission
	for rows.Next() {
		var p rbac.Permission
		if err := rows.Scan(&p); err != nil {
			return nil, err
		}
		if p.Valid() {
			out = append(out, p)
		}
	}
	return rbac.Normalize(out), rows.Err()
}

// checkGrant fails unless actor holds every permission in perms.
func checkGrant(actor *Principal, perms []rbac.Permission) error {
	if actor == nil {
		return nil // system/CLI
	}
	for _, p := range perms {
		if !actor.Has(p) {
			return fmt.Errorf("%w: %s", ErrEscalation, p)
		}
	}
	return nil
}

// SaveRole creates (create=true) or updates a custom role. The actor may only
// grant permissions it holds itself.
func (s *Service) SaveRole(ctx context.Context, actor *Principal, a Actor, r Role, create bool) error {
	r.Name = strings.TrimSpace(r.Name)
	if !roleNameRE.MatchString(r.Name) {
		return fmt.Errorf("%w: role names are 1-64 letters, digits, space, _ . -", ErrInvalidName)
	}
	if rbac.IsBuiltin(r.Name) {
		return ErrRoleBuiltin
	}
	for _, p := range r.Permissions {
		if !p.Valid() {
			return fmt.Errorf("auth: unknown permission %q", p)
		}
	}
	perms := rbac.Normalize(r.Permissions)
	var before []rbac.Permission
	if !create {
		old, err := s.Role(ctx, r.Name)
		if err != nil {
			return err
		}
		if old.Builtin {
			return ErrRoleBuiltin
		}
		before = old.Permissions
	}
	// Only the delta needs to be held by the actor: someone may edit a role's
	// description without holding every permission it already grants, but
	// removing or adding a permission they lack is refused.
	var changed []rbac.Permission
	for _, p := range perms {
		if !slices.Contains(before, p) {
			changed = append(changed, p)
		}
	}
	for _, p := range before {
		if !slices.Contains(perms, p) {
			changed = append(changed, p)
		}
	}
	if err := checkGrant(actor, changed); err != nil {
		s.record(ctx, a, "role.update", "role:"+r.Name, audit.OutcomeDenied, err.Error(), nil)
		return err
	}
	now := s.ms(s.now())
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		if create {
			res, err := tx.ExecContext(ctx, `INSERT INTO auth_roles (name, description, builtin, created_at, updated_at)
				VALUES (?, ?, 0, ?, ?) ON CONFLICT(name) DO NOTHING`, r.Name, r.Description, now, now)
			if err != nil {
				return err
			}
			if n, _ := res.RowsAffected(); n == 0 {
				return ErrRoleExists
			}
		} else if _, err := tx.ExecContext(ctx, `UPDATE auth_roles SET description = ?, updated_at = ? WHERE name = ? AND builtin = 0`,
			r.Description, now, r.Name); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM auth_role_permissions WHERE role = ?`, r.Name); err != nil {
			return err
		}
		for _, p := range perms {
			if _, err := tx.ExecContext(ctx, `INSERT INTO auth_role_permissions (role, permission) VALUES (?, ?)`, r.Name, p); err != nil {
				return err
			}
		}
		// Members' privileges changed: rotate their session IDs.
		_, err := tx.ExecContext(ctx, `UPDATE auth_sessions SET rotate = 1
			WHERE user_id IN (SELECT user_id FROM auth_user_roles WHERE role = ?)`, r.Name)
		return err
	})
	action := "role.update"
	if create {
		action = "role.create"
	}
	if err != nil {
		s.record(ctx, a, action, "role:"+r.Name, audit.OutcomeFailure, err.Error(), nil)
		return err
	}
	s.record(ctx, a, action, "role:"+r.Name, audit.OutcomeSuccess, "", map[string]any{"permissions": perms})
	return nil
}

// DeleteRole deletes a custom role (memberships are removed).
func (s *Service) DeleteRole(ctx context.Context, actor *Principal, a Actor, name string) error {
	r, err := s.Role(ctx, name)
	if err != nil {
		return err
	}
	if r.Builtin {
		s.record(ctx, a, "role.delete", "role:"+name, audit.OutcomeDenied, ErrRoleBuiltin.Error(), nil)
		return ErrRoleBuiltin
	}
	if err := checkGrant(actor, r.Permissions); err != nil {
		s.record(ctx, a, "role.delete", "role:"+name, audit.OutcomeDenied, err.Error(), nil)
		return err
	}
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE auth_sessions SET rotate = 1
			WHERE user_id IN (SELECT user_id FROM auth_user_roles WHERE role = ?)`, r.Name); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM auth_roles WHERE name = ? AND builtin = 0`, r.Name)
		return err
	})
	if err != nil {
		return err
	}
	s.record(ctx, a, "role.delete", "role:"+r.Name, audit.OutcomeSuccess, "", nil)
	return nil
}

// UserRolesAndPermissions resolves a user's roles and effective permissions.
func (s *Service) UserRolesAndPermissions(ctx context.Context, userID string) ([]string, []rbac.Permission, error) {
	roles, err := s.userRoles(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT rp.permission FROM auth_user_roles ur
		JOIN auth_role_permissions rp ON rp.role = ur.role WHERE ur.user_id = ?`, userID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var perms []rbac.Permission
	for rows.Next() {
		var p rbac.Permission
		if err := rows.Scan(&p); err != nil {
			return nil, nil, err
		}
		if p.Valid() {
			perms = append(perms, p)
		}
	}
	return roles, rbac.Normalize(perms), rows.Err()
}

func (s *Service) userRoles(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT role FROM auth_user_roles WHERE user_id = ? ORDER BY role`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// canonicalRoles maps names to stored role names, dropping unknown ones.
func (s *Service) canonicalRoles(ctx context.Context, names []string) ([]string, []string, error) {
	var out, unknown []string
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		var canon string
		err := s.db.QueryRowContext(ctx, `SELECT name FROM auth_roles WHERE name = ?`, n).Scan(&canon)
		if errors.Is(err, sql.ErrNoRows) {
			unknown = append(unknown, n)
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		if !slices.Contains(out, canon) {
			out = append(out, canon)
		}
	}
	slices.Sort(out)
	return out, unknown, nil
}

// setUserRolesTx replaces a user's roles and flags their sessions for
// rotation when the set changed.
func (s *Service) setUserRolesTx(ctx context.Context, tx *sql.Tx, userID string, roles []string) (changed bool, err error) {
	rows, err := tx.QueryContext(ctx, `SELECT role FROM auth_user_roles WHERE user_id = ? ORDER BY role`, userID)
	if err != nil {
		return false, err
	}
	var old []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			rows.Close()
			return false, err
		}
		old = append(old, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false, err
	}
	sorted := slices.Clone(roles)
	slices.Sort(sorted)
	if slices.Equal(old, sorted) {
		return false, nil
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM auth_user_roles WHERE user_id = ?`, userID); err != nil {
		return false, err
	}
	for _, r := range sorted {
		if _, err := tx.ExecContext(ctx, `INSERT INTO auth_user_roles (user_id, role) VALUES (?, ?)`, userID, r); err != nil {
			return false, err
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE auth_sessions SET rotate = 1 WHERE user_id = ?`, userID)
	return true, err
}

// enabledAdminsTx counts enabled users holding the Admin role, excluding
// excludeID.
func enabledAdminsTx(ctx context.Context, tx *sql.Tx, excludeID string) (int, error) {
	var n int
	err := tx.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM auth_users u JOIN auth_user_roles ur ON ur.user_id = u.id
		WHERE ur.role = ? AND u.disabled = 0 AND u.id <> ?`, rbac.RoleAdmin, excludeID).Scan(&n)
	return n, err
}

// rolesPermissions returns the union of permissions granted by roles.
func (s *Service) rolesPermissions(ctx context.Context, roles []string) ([]rbac.Permission, error) {
	var out []rbac.Permission
	for _, r := range roles {
		p, err := s.rolePermissions(ctx, r)
		if err != nil {
			return nil, err
		}
		out = append(out, p...)
	}
	return rbac.Normalize(out), nil
}
