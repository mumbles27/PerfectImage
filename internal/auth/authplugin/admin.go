package authplugin

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/mumbles27/PerfectImage/internal/auth"
	"github.com/mumbles27/PerfectImage/internal/rbac"
)

// --- Users ----------------------------------------------------------------

type usersData struct {
	Users         []*auth.User
	RoleOptions   []option
	Now           time.Time
	Created       *auth.User
	OneTime       string
	Notice, Error string
}

func (m *module) renderUsers(w http.ResponseWriter, r *http.Request, status int, mutate func(*usersData)) {
	ctx := r.Context()
	users, err := m.svc.Users(ctx)
	if err == nil {
		var roles []auth.Role
		roles, err = m.svc.Roles(ctx)
		d := &usersData{Users: users, RoleOptions: roleOptions(roles, nil), Now: time.Now(), Notice: flash(r)}
		if err == nil {
			if mutate != nil {
				mutate(d)
			}
			m.render(w, r, status, "users.html", "Users", d)
			return
		}
	}
	m.srv.Logger().Error("users page", "err", err)
	m.srv.Error(w, r, http.StatusInternalServerError, "Could not load users.")
}

func (m *module) usersPage(w http.ResponseWriter, r *http.Request) {
	m.renderUsers(w, r, http.StatusOK, nil)
}

func (m *module) userCreate(w http.ResponseWriter, r *http.Request) {
	p := auth.PrincipalFrom(r.Context())
	u, pw, err := m.svc.CreateUser(r.Context(), p, m.actor(r), auth.NewUser{
		Username: r.PostFormValue("username"), DisplayName: r.PostFormValue("display_name"),
		Email: r.PostFormValue("email"), Roles: r.PostForm["roles"],
	})
	if err != nil {
		m.renderUsers(w, r, http.StatusBadRequest, func(d *usersData) { d.Error = userMessage(err) })
		return
	}
	m.renderUsers(w, r, http.StatusOK, func(d *usersData) {
		d.Created, d.OneTime = u, pw
		d.Notice = "User created. Give them this one-time password over a secure channel; it is shown only once."
	})
}

type userData struct {
	User          *auth.User
	RoleOptions   []option
	Sessions      []auth.Session
	Now           time.Time
	Self          bool
	OneTime       string
	Notice, Error string
}

func (m *module) renderUser(w http.ResponseWriter, r *http.Request, status int, mutate func(*userData)) {
	ctx := r.Context()
	u, err := m.svc.UserByID(ctx, r.PathValue("id"))
	if errors.Is(err, auth.ErrUserNotFound) {
		m.srv.Error(w, r, http.StatusNotFound, "No such user.")
		return
	}
	d := &userData{User: u, Now: time.Now(), Notice: flash(r)}
	if err == nil {
		d.Self = auth.PrincipalFrom(ctx).ID == u.ID
		var roles []auth.Role
		if roles, err = m.svc.Roles(ctx); err == nil {
			d.RoleOptions = roleOptions(roles, u.Roles)
			d.Sessions, err = m.svc.Sessions(ctx, u.ID)
		}
	}
	if err != nil {
		m.srv.Logger().Error("user page", "err", err)
		m.srv.Error(w, r, http.StatusInternalServerError, "Could not load the user.")
		return
	}
	if mutate != nil {
		mutate(d)
	}
	m.render(w, r, status, "user.html", "User "+u.Username, d)
}

func (m *module) userPage(w http.ResponseWriter, r *http.Request) {
	m.renderUser(w, r, http.StatusOK, nil)
}

func (m *module) userUpdate(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	err := m.svc.UpdateUser(r.Context(), auth.PrincipalFrom(r.Context()), m.actor(r), id,
		r.PostFormValue("display_name"), r.PostFormValue("email"), r.PostForm["roles"])
	if err != nil {
		m.renderUser(w, r, http.StatusBadRequest, func(d *userData) { d.Error = userMessage(err) })
		return
	}
	redirect(w, r, "/settings/users/"+url.PathEscape(id), "saved")
}

func (m *module) userAction(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	p := auth.PrincipalFrom(ctx)
	a := m.actor(r)
	id := r.PathValue("id")
	back := "/settings/users/" + url.PathEscape(id)
	var err error
	var msg string
	switch r.PathValue("action") {
	case "disable":
		err, msg = m.svc.SetDisabled(ctx, a, id, true), "disabled"
	case "enable":
		err, msg = m.svc.SetDisabled(ctx, a, id, false), "enabled"
	case "unlock":
		err, msg = m.svc.Unlock(ctx, a, id), "unlocked"
	case "reset-mfa":
		err, msg = m.svc.ResetMFA(ctx, a, id), "mfa-reset"
	case "revoke-sessions":
		var u *auth.User
		if u, err = m.svc.UserByID(ctx, id); err == nil {
			_, err = m.svc.RevokeAllSessions(ctx, auth.Actor{ID: a.ID, Username: a.Username, Meta: a.Meta}, u.ID, "")
		}
		msg = "sessions-ended"
	case "reset-password":
		pw, rerr := m.svc.ResetPassword(ctx, p, a, id)
		if rerr != nil {
			err = rerr
			break
		}
		m.renderUser(w, r, http.StatusOK, func(d *userData) {
			d.OneTime = pw
			d.Notice = "Password reset. Give the user this one-time password over a secure channel; it is shown only once."
		})
		return
	case "delete":
		if err = m.svc.DeleteUser(ctx, p, a, id); err == nil {
			redirect(w, r, "/settings/users", "deleted")
			return
		}
	default:
		m.srv.Error(w, r, http.StatusNotFound, "Unknown action.")
		return
	}
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			m.srv.Error(w, r, http.StatusNotFound, "No such user.")
			return
		}
		m.renderUser(w, r, http.StatusBadRequest, func(d *userData) { d.Error = userMessage(err) })
		return
	}
	redirect(w, r, back, msg)
}

// --- Roles ----------------------------------------------------------------

type rolesData struct {
	Roles         []auth.Role
	Matrix        []matrixRow
	NewPerms      []option
	Role          *auth.Role
	RolePerms     []option
	Notice, Error string
}

func (m *module) renderRoles(w http.ResponseWriter, r *http.Request, status int, page string, mutate func(*rolesData)) {
	roles, err := m.svc.Roles(r.Context())
	if err != nil {
		m.srv.Logger().Error("roles page", "err", err)
		m.srv.Error(w, r, http.StatusInternalServerError, "Could not load roles.")
		return
	}
	d := &rolesData{Roles: roles, Matrix: matrix(roles), NewPerms: permOptions(rbac.All, nil), Notice: flash(r)}
	if mutate != nil {
		mutate(d)
	}
	if d.Role != nil {
		d.RolePerms = permOptions(rbac.All, d.Role.Permissions)
	}
	title := "Roles"
	if d.Role != nil {
		title = "Role " + d.Role.Name
	}
	m.render(w, r, status, page, title, d)
}

func (m *module) rolesPage(w http.ResponseWriter, r *http.Request) {
	m.renderRoles(w, r, http.StatusOK, "roles.html", nil)
}

func formPermissions(r *http.Request) []rbac.Permission {
	var out []rbac.Permission
	for _, v := range r.PostForm["permissions"] {
		out = append(out, rbac.Permission(v))
	}
	return out
}

func (m *module) roleCreate(w http.ResponseWriter, r *http.Request) {
	role := auth.Role{Name: r.PostFormValue("name"), Description: r.PostFormValue("description"),
		Permissions: formPermissions(r)}
	if err := m.svc.SaveRole(r.Context(), auth.PrincipalFrom(r.Context()), m.actor(r), role, true); err != nil {
		m.renderRoles(w, r, http.StatusBadRequest, "roles.html", func(d *rolesData) { d.Error = userMessage(err) })
		return
	}
	redirect(w, r, "/settings/roles/"+url.PathEscape(strings.TrimSpace(role.Name)), "created")
}

func (m *module) rolePage(w http.ResponseWriter, r *http.Request) {
	role, err := m.svc.Role(r.Context(), r.PathValue("name"))
	if err != nil {
		m.srv.Error(w, r, http.StatusNotFound, "No such role.")
		return
	}
	m.renderRoles(w, r, http.StatusOK, "role.html", func(d *rolesData) { d.Role = role })
}

func (m *module) roleUpdate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	role := auth.Role{Name: name, Description: r.PostFormValue("description"), Permissions: formPermissions(r)}
	if err := m.svc.SaveRole(r.Context(), auth.PrincipalFrom(r.Context()), m.actor(r), role, false); err != nil {
		cur, lerr := m.svc.Role(r.Context(), name)
		if lerr != nil {
			m.srv.Error(w, r, http.StatusNotFound, "No such role.")
			return
		}
		m.renderRoles(w, r, http.StatusBadRequest, "role.html", func(d *rolesData) { d.Role = cur; d.Error = userMessage(err) })
		return
	}
	redirect(w, r, "/settings/roles/"+url.PathEscape(name), "saved")
}

func (m *module) roleDelete(w http.ResponseWriter, r *http.Request) {
	if err := m.svc.DeleteRole(r.Context(), auth.PrincipalFrom(r.Context()), m.actor(r), r.PathValue("name")); err != nil {
		m.renderRoles(w, r, http.StatusBadRequest, "roles.html", func(d *rolesData) { d.Error = userMessage(err) })
		return
	}
	redirect(w, r, "/settings/roles", "deleted")
}

// option is a checkbox in a form (templates have no custom funcs, so
// membership is precomputed).
type option struct {
	Value       string
	Label       string
	Checked     bool
	Description string
}

func roleOptions(roles []auth.Role, selected []string) []option {
	out := make([]option, 0, len(roles))
	for _, r := range roles {
		out = append(out, option{Value: r.Name, Label: r.Name, Checked: slices.Contains(selected, r.Name), Description: r.Description})
	}
	return out
}

func permOptions(perms, selected []rbac.Permission) []option {
	out := make([]option, 0, len(perms))
	for _, p := range perms {
		out = append(out, option{Value: string(p), Label: string(p), Checked: slices.Contains(selected, p), Description: p.Description()})
	}
	return out
}

// matrixRow is one permission across all roles.
type matrixRow struct {
	Permission  rbac.Permission
	Description string
	Cells       []bool
}

func matrix(roles []auth.Role) []matrixRow {
	out := make([]matrixRow, 0, len(rbac.All))
	for _, p := range rbac.All {
		row := matrixRow{Permission: p, Description: p.Description()}
		for _, r := range roles {
			row.Cells = append(row.Cells, slices.Contains(r.Permissions, p))
		}
		out = append(out, row)
	}
	return out
}
