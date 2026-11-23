// Package rbac defines permissions and built-in roles.
//
// Owned by the auth agent. The foundation defines the permission vocabulary
// and default role grants so every package can guard routes and actions now;
// role storage, custom roles and the roles UI are added by the auth agent.
package rbac

import "slices"

// Permission is a dotted capability string, "<area>.<verb>".
type Permission string

// Permissions. Add new ones here (and to All) rather than inventing strings
// at call sites.
const (
	ImagesView     Permission = "images.view"
	ImagesBuild    Permission = "images.build"
	AppsManage     Permission = "apps.manage"
	CatalogView    Permission = "catalog.view"
	CatalogManage  Permission = "catalog.manage"
	DeployView     Permission = "deploy.view"
	DeployRun      Permission = "deploy.run"
	JobsView       Permission = "jobs.view"
	JobsCancel     Permission = "jobs.cancel"
	ProxmoxManage  Permission = "proxmox.manage"
	UsersManage    Permission = "users.manage"
	RolesManage    Permission = "roles.manage"
	AuditView      Permission = "audit.view"
	SIEMManage     Permission = "siem.manage"
	BackupRun      Permission = "backup.run"
	SettingsView   Permission = "settings.view"
	SettingsManage Permission = "settings.manage"
)

// All lists every defined permission in display order.
var All = []Permission{
	ImagesView, ImagesBuild, AppsManage, CatalogView, CatalogManage,
	DeployView, DeployRun, JobsView, JobsCancel, ProxmoxManage,
	UsersManage, RolesManage, AuditView, SIEMManage, BackupRun,
	SettingsView, SettingsManage,
}

// Built-in role names.
const (
	RoleAdmin    = "Admin"
	RoleOperator = "Operator"
	RoleBuilder  = "Builder"
	RoleViewer   = "Viewer"
)

// BuiltinRoles maps built-in role names to their default permission sets.
// Callers must not mutate the returned slices; use RolePermissions.
var BuiltinRoles = map[string][]Permission{
	RoleAdmin: All,
	RoleOperator: {
		ImagesView, ImagesBuild, AppsManage, CatalogView, CatalogManage,
		DeployView, DeployRun, JobsView, JobsCancel, AuditView, SettingsView,
	},
	RoleBuilder: {
		ImagesView, ImagesBuild, AppsManage, CatalogView, CatalogManage,
		JobsView, JobsCancel,
	},
	RoleViewer: {
		ImagesView, CatalogView, DeployView, JobsView,
	},
}

// RolePermissions returns a copy of the default permissions of a built-in
// role, or nil if the role is not built in.
func RolePermissions(role string) []Permission {
	return slices.Clone(BuiltinRoles[role])
}

// Valid reports whether p is a defined permission.
func (p Permission) Valid() bool { return slices.Contains(All, p) }

// String implements fmt.Stringer.
func (p Permission) String() string { return string(p) }
