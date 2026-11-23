package rbac

import (
	"slices"
	"strings"
	"testing"
)

func TestPermissionsWellFormed(t *testing.T) {
	seen := map[Permission]bool{}
	for _, p := range All {
		if seen[p] {
			t.Errorf("duplicate permission %s", p)
		}
		seen[p] = true
		if area, verb, ok := strings.Cut(string(p), "."); !ok || area == "" || verb == "" {
			t.Errorf("malformed permission %q", p)
		}
		if !p.Valid() {
			t.Errorf("%s not Valid", p)
		}
	}
	if Permission("nope.nope").Valid() {
		t.Error("unknown permission reported valid")
	}
}

func TestBuiltinRoles(t *testing.T) {
	tests := []struct {
		role   string
		has    []Permission
		hasNot []Permission
	}{
		{RoleAdmin, All, nil},
		{RoleOperator, []Permission{DeployRun, ImagesBuild}, []Permission{UsersManage, RolesManage, SettingsManage}},
		{RoleBuilder, []Permission{ImagesBuild, AppsManage}, []Permission{DeployRun, UsersManage}},
		{RoleViewer, []Permission{ImagesView, JobsView}, []Permission{ImagesBuild, DeployRun, JobsCancel}},
	}
	for _, tt := range tests {
		t.Run(tt.role, func(t *testing.T) {
			perms := RolePermissions(tt.role)
			for _, p := range perms {
				if !p.Valid() {
					t.Errorf("role grants undefined permission %s", p)
				}
			}
			for _, p := range tt.has {
				if !slices.Contains(perms, p) {
					t.Errorf("missing %s", p)
				}
			}
			for _, p := range tt.hasNot {
				if slices.Contains(perms, p) {
					t.Errorf("unexpected %s", p)
				}
			}
		})
	}
	if RolePermissions("nobody") != nil {
		t.Error("unknown role returned permissions")
	}
	c := RolePermissions(RoleViewer)
	c[0] = "mutated.x"
	if BuiltinRoles[RoleViewer][0] == "mutated.x" {
		t.Error("RolePermissions returned shared slice")
	}
}
