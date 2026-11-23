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

func TestHelpers(t *testing.T) {
	if !slices.Equal(BuiltinNames(), []string{RoleAdmin, RoleOperator, RoleBuilder, RoleViewer}) {
		t.Fatalf("BuiltinNames = %v", BuiltinNames())
	}
	for _, n := range BuiltinNames() {
		if _, ok := BuiltinRoles[n]; !ok {
			t.Errorf("%s missing from BuiltinRoles", n)
		}
	}
	tests := []struct {
		name string
		got  []Permission
		want []Permission
	}{
		{"normalize dedups, orders, drops unknown", Normalize([]Permission{JobsView, "x.y", ImagesView, JobsView}), []Permission{ImagesView, JobsView}},
		{"normalize empty", Normalize(nil), []Permission{}},
		{"intersect", Intersect([]Permission{DeployRun, JobsView, AuditView}, []Permission{AuditView, DeployRun}), []Permission{DeployRun, AuditView}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !slices.Equal(tt.got, tt.want) {
				t.Fatalf("got %v, want %v", tt.got, tt.want)
			}
		})
	}
	if !IsBuiltin("admin") || IsBuiltin("Auditors") {
		t.Error("IsBuiltin")
	}
	for _, p := range All {
		if p.Description() == string(p) {
			t.Errorf("%s has no description", p)
		}
	}
}
