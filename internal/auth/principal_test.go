package auth

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"github.com/mumbles27/PerfectImage/internal/rbac"
)

func TestPermissionAuthorizer(t *testing.T) {
	viewer := &Principal{Username: "v", Permissions: rbac.RolePermissions(rbac.RoleViewer)}
	tests := []struct {
		name string
		p    *Principal
		perm rbac.Permission
		want error
	}{
		{"nil principal", nil, rbac.JobsView, ErrUnauthenticated},
		{"allowed", viewer, rbac.JobsView, nil},
		{"denied", viewer, rbac.DeployRun, ErrForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := PermissionAuthorizer{}.Authorize(context.Background(), tt.p, tt.perm)
			if !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestDevAllowAllAndContext(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	if _, err := (DenyAll{}).Authenticate(r); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("DenyAll authenticated")
	}
	p, err := DevAllowAll{}.Authenticate(r)
	if err != nil || !p.Has(rbac.SettingsManage) {
		t.Fatalf("dev principal = %+v, %v", p, err)
	}
	p.Permissions[0] = "x.y"
	if DevPrincipal.Permissions[0] == "x.y" || rbac.All[0] == "x.y" {
		t.Fatal("dev principal shares permission slice")
	}
	ctx := WithPrincipal(context.Background(), p)
	if PrincipalFrom(ctx) != p || PrincipalFrom(context.Background()) != nil {
		t.Fatal("context round trip failed")
	}
}
