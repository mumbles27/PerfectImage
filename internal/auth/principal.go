// Package auth defines the authenticated identity (Principal) and the
// Authenticator / Authorizer seams used by the web layer.
//
// Owned by the auth agent, who will provide the real user store, sessions,
// login/logout pages, CSRF tokens and the `user reset-admin` command. The
// foundation ships only these interfaces plus DevAllowAll, which is installed
// solely when auth.dev_allow_all is set (loopback listeners only).
package auth

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/mumbles27/PerfectImage/internal/rbac"
)

// Errors returned by Authenticator and Authorizer.
var (
	// ErrUnauthenticated means no valid credentials were presented.
	ErrUnauthenticated = errors.New("auth: unauthenticated")
	// ErrForbidden means the principal lacks the required permission.
	ErrForbidden = errors.New("auth: forbidden")
	// ErrNotImplemented is returned by foundation stubs.
	ErrNotImplemented = errors.New("auth: not yet implemented")
)

// Principal is an authenticated user or service identity.
type Principal struct {
	ID          string
	Username    string
	DisplayName string
	Roles       []string
	// Permissions is the effective permission set resolved at authentication.
	Permissions []rbac.Permission
	// AuthMethod describes how the principal authenticated, e.g. "password",
	// "session", "token", "dev".
	AuthMethod string
	// SessionID identifies the session (empty for token/dev auth).
	SessionID string
}

// Has reports whether the principal's effective permissions include perm.
func (p *Principal) Has(perm rbac.Permission) bool {
	return p != nil && slices.Contains(p.Permissions, perm)
}

// Authenticator resolves the caller of an HTTP request. It returns
// ErrUnauthenticated (possibly wrapped) when there are no valid credentials.
type Authenticator interface {
	Authenticate(r *http.Request) (*Principal, error)
}

// Authorizer decides whether a principal may exercise a permission. It
// returns nil when allowed and ErrForbidden (possibly wrapped) otherwise.
type Authorizer interface {
	Authorize(ctx context.Context, p *Principal, perm rbac.Permission) error
}

// PermissionAuthorizer authorizes using Principal.Permissions.
type PermissionAuthorizer struct{}

// Authorize implements Authorizer.
func (PermissionAuthorizer) Authorize(_ context.Context, p *Principal, perm rbac.Permission) error {
	if p == nil {
		return ErrUnauthenticated
	}
	if !p.Has(perm) {
		return ErrForbidden
	}
	return nil
}

// DenyAll is the default Authenticator until the auth agent installs one.
type DenyAll struct{}

// Authenticate implements Authenticator.
func (DenyAll) Authenticate(*http.Request) (*Principal, error) { return nil, ErrUnauthenticated }

// DevAllowAll authenticates every request as an Admin "dev" principal and
// allows everything. Only for local development behind auth.dev_allow_all.
type DevAllowAll struct{}

// DevPrincipal is the identity used by DevAllowAll.
var DevPrincipal = Principal{
	ID:          "dev",
	Username:    "dev",
	DisplayName: "Developer (auth disabled)",
	Roles:       []string{rbac.RoleAdmin},
	Permissions: rbac.All,
	AuthMethod:  "dev",
}

// Authenticate implements Authenticator.
func (DevAllowAll) Authenticate(*http.Request) (*Principal, error) {
	p := DevPrincipal
	p.Permissions = slices.Clone(rbac.All)
	return &p, nil
}

// Authorize implements Authorizer.
func (DevAllowAll) Authorize(context.Context, *Principal, rbac.Permission) error { return nil }

type ctxKey struct{}

// WithPrincipal returns ctx carrying p.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
}

// PrincipalFrom returns the principal in ctx, or nil.
func PrincipalFrom(ctx context.Context) *Principal {
	p, _ := ctx.Value(ctxKey{}).(*Principal)
	return p
}

// AdminResetter resets (or creates) the built-in admin account and returns a
// one-time password. Implemented by the auth agent; used by
// `perfectimage user reset-admin`.
type AdminResetter interface {
	ResetAdmin(ctx context.Context, username string) (oneTimePassword string, err error)
}
