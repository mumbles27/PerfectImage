package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/mumbles27/PerfectImage/internal/rbac"
)

// Authenticate implements Authenticator. A "Authorization: Bearer" API token
// takes precedence (and is the only credential considered when present);
// otherwise the active session resolved by the CSRF middleware is used.
// Effective permissions are reloaded from the database on every request,
// so role changes apply immediately.
func (s *Service) Authenticate(r *http.Request) (*Principal, error) {
	ctx := r.Context()
	if isBearer(r) {
		return s.authenticateToken(ctx, strings.TrimSpace(r.Header.Get("Authorization")[7:]))
	}
	st := stateFrom(ctx)
	var ss *Session
	if st != nil {
		ss = st.sess
	} else if ck, err := r.Cookie(SessionCookie); err == nil {
		// Not behind Protect (e.g. tests): resolve directly.
		ss, _ = s.lookupSession(ctx, ck.Value)
	}
	if ss == nil || ss.Stage != StageActive {
		return nil, ErrUnauthenticated
	}
	p, err := s.principalFor(ctx, ss.UserID)
	if err != nil {
		return nil, err
	}
	p.AuthMethod, p.SessionID = ss.AuthMethod, ss.ID
	return p, nil
}

func (s *Service) principalFor(ctx context.Context, userID string) (*Principal, error) {
	u, err := s.UserByID(ctx, userID)
	if errors.Is(err, ErrUserNotFound) {
		return nil, ErrUnauthenticated
	}
	if err != nil {
		return nil, err
	}
	if u.Disabled {
		return nil, fmt.Errorf("%w: account disabled", ErrUnauthenticated)
	}
	roles, perms, err := s.UserRolesAndPermissions(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	return &Principal{
		ID: u.ID, Username: u.Username, DisplayName: u.DisplayName, Roles: roles, Permissions: perms,
	}, nil
}

// Authorize implements Authorizer using the principal's effective
// permissions (resolved at authentication).
func (s *Service) Authorize(_ context.Context, p *Principal, perm rbac.Permission) error {
	if p == nil {
		return ErrUnauthenticated
	}
	if !perm.Valid() || !p.Has(perm) {
		return ErrForbidden
	}
	return nil
}

var (
	_ Authenticator = (*Service)(nil)
	_ Authorizer    = (*Service)(nil)
	_ AdminResetter = (*Service)(nil)
)
