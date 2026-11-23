package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/rbac"
)

// TokenPrefix starts every personal access token (helps secret scanners).
const TokenPrefix = "pit_"

// APIToken is a personal access token (the secret is never stored).
type APIToken struct {
	ID          string
	UserID      string
	Name        string
	Prefix      string
	Permissions []rbac.Permission
	CreatedAt   time.Time
	ExpiresAt   time.Time
	LastUsedAt  time.Time
}

// Expired reports whether the token has expired at t.
func (t APIToken) Expired(at time.Time) bool { return !at.Before(t.ExpiresAt) }

// Token errors.
var (
	ErrTokenInvalid = errors.New("auth: invalid API token")
	ErrTokenScope   = errors.New("auth: token scope must be a non-empty subset of your permissions")
)

// CreateToken issues a personal access token for p, limited to perms (which
// must be a subset of p's current permissions) and expiring after ttl. The
// raw token is returned once.
func (s *Service) CreateToken(ctx context.Context, p *Principal, a Actor, name string, perms []rbac.Permission, ttl time.Duration) (*APIToken, string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 64 {
		return nil, "", fmt.Errorf("%w: token name must be 1-64 characters", ErrInvalidName)
	}
	perms = rbac.Normalize(perms)
	if len(perms) == 0 || checkGrant(p, perms) != nil {
		return nil, "", ErrTokenScope
	}
	if ttl <= 0 || ttl > s.cfg.APITokenMaxTTL {
		return nil, "", fmt.Errorf("auth: token lifetime must be between 1 day and %s", s.cfg.APITokenMaxTTL)
	}
	raw := TokenPrefix + randToken(32)
	now := s.now()
	t := &APIToken{
		ID: newID(), UserID: p.ID, Name: name, Prefix: raw[:len(TokenPrefix)+6], Permissions: perms,
		CreatedAt: now, ExpiresAt: now.Add(ttl),
	}
	pj, _ := json.Marshal(perms)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO auth_api_tokens (id, user_id, name, token_hash, prefix, permissions,
		created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.UserID, t.Name, sha256Hex(raw), t.Prefix, string(pj), s.ms(t.CreatedAt), s.ms(t.ExpiresAt)); err != nil {
		return nil, "", err
	}
	s.record(ctx, a, "auth.token.create", "token:"+t.ID, audit.OutcomeSuccess, "",
		map[string]any{"name": name, "permissions": perms, "expires_at": t.ExpiresAt})
	return t, raw, nil
}

// Tokens lists a user's tokens.
func (s *Service) Tokens(ctx context.Context, userID string) ([]APIToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, user_id, name, prefix, permissions, created_at, expires_at, last_used_at
		FROM auth_api_tokens WHERE user_id = ? ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIToken
	for rows.Next() {
		var t APIToken
		var pj string
		var c, e, l int64
		if err := rows.Scan(&t.ID, &t.UserID, &t.Name, &t.Prefix, &pj, &c, &e, &l); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(pj), &t.Permissions)
		t.CreatedAt, t.ExpiresAt, t.LastUsedAt = fromMS(c), fromMS(e), fromMS(l)
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeToken deletes one of userID's tokens.
func (s *Service) RevokeToken(ctx context.Context, a Actor, userID, tokenID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM auth_api_tokens WHERE id = ? AND user_id = ?`, tokenID, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrTokenInvalid
	}
	s.record(ctx, a, "auth.token.revoke", "token:"+tokenID, audit.OutcomeSuccess, "", nil)
	return nil
}

// authenticateToken resolves a Bearer token. The effective permissions are
// the token scope intersected with the owner's current permissions.
func (s *Service) authenticateToken(ctx context.Context, raw string) (*Principal, error) {
	if !strings.HasPrefix(raw, TokenPrefix) || len(raw) > 128 {
		return nil, ErrUnauthenticated
	}
	var t APIToken
	var pj string
	var e, l int64
	err := s.db.QueryRowContext(ctx, `SELECT id, user_id, permissions, expires_at, last_used_at FROM auth_api_tokens WHERE token_hash = ?`,
		sha256Hex(raw)).Scan(&t.ID, &t.UserID, &pj, &e, &l)
	if err != nil {
		return nil, ErrUnauthenticated
	}
	t.ExpiresAt, t.LastUsedAt = fromMS(e), fromMS(l)
	now := s.now()
	if t.Expired(now) {
		return nil, fmt.Errorf("%w: token expired", ErrUnauthenticated)
	}
	if err := json.Unmarshal([]byte(pj), &t.Permissions); err != nil {
		return nil, ErrUnauthenticated
	}
	p, err := s.principalFor(ctx, t.UserID)
	if err != nil {
		return nil, err
	}
	p.Permissions = rbac.Intersect(t.Permissions, p.Permissions)
	p.AuthMethod = "token"
	if now.Sub(t.LastUsedAt) >= touchInterval {
		_, _ = s.db.ExecContext(ctx, `UPDATE auth_api_tokens SET last_used_at = ? WHERE id = ?`, s.ms(now), t.ID)
	}
	return p, nil
}

// TokenMaxTTL returns the configured maximum token lifetime.
func (s *Service) TokenMaxTTL() time.Duration { return s.cfg.APITokenMaxTTL }
