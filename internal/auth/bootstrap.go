package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/rbac"
)

// DefaultAdminUsername is the account created on first run.
const DefaultAdminUsername = "admin"

// BootstrapFileName is written (0600) into the secrets directory with the
// first-run admin password so Windows service installs (no console) can
// retrieve it. It is deleted when that password is changed.
const BootstrapFileName = "initial-admin-password.txt"

var bootstrapFile struct {
	sync.Mutex
	path, user string
}

func removeBootstrapFile(username string) {
	bootstrapFile.Lock()
	defer bootstrapFile.Unlock()
	if bootstrapFile.path != "" && username == bootstrapFile.user {
		_ = os.Remove(bootstrapFile.path)
		bootstrapFile.path = ""
	}
}

// Bootstrap creates the initial administrator when there are no users. The
// one-time password is written to console (and to secretsDir/
// BootstrapFileName, mode 0600, when secretsDir is set) exactly once; it is
// never sent to the logger.
func (s *Service) Bootstrap(ctx context.Context, console io.Writer, secretsDir string) error {
	n, err := s.CountUsers(ctx)
	if err != nil || n > 0 {
		if secretsDir != "" {
			// Remember the file so a later password change removes it.
			p := filepath.Join(secretsDir, BootstrapFileName)
			if _, statErr := os.Stat(p); statErr == nil {
				bootstrapFile.Lock()
				bootstrapFile.path, bootstrapFile.user = p, DefaultAdminUsername
				bootstrapFile.Unlock()
			}
		}
		return err
	}
	u, pw, err := s.CreateUser(ctx, nil, SystemActor, NewUser{
		Username: DefaultAdminUsername, DisplayName: "Administrator", Roles: []string{rbac.RoleAdmin},
	})
	if err != nil {
		return fmt.Errorf("auth: bootstrap admin: %w", err)
	}
	msg := fmt.Sprintf("\n=== PerfectImage first run ===\nAdministrator account: %s\nOne-time password:     %s\nYou must change it at first sign-in. It will not be shown again.\n\n", u.Username, pw)
	if console != nil {
		_, _ = io.WriteString(console, msg)
	}
	where := "console"
	if secretsDir != "" {
		p := filepath.Join(secretsDir, BootstrapFileName)
		if err := os.MkdirAll(secretsDir, 0o700); err == nil {
			if err := os.WriteFile(p, []byte(msg), 0o600); err == nil {
				bootstrapFile.Lock()
				bootstrapFile.path, bootstrapFile.user = p, u.Username
				bootstrapFile.Unlock()
				where = "console and " + p
			}
		}
	}
	s.log.Warn("created initial administrator; the one-time password was printed once (not logged)",
		"user", u.Username, "shown_on", where)
	return nil
}

// ResetAdmin implements AdminResetter: it resets (or creates) the named
// local account with the Admin role, a new one-time password, cleared
// lockout/MFA and no sessions. Used by `perfectimage user reset-admin`.
func (s *Service) ResetAdmin(ctx context.Context, username string) (string, error) {
	if username == "" {
		username = DefaultAdminUsername
	}
	if err := s.SeedRoles(ctx); err != nil {
		return "", err
	}
	u, err := s.UserByUsername(ctx, username)
	if errors.Is(err, ErrUserNotFound) {
		_, pw, err := s.CreateUser(ctx, nil, SystemActor, NewUser{
			Username: username, DisplayName: "Administrator", Roles: []string{rbac.RoleAdmin},
		})
		if err == nil {
			s.record(ctx, SystemActor, "user.reset_admin", "user:"+username, audit.OutcomeSuccess, "created", nil)
		}
		return pw, err
	}
	if err != nil {
		return "", err
	}
	if !u.IsLocal() {
		return "", fmt.Errorf("%w: %s", ErrNotLocal, u.Source)
	}
	pw := GeneratePassword()
	hash, err := HashPassword(pw, s.argon)
	if err != nil {
		return "", err
	}
	now := s.ms(s.now())
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		for _, q := range []struct {
			sql  string
			args []any
		}{
			{`UPDATE auth_users SET password_hash = ?, must_change_password = 1, disabled = 0, failed_logins = 0,
				locked_until = 0, totp_secret = '', totp_enabled = 0, password_changed_at = ?, updated_at = ? WHERE id = ?`,
				[]any{hash, now, now, u.ID}},
			{`DELETE FROM auth_recovery_codes WHERE user_id = ?`, []any{u.ID}},
			{`DELETE FROM auth_sessions WHERE user_id = ?`, []any{u.ID}},
			{`INSERT OR IGNORE INTO auth_user_roles (user_id, role) VALUES (?, ?)`, []any{u.ID, rbac.RoleAdmin}},
		} {
			if _, err := tx.ExecContext(ctx, q.sql, q.args...); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	s.record(ctx, SystemActor, "user.reset_admin", "user:"+u.Username, audit.OutcomeSuccess, "", nil)
	return pw, nil
}
