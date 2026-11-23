package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/rbac"
)

// User sources.
const (
	SourceLocal = "local"
	SourceLDAP  = "ldap"
	// SourceOIDCPrefix + provider name.
	SourceOIDCPrefix = "oidc:"
)

// User is an account. Secret fields are never exposed.
type User struct {
	ID                 string
	Username           string
	DisplayName        string
	Email              string
	Source             string
	MustChangePassword bool
	Disabled           bool
	FailedLogins       int
	LockedUntil        time.Time
	TOTPEnabled        bool
	PasswordChangedAt  time.Time
	LastLoginAt        time.Time
	CreatedAt          time.Time
	Roles              []string

	passwordHash string
	totpSecret   string // sealed
	totpLastStep int64
}

// Locked reports whether the account is locked at t.
func (u *User) Locked(t time.Time) bool { return u.LockedUntil.After(t) }

// IsLocal reports whether the user authenticates with a local password.
func (u *User) IsLocal() bool { return u.Source == SourceLocal }

// IsOIDC reports whether the user signs in through an OIDC provider.
func (u *User) IsOIDC() bool { return strings.HasPrefix(u.Source, SourceOIDCPrefix) }

// Name returns the display name or username.
func (u *User) Name() string {
	if u.DisplayName != "" {
		return u.DisplayName
	}
	return u.Username
}

// Errors.
var (
	ErrUserNotFound       = errors.New("auth: user not found")
	ErrUserExists         = errors.New("auth: username already taken")
	ErrInvalidCredentials = errors.New("auth: invalid username or password")
	ErrAccountLocked      = errors.New("auth: account temporarily locked")
	ErrAccountDisabled    = errors.New("auth: account disabled")
	ErrRateLimited        = errors.New("auth: too many attempts, try again later")
	ErrNotLocal           = errors.New("auth: account is managed by an external identity provider")
	ErrSelf               = errors.New("auth: you cannot do this to your own account")
)

var usernameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]{0,127}$`)

// ValidUsername reports whether name is an acceptable username.
func ValidUsername(name string) bool { return usernameRE.MatchString(name) }

const userCols = `id, username, display_name, email, source, password_hash, must_change_password, disabled,
	failed_logins, locked_until, totp_secret, totp_enabled, totp_last_step, password_changed_at,
	last_login_at, created_at`

type scanner interface{ Scan(...any) error }

func scanUser(sc scanner) (*User, error) {
	var u User
	var locked, pwc, last, created int64
	err := sc.Scan(&u.ID, &u.Username, &u.DisplayName, &u.Email, &u.Source, &u.passwordHash,
		&u.MustChangePassword, &u.Disabled, &u.FailedLogins, &locked, &u.totpSecret, &u.TOTPEnabled,
		&u.totpLastStep, &pwc, &last, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, err
	}
	u.LockedUntil, u.PasswordChangedAt, u.LastLoginAt, u.CreatedAt = fromMS(locked), fromMS(pwc), fromMS(last), fromMS(created)
	return &u, nil
}

// UserByID loads a user with roles.
func (s *Service) UserByID(ctx context.Context, id string) (*User, error) {
	return s.loadUser(ctx, `SELECT `+userCols+` FROM auth_users WHERE id = ?`, id)
}

// UserByUsername loads a user (case-insensitive) with roles.
func (s *Service) UserByUsername(ctx context.Context, name string) (*User, error) {
	return s.loadUser(ctx, `SELECT `+userCols+` FROM auth_users WHERE username = ?`, name)
}

func (s *Service) loadUser(ctx context.Context, q string, arg any) (*User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx, q, arg))
	if err != nil {
		return nil, err
	}
	u.Roles, err = s.userRoles(ctx, u.ID)
	return u, err
}

// Users lists all users with roles, ordered by username.
func (s *Service) Users(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM auth_users ORDER BY username`)
	if err != nil {
		return nil, err
	}
	var users []*User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		users = append(users, u)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, u := range users {
		if u.Roles, err = s.userRoles(ctx, u.ID); err != nil {
			return nil, err
		}
	}
	return users, nil
}

// CountUsers returns the number of accounts.
func (s *Service) CountUsers(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM auth_users`).Scan(&n)
	return n, err
}

// NewUser describes an account to create.
type NewUser struct {
	Username    string
	DisplayName string
	Email       string
	Source      string // default local
	Roles       []string
	// Password is the initial local password; empty generates a one-time
	// password that is returned by CreateUser. Local users created by an
	// administrator must change it at first sign-in.
	Password string
}

// CreateUser creates an account. For local users it returns the initial
// password (generated when none was given). actor may be nil for system.
func (s *Service) CreateUser(ctx context.Context, actor *Principal, a Actor, nu NewUser) (*User, string, error) {
	nu.Username = strings.TrimSpace(nu.Username)
	if !ValidUsername(nu.Username) {
		return nil, "", fmt.Errorf("%w: usernames are 1-128 letters, digits, . _ @ -", ErrInvalidName)
	}
	if nu.Source == "" {
		nu.Source = SourceLocal
	}
	roles, unknown, err := s.canonicalRoles(ctx, nu.Roles)
	if err != nil {
		return nil, "", err
	}
	if len(unknown) > 0 {
		return nil, "", fmt.Errorf("%w: %s", ErrRoleNotFound, strings.Join(unknown, ", "))
	}
	perms, err := s.rolesPermissions(ctx, roles)
	if err != nil {
		return nil, "", err
	}
	if err := checkGrant(actor, perms); err != nil {
		s.record(ctx, a, "user.create", "user:"+nu.Username, audit.OutcomeDenied, err.Error(), nil)
		return nil, "", err
	}
	var hash, password string
	if nu.Source == SourceLocal {
		password = nu.Password
		if password == "" {
			password = GeneratePassword()
		} else if err := s.Policy().Check(nu.Username, password); err != nil {
			return nil, "", err
		}
		if hash, err = HashPassword(password, s.argon); err != nil {
			return nil, "", err
		}
	}
	now := s.ms(s.now())
	id := newID()
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO auth_users (id, username, display_name, email, source,
			password_hash, must_change_password, password_changed_at, created_at, updated_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, nu.Username, strings.TrimSpace(nu.DisplayName), strings.TrimSpace(nu.Email), nu.Source,
			hash, nu.Source == SourceLocal, now, now, now); err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return ErrUserExists
			}
			return err
		}
		_, err := s.setUserRolesTx(ctx, tx, id, roles)
		return err
	})
	if err != nil {
		s.record(ctx, a, "user.create", "user:"+nu.Username, audit.OutcomeFailure, err.Error(), nil)
		return nil, "", err
	}
	s.record(ctx, a, "user.create", "user:"+nu.Username, audit.OutcomeSuccess, "",
		map[string]any{"roles": roles, "source": nu.Source})
	u, err := s.UserByID(ctx, id)
	return u, password, err
}

// UpdateUser changes profile fields and roles. Role changes rotate the
// user's sessions.
func (s *Service) UpdateUser(ctx context.Context, actor *Principal, a Actor, id, displayName, email string, roles []string) error {
	u, err := s.UserByID(ctx, id)
	if err != nil {
		return err
	}
	roles, unknown, err := s.canonicalRoles(ctx, roles)
	if err != nil {
		return err
	}
	if len(unknown) > 0 {
		return fmt.Errorf("%w: %s", ErrRoleNotFound, strings.Join(unknown, ", "))
	}
	// The actor must hold every permission of any role being added or removed.
	var delta []string
	for _, r := range roles {
		if !slices.Contains(u.Roles, r) {
			delta = append(delta, r)
		}
	}
	for _, r := range u.Roles {
		if !slices.Contains(roles, r) {
			delta = append(delta, r)
		}
	}
	perms, err := s.rolesPermissions(ctx, delta)
	if err != nil {
		return err
	}
	if err := checkGrant(actor, perms); err != nil {
		s.record(ctx, a, "user.update", "user:"+u.Username, audit.OutcomeDenied, err.Error(), nil)
		return err
	}
	var changed bool
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if slices.Contains(u.Roles, rbac.RoleAdmin) && !slices.Contains(roles, rbac.RoleAdmin) && !u.Disabled {
			n, err := enabledAdminsTx(ctx, tx, u.ID)
			if err != nil {
				return err
			}
			if n == 0 {
				return ErrLastAdmin
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE auth_users SET display_name = ?, email = ?, updated_at = ? WHERE id = ?`,
			strings.TrimSpace(displayName), strings.TrimSpace(email), s.ms(s.now()), u.ID); err != nil {
			return err
		}
		changed, err = s.setUserRolesTx(ctx, tx, u.ID, roles)
		return err
	})
	if err != nil {
		s.record(ctx, a, "user.update", "user:"+u.Username, audit.OutcomeFailure, err.Error(), nil)
		return err
	}
	details := map[string]any{}
	if changed {
		details["roles_before"], details["roles_after"] = u.Roles, roles
	}
	s.record(ctx, a, "user.update", "user:"+u.Username, audit.OutcomeSuccess, "", details)
	return nil
}

// SetDisabled enables or disables an account. Disabling revokes sessions and
// API token use (tokens are rejected while the owner is disabled).
func (s *Service) SetDisabled(ctx context.Context, a Actor, id string, disabled bool) error {
	u, err := s.UserByID(ctx, id)
	if err != nil {
		return err
	}
	if disabled && a.ID == u.ID {
		return ErrSelf
	}
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if disabled && slices.Contains(u.Roles, rbac.RoleAdmin) {
			n, err := enabledAdminsTx(ctx, tx, u.ID)
			if err != nil {
				return err
			}
			if n == 0 {
				return ErrLastAdmin
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE auth_users SET disabled = ?, updated_at = ? WHERE id = ?`,
			disabled, s.ms(s.now()), u.ID); err != nil {
			return err
		}
		if disabled {
			_, err := tx.ExecContext(ctx, `DELETE FROM auth_sessions WHERE user_id = ?`, u.ID)
			return err
		}
		return nil
	})
	action := "user.enable"
	if disabled {
		action = "user.disable"
	}
	if err != nil {
		s.record(ctx, a, action, "user:"+u.Username, audit.OutcomeFailure, err.Error(), nil)
		return err
	}
	s.record(ctx, a, action, "user:"+u.Username, audit.OutcomeSuccess, "", nil)
	return nil
}

// DeleteUser removes an account and everything it owns.
func (s *Service) DeleteUser(ctx context.Context, actor *Principal, a Actor, id string) error {
	u, err := s.UserByID(ctx, id)
	if err != nil {
		return err
	}
	if a.ID == u.ID {
		return ErrSelf
	}
	perms, err := s.rolesPermissions(ctx, u.Roles)
	if err != nil {
		return err
	}
	if err := checkGrant(actor, perms); err != nil {
		s.record(ctx, a, "user.delete", "user:"+u.Username, audit.OutcomeDenied, err.Error(), nil)
		return err
	}
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if slices.Contains(u.Roles, rbac.RoleAdmin) && !u.Disabled {
			n, err := enabledAdminsTx(ctx, tx, u.ID)
			if err != nil {
				return err
			}
			if n == 0 {
				return ErrLastAdmin
			}
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM auth_users WHERE id = ?`, u.ID)
		return err
	})
	if err != nil {
		s.record(ctx, a, "user.delete", "user:"+u.Username, audit.OutcomeFailure, err.Error(), nil)
		return err
	}
	s.record(ctx, a, "user.delete", "user:"+u.Username, audit.OutcomeSuccess, "", nil)
	return nil
}

// Unlock clears the failed-login counter and lockout.
func (s *Service) Unlock(ctx context.Context, a Actor, id string) error {
	u, err := s.UserByID(ctx, id)
	if err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE auth_users SET failed_logins = 0, locked_until = 0, updated_at = ? WHERE id = ?`,
		s.ms(s.now()), u.ID); err != nil {
		return err
	}
	s.record(ctx, a, "user.unlock", "user:"+u.Username, audit.OutcomeSuccess, "", nil)
	return nil
}

// ResetPassword sets a new one-time password for a local user, forcing a
// change at next sign-in and revoking existing sessions. The password is
// returned once and never logged.
func (s *Service) ResetPassword(ctx context.Context, actor *Principal, a Actor, id string) (string, error) {
	u, err := s.UserByID(ctx, id)
	if err != nil {
		return "", err
	}
	if !u.IsLocal() {
		return "", ErrNotLocal
	}
	perms, err := s.rolesPermissions(ctx, u.Roles)
	if err != nil {
		return "", err
	}
	if err := checkGrant(actor, perms); err != nil {
		s.record(ctx, a, "user.password.reset", "user:"+u.Username, audit.OutcomeDenied, err.Error(), nil)
		return "", err
	}
	pw := GeneratePassword()
	if err := s.setPassword(ctx, u.ID, pw, true, ""); err != nil {
		return "", err
	}
	s.record(ctx, a, "user.password.reset", "user:"+u.Username, audit.OutcomeSuccess, "", nil)
	return pw, nil
}

// Policy returns the configured password policy.
func (s *Service) Policy() PasswordPolicy { return PasswordPolicy{MinLength: s.cfg.PasswordMinLength} }

// setPassword stores a new hash, clears lockout and revokes all sessions and
// tokens-in-flight except keepSession.
func (s *Service) setPassword(ctx context.Context, userID, password string, mustChange bool, keepSession string) error {
	hash, err := HashPassword(password, s.argon)
	if err != nil {
		return err
	}
	now := s.ms(s.now())
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE auth_users SET password_hash = ?, must_change_password = ?,
			password_changed_at = ?, failed_logins = 0, locked_until = 0, updated_at = ? WHERE id = ?`,
			hash, mustChange, now, now, userID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM auth_sessions WHERE user_id = ? AND id <> ?`, userID, keepSession)
		return err
	})
}

// ChangePassword changes a local user's own password after verifying the
// current one. Other sessions are revoked; sessionID is kept (the caller
// should rotate it).
func (s *Service) ChangePassword(ctx context.Context, a Actor, userID, current, next, sessionID string) error {
	u, err := s.UserByID(ctx, userID)
	if err != nil {
		return err
	}
	if !u.IsLocal() {
		return ErrNotLocal
	}
	if _, err := VerifyPassword(current, u.passwordHash, s.argon); err != nil {
		s.record(ctx, a, "user.password.change", "user:"+u.Username, audit.OutcomeFailure, "current password incorrect", nil)
		return ErrInvalidCredentials
	}
	if current == next {
		return &PolicyError{"must differ from the current password"}
	}
	if err := s.Policy().Check(u.Username, next); err != nil {
		return err
	}
	if err := s.setPassword(ctx, u.ID, next, false, sessionID); err != nil {
		return err
	}
	s.record(ctx, a, "user.password.change", "user:"+u.Username, audit.OutcomeSuccess, "", nil)
	removeBootstrapFile(u.Username)
	return nil
}

// Authenticated is the result of a successful first-factor login.
type Authenticated struct {
	User   *User
	Method string // password | ldap | oidc
}

// Login verifies a username/password against the local store or LDAP,
// applying rate limits, lockout with exponential backoff and audit. Error
// messages are generic to avoid account enumeration.
func (s *Service) Login(ctx context.Context, meta RequestMeta, username, password string) (*Authenticated, error) {
	username = strings.TrimSpace(username)
	a := Actor{Username: username, Meta: meta}
	fail := func(reason string, err error) (*Authenticated, error) {
		s.record(ctx, a, "auth.login", "user:"+username, audit.OutcomeFailure, reason, map[string]any{"method": "password"})
		return nil, err
	}
	if !s.ipLimit.Allow("ip:"+meta.IP) || !s.userLimit.Allow("user:"+strings.ToLower(username)) {
		return fail("rate limited", ErrRateLimited)
	}
	if username == "" || password == "" || len(password) > MaxPasswordLength {
		return fail("missing credentials", ErrInvalidCredentials)
	}
	u, err := s.UserByUsername(ctx, username)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return nil, err
	}
	now := s.now()
	if u != nil {
		a.ID, a.Username = u.ID, u.Username
		if u.Locked(now) {
			return fail("account locked", ErrAccountLocked)
		}
	}
	if u == nil || u.Source == SourceLDAP {
		if cfg, err := s.LDAPConfig(ctx); err == nil && cfg.Enabled {
			lu, err := s.loginLDAP(ctx, cfg, a, username, password)
			if err != nil {
				if u != nil {
					s.registerFailure(ctx, u)
				}
				if errors.Is(err, ErrInvalidCredentials) || errors.Is(err, ErrAccountDisabled) {
					return fail(err.Error(), ErrInvalidCredentials)
				}
				s.log.Warn("ldap login error", "err", err)
				return fail("ldap error", ErrInvalidCredentials)
			}
			s.loginSucceeded(ctx, lu)
			s.record(ctx, Actor{ID: lu.ID, Username: lu.Username, Meta: meta}, "auth.login", "user:"+lu.Username,
				audit.OutcomeSuccess, "", map[string]any{"method": "ldap"})
			return &Authenticated{User: lu, Method: "ldap"}, nil
		}
	}
	if u == nil || !u.IsLocal() || u.passwordHash == "" {
		_, _ = VerifyPassword(password, s.dummyHash, s.argon) // equalize timing
		if u == nil {
			return fail("unknown user", ErrInvalidCredentials)
		}
		return fail("not a local account", ErrInvalidCredentials)
	}
	rehash, err := VerifyPassword(password, u.passwordHash, s.argon)
	if err != nil {
		s.registerFailure(ctx, u)
		return fail("bad password", ErrInvalidCredentials)
	}
	if u.Disabled {
		return fail("account disabled", ErrAccountDisabled)
	}
	if rehash {
		if h, err := HashPassword(password, s.argon); err == nil {
			_, _ = s.db.ExecContext(ctx, `UPDATE auth_users SET password_hash = ? WHERE id = ?`, h, u.ID)
		}
	}
	s.loginSucceeded(ctx, u)
	s.record(ctx, a, "auth.login", "user:"+u.Username, audit.OutcomeSuccess, "", map[string]any{"method": "password"})
	return &Authenticated{User: u, Method: "password"}, nil
}

// registerFailure increments the failure counter and applies the lockout
// with exponential backoff once the threshold is reached.
func (s *Service) registerFailure(ctx context.Context, u *User) {
	if s.cfg.LockoutThreshold <= 0 {
		return
	}
	n := u.FailedLogins + 1
	var until int64
	if n >= s.cfg.LockoutThreshold {
		d := s.cfg.LockoutDuration
		for i := s.cfg.LockoutThreshold; i < n && d < s.cfg.LockoutMaxDuration; i++ {
			d *= 2
		}
		d = min(d, s.cfg.LockoutMaxDuration)
		until = s.ms(s.now().Add(d))
		s.log.Warn("account locked after failed logins", "user", u.Username, "failures", n, "duration", d.String())
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE auth_users SET failed_logins = failed_logins + 1,
		locked_until = MAX(locked_until, ?) WHERE id = ?`, until, u.ID); err != nil {
		s.log.Warn("record failed login", "err", err)
	}
	u.FailedLogins = n
}

func (s *Service) loginSucceeded(ctx context.Context, u *User) {
	if _, err := s.db.ExecContext(ctx, `UPDATE auth_users SET failed_logins = 0, locked_until = 0, last_login_at = ? WHERE id = ?`,
		s.ms(s.now()), u.ID); err != nil {
		s.log.Warn("record login", "err", err)
	}
}
