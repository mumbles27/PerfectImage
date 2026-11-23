package auth

import (
	"context"
	"database/sql"
	"errors"
	"html/template"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/secrets"
)

// TOTPIssuer is the issuer label shown in authenticator apps.
const TOTPIssuer = "PerfectImage"

// MFA errors.
var (
	ErrMFAInvalid     = errors.New("auth: invalid verification code")
	ErrMFANotEnrolled = errors.New("auth: no MFA enrollment in progress")
	ErrMFARequired    = errors.New("auth: MFA is required for your role and cannot be disabled")
	ErrNoSealer       = errors.New("auth: secrets sealer unavailable")
)

// Enrollment is a pending TOTP enrollment shown to the user.
type Enrollment struct {
	Secret string // base32, for manual entry
	URI    string
	// QR is a data:image/png URI, typed so html/template emits it as-is
	// (it is generated locally, never from user input).
	QR template.URL
}

func totpAAD(userID string) string { return "auth_users.totp:" + userID }

// BeginTOTP generates a new (not yet active) TOTP secret for u, stored
// sealed, and returns the provisioning data. An existing enabled secret is
// left untouched until ConfirmTOTP succeeds.
func (s *Service) BeginTOTP(ctx context.Context, u *User) (*Enrollment, error) {
	if s.sealer == nil {
		return nil, ErrNoSealer
	}
	if u.TOTPEnabled {
		return nil, errors.New("auth: MFA already enabled; disable it first")
	}
	secret := NewTOTPSecret()
	sealed, err := secrets.EncryptString(s.sealer, secret, totpAAD(u.ID))
	if err != nil {
		return nil, err
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE auth_users SET totp_secret = ?, totp_enabled = 0, updated_at = ? WHERE id = ?`,
		sealed, s.ms(s.now()), u.ID); err != nil {
		return nil, err
	}
	return enrollmentFor(u.Username, secret)
}

// PendingTOTP returns the in-progress enrollment for u (to re-render the
// QR code), or ErrMFANotEnrolled.
func (s *Service) PendingTOTP(u *User) (*Enrollment, error) {
	if u.TOTPEnabled || u.totpSecret == "" || s.sealer == nil {
		return nil, ErrMFANotEnrolled
	}
	secret, err := secrets.DecryptString(s.sealer, u.totpSecret, totpAAD(u.ID))
	if err != nil {
		return nil, ErrMFANotEnrolled
	}
	return enrollmentFor(u.Username, secret)
}

func enrollmentFor(username, secret string) (*Enrollment, error) {
	uri := TOTPURI(TOTPIssuer, username, secret)
	qrURI, err := QRCodeDataURI(uri)
	if err != nil {
		return nil, err
	}
	return &Enrollment{Secret: secret, URI: uri, QR: template.URL(qrURI)}, nil //nolint:gosec // locally generated data URI
}

// ConfirmTOTP activates the pending secret if code is valid and returns a
// fresh set of recovery codes (shown once; stored hashed).
func (s *Service) ConfirmTOTP(ctx context.Context, a Actor, u *User, code string) ([]string, error) {
	if u.TOTPEnabled || u.totpSecret == "" {
		return nil, ErrMFANotEnrolled
	}
	secret, err := secrets.DecryptString(s.sealer, u.totpSecret, totpAAD(u.ID))
	if err != nil {
		return nil, ErrMFANotEnrolled
	}
	step, ok := ValidateTOTP(secret, code, s.now(), u.totpLastStep)
	if !ok {
		s.record(ctx, a, "auth.mfa.enroll", "user:"+u.Username, audit.OutcomeFailure, "invalid code", nil)
		return nil, ErrMFAInvalid
	}
	codes := NewRecoveryCodes()
	err = s.db.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE auth_users SET totp_enabled = 1, totp_last_step = ?, updated_at = ? WHERE id = ?`,
			step, s.ms(s.now()), u.ID); err != nil {
			return err
		}
		return replaceRecoveryCodesTx(ctx, tx, u.ID, codes)
	})
	if err != nil {
		return nil, err
	}
	u.TOTPEnabled = true
	s.record(ctx, a, "auth.mfa.enroll", "user:"+u.Username, audit.OutcomeSuccess, "", nil)
	return codes, nil
}

func replaceRecoveryCodesTx(ctx context.Context, tx *sql.Tx, userID string, codes []string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM auth_recovery_codes WHERE user_id = ?`, userID); err != nil {
		return err
	}
	for _, c := range codes {
		if _, err := tx.ExecContext(ctx, `INSERT INTO auth_recovery_codes (user_id, code_hash) VALUES (?, ?)`,
			userID, hashRecoveryCode(c)); err != nil {
			return err
		}
	}
	return nil
}

// VerifyMFA checks a TOTP code or a recovery code for u during sign-in.
// Failures count towards the account lockout.
func (s *Service) VerifyMFA(ctx context.Context, a Actor, u *User, code string) error {
	fail := func(reason string) error {
		s.registerFailure(ctx, u)
		s.record(ctx, a, "auth.mfa.verify", "user:"+u.Username, audit.OutcomeFailure, reason, nil)
		return ErrMFAInvalid
	}
	if !s.userLimit.Allow("mfa:" + u.ID) {
		s.record(ctx, a, "auth.mfa.verify", "user:"+u.Username, audit.OutcomeFailure, "rate limited", nil)
		return ErrRateLimited
	}
	if u.Locked(s.now()) {
		s.record(ctx, a, "auth.mfa.verify", "user:"+u.Username, audit.OutcomeFailure, "account locked", nil)
		return ErrAccountLocked
	}
	if !u.TOTPEnabled {
		return fail("mfa not enabled")
	}
	if len(normalizeRecoveryCode(code)) == 16 {
		res, err := s.db.ExecContext(ctx, `UPDATE auth_recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at = 0`,
			s.ms(s.now()), u.ID, hashRecoveryCode(code))
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n != 1 {
			return fail("invalid recovery code")
		}
		s.loginSucceeded(ctx, u)
		s.record(ctx, a, "auth.mfa.verify", "user:"+u.Username, audit.OutcomeSuccess, "", map[string]any{"method": "recovery_code"})
		return nil
	}
	secret, err := secrets.DecryptString(s.sealer, u.totpSecret, totpAAD(u.ID))
	if err != nil {
		return fail("unreadable secret")
	}
	step, ok := ValidateTOTP(secret, code, s.now(), u.totpLastStep)
	if !ok {
		return fail("invalid code")
	}
	// Conditional update makes concurrent replays of the same code fail.
	res, err := s.db.ExecContext(ctx, `UPDATE auth_users SET totp_last_step = ? WHERE id = ? AND totp_last_step < ?`, step, u.ID, step)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return fail("code replayed")
	}
	u.totpLastStep = step
	s.loginSucceeded(ctx, u)
	s.record(ctx, a, "auth.mfa.verify", "user:"+u.Username, audit.OutcomeSuccess, "", map[string]any{"method": "totp"})
	return nil
}

// RecoveryCodesLeft returns the number of unused recovery codes.
func (s *Service) RecoveryCodesLeft(ctx context.Context, userID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM auth_recovery_codes WHERE user_id = ? AND used_at = 0`, userID).Scan(&n)
	return n, err
}

// RegenerateRecoveryCodes replaces u's recovery codes after verifying a
// current TOTP code.
func (s *Service) RegenerateRecoveryCodes(ctx context.Context, a Actor, u *User, code string) ([]string, error) {
	if err := s.VerifyMFA(ctx, a, u, code); err != nil {
		return nil, err
	}
	codes := NewRecoveryCodes()
	if err := s.db.Tx(ctx, func(tx *sql.Tx) error { return replaceRecoveryCodesTx(ctx, tx, u.ID, codes) }); err != nil {
		return nil, err
	}
	s.record(ctx, a, "auth.mfa.recovery_codes", "user:"+u.Username, audit.OutcomeSuccess, "", nil)
	return codes, nil
}

// DisableTOTP turns off MFA for the user themself after verifying a code.
func (s *Service) DisableTOTP(ctx context.Context, a Actor, u *User, code string) error {
	if req, err := s.MFARequired(ctx, u); err != nil {
		return err
	} else if req {
		return ErrMFARequired
	}
	if err := s.VerifyMFA(ctx, a, u, code); err != nil {
		return err
	}
	if err := s.clearTOTP(ctx, u.ID); err != nil {
		return err
	}
	s.record(ctx, a, "auth.mfa.disable", "user:"+u.Username, audit.OutcomeSuccess, "", nil)
	return nil
}

// ResetMFA clears another user's MFA enrollment (administrator action, e.g.
// lost device). Their sessions are revoked.
func (s *Service) ResetMFA(ctx context.Context, a Actor, userID string) error {
	u, err := s.UserByID(ctx, userID)
	if err != nil {
		return err
	}
	if err := s.clearTOTP(ctx, u.ID); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM auth_sessions WHERE user_id = ?`, u.ID); err != nil {
		return err
	}
	s.record(ctx, a, "auth.mfa.reset", "user:"+u.Username, audit.OutcomeSuccess, "", nil)
	return nil
}

func (s *Service) clearTOTP(ctx context.Context, userID string) error {
	return s.db.Tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `UPDATE auth_users SET totp_secret = '', totp_enabled = 0, updated_at = ? WHERE id = ?`,
			s.ms(s.now()), userID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `DELETE FROM auth_recovery_codes WHERE user_id = ?`, userID)
		return err
	})
}
