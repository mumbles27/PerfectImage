package auth

import (
	"context"
	"encoding/base32"
	"errors"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/mumbles27/PerfectImage/internal/audit"
)

// RFC 6238 Appendix B (SHA-1 seed), truncated to 6 digits.
func TestTOTPRFCVectors(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	tests := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}
	for _, tt := range tests {
		got, err := TOTPCode(secret, time.Unix(tt.unix, 0))
		if err != nil || got != tt.want {
			t.Errorf("T=%d: got %q, %v; want %q", tt.unix, got, err, tt.want)
		}
	}
}

func TestValidateTOTP(t *testing.T) {
	secret := NewTOTPSecret()
	now := time.Unix(1_700_000_000, 0)
	code, _ := TOTPCode(secret, now)
	prev, _ := TOTPCode(secret, now.Add(-30*time.Second))
	old, _ := TOTPCode(secret, now.Add(-90*time.Second))
	step := now.Unix() / 30
	tests := []struct {
		name     string
		code     string
		lastStep int64
		ok       bool
	}{
		{"current", code, 0, true},
		{"spaces", code[:3] + " " + code[3:], 0, true},
		{"previous step (skew)", prev, 0, true},
		{"too old", old, 0, false},
		{"replay", code, step, false},
		{"wrong length", "12345", 0, false},
		{"garbage", "abcdef", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, ok := ValidateTOTP(secret, tt.code, now, tt.lastStep); ok != tt.ok {
				t.Fatalf("ok = %v, want %v", ok, tt.ok)
			}
		})
	}
}

func TestTOTPURIAndQR(t *testing.T) {
	uri := TOTPURI("PerfectImage", "alice@example.com", "JBSWY3DPEHPK3PXP")
	u, err := url.Parse(uri)
	if err != nil || u.Scheme != "otpauth" || u.Host != "totp" || u.Query().Get("secret") != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("bad uri %q (%v)", uri, err)
	}
	qr, err := QRCodeDataURI(uri)
	if err != nil || !strings.HasPrefix(qr, "data:image/png;base64,iVBOR") {
		t.Fatalf("bad qr %.40q (%v)", qr, err)
	}
}

func TestMFAEnrollVerifyRecovery(t *testing.T) {
	f := newFixture(t, nil)
	ctx := context.Background()
	u := f.mustUser(t, "alice", "Lantern-Purple-42", "Viewer")
	a := Actor{ID: u.ID, Username: u.Username}

	enr, err := f.svc.BeginTOTP(ctx, u)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(enr.QR), "data:image/png") {
		t.Fatal("no QR")
	}
	u, _ = f.svc.UserByID(ctx, u.ID)
	if strings.Contains(u.totpSecret, enr.Secret) {
		t.Fatal("TOTP secret stored in clear")
	}
	if _, err := f.svc.ConfirmTOTP(ctx, a, u, "000000"); !errors.Is(err, ErrMFAInvalid) {
		t.Fatalf("bad code accepted: %v", err)
	}
	code, _ := TOTPCode(enr.Secret, f.clock.Now())
	codes, err := f.svc.ConfirmTOTP(ctx, a, u, code)
	if err != nil || len(codes) != RecoveryCodeCount {
		t.Fatalf("confirm: %v (%d codes)", err, len(codes))
	}
	u, _ = f.svc.UserByID(ctx, u.ID)
	if !u.TOTPEnabled {
		t.Fatal("not enabled")
	}
	// Same code again (replay) fails; next step succeeds.
	if err := f.svc.VerifyMFA(ctx, a, u, code); !errors.Is(err, ErrMFAInvalid) {
		t.Fatalf("replay accepted: %v", err)
	}
	f.clock.Add(30 * time.Second)
	next, _ := TOTPCode(enr.Secret, f.clock.Now())
	if err := f.svc.VerifyMFA(ctx, a, u, next); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Recovery codes are single-use and case/dash-insensitive.
	rc := strings.ToUpper(strings.ReplaceAll(codes[0], "-", ""))
	if err := f.svc.VerifyMFA(ctx, a, u, rc); err != nil {
		t.Fatalf("recovery code: %v", err)
	}
	if err := f.svc.VerifyMFA(ctx, a, u, codes[0]); !errors.Is(err, ErrMFAInvalid) {
		t.Fatalf("recovery code reused: %v", err)
	}
	if n, _ := f.svc.RecoveryCodesLeft(ctx, u.ID); n != RecoveryCodeCount-1 {
		t.Fatalf("left = %d", n)
	}
	var stored string
	_ = f.db.QueryRowContext(ctx, `SELECT code_hash FROM auth_recovery_codes WHERE user_id = ? LIMIT 1`, u.ID).Scan(&stored)
	for _, c := range codes {
		if strings.Contains(stored, normalizeRecoveryCode(c)) {
			t.Fatal("recovery code stored in clear")
		}
	}
	if !f.audit.has("auth.mfa.enroll", audit.OutcomeSuccess) || !f.audit.has("auth.mfa.verify", audit.OutcomeFailure) {
		t.Fatal("missing MFA audit events")
	}
	// Disable requires a valid code.
	f.clock.Add(30 * time.Second)
	if err := f.svc.DisableTOTP(ctx, a, u, "123456"); err == nil {
		t.Fatal("disabled with bad code")
	}
	c3, _ := TOTPCode(enr.Secret, f.clock.Now())
	if err := f.svc.DisableTOTP(ctx, a, u, c3); err != nil {
		t.Fatal(err)
	}
	if u, _ = f.svc.UserByID(ctx, u.ID); u.TOTPEnabled {
		t.Fatal("still enabled")
	}
}

func TestMFARequiredCannotDisable(t *testing.T) {
	f := newFixture(t, func(o *Options) { o.Config.MFARequiredRoles = []string{"admin"} })
	ctx := context.Background()
	u := f.mustUser(t, "root", "Lantern-Purple-42", "Admin")
	if req, _ := f.svc.MFARequired(ctx, u); !req {
		t.Fatal("MFA not required for Admin (case-insensitive)")
	}
	if stage, _ := f.svc.nextStage(ctx, u, "password", false); stage != StageMFAEnroll {
		t.Fatalf("stage = %s, want %s", stage, StageMFAEnroll)
	}
	if stage, _ := f.svc.nextStage(ctx, u, "oidc:corp", false); stage != StageActive {
		t.Fatalf("oidc stage = %s, want active (IdP handles MFA)", stage)
	}
	if err := f.svc.DisableTOTP(ctx, Actor{}, u, "000000"); !errors.Is(err, ErrMFARequired) {
		t.Fatalf("err = %v", err)
	}
}
