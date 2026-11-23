package auth

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestHashAndVerifyPassword(t *testing.T) {
	h, err := HashPassword("correct horse", cheapArgon)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Fatalf("unexpected encoding %q", h)
	}
	h2, _ := HashPassword("correct horse", cheapArgon)
	if h == h2 {
		t.Fatal("hashes are not salted")
	}
	stronger := cheapArgon
	stronger.Iterations = 2
	tests := []struct {
		name       string
		password   string
		hash       string
		want       Argon2Params
		wantErr    error
		wantRehash bool
	}{
		{"match", "correct horse", h, cheapArgon, nil, false},
		{"mismatch", "wrong horse", h, cheapArgon, ErrPasswordMismatch, false},
		{"rehash on new params", "correct horse", h, stronger, nil, true},
		{"malformed", "x", "$argon2id$v=19$garbage", cheapArgon, errMalformedHash, false},
		{"other algorithm", "x", "$2a$10$abcdefghijklmnopqrstuv", cheapArgon, errMalformedHash, false},
		{"absurd memory", "x", "$argon2id$v=19$m=99999999,t=1,p=1$c2FsdHNhbHQ$aGFzaGhhc2hoYXNoaGFzaA", cheapArgon, errMalformedHash, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rehash, err := VerifyPassword(tt.password, tt.hash, tt.want)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if rehash != tt.wantRehash {
				t.Fatalf("rehash = %v, want %v", rehash, tt.wantRehash)
			}
		})
	}
}

func TestPasswordPolicy(t *testing.T) {
	p := PasswordPolicy{MinLength: 12}
	tests := []struct {
		name, user, pw string
		ok             bool
	}{
		{"good", "alice", "Lantern-Purple-42", true},
		{"too short", "alice", "Sh0rt!", false},
		{"common", "alice", "passwordpassword", true}, // not in list verbatim
		{"common exact", "alice", "administrator", false},
		{"common with suffix", "alice", "Welcome1234!!", false},
		{"contains username", "alice", "my-alice-password-x", false},
		{"repetitive", "alice", "aaaaaaaaaaaaaaaa", false},
		{"blank", "alice", "              ", false},
		{"too long", "alice", strings.Repeat("ab1-", 100), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := p.Check(tt.user, tt.pw)
			if (err == nil) != tt.ok {
				t.Fatalf("Check(%q) = %v, want ok=%v", tt.pw, err, tt.ok)
			}
			var pe *PolicyError
			if err != nil && !errors.As(err, &pe) {
				t.Fatalf("error %v is not a PolicyError", err)
			}
		})
	}
}

func TestGeneratePasswordSatisfiesPolicy(t *testing.T) {
	seen := map[string]bool{}
	for range 50 {
		pw := GeneratePassword()
		if seen[pw] {
			t.Fatal("duplicate generated password")
		}
		seen[pw] = true
		if err := (PasswordPolicy{MinLength: 24}).Check("admin", pw); err != nil {
			t.Fatalf("generated %q rejected: %v", pw, err)
		}
	}
}

func TestRateLimiter(t *testing.T) {
	now := time.Unix(0, 0)
	l := NewRateLimiter(3)
	l.now = func() time.Time { return now }
	for i := range 3 {
		if !l.Allow("k") {
			t.Fatalf("attempt %d denied", i)
		}
	}
	if l.Allow("k") {
		t.Fatal("4th attempt allowed")
	}
	if !l.Allow("other") {
		t.Fatal("keys are not independent")
	}
	now = now.Add(20 * time.Second) // 3/min => one token per 20s
	if !l.Allow("k") || l.Allow("k") {
		t.Fatal("refill incorrect")
	}
	now = now.Add(time.Hour)
	l.Prune()
	if len(l.buckets) != 0 {
		t.Fatalf("prune left %d buckets", len(l.buckets))
	}
	var disabled *RateLimiter
	if !disabled.Allow("x") || !NewRateLimiter(0).Allow("x") {
		t.Fatal("disabled limiter denied")
	}
}
