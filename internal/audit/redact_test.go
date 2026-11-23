package audit

import (
	"reflect"
	"testing"
)

func TestIsSensitiveKey(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"password", true},
		{"Password", true},
		{"db_password", true},
		{"client-secret", true},
		{"hmacSecret", true},
		{"token", true},
		{"access_token", true},
		{"API-Key", true},
		{"api_key", true},
		{"Authorization", true},
		{"private.key", true},
		{"passphrase", true},
		{"user", false},
		{"action", false},
		{"target", false},
		{"keyboard", false},
	}
	for _, tt := range tests {
		if got := IsSensitiveKey(tt.key); got != tt.want {
			t.Errorf("IsSensitiveKey(%q) = %v, want %v", tt.key, got, tt.want)
		}
	}
}

func TestRedact(t *testing.T) {
	in := map[string]any{
		"user":     "alice",
		"password": "hunter2",
		"nested": map[string]any{
			"token": "abc",
			"ok":    1,
			"list":  []any{map[string]any{"secret": "x", "n": "y"}},
		},
		"headers": map[string]string{"Authorization": "Bearer z", "Accept": "json"},
	}
	want := map[string]any{
		"user":     "alice",
		"password": Redacted,
		"nested": map[string]any{
			"token": Redacted,
			"ok":    1,
			"list":  []any{map[string]any{"secret": Redacted, "n": "y"}},
		},
		"headers": map[string]any{"Authorization": Redacted, "Accept": "json"},
	}
	got := Redact(in)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Redact:\n got %#v\nwant %#v", got, want)
	}
	if in["password"] != "hunter2" {
		t.Fatal("Redact mutated its input")
	}
	if Redact(nil) != nil {
		t.Fatal("Redact(nil) != nil")
	}
}
