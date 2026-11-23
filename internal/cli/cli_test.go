package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// isolate snapshots the global registry and restores it after the test.
func isolate(t *testing.T) {
	t.Helper()
	mu.Lock()
	saved := make(map[string]Command, len(commands))
	for k, v := range commands {
		saved[k] = v
	}
	mu.Unlock()
	t.Cleanup(func() {
		mu.Lock()
		commands = saved
		mu.Unlock()
	})
}

func TestMainDispatch(t *testing.T) {
	isolate(t)
	var got []string
	Register(Command{Name: "test cmd", Summary: "test", Run: func(_ context.Context, env *Env, args []string) error {
		got = args
		return nil
	}})
	tests := []struct {
		name     string
		args     []string
		wantCode int
		wantErr  string
	}{
		{"no args", nil, 2, ""},
		{"help", []string{"help"}, 0, ""},
		{"unknown", []string{"bogus"}, 2, "unknown command"},
		{"multi word", []string{"test", "cmd", "x"}, 0, ""},
		{"stub", []string{"catalog", "validate"}, 1, "not yet implemented"},
		{"stub names interface", []string{"user", "reset-admin"}, 1, "auth.AdminResetter"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			code := Main(context.Background(), &Env{Stdout: &out, Stderr: &errb}, tt.args)
			if code != tt.wantCode || !strings.Contains(errb.String(), tt.wantErr) {
				t.Fatalf("code=%d stderr=%q", code, errb.String())
			}
		})
	}
	if len(got) != 1 || got[0] != "x" {
		t.Errorf("args = %v", got)
	}
}

func TestRegisterReplacesStubOnly(t *testing.T) {
	isolate(t)
	Register(Command{Name: "backup", Run: func(context.Context, *Env, []string) error { return nil }})
	if c, _, _ := lookup([]string{"backup"}); c.stub {
		t.Fatal("stub not replaced")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("double registration did not panic")
		}
	}()
	Register(Command{Name: "backup", Run: func(context.Context, *Env, []string) error { return nil }})
}

func TestParseFlags(t *testing.T) {
	env := &Env{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
	fs, cfg := FlagSet(env, "x")
	if err := ParseFlags(fs, []string{"--config", "/tmp/c.yaml"}); err != nil || *cfg != "/tmp/c.yaml" {
		t.Fatalf("cfg=%q err=%v", *cfg, err)
	}
	fs, _ = FlagSet(env, "x")
	if err := ParseFlags(fs, []string{"extra"}); err == nil {
		t.Fatal("extra args accepted")
	}
}
