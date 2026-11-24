package packer

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// passEnv lists environment variables inherited by packer. Everything else
// (in particular unrelated credentials in the service environment) is
// dropped.
var passEnv = []string{
	"PATH", "HOME", "USER", "LANG", "LC_ALL", "TMPDIR", "TEMP", "TMP",
	"SystemRoot", "SYSTEMROOT", "windir", "ComSpec", "PATHEXT", "USERPROFILE",
	"APPDATA", "LOCALAPPDATA", "ProgramData", "ProgramFiles", "ProgramFiles(x86)",
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
	"SSL_CERT_FILE", "SSL_CERT_DIR",
}

// BaseEnv returns the inherited allowlisted environment.
func BaseEnv() []string {
	var env []string
	for _, k := range passEnv {
		if v, ok := os.LookupEnv(k); ok {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// Runner executes packer commands.
type Runner struct {
	Binary string
	Dir    string
	Env    []string
	// Grace is how long packer gets after an interrupt before it is killed.
	Grace time.Duration
}

// Run executes packer with args. Each stdout line is passed to onStdout and
// each stderr line to onStderr. When ctx is canceled packer receives an
// interrupt (so it can delete the build VM) and is killed after Grace.
func (r Runner) Run(ctx context.Context, args []string, onStdout, onStderr func(string)) error {
	cmd := exec.CommandContext(ctx, r.Binary, args...)
	cmd.Dir = r.Dir
	cmd.Env = r.Env
	setProcAttrs(cmd)
	cmd.Cancel = func() error { return interrupt(cmd) }
	cmd.WaitDelay = r.Grace
	if cmd.WaitDelay <= 0 {
		cmd.WaitDelay = 30 * time.Second
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start packer: %w", err)
	}
	// Enforce the kill deadline here rather than relying on WaitDelay alone:
	// WaitDelay only starts inside cmd.Wait, which runs after the output
	// readers finish, and a child process holding the pipes open would
	// otherwise block them forever. Killing the process group closes them.
	done := make(chan struct{})
	go func() {
		select {
		case <-done:
			return
		case <-ctx.Done():
		}
		t := time.NewTimer(cmd.WaitDelay)
		defer t.Stop()
		select {
		case <-done:
		case <-t.C:
			killTree(cmd)
		}
	}()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); scanLines(stdout, onStdout) }()
	go func() { defer wg.Done(); scanLines(stderr, onStderr) }()
	wg.Wait()
	err = cmd.Wait()
	close(done)
	killTree(cmd)
	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return fmt.Errorf("packer %s exited with code %d", args[0], ee.ExitCode())
	}
	return err
}

func scanLines(r io.Reader, fn func(string)) {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := br.ReadString('\n')
		if line != "" && fn != nil {
			fn(strings.TrimRight(line, "\r\n"))
		}
		if err != nil {
			return
		}
	}
}
