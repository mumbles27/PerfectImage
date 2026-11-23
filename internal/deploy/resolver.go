package deploy

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync/atomic"
)

// Shells supported by InstallStep.
const (
	ShellBash       = "bash"
	ShellPowerShell = "powershell"
)

// OS families.
const (
	OSLinux   = "linux"
	OSWindows = "windows"
)

// InstallStep is one post-deploy action run in the guest via the QEMU guest
// agent.
type InstallStep struct {
	// Name is shown in the job log.
	Name string `json:"name"`
	// Shell is "bash" or "powershell".
	Shell string `json:"shell"`
	// Script is the install script. It must be idempotent and must not print
	// secrets (its output goes to the job log).
	Script string `json:"script"`
	// VerifyScript, if set, runs after Script; a non-zero exit fails the step.
	VerifyScript string `json:"verify_script,omitempty"`
}

// Validate checks the step.
func (s InstallStep) Validate() error {
	switch {
	case s.Name == "":
		return errors.New("install step has no name")
	case s.Shell != ShellBash && s.Shell != ShellPowerShell:
		return fmt.Errorf("install step %q: shell must be bash or powershell, got %q", s.Name, s.Shell)
	case s.Script == "":
		return fmt.Errorf("install step %q: empty script", s.Name)
	}
	return nil
}

// AppResolver resolves app IDs to install steps for an OS family ("linux" or
// "windows"). The catalog package provides the real implementation.
type AppResolver interface {
	Resolve(ctx context.Context, os string, appIDs []string) ([]InstallStep, error)
}

// AppInfo describes a selectable app in the wizard.
type AppInfo struct {
	ID          string
	Name        string
	Description string
}

// AppLister is optionally implemented by an AppResolver to populate the
// wizard's app checkboxes.
type AppLister interface {
	Apps(ctx context.Context, os string) ([]AppInfo, error)
}

// ErrUnknownApp is returned (wrapped) for app IDs the resolver does not know.
var ErrUnknownApp = errors.New("deploy: unknown app")

// StaticApp is an entry of a StaticResolver.
type StaticApp struct {
	Info  AppInfo
	Steps []InstallStep
}

// StaticResolver resolves apps from an in-memory map keyed by OS then app ID.
// The zero value knows no apps. It is the stub used until the catalog-backed
// resolver is installed with SetAppResolver.
type StaticResolver map[string]map[string]StaticApp

// Resolve implements AppResolver.
func (s StaticResolver) Resolve(_ context.Context, os string, ids []string) ([]InstallStep, error) {
	var out []InstallStep
	for _, id := range ids {
		app, ok := s[os][id]
		if !ok {
			return nil, fmt.Errorf("%w: %q for %s", ErrUnknownApp, id, os)
		}
		out = append(out, app.Steps...)
	}
	return out, nil
}

// Apps implements AppLister.
func (s StaticResolver) Apps(_ context.Context, os string) ([]AppInfo, error) {
	var out []AppInfo
	for _, a := range s[os] {
		out = append(out, a.Info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

type resolverBox struct{ r AppResolver }

var globalResolver atomic.Value // resolverBox

// SetAppResolver installs the resolver used by the deploy wizard and job.
// Call it from a plugin Init (any order relative to the deploy plugin); nil
// restores the empty stub.
func SetAppResolver(r AppResolver) {
	if r == nil {
		r = StaticResolver{}
	}
	globalResolver.Store(resolverBox{r})
}

// CurrentAppResolver returns the installed resolver.
func CurrentAppResolver() AppResolver {
	if b, ok := globalResolver.Load().(resolverBox); ok && b.r != nil {
		return b.r
	}
	return StaticResolver{}
}
