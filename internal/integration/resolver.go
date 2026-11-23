package integration

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/mumbles27/PerfectImage/internal/catalog"
	"github.com/mumbles27/PerfectImage/internal/deploy"
)

// CatalogResolver implements deploy.AppResolver and deploy.AppLister on top
// of the catalog.
//
// The deploy package only knows the OS family of a template ("linux" or
// "windows"), while catalog install scripts for Linux depend on the distro
// family (apt vs dnf). For Linux, each app therefore becomes one step whose
// script detects the package manager on the guest and runs the matching
// catalog script in a subshell.
type CatalogResolver struct {
	// Catalog returns the current catalog snapshot (catalog.Store.Catalog).
	Catalog func() *catalog.Catalog
}

var (
	_ deploy.AppResolver = (*CatalogResolver)(nil)
	_ deploy.AppLister   = (*CatalogResolver)(nil)
)

// linuxFamilies are tried in this order; detect is a bash condition that is
// true on guests of that family.
var linuxFamilies = []struct {
	distro string
	detect string
}{
	{catalog.DistroDebian, "command -v apt-get >/dev/null 2>&1"},
	{catalog.DistroRHEL, "command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1"},
}

// Resolve implements deploy.AppResolver. appIDs may contain app or bundle
// ids; dependencies are included, dependencies first.
func (r *CatalogResolver) Resolve(_ context.Context, os string, appIDs []string) ([]deploy.InstallStep, error) {
	if len(appIDs) == 0 {
		return nil, nil
	}
	c := r.Catalog()
	switch os {
	case deploy.OSWindows:
		steps, err := c.Resolve(catalog.Windows, "", appIDs)
		if err != nil {
			return nil, wrapUnknown(err)
		}
		out := make([]deploy.InstallStep, 0, len(steps))
		for _, s := range steps {
			out = append(out, deploy.InstallStep{Name: s.Name, Shell: deploy.ShellPowerShell, Script: s.Script, VerifyScript: s.VerifyScript})
		}
		return out, nil
	case deploy.OSLinux:
		return r.resolveLinux(c, appIDs)
	default:
		return nil, fmt.Errorf("integration: unknown OS family %q", os)
	}
}

func (r *CatalogResolver) resolveLinux(c *catalog.Catalog, appIDs []string) ([]deploy.InstallStep, error) {
	type perFamily map[string]catalog.InstallStep // app id -> step
	byFamily := make([]perFamily, len(linuxFamilies))
	var order []string // union of app ids, first-seen order (deps first)
	seen := map[string]bool{}
	var firstErr error
	resolved := 0
	for i, f := range linuxFamilies {
		steps, err := c.Resolve(catalog.Linux, f.distro, appIDs)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		resolved++
		byFamily[i] = perFamily{}
		for _, s := range steps {
			byFamily[i][s.AppID] = s
			if !seen[s.AppID] {
				seen[s.AppID] = true
				order = append(order, s.AppID)
			}
		}
	}
	if resolved == 0 {
		return nil, wrapUnknown(firstErr)
	}
	out := make([]deploy.InstallStep, 0, len(order))
	for _, id := range order {
		var name string
		var install, verify strings.Builder
		hasVerify := false
		for i, f := range linuxFamilies {
			kw := "elif"
			if i == 0 {
				kw = "if"
			}
			fmt.Fprintf(&install, "%s %s; then\n", kw, f.detect)
			fmt.Fprintf(&verify, "%s %s; then\n", kw, f.detect)
			s, ok := byFamily[i][id]
			if !ok {
				msg := fmt.Sprintf("app %q is not available for %s-family Linux guests", id, f.distro)
				fmt.Fprintf(&install, "  echo %s >&2\n  exit 1\n", shQuote(msg))
				fmt.Fprintf(&verify, "  exit 1\n")
				continue
			}
			name = s.Name
			writeSubshell(&install, s.Script)
			if strings.TrimSpace(s.VerifyScript) != "" {
				hasVerify = true
				writeSubshell(&verify, s.VerifyScript)
			} else {
				verify.WriteString("  true\n")
			}
		}
		install.WriteString("else\n  echo 'no supported package manager (apt-get, dnf or yum) found on this guest' >&2\n  exit 1\nfi\n")
		verify.WriteString("else\n  exit 1\nfi\n")
		st := deploy.InstallStep{Name: name, Shell: deploy.ShellBash, Script: install.String()}
		if hasVerify {
			st.VerifyScript = verify.String()
		}
		out = append(out, st)
	}
	return out, nil
}

// writeSubshell appends script run in a subshell, so its own `set -e`,
// `exit` and traps cannot leak into the dispatcher, and propagates its exit
// status.
func writeSubshell(b *strings.Builder, script string) {
	b.WriteString("  (\n")
	b.WriteString(strings.TrimRight(script, "\n"))
	b.WriteString("\n  )\n  exit $?\n")
}

// shQuote single-quotes s for bash.
func shQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func wrapUnknown(err error) error {
	if errors.Is(err, catalog.ErrUnknownApp) {
		return fmt.Errorf("%w: %v", deploy.ErrUnknownApp, err)
	}
	return err
}

// Apps implements deploy.AppLister: catalog apps installable on os, then
// bundles (shown with a "Bundle:" prefix), each sorted by name.
func (r *CatalogResolver) Apps(_ context.Context, os string) ([]deploy.AppInfo, error) {
	c := r.Catalog()
	supports := func(a *catalog.App) bool {
		switch os {
		case deploy.OSWindows:
			return a.Supports(catalog.Windows, "")
		case deploy.OSLinux:
			for _, f := range linuxFamilies {
				if a.Supports(catalog.Linux, f.distro) {
					return true
				}
			}
		}
		return false
	}
	var apps, bundles []deploy.AppInfo
	for _, a := range c.AppList() {
		if supports(a) {
			apps = append(apps, deploy.AppInfo{ID: a.ID, Name: a.Name, Description: a.Description})
		}
	}
	for _, b := range c.BundleList() {
		ok := len(b.Apps) > 0
		for _, id := range b.Apps {
			if a, found := c.Apps[id]; !found || !supports(a) {
				ok = false
				break
			}
		}
		if ok {
			bundles = append(bundles, deploy.AppInfo{ID: b.ID, Name: "Bundle: " + b.Name, Description: b.Description})
		}
	}
	byName := func(s []deploy.AppInfo) {
		sort.Slice(s, func(i, j int) bool { return s[i].Name < s[j].Name })
	}
	byName(apps)
	byName(bundles)
	return append(apps, bundles...), nil
}
