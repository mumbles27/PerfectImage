package catalog

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// ErrUnknownApp is returned (wrapped) by Resolve for ids that are neither an
// app nor a bundle.
var ErrUnknownApp = errors.New("catalog: unknown app or bundle")

// ErrUnsupported is returned (wrapped) when an app has no install method for
// the target OS/distro.
var ErrUnsupported = errors.New("catalog: app not available for target")

// ErrCycle is returned (wrapped) for dependency cycles.
var ErrCycle = errors.New("catalog: dependency cycle")

// ExpandBundles replaces bundle ids by their apps (ids that name an app are
// kept as is) and removes duplicates, preserving first-seen order.
func (c *Catalog) ExpandBundles(ids []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	add := func(id string) {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, ok := c.Apps[id]; ok {
			add(id)
			continue
		}
		if b, ok := c.Bundles[id]; ok {
			for _, a := range b.Apps {
				add(a)
			}
			continue
		}
		return nil, fmt.Errorf("%w: %q", ErrUnknownApp, id)
	}
	return out, nil
}

// Order returns the apps for ids (app or bundle ids) plus their transitive
// dependencies, dependencies first. It fails on unknown ids, cycles and apps
// that cannot be installed on os/distro (distro may be empty for Windows).
func (c *Catalog) Order(os OSFamily, distro string, ids []string) ([]*App, error) {
	ids, err := c.ExpandBundles(ids)
	if err != nil {
		return nil, err
	}
	const (
		white = iota
		grey
		black
	)
	color := map[string]int{}
	var order []*App
	var path []string
	var visit func(id, from string) error
	visit = func(id, from string) error {
		a, ok := c.Apps[id]
		if !ok {
			if from != "" {
				return fmt.Errorf("%w: %q (dependency of %q)", ErrUnknownApp, id, from)
			}
			return fmt.Errorf("%w: %q", ErrUnknownApp, id)
		}
		switch color[id] {
		case black:
			return nil
		case grey:
			i := slices.Index(path, id)
			return fmt.Errorf("%w: %s", ErrCycle, strings.Join(append(slices.Clone(path[i:]), id), " -> "))
		}
		if !a.Supports(os, distro) {
			target := string(os)
			if distro != "" {
				target += "/" + distro
			}
			if from != "" {
				return fmt.Errorf("%w: %q (dependency of %q) on %s", ErrUnsupported, id, from, target)
			}
			return fmt.Errorf("%w: %q on %s", ErrUnsupported, id, target)
		}
		color[id] = grey
		path = append(path, id)
		for _, d := range a.DependsOn {
			if err := visit(d, id); err != nil {
				return err
			}
		}
		path = path[:len(path)-1]
		color[id] = black
		order = append(order, a)
		return nil
	}
	for _, id := range ids {
		if err := visit(id, ""); err != nil {
			return nil, err
		}
	}
	return order, nil
}

// Resolve turns app (or bundle) ids into ordered install steps for a guest.
// os is "windows" or "linux"; distroFamily is "debian" or "rhel" for Linux
// and ignored for Windows.
func (c *Catalog) Resolve(os OSFamily, distroFamily string, appIDs []string) ([]InstallStep, error) {
	switch os {
	case Windows:
		distroFamily = ""
	case Linux:
		if distroFamily != DistroDebian && distroFamily != DistroRHEL {
			return nil, fmt.Errorf("catalog: unknown linux distro family %q", distroFamily)
		}
	default:
		return nil, fmt.Errorf("catalog: unknown os family %q", os)
	}
	apps, err := c.Order(os, distroFamily, appIDs)
	if err != nil {
		return nil, err
	}
	steps := make([]InstallStep, 0, len(apps))
	for _, a := range apps {
		steps = append(steps, Step(a, os, distroFamily))
	}
	return steps, nil
}

// Step builds the install step for one app (methods that do not apply to
// os/distro are skipped).
func Step(a *App, os OSFamily, distro string) InstallStep {
	var methods []Method
	for _, m := range a.Install.For(os) {
		if m.AppliesTo(os, distro) {
			methods = append(methods, m)
		}
	}
	s := InstallStep{AppID: a.ID, Name: a.Name, RebootRequired: a.RebootRequired}
	if os == Windows {
		s.Shell = ShellPowerShell
		s.Script = powershellInstall(a, methods)
		s.VerifyScript = powershellVerify(methods)
	} else {
		s.Shell = ShellBash
		s.Script = bashInstall(a, methods)
		s.VerifyScript = bashVerify(methods)
	}
	return s
}
