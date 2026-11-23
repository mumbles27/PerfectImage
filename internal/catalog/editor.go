package catalog

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// Kind is an editable catalog item kind.
type Kind string

// Editable kinds.
const (
	KindApp    Kind = "app"
	KindBundle Kind = "bundle"
)

func (k Kind) dir() string {
	if k == KindBundle {
		return "bundles"
	}
	return "apps"
}

// Edit modes.
const (
	ModeCreate = "create"
	ModeEdit   = "edit"
	ModeClone  = "clone"
)

// MaxDefinitionBytes caps an edited definition.
const MaxDefinitionBytes = 64 << 10

// Editor errors.
var (
	ErrNoWriteDir = errors.New("catalog: no override directory configured (catalog.dirs)")
	ErrInvalid    = errors.New("catalog: definition is invalid")
	ErrNotFound   = errors.New("catalog: item not found")
)

// SaveResult describes a validated (and possibly written) definition.
type SaveResult struct {
	ID       string
	Path     string
	Problems []Problem
	// Overrode is true when the saved file replaces an item from a
	// lower-precedence layer (e.g. the embedded catalog).
	Overrode bool
}

// Check validates a definition as it would be saved, without writing it.
func (s *Store) Check(kind Kind, text []byte, mode, originalID string) SaveResult {
	res, _, _ := s.check(kind, text, mode, originalID)
	return res
}

func (s *Store) check(kind Kind, text []byte, mode, originalID string) (SaveResult, any, *yaml.Node) {
	var res SaveResult
	if len(text) > MaxDefinitionBytes {
		res.Problems = []Problem{{File: "definition", Message: fmt.Sprintf("definition is larger than %d bytes", MaxDefinitionBytes)}}
		return res, nil, nil
	}
	// First pass only finds the id so problems can name the target file.
	var probe struct {
		ID string `yaml:"id"`
	}
	_ = yaml.Unmarshal(text, &probe)
	res.ID = probe.ID
	rel := path.Join(kind.dir(), probe.ID+".yaml")
	res.Path = rel
	if wd := s.WriteDir(); wd != "" {
		res.Path = filepath.Join(wd, filepath.FromSlash(rel))
	}

	var item any
	var node *yaml.Node
	var probs []Problem
	if kind == KindBundle {
		var b *Bundle
		b, node, probs = ParseBundle(text, res.Path)
		if b != nil {
			item = b
		}
	} else {
		var a *App
		a, node, probs = ParseApp(text, res.Path)
		if a != nil {
			item = a
		}
	}
	res.Problems = probs
	if item == nil || !idRE.MatchString(res.ID) {
		return res, nil, nil
	}

	cur := s.Catalog()
	_, existsApp := cur.Apps[res.ID]
	_, existsBundle := cur.Bundles[res.ID]
	exists := existsApp
	if kind == KindBundle {
		exists = existsBundle
	}
	switch mode {
	case ModeEdit:
		if res.ID != originalID {
			res.Problems = append(res.Problems, Problem{File: res.Path, Line: lineOf(node, "id"),
				Message: fmt.Sprintf("id cannot change while editing (was %q); use clone to copy it under a new id", originalID)})
		}
	case ModeCreate, ModeClone:
		if exists {
			res.Problems = append(res.Problems, Problem{File: res.Path, Line: lineOf(node, "id"),
				Message: fmt.Sprintf("%s %q already exists; edit it instead", kind, res.ID)})
		}
	default:
		res.Problems = append(res.Problems, Problem{File: res.Path, Message: "unknown edit mode " + mode})
	}
	if (kind == KindApp && existsBundle) || (kind == KindBundle && existsApp) {
		res.Problems = append(res.Problems, Problem{File: res.Path, Line: lineOf(node, "id"),
			Message: fmt.Sprintf("id %q is already used by a %s", res.ID, map[Kind]string{KindApp: "bundle", KindBundle: "app"}[kind])})
	}

	// Cross-validate the candidate in the context of the current catalog.
	cand := cur.clone()
	key := string(kind) + ":" + res.ID
	src := Source{Origin: s.WriteDir(), File: rel}
	switch v := item.(type) {
	case *App:
		v.Source = src
		cand.Apps[v.ID] = v
	case *Bundle:
		v.Source = src
		cand.Bundles[v.ID] = v
	}
	nodes := map[string]parsed{key: {file: res.Path, root: node}}
	for _, p := range crossValidate(cand, nodes) {
		if p.File == res.Path {
			res.Problems = append(res.Problems, p)
		}
	}
	if kind == KindApp {
		// Changing an app can create a cycle reported against another app.
		for _, cyc := range findCycles(cand) {
			for _, id := range cyc {
				if id == res.ID && cyc[0] != res.ID {
					res.Problems = append(res.Problems, Problem{File: res.Path, Line: lineOf(node, "depends_on"),
						Message: "dependency cycle: " + strings.Join(cyc, " -> ")})
					break
				}
			}
		}
	}
	sortProblems(res.Problems)
	if len(res.Problems) > 0 {
		return res, nil, node
	}
	return res, item, node
}

func isWindows() bool { return runtime.GOOS == "windows" }

// Save validates a definition and, when valid, writes it to the override
// directory and reloads the catalog. It returns ErrInvalid (with the
// problems in the result) when validation fails.
func (s *Store) Save(ctx context.Context, kind Kind, text []byte, mode, originalID string) (SaveResult, error) {
	wd := s.WriteDir()
	if wd == "" {
		return SaveResult{}, ErrNoWriteDir
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res, item, _ := s.check(kind, text, mode, originalID)
	if len(res.Problems) > 0 || item == nil {
		return res, ErrInvalid
	}
	cur := s.Catalog()
	if kind == KindApp {
		if a, ok := cur.Apps[res.ID]; ok && a.Source.Origin != wd {
			res.Overrode = true
		}
	} else if b, ok := cur.Bundles[res.ID]; ok && b.Source.Origin != wd {
		res.Overrode = true
	}
	if err := writeFileAtomic(res.Path, text); err != nil {
		return res, err
	}
	if _, err := s.reloadLocked(ctx, true); err != nil {
		return res, err
	}
	return res, nil
}

// DeleteOverride removes an item's file from the override directory, so a
// lower layer's definition (if any) applies again.
func (s *Store) DeleteOverride(ctx context.Context, kind Kind, id string) (string, error) {
	wd := s.WriteDir()
	if wd == "" {
		return "", ErrNoWriteDir
	}
	if !idRE.MatchString(id) {
		return "", ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	p := filepath.Join(wd, kind.dir(), id+".yaml")
	if err := os.Remove(p); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return p, ErrNotFound
		}
		return p, err
	}
	_, err := s.reloadLocked(ctx, true)
	return p, err
}

// Raw returns the YAML source of an item.
func (s *Store) Raw(kind Kind, id string) ([]byte, error) {
	c := s.Catalog()
	var src Source
	switch kind {
	case KindApp:
		a, ok := c.Apps[id]
		if !ok {
			return nil, ErrNotFound
		}
		src = a.Source
	case KindBundle:
		b, ok := c.Bundles[id]
		if !ok {
			return nil, ErrNotFound
		}
		src = b.Source
	case "image":
		img, ok := c.Images[id]
		if !ok {
			return nil, ErrNotFound
		}
		return fs.ReadFile(img.Files, "image.yaml")
	default:
		return nil, ErrNotFound
	}
	if src.Embedded() {
		if s.embedded == nil {
			return nil, ErrNotFound
		}
		return fs.ReadFile(s.embedded, src.File)
	}
	return fs.ReadFile(dirFS(src.Origin), src.File)
}

// IsOverride reports whether an item's file lives in the write directory.
func (s *Store) IsOverride(src Source) bool {
	wd := s.WriteDir()
	return wd != "" && src.Origin == wd
}

func writeFileAtomic(p string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(p), ".pi-edit-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Chmod(0o640); err != nil && !isWindows() {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
