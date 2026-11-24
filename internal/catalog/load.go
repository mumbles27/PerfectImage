package catalog

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Layer is one catalog source. Layers are merged in order; an item in a later
// layer replaces the item with the same id from an earlier one.
type Layer struct {
	// Origin is "embedded" or the directory path; it is recorded on every
	// item (Source.Origin) and used to build problem file names.
	Origin string
	FS     fs.FS
}

// DirLayer returns a layer for an override directory.
func DirLayer(dir string) Layer {
	return Layer{Origin: dir, FS: dirFS(dir)}
}

// Catalog is an immutable, merged snapshot of images, apps and bundles.
type Catalog struct {
	Images  map[string]*Image
	Apps    map[string]*App
	Bundles map[string]*Bundle
	// Problems are the validation findings for this snapshot.
	Problems []Problem
}

// ImageList returns images sorted by name.
func (c *Catalog) ImageList() []*Image {
	out := make([]*Image, 0, len(c.Images))
	for _, v := range c.Images {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// AppList returns apps sorted by name.
func (c *Catalog) AppList() []*App {
	out := make([]*App, 0, len(c.Apps))
	for _, v := range c.Apps {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out
}

// BundleList returns bundles sorted by name.
func (c *Catalog) BundleList() []*Bundle {
	out := make([]*Bundle, 0, len(c.Bundles))
	for _, v := range c.Bundles {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// clone returns a shallow copy with fresh maps (items are shared; they are
// never mutated after load).
func (c *Catalog) clone() *Catalog {
	n := &Catalog{Images: map[string]*Image{}, Apps: map[string]*App{}, Bundles: map[string]*Bundle{}}
	for k, v := range c.Images {
		n.Images[k] = v
	}
	for k, v := range c.Apps {
		n.Apps[k] = v
	}
	for k, v := range c.Bundles {
		n.Bundles[k] = v
	}
	return n
}

// parsed keeps the YAML node of an item so later validation can report
// line numbers.
type parsed struct {
	file string // problem file name
	root *yaml.Node
}

type loader struct {
	cat   *Catalog
	nodes map[string]parsed // "app:<id>", "bundle:<id>", "image:<id>"
	probs []Problem
}

// Load reads and merges the layers and validates the result. It only fails
// on context cancellation or unreadable layers; definition errors are
// reported in Catalog.Problems and the offending file is skipped.
func Load(ctx context.Context, layers ...Layer) (*Catalog, error) {
	l := &loader{
		cat:   &Catalog{Images: map[string]*Image{}, Apps: map[string]*App{}, Bundles: map[string]*Bundle{}},
		nodes: map[string]parsed{},
	}
	for _, layer := range layers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := l.loadLayer(layer); err != nil {
			return nil, fmt.Errorf("catalog: load %s: %w", layer.Origin, err)
		}
	}
	l.probs = append(l.probs, crossValidate(l.cat, l.nodes)...)
	sortProblems(l.probs)
	l.cat.Problems = l.probs
	return l.cat, nil
}

func (l *loader) problem(file string, line int, format string, a ...any) {
	l.probs = append(l.probs, Problem{File: file, Line: line, Message: fmt.Sprintf(format, a...)})
}

// problemFile names a file for problem reports: the real path for directory
// layers and the repository path (catalog/...) for the embedded catalog.
func problemFile(origin, rel string) string {
	if origin == OriginEmbedded {
		return path.Join("catalog", rel)
	}
	return filepath.Join(origin, filepath.FromSlash(rel))
}

func (l *loader) loadLayer(layer Layer) error {
	for _, kind := range []string{"apps", "bundles"} {
		files, err := yamlFiles(layer.FS, kind)
		if err != nil {
			return err
		}
		for _, rel := range files {
			b, err := fs.ReadFile(layer.FS, rel)
			if err != nil {
				return err
			}
			src := Source{Origin: layer.Origin, File: rel}
			pf := problemFile(layer.Origin, rel)
			if kind == "apps" {
				a, node, probs := ParseApp(b, pf)
				l.probs = append(l.probs, probs...)
				if a == nil {
					continue
				}
				l.checkFileName(pf, node, a.ID, rel, ".yaml")
				a.Source = src
				l.cat.Apps[a.ID] = a
				l.nodes["app:"+a.ID] = parsed{file: pf, root: node}
			} else {
				bu, node, probs := ParseBundle(b, pf)
				l.probs = append(l.probs, probs...)
				if bu == nil {
					continue
				}
				l.checkFileName(pf, node, bu.ID, rel, ".yaml")
				bu.Source = src
				l.cat.Bundles[bu.ID] = bu
				l.nodes["bundle:"+bu.ID] = parsed{file: pf, root: node}
			}
		}
	}

	entries, err := fs.ReadDir(layer.FS, "images")
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		rel := path.Join("images", e.Name(), "image.yaml")
		pf := problemFile(layer.Origin, rel)
		b, err := fs.ReadFile(layer.FS, rel)
		if errors.Is(err, fs.ErrNotExist) {
			l.problem(pf, 0, "image directory has no image.yaml")
			continue
		}
		if err != nil {
			return err
		}
		img, node, probs := ParseImage(b, pf)
		l.probs = append(l.probs, probs...)
		if img == nil {
			continue
		}
		if img.ID != e.Name() {
			l.problem(pf, lineOf(node, "id"), "image id %q must match its directory name %q", img.ID, e.Name())
		}
		sub, err := fs.Sub(layer.FS, path.Join("images", e.Name()))
		if err != nil {
			return err
		}
		img.Files = sub
		img.Source = Source{Origin: layer.Origin, File: rel}
		l.probs = append(l.probs, validateImageFiles(sub, problemFile(layer.Origin, path.Join("images", e.Name())))...)
		l.probs = append(l.probs, validateSeedFiles(img, sub, problemFile(layer.Origin, path.Join("images", e.Name())))...)
		l.cat.Images[img.ID] = img
		l.nodes["image:"+img.ID] = parsed{file: pf, root: node}
	}
	return nil
}

func (l *loader) checkFileName(pf string, node *yaml.Node, id, rel, ext string) {
	base := strings.TrimSuffix(strings.TrimSuffix(path.Base(rel), ".yml"), ext)
	if id != base {
		l.problem(pf, lineOf(node, "id"), "id %q must match the file name %q", id, base)
	}
}

func yamlFiles(fsys fs.FS, dir string) ([]string, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || strings.HasPrefix(n, ".") {
			continue
		}
		if strings.HasSuffix(n, ".yaml") || strings.HasSuffix(n, ".yml") {
			out = append(out, path.Join(dir, n))
		}
	}
	return out, nil
}

// ParseApp strictly decodes and validates an app definition. file is used
// in problems. It returns a nil app when the document cannot be decoded.
func ParseApp(b []byte, file string) (*App, *yaml.Node, []Problem) {
	var a App
	node, probs := decodeStrict(b, file, &a)
	if node == nil {
		return nil, nil, probs
	}
	probs = append(probs, validateApp(&a, node, file)...)
	return &a, node, probs
}

// ParseBundle strictly decodes and validates a bundle definition.
func ParseBundle(b []byte, file string) (*Bundle, *yaml.Node, []Problem) {
	var bu Bundle
	node, probs := decodeStrict(b, file, &bu)
	if node == nil {
		return nil, nil, probs
	}
	probs = append(probs, validateBundle(&bu, node, file)...)
	return &bu, node, probs
}

// ParseImage strictly decodes and validates an image.yaml.
func ParseImage(b []byte, file string) (*Image, *yaml.Node, []Problem) {
	var img Image
	node, probs := decodeStrict(b, file, &img)
	if node == nil {
		return nil, nil, probs
	}
	probs = append(probs, validateImage(&img, node, file)...)
	return &img, node, probs
}

var lineRE = regexp.MustCompile(`line (\d+): (.*)`)

// decodeStrict decodes b into v, rejecting unknown fields. It returns the
// document's root mapping node, or nil (with problems) on failure.
func decodeStrict(b []byte, file string, v any) (*yaml.Node, []Problem) {
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, yamlProblems(file, err)
	}
	if len(doc.Content) == 0 {
		return nil, []Problem{{File: file, Line: 1, Message: "empty document"}}
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, []Problem{{File: file, Line: root.Line, Message: "document must be a mapping"}}
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil {
		return nil, yamlProblems(file, err)
	}
	return root, nil
}

func yamlProblems(file string, err error) []Problem {
	var msgs []string
	var te *yaml.TypeError
	if errors.As(err, &te) {
		msgs = te.Errors
	} else {
		msgs = []string{err.Error()}
	}
	out := make([]Problem, 0, len(msgs))
	for _, m := range msgs {
		p := Problem{File: file, Message: strings.TrimPrefix(m, "yaml: ")}
		if sm := lineRE.FindStringSubmatch(m); sm != nil {
			p.Line, _ = strconv.Atoi(sm[1])
			p.Message = sm[2]
		}
		out = append(out, p)
	}
	return out
}

// lineOf returns the line of the node at path (string keys, int indexes)
// below root, falling back to the deepest node found.
func lineOf(root *yaml.Node, keys ...any) int {
	if root == nil {
		return 0
	}
	n := root
	line := n.Line
	for _, k := range keys {
		next := child(n, k)
		if next == nil {
			return line
		}
		n = next
		line = n.Line
	}
	return line
}

func child(n *yaml.Node, key any) *yaml.Node {
	switch k := key.(type) {
	case string:
		if n.Kind != yaml.MappingNode {
			return nil
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			if n.Content[i].Value == k {
				return n.Content[i+1]
			}
		}
	case int:
		if n.Kind == yaml.SequenceNode && k >= 0 && k < len(n.Content) {
			return n.Content[k]
		}
	}
	return nil
}

func sortProblems(p []Problem) {
	sort.SliceStable(p, func(i, j int) bool {
		if p[i].File != p[j].File {
			return p[i].File < p[j].File
		}
		return p[i].Line < p[j].Line
	})
}
