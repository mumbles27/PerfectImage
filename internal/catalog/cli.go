package catalog

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/mumbles27/PerfectImage/internal/cli"
	"github.com/mumbles27/PerfectImage/internal/config"
)

// DirValidator implements Validator over the given directories, optionally
// layered on top of the embedded catalog.
type DirValidator struct {
	IncludeEmbedded bool
}

var _ Validator = DirValidator{}

// Validate loads the directories (in merge order) and returns all problems.
func (v DirValidator) Validate(ctx context.Context, dirs []string) ([]Problem, error) {
	var layers []Layer
	if v.IncludeEmbedded {
		layers = append(layers, Layer{Origin: OriginEmbedded, FS: EmbeddedFS()})
	}
	for _, d := range dirs {
		layers = append(layers, DirLayer(d))
	}
	c, err := Load(ctx, layers...)
	if err != nil {
		return nil, err
	}
	return c.Problems, nil
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

// ErrProblems is returned by the CLI when validation finds problems.
var ErrProblems = errors.New("catalog has problems")

func init() {
	cli.Register(cli.Command{
		Name:    "catalog validate",
		Summary: "Validate catalog definitions (images, apps, bundles)",
		Run:     runValidate,
	})
}

func runValidate(ctx context.Context, env *cli.Env, args []string) error {
	fs, cfgPath := cli.FlagSet(env, "catalog validate")
	var dirs stringList
	fs.Var(&dirs, "dir", "catalog directory to validate (repeatable; default: catalog.dirs from --config)")
	noEmbedded := fs.Bool("no-embedded", false, "do not layer the directories on top of the built-in catalog")
	fs.Usage = func() {
		fmt.Fprintln(env.Stderr, "Usage: perfectimage catalog validate [--config path | --dir dir ...] [--no-embedded]")
		fs.PrintDefaults()
	}
	if err := cli.ParseFlags(fs, args); err != nil {
		return err
	}
	if len(dirs) == 0 {
		cfg, err := config.Load(*cfgPath)
		if err != nil {
			return err
		}
		dirs = cfg.Catalog.Dirs
	}
	for i, d := range dirs {
		if abs, err := filepath.Abs(d); err == nil {
			dirs[i] = abs
		}
	}
	probs, err := DirValidator{IncludeEmbedded: !*noEmbedded}.Validate(ctx, dirs)
	if err != nil {
		return err
	}
	for _, p := range probs {
		fmt.Fprintln(env.Stdout, p.String())
	}
	if len(probs) > 0 {
		return fmt.Errorf("%w: %d problem(s)", ErrProblems, len(probs))
	}
	fmt.Fprintf(env.Stdout, "catalog OK (%s)\n", describeSources(!*noEmbedded, dirs))
	return nil
}

func describeSources(embedded bool, dirs []string) string {
	var parts []string
	if embedded {
		parts = append(parts, OriginEmbedded)
	}
	parts = append(parts, dirs...)
	if len(parts) == 0 {
		return "no sources"
	}
	return strings.Join(parts, ", ")
}
