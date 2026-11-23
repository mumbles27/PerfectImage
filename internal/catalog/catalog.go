// Package catalog will load and validate image/app catalog definitions from
// the directories in config.CatalogConfig.Dirs (and the repo's top-level
// catalog/ directory).
//
// Owner: packer agent. The foundation only defines the Validator seam used
// by `perfectimage catalog validate`.
package catalog

import "context"

// Problem is a single validation finding.
type Problem struct {
	File    string
	Line    int
	Message string
}

// Validator validates catalog directories. Implemented by the packer agent,
// which should replace the stub CLI command via cli.Register.
type Validator interface {
	Validate(ctx context.Context, dirs []string) ([]Problem, error)
}
