package catalog

import "context"

// Problem is a single validation finding.
type Problem struct {
	File    string
	Line    int
	Message string
}

// Validator validates catalog directories. DirValidator implements it and
// backs the `perfectimage catalog validate` command.
type Validator interface {
	Validate(ctx context.Context, dirs []string) ([]Problem, error)
}
