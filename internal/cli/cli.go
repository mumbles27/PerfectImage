// Package cli is the perfectimage command registry and dispatcher.
//
// Commands are registered by name (possibly multi-word, e.g. "catalog
// validate"). The foundation registers stubs for commands owned by domain
// agents; an owner replaces its stub by calling Register with the same name
// from an init function in its package (imported by cmd/perfectimage):
//
//	func init() {
//		cli.Register(cli.Command{
//			Name:    "backup",
//			Summary: "Back up the data directory",
//			Run:     runBackup,
//		})
//	}
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/mumbles27/PerfectImage/internal/config"
)

// ErrNotImplemented is returned by stub commands.
var ErrNotImplemented = errors.New("not yet implemented")

// ErrUsage signals a usage error (exit code 2).
var ErrUsage = errors.New("usage error")

// Env is the execution environment passed to commands.
type Env struct {
	Stdout  io.Writer
	Stderr  io.Writer
	Version string
}

// Command is a CLI subcommand.
type Command struct {
	// Name is the space-separated command path, e.g. "user reset-admin".
	Name    string
	Summary string
	// Run executes the command with the remaining arguments.
	Run func(ctx context.Context, env *Env, args []string) error

	stub bool
}

var (
	mu       sync.Mutex
	commands = map[string]Command{}
)

// Register adds or replaces a command. Replacing a non-stub command panics.
func Register(c Command) {
	mu.Lock()
	defer mu.Unlock()
	if c.Name == "" || c.Run == nil {
		panic("cli: Register requires Name and Run")
	}
	if old, ok := commands[c.Name]; ok && !old.stub {
		panic("cli: command " + c.Name + " registered twice")
	}
	commands[c.Name] = c
}

// RegisterStub registers a placeholder that fails with ErrNotImplemented,
// naming the interface the owner must implement.
func RegisterStub(name, summary, owner, iface string) {
	Register(Command{
		Name:    name,
		Summary: summary + " (not yet implemented)",
		stub:    true,
		Run: func(context.Context, *Env, []string) error {
			return fmt.Errorf("%s: %w (to be provided by the %s agent via %s)", name, ErrNotImplemented, owner, iface)
		},
	})
}

func init() {
	RegisterStub("backup", "Back up the data directory", "ops", "backup.Service")
	RegisterStub("restore", "Restore the data directory from a backup", "ops", "backup.Service")
	RegisterStub("catalog validate", "Validate catalog definitions", "packer", "catalog.Validator")
	RegisterStub("user reset-admin", "Reset the built-in admin account", "auth", "auth.AdminResetter")
}

// lookup finds the longest registered command prefix of args.
func lookup(args []string) (Command, []string, bool) {
	mu.Lock()
	defer mu.Unlock()
	for n := len(args); n > 0; n-- {
		if c, ok := commands[strings.Join(args[:n], " ")]; ok {
			return c, args[n:], true
		}
	}
	return Command{}, nil, false
}

// Main dispatches args (without the program name) and returns an exit code.
func Main(ctx context.Context, env *Env, args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		Usage(env.Stdout)
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	c, rest, ok := lookup(args)
	if !ok {
		fmt.Fprintf(env.Stderr, "perfectimage: unknown command %q\n\n", strings.Join(args, " "))
		Usage(env.Stderr)
		return 2
	}
	if err := c.Run(ctx, env, rest); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		fmt.Fprintf(env.Stderr, "perfectimage %s: %v\n", c.Name, err)
		if errors.Is(err, ErrUsage) {
			return 2
		}
		return 1
	}
	return 0
}

// Usage prints the command list.
func Usage(w io.Writer) {
	mu.Lock()
	names := make([]string, 0, len(commands))
	for n := range commands {
		names = append(names, n)
	}
	sort.Strings(names)
	fmt.Fprintln(w, "Usage: perfectimage <command> [flags]")
	fmt.Fprintln(w, "\nCommands:")
	for _, n := range names {
		fmt.Fprintf(w, "  %-20s %s\n", n, commands[n].Summary)
	}
	mu.Unlock()
	fmt.Fprintln(w, "\nRun 'perfectimage <command> -h' for command flags.")
}

// FlagSet returns a FlagSet for a command with the standard --config flag.
// The returned pointer holds the config path after Parse.
func FlagSet(env *Env, name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet("perfectimage "+name, flag.ContinueOnError)
	fs.SetOutput(env.Stderr)
	cfg := fs.String("config", config.DefaultConfigPath(), "path to config.yaml")
	return fs, cfg
}

// ParseFlags parses args, mapping parse errors to ErrUsage.
func ParseFlags(fs *flag.FlagSet, args []string) error {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return err
		}
		return fmt.Errorf("%w: %v", ErrUsage, err)
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("%w: unexpected arguments %v", ErrUsage, fs.Args())
	}
	return nil
}
