// Command perfectimage is the PerfectImage service and admin CLI.
//
//	perfectimage serve      [--config path]   run the service (foreground or under SCM/systemd)
//	perfectimage install    [--config path]   install as a Windows service / systemd unit
//	perfectimage uninstall                    remove the service
//	perfectimage start|stop|status            control the installed service
//	perfectimage backup | restore             (ops agent)
//	perfectimage catalog validate             (packer agent)
//	perfectimage user reset-admin             (auth agent)
//	perfectimage version
package main

import (
	"context"
	"os"
	"runtime/debug"

	"github.com/mumbles27/PerfectImage/internal/cli"
)

// version is set at build time with -ldflags "-X main.version=v1.2.3".
var version = ""

func buildVersion() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			return bi.Main.Version
		}
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" && len(s.Value) >= 12 {
				return "dev-" + s.Value[:12]
			}
		}
	}
	return "dev"
}

func main() {
	env := &cli.Env{Stdout: os.Stdout, Stderr: os.Stderr, Version: buildVersion()}
	os.Exit(cli.Main(context.Background(), env, os.Args[1:]))
}
