package authplugin

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"

	"github.com/mumbles27/PerfectImage/internal/auth"
	"github.com/mumbles27/PerfectImage/internal/cli"
	"github.com/mumbles27/PerfectImage/internal/config"
	"github.com/mumbles27/PerfectImage/internal/store"
)

func registerCLI() {
	cli.Register(cli.Command{
		Name:    "user reset-admin",
		Summary: "Reset (or create) the admin account and print a one-time password",
		Run:     runResetAdmin,
	})
}

func runResetAdmin(ctx context.Context, env *cli.Env, args []string) error {
	fs, cfgPath := cli.FlagSet(env, "user reset-admin")
	username := fs.String("username", auth.DefaultAdminUsername, "local account to reset (created with the Admin role if missing)")
	if err := cli.ParseFlags(fs, args); err != nil {
		return err
	}
	abs, err := filepath.Abs(*cfgPath)
	if err != nil {
		return err
	}
	cfg, err := config.Load(abs)
	if err != nil {
		return err
	}
	pw, err := resetAdmin(ctx, cfg, *username)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(env.Stdout, "Account %q reset. One-time password (must be changed at sign-in):\n\n    %s\n\n"+
		"MFA, lockout and existing sessions were cleared. Restarting the service is not required.\n", *username, pw)
	return err
}

// resetAdmin opens the database (migrating it if needed) and resets the
// account through the auth.AdminResetter implementation.
func resetAdmin(ctx context.Context, cfg *config.Config, username string) (string, error) {
	db, err := store.Open(ctx, cfg.Database.Path, store.Options{BusyTimeout: cfg.Database.BusyTimeout})
	if err != nil {
		return "", err
	}
	defer db.Close()
	if err := store.Migrate(ctx, db); err != nil {
		return "", err
	}
	var r auth.AdminResetter = auth.NewService(auth.Options{DB: db, Config: cfg.Auth, Logger: slog.New(slog.DiscardHandler)})
	return r.ResetAdmin(ctx, username)
}
