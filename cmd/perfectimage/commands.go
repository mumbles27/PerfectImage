package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/kardianos/service"

	"github.com/mumbles27/PerfectImage/internal/app"
	"github.com/mumbles27/PerfectImage/internal/cli"
	"github.com/mumbles27/PerfectImage/internal/config"
)

func init() {
	cli.Register(cli.Command{Name: "serve", Summary: "Run the PerfectImage service", Run: runServe})
	cli.Register(cli.Command{Name: "install", Summary: "Install as a Windows service / systemd unit", Run: runInstall})
	cli.Register(cli.Command{Name: "uninstall", Summary: "Remove the installed service", Run: controlCmd("uninstall")})
	cli.Register(cli.Command{Name: "start", Summary: "Start the installed service", Run: controlCmd("start")})
	cli.Register(cli.Command{Name: "stop", Summary: "Stop the installed service", Run: controlCmd("stop")})
	cli.Register(cli.Command{Name: "status", Summary: "Show the installed service status", Run: runStatus})
	cli.Register(cli.Command{Name: "version", Summary: "Print the version", Run: func(_ context.Context, env *cli.Env, _ []string) error {
		_, err := fmt.Fprintln(env.Stdout, env.Version)
		return err
	}})
}

func loadConfig(env *cli.Env, name string, args []string) (*config.Config, string, error) {
	fs, cfgPath := cli.FlagSet(env, name)
	if err := cli.ParseFlags(fs, args); err != nil {
		return nil, "", err
	}
	abs, err := filepath.Abs(*cfgPath)
	if err != nil {
		return nil, "", err
	}
	cfg, err := config.Load(abs)
	if err != nil {
		return nil, "", err
	}
	return cfg, abs, nil
}

func runServe(ctx context.Context, env *cli.Env, args []string) error {
	cfg, cfgPath, err := loadConfig(env, "serve", args)
	if err != nil {
		return err
	}
	run := func(ctx context.Context) error {
		a, err := app.New(ctx, cfg, app.Options{Version: env.Version})
		if err != nil {
			return err
		}
		return a.Run(ctx)
	}
	if app.Interactive() {
		ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
		defer stop()
		return run(ctx)
	}
	s, err := app.NewService(cfgPath, run, cfg.Server.ShutdownTimeout+10*time.Second)
	if err != nil {
		return err
	}
	return s.Run()
}

func runInstall(_ context.Context, env *cli.Env, args []string) error {
	_, cfgPath, err := loadConfig(env, "install", args)
	if err != nil {
		return fmt.Errorf("config must exist and be valid before installing: %w", err)
	}
	s, err := app.NewService(cfgPath, nil, 0)
	if err != nil {
		return err
	}
	if err := s.Install(); err != nil {
		return fmt.Errorf("install service: %w", err)
	}
	fmt.Fprintf(env.Stdout, "Installed service %q using config %s\nStart it with: perfectimage start\n", app.ServiceName, cfgPath)
	return nil
}

func controlCmd(action string) func(context.Context, *cli.Env, []string) error {
	return func(_ context.Context, env *cli.Env, args []string) error {
		fs, _ := cli.FlagSet(env, action)
		if err := cli.ParseFlags(fs, args); err != nil {
			return err
		}
		s, err := app.NewService(config.DefaultConfigPath(), nil, 0)
		if err != nil {
			return err
		}
		if action == "uninstall" {
			_ = service.Control(s, "stop") // best effort
		}
		if err := service.Control(s, action); err != nil {
			return err
		}
		fmt.Fprintf(env.Stdout, "Service %q: %s ok\n", app.ServiceName, action)
		return nil
	}
}

func runStatus(_ context.Context, env *cli.Env, args []string) error {
	fs, _ := cli.FlagSet(env, "status")
	if err := cli.ParseFlags(fs, args); err != nil {
		return err
	}
	s, err := app.NewService(config.DefaultConfigPath(), nil, 0)
	if err != nil {
		return err
	}
	st, err := s.Status()
	if errors.Is(err, service.ErrNotInstalled) {
		fmt.Fprintln(env.Stdout, "not installed")
		return nil
	}
	if err != nil {
		return err
	}
	names := map[service.Status]string{service.StatusRunning: "running", service.StatusStopped: "stopped"}
	if n, ok := names[st]; ok {
		fmt.Fprintln(env.Stdout, n)
	} else {
		fmt.Fprintln(env.Stdout, "unknown")
	}
	return nil
}
