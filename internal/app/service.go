package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/kardianos/service"
)

// Service identity used for the Windows service and systemd unit.
const (
	ServiceName        = "PerfectImage"
	ServiceDisplayName = "PerfectImage"
	ServiceDescription = "Builds Proxmox VM templates with Packer, deploys VMs and installs applications."
)

// ServiceConfig returns the kardianos/service configuration that runs
// "perfectimage serve --config <configPath>".
func ServiceConfig(configPath string) *service.Config {
	return &service.Config{
		Name:        ServiceName,
		DisplayName: ServiceDisplayName,
		Description: ServiceDescription,
		Arguments:   []string{"serve", "--config", configPath},
		Dependencies: []string{
			"After=network-online.target",
			"Wants=network-online.target",
		},
		Option: service.KeyValue{
			// systemd
			"Restart":     "on-failure",
			"LimitNOFILE": 65536,
			// Windows
			"OnFailure":              "restart",
			"OnFailureDelayDuration": "10s",
			"OnFailureResetPeriod":   86400,
			"DelayedAutoStart":       true,
		},
	}
}

// RunFunc runs the service until ctx is canceled.
type RunFunc func(ctx context.Context) error

// program adapts RunFunc to service.Interface.
type program struct {
	run         RunFunc
	stopTimeout time.Duration
	log         *slog.Logger
	cancel      context.CancelFunc
	done        chan error
}

func (p *program) Start(service.Service) error {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel
	p.done = make(chan error, 1)
	go func() {
		err := p.run(ctx)
		p.done <- err
		if err != nil && ctx.Err() == nil {
			// Fatal error while running under a service manager: exit non-zero
			// so the SCM / systemd restart policy kicks in.
			p.log.Error("service failed", "err", err)
			os.Exit(1)
		}
	}()
	return nil
}

func (p *program) Stop(service.Service) error {
	if p.cancel == nil {
		return nil
	}
	p.cancel()
	select {
	case err := <-p.done:
		return err
	case <-time.After(p.stopTimeout):
		return errors.New("timed out waiting for shutdown")
	}
}

// NewService returns a kardianos service for install/uninstall/control.
// run may be nil when only controlling the service.
func NewService(configPath string, run RunFunc, stopTimeout time.Duration) (service.Service, error) {
	if run == nil {
		run = func(context.Context) error { return errors.New("run not configured") }
	}
	prg := &program{run: run, stopTimeout: stopTimeout, log: slog.Default()}
	s, err := service.New(prg, ServiceConfig(configPath))
	if err != nil {
		return nil, fmt.Errorf("service: %w", err)
	}
	return s, nil
}

// Interactive reports whether the process runs from a terminal rather than
// under the Windows SCM or systemd.
func Interactive() bool { return service.Interactive() }
