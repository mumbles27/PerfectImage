// Package authplugin wires internal/auth into the service: it installs the
// session/API-token Authenticator, the RBAC Authorizer and the
// synchronizer-token CSRF protector, serves the sign-in, account and
// user/role/SSO administration pages, and implements the
// `perfectimage user reset-admin` command.
//
// It lives in a sub-package because internal/web imports internal/auth.
package authplugin

import (
	"context"
	"embed"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/mumbles27/PerfectImage/internal/app"
	"github.com/mumbles27/PerfectImage/internal/auth"
)

//go:embed templates/*.html
var templatesFS embed.FS

//go:embed static
var staticFS embed.FS

func init() {
	app.RegisterPlugin(plugin{})
	registerCLI()
}

type plugin struct{}

func (plugin) Name() string { return "auth" }

func (plugin) Init(ctx context.Context, d *app.Deps) error {
	cfg := d.Config
	svc := auth.NewService(auth.Options{
		DB: d.DB, Sealer: d.Sealer, Audit: d.Audit, Logger: d.Logger, Config: cfg.Auth,
		SecureCookies: !cfg.Server.TLS.Disable,
	})
	if err := svc.Init(ctx); err != nil {
		return err
	}
	secretsDir := filepath.Join(cfg.DataDir, "secrets")
	if cfg.Secrets.KeyFile != "" {
		secretsDir = filepath.Dir(cfg.Secrets.KeyFile)
	}
	if err := svc.Bootstrap(ctx, os.Stderr, secretsDir); err != nil {
		return err
	}
	d.Web.SetCSRF(svc.CSRF())
	if !cfg.Auth.DevAllowAll {
		d.Web.SetAuthenticator(svc)
		d.Web.SetAuthorizer(svc)
	}
	d.Web.AddModule(&module{svc: svc, srv: d.Web, publicURL: cfg.Server.PublicURL})
	d.Go(svc.Background)
	return nil
}

func templates() fs.FS {
	sub, err := fs.Sub(templatesFS, "templates")
	if err != nil {
		panic(err)
	}
	return sub
}
