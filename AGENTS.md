# AGENTS.md: guide for contributors and coding agents

## Ground rules

1. **Read the code first.** Before changing a package, read the package docs
   (`doc.go` or the package comment), its exported API and its tests.
   `docs/architecture.md` lists every extension seam. Use the seams instead of
   editing core files.
2. **Work on a task branch** (`<area>/<short-desc>`, e.g. `auth/sessions`) and
   open a PR to `main`. Do not push directly to `main`.
3. **Run the CI checks locally before pushing.** All of them must pass:

   ```sh
   gofmt -l .                               # must print nothing
   go vet ./...
   GOOS=windows GOARCH=amd64 go vet ./...
   (umask 077; go test -race -count=1 ./...)
   go build ./...
   GOOS=windows GOARCH=amd64 go build ./...
   ```

   `make ci` runs the same set. CI also runs `govulncheck`, and runs
   `packer validate` on `catalog/`.
4. **Keep secrets out of diffs, logs and fixtures.**
   - Never commit real hostnames, tokens, passwords, keys or certificates.
     `.gitignore` blocks `*.key`, `*.pem`, `*.crt` and `/config.yaml`.
   - Test fixtures use obviously fake values.
   - Do not log secret values with slog or write them to job logs. Seal
     stored credentials with `internal/secrets`.
   - Pass Packer and other tool credentials through environment variables or
     0600 var-files, not argv.
5. **Code style.**
   - Write idiomatic Go and keep packages small.
   - Use table-driven tests.
   - Pass `context.Context` through every call that does I/O.
   - Prefer the stdlib. Discuss any new dependency in the PR.
   - Make sure Windows still builds. Platform code goes in `_windows.go` /
     `_other.go` files with build tags.
6. **Migrations are append-only.** Never edit an applied `NNNN_*.sql` file.
   Add a new one instead.

## Package ownership

| Package | Owner | Notes |
|---|---|---|
| `cmd/perfectimage`, `internal/{app,cli,config,store,secrets,jobs,logging,web,tlsutil}` | foundation | Change these only for cross-cutting fixes. Domain agents may only (a) add blank imports to `cmd/perfectimage/plugins.go` and (b) add fields to their own section in `internal/config/sections.go`, plus path fields to `resolvePaths`. |
| `internal/auth`, `internal/rbac` | auth agent | Keep the `Principal`, `Authenticator`, `Authorizer` and `AdminResetter` signatures stable. Add permissions in `rbac/permissions.go`. |
| `internal/proxmox`, `internal/deploy` | proxmox agent | |
| `internal/packer`, `internal/catalog`, `catalog/` | packer agent | |
| `internal/audit`, `internal/siem`, `internal/backup` | ops agent | Keep the `audit.Event` and `audit.Recorder` shapes stable. Install the real recorder with `Deps.Audit.Set`. |

## How a domain package plugs in

```go
package packer

//go:embed migrations/*.sql
var migrations embed.FS

//go:embed templates/*.html
var templates embed.FS

func init() {
	sub, _ := fs.Sub(migrations, "migrations")
	store.RegisterMigrations("packer", sub) // tables: packer_*
	app.RegisterPlugin(plugin{})
}

type plugin struct{}

func (plugin) Name() string { return "packer" }

func (plugin) Init(ctx context.Context, d *app.Deps) error {
	svc := &Service{db: d.DB, sealer: d.Sealer, audit: d.Audit, log: d.Logger, cfg: d.Config.Packer}
	if err := d.Jobs.Register("packer.build", svc); err != nil { // implements jobs.Handler
		return err
	}
	d.Web.AddModule(&module{svc: svc}) // implements web.Module (+ TemplateProvider)
	return nil
}
```

Then add `_ "github.com/mumbles27/PerfectImage/internal/packer"` to
`cmd/perfectimage/plugins.go`.

Conventions:

- **Table names**: prefix with your namespace (`auth_users`, `proxmox_clusters`).
- **Job types**: `<ns>.<verb>`.
- **Audit actions**: dotted (`image.build.start`).
- **Routes**: guarded by the narrowest `rbac` permission. Use
  `rt.HandleFunc("POST /build", rbac.ImagesBuild, h)`.
- **Templates**: namespaced `"<module>/<file>.html"` and must define
  `content`.
- **Scripts**: no inline JS or CSS (CSP). Add files under your module or
  extend `internal/web/static`.
