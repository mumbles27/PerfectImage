# PerfectImage architecture

PerfectImage is a single Go binary that runs as a Windows service or a systemd
unit. It serves an HTML UI (server-rendered `html/template` with htmx). It runs
long operations (Packer builds, VM deploys, app installs) as persistent
background jobs, and it stores state in SQLite.

```
            ┌──────────────── cmd/perfectimage ────────────────┐
            │ cli registry: serve install uninstall start stop │
            │ status version backup restore catalog validate   │
            │ user reset-admin                                 │
            └───────────────┬──────────────────────────────────┘
                            │ serve
                    ┌───────▼────────┐
                    │  internal/app  │  bootstrap + kardianos/service + graceful shutdown
                    └───────┬────────┘
   config ─► logging ─► secrets ─► store (+migrations) ─► jobs ─► plugins ─► web (HTTPS)
```

## Bootstrap order (`internal/app`)

1. **config**: `config.Load(path)` decodes YAML strictly (unknown keys are
   rejected). It resolves relative paths against the config file's directory,
   applies defaults (including each section's `Defaulter`) and validates
   (including each section's `Validator`).
2. **logging**: slog JSON to stdout and to a size-rotated file. Records fan
   out to registered `logging.Sink`s.
3. **secrets**: loads or creates the 32-byte master key. Linux uses a 0600 key
   file. Windows uses a DPAPI-protected blob (machine scope). The app gets an
   AES-256-GCM `secrets.Sealer`.
4. **store**: SQLite (modernc, pure Go) with WAL, a busy timeout, foreign keys
   and `BEGIN IMMEDIATE`. Migrations run for every registered namespace:
   `core` first, then the rest alphabetically.
5. **jobs**: `jobs.Manager`, created with N workers but not yet started.
6. **web**: `web.Server` with secure defaults: `auth.DenyAll` authenticator,
   `auth.PermissionAuthorizer` and stdlib cross-origin CSRF protection.
   `auth.dev_allow_all` swaps in `auth.DevAllowAll`, but only on loopback
   listeners.
7. **plugins**: each registered `app.Plugin` gets `Init(ctx, *app.Deps)` in
   import order. Plugins register job handlers, web modules, sinks, the audit
   recorder, the authenticator and readiness checks here.
8. **Run**: makes sure a TLS cert exists (self-signed if none is configured),
   starts the job workers and background tasks, then serves HTTPS.

On shutdown (signal, SCM stop, or `systemctl stop`):

1. Cancel the request base context, so SSE streams end.
2. Call `http.Server.Shutdown`.
3. Stop the job manager. Running jobs get a canceled context and are marked
   `failed: interrupted: service shutdown`.
4. Cancel background tasks.
5. Run the `OnShutdown` hooks in reverse order.
6. Close the DB and the log files.

## Extension seams (for domain agents)

| Need | Seam | Where |
|---|---|---|
| Wire a domain into the service | `app.RegisterPlugin(app.Plugin)` + blank import in `cmd/perfectimage/plugins.go` | `internal/app/plugin.go` |
| Own DB tables | `store.RegisterMigrations("<ns>", fs.FS)` from `init()`; files `NNNN_name.sql` | `internal/store/migrate.go` |
| Background work | `Deps.Jobs.Register("<ns>.<verb>", jobs.Handler)`, `Enqueue(ctx, type, payload, actor)` | `internal/jobs` |
| Pages / endpoints | implement `web.Module` (+ optional `web.TemplateProvider`), `Deps.Web.AddModule(m)` | `internal/web/module.go` |
| Authentication | `Deps.Web.SetAuthenticator(auth.Authenticator)` | `internal/auth/principal.go` |
| Authorization | `Deps.Web.SetAuthorizer(auth.Authorizer)` | `internal/auth/principal.go` |
| CSRF tokens | `Deps.Web.SetCSRF(web.CSRFProtector)` | `internal/web/middleware.go` |
| Audit events | `Deps.Audit.Record(ctx, audit.Event{...})`; ops installs the real recorder with `Deps.Audit.Set(r)` | `internal/audit/event.go` |
| Log forwarding | `Deps.Logging.AddSink(logging.Sink)` | `internal/logging/logging.go` |
| Config | add fields to your section struct (`AuthConfig`, `ProxmoxConfig`, `PackerConfig`, `SIEMConfig`, `BackupConfig`); optionally implement `config.Validator` / `config.Defaulter` | `internal/config/sections.go` |
| CLI commands | `cli.Register(cli.Command{Name: "backup", ...})` replaces the stub | `internal/cli/cli.go` |
| Secrets at rest | `secrets.EncryptString(d.Sealer, value, aad)` / `DecryptString` | `internal/secrets` |
| Readiness | `Deps.Web.AddReadinessCheck(name, func(ctx) error)` | `internal/web/server.go` |
| Shutdown / background | `Deps.OnShutdown(fn)`, `Deps.Go(fn)` | `internal/app/plugin.go` |

## Web layer

The middleware runs in this order, outermost first:

1. `Recover`
2. `RequestID`
3. `AccessLog`
4. `SecurityHeaders` (CSP with no inline script or style, HSTS when TLS is
   on, `nosniff`, `DENY` framing)
5. `CSRFProtector.Protect`
6. `authenticate`, which puts the `*auth.Principal` in the context
7. the router

`Router.Handle(pattern, perm, h)` wraps the handler with
`Server.RequirePermission(perm)`:

- No principal: browser GETs are redirected to `/login` once a module
  registers that path. Everything else gets 401.
- Missing permission: the request gets 403 and an `authz.deny` audit event is
  recorded.
- Empty `perm`: any signed-in principal is allowed.

**Navigation.** The core sections are Dashboard `/`, Build `/build`, Deploy
`/deploy`, Catalog `/catalog`, Jobs `/jobs`, Audit `/audit` and Settings
`/settings`. A module's `Nav()` entry with the same path replaces the core
entry. Any section without a registered page shows a "coming soon"
placeholder. Nav items are filtered per request through the `Authorizer`.

**Templates.** `templates/layout.html` defines `layout`. Page templates
define `content`, plus optional `head` and `scripts`. Module templates are
addressed as `"<module>/<file>.html"`. To render, call
`rt.Render(w, r, name, title, data)`, or for htmx fragments call
`Server.RenderPartial(w, r, name, block, data)`. Every template receives
`web.PageData`: `.Title`, `.Nav`, `.Principal`, `.CSRFToken`, `.RequestID`,
`.Version` and `.Data`.

**Static files.** `internal/web/static` is embedded and holds htmx 2.0.11,
`app.css` and `app.js`. Inline `<script>` is forbidden by the CSP, so put
behavior in `.js` files.

**Job log streaming.** `GET /jobs/{id}/stream` is a Server-Sent Events
endpoint with three events:

- `log`: `{"id","time","line"}`
- `status`
- `done`

It supports reconnects through `Last-Event-ID`. Hub events only wake the
stream. Log lines are always read from `job_logs`, so slow clients never
lose a line.

## Jobs

The lifecycle is:

- `queued` → `running` → `succeeded`, `failed` or `canceled`
- `queued` → `canceled`

- **Claiming.** A worker claims a job with a single
  `UPDATE ... RETURNING` statement.
- **Results and logs.** `Handler.Run(ctx, *Job, *LogWriter)` returns
  `(result any, err error)`. A non-nil result is stored as JSON. The
  `LogWriter` splits output into lines (max 8 KiB each) and is safe to use
  from concurrent goroutines, for example as both stdout and stderr of an
  `exec.Cmd`.
- **Cancellation.** Users cancel through `Manager.Cancel`, which cancels
  the job's context.
- **Crash recovery.** Jobs still `running` at startup are marked
  `failed: interrupted: service restarted while running`.
- **Panics.** A panicking handler fails its job. The stack goes to the
  service log, not the job log.

## Data layout (`data_dir`)

```
perfectimage.db (+ -wal, -shm)   SQLite, 0600
secrets/master.key               Linux, 0600 raw 32 bytes
secrets/master.key.dpapi         Windows, DPAPI blob
tls/selfsigned.{crt,key}         auto-generated when no cert configured
logs/perfectimage.log[.N]        rotated JSON logs
```

## Security notes

- HTTPS is on by default. Plain HTTP (`server.tls.disable`) and
  `auth.dev_allow_all` are both rejected unless the listener is loopback.
- Never log secrets, and never write them to job logs. Seal credentials with
  `secrets` before storing them, and pass an `aad` that identifies the row
  or purpose.
- The access log leaves out query strings. Request IDs taken from clients
  are validated first.
- On Windows the installer restricts `%ProgramData%\PerfectImage` to SYSTEM
  and Administrators. The systemd unit runs as a dedicated user with
  `UMask=0077` and strict sandboxing.
