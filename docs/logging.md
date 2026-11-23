# Logging

PerfectImage logs structured JSON with `log/slog`, set up in
`internal/logging`. Every record goes to three places:

- stdout (journald on Linux), when `log.stdout` is true (the default)
- a size-rotated file, `log.file` (default `<data_dir>/logs/perfectimage.log`,
  `log.max_size_mb` / `log.max_backups`; `"-"` disables it)
- registered **sinks**. Each sink has its own level, so a sink can receive
  records below `log.level`.

```yaml
log:
  level: info        # debug | info | warn | error
  file: ""
  max_size_mb: 50
  max_backups: 5
  stdout: true
```

## Conventions

- Use a component logger: `d.Logger.With("component", "packer")`.
- Never log secret values: passwords, tokens, keys, passphrases or
  Authorization headers. Job logs are visible in the UI and are held to the
  same rule.
- Log errors with an `err` attribute. Put identifiers (job ID, output name,
  request ID) in attributes, not in the message.
- Security-relevant actions belong in the **audit log**
  (`Deps.Audit.Record`), not only in application logs. See
  [siem.md](siem.md).

## Forwarding logs to a SIEM

Outputs listing `logs` in `streams` receive application records at or above
their `min_level` through the `siem` sink.

- **Format.** Records are flattened: group attributes become `group.key`, and
  `With` attributes are included. Each record is converted to the SIEM record
  format (`kind: "log"`).
- **Redaction.** Attribute keys that look secret are redacted with
  `[REDACTED]`. Redaction is a safety net, not a licence to log secrets.
- **Non-blocking.** The sink never blocks a logging call. Records that do not
  fit the output's queue are dropped and counted on `/settings/siem`.
- **No loops.** Records from the SIEM component itself (`component=siem`) are
  not forwarded, so a failing output cannot feed itself.

The HTTP access log (`msg: "http request"`, info level) is forwarded like any
other record. To forward only problems, set `min_level: warn`.

## Writing a sink

Implement `logging.Sink` and register it with `Deps.Logging.AddSink`. A sink
must not block: buffer and drop, or hand off to a goroutine. It must not log
through the application logger. `Logging.Close` closes sinks after the
plugins' shutdown hooks have run.
