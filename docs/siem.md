# Audit log and SIEM forwarding

## Audit log (`internal/audit/auditlog`)

Security-relevant actions are recorded through `Deps.Audit.Record(ctx, audit.Event{...})`.
The ops plugin installs a persistent recorder that does the following:

- **Asynchronous writes.** `Record` validates the event, puts it in a bounded
  buffer (`siem.audit_queue_size`, default 4096) and returns. A single writer
  goroutine batches events into transactions. If the buffer stays full for
  100 ms, the event is dropped, counted and an error is logged. `/readyz`
  reports `audit` as failing once the buffer is 90% full.
- **Append-only storage.** Events go to the `audit_events` table. SQLite
  triggers reject every `UPDATE`. They also reject any `DELETE` that is not
  part of retention.
- **Hash chain.** Each row stores `prev_hash` and
  `hash = hex(SHA-256(prev_hash || "\n" || canonical JSON))`. The canonical
  JSON is the event with fields in a fixed order, UTC time with millisecond
  precision, and the stored (redacted) details. The first event chains from
  64 zeros.
- **Verification.** `Store.Verify` walks the chain from the retention anchor
  and reports the first broken event:
  - a modified field gives a hash mismatch
  - a deleted or reordered event gives a `prev_hash` mismatch

  The `/audit` page shows the result as a badge (cached for 30 s; *re-check*
  forces a new run). A broken chain is logged and recorded as
  `audit.chain.broken`.
- **Retention.** `siem.audit_retention` (default `8760h`; `0` keeps events
  forever) is applied every 6 hours. It always removes a contiguous prefix of
  the chain and first moves the anchor (`audit_chain`) to the newest removed
  hash, so the remaining chain still verifies. Each prune is audited as
  `audit.retention.prune`.
- **Redaction.** Detail keys that look secret (`password`, `secret`, `token`,
  `api_key`, `authorization`, `passphrase`, …) are replaced with
  `[REDACTED]` before they are stored.
- **Metrics.** `GET /audit/metrics` (JSON) reports enqueued, recorded,
  dropped, write errors, pruned, queue length and capacity, and the last
  error. The same counters appear on `/audit`.

### UI and export

`/audit` requires `audit.view`. It offers these filters:

- time range
- actor (substring)
- action (prefix, e.g. `auth.`)
- outcome
- target (substring)

Results show newest first, 50 per page. **Export** (`/audit/export?format=csv|json`)
streams every matching event in chain order. JSON export is JSON lines. CSV
cells are protected against spreadsheet formula injection. Every export is
itself audited as `audit.export`, together with its format and filter. If that
audit event cannot be recorded, the export is refused.

Other ops packages reach the store with `auditlog.For(deps)`.
`Store.Subscribe(fn)` delivers persisted entries (with seq and hash) after each
commit. The SIEM uses it to stream audit events.

## SIEM outputs (`internal/siem`)

Outputs are configured in `siem.outputs` (see `config.example.yaml`). Changes
take effect after a restart. Each output forwards one or both streams:

- `audit`: persisted audit events
- `logs`: application log records at or above `min_level`, delivered through a
  `logging.Sink`

| type | transport | notes |
|---|---|---|
| `syslog` | RFC 5424 over `udp://`, `tcp://` (RFC 6587 octet counting) or `tls://` | MSG is the record as JSON; SD-ID `perfectimage@32473` carries kind/action/outcome/actor/target |
| `cef` | ArcSight `CEF:0` carried in RFC 5424 syslog | extensions `rt suser suid src act outcome reason cs1=target cs2=request_id msg=details` |
| `splunk_hec` | HTTP Event Collector `POST /services/collector/event` | credential **token**; `index`, `sourcetype` (default `perfectimage:json`) |
| `elastic` | Elasticsearch / OpenSearch `POST /_bulk` (`create` with the record ID, so retries are idempotent) | credential **api_key** (encoded, or `id:key`), or `username` + credential **password**; ECS-style documents |
| `webhook` | HTTPS `POST` of `{"source","sent_at","events":[...]}` | custom `headers`; optional credentials **hmac_secret** and **auth_header** (sent as `Authorization`) |
| `file` | local JSON lines with size rotation | `path`, `max_size_mb`, `max_files` |

TLS settings (`ca_file`, `cert_file`/`key_file` for mutual TLS, `server_name`,
`insecure_skip_verify`) apply to `tls://` syslog and to HTTPS outputs. HTTP
outputs never follow redirects, so credentials are never sent to a redirect
target.

### Webhook signature

When `hmac_secret` is set, each request carries two headers:

```
X-PerfectImage-Timestamp: <unix seconds>
X-PerfectImage-Signature: sha256=<hex HMAC-SHA256(secret, timestamp + "." + body)>
```

Receivers should recompute the signature over the raw body, compare in
constant time and reject stale timestamps.

### Record format

```json
{"id":"…","kind":"audit|log","time":"RFC 3339","level":"info|warn|error|debug",
 "host":"…","message":"<action or log message>",
 "fields":{"action":"…","outcome":"…","actor":"…","target":"…","details":{…},"seq":7,"hash":"…"}}
```

Elastic documents map these to ECS fields:

- `@timestamp`, `message`
- `event.{id,kind,dataset,action,outcome,type,category,severity}`
- `user.{name,id}`, `source.ip`, `user_agent.original`, `http.request.id`
- `host.hostname`, `log.level`
- `perfectimage.*` for everything else

A `denied` outcome maps to `event.outcome: failure` with `event.type: [denied]`.

### Delivery guarantees

Delivery is at least once.

- **Queueing.** Enqueueing never blocks. Each output has a bounded queue
  (`queue_size`). Records that do not fit are dropped and counted.
- **Batching.** The worker sends batches of up to `batch_size` records, or
  whatever is queued every `flush_interval`.
- **Retries.** A failed batch is retried with exponential backoff and jitter:
  500 ms, doubling up to `max_backoff`.
  - HTTP 401, 403, 404, 408, 429 and 5xx are retried, so data survives until a
    credential or endpoint is fixed.
  - Other 4xx responses and Elastic per-item rejections are permanent. Those
    records are dropped and counted.
- **Spill buffer.** While an output is failing, new and failed batches go, in
  order, to an on-disk spill file: `<spill_dir>/<name>.spill`, at most
  `spill_max_mb`, default 64 MiB. When the spill cap is reached, records are
  dropped. The spill buffer is drained first once the destination recovers.
  It survives restarts: on shutdown, undeliverable records are spilled and
  sent on the next start.
- **Memory backlog.** With `spill_max_mb: -1`, the backlog is kept in memory
  (up to `queue_size`) and lost on restart.

### `/settings/siem`

Requires `siem.manage`. The page provides:

- live health per output: sent, failed attempts, dropped, queued, spilled,
  last error
- credential entry. Values are sealed with the master key in
  `siem_credentials` (AAD `siem:<output>:<field>`), take effect on the next
  send, are never displayed, and are audited as `siem.credential.set` or
  `siem.credential.clear`.
- **Send test event**, which delivers one synthetic `siem.test` record
  directly and shows the result. It is audited as `siem.test`.

### Redaction and loops

Before any record leaves the process, keys matching `password`, `passwd`,
`passphrase`, `secret`, `token`, `apikey`/`api_key`, `authorization`,
`privatekey`, `credential`, `cookie` or `sessionid` (any case or separator) are
replaced with `[REDACTED]` at every nesting level. SIEM log records carry
`component=siem` and are never forwarded, so a failing output cannot feed
itself.
