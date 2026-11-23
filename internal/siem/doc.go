// Package siem forwards audit events and application logs to external
// SIEMs.
//
// Outputs are configured in config.SIEMConfig.Outputs:
//
//   - syslog: RFC 5424 over UDP, TCP (RFC 6587 octet counting) or TLS
//     (custom CA, client certificate); MSG is the record as JSON
//   - cef: ArcSight CEF:0 carried in RFC 5424 syslog
//   - splunk_hec: Splunk HTTP Event Collector (token, index, sourcetype)
//   - elastic: Elasticsearch/OpenSearch _bulk with an ECS-style mapping
//     (API key or basic auth)
//   - webhook: HTTPS JSON POST with custom headers and an HMAC-SHA256
//     signature
//   - file: local JSON-lines file with size rotation
//
// Each output has a bounded in-memory queue, batching, exponential backoff
// with jitter and a size-capped on-disk spill buffer that survives restarts.
// Enqueueing never blocks: the audit stream subscribes to the persistent
// audit log (auditlog.Store.Subscribe) and the log stream is a
// logging.Sink. Sensitive keys (password, secret, token, ...) are redacted
// before records leave the process. Credentials are sealed in the
// siem_credentials table and set on /settings/siem.
//
// See docs/siem.md.
package siem
