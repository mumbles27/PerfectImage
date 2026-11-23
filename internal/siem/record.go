package siem

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/audit/auditlog"
)

// Record kinds.
const (
	KindAudit = "audit"
	KindLog   = "log"
)

// Record is the normalized unit forwarded to every output. Fields are
// already redacted.
type Record struct {
	ID      string         `json:"id"`
	Kind    string         `json:"kind"`
	Time    time.Time      `json:"time"`
	Level   string         `json:"level"` // debug|info|warn|error for logs; info|warn for audit
	Host    string         `json:"host,omitempty"`
	Message string         `json:"message"`
	Fields  map[string]any `json:"fields,omitempty"`
}

// str returns Fields[k] as a string ("" if absent).
func (r Record) str(k string) string {
	v, ok := r.Fields[k]
	if !ok || v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func randomID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// FromAudit converts a persisted audit entry.
func FromAudit(e auditlog.Entry, host string) Record {
	f := map[string]any{
		"action":  e.Action,
		"outcome": string(e.Outcome),
		"seq":     e.Seq,
		"hash":    e.Hash,
	}
	for k, v := range map[string]string{"actor": e.Actor, "actor_id": e.ActorID, "target": e.Target,
		"reason": e.Reason, "source_ip": e.SourceIP, "user_agent": e.UserAgent, "request_id": e.RequestID} {
		if v != "" {
			f[k] = v
		}
	}
	if len(e.Details) > 0 {
		f["details"] = audit.Redact(e.Details)
	}
	level := "info"
	if e.Outcome != audit.OutcomeSuccess {
		level = "warn"
	}
	id := e.ID
	if id == "" {
		id = randomID()
	}
	return Record{ID: id, Kind: KindAudit, Time: e.Time.UTC(), Level: level, Host: host, Message: e.Action, Fields: f}
}

// FromLog converts a (flattened) slog record. Sensitive attribute keys are
// redacted.
func FromLog(r slog.Record, host string) Record {
	f := map[string]any{}
	r.Attrs(func(a slog.Attr) bool {
		f[a.Key] = attrValue(a.Value)
		return true
	})
	t := r.Time
	if t.IsZero() {
		t = time.Now()
	}
	return Record{
		ID: randomID(), Kind: KindLog, Time: t.UTC(), Level: levelName(r.Level), Host: host,
		Message: r.Message, Fields: audit.Redact(f),
	}
}

func attrValue(v slog.Value) any {
	v = v.Resolve()
	switch v.Kind() {
	case slog.KindString:
		return v.String()
	case slog.KindInt64:
		return v.Int64()
	case slog.KindUint64:
		return v.Uint64()
	case slog.KindFloat64:
		return v.Float64()
	case slog.KindBool:
		return v.Bool()
	case slog.KindDuration:
		return v.Duration().String()
	case slog.KindTime:
		return v.Time().UTC().Format(time.RFC3339Nano)
	case slog.KindGroup:
		m := map[string]any{}
		for _, a := range v.Group() {
			m[a.Key] = attrValue(a.Value)
		}
		return m
	default:
		if err, ok := v.Any().(error); ok {
			return err.Error()
		}
		return fmt.Sprint(v.Any())
	}
}

func levelName(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "error"
	case l >= slog.LevelWarn:
		return "warn"
	case l >= slog.LevelInfo:
		return "info"
	default:
		return "debug"
	}
}

// syslogSeverity maps a record to an RFC 5424 severity.
func syslogSeverity(r Record) int {
	if r.Kind == KindAudit {
		if r.str("outcome") == string(audit.OutcomeSuccess) {
			return 5 // notice
		}
		return 4 // warning
	}
	switch r.Level {
	case "error":
		return 3
	case "warn":
		return 4
	case "debug":
		return 7
	default:
		return 6
	}
}

// cefSeverity maps a record to a CEF severity (0-10).
func cefSeverity(r Record) int {
	if r.Kind == KindAudit {
		switch r.str("outcome") {
		case string(audit.OutcomeSuccess):
			return 3
		case string(audit.OutcomeDenied):
			return 7
		default:
			return 6
		}
	}
	switch r.Level {
	case "error":
		return 8
	case "warn":
		return 6
	case "debug":
		return 1
	default:
		return 3
	}
}
