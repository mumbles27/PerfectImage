package siem

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// sdID is the RFC 5424 structured-data ID. 32473 is the IANA example
// enterprise number reserved for documentation (RFC 5612).
const sdID = "perfectimage@32473"

var facilities = map[string]int{
	"kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5, "lpr": 6, "news": 7,
	"uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11, "ntp": 12, "security": 13, "console": 14,
	"local0": 16, "local1": 17, "local2": 18, "local3": 19, "local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

// parseFacility returns the numeric facility for a name.
func parseFacility(name string) (int, error) {
	f, ok := facilities[strings.ToLower(name)]
	if !ok {
		return 0, fmt.Errorf("unknown syslog facility %q", name)
	}
	return f, nil
}

// headerToken sanitizes an RFC 5424 header field (PRINTUSASCII, no spaces).
func headerToken(s string, maxLen int) string {
	if s == "" {
		return "-"
	}
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s) && len(b) < maxLen; i++ {
		c := s[i]
		if c < 33 || c > 126 {
			c = '_'
		}
		b = append(b, c)
	}
	return string(b)
}

// sdEscape escapes an SD-PARAM value (RFC 5424 §6.3.3).
func sdEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`).Replace(s)
}

// formatSyslog renders an RFC 5424 message whose MSG is body.
func formatSyslog(r Record, facility int, appName, body string) []byte {
	pri := facility*8 + syslogSeverity(r)
	var sd strings.Builder
	sd.WriteString("[" + sdID + ` kind="` + r.Kind + `"`)
	for _, k := range []string{"action", "outcome", "actor", "target"} {
		if v := r.str(k); v != "" {
			sd.WriteString(" " + k + `="` + sdEscape(v) + `"`)
		}
	}
	if r.Kind == KindLog {
		sd.WriteString(` level="` + r.Level + `"`)
	}
	sd.WriteString("]")
	return fmt.Appendf(nil, "<%d>1 %s %s %s %d %s %s %s",
		pri, r.Time.UTC().Format("2006-01-02T15:04:05.000000Z07:00"),
		headerToken(r.Host, 255), headerToken(appName, 48), os.Getpid(), headerToken(r.Kind, 32),
		sd.String(), body)
}

// jsonBody is the JSON representation used by syslog MSG, file and webhook.
func jsonBody(r Record) string {
	b, err := json.Marshal(r)
	if err != nil {
		b, _ = json.Marshal(Record{ID: r.ID, Kind: r.Kind, Time: r.Time, Level: r.Level, Message: r.Message,
			Fields: map[string]any{"_error": "fields not encodable"}})
	}
	return string(b)
}

func cefHeaderEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `|`, `\|`, "\r", " ", "\n", " ").Replace(s)
}

func cefExtEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `=`, `\=`, "\r\n", `\n`, "\n", `\n`, "\r", `\r`).Replace(s)
}

// formatCEF renders an ArcSight CEF:0 event.
func formatCEF(r Record, version string) string {
	sig, name := "log", r.Message
	if r.Kind == KindAudit {
		sig = r.str("action")
		name = r.str("action")
		if o := r.str("outcome"); o != "" {
			name += " " + o
		}
	}
	if len(name) > 512 {
		name = name[:512]
	}
	ext := []struct{ k, v string }{
		{"rt", strconv.FormatInt(r.Time.UnixMilli(), 10)},
		{"externalId", r.ID},
		{"dvchost", r.Host},
		{"cat", r.Kind},
		{"suser", r.str("actor")},
		{"suid", r.str("actor_id")},
		{"src", r.str("source_ip")},
		{"act", r.str("action")},
		{"outcome", r.str("outcome")},
		{"reason", r.str("reason")},
		{"requestClientApplication", r.str("user_agent")},
		{"cs1Label", "target"}, {"cs1", r.str("target")},
		{"cs2Label", "request_id"}, {"cs2", r.str("request_id")},
	}
	var b strings.Builder
	fmt.Fprintf(&b, "CEF:0|PerfectImage|PerfectImage|%s|%s|%s|%d|",
		cefHeaderEscape(version), cefHeaderEscape(sig), cefHeaderEscape(name), cefSeverity(r))
	first := true
	for _, e := range ext {
		if e.v == "" || (strings.HasSuffix(e.k, "Label") && r.Kind != KindAudit) {
			continue
		}
		if !first {
			b.WriteByte(' ')
		}
		first = false
		b.WriteString(e.k + "=" + cefExtEscape(e.v))
	}
	msg := r.Message
	if r.Kind == KindAudit {
		if d, ok := r.Fields["details"]; ok {
			j, _ := json.Marshal(d)
			msg = string(j)
		} else {
			msg = ""
		}
	} else if len(r.Fields) > 0 {
		j, _ := json.Marshal(r.Fields)
		msg += " " + string(j)
	}
	if msg != "" {
		b.WriteString(" msg=" + cefExtEscape(msg))
	}
	return b.String()
}

// ecsDocument maps a record onto Elastic Common Schema fields.
func ecsDocument(r Record) map[string]any {
	event := map[string]any{
		"id": r.ID, "kind": "event", "module": "perfectimage",
		"dataset":  "perfectimage." + r.Kind,
		"created":  time.Now().UTC().Format(time.RFC3339Nano),
		"severity": syslogSeverity(r),
	}
	doc := map[string]any{
		"@timestamp": r.Time.UTC().Format(time.RFC3339Nano),
		"message":    r.Message,
		"ecs":        map[string]any{"version": "8.11.0"},
		"service":    map[string]any{"name": "perfectimage", "type": "perfectimage"},
		"log":        map[string]any{"level": r.Level},
		"event":      event,
	}
	if r.Host != "" {
		doc["host"] = map[string]any{"hostname": r.Host, "name": r.Host}
	}
	if r.Kind == KindAudit {
		event["category"] = []string{"configuration"}
		event["action"] = r.str("action")
		switch o := r.str("outcome"); o {
		case "success":
			event["outcome"] = "success"
			event["type"] = []string{"info"}
		case "denied":
			event["outcome"] = "failure"
			event["type"] = []string{"denied"}
		default:
			event["outcome"] = "failure"
			event["type"] = []string{"info"}
		}
		if strings.HasPrefix(r.str("action"), "auth.") {
			event["category"] = []string{"authentication"}
		}
		user := map[string]any{}
		if v := r.str("actor"); v != "" {
			user["name"] = v
		}
		if v := r.str("actor_id"); v != "" {
			user["id"] = v
		}
		if len(user) > 0 {
			doc["user"] = user
		}
		if v := r.str("source_ip"); v != "" {
			doc["source"] = map[string]any{"ip": v}
		}
		if v := r.str("user_agent"); v != "" {
			doc["user_agent"] = map[string]any{"original": v}
		}
		if v := r.str("request_id"); v != "" {
			doc["http"] = map[string]any{"request": map[string]any{"id": v}}
		}
		pi := map[string]any{"audit": map[string]any{"seq": r.Fields["seq"], "hash": r.Fields["hash"]}}
		for _, k := range []string{"target", "reason"} {
			if v := r.str(k); v != "" {
				pi[k] = v
			}
		}
		if d, ok := r.Fields["details"]; ok {
			pi["details"] = d
		}
		doc["perfectimage"] = pi
	} else if len(r.Fields) > 0 {
		doc["perfectimage"] = map[string]any{"fields": r.Fields}
	}
	return doc
}

// sortedKeys returns the keys of m in order (stable header output).
func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
