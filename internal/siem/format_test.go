package siem

import (
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/audit/auditlog"
)

func TestFormatCEF(t *testing.T) {
	e := testEntry()
	e.Action = "auth|login"
	e.Target = `a=b\c` + "\nd"
	e.Outcome = audit.OutcomeDenied
	got := formatCEF(FromAudit(e, "h1"), "1.0")
	for _, want := range []string{
		`CEF:0|PerfectImage|PerfectImage|1.0|auth\|login|auth\|login denied|7|`,
		`rt=1777629600000`, `suser=alice`, `src=192.0.2.10`, `outcome=denied`,
		`cs1Label=target cs1=a\=b\\c\nd`, `dvchost=h1`,
		`msg={"password":"[REDACTED]","template":"ubuntu"}`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("CEF %q missing %q", got, want)
		}
	}
	if strings.Contains(got, "hunter2") {
		t.Fatal("secret in CEF")
	}
}

func TestFormatSyslogEscapingAndPRI(t *testing.T) {
	tests := []struct {
		name string
		rec  Record
		fac  int
		pri  string
	}{
		{"audit success local0", FromAudit(testEntry(), "h"), 16, "<133>"},
		{"audit failure auth", func() Record {
			e := testEntry()
			e.Outcome = audit.OutcomeFailure
			return FromAudit(e, "h")
		}(), 4, "<36>"},
		{"log error local7", Record{Kind: KindLog, Level: "error", Time: time.Now(), Message: "x"}, 23, "<187>"},
		{"log debug user", Record{Kind: KindLog, Level: "debug", Time: time.Now(), Message: "x"}, 1, "<15>"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := string(formatSyslog(tt.rec, tt.fac, "my app", "body"))
			if !strings.HasPrefix(msg, tt.pri+"1 ") || !strings.HasSuffix(msg, " body") || !strings.Contains(msg, " my_app ") {
				t.Fatalf("syslog %q", msg)
			}
		})
	}
	e := testEntry()
	e.Target = `x"]\y`
	msg := string(formatSyslog(FromAudit(e, ""), 16, "pi", "-"))
	if !strings.Contains(msg, `target="x\"\]\\y"`) || !strings.Contains(msg, " - pi ") {
		t.Fatalf("SD escaping / nil host: %q", msg)
	}
}

func TestRedactionInRecords(t *testing.T) {
	e := auditlog.Entry{Event: audit.Event{Action: "x", Outcome: audit.OutcomeSuccess,
		Details: map[string]any{"nested": map[string]any{"apiKey": "k", "ok": "v"}, "Secret": "s"}}}
	r := FromAudit(e, "")
	d := r.Fields["details"].(map[string]any)
	if d["Secret"] != audit.Redacted || d["nested"].(map[string]any)["apiKey"] != audit.Redacted ||
		d["nested"].(map[string]any)["ok"] != "v" {
		t.Fatalf("audit details %v", d)
	}
	lr := slog.NewRecord(time.Now(), slog.LevelInfo, "m", 0)
	lr.AddAttrs(slog.String("token", "t"), slog.String("user", "u"),
		slog.Group("req", slog.String("authorization", "Bearer x")))
	got := FromLog(lr, "")
	if got.Fields["token"] != audit.Redacted || got.Fields["user"] != "u" ||
		got.Fields["req"].(map[string]any)["authorization"] != audit.Redacted {
		t.Fatalf("log fields %v", got.Fields)
	}
}

func TestECSMapping(t *testing.T) {
	e := testEntry()
	e.Action = "auth.login"
	e.Outcome = audit.OutcomeDenied
	doc := ecsDocument(FromAudit(e, "h"))
	ev := doc["event"].(map[string]any)
	if ev["outcome"] != "failure" || ev["type"].([]string)[0] != "denied" ||
		ev["category"].([]string)[0] != "authentication" || ev["dataset"] != "perfectimage.audit" {
		t.Fatalf("event %v", ev)
	}
	if doc["host"].(map[string]any)["hostname"] != "h" || doc["http"].(map[string]any)["request"].(map[string]any)["id"] != "req1" {
		t.Fatalf("doc %v", doc)
	}
}
