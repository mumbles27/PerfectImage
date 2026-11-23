package auditlog

import (
	"context"
	"encoding/csv"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/auth"
	"github.com/mumbles27/PerfectImage/internal/web"
)

func newTestServer(t *testing.T, s *Store) http.Handler {
	t.Helper()
	srv := web.NewServer(web.Options{Audit: s})
	srv.SetAuthenticator(auth.DevAllowAll{})
	srv.SetAuthorizer(auth.DevAllowAll{})
	srv.AddModule(&module{st: s})
	h, err := srv.Handler()
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func get(t *testing.T, h http.Handler, url string, hdr ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, url, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAuditPages(t *testing.T) {
	ctx := context.Background()
	s := newStore(t, openDB(t), Options{})
	record(t, s,
		audit.Event{Actor: "alice", Action: "auth.login", Target: "=cmd|' /C calc'!A0"},
		audit.Event{Actor: "bob", Action: "image.build.start", Outcome: audit.OutcomeFailure},
	)
	h := newTestServer(t, s)

	rec := get(t, h, "/audit?actor=alice")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "auth.login") ||
		strings.Contains(rec.Body.String(), "image.build.start") {
		t.Fatalf("list: %d %s", rec.Code, rec.Body.String())
	}
	if rec := get(t, h, "/audit?outcome=bogus"); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad outcome: %d", rec.Code)
	}

	rec = get(t, h, "/audit/verify", "HX-Request", "true")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "chain verified") {
		t.Fatalf("verify: %d %s", rec.Code, rec.Body.String())
	}

	rec = get(t, h, "/audit/export?format=csv&actor=alice")
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "text/csv; charset=utf-8" {
		t.Fatalf("export: %d %v", rec.Code, rec.Header())
	}
	rows, err := csv.NewReader(rec.Body).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	// header + auth.login + the audit.export event itself (actor "dev" does
	// not match "alice", so only the login row).
	if len(rows) != 2 || rows[1][5] != "auth.login" || !strings.HasPrefix(rows[1][6], "'=") {
		t.Fatalf("csv rows %q", rows)
	}

	rec = get(t, h, "/audit/export?format=json&action=audit.export")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"action":"audit.export"`) {
		t.Fatalf("json export: %d %s", rec.Code, rec.Body.String())
	}
	if rec := get(t, h, "/audit/export?format=xml"); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad format: %d", rec.Code)
	}

	// Exports were audited with the filter and format.
	_ = s.Flush(ctx)
	got, _, err := s.Query(ctx, Filter{Action: "audit.export"})
	if err != nil || len(got) != 2 || got[1].Details["format"] != "csv" || got[1].Actor != "dev" {
		t.Fatalf("export audit events: %+v %v", got, err)
	}

	if rec := get(t, h, "/audit/metrics"); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"recorded"`) {
		t.Fatalf("metrics: %d %s", rec.Code, rec.Body.String())
	}
	if rec := get(t, h, StylesheetPath); rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Type"), "text/css") {
		t.Fatalf("css: %d", rec.Code)
	}
}

func TestAuditRequiresPermission(t *testing.T) {
	s := newStore(t, openDB(t), Options{})
	srv := web.NewServer(web.Options{Audit: s})
	viewer := auth.Principal{ID: "v", Username: "viewer"}
	srv.SetAuthenticator(authFunc(func(*http.Request) (*auth.Principal, error) { p := viewer; return &p, nil }))
	srv.AddModule(&module{st: s})
	h, err := srv.Handler()
	if err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"/audit", "/audit/export?format=csv", "/audit/verify"} {
		if rec := get(t, h, u); rec.Code != http.StatusForbidden {
			t.Fatalf("%s: %d", u, rec.Code)
		}
	}
}

type authFunc func(*http.Request) (*auth.Principal, error)

func (f authFunc) Authenticate(r *http.Request) (*auth.Principal, error) { return f(r) }
