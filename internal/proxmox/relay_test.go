package proxmox

import (
	"context"
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRelay(t *testing.T) {
	var gotAuth, gotHost, gotFwd string
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotHost, gotFwd = r.Header.Get("Authorization"), r.Host, r.Header.Get("X-Forwarded-For")
		_, _ = io.WriteString(w, `{"data":{"version":"9.0"}}`)
	}))
	defer upstream.Close()
	sum := sha256.Sum256(upstream.Certificate().Raw)
	goodFP := FormatFingerprint(sum[:])
	badFP := strings.Repeat("AB:", 31) + "AB"

	start := func(t *testing.T, fp string) *Relay {
		t.Helper()
		r, err := StartRelay(RelayOptions{Endpoint: upstream.URL, Fingerprint: fp})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = r.Close(ctx)
		})
		return r
	}
	get := func(t *testing.T, url, host string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		req.Header.Set("Authorization", "PVEAPIToken=u@pam!t=fake-secret")
		if host != "" {
			req.Host = host
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}

	t.Run("forwards with pinned TLS", func(t *testing.T) {
		r := start(t, goodFP)
		if !strings.HasPrefix(r.URL(), "http://127.0.0.1:") {
			t.Fatalf("URL = %s", r.URL())
		}
		code, body := get(t, r.URL()+"/version", "")
		if code != 200 || !strings.Contains(body, `"9.0"`) {
			t.Fatalf("code=%d body=%s", code, body)
		}
		if gotAuth != "PVEAPIToken=u@pam!t=fake-secret" {
			t.Errorf("Authorization not forwarded: %q", gotAuth)
		}
		if gotHost != strings.TrimPrefix(upstream.URL, "https://") {
			t.Errorf("upstream Host = %q", gotHost)
		}
		if gotFwd != "" {
			t.Errorf("X-Forwarded-For leaked: %q", gotFwd)
		}
	})
	t.Run("wrong pin fails closed", func(t *testing.T) {
		r := start(t, badFP)
		code, body := get(t, r.URL()+"/version", "")
		if code != http.StatusBadGateway || !strings.Contains(body, "fingerprint") {
			t.Fatalf("code=%d body=%s", code, body)
		}
	})
	t.Run("rejects foreign Host", func(t *testing.T) {
		r := start(t, goodFP)
		if code, _ := get(t, r.URL()+"/version", "evil.example:80"); code != http.StatusMisdirectedRequest {
			t.Fatalf("code = %d", code)
		}
	})
	t.Run("only api paths", func(t *testing.T) {
		r := start(t, goodFP)
		base := strings.TrimSuffix(r.URL(), "/api2/json")
		if code, _ := get(t, base+"/", ""); code != http.StatusNotFound {
			t.Fatalf("code = %d", code)
		}
	})
}
