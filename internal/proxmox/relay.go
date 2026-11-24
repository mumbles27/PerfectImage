package proxmox

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// Relay is a loopback-only reverse proxy in front of one Proxmox endpoint.
//
// External tools such as Packer's proxmox plugin only support system-root
// verification or no verification at all. For clusters that rely on a
// pinned fingerprint or a private CA (for example a node certificate whose
// SANs do not include the address PerfectImage uses), the tool talks plain
// HTTP to the relay on 127.0.0.1 and the relay connects onward with the same
// TLS verification PerfectImage uses itself (TLSConfig). Verification is
// therefore never disabled.
//
// The relay adds no credentials: callers send their own Authorization
// header. It only forwards /api2/ paths and rejects requests whose Host
// header is not the relay's own address, which blocks DNS-rebinding attempts
// from browsers on the same machine.
type Relay struct {
	ln     net.Listener
	srv    *http.Server
	host   string // 127.0.0.1:port
	target *url.URL
	done   chan struct{}
}

// RelayOptions configures StartRelay. The TLS fields mirror Options.
type RelayOptions struct {
	// Endpoint is the Proxmox API endpoint (https://host:port[/api2/json]).
	Endpoint           string
	CAPEM              []byte
	CAFile             string
	Fingerprint        string
	InsecureSkipVerify bool
	Logger             *slog.Logger
}

// StartRelay listens on a random loopback port and serves until Close.
func StartRelay(o RelayOptions) (*Relay, error) {
	base, err := NormalizeEndpoint(o.Endpoint)
	if err != nil {
		return nil, err
	}
	target, err := url.Parse(strings.TrimSuffix(base, "/api2/json"))
	if err != nil {
		return nil, err
	}
	tc, err := TLSConfig(o.CAPEM, o.CAFile, o.Fingerprint, o.InsecureSkipVerify)
	if err != nil {
		return nil, err
	}
	log := o.Logger
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	log = log.With("component", "proxmox-relay", "endpoint", base)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("proxmox relay: listen: %w", err)
	}
	r := &Relay{ln: ln, host: ln.Addr().String(), target: target, done: make(chan struct{})}

	transport := &http.Transport{
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:     tc,
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     90 * time.Second,
		MaxIdleConnsPerHost: 8,
		ForceAttemptHTTP2:   true,
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = target.Host
			// Do not advertise the relay or the local client upstream.
			pr.Out.Header.Del("X-Forwarded-For")
			pr.Out.Header.Del("X-Forwarded-Host")
			pr.Out.Header.Del("X-Forwarded-Proto")
		},
		Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, err error) {
			// Never log headers: they carry the API token.
			log.Warn("relay upstream error", "method", req.Method, "path", req.URL.Path, "err", err)
			http.Error(w, "proxmox relay: upstream error: "+err.Error(), http.StatusBadGateway)
		},
	}
	r.srv = &http.Server{
		Handler:           r.guard(proxy),
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	go func() {
		defer close(r.done)
		if err := r.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("relay stopped", "err", err)
		}
	}()
	log.Info("proxmox relay listening", "addr", r.host)
	return r, nil
}

func (r *Relay) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Host != r.host {
			http.Error(w, "proxmox relay: unexpected Host", http.StatusMisdirectedRequest)
			return
		}
		if !strings.HasPrefix(req.URL.Path, "/api2/") {
			http.NotFound(w, req)
			return
		}
		next.ServeHTTP(w, req)
	})
}

// URL returns the relay's API base URL (http://127.0.0.1:port/api2/json).
func (r *Relay) URL() string { return "http://" + r.host + "/api2/json" }

// Target returns the upstream base URL (https://host:port).
func (r *Relay) Target() string { return r.target.String() }

// Close stops the relay and waits for in-flight requests up to ctx.
func (r *Relay) Close(ctx context.Context) error {
	err := r.srv.Shutdown(ctx)
	select {
	case <-r.done:
	case <-ctx.Done():
	}
	return err
}
