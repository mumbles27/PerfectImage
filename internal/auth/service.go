package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/mumbles27/PerfectImage/internal/audit"
	"github.com/mumbles27/PerfectImage/internal/config"
	"github.com/mumbles27/PerfectImage/internal/secrets"
	"github.com/mumbles27/PerfectImage/internal/store"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Migrations returns the auth schema (namespace "auth", tables auth_*).
func Migrations() fs.FS {
	sub, err := fs.Sub(migrationsFS, "migrations")
	if err != nil {
		panic(err)
	}
	return sub
}

func init() { store.RegisterMigrations("auth", Migrations()) }

// Options configures a Service.
type Options struct {
	DB     *store.DB
	Sealer secrets.Sealer
	Audit  audit.Recorder
	Logger *slog.Logger
	Config config.AuthConfig
	// SecureCookies sets the Secure attribute on cookies (false only for
	// plain-HTTP loopback development).
	SecureCookies bool
	// Argon2 overrides DefaultArgon2Params (tests use cheaper parameters).
	Argon2 *Argon2Params
	// HTTPClient is used for OIDC (default: 15s timeout).
	HTTPClient *http.Client
	// LDAPDialer overrides the LDAP connection factory (tests).
	LDAPDialer LDAPDialer
	// Now overrides the clock (tests).
	Now func() time.Time
}

// Service implements users, sessions, MFA, roles, API tokens and SSO. It is
// the Authenticator, Authorizer, AdminResetter and CSRF protector installed
// by the auth plugin.
type Service struct {
	db     *store.DB
	sealer secrets.Sealer
	audit  audit.Recorder
	log    *slog.Logger
	cfg    config.AuthConfig
	argon  Argon2Params
	secure bool
	http   *http.Client
	ldial  LDAPDialer
	now    func() time.Time

	ipLimit   *RateLimiter
	userLimit *RateLimiter
	csrfKey   []byte
	dummyHash string
}

// NewService returns a Service. Call Init before serving requests.
func NewService(o Options) *Service {
	if o.Logger == nil {
		o.Logger = slog.New(slog.DiscardHandler)
	}
	if o.Audit == nil {
		o.Audit = audit.NopRecorder{}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	if o.LDAPDialer == nil {
		o.LDAPDialer = dialLDAP
	}
	cfg := o.Config
	cfg.ApplyDefaults(nil)
	s := &Service{
		db: o.DB, sealer: o.Sealer, audit: o.Audit, log: o.Logger.With("component", "auth"),
		cfg: cfg, argon: DefaultArgon2Params, secure: o.SecureCookies, http: o.HTTPClient,
		ldial: o.LDAPDialer, now: o.Now,
	}
	if o.Argon2 != nil {
		s.argon = *o.Argon2
	}
	if cfg.LoginRatePerIP > 0 {
		s.ipLimit = NewRateLimiter(cfg.LoginRatePerIP)
	}
	if cfg.LoginRatePerUser > 0 {
		s.userLimit = NewRateLimiter(cfg.LoginRatePerUser)
	}
	return s
}

// Init seeds built-in roles, loads the CSRF key and prepares the dummy hash
// used to equalize login timing for unknown users.
func (s *Service) Init(ctx context.Context) error {
	if err := s.SeedRoles(ctx); err != nil {
		return err
	}
	key, err := s.loadOrCreateKey(ctx, "auth.csrf_key")
	if err != nil {
		return err
	}
	s.csrfKey = key
	s.dummyHash, err = HashPassword(GeneratePassword(), s.argon)
	return err
}

// loadOrCreateKey returns a persistent 32-byte key stored sealed in the
// settings table.
func (s *Service) loadOrCreateKey(ctx context.Context, name string) ([]byte, error) {
	if s.sealer == nil {
		return randBytes(32), nil
	}
	v, err := s.db.GetSetting(ctx, name)
	if err == nil {
		if k, derr := secrets.DecryptString(s.sealer, v, name); derr == nil && len(k) == 32 {
			return []byte(k), nil
		}
		s.log.Warn("regenerating unreadable key", "key", name)
	}
	k := randBytes(32)
	enc, err := secrets.EncryptString(s.sealer, string(k), name)
	if err != nil {
		return nil, err
	}
	return k, s.db.SetSetting(ctx, name, enc)
}

// Background prunes expired sessions, OIDC states and rate-limit buckets
// until ctx ends. Run it with app.Deps.Go.
func (s *Service) Background(ctx context.Context) {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for {
		s.prune(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *Service) prune(ctx context.Context) {
	now := s.ms(s.now())
	if _, err := s.db.ExecContext(ctx, `DELETE FROM auth_sessions WHERE expires_at < ?`, now); err != nil && ctx.Err() == nil {
		s.log.Warn("prune sessions", "err", err)
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM auth_oidc_states WHERE expires_at < ?`, now); err != nil && ctx.Err() == nil {
		s.log.Warn("prune oidc states", "err", err)
	}
	s.ipLimit.Prune()
	s.userLimit.Prune()
}

// RequestMeta carries request attributes for audit events.
type RequestMeta struct {
	IP        string
	UserAgent string
	RequestID string
}

// MetaFrom extracts RequestMeta from r (request ID supplied by the caller).
func MetaFrom(r *http.Request, requestID string) RequestMeta {
	return RequestMeta{IP: ClientIP(r), UserAgent: r.UserAgent(), RequestID: requestID}
}

// ClientIP returns the remote IP of r (no proxy headers are trusted).
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// Actor identifies who performs an administrative action.
type Actor struct {
	ID       string
	Username string
	Meta     RequestMeta
}

// ActorFrom builds an Actor from a principal.
func ActorFrom(p *Principal, m RequestMeta) Actor {
	if p == nil {
		return Actor{Username: "anonymous", Meta: m}
	}
	return Actor{ID: p.ID, Username: p.Username, Meta: m}
}

// SystemActor is used for CLI and bootstrap actions.
var SystemActor = Actor{Username: "system"}

func (s *Service) record(ctx context.Context, a Actor, action, target string, outcome audit.Outcome, reason string, details map[string]any) {
	ev := audit.Event{
		ActorID: a.ID, Actor: a.Username, Action: action, Target: target, Outcome: outcome,
		Reason: reason, SourceIP: a.Meta.IP, UserAgent: a.Meta.UserAgent, RequestID: a.Meta.RequestID,
		Details: details,
	}
	if err := s.audit.Record(context.WithoutCancel(ctx), ev); err != nil {
		s.log.Warn("audit record failed", "action", action, "err", err)
	}
}

func (s *Service) ms(t time.Time) int64 { return t.UTC().UnixMilli() }

func fromMS(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.UnixMilli(v).UTC()
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return b
}

func randToken(n int) string { return base64.RawURLEncoding.EncodeToString(randBytes(n)) }

func newID() string { return hex.EncodeToString(randBytes(16)) }

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
