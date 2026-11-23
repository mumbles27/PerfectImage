package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// mockIdP is a minimal OpenID Provider: discovery, JWKS, and a token
// endpoint enforcing client auth, redirect URI and PKCE (S256).
type mockIdP struct {
	srv *httptest.Server
	key *rsa.PrivateKey
	t   *testing.T

	mu    sync.Mutex
	codes map[string]grant
	// claims returned in the next ID token (sub, groups, ...).
	claims map[string]any
	// nonceOverride replaces the nonce (to test nonce mismatch).
	nonceOverride string
	now           func() time.Time
}

type grant struct{ challenge, nonce, redirect string }

func newMockIdP(t *testing.T, now func() time.Time) *mockIdP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m := &mockIdP{key: key, t: t, codes: map[string]grant{}, now: now}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": m.srv.URL, "authorization_endpoint": m.srv.URL + "/authorize",
			"token_endpoint": m.srv.URL + "/token", "jwks_uri": m.srv.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported":              []string{"code"},
		})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
		b64 := base64.RawURLEncoding
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
			"n": b64.EncodeToString(key.N.Bytes()), "e": b64.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("POST /token", m.token)
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

// authorize simulates the user approving at the IdP: it records the PKCE
// challenge and nonce for a new code.
func (m *mockIdP) authorize(authURL string) (code, state string) {
	u, err := url.Parse(authURL)
	if err != nil {
		m.t.Fatal(err)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		m.t.Fatalf("PKCE not requested: %v", q)
	}
	if q.Get("nonce") == "" || q.Get("state") == "" || q.Get("client_id") != "pi-client" {
		m.t.Fatalf("missing nonce/state/client: %v", q)
	}
	code = randToken(8)
	m.mu.Lock()
	m.codes[code] = grant{challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), redirect: q.Get("redirect_uri")}
	m.mu.Unlock()
	return code, q.Get("state")
}

func (m *mockIdP) token(w http.ResponseWriter, r *http.Request) {
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostFormValue("client_id"), r.PostFormValue("client_secret")
	}
	if id != "pi-client" || secret != "fake-client-secret" {
		http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
		return
	}
	m.mu.Lock()
	g, found := m.codes[r.PostFormValue("code")]
	delete(m.codes, r.PostFormValue("code"))
	m.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
	if !found || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge || r.PostFormValue("redirect_uri") != g.redirect {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	now := m.now()
	claims := map[string]any{"iss": m.srv.URL, "aud": "pi-client", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "nonce": g.nonce}
	if m.nonceOverride != "" {
		claims["nonce"] = m.nonceOverride
	}
	for k, v := range m.claims {
		claims[k] = v
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 300, "id_token": m.sign(claims)})
}

func (m *mockIdP) sign(claims map[string]any) string {
	b64 := base64.RawURLEncoding
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	p, _ := json.Marshal(claims)
	in := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	sum := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, m.key, crypto.SHA256, sum[:])
	if err != nil {
		m.t.Fatal(err)
	}
	return in + "." + b64.EncodeToString(sig)
}

func TestOIDCFlow(t *testing.T) {
	f := newFixture(t, nil)
	// go-oidc verifies exp/iat against the real clock; keep the mock IdP on it.
	idp := newMockIdP(t, time.Now)
	ctx := context.Background()
	a := Actor{Username: "admin"}
	prov := OIDCProvider{
		Name: "corp", DisplayName: "Corp SSO", Issuer: idp.srv.URL, ClientID: "pi-client",
		ClientSecret: "fake-client-secret", Scopes: []string{"profile", "email"}, GroupsClaim: "groups",
		RoleMap: map[string][]string{"pi-admins": {"Admin"}, "pi-ops": {"Operator"}}, DefaultRoles: []string{"Viewer"},
		JIT: true, Enabled: true,
	}
	if err := f.svc.SaveOIDCProvider(ctx, a, prov); err != nil {
		t.Fatal(err)
	}
	var sealed string
	_ = f.db.QueryRowContext(ctx, `SELECT client_secret FROM auth_oidc_providers`).Scan(&sealed)
	if strings.Contains(sealed, "fake-client-secret") || sealed == "" {
		t.Fatal("client secret not sealed")
	}
	listed, _ := f.svc.OIDCProviders(ctx, true)
	if len(listed) != 1 || listed[0].ClientSecret != "" || !listed[0].HasSecret {
		t.Fatalf("listed = %+v", listed)
	}
	if err := f.svc.TestOIDC(ctx, a, "corp"); err != nil {
		t.Fatalf("test discovery: %v", err)
	}
	const redirect = "https://pi.example.test/login/oidc/corp/callback"
	meta := RequestMeta{IP: "198.51.100.7"}

	begin := func() (code, state string) {
		authURL, st, err := f.svc.OIDCBegin(ctx, "corp", redirect, "/jobs?x=1")
		if err != nil {
			t.Fatal(err)
		}
		code, state = idp.authorize(authURL)
		if state != st {
			t.Fatal("state mismatch in auth URL")
		}
		return code, state
	}

	// 1. JIT provisioning with group -> role mapping.
	idp.claims = map[string]any{"sub": "u-123", "preferred_username": "olivia", "email": "olivia@example.test",
		"name": "Olivia", "groups": []string{"pi-ops", "unrelated"}}
	code, state := begin()
	au, next, err := f.svc.OIDCComplete(ctx, meta, "corp", redirect, state, code)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if next != "/jobs?x=1" || au.Method != "oidc:corp" || au.User.Username != "olivia" || au.User.Source != "oidc:corp" {
		t.Fatalf("got %+v next=%q", au.User, next)
	}
	if !slices.Equal(au.User.Roles, []string{"Operator", "Viewer"}) {
		t.Fatalf("roles = %v", au.User.Roles)
	}
	if stage, _ := f.svc.nextStage(ctx, au.User, au.Method, false); stage != StageActive {
		t.Fatalf("stage = %s", stage)
	}

	// 2. State is single-use.
	if _, _, err := f.svc.OIDCComplete(ctx, meta, "corp", redirect, state, code); !errors.Is(err, ErrOIDCState) {
		t.Fatalf("replayed state: %v", err)
	}

	// 3. Re-login syncs roles (now admin) and keeps the same account.
	idp.claims["groups"] = []string{"pi-admins"}
	code, state = begin()
	au2, _, err := f.svc.OIDCComplete(ctx, meta, "corp", redirect, state, code)
	if err != nil || au2.User.ID != au.User.ID || !slices.Equal(au2.User.Roles, []string{"Admin", "Viewer"}) {
		t.Fatalf("relogin: %+v, %v", au2, err)
	}

	// 4. Nonce mismatch is rejected.
	idp.nonceOverride = "evil"
	code, state = begin()
	if _, _, err := f.svc.OIDCComplete(ctx, meta, "corp", redirect, state, code); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("nonce mismatch accepted: %v", err)
	}
	idp.nonceOverride = ""

	// 5. State bound to the provider it was issued for.
	_ = f.svc.SaveOIDCProvider(ctx, a, OIDCProvider{Name: "other", Issuer: idp.srv.URL, ClientID: "pi-client", Enabled: true})
	code, state = begin()
	if _, _, err := f.svc.OIDCComplete(ctx, meta, "other", redirect, state, code); !errors.Is(err, ErrOIDCState) {
		t.Fatalf("cross-provider state: %v", err)
	}

	// 6. State expiry.
	code, state = begin()
	f.clock.Add(11 * time.Minute)
	if _, _, err := f.svc.OIDCComplete(ctx, meta, "corp", redirect, state, code); !errors.Is(err, ErrOIDCState) {
		t.Fatalf("expired state: %v", err)
	}

	// 7. Local account with the same username is never taken over.
	f.mustUser(t, "mallory", "Lantern-Purple-42", "Admin")
	idp.claims = map[string]any{"sub": "u-999", "preferred_username": "mallory", "groups": []string{}}
	code, state = begin()
	au3, _, err := f.svc.OIDCComplete(ctx, meta, "corp", redirect, state, code)
	if err != nil || au3.User.Username == "mallory" || !slices.Equal(au3.User.Roles, []string{"Viewer"}) {
		t.Fatalf("takeover: %+v, %v", au3.User, err)
	}

	// 8. JIT disabled: unknown subjects are refused.
	prov.JIT, prov.ClientSecret = false, ""
	if err := f.svc.SaveOIDCProvider(ctx, a, prov); err != nil {
		t.Fatal(err)
	}
	idp.claims = map[string]any{"sub": "u-new"}
	code, state = begin() // also proves the stored secret was kept
	if _, _, err := f.svc.OIDCComplete(ctx, meta, "corp", redirect, state, code); !errors.Is(err, ErrNotProvisioned) {
		t.Fatalf("jit disabled: %v", err)
	}

	// 9. Disabled provider cannot start a flow.
	prov.Enabled = false
	_ = f.svc.SaveOIDCProvider(ctx, a, prov)
	if _, _, err := f.svc.OIDCBegin(ctx, "corp", redirect, "/"); !errors.Is(err, ErrProviderNotFound) {
		t.Fatalf("disabled provider: %v", err)
	}
}

func TestSaveOIDCProviderValidation(t *testing.T) {
	f := newFixture(t, nil)
	tests := []struct {
		name string
		p    OIDCProvider
	}{
		{"bad slug", OIDCProvider{Name: "Bad Name", Issuer: "https://idp", ClientID: "c"}},
		{"http issuer", OIDCProvider{Name: "x", Issuer: "http://idp.example.com", ClientID: "c"}},
		{"no client", OIDCProvider{Name: "x", Issuer: "https://idp.example.com"}},
		{"unknown role", OIDCProvider{Name: "x", Issuer: "https://idp.example.com", ClientID: "c", DefaultRoles: []string{"Ghost"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := f.svc.SaveOIDCProvider(context.Background(), SystemActor, tt.p); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestSafeNext(t *testing.T) {
	tests := map[string]string{
		"":                     "/",
		"/jobs?x=1":            "/jobs?x=1",
		"//evil.example":       "/",
		"/\\evil.example":      "/",
		"https://evil.example": "/",
		"jobs":                 "/",
		"/login?next=/x":       "/",
		"/ok\r\nSet-Cookie:x":  "/",
	}
	for in, want := range tests {
		if got := SafeNext(in); got != want {
			t.Errorf("SafeNext(%q) = %q, want %q", in, got, want)
		}
	}
}
