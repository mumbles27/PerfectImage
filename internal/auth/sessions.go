package auth

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/mumbles27/PerfectImage/internal/audit"
)

// Session stages. A session is only an authenticated identity in
// StageActive; the other stages are steps of an in-progress sign-in.
const (
	StageActive    = "active"
	StageMFA       = "mfa"        // password ok, TOTP code required
	StagePassword  = "password"   // forced password change
	StageMFAEnroll = "mfa_enroll" // role requires MFA, user has none yet
)

// pendingTTL bounds how long a partially completed sign-in may last.
const pendingTTL = 10 * time.Minute

// touchInterval throttles last_seen_at updates.
const touchInterval = time.Minute

// Cookie names.
const (
	SessionCookie    = "pi_session"
	preSessionCookie = "pi_pre"
)

// Session is a server-side session. ID is the SHA-256 of the cookie value.
type Session struct {
	ID         string
	UserID     string
	Stage      string
	CSRFToken  string
	AuthMethod string
	Rotate     bool
	IP         string
	UserAgent  string
	CreatedAt  time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time

	token string // raw cookie value; only set when freshly issued
}

// ErrNoSession means there is no valid session for the request.
var ErrNoSession = errors.New("auth: no session")

// Sessions lists a user's sessions, newest first.
func (s *Service) Sessions(ctx context.Context, userID string) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, user_id, stage, csrf_token, auth_method, rotate, ip, user_agent,
		created_at, last_seen_at, expires_at FROM auth_sessions WHERE user_id = ? AND stage = ? ORDER BY last_seen_at DESC`,
		userID, StageActive)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		ss, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		if s.sessionValid(ss) {
			out = append(out, *ss)
		}
	}
	return out, rows.Err()
}

func scanSession(sc scanner) (*Session, error) {
	var ss Session
	var c, l, e int64
	err := sc.Scan(&ss.ID, &ss.UserID, &ss.Stage, &ss.CSRFToken, &ss.AuthMethod, &ss.Rotate, &ss.IP,
		&ss.UserAgent, &c, &l, &e)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoSession
	}
	if err != nil {
		return nil, err
	}
	ss.CreatedAt, ss.LastSeenAt, ss.ExpiresAt = fromMS(c), fromMS(l), fromMS(e)
	return &ss, nil
}

func (s *Service) sessionValid(ss *Session) bool {
	now := s.now()
	if !now.Before(ss.ExpiresAt) {
		return false
	}
	if ss.Stage == StageActive && !now.Before(ss.LastSeenAt.Add(s.cfg.SessionTTL)) {
		return false
	}
	return true
}

// createSession issues a new session for userID in stage.
func (s *Service) createSession(ctx context.Context, userID, stage, method string, meta RequestMeta) (*Session, error) {
	now := s.now()
	ss := &Session{
		token: randToken(32), UserID: userID, Stage: stage, CSRFToken: randToken(32), AuthMethod: method,
		IP: meta.IP, UserAgent: truncate(meta.UserAgent, 256), CreatedAt: now, LastSeenAt: now,
	}
	ss.ID = sha256Hex(ss.token)
	ss.ExpiresAt = s.expiry(ss)
	_, err := s.db.ExecContext(ctx, `INSERT INTO auth_sessions (id, user_id, stage, csrf_token, auth_method, ip, user_agent,
		created_at, last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ss.ID, ss.UserID, ss.Stage, ss.CSRFToken, ss.AuthMethod, ss.IP, ss.UserAgent,
		s.ms(ss.CreatedAt), s.ms(ss.LastSeenAt), s.ms(ss.ExpiresAt))
	if err != nil {
		return nil, err
	}
	return ss, nil
}

func (s *Service) expiry(ss *Session) time.Time {
	if ss.Stage != StageActive {
		return s.now().Add(pendingTTL)
	}
	return ss.CreatedAt.Add(s.cfg.SessionAbsoluteTTL)
}

// rotateSession replaces ss with a fresh ID and CSRF token (and optionally a
// new stage), deleting the old row atomically. Entering StageActive resets
// the absolute lifetime.
func (s *Service) rotateSession(ctx context.Context, ss *Session, stage string) (*Session, error) {
	now := s.now()
	n := *ss
	n.token = randToken(32)
	n.ID = sha256Hex(n.token)
	n.CSRFToken = randToken(32)
	n.Rotate = false
	n.LastSeenAt = now
	if stage != ss.Stage && stage == StageActive {
		n.CreatedAt = now
	}
	n.Stage = stage
	n.ExpiresAt = s.expiry(&n)
	err := s.db.Tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, `DELETE FROM auth_sessions WHERE id = ?`, ss.ID)
		if err != nil {
			return err
		}
		if k, _ := res.RowsAffected(); k == 0 {
			return ErrNoSession // concurrently rotated or revoked
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO auth_sessions (id, user_id, stage, csrf_token, auth_method, ip, user_agent,
			created_at, last_seen_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			n.ID, n.UserID, n.Stage, n.CSRFToken, n.AuthMethod, n.IP, n.UserAgent,
			s.ms(n.CreatedAt), s.ms(n.LastSeenAt), s.ms(n.ExpiresAt))
		return err
	})
	if err != nil {
		return nil, err
	}
	return &n, nil
}

// lookupSession resolves a raw cookie value.
func (s *Service) lookupSession(ctx context.Context, token string) (*Session, error) {
	if token == "" || len(token) > 128 {
		return nil, ErrNoSession
	}
	ss, err := scanSession(s.db.QueryRowContext(ctx, `SELECT id, user_id, stage, csrf_token, auth_method, rotate, ip, user_agent,
		created_at, last_seen_at, expires_at FROM auth_sessions WHERE id = ?`, sha256Hex(token)))
	if err != nil {
		return nil, err
	}
	if !s.sessionValid(ss) {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM auth_sessions WHERE id = ?`, ss.ID)
		return nil, ErrNoSession
	}
	ss.token = token
	if ss.Stage == StageActive && s.now().Sub(ss.LastSeenAt) >= touchInterval {
		ss.LastSeenAt = s.now()
		if _, err := s.db.ExecContext(ctx, `UPDATE auth_sessions SET last_seen_at = ? WHERE id = ?`,
			s.ms(ss.LastSeenAt), ss.ID); err != nil {
			s.log.Warn("touch session", "err", err)
		}
	}
	return ss, nil
}

// RevokeSession deletes one of userID's sessions.
func (s *Service) RevokeSession(ctx context.Context, a Actor, userID, sessionID string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM auth_sessions WHERE id = ? AND user_id = ?`, sessionID, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNoSession
	}
	s.record(ctx, a, "auth.session.revoke", "user:"+a.Username, audit.OutcomeSuccess, "", nil)
	return nil
}

// RevokeAllSessions deletes all of userID's sessions except keep ("" for
// none). Returns how many were removed.
func (s *Service) RevokeAllSessions(ctx context.Context, a Actor, userID, keep string) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM auth_sessions WHERE user_id = ? AND id <> ?`, userID, keep)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	action := "auth.logout_all"
	if keep != "" {
		action = "auth.logout_others"
	}
	s.record(ctx, a, action, "user:"+a.Username, audit.OutcomeSuccess, "", map[string]any{"sessions": n})
	return n, nil
}

// ---------------------------------------------------------------------------
// Request state: the CSRF middleware resolves the session once per request
// and shares it with the authenticator and handlers via the context.

type reqState struct {
	sess *Session
	pre  string // anonymous pre-session binding value
	// issued is set when this request changed the session cookie.
	issued bool
}

type stateKey struct{}

func stateFrom(ctx context.Context) *reqState {
	st, _ := ctx.Value(stateKey{}).(*reqState)
	return st
}

// CurrentSession returns the session (in any stage) resolved for r, or nil.
func CurrentSession(r *http.Request) *Session {
	if st := stateFrom(r.Context()); st != nil {
		return st.sess
	}
	return nil
}

func (s *Service) setSessionCookie(w http.ResponseWriter, ss *Session) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: ss.token, Path: "/", HttpOnly: true, Secure: s.secure,
		SameSite: http.SameSiteLaxMode, Expires: ss.ExpiresAt,
	})
}

func (s *Service) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: s.secure,
		SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
}

// StartSession creates a session for a first-factor-authenticated user, in
// the stage required by their MFA/password state, sets the cookie (always a
// fresh ID: session fixation is impossible) and drops any previous session
// of this browser. It returns the resulting stage.
func (s *Service) StartSession(ctx context.Context, w http.ResponseWriter, r *http.Request, au *Authenticated, meta RequestMeta) (string, error) {
	stage, err := s.nextStage(ctx, au.User, au.Method, false)
	if err != nil {
		return "", err
	}
	if st := stateFrom(r.Context()); st != nil && st.sess != nil {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM auth_sessions WHERE id = ?`, st.sess.ID)
	}
	ss, err := s.createSession(ctx, au.User.ID, stage, au.Method, meta)
	if err != nil {
		return "", err
	}
	s.setSessionCookie(w, ss)
	if st := stateFrom(r.Context()); st != nil {
		st.sess, st.issued = ss, true
	}
	return stage, nil
}

// Advance moves the request's pending session to the next stage after the
// current step was completed (mfaDone: a second factor was verified),
// rotating the session ID. It returns the new stage.
func (s *Service) Advance(ctx context.Context, w http.ResponseWriter, r *http.Request, mfaDone bool) (string, error) {
	st := stateFrom(r.Context())
	if st == nil || st.sess == nil {
		return "", ErrNoSession
	}
	u, err := s.UserByID(ctx, st.sess.UserID)
	if err != nil {
		return "", err
	}
	if u.Disabled {
		return "", ErrAccountDisabled
	}
	stage, err := s.nextStage(ctx, u, st.sess.AuthMethod, mfaDone || st.sess.Stage != StageMFA)
	if err != nil {
		return "", err
	}
	ss, err := s.rotateSession(ctx, st.sess, stage)
	if err != nil {
		return "", err
	}
	s.setSessionCookie(w, ss)
	st.sess, st.issued = ss, true
	return stage, nil
}

// RotateCurrent issues a new ID for the request's session (privilege
// change, password or MFA change).
func (s *Service) RotateCurrent(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	st := stateFrom(r.Context())
	if st == nil || st.sess == nil {
		return ErrNoSession
	}
	ss, err := s.rotateSession(ctx, st.sess, st.sess.Stage)
	if err != nil {
		return err
	}
	s.setSessionCookie(w, ss)
	st.sess, st.issued = ss, true
	return nil
}

// Logout deletes the request's session and clears the cookie.
func (s *Service) Logout(ctx context.Context, w http.ResponseWriter, r *http.Request, meta RequestMeta) {
	st := stateFrom(r.Context())
	s.clearSessionCookie(w)
	if st == nil || st.sess == nil {
		return
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM auth_sessions WHERE id = ?`, st.sess.ID)
	a := Actor{ID: st.sess.UserID, Meta: meta}
	if u, err := s.UserByID(ctx, st.sess.UserID); err == nil {
		a.Username = u.Username
	}
	s.record(ctx, a, "auth.logout", "user:"+a.Username, audit.OutcomeSuccess, "", nil)
	st.sess = nil
}

// nextStage decides the sign-in stage after first-factor authentication.
func (s *Service) nextStage(ctx context.Context, u *User, method string, mfaDone bool) (string, error) {
	external := strings.HasPrefix(method, "oidc")
	if !external && u.TOTPEnabled && !mfaDone {
		return StageMFA, nil
	}
	if u.IsLocal() && u.MustChangePassword {
		return StagePassword, nil
	}
	if !external && !u.TOTPEnabled {
		req, err := s.MFARequired(ctx, u)
		if err != nil {
			return "", err
		}
		if req {
			return StageMFAEnroll, nil
		}
	}
	return StageActive, nil
}

// MFARequired reports whether u holds a role listed in mfa_required_roles.
func (s *Service) MFARequired(ctx context.Context, u *User) (bool, error) {
	if len(s.cfg.MFARequiredRoles) == 0 {
		return false, nil
	}
	roles := u.Roles
	if roles == nil {
		var err error
		if roles, err = s.userRoles(ctx, u.ID); err != nil {
			return false, err
		}
	}
	for _, r := range roles {
		if slices.ContainsFunc(s.cfg.MFARequiredRoles, func(x string) bool { return strings.EqualFold(x, r) }) {
			return true, nil
		}
	}
	return false, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
