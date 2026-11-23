# Authentication and authorization

The auth module (`internal/auth`, `internal/auth/authplugin`, `internal/rbac`)
provides local accounts, sessions, CSRF protection, TOTP MFA, role-based
access control, API tokens, OIDC single sign-on and LDAP/Active Directory
sign-in.

- `internal/auth` holds the logic: `auth.Service` implements
  `auth.Authenticator`, `auth.Authorizer`, `auth.AdminResetter` and the CSRF
  protector. It does not import `internal/web`.
- `internal/auth/authplugin` is the `app.Plugin`. It holds the web pages,
  templates and the `user reset-admin` command. It is a sub-package because
  `internal/web` imports `internal/auth`.

## First run and admin recovery

On first start, if there are no users, the service creates `admin` with the
`Admin` role and a random one-time password. That password goes to two places:

- once to the console (stderr, which ends up in the systemd journal);
- `<secrets dir>/initial-admin-password.txt` (mode 0600). Use this on Windows,
  where a service has no console. The file is deleted when the admin changes
  the password.

The password never goes to the logger, so it is not in the log files or SIEM
output. The admin must change it at first sign-in.

Lost access? Run this on the server:

```sh
perfectimage user reset-admin [--config path] [--username admin]
```

The command resets (or creates) the local account. It does the following:

- sets a new one-time password, which you must change at sign-in;
- re-enables the account and restores the `Admin` role;
- clears lockout, MFA and recovery codes;
- revokes all of the account's sessions.

The running service does not need a restart.

## Configuration (`auth:` in config.yaml)

| Key | Default | Meaning |
|---|---|---|
| `session_ttl` | `8h` | Idle timeout |
| `session_absolute_ttl` | `24h` | Hard limit per sign-in |
| `password_min_length` | `12` | Minimum length of local passwords (8–128) |
| `lockout_threshold` | `5` | Failed attempts before a lockout (`-1` = off) |
| `lockout_duration` / `lockout_max_duration` | `1m` / `1h` | First lockout; doubles with each further failure up to the max |
| `login_rate_per_ip` / `login_rate_per_user` | `30` / `10` | Sign-in attempts per minute (`-1` = off) |
| `mfa_required_roles` | `[]` | Roles that must enroll TOTP (e.g. `[Admin]`) |
| `api_token_max_ttl` | `8760h` | Longest allowed API token lifetime |
| `dev_allow_all` | `false` | Development only, loopback only. Every request is an admin. Sign-in pages stay available. |

OIDC providers and the LDAP directory are configured in the UI under
**Settings › SSO**, not in this file. Client secrets and bind passwords are
sealed with the master key (`secrets.Sealer`, AES-256-GCM, with
per-purpose AAD).

## Local accounts

- **Hashing.** Passwords are hashed with argon2id: m=19 MiB, t=2, p=1, a
  16-byte salt, stored in PHC format. A hash made with older parameters is
  upgraded on the next successful sign-in.
- **Policy.**
  - Minimum length, and at most 256 bytes.
  - An embedded denylist of common passwords
    (`internal/auth/common_passwords.txt`). Matching ignores case and also
    catches trailing digits or symbols, e.g. `Welcome2024!`.
  - No username inside the password, and no highly repetitive input.
- **Lockout.** After `lockout_threshold` consecutive failures the account is
  locked for `lockout_duration`. Each further failure doubles the lockout, up
  to `lockout_max_duration`. Failed MFA codes count as failures too. An
  administrator can unlock an account from Settings › Users.
- **Rate limiting.** In-memory token buckets limit attempts per client IP and
  per username. No proxy headers are trusted.
- **Enumeration.** Error messages are generic. Unknown users still pay the
  argon2 cost.
- **Created accounts.** Accounts created by an administrator, and admin
  password resets, get a one-time password. That password is shown once, and
  the user must change it at first sign-in. Changing a password signs out
  every other session.

## Sign-in flow and sessions

```
/login ──password ok──► [mfa] ──► [password change] ──► [mfa enrollment] ──► active
        └─ /login/oidc/{p} ─────────────────────────────────────────────────┘
```

**Sessions**

- Sessions live in the database (`auth_sessions`).
- The cookie `pi_session` holds a random 256-bit value. The database stores
  only its SHA-256.
- The cookie is `HttpOnly`, `SameSite=Lax`, and `Secure` whenever TLS is on.
- A session in an intermediate stage (`mfa`, `password`, `mfa_enroll`) is not
  authenticated. It expires after 10 minutes.

**Rotation.** The session ID is rotated:

- at every stage change, so session fixation is impossible;
- after a password change or an MFA change;
- on privilege change. When a user's roles or a role's permissions change, the
  user's sessions are flagged, and the next request gets a new ID.

**Freshness.** Permissions are re-read from the database on every request, so
role changes take effect immediately. Disabling a user revokes their sessions
at once.

**Logout.**

- `POST /logout` ends the current session.
- On `/account`, a user can:
  - sign out a single session,
  - sign out all other sessions,
  - sign out everywhere.

## CSRF

`auth.Service.CSRF()` is installed with `web.Server.SetCSRF`. It works as
follows:

- **Signed-in browsers.** Each session has its own random synchronizer token,
  stored with the session row.
- **Anonymous browsers** (the sign-in forms). A random `pi_pre` cookie binds
  the token: the token is HMAC(key, pre-session value), and the key is sealed
  in the `settings` table.
- **Where the token goes.** The layout puts the token in
  `<meta name="csrf-token">`. `app.js` sends it as the `X-CSRF-Token` header
  on htmx requests, and forms post it as `csrf_token`.
- **Cross-origin requests** are also rejected by `http.CrossOriginProtection`.
- **API tokens.** Requests with `Authorization: Bearer` carry no ambient
  credentials, so they are exempt from the token check.

## MFA (TOTP, RFC 6238)

- **Enrollment** (Account page, or forced by `mfa_required_roles`):
  - shows a QR code, rendered in pure Go (`rsc.io/qr`) as a `data:` PNG,
    together with the manual-entry key;
  - stores the secret sealed;
  - activates it only after the first valid code.
- **Codes.** Codes are SHA-1, 6 digits, 30 s, with ±1 step of skew. Replay is
  blocked: each accepted time step must be newer than the last.
- **Recovery codes.** Ten 80-bit recovery codes are shown once and stored as
  SHA-256 hashes. Each works once. They can be regenerated with a current
  code.
- **Disabling.** MFA can only be disabled with a current code, and not at all
  while a required role is held. Administrators can reset a user's MFA if a
  device is lost.
- **SSO users.** OIDC users skip local MFA; the IdP is responsible for it.
  LDAP users use local TOTP like local users.

## RBAC

- **Tables.**
  - `auth_roles` and `auth_role_permissions` hold roles and their permissions.
  - `auth_user_roles` holds role membership.
- **Built-in roles** come from `rbac.BuiltinRoles` (Admin, Operator, Builder,
  Viewer). They are re-seeded at every start, so new permissions reach
  upgraded installs. They cannot be edited or deleted.
- **Custom roles** are managed at Settings › Roles, which also shows the
  permission matrix.
- **Effective permissions** are the union of a user's roles' permissions.
- **No escalation.** An administrator can only grant, remove or assign
  permissions and roles they hold themselves. The last enabled Admin cannot be
  demoted, disabled or deleted, and nobody can disable or delete their own
  account.
- **Route permissions:**
  - `users.manage`: Settings › Users
  - `roles.manage`: Settings › Roles
  - `settings.manage`: Settings › SSO
  - `/account`: any signed-in user

## API tokens

- **Creation.** Users create personal access tokens on the Account page. A
  token is `pit_` followed by 256 random bits.
- **Display and storage.** The token is shown once and stored as SHA-256.
- **Scope and expiry.** Each token has an expiry (at most
  `api_token_max_ttl`) and a scope. The scope must be a non-empty subset of
  the owner's permissions.
- **Usage.** Send `Authorization: Bearer pit_…`.
- **Effective permissions.** At use time, a token's permissions are its scope
  intersected with the owner's current permissions. Downgrading or disabling
  the owner therefore limits or stops the token.
- **Limits.** Tokens cannot be used for account or administration changes
  (password, MFA, tokens, users, roles, SSO); those need an interactive
  session.

## OIDC single sign-on

Uses `github.com/coreos/go-oidc/v3` and `golang.org/x/oauth2`.

- **Providers.** You can configure several providers, each with a URL slug.
  The login page shows a button for each enabled provider.
- **Redirect URI** to register at the IdP:
  `https://<server.public_url>/login/oidc/<slug>/callback`. Set
  `server.public_url`. Without it, the URI is built from the request's Host
  header.
- **Flow.** Authorization code with PKCE (S256), a random `state` and a random
  `nonce`:
  - The state is stored server-side (hashed) for 10 minutes and is
    single-use.
  - The state is bound to the provider and to the browser through a
    `pi_oidc_state` cookie.
- **ID token checks.** Signature (JWKS), issuer, audience, expiry and nonce.
- **Just-in-time provisioning** (per provider):
  - Unknown subjects get an account with source `oidc:<slug>`, named after
    `preferred_username` or `email`.
  - Accounts are linked by `(provider, sub)`, never by username. An IdP
    therefore cannot take over an existing local account; a name clash gets a
    suffix.
  - If JIT provisioning is off, unknown subjects are refused.
- **Roles.** The groups claim (default `groups`) is mapped to roles with
  `group => Role, Role` lines, plus default roles. Roles are re-synced at
  every sign-in.
- **Test discovery** fetches the discovery document.

## LDAP / Active Directory

Uses `github.com/go-ldap/ldap/v3`.

- **Transport.**
  - `ldaps://`, or `ldap://` with StartTLS. Plain LDAP is refused.
  - Optional pinned CA (PEM) and TLS server name.
  - The configurable timeout applies to dialing and to every operation.
- **Search-then-bind.**
  1. Bind as the service account.
  2. Search `user_base_dn` with `user_filter`. `{username}` is replaced by the
     escaped username, and exactly one entry must match.
  3. Bind as that DN with the user's password. Empty passwords are rejected,
     so an unauthenticated bind is impossible.
  4. Bind as the service account again to read groups.
- **Nested groups.** Resolved by iterative `member`/`uniqueMember` searches up
  to depth 8, with cycle protection. For Active Directory, you can instead use
  a single `LDAP_MATCHING_RULE_IN_CHAIN` query.
- **Role mapping.** Group DNs or CNs (case-insensitive) map to roles, plus
  default roles. Roles are re-synced at every sign-in.
- **Accounts.**
  - LDAP users are provisioned with source `ldap`.
  - Local accounts always sign in with their local password.
  - Lockout and rate limits apply as for local users.
- **Test connection.** Settings › SSO › LDAP *Test connection* binds with the
  service account. Given a test username, it also resolves that user's groups
  and roles; no password is needed.

## Why no SAML

SAML is deliberately not supported. The maintained Go implementation,
`github.com/crewjam/saml`, is affected by Go vulnerability advisory
**GO-2026-6909** (published 2026-11-05). The advisory describes two flaws:

- A signed assertion that has no `<saml:Issuer>` makes the service provider
  panic with a nil-pointer dereference.
- `Subject.NameID` matches a `NameID` element from a foreign XML namespace.
  An authenticated principal can use this to spoof the NameID value.

The advisory covers every version (introduced 0) and no fixed release is
available. SAML's XML-signature
handling has a long history of signature-wrapping and canonicalization bypasses.
OIDC covers the same IdPs (Entra ID, Okta, Keycloak, ADFS, Google). It does
this with a much smaller and better-audited attack surface, and we would
rather not ship an authentication path that `govulncheck` flags. SAML may be
reconsidered once a patched, maintained library exists.

## Audit events

Every security-relevant action emits an `audit.Event` through `Deps.Audit`.
Events never contain passwords, tokens, TOTP secrets or recovery codes.

| Area | Actions |
|---|---|
| Sign-in | `auth.login`, `auth.logout`, `auth.logout_all`, `auth.logout_others`, `auth.session.revoke` |
| MFA | `auth.mfa.enroll`, `auth.mfa.verify`, `auth.mfa.disable`, `auth.mfa.reset`, `auth.mfa.recovery_codes` |
| Users | `user.create`, `user.update`, `user.enable`, `user.disable`, `user.delete`, `user.unlock`, `user.password.change`, `user.password.reset`, `user.provision`, `user.roles.sync`, `user.reset_admin` |
| Roles | `role.create`, `role.update`, `role.delete` |
| API tokens | `auth.token.create`, `auth.token.revoke` |
| SSO | `sso.oidc.save`, `sso.oidc.delete`, `sso.oidc.test`, `sso.ldap.save`, `sso.ldap.test` |

Authorization denials (`authz.deny`) are recorded by the web layer.

Known gap: `perfectimage user reset-admin` runs outside the service, so its
`user.reset_admin` event only reaches the audit log if the ops recorder is
reachable from the CLI. Today it is not, and the command prints to the
console instead.

## Database tables

All tables are created by `internal/auth/migrations`:

- `auth_users`
- `auth_recovery_codes`
- `auth_roles`
- `auth_role_permissions`
- `auth_user_roles`
- `auth_sessions`
- `auth_api_tokens`
- `auth_identities`
- `auth_oidc_providers`
- `auth_oidc_states`
- `auth_ldap_config`
