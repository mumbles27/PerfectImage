-- Auth tables. Timestamps are Unix milliseconds (UTC); 0 means "never".

CREATE TABLE auth_users (
    id                   TEXT PRIMARY KEY,
    username             TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    display_name         TEXT    NOT NULL DEFAULT '',
    email                TEXT    NOT NULL DEFAULT '',
    -- local | ldap | oidc:<provider>
    source               TEXT    NOT NULL DEFAULT 'local',
    password_hash        TEXT    NOT NULL DEFAULT '',
    must_change_password INTEGER NOT NULL DEFAULT 0,
    disabled             INTEGER NOT NULL DEFAULT 0,
    failed_logins        INTEGER NOT NULL DEFAULT 0,
    locked_until         INTEGER NOT NULL DEFAULT 0,
    -- sealed with secrets.Sealer (aad "auth_users.totp:<id>")
    totp_secret          TEXT    NOT NULL DEFAULT '',
    totp_enabled         INTEGER NOT NULL DEFAULT 0,
    totp_last_step       INTEGER NOT NULL DEFAULT 0,
    password_changed_at  INTEGER NOT NULL DEFAULT 0,
    last_login_at        INTEGER NOT NULL DEFAULT 0,
    created_at           INTEGER NOT NULL,
    updated_at           INTEGER NOT NULL
);

CREATE TABLE auth_recovery_codes (
    user_id   TEXT    NOT NULL REFERENCES auth_users (id) ON DELETE CASCADE,
    code_hash TEXT    NOT NULL,
    used_at   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (user_id, code_hash)
);

CREATE TABLE auth_roles (
    name        TEXT PRIMARY KEY COLLATE NOCASE,
    description TEXT    NOT NULL DEFAULT '',
    builtin     INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);

CREATE TABLE auth_role_permissions (
    role       TEXT NOT NULL REFERENCES auth_roles (name) ON DELETE CASCADE ON UPDATE CASCADE,
    permission TEXT NOT NULL,
    PRIMARY KEY (role, permission)
);

CREATE TABLE auth_user_roles (
    user_id TEXT NOT NULL REFERENCES auth_users (id) ON DELETE CASCADE,
    role    TEXT NOT NULL REFERENCES auth_roles (name) ON DELETE CASCADE ON UPDATE CASCADE,
    PRIMARY KEY (user_id, role)
);

CREATE INDEX auth_user_roles_role ON auth_user_roles (role);

CREATE TABLE auth_sessions (
    -- hex SHA-256 of the opaque cookie value; the raw value is never stored
    id           TEXT PRIMARY KEY,
    user_id      TEXT    NOT NULL REFERENCES auth_users (id) ON DELETE CASCADE,
    -- active | mfa | password | mfa_enroll
    stage        TEXT    NOT NULL,
    csrf_token   TEXT    NOT NULL,
    auth_method  TEXT    NOT NULL,
    rotate       INTEGER NOT NULL DEFAULT 0,
    ip           TEXT    NOT NULL DEFAULT '',
    user_agent   TEXT    NOT NULL DEFAULT '',
    created_at   INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL
);

CREATE INDEX auth_sessions_user ON auth_sessions (user_id);
CREATE INDEX auth_sessions_expires ON auth_sessions (expires_at);

CREATE TABLE auth_api_tokens (
    id           TEXT PRIMARY KEY,
    user_id      TEXT    NOT NULL REFERENCES auth_users (id) ON DELETE CASCADE,
    name         TEXT    NOT NULL,
    -- hex SHA-256 of the token; the raw token is shown once at creation
    token_hash   TEXT    NOT NULL UNIQUE,
    prefix       TEXT    NOT NULL,
    -- JSON array of rbac permissions (subset of the owner's at creation)
    permissions  TEXT    NOT NULL DEFAULT '[]',
    created_at   INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX auth_api_tokens_user ON auth_api_tokens (user_id);

CREATE TABLE auth_identities (
    provider TEXT NOT NULL,
    subject  TEXT NOT NULL,
    user_id  TEXT NOT NULL REFERENCES auth_users (id) ON DELETE CASCADE,
    PRIMARY KEY (provider, subject)
);

CREATE TABLE auth_oidc_providers (
    name          TEXT PRIMARY KEY COLLATE NOCASE,
    display_name  TEXT    NOT NULL,
    issuer        TEXT    NOT NULL,
    client_id     TEXT    NOT NULL,
    -- sealed (aad "auth_oidc_providers.client_secret:<name>")
    client_secret TEXT    NOT NULL DEFAULT '',
    scopes        TEXT    NOT NULL DEFAULT '[]',
    groups_claim  TEXT    NOT NULL DEFAULT 'groups',
    role_map      TEXT    NOT NULL DEFAULT '{}',
    default_roles TEXT    NOT NULL DEFAULT '[]',
    jit           INTEGER NOT NULL DEFAULT 1,
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    INTEGER NOT NULL,
    updated_at    INTEGER NOT NULL
);

CREATE TABLE auth_oidc_states (
    state_hash TEXT PRIMARY KEY,
    provider   TEXT    NOT NULL,
    nonce      TEXT    NOT NULL,
    verifier   TEXT    NOT NULL,
    next       TEXT    NOT NULL DEFAULT '',
    expires_at INTEGER NOT NULL
);

CREATE TABLE auth_ldap_config (
    id     INTEGER PRIMARY KEY CHECK (id = 1),
    -- JSON-encoded LDAPConfig with BindPassword removed
    config TEXT    NOT NULL,
    -- sealed (aad "auth_ldap_config.bind_password")
    bind_password TEXT NOT NULL DEFAULT '',
    updated_at INTEGER NOT NULL
);
