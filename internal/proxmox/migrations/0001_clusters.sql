-- Proxmox VE cluster connections. Timestamps are Unix milliseconds (UTC).
-- token_secret is sealed with internal/secrets (aad "proxmox:cluster:<name>:token").

CREATE TABLE proxmox_clusters (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    name                 TEXT    NOT NULL UNIQUE,
    endpoint             TEXT    NOT NULL,
    token_id             TEXT    NOT NULL DEFAULT '',
    token_secret         TEXT    NOT NULL DEFAULT '',
    ca_pem               TEXT    NOT NULL DEFAULT '',
    ca_file              TEXT    NOT NULL DEFAULT '',
    fingerprint          TEXT    NOT NULL DEFAULT '',
    insecure_skip_verify INTEGER NOT NULL DEFAULT 0,
    default_node         TEXT    NOT NULL DEFAULT '',
    default_storage      TEXT    NOT NULL DEFAULT '',
    default_bridge       TEXT    NOT NULL DEFAULT '',
    default_pool         TEXT    NOT NULL DEFAULT '',
    source               TEXT    NOT NULL DEFAULT 'ui' CHECK (source IN ('ui', 'config')),
    created_at           INTEGER NOT NULL,
    updated_at           INTEGER NOT NULL
);
