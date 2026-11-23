-- Deployment history (one row per deploy.vm job). Timestamps are Unix ms (UTC).
-- Never store secrets here.

CREATE TABLE deploy_deployments (
    job_id        TEXT PRIMARY KEY,
    cluster       TEXT    NOT NULL,
    node          TEXT    NOT NULL DEFAULT '',
    vmid          INTEGER NOT NULL DEFAULT 0,
    name          TEXT    NOT NULL,
    template      TEXT    NOT NULL DEFAULT '',
    os            TEXT    NOT NULL DEFAULT '',
    apps          TEXT    NOT NULL DEFAULT '[]',
    status        TEXT    NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed')),
    error         TEXT    NOT NULL DEFAULT '',
    ip_addresses  TEXT    NOT NULL DEFAULT '',
    cleaned_up    INTEGER NOT NULL DEFAULT 0,
    requested_by  TEXT    NOT NULL DEFAULT '',
    created_at    INTEGER NOT NULL,
    finished_at   INTEGER
);

CREATE INDEX deploy_deployments_created ON deploy_deployments (created_at DESC);
