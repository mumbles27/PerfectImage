-- Core foundation tables. Timestamps are Unix milliseconds (UTC).

CREATE TABLE settings (
    key        TEXT PRIMARY KEY,
    value      TEXT    NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE jobs (
    id          TEXT PRIMARY KEY,
    type        TEXT    NOT NULL,
    status      TEXT    NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'canceled')),
    payload     TEXT    NOT NULL DEFAULT '{}',
    result      TEXT,
    error       TEXT,
    created_by  TEXT    NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL,
    started_at  INTEGER,
    finished_at INTEGER
);

CREATE INDEX jobs_status_created ON jobs (status, created_at);
CREATE INDEX jobs_created ON jobs (created_at DESC);

CREATE TABLE job_logs (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT    NOT NULL REFERENCES jobs (id) ON DELETE CASCADE,
    ts     INTEGER NOT NULL,
    line   TEXT    NOT NULL
);

CREATE INDEX job_logs_job ON job_logs (job_id, id);
