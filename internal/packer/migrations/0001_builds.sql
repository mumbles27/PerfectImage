-- Packer build history. Timestamps are Unix milliseconds (UTC).
-- build_password holds the per-build guest password sealed with the
-- service master key (secrets.EncryptString, AAD "packer_build:<id>").

CREATE TABLE packer_builds (
    id             TEXT PRIMARY KEY,
    job_id         TEXT    NOT NULL DEFAULT '',
    image_id       TEXT    NOT NULL,
    image_name     TEXT    NOT NULL DEFAULT '',
    os_family      TEXT    NOT NULL DEFAULT '',
    cluster        TEXT    NOT NULL,
    node           TEXT    NOT NULL,
    template_name  TEXT    NOT NULL,
    vm_id          INTEGER NOT NULL DEFAULT 0,
    request        TEXT    NOT NULL DEFAULT '{}',
    apps           TEXT    NOT NULL DEFAULT '[]',
    status         TEXT    NOT NULL CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'canceled')),
    artifact_id    TEXT    NOT NULL DEFAULT '',
    error          TEXT    NOT NULL DEFAULT '',
    build_password TEXT    NOT NULL DEFAULT '',
    workdir        TEXT    NOT NULL DEFAULT '',
    created_by     TEXT    NOT NULL DEFAULT '',
    created_at     INTEGER NOT NULL,
    started_at     INTEGER,
    finished_at    INTEGER
);

CREATE INDEX packer_builds_created ON packer_builds (created_at DESC);
CREATE INDEX packer_builds_job ON packer_builds (job_id);
