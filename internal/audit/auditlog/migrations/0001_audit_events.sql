-- Append-only, hash-chained audit log. Timestamps are Unix milliseconds (UTC).
--
-- Every row stores the hash of its predecessor (prev_hash) and its own hash,
-- SHA-256 over prev_hash and the canonical JSON of the event. Rows can never
-- be updated. Rows can only be deleted by the retention job, which first moves
-- the chain anchor (audit_chain) past them so verification starts from the
-- last pruned hash.

CREATE TABLE audit_events (
    seq        INTEGER PRIMARY KEY AUTOINCREMENT,
    id         TEXT    NOT NULL UNIQUE,
    ts         INTEGER NOT NULL,
    actor_id   TEXT    NOT NULL DEFAULT '',
    actor      TEXT    NOT NULL DEFAULT '',
    action     TEXT    NOT NULL,
    target     TEXT    NOT NULL DEFAULT '',
    outcome    TEXT    NOT NULL,
    reason     TEXT    NOT NULL DEFAULT '',
    source_ip  TEXT    NOT NULL DEFAULT '',
    user_agent TEXT    NOT NULL DEFAULT '',
    request_id TEXT    NOT NULL DEFAULT '',
    details    TEXT    NOT NULL DEFAULT '{}',
    prev_hash  TEXT    NOT NULL,
    hash       TEXT    NOT NULL
);

CREATE INDEX audit_events_ts ON audit_events (ts);
CREATE INDEX audit_events_actor ON audit_events (actor, ts);
CREATE INDEX audit_events_action ON audit_events (action, ts);

CREATE TABLE audit_chain (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    anchor_seq   INTEGER NOT NULL DEFAULT 0,
    anchor_hash  TEXT    NOT NULL DEFAULT '0000000000000000000000000000000000000000000000000000000000000000',
    pruned_total INTEGER NOT NULL DEFAULT 0,
    updated_at   INTEGER NOT NULL DEFAULT 0
);

INSERT INTO audit_chain (id) VALUES (1);

CREATE TRIGGER audit_events_no_update BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

CREATE TRIGGER audit_events_no_delete BEFORE DELETE ON audit_events
WHEN OLD.seq > (SELECT anchor_seq FROM audit_chain WHERE id = 1)
BEGIN
    SELECT RAISE(ABORT, 'audit_events is append-only');
END;

CREATE TRIGGER audit_chain_forward_only BEFORE UPDATE ON audit_chain
WHEN NEW.anchor_seq < OLD.anchor_seq
BEGIN
    SELECT RAISE(ABORT, 'audit chain anchor cannot move backwards');
END;
