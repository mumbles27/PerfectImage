-- Sealed SIEM output credentials (HEC tokens, API keys, passwords, HMAC
-- secrets). value is a secrets.EncryptString token bound to
-- "siem:<output>:<field>". Timestamps are Unix milliseconds (UTC).

CREATE TABLE siem_credentials (
    output     TEXT    NOT NULL,
    field      TEXT    NOT NULL,
    value      TEXT    NOT NULL,
    updated_at INTEGER NOT NULL,
    updated_by TEXT    NOT NULL DEFAULT '',
    PRIMARY KEY (output, field)
);
