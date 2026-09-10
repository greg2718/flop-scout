-- A1-LG2 additions to the unchanged nine-table V2/A1 baseline.
-- Run with foreign_keys=ON. These are contract DDL, not a runtime migration.
CREATE TABLE legacy_generation_reports (
    raw_ref BLOB PRIMARY KEY NOT NULL
        CHECK (typeof(raw_ref) = 'blob' AND length(raw_ref) = 32),
    reported_code INTEGER NOT NULL
        CHECK (typeof(reported_code) = 'integer' AND reported_code IN (0, 1)),
    message_id TEXT GENERATED ALWAYS AS ('sm1:' || lower(hex(raw_ref))) VIRTUAL
) WITHOUT ROWID;

CREATE TABLE legacy_generation_witnesses (
    raw_ref BLOB NOT NULL
        CHECK (typeof(raw_ref) = 'blob' AND length(raw_ref) = 32),
    cache_kind INTEGER NOT NULL
        CHECK (typeof(cache_kind) = 'integer' AND cache_kind IN (1, 2, 3)),
    record_hash BLOB NOT NULL
        CHECK (typeof(record_hash) = 'blob' AND length(record_hash) = 32),
    locator TEXT NOT NULL
        CHECK (typeof(locator) = 'text' AND length(locator) <= 256
            AND (locator = '' OR length(trim(locator)) > 0)),
    PRIMARY KEY (raw_ref, cache_kind, record_hash, locator),
    FOREIGN KEY (raw_ref) REFERENCES legacy_generation_reports(raw_ref)
) WITHOUT ROWID;
