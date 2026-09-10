-- Frozen Router V2 revision A1; user_version=2.
PRAGMA user_version = 2;
CREATE TABLE snapshot_meta (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    schema TEXT NOT NULL CHECK (schema = 'scout-router-projection/v2'),
    database_content_id TEXT NOT NULL,
    content_created_at TEXT NOT NULL,
    selection_policy_sha256 TEXT NOT NULL
);
CREATE TABLE messages (
    projection_row_id TEXT PRIMARY KEY NOT NULL,
    room TEXT NOT NULL,
    generation TEXT NOT NULL,
    seq INTEGER NOT NULL CHECK (seq >= 0),
    timestamp TEXT,
    sender TEXT NOT NULL,
    signed INTEGER NOT NULL CHECK (signed IN (0, 1)),
    text TEXT NOT NULL,
    normalized_text TEXT,
    template_normalized_hash TEXT,
    nonce TEXT,
    sig TEXT,
    message_hash TEXT,
    verification_status TEXT,
    source_export_hash TEXT,
    source_export_path TEXT,
    evidence_id TEXT
);
CREATE TABLE interactions (
    projection_row_id TEXT PRIMARY KEY NOT NULL,
    source_did TEXT NOT NULL,
    target_did TEXT NOT NULL,
    relationship_type TEXT NOT NULL,
    confidence REAL NOT NULL
);
CREATE TABLE source_provenance (
    entity_type TEXT NOT NULL CHECK (entity_type IN ('message', 'interaction')),
    projection_row_id TEXT NOT NULL,
    source_namespace TEXT NOT NULL,
    source_record_locator TEXT NOT NULL,
    scout_event_id TEXT,
    raw_record_id TEXT,
    raw_record_sha256 TEXT,
    annotations_json TEXT NOT NULL,
    PRIMARY KEY (entity_type, projection_row_id)
);
CREATE TABLE watermarks (
    room TEXT NOT NULL,
    generation TEXT NOT NULL,
    record_count INTEGER NOT NULL CHECK (record_count > 0),
    min_seq INTEGER NOT NULL CHECK (min_seq >= 0),
    max_seq INTEGER NOT NULL CHECK (max_seq >= min_seq),
    PRIMARY KEY (room, generation)
);
CREATE INDEX messages_coverage ON messages(room, generation, seq);
CREATE TABLE selection_membership (
    entity_type TEXT NOT NULL CHECK (entity_type IN ('message', 'interaction')),
    projection_row_id TEXT NOT NULL,
    retention_class TEXT NOT NULL,
    first_observed_at TEXT NOT NULL,
    retain_until TEXT,
    pin_roots_json TEXT NOT NULL,
    PRIMARY KEY (entity_type, projection_row_id)
);
CREATE TABLE coverage_history (
    room TEXT NOT NULL,
    generation TEXT NOT NULL,
    max_ever_projected_seq INTEGER NOT NULL CHECK (max_ever_projected_seq >= 0),
    witness_source_locator TEXT NOT NULL,
    witness_record_sha256 TEXT NOT NULL,
    PRIMARY KEY (room, generation)
);

CREATE TABLE durable_qualifications (
    qualification_id TEXT PRIMARY KEY NOT NULL,
    record_json TEXT NOT NULL
);
CREATE TABLE qualification_events (
    event_id TEXT PRIMARY KEY NOT NULL,
    qualification_id TEXT NOT NULL REFERENCES durable_qualifications(qualification_id),
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    event_json TEXT NOT NULL,
    UNIQUE (qualification_id, sequence)
);
