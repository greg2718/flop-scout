-- Proposed A1-LG2-TL1 addition to the unchanged eleven-table LG2 schema.
-- Contract DDL only; no runtime migration is implemented.
CREATE TABLE legacy_tclk_records (
    raw_ref BLOB PRIMARY KEY NOT NULL
        CHECK (typeof(raw_ref) = 'blob' AND length(raw_ref) = 32),
    claimed_type_code INTEGER NOT NULL
        CHECK (typeof(claimed_type_code) = 'integer' AND claimed_type_code IN (0, 1, 2, 3)),
    nonconformance_mask INTEGER NOT NULL
        CHECK (typeof(nonconformance_mask) = 'integer'
            AND nonconformance_mask > 0 AND nonconformance_mask <= 1023),
    message_id TEXT GENERATED ALWAYS AS ('sm1:' || lower(hex(raw_ref))) VIRTUAL
) WITHOUT ROWID;
