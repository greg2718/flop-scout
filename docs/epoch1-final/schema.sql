CREATE TABLE messages (
            room TEXT NOT NULL,
            seq INTEGER NOT NULL,
            timestamp TEXT,
            sender TEXT NOT NULL,
            signed INTEGER NOT NULL,
            text TEXT NOT NULL,
            normalized_text TEXT NOT NULL,
            normalized_hash TEXT NOT NULL,
            discovered_at TEXT NOT NULL, template_normalized_text TEXT NOT NULL DEFAULT '', template_normalized_hash TEXT NOT NULL DEFAULT '',
            PRIMARY KEY (room, seq)
        );
CREATE INDEX idx_messages_sender ON messages(sender);
CREATE INDEX idx_messages_hash ON messages(normalized_hash);
CREATE TABLE rooms (
            room TEXT PRIMARY KEY,
            first_observed_at TEXT NOT NULL,
            last_observed_at TEXT NOT NULL,
            last_seq INTEGER
        );
CREATE TABLE interactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_did TEXT NOT NULL,
            target_did TEXT NOT NULL,
            room TEXT NOT NULL,
            source_seq INTEGER NOT NULL,
            response_seq INTEGER NOT NULL,
            source_timestamp TEXT,
            response_timestamp TEXT,
            relationship_type TEXT NOT NULL,
            confidence REAL NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE (room, source_seq, response_seq, relationship_type)
        );
CREATE TABLE sqlite_sequence(name,seq);
CREATE TABLE opportunities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room TEXT NOT NULL,
            seq INTEGER NOT NULL,
            sender TEXT NOT NULL,
            message_text TEXT NOT NULL,
            category TEXT NOT NULL,
            reason TEXT NOT NULL,
            confidence REAL NOT NULL,
            status TEXT NOT NULL DEFAULT 'new'
                CHECK (status IN ('new', 'reviewed', 'ignored', 'acted')),
            created_at TEXT NOT NULL, tier TEXT NOT NULL DEFAULT 'LOW', signed_status TEXT NOT NULL DEFAULT 'UNSIGNED', request_signal TEXT NOT NULL DEFAULT 'NO', normalized_duplicate_count INTEGER NOT NULL DEFAULT 1, distinct_dids_using_template INTEGER NOT NULL DEFAULT 1, originality_classification TEXT NOT NULL DEFAULT 'UNIQUE', capability_match TEXT NOT NULL DEFAULT 'LOW', noise_flags TEXT NOT NULL DEFAULT 'NONE', exact_distinct_dids INTEGER NOT NULL DEFAULT 1, actionability TEXT NOT NULL DEFAULT 'NO', unresolved_problem TEXT NOT NULL DEFAULT 'NO', request_strength TEXT NOT NULL DEFAULT 'NONE', template_message_count INTEGER NOT NULL DEFAULT 1, template_distinct_dids INTEGER NOT NULL DEFAULT 1, template_originality_classification TEXT NOT NULL DEFAULT 'UNIQUE', rejection_reasons TEXT NOT NULL DEFAULT '',
            UNIQUE (room, seq)
        );
CREATE TABLE local_signed_activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT NOT NULL,
            source_key TEXT NOT NULL UNIQUE,
            did TEXT NOT NULL,
            room TEXT NOT NULL,
            seq INTEGER,
            nonce INTEGER,
            text TEXT NOT NULL,
            normalized_text TEXT NOT NULL,
            normalized_hash TEXT NOT NULL,
            created_at TEXT,
            imported_at TEXT NOT NULL
        , template_normalized_text TEXT NOT NULL DEFAULT '', template_normalized_hash TEXT NOT NULL DEFAULT '');
CREATE INDEX idx_messages_template_hash ON messages(template_normalized_hash);
CREATE TABLE service_state (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
CREATE TABLE validation_watches (
            validation_id TEXT PRIMARY KEY,
            target_did TEXT NOT NULL,
            outbound_room TEXT NOT NULL,
            outbound_seq INTEGER NOT NULL,
            outbound_timestamp TEXT,
            preferred_response_room TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'watching',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
CREATE TABLE validation_response_candidates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            validation_id TEXT NOT NULL,
            response_type TEXT NOT NULL,
            room TEXT NOT NULL,
            seq INTEGER NOT NULL,
            timestamp TEXT,
            sender TEXT NOT NULL,
            validation_id_present INTEGER NOT NULL,
            message_hash TEXT NOT NULL,
            bounded_text TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE (validation_id, room, seq)
        );
CREATE INDEX idx_validation_responses_validation ON validation_response_candidates(validation_id);
CREATE TABLE evidence_records (
            evidence_id TEXT PRIMARY KEY,
            room TEXT NOT NULL,
            generation TEXT NOT NULL,
            seq INTEGER NOT NULL,
            server_timestamp TEXT,
            did TEXT,
            nonce INTEGER,
            sig TEXT,
            text TEXT NOT NULL,
            message_hash TEXT NOT NULL,
            canonical_payload_hash TEXT,
            retrieved_at TEXT NOT NULL,
            source TEXT NOT NULL,
            verification_status TEXT NOT NULL,
            raw_record_json TEXT NOT NULL,
            UNIQUE (room, generation, seq, evidence_id)
        );
CREATE INDEX idx_evidence_records_room_generation_seq ON evidence_records(room, generation, seq);
CREATE TABLE tclk_frames (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room TEXT NOT NULL,
            generation TEXT NOT NULL,
            seq INTEGER NOT NULL,
            transport_did TEXT,
            transport_verification_status TEXT NOT NULL,
            transport_binding_status TEXT NOT NULL,
            frame_hash TEXT NOT NULL,
            frame_type TEXT,
            frame_from TEXT,
            offer_id TEXT,
            contract_id TEXT,
            ref TEXT,
            job_proto TEXT,
            job_id TEXT,
            job_context_json TEXT,
            role TEXT,
            lock_kind TEXT,
            asset TEXT,
            amount TEXT,
            rails_json TEXT,
            expires_ms INTEGER,
            claim_by_ms INTEGER,
            refund_after_ms INTEGER,
            observed_at TEXT NOT NULL,
            parse_status TEXT NOT NULL,
            raw_text TEXT NOT NULL,
            parse_error TEXT,
            UNIQUE (room, generation, seq)
        );
CREATE TABLE tclk_capability_hints (
            did TEXT NOT NULL,
            rail TEXT NOT NULL,
            source TEXT NOT NULL,
            observed_at TEXT NOT NULL,
            verification_status TEXT NOT NULL DEFAULT 'UNVERIFIED_HINT',
            PRIMARY KEY (did, rail, source)
        );
CREATE INDEX idx_tclk_frames_type ON tclk_frames(frame_type, parse_status);
CREATE INDEX idx_tclk_frames_transport ON tclk_frames(transport_did, transport_binding_status);
CREATE TABLE kibble_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            room TEXT NOT NULL,
            generation TEXT NOT NULL,
            seq INTEGER NOT NULL,
            server_timestamp TEXT,
            sender_did TEXT,
            nonce INTEGER,
            signature TEXT,
            signature_verification TEXT NOT NULL,
            exact_text TEXT NOT NULL,
            message_hash TEXT NOT NULL,
            event_type TEXT,
            event_version TEXT,
            job_id TEXT,
            observed_at TEXT NOT NULL,
            parse_status TEXT NOT NULL,
            parse_error TEXT,
            payload_json TEXT,
            source_class TEXT NOT NULL DEFAULT 'SOURCE_TRANSCRIPT',
            UNIQUE (room, generation, seq)
        );
CREATE TABLE kibble_jobs (
            source TEXT NOT NULL,
            job_id TEXT PRIMARY KEY,
            category TEXT,
            title TEXT,
            requirements TEXT,
            poster_did TEXT,
            worker_did TEXT,
            status TEXT NOT NULL,
            observed_seq INTEGER,
            signature_verified INTEGER NOT NULL DEFAULT 0,
            settlement_rail TEXT,
            settlement_value_backed INTEGER NOT NULL DEFAULT 0,
            updated_at TEXT NOT NULL
        );
CREATE TABLE kibble_reconciliation (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            checked_at TEXT NOT NULL,
            matched_jobs INTEGER NOT NULL,
            board_only_jobs INTEGER NOT NULL,
            room_only_jobs INTEGER NOT NULL,
            status_mismatches INTEGER NOT NULL,
            worker_mismatches INTEGER NOT NULL,
            result_hash_mismatches INTEGER NOT NULL,
            attestation_count_differences INTEGER NOT NULL,
            board_status TEXT NOT NULL,
            details_json TEXT NOT NULL
        );
CREATE INDEX idx_kibble_events_job ON kibble_events(job_id, event_type);
CREATE TABLE evidence_schema(version INTEGER PRIMARY KEY, migrated_at TEXT NOT NULL);
CREATE TABLE raw_network_records(
 raw_record_id TEXT PRIMARY KEY, source TEXT NOT NULL, source_endpoint TEXT,
 room TEXT NOT NULL, generation TEXT, reported_generation TEXT, seq INTEGER,
 network_timestamp TEXT, retrieved_at TEXT NOT NULL, nonce TEXT,
 sender_did TEXT, signature TEXT, raw_text TEXT, raw_text_sha256 TEXT NOT NULL,
 raw_record_json TEXT NOT NULL, signature_status TEXT NOT NULL, signature_error TEXT,
 did_mismatch INTEGER NOT NULL, transport_metadata_json TEXT NOT NULL,
 ingestion_schema TEXT NOT NULL, ingestion_version TEXT NOT NULL, created_at TEXT NOT NULL,
 legacy_record INTEGER NOT NULL, raw_completeness TEXT NOT NULL,
 UNIQUE(raw_record_id,raw_text_sha256));
CREATE INDEX raw_position ON raw_network_records(source,room,generation,seq);
CREATE INDEX raw_room_sequence ON raw_network_records(room,seq);
CREATE INDEX raw_hash ON raw_network_records(raw_text_sha256);
CREATE INDEX raw_time ON raw_network_records(retrieved_at);
CREATE INDEX raw_did ON raw_network_records(sender_did,retrieved_at);
CREATE TRIGGER raw_no_replace BEFORE INSERT ON raw_network_records
 WHEN EXISTS(SELECT 1 FROM raw_network_records WHERE raw_record_id=NEW.raw_record_id)
 BEGIN SELECT RAISE(IGNORE); END;
CREATE TRIGGER raw_no_update BEFORE UPDATE ON raw_network_records
 BEGIN SELECT RAISE(ABORT,'raw evidence is immutable'); END;
CREATE TRIGGER raw_no_delete BEFORE DELETE ON raw_network_records
 BEGIN SELECT RAISE(ABORT,'raw evidence is immutable'); END;
CREATE TABLE observed_events(
 event_id INTEGER PRIMARY KEY AUTOINCREMENT, raw_record_id TEXT NOT NULL UNIQUE,
 raw_text_sha256 TEXT NOT NULL, classification TEXT NOT NULL, source TEXT NOT NULL,
 room TEXT NOT NULL, seq INTEGER, sender_did TEXT, event_timestamp TEXT, parsed_at TEXT NOT NULL,
 parser_version TEXT NOT NULL, classification_version TEXT NOT NULL,
 classification_reason TEXT NOT NULL, signature_status TEXT NOT NULL, parse_status TEXT NOT NULL,
 structured_payload_json TEXT NOT NULL, normalized_template_hash TEXT,
 duplicate_group_id TEXT, duplicate_kind TEXT NOT NULL, similarity_reason TEXT,
 FOREIGN KEY(raw_record_id,raw_text_sha256) REFERENCES raw_network_records(raw_record_id,raw_text_sha256));
CREATE INDEX event_content_hash ON observed_events(raw_text_sha256);
CREATE INDEX event_class ON observed_events(classification,event_id);
CREATE INDEX event_template ON observed_events(normalized_template_hash);
CREATE TABLE watch_collections(name TEXT PRIMARY KEY,enabled INTEGER NOT NULL);
CREATE TABLE watch_collection_sources(collection TEXT REFERENCES watch_collections(name),room TEXT,PRIMARY KEY(collection,room));
CREATE TABLE raw_record_watch_membership(raw_record_id TEXT REFERENCES raw_network_records(raw_record_id),collection TEXT REFERENCES watch_collections(name),PRIMARY KEY(raw_record_id,collection));
CREATE TABLE evidence_settings(name TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE evidence_metrics(name TEXT PRIMARY KEY,value INTEGER NOT NULL);
CREATE TABLE evidence_poll_cycles(id INTEGER PRIMARY KEY AUTOINCREMENT,started_at TEXT NOT NULL,finished_at TEXT,status TEXT NOT NULL,details_json TEXT NOT NULL);
CREATE TABLE evidence_retrievals(id INTEGER PRIMARY KEY AUTOINCREMENT,raw_record_id TEXT NOT NULL REFERENCES raw_network_records(raw_record_id),retrieved_at TEXT NOT NULL,source_endpoint TEXT,transport_metadata_json TEXT NOT NULL);
CREATE INDEX retrieval_time ON evidence_retrievals(retrieved_at);
CREATE TABLE compatibility_evidence_links(
        cache_table TEXT NOT NULL, cache_rowid INTEGER NOT NULL, raw_record_id TEXT NOT NULL,
        raw_text_sha256 TEXT NOT NULL, PRIMARY KEY(cache_table,cache_rowid),
        FOREIGN KEY(raw_record_id,raw_text_sha256) REFERENCES raw_network_records(raw_record_id,raw_text_sha256));
CREATE TRIGGER link_messages_insert AFTER INSERT ON messages
            BEGIN INSERT OR REPLACE INTO compatibility_evidence_links
            SELECT 'messages',NEW.rowid,r.raw_record_id,r.raw_text_sha256 FROM raw_network_records r
            WHERE r.room=NEW.room AND r.seq=NEW.seq AND r.raw_text=NEW.text
            ORDER BY r.legacy_record,r.created_at LIMIT 1; END;
CREATE TRIGGER link_messages_delete AFTER DELETE ON messages
            BEGIN DELETE FROM compatibility_evidence_links WHERE cache_table='messages' AND cache_rowid=OLD.rowid; END;
CREATE TRIGGER link_evidence_records_insert AFTER INSERT ON evidence_records
            BEGIN INSERT OR REPLACE INTO compatibility_evidence_links
            SELECT 'evidence_records',NEW.rowid,r.raw_record_id,r.raw_text_sha256 FROM raw_network_records r
            WHERE r.room=NEW.room AND r.seq=NEW.seq AND r.raw_text=NEW.text AND (r.generation=NEW.generation OR r.reported_generation=NEW.generation OR (r.generation IS NULL AND NEW.generation IN ('UNKNOWN_LEGACY','GENERATION_MISSING')))
            ORDER BY r.legacy_record,r.created_at LIMIT 1; END;
CREATE TRIGGER link_evidence_records_delete AFTER DELETE ON evidence_records
            BEGIN DELETE FROM compatibility_evidence_links WHERE cache_table='evidence_records' AND cache_rowid=OLD.rowid; END;
CREATE TRIGGER link_tclk_frames_insert AFTER INSERT ON tclk_frames
            BEGIN INSERT OR REPLACE INTO compatibility_evidence_links
            SELECT 'tclk_frames',NEW.rowid,r.raw_record_id,r.raw_text_sha256 FROM raw_network_records r
            WHERE r.room=NEW.room AND r.seq=NEW.seq AND r.raw_text=NEW.raw_text AND (r.generation=NEW.generation OR r.reported_generation=NEW.generation OR (r.generation IS NULL AND NEW.generation IN ('UNKNOWN_LEGACY','GENERATION_MISSING')))
            ORDER BY r.legacy_record,r.created_at LIMIT 1; END;
CREATE TRIGGER link_tclk_frames_delete AFTER DELETE ON tclk_frames
            BEGIN DELETE FROM compatibility_evidence_links WHERE cache_table='tclk_frames' AND cache_rowid=OLD.rowid; END;
CREATE TRIGGER link_kibble_events_insert AFTER INSERT ON kibble_events
            BEGIN INSERT OR REPLACE INTO compatibility_evidence_links
            SELECT 'kibble_events',NEW.rowid,r.raw_record_id,r.raw_text_sha256 FROM raw_network_records r
            WHERE r.room=NEW.room AND r.seq=NEW.seq AND r.raw_text=NEW.exact_text AND (r.generation=NEW.generation OR r.reported_generation=NEW.generation OR (r.generation IS NULL AND NEW.generation IN ('UNKNOWN_LEGACY','GENERATION_MISSING')))
            ORDER BY r.legacy_record,r.created_at LIMIT 1; END;
CREATE TRIGGER link_kibble_events_delete AFTER DELETE ON kibble_events
            BEGIN DELETE FROM compatibility_evidence_links WHERE cache_table='kibble_events' AND cache_rowid=OLD.rowid; END;
CREATE TRIGGER link_opportunities_insert AFTER INSERT ON opportunities
            BEGIN INSERT OR REPLACE INTO compatibility_evidence_links
            SELECT 'opportunities',NEW.rowid,r.raw_record_id,r.raw_text_sha256 FROM raw_network_records r
            WHERE r.room=NEW.room AND r.seq=NEW.seq AND r.raw_text=NEW.message_text
            ORDER BY r.legacy_record,r.created_at LIMIT 1; END;
CREATE TRIGGER link_opportunities_delete AFTER DELETE ON opportunities
            BEGIN DELETE FROM compatibility_evidence_links WHERE cache_table='opportunities' AND cache_rowid=OLD.rowid; END;
CREATE TRIGGER link_validation_response_candidates_insert AFTER INSERT ON validation_response_candidates
            BEGIN INSERT OR REPLACE INTO compatibility_evidence_links
            SELECT 'validation_response_candidates',NEW.rowid,r.raw_record_id,r.raw_text_sha256 FROM raw_network_records r
            WHERE r.room=NEW.room AND r.seq=NEW.seq AND r.raw_text_sha256=NEW.message_hash
            ORDER BY r.legacy_record,r.created_at LIMIT 1; END;
CREATE TRIGGER link_validation_response_candidates_delete AFTER DELETE ON validation_response_candidates
            BEGIN DELETE FROM compatibility_evidence_links WHERE cache_table='validation_response_candidates' AND cache_rowid=OLD.rowid; END;
CREATE TABLE evidence_source_gaps(
 gap_id TEXT PRIMARY KEY, source TEXT NOT NULL, source_endpoint TEXT NOT NULL,
 room TEXT NOT NULL, generation TEXT NOT NULL, last_durable_seq INTEGER NOT NULL,
 first_available_seq INTEGER NOT NULL, server_latest_seq INTEGER,
 detected_at TEXT NOT NULL, gap_type TEXT NOT NULL CHECK(gap_type='UPSTREAM_RETENTION_GAP'),
 reason TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('UNRESOLVED','RECOVERED')),
 recovery_at TEXT, first_recovered_raw_record_id TEXT, first_recovered_raw_hash TEXT,
 metadata_json TEXT NOT NULL, created_at TEXT NOT NULL,
 FOREIGN KEY(first_recovered_raw_record_id,first_recovered_raw_hash)
 REFERENCES raw_network_records(raw_record_id,raw_text_sha256));
CREATE TRIGGER gap_no_replace BEFORE INSERT ON evidence_source_gaps
 WHEN EXISTS(SELECT 1 FROM evidence_source_gaps WHERE gap_id=NEW.gap_id)
 BEGIN SELECT RAISE(IGNORE); END;
CREATE TRIGGER gap_no_delete BEFORE DELETE ON evidence_source_gaps
 BEGIN SELECT RAISE(ABORT,'source gap is immutable'); END;
CREATE TRIGGER gap_protect BEFORE UPDATE ON evidence_source_gaps
 WHEN OLD.status='RECOVERED' OR NEW.status!='RECOVERED'
 OR NEW.recovery_at IS NULL OR NEW.first_recovered_raw_record_id IS NULL
 OR NEW.first_recovered_raw_hash IS NULL
 OR OLD.gap_id IS NOT NEW.gap_id OR OLD.source IS NOT NEW.source
 OR OLD.source_endpoint IS NOT NEW.source_endpoint OR OLD.room IS NOT NEW.room
 OR OLD.generation IS NOT NEW.generation OR OLD.last_durable_seq IS NOT NEW.last_durable_seq
 OR OLD.first_available_seq IS NOT NEW.first_available_seq
 OR OLD.server_latest_seq IS NOT NEW.server_latest_seq OR OLD.detected_at IS NOT NEW.detected_at
 OR OLD.gap_type IS NOT NEW.gap_type OR OLD.reason IS NOT NEW.reason
 OR OLD.metadata_json IS NOT NEW.metadata_json OR OLD.created_at IS NOT NEW.created_at
 BEGIN SELECT RAISE(ABORT,'only one source gap recovery transition is allowed'); END;
CREATE TABLE source_coverage_state(
 source TEXT NOT NULL, room TEXT NOT NULL, generation TEXT NOT NULL,
 coverage_cursor INTEGER NOT NULL, observed_high_water INTEGER NOT NULL,
 server_tail_high_water INTEGER, coverage_status TEXT NOT NULL,
 backfill_required INTEGER NOT NULL, backfill_from_seq INTEGER, backfill_to_seq INTEGER,
 last_checked_at TEXT, last_backfill_at TEXT, last_backfill_result TEXT, origin_unknown INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(room,generation));
CREATE TABLE evidence_export_snapshots(
 snapshot_id TEXT PRIMARY KEY, room TEXT NOT NULL, generation TEXT NOT NULL,
 source_endpoint TEXT NOT NULL, sha256 TEXT NOT NULL, path TEXT NOT NULL,
 retrieved_at TEXT NOT NULL, record_count INTEGER NOT NULL, first_seq INTEGER,
 last_seq INTEGER, consecutive INTEGER NOT NULL, processed_records INTEGER NOT NULL DEFAULT 0,
 status TEXT NOT NULL DEFAULT 'VALIDATED', metadata_json TEXT NOT NULL);
CREATE TABLE evidence_retention_losses(
 loss_id TEXT PRIMARY KEY, room TEXT NOT NULL, generation TEXT NOT NULL,
 last_durable_seq INTEGER NOT NULL, first_available_seq INTEGER NOT NULL,
 snapshot_id TEXT NOT NULL REFERENCES evidence_export_snapshots(snapshot_id),
 detected_at TEXT NOT NULL, gap_type TEXT NOT NULL,
 sequence_contract TEXT NOT NULL, first_raw_id TEXT NOT NULL REFERENCES raw_network_records(raw_record_id));
CREATE TABLE evidence_gap_reassessments(
 reassessment_id TEXT PRIMARY KEY, gap_id TEXT NOT NULL REFERENCES evidence_source_gaps(gap_id),
 assessed_at TEXT NOT NULL, assessment TEXT NOT NULL, reason TEXT NOT NULL,
 evidence_source TEXT NOT NULL, evidence_endpoint TEXT NOT NULL, evidence_hash TEXT NOT NULL,
 snapshot_id TEXT NOT NULL REFERENCES evidence_export_snapshots(snapshot_id), metadata_json TEXT NOT NULL);
CREATE TABLE evidence_coverage_events(
 event_id INTEGER PRIMARY KEY, room TEXT NOT NULL, generation TEXT NOT NULL,
 kind TEXT NOT NULL, created_at TEXT NOT NULL, details_json TEXT NOT NULL);
CREATE TABLE evidence_room_health(
 room TEXT PRIMARY KEY, last_poll_at TEXT, poll_duration REAL, effective_rate REAL,
 next_due TEXT, failures INTEGER NOT NULL DEFAULT 0, last_error TEXT);
CREATE TRIGGER evidence_retention_losses_no_UPDATE BEFORE UPDATE ON evidence_retention_losses BEGIN SELECT RAISE(ABORT,'provenance is immutable'); END;
CREATE TRIGGER evidence_retention_losses_no_DELETE BEFORE DELETE ON evidence_retention_losses BEGIN SELECT RAISE(ABORT,'provenance is immutable'); END;
CREATE TRIGGER evidence_retention_losses_no_replace BEFORE INSERT ON evidence_retention_losses WHEN EXISTS(SELECT 1 FROM evidence_retention_losses WHERE rowid=NEW.rowid) BEGIN SELECT RAISE(IGNORE); END;
CREATE TRIGGER evidence_gap_reassessments_no_UPDATE BEFORE UPDATE ON evidence_gap_reassessments BEGIN SELECT RAISE(ABORT,'provenance is immutable'); END;
CREATE TRIGGER evidence_gap_reassessments_no_DELETE BEFORE DELETE ON evidence_gap_reassessments BEGIN SELECT RAISE(ABORT,'provenance is immutable'); END;
CREATE TRIGGER evidence_gap_reassessments_no_replace BEFORE INSERT ON evidence_gap_reassessments WHEN EXISTS(SELECT 1 FROM evidence_gap_reassessments WHERE rowid=NEW.rowid) BEGIN SELECT RAISE(IGNORE); END;
CREATE TRIGGER evidence_coverage_events_no_UPDATE BEFORE UPDATE ON evidence_coverage_events BEGIN SELECT RAISE(ABORT,'provenance is immutable'); END;
CREATE TRIGGER evidence_coverage_events_no_DELETE BEFORE DELETE ON evidence_coverage_events BEGIN SELECT RAISE(ABORT,'provenance is immutable'); END;
CREATE TRIGGER evidence_coverage_events_no_replace BEFORE INSERT ON evidence_coverage_events WHEN EXISTS(SELECT 1 FROM evidence_coverage_events WHERE rowid=NEW.rowid) BEGIN SELECT RAISE(IGNORE); END;
CREATE TRIGGER evidence_retention_losses_identity BEFORE INSERT ON evidence_retention_losses WHEN EXISTS(SELECT 1 FROM evidence_retention_losses WHERE loss_id=NEW.loss_id) BEGIN SELECT RAISE(IGNORE); END;
CREATE TRIGGER evidence_gap_reassessments_identity BEFORE INSERT ON evidence_gap_reassessments WHEN EXISTS(SELECT 1 FROM evidence_gap_reassessments WHERE reassessment_id=NEW.reassessment_id) BEGIN SELECT RAISE(IGNORE); END;
CREATE TRIGGER snapshot_facts_immutable BEFORE UPDATE ON evidence_export_snapshots
            WHEN OLD.snapshot_id IS NOT NEW.snapshot_id OR OLD.room IS NOT NEW.room OR OLD.generation IS NOT NEW.generation
            OR OLD.source_endpoint IS NOT NEW.source_endpoint OR OLD.sha256 IS NOT NEW.sha256 OR OLD.path IS NOT NEW.path
            OR OLD.retrieved_at IS NOT NEW.retrieved_at OR OLD.record_count IS NOT NEW.record_count
            OR OLD.first_seq IS NOT NEW.first_seq OR OLD.last_seq IS NOT NEW.last_seq OR OLD.consecutive IS NOT NEW.consecutive
            OR OLD.metadata_json IS NOT NEW.metadata_json OR NEW.processed_records<OLD.processed_records
            OR NEW.processed_records>OLD.record_count
            BEGIN SELECT RAISE(ABORT,'snapshot provenance/checkpoint protected'); END;
CREATE TRIGGER snapshot_no_delete BEFORE DELETE ON evidence_export_snapshots BEGIN SELECT RAISE(ABORT,'snapshot provenance protected'); END;
CREATE TRIGGER snapshot_no_replace BEFORE INSERT ON evidence_export_snapshots WHEN EXISTS(SELECT 1 FROM evidence_export_snapshots WHERE snapshot_id=NEW.snapshot_id) BEGIN SELECT RAISE(IGNORE); END;
