"""Local evidence store. No network, identity files, or execution of remote content."""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path

SCHEMA = 'flop-scout-evidence/v1'
VERSION = '1'
SAFETY_KEYS = ('network_writes', 'url_follows', 'wallet_accesses', 'faucet_claims',
               'tclk_actions', 'kibble_claims', 'private_key_accesses')
DEFAULT_COLLECTIONS = {
    name: {'enabled': True, 'rooms': rooms} for name, rooms in {
        'faucet': ['faucet'], 'kibble': ['kibble'],
        'consensus_layer': ['consensus_layer'], 'tclk': ['tclk-offers'],
        'a2a_mesh_router': ['a2a_mesh_router'], 'external_work_offers': [],
        'registry_announcements': [], 'official_protocol_announcements': [],
        'competitor_projects': ['flop-evidence-scout'],
    }.items()
}


def now():
    return datetime.now(timezone.utc).isoformat()


def dumps(value):
    # JSON is an envelope reconstruction, NEVER the signed text/preimage.
    return json.dumps(value, ensure_ascii=True, separators=(',', ':'), allow_nan=False)


def safe_utf8(value):
    if not isinstance(value, str):
        return None
    try:
        value.encode('utf-8')
        return value
    except UnicodeEncodeError:
        return None


def scalar_text(value):
    if value is None:
        return None
    return safe_utf8(value) if isinstance(value,str) else dumps(value)


def digest(text):
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


def integer(value):
    if type(value) is int:
        return value if 0 <= value <= 9223372036854775807 else None
    if isinstance(value, str) and re.fullmatch(r'[0-9]+', value):
        return integer(int(value))
    return None


def load_collections(path=None):
    config = json.loads(dumps(DEFAULT_COLLECTIONS))
    if path is not None and Path(path).exists():
        override = json.loads(Path(path).read_text())
        if not isinstance(override, dict):
            raise ValueError('Watch configuration must be an object')
        config.update(override)
    for name, item in config.items():
        if not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', name) or not isinstance(item, dict):
            raise ValueError('Invalid watch collection')
        if type(item.get('enabled')) is not bool or not isinstance(item.get('rooms'), list):
            raise ValueError('Each collection needs enabled and rooms')
        for room in item['rooms']:
            if not isinstance(room, str) or not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,47}', room):
                raise ValueError('Only configured Technocore room names are allowed')
    return config


def sync_collections(conn, config):
    config_hash = digest(dumps(config))
    old = conn.execute("SELECT value FROM evidence_settings WHERE name='watch_config_hash'").fetchone()
    if old and old[0] == config_hash:
        return
    with conn:
        conn.execute("INSERT OR REPLACE INTO evidence_settings VALUES ('watch_config_hash',?)",(config_hash,))
        conn.execute('UPDATE watch_collections SET enabled=0')
        conn.execute('DELETE FROM watch_collection_sources')
        for name, item in config.items():
            conn.execute('INSERT INTO watch_collections VALUES (?,?) ON CONFLICT(name) DO UPDATE SET enabled=excluded.enabled', (name, int(item['enabled'])))
            for room in set(item['rooms']):
                conn.execute('INSERT INTO watch_collection_sources VALUES (?,?)', (name, room))
        conn.execute('''INSERT OR IGNORE INTO raw_record_watch_membership
            SELECT r.raw_record_id,s.collection FROM raw_network_records r
            JOIN watch_collection_sources s ON r.room=s.room
            JOIN watch_collections c ON c.name=s.collection WHERE c.enabled=1''')


DDL = '''
CREATE TABLE IF NOT EXISTS evidence_schema(version INTEGER PRIMARY KEY, migrated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS raw_network_records(
 raw_record_id TEXT PRIMARY KEY, source TEXT NOT NULL, source_endpoint TEXT,
 room TEXT NOT NULL, generation TEXT, reported_generation TEXT, seq INTEGER,
 network_timestamp TEXT, retrieved_at TEXT NOT NULL, nonce TEXT,
 sender_did TEXT, signature TEXT, raw_text TEXT, raw_text_sha256 TEXT NOT NULL,
 raw_record_json TEXT NOT NULL, signature_status TEXT NOT NULL, signature_error TEXT,
 did_mismatch INTEGER NOT NULL, transport_metadata_json TEXT NOT NULL,
 ingestion_schema TEXT NOT NULL, ingestion_version TEXT NOT NULL, created_at TEXT NOT NULL,
 legacy_record INTEGER NOT NULL, raw_completeness TEXT NOT NULL,
 UNIQUE(raw_record_id,raw_text_sha256));
CREATE INDEX IF NOT EXISTS raw_position ON raw_network_records(source,room,generation,seq);
CREATE INDEX IF NOT EXISTS raw_room_sequence ON raw_network_records(room,seq);
CREATE INDEX IF NOT EXISTS raw_hash ON raw_network_records(raw_text_sha256);
CREATE INDEX IF NOT EXISTS raw_time ON raw_network_records(retrieved_at);
CREATE INDEX IF NOT EXISTS raw_did ON raw_network_records(sender_did,retrieved_at);
CREATE TRIGGER IF NOT EXISTS raw_no_replace BEFORE INSERT ON raw_network_records
 WHEN EXISTS(SELECT 1 FROM raw_network_records WHERE raw_record_id=NEW.raw_record_id)
 BEGIN SELECT RAISE(IGNORE); END;
CREATE TRIGGER IF NOT EXISTS raw_no_update BEFORE UPDATE ON raw_network_records
 BEGIN SELECT RAISE(ABORT,'raw evidence is immutable'); END;
CREATE TRIGGER IF NOT EXISTS raw_no_delete BEFORE DELETE ON raw_network_records
 BEGIN SELECT RAISE(ABORT,'raw evidence is immutable'); END;
CREATE TABLE IF NOT EXISTS observed_events(
 event_id INTEGER PRIMARY KEY AUTOINCREMENT, raw_record_id TEXT NOT NULL UNIQUE,
 raw_text_sha256 TEXT NOT NULL, classification TEXT NOT NULL, source TEXT NOT NULL,
 room TEXT NOT NULL, seq INTEGER, sender_did TEXT, event_timestamp TEXT, parsed_at TEXT NOT NULL,
 parser_version TEXT NOT NULL, classification_version TEXT NOT NULL,
 classification_reason TEXT NOT NULL, signature_status TEXT NOT NULL, parse_status TEXT NOT NULL,
 structured_payload_json TEXT NOT NULL, normalized_template_hash TEXT,
 duplicate_group_id TEXT, duplicate_kind TEXT NOT NULL, similarity_reason TEXT,
 FOREIGN KEY(raw_record_id,raw_text_sha256) REFERENCES raw_network_records(raw_record_id,raw_text_sha256));
CREATE INDEX IF NOT EXISTS event_content_hash ON observed_events(raw_text_sha256);
CREATE INDEX IF NOT EXISTS event_class ON observed_events(classification,event_id);
CREATE INDEX IF NOT EXISTS event_template ON observed_events(normalized_template_hash);
CREATE TABLE IF NOT EXISTS watch_collections(name TEXT PRIMARY KEY,enabled INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS watch_collection_sources(collection TEXT REFERENCES watch_collections(name),room TEXT,PRIMARY KEY(collection,room));
CREATE TABLE IF NOT EXISTS raw_record_watch_membership(raw_record_id TEXT REFERENCES raw_network_records(raw_record_id),collection TEXT REFERENCES watch_collections(name),PRIMARY KEY(raw_record_id,collection));
CREATE TABLE IF NOT EXISTS evidence_settings(name TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS evidence_metrics(name TEXT PRIMARY KEY,value INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS evidence_poll_cycles(id INTEGER PRIMARY KEY AUTOINCREMENT,started_at TEXT NOT NULL,finished_at TEXT,status TEXT NOT NULL,details_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS evidence_retrievals(id INTEGER PRIMARY KEY AUTOINCREMENT,raw_record_id TEXT NOT NULL REFERENCES raw_network_records(raw_record_id),retrieved_at TEXT NOT NULL,source_endpoint TEXT,transport_metadata_json TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS retrieval_time ON evidence_retrievals(retrieved_at);
'''


def initialize(conn, verify):
    """Version-gated, transactional migration; never called by readers."""
    conn.execute('PRAGMA foreign_keys=ON')
    if conn.execute("SELECT 1 FROM sqlite_master WHERE name='evidence_schema'").fetchone():
        if conn.execute('SELECT 1 FROM evidence_schema WHERE version=1').fetchone():
            return
    # execute each statement without executescript's implicit pre-commit.
    with conn:
        if not conn.in_transaction:
            conn.execute('BEGIN IMMEDIATE')
        statement = ''
        for line in DDL.splitlines(True):
            statement += line
            if sqlite3.complete_statement(statement):
                conn.execute(statement)
                statement = ''
        for key in (*SAFETY_KEYS, 'cursor_regressions', 'database_errors', 'read_failures', 'recoveries', 'records_ingested', 'exact_duplicate_suppression'):
            conn.execute('INSERT OR IGNORE INTO evidence_metrics VALUES (?,0)', (key,))
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if 'evidence_records' in tables:
            for row in conn.execute('SELECT * FROM evidence_records'):
                row = dict(row)
                try:
                    raw = json.loads(row['raw_record_json'])
                except (ValueError, TypeError, RecursionError):
                    raw = {'seq': row['seq'], 'text': row['text'], 'did': row['did'], 'nonce': row['nonce'], 'sig': row['sig']}
                ingest(conn, row['room'], raw, verify, generation=None,
                       reported_generation=row['generation'], source='legacy_evidence',
                       retrieved_at=row['retrieved_at'], legacy=True)
        if 'messages' in tables:
            for row in conn.execute('SELECT * FROM messages'):
                if conn.execute('SELECT 1 FROM raw_network_records WHERE room=? AND seq=? AND raw_text=? LIMIT 1',(row['room'],row['seq'],row['text'])).fetchone():
                    continue
                raw = {'seq': row['seq'], 'text': row['text'], 'from': row['sender'], 'ts': row['timestamp']}
                ingest(conn, row['room'], raw, verify, source='legacy_messages',
                       retrieved_at=row['discovered_at'], legacy=True)
        compatibility_links(conn, verify)
        if 'tclk_capability_hints' in tables:
            for hint in conn.execute('SELECT rowid AS cache_id,* FROM tclk_capability_hints'):
                record = dict(hint)
                cache_id = record.pop('cache_id')
                rid = ingest(conn,'',record,verify,source='legacy_note_hint',legacy=True)
                hash_value = conn.execute('SELECT raw_text_sha256 FROM raw_network_records WHERE raw_record_id=?',(rid,)).fetchone()[0]
                conn.execute('INSERT OR IGNORE INTO compatibility_evidence_links VALUES (?,?,?,?)',('tclk_capability_hints',cache_id,rid,hash_value))
        conn.execute('INSERT INTO evidence_schema VALUES (1,?)', (now(),))


CLASSES = {x: x for x in ('IDENTITY_PRESENCE','PROMOTIONAL_CLAIM','WORK_REQUEST',
    'WORK_ACCEPTANCE','WORK_RESULT','VERIFICATION_RESULT','EXTERNAL_RAIL_CLAIM',
    'OFFICIAL_NETWORK_ANNOUNCEMENT','REGISTRY_ANNOUNCEMENT','CAPABILITY_CLAIM')}
ALIASES = {'presence': 'IDENTITY_PRESENCE', 'capability': 'PROMOTIONAL_CLAIM',
    'work_request': 'WORK_REQUEST', 'work_acceptance': 'WORK_ACCEPTANCE',
    'work_result': 'WORK_RESULT', 'verification_result': 'VERIFICATION_RESULT',
    'external_rail_claim': 'EXTERNAL_RAIL_CLAIM',
    'official_network_announcement': 'OFFICIAL_NETWORK_ANNOUNCEMENT',
    'registry_announcement': 'REGISTRY_ANNOUNCEMENT'}


def classify(raw, status):
    text = raw.get('text') if isinstance(raw, dict) else None
    payload = {'claim_only': True, 'correctness_verified': False,
               'operator_relationship': None}
    if not isinstance(text, str):
        return 'MALFORMED_UNVERIFIABLE_EVENT', 'MALFORMED', 'text is not a string', payload
    if status in ('FAILED', 'UNSUPPORTED'):
        return 'MALFORMED_UNVERIFIABLE_EVENT', 'UNVERIFIABLE', 'transport signature not verified', payload
    if text.startswith('tclk1 '):
        try:
            frame = json.loads(text[6:])
            if not isinstance(frame, dict) or frame.get('type') not in ('offer','accept','lock','reveal','refund','cancel','receipt'):
                raise ValueError('unsupported frame')
            payload['frame'] = frame
            payload['settlement_executed'] = False
            payload['external_rail_claim'] = frame['type'] in ('lock','reveal','refund','receipt')
            return 'TCLK_TRANSCRIPT_EVENT', 'PARSED', 'recognized tclk1 frame; observed only', payload
        except (ValueError, TypeError, RecursionError):
            return 'MALFORMED_UNVERIFIABLE_EVENT', 'MALFORMED', 'malformed tclk1 frame', payload
    try:
        obj = json.loads(text)
    except (ValueError, RecursionError):
        obj = None
        if text.lstrip().startswith(('{', '[')):
            return 'MALFORMED_UNVERIFIABLE_EVENT', 'MALFORMED', 'invalid JSON-looking content', payload
    if isinstance(obj, dict):
        payload['content'] = obj
        if obj.get('type') in ('JOB','CLAIM','RESULT','DELIVER','ATTEST','ACCEPT','WITNESS','BRIEF') and (obj.get('version',obj.get('v')) in ('1','v1',1) or str(obj.get('schema_version','')).endswith('.v1')):
            cls = {'JOB':'KIBBLE_JOB','CLAIM':'KIBBLE_CLAIM','RESULT':'KIBBLE_RESULT','DELIVER':'KIBBLE_RESULT','ATTEST':'KIBBLE_ATTESTATION','ACCEPT':'WORK_ACCEPTANCE','WITNESS':'VERIFICATION_RESULT','BRIEF':'WORK_REQUEST'}[obj['type']]
            return cls, 'PARSED', 'self-declared Kibble event; no work or payment verified', payload
        kind = obj.get('type', obj.get('event', obj.get('classification')))
        classification = (CLASSES.get(kind) or ALIASES.get(kind)) if isinstance(kind, str) else None
        if classification:
            return classification, 'PARSED', 'self-declared message type; no truth assertion', payload
    rules = (
        ('VERIFICATION_RESULT', r'^(?:verification result|bench result)\b'),
        ('WORK_RESULT', r'^(?:work result|result:)'),
        ('WORK_ACCEPTANCE', r'^(?:work acceptance|accepted job|i accept the task)\b'),
        ('WORK_REQUEST', r'^(?:work request|request:|help needed|looking for an agent)\b'),
        ('EXTERNAL_RAIL_CLAIM', r'^(?:payment sent|settlement claim|funds transferred)\b'),
        ('IDENTITY_PRESENCE', r'^(?:presence:|hello[,! ]|online\b)'),
        ('PROMOTIONAL_CLAIM', r'^(?:capabilities:|i can |we offer |available for )'),
    )
    for cls, pattern in rules:
        if re.search(pattern, text, re.I):
            return cls, 'PARSED', 'anchored lexical claim rule', payload
    return 'UNCLASSIFIED', 'UNKNOWN', 'no supported deterministic rule', payload


def template(text, classification):
    # Only promotional claims. Never erase task/result fields.
    if classification not in ('PROMOTIONAL_CLAIM', 'CAPABILITY_CLAIM'):
        return None
    normalized = re.sub(r'\b(timestamp|nonce|seq|job_id|uuid)(\s*[:=]\s*)([A-Za-z0-9_.:+-]+)', r'\1\2<variable>', text)
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            obj = {k: ('<variable>' if k in ('timestamp','nonce','seq','job_id','uuid') and isinstance(v, (str,int)) else v) for k,v in obj.items()}
            normalized = dumps(obj)
    except (ValueError, RecursionError):
        pass
    return digest(normalized)


def raw_identity(source, room, generation, reported_generation, raw):
    # Sorted envelope keys stabilize transport serializations; string values are untouched.
    return digest(json.dumps([source,room,generation,reported_generation,raw], sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False))


def ingest(conn, room, raw, verify, *, generation=None, reported_generation=None,
           source=None, endpoint=None, retrieved_at=None, metadata=None, legacy=False):
    source = source or ('technocore_mailbox' if room.startswith('mb-') else 'technocore_room')
    retrieved_at = retrieved_at if retrieved_at is not None else ("" if legacy else now())
    generation = str(generation) if generation is not None else None
    if generation is not None and safe_utf8(generation) is None:
        reported_generation = dumps(generation)
        generation = None
    rid = raw_identity(source, room, generation, reported_generation, raw)
    data = raw if isinstance(raw, dict) else {}
    text = data.get('text')
    text = text if isinstance(text, str) else None
    try:
        text_hash = digest(text) if text is not None else digest(dumps(raw))
    except UnicodeEncodeError:
        # Lone surrogate is not UTF-8 text. The JSON envelope retains it losslessly.
        text = None
        text_hash = digest(dumps(raw))
    mismatch = data.get('did') is not None and data.get('from') is not None and data['did'] != data['from']
    nonce = data.get('nonce')
    nonce_valid = (type(nonce) is int and 0 <= nonce <= 9999999999999999999) or (isinstance(nonce,str) and re.fullmatch(r'[0-9]{1,19}',nonce))
    if text is None:
        status, error = 'UNSUPPORTED', 'missing/non-UTF8 text'
    elif mismatch:
        status, error = 'FAILED', 'DID_MISMATCH'
    elif data.get('sig') is None:
        status, error = 'MISSING', 'signature absent'
    elif not nonce_valid:
        status, error = 'UNSUPPORTED', 'nonce must be decimal digits, never float'
    else:
        try:
            result = verify(room, data)
            status = {'VERIFIED_OFFLINE':'VERIFIED_OFFLINE', 'INVALID_SIGNATURE':'FAILED'}.get(result, 'UNSUPPORTED')
            error = None if status == 'VERIFIED_OFFLINE' else result
        except (ValueError, TypeError, OverflowError) as exc:
            status, error = 'UNSUPPORTED', str(exc)
    sender = data.get('did', data.get('from'))
    sender = safe_utf8(sender)
    if text is not None and text.startswith('tclk1 '):
        try:
            frame = json.loads(text[6:])
            if isinstance(frame,dict) and frame.get('from') is not None and frame['from'] != sender:
                mismatch = True
                error = 'TCLK_FRAME_DID_MISMATCH'
        except (ValueError, RecursionError):
            pass
    sig = data.get('sig')
    sig = safe_utf8(sig)
    metadata = dict(metadata or {})
    metadata['envelope_serialization'] = 'reconstructed JSON; signed text unchanged'
    metadata['hash_basis'] = 'raw_text_utf8' if text is not None else 'raw_record_json_ascii'
    cur = conn.execute('''INSERT OR IGNORE INTO raw_network_records VALUES
        (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
        (rid,source,endpoint,room,generation,reported_generation,integer(data.get('seq')),
         scalar_text(data.get('ts',data.get('timestamp',data.get('time')))),retrieved_at,
         scalar_text(nonce),sender,sig,text,text_hash,dumps(raw),status,error,int(mismatch),dumps(metadata),
         SCHEMA,VERSION,now(),int(legacy),'PARTIAL' if legacy or endpoint is None else 'COMPLETE'))
    inserted = cur.rowcount == 1
    if inserted:
        bump(conn, 'records_ingested')
    if not inserted:
        bump(conn, 'exact_duplicate_suppression')
        conn.execute('INSERT INTO evidence_retrievals(raw_record_id,retrieved_at,source_endpoint,transport_metadata_json) VALUES (?,?,?,?)', (rid,retrieved_at,endpoint,dumps(metadata)))
    # Always repair missing derived rows, including recovery after raw-only persistence.
    stored = conn.execute('SELECT * FROM raw_network_records WHERE raw_record_id=?',(rid,)).fetchone()
    derive(conn, stored)
    conn.execute('''INSERT OR IGNORE INTO raw_record_watch_membership
        SELECT ?,s.collection FROM watch_collection_sources s JOIN watch_collections c
        ON c.name=s.collection WHERE s.room=? AND c.enabled=1''',(rid,room))
    return rid


def derive(conn, row):
    if conn.execute('SELECT 1 FROM observed_events WHERE raw_record_id=?',(row['raw_record_id'],)).fetchone():
        return
    raw = json.loads(row['raw_record_json'])
    cls, parse, reason, payload = classify(raw, row['signature_status'])
    if row['seq'] is None and row['room'] != '':
        cls, parse, reason = 'MALFORMED_UNVERIFIABLE_EVENT','MALFORMED','missing/invalid sequence'
    if row['did_mismatch']:
        cls, parse, reason = 'MALFORMED_UNVERIFIABLE_EVENT','UNVERIFIABLE','DID binding mismatch'
    th = template(row['raw_text'], cls) if row['raw_text'] is not None else None
    prior = conn.execute('SELECT event_id FROM observed_events WHERE raw_text_sha256=? LIMIT 1',(row['raw_text_sha256'],)).fetchone()
    near = conn.execute('SELECT event_id FROM observed_events WHERE normalized_template_hash=? LIMIT 1',(th,)).fetchone() if th else None
    kind = 'EXACT_DUPLICATE' if prior else ('TEMPLATE_VARIANT' if near else 'UNIQUE')
    group = 'text:'+row['raw_text_sha256'] if prior else ('template:'+th if th else None)
    conn.execute('''INSERT INTO observed_events(raw_record_id,raw_text_sha256,classification,
        source,room,seq,sender_did,event_timestamp,parsed_at,parser_version,classification_version,
        classification_reason,signature_status,parse_status,structured_payload_json,
        normalized_template_hash,duplicate_group_id,duplicate_kind,similarity_reason)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
        (row['raw_record_id'],row['raw_text_sha256'],cls,row['source'],row['room'],row['seq'],
         row['sender_did'],row['network_timestamp'],now(),VERSION,VERSION,reason,row['signature_status'],parse,
         dumps(payload),th,group,kind,'exact content hash' if prior else ('promotional variable fields only' if near else None)))


def repair(conn):
    with conn:
        for row in conn.execute('SELECT r.* FROM raw_network_records r LEFT JOIN observed_events e USING(raw_record_id) WHERE e.event_id IS NULL'):
            derive(conn,row)


def bump(conn, name, count=1):
    conn.execute('INSERT INTO evidence_metrics VALUES (?,?) ON CONFLICT(name) DO UPDATE SET value=value+excluded.value',(name,count))


def integrity(conn):
    result = {'raw_records':conn.execute('SELECT count(*) FROM raw_network_records').fetchone()[0],
              'parsed_events':conn.execute('SELECT count(*) FROM observed_events').fetchone()[0]}
    result['orphaned_events'] = conn.execute('SELECT count(*) FROM observed_events e LEFT JOIN raw_network_records r USING(raw_record_id) WHERE r.raw_record_id IS NULL').fetchone()[0]
    result['hash_mismatches'] = conn.execute('SELECT count(*) FROM observed_events e JOIN raw_network_records r USING(raw_record_id) WHERE e.raw_text_sha256 != r.raw_text_sha256').fetchone()[0]
    result['raw_identity_mismatches'] = 0
    for row in conn.execute('SELECT * FROM raw_network_records'):
        identity = raw_identity(row['source'],row['room'],row['generation'],row['reported_generation'],json.loads(row['raw_record_json']))
        result['raw_identity_mismatches'] += identity != row['raw_record_id']
        expected = digest(row['raw_text'] if row['raw_text'] is not None else row['raw_record_json'])
        if expected != row['raw_text_sha256']:
            result['hash_mismatches'] += 1
    result['missing_events'] = conn.execute('SELECT count(*) FROM raw_network_records r LEFT JOIN observed_events e USING(raw_record_id) WHERE e.event_id IS NULL').fetchone()[0]
    result['seq_conflicts'] = conn.execute('''SELECT count(*) FROM (SELECT 1 FROM raw_network_records
        WHERE seq IS NOT NULL GROUP BY source,room,generation,seq HAVING count(DISTINCT raw_text_sha256)>1)''').fetchone()[0]
    result['signature_failures'] = conn.execute("SELECT count(*) FROM raw_network_records WHERE signature_status='FAILED'").fetchone()[0]
    result['unlinked_compatibility_records'] = 0
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for table in (*COMPAT_TEXT, 'tclk_capability_hints'):
        if table in tables:
            result['unlinked_compatibility_records'] += conn.execute(f"SELECT count(*) FROM {table} c LEFT JOIN compatibility_evidence_links l ON l.cache_table=? AND l.cache_rowid=c.rowid WHERE l.raw_record_id IS NULL",(table,)).fetchone()[0]
    result['foreign_key_errors'] = len(conn.execute('PRAGMA foreign_key_check').fetchall())
    result['status'] = 'FAIL' if any(result[k] for k in ('orphaned_events','hash_mismatches','missing_events','unlinked_compatibility_records','foreign_key_errors','raw_identity_mismatches')) else 'PASS'
    return result


def feed(conn, since_id=0, since_seq=None, classification=None, collection=None, limit=None):
    where, params = ['e.event_id>?'], [since_id]
    if since_seq is not None:
        where.append('e.seq>?'); params.append(since_seq)
    if classification:
        where.append('e.classification=?'); params.append(classification)
    if collection:
        where.append('EXISTS(SELECT 1 FROM raw_record_watch_membership m WHERE m.raw_record_id=e.raw_record_id AND m.collection=?)'); params.append(collection)
    sql = '''SELECT e.*,r.generation,r.reported_generation,r.retrieved_at,r.source_endpoint,
        r.raw_completeness,r.legacy_record,r.raw_record_json FROM observed_events e JOIN raw_network_records r
        USING(raw_record_id) WHERE '''+' AND '.join(where)+' ORDER BY e.event_id'
    if limit is not None:
        sql += ' LIMIT ?'; params.append(limit)
    for row in conn.execute(sql,params):
        item = dict(row)
        item['schema'] = SCHEMA
        item['structured_event'] = json.loads(item.pop('structured_payload_json'))
        raw = json.loads(item.pop('raw_record_json'))
        item['timestamp'] = raw.get('ts',raw.get('timestamp',raw.get('time'))) if isinstance(raw,dict) else None
        item.pop('event_timestamp')
        item['watch_collections'] = [r[0] for r in conn.execute('SELECT collection FROM raw_record_watch_membership WHERE raw_record_id=? ORDER BY collection',(item['raw_record_id'],))]
        item['operator_relationship'] = None
        yield item


# Operational reports use capture time, never parser/insertion time or unsigned
# network timestamps. This also corrects already-migrated databases read-only.
OBSERVED = "r.legacy_record=0 AND r.raw_completeness='COMPLETE' AND julianday(r.retrieved_at) IS NOT NULL"


def first_observed_dids(conn, start, end, *, include_end=False):
    upper_comparison = "<=" if include_end else "<"
    return [dict(row) for row in conn.execute(f"""
        SELECT r.sender_did, min(julianday(r.retrieved_at)) AS first_observation_jd,
               strftime('%Y-%m-%dT%H:%M:%fZ',min(julianday(r.retrieved_at))) AS first_network_seen_at,
               min(r.created_at) AS first_local_schema_insert_at
        FROM raw_network_records r
        WHERE {OBSERVED} AND r.sender_did LIKE 'did:key:%'
          AND NOT EXISTS (SELECT 1 FROM raw_network_records history
                          WHERE history.sender_did=r.sender_did AND history.legacy_record=1)
        GROUP BY r.sender_did
        HAVING min(julianday(r.retrieved_at))>=julianday(?)
           AND min(julianday(r.retrieved_at)){upper_comparison}julianday(?)
        ORDER BY r.sender_did
        """, (start,end))]


def metrics(conn, db_path=None):
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if 'evidence_schema' not in tables:
        return {'status':'MIGRATION_REQUIRED', 'network_reads':0}
    count = lambda sql, params=(): conn.execute(sql,params).fetchone()[0]
    current = datetime.now(timezone.utc)
    cutoff = (current-timedelta(days=1)).isoformat()
    upper = current.isoformat()
    result = dict(conn.execute('SELECT name,value FROM evidence_metrics'))
    result.update(raw_records=count('SELECT count(*) FROM raw_network_records'),
        parsed_events=count('SELECT count(*) FROM observed_events'),
        events_last_hour=count(f"SELECT count(*) FROM observed_events e JOIN raw_network_records r USING(raw_record_id) WHERE {OBSERVED} AND julianday(r.retrieved_at)>=julianday(?) AND julianday(r.retrieved_at)<=julianday(?)",((current-timedelta(hours=1)).isoformat(),upper)),
        events_last_24h=count(f"SELECT count(*) FROM observed_events e JOIN raw_network_records r USING(raw_record_id) WHERE {OBSERVED} AND julianday(r.retrieved_at)>=julianday(?) AND julianday(r.retrieved_at)<=julianday(?)",(cutoff,upper)),
        new_dids_last_24h=len(first_observed_dids(conn,cutoff,upper,include_end=True)),
        signature_verified=count("SELECT count(*) FROM raw_network_records WHERE signature_status='VERIFIED_OFFLINE'"),
        signature_failures=count("SELECT count(*) FROM raw_network_records WHERE signature_status='FAILED'"),
        did_mismatches=count('SELECT count(*) FROM raw_network_records WHERE did_mismatch=1'),
        malformed_records=count("SELECT count(*) FROM observed_events WHERE parse_status='MALFORMED'"),
        template_variants=count("SELECT count(*) FROM observed_events WHERE duplicate_kind='TEMPLATE_VARIANT'"),
        watch_collections_active=count('SELECT count(*) FROM watch_collections WHERE enabled=1'), network_reads=0)
    result['total_persisted_records'] = result['raw_records']
    result['records_ingested_scope'] = 'cumulative raw inserts, including migration; not soak activity'
    result['live_records_ingested'] = count(f'SELECT count(*) FROM raw_network_records r WHERE {OBSERVED}')
    result['live_records_ingested_scope'] = 'non-legacy COMPLETE captures, including targeted reads; not restricted to poll cycles'
    result['activity_time_basis'] = 'retrieved_at of non-legacy COMPLETE records; windows exclude future timestamps'
    result['db_size_bytes'] = Path(db_path).stat().st_size if db_path and Path(db_path).exists() else None
    result['wal_size_bytes'] = Path(str(db_path)+'-wal').stat().st_size if db_path and Path(str(db_path)+'-wal').exists() else 0
    result['cursors'] = dict(conn.execute("SELECT key,value FROM service_state WHERE key LIKE 'cursor:%'")) if 'service_state' in tables else {}
    cycles = conn.execute('SELECT * FROM evidence_poll_cycles ORDER BY id DESC LIMIT 1').fetchone()
    result['last_cycle'] = dict(cycles) if cycles else None
    for key, condition in (('last_successful_poll',"status='SUCCESS'"),('last_read_failure',"status='READ_FAILED'")):
        result[key] = count('SELECT max(finished_at) FROM evidence_poll_cycles WHERE '+condition)
    result['backlog_remaining'] = any(v == 'CATCHING_UP' for v in result['cursors'].values())
    result['soak'] = {'start_timestamp':count('SELECT min(started_at) FROM evidence_poll_cycles'),
        'poll_cycles':count('SELECT count(*) FROM evidence_poll_cycles'),
        'successful_cycles':count("SELECT count(*) FROM evidence_poll_cycles WHERE status='SUCCESS'"),
        'failed_cycles':count("SELECT count(*) FROM evidence_poll_cycles WHERE status NOT IN ('SUCCESS','RUNNING')"),
        'incomplete_cycles':count("SELECT count(*) FROM evidence_poll_cycles WHERE status='RUNNING'")}
    start = result['soak']['start_timestamp']
    result['soak']['runtime_seconds'] = (datetime.now(timezone.utc)-datetime.fromisoformat(start)).total_seconds() if start else 0
    result['safety_scope'] = 'local observation code counters; not a host-wide audit'
    return result


def daily(conn, date=None):
    date = date or datetime.now(timezone.utc).date().isoformat()
    start = datetime.strptime(date,'%Y-%m-%d').replace(tzinfo=timezone.utc)
    end = start+timedelta(days=1)
    args = (start.isoformat(),end.isoformat())
    result = {'date':date,'timezone':'UTC','network_reads':0,
              'activity_time_basis':'retrieved_at of non-legacy COMPLETE records; legacy excluded'}
    rows = conn.execute(f'''SELECT e.*,r.retrieved_at,r.did_mismatch,r.raw_text,r.generation FROM observed_events e
        JOIN raw_network_records r USING(raw_record_id) WHERE {OBSERVED} AND julianday(r.retrieved_at)>=julianday(?) AND julianday(r.retrieved_at)<julianday(?)''',args).fetchall()
    result['classifications'] = {}
    result['watch_changes'] = {r[0]:0 for r in conn.execute('SELECT name FROM watch_collections')}
    result['duplicates'] = {'exact_reposts':0,'template_variants':0,'rereads':conn.execute(f'SELECT count(*) FROM evidence_retrievals x JOIN raw_network_records r USING(raw_record_id) WHERE {OBSERVED} AND julianday(x.retrieved_at)>=julianday(?) AND julianday(x.retrieved_at)<julianday(?)',args).fetchone()[0]}
    result['malformed'] = result['signature_failures'] = result['did_mismatches'] = 0
    result['tclk'] = {'transcript_events':0,'offers':0,'malformed_frames':0,'settlement_rail_claims':0,'executed_actions':0}
    groups = {}
    for row in rows:
        cls = row['classification']
        result['classifications'][cls] = result['classifications'].get(cls,0)+1
        result['malformed'] += row['parse_status']=='MALFORMED'
        result['signature_failures'] += row['signature_status']=='FAILED'
        result['did_mismatches'] += row['did_mismatch']
        if row['duplicate_kind']=='EXACT_DUPLICATE': result['duplicates']['exact_reposts'] += 1
        if row['duplicate_kind']=='TEMPLATE_VARIANT': result['duplicates']['template_variants'] += 1
        if row['duplicate_group_id']: groups[row['duplicate_group_id']] = groups.get(row['duplicate_group_id'],0)+1
        for member in conn.execute('SELECT collection FROM raw_record_watch_membership WHERE raw_record_id=?',(row['raw_record_id'],)):
            result['watch_changes'][member[0]] += 1
        payload = json.loads(row['structured_payload_json'])
        result['tclk']['transcript_events'] += cls=='TCLK_TRANSCRIPT_EVENT'
        result['tclk']['offers'] += payload.get('frame',{}).get('type')=='offer'
        result['tclk']['malformed_frames'] += bool((row['raw_text'] or '').startswith('tclk1 ') and row['parse_status']=='MALFORMED')
        result['tclk']['settlement_rail_claims'] += bool(payload.get('external_rail_claim') or cls=='EXTERNAL_RAIL_CLAIM')
    result['duplicates']['top_groups'] = sorted(groups.items(),key=lambda x:(-x[1],x[0]))[:10]
    result['new_dids'] = first_observed_dids(conn,*args)
    for item in result['new_dids']:
        item['first_seen'] = item['first_network_seen_at']  # compatible output alias
        item['first_seen_rooms'] = [r[0] for r in conn.execute(
            f"SELECT DISTINCT r.room FROM raw_network_records r WHERE {OBSERVED} AND r.sender_did=? AND julianday(r.retrieved_at)=? ORDER BY r.room",
            (item['sender_did'],item.pop('first_observation_jd')))]
    result['new_did_count'] = len(result['new_dids'])
    result['useful_work'] = {k:result['classifications'].get(k,0) for k in ('WORK_REQUEST','WORK_ACCEPTANCE','WORK_RESULT','VERIFICATION_RESULT')}
    result['provenance_conflicts'] = conn.execute(f'''SELECT count(*) FROM (SELECT source,room,generation,seq FROM raw_network_records r
        WHERE {OBSERVED} AND seq IS NOT NULL GROUP BY source,room,generation,seq HAVING count(DISTINCT raw_text_sha256)>1 AND max(julianday(retrieved_at))>=julianday(?) AND max(julianday(retrieved_at))<julianday(?))''',args).fetchone()[0]
    result['safety'] = {k:v for k,v in conn.execute('SELECT name,value FROM evidence_metrics') if k in SAFETY_KEYS}
    result['safety_scope'] = 'cumulative observation counters since migration; daily network reads=0'
    return result


# Compatibility tables remain local indexes; consumers use observed_events.
# These links make their retained source material auditable as well.
COMPAT_TEXT = {'messages':'text','evidence_records':'text','tclk_frames':'raw_text',
               'kibble_events':'exact_text','opportunities':'message_text',
               'validation_response_candidates':'bounded_text'}


def compatibility_links(conn, verify):
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    conn.execute('''CREATE TABLE IF NOT EXISTS compatibility_evidence_links(
        cache_table TEXT NOT NULL, cache_rowid INTEGER NOT NULL, raw_record_id TEXT NOT NULL,
        raw_text_sha256 TEXT NOT NULL, PRIMARY KEY(cache_table,cache_rowid),
        FOREIGN KEY(raw_record_id,raw_text_sha256) REFERENCES raw_network_records(raw_record_id,raw_text_sha256))''')
    for table, column in COMPAT_TEXT.items():
        if table not in tables:
            continue
        columns = {r[1] for r in conn.execute(f'PRAGMA table_info({table})')}
        generation_clause = " AND (r.generation=NEW.generation OR r.reported_generation=NEW.generation OR (r.generation IS NULL AND NEW.generation IN ('UNKNOWN_LEGACY','GENERATION_MISSING')))" if 'generation' in columns else ''
        for row in conn.execute(f'SELECT rowid AS cache_id,* FROM {table}'):
            row = dict(row)
            match_column = 'raw_text_sha256' if table == 'validation_response_candidates' else 'raw_text'
            match_value = row['message_hash'] if table == 'validation_response_candidates' else row[column]
            found = conn.execute(f'SELECT raw_record_id,raw_text_sha256 FROM raw_network_records WHERE room=? AND seq=? AND {match_column}=? ORDER BY legacy_record,created_at LIMIT 1',(row['room'],row['seq'],match_value)).fetchone()
            if found is None:
                raw = {'seq':row['seq'],'text':row[column]}
                for key, candidates in {'did':('did','sender_did','transport_did','sender'),'nonce':('nonce',),'sig':('sig','signature'),'ts':('server_timestamp','timestamp')}.items():
                    for candidate in candidates:
                        if candidate in row:
                            raw[key] = row[candidate]
                            break
                rid = ingest(conn,row['room'],raw,verify,source='legacy_'+table,legacy=True,reported_generation=row.get('generation'))
                found = conn.execute('SELECT raw_record_id,raw_text_sha256 FROM raw_network_records WHERE raw_record_id=?',(rid,)).fetchone()
            conn.execute('INSERT OR IGNORE INTO compatibility_evidence_links VALUES (?,?,?,?)',(table,row['cache_id'],*found))
        # Table names and columns are a fixed local allowlist, never remote identifiers.
        text_match = 'r.raw_text_sha256=NEW.message_hash' if table == 'validation_response_candidates' else f'r.raw_text=NEW.{column}'
        conn.execute(f'''CREATE TRIGGER IF NOT EXISTS link_{table}_insert AFTER INSERT ON {table}
            BEGIN INSERT OR REPLACE INTO compatibility_evidence_links
            SELECT '{table}',NEW.rowid,r.raw_record_id,r.raw_text_sha256 FROM raw_network_records r
            WHERE r.room=NEW.room AND r.seq=NEW.seq AND {text_match}{generation_clause}
            ORDER BY r.legacy_record,r.created_at LIMIT 1; END''')
        conn.execute(f'''CREATE TRIGGER IF NOT EXISTS link_{table}_delete AFTER DELETE ON {table}
            BEGIN DELETE FROM compatibility_evidence_links WHERE cache_table='{table}' AND cache_rowid=OLD.rowid; END''')
