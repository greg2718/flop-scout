"""LG1 source proof and audit-only representation. No network or implicit paths."""
from scout_projection_contract import *

CACHE_TEXT = {'messages':'text', 'evidence_records':'text', 'tclk_frames':'raw_text',
              'kibble_events':'exact_text', 'opportunities':'message_text',
              'validation_response_candidates':'bounded_text'}
REPORT_TABLES = {'evidence_records', 'tclk_frames', 'kibble_events'}


class LegacyGenerationError(ProjectionError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)  # Never include remote text, identities or signatures.


def check(ok, code='LG1_INVALID_LINKAGE'):
    if not ok: raise LegacyGenerationError(code)


def binding(raw, table, record):
    check(table in CACHE_TEXT)
    check(record.get('room') == raw['room'] and type(record.get('seq')) is int and record['seq'] == raw['seq'])
    value = record.get(CACHE_TEXT[table])
    if table == 'validation_response_candidates':
        check(record.get('message_hash') == raw['raw_text_sha256'])
    else:
        check(value == raw['raw_text'] and text_hash(value) == raw['raw_text_sha256'])
    for key in ('message_hash', 'frame_hash'):
        if key in record: check(record[key] == raw['raw_text_sha256'])
    sender_key = next((k for k in ('did','sender_did','transport_did','sender') if k in record), None)
    # Schema absence is not agreement; an available identity assertion must bind.
    if sender_key:
        check(record[sender_key] is not None and record[sender_key] == raw['sender_did'])
    for key, raw_key in [('sig','signature'),('signature','signature'),('server_timestamp','network_timestamp'),('timestamp','network_timestamp')]:
        if key in record: check(record[key] == raw[raw_key])
    if 'nonce' in record:
        value = record['nonce']; original = raw['nonce']
        check(value is None and original is None or type(value) is int and type(original) is str and re.fullmatch('[0-9]+',original) and value == int(original))
    if 'source_endpoint' in record: check(record['source_endpoint'] is None,'LG1_INCOMPATIBLE_LINEAGE')
    if table == 'evidence_records':
        check(record.get('source') == 'service-poll', 'LG1_UNSUPPORTED_LEGACY')
        envelope = loads(record['raw_record_json'])
        check(envelope == loads(raw['raw_record_json']))
    return record


def from_originals(originals):
    """Reconstruct the exact public object from retained, unmodified source rows."""
    keys(originals, {'raw','event','cache_records'})
    raw = originals['raw']; event = originals['event']
    check(type(raw) is dict and type(event) is dict)
    check(raw.get('generation') in (None,'UNKNOWN_LEGACY') and raw.get('source') == 'legacy_evidence'
          and type(raw.get('legacy_record')) is int and raw['legacy_record'] == 1
          and raw.get('raw_completeness') == 'PARTIAL' and raw.get('ingestion_schema') == 'flop-scout-evidence/v1'
          and (type(raw.get('ingestion_version')) is int and raw['ingestion_version'] == 1 or raw.get('ingestion_version') == '1'), 'LG1_UNSUPPORTED_LEGACY')
    report = raw.get('reported_generation')
    check(type(report) is str and report in ('0','1'), 'LG1_UNSUPPORTED_LEGACY')
    check(raw.get('source_endpoint') is None, 'LG1_INCOMPATIBLE_LINEAGE')
    metadata = loads(raw['transport_metadata_json'])
    check(type(metadata) is dict and set(metadata) <= {'envelope_serialization','hash_basis'}, 'LG1_INCOMPATIBLE_LINEAGE')
    if 'envelope_serialization' in metadata:
        check(metadata['envelope_serialization'] == 'reconstructed JSON; signed text unchanged', 'LG1_UNSUPPORTED_LEGACY')
    if 'hash_basis' in metadata: check(metadata['hash_basis'] == 'raw_text_utf8')
    sha(raw['raw_record_id']); sha(raw['raw_text_sha256'])
    check(type(raw['raw_text']) is str and text_hash(raw['raw_text']) == raw['raw_text_sha256'])
    envelope = loads(raw['raw_record_json'])
    check(type(envelope) is dict and envelope.get('text') == raw['raw_text'])
    import scout_evidence
    check(scout_evidence.raw_identity(raw['source'],raw['room'],raw['generation'],report,envelope) == raw['raw_record_id'])
    check(event.get('raw_record_id') == raw['raw_record_id'] and event.get('raw_text_sha256') == raw['raw_text_sha256'])
    check(type(event.get('event_id')) is int and event['event_id'] >= 0)
    # Bind normalized raw columns to their immutable original envelope as well.
    check(type(envelope.get('seq')) is int and envelope['seq'] == raw['seq'])
    check(envelope.get('did',envelope.get('from')) == raw['sender_did'] and raw['sender_did'] is not None)
    check(envelope.get('sig') == raw['signature'])
    nonce = envelope.get('nonce')
    check((None if nonce is None else str(nonce)) == raw['nonce'] and (nonce is None or type(nonce) in (str,int)))
    stamp = envelope.get('ts',envelope.get('timestamp',envelope.get('time')))
    check((None if stamp is None else str(stamp)) == raw['network_timestamp'])
    entries = originals['cache_records']; check(type(entries) is list and len(entries) <= 256)
    refs = {}; tables = set()
    for entry in entries:
        keys(entry, {'cache_table','record','raw_text_sha256'})
        table = entry['cache_table']; record = entry['record']
        check(table not in tables, 'LG1_AMBIGUOUS_CACHE'); tables.add(table)
        check(entry['raw_text_sha256'] == raw['raw_text_sha256'])
        binding(raw,table,record)
        if 'generation' not in record: continue
        check(type(record['generation']) is str and record['generation'] == report, 'LG1_GENERATION_CONFLICT')
        check(table in REPORT_TABLES, 'LG1_UNSUPPORTED_LEGACY')
        h = digest(record)
        locator = record['evidence_id'] if table == 'evidence_records' else h
        string(locator)
        ref = dict(cache_table=table, source_record_locator=locator, record_sha256=h, reported_generation=report)
        key = (table,locator)
        check(key not in refs or refs[key] == ref, 'LG1_GENERATION_CONFLICT'); refs[key] = ref
    check('evidence_records' in tables, 'LG1_UNSUPPORTED_LEGACY')
    result = dict(LEGACY_FIXED, captured_generation='UNKNOWN_LEGACY', reported_generation=report,
                  raw_record_id=raw['raw_record_id'], raw_text_sha256=raw['raw_text_sha256'],
                  linked_cache_records=sorted(refs.values(),key=canonical))
    validate_legacy_annotation(result)
    return result


def _source_proof(conn, raw, prepared=None):
    """Check full link set and alternative identities at the source's read cut."""
    check(prepared is None or prepared.conn is conn)
    links = prepared.links.get(raw['raw_record_id'],[]) if prepared is not None else conn.execute('SELECT cache_table,cache_rowid,raw_text_sha256 FROM compatibility_evidence_links WHERE raw_record_id=? ORDER BY cache_table,cache_rowid',(raw['raw_record_id'],)).fetchmany(257)
    check(len(links)<=256,'LG1_LINK_BOUND_EXCEEDED')
    records = []
    for link in links:
        table = link['cache_table']; check(table in CACHE_TEXT, 'LG1_UNSUPPORTED_LEGACY')
        row = prepared.records.get((table,link['cache_rowid'])) if prepared is not None else conn.execute('SELECT * FROM '+table+' WHERE rowid=?',(link['cache_rowid'],)).fetchone()
        check(row is not None)
        records.append(dict(cache_table=table,record=dict(row),raw_text_sha256=link['raw_text_sha256']))
    reports = {r['record'].get('generation') for r in records if r['record'].get('generation') not in (None,'UNKNOWN_LEGACY','GENERATION_MISSING','')}
    if raw.get('reported_generation') not in (None,'UNKNOWN_LEGACY','GENERATION_MISSING',''): reports.add(raw['reported_generation'])
    if len(reports) > 1: raise LegacyGenerationError('LG1_GENERATION_CONFLICT')
    check(not (raw['raw_record_id'] in prepared.alternates if prepared is not None else conn.execute('SELECT 1 FROM raw_network_records WHERE room=? AND seq=? AND raw_text_sha256=? AND raw_record_id<>? LIMIT 1',(raw['room'],raw['seq'],raw['raw_text_sha256'],raw['raw_record_id'])).fetchone()), 'LG1_ALTERNATE_RAW')
    # The admitted class had no retrieval proof. Do not infer lineage from a later retrieval.
    check(not (raw['raw_record_id'] in prepared.retrievals if prepared is not None else conn.execute('SELECT 1 FROM evidence_retrievals WHERE raw_record_id=? LIMIT 1',(raw['raw_record_id'],)).fetchone()), 'LG1_INCOMPATIBLE_LINEAGE')
    event = prepared.events.get(raw['raw_record_id']) if prepared is not None else conn.execute('SELECT * FROM observed_events WHERE raw_record_id=?',(raw['raw_record_id'],)).fetchone()
    check(event is not None)
    originals = dict(raw=raw,event=dict(event),cache_records=records)
    return from_originals(originals), originals


def source_proof(conn, raw, prepared=None):
    try:
        return _source_proof(conn, raw, prepared)
    except LegacyGenerationError:
        raise
    except ProjectionError as exc:
        raise LegacyGenerationError('LG1_INVALID_LINKAGE') from exc


def validate_bundle_proof(bundle):
    from scout_projection_compact import logical_audit
    annotation = logical_audit(bundle)
    originals = bundle.get('legacy_generation_originals')
    if annotation is None:
        check(originals is None)
        return
    check(originals is not None)
    check(from_originals(originals) == annotation)
    raw = originals['raw']; event = originals['event']; msg = bundle['message']; prov = bundle['provenance']
    check(msg['generation'] == 'UNKNOWN_LEGACY' and msg['projection_row_id'] == 'sm1:'+raw['raw_record_id'])
    for m,r in [('room','room'),('seq','seq'),('text','raw_text'),('sender','sender_did'),('nonce','nonce'),('sig','signature'),('timestamp','network_timestamp')]:check(msg[m] == raw[r])
    from scout_projection_source import observed_time
    check(bundle['first_observed_at'] == observed_time(raw['created_at']))
    check(prov['source_record_locator'] == raw['raw_record_id'])
    check(prov['raw_record_id'] == raw['raw_record_id'] and prov['source_namespace'] == raw['source'] and prov['scout_event_id'] == str(event['event_id']))
    facts = bundle['facts']
    mismatch = bool(raw['did_mismatch']) or any(r['cache_table']=='tclk_frames' and r['record'].get('transport_binding_status')=='TCLK_DID_MISMATCH' for r in originals['cache_records'])
    if 'tclk_original' in bundle and loads(bundle['provenance']['annotations_json'])['classification'] == 'TCLK_LEGACY_NONCONFORMING':
        from scout_projection_tclk import authenticated_original
        check(authenticated_original(bundle['tclk_original']))
        # Preserve every LG2 raw/cache byte. TL1 separately establishes that a
        # parser's missing-from diagnosis is not contradictory signed authorship.
        mismatch = bool(raw['did_mismatch'])
    check(facts['did_mismatch'] == mismatch)
    evidence = next(r['record'] for r in originals['cache_records'] if r['cache_table']=='evidence_records')
    check(msg['evidence_id'] == evidence['evidence_id'] and msg['verification_status'] == evidence['verification_status'])
    check(facts['signature_failure'] == (raw['signature_status']=='FAILED' or evidence['verification_status']=='INVALID_SIGNATURE'))


def continuity(old, new):
    """Report/class immutability and monotone exact references within LG1."""
    if old is None:
        check(new is None, 'LG1_LATE_CLASS_CHANGE')
        return
    check(new is not None, 'LG1_AUDIT_REMOVAL')
    check({k:v for k,v in old.items() if k!='linked_cache_records'} == {k:v for k,v in new.items() if k!='linked_cache_records'}, 'LG1_GENERATION_CONFLICT')
    before={canonical(r) for r in old['linked_cache_records']}; after={canonical(r) for r in new['linked_cache_records']}
    check(before <= after, 'LG1_AUDIT_REMOVAL')
