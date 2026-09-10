"""A1-LG2 normalized audit storage. Captured authority never changes.

Only bounded logical decoding uses the historical LG1 shape; it is never emitted
in LG2 annotations or copied into LG2 private input versions.
"""
from scout_projection_contract import *

CACHE_KINDS = {1: 'evidence_records', 2: 'tclk_frames', 3: 'kibble_events'}
CACHE_CODES = {v: k for k, v in CACHE_KINDS.items()}


def encode(audit):
    if audit is None: return None
    validate_legacy_annotation(audit)
    return dict(reported_code=int(audit['reported_generation']), witnesses=sorted([
        [CACHE_CODES[r['cache_table']], r['record_sha256'],
         '' if r['source_record_locator'] == r['record_sha256'] else r['source_record_locator']]
        for r in audit['linked_cache_records']]))


def decode(value, message, provenance, base):
    if value is None: return None
    keys(value, {'reported_code', 'witnesses'})
    code = value['reported_code']; rows = value['witnesses']
    require(type(code) is int and code in (0, 1), 'Invalid LG2 reported code')
    require(type(rows) is list and 1 <= len(rows) <= 256, 'Invalid LG2 witness count')
    refs = []
    for row in rows:
        require(type(row) is list and len(row) == 3, 'Invalid LG2 witness shape')
        kind, h, token = row
        require(type(kind) is int and kind in CACHE_KINDS, 'Invalid LG2 cache kind')
        sha(h)
        require(type(token) is str and token != h, 'Noncanonical LG2 locator token')
        if token != '': string(token)
        refs.append(dict(cache_table=CACHE_KINDS[kind], record_sha256=h,
                         source_record_locator=h if token == '' else token,
                         reported_generation=str(code)))
    require(rows == sorted(rows) and len({canonical(r) for r in rows}) == len(rows), 'Unsorted/duplicate LG2 witnesses')
    audit = dict(LEGACY_FIXED, captured_generation='UNKNOWN_LEGACY', reported_generation=str(code),
                 raw_record_id=provenance['raw_record_id'], raw_text_sha256=text_hash(message['text']),
                 linked_cache_records=sorted(refs, key=canonical))
    validate_legacy_annotation(audit, message, provenance)
    require(len(canonical(dict(base, legacy_generation=audit))) <= 65536, 'LG2 logical annotation exceeds limit')
    return audit


def logical_audit(bundle):
    base = loads(bundle['provenance']['annotations_json'], 65536)
    if 'legacy_generation_compact' not in bundle: return base.get('legacy_generation')
    annotations(base, TL1_REVISION if 'tclk_original' in bundle else LG2_REVISION)
    return decode(bundle['legacy_generation_compact'], bundle['message'], bundle['provenance'], base)


def convert_bundle(bundle):
    result = loads(canonical(bundle))
    base = annotations(loads(result['provenance']['annotations_json']), REVISION)
    result['legacy_generation_compact'] = encode(base.pop('legacy_generation'))
    result['provenance']['annotations_json'] = canonical(base).decode()
    return result


def prefix(schema):
    require(schema in ('', 'projection.'), 'Unsupported LG2 database namespace')
    return schema


def read_value(conn, raw_id, schema=''):
    prefix(schema); sha(raw_id); raw = bytes.fromhex(raw_id)
    report = conn.execute('SELECT reported_code FROM '+schema+'legacy_generation_reports WHERE raw_ref=?', (raw,)).fetchone()
    if report is None: return None
    rows = conn.execute('SELECT cache_kind,record_hash,locator FROM '+schema+'legacy_generation_witnesses WHERE raw_ref=? ORDER BY cache_kind,record_hash,locator LIMIT 257', (raw,)).fetchall()
    require(len(rows) <= 256, 'LG2 witness count exceeds limit')
    values = []
    for kind, h, token in rows:
        require(type(h) is bytes and len(h) == 32, 'Invalid LG2 record hash BLOB')
        values.append([kind, h.hex(), token])
    return dict(reported_code=report[0], witnesses=values)


def read_audit(conn, provenance, schema=''):
    if provenance['entity_type'] != 'message': return None
    raw_id = provenance['raw_record_id']
    # Only admitted LG rows require binary raw identity; base A1 provenance can
    # carry another source locator and cannot match any LG2 binary reference.
    if type(raw_id) is not str or re.fullmatch('[0-9a-f]{64}', raw_id) is None: return None
    value = read_value(conn, raw_id, schema)
    if value is None: return None
    message = conn.execute('SELECT * FROM '+prefix(schema)+'messages WHERE projection_row_id=?', (provenance['projection_row_id'],)).fetchone()
    require(message is not None, 'Orphan LG2 report')
    return decode(value, dict(message), dict(provenance), loads(provenance['annotations_json']))


class WriteBatch:
    """Exact prior-state checks plus bounded inserts in the owner's transaction."""
    def __init__(self,conn,bundles):
        require(conn.in_transaction,'LG2 write batch requires a transaction')
        require(len(bundles)<=500,'LG2 write batch exceeds operational bound')
        self.conn=conn;self.values={};self.reports=[];self.witnesses=[]
        raw_ids={b['provenance']['raw_record_id'] for b in bundles if b.get('legacy_generation_compact') is not None}
        refs=[bytes.fromhex(sha(r)) for r in sorted(raw_ids)]
        self.values={r:None for r in raw_ids}
        if not refs:return
        marks=','.join('?' for _ in refs)
        for raw,code in conn.execute('SELECT raw_ref,reported_code FROM projection.legacy_generation_reports WHERE raw_ref IN ('+marks+')',refs):
            self.values[raw.hex()]=dict(reported_code=code,witnesses=[])
        for raw,kind,h,token in conn.execute('SELECT raw_ref,cache_kind,record_hash,locator FROM projection.legacy_generation_witnesses WHERE raw_ref IN ('+marks+') ORDER BY raw_ref,cache_kind,record_hash,locator',refs):
            value=self.values[raw.hex()];require(value is not None,'Orphan LG2 witness')
            require(type(h) is bytes and len(h)==32,'Invalid LG2 record hash BLOB')
            value['witnesses'].append([kind,h.hex(),token])
            require(len(value['witnesses'])<=256,'LG2 witness count exceeds limit')

    def flush(self):
        if self.reports:self.conn.executemany('INSERT INTO projection.legacy_generation_reports(raw_ref,reported_code) VALUES(?,?)',self.reports)
        if self.witnesses:self.conn.executemany('INSERT INTO projection.legacy_generation_witnesses VALUES(?,?,?,?)',self.witnesses)
        self.reports.clear();self.witnesses.clear()


def sync(conn, bundle, schema='projection.', batch=None):
    prefix(schema)
    value = bundle['legacy_generation_compact']; audit = logical_audit(bundle)
    if value is None: return False
    raw_id=audit['raw_record_id'];raw=bytes.fromhex(raw_id)
    if batch is not None:
        require(batch.conn is conn and schema=='projection.' and raw_id in batch.values,'Unbound LG2 write batch')
    old = read_value(conn,raw_id,schema) if batch is None else batch.values[raw_id]
    if old == value: return False
    before=set()
    if old is not None:
        before={canonical(r) for r in old['witnesses']}
        require(old['reported_code'] == value['reported_code'] and before <= {canonical(r) for r in value['witnesses']}, 'LG2 audit removal/conflict')
    reports=[] if old is not None else [(raw,value['reported_code'])]
    witnesses=[(raw,kind,bytes.fromhex(h),token) for kind,h,token in value['witnesses'] if canonical([kind,h,token]) not in before]
    # Only previously checked, genuinely new rows are inserted. Conflicts cannot
    # be hidden behind IGNORE, and unchanged report/witness sets do not write.
    if batch is not None:
        batch.reports.extend(reports);batch.witnesses.extend(witnesses);batch.values[raw_id]=value
    else:
        if reports:conn.executemany('INSERT INTO '+schema+'legacy_generation_reports(raw_ref,reported_code) VALUES(?,?)',reports)
        if witnesses:conn.executemany('INSERT INTO '+schema+'legacy_generation_witnesses VALUES(?,?,?,?)',witnesses)
    return True


def remove(conn, rid, schema='projection.'):
    prefix(schema)
    if not re.fullmatch('sm1:[0-9a-f]{64}', rid): return
    raw = bytes.fromhex(sha(rid[4:]))
    conn.execute('DELETE FROM '+schema+'legacy_generation_witnesses WHERE raw_ref=?', (raw,))
    conn.execute('DELETE FROM '+schema+'legacy_generation_reports WHERE raw_ref=?', (raw,))


def validate_relations(conn, schema=''):
    prefix(schema)
    require(not conn.execute(f'''SELECT r.message_id FROM {schema}legacy_generation_reports r
        LEFT JOIN {schema}messages m ON m.projection_row_id=r.message_id
        LEFT JOIN {schema}source_provenance p ON p.entity_type='message' AND p.projection_row_id=r.message_id
        WHERE m.projection_row_id IS NULL OR p.projection_row_id IS NULL
        OR m.generation<>'UNKNOWN_LEGACY' OR p.raw_record_id IS NOT lower(hex(r.raw_ref)) LIMIT 1''').fetchone(), 'LG2 logical foreign key failure')
    require(not conn.execute(f'''SELECT 1 FROM {schema}legacy_generation_witnesses w LEFT JOIN {schema}legacy_generation_reports r USING(raw_ref) WHERE r.raw_ref IS NULL LIMIT 1''').fetchone(), 'Orphan LG2 witness')


def validate_all(conn, schema=''):
    validate_relations(conn, schema)
    # Keep reports outermost: the generated message_id has no public index.
    # An ordinary inner join can scan all reports once per provenance row.
    for row in conn.execute(f'''SELECT p.* FROM {schema}legacy_generation_reports r CROSS JOIN {schema}source_provenance p ON p.entity_type='message' AND p.projection_row_id=r.message_id'''):
        read_audit(conn, row, schema)


def verify_private(projector):
    """Checks absent reports too: public membership alone cannot prove completeness."""
    conn = projector.conn
    validate_relations(conn, 'projection.')
    for row in conn.execute("SELECT p.* FROM projection.source_provenance p WHERE entity_type='message'"):
        original = projector.bundle(row['projection_row_id'])
        if projector.config['contract_revision'] == TL1_REVISION and projector.get('tl1_activation_pending') == '1' and 'tclk_original' not in original:
            # An explicit migration may be interrupted before its complete-cut
            # remap. Old LG2 originals remain verifiable and cannot be published
            # as TL1 while the activation marker is pending.
            from scout_projection_legacy import validate_bundle_proof
            validate_bundle_proof(original)
        else:
            projector.validate_bundle(original)
        require(logical_audit(original) == read_audit(conn, row, 'projection.'), 'LG2 retained audit differs from replay input')


def statistics(conn, schema=''):
    prefix(schema)
    counts = {'0': 0, '1': 0}
    for code, count in conn.execute(f'SELECT reported_code,count(*) FROM {schema}legacy_generation_reports GROUP BY reported_code'):
        require(type(code) is int and code in (0, 1), 'Invalid LG2 reported code'); counts[str(code)] = count
    report_count = sum(counts.values())
    witness_count, max_count = conn.execute(f'SELECT coalesce(sum(n),0),coalesce(max(n),0) FROM (SELECT count(*) n FROM {schema}legacy_generation_witnesses GROUP BY raw_ref)').fetchone()
    histogram = dict(conn.execute(f"SELECT length(CAST(CASE WHEN locator='' THEN lower(hex(record_hash)) ELSE locator END AS BLOB)),count(*) FROM {schema}legacy_generation_witnesses GROUP BY 1"))
    def percentile(q):
        target = math.ceil(witness_count*q); cumulative = 0
        for size, n in sorted(histogram.items()):
            cumulative += n
            if cumulative >= target: return size
        return 0
    return dict(contract_revision=LG2_REVISION, legacy_generation_encoding=LG2_ENCODING,
                non_authoritative_report_counts=counts, report_count=report_count, witness_count=witness_count,
                average_witnesses_per_report=witness_count/report_count if report_count else 0,
                max_witnesses_per_report=max_count,
                average_locator_bytes=sum(k*v for k,v in histogram.items())/witness_count if witness_count else 0,
                p50_locator_bytes=percentile(.5), p95_locator_bytes=percentile(.95), max_locator_bytes=max(histogram, default=0))


def validate_schema(conn, schema='', revision=LG2_REVISION):
    prefix(schema)
    reference=sqlite3.connect(':memory:')
    try:
        require(revision in (LG2_REVISION, TL1_REVISION), 'Unsupported compact schema revision')
        reference.executescript(sql_for(revision))
        query="SELECT type,name,tbl_name,sql FROM {}sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
        require([tuple(r) for r in conn.execute(query.format(schema))]==[tuple(r) for r in reference.execute(query.format(''))],'Exact LG2 schema required')
        for table in tables_for(revision):
            require([tuple(r) for r in conn.execute('PRAGMA '+schema+'table_xinfo('+table+')')]==[tuple(r) for r in reference.execute('PRAGMA table_xinfo('+table+')')],'Exact LG2 generated columns required')
    finally:reference.close()
