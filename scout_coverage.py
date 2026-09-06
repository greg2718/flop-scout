"""Coverage and export provenance. Local bookkeeping; network transport lives in Scout."""
from __future__ import annotations
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
import scout_evidence as ev

CONTRACT = 'technocore-room-local-consecutive/v1'
MAX_EXPORT_BYTES = 32 * 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024
MAX_EXPORT_RECORDS = 100000
BATCH_SIZE = 200
DDL = '''
CREATE TABLE IF NOT EXISTS source_coverage_state(
 source TEXT NOT NULL, room TEXT NOT NULL, generation TEXT NOT NULL,
 coverage_cursor INTEGER NOT NULL, observed_high_water INTEGER NOT NULL,
 server_tail_high_water INTEGER, coverage_status TEXT NOT NULL,
 backfill_required INTEGER NOT NULL, backfill_from_seq INTEGER, backfill_to_seq INTEGER,
 last_checked_at TEXT, last_backfill_at TEXT, last_backfill_result TEXT,
 origin_unknown INTEGER NOT NULL DEFAULT 0,
 PRIMARY KEY(room,generation));
CREATE TABLE IF NOT EXISTS evidence_export_snapshots(
 snapshot_id TEXT PRIMARY KEY, room TEXT NOT NULL, generation TEXT NOT NULL,
 source_endpoint TEXT NOT NULL, sha256 TEXT NOT NULL, path TEXT NOT NULL,
 retrieved_at TEXT NOT NULL, record_count INTEGER NOT NULL, first_seq INTEGER,
 last_seq INTEGER, consecutive INTEGER NOT NULL, processed_records INTEGER NOT NULL DEFAULT 0,
 status TEXT NOT NULL DEFAULT 'VALIDATED', metadata_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS evidence_retention_losses(
 loss_id TEXT PRIMARY KEY, room TEXT NOT NULL, generation TEXT NOT NULL,
 last_durable_seq INTEGER NOT NULL, first_available_seq INTEGER NOT NULL,
 snapshot_id TEXT NOT NULL REFERENCES evidence_export_snapshots(snapshot_id),
 detected_at TEXT NOT NULL, gap_type TEXT NOT NULL,
 sequence_contract TEXT NOT NULL, first_raw_id TEXT NOT NULL REFERENCES raw_network_records(raw_record_id));
CREATE TABLE IF NOT EXISTS evidence_gap_reassessments(
 reassessment_id TEXT PRIMARY KEY, gap_id TEXT NOT NULL REFERENCES evidence_source_gaps(gap_id),
 assessed_at TEXT NOT NULL, assessment TEXT NOT NULL, reason TEXT NOT NULL,
 evidence_source TEXT NOT NULL, evidence_endpoint TEXT NOT NULL, evidence_hash TEXT NOT NULL,
 snapshot_id TEXT NOT NULL REFERENCES evidence_export_snapshots(snapshot_id), metadata_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS evidence_coverage_events(
 event_id INTEGER PRIMARY KEY, room TEXT NOT NULL, generation TEXT NOT NULL,
 kind TEXT NOT NULL, created_at TEXT NOT NULL, details_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS evidence_room_health(
 room TEXT PRIMARY KEY, last_poll_at TEXT, poll_duration REAL, effective_rate REAL,
 next_due TEXT, failures INTEGER NOT NULL DEFAULT 0, last_error TEXT);
'''


def install_schema(conn):
    if conn.execute('SELECT 1 FROM evidence_schema WHERE version=3').fetchone():
        return
    with conn:
        statement = ''
        for line in DDL.splitlines(True):
            statement += line
            if sqlite3.complete_statement(statement):
                conn.execute(statement); statement = ''
        for table in ('evidence_retention_losses', 'evidence_gap_reassessments', 'evidence_coverage_events'):
            for action in ('UPDATE', 'DELETE'):
                conn.execute(f"CREATE TRIGGER IF NOT EXISTS {table}_no_{action} BEFORE {action} ON {table} BEGIN SELECT RAISE(ABORT,'provenance is immutable'); END")
            conn.execute(f"CREATE TRIGGER IF NOT EXISTS {table}_no_replace BEFORE INSERT ON {table} WHEN EXISTS(SELECT 1 FROM {table} WHERE rowid=NEW.rowid) BEGIN SELECT RAISE(IGNORE); END")
        # Prevent REPLACE from deleting immutable rows via their text primary key.
        for table, key in [('evidence_retention_losses','loss_id'),('evidence_gap_reassessments','reassessment_id')]:
            conn.execute(f"CREATE TRIGGER IF NOT EXISTS {table}_identity BEFORE INSERT ON {table} WHEN EXISTS(SELECT 1 FROM {table} WHERE {key}=NEW.{key}) BEGIN SELECT RAISE(IGNORE); END")
        conn.execute("""CREATE TRIGGER IF NOT EXISTS snapshot_facts_immutable BEFORE UPDATE ON evidence_export_snapshots
            WHEN OLD.snapshot_id IS NOT NEW.snapshot_id OR OLD.room IS NOT NEW.room OR OLD.generation IS NOT NEW.generation
            OR OLD.source_endpoint IS NOT NEW.source_endpoint OR OLD.sha256 IS NOT NEW.sha256 OR OLD.path IS NOT NEW.path
            OR OLD.retrieved_at IS NOT NEW.retrieved_at OR OLD.record_count IS NOT NEW.record_count
            OR OLD.first_seq IS NOT NEW.first_seq OR OLD.last_seq IS NOT NEW.last_seq OR OLD.consecutive IS NOT NEW.consecutive
            OR OLD.metadata_json IS NOT NEW.metadata_json OR NEW.processed_records<OLD.processed_records
            OR NEW.processed_records>OLD.record_count
            BEGIN SELECT RAISE(ABORT,'snapshot provenance/checkpoint protected'); END""")
        conn.execute("CREATE TRIGGER IF NOT EXISTS snapshot_no_delete BEFORE DELETE ON evidence_export_snapshots BEGIN SELECT RAISE(ABORT,'snapshot provenance protected'); END")
        conn.execute("CREATE TRIGGER IF NOT EXISTS snapshot_no_replace BEFORE INSERT ON evidence_export_snapshots WHEN EXISTS(SELECT 1 FROM evidence_export_snapshots WHERE snapshot_id=NEW.snapshot_id) BEGIN SELECT RAISE(IGNORE); END")
        conn.execute('INSERT INTO evidence_schema VALUES (3,?)', (ev.now(),))


def initialize(conn):
    import scout_schema
    if conn.execute('SELECT 1 FROM evidence_schema WHERE version=3').fetchone():
        scout_schema.reconcile(conn)
    else:
        install_schema(conn)
        scout_schema.reconcile(conn)


def source(room):
    return 'technocore_mailbox' if room.startswith('mb-') else 'technocore_room'


def state(conn, room, generation, seed=0):
    gen = str(generation) if generation is not None else 'GENERATION_MISSING'
    row = conn.execute('SELECT * FROM source_coverage_state WHERE room=? AND generation=?',(room,gen)).fetchone()
    if row is None:
        # Old gap recovery advanced a high-water mark, not proven coverage. Do
        # not grandfather those jumps into the new coverage model.
        gap = conn.execute('SELECT min(last_durable_seq) FROM evidence_source_gaps WHERE room=? AND generation=?',(room,gen)).fetchone()[0]
        cursor = min(seed,gap) if gap is not None else seed
        pending = cursor < seed
        with conn:
            conn.execute('INSERT INTO source_coverage_state VALUES (?,?,?,?,?,?,?,?,?,?,NULL,NULL,NULL,0)',
                (source(room),room,gen,cursor,seed,None,'BACKFILL_REQUIRED' if pending else 'UNRESOLVED',int(pending),cursor+1 if pending else None,seed if pending else None))
        row = conn.execute('SELECT * FROM source_coverage_state WHERE room=? AND generation=?',(room,gen)).fetchone()
    return dict(row)


def event(conn, room, generation, kind, details):
    conn.execute('INSERT INTO evidence_coverage_events(room,generation,kind,created_at,details_json) VALUES (?,?,?,?,?)',
        (room,str(generation),kind,ev.now(),ev.dumps(details)))


def contiguous(conn, room, generation, cursor):
    # Streaming distinct positions; duplicates/conflicts never imply extra coverage.
    rows = conn.execute('''SELECT DISTINCT r.seq FROM raw_network_records r
        JOIN observed_events e USING(raw_record_id,raw_text_sha256)
        WHERE r.source=? AND r.room=? AND r.generation=? AND r.seq>?
        AND r.raw_completeness='COMPLETE' ORDER BY r.seq''',(source(room),room,str(generation),cursor))
    for row in rows:
        if row[0] != cursor+1:
            break
        cursor = row[0]
    return cursor


def save_tail(conn, room, generation, seed, high, server, *, ambiguous=False):
    current = state(conn,room,generation,seed)
    old = current['coverage_cursor']
    observed = max(current['observed_high_water'],high or 0)
    cursor = old if ambiguous else contiguous(conn,room,generation,old)
    pending = cursor < max(observed,server or 0)
    status = 'UNRESOLVED' if ambiguous else ('BACKFILL_REQUIRED' if pending else 'CURRENT')
    with conn:
        conn.execute('''UPDATE source_coverage_state SET coverage_cursor=?,observed_high_water=?,
            server_tail_high_water=?,coverage_status=?,backfill_required=?,backfill_from_seq=?,
            backfill_to_seq=?,last_checked_at=?,origin_unknown=? WHERE room=? AND generation=?''',
            (cursor,observed,server,status,int(pending or ambiguous),cursor+1 if pending else None,
             max(observed,server or 0) if pending else None,ev.now(),int(current['origin_unknown'] and cursor==old),room,current['generation']))
        ev.bump(conn,'tail_windows_observed')
        event(conn,room,current['generation'],'TAIL_WINDOW_OBSERVED',{'coverage_cursor':cursor,'observed_high_water':observed,'server_tail_high_water':server})
        if pending and not current['backfill_required']:
            event(conn,room,current['generation'],'BACKFILL_REQUIRED',{'from_seq':cursor+1,'to_seq':max(observed,server or 0)})
    return state(conn,room,generation)


def inspect_export(path, room, generation, endpoint, expected_endpoint, metadata):
    """Validate a fully downloaded bounded JSONL file before any coverage decision."""
    if generation is None or str(generation) in ('GENERATION_MISSING','UNKNOWN_LEGACY'):
        raise ValueError('Export requires an expected generation')
    if endpoint != expected_endpoint:
        raise ValueError('Unexpected export endpoint')
    headers = {k.lower():v for k,v in metadata.get('headers',{}).items()}
    if headers.get('x-room-generation') is None or str(headers['x-room-generation']) != str(generation):
        raise ValueError('Export generation missing or mismatched')
    if metadata.get('generation_conflict'):
        raise ValueError('Export generation conflict')
    size = Path(path).stat().st_size
    if size > MAX_EXPORT_BYTES or not metadata.get('complete'):
        raise ValueError('Export incomplete or oversized')
    length = headers.get('content-length')
    if length is not None and int(length) != size:
        raise ValueError('Export content length mismatch')
    count = 0; first = last = None; consecutive = True; digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        while True:
            line = stream.readline(MAX_LINE_BYTES+1)
            if not line:
                break
            if len(line)>MAX_LINE_BYTES or not line.endswith(b'\n'):
                raise ValueError('Export line oversized or incomplete')
            digest.update(line)
            raw = json.loads(line)
            if not isinstance(raw,dict) or ev.integer(raw.get('seq')) is None:
                raise ValueError('Export record has no valid sequence')
            if raw.get('room',room) != room or str(raw.get('generation',generation)) != str(generation):
                raise ValueError('Export record room/generation mismatch')
            seq = ev.integer(raw['seq'])
            if last is not None and seq <= last:
                raise ValueError('Export ordering invalid')
            if last is not None and seq != last+1:
                consecutive = False
            if first is None: first = seq
            last = seq; count += 1
            if count>MAX_EXPORT_RECORDS:
                raise ValueError('Too many export records')
    sha = digest.hexdigest()
    if metadata.get('sha256',sha)!=sha or metadata.get('bytes',size)!=size:
        raise ValueError('Export differs from captured hash/size')
    sid = ev.digest(ev.dumps([room,str(generation),endpoint,sha]))
    return {'snapshot_id':sid,'room':room,'generation':str(generation),'source_endpoint':endpoint,
        'sha256':sha,'path':str(path),'retrieved_at':metadata.get('retrieved_at',ev.now()),
        'record_count':count,'first_seq':first,'last_seq':last,'consecutive':int(consecutive),
        'metadata_json':ev.dumps(metadata)}


def register_snapshot(conn, snapshot):
    with conn:
        columns = ','.join(snapshot)
        conn.execute(f"INSERT OR IGNORE INTO evidence_export_snapshots({columns}) VALUES ({','.join('?' for _ in snapshot)})",tuple(snapshot.values()))
    return dict(conn.execute('SELECT * FROM evidence_export_snapshots WHERE snapshot_id=?',(snapshot['snapshot_id'],)).fetchone())


def apply_export_steps(conn, snapshot, ingest_batch, *, seed=0, after_batch=None):
    s = register_snapshot(conn,snapshot)
    current = state(conn,s['room'],s['generation'],seed)
    with conn:
        conn.execute("UPDATE source_coverage_state SET coverage_status='BACKFILLING' WHERE room=? AND generation=?",(s['room'],s['generation']))
        ev.bump(conn,'backfills_started')
        event(conn,s['room'],s['generation'],'BACKFILL_STARTED',{'snapshot_id':s['snapshot_id']})
    processed = s['processed_records']
    batch = []
    def persist_batch(batch, position):
        before = conn.execute("SELECT value FROM evidence_metrics WHERE name='records_ingested'").fetchone()[0]
        ingest_batch(batch,s)
        after = conn.execute("SELECT value FROM evidence_metrics WHERE name='records_ingested'").fetchone()[0]
        with conn:
            conn.execute('UPDATE evidence_export_snapshots SET processed_records=? WHERE snapshot_id=?',(position,s['snapshot_id']))
            ev.bump(conn,'backfill_records_recovered',after-before)
        if after_batch: after_batch(position)
    with Path(s['path']).open('rb') as stream:
        for position,line in enumerate(stream,1):
            if position<=processed: continue
            batch.append(json.loads(line))
            if len(batch)==BATCH_SIZE:
                persist_batch(batch,position); batch=[]
                yield position
        if batch:
            persist_batch(batch,position)
            yield position
    # Tails may advance this source between export batches. Re-read its state
    # before finalization so an old snapshot cannot overwrite newer high waters.
    current = state(conn,s['room'],s['generation'],seed)
    # All export records/links are now durable. Gapped exports may be useful raw
    # evidence but cannot prove a retention boundary or complete coverage.
    old = current['coverage_cursor']
    cursor = contiguous(conn,s['room'],s['generation'],old)
    loss = None
    if s['consecutive'] and s['first_seq'] is not None and s['first_seq']>old+1 and not current['origin_unknown']:
        loss = ev.digest(ev.dumps([s['room'],s['generation'],old,s['first_seq'],'CONFIRMED_UPSTREAM_RETENTION_LOSS']))
        raw = conn.execute('SELECT r.raw_record_id FROM raw_network_records r JOIN observed_events e USING(raw_record_id,raw_text_sha256) WHERE r.source=? AND r.room=? AND r.generation=? AND r.seq=? LIMIT 1',
            (source(s['room']),s['room'],s['generation'],s['first_seq'])).fetchone()
        if raw is None: raise RuntimeError('Missing recovery evidence')
        with conn:
            conn.execute('INSERT OR IGNORE INTO evidence_retention_losses VALUES (?,?,?,?,?,?,?,?,?,?)',
                (loss,s['room'],s['generation'],old,s['first_seq'],s['snapshot_id'],ev.now(),'CONFIRMED_UPSTREAM_RETENTION_LOSS',CONTRACT,raw[0]))
        cursor = contiguous(conn,s['room'],s['generation'],s['first_seq']-1)
    if current['origin_unknown'] and s['consecutive'] and s['first_seq'] is not None:
        cursor = contiguous(conn,s['room'],s['generation'],s['first_seq']-1)
        with conn:
            event(conn,s['room'],s['generation'],'GENERATION_BASELINE_ESTABLISHED',{'snapshot_id':s['snapshot_id'],'first_retained':s['first_seq']})
    high = max(current['observed_high_water'],s['last_seq'] or 0)
    pending = cursor < max(high,current['server_tail_high_water'] or 0)
    status = 'UNRESOLVED' if pending or not s['consecutive'] or not s['record_count'] else ('CONFIRMED_RETENTION_LOSS' if loss else 'CURRENT_AFTER_BACKFILL')
    with conn:
        conn.execute("UPDATE evidence_export_snapshots SET status='PERSISTED' WHERE snapshot_id=?",(s['snapshot_id'],))
    reassess(conn,s)
    with conn:
        conn.execute('''UPDATE source_coverage_state SET coverage_cursor=?,observed_high_water=?,coverage_status=?,
            backfill_required=?,backfill_from_seq=?,backfill_to_seq=?,last_backfill_at=?,last_backfill_result=?,origin_unknown=?
            WHERE room=? AND generation=?''',(cursor,high,status,int(status=='UNRESOLVED'),cursor+1 if pending else None,
            high if pending else None,ev.now(),status,int(current['origin_unknown'] and status=='UNRESOLVED'),s['room'],s['generation']))
        conn.execute("UPDATE evidence_export_snapshots SET status='PERSISTED' WHERE snapshot_id=?",(s['snapshot_id'],))
        ev.bump(conn,'backfills_completed' if status!='UNRESOLVED' else 'backfills_failed')
        event(conn,s['room'],s['generation'],'BACKFILL_COMPLETED' if status!='UNRESOLVED' else 'BACKFILL_UNRESOLVED',{'snapshot_id':s['snapshot_id'],'coverage_cursor':cursor,'status':status})
    yield state(conn,s['room'],s['generation'])


def apply_export(conn, snapshot, ingest_batch, **kwargs):
    result = None
    for step in apply_export_steps(conn,snapshot,ingest_batch,**kwargs):
        if isinstance(step,dict): result = step
    return result


def reassess(conn, s):
    if s.get('status') != 'PERSISTED':
        stored = conn.execute('SELECT status FROM evidence_export_snapshots WHERE snapshot_id=?',(s['snapshot_id'],)).fetchone()
        if not stored or stored[0]!='PERSISTED': raise ValueError('Reassessment requires persisted export')
    for gap in conn.execute('SELECT * FROM evidence_source_gaps WHERE room=? AND generation=?',(s['room'],s['generation'])).fetchall():
        assessment = 'UNRESOLVED'
        reason = 'Snapshot cannot establish availability of the entire historical interval'
        if s['consecutive'] and s['first_seq'] is not None:
            if s['first_seq']<=gap['last_durable_seq']+1 and s['last_seq']>=gap['first_available_seq']-1:
                assessment = 'FALSE_POSITIVE_TAIL_WINDOW'
                reason = 'Complete export contains the interval previously labeled unavailable'
            elif s['first_seq']>gap['last_durable_seq']+1:
                assessment = 'CONFIRMED_RETENTION_LOSS'
                reason = 'Required history unavailable at export capture time; not proof of unavailability at original detection'
        rid = ev.digest(ev.dumps([gap['gap_id'],s['snapshot_id'],assessment]))
        with conn:
            conn.execute('INSERT OR IGNORE INTO evidence_gap_reassessments VALUES (?,?,?,?,?,?,?,?,?,?)',
                (rid,gap['gap_id'],ev.now(),assessment,reason,'technocore_export',s['source_endpoint'],s['sha256'],s['snapshot_id'],
                 ev.dumps({'availability_as_of':s['retrieved_at'],'original_detection_at':gap['detected_at']})))


def failed(conn, room, generation, error):
    state(conn,room,generation)
    with conn:
        conn.execute("UPDATE source_coverage_state SET coverage_status='UNRESOLVED',backfill_required=1,last_backfill_result=? WHERE room=? AND generation=?",(str(error),room,str(generation)))
        ev.bump(conn,'backfills_failed')
        event(conn,room,generation,'BACKFILL_FAILED',{'error':str(error)})


def tables_present(conn):
    return conn.execute("SELECT 1 FROM sqlite_master WHERE name='source_coverage_state'").fetchone() is not None


def provenance(conn):
    if not tables_present(conn): return
    for table,schema in [('source_coverage_state','flop-scout-coverage/v1'),('evidence_export_snapshots','flop-scout-backfill/v1'),('evidence_retention_losses','flop-scout-confirmed-retention-loss/v1'),('evidence_gap_reassessments','flop-scout-source-gap-reassessment/v1')]:
        for row in conn.execute(f'SELECT * FROM {table}'):
            yield dict(row,schema=schema)


def metrics(conn):
    if not tables_present(conn): return {}
    rows = [dict(r) for r in conn.execute('SELECT * FROM source_coverage_state')]
    key = lambda r: r['source']+'/'+r['room']+'/'+r['generation']
    out = {name:{key(r):r[column] for r in rows} for name,column in [('coverage_cursor_by_source','coverage_cursor'),('observed_high_water_by_source','observed_high_water'),('server_high_water_by_source','server_tail_high_water')]}
    out['coverage_sources'] = rows
    out['backfill_required_sources'] = [key(r) for r in rows if r['backfill_required']]
    out['unresolved_coverage_sources'] = [key(r) for r in rows if r['coverage_status'] in ('UNRESOLVED','BACKFILL_REQUIRED','BACKFILLING')]
    out['confirmed_retention_losses'] = conn.execute('SELECT count(*) FROM evidence_retention_losses').fetchone()[0]
    out['false_positive_gap_reassessments'] = conn.execute("SELECT count(DISTINCT gap_id) FROM evidence_gap_reassessments WHERE assessment='FALSE_POSITIVE_TAIL_WINDOW'").fetchone()[0]
    out['original_gap_detections'] = conn.execute('SELECT count(*) FROM evidence_source_gaps').fetchone()[0]
    for metric in ('backfills_started','backfills_completed','backfills_failed','backfill_records_recovered'):
        row=conn.execute('SELECT value FROM evidence_metrics WHERE name=?',(metric,)).fetchone();out[metric]=row[0] if row else 0
    health=[dict(r) for r in conn.execute('SELECT * FROM evidence_room_health')]
    for label,column in [('per_room_poll_duration','poll_duration'),('per_room_effective_rate','effective_rate'),('per_room_next_due','next_due')]:
        out[label]={r['room']:r[column] for r in health}
    out['per_room_last_poll_age']={r['room']:(datetime.now(timezone.utc)-datetime.fromisoformat(r['last_poll_at'])).total_seconds() if r['last_poll_at'] else None for r in health}
    out['per_room_health']=health
    import scout_worker
    out.update(scout_worker.scheduler_metrics(conn))
    return out


def daily(conn, start, end):
    if not tables_present(conn): return {}
    names={'TAIL WINDOWS OBSERVED':'TAIL_WINDOW_OBSERVED','BACKFILLS REQUIRED':'BACKFILL_REQUIRED','BACKFILLS COMPLETED':'BACKFILL_COMPLETED'}
    out={label:conn.execute('SELECT count(*) FROM evidence_coverage_events WHERE kind=? AND created_at>=? AND created_at<?',(kind,start,end)).fetchone()[0] for label,kind in names.items()}
    out['CONFIRMED RETENTION LOSSES']=conn.execute('SELECT count(*) FROM evidence_retention_losses WHERE detected_at>=? AND detected_at<?',(start,end)).fetchone()[0]
    out['FALSE-POSITIVE HISTORICAL GAP REASSESSMENTS']=conn.execute("SELECT count(*) FROM evidence_gap_reassessments WHERE assessment='FALSE_POSITIVE_TAIL_WINDOW' AND assessed_at>=? AND assessed_at<?",(start,end)).fetchone()[0]
    out['UNRESOLVED COVERAGE']=metrics(conn)['unresolved_coverage_sources']
    return out


def integrity(conn):
    if not tables_present(conn): return 0
    errors=0
    for s in conn.execute('SELECT * FROM evidence_export_snapshots'):
        try:
            checked=inspect_export(s['path'],s['room'],s['generation'],s['source_endpoint'],f"https://technocore.chat/r/{s['room']}/export",json.loads(s['metadata_json']))
            errors+=any(checked[k]!=s[k] for k in ('snapshot_id','sha256','first_seq','last_seq','record_count','consecutive'))
            errors+=s['processed_records']>s['record_count']
            with Path(s['path']).open('rb') as stream:
                for index,line in enumerate(stream):
                    if index>=s['processed_records']: break
                    raw=json.loads(line)
                    rid=ev.raw_identity(source(s['room']),s['room'],s['generation'],None,raw)
                    errors+=not bool(conn.execute('SELECT 1 FROM raw_network_records JOIN observed_events USING(raw_record_id,raw_text_sha256) WHERE raw_record_id=?',(rid,)).fetchone())
        except (OSError,ValueError,TypeError,RecursionError): errors+=1
    for loss in conn.execute('SELECT l.*,s.first_seq,s.consecutive,s.room AS sr,s.generation AS sg,r.room AS rr,r.generation AS rg,r.seq AS rs FROM evidence_retention_losses l LEFT JOIN evidence_export_snapshots s USING(snapshot_id) LEFT JOIN raw_network_records r ON r.raw_record_id=l.first_raw_id'):
        errors+=loss['loss_id']!=ev.digest(ev.dumps([loss['room'],loss['generation'],loss['last_durable_seq'],loss['first_available_seq'],'CONFIRMED_UPSTREAM_RETENTION_LOSS']))
        errors+=loss['sequence_contract']!=CONTRACT
        errors+=not (loss['room']==loss['sr']==loss['rr'] and loss['generation']==loss['sg']==loss['rg'] and loss['first_seq']==loss['first_available_seq']==loss['rs'] and loss['consecutive'] and loss['first_available_seq']>loss['last_durable_seq']+1)
    for row in conn.execute('SELECT a.*,s.sha256,s.source_endpoint,s.room AS sr,s.generation AS sg,g.room AS gr,g.generation AS gg FROM evidence_gap_reassessments a LEFT JOIN evidence_export_snapshots s USING(snapshot_id) LEFT JOIN evidence_source_gaps g USING(gap_id)'):
        errors+=row['reassessment_id']!=ev.digest(ev.dumps([row['gap_id'],row['snapshot_id'],row['assessment']]))
        errors+=not (row['evidence_hash']==row['sha256'] and row['evidence_endpoint']==row['source_endpoint'] and row['sr']==row['gr'] and row['sg']==row['gg'])
    for row in conn.execute('SELECT * FROM source_coverage_state'):
        errors+=row['coverage_cursor']>row['observed_high_water'] or row['coverage_cursor']<0
    return errors
