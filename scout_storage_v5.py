"""Opt-in v5 storage migration for copied Scout databases only."""
import json
import sqlite3
from pathlib import Path

LIVE = Path.home()/'.flop_scout'/'observer.sqlite'

DDL = '''
CREATE TABLE IF NOT EXISTS evidence_records_v2(
 evidence_id TEXT PRIMARY KEY, raw_record_id TEXT NOT NULL, raw_text_sha256 TEXT NOT NULL,
 room TEXT NOT NULL, generation TEXT NOT NULL, seq INTEGER NOT NULL, server_timestamp TEXT,
 did TEXT, nonce INTEGER, sig TEXT, message_hash TEXT NOT NULL, canonical_payload_hash TEXT,
 retrieved_at TEXT NOT NULL, source TEXT NOT NULL, verification_status TEXT NOT NULL,
 FOREIGN KEY(raw_record_id,raw_text_sha256) REFERENCES raw_network_records(raw_record_id,raw_text_sha256),
 UNIQUE(room,generation,seq,evidence_id));
CREATE INDEX IF NOT EXISTS evidence_v2_raw ON evidence_records_v2(raw_record_id,raw_text_sha256);
CREATE VIEW IF NOT EXISTS evidence_records_v2_expanded AS
 SELECT v.*,r.raw_text AS text,r.raw_record_json FROM evidence_records_v2 v
 JOIN raw_network_records r USING(raw_record_id,raw_text_sha256);
CREATE TABLE IF NOT EXISTS evidence_retrieval_state(
 raw_record_id TEXT PRIMARY KEY, raw_text_sha256 TEXT NOT NULL,
 first_retrieved_at TEXT NOT NULL,last_retrieved_at TEXT NOT NULL,
 first_batch_id INTEGER NOT NULL,last_batch_id INTEGER NOT NULL,reread_count INTEGER NOT NULL DEFAULT 0,
 FOREIGN KEY(raw_record_id,raw_text_sha256) REFERENCES raw_network_records(raw_record_id,raw_text_sha256),
 CHECK(reread_count>=0),CHECK(last_retrieved_at>=first_retrieved_at));
CREATE INDEX IF NOT EXISTS retrieval_state_last ON evidence_retrieval_state(last_retrieved_at);
'''

def enabled(conn):
    return bool(conn.execute("SELECT 1 FROM evidence_schema WHERE version=5").fetchone())

def record_reread(conn, raw_record_id, raw_text_sha256, batch_id, retrieved_at):
    """V5-only durable reread aggregation; never writes a REREAD link."""
    conn.execute('''INSERT INTO evidence_retrieval_state
      VALUES (?,?,?,?,?,?,1)
      ON CONFLICT(raw_record_id) DO UPDATE SET last_retrieved_at=excluded.last_retrieved_at,
      last_batch_id=excluded.last_batch_id,reread_count=reread_count+1''',
      (raw_record_id,raw_text_sha256,retrieved_at,retrieved_at,batch_id,batch_id))

def record_observation(conn, raw_record_id, raw_text_sha256, batch_id, retrieved_at, initial):
    """Application write-path hook, gated by the v5 marker."""
    if not enabled(conn):
        conn.execute('INSERT OR IGNORE INTO evidence_retrieval_links(raw_record_id,retrieval_batch_id,relationship_kind) VALUES (?,?,?)',
                     (raw_record_id,batch_id,'INITIAL' if initial else 'REREAD'))
        return
    if initial:
        conn.execute('INSERT OR IGNORE INTO evidence_retrieval_links(raw_record_id,retrieval_batch_id,relationship_kind) VALUES (?,?,\'INITIAL\')',
                     (raw_record_id,batch_id))
        conn.execute('''INSERT OR IGNORE INTO evidence_retrieval_state VALUES (?,?,?,?,?,?,0)''',
                     (raw_record_id,raw_text_sha256,retrieved_at,retrieved_at,batch_id,batch_id))
    else: record_reread(conn,raw_record_id,raw_text_sha256,batch_id,retrieved_at)

def classify(conn):
    sql='''SELECT count(*),coalesce(sum(has_initial=1 AND has_reread=0),0),
      coalesce(sum(has_initial=1 AND has_reread=1),0),coalesce(sum(has_initial=0 AND has_reread=1),0),
      coalesce(sum(has_initial=0 AND has_reread=0),0) FROM (
      SELECT b.id,max(l.relationship_kind='INITIAL') has_initial,max(l.relationship_kind='REREAD') has_reread
      FROM evidence_retrieval_batches b LEFT JOIN evidence_retrieval_links l ON l.retrieval_batch_id=b.id GROUP BY b.id)'''
    total,initial,mixed,reread,orphan=conn.execute(sql).fetchone()
    links=dict(conn.execute("SELECT relationship_kind,count(*) FROM evidence_retrieval_links GROUP BY relationship_kind"))
    return dict(total_batches=total,initial_bearing=initial,mixed=mixed,reread_only=reread,orphan=orphan,
                initial_links=links.get('INITIAL',0),reread_links=links.get('REREAD',0))

def invariants(conn):
    q=lambda sql:conn.execute(sql).fetchone()[0]
    return dict(v2_orphans=q('''SELECT count(*) FROM evidence_records_v2 v LEFT JOIN raw_network_records r
       ON r.raw_record_id=v.raw_record_id AND r.raw_text_sha256=v.raw_text_sha256 WHERE r.raw_record_id IS NULL'''),
      text_mismatches=q('''SELECT count(*) FROM evidence_records e JOIN evidence_records_v2 v USING(evidence_id)
       JOIN raw_network_records r ON r.raw_record_id=v.raw_record_id AND r.raw_text_sha256=v.raw_text_sha256 WHERE e.text IS NOT r.raw_text'''),
      json_mismatches=q('''SELECT count(*) FROM evidence_records e JOIN evidence_records_v2 v USING(evidence_id)
       JOIN raw_network_records r ON r.raw_record_id=v.raw_record_id AND r.raw_text_sha256=v.raw_text_sha256 WHERE e.raw_record_json IS NOT r.raw_record_json'''),
      foreign_key_errors=len(conn.execute('PRAGMA foreign_key_check').fetchall()),
      integrity_check=conn.execute('PRAGMA integrity_check').fetchone()[0])

def report(path):
    with sqlite3.connect(Path(path)) as conn:
        tables={x[0] for x in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        result=dict(title='SCOUT STORAGE V5 DRY RUN',path=str(Path(path).resolve()),mode='DRY_RUN',schema_v5='evidence_records_v2' in tables,
                    canonical_raw_records=conn.execute('SELECT count(*) FROM raw_network_records').fetchone()[0],
                    evidence_records=conn.execute('SELECT count(*) FROM evidence_records').fetchone()[0],retrieval=classify(conn))
        if 'evidence_records_v2' in tables:
            result['invariants']=invariants(conn)
            result['retrieval_state']=dict(rows=conn.execute('SELECT count(*) FROM evidence_retrieval_state').fetchone()[0],
                reread_total=conn.execute('SELECT coalesce(sum(reread_count),0) FROM evidence_retrieval_state').fetchone()[0])
        result['projected_duplicate_payload_bytes']=conn.execute('SELECT coalesce(sum(length(text)+length(raw_record_json)),0) FROM evidence_records').fetchone()[0]
        return result

def migrate(path, apply=False):
    target=Path(path).resolve()
    if target==LIVE.resolve(): raise ValueError('Refusing live production database')
    if not apply:return report(target)
    with sqlite3.connect(target) as conn:
        conn.execute('PRAGMA foreign_keys=ON'); conn.executescript(DDL)
        conn.execute('''INSERT OR IGNORE INTO evidence_records_v2
          SELECT e.evidence_id,r.raw_record_id,r.raw_text_sha256,e.room,e.generation,e.seq,e.server_timestamp,e.did,e.nonce,e.sig,
          e.message_hash,e.canonical_payload_hash,e.retrieved_at,e.source,e.verification_status
          FROM evidence_records e JOIN raw_network_records r ON r.room=e.room AND r.seq=e.seq AND r.raw_text=e.text''')
        conn.execute('''INSERT INTO evidence_retrieval_state
          SELECT l.raw_record_id,r.raw_text_sha256,min(b.retrieved_at),max(b.retrieved_at),min(b.id),max(b.id),
          sum(l.relationship_kind='REREAD') FROM evidence_retrieval_links l JOIN evidence_retrieval_batches b ON b.id=l.retrieval_batch_id
          JOIN raw_network_records r ON r.raw_record_id=l.raw_record_id GROUP BY l.raw_record_id
          ON CONFLICT(raw_record_id) DO NOTHING''')
        conn.execute("INSERT OR IGNORE INTO evidence_schema VALUES (5,datetime('now'))")
    return report(target)

def main(argv=None):
    import argparse
    p=argparse.ArgumentParser();p.add_argument('db',type=Path);p.add_argument('--apply',action='store_true');a=p.parse_args(argv)
    print(json.dumps(migrate(a.db,a.apply),indent=2,sort_keys=True))

if __name__=='__main__':main()
