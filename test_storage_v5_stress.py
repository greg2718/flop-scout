"""Dedicated 10,000 x 100 v5 bounded-growth regression."""
import sqlite3
import scout_storage_v5 as v5


def test_10000_by_100_rereads_are_bounded(tmp_path):
    path=tmp_path/'stress.sqlite';c=sqlite3.connect(path)
    c.executescript('''CREATE TABLE evidence_schema(version INTEGER PRIMARY KEY,migrated_at TEXT);
    CREATE TABLE raw_network_records(raw_record_id TEXT PRIMARY KEY,raw_text_sha256 TEXT NOT NULL,UNIQUE(raw_record_id,raw_text_sha256));
    CREATE TABLE evidence_retrieval_links(raw_record_id TEXT,retrieval_batch_id INTEGER,relationship_kind TEXT,UNIQUE(raw_record_id,retrieval_batch_id,relationship_kind));'''+v5.DDL)
    c.execute("INSERT INTO evidence_schema VALUES(5,'x')")
    rows=[(f'r{i}',f'h{i}') for i in range(10000)]
    c.executemany('INSERT INTO raw_network_records VALUES (?,?)',rows)
    for rid,h in rows:v5.record_observation(c,rid,h,1,'2026-01-01',True)
    initial_pages=c.execute('PRAGMA page_count').fetchone()[0]
    for cycle in range(100):
        for rid,h in rows:v5.record_observation(c,rid,h,cycle+2,f'2026-02-{cycle:02d}',False)
    c.commit();final_pages=c.execute('PRAGMA page_count').fetchone()[0]
    assert c.execute('SELECT count(*) FROM raw_network_records').fetchone()[0]==10000
    assert c.execute("SELECT count(*) FROM evidence_retrieval_links WHERE relationship_kind='INITIAL'").fetchone()[0]==10000
    assert c.execute("SELECT count(*) FROM evidence_retrieval_links WHERE relationship_kind='REREAD'").fetchone()[0]==0
    assert c.execute('SELECT count(*),sum(reread_count) FROM evidence_retrieval_state').fetchone()==(10000,1000000)
    assert final_pages-initial_pages < 500
