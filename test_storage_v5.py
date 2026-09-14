import sqlite3
import scout_storage_v5 as v5


def fixture(path):
    c=sqlite3.connect(path);c.executescript('''
    PRAGMA foreign_keys=ON;
    CREATE TABLE evidence_schema(version INTEGER PRIMARY KEY,migrated_at TEXT);
    CREATE TABLE raw_network_records(raw_record_id TEXT PRIMARY KEY,raw_text_sha256 TEXT NOT NULL,room TEXT,seq INTEGER,raw_text TEXT,raw_record_json TEXT,UNIQUE(raw_record_id,raw_text_sha256));
    CREATE TABLE evidence_records(evidence_id TEXT PRIMARY KEY,room TEXT,generation TEXT,seq INTEGER,server_timestamp TEXT,did TEXT,nonce INTEGER,sig TEXT,text TEXT,message_hash TEXT,canonical_payload_hash TEXT,retrieved_at TEXT,source TEXT,verification_status TEXT,raw_record_json TEXT);
    CREATE TABLE evidence_retrieval_batches(id INTEGER PRIMARY KEY,retrieved_at TEXT,source_endpoint TEXT,transport_metadata_json TEXT,envelope_serialization TEXT,hash_basis TEXT);
    CREATE TABLE evidence_retrieval_links(id INTEGER PRIMARY KEY,raw_record_id TEXT,retrieval_batch_id INTEGER,relationship_kind TEXT);
    CREATE TABLE observed_events(raw_record_id TEXT);
    ''')
    c.execute("INSERT INTO raw_network_records VALUES ('r','h','lobby',1,'hello','{\"text\":\"hello\"}')")
    c.execute("INSERT INTO evidence_records VALUES ('e','lobby','0',1,NULL,NULL,NULL,NULL,'hello','h',NULL,'2026-01-01','x','VERIFIED','{\"text\":\"hello\"}')")
    c.executemany("INSERT INTO evidence_retrieval_batches VALUES (?,?,NULL,'{}','x','x')",[(1,'2026-01-01'),(2,'2026-01-02'),(3,'2026-01-03')])
    c.executemany("INSERT INTO evidence_retrieval_links VALUES (?,?,?,?)",[(1,'r',1,'INITIAL'),(2,'r',2,'REREAD'),(3,'r',3,'REREAD')]);c.commit();c.close()


def test_v5_dry_run_and_copy_migration(tmp_path):
    path=tmp_path/'copy.sqlite';fixture(path)
    before=v5.migrate(path)
    assert before['mode']=='DRY_RUN' and not before['schema_v5']
    result=v5.migrate(path,apply=True)
    assert result['schema_v5']
    assert result['retrieval']=={'total_batches':3,'initial_bearing':1,'mixed':0,'reread_only':2,'orphan':0,'initial_links':1,'reread_links':2}
    assert result['invariants']=={'v2_orphans':0,'text_mismatches':0,'json_mismatches':0,'foreign_key_errors':0,'integrity_check':'ok'}
    with sqlite3.connect(path) as c:
        assert c.execute('SELECT reread_count FROM evidence_retrieval_state').fetchone()[0]==2
        assert c.execute('SELECT text,raw_record_json FROM evidence_records_v2_expanded').fetchone()==('hello','{"text":"hello"}')


def test_v5_rereads_are_aggregated_not_linked(tmp_path):
    path=tmp_path/'copy.sqlite';fixture(path);v5.migrate(path,apply=True)
    with sqlite3.connect(path) as c:
        for batch in range(4,104):
            c.execute("INSERT INTO evidence_retrieval_batches VALUES (?,? ,NULL,'{}','x','x')",(batch,f'2026-02-{batch:02d}'))
            v5.record_observation(c,'r','h',batch,f'2026-02-{batch:02d}',False)
        assert c.execute("SELECT count(*) FROM evidence_retrieval_links WHERE relationship_kind='REREAD'").fetchone()[0]==2
        assert c.execute('SELECT reread_count FROM evidence_retrieval_state').fetchone()[0]==102
