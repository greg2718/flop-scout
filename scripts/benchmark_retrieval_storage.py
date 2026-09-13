"""Local synthetic comparison for duplicated versus batch-normalized retrievals."""
import json
import sqlite3
import tempfile
import time
from pathlib import Path


ROWS = 20_000
PAGE = 200
METADATA = json.dumps({'headers': {'cf-ray': 'x'*32, 'server': 'cloudflare', 'cache-control': 'no-cache', 'vary': 'Accept-Encoding'}, 'status': 200, 'tls': {'version': 'TLSv1.3', 'cipher': 'AES_256_GCM'}, 'request': {'accept': 'application/json'}, 'trace': 'z'*620}, separators=(',', ':'))


def size(path):
    with sqlite3.connect(path) as conn:
        return conn.execute('PRAGMA page_count').fetchone()[0] * conn.execute('PRAGMA page_size').fetchone()[0]


def old(path):
    with sqlite3.connect(path) as conn:
        conn.execute('CREATE TABLE r(raw_record_id TEXT,retrieved_at TEXT,source_endpoint TEXT,transport_metadata_json TEXT)')
        start=time.perf_counter()
        conn.executemany('INSERT INTO r VALUES (?,?,?,?)', ((f'r{i}','2026-09-13T00:00:00+00:00','/r/lobby',METADATA) for i in range(ROWS)))
        conn.commit()
    return time.perf_counter()-start


def normalized(path):
    with sqlite3.connect(path) as conn:
        conn.executescript('CREATE TABLE b(id INTEGER PRIMARY KEY,retrieved_at TEXT,source_endpoint TEXT,metadata TEXT); CREATE TABLE l(raw_record_id TEXT,batch_id INTEGER,kind TEXT);')
        start=time.perf_counter()
        for page in range(ROWS//PAGE):
            batch=conn.execute('INSERT INTO b(retrieved_at,source_endpoint,metadata) VALUES (?,?,?)',('2026-09-13T00:00:00+00:00','/r/lobby',METADATA)).lastrowid
            conn.executemany('INSERT INTO l VALUES (?,?,?)',((f'r{i}',batch,'REREAD') for i in range(page*PAGE,(page+1)*PAGE)))
        conn.commit()
    return time.perf_counter()-start


if __name__ == '__main__':
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp); before=old(root/'old.sqlite'); after=normalized(root/'new.sqlite')
        old_bytes=size(root/'old.sqlite'); new_bytes=size(root/'new.sqlite')
        print(json.dumps({'rows':ROWS,'page_size':PAGE,'old_bytes_per_retrieval':old_bytes/ROWS,
            'new_bytes_per_retrieval_link':new_bytes/ROWS,'batch_metadata_size':len(METADATA),
            'storage_reduction_percent':100*(1-new_bytes/old_bytes),'throughput_delta_percent':100*(before/after-1)},sort_keys=True))
