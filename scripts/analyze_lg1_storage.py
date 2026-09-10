#!/usr/bin/env python3
"""Read-only fixture audit and unpublished bounded row-template sizing experiments.

No producer, source or contract mutation. Scaled files are NOT Router fixtures:
repeated payload templates measure SQLite storage, not source authority/replay.
"""
import argparse
import collections
import hashlib
import json
import pathlib
import shutil
import sqlite3


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False)
def ro(path):
    conn=sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True);conn.row_factory=sqlite3.Row;return conn


def stats(path):
    with ro(path) as c:
        objects={r['name']:dict(r) for r in c.execute('SELECT name,count(*) AS pages,sum(pgsize) AS bytes,sum(payload) AS payload_bytes,sum(unused) AS unused_bytes FROM dbstat GROUP BY name')}
        schema={r['name']:dict(r) for r in c.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_stat%'")}
        for name,obj in objects.items():obj.update(kind=schema.get(name,{}).get('type','table'),table=schema.get(name,{}).get('tbl_name',name))
        counts={r['name']:c.execute('SELECT count(*) FROM "'+r['name']+'"').fetchone()[0] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}
        return dict(size_bytes=path.stat().st_size,page_size=c.execute('PRAGMA page_size').fetchone()[0],auto_vacuum=c.execute('PRAGMA auto_vacuum').fetchone()[0],non_dbstat_bytes=path.stat().st_size-sum(x['bytes'] for x in objects.values()),freelist_bytes=c.execute('PRAGMA freelist_count').fetchone()[0]*c.execute('PRAGMA page_size').fetchone()[0],objects=objects,row_counts=counts,payload_floor_bytes=sum(x['payload_bytes'] for x in objects.values()),index_bytes=sum(x['bytes'] for x in objects.values() if x['kind']=='index'))


def delta(a,b):
    objects={name:{key:b['objects'].get(name,{}).get(key,0)-a['objects'].get(name,{}).get(key,0) for key in ('bytes','payload_bytes','unused_bytes')} for name in set(a['objects'])|set(b['objects'])}
    n=b['row_counts']['messages']
    return dict(bytes=b['size_bytes']-a['size_bytes'],percent=100*(b['size_bytes']/a['size_bytes']-1),bytes_per_row=(b['size_bytes']-a['size_bytes'])/n,index_bytes_per_row=(b['index_bytes']-a['index_bytes'])/n,provenance_bytes_per_row=objects['source_provenance']['bytes']/n,objects=objects,lg1_payload_floor_over_a1_file_percent=100*(b['payload_floor_bytes']/a['size_bytes']-1))


def payloads(path):
    with ro(path) as c:
        sums=collections.Counter();keys=collections.Counter()
        for row in c.execute('SELECT annotations_json FROM source_provenance'):
            obj=json.loads(row[0]);sums['annotations_json']+=len(row[0].encode())
            legacy=obj.get('legacy_generation')
            if legacy:
                sums['legacy_generation_value']+=len(canonical(legacy).encode())
                for key,value in legacy.items():keys[key]+=len(canonical({key:value}).encode())-2
        return dict(total_bytes=dict(sums),legacy_fields_key_and_value_bytes=dict(keys))


def scale(template,path,count):
    """Same three populated row families, exact schema and equal-width IDs."""
    with ro(template) as old,sqlite3.connect(path) as new:
        new.executescript(';'.join(r[0] for r in old.execute("SELECT sql FROM sqlite_master WHERE sql IS NOT NULL ORDER BY type DESC,name"))+';')
        new.execute('PRAGMA user_version=2')
        rows={table:[dict(r) for r in old.execute('SELECT * FROM '+table+' ORDER BY projection_row_id LIMIT 200')] for table in ('messages','source_provenance','selection_membership')}
        for table in ('snapshot_meta','watermarks','coverage_history'):
            data=old.execute('SELECT * FROM '+table).fetchall()
            if data:new.executemany('INSERT INTO '+table+' VALUES('+','.join('?' for _ in data[0])+')',[tuple(r) for r in data])
        for start in range(0,count,200):
            for table,templates in rows.items():
                batch=[]
                for i in range(start,min(start+200,count)):
                    row=dict(templates[i%len(templates)]);raw=hashlib.sha256(('storage-template-'+str(i)).encode()).hexdigest();row['projection_row_id']='sm1:'+raw
                    if table=='messages':row['seq']=i+1
                    elif table=='source_provenance':
                        row.update(raw_record_id=raw,source_record_locator=raw,scout_event_id=str(i+1))
                        ann=json.loads(row['annotations_json'])
                        if ann.get('legacy_generation'):ann['legacy_generation']['raw_record_id']=raw
                        row['annotations_json']=canonical(ann)
                    batch.append(tuple(row.values()))
                new.executemany('INSERT INTO '+table+' VALUES('+','.join('?' for _ in batch[0])+')',batch)
            new.commit()
        new.execute('UPDATE watermarks SET record_count=?,min_seq=1,max_seq=?',(count,count))
        new.commit();new.execute('VACUUM')
    return stats(path)


def audit_indexes(path):
    with ro(path) as c:
        raw=c.execute('SELECT raw_record_id,room,seq,raw_text_sha256 FROM raw_network_records LIMIT 1').fetchone()
        queries={
            'legacy_links':('SELECT cache_table,cache_rowid,raw_text_sha256 FROM compatibility_evidence_links WHERE raw_record_id=? ORDER BY cache_table,cache_rowid',(raw[0],)),
            'alternate_candidate':('SELECT 1 FROM raw_network_records WHERE room=? AND seq=? AND raw_text_sha256=? AND raw_record_id<>? LIMIT 1',(raw[1],raw[2],raw[3],raw[0])),
            'retrieval_proof':('SELECT 1 FROM evidence_retrievals WHERE raw_record_id=? LIMIT 1',(raw[0],)),
            'evidence_cache':("SELECT c.* FROM evidence_records c JOIN compatibility_evidence_links l ON l.cache_table=? AND l.cache_rowid=c.rowid WHERE l.raw_record_id=?",('evidence_records',raw[0])),
        }
        return {name:dict(sql=sql,plan=[dict(row) for row in c.execute('EXPLAIN QUERY PLAN '+sql,params)]) for name,(sql,params) in queries.items()}


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=pathlib.Path,required=True);parser.add_argument('--baseline',type=pathlib.Path,required=True);args=parser.parse_args()
    root=args.root.resolve();base=args.baseline.resolve()
    if not root.is_relative_to(pathlib.Path('/private/tmp')) or not base.is_relative_to(pathlib.Path('/private/tmp')):raise ValueError('Temporary paths only')
    root.mkdir(exist_ok=False)
    paths={mode:next((base/(mode+'-0')/'public').glob('*.sqlite')) for mode in ('A1','LG1_REPORTED')}
    original={mode:stats(p) for mode,p in paths.items()}
    ledgers={mode:stats(base/(mode+'-0')/'state'/'projection.sqlite.ledger') for mode in paths}
    result=dict(original=original,original_delta=delta(original['A1'],original['LG1_REPORTED']),payloads={mode:payloads(p) for mode,p in paths.items()},ledgers=ledgers,index_plans=audit_indexes(base/'LG1_REPORTED-0'/'source.sqlite'),source=stats(base/'LG1_REPORTED-0'/'source.sqlite'),scales={},page_size_trials={},scope='Original 2000-row producer artifacts; 1k/10k/100k UNPUBLISHED row-template storage experiments, not end-to-end producer/Router benchmarks.')
    for count in (1000,10000,100000):
        pair={mode:scale(path,root/f'{mode}-{count}.sqlite',count) for mode,path in paths.items()}
        result['scales'][str(count)]=dict(pair=pair,delta=delta(pair['A1'],pair['LG1_REPORTED']))
    for size in (1024,2048,4096,8192,16384,32768,65536):
        trial=root/f'page-{size}.sqlite';shutil.copyfile(paths['LG1_REPORTED'],trial)
        with sqlite3.connect(trial) as c:c.execute('PRAGMA page_size='+str(size));c.execute('VACUUM')
        result['page_size_trials'][str(size)]=stats(trial)
    (root/'report.json').write_text(json.dumps(result,sort_keys=True,indent=2)+'\n')
    print(root/'report.json')


if __name__=='__main__':main()
