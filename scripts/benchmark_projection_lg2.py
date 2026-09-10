#!/usr/bin/env python3
"""Bounded local LG2 storage and producer benchmarks. No production paths."""
import argparse
import json
import resource
import sqlite3
import statistics
import subprocess
import sys
import time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scout_projection_contract import *
from scout_projection import Projector, initialize
from scout_projection_source import map_raw, map_batch, Outbox
from scout_projection_publish import publish, validate_database, file_hash
from scout_projection_compact import encode, statistics as compact_statistics
from scripts.projection_lg1_support import source, add_legacy, NOW, DID
from scripts.projection_fixture_support import empty_pins
from scripts.analyze_lg1_storage import stats

MODES={'A1':'A1','LG1':REVISION,'LG2':LG2_REVISION}
MULTI=32890/161073


def storage(root, sizes):
    """Exact producer row shapes, scaled identities; sizing files are not publications.

    Both encodings use identical logical LG1 reports with measured real synthetic
    cache locators. No invented shortened locator or dropped witness is used.
    """
    root.mkdir();results={}
    c=source();single=add_legacy(c,text='ordinary synthetic context 1');multi=add_legacy(c,2,text='ordinary synthetic context 2',protocol_cache=True)
    templates=[map_raw(c,r) for r in (single,multi)];c.close()
    for count in sizes:
        pair={};extra=round(count*MULTI)
        for mode,revision in MODES.items():
            path=root/f'{mode}-{count}.sqlite'
            db=sqlite3.connect(str(path));db.row_factory=sqlite3.Row;db.execute('PRAGMA foreign_keys=ON');db.executescript(sql_for(revision))
            db.execute('INSERT INTO snapshot_meta VALUES(1,?,?,?,?)',(SCHEMA,'1',NOW,POLICY_SHA))
            for start in range(0,count,200):
                messages=[];provs=[];members=[];reports=[];witnesses=[]
                for i in range(start,min(start+200,count)):
                    b=templates[int(i<extra)];m=dict(b['message']);p=dict(b['provenance']);a=loads(p['annotations_json'])
                    raw=text_hash('lg2-storage-'+str(i));rid='sm1:'+raw;m.update(projection_row_id=rid,seq=i+1)
                    p.update(projection_row_id=rid,raw_record_id=raw,source_record_locator=raw,scout_event_id=str(i+1))
                    audit=a['legacy_generation'];audit['raw_record_id']=raw
                    audit['reported_generation']=str(i%2)
                    for r in audit['linked_cache_records']:r['reported_generation']=str(i%2)
                    if mode!='LG1':a.pop('legacy_generation')
                    p['annotations_json']=canonical(a).decode()
                    messages.append(tuple(m.values()));provs.append(tuple(p.values()))
                    members.append(('message',rid,'CONTEXT',NOW,plus(NOW,2592000),'[]'))
                    if mode=='LG2':
                        v=encode(audit);r=bytes.fromhex(raw);reports.append((r,v['reported_code']))
                        witnesses.extend((r,k,bytes.fromhex(h),loc) for k,h,loc in v['witnesses'])
                db.executemany('INSERT INTO messages VALUES('+','.join('?' for _ in messages[0])+')',messages)
                db.executemany('INSERT INTO source_provenance VALUES(?,?,?,?,?,?,?,?)',provs)
                db.executemany('INSERT INTO selection_membership VALUES(?,?,?,?,?,?)',members)
                if reports:
                    db.executemany('INSERT INTO legacy_generation_reports(raw_ref,reported_code) VALUES(?,?)',reports)
                    db.executemany('INSERT INTO legacy_generation_witnesses VALUES(?,?,?,?)',witnesses)
                db.commit()
            db.execute('INSERT INTO watermarks VALUES(?,?,?,?,?)',('technocore','UNKNOWN_LEGACY',count,1,count))
            db.execute('INSERT INTO coverage_history VALUES(?,?,?,?,?)',('technocore','UNKNOWN_LEGACY',count,raw,digest(m)))
            db.commit();assert db.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
            assert not db.execute('PRAGMA foreign_key_check').fetchone()
            locators=compact_statistics(db) if mode=='LG2' else None
            db.close();pair[mode]=stats(path)
            if locators:pair[mode]['locator_statistics']=locators
        baseline=pair['A1'];compact=pair['LG2'];lg1=pair['LG1']
        lgobjects=[compact['objects'][t] for t in LG2_TABLES]
        comparison=dict(lg2_added_bytes=compact['size_bytes']-baseline['size_bytes'],lg1_added_bytes=lg1['size_bytes']-baseline['size_bytes'],
            lg2_total_delta_percent=100*(compact['size_bytes']/baseline['size_bytes']-1),lg1_total_delta_percent=100*(lg1['size_bytes']/baseline['size_bytes']-1),
            lg2_vs_lg1_delta_percent=100*(compact['size_bytes']/lg1['size_bytes']-1),
            lg2_payload_delta_percent=100*(compact['payload_floor_bytes']/baseline['payload_floor_bytes']-1),
            lg1_payload_delta_percent=100*(lg1['payload_floor_bytes']/baseline['payload_floor_bytes']-1),
            bytes_per_report=sum(o['bytes'] for o in lgobjects)/count,
            report_table_bytes_per_report=lgobjects[0]['bytes']/count,
            witness_table_bytes_per_witness=lgobjects[1]['bytes']/(count+extra),
            average_witnesses_per_report=(count+extra)/count)
        results[str(count)]=dict(modes=pair,comparison=comparison)
        if comparison['lg2_total_delta_percent']>25:break
    result=dict(scope='UNPUBLISHED row-template sizing only; exact producer schema and synthetic cache locator shapes. Scaled raw IDs have no private source originals and these files must not be consumed as Router fixtures.',sizes=results,production_access=False)
    (root/'report.json').write_bytes(canonical(result)+b'\n');return result


def trial(root, mode, count):
    root.mkdir();revision=MODES[mode];c=source(root/'source.sqlite')
    for n in range(1,count+1):add_legacy(c,n,report=None if mode=='A1' else str(n%2),text='ordinary synthetic context '+str(n),protocol_cache=n<=round(count*MULTI))
    Outbox(c,epoch='benchmark-epoch',install=True,revision=revision)
    # Transparent per-call clocks: class admission and compact conversion are
    # included in total throughput; counters are never subtracted from totals.
    import scout_projection_legacy as legacy
    import scout_projection_compact as compact
    clocks={'class_admission_seconds':0.,'encode_seconds':0.,'decode_seconds':0.}
    def timed(module,name,key):
        original=getattr(module,name)
        def wrapped(*args,**kwargs):
            start=time.perf_counter()
            try:return original(*args,**kwargs)
            finally:clocks[key]+=time.perf_counter()-start
        setattr(module,name,wrapped)
    timed(legacy,'source_proof','class_admission_seconds');timed(compact,'encode','encode_seconds');timed(compact,'decode','decode_seconds')
    path=root/'state'/'projection.sqlite';initialize(path,epoch='benchmark-epoch',router_source_id='router',router_epoch='router-epoch',router_did=DID,contract_revision=revision)
    mapping=update=0.
    with Projector(path) as p:
        start=time.perf_counter();number=p.begin(str(count),NOW,'BOOTSTRAP');update+=time.perf_counter()-start
        cursor=c.execute('SELECT raw_record_id FROM raw_network_records ORDER BY seq')
        while True:
            rows=cursor.fetchmany(200)
            if not rows:break
            start=time.perf_counter();bundles=map_batch(c,[r[0] for r in rows],revision=revision);mapping+=time.perf_counter()-start
            start=time.perf_counter();p.stage(number,bundles);bundles=None;update+=time.perf_counter()-start
        start=time.perf_counter();p.seal(number);update+=time.perf_counter()-start
        update_clocks=dict(clocks);empty_pins(p)
        start=time.perf_counter()
        with sqlite3.connect(str(root/'backup.sqlite')) as backup:p.conn.backup(backup,name='projection',pages=200)
        backup_seconds=time.perf_counter()-start
        start=time.perf_counter();out=publish(p,root/'public',checked_cut=p.status()['source_cut'],evaluated_at=NOW);publication=time.perf_counter()-start
        artifact=root/'public'/out['manifest']['database']
        start=time.perf_counter();validate_database(artifact,contract_revision=revision);validation=time.perf_counter()-start
        start=time.perf_counter();file_hash(artifact);hash_seconds=time.perf_counter()-start
        assert out['manifest']['row_counts']['messages']==count
        ledger_bytes=p.ledger.stat().st_size
        start=time.perf_counter();n=p.begin(str(count),plus(NOW,2592001),'EXPIRY');p.seal(n);expiry=time.perf_counter()-start
        assert p.conn.execute('SELECT count(*) FROM projection.messages').fetchone()[0]==0
    c.close();peak=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*(1 if sys.platform=='darwin' else 1024)
    return dict(mode=mode,records=count,mapping_seconds=mapping,projection_update_seconds=update,rows_per_second=count/(mapping+update),class_rows_per_second=count/update_clocks['class_admission_seconds'] if update_clocks['class_admission_seconds'] else None,**update_clocks,backup_seconds=backup_seconds,publication_seconds=publication,validation_seconds=validation,sha256_seconds=hash_seconds,expiry_seconds=expiry,expiry_rows_per_second=count/expiry,database_bytes=artifact.stat().st_size,private_ledger_bytes=ledger_bytes,peak_rss_bytes=peak)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True);parser.add_argument('--storage',action='store_true');parser.add_argument('--trial',choices=MODES);parser.add_argument('--records',type=int,default=2000);parser.add_argument('--repetitions',type=int,default=3);args=parser.parse_args()
    root=args.root.resolve();require(root.is_relative_to(Path('/private/tmp')) and not root.exists(),'Unused temporary root required')
    require(1<=args.records<=10000 and 1<=args.repetitions<=10,'Bounded benchmark required')
    if args.storage:storage(root,(1000,10000,100000,161073));print(root/'report.json');return
    if args.trial:print(json.dumps(trial(root,args.trial,args.records)));return
    root.mkdir();trials=[]
    for rep in range(args.repetitions):
        # Rotate mode order to reduce warm-cache ordering bias.
        modes=list(MODES);modes=modes[rep%3:]+modes[:rep%3]
        for mode in modes:
            output=subprocess.check_output([sys.executable,__file__,'--root',str(root/f'{mode}-{rep}'),'--records',str(args.records),'--trial',mode],text=True)
            trials.append(json.loads(output))
    metrics=[k for k,v in trials[0].items() if k not in ('mode','records') and v is not None]
    medians={mode:{k:statistics.median(r[k] for r in trials if r['mode']==mode) for k in metrics} for mode in MODES}
    delta={mode:{k:100*(medians[mode][k]/medians['A1'][k]-1) if medians['A1'][k] else None for k in metrics} for mode in ('LG1','LG2')}
    result=dict(schema='scout-lg2-synthetic-performance/v1',records=args.records,repetitions=args.repetitions,trials=trials,median=medians,percent_change_vs_a1=delta,production_access=False,python=sys.version,sqlite=sqlite3.sqlite_version,limitations=['Fresh process per trial; RSS includes synthetic source setup.','A1 controls omit reported metadata because A1 cannot admit legacy reports. LG1/LG2 evidence and witness multiplicity match.','Small synthetic full producer runs; no production-size timing or Router acceptance claim.','Class admission and normalization clocks are included in overall elapsed time. Backup is timed independently; publication includes verification and hashing.'])
    (root/'report.json').write_bytes(canonical(result)+b'\n');print(root/'report.json')

if __name__=='__main__':main()
