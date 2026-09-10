#!/usr/bin/env python3
"""Generate local consumer fixtures; no production state or remote operations."""
from pathlib import Path
import argparse
import shutil
import sqlite3
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from projection_fixture_support import *
from scout_projection_publish import publish,atomic_json,file_hash,validate_database


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True);parser.add_argument('--large-source',type=Path,required=True);args=parser.parse_args();root=args.root.resolve()
    require(str(root).startswith('/private/tmp/'),'Fixtures require /private/tmp');require(not root.exists(),'Refuse fixture overwrite');root.mkdir()
    index={}
    with create(root/'state',local=[DID,'did:key:z6MkBench']) as p:
        apply(p,[bundle()]);empty_pins(p)
        first=publish(p,root/'normal',checked_cut=p.status()['source_cut'],evaluated_at=NOW);index['normal']=first['pointer']
        shutil.copytree(root/'normal',root/'heartbeat-reuse')
        heartbeat=publish(p,root/'heartbeat-reuse',checked_cut=p.status()['source_cut'],evaluated_at=plus(NOW,1));index['heartbeat-reuse']=heartbeat['pointer']
        apply(p,[bundle(2)],plus(NOW,2),'SOURCE_BATCH')
        downgrade=publish(p,root/'duplicate-downgrade',checked_cut=p.status()['source_cut'],evaluated_at=plus(NOW,3));index['duplicate-downgrade']=downgrade['pointer']
        p.append_event(invalidation(p,quals(p)[0]['qualification_id'],plus(NOW,4)))
        invalidated=publish(p,root/'invalidation-audit',checked_cut=p.status()['source_cut'],evaluated_at=plus(NOW,5));index['invalidation-audit']=invalidated['pointer']
        request=dict(schema_version='flop-verification-request/v1',request_id='fixture-request',target_agent_did=DID,requester_did=DID,routing_decision_id='fixture-decision',routing_decision_hash='1'*64,task_hash='2'*64,independent_reputation=False)
        result=dict(schema_version='flop-verification-result/v1',request_id='fixture-request',bench_did='did:key:z6MkBench',status='PASS',artifact_hashes=dict(request_sha256=digest(request)),reproducibility='DETERMINISTIC',independent_reputation=False)
        refs=[p.import_artifact(name,canonical(obj),source_id='scout-verification',epoch='fixture-epoch',authority='CONTROLLED_BENCH',observed_at=plus(NOW,6)) for name,obj in [('request',request),('result',result)]]
        p.qualify_local_bench(*refs,evaluated_at=plus(NOW,7))
        bench=publish(p,root/'same-operator-bench',checked_cut=p.status()['source_cut'],evaluated_at=plus(NOW,8));index['same-operator-bench']=bench['pointer']
        audit_dir=root/'local-audit-originals';audit_dir.mkdir()
        for row in p.conn.execute('SELECT id,body FROM local_artifacts'):(audit_dir/(row['id']+'.json')).write_bytes(row['body'])
        p.replay_to(root/'reconstructed'/'projection.sqlite')
    with create(root/'unknown-state') as p:
        apply(p,[bundle(text='ordinary synthetic context',generation='UNKNOWN_LEGACY')]);empty_pins(p)
        unknown=publish(p,root/'unknown-legacy',checked_cut=p.status()['source_cut'],evaluated_at=NOW);index['unknown-legacy']=unknown['pointer']
    # Large fixture uses a measured synthetic exact-schema benchmark. It is for
    # consumer size/readiness development, not a verified real-world audit claim.
    large_source=args.large_source.resolve();require(str(large_source).startswith('/private/tmp/'),'Synthetic large fixture source must be temporary');require(readiness(large_source.stat().st_size)=='WARNING_LARGE','Large fixture needs measured WARNING_LARGE content')
    details=validate_database(large_source);large=root/'large-size-warning';large.mkdir();h=file_hash(large_source);name=f'router-projection-v2-1-{h}.sqlite';shutil.copyfile(large_source,large/name)
    manifest=dict(first['manifest'],snapshot_id='1',database_content_id='1',database=name,sha256=h,size_bytes=large_source.stat().st_size,source_checkpoint=dict(source_id='scout-observer',epoch='benchmark-epoch',committed_event_id=str(details['row_counts']['messages'])),row_counts=details['row_counts'],watermarks=details['watermarks'],coverage_history=details['coverage_history'],next_expiry_at=details['next_expiry_at'])
    mh=digest(manifest);mn=f'manifest-v2-1-{mh}.json';atomic_json(large,mn,manifest);pointer=dict(schema='flop-scout-router-current/v2',manifest=mn,manifest_sha256=mh,published_at=NOW);atomic_json(large,'current.json',pointer,False);index['large-size-warning']=pointer
    # A sparse oversized file exercises rejection by advertised/actual byte count
    # before SQLite is opened. Padding is deliberate test data, not truncation.
    oversize=root/'oversize-rejection';oversize.mkdir();temp=oversize/'oversize.tmp';shutil.copyfile(root/'normal'/first['manifest']['database'],temp)
    with open(temp,'r+b') as stream:stream.truncate(4*1024**3+4096)
    h=file_hash(temp);name=f'router-projection-v2-1-{h}.sqlite';temp.rename(oversize/name)
    manifest=dict(first['manifest'],snapshot_id='1',database=name,sha256=h,size_bytes=(oversize/name).stat().st_size)
    mh=digest(manifest);mn=f'manifest-v2-1-{mh}.json';atomic_json(oversize,mn,manifest);pointer=dict(schema='flop-scout-router-current/v2',manifest=mn,manifest_sha256=mh,published_at=NOW);atomic_json(oversize,'current.json',pointer,False);index['oversize-rejection']=pointer
    (root/'index.json').write_bytes(canonical(dict(fixtures=index,production_usable=False,timestamps='Fixed synthetic clock; consumer freshness tests must inject this clock',large='Synthetic measured A1 shape; opaque synthetic authority references',oversize='Sparse physical padding deliberately exceeds 4 GiB; consumer must reject before SQLite access'))+b'\n')
    print(root)


if __name__=='__main__':main()
