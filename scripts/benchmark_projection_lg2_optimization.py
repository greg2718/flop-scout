#!/usr/bin/env python3
"""Full synthetic producer runs and bounded-batch telemetry. Temporary paths only."""
import argparse
import json
import resource
import sqlite3
import sys
import time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import scripts.profile_projection_lg2 as meter
from scout_projection_contract import *
from scout_projection import Projector,initialize
from scout_projection_source import Outbox,map_batch,map_raw
from scout_projection_publish import publish,validate_database
from scripts.projection_lg1_support import source,add_legacy,DID,NOW
from scripts.projection_fixture_support import empty_pins


def run(root,mode,count,batch_size,shape,reuse_source=None,prepare_only=False):
    root.mkdir();original_connect=sqlite3.connect
    def measured_connect(*a,**kw):
        kw.setdefault('factory',meter.MeasuredConnection);c=original_connect(*a,**kw)
        c.set_trace_callback(lambda q:meter.traced.update([q.split()[0].upper()]) if meter.active and q.strip() else None)
        return c
    sqlite3.connect=measured_connect
    revision='A1' if mode=='A1' else LG2_REVISION
    # Two fixed synthetic public identities keep each whole-sender group within
    # the unchanged 100k capacity. No private keys or real identities are used.
    import flop_scout
    peer='did:key:z'+flop_scout.b58encode(flop_scout.ED25519_MULTICODEC+bytes(reversed(range(32))))
    extra=round(count*32890/161073) if shape=='mixed' else count if shape=='multi' else 0
    start=time.perf_counter()
    if reuse_source:
        require(reuse_source.resolve().is_relative_to(Path('/private/tmp')),'Synthetic temporary source only')
        c=sqlite3.connect(str(root/'source.sqlite'));c.row_factory=sqlite3.Row
        with original_connect(reuse_source.resolve().as_uri()+'?mode=ro',uri=True) as original:original.backup(c,pages=200)
        original.close()
        Outbox(c,epoch='benchmark-epoch',revision=revision)
        require(c.execute('SELECT count(*) FROM raw_network_records').fetchone()[0]==count,'Wrong reusable population')
        require(c.execute('SELECT count(*) FROM kibble_events').fetchone()[0]==extra,'Wrong reusable witness population')
        require(c.execute('SELECT count(*) FROM raw_network_records WHERE reported_generation IS NOT NULL').fetchone()[0]==(0 if mode in ('A1','LG2_NULL') else count),'Wrong reusable report population')
    else:
        c=source(root/'source.sqlite');Outbox(c,epoch='benchmark-epoch',install=True,revision=revision)
        for n in range(1,count+1):
            add_legacy(c,n,report=None if mode in ('A1','LG2_NULL') else str(n%2),text='ordinary synthetic context '+str(n),protocol_cache=n<=extra,sender=DID if n%2 else peer)
            if n%10000==0:print(json.dumps(dict(phase='source',records=n,elapsed=time.perf_counter()-start)),flush=True)
    setup=time.perf_counter()-start
    if prepare_only:
        c.close()
        (root/'source-fixture.json').write_bytes(canonical(dict(mode=mode,records=count,shape=shape,source_setup_seconds=setup,source=str(root/'source.sqlite')))+b'\n')
        print(root/'source-fixture.json',flush=True);return
    path=root/'state'/'projection.sqlite'
    initialize(path,epoch='benchmark-epoch',router_source_id='router',router_epoch='router-epoch',router_did=DID,contract_revision=revision)
    mapping=staging=0.;start=time.perf_counter();meter.active=True
    with Projector(path,write_batch_size=batch_size) as p:
        n=p.begin(str(count),NOW,'BOOTSTRAP');cursor=c.execute('SELECT raw_record_id FROM raw_network_records ORDER BY seq')
        processed=0
        while True:
            rows=cursor.fetchmany(200)
            if not rows:break
            t=time.perf_counter();bundles=map_batch(c,[r[0] for r in rows],revision=revision);mapping+=time.perf_counter()-t
            t=time.perf_counter();p.stage(n,bundles);bundles=None;staging+=time.perf_counter()-t;processed+=len(rows)
            if processed%10000==0:print(json.dumps(dict(phase='mapped_staged',records=processed,elapsed=time.perf_counter()-start)),flush=True)
        print(json.dumps(dict(phase='seal',records=count)),flush=True)
        p.seal(n);elapsed=time.perf_counter()-start;meter.active=False
        print(json.dumps(dict(phase='update_complete',seconds=elapsed,rows_per_second=count/elapsed)),flush=True)
        update_sql=[dict(sql=k,**v) for k,v in meter.sql_stats.items()]
        update_commits=meter.distribution(meter.commits);update_holds=meter.distribution(meter.holds)
        actual_traced=dict(meter.traced)
        (root/'update-only.json').write_bytes(canonical(dict(records=count,seconds=elapsed,rows_per_second=count/elapsed,commit=update_commits,writer_hold=update_holds,sql=update_sql,traced_sql=actual_traced))+b'\n')
        status=p.legacy_status();expected=0 if mode in ('A1','LG2_NULL') else count
        if mode!='A1':
            assert status['report_count']==expected
            assert status['witness_count']==(count+extra if expected else 0)
        empty_pins(p)
        publication_commit_start=len(meter.commits);meter.active=True
        t=time.perf_counter();publication=publish(p,root/'public',checked_cut=p.status()['source_cut'],evaluated_at=NOW);publication_seconds=time.perf_counter()-t
        artifact=root/'public'/publication['manifest']['database']
        t=time.perf_counter();validate_database(artifact,contract_revision=revision);validation_seconds=time.perf_counter()-t
        print(json.dumps(dict(phase='publication_validated',publication_seconds=publication_seconds,validation_seconds=validation_seconds)),flush=True)
        journal={name:p.conn.execute('PRAGMA '+name+'.journal_mode').fetchone()[0] for name in ('main','projection')}
        assert set(journal.values())=={'delete'}
        t=time.perf_counter();checkpoint=tuple(p.conn.execute('PRAGMA projection.wal_checkpoint(PASSIVE)').fetchone());checkpoint_probe=time.perf_counter()-t
        # The pair cannot produce WAL files while its fixed journal mode is DELETE.
        assert all(not Path(str(db)+'-wal').exists() for db in (p.path,p.ledger))
        ledger_bytes=p.ledger.stat().st_size
        publication_commits=meter.distribution(meter.commits[publication_commit_start:]);expiry_commit_start=len(meter.commits)
        print(json.dumps(dict(phase='expiry',records=count)),flush=True)
        t=time.perf_counter();n=p.begin(str(count),plus(NOW,2592001),'EXPIRY');p.seal(n);expiry=time.perf_counter()-t
        assert p.conn.execute('SELECT count(*) FROM projection.messages').fetchone()[0]==0
        if mode!='A1':assert p.legacy_status()['witness_count']==0
        meter.active=False;expiry_commits=meter.distribution(meter.commits[expiry_commit_start:])
    c.close();peak=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*(1 if sys.platform=='darwin' else 1024)
    result=dict(mode=mode,shape=shape,records=count,write_batch_size=batch_size,source_setup_seconds=setup,total_update_seconds=elapsed,mapping_seconds=mapping,staging_seconds=staging,rows_per_second=count/elapsed,microseconds_per_record=elapsed/count*1e6,report_count=expected,witness_count=count+extra if expected else 0,database_bytes=artifact.stat().st_size,private_ledger_bytes=ledger_bytes,peak_rss_bytes=peak,commit=update_commits,writer_hold=update_holds,sql=update_sql,sql_calls=sum(r['calls'] for r in update_sql),rows_changed=sum(r['rows_changed'] for r in update_sql),traced_sql=actual_traced,journal_modes=journal,wal_high_water_bytes=0,checkpoint_applicable=False,checkpoint_probe_result=checkpoint,checkpoint_probe_seconds=checkpoint_probe,publication_seconds=publication_seconds,validation_seconds=validation_seconds,expiry_seconds=expiry,expiry_rows_per_second=count/expiry,scope='Full synthetic source mapping, private replay ledger, projection, publication and expiry. Telemetry included in update elapsed time; compare paired modes from this harness. No production data or services. Index maintenance is included in statement execution cost.')
    result.update(input_buffers_released_after_staging=True,source_setup_kind='copied existing synthetic fixture' if reuse_source else 'constructed synthetic fixture',reused_source=str(reuse_source) if reuse_source else None,publication_commit=publication_commits,expiry_commit=expiry_commits,lifecycle_commit=meter.distribution(meter.commits),lifecycle_writer_hold=meter.distribution(meter.holds))
    (root/'result.json').write_bytes(canonical(result)+b'\n');print(root/'result.json',flush=True)


def main():
    p=argparse.ArgumentParser();p.add_argument('--root',required=True,type=Path);p.add_argument('--mode',choices=['A1','LG2','LG2_NULL'],required=True);p.add_argument('--records',type=int,default=2000);p.add_argument('--batch',type=int,choices=[50,100,200,500],default=50);p.add_argument('--shape',choices=['single','multi','mixed'],default='mixed');p.add_argument('--reuse-source',type=Path);p.add_argument('--prepare-only',action='store_true');a=p.parse_args()
    root=a.root.resolve();require(root.is_relative_to(Path('/private/tmp')) and not root.exists(),'Unused temporary root required');require(1<=a.records<=161073,'Bounded synthetic population required')
    run(root,a.mode,a.records,a.batch,a.shape,a.reuse_source,a.prepare_only)

if __name__=='__main__':main()
