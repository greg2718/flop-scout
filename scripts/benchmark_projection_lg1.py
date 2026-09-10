#!/usr/bin/env python3
"""Paired synthetic LG1 overhead benchmark, fresh process per trial, temp only."""
import argparse
import json
import resource
import statistics
import subprocess
import sys
import time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scripts.projection_lg1_support import source,add_legacy,NOW,DID
from scripts.projection_fixture_support import empty_pins
from scout_projection import initialize,Projector
from scout_projection_contract import *
from scout_projection_source import map_raw,Outbox
from scout_projection_publish import publish,validate_database


def trial(root,mode,count):
    root.mkdir();c=source(root/'source.sqlite');revision='A1' if mode=='A1' else REVISION
    # Matched source payloads; A1/null controls omit concrete reported metadata.
    for n in range(1,count+1):add_legacy(c,n,report=str(n%2) if mode=='LG1_REPORTED' else None,text='ordinary synthetic context '+str(n))
    Outbox(c,epoch='benchmark-epoch',install=True,revision=revision)
    path=root/'state'/'projection.sqlite'
    initialize(path,epoch='benchmark-epoch',router_source_id='router',router_epoch='router-epoch',router_did=DID,contract_revision=revision)
    mapping=projection=0.0
    with Projector(path) as p:
        start=time.perf_counter();number=p.begin(str(count),NOW,'BOOTSTRAP');projection+=time.perf_counter()-start
        cursor=c.execute('SELECT raw_record_id FROM raw_network_records ORDER BY seq')
        while True:
            rows=cursor.fetchmany(200)
            if not rows:break
            start=time.perf_counter();bundles=[map_raw(c,r[0],revision=revision) for r in rows];mapping+=time.perf_counter()-start
            start=time.perf_counter();p.stage(number,bundles);projection+=time.perf_counter()-start
        start=time.perf_counter();p.seal(number);projection+=time.perf_counter()-start
        empty_pins(p)
        start=time.perf_counter();result=publish(p,root/'public',checked_cut=p.status()['source_cut'],evaluated_at=NOW);publication=time.perf_counter()-start
        artifact=root/'public'/result['manifest']['database']
        start=time.perf_counter();validate_database(artifact,contract_revision=revision);validation=time.perf_counter()-start
        assert result['manifest']['row_counts']['messages']==count
        private_size=path.with_suffix(path.suffix+'.ledger').stat().st_size
    c.close()
    peak=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss*(1 if sys.platform=='darwin' else 1024)
    return dict(mode=mode,records=count,mapping_seconds=mapping,projection_seconds=projection,rows_per_second=count/(mapping+projection),publication_seconds=publication,validation_seconds=validation,database_bytes=artifact.stat().st_size,private_ledger_bytes=private_size,peak_rss_bytes=peak)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True);parser.add_argument('--records',type=int,default=2000);parser.add_argument('--repetitions',type=int,default=3);parser.add_argument('--trial',choices=['A1','LG1_NULL','LG1_REPORTED']);args=parser.parse_args()
    root=args.root.resolve();require(root.is_relative_to(Path('/private/tmp')) and not root.exists(),'Unused temporary root required')
    require(1<=args.records<=10000 and 1<=args.repetitions<=10,'Bound synthetic work')
    if args.trial:
        print(json.dumps(trial(root,args.trial,args.records)));return
    root.mkdir();results=[]
    for rep in range(args.repetitions):
        for mode in ('A1','LG1_NULL','LG1_REPORTED'):
            output=subprocess.check_output([sys.executable,__file__,'--root',str(root/f'{mode}-{rep}'),'--records',str(args.records),'--trial',mode],text=True)
            results.append(json.loads(output))
    metrics=[k for k in results[0] if k not in ('mode','records')]
    medians={mode:{key:statistics.median(r[key] for r in results if r['mode']==mode) for key in metrics} for mode in ('A1','LG1_NULL','LG1_REPORTED')}
    overhead={mode:{key:100*(medians[mode][key]/medians['A1'][key]-1) for key in metrics} for mode in ('LG1_NULL','LG1_REPORTED')}
    report=dict(schema='scout-lg1-synthetic-overhead/v1',records=args.records,repetitions=args.repetitions,environment=dict(python=sys.version,platform=sys.platform),trials=results,median=medians,percent_change_vs_a1=overhead,production_data=False,limitations=['Matched synthetic text, one evidence cache reference per raw; A1 and LG1_NULL controls omit reported generations because strict A1 cannot admit the LG1 class.','Fresh process per trial; peak RSS includes source setup. Projection throughput includes source mapping, staging and full-cut rules; publication includes producer validation.','No production-size or Router-consumer readiness claim. Full originals are retained privately; required annotations may materially increase artifact size.'])
    (root/'report.json').write_bytes(canonical(report)+b'\n');print(root/'report.json')


if __name__=='__main__':main()
