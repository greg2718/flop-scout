#!/usr/bin/env python3
"""Source-query counts and old/new fixture parity, with synthetic/temp inputs only."""
import argparse
import collections
import json
import sqlite3
import sys
import time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scout_projection_contract import *
from scout_projection_source import map_raw,map_batch,Outbox
from scout_projection_publish import validate_database
from scripts.projection_lg1_support import source,add_legacy


def counts():
    result={}
    for shape in ('normal','single','multi','conflict'):
        c=source();Outbox(c,epoch='counts',install=True,revision=LG2_REVISION)
        ids=[add_legacy(c,n,report=None if shape=='normal' else '0',protocol_cache=shape=='multi',text='ordinary context '+str(n)) for n in range(1,51)]
        if shape=='conflict':
            with c:c.execute("UPDATE evidence_records SET generation='1' WHERE seq=1")
        result[shape]={}
        for mode in ('scalar','batch'):
            events=collections.Counter();c.set_trace_callback(lambda q:events.update([q.split()[0].upper()]) if q.strip() else None)
            t=time.perf_counter();error=None
            try:
                if mode=='scalar':out=[map_raw(c,r,revision=LG2_REVISION) for r in ids]
                else:out=map_batch(c,ids,revision=LG2_REVISION)
            except ProjectionError as exc:error=str(exc)
            elapsed=time.perf_counter()-t;c.set_trace_callback(None)
            result[shape][mode]=dict(input_count=50,completed_count=0 if error else len(out),seconds=elapsed,sql=dict(events),error=error,selects_per_successful_record=events['SELECT']/50 if not error else None)
        c.close()
    return result


def parity(old_root,new_root):
    old=json.loads((old_root/'index.json').read_text());new=json.loads((new_root/'index.json').read_text())
    require(set(old['fixtures'])==set(new['fixtures']),'Fixture case set changed');result={}
    for name,before in old['fixtures'].items():
        after=new['fixtures'][name];require(before['expected']==after['expected'],'Fixture decision changed')
        dbs=[]
        for root,item in ((old_root,before),(new_root,after)):
            current=loads((root/name/'current.json').read_bytes());manifest=loads((root/name/current['manifest']).read_bytes())
            dbs.append(root/name/manifest['database']);revision_binding(manifest)
        accepted=[]
        for path in dbs:
            try:validate_database(path,contract_revision=LG2_REVISION);accepted.append(True)
            except ProjectionError:accepted.append(False)
        require(accepted==[before['expected']=='ACCEPT']*2,'Fixture validation outcome changed')
        with connect(dbs[0],True) as a,connect(dbs[1],True) as b:
            for table in tables_for(LG2_REVISION):
                cols=[r[1] for r in a.execute('PRAGMA table_info('+table+')')];query='SELECT * FROM '+table+' ORDER BY '+','.join(cols)
                x=a.execute(query);y=b.execute(query)
                while True:
                    left=[tuple(r) for r in x.fetchmany(200)];right=[tuple(r) for r in y.fetchmany(200)]
                    require(left==right,'Fixture facts changed: '+name+'/'+table)
                    if not left:break
        result[name]=dict(expected=before['expected'],facts_identical=True)
    # Full private workflow tables also remain identical for each generated state.
    workflows={}
    for ledger in old_root.glob('*-state/*.ledger'):
        other=new_root/ledger.relative_to(old_root)
        with connect(ledger,True) as a,connect(other,True) as b:
            left=[tuple(r) for r in a.execute('SELECT * FROM workflows ORDER BY id')];right=[tuple(r) for r in b.execute('SELECT * FROM workflows ORDER BY id')]
            require(left==right,'Workflow fixture state changed');workflows[str(ledger.relative_to(old_root))]=len(left)
    return dict(fixtures=result,workflow_rows=workflows)


def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--old',type=Path);p.add_argument('--new',type=Path);a=p.parse_args()
    require(a.output.resolve().is_relative_to(Path('/private/tmp')) and not a.output.exists(),'Unused temporary output required')
    result=dict(source_counts=counts())
    if a.old and a.new:
        require(all(x.resolve().is_relative_to(Path('/private/tmp')) for x in (a.old,a.new)),'Temporary fixtures only')
        result['parity']=parity(a.old,a.new)
    a.output.write_bytes(canonical(result)+b'\n');print(a.output)

if __name__=='__main__':main()
