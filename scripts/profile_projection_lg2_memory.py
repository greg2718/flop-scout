#!/usr/bin/env python3
"""Self-process phase RSS diagnostics on a synthetic producer trial."""
import argparse
import json
import resource
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scripts.benchmark_projection_lg2 import trial
from scout_projection import Projector


def main():
    p=argparse.ArgumentParser();p.add_argument('--root',type=Path,required=True);p.add_argument('--mode',choices=['A1','LG2'],required=True);a=p.parse_args()
    assert a.root.resolve().is_relative_to(Path('/private/tmp')) and not a.root.exists()
    phases=[];counts={}
    def sample(label,projector):
        phases.append(dict(phase=label,peak_rss_bytes=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,cache_kib={db:projector.conn.execute('PRAGMA '+db+'.cache_size').fetchone()[0] for db in ('main','projection')}))
    def wrap(name):
        original=getattr(Projector,name)
        def measured(projector,*args,**kwargs):
            counts[name]=counts.get(name,0)+1
            if name=='begin' or name=='evaluate_sender':sample(name+':before:'+str(counts[name]),projector)
            result=original(projector,*args,**kwargs)
            if name!='stage' or counts[name] in (1,10):sample(name+':after:'+str(counts[name]),projector)
            return result
        setattr(Projector,name,measured)
    for name in ('begin','stage','evaluate_sender','seal','verify_ledger'):wrap(name)
    result=trial(a.root.resolve(),a.mode,2000)
    (a.root/'memory.json').write_text(json.dumps(dict(result=result,phases=phases),indent=2)+'\n');print(a.root/'memory.json')

if __name__=='__main__':main()
