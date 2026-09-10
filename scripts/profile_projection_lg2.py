#!/usr/bin/env python3
"""Temporary-only Python/SQLite update profiler; SQL parameters are never logged."""
import argparse
import collections
import cProfile
import json
import math
import pstats
import re
import sqlite3
import sys
import time
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))

active=False
sql_stats=collections.defaultdict(lambda:dict(calls=0,seconds=0.,rows_changed=0))
traced=collections.Counter()
commits=[]
holds=[]

class MeasuredConnection(sqlite3.Connection):
    hold_started=None
    finish_depth=0
    def measured(self,fn,sql,args):
        if not active:return fn(sql,*args)
        before=self.total_changes;start=time.perf_counter()
        if not self.in_transaction and re.match(r'\s*(INSERT|UPDATE|DELETE|BEGIN)',sql,re.I):self.hold_started=start
        try:return fn(sql,*args)
        finally:
            stat=sql_stats[sql];stat['calls']+=1;stat['seconds']+=time.perf_counter()-start;stat['rows_changed']+=self.total_changes-before
    def execute(self,sql,*args):return self.measured(super().execute,sql,args)
    def executemany(self,sql,*args):return self.measured(super().executemany,sql,args)
    def finish(self,fn,*args):
        measured=active and self.in_transaction and self.finish_depth==0;start=time.perf_counter();self.finish_depth+=1
        try:return fn(*args)
        finally:
            if measured:
                end=time.perf_counter();commits.append(end-start)
                if self.hold_started is not None:holds.append(end-self.hold_started)
            self.finish_depth-=1
            if self.finish_depth==0:self.hold_started=None
    def commit(self):return self.finish(super().commit)
    def __exit__(self,*args):return self.finish(super().__exit__,*args)


def distribution(values):
    values=sorted(values)
    return dict(count=len(values),total_seconds=sum(values),p50_ms=values[math.ceil(len(values)*.5)-1]*1000 if values else 0,p95_ms=values[math.ceil(len(values)*.95)-1]*1000 if values else 0,max_ms=max(values,default=0)*1000)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True);parser.add_argument('--mode',choices=['A1','LG2'],required=True);parser.add_argument('--records',type=int,default=2000);args=parser.parse_args()
    root=args.root.resolve();assert root.is_relative_to(Path('/private/tmp')) and not root.exists()
    connect=sqlite3.connect
    def measured_connect(*a,**kw):
        kw.setdefault('factory',MeasuredConnection);c=connect(*a,**kw)
        c.set_trace_callback(lambda sql:traced.update([sql.split()[0].upper()]) if active and sql.strip() else None)
        return c
    sqlite3.connect=measured_connect
    from scripts.benchmark_projection_lg2 import trial
    from scout_projection import Projector
    profile=cProfile.Profile();begin=Projector.begin;seal=Projector.seal
    def begin_profile(p,*a,**kw):
        global active
        if (len(a)>2 and a[2]=='BOOTSTRAP') or kw.get('kind')=='BOOTSTRAP':active=True;profile.enable()
        return begin(p,*a,**kw)
    def seal_profile(p,*a,**kw):
        global active
        try:return seal(p,*a,**kw)
        finally:
            if active:profile.disable();active=False
    Projector.begin=begin_profile;Projector.seal=seal_profile
    result=trial(root,args.mode,args.records)
    profile.dump_stats(str(root/'update.prof'))
    stats=pstats.Stats(profile)
    funcs=[dict(file=Path(f).name,line=line,function=name,calls=v[1],self_seconds=v[2],cumulative_seconds=v[3]) for (f,line,name),v in stats.stats.items()]
    data=dict(mode=args.mode,records=args.records,scope='Instrumented initial update only; timings include profiling overhead. SQL execution time excludes cursor iteration after execute. Index maintenance is included in statement cost, not separately attributable.',metrics=result,commit=distribution(commits),writer_hold=distribution(holds),sql=sorted([dict(sql=k,**v) for k,v in sql_stats.items()],key=lambda r:r['seconds'],reverse=True),python_by_self=sorted(funcs,key=lambda r:r['self_seconds'],reverse=True)[:50],python_by_cumulative=sorted(funcs,key=lambda r:r['cumulative_seconds'],reverse=True)[:50])
    data.update(traced_sql=dict(traced),sql_calls=sum(v['calls'] for v in sql_stats.values()),rows_changed=sum(v['rows_changed'] for v in sql_stats.values()))
    (root/'profile.json').write_text(json.dumps(data,indent=2)+'\n');print(root/'profile.json')

if __name__=='__main__':main()
