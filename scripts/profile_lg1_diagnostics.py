"""Instrument existing synthetic producer; profiling results are not throughput gates."""
import argparse,cProfile,gc,json,pathlib,pstats,sys,tracemalloc
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from scripts.benchmark_projection_lg1 import trial
from scout_projection_contract import connect,canonical,loads
from scout_projection_source import map_raw
parser=argparse.ArgumentParser();parser.add_argument('--root',type=pathlib.Path,required=True);parser.add_argument('--mode',choices=['A1','LG1_REPORTED'],required=True)
args=parser.parse_args();root=args.root.resolve();mode=args.mode
if not root.is_relative_to(pathlib.Path('/private/tmp')):raise ValueError('Temporary root required')
root.mkdir(exist_ok=True)
pr=cProfile.Profile();timing=pr.runcall(trial,root/(mode+'-profile'),mode,1000);pr.dump_stats(str(root/(mode+'.pstats')))
st=pstats.Stats(pr)
entries=[]
for (file,line,name),(primitive,calls,self_time,cumulative,callers) in st.stats.items():
 if 'scout_projection' in file or 'sqlite3' in name or name in ('dumps','loads','encode','decode','iterencode'):
  entries.append(dict(file=file,line=line,function=name,calls=calls,self_seconds=self_time,cumulative_seconds=cumulative))
entries.sort(key=lambda x:-x['self_seconds'])
path=root/(mode+'-profile')/'source.sqlite';revision='A1' if mode=='A1' else 'A1-LG1'
with connect(path,True) as c:
 ids=[r[0] for r in c.execute('SELECT raw_record_id FROM raw_network_records ORDER BY seq LIMIT 200')]
 query_count=[0]
 c.set_trace_callback(lambda sql:query_count.__setitem__(0,query_count[0]+1))
 gc.collect();tracemalloc.start();batch=[map_raw(c,r,revision=revision) for r in ids]
 mapped_current,mapped_peak=tracemalloc.get_traced_memory();serialized=sum(len(canonical(b)) for b in batch)
 snapshot=tracemalloc.take_snapshot();top=[dict(location=str(s.traceback),bytes=s.size,count=s.count) for s in snapshot.statistics('lineno')[:12]]
 tracemalloc.stop()
 out=dict(mode=mode,profiled_trial=timing,profile=entries,mapped_200=dict(sql_statements=query_count[0],serialized_bytes=serialized,traced_live_bytes=mapped_current,traced_peak_bytes=mapped_peak,allocation_sites=top))
 (root/(mode+'-profile.json')).write_text(json.dumps(out,indent=2)+'\n')
 print(mode,'done')
