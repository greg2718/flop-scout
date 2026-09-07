"""Offline production-copy benchmark. Never open production paths for writing.
Run with --db under /private/tmp/scout-sqlite-latency and a compiled VFS probe.
Artifacts contain timings/schema only, not room payloads. SQLite settings here
are experiments on a disposable copy, NOT worker configuration.
"""
import argparse,ctypes,json,os,pathlib,re,sqlite3,sys,time,statistics
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
p=argparse.ArgumentParser();p.add_argument('--pin-reader',action='store_true');p.add_argument('--replay-existing',action='store_true');p.add_argument('--db',type=pathlib.Path,required=True);p.add_argument('--output',type=pathlib.Path,required=True);p.add_argument('--auto',type=int,default=1000);p.add_argument('--sync',choices=['NORMAL','FULL'],default='NORMAL');p.add_argument('--repeats',type=int,default=3);p.add_argument('--start',type=int,default=1000000000);a=p.parse_args()
assert a.db.resolve().parent==pathlib.Path('/private/tmp/scout-sqlite-latency') and a.db.name!='baseline.sqlite'
assert a.db.is_file();os.environ['FLOP_SCOUT_STATE_DIR']='/private/tmp/scout-sqlite-latency/state'
import flop_scout as scout
probe=ctypes.CDLL('/private/tmp/scout-sqlite-latency/probe.dylib');probe.scout_probe_value.restype=ctypes.c_double;assert probe.scout_probe_init()==0
out=a.output.open('w');events=[]
def emit(x):events.append(x);out.write(json.dumps(x)+'\n');out.flush()
def io():return {(('db','wal')[k]+'_'+op):[probe.scout_probe_value(k,j,f) for f in range(4)] for k in range(2) for j,op in enumerate(['read','write','sync','truncate','control','checkpoint_copy'])}
def delta(before):return {k:[v[i]-before[k][i] for i in (0,1,3)] for k,v in io().items()} # count, ms, bytes
class Conn(sqlite3.Connection):
 def execute(self,sql,*args,**kw):
  t=time.monotonic();r=super().execute(sql,*args,**kw);elapsed=(time.monotonic()-t)*1000
  verb=sql.strip().split()[0].upper()
  if verb in ('INSERT','UPDATE','DELETE'):
   m=re.search(r'(?:INTO|UPDATE|FROM)\s+(\w+)',sql,re.I);emit({'kind':'execute','table':m.group(1) if m else '?','ms':elapsed,'batch':batch[0]})
  return r
 def finish(self,fn):
  if not self.in_transaction or getattr(self,'_finishing',False):return fn()
  self._finishing=True
  before=io();size=wal_size();t=time.monotonic();result=fn();self._finishing=False;ms=(time.monotonic()-t)*1000
  emit({'kind':'commit','ms':ms,'batch':batch[0],'wal_before':size,'wal_after':wal_size(),'io':delta(before)})
  return result
 def commit(self):return self.finish(super().commit)
 def __exit__(self,*args):return self.finish(lambda:super(Conn,self).__exit__(*args))
def wal_size():
 try:return pathlib.Path(str(a.db)+'-wal').stat().st_size
 except FileNotFoundError:return 0
batch=[0];c=sqlite3.connect(a.db,factory=Conn);c.row_factory=sqlite3.Row
c.execute('PRAGMA foreign_keys=ON');c.execute('PRAGMA busy_timeout=5000');c.execute('PRAGMA synchronous='+a.sync);c.execute('PRAGMA wal_autocheckpoint='+str(a.auto))
emit({'kind':'settings','sqlite_version':sqlite3.sqlite_version,'pragmas':{k:c.execute('PRAGMA '+k).fetchone()[0] for k in ['journal_mode','synchronous','wal_autocheckpoint','page_size','page_count','freelist_count','cache_size','mmap_size','temp_store','locking_mode','busy_timeout','fullfsync','checkpoint_fullfsync']}})
reader=None
if a.pin_reader:
 reader=sqlite3.connect(a.db);reader.execute('BEGIN');reader.execute('SELECT count(*) FROM evidence_schema').fetchone()
templates=[]
if a.replay_existing:
 templates=[(r[0],json.loads(r[1])) for r in c.execute("SELECT generation,raw_record_json FROM raw_network_records WHERE room='lobby' ORDER BY seq DESC LIMIT 200")]
 assert len(templates)==200
seq=a.start;start=time.monotonic()
for repeat in range(a.repeats):
 for n in [1,5,10,25,50,100,200]:
  batch[0]=n;records=[{'seq':seq+i,'text':f'Offline persistence benchmark sample {seq+i} '+('data '*100),'sender':'benchmark-unsigned','timestamp':'2026-09-07T00:00:00Z'} for i in range(n)];seq+=n
  generation='copy-benchmark'
  if templates:
   generation=templates[0][0];records=[dict(v) for g,v in templates[:n]];assert all(g==generation for g,v in templates[:n])
  t=time.monotonic();scout.ingest_messages(c,'lobby',records,generation=generation,source='copy-benchmark');elapsed=time.monotonic()-t
  emit({'kind':'batch','rows':n,'seconds':elapsed,'repeat':repeat,'wal_bytes':wal_size()});print(json.dumps(events[-1]),flush=True)
  if a.auto==0 and wal_size()>4*1024*1024:
   before=io();t=time.monotonic();result=tuple(c.execute('PRAGMA wal_checkpoint(PASSIVE)').fetchone());elapsed=(time.monotonic()-t)*1000
   emit({'kind':'checkpoint','mode':'PASSIVE','ms':elapsed,'result':result,'io':delta(before),'wal_bytes':wal_size()});print(json.dumps(events[-1]),flush=True)
if reader:
 reader.close();batch[0]=1
 c.execute("INSERT OR REPLACE INTO evidence_settings VALUES ('benchmark_release','1')");c.commit()
 before=io();t=time.monotonic();result=tuple(c.execute('PRAGMA wal_checkpoint(PASSIVE)').fetchone())
 emit({'kind':'checkpoint','mode':'PASSIVE','ms':(time.monotonic()-t)*1000,'result':result,'io':delta(before),'wal_bytes':wal_size()})
emit({'kind':'summary','rows':seq-a.start,'seconds':time.monotonic()-start,'wal_highwater':max([x.get('wal_after',x.get('wal_bytes',0)) for x in events])})
c.close();out.close()
