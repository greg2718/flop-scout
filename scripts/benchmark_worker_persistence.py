"""Offline worker replay on a disposable production-sized copy; no network.
See docs/sqlite-checkpoint-latency.md for setup and limitations.
"""
import os,sys,pathlib,sqlite3,json,threading,time,statistics,copy
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]));os.environ['FLOP_SCOUT_STATE_DIR']='/private/tmp/scout-sqlite-latency/runtime-state'
import flop_scout as scout,scout_runtime as rt,scout_worker as worker,scout_checkpoint as cp,scout_diagnostics as dg
path=pathlib.Path(sys.argv[1] if len(sys.argv)>1 else '/private/tmp/scout-sqlite-latency/runtime.sqlite');assert path.is_file() and path.resolve().parent==pathlib.Path('/private/tmp/scout-sqlite-latency') and path.name!='baseline.sqlite'
rooms=['lobby','faucet','technocore','kibble','tclk-offers','consensus_layer','a2a_mesh_router','flop-evidence-scout','mb-flop-scout']
c=sqlite3.connect(path);c.row_factory=sqlite3.Row;templates={};nextseq={}
for room in rooms:
 templates[room]=[json.loads(x[0]) for x in c.execute('SELECT raw_record_json FROM raw_network_records WHERE room=? ORDER BY seq DESC LIMIT 8',(room,))]
 nextseq[room]=c.execute('SELECT max(seq) FROM raw_network_records WHERE room=?',(room,)).fetchone()[0] or 0
before=dict(c.execute('SELECT name,value FROM evidence_metrics'));c.close();lock=threading.Lock();stop=threading.Event();commits=[];checks=[];samples=[];generated={r:0 for r in rooms}
original=dg.TimedConnection._finish
# Observe real commits; do not change transaction behavior.
def finish(self,fn,rollback=False):
 measure=self.in_transaction and not getattr(self,'_finishing',False) and not rollback
 result=original(self,fn,rollback)
 if measure:commits.append(getattr(self,'recent_commit_ms',0))
 return result
dg.TimedConnection._finish=finish
original_cp=cp.Checkpoints.checkpoint
def checkpoint(self):
 result=original_cp(self);checks.append(result[1]);return result
cp.Checkpoints.checkpoint=checkpoint

def reader(room,kind,generation,cursor):
 assert kind=='tail';time.sleep(.10)
 n=200 if room in ['lobby','faucet'] else 10
 with lock:
  records=[]
  for i in range(n):
   raw=copy.deepcopy(templates[room][i%len(templates[room])]) if templates[room] else {'text':'offline sample','sender':'unsigned'}
   nextseq[room]+=1;raw['seq']=nextseq[room];records.append(raw)
  generated[room]+=n
 return {'messages':records,'latest_seq':nextseq[room]},generation
settings=worker.configuration(rooms)
for v in settings.values():v['export_backfill_enabled']=False
r=rt.Runtime(path,settings,reader=reader,stop=stop);errors=[]
def run():
 try:r.run()
 except BaseException as e:errors.append(repr(e))
th=threading.Thread(target=run);start=time.monotonic();th.start()
for _ in range(int(os.environ.get("SCOUT_BENCH_SECONDS","120"))):
 time.sleep(1);x=r.diag.snapshot();samples.append(x)
 if not th.is_alive():break
stop.set();th.join();elapsed=time.monotonic()-start
root=path.parent
(root/(path.stem+'-samples.json')).write_text(json.dumps(samples))
def distribution(v):
 v=sorted(v);return {'n':len(v),'p50_ms':statistics.median(v) if v else None,'p95_ms':v[int(.95*(len(v)-1))] if v else None,'max_ms':max(v) if v else None}
result={'sqlite_version':sqlite3.sqlite_version,'seconds':elapsed,'generated_records':generated,'commits':distribution(commits),'checkpoints':distribution(checks),'checkpoint_concurrency':r.checkpointer.concurrent,'max_tail_queue_age':max(x['queues'].get('oldest_tail_queue_age',0) for x in samples),'wal_high_water':max(x.get('sqlite_wal_bytes',0) for x in samples),'errors':errors}
with sqlite3.connect(path.as_uri()+'?mode=ro',uri=True) as measured:
 after=dict(measured.execute('SELECT name,value FROM evidence_metrics'))
result['committed_raw_records']=after['records_ingested']-before['records_ingested']
result['rows_per_second']=result['committed_raw_records']/elapsed
result['max_completed_tail_page_seconds']=r.diag.snapshot().get('tail_page_persist_max_duration_ms',0)/1000
result['wal_high_water']=max(x.get('sqlite_wal_high_water',x.get('sqlite_wal_bytes',0)) for x in samples)
result['safety']={k:after.get(k) for k in ['network_writes','url_follows','wallet_accesses','faucet_claims','kibble_claims','tclk_actions','private_key_accesses','cursor_regressions','database_errors']}
(root/(path.stem+'-results.json')).write_text(json.dumps(result,indent=2));print(json.dumps(result,indent=2))
