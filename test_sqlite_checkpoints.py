"""Maintenance admission, pressure, crash recovery, and timing regressions."""
import json,sqlite3,threading,time,subprocess,sys,os
from concurrent.futures import Future
from pathlib import Path
import pytest
import scout_checkpoint as cp
import scout_diagnostics as dg
from scout_runtime import BatchBudget

@pytest.mark.parametrize('version,safe',[((3,51,0),False),((3,51,2),False),((3,51,3),True),((3,50,7),True),((3,44,6),True),((3,50,6),False)])
def test_checkpoint_version_gate(version,safe):assert cp.concurrent_safe(version)==safe

@pytest.fixture
def store(tmp_path):
 p=tmp_path/'db.sqlite';c=sqlite3.connect(p);c.execute('PRAGMA journal_mode=WAL');c.execute('PRAGMA wal_autocheckpoint=0');c.execute('CREATE TABLE t(x PRIMARY KEY)');c.commit()
 yield p,c
 c.close()

def test_checkpoint_thresholds_and_urgent_tail_priority(store):
 p,c=store;now=[0];d=dg.Diagnostics();m=cp.Checkpoints(p,d,clock=lambda:now[0],soft=1,interval=5)
 try:
  m.changed();now[0]=6;m.step(urgent=True);assert m.future is None
  m.step(writer_busy=True);assert m.future is None
  m.step();assert m.future is not None
  m.future.result();m.step();assert not m.dirty
 finally:m.close()

@pytest.mark.parametrize('result',[(0,100,20),(1,-1,-1)])
def test_passive_incomplete_has_cooldown(store,result):
 p,c=store;now=[6];m=cp.Checkpoints(p,dg.Diagnostics(),clock=lambda:now[0]);m.changed();m.future=Future();m.future.set_result((result,2));m.last_attempt=6
 try:
  m.step();assert m.dirty and m.failed and m.future is None
 finally:m.close()

def test_checkpoint_exception_retains_pending(store):
 p,c=store;m=cp.Checkpoints(p,dg.Diagnostics());m.changed();m.future=Future();m.future.set_exception(sqlite3.OperationalError('busy'))
 try:m.step();assert m.dirty and 'OperationalError' in m.failed
 finally:m.close()

@pytest.mark.parametrize('concurrent',[False,True])
def test_checkpoint_off_scheduler_and_readers_continue(store,concurrent):
 p,c=store;now=[0];d=dg.Diagnostics();m=cp.Checkpoints(p,d,clock=lambda:now[0],soft=1,interval=1,concurrent=concurrent)
 entered=threading.Event();release=threading.Event();threads=[]
 original=m.checkpoint
 def slow():
  threads.append(threading.get_ident());entered.set();assert release.wait(5);return original()
 m.checkpoint=slow
 try:
  m.changed();now[0]=2;m.step();assert entered.wait(2);assert threads[0]!=threading.get_ident()
  assert m.blocks_writes is (not concurrent)
  # Read-only SQLite reads and the scheduler continue during maintenance.
  with sqlite3.connect(p.as_uri()+'?mode=ro',uri=True) as r:assert r.execute('SELECT count(*) FROM t').fetchone()[0]==0
  for _ in range(50):d.tick();m.step(urgent=True)
  assert d.snapshot()['event_loop_health']=='HEALTHY'
 finally:release.set();m.close()

def test_hard_wal_bound_stops_admission_without_forcing_urgent_checkpoint(store):
 p,c=store;m=cp.Checkpoints(p,dg.Diagnostics(),hard=1,soft=1)
 try:
  m.changed();m.step(urgent=True);assert m.blocks_writes and m.future is None
  assert m.diag.values['sqlite_checkpoint_pressure']=='BLOCKING'
 finally:m.close()

def test_writes_during_checkpoint_remain_pending(store):
 p,c=store;m=cp.Checkpoints(p,dg.Diagnostics());m.changed();m.admitted_epoch=m.epoch;m.changed();m.future=Future();m.future.set_result(((0,10,10),1))
 try:m.step(urgent=True);assert m.dirty
 finally:m.close()

def test_commit_budget_shrink_and_cautious_recovery():
 b=BatchBudget();b.size=100;b.observe(100,.001,commit_ms=11000);assert b.size==25
 b.observe(25,.001,checkpoint_ms=5000);assert b.size==6
 b.observe(6,.001,tail_age=30);assert b.size==12
 b.observe(12,.001);assert b.size==24

def test_commit_instrumentation_counts_real_commit_once(tmp_path):
 d=dg.Diagnostics();c=sqlite3.connect(tmp_path/'db',factory=dg.TimedConnection);c.diagnostic_path=tmp_path/'db';c.execute('CREATE TABLE t(x)')
 try:
  with dg.use(d):
   with c:c.execute('INSERT INTO t VALUES(1)')
  x=d.snapshot();assert x['sqlite_commit_count']==1;assert x['sqlite_rows_per_commit']==1
  assert x['sqlite_commit_ms']>=0 and x['sqlite_transaction_ms']>=x['sqlite_commit_ms']
 finally:c.close()

def test_active_long_commit_unmistakably_blocking():
 now=[0];d=dg.Diagnostics(clock=lambda:now[0])
 with d.operation('sqlite_commit'):
  now[0]=11;d.tick();assert d.snapshot()['sqlite_commit_health']=='BLOCKING'

def test_active_checkpoint_health_includes_nested_phases():
 now=[0];d=dg.Diagnostics(clock=lambda:now[0])
 with d.operation('sqlite_checkpoint'):
  now[0]=9
  with d.operation('sqlite_checkpoint_restart'):
   now[0]=11;d.tick();assert d.snapshot()['sqlite_checkpoint_health']=='BLOCKING'

@pytest.mark.parametrize('mode',['NORMAL','FULL'])
def test_crash_during_checkpoint_keeps_committed_evidence(tmp_path,mode):
    p=tmp_path/'db';ready=tmp_path/'ready'
    library=tmp_path/'probe.dylib'
    subprocess.run(['clang','-shared','-fPIC','-O2',str(Path(__file__).parent/'scripts/sqlite_vfs_probe.c'),'-lsqlite3','-o',str(library)],check=True,capture_output=True)
    code='''import sqlite3,sys,os,ctypes
p,ready,mode,library=sys.argv[1:];probe=ctypes.CDLL(library);assert probe.scout_probe_init()==0
c=sqlite3.connect(p);c.execute('PRAGMA journal_mode=WAL');c.execute('PRAGMA wal_autocheckpoint=0');c.execute('PRAGMA synchronous='+mode);c.execute('CREATE TABLE raw(id PRIMARY KEY,hash UNIQUE)');c.execute('CREATE TABLE parsed(id PRIMARY KEY,raw_hash REFERENCES raw(hash))');c.execute('PRAGMA foreign_keys=ON')
with c:
 c.executemany('INSERT INTO raw VALUES(?,?)',[(i,str(i)) for i in range(1000)])
 c.executemany('INSERT INTO parsed VALUES(?,?)',[(i,str(i)) for i in range(1000)])
# Real abrupt process exit during the fifth main-database checkpoint page write.
probe.scout_probe_crash_after(5)
c.execute('PRAGMA wal_checkpoint(PASSIVE)')
'''
    r=subprocess.run([sys.executable,'-c',code,str(p),str(ready),mode,str(library)]);assert r.returncode==23
    with sqlite3.connect(p) as c:
        assert c.execute('PRAGMA integrity_check').fetchone()[0]=='ok'
        assert not c.execute('PRAGMA foreign_key_check').fetchall()
        assert c.execute('SELECT count(*) FROM parsed JOIN raw ON parsed.raw_hash=raw.hash').fetchone()[0]==1000

def test_shutdown_pending_wal_preserved(store):
 p,c=store;c.execute('INSERT INTO t VALUES(1)');c.commit();reader=sqlite3.connect(p);reader.execute('BEGIN');reader.execute('SELECT * FROM t').fetchall()
 m=cp.Checkpoints(p,dg.Diagnostics());m.changed();m.close();m.close()
 assert c.execute('SELECT * FROM t').fetchone()[0]==1
 reader.close()

def test_recycled_wal_capacity_does_not_deadlock_writer(store):
 p,c=store;m=cp.Checkpoints(p,dg.Diagnostics(),hard=1)
 try:
  m.changed();m.mode='RESTART';m.admitted_epoch=m.epoch;m.future=Future();m.future.set_result(((0,10,10),1));m.step(urgent=True)
  m.changed();m.refresh();assert not m.blocks_writes
 finally:m.close()

def test_soft_limit_drains_pages_but_readers_resume_during_checkpoint(store):
 p,c=store;m=cp.Checkpoints(p,dg.Diagnostics(),soft=1)
 try:
  m.changed();m.refresh();assert m.drain_tail_admission
  m.future=Future();assert not m.drain_tail_admission
  m.future.set_result(((0,1,1),1))
 finally:m.close()

def test_checkpoint_retry_not_delayed_until_large_time_interval(store):
 p,c=store;now=[0];m=cp.Checkpoints(p,dg.Diagnostics(),clock=lambda:now[0],soft=1,interval=5)
 try:
  m.changed();now[0]=1.1;m.step();assert m.future is not None
 finally:m.close()

def test_high_watermark_drains_admitted_tail_before_maintenance(tmp_path):
 from types import SimpleNamespace
 from scout_runtime import Runtime
 r=Runtime(tmp_path/'db',{})
 r.checkpointer=SimpleNamespace(blocks_writes=True,future=None,concurrent=True,pressure=True)
 r.tails={'lobby':{'turn_ready':0,'queued':0}};submitted=[]
 r.submit_write=lambda kind,*args:submitted.append(kind)
 r.turns=16;r.export={'ready':True}  # export fairness must not bypass WAL pressure
 r.choose_write();assert submitted==['tail']
 r.tails.clear();submitted.clear();r.export={'ready':True}
 r.choose_write();assert not submitted  # no unbounded export/status work
 r.checkpointer.future=Future();r.checkpointer.concurrent=False;r.tails={'lobby':{'turn_ready':0,'queued':0}}
 r.choose_write();assert not submitted  # old SQLite must still serialize

def test_high_watermark_checkpoint_holds_writer_gap_even_when_patched(store):
 p,c=store;now=[0];m=cp.Checkpoints(p,dg.Diagnostics(),clock=lambda:now[0],soft=1,hard=1,concurrent=True)
 try:
  m.changed();now[0]=2;m.step();assert m.future is not None and m.serial_turn and m.blocks_writes
 finally:m.close()

def test_reader_can_allow_passive_completion_but_prevent_reuse(store):
 p,c=store;reader=sqlite3.connect(p);reader.execute('BEGIN');reader.execute('SELECT * FROM t').fetchall()
 now=[0];m=cp.Checkpoints(p,dg.Diagnostics(),clock=lambda:now[0],hard=1,soft=1,concurrent=True)
 try:
  m.changed();now[0]=2;m.step();result,ms=m.future.result(timeout=3)
  assert result[0]==1 and result[1]==result[2] and m.mode=='RESTART'
  m.step();assert m.pressure and m.dirty
  reader.close();now[0]=4;m.step();result,ms=m.future.result(timeout=3)
  assert result[0]==0;m.step();assert not m.pressure
 finally:reader.close();m.close()
