"""Bounded operation timings and a scheduler watchdog; never uses SQLite."""
from collections import Counter, deque
from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
import json
import math
import os
from pathlib import Path
import sqlite3
import threading
import time
from datetime import datetime, timezone

_CURRENT = ContextVar('scout_diagnostics', default=None)


def failure_class(error):
    text=str(error).lower()
    status=getattr(error,'status',None) or getattr(error,'code',None)
    if status==429:return 'HTTP_429'
    if status==503:return 'HTTP_503'
    if 'shutdown' in text or 'cancelled' in text:return 'WORKER_SHUTDOWN'
    if isinstance(error,TimeoutError) or 'timeout' in text or 'deadline' in text:return 'HTTP_TIMEOUT'
    if isinstance(error,sqlite3.Error):
        return 'SQLITE_BUSY' if 'locked' in text or 'busy' in text else 'SQLITE_ERROR'
    if 'generation' in text:return 'GENERATION_MISMATCH'
    if 'unresolved' in text or 'coverage' in text:return 'COVERAGE_CONFLICT'
    if isinstance(error,json.JSONDecodeError):return 'PARSE_ERROR'
    if isinstance(error,OSError):return 'SNAPSHOT_IO_ERROR'
    if any(s in text for s in ('incomplete','length','oversized','hash','size limit','ordering','export changed')):return 'EXPORT_INCOMPLETE'
    return 'OTHER'


@contextmanager
def use(diagnostics):
    token=_CURRENT.set(diagnostics)
    try:yield
    finally:_CURRENT.reset(token)


@contextmanager
def operation(name,room=None):
    diag=_CURRENT.get()
    if diag is None:
        yield
        return
    with diag.operation(name,room):yield


def timed(name):
    def decorate(fn):
        @wraps(fn)
        def run(*args,**kwargs):
            with operation(name):return fn(*args,**kwargs)
        return run
    return decorate


class Diagnostics:
    def __init__(self,path=None,clock=time.monotonic,wall=time.time):
        self.path=Path(path) if path else None;self.clock=clock;self.wall=wall
        self.lock=threading.RLock();self.active={};self.recent=deque(maxlen=64)
        self.writer_holds=Counter()
        self.events=deque(maxlen=32);self.values={};self.failures=Counter();self.by_room={}
        self.last_tick=clock();self.tick_duration=0;self.max_lag=0;self.last_stall=0
        self.lifecycle='STARTING';self.queues={};self.closed=threading.Event();self.thread=None

    @contextmanager
    def operation(self,name,room=None):
        ident=threading.get_ident();start=self.clock()
        item=dict(type=name,room=room,started_at=self.wall(),monotonic=start,thread=threading.current_thread().name)
        with self.lock:
            stack=self.active.setdefault(ident,[])
            if room is None and stack:item['room']=stack[-1]['room']
            stack.append(item)
        try:yield
        finally:
            elapsed=(self.clock()-start)*1000
            with self.lock:
                self.active[ident].pop()
                self.values[name+'_duration_ms']=elapsed
                self.values[name+'_total_duration_ms']=self.values.get(name+'_total_duration_ms',0)+elapsed
                self.values[name+'_count']=self.values.get(name+'_count',0)+1
                self.values[name+'_max_duration_ms']=max(elapsed,self.values.get(name+'_max_duration_ms',0))
                if name=='sqlite_write':
                    # Fixed 1 ms histogram, bounded even during a long service run.
                    bucket=min(60000,int(elapsed)+1)
                    self.writer_holds[bucket]+=1
                    rank=max(1,(math.ceil(sum(self.writer_holds.values())*.95)))
                    total=0
                    for bound,count in sorted(self.writer_holds.items()):
                        total+=count
                        if total>=rank:
                            self.values['writer_hold_p95_ms']=bound;break
                    self.values['writer_hold_max_ms']=self.values[name+'_max_duration_ms']
                if elapsed>=100:self.recent.append(dict(item,duration_ms=elapsed))

    def tick(self):
        with self.lock:
            now=self.clock();self.tick_duration=now-self.last_tick
            self.max_lag=max(self.max_lag,max(0,self.tick_duration-0.25)*1000)
            self.last_tick=now

    def failed(self,room,error):
        cls=failure_class(error)
        with self.lock:
            self.failures[cls]+=1;self.by_room.setdefault(room,Counter())[cls]+=1

    def snapshot(self):
        with self.lock:
            age=max(0,self.clock()-self.last_tick);lag=max(0,age-0.25)*1000
            self.max_lag=max(self.max_lag,lag)
            if age>2 and self.clock()-self.last_stall>2:
                self.events.append(dict(type='EVENT_LOOP_STALL',at=self.wall(),lag_ms=lag));self.last_stall=self.clock()
            active=[dict(stack[-1],elapsed=self.clock()-stack[-1]['monotonic']) for stack in self.active.values() if stack]
            primary=max(active,key=lambda x:x['elapsed'],default=None)
            values={k:0 for k in ('sqlite_queue_wait_ms','sqlite_max_queue_wait_ms','sqlite_write_duration_ms',
                'sqlite_write_max_duration_ms','export_fetch_duration_ms','export_parse_duration_ms',
                'export_persist_duration_ms','tail_fetch_duration_ms','tail_persist_duration_ms','snapshot_write_duration_ms')}
            values.update(self.values)
            commit=max(values.get('sqlite_commit_ms',0),max((x['elapsed']*1000 for x in active if x['type']=='sqlite_commit'),default=0))
            checkpoint=max(values.get('sqlite_checkpoint_ms',0),max(((self.clock()-x['monotonic'])*1000 for stack in self.active.values() for x in stack if x['type']=='sqlite_checkpoint'),default=0))
            values['sqlite_commit_health']='BLOCKING' if commit>10000 else 'DEGRADED' if commit>250 else 'HEALTHY'
            values['sqlite_checkpoint_health']='BLOCKING' if checkpoint>10000 else 'DEGRADED' if checkpoint>1000 else 'HEALTHY'
            for key in ('sqlite_commit_ms','sqlite_max_commit_ms','sqlite_checkpoint_ms','sqlite_max_checkpoint_ms',
                        'slow_commit_count','slow_checkpoint_count','sqlite_batch_size','sqlite_rows_per_commit'):
                values.setdefault(key,0)
            return dict(values,worker_lifecycle=self.lifecycle,event_loop_lag_ms=lag,event_loop_max_lag_ms=self.max_lag,
                        event_loop_health='STALLED' if age>2 else 'DEGRADED' if age>0.5 else 'HEALTHY',
                        scheduler_tick_age=age,scheduler_tick_duration=self.tick_duration,
                        active_operation=primary,current_active_operation=primary['type'] if primary else None,
                        current_active_room=primary['room'] if primary else None,
                        current_active_operation_started_at=primary['started_at'] if primary else None,
                        active_operations=active,slowest_recent_operations=sorted(self.recent,key=lambda x:x['duration_ms'],reverse=True)[:10],
                        backfill_failure_scope='current runtime; historical totals remain in evidence metrics',
                        backfill_failures_by_class=dict(self.failures),
                        backfill_failures_by_room={r:dict(v) for r,v in self.by_room.items()},
                        stall_events=list(self.events),queues=dict(self.queues),updated_at=self.wall(),
                        scheduler_snapshot=getattr(self,'scheduler',None),
                        sqlite_max_write_duration_ms=values['sqlite_write_max_duration_ms'])

    def write(self):
        if self.path is None:return
        self.path.parent.mkdir(parents=True,exist_ok=True)
        temp=self.path.with_suffix('.tmp')
        temp.write_text(json.dumps(self.snapshot()))
        os.replace(temp,self.path)

    def start(self):
        def watch():
            expected=self.clock()+0.25
            while not self.closed.wait(0.25):
                lag=max(0,self.clock()-expected)*1000
                with self.lock:
                    self.values['watchdog_wakeup_lag_ms']=lag
                    self.values['watchdog_max_wakeup_lag_ms']=max(lag,self.values.get('watchdog_max_wakeup_lag_ms',0))
                expected=self.clock()+0.25
                try:self.write()
                except OSError:
                    with self.lock:self.values['diagnostic_write_errors']=self.values.get('diagnostic_write_errors',0)+1
        self.thread=threading.Thread(target=watch,name='scout-watchdog',daemon=True);self.thread.start()

    def close(self):
        self.closed.set()
        if self.thread:self.thread.join(timeout=2)
        self.write()


class TimedConnection(sqlite3.Connection):
    """Timing only: retain SQLite transaction, durability and thread checks."""
    def execute(self,sql,*args,**kwargs):
        verb=sql.lstrip().split(None,1)[0].lower() if sql.strip() else 'statement'
        label='sqlite_'+verb if verb in ('select','insert','update','delete') else 'sqlite_statement'
        before=self.in_transaction;changes=self.total_changes;started=time.monotonic()
        with operation(label):result=super().execute(sql,*args,**kwargs)
        if not before and self.in_transaction:
            self.transaction_started=started;self.transaction_changes=changes
        return result

    def _finish(self,fn,rollback=False):
        if not self.in_transaction or getattr(self,'_finishing',False):return fn()
        self._finishing=True;start=time.monotonic();diag=_CURRENT.get()
        def wal_size():
            try:return Path(str(self.diagnostic_path)+'-wal').stat().st_size
            except (AttributeError,FileNotFoundError):return 0
        before=wal_size()
        try:
            with operation('sqlite_rollback' if rollback else 'sqlite_commit'):return fn()
        finally:
            self._finishing=False;elapsed=(time.monotonic()-start)*1000
            if diag is not None and not rollback:
                self.recent_commit_ms=elapsed
                self.turn_commit_max_ms=max(elapsed,getattr(self,'turn_commit_max_ms',0))
                with diag.lock:
                    diag.values.update(sqlite_commit_ms=elapsed,
                        sqlite_max_commit_ms=max(elapsed,diag.values.get('sqlite_max_commit_ms',0)),
                        sqlite_rows_per_commit=self.total_changes-getattr(self,'transaction_changes',self.total_changes),
                        sqlite_rows_per_commit_scope='SQLite total_changes delta, includes metadata and trigger changes',
                        sqlite_transaction_ms=(time.monotonic()-getattr(self,'transaction_started',start))*1000,
                        sqlite_wal_before_commit=before,sqlite_wal_after_commit=wal_size())
                    if elapsed>250:diag.values['slow_commit_count']=diag.values.get('slow_commit_count',0)+1

    def commit(self):return self._finish(super().commit)
    def __exit__(self,*args):
        return self._finish(lambda:super(TimedConnection,self).__exit__(*args),rollback=args[0] is not None)
