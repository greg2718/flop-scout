"""Bounded checkpoint maintenance; no schema/DML or network operations.

Patched SQLite permits a checkpoint-only connection alongside the sole DML
owner. Older versions serialize admission to avoid the documented WAL-reset
race. A saturated WAL stops write admission rather than growing indefinitely.
"""
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import sqlite3
import time
import scout_diagnostics as diagnostics


def concurrent_safe(version=None):
    v=tuple(version or sqlite3.sqlite_version_info)
    return v>=(3,51,3) or (v[:2]==(3,50) and v>=(3,50,7)) or (v[:2]==(3,44) and v>=(3,44,6))


class Checkpoints:
    def __init__(self,path,diag,clock=time.monotonic,soft=4*1024*1024,hard=128*1024*1024,interval=5,concurrent=None):
        self.path=Path(path);self.diag=diag;self.clock=clock
        self.soft=soft;self.hard=hard;self.interval=interval
        self.concurrent=concurrent_safe() if concurrent is None else concurrent
        self.pool=ThreadPoolExecutor(max_workers=1,thread_name_prefix='scout-checkpoint')
        self.future=None;self.connection=None;self.last_attempt=clock();self.dirty=False
        self.wal_bytes=0;self.failed=None;self.pressure=False;self.page_size=4096
        self.last_ms=0;self.max_ms=0;self.epoch=0;self.admitted_epoch=0;self.closed=False
        self.completed_capacity=0
        self.serial_turn=not self.concurrent
        self.mode='PASSIVE'

    def changed(self):self.dirty=True;self.epoch+=1

    def refresh(self):
        try:self.wal_bytes=Path(str(self.path)+'-wal').stat().st_size
        except FileNotFoundError:self.wal_bytes=0
        self.completed_capacity=min(self.completed_capacity,self.wal_bytes)
        # SQLite can recycle a fully checkpointed WAL without truncating its
        # physical allocation. Reused capacity is not fresh unbounded growth.
        self.pressure=self.wal_bytes>=self.hard and self.dirty and self.wal_bytes>self.completed_capacity
        with self.diag.lock:
            self.diag.values.update(sqlite_wal_bytes=self.wal_bytes,
                sqlite_wal_pages=max(0,(self.wal_bytes-32)//(self.page_size+24)),
                sqlite_wal_pages_scope='physical file capacity, not uncheckpointed frames',
                sqlite_checkpoint_pending=bool(self.dirty or self.future),
                sqlite_checkpoint_mode=self.mode,sqlite_checkpoint_concurrency=('serialized_recycle' if self.future and self.serial_turn else 'concurrent') if self.concurrent else 'serialized_unpatched_sqlite',
                sqlite_checkpoint_pressure='BLOCKING' if self.pressure else 'DEGRADED' if self.failed else 'HEALTHY',
                sqlite_checkpoint_error=self.failed)
            self.diag.values['sqlite_wal_high_water']=max(self.wal_bytes,self.diag.values.get('sqlite_wal_high_water',0))

    @property
    def blocks_writes(self):return self.pressure or (self.future is not None and self.serial_turn)

    @property
    def drain_tail_admission(self):
        # Finish already-fetched pages before admitting another burst. This
        # creates a maintenance slot without placing a checkpoint ahead of an
        # urgent tail. Once maintenance is active, readers may continue again.
        return self.pressure or (self.dirty and self.wal_bytes>=self.soft and self.future is None)

    def checkpoint(self):
        # Created, used, and closed only on the maintenance thread. No DML.
        if self.connection is None:
            self.connection=sqlite3.connect(self.path.resolve().as_uri()+'?mode=rw',uri=True,timeout=0)
            self.connection.execute('PRAGMA busy_timeout=0')
            self.connection.execute('PRAGMA wal_autocheckpoint=0')
            self.connection.execute('PRAGMA synchronous=FULL')
            self.page_size=self.connection.execute('PRAGMA page_size').fetchone()[0]
        t=self.clock()
        with diagnostics.use(self.diag),diagnostics.operation('sqlite_checkpoint'):
            self.mode='PASSIVE'
            with diagnostics.operation('sqlite_checkpoint_passive'):
                result=tuple(self.connection.execute('PRAGMA wal_checkpoint(PASSIVE)').fetchone())
            if self.serial_turn and self.wal_bytes>=self.hard and result[0]==0 and result[1]==result[2]:
                # PASSIVE completion alone does not promise WAL reuse if a
                # reader still holds a WAL snapshot. Zero busy timeout makes
                # this a fail-fast lock attempt, not an unbounded reader wait.
                self.mode='RESTART'
                with diagnostics.operation('sqlite_checkpoint_restart'):
                    result=tuple(self.connection.execute('PRAGMA wal_checkpoint(RESTART)').fetchone())
        ended=self.clock();self.last_interval=(t,ended)
        return result,(ended-t)*1000

    def step(self,urgent=False,writer_busy=False):
        if self.future and self.future.done():
            try:
                (busy,log,done),ms=self.future.result()
                self.last_ms=ms;self.max_ms=max(self.max_ms,ms)
                complete=busy==0 and log>=0 and done==log
                if complete:
                    try:
                        size=Path(str(self.path)+'-wal').stat().st_size
                        self.completed_capacity=size if self.mode=='RESTART' else min(size,self.hard-1)
                    except FileNotFoundError:self.completed_capacity=0
                self.dirty=not complete or self.epoch!=self.admitted_epoch
                self.failed=None if complete else self.mode+' incomplete or busy; retry after cooldown'
                with self.diag.lock:
                    self.diag.values.update(sqlite_checkpoint_ms=ms,sqlite_max_checkpoint_ms=self.max_ms,
                        sqlite_checkpoint_log_frames=log,sqlite_checkpointed_frames=done)
                    if ms>1000:self.diag.values['slow_checkpoint_count']=self.diag.values.get('slow_checkpoint_count',0)+1
            except Exception as exc:
                self.failed=type(exc).__name__+': '+str(exc);self.dirty=True
            self.future=None
        self.refresh()
        # Never start maintenance ahead of a fetched tail. Runtime drains only
        # its finite admitted tail work at high pressure, creating a safe slot.
        # Pinned readers/errors remain visible; there is no destructive fallback.
        due=self.dirty and (self.wal_bytes>=self.soft or self.clock()-self.last_attempt>=self.interval)
        if due and not urgent and not writer_busy and self.future is None and self.clock()-self.last_attempt>=min(1,self.interval):
            self.last_attempt=self.clock();self.admitted_epoch=self.epoch
            # A high-water recycle turn needs a writer gap through completion;
            # otherwise continuous commits can indefinitely prevent WAL reset.
            self.serial_turn=not self.concurrent or self.wal_bytes>=self.hard
            self.future=self.pool.submit(self.checkpoint)

    def close(self):
        # No forced FULL/TRUNCATE checkpoint. SQLite closes on the maintenance
        # thread; outstanding WAL is retained/recovered by SQLite after a crash.
        if self.closed:return
        self.closed=True
        def finish():
            if self.connection:self.connection.close()
        try:self.pool.submit(finish).result()
        finally:self.pool.shutdown(wait=True)
