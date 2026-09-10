"""One observation process: bounded network tasks, one SQLite owner thread."""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import signal
import threading
import time
import scout_coverage as coverage
import scout_evidence as evidence

DEFAULTS = {
    'lobby': {'poll_interval_seconds':1, 'priority':0},
    'faucet': {'poll_interval_seconds':2, 'priority':1},
    'technocore': {'poll_interval_seconds':20, 'priority':2},
    'kibble': {'poll_interval_seconds':20, 'priority':2},
    'tclk-offers': {'poll_interval_seconds':30, 'priority':3},
}


def configuration(rooms, path=None, collections=None):
    result = {room:{'poll_interval_seconds':60,'priority':10,'export_backfill_enabled':True,
                    **DEFAULTS.get(room,{})} for room in rooms}
    for collection in (collections or {}).values():
        if not collection.get('enabled'): continue
        for room in collection['rooms']:
            if room in result:
                result[room].update({k:collection[k] for k in ('poll_interval_seconds','priority','export_backfill_enabled') if k in collection})
    if path and Path(path).exists():
        overrides=json.loads(Path(path).read_text())
        if not isinstance(overrides,dict): raise ValueError('Polling configuration must map configured rooms to settings')
        for room,settings in overrides.items():
            if room not in result or not isinstance(settings,dict): raise ValueError('Unknown polling room')
            if set(settings)-{'poll_interval_seconds','priority','export_backfill_enabled'}: raise ValueError('Unknown polling setting')
            result[room].update(settings)
    for settings in result.values():
        interval=settings['poll_interval_seconds']
        if type(interval) not in (int,float) or not 0.5<=interval<=86400: raise ValueError('Poll interval must be 0.5..86400 seconds')
        if type(settings['priority']) is not int or not 0<=settings['priority']<=100: raise ValueError('Priority must be 0..100')
        if type(settings['export_backfill_enabled']) is not bool: raise ValueError('export_backfill_enabled must be boolean')
    return result


def backoff(failures, interval, error):
    delay=min(max(300,interval),max(5,interval)*2**min(failures-1,6))
    retry=getattr(error,'retry_after',None)
    if retry is None and getattr(error,'headers',None): retry=error.headers.get('Retry-After')
    if retry:
        try: delay=max(delay,float(retry))
        except (ValueError,TypeError):
            from email.utils import parsedate_to_datetime
            try: delay=max(delay,(parsedate_to_datetime(retry)-datetime.now(timezone.utc)).total_seconds())
            except (ValueError,TypeError): pass
    return delay


class Coordinator:
    def __init__(self, conn, settings, *, concurrency=4, reader=None, clock=time.monotonic,
                 wall_clock=time.time, stop=None):
        if not 1<=concurrency<=8: raise ValueError('Concurrency must be 1..8')
        self.conn=conn; self.settings=settings; self.clock=clock; self.wall_clock=wall_clock
        self.stop=stop or threading.Event(); self.reader=reader or self.read
        self.concurrency=concurrency; self.due={r:clock() for r in settings}
        self.failures={r:0 for r in settings}; self.inflight={}; self.active_rooms=set()
        self.last_observation={}; self.owner=threading.get_ident(); self.exports=[]
        self.needs_tail_refresh=set(); self.backfill_pending={}; self.backfill_due={}
        self.backfill_failures={r:0 for r in settings}
        self.started_at=wall_clock(); self.last_published=float('-inf')
        self.polls={r:dict(target_interval_seconds=v['poll_interval_seconds'],
                          last_poll_started=None,last_poll_completed=None,
                          max_observed_poll_age=0,polls_completed=0) for r,v in settings.items()}
        self.once=False; self.tail_done=set(); self.export_done=set()
        for row in conn.execute('SELECT * FROM evidence_room_health'):
            room=row['room']
            if room not in settings: continue
            self.failures[room]=row['failures']
            self.polls[room]['last_poll_completed']=row['last_poll_at']
            if row['failures']:
                self.needs_tail_refresh.add(room)
                if row['next_due']:
                    remaining=datetime.fromisoformat(row['next_due']).timestamp()-wall_clock()
                    self.due[room]=clock()+max(0,remaining)
        saved=conn.execute("SELECT value FROM evidence_settings WHERE name='worker_scheduler_v1'").fetchone()
        if saved:
            previous=json.loads(saved[0])
            for room, info in previous['rooms'].items():
                if room not in settings: continue
                for key in ('last_poll_started','last_poll_completed','max_observed_poll_age','polls_completed'):
                    self.polls[room][key]=info[key]
                self.backfill_failures[room]=info.get('backfill_failures',0)
                retry=info.get('backfill_next_due')
                if retry: self.backfill_due[room]=clock()+max(0,datetime.fromisoformat(retry).timestamp()-wall_clock())
            for room, stamp in previous.get('pending_backfills',{}).items():
                if room in settings:
                    self.backfill_pending[room]=clock()-max(0,wall_clock()-datetime.fromisoformat(stamp).timestamp())

    def stamp(self, monotonic=None):
        value=self.wall_clock() if monotonic is None else self.wall_clock()+monotonic-self.clock()
        return datetime.fromtimestamp(value,timezone.utc).isoformat()

    def read(self, room, kind, generation, cursor):
        import flop_scout as scout
        if kind=='export': return scout.fetch_room_export(room,generation,stop_event=self.stop)
        return scout.observation_only(scout.fetch_room_view)(room,200,since=cursor,allow_missing=True)

    def candidates(self):
        # EDF: requeued work receives a new future deadline and cannot overtake
        # a room already due. Static priority is only a simultaneous-deadline tie.
        return sorted((r for r in self.settings if r not in self.active_rooms and self.due[r]<=self.clock()
                       and not (self.once and r in self.tail_done)),
                      key=lambda r:(self.due[r],self.settings[r]['priority'],r))

    def discover_backfills(self):
        import flop_scout as scout
        for room in self.settings:
            cursor=scout.room_cursor(self.conn,room)
            row=self.conn.execute('SELECT * FROM source_coverage_state WHERE room=? AND generation=?',
                                  (room,cursor['generation'])).fetchone()
            eligible=(row and row['backfill_required'] and self.settings[room]['export_backfill_enabled']
                      and cursor['generation'] not in (None,'GENERATION_MISSING','UNKNOWN_LEGACY')
                      and not (self.once and (room in self.export_done or (room in self.tail_done and self.failures[room]))))
            if eligible: self.backfill_pending.setdefault(room,self.clock())
            else: self.backfill_pending.pop(room,None)

    def schedule(self,pool,export_pool=None):
        import flop_scout as scout
        for room in self.candidates():
            if sum(v[1]=='tail' for v in self.inflight.values())>=self.concurrency or self.stop.is_set(): break
            cursor=scout.room_cursor(self.conn,room)
            future=pool.submit(self.reader,room,'tail',cursor['generation'],cursor['last_seq'])
            self.inflight[future]=(room,'tail',self.clock(),cursor['generation'])
            self.active_rooms.add(room)
            self.polls[room]['last_poll_started']=self.stamp()
        self.discover_backfills()
        # One independent slow reader; its queued/processing snapshot counts
        # against the same slot. It cannot occupy any tail reader capacity.
        if export_pool is not None and not self.exports and not any(v[1]=='export' for v in self.inflight.values()) and not self.stop.is_set():
            for room in self.backfill_pending:
                if room in self.needs_tail_refresh or self.backfill_due.get(room,0)>self.clock(): continue
                cursor=scout.room_cursor(self.conn,room)
                row=self.conn.execute('SELECT * FROM source_coverage_state WHERE room=? AND generation=?',(room,cursor['generation'])).fetchone()
                resumable=self.conn.execute('SELECT * FROM evidence_export_snapshots WHERE room=? AND generation=? ORDER BY retrieved_at DESC LIMIT 1',(room,cursor['generation'])).fetchone()
                if resumable and (resumable['processed_records']<resumable['record_count'] or resumable['status']=='VALIDATED' or (row['coverage_status']=='BACKFILLING' and (resumable['last_seq'] or 0)>=row['observed_high_water'])):
                    future=export_pool.submit(lambda snapshot=dict(resumable):snapshot)
                else:
                    future=export_pool.submit(self.reader,room,'export',cursor['generation'],cursor['last_seq'])
                self.inflight[future]=(room,'export',self.clock(),cursor['generation'])
                if self.once: self.export_done.add(room)
                break
        self.publish_metrics()

    def health(self,room,started,error=None,high=None):
        now=self.clock(); settings=self.settings[room]
        self.failures[room]=self.failures[room]+1 if error else 0
        delay=backoff(self.failures[room],settings['poll_interval_seconds'],error) if error else settings['poll_interval_seconds']
        self.due[room]=now+delay
        info=self.polls[room]
        baseline=datetime.fromisoformat(info['last_poll_completed']).timestamp() if info['last_poll_completed'] else self.started_at
        info['max_observed_poll_age']=max(info['max_observed_poll_age'],self.wall_clock()-baseline)
        if not error:
            info['last_poll_completed']=self.stamp(); info['polls_completed']+=1
        rate=None
        if high is not None:
            previous=self.last_observation.get(room)
            if previous and high>=previous[1] and now>previous[0]: rate=(high-previous[1])/(now-previous[0])
            self.last_observation[room]=(now,high)
        with self.conn:
            self.conn.execute('''INSERT INTO evidence_room_health VALUES (?,?,?,?,?,?,?)
                ON CONFLICT(room) DO UPDATE SET last_poll_at=excluded.last_poll_at,poll_duration=excluded.poll_duration,
                effective_rate=COALESCE(excluded.effective_rate,evidence_room_health.effective_rate),next_due=excluded.next_due,
                failures=excluded.failures,last_error=excluded.last_error''',
                (room,info['last_poll_completed'],now-started,rate,self.stamp(self.due[room]),self.failures[room],str(error) if error else None))

    def export_finished(self,room,error=None):
        # Repeated work joins the BACK of the FIFO on the next discovery pass.
        self.backfill_pending.pop(room,None)
        self.backfill_failures[room]=self.backfill_failures[room]+1 if error else 0
        self.backfill_due[room]=self.clock()+(backoff(self.backfill_failures[room],self.settings[room]['poll_interval_seconds'],error) if error else 0)
        if error: self.needs_tail_refresh.add(room)

    def persist(self,future):
        import flop_scout as scout
        assert threading.get_ident()==self.owner, 'SQLite persistence must stay on coordinator thread'
        room,kind,started,generation=self.inflight.pop(future)
        persistence_started=False
        try:
            result=future.result()
            if kind=='tail':
                persistence_started=True
                result=scout.service_poll_room(self.conn,room,response=result)
                if result['continuity']=='READ_FAILED': raise RuntimeError(result['last_read_error'])
                self.health(room,started,high=result['observed_high_water'])
                self.needs_tail_refresh.discard(room)
            else:
                if result['room']!=room or result['generation']!=str(generation): raise ValueError('Backfill response room/generation mismatch')
                if scout.room_cursor(self.conn,room)['generation']!=str(generation): raise ValueError('Generation changed during export download')
                self.exports.append((room,started,generation,scout.persist_export_steps(self.conn,result)))
        except (Exception,SystemExit) as exc:
            if kind=='export':
                coverage.failed(self.conn,room,generation,exc); self.export_finished(room,exc)
            else:
                if not persistence_started:
                    with self.conn: evidence.bump(self.conn,'read_failures')
                self.health(room,started,error=exc)
        finally:
            if kind=='tail':
                self.active_rooms.discard(room); self.tail_done.add(room)
            self.publish_metrics(force=True)

    def persist_export_batch(self):
        import flop_scout as scout
        assert threading.get_ident()==self.owner, 'SQLite persistence must stay on coordinator thread'
        if not self.exports: return
        room,started,generation,iterator=self.exports[0]
        try:
            result=next(iterator)
            if isinstance(result,dict):
                # A tail may have moved to another epoch while this snapshot was
                # processed. Keep its provenance, never overwrite the active epoch.
                if scout.room_cursor(self.conn,room)['generation']==str(generation):
                    scout.update_room_cursor(self.conn,room,generation,result['coverage_cursor'])
                    scout.set_state(self.conn,f'cursor:{room}:continuity',result['coverage_status'])
                error=RuntimeError('Export coverage unresolved') if result['backfill_required'] else None
                self.export_finished(room,error); self.exports.pop(0)
        except (Exception,SystemExit) as exc:
            coverage.failed(self.conn,room,generation,exc)
            self.export_finished(room,exc); self.exports.pop(0)
        self.publish_metrics()

    def publish_metrics(self,force=False):
        if not force and self.clock()-self.last_published<1: return
        snapshot=dict(started_at=datetime.fromtimestamp(self.started_at,timezone.utc).isoformat(),
                      updated_at=self.stamp(),rooms={},
                      pending_backfills={r:self.stamp(t) for r,t in self.backfill_pending.items()},
                      pending_tails={r:self.stamp(self.due[r]) for r in self.settings if self.due[r]<=self.clock()},
                      tail_inflight=sum(v[1]=='tail' for v in self.inflight.values()),
                      export_inflight=sum(v[1]=='export' for v in self.inflight.values())+len(self.exports))
        for room,info in self.polls.items():
            snapshot['rooms'][room]=dict(info,next_due=self.stamp(self.due[room]),
                                        backfill_failures=self.backfill_failures[room],
                                        backfill_next_due=self.stamp(self.backfill_due.get(room,self.clock())))
        with self.conn:
            self.conn.execute("INSERT INTO evidence_settings VALUES ('worker_scheduler_v1',?) ON CONFLICT(name) DO UPDATE SET value=excluded.value",(json.dumps(snapshot),))
        self.last_published=self.clock()

    def run(self, *, once=False):
        self.once=once
        with ThreadPoolExecutor(max_workers=self.concurrency,thread_name_prefix='scout-tail') as pool, ThreadPoolExecutor(max_workers=1,thread_name_prefix='scout-export') as export_pool:
            try:
                while not self.stop.is_set():
                    self.schedule(pool,export_pool)
                    done,_=wait(self.inflight,timeout=0 if self.exports else 0.1,return_when=FIRST_COMPLETED) if self.inflight else (set(),set())
                    # Process already-admitted tails before one bounded export batch.
                    for future in sorted(done,key=lambda f:(self.inflight[f][1]!='tail',self.inflight[f][2],self.inflight[f][0])):
                        self.persist(future)
                    self.persist_export_batch()
                    self.discover_backfills()
                    if once and len(self.tail_done)==len(self.settings) and not self.inflight and not self.exports and not self.backfill_pending: break
                    if not self.inflight and not self.exports: self.stop.wait(0.1)
            finally:
                for future in self.inflight: future.cancel()
                for _,_,_,iterator in self.exports: iterator.close()
                self.publish_metrics(force=True)
                # Committed snapshot batches survive; GETs have bounded timeouts.


def scheduler_metrics(conn, now=None):
    row=conn.execute("SELECT value FROM evidence_settings WHERE name='worker_scheduler_v1'").fetchone()
    data=json.loads(row[0]) if row else None
    detail={}
    database=conn.execute('PRAGMA database_list').fetchone()[2]
    if database:
        path=Path(database).parent/'run'/'worker-diagnostics.json'
        try:
            if path.stat().st_size<=1024*1024:
                detail=json.loads(path.read_text())
                if detail.get('scheduler_snapshot'):data=detail['scheduler_snapshot']
        except (OSError,ValueError):pass
    if data is None:return {'scheduler_health':'UNKNOWN'}
    return scheduler_status(data,detail,now)


def read_diagnostics(state_dir,now=None):
    path=Path(state_dir)/'run'/'worker-diagnostics.json'
    try:
        if path.stat().st_size>1024*1024:raise ValueError('Diagnostics file oversized')
        detail=json.loads(path.read_text())
        if not isinstance(detail,dict):raise ValueError('Invalid diagnostics object')
        data=detail.get('scheduler_snapshot')
        if not data:return dict(detail,scheduler_health='UNKNOWN')
        return scheduler_status(data,detail,now)
    except (OSError,ValueError,TypeError,KeyError) as exc:
        return dict(scheduler_health='UNKNOWN',diagnostics_status='UNAVAILABLE',reason=str(exc))


def scheduler_status(data,detail=None,now=None):
    detail=dict(detail or {})
    now=time.time() if now is None else now
    age=lambda stamp:max(0,now-datetime.fromisoformat(stamp).timestamp())
    rooms={}
    for room,info in data['rooms'].items():
        info=dict(info)
        interval=info['target_interval_seconds']
        current=age(info['last_poll_completed'] or data['started_at'])
        info.update(current_poll_age=current,overdue_seconds=max(0,current-interval),
                    overdue_ratio=max(0,current-interval)/interval,
                    max_observed_poll_age=max(current,info['max_observed_poll_age']),
                    health='STARVED' if current>5*interval else 'DEGRADED' if current>2*interval else 'HEALTHY')
        rooms[room]=info
    starved=[r for r,v in rooms.items() if v['health']=='STARVED']
    degraded=[r for r,v in rooms.items() if v['health']=='DEGRADED']
    result=dict(scheduler_health='STARVED' if starved else 'DEGRADED' if degraded else 'HEALTHY',
                scheduler_rooms=rooms,rooms_overdue=[r for r,v in rooms.items() if v['overdue_seconds']>0],
                rooms_degraded=degraded,rooms_starved=starved,
                max_poll_age_seconds=max((v['current_poll_age'] for v in rooms.values()),default=0),
                max_overdue_ratio=max((v['overdue_ratio'] for v in rooms.values()),default=0),
                scheduler_queue_depth=len(data['pending_tails']),backfill_queue_depth=len(data['pending_backfills']),
                oldest_pending_tail_age=max((age(t) for t in data['pending_tails'].values()),default=0),
                oldest_pending_backfill_age=max((age(t) for t in data['pending_backfills'].values()),default=0),
                scheduler_status_age=age(data['updated_at']),tail_inflight=data['tail_inflight'],
                export_inflight=data['export_inflight'])
    if detail:
        detail.pop('scheduler_snapshot',None)
        detail['diagnostic_status_age']=max(0,now-detail['updated_at'])
        detail['scheduler_tick_age']+=detail['diagnostic_status_age']
        detail['event_loop_lag_ms']=max(detail['event_loop_lag_ms'],max(0,detail['scheduler_tick_age']-0.25)*1000)
        detail['event_loop_max_lag_ms']=max(detail['event_loop_lag_ms'],detail['event_loop_max_lag_ms'])
        if detail['scheduler_tick_age']>2:detail['event_loop_health']='STALLED'
        result.update(detail)
        result.update(detail.get('queues',{}))
        result['sqlite']=dict(queue_depth=result.get('sqlite_queue',0),max_wait=result.get('sqlite_max_queue_wait_ms',0),
                              max_write_duration=result.get('sqlite_max_write_duration_ms',0))
    return result


def run(config=None, concurrency=4, projection=None):
    import flop_scout as scout
    stop=threading.Event()
    previous={sig:signal.signal(sig,lambda *_:stop.set()) for sig in (signal.SIGTERM,signal.SIGINT)}
    try:
        with scout.poll_lock() as acquired:
            if not acquired: return
            from scout_runtime import Runtime
            Runtime(scout.OBSERVER_DB,config=config,concurrency=concurrency,stop=stop,projection=projection).run()
    finally:
        for sig,handler in previous.items(): signal.signal(sig,handler)
