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
    def __init__(self, conn, settings, *, concurrency=4, reader=None, clock=time.monotonic, stop=None):
        if not 1<=concurrency<=8: raise ValueError('Concurrency must be 1..8')
        self.conn=conn; self.settings=settings; self.clock=clock
        self.stop=stop or threading.Event(); self.reader=reader or self.read
        self.concurrency=concurrency; self.due={r:0 for r in settings}
        self.failures={r:0 for r in settings}; self.inflight={}; self.active_rooms=set()
        self.last_observation={}; self.owner=threading.get_ident()
        self.exports=[]
        self.needs_tail_refresh=set()
        for row in conn.execute('SELECT * FROM evidence_room_health'):
            if row['room'] in settings:
                self.failures[row['room']]=row['failures']
                if row['failures']: self.needs_tail_refresh.add(row['room'])
                if row['next_due'] and row['failures']:
                    remaining=(datetime.fromisoformat(row['next_due'])-datetime.now(timezone.utc)).total_seconds()
                    self.due[row['room']]=clock()+max(0,remaining)

    def read(self, room, kind, generation, cursor):
        import flop_scout as scout
        if kind=='export': return scout.fetch_room_export(room,generation,stop_event=self.stop)
        return scout.observation_only(scout.fetch_room_view)(room,200,since=cursor,allow_missing=True)

    def candidates(self):
        return sorted((r for r in self.settings if r not in self.active_rooms and self.due[r]<=self.clock()),
                      key=lambda r:(self.settings[r]['priority'],self.due[r],r))

    def schedule(self,pool):
        import flop_scout as scout
        for room in self.candidates():
            if len(self.inflight)>=self.concurrency or self.stop.is_set(): break
            cursor=scout.room_cursor(self.conn,room)
            row=self.conn.execute('SELECT * FROM source_coverage_state WHERE room=? AND generation=?',(room,cursor['generation'])).fetchone()
            kind='export' if row and row['backfill_required'] and room not in self.needs_tail_refresh and self.settings[room]['export_backfill_enabled'] and cursor['generation'] not in (None,'GENERATION_MISSING','UNKNOWN_LEGACY') else 'tail'
            # Reserve capacity for high-frequency tails while a large export downloads.
            if kind=='export' and (self.exports or any(v[1]=='export' for v in self.inflight.values())): continue
            resumable = self.conn.execute("SELECT * FROM evidence_export_snapshots WHERE room=? AND generation=? ORDER BY retrieved_at DESC LIMIT 1",(room,cursor['generation'])).fetchone() if kind=='export' else None
            # Resume only an unfinished/covered-range snapshot, never loop forever
            # on an old snapshot that cannot bridge newer observations.
            if resumable and (resumable['processed_records']<resumable['record_count'] or resumable['status']=='VALIDATED' or (row and row['coverage_status']=='BACKFILLING' and (resumable['last_seq'] or 0)>=row['observed_high_water'])):
                future=pool.submit(lambda snapshot=dict(resumable):snapshot)
            else:
                future=pool.submit(self.reader,room,kind,cursor['generation'],cursor['last_seq'])
            self.inflight[future]=(room,kind,self.clock(),cursor['generation'])
            self.active_rooms.add(room)

    def health(self,room,started,error=None,high=None):
        now=self.clock(); settings=self.settings[room]
        self.failures[room]=self.failures[room]+1 if error else 0
        delay=backoff(self.failures[room],settings['poll_interval_seconds'],error) if error else settings['poll_interval_seconds']
        self.due[room]=now+delay
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
                (room,evidence.now(),now-started,rate,(datetime.now(timezone.utc)+timedelta(seconds=delay)).isoformat(),self.failures[room],str(error) if error else None))

    def persist(self,future):
        import flop_scout as scout
        assert threading.get_ident()==self.owner, 'SQLite persistence must stay on coordinator thread'
        room,kind,started,generation=self.inflight.pop(future)
        persistence_started = False
        try:
            result=future.result()
            if kind=='tail':
                persistence_started = True
                result=scout.service_poll_room(self.conn,room,response=result)
                if result['continuity']=='READ_FAILED': raise RuntimeError(result['last_read_error'])
                self.health(room,started,high=result['observed_high_water'])
                self.needs_tail_refresh.discard(room)
                if result['backlog_remaining'] and self.settings[room]['export_backfill_enabled']:
                    self.due[room]=self.clock()
                    with self.conn:
                        self.conn.execute('UPDATE evidence_room_health SET next_due=? WHERE room=?',(evidence.now(),room))
                self.active_rooms.remove(room)
            else:
                if result['room']!=room or result['generation']!=str(generation): raise ValueError('Backfill response room/generation mismatch')
                iterator=scout.persist_export_steps(self.conn,result)
                self.exports.append((room,started,generation,iterator))
        except (Exception,SystemExit) as exc:
            if kind=='export':
                coverage.failed(self.conn,room,generation,exc)
                self.needs_tail_refresh.add(room)
            elif not persistence_started:
                with self.conn: evidence.bump(self.conn,'read_failures')
            self.health(room,started,error=exc)
            self.active_rooms.discard(room)

    def persist_export_batch(self):
        import flop_scout as scout
        if not self.exports: return
        room,started,generation,iterator=self.exports[0]
        try:
            result=next(iterator)
            if isinstance(result,dict):
                scout.update_room_cursor(self.conn,room,generation,result['coverage_cursor'])
                scout.set_state(self.conn,f'cursor:{room}:continuity',result['coverage_status'])
                error=RuntimeError('Export coverage unresolved') if result['backfill_required'] else None
                self.health(room,started,error=error,high=result['observed_high_water'])
                if error:self.needs_tail_refresh.add(room)
                self.active_rooms.remove(room); self.exports.pop(0)
        except (Exception,SystemExit) as exc:
            coverage.failed(self.conn,room,generation,exc)
            self.needs_tail_refresh.add(room)
            self.health(room,started,error=exc)
            self.active_rooms.remove(room); self.exports.pop(0)

    def run(self, *, once=False):
        completed=set()
        backfilled=set()
        with ThreadPoolExecutor(max_workers=self.concurrency,thread_name_prefix='scout-read') as pool:
            while not self.stop.is_set():
                if once:
                    for room in completed: self.due[room]=float('inf')
                self.schedule(pool)
                done,_=wait(self.inflight,timeout=0 if self.exports else 0.1,return_when=FIRST_COMPLETED) if self.inflight else (set(),set())
                for future in done:
                    room=self.inflight[future][0]
                    self.persist(future)
                    if once:
                        row=self.conn.execute('SELECT backfill_required,generation FROM source_coverage_state WHERE room=? ORDER BY last_checked_at DESC LIMIT 1',(room,)).fetchone()
                        if row and row[0] and row[1] not in ('GENERATION_MISSING','UNKNOWN_LEGACY') and self.settings[room]['export_backfill_enabled'] and room not in backfilled and not self.failures[room]:
                            backfilled.add(room)
                        else: completed.add(room)
                self.persist_export_batch()
                if once and len(completed)==len(self.settings) and not self.inflight and not self.exports: break
                if not self.inflight and not self.exports: self.stop.wait(0.1)
            for future in self.inflight: future.cancel()
            # Running GETs have bounded timeouts and observe the shutdown flag.


def run(config=None, concurrency=4):
    import flop_scout as scout
    stop=threading.Event()
    previous={sig:signal.signal(sig,lambda *_:stop.set()) for sig in (signal.SIGTERM,signal.SIGINT)}
    try:
        with scout.poll_lock() as acquired:
            if not acquired: return
            with scout.observer_connect() as conn:
                settings=configuration(scout.validation_watch_rooms(conn),config or scout.HOME/'polling.json',
                    evidence.load_collections(scout.HOME/'watch_collections.json'))
                Coordinator(conn,settings,concurrency=concurrency,stop=stop).run()
    finally:
        for sig,handler in previous.items(): signal.signal(sig,handler)
