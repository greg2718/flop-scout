"""Real threaded persistence plus controlled-clock blocking-operation regression tests."""
from pathlib import Path
from concurrent.futures import Future
import json
import threading
import time
from unittest.mock import patch
import pytest
import flop_scout as scout
import scout_coverage as cv
import scout_evidence as ev
import scout_worker as worker
import scout_runtime as runtime
import scout_diagnostics as diag
import scout_preparation as prep
from coverage_test_support import messages,export_snapshot


@pytest.fixture
def state(tmp_path,monkeypatch):
    monkeypatch.setattr(scout,'HOME',tmp_path)
    monkeypatch.setattr(scout,'LOG_FILE',tmp_path/'activity.jsonl')
    path=tmp_path/'observer.sqlite'
    c=scout.observer_connect_write(path)
    scout.update_room_cursor(c,'lobby','g1',100)
    cv.state(c,'lobby','g1',100)
    c.execute("UPDATE source_coverage_state SET backfill_required=1 WHERE room='lobby'");c.commit();c.close()
    return path


def test_real_runtime_interleaves_and_preserves_integrity(state,tmp_path):
    snapshot=export_snapshot(tmp_path,messages(101,600),room='lobby')
    threads={'write':set(),'read':set()}
    def read(room,kind,*_):
        threads['read'].add(threading.get_ident())
        return snapshot if kind=='export' else ({'messages':messages(501,510) if room=='lobby' else messages(1,1),'latest_seq':600 if room=='lobby' else 1},'g1')
    original=scout.ingest_messages
    def persist(*args,**kwargs):
        threads['write'].add(threading.get_ident());return original(*args,**kwargs)
    r=runtime.Runtime(state,worker.configuration(['lobby','quiet','mb-flop-scout']),reader=read)
    with patch.object(scout,'ingest_messages',side_effect=persist):r.run(once=True)
    timing=r.diag.snapshot()['tail_page_timing_history']
    assert {x['room'] for x in timing}=={'lobby','quiet','mb-flop-scout'}
    assert [x['sequence'] for x in timing]==list(range(1,len(timing)+1))
    assert all(x['upstream_get_ms']>=0 and x['internal_ms']>=x['writer_ms'] and x['internal_ms']>=x['elapsed_ms'] for x in timing)
    assert len(threads['write'])==1
    assert threading.get_ident() not in threads['write']
    assert not threads['write'] & threads['read']
    with scout.observer_connect_readonly(state) as c:
        result=ev.integrity(c)
        assert result['status']=='PASS',result
        assert scout.room_cursor(c,'lobby')['last_seq']==600
        assert scout.room_cursor(c,'quiet')['last_seq']==1
        assert all(ev.metrics(c)[key]==0 for key in ev.SAFETY_KEYS)
        status=worker.scheduler_metrics(c)
        assert 'sqlite_commit_max_duration_ms' in status
        assert status['tail_read_queue']<=4


@pytest.mark.parametrize('error,expected',[
    (TimeoutError('read'), 'HTTP_TIMEOUT'),
    (scout.ObservationReadError('busy',429,'30'),'HTTP_429'),
    (scout.ObservationReadError('busy',503),'HTTP_503'),
    (ValueError('Export generation mismatch'),'GENERATION_MISMATCH'),
    (ValueError('Export incomplete'),'EXPORT_INCOMPLETE'),
    (OSError('disk full'),'SNAPSHOT_IO_ERROR'),
    (__import__('sqlite3').OperationalError('database locked'),'SQLITE_BUSY'),
    (__import__('sqlite3').OperationalError('bad SQL'),'SQLITE_ERROR'),
    (RuntimeError('Export coverage unresolved'),'COVERAGE_CONFLICT'),
    (json.JSONDecodeError('bad','x',0),'PARSE_ERROR'),
    (RuntimeError('worker shutdown'),'WORKER_SHUTDOWN'),
    (RuntimeError('unexpected'),'OTHER'),
])
def test_failure_classes(error,expected):assert diag.failure_class(error)==expected


def test_watchdog_identifies_legacy_synchronous_stall():
    now=[0.0];d=diag.Diagnostics(clock=lambda:now[0],wall=lambda:1700000000+now[0])
    d.tick()
    with d.operation('export_parse','lobby'):
        now[0]=120
        status=d.snapshot()
        assert status['event_loop_health']=='STALLED'
        assert status['event_loop_max_lag_ms']==119750
        assert status['current_active_operation']=='export_parse'
        assert status['current_active_room']=='lobby'
        assert status['stall_events'][0]['type']=='EVENT_LOOP_STALL'
    assert d.snapshot()['export_parse_max_duration_ms']==120000


def test_budget_never_starts_with_slow_200_record_turn():
    b=runtime.BatchBudget()
    assert b.size==1
    for _ in range(20):
        # A hypothetical 200-record SQL turn would take 30 seconds.
        size=b.size;b.observe(size,size*0.15)
        assert b.size==1
    b.observe(1,0.00001)
    assert b.size==2


@pytest.mark.parametrize('phase',['export_parse','snapshot_write','signature_verify'])
def test_slow_export_preparation_does_not_block_scheduler(state,tmp_path,phase):
    entered=threading.Event();release=threading.Event();stop=threading.Event()
    now=[0.0]
    snapshot=export_snapshot(tmp_path,messages(101,300),room='lobby')
    def read(room,kind,*_):
        if kind=='export':
            with diag.operation(phase,room):
                entered.set();assert release.wait(15)
            return snapshot
        return ({'messages':[],'latest_seq':100 if room=='lobby' else 0},'g1')
    r=runtime.Runtime(state,worker.configuration(['lobby','quiet','mb-flop-scout']),reader=read,
                      clock=lambda:now[0],wall=lambda:1700000000+now[0],stop=stop)
    # Run the actual scheduler and actual SQLite owner on separate threads.
    error=[]
    def run():
        try:r.run()
        except BaseException as exc:error.append(exc)
    thread=threading.Thread(target=run);thread.start()
    try:
        assert entered.wait(3)
        for _ in range(300):
            now[0]+=0.1
            deadline=time.monotonic()+2
            while r.diag.last_tick<now[0] and time.monotonic()<deadline:
                time.sleep(0.001)
            assert r.diag.last_tick>=now[0]
        assert r.diag.snapshot()['event_loop_max_lag_ms']<500
        assert r.data['quiet']['poll']['polls_completed']>=1
        assert r.data['mb-flop-scout']['poll']['polls_completed']>=1
        assert r.diag.snapshot()['current_active_operation']==phase
    finally:
        stop.set();release.set();thread.join(5)
    assert not thread.is_alive() and not error,error
    assert r.diag.snapshot()[phase+'_max_duration_ms']>=29000


def test_prepared_verification_not_repeated_on_writer(state):
    record=messages(101,101)[0]
    with patch.object(scout,'verify_signed_record_offline',return_value='UNSIGNED') as verify:
        cache=prep.prepare('lobby',[record]);assert verify.call_count==1
    token=scout._VERIFICATION_CACHE.set(cache)
    try:
        # No cryptographic backend call is needed after preparation, but changing
        # exact signed content cannot use a different record's cached verdict.
        assert scout.verify_signed_record_offline('lobby',record)=='UNSIGNED'
        changed=dict(record,sig='invalid')
        assert scout.verify_signed_record_offline('lobby',changed)!='UNSIGNED'
    finally:scout._VERIFICATION_CACHE.reset(token)


class SimulationPool:
    def __init__(self,clock,diagnostics,writer=False):
        self.clock=clock;self.diag=diagnostics;self.writer=writer;self.jobs=[];self.max_jobs=0
    def submit(self,fn,*args):
        delay=0.002;kind=getattr(fn,'task_kind',None)
        if kind=='tail':
            job,size=fn.task_args[1:];count=min(size,len(job['records'])-job['offset']);delay=0.001+count*0.0001
        elif kind=='export_batch':
            count=len(fn.task_args[2]);position=fn.task_args[4]
            # A 200-record turn in the first slow region would take 30 seconds.
            delay=0.002+count*(0.15 if position<=40 else 0.0003)
        elif args and args[0]=='tail_read_prepare':delay=0.2
        elif args and args[0]=='export_open':delay=90 # 30s parse + 30s snapshot I/O + 30s verification
        f=Future();self.jobs.append((self.clock[0]+delay,f,fn,args,delay,kind));self.max_jobs=max(self.max_jobs,len(self.jobs));return f
    def pump(self):
        for item in list(self.jobs):
            end,f,fn,args,delay,kind=item
            if end>self.clock[0]:continue
            self.jobs.remove(item)
            try:
                value=fn(*args)
                if kind:
                    value['_write_seconds']=delay
                    with self.diag.lock:
                        self.diag.values['sqlite_write_duration_ms']=delay*1000
                        self.diag.values['sqlite_write_max_duration_ms']=max(delay*1000,self.diag.values.get('sqlite_write_max_duration_ms',0))
                f.set_result(value)
            except BaseException as exc:f.set_exception(exc)


class SimulationStorage:
    def __init__(self,rooms,clock):
        import copy
        self.copy=copy.deepcopy;self.clock=clock;self.settings=worker.configuration(rooms);self.counts=dict.fromkeys(rooms,0)
        self.completed=0;self.records=0;self.tail_times={r:[] for r in rooms}
        self.data={r:dict(cursor=dict(generation='g1',last_seq=100),coverage=dict(backfill_required=1,coverage_status='BACKFILL_REQUIRED',observed_high_water=100),snapshot=None,
                         poll=dict(target_interval_seconds=self.settings[r]['poll_interval_seconds'],last_poll_started=None,last_poll_completed=None,max_observed_poll_age=0,polls_completed=0),
                         due=0,failures=0,backfill_due=0,backfill_failures=0) for r in rooms}
    def metadata(self):return self.copy(self.data)
    def tail(self,room,job,size):
        count=min(size,len(job['records'])-job['offset']);offset=job['offset']+count
        if offset<len(job['records']):return dict(records=count,offset=offset,inserted=offset)
        now=self.clock[0];v=self.data[room];poll=v['poll'];previous=self.tail_times[room][-1] if self.tail_times[room] else 0
        poll['max_observed_poll_age']=max(poll['max_observed_poll_age'],now-previous)
        poll['last_poll_completed']=datetime_stamp(now);poll['last_poll_started']=job['started_wall'];poll['polls_completed']+=1
        v['due']=now+self.settings[room]['poll_interval_seconds'];v['coverage']['backfill_required']=1
        self.tail_times[room].append(now)
        return dict(records=count,done=True,metadata=self.metadata())
    def export_batch(self,room,snapshot,batch,prepared,position,done):
        self.records+=len(batch)
        if done:
            self.completed+=1;self.data[room]['coverage']['backfill_required']=0
            return dict(records=len(batch),done=True,metadata=self.metadata())
        return dict(records=len(batch))
    def save_status(self,snapshot):return {}


def datetime_stamp(now):
    from datetime import datetime,timezone
    return datetime.fromtimestamp(1700000000+now,timezone.utc).isoformat()


class SimulationExport:
    def __init__(self,room):self.position=0;self.snapshot=dict(room=room,generation='g1',record_count=40000)
    def batch(self,size):
        count=min(size,40000-self.position);self.position+=count
        return [dict(seq=n) for n in range(count)],{},self.position,self.position==40000
    def close(self):pass


def test_forty_minute_global_stall_qualification(tmp_path):
    rooms=['lobby','faucet','technocore','kibble','tclk-offers','consensus_layer','quiet','mb-flop-scout']
    now=[0.0];model=SimulationStorage(rooms,now)
    r=runtime.Runtime(tmp_path/'model.sqlite',model.settings,clock=lambda:now[0],wall=lambda:1700000000+now[0])
    r.storage=model;r.data=model.metadata()
    r.tail_pool=SimulationPool(now,r.diag);r.export_pool=SimulationPool(now,r.diag);r.write_pool=SimulationPool(now,r.diag,True)
    r.read_tail=lambda room,cursor:(({'messages':[]},'g1'),[{'seq':n} for n in range(200 if room in ('lobby','faucet') else 1)],{})
    r.open_export=lambda room,cursor,snapshot:SimulationExport(room)
    maxima=dict(tail_queue_age=0,backfill_queue_age=0,tail_persist_queue=0,sqlite_queue=0)
    while now[0]<2400:
        for pool in (r.tail_pool,r.export_pool,r.write_pool):pool.pump()
        r.step()
        q=r.diag.queues
        maxima['tail_queue_age']=max(maxima['tail_queue_age'],q['oldest_tail_queue_age'])
        maxima['backfill_queue_age']=max(maxima['backfill_queue_age'],q['oldest_backfill_queue_age'])
        maxima['tail_persist_queue']=max(maxima['tail_persist_queue'],q['tail_persist_queue'])
        maxima['sqlite_queue']=max(maxima['sqlite_queue'],q['sqlite_queue'])
        now[0]+=0.01
    ages={room:max(b-a for a,b in zip([0]+times,times+[now[0]])) for room,times in model.tail_times.items()}
    limits=dict(lobby=5,faucet=10,technocore=40,kibble=40,**{'tclk-offers':60,'consensus_layer':120,'quiet':120,'mb-flop-scout':120})
    assert all(ages[room]<=limits[room] for room in rooms),ages
    assert all(ages[room]<=2*model.settings[room]['poll_interval_seconds'] for room in rooms),ages
    assert r.diag.snapshot()['event_loop_max_lag_ms']<250
    assert model.completed>0 and model.records>40000
    assert r.tail_pool.max_jobs<=4 and r.export_pool.max_jobs<=1 and r.write_pool.max_jobs<=1
    assert maxima['tail_persist_queue']<=8 and maxima['sqlite_queue']<=9
    report=dict(simulated_seconds=2400,max_poll_ages=ages,event_loop_max_lag_ms=r.diag.snapshot()['event_loop_max_lag_ms'],
                sqlite_max_write_duration_ms=r.diag.snapshot()['sqlite_max_write_duration_ms'],
                backfills_completed=model.completed,backfill_records=model.records,**maxima)
    (tmp_path/'global-stall-results.json').write_text(json.dumps(report,indent=2));print(json.dumps(report))


def test_legacy_blocking_operation_ages_every_room(state):
    now=[0.0];rooms=['lobby','faucet','technocore','kibble','quiet','mb-flop-scout']
    with scout.observer_connect_write(state) as c:
        co=worker.Coordinator(c,worker.configuration(rooms),clock=lambda:now[0],wall_clock=lambda:1700000000+now[0])
        for room in rooms:co.health(room,0,high=100)
        co.publish_metrics(force=True)
        d=diag.Diagnostics(clock=lambda:now[0],wall=lambda:1700000000+now[0])
        with d.operation('sqlite_commit','lobby'):
            now[0]=160
            assert d.snapshot()['event_loop_health']=='STALLED'
            status=worker.scheduler_metrics(c,1700000160)
            assert all(v['current_poll_age']>=160 for v in status['scheduler_rooms'].values())


def test_slow_sqlite_is_visible_but_scheduler_keeps_ticking(state,tmp_path):
    entered=threading.Event();release=threading.Event();stop=threading.Event();now=[0.0]
    snapshot=export_snapshot(tmp_path,messages(101,300),room='lobby')
    def read(room,kind,*_):
        return snapshot if kind=='export' else ({'messages':[],'latest_seq':300 if room=='lobby' else 0},'g1')
    original=runtime.Storage.export_batch
    def slow(*args):
        entered.set();assert release.wait(15);return original(*args)
    r=runtime.Runtime(state,worker.configuration(['lobby','quiet','mb-flop-scout']),reader=read,stop=stop,
                      clock=lambda:now[0],wall=lambda:1700000000+now[0])
    errors=[]
    def run():
        try:r.run()
        except BaseException as e:errors.append(e)
    with patch.object(runtime.Storage,'export_batch',side_effect=slow,autospec=True):
        thread=threading.Thread(target=run);thread.start()
        try:
            assert entered.wait(5)
            for _ in range(300):
                now[0]+=0.1
                deadline=time.monotonic()+2
                while r.diag.last_tick<now[0] and time.monotonic()<deadline:time.sleep(0.001)
                assert r.diag.last_tick>=now[0]
            status=r.diag.snapshot()
            assert status['event_loop_max_lag_ms']<500
            assert status['current_active_operation']=='sqlite_write'
            assert r.diag.queues['tail_persist_queue']>0
        finally:
            stop.set();release.set();thread.join(5)
    assert not thread.is_alive() and not errors,errors
    assert r.diag.snapshot()['sqlite_max_write_duration_ms']>=29000
    with scout.observer_connect_readonly(state) as c:assert ev.integrity(c)['status']=='PASS'


def test_export_stream_bounds_and_detects_mutation(tmp_path):
    snapshot=export_snapshot(tmp_path,messages(1,40000),room='lobby')
    stream=prep.ExportStream(snapshot)
    batch,cache,position,done=stream.batch(17)
    assert len(batch)==17 and position==17 and not done
    # Simulate an in-place file mutation after validation. Final hashing must
    # reject it; changed file bytes cannot authorize coverage advancement.
    with Path(snapshot['path']).open('ab') as out:out.write(b'{}\n')
    with pytest.raises(ValueError,match='changed'):
        while True:
            _,_,_,done=stream.batch(200)
            if done:break


def test_export_retry_scheduled_without_sleep(state,tmp_path):
    def read(room,kind,*_):
        if kind=='export':raise scout.ObservationReadError('rate limited',429,'90')
        return ({'messages':[],'latest_seq':200 if room=='lobby' else 0},'g1')
    r=runtime.Runtime(state,worker.configuration(['lobby','quiet']),reader=read)
    before=time.monotonic();r.run(once=True)
    assert time.monotonic()-before<5
    assert r.data['lobby']['backfill_due']-time.monotonic()>80
    assert r.diag.snapshot()['backfill_failures_by_class']=={'HTTP_429':1}
    assert r.data['quiet']['poll']['polls_completed']==1


def test_runtime_failure_accounting_is_not_doubled(state):
    r=runtime.Runtime(state,worker.configuration(['lobby']),reader=lambda *_:({'messages':messages(101,101),
                      '_scout_transport':{'generation_conflict':True}},'g1'))
    r.run(once=True)
    with scout.observer_connect_readonly(state) as c:
        assert ev.metrics(c)['read_failures']==1
        assert ev.integrity(c)['status']=='PASS'


def test_diagnostics_cli_needs_no_sqlite_or_home_initialization(tmp_path):
    import subprocess,sys,os
    run=tmp_path/'run';run.mkdir()
    d=diag.Diagnostics(run/'worker-diagnostics.json')
    d.write()
    env=dict(os.environ,FLOP_SCOUT_STATE_DIR=str(tmp_path/'not-created'))
    before=(run/'worker-diagnostics.json').read_bytes()
    r=subprocess.run([sys.executable,'flop_scout.py','worker','diagnostics','--state-dir',str(tmp_path)],env=env,capture_output=True,text=True,timeout=5)
    assert r.returncode==0,r.stderr
    assert json.loads(r.stdout)['scheduler_health']=='UNKNOWN'
    assert before==(run/'worker-diagnostics.json').read_bytes()
    assert not (tmp_path/'not-created').exists()
    assert not (tmp_path/'observer.sqlite').exists()


def test_runtime_shutdown_checkpoint_resumes_without_redownload(state,tmp_path):
    stop=threading.Event();snapshot=export_snapshot(tmp_path,messages(101,600),room='lobby')
    original=runtime.Storage.export_batch
    def first_batch(*args):
        result=original(*args)
        if not result.get('done'):stop.set()
        return result
    def read(room,kind,*_):
        return snapshot if kind=='export' else ({'messages':[],'latest_seq':600},'g1')
    r=runtime.Runtime(state,worker.configuration(['lobby']),reader=read,stop=stop)
    with patch.object(runtime.Storage,'export_batch',side_effect=first_batch,autospec=True):r.run()
    with scout.observer_connect_readonly(state) as c:
        checkpoint=c.execute('SELECT processed_records FROM evidence_export_snapshots').fetchone()[0]
        assert 0<checkpoint<500
        assert ev.integrity(c)['status']=='PASS'
    def tail_only(room,kind,*_):
        assert kind=='tail','captured export must resume locally'
        return ({'messages':[],'latest_seq':600},'g1')
    runtime.Runtime(state,worker.configuration(['lobby']),reader=tail_only).run(once=True)
    with scout.observer_connect_readonly(state) as c:
        assert scout.room_cursor(c,'lobby')['last_seq']==600
        assert ev.integrity(c)['status']=='PASS'


def test_identical_export_snapshot_is_not_rewritten(tmp_path,monkeypatch):
    import io
    monkeypatch.setattr(scout,'HOME',tmp_path)
    content=b''.join((json.dumps(r)+'\n').encode() for r in messages(1,10))
    class Response(io.BytesIO):
        status=200
        headers={'X-Room-Generation':'g1','Content-Length':str(len(content))}
    class Opener:
        def open(self,*args,**kwargs):return Response(content)
    monkeypatch.setattr(scout.urllib.request,'build_opener',lambda *_:Opener())
    first=scout.fetch_room_export('lobby','g1')
    before=Path(first['path']).stat()
    second=scout.fetch_room_export('lobby','g1')
    after=Path(second['path']).stat()
    assert first['snapshot_id']==second['snapshot_id']
    assert before.st_ino==after.st_ino and before.st_mtime_ns==after.st_mtime_ns


def test_budget_reduces_after_cost_change():
    b=runtime.BatchBudget()
    for _ in range(10):b.observe(b.size,0.00001)
    assert b.size==200
    b.observe(200,30)
    assert b.size==1


def test_completed_writer_wakes_scheduler_without_timer(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from types import SimpleNamespace
    r=runtime.Runtime(tmp_path/'unused.sqlite')
    r.storage=SimpleNamespace(tail=lambda *_: {'records':1})
    with ThreadPoolExecutor(max_workers=1) as pool:
        r.write_pool=pool
        r.submit_write('tail','lobby',('lobby',{},1))
        assert r.wakeup.wait(1), 'Completed writer must signal the scheduler'
        assert r.writer_job['future'].result()['records']==1


def test_backlogged_fast_turns_recover_batch_size():
    b=runtime.BatchBudget()
    for _ in range(8):
        b.observe(b.size,b.size*.0005,tail_age=60)
    assert b.size==50
    b.observe(50,5,tail_age=60)
    assert b.size==1


def test_tail_owner_yields_after_one_bounded_chunk(monkeypatch):
    from types import SimpleNamespace
    now=[0.0];calls=[]
    monkeypatch.setattr(runtime.time,'monotonic',lambda:now[0])
    storage=runtime.Storage.__new__(runtime.Storage)
    storage.tail_budgets={};storage.conn=SimpleNamespace(turn_commit_max_ms=0)
    def batch(room,job,size):
        count=min(size,200-job['offset']);calls.append(count);now[0]+=count*.001
        return dict(records=count,offset=job['offset']+count,inserted=job['inserted']+count,done=job['offset']+count==200)
    storage._tail_batch=batch
    result=storage.tail('lobby',dict(offset=0,inserted=0),1)
    assert calls==[1]
    assert result['records']==1
    assert now[0]==.001
    calls.clear()
    result=storage.tail('lobby',dict(offset=1,inserted=1),200)
    assert calls==[8] and result['offset']==9


def test_tail_priority_has_bounded_backfill_opportunity(tmp_path):
    from types import SimpleNamespace
    now=[0.0];r=runtime.Runtime(tmp_path/'unused.sqlite',clock=lambda:now[0])
    r.tails={'new':dict(queued=1,turn_ready=1),'old':dict(queued=0,turn_ready=0)}
    r.export=dict(ready=([],{},0,False),room='backfill',stream=SimpleNamespace(snapshot={}),ready_at=0)
    submitted=[];r.submit_write=lambda kind,room,*args:submitted.append((kind,room))
    r.choose_write();assert submitted[-1]==('tail','old')
    now[0]=1.999;r.choose_write();assert submitted[-1]==('tail','old')
    now[0]=2;r.choose_write();assert submitted[-1]==('export_batch','backfill')
    r.choose_write();assert submitted[-1]==('tail','old')


def test_queue_accounting_clips_competing_work_intervals(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    from types import SimpleNamespace
    r=runtime.Runtime(tmp_path/'unused.sqlite',clock=lambda:10)
    r.storage=SimpleNamespace(tail=lambda *_:dict(records=1))
    r.work_intervals.extend([(0,4,'tail'),(4,7,'backfill'),(7,9,'maintenance')])
    page={}
    with ThreadPoolExecutor(max_workers=1) as pool:
        r.write_pool=pool;r.submit_write('tail','lobby',('lobby',page,1),queued=3)
        r.writer_job['future'].result()
    assert page['queue_seconds']==7
    assert page['wait_tail']==1 and page['wait_backfill']==3 and page['wait_maintenance']==2 and page['wait_scheduler']==1
