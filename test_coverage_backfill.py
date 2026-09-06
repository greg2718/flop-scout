import io
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import threading
import urllib.error
from concurrent.futures import Future, ThreadPoolExecutor
from unittest.mock import patch
import pytest
import flop_scout as scout
import scout_coverage as cv
import scout_evidence as ev
import scout_worker as worker
from coverage_test_support import messages, tail, export_snapshot


@pytest.fixture
def db(tmp_path,monkeypatch):
    monkeypatch.setattr(scout,'HOME',tmp_path)
    monkeypatch.setattr(scout,'LOG_FILE',tmp_path/'activity.jsonl')
    conn=scout.observer_connect_write(tmp_path/'observer.sqlite')
    scout.update_room_cursor(conn,'technocore','g1',100)
    yield conn
    conn.close()


def observe(db,first=150,last=200,gen='g1'):
    return scout.service_poll_room(db,'technocore',response=(tail(messages(first,last),100,200,gen),gen))


def check(db):
    result=ev.integrity(db)
    assert result['status']=='PASS',result
    return result


def test_tail_high_water_without_coverage(db):
    r=observe(db)
    assert r['coverage_cursor']==100 and r['observed_high_water']==200 and r['server_tail_high_water']==200
    assert r['continuity']=='BACKFILL_REQUIRED'
    assert len(ev.source_gaps(db))==0
    assert check(db)['raw_records']==51
    assert ev.metrics(db)['read_failures']==0


def test_backfill_recovers_missing_and_deduplicates(db,tmp_path):
    observe(db)
    snapshot=export_snapshot(tmp_path,messages(1,200))
    r=scout.backfill_room(db,'technocore',snapshot)
    assert r['coverage_cursor']==r['observed_high_water']==200
    assert r['coverage_status']=='CURRENT_AFTER_BACKFILL'
    assert check(db)['raw_records']==200
    assert ev.metrics(db)['confirmed_retention_losses']==0
    assert ev.metrics(db)['backfill_records_recovered']==149 # includes retained pre-checkpoint evidence
    r=observe(db,201,202)
    assert r['continuity']=='CURRENT'
    assert all(ev.metrics(db)[k]==0 for k in (*ev.SAFETY_KEYS,'cursor_regressions'))


def test_coverage_requires_matching_event_link(db):
    with patch.object(ev,'derive',return_value=None):
        with pytest.raises(RuntimeError,match='fully persisted'): observe(db,101,102)
    assert scout.room_cursor(db,'technocore')['last_seq']==100
    observe(db,101,102)
    assert check(db)['raw_records']==2


def test_parser_failure_retains_raw_and_repairs(db):
    with patch.object(ev,'derive',side_effect=ValueError('parse failure')):
        with pytest.raises(ValueError):observe(db)
    assert db.execute('SELECT count(*) FROM raw_network_records').fetchone()[0]==51
    assert scout.room_cursor(db,'technocore')['last_seq']==100
    observe(db)
    check(db)


@pytest.mark.parametrize('limit',[10,50,200,800])
def test_verified_tail_fixture(limit):
    r=tail(messages(1,1000),100,limit)
    assert len(r['messages'])==min(limit,200)
    assert r['first_seq']==1001-min(limit,200)
    assert r['last_seq']==1000
    assert [m['seq'] for m in r['messages']]==sorted(m['seq'] for m in r['messages'])


@pytest.mark.parametrize('limit,first,last',[(10,5014195,5014204),(50,5014155,5014204),(200,5014009,5014208)])
def test_captured_http_fixture(db,limit,first,last):
    obj=json.loads(Path(f'tests/fixtures/technocore-tail-{limit}.json').read_text())
    scout.update_room_cursor(db,'technocore','0',5013467)
    r=scout.service_poll_room(db,'technocore',response=(obj,'0'),page_size=limit)
    assert obj['first_seq']==first and obj['last_seq']==last
    assert r['cursor_after']==5013467 and r['observed_high_water']==last
    assert not ev.source_gaps(db)
    assert check(db)['raw_records']==limit


def test_complete_export_proves_retention_loss(db,tmp_path):
    observe(db,900,1099)
    snap=export_snapshot(tmp_path,messages(800,1099))
    r=scout.backfill_room(db,'technocore',snap)
    assert r['coverage_cursor']==1099 and r['coverage_status']=='CONFIRMED_RETENTION_LOSS'
    loss=dict(db.execute('SELECT * FROM evidence_retention_losses').fetchone())
    assert loss['last_durable_seq']==100 and loss['first_available_seq']==800
    assert loss['sequence_contract']==cv.CONTRACT
    assert check(db)['raw_records']==300
    assert not ev.source_gaps(db)
    r=observe(db,1100,1100)
    assert r['continuity']=='CURRENT' and ev.metrics(db)['confirmed_retention_losses']==1


@pytest.mark.parametrize('kind',['missing_generation','mismatch','conflict','room','endpoint','newline','length','ordering','invalid_json','float_seq'])
def test_export_validation_fail_closed(db,tmp_path,kind):
    observe(db)
    records=messages(1,200)
    metadata={'headers':{'X-Room-Generation':'g1'},'complete':True}
    endpoint='https://technocore.chat/r/technocore/export';actual=endpoint
    if kind=='missing_generation':metadata['headers']={}
    if kind=='mismatch':metadata['headers']['X-Room-Generation']='g2'
    if kind=='conflict':metadata['generation_conflict']=True
    if kind=='room':records[0]['room']='other'
    if kind=='endpoint':actual='https://evil.example/export'
    if kind=='ordering':records[1],records[2]=records[2],records[1]
    if kind=='float_seq':records[0]['seq']=1.0
    raw=b''.join(json.dumps(r).encode()+b'\n' for r in records)
    if kind=='newline':raw=raw[:-1]
    if kind=='invalid_json':raw=b'{broken}\n'
    if kind=='length':metadata['headers']['Content-Length']=str(len(raw)+1)
    path=tmp_path/'bad.jsonl';path.write_bytes(raw)
    with pytest.raises(ValueError):cv.inspect_export(path,'technocore','g1',actual,endpoint,metadata)
    assert scout.room_cursor(db,'technocore')['last_seq']==100
    assert ev.metrics(db)['confirmed_retention_losses']==0
    check(db)


@pytest.mark.parametrize('kind',['bytes','line','records','incomplete'])
def test_export_bounds(db,tmp_path,monkeypatch,kind):
    if kind=='bytes':monkeypatch.setattr(cv,'MAX_EXPORT_BYTES',10)
    if kind=='line':monkeypatch.setattr(cv,'MAX_LINE_BYTES',10)
    if kind=='records':monkeypatch.setattr(cv,'MAX_EXPORT_RECORDS',10)
    with pytest.raises(ValueError):export_snapshot(tmp_path,messages(1,20),complete=kind!='incomplete')


def test_sparse_export_never_proves_loss(db,tmp_path):
    observe(db,900,1099)
    r=scout.backfill_room(db,'technocore',export_snapshot(tmp_path,[{'seq':800,'text':'x'},{'seq':1099,'text':'y'}]))
    assert r['coverage_cursor']==100 and r['coverage_status']=='UNRESOLVED'
    assert ev.metrics(db)['confirmed_retention_losses']==0
    check(db)


def test_empty_export_never_proves_loss(db,tmp_path):
    observe(db)
    r=scout.backfill_room(db,'technocore',export_snapshot(tmp_path,[]))
    assert r['coverage_status']=='UNRESOLVED' and r['coverage_cursor']==100
    check(db)


def test_historical_false_gap_reassessment_is_append_only(db,tmp_path):
    gid=ev.record_gap(db,'technocore','g1',100,150,200,'https://technocore.chat/r/technocore',{})
    original=dict(db.execute('SELECT * FROM evidence_source_gaps').fetchone())
    observe(db)
    snap=export_snapshot(tmp_path,messages(1,200))
    scout.backfill_room(db,'technocore',snap)
    scout.backfill_room(db,'technocore',snap)
    rows=db.execute('SELECT * FROM evidence_gap_reassessments').fetchall()
    assert len(rows)==1 and rows[0]['assessment']=='FALSE_POSITIVE_TAIL_WINDOW'
    assert dict(db.execute('SELECT * FROM evidence_source_gaps').fetchone())==original
    assert ev.metrics(db)['false_positive_gap_reassessments']==1
    for table in ('evidence_source_gaps','evidence_gap_reassessments'):
        with pytest.raises(sqlite3.IntegrityError):db.execute('DELETE FROM '+table)
        db.rollback()
    check(db)


@pytest.mark.parametrize('first,last,assessment',[(1,200,'FALSE_POSITIVE_TAIL_WINDOW'),(125,200,'CONFIRMED_RETENTION_LOSS'),(1,120,'UNRESOLVED')])
def test_reassessment_interpretation(db,tmp_path,first,last,assessment):
    ev.record_gap(db,'technocore','g1',100,150,200,'/r/technocore',{})
    scout.backfill_room(db,'technocore',export_snapshot(tmp_path,messages(first,last)))
    row=db.execute('SELECT * FROM evidence_gap_reassessments').fetchone()
    assert row['assessment']==assessment
    if assessment=='CONFIRMED_RETENTION_LOSS':assert 'not proof' in row['reason']
    check(db)


def test_old_false_cursor_not_grandfathered(db):
    ev.record_gap(db,'technocore','g1',50,150,200,'/r/technocore',{})
    scout.update_room_cursor(db,'technocore','g1',200)
    r=observe(db,201,202)
    assert r['coverage_cursor']==50 and r['observed_high_water']==202
    assert r['continuity']=='BACKFILL_REQUIRED'


@pytest.mark.parametrize('point',['batch','completion','cursor'])
def test_backfill_crash_replay(db,tmp_path,point):
    observe(db,450,500)
    snap=export_snapshot(tmp_path,messages(1,500))
    if point=='batch':
        with pytest.raises(RuntimeError):scout.persist_export(db,snap,after_batch=lambda _:(_ for _ in ()).throw(RuntimeError('crash')))
    elif point=='completion':
        with patch.object(cv,'reassess',side_effect=RuntimeError('crash')):
            with pytest.raises(RuntimeError):scout.persist_export(db,snap)
    else:
        with patch.object(scout,'update_room_cursor',side_effect=RuntimeError('crash')):
            with pytest.raises(RuntimeError):scout.backfill_room(db,'technocore',snap)
    check(db)
    with scout.observer_connect_write(tmp_path/'observer.sqlite') as resumed:
        r=scout.backfill_room(resumed,'technocore',snap)
        assert r['coverage_cursor']==500
        assert check(resumed)['raw_records']==500


def test_actual_process_crash_and_replay(tmp_path):
    snap=export_snapshot(tmp_path,messages(1,500))
    (tmp_path/'snapshot.json').write_text(json.dumps(snap))
    code='''
import os,json
from pathlib import Path
import flop_scout as s
conn=s.observer_connect_write()
if s.room_cursor(conn,'technocore')['generation'] is None:s.update_room_cursor(conn,'technocore','g1',100)
snapshot=json.loads((s.HOME/'snapshot.json').read_text())
s.persist_export(conn,snapshot,after_batch=lambda _:os._exit(19))
'''
    env=dict(os.environ,FLOP_SCOUT_STATE_DIR=str(tmp_path))
    proc=subprocess.run([sys.executable,'-c',code],env=env,capture_output=True,timeout=15)
    assert proc.returncode==19,proc.stderr
    with scout.observer_connect_write(tmp_path/'observer.sqlite') as c:
        assert scout.room_cursor(c,'technocore')['last_seq']==100
        check(c)
        scout.backfill_room(c,'technocore',snap)
        assert check(c)['raw_records']==500


def test_export_batches_release_sqlite_writer(db,tmp_path):
    observe(db,900,1099)
    snap=export_snapshot(tmp_path,messages(1,1099))
    seen=[]
    def checkpoint(position):
        with scout.observer_connect_readonly(tmp_path/'observer.sqlite') as read:
            seen.append(read.execute('SELECT count(*) FROM raw_network_records').fetchone()[0])
            assert scout.room_cursor(read,'technocore')['last_seq']==100
        with sqlite3.connect(tmp_path/'observer.sqlite',timeout=.1) as writer:
            writer.execute('BEGIN IMMEDIATE');writer.rollback()
    scout.persist_export(db,snap,after_batch=checkpoint)
    assert len(seen)==6
    check(db)


def test_backfill_error_records_failure_not_false_loss(db):
    observe(db)
    with patch.object(scout,'fetch_room_export',side_effect=TimeoutError('offline')):
        with pytest.raises(TimeoutError):scout.backfill_room(db,'technocore')
    m=ev.metrics(db)
    assert m['backfills_failed']==1 and m['confirmed_retention_losses']==0
    assert m['unresolved_coverage_sources']
    check(db)


def test_status_daily_typed_provenance_readonly(db,tmp_path):
    observe(db)
    scout.backfill_room(db,'technocore',export_snapshot(tmp_path,messages(1,200)))
    with scout.observer_connect_readonly(tmp_path/'observer.sqlite') as reader:
        m=ev.metrics(reader)
        assert m['coverage_cursor_by_source']['technocore_room/technocore/g1']==200
        assert m['observed_high_water_by_source']['technocore_room/technocore/g1']==200
        assert m['backfills_completed']==1
        d=ev.daily(reader)['coverage_provenance']
        assert d['TAIL WINDOWS OBSERVED']==d['BACKFILLS COMPLETED']==1
        assert not d['UNRESOLVED COVERAGE']
        schemas={r['schema'] for r in cv.provenance(reader)}
        assert 'flop-scout-coverage/v1' in schemas and 'flop-scout-backfill/v1' in schemas
        assert all(r['raw_record_id'] for r in ev.feed(reader))
        check(reader)


@pytest.mark.parametrize('signal_number',[signal.SIGTERM,signal.SIGINT])
def test_worker_clean_shutdown_and_singleton(tmp_path,signal_number):
    code='''
import flop_scout as s
import scout_worker as w
s.validation_watch_rooms=lambda _:['lobby']
s.fetch_room_view=lambda *a,**kw:({'messages':[],'last_seq':0},'0')
w.run()
'''
    env=dict(os.environ,FLOP_SCOUT_STATE_DIR=str(tmp_path))
    p=subprocess.Popen([sys.executable,'-u','-c',code],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        assert p.stdout.readline().strip()=='POLL_LOCK_ACQUIRED'
        loser=subprocess.run([sys.executable,'-u','-c',code],env=env,capture_output=True,text=True,timeout=10)
        assert loser.returncode==0 and 'SKIP active poll lock held' in loser.stdout
        p.send_signal(signal_number);_,error=p.communicate(timeout=10)
        assert p.returncode==0,error
    finally:
        if p.poll() is None:p.kill();p.communicate()


def test_concurrent_readers_serialized_writer(db):
    barrier=threading.Barrier(3); readers=set(); writers=set()
    rooms=['lobby','faucet','technocore'];settings=worker.configuration(rooms)
    def read(room,*_):
        readers.add(threading.get_ident());barrier.wait(timeout=5)
        return ({'messages':messages(1,1),'last_seq':1},'new')
    original=scout.service_poll_room
    def persist(*args,**kwargs):
        writers.add(threading.get_ident());return original(*args,**kwargs)
    with patch.object(scout,'service_poll_room',side_effect=persist):
        worker.Coordinator(db,settings,concurrency=3,reader=read).run(once=True)
    assert len(readers)==3 and writers=={threading.get_ident()}
    check(db)


def test_deterministic_priority_schedule(db):
    now=[100.0];coordinator=worker.Coordinator(db,worker.configuration(['tclk-offers','lobby','faucet']),clock=lambda:now[0])
    assert coordinator.candidates()==['lobby','faucet','tclk-offers']
    coordinator.health('lobby',100,high=100)
    coordinator.health('faucet',100,high=100)
    assert coordinator.due['lobby']==101 and coordinator.due['faucet']==102
    now[0]=101
    assert coordinator.candidates()==['lobby','tclk-offers']
    coordinator.health('lobby',101,high=150)
    assert ev.metrics(db)['per_room_effective_rate']['lobby']==50


@pytest.mark.parametrize('status',[429,503,500,None])
def test_backoff(db,status):
    err=scout.ObservationReadError('unavailable',status,'90' if status==429 else None)
    assert worker.backoff(1,1,err)==(90 if status==429 else 5)
    assert worker.backoff(3,1,err)>worker.backoff(1,1,Exception())
    c=worker.Coordinator(db,worker.configuration(['lobby']),clock=lambda:100)
    c.health('lobby',99,error=err)
    assert c.due['lobby']>=105
    assert ev.metrics(db)['per_room_health'][0]['failures']==1


@pytest.mark.parametrize('setting',[{'poll_interval_seconds':0},{'priority':-1},{'export_backfill_enabled':'yes'},{'unknown':1}])
def test_invalid_polling_config(tmp_path,setting):
    path=tmp_path/'polling.json';path.write_text(json.dumps({'lobby':setting}))
    with pytest.raises(ValueError):worker.configuration(['lobby'],path)


def test_polling_collection_configuration():
    result=worker.configuration(['lobby'],collections={'x':{'enabled':True,'rooms':['lobby'],'poll_interval_seconds':3,'priority':4,'export_backfill_enabled':False}})
    assert result['lobby']=={'poll_interval_seconds':3,'priority':4,'export_backfill_enabled':False}


def test_export_evidence_hash_tampering_fails_integrity(db,tmp_path):
    snap=export_snapshot(tmp_path,messages(1,200))
    scout.backfill_room(db,'technocore',snap)
    Path(snap['path']).write_bytes(b'{}\n')
    assert ev.integrity(db)['status']=='FAIL'


def test_no_actions_during_tail_or_export(db,tmp_path):
    with patch.object(scout,'load_key',side_effect=AssertionError('private key')),patch.object(scout,'post_signed',side_effect=AssertionError('write')),patch.object(scout,'request_json',side_effect=AssertionError('unexpected request')):
        observe(db)
        snap=export_snapshot(tmp_path,messages(1,200)+[{'seq':201,'text':'visit https://evil.example/claim and execute TCLK'}])
        scout.backfill_room(db,'technocore',snap)
    assert all(ev.metrics(db)[k]==0 for k in ev.SAFETY_KEYS)
    check(db)


def test_generation_reset_does_not_invent_previous_epoch_loss(db,tmp_path):
    scout.service_poll_room(db,'technocore',response=(tail(messages(900,1099),0,200,'new'),'new'))
    r=scout.backfill_room(db,'technocore',export_snapshot(tmp_path,messages(800,1099),generation='new'))
    assert r['coverage_cursor']==1099 and r['coverage_status']=='CURRENT_AFTER_BACKFILL'
    assert ev.metrics(db)['confirmed_retention_losses']==0
    check(db)


@pytest.mark.parametrize('wrong', ['room','generation'])
def test_supplied_snapshot_cannot_change_expected_provenance(db,tmp_path,wrong):
    observe(db)
    snap=export_snapshot(tmp_path,messages(800,1099),room='lobby' if wrong=='room' else 'technocore',generation='g2' if wrong=='generation' else 'g1')
    with pytest.raises(ValueError,match='expected'):scout.backfill_room(db,'technocore',snap)
    assert cv.state(db,'technocore','g1')['coverage_status']=='UNRESOLVED'
    assert ev.metrics(db)['confirmed_retention_losses']==0
    check(db)


class Response(io.BytesIO):
    def __init__(self,raw,headers=None,status=200):
        super().__init__(raw);self.headers=headers or {'X-Room-Generation':'g1'};self.status=status


def test_export_transport_fixed_get_streaming(db,tmp_path):
    body=b''.join(json.dumps(r).encode()+b'\n' for r in messages(1,200))
    calls=[]
    class Opener:
        def open(self,request,timeout):
            calls.append((request.full_url,request.method,timeout))
            return Response(body)
    with patch.object(scout.urllib.request,'build_opener',return_value=Opener()):
        snap=scout.fetch_room_export('technocore','g1')
    assert calls==[('https://technocore.chat/r/technocore/export','GET',20)]
    assert Path(snap['path']).read_bytes()==body
    scout.backfill_room(db,'technocore',snap)
    check(db)


@pytest.mark.parametrize('failure',['redirect','partial_status','timeout','oversize','shutdown'])
def test_export_transport_fails_closed(db,tmp_path,monkeypatch,failure):
    body=b'{"seq":101,"text":"x"}\n'
    stop=threading.Event()
    if failure=='shutdown':stop.set()
    if failure=='oversize':monkeypatch.setattr(cv,'MAX_EXPORT_BYTES',1)
    class Opener:
        def open(self,request,timeout):
            if failure=='redirect':
                scout.ObservationRedirectBlocked().redirect_request(request,None,302,'redirect',{},'https://evil.example')
            if failure=='timeout':raise TimeoutError('offline')
            return Response(body,status=206 if failure=='partial_status' else 200)
    with patch.object(scout.urllib.request,'build_opener',return_value=Opener()):
        with pytest.raises((ValueError,TimeoutError,urllib.error.HTTPError)):
            scout.fetch_room_export('technocore','g1',stop_event=stop)
    assert not list((tmp_path/'evidence/export-snapshots').glob('download-*'))
    assert ev.metrics(db)['confirmed_retention_losses']==0


def test_worker_resumes_snapshot_without_network(db,tmp_path):
    observe(db,450,500)
    snapshot=export_snapshot(tmp_path,messages(1,500))
    with pytest.raises(RuntimeError):
        scout.persist_export(db,snapshot,after_batch=lambda _:(_ for _ in ()).throw(RuntimeError('crash')))
    stop=threading.Event()
    coordinator=worker.Coordinator(db,worker.configuration(['technocore']),reader=lambda *_:(_ for _ in ()).throw(AssertionError('must resume local snapshot')),stop=stop)
    with ThreadPoolExecutor(max_workers=1) as pool:
        coordinator.schedule(pool)
        f=next(iter(coordinator.inflight));f.result(timeout=3);coordinator.persist(f)
        while coordinator.exports:coordinator.persist_export_batch()
    assert scout.room_cursor(db,'technocore')['last_seq']==500
    assert check(db)['raw_records']==500


def test_worker_interleaves_tail_persistence_between_export_batches(db,tmp_path):
    observe(db,450,500)
    snapshot=export_snapshot(tmp_path,messages(1,500))
    coordinator=worker.Coordinator(db,worker.configuration(['technocore','lobby']))
    export_future=Future();export_future.set_result(snapshot)
    coordinator.inflight[export_future]=('technocore','export',coordinator.clock(),'g1')
    coordinator.active_rooms.add('technocore');coordinator.persist(export_future)
    coordinator.persist_export_batch()
    assert db.execute('SELECT processed_records FROM evidence_export_snapshots').fetchone()[0]==200
    tail_future=Future();tail_future.set_result(({'messages':messages(1,1),'last_seq':1},'g1'))
    coordinator.inflight[tail_future]=('lobby','tail',coordinator.clock(),'g1')
    coordinator.active_rooms.add('lobby');coordinator.persist(tail_future)
    assert scout.room_cursor(db,'lobby')['last_seq']==1
    assert scout.room_cursor(db,'technocore')['last_seq']==100
    while coordinator.exports:coordinator.persist_export_batch()
    check(db)


def test_backoff_survives_worker_restart(db):
    settings=worker.configuration(['lobby'])
    c=worker.Coordinator(db,settings)
    c.health('lobby',c.clock(),error=scout.ObservationReadError('429',429,'120'))
    restarted=worker.Coordinator(db,settings)
    assert restarted.failures['lobby']==1
    assert restarted.due['lobby']-restarted.clock()>110
    assert not restarted.candidates()


def test_provenance_corruption_is_detected(db,tmp_path):
    ev.record_gap(db,'technocore','g1',100,150,200,'/r/technocore',{})
    scout.backfill_room(db,'technocore',export_snapshot(tmp_path,messages(1,200)))
    db.execute('DROP TRIGGER evidence_gap_reassessments_no_UPDATE')
    db.execute("UPDATE evidence_gap_reassessments SET evidence_hash='wrong'");db.commit()
    assert ev.integrity(db)['coverage_integrity_errors']>0


def test_single_sweep_performs_backfill(db,tmp_path):
    snapshot=export_snapshot(tmp_path,messages(1,200))
    calls=[]
    def read(room,kind,*_):
        calls.append(kind)
        return (tail(messages(150,200),100),'g1') if kind=='tail' else snapshot
    worker.Coordinator(db,worker.configuration(['technocore']),reader=read).run(once=True)
    assert calls==['tail','export']
    assert scout.room_cursor(db,'technocore')['last_seq']==200
    check(db)


def test_v2_migration_is_local_and_readers_do_not_migrate(tmp_path):
    path=tmp_path/'legacy.sqlite'
    with scout.observer_connect_write(path) as c:
        for table in ('evidence_room_health','evidence_coverage_events','evidence_gap_reassessments','evidence_retention_losses','evidence_export_snapshots','source_coverage_state'):
            c.execute('DROP TABLE '+table)
        c.execute('DELETE FROM evidence_schema WHERE version=3');c.commit()
    with scout.observer_connect_readonly(path) as c:
        assert cv.metrics(c)=={} and ev.integrity(c)['status']=='PASS'
        assert not c.execute('SELECT 1 FROM evidence_schema WHERE version=3').fetchone()
    with scout.observer_connect_write(path) as c:
        assert cv.tables_present(c)
        check(c)


def test_original_gap_recovery_hash_integrity_preserved(db,tmp_path):
    gid=ev.record_gap(db,'technocore','g1',100,150,200,'/r/technocore',{})
    observe(db)
    ev.recover_gaps(db,'technocore','g1',100,messages(150,200))
    check(db)
    db.execute('DROP TRIGGER gap_protect');db.commit()
    db.execute('PRAGMA foreign_keys=OFF')
    db.execute("UPDATE evidence_source_gaps SET first_recovered_raw_hash='wrong' WHERE gap_id=?",(gid,));db.commit()
    assert ev.integrity(db)['source_gap_errors']==1


def test_snapshot_facts_and_reassessment_replace_are_immutable(db,tmp_path):
    ev.record_gap(db,'technocore','g1',100,150,200,'/r/technocore',{})
    scout.backfill_room(db,'technocore',export_snapshot(tmp_path,messages(1,200)))
    with pytest.raises(sqlite3.IntegrityError):db.execute("UPDATE evidence_export_snapshots SET first_seq=900")
    db.rollback()
    row=dict(db.execute('SELECT * FROM evidence_gap_reassessments').fetchone())
    original=row['reason'];row['reason']='rewrite'
    with db:db.execute('INSERT OR REPLACE INTO evidence_gap_reassessments VALUES ('+','.join('?' for _ in row)+')',tuple(row.values()))
    assert db.execute('SELECT reason FROM evidence_gap_reassessments').fetchone()[0]==original
    check(db)


def test_captured_metadata_hash_binds_imported_export(tmp_path):
    with pytest.raises(ValueError,match='hash/size'):
        export_snapshot(tmp_path,messages(1,10),sha256='wrong')


def test_declining_legacy_alias_is_not_required_for_coverage_reset(db):
    ev.record_gap(db,'technocore','g1',50,150,200,'/r/technocore',{})
    scout.update_room_cursor(db,'technocore','g1',200)
    observe(db,201,202)
    assert scout.room_cursor(db,'technocore')['last_seq']==50
    assert scout.get_state(db,'cursor:technocore:seq')=='200'
    assert ev.metrics(db)['cursor_regressions']==0


def test_worker_does_not_double_count_persistence_read_failure(db):
    coordinator=worker.Coordinator(db,worker.configuration(['technocore']))
    future=Future();future.set_result(({'messages':messages(101,101),'_scout_transport':{'generation_conflict':True}},'g1'))
    coordinator.inflight[future]=('technocore','tail',coordinator.clock(),'g1')
    coordinator.active_rooms.add('technocore')
    coordinator.persist(future)
    assert ev.metrics(db)['read_failures']==1


def test_worker_refreshes_tail_after_export_generation_rejection(db):
    observe(db)
    now=[100.0]
    calls=[]
    def read(room,kind,*_):
        calls.append(kind)
        return ({'messages':messages(1,1),'last_seq':1},'new')
    coordinator=worker.Coordinator(db,worker.configuration(['technocore']),reader=read,clock=lambda:now[0])
    bad=Future();bad.set_exception(ValueError('Export generation mismatch'))
    coordinator.inflight[bad]=('technocore','export',100,'g1');coordinator.active_rooms.add('technocore')
    coordinator.persist(bad)
    now[0]=coordinator.due['technocore']
    with ThreadPoolExecutor(max_workers=1) as pool:
        coordinator.schedule(pool)
        f=next(iter(coordinator.inflight));f.result(timeout=2);coordinator.persist(f)
    assert calls==['tail']
    assert scout.room_cursor(db,'technocore')['generation']=='new'
    assert ev.metrics(db)['confirmed_retention_losses']==0


def test_new_generation_contiguous_tail_establishes_origin(db,tmp_path):
    scout.service_poll_room(db,'technocore',response=(tail(messages(1,100),0,200,'new'),'new'))
    assert cv.state(db,'technocore','new')['origin_unknown']==0
    scout.service_poll_room(db,'technocore',response=(tail(messages(900,1099),100,200,'new'),'new'))
    scout.backfill_room(db,'technocore',export_snapshot(tmp_path,messages(800,1099),generation='new'))
    assert ev.metrics(db)['confirmed_retention_losses']==1
    check(db)
