"""Controlled-clock scheduling under permanent backlog; no network or wall waits."""
from concurrent.futures import Future
import json
from pathlib import Path
import sqlite3
import threading
from unittest.mock import patch

import pytest
import flop_scout as scout
import scout_coverage as cv
import scout_evidence as ev
import scout_worker as worker
from coverage_test_support import messages, tail, export_snapshot

ROOMS=['lobby','faucet','technocore','kibble','tclk-offers','consensus_layer','quiet']


@pytest.fixture
def db(tmp_path,monkeypatch):
    monkeypatch.setattr(scout,'HOME',tmp_path)
    monkeypatch.setattr(scout,'LOG_FILE',tmp_path/'activity.jsonl')
    c=scout.observer_connect_write(tmp_path/'observer.sqlite')
    for room in ROOMS:
        scout.update_room_cursor(c,room,'g1',100)
        cv.state(c,room,'g1',100)
    c.execute('UPDATE source_coverage_state SET backfill_required=1');c.commit()
    yield c
    c.close()


class FakePool:
    def __init__(self,now,latency,kind):
        self.now=now;self.latency=latency;self.kind=kind;self.jobs=[];self.calls=[]
    def submit(self,fn,*args):
        f=Future()
        self.jobs.append((self.now[0]+self.latency,f,fn,args))
        if args:self.calls.append((args[0],self.now[0]))
        return f
    def complete(self):
        for end,f,fn,args in list(self.jobs):
            if end<=self.now[0]:
                self.jobs.remove((end,f,fn,args))
                try:f.set_result(fn(*args))
                except BaseException as exc:f.set_exception(exc)


def simulate(db,seconds=2400,export_batches=80,latency=0.2,write_cost=0.005,fail_lobby=False):
    now=[0.0]; settings=worker.configuration(ROOMS)
    def read(room,kind,*_):
        if fail_lobby and room=='lobby' and kind=='tail':
            raise scout.ObservationReadError('429',429,'90')
        return ({'room':room,'generation':'g1'} if kind=='export' else ({'room':room},'g1'))
    co=worker.Coordinator(db,settings,concurrency=2,reader=read,clock=lambda:now[0],wall_clock=lambda:1700000000+now[0])
    tails=FakePool(now,latency,'tail');exports=FakePool(now,0.5,'export')
    tail_times={r:[] for r in ROOMS};export_turns=[];writer_threads=set()
    def persist_tail(conn,room,response):
        writer_threads.add(threading.get_ident());now[0]+=write_cost
        tail_times[room].append(now[0])
        return dict(continuity='BACKFILL_REQUIRED',observed_high_water=100,backlog_remaining=True)
    def persist_export(conn,snapshot):
        writer_threads.add(threading.get_ident());export_turns.append(snapshot['room'])
        for _ in range(export_batches):
            now[0]+=write_cost
            yield 200
        # Deliberately permanent backlog: this room immediately requests another
        # export turn, including lobby and faucet. The queue must still rotate.
        yield dict(coverage_cursor=100,coverage_status='CURRENT',backfill_required=False,observed_high_water=100)
    with patch.object(scout,'service_poll_room',side_effect=persist_tail),patch.object(scout,'persist_export_steps',side_effect=persist_export):
        while now[0]<seconds:
            co.schedule(tails,exports)
            tails.complete();exports.complete()
            for f in sorted(list(co.inflight),key=lambda f:(co.inflight[f][1]!='tail',co.inflight[f][2])):
                if f.done():co.persist(f)
            co.persist_export_batch()
            assert sum(v[1]=='tail' for v in co.inflight.values())<=2
            assert sum(v[1]=='export' for v in co.inflight.values())+len(co.exports)<=1
            assert len(co.backfill_pending)<=len(ROOMS)
            now[0]+=0.05
    maxima={r:max(b-a for a,b in zip([0]+times,times+[now[0]])) for r,times in tail_times.items() if times}
    return co,tail_times,export_turns,maxima,writer_threads


def test_forty_minutes_busy_backfills_bounded_tails(db,tmp_path):
    co,times,turns,maximum,writers=simulate(db)
    for room in ROOMS:
        assert len(times[room])>=30
        assert maximum[room]<=worker.configuration(ROOMS)[room]['poll_interval_seconds']+1.5
    assert writers=={threading.get_ident()}
    assert set(turns[:len(ROOMS)])==set(ROOMS)
    assert all(len(set(turns[i:i+len(ROOMS)]))==len(ROOMS) for i in range(0,len(turns)-len(ROOMS),len(ROOMS)))
    assert worker.scheduler_metrics(db,1700002400)['rooms_starved']==[]
    result={'simulated_seconds':2400,'max_poll_ages_seconds':maximum,'poll_counts':{r:len(v) for r,v in times.items()},'export_turns':len(turns)}
    (tmp_path/'fairness-results.json').write_text(json.dumps(result,indent=2))
    print(json.dumps(result,sort_keys=True))


def test_queue_pressure_still_serves_all_rooms(db):
    _,times,turns,maximum,_=simulate(db,seconds=300,latency=2,write_cost=0.2)
    assert all(len(times[r])>=4 for r in ROOMS)
    assert max(maximum.values())<75
    assert set(turns[:7])==set(ROOMS)


def test_429_only_delays_affected_room(db):
    co,times,_,maximum,_=simulate(db,seconds=200,fail_lobby=True)
    assert not times['lobby']
    assert all(times[r] for r in ROOMS if r!='lobby')
    assert maximum['technocore']<22
    assert co.failures['lobby']>0 and co.failures['technocore']==0
    assert worker.scheduler_metrics(db,1700000200)['rooms_starved']==['lobby']


def test_ten_times_overdue_beats_newly_due(db):
    now=[1000.0]
    co=worker.Coordinator(db,worker.configuration(ROOMS),clock=lambda:now[0])
    co.due['technocore']=800
    assert co.candidates()[0]=='technocore'


def test_failed_backfill_keeps_tail_and_other_backfills_eligible(db):
    now=[100.0];co=worker.Coordinator(db,worker.configuration(ROOMS),clock=lambda:now[0])
    co.discover_backfills()
    before=dict(co.due)
    f=Future();f.set_exception(scout.ObservationReadError('429',429,'90'))
    co.inflight[f]=('lobby','export',100,'g1');co.persist(f)
    assert co.due==before
    assert co.backfill_due['lobby']>=190
    assert 'lobby' in co.candidates()
    tails=FakePool(now,1,'tail');exports=FakePool(now,1,'export')
    co.schedule(tails,exports)
    assert exports.calls[0][0]=='faucet'


def test_same_room_tail_and_export_do_not_regress_coverage(db,tmp_path):
    db.execute('UPDATE source_coverage_state SET backfill_required=0');db.commit()
    snapshot=export_snapshot(tmp_path,messages(101,500))
    co=worker.Coordinator(db,worker.configuration(['technocore']))
    f=Future();f.set_result(snapshot)
    co.inflight[f]=('technocore','export',co.clock(),'g1');co.persist(f)
    co.persist_export_batch()
    # Export saved 101..300. Tail bridges onwards while the same export is open.
    # Use all consecutive records in a bounded tail so 301..350 bridge too.
    f=Future();f.set_result(({'messages':messages(301,500),'latest_seq':500},'g1'))
    co.inflight[f]=('technocore','tail',co.clock(),'g1');co.active_rooms.add('technocore');co.persist(f)
    assert cv.state(db,'technocore','g1')['coverage_cursor']==500
    later=Future();later.set_result(({'messages':messages(501,550),'latest_seq':550},'g1'))
    co.inflight[later]=('technocore','tail',co.clock(),'g1');co.persist(later)
    while co.exports:co.persist_export_batch()
    state=cv.state(db,'technocore','g1')
    assert state['coverage_cursor']==state['observed_high_water']==state['server_tail_high_water']==550
    assert scout.room_cursor(db,'technocore')['last_seq']==550
    assert ev.integrity(db)['status']=='PASS'


def test_new_generation_during_export_keeps_active_epoch(db,tmp_path):
    snapshot=export_snapshot(tmp_path,messages(101,500))
    co=worker.Coordinator(db,worker.configuration(['technocore']))
    f=Future();f.set_result(snapshot);co.inflight[f]=('technocore','export',co.clock(),'g1');co.persist(f)
    co.persist_export_batch()
    f=Future();f.set_result(({'messages':messages(1,1),'latest_seq':1},'g2'))
    co.inflight[f]=('technocore','tail',co.clock(),'g1');co.persist(f)
    while co.exports:co.persist_export_batch()
    assert scout.room_cursor(db,'technocore')['generation']=='g2'
    assert scout.room_cursor(db,'technocore')['last_seq']==1
    assert ev.integrity(db)['status']=='PASS'


def test_metrics_age_even_when_worker_stops(db):
    now=[0.0];co=worker.Coordinator(db,worker.configuration(ROOMS),clock=lambda:now[0],wall_clock=lambda:1700000000+now[0])
    co.publish_metrics(force=True)
    status=worker.scheduler_metrics(db,1700002400)
    assert set(status['rooms_starved'])==set(ROOMS)
    assert status['max_poll_age_seconds']==2400
    assert status['scheduler_status_age']==2400
    before=db.total_changes
    worker.scheduler_metrics(db,1700002500)
    assert db.total_changes==before


def test_backfill_completion_is_not_a_tail_poll(db):
    co=worker.Coordinator(db,worker.configuration(ROOMS))
    before=dict(co.polls['lobby']);due=co.due['lobby']
    co.export_finished('lobby')
    assert before==co.polls['lobby'] and co.due['lobby']==due


def test_shutdown_preserves_checkpoint_and_restart_resumes(db,tmp_path):
    stop=threading.Event();snapshot=export_snapshot(tmp_path,messages(101,600))
    original=scout.persist_export_steps
    def read(room,kind,*_):
        return snapshot if kind=='export' else ({'messages':[],'latest_seq':600},'g1')
    def steps(conn,result):
        iterator=original(conn,result)
        try:
            yield_value=next(iterator)
            stop.set()
            yield yield_value
        finally:iterator.close()
    co=worker.Coordinator(db,worker.configuration(['technocore']),reader=read,stop=stop)
    with patch.object(scout,'persist_export_steps',side_effect=steps):co.run()
    assert db.execute('SELECT processed_records FROM evidence_export_snapshots').fetchone()[0]==200
    assert ev.integrity(db)['status']=='PASS'
    def restarted_read(room,kind,*_):
        assert kind=='tail', 'restart should resume captured snapshot without a network export'
        return ({'messages':[],'latest_seq':600},'g1')
    worker.Coordinator(db,worker.configuration(['technocore']),reader=restarted_read).run(once=True)
    assert db.execute('SELECT processed_records FROM evidence_export_snapshots').fetchone()[0]==500
    assert scout.room_cursor(db,'technocore')['last_seq']==600
    assert ev.integrity(db)['status']=='PASS'


def test_stalled_export_uses_no_tail_slot_even_at_concurrency_one(db):
    now=[0.0]
    co=worker.Coordinator(db,worker.configuration(ROOMS),concurrency=1,
                          reader=lambda room,kind,*_: ({'messages':[],'latest_seq':100},'g1'),
                          clock=lambda:now[0],wall_clock=lambda:1700000000+now[0])
    tails=FakePool(now,0.1,'tail');exports=FakePool(now,9999,'export')
    for _ in range(1300):
        co.schedule(tails,exports);tails.complete()
        for f in list(co.inflight):
            if f.done():co.persist(f)
        now[0]+=0.1
    assert len(exports.jobs)==1
    assert all(co.polls[r]['polls_completed']>=2 for r in ROOMS)


def test_backfill_retry_and_fifo_survive_restart(db):
    now=[0.0];settings=worker.configuration(ROOMS)
    co=worker.Coordinator(db,settings,clock=lambda:now[0],wall_clock=lambda:1700000000+now[0])
    co.discover_backfills()
    co.export_finished('lobby',RuntimeError('failed'))
    co.discover_backfills();co.publish_metrics(force=True)
    restored=worker.Coordinator(db,settings,clock=lambda:now[0],wall_clock=lambda:1700000000+now[0])
    assert list(restored.backfill_pending)==list(co.backfill_pending)
    assert restored.backfill_due['lobby']==co.backfill_due['lobby']
    assert restored.backfill_failures['lobby']==1


@pytest.mark.parametrize('age,health',[(2,'HEALTHY'),(2.1,'DEGRADED'),(5,'DEGRADED'),(5.1,'STARVED')])
def test_scheduler_sla_thresholds(db,age,health):
    c=worker.Coordinator(db,worker.configuration(['lobby']),clock=lambda:0,wall_clock=lambda:1700000000)
    c.publish_metrics(force=True)
    result=worker.scheduler_metrics(db,1700000000+age)
    assert result['scheduler_health']==health
    assert result['scheduler_rooms']['lobby']['overdue_ratio']==pytest.approx(max(0,age-1))


def test_legacy_fixed_priority_export_admission_starves_for_forty_minutes():
    # Minimal frozen reproduction of the old candidates/schedule/health policy:
    # all rooms need export, exactly one export slot, fixed priority first, and
    # completion sets room's next due using its ordinary polling interval.
    settings=worker.configuration(ROOMS);due=dict.fromkeys(ROOMS,0);turns=dict.fromkeys(ROOMS,0)
    for now in range(2400):
        eligible=sorted((r for r in ROOMS if due[r]<=now),key=lambda r:(settings[r]['priority'],due[r],r))
        room=eligible[0]
        turns[room]+=1
        due[room]=now+settings[room]['poll_interval_seconds']
    assert turns['lobby']==2400
    assert all(turns[r]==0 and due[r]==0 for r in ROOMS if r!='lobby')


def test_once_failed_tail_with_pending_backfill_finishes(db):
    c=worker.Coordinator(db,worker.configuration(['technocore']),
                         reader=lambda *_:(_ for _ in ()).throw(RuntimeError('unavailable')))
    c.needs_tail_refresh.add('technocore')
    c.run(once=True)
    assert c.tail_done=={'technocore'} and not c.backfill_pending
