"""Adversarial preparation, deterministic recovery and bounded real writer turns."""
import threading
import time
from unittest.mock import patch
import pytest
import flop_scout as scout
import scout_evidence as evidence
import scout_preparation as preparation
import scout_runtime as runtime
import scout_worker as worker
from coverage_test_support import messages


def test_slow_page_preparation_and_sql_yield(tmp_path,monkeypatch):
    monkeypatch.setattr(scout,'HOME',tmp_path)
    path=tmp_path/'observer.sqlite'
    rooms=['lobby','quiet','third','fourth']
    settings=worker.configuration(rooms)
    for v in settings.values():v['export_backfill_enabled']=False
    def reader(room,*_):
        return {'messages':messages(1,80 if room=='lobby' else 8),'latest_seq':80 if room=='lobby' else 8},'g1'
    original=evidence.classify
    def classify(raw,status):
        assert threading.current_thread().name.startswith('scout-tail')
        time.sleep(.015) # >1 second page preparation must not own SQLite.
        return original(raw,status)
    ingest=scout.ingest_messages
    calls=[]
    def slow_sql(conn,room,records,**kwargs):
        assert len(records)<=8
        time.sleep(.04*len(records)) # Unexpected per-record execution cost.
        calls.append((room,len(records)))
        return ingest(conn,room,records,**kwargs)
    r=runtime.Runtime(path,settings,reader=reader)
    with patch.object(evidence,'classify',side_effect=classify),patch.object(scout,'ingest_messages',side_effect=slow_sql):
        r.run(once=True)
    d=r.diag.snapshot()
    assert d['writer_hold_p95_ms']<500,d
    assert d['writer_hold_max_ms']<1500,d
    assert d['sqlite_max_queue_wait_ms']<3000,d
    assert d['sqlite_max_commit_ms']<1000,d
    assert d['sqlite_max_checkpoint_ms']<2000,d
    assert len(r.tail_done)==len(rooms)
    with scout.observer_connect_readonly(path) as c:
        assert evidence.integrity(c)['status']=='PASS'
        assert scout.room_cursor(c,'lobby')['last_seq']==80
    print({k:d[k] for k in ('writer_hold_p95_ms','writer_hold_max_ms','sqlite_max_queue_wait_ms','sqlite_max_commit_ms','sqlite_max_checkpoint_ms')})


def test_prepared_replay_repairs_partial_chunk(tmp_path):
    path=tmp_path/'db';c=scout.observer_connect_write(path)
    records=messages(1,12)
    plan=preparation.prepare_page('lobby',records,generation='g1',endpoint='/r/lobby')
    def persist(items,raw):
        with patch.object(evidence,'classify',side_effect=AssertionError('writer classification')),patch.object(scout,'prepare_compatibility',side_effect=AssertionError('writer parsing')),patch.object(scout,'verify_signed_record_offline',side_effect=AssertionError('writer verification')):
            return scout.ingest_messages(c,'lobby',raw,generation='g1',prepared=items)
    persist(plan['items'][:4],records[:4])
    c.close();c=scout.observer_connect_write(path)
    persist(plan['items'],records)
    assert c.execute('SELECT count(*) FROM raw_network_records').fetchone()[0]==12
    assert evidence.integrity(c)['status']=='PASS'
    assert c.execute('SELECT count(*) FROM messages').fetchone()[0]==12
    c.close()


def test_long_coverage_scan_resumes_in_bounded_ranges(tmp_path):
    import scout_coverage as coverage
    c=scout.observer_connect_write(tmp_path/'db')
    records=messages(1,100)
    plan=preparation.prepare_page('lobby',records,generation='g1',endpoint='/r/lobby')
    scout.ingest_messages(c,'lobby',records,generation='g1',prepared=plan['items'])
    work={};token=coverage.COVERAGE_WORK.set(work);turns=0
    try:
        while True:
            turns+=1
            try:
                assert coverage.contiguous(c,'lobby','g1',0)==100
                break
            except coverage.CoveragePending:
                assert work[('lobby','g1',0)][0]==32*turns
        assert turns==4
    finally:
        coverage.COVERAGE_WORK.reset(token);c.close()


def test_export_reassessment_yields_without_duplicate_finalization(tmp_path):
    import scout_coverage as coverage
    from coverage_test_support import export_snapshot
    c=scout.observer_connect_write(tmp_path/'db')
    for i in range(9):
        evidence.record_gap(c,'technocore','g1',i,150+i,200,'/r/technocore',{})
    snapshot=export_snapshot(tmp_path,messages(1,200))
    saved=coverage.begin_export(c,snapshot)
    plan=preparation.prepare_page('technocore',messages(1,200),generation='g1',endpoint=snapshot['source_endpoint'])
    scout.ingest_messages(c,'technocore',messages(1,200),generation='g1',prepared=plan['items'])
    work={};token=coverage.COVERAGE_WORK.set(work);turns=0
    try:
        while True:
            turns+=1
            try:
                result=coverage.finish_export(c,saved)
                break
            except coverage.CoveragePending:pass
        assert turns>=9
        assert result['coverage_cursor']==200
        assert c.execute('SELECT count(*) FROM evidence_gap_reassessments').fetchone()[0]==9
        assert c.execute("SELECT count(*) FROM evidence_coverage_events WHERE kind='BACKFILL_COMPLETED'").fetchone()[0]==1
    finally:coverage.COVERAGE_WORK.reset(token);c.close()
