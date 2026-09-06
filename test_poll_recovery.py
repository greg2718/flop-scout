"""Production-hardening regressions; all state and workers are temporary."""
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
from unittest.mock import patch

import pytest
import flop_scout as scout
import scout_evidence as ev


@pytest.fixture
def state(tmp_path, monkeypatch):
    monkeypatch.setattr(scout, 'HOME', tmp_path)
    conn = scout.observer_connect_write(tmp_path/'observer.sqlite')
    scout.update_room_cursor(conn, 'technocore', 'g1', 4507918)
    yield conn
    conn.close()


def page(start=4991500, count=200, latest=4991710, first=4991500):
    return {'messages':[{'seq':i, 'text':f'observed {i}', 'from':'fixture'} for i in range(start,start+count)],
            'first_seq':first, 'latest_seq':latest}


def poll(conn, data=None, **kwargs):
    with patch.object(scout, 'fetch_room_view', return_value=(data or page(), 'g1')):
        return scout.service_poll_room(conn, 'technocore', **kwargs)


def cursor(conn):
    return scout.room_cursor(conn,'technocore')['last_seq']


def test_production_gap_catchup_and_current(state):
    result = poll(state, max_pages=1)
    assert result['continuity']=='CATCHING_UP_AFTER_GAP'
    assert cursor(state)==4991699
    assert result['known_retention_gaps']==1
    result = poll(state,page(4991700,11))
    assert result['continuity']=='CURRENT'
    assert cursor(state)==4991710
    metrics = ev.metrics(state)
    assert metrics['retention_gaps_detected']==metrics['retention_gaps_recovered']==1
    assert metrics['unresolved_retention_gaps']==metrics['read_failures']==0
    assert metrics['retention_gaps_during_soak']==1
    assert result['known_retention_gaps']==1
    assert ev.integrity(state)['raw_records']==211
    assert ev.integrity(state)['status']=='PASS'
    assert all(metrics[k]==0 for k in (*ev.SAFETY_KEYS,'cursor_regressions','database_errors'))
    daily=ev.daily(state)['upstream_retention_gaps']
    assert daily['detected_today']==daily['recovered_today']==1
    assert daily['sources'][0]['last_durable_seq']==4507918


def test_gap_and_whole_page_durable_before_cursor(state):
    original=scout.update_room_cursor
    def check(conn, *args):
        with scout.observer_connect_readonly(Path(scout.HOME)/'observer.sqlite') as reader:
            assert ev.source_gaps(reader)[0]['status']=='RECOVERED'
            assert ev.integrity(reader)['raw_records']==200
            assert ev.integrity(reader)['status']=='PASS'
            assert cursor(reader)==4507918
        return original(conn,*args)
    with patch.object(scout,'update_room_cursor',side_effect=check):
        poll(state,max_pages=1)


@pytest.mark.parametrize('boundary',['gap','raw','after_gap','after_raw','cursor'])
def test_failure_restart_idempotent(state,boundary):
    target={'gap':(ev,'record_gap'),'raw':(ev,'ingest'),'after_gap':(scout,'ingest_messages'),
            'after_raw':(scout,'highest_persisted_page_seq'),'cursor':(scout,'update_room_cursor')}[boundary]
    with patch.object(*target,side_effect=sqlite3.OperationalError('injected crash')):
        with pytest.raises(sqlite3.OperationalError):
            poll(state,max_pages=1)
    assert cursor(state)==4507918
    before = len(ev.source_gaps(state))
    assert before==(0 if boundary=='gap' else 1)
    assert ev.metrics(state)['read_failures']==1
    # Close/reopen a real SQLite connection to model a process restart.
    db = Path(scout.HOME)/'observer.sqlite'
    state.close()
    resumed = scout.observer_connect_write(db)
    try:
        poll(resumed,max_pages=1)
        assert cursor(resumed)==4991699
        assert len(ev.source_gaps(resumed))==1
        assert ev.integrity(resumed)['raw_records']==200
        assert ev.integrity(resumed)['status']=='PASS'
    finally:
        resumed.close()


def test_deterministic_identity_and_generation(state):
    args=('technocore','g1',4507918,4991500,4991710,'/r/technocore',{})
    first=ev.record_gap(state,*args)
    assert ev.record_gap(state,*args)==first
    other=ev.record_gap(state,args[0],'g2',*args[2:])
    assert other!=first
    assert len(ev.source_gaps(state))==2


@pytest.mark.parametrize('first',[None,1,4507918,4507919])
def test_sparse_sequences_alone_not_gaps(state,first):
    data=page(count=1,latest=4991500,first=first)
    assert poll(state,data)['continuity']=='CURRENT'
    assert not ev.source_gaps(state)


@pytest.mark.parametrize('raw',[None,{'seq':4991500,'text':{}},
    {'seq':4991500,'text':'bad signed','from':'did:key:invalid','did':'did:key:invalid','nonce':1,'sig':'invalid'}])
def test_malformed_and_bad_signature_retained(state,raw):
    data=page(4991501,1,4991501)
    data['messages'].insert(0,raw)
    result=poll(state,data)
    assert result['continuity']=='RETENTION_GAP_RECOVERED'
    assert ev.integrity(state)['raw_records']==2
    assert ev.integrity(state)['status']=='PASS'
    assert any(json.loads(row[0])==raw for row in state.execute('SELECT raw_record_json FROM raw_network_records'))


def test_gap_immutable_and_integrity_validates_recovery(state):
    poll(state,max_pages=1)
    for sql in ('DELETE FROM evidence_source_gaps', 'UPDATE evidence_source_gaps SET last_durable_seq=1',
                "UPDATE evidence_source_gaps SET status='UNRESOLVED'"):
        with pytest.raises(sqlite3.IntegrityError):
            state.execute(sql)
        state.rollback()
    state.execute('DROP TRIGGER gap_protect')
    state.execute("UPDATE evidence_source_gaps SET generation='wrong'")
    assert ev.integrity(state)['source_gap_errors']>0
    assert ev.integrity(state)['status']=='FAIL'


def test_empty_retained_page_fails_safely(state):
    result=poll(state,page(count=0))
    assert result['continuity']=='READ_FAILED'
    assert cursor(state)==4507918
    assert ev.metrics(state)['unresolved_retention_gaps']==1
    assert ev.metrics(state)['read_failures']==1


def test_generation_conflict_never_recovers(state):
    data=page(count=1)
    data['_scout_transport']={'generation_conflict':True}
    assert poll(state,data)['continuity']=='READ_FAILED'
    assert cursor(state)==4507918
    assert not ev.source_gaps(state)


WORKER = '''
import os, sys
from pathlib import Path
import flop_scout as s

def work():
    with (s.HOME/'db-writes').open('a') as f: f.write('write\\n')
    with (s.HOME/'network-reads').open('a') as f: f.write('read\\n')
    print('OBSERVATION_STARTED',flush=True)
    command=sys.stdin.readline().strip()
    if command=='crash': os._exit(17)
s._service_poll_unlocked=work
s.service_poll()
'''


def worker(tmp_path, code=WORKER):
    env=dict(os.environ,FLOP_SCOUT_STATE_DIR=str(tmp_path))
    return subprocess.Popen([sys.executable,'-u','-c',code],env=env,stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)


@pytest.mark.parametrize('ending',['normal','crash',signal.SIGKILL,signal.SIGTERM,signal.SIGINT])
def test_kernel_lock_lifecycle(tmp_path,ending):
    first=worker(tmp_path)
    try:
        assert first.stdout.readline().strip()=='POLL_LOCK_ACQUIRED'
        assert first.stdout.readline().strip()=='OBSERVATION_STARTED'
        second=worker(tmp_path)
        out,err=second.communicate(timeout=10)
        assert second.returncode==0
        assert out.strip()=='SKIP active poll lock held'
        assert (tmp_path/'db-writes').read_text()=='write\n'
        assert (tmp_path/'network-reads').read_text()=='read\n'
        if ending in ('normal','crash'):
            first.communicate(input=ending+'\n',timeout=10)
        else:
            first.send_signal(ending)
            first.communicate(timeout=10)
        assert (tmp_path/'run/service-poll.flock').exists()
        third=worker(tmp_path)
        out,err=third.communicate(input='normal\n',timeout=10)
        assert third.returncode==0
        assert out.splitlines()==['POLL_LOCK_ACQUIRED','OBSERVATION_STARTED']
        assert (tmp_path/'db-writes').read_text()=='write\nwrite\n'
        assert (tmp_path/'run/poll-lock-contention.log').read_text()=='SKIP\n'
    finally:
        if first.poll() is None:
            first.kill()
            first.communicate(timeout=10)


def test_launchd_wrapper_and_manual_share_lock(tmp_path):
    repo=tmp_path/'repo'; repo.mkdir()
    (repo/'.venv').symlink_to(Path(sys.executable).parent.parent, target_is_directory=True)
    (repo/'flop_scout.py').write_text('import sys\nsys.path.insert(0,'+repr(str(Path.cwd()))+')\n'+WORKER)
    first=worker(tmp_path)
    try:
        assert first.stdout.readline().strip()=='POLL_LOCK_ACQUIRED'
        assert first.stdout.readline().strip()=='OBSERVATION_STARTED'
        result=subprocess.run(['zsh','scripts/scout-service-poll.sh'],env=dict(os.environ,
            FLOP_SCOUT_REPO=str(repo),FLOP_SCOUT_STATE_DIR=str(tmp_path)),capture_output=True,timeout=10)
        assert result.returncode==0
        log=(tmp_path/'logs/service-poll.log').read_text()
        assert 'START' in log and 'SKIP active poll lock held' in log and 'END rc=0' in log
        assert (tmp_path/'db-writes').read_text()=='write\n'
    finally:
        first.kill(); first.communicate(timeout=10)


def test_persistent_legacy_directory_does_not_block_kernel_lock(tmp_path):
    (tmp_path/'run/service-poll.lock').mkdir(parents=True)
    proc=worker(tmp_path)
    out,_=proc.communicate('normal\n',timeout=10)
    assert 'POLL_LOCK_ACQUIRED' in out
    assert (tmp_path/'run/service-poll.lock').is_dir()


def test_status_contention_metric_readonly(state):
    run=Path(scout.HOME)/'run'; run.mkdir()
    (run/'poll-lock-contention.log').write_text('SKIP\nSKIP\n')
    with scout.observer_connect_readonly(Path(scout.HOME)/'observer.sqlite') as conn:
        assert ev.metrics(conn,Path(scout.HOME)/'observer.sqlite')['poll_lock_contention_skips']==2


def test_derived_failure_keeps_complete_raw_page_and_repairs(state):
    with patch.object(ev,'derive',side_effect=ValueError('parser failed')):
        with pytest.raises(ValueError):
            poll(state,max_pages=1)
    assert cursor(state)==4507918
    assert ev.integrity(state)['raw_records']==200
    assert ev.integrity(state)['missing_events']==200
    poll(state,max_pages=1)
    assert ev.integrity(state)['status']=='PASS'
    assert ev.integrity(state)['raw_records']==200


@pytest.mark.parametrize('boundary',['after_gap','after_raw','before_cursor'])
def test_actual_process_crash_during_gap_recovery(tmp_path,boundary):
    code='''
import os
import flop_scout as s
import scout_evidence as ev
s.fetch_room_view=lambda *a,**k: ({'messages':[{'seq':4991500,'text':'raw evidence'}],'first_seq':4991500,'latest_seq':4991500},'g1')
conn=s.observer_connect_write()
if s.room_cursor(conn,'technocore')['last_seq']==0: s.update_room_cursor(conn,'technocore','g1',4507918)
'''
    target={'after_gap':'s.ingest_messages','after_raw':'s.highest_persisted_page_seq','before_cursor':'s.update_room_cursor'}[boundary]
    first=worker(tmp_path,code+target+'=lambda *a,**k: os._exit(17)\ns.service_poll_room(conn,"technocore")\n')
    first.communicate(timeout=10)
    assert first.returncode==17
    with scout.observer_connect_readonly(tmp_path/'observer.sqlite') as reader:
        assert cursor(reader)==4507918
        assert len(ev.source_gaps(reader))==1
    second=worker(tmp_path,code+'s.service_poll_room(conn,"technocore")\n')
    _,err=second.communicate(timeout=10)
    assert second.returncode==0,err
    with scout.observer_connect_readonly(tmp_path/'observer.sqlite') as reader:
        assert cursor(reader)==4991500
        assert len(ev.source_gaps(reader))==1
        assert ev.integrity(reader)['raw_records']==1
        assert ev.integrity(reader)['status']=='PASS'


@pytest.mark.parametrize('active',['','123 /bin/zsh /tmp/scout-service-poll.sh','123 python /tmp/flop_scout.py service-poll'])
def test_legacy_migration_checks_processes(tmp_path,active,capsys):
    import importlib.util
    spec=importlib.util.spec_from_file_location('migration','scripts/scout-recover-legacy-lock.py')
    migration=importlib.util.module_from_spec(spec); spec.loader.exec_module(migration)
    legacy=tmp_path/'run/service-poll.lock'; legacy.mkdir(parents=True)
    with patch.object(migration.subprocess,'run',return_value=subprocess.CompletedProcess([],0,active,'')):
        if active:
            with pytest.raises(SystemExit,match='active'):
                migration.recover(tmp_path,True)
            assert legacy.exists()
        else:
            migration.recover(tmp_path,True)
            assert not legacy.exists()
            assert 'LEGACY_STALE_LOCK_RECOVERED' in capsys.readouterr().out
    with pytest.raises(SystemExit,match='quiesce'):
        migration.recover(tmp_path,False)


def test_bad_signature_available_record_is_explicit_failure_evidence(state):
    # Fixed public fixture only; never access an identity file.
    from test_scout_evidence import EvidenceTests
    raw=EvidenceTests().raw(seq=4991500,room='technocore')
    raw['text']='tampered signed text'
    data=page(count=0,latest=4991500); data['messages']=[raw]
    assert poll(state,data)['continuity']=='RETENTION_GAP_RECOVERED'
    assert ev.integrity(state)['signature_failures']==1
    assert ev.integrity(state)['status']=='PASS'


def test_gap_durable_before_raw_and_raw_durable_before_derivation(state):
    original_ingest=ev.ingest
    original_derive=ev.derive
    db=Path(scout.HOME)/'observer.sqlite'
    def ingest(*args,**kwargs):
        with scout.observer_connect_readonly(db) as reader:
            assert len(ev.source_gaps(reader))==1
            assert cursor(reader)==4507918
        return original_ingest(*args,**kwargs)
    def derive(*args,**kwargs):
        with scout.observer_connect_readonly(db) as reader:
            assert ev.integrity(reader)['raw_records']==3
            assert cursor(reader)==4507918
        return original_derive(*args,**kwargs)
    with patch.object(ev,'ingest',side_effect=ingest),patch.object(ev,'derive',side_effect=derive):
        poll(state,page(count=3,latest=4991502))


@pytest.mark.parametrize('field,value',[
    ('first_recovered_raw_record_id','absent'),('first_recovered_raw_hash','wrong'),('source','wrong')])
def test_integrity_rejects_invalid_gap_references(state,field,value):
    poll(state,max_pages=1)
    state.execute('DROP TRIGGER gap_protect'); state.commit()
    state.execute('PRAGMA foreign_keys=OFF')
    state.execute(f'UPDATE evidence_source_gaps SET {field}=?',(value,)); state.commit()
    assert ev.integrity(state)['source_gap_errors']>0
    assert ev.integrity(state)['status']=='FAIL'


def test_missing_derived_link_prevents_cursor(state):
    data=page(count=1,latest=4991500)
    with patch.object(ev,'derive',return_value=None):
        with pytest.raises(RuntimeError,match='fully persisted'):
            poll(state,data)
    assert cursor(state)==4507918
    assert ev.integrity(state)['raw_records']==1


def test_readonly_old_schema_needs_no_gap_migration(state):
    state.execute('DROP TABLE evidence_source_gaps')
    state.execute('DELETE FROM evidence_schema WHERE version=2'); state.commit()
    db=Path(scout.HOME)/'observer.sqlite'
    with scout.observer_connect_readonly(db) as reader:
        assert ev.metrics(reader)['retention_gaps_detected']==0
        assert ev.integrity(reader)['status']=='PASS'
        assert ev.daily(reader)['upstream_retention_gaps']['unresolved']==0
    with scout.observer_connect_write(db) as writer:
        assert writer.execute('SELECT 1 FROM evidence_schema WHERE version=2').fetchone()
        assert not ev.source_gaps(writer)


def test_missing_generation_cannot_silently_skip_retention_gap(state):
    with patch.object(scout,'fetch_room_view',return_value=(page(count=1),None)):
        result=scout.service_poll_room(state,'technocore')
    assert result['continuity']=='READ_FAILED'
    assert cursor(state)==4507918
    assert ev.integrity(state)['raw_records']==1
    assert not ev.source_gaps(state)
