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


def test_deterministic_identity_and_generation(state):
    args=('technocore','g1',4507918,4991500,4991710,'/r/technocore',{})
    first=ev.record_gap(state,*args)
    assert ev.record_gap(state,*args)==first
    other=ev.record_gap(state,args[0],'g2',*args[2:])
    assert other!=first
    assert len(ev.source_gaps(state))==2


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
