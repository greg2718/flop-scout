"""Offline populated-schema drift and startup regression checks."""
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from unittest.mock import patch

import pytest
import flop_scout as scout
import scout_coverage as cv
import scout_evidence as ev
import scout_schema as schema
import scout_worker as worker
from coverage_test_support import messages, tail, export_snapshot


@pytest.fixture
def populated(tmp_path, monkeypatch):
    monkeypatch.setattr(scout, 'HOME', tmp_path)
    monkeypatch.setattr(scout, 'LOG_FILE', tmp_path/'activity.jsonl')
    path = tmp_path/'observer.sqlite'
    conn = scout.observer_connect_write(path)
    scout.update_room_cursor(conn, 'technocore', 'g1', 100)
    scout.service_poll_room(conn, 'technocore', response=(tail(messages(150,160),100,200,'g1'),'g1'))
    snapshot = export_snapshot(tmp_path, messages(101,160))
    cv.register_snapshot(conn, snapshot)
    conn.commit()
    yield conn, path
    conn.close()


def drop_origin(conn):
    conn.execute('ALTER TABLE source_coverage_state DROP COLUMN origin_unknown')
    conn.commit()


def rows(conn):
    return {t: [tuple(r) for r in conn.execute('SELECT * FROM '+schema.quote(t))]
            for t, v in schema.contract().items() if v['kind']=='table' and t!='source_coverage_state'}


def test_populated_repair_preserves_evidence_and_backfills(populated):
    c, _ = populated
    old = rows(c)
    coverage = [tuple(r)[:-1] for r in c.execute('SELECT * FROM source_coverage_state')]
    drop_origin(c)
    assert schema.status(c)['status']=='RECONCILIATION_REQUIRED'
    with pytest.raises(KeyError, match='origin_unknown'):
        cv.save_tail(c,'technocore','g1',100,160,160)
    assert schema.reconcile(c)['changed']
    assert schema.status(c)['status']=='PASS'
    assert old == rows(c) # includes IDs, hashes, counts, events and all backfill rows
    assert coverage == [tuple(r)[:-1] for r in c.execute('SELECT * FROM source_coverage_state')]
    assert all(r[0]==1 for r in c.execute('SELECT origin_unknown FROM source_coverage_state'))
    assert ev.integrity(c)['status']=='PASS'
    changes = c.total_changes
    assert not schema.reconcile(c)['changed']
    assert c.total_changes == changes
    cv.save_tail(c,'technocore','g1',100,160,160)


def test_multiple_missing_objects(populated):
    c,_=populated
    drop_origin(c)
    c.execute('DROP INDEX raw_position')
    c.execute('DROP TRIGGER snapshot_no_delete')
    c.execute('DROP TRIGGER snapshot_no_replace')
    s=schema.status(c)
    assert s['missing_columns']==['source_coverage_state.origin_unknown']
    assert s['missing_indexes']==['raw_position']
    assert set(s['missing_triggers'])=={'snapshot_no_delete','snapshot_no_replace'}
    assert schema.reconcile(c)['status']=='PASS'


@pytest.mark.parametrize('definition', ['TEXT NOT NULL DEFAULT 0','INTEGER DEFAULT 0','INTEGER NOT NULL DEFAULT 1'])
def test_incompatible_column_fails_closed(populated,definition):
    c,_=populated
    drop_origin(c)
    c.execute('ALTER TABLE source_coverage_state ADD COLUMN origin_unknown '+definition)
    assert schema.status(c)['status']=='INCOMPATIBLE'
    with pytest.raises(schema.SchemaDrift, match='SCHEMA_DRIFT'):
        schema.reconcile(c)


def test_missing_table_not_replaced_with_empty_history(populated):
    c,_=populated
    c.execute('DROP TABLE evidence_room_health')
    assert 'evidence_room_health' in schema.status(c)['missing_tables']
    with pytest.raises(schema.SchemaDrift): schema.reconcile(c)


def test_read_only_status_bytes_unchanged(populated):
    c,path=populated
    drop_origin(c)
    c.execute('PRAGMA wal_checkpoint(TRUNCATE)')
    def hashes():
        return {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in path.parent.glob('observer.sqlite*')}
    before=hashes()
    env=dict(os.environ, FLOP_SCOUT_STATE_DIR=str(path.parent/'must-not-be-created'))
    r=subprocess.run([sys.executable,'flop_scout.py','evidence','schema-status','--db',str(path)],env=env,capture_output=True,text=True)
    assert r.returncode==1
    assert json.loads(r.stdout)['status']=='RECONCILIATION_REQUIRED'
    assert before==hashes()
    assert not (path.parent/'must-not-be-created').exists()


def test_atomic_rollback_on_post_repair_failure(populated):
    c,_=populated
    drop_origin(c)
    c.execute('DROP INDEX raw_position')
    before=rows(c)
    real=schema.status
    calls=[]
    def fail_after(conn):
        result=real(conn)
        calls.append(1)
        if len(calls)==2: raise RuntimeError('injected verification failure')
        return result
    with patch.object(schema,'status',side_effect=fail_after):
        with pytest.raises(RuntimeError,match='injected'): schema.reconcile(c)
    assert rows(c)==before
    assert schema.status(c)['missing_columns']
    assert schema.status(c)['missing_indexes']==['raw_position']
    assert c.execute('PRAGMA integrity_check').fetchone()[0]=='ok'


def test_worker_startup_reconciles_before_coordinator(populated,monkeypatch):
    c,path=populated
    drop_origin(c)
    monkeypatch.setattr(scout,'observer_connect',lambda:scout.observer_connect_write(path))
    called=[]
    def run(coordinator):
        assert schema.status(coordinator.conn)['status']=='PASS'
        cv.save_tail(coordinator.conn,'technocore','g1',100,160,160)
        called.append(True)
    monkeypatch.setattr(worker.Coordinator,'run',run)
    worker.run()
    assert called


def test_worker_incompatible_fails_before_coordinator(populated,monkeypatch):
    c,path=populated
    drop_origin(c)
    c.execute('ALTER TABLE source_coverage_state ADD COLUMN origin_unknown TEXT')
    c.commit()
    monkeypatch.setattr(scout,'observer_connect',lambda:scout.observer_connect_write(path))
    with patch.object(worker,'Coordinator') as coordinator:
        with pytest.raises(schema.SchemaDrift,match='SCHEMA_DRIFT'):worker.run()
        coordinator.assert_not_called()


def test_historical_unknown_does_not_invent_retention_loss(populated,tmp_path):
    c,_=populated
    drop_origin(c)
    schema.reconcile(c)
    snapshot=export_snapshot(tmp_path,messages(140,160))
    result=scout.backfill_room(c,'technocore',snapshot)
    assert result['coverage_cursor']==160
    assert result['origin_unknown']==0
    assert c.execute('SELECT count(*) FROM evidence_retention_losses').fetchone()[0]==0
    assert c.execute("SELECT count(*) FROM evidence_coverage_events WHERE kind='GENERATION_BASELINE_ESTABLISHED'").fetchone()[0]==1
    assert ev.integrity(c)['status']=='PASS'


@pytest.mark.parametrize('kind,name,sql',[
    ('INDEX','raw_hash','CREATE INDEX raw_hash ON raw_network_records(room)'),
    ('TRIGGER','raw_no_delete','CREATE TRIGGER raw_no_delete BEFORE DELETE ON raw_network_records BEGIN SELECT 1; END')])
def test_wrong_index_or_trigger_detected(populated,kind,name,sql):
    c,_=populated
    c.execute('DROP '+kind+' '+name)
    c.execute(sql)
    assert schema.status(c)['status']=='INCOMPATIBLE'
    with pytest.raises(schema.SchemaDrift):schema.reconcile(c)


def test_missing_other_column_is_not_guessed(populated):
    c,_=populated
    c.execute('ALTER TABLE evidence_room_health DROP COLUMN effective_rate')
    s=schema.status(c)
    assert 'evidence_room_health.effective_rate' in s['missing_columns']
    assert s['status']=='INCOMPATIBLE'
    with pytest.raises(schema.SchemaDrift):schema.reconcile(c)


@pytest.mark.parametrize('transform',[
    lambda sql: sql.replace('REFERENCES evidence_export_snapshots(snapshot_id)', 'REFERENCES evidence_export_snapshots(sha256)'),
    lambda sql: sql.replace("sequence_contract TEXT NOT NULL", "sequence_contract TEXT NOT NULL CHECK(length(sequence_contract)>1)"),
])
def test_fk_and_constraint_drift_detected(populated,transform):
    c,_=populated
    definition=c.execute("SELECT sql FROM sqlite_master WHERE name='evidence_retention_losses'").fetchone()[0]
    c.execute('DROP TABLE evidence_retention_losses')
    c.execute(transform(definition))
    assert schema.status(c)['status']=='INCOMPATIBLE'
    with pytest.raises(schema.SchemaDrift):schema.reconcile(c)


def test_preserves_existing_origin_flags(populated):
    c,_=populated
    c.execute('UPDATE source_coverage_state SET origin_unknown=1')
    c.commit()
    assert not schema.reconcile(c)['changed']
    assert c.execute('SELECT origin_unknown FROM source_coverage_state').fetchone()[0]==1


def test_trigger_literal_case_change_fails_closed(populated):
    c,_=populated
    definition=c.execute("SELECT sql FROM sqlite_master WHERE name='gap_protect'").fetchone()[0]
    c.execute('DROP TRIGGER gap_protect')
    c.execute(definition.replace("'RECOVERED'", "'recovered'"))
    assert schema.status(c)['status']=='INCOMPATIBLE'


def test_reconcile_cli_on_temporary_fixture(populated):
    c,path=populated
    drop_origin(c)
    env=dict(os.environ,FLOP_SCOUT_STATE_DIR=str(path.parent))
    cmd=[sys.executable,'flop_scout.py','evidence','reconcile-schema','--db',str(path)]
    for changed in (True,False):
        r=subprocess.run(cmd,env=env,capture_output=True,text=True)
        assert r.returncode==0,r.stderr
        assert json.loads(r.stdout)['changed']==changed
    assert ev.integrity(c)['status']=='PASS'
