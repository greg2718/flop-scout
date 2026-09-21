import copy
import sqlite3
from pathlib import Path
import pytest
import scout_epoch_planner as p
from scout_epoch_planner_sqlite import records_from_current_source

def rec(i, reasons=None, deps=None, recency=None, domain='messages'):
    return dict(record_id='r%d'%i,content_sha256='%064x'%i,source_position=i,room='room',generation='1',domain=domain,observation_class='CLASS',recency=i if recency is None else recency,mandatory_reasons=sorted(reasons or []),dependencies=sorted(deps or []),archive_required=True,retained_floor=i)
def policy(**change):
    out=dict(target=4,headroom=1,reserve=1,hard_max=50000,selection_policy_version='v1',source_cut='10',predecessor_epoch_id='se2:prior',archive_commitment='a'*64,prior_floors={})
    out.update(change);return out
def code(call):
    with pytest.raises(p.PlanError) as e:call()
    return e.value.code
def test_deterministic_closure_hash_and_no_text():
    rows=[rec(1,['PERMANENT'],['r2']),rec(2),rec(3),rec(4),rec(5)]
    a=p.plan(rows,policy());b=p.plan(list(reversed(rows)),policy())
    assert a==b and a['mandatory_record_ids']==['r1','r2'] and 'text' not in str(a).lower()
def test_mandatory_reasons_dependencies_and_capacity_fail_closed():
    rows=[rec(1,['PINNED'],['r2']),rec(2,['QUALIFICATION']),rec(3)]
    assert set(p.plan(rows,policy())['mandatory_record_ids'])=={'r1','r2'}
    assert code(lambda:p.plan([rec(1,['PINNED'],['missing'])],policy()))=='PLAN_DEPENDENCY_MISSING'
    assert code(lambda:p.plan(rows,policy(target=1)))=='PLAN_MANDATORY_CAPACITY'
    assert code(lambda:p.plan(rows,policy(target=50000,headroom=1,reserve=1)))=='PLAN_CAPACITY'
def test_conflicts_floors_and_ties():
    rows=[rec(1),rec(2,recency=1),rec(3,recency=1)]
    assert p.plan(rows,policy(target=2))['optional_record_ids']==['r1','r2']
    bad=copy.deepcopy(rows);bad[1]['source_position']=1
    assert code(lambda:p.plan(bad,policy()))=='PLAN_SOURCE_POSITION'
    assert code(lambda:p.plan(rows,policy(prior_floors={'room|1|messages':99})))=='PLAN_FLOOR_REGRESSION'
def test_read_only_adapter_and_schema_rejection(tmp_path):
    path=(tmp_path/'fixture.sqlite').resolve();conn=sqlite3.connect(path)
    conn.executescript('CREATE TABLE raw_network_records(raw_record_id TEXT PRIMARY KEY,raw_text_sha256 TEXT,room TEXT,generation TEXT);CREATE TABLE observed_events(event_id INTEGER PRIMARY KEY,raw_record_id TEXT);INSERT INTO raw_network_records VALUES("r","a","room","1");INSERT INTO observed_events VALUES(1,"r");');conn.commit();conn.close()
    rows=records_from_current_source(path);assert rows[0]['mandatory_reasons']==['UNRESOLVED_DEPENDENCIES']
    with sqlite3.connect(path) as c:assert c.execute('SELECT count(*) FROM observed_events').fetchone()[0]==1
    bad=(tmp_path/'bad.sqlite').resolve();sqlite3.connect(bad).close()
    assert code(lambda:records_from_current_source(bad))=='PLAN_ADAPTER_SCHEMA'
