import sqlite3
import pytest
import flop_scout
from scout_projection_source import Outbox, reconcile_tclk_indexes
from scout_projection_contract import ProjectionError

CONTRACT={
    'router_projection_tclk_offer':('offer_id','frame_type','room','generation'),
    'router_projection_tclk_contract':('contract_id','room','generation'),
}

def database():
    c=sqlite3.connect(':memory:');c.row_factory=sqlite3.Row;flop_scout.init_observer_db(c)
    return c

def columns(c,name):return tuple(r[2] for r in c.execute("PRAGMA index_info('"+name+"')"))

def test_fresh_and_existing_outbox_reconcile_tclk_indexes():
    c=database();Outbox(c,epoch='e',install=True)
    assert {name:columns(c,name) for name in CONTRACT}==CONTRACT
    c.execute('DROP INDEX router_projection_tclk_offer');c.execute('DROP INDEX router_projection_tclk_contract')
    before=c.execute('SELECT count(*) FROM raw_network_records').fetchone()[0]
    Outbox(c,epoch='e',install=True)
    assert {name:columns(c,name) for name in CONTRACT}==CONTRACT
    assert c.execute('SELECT count(*) FROM raw_network_records').fetchone()[0]==before

@pytest.mark.parametrize('name,definition',[
    ('router_projection_tclk_offer','offer_id,room,frame_type,generation'),
    ('router_projection_tclk_contract','contract_id,generation,room'),
])
def test_wrong_named_tclk_index_fails_closed(name,definition):
    c=database();c.execute('CREATE INDEX '+name+' ON tclk_frames('+definition+')')
    with pytest.raises(ProjectionError,match='SCHEMA_DRIFT'):
        reconcile_tclk_indexes(c)

def test_unrelated_index_tolerated_and_union_plan_uses_both():
    c=database();Outbox(c,epoch='e',install=True);c.execute('CREATE INDEX unrelated_tclk ON tclk_frames(ref)')
    for i in range(2):
        c.execute("INSERT INTO tclk_frames(room,generation,seq,transport_verification_status,transport_binding_status,frame_hash,offer_id,contract_id,observed_at,parse_status,raw_text) VALUES('r','g',?,'V','B',?,? ,?,'n','P','x')",(i,str(i),'offer' if i==0 else None,'contract' if i else None))
    plan=' '.join(r[3] for r in c.execute("EXPLAIN QUERY PLAN WITH roots AS (SELECT rowid FROM tclk_frames WHERE offer_id=? UNION SELECT rowid FROM tclk_frames WHERE contract_id=?) SELECT * FROM roots",('offer','contract')))
    assert 'router_projection_tclk_offer' in plan and 'router_projection_tclk_contract' in plan
