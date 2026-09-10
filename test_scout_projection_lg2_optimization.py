"""Exact source parity and bounded LG2 owner transactions on synthetic data."""
import copy
import threading
import pytest
from scout_projection_contract import *
from scout_projection_source import map_raw,map_batch,Outbox
from scout_projection_batch import SOURCE_BATCH_ROWS
from scout_projection_compact import WriteBatch,sync
from scout_projection import Projector,initialize
from scripts.projection_lg1_support import source,add_legacy,DID,NOW,TEXT
from test_scout_projection import apply,quals
from test_scout_projection_lg2 import create


def sources(count=100,multi=True,report='0'):
    c=source();Outbox(c,epoch='source-epoch',install=True,revision=LG2_REVISION)
    ids=[add_legacy(c,n,report=report,protocol_cache=multi,text='ordinary synthetic context '+str(n)) for n in range(1,count+1)]
    return c,ids


@pytest.mark.parametrize('count',[1,49,50,51,200])
@pytest.mark.parametrize('report',[None,'0','1'])
def test_batch_exact_source_parity(count,report):
    c,ids=sources(count,report=report)
    try:
        before=[map_raw(c,r,revision=LG2_REVISION) for r in ids]
        assert map_batch(c,ids,revision=LG2_REVISION)==before
        assert not c.in_transaction
    finally:c.close()


def test_batched_sql_count_and_query_plans():
    c,ids=sources(100)
    try:
        queries=[];c.set_trace_callback(queries.append)
        for rid in ids:map_raw(c,rid,revision=LG2_REVISION)
        before=sum(q.startswith('SELECT') for q in queries);queries.clear()
        map_batch(c,ids,revision=LG2_REVISION)
        after=sum(q.startswith('SELECT') for q in queries)
        assert after<=16 and after<before/20
        alternate=next(q for q in queries if 'AND EXISTS' in q)
        plan=[r[3] for r in c.execute('EXPLAIN QUERY PLAN '+alternate)]
        assert any('SEARCH a USING' in r for r in plan)
        assert not any(r.startswith('SCAN a') for r in plan)
    finally:c.close()


@pytest.mark.parametrize('mutation', ['generation','hash','room','sender','alternate','retrieval','missing_cache'])
def test_conflict_rejected_with_batching(mutation):
    c,ids=sources(3)
    try:
        with c:
            if mutation in ('generation','hash','room','sender'):
                field={'generation':'generation','hash':'message_hash','room':'room','sender':'did'}[mutation]
                value={'generation':'1','hash':'a'*64,'room':'wrong','sender':'did:key:z6MkWrong'}[mutation]
                c.execute('UPDATE evidence_records SET '+field+'=? WHERE seq=2',(value,))
            elif mutation=='alternate':
                import scout_evidence
                raw=loads(c.execute('SELECT raw_record_json FROM raw_network_records WHERE seq=2').fetchone()[0])
                scout_evidence.ingest(c,'technocore',raw,lambda r,m:'UNSIGNED',source='other',generation='0')
            elif mutation=='retrieval':
                # A repeated retrieval adds lineage unavailable in the admitted class.
                add_legacy(c,2,protocol_cache=True,text='ordinary synthetic context 2')
            elif mutation=='missing_cache':c.execute('DELETE FROM evidence_records WHERE seq=2')
        with pytest.raises(ProjectionError):map_raw(c,ids[1],revision=LG2_REVISION)
        with pytest.raises(ProjectionError):map_batch(c,ids,revision=LG2_REVISION)
        assert not c.in_transaction
    finally:c.close()


def test_caller_transaction_preserved():
    c,ids=sources(2)
    try:
        c.execute('BEGIN');map_batch(c,ids,revision=LG2_REVISION)
        assert c.in_transaction
        c.rollback()
    finally:c.close()


def test_expiry_uses_composite_keys_and_preserves_watermarks(tmp_path):
    c,ids=sources(100)
    try:
        with create(tmp_path/'state') as p:
            apply(p,map_batch(c,ids,revision=LG2_REVISION))
            traced=[];p.conn.set_trace_callback(traced.append)
            with p.conn:
                for rid in ids[:50]:p._remove('sm1:'+rid)
            p.conn.set_trace_callback(None)
            queries={q for q in traced if q.startswith(('DELETE FROM projection.source_provenance','DELETE FROM projection.selection_membership','SELECT 1 FROM projection.selection_membership'))}
            assert queries
            for query in queries:
                plan=[r[3] for r in p.conn.execute('EXPLAIN QUERY PLAN '+query)]
                assert any(detail.startswith('SEARCH ') for detail in plan)
                assert not any(detail.startswith('SCAN ') for detail in plan)
            assert tuple(p.conn.execute('SELECT record_count,min_seq,max_seq FROM projection.watermarks').fetchone())==(50,51,100)
            assert p.legacy_status()['report_count']==50
            assert p.legacy_status()['witness_count']==100
            assert p.conn.execute('PRAGMA foreign_key_check').fetchall()==[]
    finally:c.close()


@pytest.mark.parametrize('cancel',[False,True])
def test_group_fanout_is_bounded_and_resumable(tmp_path,cancel):
    with create(tmp_path/'state') as p:
        n=p.begin('0',NOW,'BOOTSTRAP');transactions=[];pending=[0]
        def traced(sql):
            if sql.startswith('INSERT OR IGNORE INTO evaluation_groups'):pending[0]+=1
            if sql=='COMMIT':
                transactions.append(pending[0]);pending[0]=0
                if cancel and len(transactions)==1:p.stop.set()
        p.conn.set_trace_callback(traced)
        query="WITH RECURSIVE senders(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM senders WHERE n<450) SELECT printf('synthetic-sender-%d',n) FROM senders"
        if cancel:
            with pytest.raises(InterruptedError):p.include_groups(n,query,())
            assert p.conn.execute('SELECT count(*) FROM evaluation_groups').fetchone()[0]==200
            p.stop.clear()
        p.include_groups(n,query,())
        p.conn.set_trace_callback(None)
        assert max(transactions)==200 and all(0<=count<=200 for count in transactions)
        assert p.conn.execute('SELECT count(*) FROM evaluation_groups').fetchone()[0]==450


def test_bounded_write_batch_and_noop(tmp_path):
    c,ids=sources(100)
    try:
        bundles=map_batch(c,ids,revision=LG2_REVISION)
        with create(tmp_path) as p:
            q=[];p.conn.set_trace_callback(q.append);apply(p,bundles)
            assert p.legacy_status()['report_count']==100 and p.legacy_status()['witness_count']==200
            assert sum('SELECT raw_ref,reported_code FROM projection.legacy_generation_reports WHERE raw_ref IN' in x for x in q)==2
            q.clear();apply(p,bundles,plus(NOW,1),'SOURCE_BATCH')
            assert not any(x.startswith('INSERT INTO projection.legacy_generation_') for x in q)
            assert not any(x.startswith('UPDATE projection.source_provenance') for x in q)
            assert not quals(p)
    finally:c.close()


def test_stage_noop_and_conflict_atomic(tmp_path):
    c,ids=sources(3)
    try:
        bundles=map_batch(c,ids,revision=LG2_REVISION)
        with create(tmp_path) as p:
            n=p.begin('3',NOW,'BOOTSTRAP');p.stage(n,bundles)
            changed=p.conn.total_changes;p.stage(n,bundles)
            assert p.conn.total_changes==changed
            bad=copy.deepcopy(bundles);bad[1]['legacy_generation_compact']['reported_code']=1
            with pytest.raises(ProjectionError):p.stage(n,bad)
            assert p.conn.total_changes==changed
            p.seal(n)
    finally:c.close()


def test_cancellation_rolls_back_current_batch_and_replays(tmp_path,monkeypatch):
    c,ids=sources(125)
    try:
        bundles=map_batch(c,ids,revision=LG2_REVISION)
        with create(tmp_path/'p') as p:
            n=p.begin('125',NOW,'BOOTSTRAP');p.stage(n,bundles)
            original=p._upsert_message;calls=[]
            def cancelled(*a,**kw):
                calls.append(1);result=original(*a,**kw)
                if len(calls)==63:p.stop.set()
                return result
            monkeypatch.setattr(p,'_upsert_message',cancelled)
            with pytest.raises(InterruptedError):p.seal(n)
            assert p.conn.execute("SELECT status FROM evaluations WHERE number=?",(n,)).fetchone()[0]=='APPLYING'
            count=p.conn.execute('SELECT count(*) FROM projection.messages').fetchone()[0]
            assert 0<count<125
            assert p.conn.execute('SELECT count(*) FROM projection.legacy_generation_reports').fetchone()[0]==count
            assert not p.conn.execute('PRAGMA projection.foreign_key_check').fetchone()
            monkeypatch.setattr(p,'_upsert_message',original);p.stop.clear();p.resume(n)
            p.verify_ledger();p.replay_to(tmp_path/'replay'/'projection.sqlite')
    finally:c.close()


@pytest.mark.parametrize('batch_size',[50,100,200,500])
def test_bounded_owner_sizes_preserve_replay(tmp_path,batch_size):
    c,ids=sources(101)
    try:
        bundles=map_batch(c,ids,revision=LG2_REVISION)
        path=tmp_path/'projection.sqlite'
        initialize(path,epoch='source-epoch',router_source_id='router',router_epoch='router-epoch',router_did=DID,contract_revision=LG2_REVISION)
        with Projector(path,write_batch_size=batch_size) as p:
            apply(p,bundles);p.replay_to(tmp_path/'again'/'projection.sqlite')
    finally:c.close()


def test_existing_qualification_retention_after_fast_path(tmp_path):
    with source() as c:
        rid=add_legacy(c,report='0',protocol_cache=True,text=TEXT)
        b=map_batch(c,[rid],revision=LG2_REVISION)
        with create(tmp_path) as p:
            apply(p,b);before=quals(p);assert before
            apply(p,b,plus(NOW,1),'SOURCE_BATCH')
            assert quals(p)==before
            assert p.conn.execute('SELECT retain_until FROM projection.selection_membership').fetchone()[0] is None
            p.replay_to(tmp_path/'again'/'projection.sqlite')


def test_incompatible_capture_lineage_batch():
    import scout_evidence
    with source() as c:
        Outbox(c,epoch='source-epoch',install=True,revision=LG2_REVISION)
        raw=dict(seq=1,did=DID,nonce=124,ts=NOW,text=TEXT)
        with c:rid=scout_evidence.ingest(c,'technocore',raw,lambda r,m:'UNSIGNED',source='legacy_evidence',generation=None,reported_generation='0',legacy=True,endpoint='invalid',retrieved_at=NOW)
        add_legacy(c,1,protocol_cache=True,cache_only=True)
        with pytest.raises(ProjectionError):map_raw(c,rid,revision=LG2_REVISION)
        with pytest.raises(ProjectionError):map_batch(c,[rid],revision=LG2_REVISION)


def test_source_batch_snapshot_and_later_ambiguity(tmp_path,monkeypatch):
    import sqlite3
    import scout_evidence
    from scout_projection_batch import SourceInputs
    path=tmp_path/'source.sqlite';c=source(path)
    try:
        c.execute('PRAGMA journal_mode=WAL')
        Outbox(c,epoch='source-epoch',install=True,revision=LG2_REVISION)
        ids=[add_legacy(c,n,text='ordinary '+str(n)) for n in range(1,101)]
        original=SourceInputs.__init__;called=[]
        def inject(self,conn,raw_ids):
            original(self,conn,raw_ids);called.append(1)
            if len(called)==1:
                with sqlite3.connect(path) as writer:
                    writer.row_factory=sqlite3.Row
                    raw=loads(writer.execute('SELECT raw_record_json FROM raw_network_records WHERE seq=75').fetchone()[0])
                    scout_evidence.ingest(writer,'technocore',raw,lambda r,m:'UNSIGNED',source='other',generation='0')
        monkeypatch.setattr(SourceInputs,'__init__',inject)
        assert len(map_batch(c,ids,revision=LG2_REVISION))==100
        with pytest.raises(ProjectionError,match='ALTERNATE_RAW'):map_batch(c,ids,revision=LG2_REVISION)
    finally:c.close()


@pytest.mark.parametrize('with_spikes',[False,True])
def test_scheduler_room_cadence_with_bounded_writer_cost(tmp_path,monkeypatch,with_spikes):
    import flop_scout as scout
    import scout_coverage as coverage
    import scout_worker as worker
    from test_scheduler_fairness import simulate,ROOMS
    monkeypatch.setattr(scout,'HOME',tmp_path);monkeypatch.setattr(scout,'LOG_FILE',tmp_path/'activity.jsonl')
    c=scout.observer_connect_write(tmp_path/'observer.sqlite')
    try:
        for room in ROOMS:
            scout.update_room_cursor(c,room,'g1',100);coverage.state(c,room,'g1',100)
        c.execute('UPDATE source_coverage_state SET backfill_required=1');c.commit()
        class PersistenceCost:
            calls=0
            def __radd__(self,value):
                self.calls+=1
                return value+(.75 if with_spikes and self.calls%100==0 else .2)
        _,times,_,maximum,writers=simulate(c,seconds=600,write_cost=PersistenceCost())
        assert all(times[r] for r in ROOMS)
        assert len(writers)==1
        assert all(maximum[r]<=worker.configuration(ROOMS)[r]['poll_interval_seconds']+3 for r in ROOMS)
        (tmp_path/'lg2-cadence.json').write_bytes(canonical(dict(modeled_writer_seconds=.2,modeled_spike_seconds=.75 if with_spikes else None,spike_every_steps=100 if with_spikes else None,maximum_poll_gap_seconds=maximum))+b'\n')
    finally:c.close()
