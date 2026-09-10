"""All V2 tests use synthetic bytes and temporary SQLite state."""
from pathlib import Path
import json
import sqlite3
import threading
import pytest
from scout_projection_contract import *
from scout_projection import Projector, initialize, read_status
from scout_projection_model import *
from scout_projection_pins import import_pins
from scout_projection_publish import publish, validate_database, retain, file_hash

NOW='2026-09-08T12:00:00.000000Z'
DID='did:key:z6MkSyntheticSource'
TEXT='I diagnosed the Technocore API HTTP 400 failure when the signed post used the wrong endpoint. After switching to /r/technocore?format=json, I reproduced the regression with a fixture and verified the request returned HTTP 200.'


def bundle(n=1,text=TEXT,sender=DID,first=NOW,room='technocore',generation='0',signed=1):
    rid='sm1:raw-'+str(n)
    message=dict(projection_row_id=rid,room=room,generation=generation,seq=n,timestamp=None,sender=sender,signed=signed,text=text,normalized_text=text.casefold(),template_normalized_hash=text_hash(text.casefold()),nonce='000123',sig=None,message_hash=text_hash(text),verification_status='LEGACY_SERVER_VERIFIED_NO_SIGNATURE',source_export_hash=None,source_export_path=None,evidence_id='evidence-'+str(n))
    provenance=dict(entity_type='message',projection_row_id=rid,source_namespace='service-poll',source_record_locator='raw-'+str(n),scout_event_id=str(n),raw_record_id='raw-'+str(n),raw_record_sha256=None,annotations_json=canonical(ANNOTATIONS).decode())
    return dict(message=message,provenance=provenance,first_observed_at=first,facts=dict(signature_failure=False,did_mismatch=False,identity_binding=False,official=False,operator_local=False,workflow=None),dependencies=[])


def create(tmp_path,local=()):
    path=tmp_path/'projection.sqlite'
    initialize(path,epoch='source-epoch',router_source_id='router',router_epoch='router-epoch',router_did='did:key:z6MkRouter',local_dids=local)
    return Projector(path)


def apply(p,rows,when=NOW,kind='BOOTSTRAP',cut=None):
    n=p.begin(cut or str(max((r['message']['seq'] for r in rows),default=0)),when,kind)
    for i in range(0,len(rows),200):p.stage(n,rows[i:i+200])
    return p.seal(n)


def empty_pins(p):
    doc=dict(schema='flop-router-projection-pins/v1',source_id='router',epoch='router-epoch',revision='0',produced_at=NOW,previous_sha256=None,pins=[])
    doc['content_sha256']=digest(doc);return import_pins(p,canonical(doc),now=NOW)


def quals(p):return [loads(r[0]) for r in p.conn.execute('SELECT record_json FROM projection.durable_qualifications ORDER BY qualification_id')]


def test_a1_duplicate_downgrade_permanent_restart(tmp_path):
    with create(tmp_path,local=[DID]) as p:
        apply(p,[bundle()]);before=quals(p)
        assert any(q['claim']['id']=='software.debugging' for q in before)
        assert all(q['same_operator'] and not q['independent_reputation'] for q in before)
        apply(p,[bundle(2)],plus(NOW,1),'SOURCE_BATCH')
        assert quals(p)==before
        ann=loads(p.conn.execute("SELECT annotations_json FROM projection.source_provenance WHERE projection_row_id='sm1:raw-1'").fetchone()[0])
        assert next(x for x in ann['capability_support'] if x['capability_id']=='software.debugging')['classification']=='SIGNAL'
        assert p.conn.execute("SELECT retain_until FROM projection.selection_membership WHERE projection_row_id='sm1:raw-1'").fetchone()[0] is None
        empty_pins(p)
        out=publish(p,tmp_path/'public',checked_cut=p.status()['source_cut'],evaluated_at=plus(NOW,2))
        assert out['manifest']['contract_revision']==REVISION
    with Projector(tmp_path/'projection.sqlite') as p:
        assert quals(p)==before
        heartbeat=publish(p,tmp_path/'public',checked_cut=p.status()['source_cut'],evaluated_at=plus(NOW,3))
        assert heartbeat['manifest']['publication_kind']=='HEARTBEAT'
        assert heartbeat['manifest']['database']==out['manifest']['database']


def test_bootstrap_does_not_manufacture_prefix_qualification(tmp_path):
    with create(tmp_path) as p:
        apply(p,[bundle(1),bundle(2)])
        assert not quals(p)


@pytest.mark.parametrize('raw',[b'{"a":1,"a":2}',b'{"a":NaN}',b'{"a":Infinity}',b'\xef\xbb\xbf{}'])
def test_strict_json(raw):
    with pytest.raises(ProjectionError):loads(raw)


@pytest.mark.parametrize('text,expected',[
 ('tclk1 {"type":"offer","text":"work request"}','TCLK_TRANSCRIPT_EVENT'),
 ('{"v":1,"type":"JOB","text":"work request"}','KIBBLE_JOB'),
 ('{"version":"1","type":"RESULT"}','KIBBLE_RESULT'),
 ('{"schema_version":"flop-verification-result/v1","type":"WORK_RESULT"}','VERIFICATION_RESULT'),
 ('hello, I can debug','IDENTITY_PRESENCE'),
 ('tclk1 {broken','TCLK_TRANSCRIPT_EVENT'),
 ('{"unknown":','MALFORMED_UNVERIFIABLE_EVENT'),
])
def test_classifier_precedence(text,expected):assert classify(text)[0]==expected


def test_stable_interaction_and_distinct_endpoints(tmp_path):
    with create(tmp_path) as p:
        apply(p,[bundle(1,text='hello one'),bundle(2,text='hello two'),bundle(3,text='hello three')])
        a=p.add_interaction('sm1:raw-1','sm1:raw-2','subsequent_signed_post_within_5_signed_messages',0.5)
        assert a==p.add_interaction('sm1:raw-1','sm1:raw-2','subsequent_signed_post_within_5_signed_messages',0.5)
        assert a!=p.add_interaction('sm1:raw-1','sm1:raw-3','subsequent_signed_post_within_5_signed_messages',0.5)


def test_expiry_and_coverage_history(tmp_path):
    with create(tmp_path) as p:
        apply(p,[bundle(text='ordinary context',generation='UNKNOWN_LEGACY')])
        apply(p,[],plus(NOW,2592000),'EXPIRY',cut='1')
        assert p.conn.execute('SELECT count(*) FROM projection.messages').fetchone()[0]==0
        assert p.conn.execute('SELECT max_ever_projected_seq FROM projection.coverage_history').fetchone()[0]==1


def test_cancel_pending_cut_restart(tmp_path):
    with create(tmp_path) as p:
        n=p.begin('1',NOW,'BOOTSTRAP');p.stage(n,[bundle()]);p.stop.set()
        with pytest.raises(InterruptedError):p.seal(n)
    with Projector(tmp_path/'projection.sqlite') as p:
        assert p.status()['pending_evaluations']==1
        p.seal(n)
        assert quals(p)


def test_missing_ledger_fails_closed(tmp_path):
    with create(tmp_path) as p:apply(p,[bundle()])
    (tmp_path/'projection.sqlite.ledger').unlink()
    with pytest.raises(ProjectionError):Projector(tmp_path/'projection.sqlite')


def test_pointer_failure_and_shared_retention(tmp_path):
    with create(tmp_path) as p:
        apply(p,[bundle()]);empty_pins(p);root=tmp_path/'public'
        first=publish(p,root,checked_cut=p.status()['source_cut'],evaluated_at=NOW)
        original=(root/'current.json').read_bytes()
        def fail(stage):
            if stage=='manifest':raise RuntimeError('injected')
        with pytest.raises(RuntimeError):publish(p,root,checked_cut=p.status()['source_cut'],evaluated_at=plus(NOW,1),fail=fail)
        assert (root/'current.json').read_bytes()==original
        last=publish(p,root,checked_cut=p.status()['source_cut'],evaluated_at=plus(NOW,2))
        assert int(last['manifest']['snapshot_id'])>int(first['manifest']['snapshot_id'])+1
        retain(root,keep=1)
        assert (root/first['manifest']['database']).exists()
        unrelated=root/'operator.txt';unrelated.write_text('keep');retain(root,keep=1);assert unrelated.exists()


def test_qualification_corruption(tmp_path):
    with create(tmp_path) as p:
        apply(p,[bundle()])
        with p.conn:p.conn.execute("UPDATE projection.durable_qualifications SET record_json='{}'")
    with pytest.raises(ProjectionError):Projector(tmp_path/'projection.sqlite')


def test_readonly_status(tmp_path):
    with create(tmp_path) as p:apply(p,[bundle()])
    before={f.name:file_hash(f) for f in tmp_path.iterdir() if f.is_file()}
    assert read_status(tmp_path/'projection.sqlite')['pending_evaluations']==0
    assert before=={f.name:file_hash(f) for f in tmp_path.iterdir() if f.is_file()}


@pytest.mark.parametrize('size,state',[(0,'QUALIFIED'),(512*1024**2,'QUALIFIED'),(1024**3,'WARNING_LARGE'),(4*1024**3+1,'OVERSIZE')])
def test_readiness(size,state):assert readiness(size)==state


def invalidation(p,qid,when=plus(NOW,1)):
    proof=p.source_ref('sm1:raw-1')
    directive=dict(schema='flop-scout-qualification-directive/v1',verifier_version='fixture-signature-audit/v1',qualification_id=qid,event_type='INVALIDATED',reason_code='SIGNATURE_PROVENANCE_FAILURE',proof_refs=[proof],superseded_by=None)
    authority=p.import_artifact('audit-1',canonical(directive),source_id='scout-audit',epoch='audit-epoch',authority='AUDIT_DIRECTIVE',observed_at=when)
    event=dict(schema='router-qualification-event/v1',qualification_id=qid,sequence=1,previous_event_sha256=None,event_type='INVALIDATED',recorded_at=when,reason_code='SIGNATURE_PROVENANCE_FAILURE',proof_refs=[proof],authority_ref=authority,superseded_by=None,qualification_policy_version=POLICY['qualification_policy_version'])
    event['event_id']=identity('dqe1',event);return event


def test_a1_invalidation_retains_original_and_proof(tmp_path):
    with create(tmp_path) as p:
        apply(p,[bundle()]);before=quals(p);event=invalidation(p,before[0]['qualification_id'])
        p.append_event(event);assert p.append_event(event)==event['event_id']
        assert quals(p)==before and effective_status([event])=='INVALIDATED'
        apply(p,[],plus(NOW,100*86400),'EXPIRY',cut='1')
        assert p.conn.execute('SELECT count(*) FROM projection.messages').fetchone()[0]==1
        assert p.conn.execute('SELECT count(*) FROM projection.qualification_events').fetchone()[0]==1
        empty_pins(p);publish(p,tmp_path/'public',checked_cut=p.status()['source_cut'],evaluated_at=plus(NOW,100*86400))


def test_a1_room_allegation_cannot_invalidate(tmp_path):
    with create(tmp_path) as p:
        apply(p,[bundle()]);event=invalidation(p,quals(p)[0]['qualification_id'])
        event['authority_ref']=p.source_ref('sm1:raw-1');event['event_id']=identity('dqe1',{k:v for k,v in event.items() if k!='event_id'})
        with pytest.raises(ProjectionError):p.append_event(event)
        assert p.conn.execute('SELECT count(*) FROM projection.qualification_events').fetchone()[0]==0


def test_a1_audit_fork_and_current_downgrade_rejected(tmp_path):
    with create(tmp_path) as p:
        apply(p,[bundle()]);event=invalidation(p,quals(p)[0]['qualification_id']);p.append_event(event)
        event['recorded_at']=plus(NOW,2);event['event_id']=identity('dqe1',{k:v for k,v in event.items() if k!='event_id'})
        with pytest.raises(ProjectionError):p.append_event(event)
        event['sequence']=2;event['event_type']='DOWNGRADE';event['event_id']=identity('dqe1',{k:v for k,v in event.items() if k!='event_id'})
        with pytest.raises(ProjectionError):p.append_event(event)


def test_a1_local_bench_same_operator(tmp_path):
    bench='did:key:z6MkBench'
    with create(tmp_path,local=[DID,bench]) as p:
        apply(p,[])
        request=dict(schema_version='flop-verification-request/v1',request_id='request-1',target_agent_did=DID,requester_did=DID,routing_decision_id='decision-1',routing_decision_hash='1'*64,task_hash='2'*64,independent_reputation=False)
        result=dict(schema_version='flop-verification-result/v1',request_id='request-1',bench_did=bench,status='PASS',artifact_hashes=dict(request_sha256=digest(request)),reproducibility='DETERMINISTIC',independent_reputation=False)
        refs=[p.import_artifact(name,canonical(obj),source_id='scout-verification',epoch='verification-epoch',authority='CONTROLLED_BENCH',observed_at=NOW) for name,obj in [('request-1',request),('result-1',result)]]
        qid=p.qualify_local_bench(*refs,evaluated_at=plus(NOW,1));record=quals(p)[0]
        assert record['qualification_id']==qid and record['source_ref']['kind']=='LOCAL_ARTIFACT'
        assert record['same_operator'] and record['independent_reputation'] is False and record['correctness']=='PASS'
        assert p.conn.execute('SELECT count(*) FROM projection.messages').fetchone()[0]==0
        empty_pins(p);publish(p,tmp_path/'public',checked_cut=p.status()['source_cut'],evaluated_at=plus(NOW,2))
        result['status']='FAIL'
        failed=p.import_artifact('failed',canonical(result),source_id='scout-verification',epoch='verification-epoch',authority='CONTROLLED_BENCH',observed_at=plus(NOW,3))
        p.qualify_local_bench(refs[0],failed,evaluated_at=plus(NOW,4))
        workflow=tuple(p.conn.execute('SELECT * FROM workflows').fetchone())
        assert workflow[2]=='CONFLICT' and workflow[3] is None
        p.replay_to(tmp_path/'rebuilt'/'projection.sqlite')
        with Projector(tmp_path/'rebuilt'/'projection.sqlite') as rebuilt:
            assert tuple(rebuilt.conn.execute('SELECT * FROM workflows').fetchone())==workflow
        result['artifact_hashes']['request_sha256']='f'*64
        wrong=p.import_artifact('wrong',canonical(result),source_id='scout-verification',epoch='verification-epoch',authority='CONTROLLED_BENCH',observed_at=NOW)
        with pytest.raises(ProjectionError):p.qualify_local_bench(refs[0],wrong,evaluated_at=plus(NOW,3))


def test_a1_replay_determinism_across_chunk_order(tmp_path):
    directories=[tmp_path/'one',tmp_path/'two'];outputs=[]
    for index,directory in enumerate(directories):
        with create(directory) as p:
            rows=[bundle(1),bundle(2,text='ordinary context',sender='invalid-source')]
            apply(p,list(reversed(rows)) if index else rows)
            apply(p,[bundle(3)],plus(NOW,1),'SOURCE_BATCH')
            outputs.append((quals(p),[tuple(r) for r in p.conn.execute('SELECT * FROM projection.messages ORDER BY projection_row_id')]))
    assert outputs[0]==outputs[1]


def test_a1_rule_version_changes_cannot_rewrite_history(tmp_path):
    with create(tmp_path) as p:
        apply(p,[bundle()]);record=quals(p)[0];original=canonical(record)
        for field in ('policy_version','classifier_version'):
            changed=dict(record);changed[field]='unreviewed/999';changed['qualification_id']=identity('dq1',{k:v for k,v in changed.items() if k!='qualification_id'})
            with pytest.raises(ProjectionError):validate_qualification(changed)
        assert canonical(quals(p)[0])==original


def test_a1_corrupt_input_manifest_rejected(tmp_path):
    with create(tmp_path) as p:
        apply(p,[bundle()])
        with p.conn:p.conn.execute('DELETE FROM evaluation_inputs')
    with pytest.raises(ProjectionError):Projector(tmp_path/'projection.sqlite')


def pin_doc(p,refs,revision=0,previous=None):
    pin=dict(schema='flop-router-projection-pin/v1',created_at=NOW,producer='FLOP_ROUTER',router_did=p.config['router_did'],reason='RETAIN_EVIDENCE',root=dict(kind='ROUTING_DECISION',id='decision-1'),decision_id='decision-1',task_hash=None,retention_mode='PERMANENT',operator_group=FAMILY,evidence_refs=sorted(refs,key=canonical),dependency_refs=[])
    pin['pin_id']=identity('rp1',{k:pin[k] for k in ('schema','producer','router_did','root','evidence_refs','dependency_refs')});pin['content_sha256']=digest(pin)
    doc=dict(schema='flop-router-projection-pins/v1',source_id='router',epoch='router-epoch',revision=str(revision),produced_at=NOW,previous_sha256=previous,pins=[pin]);doc['content_sha256']=digest(doc);return doc


def test_pin_cycles_dependency_expiry_and_monotonicity(tmp_path):
    with create(tmp_path) as p:
        a=bundle(1,text='ordinary context');b=bundle(2,text='other context');a['dependencies']=['sm1:raw-2'];b['dependencies']=['sm1:raw-1'];apply(p,[a,b])
        ref=p.source_ref('sm1:raw-1');ref['kind']='MESSAGE';doc=pin_doc(p,[ref]);import_pins(p,canonical(doc),now=NOW)
        assert p.closure(['sm1:raw-1'])==['sm1:raw-1','sm1:raw-2']
        apply(p,[],plus(NOW,31*86400),'EXPIRY',cut='2')
        assert p.conn.execute('SELECT count(*) FROM projection.messages').fetchone()[0]==2
        removal=dict(doc,revision='1',previous_sha256=doc['content_sha256'],pins=[]);removal['content_sha256']=digest({k:v for k,v in removal.items() if k!='content_sha256'})
        with pytest.raises(ProjectionError):import_pins(p,canonical(removal),now=NOW)
        assert p.conn.execute('SELECT count(*) FROM pins').fetchone()[0]==1


def test_interrupted_pin_import_resumes_exact_export(tmp_path,monkeypatch):
    with create(tmp_path) as p:
        apply(p,[bundle(text='ordinary conversation')])
        ref=p.source_ref('sm1:raw-1');ref['kind']='MESSAGE';doc=pin_doc(p,[ref])
        original=p.apply_pin_member
        def interrupted(*args):raise InterruptedError('injected pin batch interruption')
        monkeypatch.setattr(p,'apply_pin_member',interrupted)
        with pytest.raises(InterruptedError):import_pins(p,canonical(doc),now=NOW)
        assert p.get('pending_pin_sha256')==doc['content_sha256']
        with pytest.raises(ProjectionError):p.begin('1',NOW,'EXPIRY')
        monkeypatch.setattr(p,'apply_pin_member',original)
        import_pins(p,canonical(doc),now=NOW)
        assert not p.get('pending_pin_sha256') and not p.get('pin_error')
        p.replay_to(tmp_path/'reconstructed'/'projection.sqlite')


def test_pending_missing_pin_blocks_publication(tmp_path):
    with create(tmp_path) as p:
        apply(p,[bundle(text='ordinary context')]);empty_pins(p)
        previous=p.conn.execute('SELECT hash FROM pin_exports').fetchone()[0]
        ref=dict(kind='MESSAGE',source_id='scout-observer',source_epoch='source-epoch',id='sm1:missing',sha256=None)
        doc=pin_doc(p,[ref],revision=1,previous=previous)
        with pytest.raises(ProjectionError):import_pins(p,canonical(doc),now=NOW)
        with pytest.raises(ProjectionError):publish(p,tmp_path/'public',checked_cut=p.status()['source_cut'],evaluated_at=NOW)


def test_workflow_unresolved_and_authoritative_closure(tmp_path):
    with create(tmp_path) as p:
        wid,ident=workflow_identity('kibble/v1',DID,'technocore','0','job_id','job-1')
        rows=[bundle(n,text=canonical(dict(type=t,v=1,job_id='job-1')).decode()) for n,t in [(1,'JOB'),(2,'RESULT'),(3,'ACCEPT')]]
        for b,role in zip(rows,['ROOT','RESULT','TERMINAL']):b['facts']['workflow']=dict(id=wid,identity=ident,role=role,root_id='sm1:raw-1',result_id='sm1:raw-2' if role=='TERMINAL' else None,authenticated=True,deadline_ms=None,terminal='ACCEPT' if role=='TERMINAL' else None)
        apply(p,rows[:2]);assert p.conn.execute('SELECT closed_at FROM workflows').fetchone()[0] is None
        rows[2]['first_observed_at']=plus(NOW,10);apply(p,rows[2:],plus(NOW,10),'SOURCE_BATCH')
        state=p.conn.execute('SELECT * FROM workflows').fetchone();assert state['state']=='CLOSED' and state['closed_at']==plus(NOW,10)
        assert p.conn.execute('SELECT min(retain_until) FROM projection.selection_membership').fetchone()[0]==plus(NOW,7776010)


def test_bound_kibble_claim_remains_open(tmp_path):
    with create(tmp_path) as p:
        wid,ident=workflow_identity('kibble/v1',DID,'technocore','0','job_id','claimed-job')
        rows=[bundle(n,text=canonical(dict(type=t,v=1,job_id='claimed-job')).decode()) for n,t in [(1,'JOB'),(2,'CLAIM')]]
        for b,role in zip(rows,['ROOT','CLAIM']):b['facts']['workflow']=dict(id=wid,identity=ident,role=role,root_id='sm1:raw-1',result_id=None,authenticated=True,deadline_ms=None,terminal=None)
        apply(p,rows)
        state=p.conn.execute('SELECT * FROM workflows').fetchone()
        assert state['state']=='CLAIMED' and state['closed_at'] is None
        assert p.conn.execute('SELECT count(*) FROM projection.selection_membership WHERE retain_until IS NOT NULL').fetchone()[0]==0


def test_symlink_artifact_rejected(tmp_path):
    with create(tmp_path) as p:
        apply(p,[bundle()]);empty_pins(p);root=tmp_path/'public';first=publish(p,root,checked_cut=p.status()['source_cut'],evaluated_at=NOW)
        artifact=root/first['manifest']['database'];other=tmp_path/'other';artifact.rename(other);artifact.symlink_to(other)
        with pytest.raises(ProjectionError):publish(p,root,checked_cut=p.status()['source_cut'],evaluated_at=plus(NOW,1))


def test_source_mapping_and_whole_outbox_cut(tmp_path):
    import flop_scout
    from scout_projection_source import Outbox,bootstrap,consume,map_raw
    source=tmp_path/'source.sqlite';conn=sqlite3.connect(str(source));conn.row_factory=sqlite3.Row;flop_scout.init_observer_db(conn)
    with create(tmp_path/'projection') as p:
        apply(p,[],utc())
        outbox=Outbox(conn,epoch=p.config['epoch'],install=True)
        for n in (1,2):
            flop_scout.ingest_messages(conn,'technocore',[dict(seq=n,did=DID,text=TEXT)],generation='0',source='service-poll')
            outbox.capture(complete=n==2)
            if n==1:
                result=consume(p,source);assert not result['source_caught_up'] and not quals(p)
        result=consume(p,source);assert result['source_caught_up']
        assert p.conn.execute('SELECT count(*) FROM projection.messages').fetchone()[0]==2
        assert not quals(p)
        assert consume(p,source)['source_caught_up']
    conn.close()


def test_source_incomplete_raw_cannot_bootstrap(tmp_path):
    import flop_scout
    import scout_evidence
    from scout_projection_source import bootstrap
    source=tmp_path/'source.sqlite';conn=sqlite3.connect(str(source));conn.row_factory=sqlite3.Row;flop_scout.init_observer_db(conn)
    with conn:scout_evidence.ingest(conn,'technocore',dict(seq=1,did=DID,text='hello'),flop_scout.verify_signed_record_offline,source='fixture',derive_events=False)
    with create(tmp_path/'projection') as p:
        with pytest.raises(ProjectionError):bootstrap(p,source,'0',utc())
    conn.close()


def test_full_ledger_reconstruction_with_pins_and_audit(tmp_path):
    with create(tmp_path/'source') as p:
        apply(p,[bundle()]);ref=p.source_ref('sm1:raw-1');ref['kind']='MESSAGE'
        doc=pin_doc(p,[ref]);import_pins(p,canonical(doc),now=NOW)
        before=quals(p);apply(p,[bundle(2)],plus(NOW,1),'SOURCE_BATCH');p.append_event(invalidation(p,before[0]['qualification_id'],plus(NOW,2)))
        result=p.replay_to(tmp_path/'rebuilt'/'projection.sqlite');assert result['history_verified']
    with Projector(tmp_path/'rebuilt'/'projection.sqlite') as rebuilt:assert quals(rebuilt)==before


def test_a1_objective_contradiction_preserves_positive_history(tmp_path):
    bench='did:key:z6MkBench'
    with create(tmp_path,local=[DID,bench]) as p:
        apply(p,[bundle()]);before=quals(p)
        request=dict(schema_version='flop-verification-request/v1',request_id='objective-1',target_agent_did=DID,requester_did=DID,routing_decision_id='decision-1',routing_decision_hash='1'*64,task_hash='2'*64,capability_id='software.debugging',independent_reputation=False)
        result=dict(schema_version='flop-verification-result/v1',request_id='objective-1',bench_did=bench,status='FAIL',artifact_hashes=dict(request_sha256=digest(request)),reproducibility='DETERMINISTIC',checks=dict(reproduced_expected_fix=False),independent_reputation=False)
        refs=[p.import_artifact(name,canonical(obj),source_id='scout-verification',epoch='verification-epoch',authority='OBJECTIVE_VALIDATION',observed_at=NOW) for name,obj in [('request-1',request),('result-1',result)]]
        p.qualify_objective_contradiction(*refs,evaluated_at=plus(NOW,1))
        after=quals(p);assert all(record in after for record in before)
        assert any(q['qualification_type']=='CAPABILITY_CONTRADICTION' and q['qualification_outcome']=='CONTRADICTED' for q in after)
        assert not p.conn.execute('SELECT 1 FROM projection.qualification_events').fetchone()
        assert p.replay_to(tmp_path/'replayed'/'projection.sqlite')['history_verified']


def test_global_template_senders_before_did_filter(tmp_path):
    with create(tmp_path) as p:
        first=bundle();apply(p,[first]);before=quals(p)
        other=bundle(2,sender='not-a-valid-DID',room='other-room');apply(p,[other],plus(NOW,1),'SOURCE_BATCH')
        ann=loads(p.conn.execute("SELECT annotations_json FROM projection.source_provenance WHERE projection_row_id='sm1:raw-1'").fetchone()[0])
        assert next(v for v in ann['capability_support'] if v['capability_id']=='software.debugging')['classification']=='SIGNAL'
        assert quals(p)==before


def test_tclk_deadline_and_active_obligation(tmp_path):
    for active in (False,True):
        with create(tmp_path/str(active)) as p:
            wid,ident=workflow_identity('tclk/1',DID,'technocore','0','offer_id','offer-1')
            deadline=int(instant(plus(NOW,10)).timestamp())*1000
            row=bundle(text='tclk1 {"type":"offer"}')
            row['facts']['workflow']=dict(id=wid,identity=ident,role='ROOT',root_id='sm1:raw-1',result_id=None,authenticated=True,deadline_ms=deadline,terminal=None)
            rows=[row]
            if active:
                second=bundle(2,text='tclk1 {"type":"lock"}')
                second['facts']['workflow']=dict(row['facts']['workflow'],role='LOCK',deadline_ms=None);rows.append(second)
            apply(p,rows)
            apply(p,[],plus(NOW,11),'EXPIRY',cut=str(len(rows)))
            state=p.conn.execute('SELECT * FROM workflows').fetchone()
            assert state['state']==('OPEN' if active else 'EXPIRED')
            assert state['closed_at']==(None if active else plus(NOW,10))
            if not active:assert state['closure_reason']=='TCLK_OFFER_DEADLINE'


def test_noncanonical_sequence_and_missing_provenance_rejected(tmp_path):
    with create(tmp_path) as p:
        row=bundle();row['message']['seq']=1.0;n=p.begin('1',NOW,'BOOTSTRAP')
        with pytest.raises(ProjectionError):p.stage(n,[row])
        row=bundle();row['provenance']['raw_record_id']=None
        with pytest.raises(ProjectionError):p.stage(n,[row])


def test_twenty_digit_publication_ids(tmp_path):
    with create(tmp_path) as p:
        apply(p,[bundle()]);empty_pins(p)
        with p.conn:p.set('publication_id','9999999999999999999');p.set('content_id','9999999999999999999')
        result=publish(p,tmp_path/'public',checked_cut=p.status()['source_cut'],evaluated_at=NOW)
        assert result['manifest']['snapshot_id']=='10000000000000000000'


def test_single_writer_lock(tmp_path):
    with create(tmp_path) as p:
        with pytest.raises(ProjectionError):Projector(p.path)


def test_projection_never_uses_network_or_identity(tmp_path,monkeypatch):
    import socket
    def forbidden(*args,**kwargs):raise AssertionError('Network was used')
    monkeypatch.setattr(socket,'socket',forbidden)
    with create(tmp_path) as p:
        apply(p,[bundle()]);empty_pins(p);publish(p,tmp_path/'public',checked_cut=p.status()['source_cut'],evaluated_at=NOW)
        assert not any('identity' in path.name or path.suffix=='.pem' for path in tmp_path.rglob('*'))


def test_pointer_rollback_cannot_refresh_old_content(tmp_path):
    with create(tmp_path) as p:
        apply(p,[bundle()]);empty_pins(p);root=tmp_path/'public'
        publish(p,root,checked_cut=p.status()['source_cut'],evaluated_at=NOW);old=(root/'current.json').read_bytes()
        apply(p,[bundle(2,text='new context')],plus(NOW,1),'SOURCE_BATCH')
        publish(p,root,checked_cut=p.status()['source_cut'],evaluated_at=plus(NOW,2))
        (root/'current.json').write_bytes(old)
        with pytest.raises(ProjectionError):publish(p,root,checked_cut=p.status()['source_cut'],evaluated_at=plus(NOW,3))


def test_pinned_interaction_and_endpoints_survive_expiry(tmp_path):
    with create(tmp_path) as p:
        apply(p,[bundle(1,text='one'),bundle(2,text='two')]);edge=p.add_interaction('sm1:raw-1','sm1:raw-2','reply_to',1.0)
        ref=dict(kind='INTERACTION',source_id=p.config['source_id'],source_epoch=p.config['epoch'],id=edge,sha256=edge[4:])
        import_pins(p,canonical(pin_doc(p,[ref])),now=NOW)
        apply(p,[],plus(NOW,31*86400),'EXPIRY',cut='2')
        assert p.conn.execute('SELECT count(*) FROM projection.interactions').fetchone()[0]==1
        assert p.conn.execute('SELECT count(*) FROM projection.messages').fetchone()[0]==2
        assert p.conn.execute("SELECT retain_until FROM projection.selection_membership WHERE entity_type='interaction'").fetchone()[0] is None


def test_unsigned_chatter_is_outside_selected_scope(tmp_path):
    import flop_scout
    from scout_projection_source import Outbox,consume
    source=tmp_path/'source.sqlite';conn=sqlite3.connect(str(source));conn.row_factory=sqlite3.Row;flop_scout.init_observer_db(conn)
    with create(tmp_path/'projection') as p:
        apply(p,[],utc());outbox=Outbox(conn,epoch=p.config['epoch'],install=True)
        flop_scout.ingest_messages(conn,'lobby',[dict(seq=1,text='ordinary unsigned chatter')],generation='g1',source='service-poll')
        outbox.capture(complete=True);assert consume(p,source)['source_caught_up']
        assert p.conn.execute('SELECT count(*) FROM projection.messages').fetchone()[0]==0
    conn.close()


def test_projection_status_cli_does_not_initialize_default_state(tmp_path):
    import os,subprocess,sys
    with create(tmp_path/'explicit') as p:apply(p,[])
    unused=tmp_path/'must-not-be-created'
    env=dict(os.environ,FLOP_SCOUT_STATE_DIR=str(unused))
    completed=subprocess.run([sys.executable,str(Path(__file__).with_name('flop_scout.py')),'projection','--db',str(tmp_path/'explicit'/'projection.sqlite'),'status'],env=env,capture_output=True,text=True)
    assert completed.returncode==0,completed.stderr
    assert not unused.exists()


def test_already_expired_tclk_uses_deadline_not_ingestion_clock(tmp_path):
    with create(tmp_path) as p:
        wid,ident=workflow_identity('tclk/1',DID,'technocore','0','offer_id','old-offer')
        row=bundle(text='tclk1 {"type":"offer","from":"'+DID+'"}')
        row['facts']['workflow']=dict(id=wid,identity=ident,role='ROOT',root_id='sm1:raw-1',result_id=None,authenticated=True,deadline_ms=1000,terminal=None)
        apply(p,[row]);assert p.conn.execute('SELECT count(*) FROM projection.messages').fetchone()[0]==0
        assert p.conn.execute('SELECT closed_at FROM workflows').fetchone()[0]=='1970-01-01T00:00:01.000000Z'


def test_opt_in_worker_keeps_single_source_writer_and_complete_cuts(tmp_path,monkeypatch):
    import flop_scout as scout
    import scout_worker as worker
    import scout_runtime as runtime
    import scout_coverage as coverage
    import scout_evidence as evidence
    from scout_projection_source import Outbox,consume
    monkeypatch.setattr(scout,'HOME',tmp_path);monkeypatch.setattr(scout,'LOG_FILE',tmp_path/'activity.jsonl')
    source=tmp_path/'observer.sqlite';conn=scout.observer_connect_write(source)
    scout.update_room_cursor(conn,'technocore','g1',0);coverage.state(conn,'technocore','g1',0);conn.commit()
    with create(tmp_path/'projection') as p:
        apply(p,[],utc());empty_pins(p)
        pins=tmp_path/'pins.json';pins.write_text(p.conn.execute('SELECT body FROM pin_exports').fetchone()[0])
        Outbox(conn,epoch=p.config['epoch'],install=True)
        config=dict(path=str(p.path),root=str(tmp_path/'public'),pins=str(pins),cadence=900)
    conn.close();settings=worker.configuration(['technocore']);settings['technocore']['export_backfill_enabled']=False
    owners=set();original=scout.ingest_messages
    def ingest(*args,**kwargs):owners.add(threading.get_ident());return original(*args,**kwargs)
    monkeypatch.setattr(scout,'ingest_messages',ingest)
    def read(room,kind,*args):
        assert kind=='tail'
        return ({'messages':[dict(seq=n,did=DID,text=TEXT) for n in range(1,6)],'latest_seq':5},'g1')
    runtime.Runtime(source,settings,reader=read,projection=config).run(once=True)
    assert len(owners)==1 and threading.get_ident() not in owners
    with Projector(tmp_path/'projection'/'projection.sqlite') as p:
        assert consume(p,source)['source_caught_up']
        assert p.conn.execute('SELECT count(*) FROM projection.messages').fetchone()[0]==5
        assert not quals(p)
    with scout.observer_connect_readonly(source) as conn:
        assert evidence.integrity(conn)['status']=='PASS'
        assert all(evidence.metrics(conn)[key]==0 for key in evidence.SAFETY_KEYS)


def test_prior_publication_detects_lost_audit_even_if_both_working_copies_lost(tmp_path):
    with create(tmp_path) as p:
        apply(p,[bundle()]);empty_pins(p);root=tmp_path/'public';publish(p,root,checked_cut=p.status()['source_cut'],evaluated_at=NOW)
        original=(root/'current.json').read_bytes();qid=quals(p)[0]['qualification_id']
        with p.conn:
            p.conn.execute('DELETE FROM qualification_keys WHERE qualification_id=?',(qid,));p.conn.execute('DELETE FROM projection.durable_qualifications WHERE qualification_id=?',(qid,));p.set('dirty','1')
        with pytest.raises(ProjectionError):publish(p,root,checked_cut=p.status()['source_cut'],evaluated_at=plus(NOW,1))
        assert (root/'current.json').read_bytes()==original
