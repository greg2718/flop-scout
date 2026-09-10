"""LG1 class, wire, replay and authority boundaries on synthetic temporary data."""
import copy
import sqlite3
from pathlib import Path
import pytest
import scout_evidence
from scout_projection_contract import *
from scout_projection_source import map_raw,Outbox,consume,bootstrap,pack,unpack,resolve_interaction
from scout_projection_legacy import from_originals,continuity,LegacyGenerationError
from scout_projection import Projector,initialize,read_status
from scout_projection_publish import publish,validate_database
from scripts.projection_lg1_support import source,add_legacy,NOW,DID,TEXT
from test_scout_projection import create,apply,empty_pins,quals,bundle


@pytest.mark.parametrize('report',['0','1'])
def test_lg1_complete_representation_replay_watermarks(tmp_path,report):
    c=source();rid=add_legacy(c,report=report,protocol_cache=True);before=dict(c.execute('SELECT * FROM raw_network_records').fetchone())
    b=map_raw(c,rid,[DID]);ann=loads(b['provenance']['annotations_json'])['legacy_generation']
    assert ann['captured_generation']=='UNKNOWN_LEGACY' and ann['reported_generation']==report
    assert ann['generation_authority']=='LEGACY_REPORTED_ONLY' and ann['generation_match_status']=='UNRESOLVED_LEGACY'
    assert len(ann['linked_cache_records'])==2 and ann['linked_cache_records']==sorted(ann['linked_cache_records'],key=canonical)
    assert all(r['source_record_locator']!=str(1) for r in ann['linked_cache_records'])
    assert from_originals(b['legacy_generation_originals'])==ann
    with create(tmp_path/'p',local=[DID]) as p:
        apply(p,[b]);original=quals(p)
        assert original and all(q['same_operator'] and not q['independent_reputation'] for q in original)
        for q in original:
            assert q['source_ref']['id']=='sm1:'+rid and q['source_ref']['sha256']==text_hash(TEXT)
            assert 'legacy_generation' not in q and 'resolved_generation' not in q
        assert [r[0] for r in p.conn.execute('SELECT generation FROM projection.watermarks')]==['UNKNOWN_LEGACY']
        assert [r[0] for r in p.conn.execute('SELECT generation FROM projection.coverage_history')]==['UNKNOWN_LEGACY']
        empty_pins(p);first=publish(p,tmp_path/'public',checked_cut=p.status()['source_cut'],evaluated_at=NOW)
        assert first['manifest']['contract_revision']==REVISION and first['manifest']['legacy_generation_policy']==LEGACY_POLICY
        next_pub=publish(p,tmp_path/'public',checked_cut=p.status()['source_cut'],evaluated_at=plus(NOW,1))
        assert next_pub['manifest']['publication_kind']=='HEARTBEAT' and next_pub['manifest']['database']==first['manifest']['database']
        assert p.legacy_status()['non_authoritative_report_counts'][report]==1
        p.replay_to(tmp_path/'replay'/'projection.sqlite')
    with Projector(tmp_path/'replay'/'projection.sqlite') as p:
        assert quals(p)==original
        assert loads(p.bundle('sm1:'+rid)['provenance']['annotations_json'])['legacy_generation']==ann
    assert dict(c.execute('SELECT * FROM raw_network_records').fetchone())==before
    c.close()


@pytest.mark.parametrize('field,value',[
 ('source','legacy_messages'),('legacy_record',0),('legacy_record',True),('raw_completeness','COMPLETE'),
 ('ingestion_schema','flop-scout-evidence/v2'),('ingestion_version','2'),('ingestion_version',True),
 ('reported_generation','2'),('reported_generation',0),('source_endpoint','https://synthetic.invalid/r/x'),
 ('generation','0'),('raw_text_sha256','0'*64),('sender_did','did:key:z6MkDifferent'),('seq',99),
 ('raw_record_id','f'*64),('nonce','999'),('signature','changed'),('network_timestamp',plus(NOW,1)),
 ('transport_metadata_json','{"generation_conflict":true}'),('transport_metadata_json','{"body_generation":"0"}'),
])
def test_lg1_class_and_immutable_raw_boundaries(field,value):
    c=source();rid=add_legacy(c);original=map_raw(c,rid)['legacy_generation_originals'];original['raw'][field]=value
    with pytest.raises(ProjectionError):from_originals(original)
    c.close()


@pytest.mark.parametrize('field,value',[
 ('source','observe'),('generation','1'),('generation','UNKNOWN_LEGACY'),('message_hash','f'*64),
 ('did','did:key:z6MkDifferent'),('did',None),('seq',22),('room','other'),('text','different'),
 ('nonce',1.0),('nonce',None),('sig','changed'),('server_timestamp',None),
])
def test_lg1_cache_bindings_fail(field,value):
    c=source();rid=add_legacy(c);original=map_raw(c,rid)['legacy_generation_originals']
    original['cache_records'][0]['record'][field]=value
    with pytest.raises(ProjectionError):from_originals(original)
    c.close()


@pytest.mark.parametrize('report',['0','1'])
def test_a1_rejects_lg1_class(report):
    c=source();rid=add_legacy(c,report=report)
    with pytest.raises(ProjectionError):map_raw(c,rid,revision='A1')
    c.close()


def test_lg1_competing_reports_and_alternate_candidate(tmp_path):
    c=source();rid=add_legacy(c,protocol_cache=True)
    with c:c.execute("UPDATE kibble_events SET generation='1'")
    with pytest.raises(LegacyGenerationError,match='GENERATION_CONFLICT'):map_raw(c,rid)
    with c:c.execute("UPDATE kibble_events SET generation='0'")
    raw=loads(c.execute('SELECT raw_record_json FROM raw_network_records').fetchone()[0])
    with c:scout_evidence.ingest(c,'technocore',raw,lambda r,m:'UNSIGNED',source='other',generation='0')
    with pytest.raises(LegacyGenerationError,match='ALTERNATE_RAW'):map_raw(c,rid)
    c.close()


@pytest.mark.parametrize('captured,reported',[('0','1'),('1','0')])
def test_concrete_conflict_preserved(captured,reported):
    import flop_scout
    c=source()
    raw=dict(seq=1,did=DID,text=TEXT)
    with c:rid=scout_evidence.ingest(c,'technocore',raw,lambda r,m:'UNSIGNED',generation=captured,reported_generation=reported)
    with pytest.raises(LegacyGenerationError,match='GENERATION_CONFLICT'):map_raw(c,rid)
    c.close()


def test_lg1_negative_evidence_not_promoted(tmp_path):
    c=source();rid=add_legacy(c,negative=True)
    with create(tmp_path) as p:
        b=map_raw(c,rid);assert b['facts']['signature_failure']
        apply(p,[b]);assert all(q['qualification_type']=='NEGATIVE_FACT' for q in quals(p))
        assert p.conn.execute('SELECT retention_class FROM projection.selection_membership').fetchone()[0]=='NEGATIVE_EVIDENCE'
        assert p.conn.execute('SELECT verification_status FROM projection.messages').fetchone()[0]=='INVALID_SIGNATURE'
    c.close()


def test_legacy_audit_original_loss_and_ref_loss(tmp_path):
    c=source();rid=add_legacy(c,protocol_cache=True);b=map_raw(c,rid)
    with create(tmp_path) as p:
        missing=copy.deepcopy(b);del missing['legacy_generation_originals']
        with pytest.raises(ProjectionError):p.validate_bundle(missing)
        apply(p,[b]);smaller=copy.deepcopy(b)
        smaller['legacy_generation_originals']['cache_records']=[r for r in smaller['legacy_generation_originals']['cache_records'] if r['cache_table']=='evidence_records']
        ann=loads(smaller['provenance']['annotations_json']);ann['legacy_generation']=from_originals(smaller['legacy_generation_originals']);smaller['provenance']['annotations_json']=canonical(ann).decode()
        with pytest.raises(ProjectionError,match='AUDIT_REMOVAL'):apply(p,[smaller],plus(NOW,1),'SOURCE_BATCH')
    c.close()


@pytest.mark.parametrize('mutation',['extra','wrong_authority','bad_hash','duplicate_ref','extra_ref_key','report_conflict','no_evidence_ref','too_many_refs'])
def test_lg1_closed_annotation_bounds(mutation):
    c=source();rid=add_legacy(c);a=loads(map_raw(c,rid)['provenance']['annotations_json'])
    g=a['legacy_generation']
    if mutation=='extra':g['resolved_generation']='0'
    elif mutation=='wrong_authority':g['generation_authority']='AUTHORITATIVE'
    elif mutation=='bad_hash':g['raw_text_sha256']='X'*64
    elif mutation=='duplicate_ref':g['linked_cache_records']*=2
    elif mutation=='extra_ref_key':g['linked_cache_records'][0]['rowid']=1
    elif mutation=='report_conflict':g['linked_cache_records'][0]['reported_generation']='1'
    elif mutation=='no_evidence_ref':g['linked_cache_records'][0]['cache_table']='tclk_frames'
    else:g['linked_cache_records']*=257
    with pytest.raises(ProjectionError):annotations(a)
    c.close()


def test_lg1_interaction_captured_identity_and_audit_multiplicity(tmp_path):
    c=source();a=add_legacy(c,1,report='0',protocol_cache=True);b=add_legacy(c,2,report='1',text='ordinary synthetic context')
    with create(tmp_path) as p:
        apply(p,[map_raw(c,a),map_raw(c,b)])
        edge=dict(room='technocore',source_seq=1,response_seq=2,source_did=DID,target_did=DID,relationship_type='explicit_reply',confidence=.5)
        resolved=resolve_interaction(c,edge);eid=p.add_interaction(**resolved)
        assert eid==p.add_interaction(**resolved)
        identity_obj=loads(p.get('interaction:'+eid));assert {e['generation'] for e in identity_obj['endpoints']}=={'UNKNOWN_LEGACY'}
        # Report is absent from the canonical endpoint identity; it cannot rename an edge.
        assert interaction_identity('explicit_reply',*[{k:v for k,v in e.items() if k!='role'} for e in identity_obj['endpoints']])[0]==eid
        p.replay_to(tmp_path/'again'/'projection.sqlite')
        assert p.conn.execute('SELECT count(*) FROM projection.interactions').fetchone()[0]==1
        assert loads(p.conn.execute("SELECT annotations_json FROM projection.source_provenance WHERE entity_type='interaction'").fetchone()[0])['legacy_generation'] is None
    c.close()


def test_lg1_workflow_cannot_bridge_concrete_domain():
    import flop_scout
    c=source()
    job=json.dumps(dict(type='JOB',v=1,job_id='same-job'))
    rid=add_legacy(c,1,text=job,room='kibble',protocol_cache=True,verified=True)
    b=map_raw(c,rid)
    assert b['message']['generation']=='UNKNOWN_LEGACY'
    assert b['facts']['workflow']['authenticated'] and b['facts']['workflow']['identity']['scope']['generation']=='UNKNOWN_LEGACY'
    terminal=dict(seq=2,did=DID,text=json.dumps(dict(type='ACCEPT',v=1,job_id='same-job',result_raw_record_id=rid)))
    # A concrete-generation root cannot be selected by a reported legacy value.
    with c:flop_scout.ingest_messages(c,'kibble',[terminal],generation='0',source='service-poll')
    terminal_id=c.execute("SELECT raw_record_id FROM raw_network_records WHERE generation='0'").fetchone()[0]
    assert map_raw(c,terminal_id)['facts']['workflow'] is None
    c.close()


def test_lg1_explicit_transition_new_content_and_history(tmp_path):
    path=tmp_path/'working'/'projection.sqlite'
    initialize(path,epoch='source-epoch',router_source_id='router',router_epoch='router-epoch',router_did=DID,contract_revision='A1')
    row=bundle();row['provenance']['annotations_json']=canonical(A1_ANNOTATIONS).decode()
    with Projector(path) as p:
        apply(p,[row]);before=quals(p);empty_pins(p)
        old=publish(p,tmp_path/'public',checked_cut=p.status()['source_cut'],evaluated_at=NOW)['manifest']
        transition=p.enable_lg1();assert quals(p)==before
        archive=Path(transition['a1_private_archive'])
        with connect(archive/p.ledger.name,True) as archived:
            assert loads(archived.execute('SELECT json FROM configuration').fetchone()[0])['contract_revision']=='A1'
        with connect(archive/p.path.name,True) as archived:
            assert [loads(r[0]) for r in archived.execute('SELECT record_json FROM durable_qualifications ORDER BY qualification_id')]==before
        new=publish(p,tmp_path/'public',checked_cut=p.status()['source_cut'],evaluated_at=plus(NOW,1))['manifest']
        assert old['contract_revision']=='A1' and new['contract_revision']==REVISION
        assert new['publication_kind']=='CONTENT' and int(new['database_content_id'])>int(old['database_content_id'])
        assert new['database']!=old['database'] and int(new['snapshot_id'])>int(old['snapshot_id'])
        assert (tmp_path/'public'/old['database']).exists()
        p.replay_to(tmp_path/'replay'/'projection.sqlite')
        with pytest.raises(ProjectionError):p.enable_lg1()
    with Projector(tmp_path/'replay'/'projection.sqlite') as p:assert quals(p)==before


@pytest.mark.parametrize('wrong',[{},dict(contract_revision='A1',legacy_generation_policy=LEGACY_POLICY),dict(contract_revision=REVISION),dict(contract_revision=REVISION,legacy_generation_policy=dict(LEGACY_POLICY,watermark_domain='REPORTED'))])
def test_lg1_revision_policy_rejection(wrong):
    with pytest.raises(ProjectionError):revision_binding(wrong)


def test_lg1_outbox_binding_late_candidate_and_diagnostics(tmp_path):
    c=source(tmp_path/'source.sqlite');rid=add_legacy(c)
    with create(tmp_path/'p') as p:
        out=Outbox(c,epoch='source-epoch',install=True)
        bootstrap(p,tmp_path/'source.sqlite','1',NOW)
        raw=loads(c.execute('SELECT raw_record_json FROM raw_network_records').fetchone()[0])
        with c:scout_evidence.ingest(c,'technocore',raw,lambda r,m:'UNSIGNED',generation='0',source='other')
        assert c.execute('SELECT 1 FROM router_projection_pending WHERE raw_record_id=?',(rid,)).fetchone()
        with pytest.raises(ProjectionError):out.capture(complete=True)
        p.legacy_error(LegacyGenerationError('LG1_GENERATION_CONFLICT'))
        assert p.legacy_status()['true_generation_conflicts_rejected']==1
    assert read_status(tmp_path/'p'/'projection.sqlite')['lg1_conflicts']=='1'
    with pytest.raises(ProjectionError):unpack(pack([],REVISION),'A1')
    with pytest.raises(ProjectionError):unpack([],REVISION)
    c.close()


def test_non_lg1_unknown_and_concrete_annotation_null(tmp_path):
    with create(tmp_path) as p:
        apply(p,[bundle(1,text='ordinary context',generation='UNKNOWN_LEGACY'),bundle(2,text='other context',generation='0')])
        assert all(loads(r[0])['legacy_generation'] is None for r in p.conn.execute('SELECT annotations_json FROM projection.source_provenance'))


def test_lg1_ambiguous_roots_not_selected_by_report():
    c=source();job=json.dumps(dict(type='JOB',v=1,job_id='ambiguous'))
    add_legacy(c,1,report='0',text=job,room='kibble',protocol_cache=True,verified=True)
    import flop_scout
    other='did:key:z'+flop_scout.b58encode(flop_scout.ED25519_MULTICODEC+bytes(reversed(range(32))))
    add_legacy(c,2,report='1',text=job,room='kibble',sender=other,protocol_cache=True,verified=True)
    rid=add_legacy(c,3,report='0',text=json.dumps(dict(type='ACCEPT',v=1,job_id='ambiguous')),room='kibble',protocol_cache=True,verified=True)
    with pytest.raises(ProjectionError,match='Ambiguous workflow root issuer'):map_raw(c,rid)
    c.close()


def test_lg1_qualified_dependency_originals_required_on_reopen(tmp_path):
    c=source();rid=add_legacy(c)
    with create(tmp_path) as p:
        apply(p,[map_raw(c,rid)])
        with p.conn:p.conn.execute("UPDATE input_versions SET body='{}'")
        with pytest.raises(ProjectionError):p.verify_ledger()
    c.close()


def test_lg1_valid_cache_addition_preserves_ids_and_qualifications(tmp_path):
    c=source();rid=add_legacy(c)
    with create(tmp_path) as p:
        apply(p,[map_raw(c,rid)]);before=quals(p)
        add_legacy(c,protocol_cache=True,cache_only=True)
        apply(p,[map_raw(c,rid)],plus(NOW,1),'SOURCE_BATCH')
        assert quals(p)==before
        assert len(loads(p.bundle('sm1:'+rid)['provenance']['annotations_json'])['legacy_generation']['linked_cache_records'])==2
        assert p.conn.execute('SELECT count(*) FROM projection.messages').fetchone()[0]==1
        p.replay_to(tmp_path/'again'/'projection.sqlite')
    c.close()


def test_lg1_wire_revision_mixing_rejected(tmp_path):
    with create(tmp_path) as p:
        old=bundle();old['provenance']['annotations_json']=canonical(A1_ANNOTATIONS).decode()
        with pytest.raises(ProjectionError):p.validate_bundle(old)
        apply(p,[bundle()]);empty_pins(p)
        out=publish(p,tmp_path/'public',checked_cut=p.status()['source_cut'],evaluated_at=NOW)
        with pytest.raises(ProjectionError):validate_database(tmp_path/'public'/out['manifest']['database'],contract_revision='A1')


@pytest.mark.parametrize('text',['tclk1 {broken','{"type":"JOB","v":1,"job_id":"broken"','tclk1 {"type":"offer","from":"did:key:z6MkDifferent","id":"offer"}'])
def test_lg1_malformed_and_mismatched_protocol_remains_negative(tmp_path,text):
    c=source();rid=add_legacy(c,text=text)
    with create(tmp_path) as p:
        b=map_raw(c,rid);apply(p,[b])
        assert b['facts']['workflow'] is None
        assert not any(q['qualification_type'] not in ('NEGATIVE_FACT',) for q in quals(p))
        assert loads(p.bundle('sm1:'+rid)['provenance']['annotations_json'])['legacy_generation'] is not None
    c.close()


def test_lg1_late_retrieval_blocks_without_mutating_raw(tmp_path):
    c=source();rid=add_legacy(c);before=dict(c.execute('SELECT * FROM raw_network_records').fetchone())
    Outbox(c,epoch='source-epoch',install=True)
    add_legacy(c)
    assert c.execute('SELECT 1 FROM router_projection_pending WHERE raw_record_id=?',(rid,)).fetchone()
    with pytest.raises(LegacyGenerationError,match='INCOMPATIBLE_LINEAGE'):map_raw(c,rid)
    assert dict(c.execute('SELECT * FROM raw_network_records').fetchone())==before
    c.close()


def test_lg1_runtime_source_diagnostic_is_scoped_and_redacted():
    from types import SimpleNamespace
    from threading import Lock
    from scout_runtime import Storage
    def reject(**kwargs):raise LegacyGenerationError('LG1_GENERATION_CONFLICT')
    storage=SimpleNamespace(projection_outbox=SimpleNamespace(capture=reject,revision=REVISION),projection_retry_at=0,projection_active=set(),diag=SimpleNamespace(lock=Lock(),values={}))
    Storage.projection_capture(storage)
    status=storage.diag.values['router_projection_source']
    assert status['true_generation_conflicts_rejected']==1 and status['last_lg1_error']=='LG1_GENERATION_CONFLICT'
    assert status['legacy_generation_policy']==LEGACY_POLICY and 'source capture attempts' in status['rejection_count_scope']
    assert DID not in canonical(status).decode() and TEXT not in canonical(status).decode()


@pytest.mark.parametrize('mutation',['extra','missing','wrong_policy','downgrade'])
def test_lg1_manifest_closed_revision_shape(tmp_path,mutation):
    from scout_projection_publish import manifest_revision
    with create(tmp_path) as p:
        apply(p,[bundle()]);empty_pins(p)
        m=publish(p,tmp_path/'public',checked_cut=p.status()['source_cut'],evaluated_at=NOW)['manifest']
        if mutation=='extra':m['unknown']=None
        elif mutation=='missing':del m['legacy_generation_policy']
        elif mutation=='wrong_policy':m['legacy_generation_policy']=dict(LEGACY_POLICY,authority='AUTHORITATIVE')
        else:m['contract_revision']='A1'
        with pytest.raises(ProjectionError):manifest_revision(m)


def test_lg1_edge_only_outbox_is_revision_bound(tmp_path):
    c=source(tmp_path/'source.sqlite');a=add_legacy(c,1);b=add_legacy(c,2,text='ordinary context')
    with create(tmp_path/'p') as p:
        out=Outbox(c,epoch='source-epoch',install=True)
        bootstrap(p,tmp_path/'source.sqlite','2',NOW)
        with c:c.execute("INSERT INTO router_projection_pending_edges VALUES(?,?,?,?,?,?,?)",('technocore',1,2,DID,DID,'explicit_reply',.5))
        out.capture(complete=True)
        payload=loads(c.execute('SELECT payload FROM router_projection_outbox_parts').fetchone()[0])
        assert unpack(payload,REVISION)==[]
        assert consume(p,tmp_path/'source.sqlite')['source_caught_up']
        assert p.conn.execute('SELECT count(*) FROM projection.interactions').fetchone()[0]==1
    c.close()
