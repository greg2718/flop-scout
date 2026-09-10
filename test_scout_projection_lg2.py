"""LG2 contract tests: synthetic originals, explicit temporary projection pairs."""
import copy
import json
from scout_projection_source import resolve_interaction
import sqlite3
import pytest
from scout_projection_contract import *
from scout_projection_compact import *
from scout_projection import Projector, initialize, read_status
from scout_projection_source import map_raw, pack, unpack, Outbox, consume
from scout_projection_publish import publish, validate_database, manifest_revision
from scripts.projection_lg1_support import source, add_legacy, NOW, DID, TEXT
from test_scout_projection import apply, empty_pins, quals, bundle as old_bundle, create as old_create


def create(root, local=()):
    path=root/'projection.sqlite'
    initialize(path,epoch='source-epoch',router_source_id='router',router_epoch='router-epoch',router_did='did:key:z6MkRouter',local_dids=local,contract_revision=LG2_REVISION)
    return Projector(path)


def bundle(**kwargs):
    b=convert_bundle(old_bundle(**kwargs));raw=text_hash(b['provenance']['raw_record_id'])
    b['provenance'].update(raw_record_id=raw,source_record_locator=raw,projection_row_id='sm1:'+raw)
    b['message']['projection_row_id']='sm1:'+raw
    return b


def mapped(report='0', multi=True, **kwargs):
    with source() as c:
        rid=add_legacy(c,report=report,protocol_cache=multi,**kwargs)
        return map_raw(c,rid,[DID],LG2_REVISION)


@pytest.mark.parametrize('report',['0','1'])
def test_roundtrip_publish_replay(report,tmp_path):
    b=mapped(report)
    with create(tmp_path/'p',local=[DID]) as p:
        apply(p,[b]);before=quals(p);assert before
        assert all(q['same_operator'] and not q['independent_reputation'] for q in before)
        assert len(logical_audit(b)['linked_cache_records'])==2
        stats=p.legacy_status();assert stats['report_count']==1 and stats['witness_count']==2
        assert stats['non_authoritative_report_counts'][report]==1
        assert [r[0] for r in p.conn.execute('SELECT generation FROM projection.watermarks')]==['UNKNOWN_LEGACY']
        for r in p.conn.execute('SELECT annotations_json FROM projection.source_provenance'):assert set(loads(r[0]))==set(A1_ANNOTATIONS)
        empty_pins(p);a=publish(p,tmp_path/'public',checked_cut=p.status()['source_cut'],evaluated_at=NOW)
        assert manifest_revision(a['manifest'])==LG2_REVISION
        assert a['manifest']['row_counts']['legacy_generation_witnesses']==2
        validate_database(tmp_path/'public'/a['manifest']['database'],contract_revision=LG2_REVISION)
        h=publish(p,tmp_path/'public',checked_cut=p.status()['source_cut'],evaluated_at=plus(NOW,1))
        assert h['manifest']['publication_kind']=='HEARTBEAT' and h['manifest']['database']==a['manifest']['database']
        p.replay_to(tmp_path/'replay'/'projection.sqlite')
        assert quals(p)==before
    assert read_status(tmp_path/'p'/'projection.sqlite')['witness_count']==2
    with Projector(tmp_path/'replay'/'projection.sqlite') as p:assert quals(p)==before


@pytest.mark.parametrize('code',[2,-1,True,0.0,'0',None])
def test_bad_report_enum(code):
    b=mapped();b['legacy_generation_compact']['reported_code']=code
    with pytest.raises(ProjectionError):logical_audit(b)


@pytest.mark.parametrize('code',[0,4,True,1.0,'1',None])
def test_bad_cache_enum(code):
    b=mapped();b['legacy_generation_compact']['witnesses'][0][0]=code
    with pytest.raises(ProjectionError):logical_audit(b)


@pytest.mark.parametrize('token',[None,123,' ','x'*257])
def test_bad_locator(token):
    b=mapped(multi=False);b['legacy_generation_compact']['witnesses'][0][2]=token
    with pytest.raises(ProjectionError):logical_audit(b)


def test_canonical_locator_and_conflicting_locator():
    b=mapped(multi=False);v=b['legacy_generation_compact'];w=v['witnesses'][0]
    w[2]='';assert logical_audit(b)['linked_cache_records'][0]['source_record_locator']==w[1]
    w[2]=w[1]
    with pytest.raises(ProjectionError):logical_audit(b)
    w[2]='kept exact λ locator';assert logical_audit(b)['linked_cache_records'][0]['source_record_locator']==w[2]
    v['witnesses'].append([w[0],'e'*64,w[2]]);v['witnesses'].sort()
    with pytest.raises(ProjectionError):logical_audit(b)


@pytest.mark.parametrize('mutation',['duplicate','no_evidence','empty','too_many','hash'])
def test_witness_bounds(mutation):
    b=mapped(multi=False);v=b['legacy_generation_compact'];w=v['witnesses'][0]
    if mutation=='duplicate':v['witnesses'].append(copy.deepcopy(w))
    if mutation=='no_evidence':w[0]=2
    if mutation=='empty':v['witnesses']=[]
    if mutation=='too_many':v['witnesses']=[w]*257
    if mutation=='hash':w[1]='no'
    with pytest.raises(ProjectionError):logical_audit(b)


def test_logical_annotation_bound():
    b=mapped(multi=False)
    b['legacy_generation_compact']['witnesses']=[[1,text_hash(str(n)),('locator-'+str(n)).ljust(256,'z')] for n in range(256)]
    b['legacy_generation_compact']['witnesses'].sort()
    with pytest.raises(ProjectionError,match='logical annotation'):logical_audit(b)


@pytest.mark.parametrize('change',['policy','encoding','revision','json'])
def test_mixed_encoding(change,tmp_path):
    meta=revision_metadata(LG2_REVISION)
    if change=='policy':meta.pop('legacy_generation_policy')
    elif change=='encoding':meta['legacy_generation_encoding']='future'
    elif change=='revision':meta['contract_revision']=REVISION
    if change!='json':
        with pytest.raises(ProjectionError):revision_binding(meta)
    else:
        with create(tmp_path) as p:
            b=bundle();a=loads(b['provenance']['annotations_json']);a['legacy_generation']=None;b['provenance']['annotations_json']=canonical(a).decode()
            with pytest.raises(ProjectionError):p.validate_bundle(b)
    with pytest.raises(ProjectionError):unpack(pack([],LG2_REVISION),REVISION)
    with pytest.raises(ProjectionError):unpack(pack([],REVISION),LG2_REVISION)


@pytest.mark.parametrize('damage',['report','witness','original','generation','lineage'])
def test_private_proof_and_loss_fail(damage,tmp_path):
    b=mapped()
    with create(tmp_path,local=[DID]) as p:
        if damage in ('original','generation','lineage'):
            if damage=='original':del b['legacy_generation_originals']
            if damage=='generation':b['legacy_generation_originals']['raw']['generation']='0'
            if damage=='lineage':b['legacy_generation_originals']['raw']['source_endpoint']='changed'
            with pytest.raises(ProjectionError):p.validate_bundle(b)
        else:
            apply(p,[b])
            with p.conn:
                p.conn.execute('DELETE FROM projection.legacy_generation_witnesses')
                if damage=='report':p.conn.execute('DELETE FROM projection.legacy_generation_reports')
            with pytest.raises(ProjectionError):p.verify_ledger()


def test_lg1_migration_archive_content_history(tmp_path):
    with source() as c:
        rid=add_legacy(c,protocol_cache=True);b=map_raw(c,rid,[DID])
    with old_create(tmp_path/'p',local=[DID]) as p:
        apply(p,[b]);empty_pins(p);q=quals(p)
        first=publish(p,tmp_path/'public',checked_cut=p.status()['source_cut'],evaluated_at=NOW)
        old_evals=[tuple(r) for r in p.conn.execute('SELECT * FROM evaluations')]
        result=p.enable_lg2();archive=Path(result['lg1_private_archive']);assert (archive/'archive.json').exists()
        assert old_evals==[tuple(r) for r in p.conn.execute('SELECT * FROM evaluations')]
        assert quals(p)==q and p.bundle('sm1:'+rid)['legacy_generation_compact'] is not None
        next_pub=publish(p,tmp_path/'public',checked_cut=p.status()['source_cut'],evaluated_at=plus(NOW,1))
        assert next_pub['manifest']['publication_kind']=='CONTENT'
        public_archive=Path(next_pub['lg1_publication_archive'])
        assert (public_archive/first['manifest']['database']).read_bytes()==(tmp_path/'public'/first['manifest']['database']).read_bytes()
        for k in ('database','database_content_id','snapshot_id'):assert first['manifest'][k]!=next_pub['manifest'][k]
        from scout_projection_publish import retain
        retain(tmp_path/'public',keep=1)
        assert (public_archive/first['manifest']['database']).exists()
        p.replay_to(tmp_path/'replayed'/'projection.sqlite')
        with pytest.raises(ProjectionError):p.enable_lg1()
        with pytest.raises(ProjectionError):p.enable_lg2()


def test_idempotent_and_expiry(tmp_path):
    b=mapped(text='ordinary context')
    with create(tmp_path,local=[DID]) as p:
        apply(p,[b]);apply(p,[b],plus(NOW,1),'SOURCE_BATCH')
        assert p.legacy_status()['witness_count']==2
        apply(p,[],plus(NOW,2592001),'EXPIRY',cut='1')
        assert p.legacy_status()['report_count']==0 and p.legacy_status()['witness_count']==0
        p.verify_ledger()


def test_source_conflicts_and_outbox(tmp_path):
    with source(tmp_path/'source.sqlite') as c:
        out=Outbox(c,local_dids=[DID],epoch='source-epoch',install=True,revision=LG2_REVISION)
        rid=add_legacy(c,protocol_cache=True)
        with create(tmp_path/'p',local=[DID]) as p:
            # A first outbox evaluation requires an explicit empty bootstrap.
            apply(p,[],cut='0');out.capture(complete=True)
            consume(p,tmp_path/'source.sqlite')
            assert p.legacy_status()['report_count']==1
            with c:c.execute("UPDATE kibble_events SET generation='1'")
            with pytest.raises(ProjectionError):map_raw(c,rid,revision=LG2_REVISION)


def test_schema_generated_column_mixed_reject(tmp_path):
    with create(tmp_path) as p:
        apply(p,[bundle()]);assert p.legacy_status()['report_count']==0
        validate_database(p.path,contract_revision=LG2_REVISION)
        with pytest.raises(ProjectionError):validate_database(p.path,contract_revision=REVISION)
        assert [tuple(r) for r in p.conn.execute('PRAGMA projection.table_xinfo(legacy_generation_reports)')][-1][-1]==2


def test_lg2_interaction_captured_identity_and_audit_multiplicity(tmp_path):
    c=source();a=add_legacy(c,1,report='0',protocol_cache=True);b=add_legacy(c,2,report='1',text='ordinary synthetic context')
    with create(tmp_path) as p:
        apply(p,[map_raw(c,a,revision=LG2_REVISION),map_raw(c,b,revision=LG2_REVISION)])
        edge=dict(room='technocore',source_seq=1,response_seq=2,source_did=DID,target_did=DID,relationship_type='explicit_reply',confidence=.5)
        resolved=resolve_interaction(c,edge);eid=p.add_interaction(**resolved)
        assert eid==p.add_interaction(**resolved)
        identity_obj=loads(p.get('interaction:'+eid));assert {e['generation'] for e in identity_obj['endpoints']}=={'UNKNOWN_LEGACY'}
        # Report is absent from the canonical endpoint identity; it cannot rename an edge.
        assert interaction_identity('explicit_reply',*[{k:v for k,v in e.items() if k!='role'} for e in identity_obj['endpoints']])[0]==eid
        p.replay_to(tmp_path/'again'/'projection.sqlite')
        assert p.conn.execute('SELECT count(*) FROM projection.interactions').fetchone()[0]==1
        assert 'legacy_generation' not in loads(p.conn.execute("SELECT annotations_json FROM projection.source_provenance WHERE entity_type='interaction'").fetchone()[0])
    c.close()


def test_lg2_workflow_cannot_bridge_concrete_domain():
    import flop_scout
    c=source()
    job=json.dumps(dict(type='JOB',v=1,job_id='same-job'))
    rid=add_legacy(c,1,text=job,room='kibble',protocol_cache=True,verified=True)
    b=map_raw(c,rid,revision=LG2_REVISION)
    assert b['message']['generation']=='UNKNOWN_LEGACY'
    assert b['facts']['workflow']['authenticated'] and b['facts']['workflow']['identity']['scope']['generation']=='UNKNOWN_LEGACY'
    terminal=dict(seq=2,did=DID,text=json.dumps(dict(type='ACCEPT',v=1,job_id='same-job',result_raw_record_id=rid)))
    # A concrete-generation root cannot be selected by a reported legacy value.
    with c:flop_scout.ingest_messages(c,'kibble',[terminal],generation='0',source='service-poll')
    terminal_id=c.execute("SELECT raw_record_id FROM raw_network_records WHERE generation='0'").fetchone()[0]
    assert map_raw(c,terminal_id,revision=LG2_REVISION)['facts']['workflow'] is None
    c.close()


def test_lg2_ambiguous_roots_not_selected_by_report():
    c=source();job=json.dumps(dict(type='JOB',v=1,job_id='ambiguous'))
    add_legacy(c,1,report='0',text=job,room='kibble',protocol_cache=True,verified=True)
    import flop_scout
    other='did:key:z'+flop_scout.b58encode(flop_scout.ED25519_MULTICODEC+bytes(reversed(range(32))))
    add_legacy(c,2,report='1',text=job,room='kibble',sender=other,protocol_cache=True,verified=True)
    rid=add_legacy(c,3,report='0',text=json.dumps(dict(type='ACCEPT',v=1,job_id='ambiguous')),room='kibble',protocol_cache=True,verified=True)
    with pytest.raises(ProjectionError,match='Ambiguous workflow root issuer'):map_raw(c,rid,revision=LG2_REVISION)
    c.close()


def test_lg2_valid_cache_addition_preserves_ids_and_qualifications(tmp_path):
    c=source();rid=add_legacy(c)
    with create(tmp_path) as p:
        apply(p,[map_raw(c,rid,revision=LG2_REVISION)]);before=quals(p)
        add_legacy(c,protocol_cache=True,cache_only=True)
        apply(p,[map_raw(c,rid,revision=LG2_REVISION)],plus(NOW,1),'SOURCE_BATCH')
        assert quals(p)==before
        assert len(logical_audit(p.bundle('sm1:'+rid))['linked_cache_records'])==2
        assert p.conn.execute('SELECT count(*) FROM projection.messages').fetchone()[0]==1
        p.replay_to(tmp_path/'again'/'projection.sqlite')
    c.close()


def test_lg2_negative_evidence_not_promoted(tmp_path):
    c=source();rid=add_legacy(c,negative=True)
    with create(tmp_path) as p:
        b=map_raw(c,rid,revision=LG2_REVISION);assert b['facts']['signature_failure']
        apply(p,[b]);assert all(q['qualification_type']=='NEGATIVE_FACT' for q in quals(p))
        assert p.conn.execute('SELECT retention_class FROM projection.selection_membership').fetchone()[0]=='NEGATIVE_EVIDENCE'
        assert p.conn.execute('SELECT verification_status FROM projection.messages').fetchone()[0]=='INVALID_SIGNATURE'
    c.close()


def test_normalized_storage_budget(tmp_path):
    from scripts.benchmark_projection_lg2 import storage
    result=storage(tmp_path/'storage',(1000,))['sizes']['1000']
    assert result['comparison']['lg2_total_delta_percent']<=25
    assert result['modes']['LG2']['index_bytes']==result['modes']['A1']['index_bytes']
    assert result['modes']['LG2']['locator_statistics']['witness_count']==1204


def test_manifest_report_counts_closed(tmp_path):
    with create(tmp_path) as p:
        apply(p,[bundle()]);empty_pins(p)
        m=publish(p,tmp_path/'public',checked_cut=p.status()['source_cut'],evaluated_at=NOW)['manifest']
        del m['row_counts']['legacy_generation_reports']
        with pytest.raises(ProjectionError):manifest_revision(m)


def test_startup_exact_schema(tmp_path):
    with create(tmp_path) as p:
        path=p.path
        with p.conn:p.conn.execute('CREATE INDEX projection.unreviewed_lg2 ON legacy_generation_witnesses(locator)')
    with pytest.raises(ProjectionError,match='Exact LG2 schema'):Projector(path)


@pytest.mark.parametrize('captured,reported',[('0','1'),('1','0')])
def test_concrete_generation_conflict(captured,reported):
    import scout_evidence
    with source() as c:
        with c:rid=scout_evidence.ingest(c,'technocore',dict(seq=1,did=DID,text=TEXT),lambda r,m:'UNSIGNED',generation=captured,reported_generation=reported)
        with pytest.raises(ProjectionError,match='GENERATION_CONFLICT'):map_raw(c,rid,revision=LG2_REVISION)


def test_archive_replay_a1_lg1_lg2(tmp_path):
    path=tmp_path/'p'/'projection.sqlite'
    initialize(path,epoch='source-epoch',router_source_id='router',router_epoch='router-epoch',router_did=DID,contract_revision='A1')
    b=old_bundle();a=loads(b['provenance']['annotations_json']);a.pop('legacy_generation');b['provenance']['annotations_json']=canonical(a).decode()
    with Projector(path) as p:
        apply(p,[b]);before=quals(p);p.enable_lg1();p.enable_lg2()
        assert quals(p)==before
        p.replay_to(tmp_path/'replay'/'projection.sqlite')


@pytest.mark.parametrize('kind',[1,2,3])
def test_cache_kind_exact_roundtrip(kind):
    b=mapped(multi=False);v=b['legacy_generation_compact']
    if kind!=1:v['witnesses'].append([kind,'a'*64,''])
    audit=logical_audit(b)
    assert CACHE_KINDS[kind] in {r['cache_table'] for r in audit['linked_cache_records']}
    assert encode(audit)==v


def test_empty_projection_downgrade_rejected(tmp_path):
    from scout_projection_publish import validate_history_extension
    with create(tmp_path/'lg2') as a,old_create(tmp_path/'lg1') as b:
        with pytest.raises(ProjectionError,match='downgrade'):
            validate_history_extension(a.path,b.path,previous_revision=LG2_REVISION,current_revision=REVISION)


def test_validation_uses_indexed_provenance_lookup(tmp_path):
    with create(tmp_path,local=[DID]) as p:
        apply(p,[mapped()])
        seen=[]
        p.conn.set_trace_callback(seen.append)
        validate_all(p.conn,'projection.')
        p.conn.set_trace_callback(None)
        query=next(q for q in seen if q.startswith('SELECT p.*'))
        plan=[r[3] for r in p.conn.execute('EXPLAIN QUERY PLAN '+query)]
        assert 'SCAN r' in plan
        assert any('entity_type=? AND projection_row_id=?' in item for item in plan)
