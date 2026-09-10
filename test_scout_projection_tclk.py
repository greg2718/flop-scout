"""Independent golden structural vectors for the approved TL1 boundary."""
import hashlib
import json
import sqlite3
from pathlib import Path
import pytest
from scout_projection_contract import ProjectionError
import scout_projection_tclk as tl1

DID = 'did:key:z6Mk' + '1' * 44
HEX = '0x' + '1' * 64
ACCEPT = dict(type='accept', **{'from': DID}, ref=HEX, contract=HEX, statement=HEX, nonce='12345678')
RECEIPT = dict(type='receipt', **{'from': DID}, contract=HEX, outcome='claimed')


def frame(value):
    return 'tclk1 ' + json.dumps(value, separators=(',', ':'))


@pytest.mark.parametrize('obj,expected', [
    (ACCEPT, (1, 0)),
    ({**ACCEPT, 'paymentKey': '0x' + '00' * 33}, (1, 0)),
    ({**RECEIPT, 'outcome': ['claimed']}, (2, 272)),
    ({k: v for k, v in ACCEPT.items() if k != 'ref'}, (1, 1)),
    ({k: v for k, v in ACCEPT.items() if k != 'contract'}, (1, 2)),
    ({**{k: v for k, v in ACCEPT.items() if k not in ('ref', 'contract')}, 'offer_id': HEX}, (1, 15)),
    ({**ACCEPT, 'offer_id': HEX}, (1, 4)),
    ({**ACCEPT, 'offer_id': 'different'}, (1, 36)),
    ({**ACCEPT, 'ref': None}, (1, 256)),
    ({**ACCEPT, 'ref': HEX+'\n'}, (1, 256)),
    ({**ACCEPT, 'nonce': '12345678\r'}, (1, 256)),
    ({**ACCEPT, 'ref': None, 'contract': ''}, (1, 264)),
    ({k: v for k, v in RECEIPT.items() if k != 'contract'}, (2, 26)),
    ({**RECEIPT, 'offer_id': None}, (2, 20)),
    ({**RECEIPT, 'unknown': True}, (2, 80)),
    ({}, (0, 512)),
    ({'type': 'ACCEPT'}, (3, 512)),
    ({'type': None, 'offer_id': {}}, (0, 516)),
    ({'type': 'future', 'from': None}, (3, 768)),
    ({k: v for k, v in ACCEPT.items() if k != 'from'}, (1, 64)),
    (RECEIPT, (2, 0)),
])
def test_golden_schema_masks(obj, expected):
    assert tl1.structural(frame(obj)) == expected


@pytest.mark.parametrize('text', ['tclk1 {', 'tclk1 null', 'tclk1 []',
                                 'tclk1 {"type":"accept","type":"receipt"}',
                                 'tclk1 {"type":"accept","job":{"id":1,"id":2}}',
                                 'tclk1 {"x":NaN}'])
def test_unavailable_is_only_128(text):
    assert tl1.structural(text) == (0, 128)
    assert all('value' not in claim for claim in tl1.claims(text).values())


def test_claim_types_are_preserved():
    result = tl1.claims(frame({'offer_id': ['x'], 'ref': None}))
    assert result == {'offer_id': {'state': 'PRESENT_TYPED_VALUE', 'value': ['x']},
                      'ref': {'state': 'PRESENT_NULL', 'value': None},
                      'contract': {'state': 'ABSENT'}}


def test_decoder_drift_cannot_affect_structural_result(monkeypatch):
    # No decoder callback/result participates in this API. The two disagreeing
    # cases remain stable regardless of a telemetry consumer's decoder output.
    cases = [(dict(ACCEPT, paymentKey='0x'+'00'*33), 0),
             (dict(RECEIPT, outcome=['claimed']), 272)]
    for decoder_result in (True, False, None):
        monkeypatch.setattr(tl1, 'decoder_diagnostic', lambda text: decoder_result)
        for value, mask in cases:
            assert tl1.structural(frame(value))[1] == mask
        from scripts.projection_tl1_support import mapped, cohort
        bundle = mapped()
        result = (bundle, cohort([bundle]))
        if decoder_result is True:
            baseline = result
        else:
            assert result == baseline


@pytest.mark.parametrize('key', list(tl1.PIN))
def test_each_pin_field_is_mandatory_and_exact(key):
    value = dict(tl1.PIN)
    del value[key]
    with pytest.raises(ProjectionError):
        tl1.verify_pin(value)
    value[key] = 'main'
    with pytest.raises(ProjectionError):
        tl1.verify_pin(value)


def test_approved_schema_bytes_and_exact_ddl():
    assert len(tl1.verify_pin(tl1.PIN)) == 6070
    conn = sqlite3.connect(':memory:')
    conn.executescript(Path('docs/router-tclk-legacy-tl1-schema.sql').read_text())
    raw = bytes.fromhex('01'*32)
    conn.execute('INSERT INTO legacy_tclk_records VALUES(?,?,?)', (raw, 1, 15))
    assert conn.execute('SELECT message_id FROM legacy_tclk_records').fetchone()[0] == 'sm1:'+'01'*32
    for row in [(b'x', 1, 15), (b'2'*32, 4, 15), (b'3'*32, 1, 1024), (b'4'*32, 1, 0)]:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute('INSERT INTO legacy_tclk_records VALUES(?,?,?)', row)
    conn.close()


def test_cohort_union_digest_and_limits():
    ids = [hashlib.sha256(str(i).encode()).hexdigest() for i in range(4097)]
    for size in (0, 2505, 4096):
        selected = ids[:size]
        assert tl1.cohort_digest(selected) == tl1.cohort_digest(list(reversed(selected)))
    with pytest.raises(ProjectionError):
        tl1.cohort_digest(ids)
    with pytest.raises(ProjectionError):
        tl1.cohort_digest([ids[0], ids[0]])


@pytest.mark.parametrize('field,bound', [('enrolled', 4096), ('held_messages', 100000), ('dependency_bytes', 268435456)])
def test_capacity_inclusive_boundary(field, bound):
    values = dict(enrolled=0, held_messages=0, dependency_bytes=0)
    for count in (bound-1, bound):
        values[field] = count
        assert not tl1.require_capacity(**values)['overflow']
    values[field] = bound+1
    with pytest.raises(ProjectionError, match='TL1_CAPACITY_EXCEEDED'):
        tl1.require_capacity(**values)


def test_accounting_uses_all_columns_and_blob_hex():
    row = dict(raw_ref=b'\x00\xff', claimed_type_code=1, nonconformance_mask=15, message_id='sm1:x')
    expected = '["legacy_tclk_records",{"claimed_type_code":1,"message_id":"sm1:x","nonconformance_mask":15,"raw_ref":"00ff"}]\n'
    assert tl1.serialized_row_bytes('legacy_tclk_records', row) == len(expected.encode())


@pytest.mark.parametrize('mask', [0, 1024, -1, True, 1.5])
def test_unknown_reason_rejects(mask):
    with pytest.raises(ProjectionError):
        tl1.reason_names(mask)


def test_authenticated_enrollment_publish_heartbeat_and_restart(tmp_path):
    from scripts.projection_tl1_support import mapped, cohort, NOW
    from scout_projection import initialize, Projector
    from scout_projection_contract import TL1_REVISION, plus
    from scout_projection_publish import publish
    from test_scout_projection import apply, empty_pins, quals
    bundle = mapped()
    enrollment, ids = cohort([bundle])
    path = tmp_path/'work'/'projection.sqlite'
    initialize(path, epoch='source-epoch', router_source_id='router', router_epoch='router-epoch', router_did=DID,
               contract_revision=TL1_REVISION, legacy_tclk_cohort=enrollment, legacy_tclk_raw_ids=ids, local_dids=[bundle['message']['sender']])
    with Projector(path) as owner:
        apply(owner, [bundle])
        assert owner.conn.execute('SELECT count(*) FROM projection.legacy_tclk_records').fetchone()[0] == 1
        assert owner.conn.execute('SELECT retain_until FROM projection.selection_membership').fetchone()[0] is None
        assert not quals(owner)
        assert owner.conn.execute('SELECT count(*) FROM workflows').fetchone()[0] == 0
        empty_pins(owner)
        first = publish(owner, tmp_path/'public', checked_cut=owner.status()['source_cut'], evaluated_at=NOW)
        second = publish(owner, tmp_path/'public', checked_cut=owner.status()['source_cut'], evaluated_at=plus(NOW, 1))
        assert first['manifest']['contract_revision'] == TL1_REVISION
        assert second['manifest']['publication_kind'] == 'HEARTBEAT'
        assert first['manifest']['database'] == second['manifest']['database']
    with Projector(path) as owner:
        assert not quals(owner)
        owner.replay_to(tmp_path/'replay'/'projection.sqlite')


def test_ambiguous_hint_holds_expired_offers_and_preserves_generation(tmp_path):
    from scripts.projection_tl1_support import add, cohort, source, offer, DID as AUTHOR, NOW
    from scout_projection_source import map_batch
    from scout_projection import initialize, Projector
    from scout_projection_contract import TL1_REVISION, plus
    from test_scout_projection import apply, quals
    conn = source()
    root = offer()
    ids = [add(conn, n=1, obj=root), add(conn, n=2, obj=root),
           add(conn, n=3, obj={'type':'accept','from':AUTHOR,'offer_id':root['id'],'statement':HEX,'nonce':'12345678'}),
           add(conn, n=4, obj=root, generation='0')]
    bundles = map_batch(conn, ids, [AUTHOR], TL1_REVISION)
    enrollment, members = cohort(bundles)
    path = tmp_path/'projection.sqlite'
    initialize(path, epoch='source-epoch', router_source_id='router', router_epoch='router-epoch', router_did=AUTHOR,
               local_dids=[AUTHOR], contract_revision=TL1_REVISION, legacy_tclk_cohort=enrollment, legacy_tclk_raw_ids=members)
    with Projector(path) as owner:
        apply(owner, bundles)
        hints = tl1.audit_hints(owner.conn, 'projection.')
        assert hints['audit_hint_count'] == 2 and hints['ambiguous_hint_count'] == 1
        assert {h['candidate_message_id'] for h in hints['hints']} == {'sm1:'+ids[0], 'sm1:'+ids[1]}
        assert owner.conn.execute('SELECT count(*) FROM projection.messages').fetchone()[0] == 3
        assert not owner.conn.execute('SELECT 1 FROM projection.selection_membership WHERE retain_until IS NOT NULL').fetchone()
        assert not quals(owner)
        apply(owner, [], when=plus(NOW, 200*86400), kind='EXPIRY', cut='4')
        assert owner.conn.execute('SELECT count(*) FROM projection.messages').fetchone()[0] == 3
        assert owner.conn.execute('SELECT count(*) FROM projection.legacy_tclk_records').fetchone()[0] == 1
    conn.close()


@pytest.mark.parametrize('interrupted', [False, True])
def test_explicit_migration_preserves_old_qualification_and_archive(tmp_path, interrupted):
    from scripts.projection_tl1_support import add, cohort, source, DID as AUTHOR, NOW
    from scripts.projection_lg1_support import TEXT
    from scout_projection_source import map_raw, Outbox, migrate_tl1
    from scout_projection import initialize, Projector
    from scout_projection_contract import LG2_REVISION, TL1_REVISION, plus
    from scout_projection_publish import publish
    from test_scout_projection import apply, empty_pins, quals
    source_path = tmp_path/'source.sqlite'; conn = source(source_path)
    initial = add(conn, n=1, text=TEXT)
    baseline = map_raw(conn, initial, [AUTHOR], LG2_REVISION)
    path = tmp_path/'projection.sqlite'
    initialize(path, epoch='source-epoch', router_source_id='router', router_epoch='router-epoch', router_did=AUTHOR, local_dids=[AUTHOR], contract_revision=LG2_REVISION)
    with Projector(path) as owner:
        apply(owner, [baseline]); old_quals = quals(owner); assert old_quals
        empty_pins(owner)
        publish(owner, tmp_path/'public', checked_cut=owner.status()['source_cut'], evaluated_at=NOW)
        legacy = add(conn, n=2)
        enrollment, members = cohort([map_raw(conn, legacy, [AUTHOR], TL1_REVISION)])
        Outbox(conn, [AUTHOR], epoch='source-epoch', install=True, revision=LG2_REVISION)
        conn.close()
        if interrupted:
            owner.activate_tl1(enrollment, members)
    with Projector(path) as owner:
        if interrupted:
            assert owner.get('tl1_activation_pending') == '1'
        migrate_tl1(owner, source_path, enrollment, members, plus(NOW, 1))
        assert quals(owner) == old_quals
        result = publish(owner, tmp_path/'public', checked_cut=owner.status()['source_cut'], evaluated_at=plus(NOW, 1))
        assert result['manifest']['publication_kind'] == 'CONTENT'
        assert list((tmp_path/'public').glob('lg2-publication-archive-*'))
        owner.replay_to(tmp_path/'replayed'/'projection.sqlite')
    with Projector(path) as owner:
        assert quals(owner) == old_quals


@pytest.mark.parametrize('legacy_shape', ['alias','receipt','malformed'])
def test_hold_only_interaction_dependency_never_qualifies(tmp_path,legacy_shape):
    from scripts.projection_tl1_support import source, add, offer, cohort, DID as AUTHOR, NOW
    from scripts.projection_lg1_support import TEXT
    from scout_projection_source import map_batch
    from scout_projection import initialize, Projector
    from scout_projection_contract import TL1_REVISION, plus
    from test_scout_projection import quals
    conn=source()
    legacy_args = {} if legacy_shape=='alias' else {'obj':{'type':'receipt','from':AUTHOR,'outcome':'claimed'}} if legacy_shape=='receipt' else {'text':'tclk1 {'}
    ids=[add(conn,n=1,obj=offer()),add(conn,n=2,**legacy_args),add(conn,n=3,text=TEXT)]
    bundles=map_batch(conn,ids,[AUTHOR],TL1_REVISION);enrollment,members=cohort(bundles)
    path=tmp_path/'projection.sqlite'
    initialize(path,epoch='source-epoch',router_source_id='router',router_epoch='router-epoch',router_did=AUTHOR,local_dids=[AUTHOR],contract_revision=TL1_REVISION,legacy_tclk_cohort=enrollment,legacy_tclk_raw_ids=members)
    with Projector(path) as owner:
        number=owner.begin('3',plus(NOW,100*86400),'BOOTSTRAP')
        owner.stage(number,bundles)
        owner.stage_edges(number,[dict(source_id='sm1:'+ids[0],target_id='sm1:'+ids[2],relationship_type='REPLIED_TO',confidence=0.5)])
        owner.seal(number)
        assert not quals(owner)
        assert owner.conn.execute('SELECT count(*) FROM projection.messages').fetchone()[0]==3
        assert owner.conn.execute('SELECT count(*) FROM projection.interactions').fetchone()[0]==1
        assert not owner.conn.execute('SELECT 1 FROM projection.selection_membership WHERE retain_until IS NOT NULL').fetchone()
        result=json.loads(owner.get('tl1_status'));assert result['held_message_count']==3
        owner.replay_to(tmp_path/'replay'/'projection.sqlite')
    conn.close()


@pytest.mark.parametrize('text,expected_mask', [('tclk1 {',128),('tclk1 {"type":"accept","type":"receipt"}',128)])
def test_authenticated_unparseable_originals_enter_only_explicit_cohort(text,expected_mask,tmp_path):
    from scripts.projection_tl1_support import mapped, cohort
    from scout_projection import initialize, Projector
    from scout_projection_contract import TL1_REVISION
    from test_scout_projection import apply
    bundle=mapped(text=text);enrollment,ids=cohort([bundle])
    path=tmp_path/'projection.sqlite'
    initialize(path,epoch='source-epoch',router_source_id='router',router_epoch='router-epoch',router_did=DID,local_dids=[bundle['message']['sender']],contract_revision=TL1_REVISION,legacy_tclk_cohort=enrollment,legacy_tclk_raw_ids=ids)
    with Projector(path) as owner:
        apply(owner,[bundle])
        assert owner.conn.execute('SELECT nonconformance_mask FROM projection.legacy_tclk_records').fetchone()[0]==expected_mask


def test_new_independent_qualification_binds_policy_three(tmp_path):
    from scripts.projection_tl1_support import mapped, cohort
    from scripts.projection_lg1_support import TEXT
    from scout_projection import initialize, Projector
    from scout_projection_contract import TL1_REVISION
    from test_scout_projection import apply, quals
    bundle=mapped(text=TEXT);enrollment,ids=cohort([bundle]);path=tmp_path/'projection.sqlite'
    initialize(path,epoch='source-epoch',router_source_id='router',router_epoch='router-epoch',router_did=DID,local_dids=[bundle['message']['sender']],contract_revision=TL1_REVISION,legacy_tclk_cohort=enrollment,legacy_tclk_raw_ids=ids)
    with Projector(path) as owner:
        apply(owner,[bundle]);records=quals(owner);assert records
        assert all(record['policy_version']=='router-evidence-horizons/3' and record['classifier_version']=='router-evidence-classes/3' for record in records)


def test_unenrolled_arrival_and_missing_cohort_fail_closed(tmp_path):
    from scripts.projection_tl1_support import mapped, cohort
    from scout_projection import initialize, Projector
    from scout_projection_contract import TL1_REVISION
    from test_scout_projection import apply
    bundle=mapped();enrollment,ids=cohort([bundle]);path=tmp_path/'projection.sqlite'
    initialize(path,epoch='source-epoch',router_source_id='router',router_epoch='router-epoch',router_did=DID,local_dids=[bundle['message']['sender']],contract_revision=TL1_REVISION,legacy_tclk_cohort=enrollment,legacy_tclk_raw_ids=ids)
    with Projector(path) as owner:
        apply(owner,[bundle])
        another=mapped(n=2)
        number=owner.begin('2','2026-09-09T12:00:00.000000Z','SOURCE_BATCH')
        with pytest.raises(ProjectionError,match='TL1_UNENROLLED'):
            owner.stage(number,[another])
        assert owner.status()['readiness']=='NOT_READY'
        with pytest.raises(ProjectionError):owner.activate_tl1(enrollment,ids)


@pytest.mark.parametrize('generation', [None,'0'])
def test_receipt_keeps_captured_generation(generation,tmp_path):
    from scripts.projection_tl1_support import mapped, cohort, DID as AUTHOR
    from scout_projection import initialize, Projector
    from scout_projection_contract import TL1_REVISION
    from test_scout_projection import apply
    bundle=mapped(generation=generation,obj=dict(type='receipt',**{'from':AUTHOR},outcome='claimed'))
    enrollment,ids=cohort([bundle]);path=tmp_path/'projection.sqlite'
    initialize(path,epoch='source-epoch',router_source_id='router',router_epoch='router-epoch',router_did=DID,local_dids=[AUTHOR],contract_revision=TL1_REVISION,legacy_tclk_cohort=enrollment,legacy_tclk_raw_ids=ids)
    with Projector(path) as owner:
        apply(owner,[bundle])
        assert owner.conn.execute('SELECT generation FROM projection.messages').fetchone()[0] == ('UNKNOWN_LEGACY' if generation is None else generation)
        assert owner.conn.execute('SELECT claimed_type_code,nonconformance_mask FROM projection.legacy_tclk_records').fetchone()[:] == (2,26)
