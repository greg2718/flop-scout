"""Generate independent Router handoff fixtures in an explicitly temporary root."""
import argparse
import hashlib
import json
import shutil
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import flop_scout as scout
from scripts.projection_tl1_support import source, add, offer, cohort, DID, HEX, NOW
from scout_projection import initialize, Projector
from scout_projection_source import map_batch
from scout_projection_contract import TL1_REVISION, canonical, digest, plus
from scout_projection_publish import publish, manifest_revision
from scout_projection_tclk import structural, decoder_diagnostic
from test_scout_projection import apply, empty_pins

# A second public test secret represents an independent test counterparty only.
TAKER = Ed25519PrivateKey.from_private_bytes(bytes(reversed(range(32))))
TAKER_DID = scout.public_did(TAKER)


def accepted(root):
    core=dict(**{'from':TAKER_DID},ref=root['id'],statement=HEX,nonce='87654321')
    contract='0x'+hashlib.sha256(('FLOP::tclk::v1|contract|'+json.dumps(dict(offer=root,accept=core),sort_keys=True,separators=(',',':'),ensure_ascii=True)).encode()).hexdigest()
    return dict(type='accept',contract=contract,**core)


def scenario(root, name, specs):
    target=root/name;target.mkdir()
    conn=source(target/'synthetic-source.sqlite')
    ids=[add(conn,n=index,**spec) for index,spec in enumerate(specs,1)]
    bundles=map_batch(conn,ids,[DID,TAKER_DID],TL1_REVISION);conn.close()
    enrollment,members=cohort(bundles)
    path=target/'work'/'projection.sqlite'
    initialize(path,epoch='source-epoch',router_source_id='router',router_epoch='router-epoch',router_did=DID,
               local_dids=[DID,TAKER_DID],contract_revision=TL1_REVISION,legacy_tclk_cohort=enrollment,legacy_tclk_raw_ids=members)
    with Projector(path) as owner:
        apply(owner,bundles);empty_pins(owner)
        result=publish(owner,target/'public',checked_cut=owner.status()['source_cut'],evaluated_at=NOW)
        heart=publish(owner,target/'public',checked_cut=owner.status()['source_cut'],evaluated_at=plus(NOW,1))
        owner.replay_to(target/'replay'/'projection.sqlite')
        diagnostics=json.loads(owner.get('tl1_status'))
    vectors=[dict(raw_id=b['provenance']['raw_record_id'],schema_pass=structural(b['message']['text'])[1]==0,decoder_pass=decoder_diagnostic(b['message']['text'])) for b in bundles if b['message']['text'].startswith('tclk1 ')]
    record=dict(name=name,expected='ACCEPT_VALID_TL1_ARTIFACT',public_root=str(target/'public'),manifest=result['pointer']['manifest'],heartbeat_manifest=heart['pointer']['manifest'],cohort=enrollment,raw_ids=members,diagnostics=diagnostics,vectors=vectors)
    (target/'expected.json').write_bytes(canonical(record))
    return record


def rejected_manifest(root, name, source_record, mutate):
    target=root/name;shutil.copytree(source_record['public_root'],target)
    pointer=json.loads((target/'current.json').read_text());manifest=json.loads((target/pointer['manifest']).read_text())
    mutate(manifest)
    mh=digest(manifest);name_file=f"manifest-v2-{manifest['snapshot_id']}-{mh}.json"
    (target/name_file).write_bytes(canonical(manifest));pointer.update(manifest=name_file,manifest_sha256=mh)
    (target/'current.json').write_bytes(canonical(pointer))
    rejected=False
    try:manifest_revision(manifest)
    except ValueError:rejected=True
    assert rejected
    return dict(name=name,expected='REJECT',public_root=str(target),manifest=name_file)


def run(root, maximum_public):
    root.mkdir(parents=True,exist_ok=False)
    offer_frame=offer(expires_ms=2000000000000)
    accept=accepted(offer_frame)
    alias=dict(type='accept',**{'from':DID},offer_id=offer_frame['id'],statement=HEX,nonce='12345678')
    receipt=dict(type='receipt',**{'from':DID},contract=HEX,outcome=['claimed'])
    cases=[
        ('schema-fail-decoder-fail',[dict(obj=alias)]),
        ('schema-fail-decoder-pass',[dict(obj=receipt)]),
        ('schema-pass-decoder-fail',[dict(obj=offer_frame),dict(obj=dict(accept,paymentKey='0x'+'00'*33),key=TAKER)]),
        ('schema-pass-decoder-pass',[dict(obj=offer_frame),dict(obj=accept,key=TAKER)]),
        ('normative-accept',[dict(obj=offer_frame),dict(obj=accept,key=TAKER)]),
        ('offer-id-only',[dict(obj=alias)]),
        ('one-audit-candidate',[dict(obj=offer_frame),dict(obj=alias)]),
        ('ambiguous-audit-hint',[dict(obj=offer_frame),dict(obj=offer_frame),dict(obj=alias)]),
        ('missing-link-receipt',[dict(obj=dict(type='receipt',**{'from':DID},outcome='claimed'))]),
        ('invalid-signature',[dict(obj=alias,invalid_signature=True)]),
        ('cross-generation',[dict(obj=offer_frame,generation='0'),dict(obj=alias)]),
        ('same-operator',[dict(obj=alias)]),
        ('heartbeat-reuse',[dict(obj=alias)]),
    ]
    records=[scenario(root,name,specs) for name,specs in cases]
    maximum=root/'capacity-near-limit';shutil.copytree(maximum_public,maximum)
    pointer=json.loads((maximum/'current.json').read_text())
    records.append(dict(name='capacity-near-limit',expected='ACCEPT_VALID_TL1_ARTIFACT',public_root=str(maximum),manifest=pointer['manifest']))
    records.append(rejected_manifest(root,'capacity-overflow-rejection',records[-1],lambda m:m['legacy_tclk_cohort'].update(record_count=4097)))
    records.append(rejected_manifest(root,'wrong-schema-pin',records[0],lambda m:m.update(tclk_frame_schema_sha256='0'*64)))
    records.append(rejected_manifest(root,'mixed-representation',records[0],lambda m:m.update(contract_revision='A1-LG2')))
    (root/'index.json').write_text(json.dumps(records,indent=2)+'\n')
    print(json.dumps(dict(root=str(root),fixture_count=len(records))))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True);parser.add_argument('--maximum-public',type=Path,required=True)
    args=parser.parse_args();assert str(args.root).startswith('/private/tmp/') and str(args.maximum_public).startswith('/private/tmp/')
    run(args.root,args.maximum_public)
