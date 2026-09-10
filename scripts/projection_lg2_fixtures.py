#!/usr/bin/env python3
"""Local A1-LG2 consumer fixtures. Never reads operator state or contacts a server."""
import argparse
import shutil
import sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scripts.projection_fixture_support import *
from scripts.projection_lg1_support import source,add_legacy,DID as LEGACY_DID
from scout_projection_source import map_raw
from scout_projection_compact import convert_bundle
from scout_projection import initialize,Projector


def create(root,local=()):
    path=root/'projection.sqlite'
    initialize(path,epoch='source-epoch',router_source_id='router',router_epoch='router-epoch',router_did='did:key:z6MkRouter',local_dids=local,contract_revision=LG2_REVISION)
    return Projector(path)


_original_bundle=bundle
def bundle(*args,**kwargs):return convert_bundle(_original_bundle(*args,**kwargs))

from scout_projection_publish import publish,validate_database,file_hash,atomic_json


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True);args=parser.parse_args()
    root=args.root.resolve();require(root.is_relative_to(Path('/private/tmp')),'Temporary root required');require(not root.exists(),'Refuse overwrite');root.mkdir()
    index={}
    def save(p,name,when=NOW):
        result=publish(p,root/name,checked_cut=p.status()['source_cut'],evaluated_at=when)
        revision_binding(result['manifest']);validate_database(root/name/result['manifest']['database'],contract_revision=LG2_REVISION)
        index[name]=dict(current=str(root/name/'current.json'),expected='ACCEPT',manifest=result['pointer']['manifest'],revision=LG2_REVISION)
        return result
    with create(root/'normal-state',local=[DID,'did:key:z6MkBench']) as p:
        apply(p,[bundle()]);empty_pins(p);first=save(p,'normal-concrete')
        shutil.copytree(root/'normal-concrete',root/'heartbeat-reuse');second=save(p,'heartbeat-reuse',plus(NOW,1))
        require(second['manifest']['publication_kind']=='HEARTBEAT' and first['manifest']['database']==second['manifest']['database'],'Invalid heartbeat fixture')
        request=dict(schema_version='flop-verification-request/v1',request_id='lg2-fixture-request',target_agent_did=DID,requester_did=DID,routing_decision_id='fixture-decision',routing_decision_hash='1'*64,task_hash='2'*64,independent_reputation=False)
        result=dict(schema_version='flop-verification-result/v1',request_id='lg2-fixture-request',bench_did='did:key:z6MkBench',status='PASS',artifact_hashes=dict(request_sha256=digest(request)),reproducibility='DETERMINISTIC',independent_reputation=False)
        refs=[p.import_artifact(name,canonical(obj),source_id='scout-verification',epoch='fixture-epoch',authority='CONTROLLED_BENCH',observed_at=plus(NOW,2)) for name,obj in [('request',request),('result',result)]]
        p.qualify_local_bench(*refs,evaluated_at=plus(NOW,3));save(p,'same-operator-bench',plus(NOW,4))
        original=next(q for q in quals(p) if q['source_ref']['id']=='sm1:raw-1')
        p.append_event(invalidation(p,original['qualification_id'],plus(NOW,5)));save(p,'qualification-invalidation',plus(NOW,6))
        p.replay_to(root/'normal-replayed'/'projection.sqlite')
    for report in ('0','1'):
        c=source(root/f'legacy-{report}-source.sqlite');rid=add_legacy(c,report=report,protocol_cache=True)
        with create(root/f'legacy-{report}-state',local=[LEGACY_DID]) as p:
            apply(p,[map_raw(c,rid,[LEGACY_DID],revision=LG2_REVISION)]);empty_pins(p);result=save(p,'legacy-reported-'+report)
            p.replay_to(root/f'legacy-{report}-replayed'/'projection.sqlite')
        if report=='0':
            shutil.copytree(root/'legacy-reported-0',root/'multiple-same-generation-witnesses')
            index['multiple-same-generation-witnesses']=dict(index['legacy-reported-0'],current=str(root/'multiple-same-generation-witnesses'/'current.json'))
            # Deliberately corrupt an audit report, then recompute artifact hashes.
            # This tests semantic rejection despite self-consistent publication hashes.
            invalid=root/'true-conflict';invalid.mkdir();manifest=dict(result['manifest'])
            temp=invalid/'invalid.sqlite';shutil.copyfile(root/'legacy-reported-0'/manifest['database'],temp)
            with connect(temp) as db:
                # Contradict the captured generation while retaining a legacy report.
                db.execute("UPDATE messages SET generation='0'")
            try:validate_database(temp,contract_revision=LG2_REVISION)
            except ProjectionError:pass
            else:raise AssertionError('Conflict fixture was accepted')
            h=file_hash(temp);name=f'router-projection-v2-1-{h}.sqlite';temp.rename(invalid/name)
            manifest.update(database=name,sha256=h,size_bytes=(invalid/name).stat().st_size)
            mh=digest(manifest);mn=f'manifest-v2-1-{mh}.json';atomic_json(invalid,mn,manifest)
            atomic_json(invalid,'current.json',dict(schema='flop-scout-router-current/v2',manifest=mn,manifest_sha256=mh,published_at=NOW),False)
            index['true-conflict']=dict(current=str(invalid/'current.json'),expected='REJECT',reason='concrete captured generation contradicts legacy report; hashes intentionally valid',revision=LG2_REVISION)
        c.close()
    with create(root/'unknown-state') as p:
        apply(p,[bundle(text='ordinary synthetic context',generation='UNKNOWN_LEGACY')]);empty_pins(p);save(p,'unknown-without-lg2')
    (root/'index.json').write_bytes(canonical(dict(schema='scout-lg2-development-fixtures/v1',fixtures=index,production_usable=False,clock=NOW,notes='Synthetic public identities and controlled local authority premises; no real signatures. Inject fixed clock for consumer freshness. Private replay/source originals are included only under this temporary root.'))+b'\n')
    print(root/'index.json')


if __name__=='__main__':main()
