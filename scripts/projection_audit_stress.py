"""Small real-producer duplicate/supersession stress case, entirely temporary."""
import sys,time,json
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from projection_fixture_support import *
from scout_projection_publish import publish
root=Path(sys.argv[1]).resolve();require(str(root).startswith('/private/tmp/'),'Temporary state required');require(not root.exists(),'Refuse overwrite')
start=time.perf_counter()
with create(root/'duplicate') as p:
    apply(p,[bundle()]);first=len(quals(p));before=p.path.stat().st_size
    apply(p,[bundle(n) for n in range(2,202)],plus(NOW,1),'SOURCE_BATCH')
    duplicate=dict(messages=p.conn.execute('SELECT count(*) FROM projection.messages').fetchone()[0],qualifications_before=first,qualifications_after=len(quals(p)),projection_bytes=p.path.stat().st_size,ledger_bytes=p.ledger.stat().st_size,initial_projection_bytes=before)
    assert duplicate['qualifications_after']==first
with create(root/'supersession') as p:
    apply(p,[bundle(n,text=TEXT+' Diagnostic case '+str(n)) for n in range(1,51)])
    witnesses=sorted([q for q in quals(p) if q['claim']['id']=='software.debugging'],key=lambda q:int(q['scout_event_id']))
    assert len(witnesses)==50
    for number,(old,new) in enumerate(zip(witnesses,witnesses[1:]),1):
        proofs=sorted([old['source_ref'],new['source_ref']],key=canonical)
        directive=dict(schema='flop-scout-qualification-directive/v1',verifier_version='synthetic-preference-audit/v1',qualification_id=old['qualification_id'],event_type='SUPERSEDED',reason_code='NEW_QUALIFICATION',proof_refs=proofs,superseded_by=new['qualification_id'])
        authority=p.import_artifact('supersession-'+str(number),canonical(directive),source_id='scout-audit',epoch='audit-epoch',authority='AUDIT_DIRECTIVE',observed_at=plus(NOW,number))
        event=dict(schema='router-qualification-event/v1',qualification_id=old['qualification_id'],sequence=1,previous_event_sha256=None,event_type='SUPERSEDED',recorded_at=plus(NOW,number),reason_code='NEW_QUALIFICATION',proof_refs=proofs,authority_ref=authority,superseded_by=new['qualification_id'],qualification_policy_version=POLICY['qualification_policy_version'])
        event['event_id']=identity('dqe1',event);p.append_event(event)
    empty_pins(p);published=publish(p,root/'supersession-publication',checked_cut=p.status()['source_cut'],evaluated_at=plus(NOW,51))
    assert p.conn.execute("SELECT count(*) FROM projection.selection_membership WHERE retention_class='NEGATIVE_EVIDENCE'").fetchone()[0]==0
    supersession=dict(messages=50,qualifications=len(quals(p)),qualification_events=49,projection_bytes=p.path.stat().st_size,ledger_bytes=p.ledger.stat().st_size,publication_bytes=published['manifest']['size_bytes'])
    p.replay_to(root/'replayed'/'projection.sqlite')
results=dict(duplicate=duplicate,supersession=supersession,elapsed_seconds=time.perf_counter()-start,synthetic=True)
(root/'results.json').write_bytes(canonical(results)+b'\n');print(json.dumps(results,indent=2))
