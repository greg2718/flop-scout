"""Synthetic local-only development inputs; no identity or network access."""
from scout_projection_contract import *
from scout_projection_model import *
from scout_projection import Projector,initialize
from scout_projection_pins import import_pins

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

def invalidation(p,qid,when=plus(NOW,1)):
    proof=p.source_ref('sm1:raw-1')
    directive=dict(schema='flop-scout-qualification-directive/v1',verifier_version='fixture-signature-audit/v1',qualification_id=qid,event_type='INVALIDATED',reason_code='SIGNATURE_PROVENANCE_FAILURE',proof_refs=[proof],superseded_by=None)
    authority=p.import_artifact('audit-1',canonical(directive),source_id='scout-audit',epoch='audit-epoch',authority='AUDIT_DIRECTIVE',observed_at=when)
    event=dict(schema='router-qualification-event/v1',qualification_id=qid,sequence=1,previous_event_sha256=None,event_type='INVALIDATED',recorded_at=when,reason_code='SIGNATURE_PROVENANCE_FAILURE',proof_refs=[proof],authority_ref=authority,superseded_by=None,qualification_policy_version=POLICY['qualification_policy_version'])
    event['event_id']=identity('dqe1',event);return event
