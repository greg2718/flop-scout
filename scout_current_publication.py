"""Bounded current-only source enrollment; never opens a historical projection.

Run as a separate process. Live evidence is read-only in short transactions.
The existing A1 producer and Router validator retain their unchanged semantics.
"""
from __future__ import annotations
import argparse
from contextlib import closing
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time

from scout_projection_contract import canonical, digest, require, utc, instant

LOCAL_DIDS = (
 'did:key:z6MkfJnczowbivU9SEDcZ77MEpKUfQTVbcD3i1gcwsfo4yL1',
 'did:key:z6MkqqqEMxujBTEAvoanSx6pVBMMZzLP7gMUcmNVdYHS3BVk',
 'did:key:z6MkpGs1L6fYEsaXsDfyDfrTxbKVeZ3evuPaBj2x38KzupPd')
TABLES=('raw_network_records','observed_events','messages','evidence_records',
 'tclk_frames','kibble_events','compatibility_evidence_links','evidence_export_snapshots',
 'evidence_retrievals','interactions')
CLASSES=('IDENTITY_PRESENCE','CAPABILITY_CLAIM','VERIFICATION_REQUEST','VERIFICATION_RESULT',
 'WORK_REQUEST','WORK_ACCEPTANCE','WORK_RESULT','TCLK_TRANSCRIPT_EVENT','KIBBLE_JOB',
 'KIBBLE_CLAIM','KIBBLE_RESULT','KIBBLE_ATTESTATION','OFFICIAL_NETWORK_ANNOUNCEMENT',
 'MALFORMED_UNVERIFIABLE_EVENT')
MAX_RECORDS=50000


def atomic(path,value):
    temp=path.with_name('.'+path.name+'.tmp')
    with temp.open('wb') as f:f.write(canonical(value));f.flush();os.fsync(f.fileno())
    os.replace(temp,path)
    fd=os.open(path.parent,os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)


class Source:
    def __init__(self,path):
        require(path.is_absolute() and not path.is_symlink(),'Explicit regular source path required')
        self.conn=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=.1)
        self.conn.row_factory=sqlite3.Row
        self.conn.execute('PRAGMA query_only=ON');self.conn.execute('PRAGMA cache_size=-4096')
        self.deadline=0;self.calls=0
        self.conn.set_progress_handler(lambda:int(time.monotonic()>self.deadline),1000)
    def rows(self,sql,args=()):
        self.deadline=time.monotonic()+1;self.calls+=1
        return self.conn.execute(sql,args).fetchall()
    def close(self):self.conn.close()


def insert_rows(dst,table,rows):
    for r in rows:
        r=dict(r);cols=list(r)
        dst.execute('INSERT OR IGNORE INTO '+table+' ('+','.join(cols)+') VALUES ('+','.join('?' for _ in cols)+')',tuple(r.values()))


def extract(source,path,when,limit,pins):
    require(1<=limit<=25000,'Current admission cap must be 1..25000; closure cap is 50000')
    cutoff=instant(when)-timedelta(days=7)
    cut=source.rows('SELECT coalesce(max(event_id),0) FROM observed_events')[0][0]
    candidates={};scanned=0
    def collect(rows):
        nonlocal scanned
        scanned+=len(rows);require(scanned<=50000,'Candidate scan budget exceeded')
        for r in rows:
            r=dict(r)
            stamp=r.get('parsed_at')
            if stamp and datetime.fromisoformat(stamp.replace('Z','+00:00'))>=cutoff:candidates[r['raw_record_id']]=r
    # Cover rare semantic classes before recent ambient traffic. Every query
    # uses an existing bounded B-tree range, never an unindexed time scan.
    for cls in CLASSES:
        collect(source.rows('SELECT event_id,raw_record_id,parsed_at FROM observed_events INDEXED BY event_class WHERE classification=? AND event_id<=? ORDER BY event_id DESC LIMIT 1000',(cls,cut)))
    preferred=sorted(candidates,key=lambda k:(-candidates[k]['event_id'],k))[:limit]
    collect(source.rows('SELECT event_id,raw_record_id,parsed_at FROM observed_events WHERE event_id<=? ORDER BY event_id DESC LIMIT 10000',(cut,)))
    chosen=list(dict.fromkeys(preferred+sorted(candidates,key=lambda k:(-candidates[k]['event_id'],k))))[:limit]
    required=set()
    for pin in pins['pins']:
        for ref in pin['evidence_refs']+pin['dependency_refs']:
            if ref['kind']=='RAW_RECORD':required.add(ref['id'])
            elif ref['kind'] in ('MESSAGE','PROJECTED_MESSAGE'):
                require(ref['id'].startswith('sm1:'),'Unsupported pinned message identity');required.add(ref['id'][4:])
            elif ref['kind']=='SCOUT_EVENT':
                rows=source.rows('SELECT raw_record_id FROM observed_events WHERE event_id=?',(int(ref['id']),));require(len(rows)==1,'Missing pinned event');required.add(rows[0][0])
            else:raise ValueError('Explicit pinned dependency resolver required for '+ref['kind'])
    # Include latest public evidence for the configured local operator family.
    for did in LOCAL_DIDS:
        for r in source.rows('SELECT raw_record_id FROM raw_network_records INDEXED BY raw_did WHERE sender_did=? ORDER BY retrieved_at DESC LIMIT 64',(did,)):
            required.add(r[0])
    # A bounded authoritative-root reserve allows recent workflow transitions
    # to retain roots outside the seven-day ambient window.
    roots=[]
    for typ in ('offer','accept','lock','settle','cancel','refund'):
        rows=source.rows("SELECT id FROM tclk_frames INDEXED BY idx_tclk_frames_type WHERE frame_type=? AND parse_status='TCLK_PARSEABLE' ORDER BY id DESC LIMIT 500",(typ,))
        for r in rows:
            roots.extend(source.rows("SELECT raw_record_id FROM compatibility_evidence_links WHERE cache_table='tclk_frames' AND cache_rowid=?",(r[0],)))
    required.update(r[0] for r in roots)
    chosen=sorted(set(chosen)|required)
    require(len(chosen)<=MAX_RECORDS,'Required dependency capacity exceeded')
    dst=sqlite3.connect(path);dst.row_factory=sqlite3.Row
    for table in TABLES:
        ddl=source.rows("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(table,))
        require(len(ddl)==1,'Missing source table '+table);dst.execute(ddl[0][0])
    dst.executescript('CREATE INDEX current_links ON compatibility_evidence_links(raw_record_id,cache_table); CREATE INDEX current_raw_position ON raw_network_records(room,generation,seq); CREATE INDEX current_tclk_offer ON tclk_frames(offer_id); CREATE INDEX current_tclk_contract ON tclk_frames(contract_id); CREATE INDEX current_kibble_job ON kibble_events(job_id,event_type);')
    kept,excluded,copied_bytes=copy_records(source,dst,chosen,cut,required,pins)
    # Point-bounded interaction tail; include only exact endpoints represented
    # in the extract, so no historical interaction scan or guessed generation.
    edges=source.rows('SELECT * FROM interactions ORDER BY id DESC LIMIT 2000')
    from scout_projection_source import resolve_interaction
    unresolved=0
    for edge in edges:
        try:resolve_interaction(dst,dict(edge))
        except ValueError:unresolved+=1;continue
        insert_rows(dst,'interactions',[edge])
    dst.commit();dst.close()
    return dict(source_cut=str(cut),selected=len(kept),candidate_rows=scanned,
        excluded_historical=excluded,unresolved_interactions=unresolved,source_payload_bytes=copied_bytes,
        cutoff=utc(cutoff),evaluated_at=when,raw_ids_sha256=digest(kept),source_queries=source.calls)


def copy_records(source,dst,chosen,cut,required=(),pins=None):
    pins=pins or {'pins':[]}
    kept=[];excluded=0;copied_bytes=0
    for rid in chosen:
        raw=source.rows('SELECT * FROM raw_network_records WHERE raw_record_id=?',(rid,))
        event=source.rows('SELECT * FROM observed_events WHERE raw_record_id=? AND event_id<=?',(rid,cut))
        require(raw and event,'Incomplete committed source dependency')
        raw=dict(raw[0]);event=dict(event[0])
        current=raw['raw_text'] is not None and (not raw['legacy_record'] or rid in required)
        if not current:
            require(rid not in required or rid not in {ref['id'].removeprefix('sm1:') for p in pins['pins'] for ref in p['evidence_refs']+p['dependency_refs']},'Pinned dependency requires parked historical qualification')
            excluded+=1;continue
        copied_bytes+=len(canonical(raw))+len(canonical(event));require(copied_bytes<=128*1024**2,'Source payload byte budget exceeded')
        insert_rows(dst,'raw_network_records',[raw]);insert_rows(dst,'observed_events',[event]);kept.append(rid)
        # Legacy reserve keeps exact original raw evidence as UNKNOWN_LEGACY.
        # Do not borrow a reported cache generation or activate LG1/LG2/TL1.
        for table in (() if raw['legacy_record'] else ('messages','evidence_records','tclk_frames','kibble_events')):
            sql='SELECT rowid AS rowid,* FROM '+table+' WHERE room=? AND seq=?'
            args=(raw['room'],raw['seq'])
            if table!='messages':sql+=' AND generation=?';args+=(raw['generation'],)
            # All four lookups use existing room/sequence unique indexes.
            for cache in source.rows(sql+' LIMIT 4',args):
                link=source.rows('SELECT * FROM compatibility_evidence_links WHERE cache_table=? AND cache_rowid=? AND raw_record_id=?',(table,cache['rowid'],rid))
                if link:
                    insert_rows(dst,table,[cache]);insert_rows(dst,'compatibility_evidence_links',link)
        metadata=json.loads(raw['transport_metadata_json'])
        if metadata.get('snapshot_id'):
            insert_rows(dst,'evidence_export_snapshots',source.rows('SELECT * FROM evidence_export_snapshots WHERE snapshot_id=?',(metadata['snapshot_id'],)))
        if len(kept)%50==0:dst.commit()
    dst.commit()
    return kept,excluded,copied_bytes


def current_bundle(source,rid):
    """A1 current source adapter: missing roots remain unresolved, never closed."""
    from scout_projection_source import map_raw,observed_time,exact_cache,generation
    from scout_projection_contract import annotation_template,annotations,text_hash
    from scout_projection_model import workflow_identity
    try:return map_raw(source,rid,LOCAL_DIDS,'A1')
    except ValueError as exc:
        if str(exc)!='Authenticated TCLK transition has no authoritative offer root':raise
    raw=dict(source.execute('SELECT * FROM raw_network_records WHERE raw_record_id=?',(rid,)).fetchone())
    event=source.execute('SELECT event_id FROM observed_events WHERE raw_record_id=?',(rid,)).fetchone()
    verified=exact_cache(source,'evidence_records',raw,'A1')
    msg=dict(projection_row_id='sm1:'+rid,room=raw['room'],generation=generation(raw['generation']),
        seq=raw['seq'],timestamp=raw['network_timestamp'],sender=raw['sender_did'],signed=1,
        text=raw['raw_text'],normalized_text=None,template_normalized_hash=None,nonce=raw['nonce'],
        sig=raw['signature'],message_hash=text_hash(raw['raw_text']),
        verification_status=verified['verification_status'] if verified else None,
        source_export_hash=None,source_export_path=None,evidence_id=verified['evidence_id'] if verified else None)
    ann=annotation_template('A1');ann['classification']='TCLK_TRANSCRIPT_EVENT'
    if msg['sender'] in LOCAL_DIDS:ann.update(operator_group='local-flop-agent-family',same_operator=True,independent_reputation=False)
    wid,ident=workflow_identity('scout-unresolved/v1',msg['sender'],msg['room'],msg['generation'],
        'raw_record_id',rid,namespace=raw['source'])
    workflow=dict(id=wid,identity=ident,role='ROOT',root_id=msg['projection_row_id'],result_id=None,
        authenticated=raw['signature_status']=='VERIFIED_OFFLINE',deadline_ms=None,terminal=None)
    return dict(message=msg,provenance=dict(entity_type='message',projection_row_id=msg['projection_row_id'],
        source_namespace=raw['source'],source_record_locator=rid,scout_event_id=str(event[0]),
        raw_record_id=rid,raw_record_sha256=None,annotations_json=canonical(annotations(ann,'A1')).decode()),
        first_observed_at=observed_time(raw['created_at']),facts=dict(signature_failure=raw['signature_status']=='FAILED',
        did_mismatch=bool(raw['did_mismatch']),identity_binding=False,official=False,
        operator_local=msg['sender'] in LOCAL_DIDS,workflow=workflow),dependencies=[])


def generate(source_path,work,root,router_state,pins_path=None,limit=25000):
    from scout_projection import initialize,Projector
    from scout_projection_source import map_raw,resolve_interaction
    from scout_projection_pins import import_pins
    from scout_projection_publish import publish
    started=time.monotonic();when=utc()
    for path in (work,root):
        require(path.is_absolute() and not path.is_symlink(),'Absolute non-symlink output required')
        path.mkdir(parents=True,exist_ok=True)
    require(work.resolve()!=root.resolve(),'Separate private state and publication root required')
    with (work/'owner.lock').open('a+b') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        state=json.loads(router_state.read_text())
        if pins_path:pins=json.loads(pins_path.read_text())
        else:
            require(not state.get('last_accepted_projection_v2') and not state.get('last_accepted_snapshot'),'Existing Router publication requires cumulative pin export')
            require(not state.get('scout_contract'),'Existing Router contract requires explicit pins')
            pins=dict(schema='flop-router-projection-pins/v1',source_id='router-current-shadow',epoch='initial-current-shadow',revision='0',produced_at=when,previous_sha256=None,pins=[])
            pins['content_sha256']=digest(pins)
        # An existing plan is immutable: interrupted builds resume the same cut.
        plan_path=work/'plan.json';extract_path=work/'current-source.sqlite'
        if plan_path.exists():plan=json.loads(plan_path.read_text());when=plan['evaluated_at'];pins=json.loads((work/'pins.json').read_text())
        else:
            require(not (root/'current.json').exists(),'New enrollment requires a fresh publication root')
            require(not (work/'projection.sqlite').exists() and not (work/'projection.sqlite.ledger').exists(),'Refuse pre-existing projection without a bounded plan')
            extract_path.unlink(missing_ok=True)
            src=Source(source_path)
            try:plan=extract(src,extract_path,when,limit,pins)
            finally:src.close()
            plan.update(source_path=str(source_path),router_state_sha256=digest(state),pins_sha256=pins['content_sha256'])
            atomic(work/'pins.json',pins);atomic(plan_path,plan)
        epoch='bounded-current-'+digest(plan)[:24];projection=work/'projection.sqlite'
        if not projection.exists():initialize(projection,epoch=epoch,source_id='scout-current-bounded',router_source_id=pins['source_id'],router_epoch=pins['epoch'],router_did=LOCAL_DIDS[2],local_dids=LOCAL_DIDS,contract_revision='A1')
        with closing(sqlite3.connect(projection.with_suffix('.sqlite.ledger').as_uri()+'?mode=ro',uri=True)) as probe:
            config=json.loads(probe.execute('SELECT json FROM configuration').fetchone()[0])
            require(config['source_id']=='scout-current-bounded' and config['epoch']==epoch and config['contract_revision']=='A1','Refuse historical or mismatched projection')
        with Projector(projection) as p, closing(sqlite3.connect(extract_path)) as source:
            source.row_factory=sqlite3.Row
            if not p.get('source_cut'):
                pending=p.conn.execute("SELECT number,status FROM evaluations WHERE status!='COMPLETE'").fetchone()
                n=pending['number'] if pending else p.begin(plan['source_cut'],when,'BOOTSTRAP')
                if pending is None or pending['status']=='STAGING':
                    batch=[]
                    for row in source.execute('SELECT raw_record_id FROM observed_events ORDER BY event_id'):
                        b=current_bundle(source,row[0])
                        if b is not None:batch.append(b)
                        if len(batch)==50:p.stage(n,batch);batch=[]
                    if batch:p.stage(n,batch)
                    edges=[resolve_interaction(source,dict(r)) for r in source.execute('SELECT * FROM interactions ORDER BY id')]
                    for start in range(0,len(edges),50):p.stage_edges(n,edges[start:start+50])
                    p.seal(n)
                else:p.resume(n)
            import_pins(p,canonical(pins),now=when)
            result=publish(p,root,checked_cut=p.status()['source_cut'],evaluated_at=when)
            latest=source.execute('SELECT max(created_at) FROM raw_network_records').fetchone()[0]
            report=dict(publication_root=str(root),database=str(root/result['manifest']['database']),
                record_count=result['manifest']['row_counts']['messages'],row_counts=result['manifest']['row_counts'],
                time_horizon='7 days, class-stratified <=25000 ambient records; <=50000 including bounded root/identity/pin reserve',
                size_bytes=result['manifest']['size_bytes'],generation_seconds=time.monotonic()-started,
                latest_evidence_at=latest,latest_evidence_age_seconds=(datetime.now(timezone.utc)-datetime.fromisoformat(latest.replace('Z','+00:00'))).total_seconds(),
                source_selection=plan,contract_revision='A1',pin_count=len(pins['pins']),ready=True)
            atomic(work/'result.json',report);return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source','work','root','router-state'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--pins',type=Path);parser.add_argument('--limit',type=int,default=25000)
    args=parser.parse_args()
    print(json.dumps(generate(args.source,args.work,args.root,args.router_state,args.pins,args.limit),indent=2))


if __name__=='__main__':main()
