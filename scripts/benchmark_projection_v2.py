#!/usr/bin/env python3
"""Post-A1 synthetic sizing. Never opens an observer or production path.

Materializes exact published rows with 10% concrete-support messages, all
qualifying capability witnesses per such message, and audit events for 1% of messages. This measures storage/backup/validation, not warehouse ingest.
Each capability group has one distinct sender/template, so duplicate suppression
cannot manufacture a historical prefix success. Update timing separately exercises
the Projector API over complete 200-row cuts.
"""
from pathlib import Path
import argparse
import hashlib
import json
import resource
import sqlite3
import sys
import time
from dataclasses import asdict
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from scout_projection_contract import *
from scout_projection_model import validate_qualification
from scout_projection_publish import validate_database,file_hash
from scout_projection import initialize,Projector
import scout_projection_rules as rules
from projection_fixture_support import bundle,apply,NOW,TEXT


def timed(fn):
    start=time.perf_counter();value=fn();return value,time.perf_counter()-start


def materialize(path,count):
    conn=sqlite3.connect(str(path));conn.executescript(SQL);conn.execute('PRAGMA journal_mode=DELETE');conn.execute('PRAGMA synchronous=FULL');conn.execute('PRAGMA cache_size=-16384')
    conn.execute('INSERT INTO snapshot_meta VALUES(1,?,?,?,?)',(SCHEMA,'1',NOW,POLICY_SHA));conn.commit()
    started=time.perf_counter();ann=canonical(dict(ANNOTATIONS,classification='UNCLASSIFIED')).decode();last=None;audit_bytes=0;event_bytes=0
    for start in range(1,count+1,200):
        messages=[];provenance=[];membership=[];qualifications=[];events=[]
        for n in range(start,min(start+200,count+1)):
            text=(TEXT+' Diagnostic specimen '+str(n)+'. '+('Recorded a bounded local test input. '*12)) if n%10==0 else ('Neighbours described the weather and their afternoon walk through the garden. '*10)+' Conversation '+str(n)+'.'
            rid='sm1:benchmark-'+str(n);h=text_hash(text);did='did:key:z6MkSynthetic'+str(n).replace('0','z');evidence='benchmark-evidence-'+str(n)
            msg=dict(projection_row_id=rid,room='synthetic-room',generation='UNKNOWN_LEGACY' if n%20==0 else '0',seq=n,timestamp=None,sender=did,signed=1,text=text,normalized_text=rules.normalize_text(text),template_normalized_hash=h,nonce=None,sig=None,message_hash=h,verification_status='LEGACY_SERVER_VERIFIED_NO_SIGNATURE',source_export_hash=None,source_export_path=None,evidence_id=evidence)
            messages.append(tuple(msg.values()));provenance.append(('message',rid,'benchmark-source','benchmark-'+str(n),str(n),'benchmark-'+str(n),None,ann))
            membership.append(('message',rid,'NEGATIVE_EVIDENCE' if n%100==0 else 'CAPABILITY_SUPPORT' if n%10==0 else 'CONTEXT',NOW,None if n%10==0 else plus(NOW,2592000),'[]'))
            if n%10==0:
                ref=dict(kind='PROJECTED_MESSAGE',source_id='scout-observer',source_epoch='benchmark-epoch',id=rid,sha256=h)
                group=[dict(source_ref=ref,duplicate_count=1,template_dids=1)]
                obs=rules.AgentObservation(identity=rules.AgentIdentity(did),room=msg['room'],sequence_id=n,timestamp=None,text=text,normalized_text=rules.normalize_text(text),template_hash=h,is_signed=True,generation=msg['generation'],message_hash=h,evidence_id=evidence)
                decisions=[rules.capability_evidence_decisions([obs],rule.capability_id)[0] for rule in rules.CAPABILITY_RULES]
                decisions=[d for d in decisions if d.passed_threshold and d.support_contribution in {'LIMITED','STRONG'}]
                require(decisions,'Synthetic concrete source did not qualify')
                current=dict(ANNOTATIONS,classification='UNCLASSIFIED',capability_support=sorted([dict(capability_id=d.capability_id,classification=d.support_contribution,evidence_id=evidence) for d in decisions],key=canonical))
                provenance[-1]=(*provenance[-1][:-1],canonical(current).decode())
                for decision in decisions:
                    rule_input=dict(rule_id='capability_evidence_decisions:'+decision.capability_id,observation={k:v for k,v in asdict(obs).items() if k!='text'},text_ref=ref,output=asdict(decision))
                    q=dict(schema='router-durable-qualification/v1',source_ref=ref,scout_event_id=str(n),evidence_id=evidence,subject_did=did,claim=dict(kind='CAPABILITY',id=decision.capability_id),qualification_type='CAPABILITY_USE',qualification_outcome=decision.support_contribution,qualified_at=NOW,policy_version=POLICY['version'],policy_sha256=POLICY_SHA,classifier_version=POLICY['classifier_version'],qualification_policy_version=POLICY['qualification_policy_version'],bootstrap_id='benchmark-bootstrap',evaluation_id='benchmark-complete-cut',source_cut=dict(source_id='scout-observer',epoch='benchmark-epoch',committed_event_id=str(count)),rule_id='capability_evidence_decisions:'+decision.capability_id,rule_input_sha256=digest(rule_input),rule_group_sha256=digest(group),provenance_refs=[ref],operator_group=None,same_operator=None,independent_reputation=None,authenticity='LEGACY_SERVER_VERIFIED_NO_SIGNATURE',correctness=None,reproducibility=None,initial_status='VALID')
                    q['qualification_id']=identity('dq1',q);encoded=canonical(q).decode();qualifications.append((q['qualification_id'],encoded));audit_bytes+=len(encoded.encode())
                    if n%100==0:
                        e=dict(schema='router-qualification-event/v1',qualification_id=q['qualification_id'],sequence=1,previous_event_sha256=None,event_type='INVALIDATED',recorded_at=NOW,reason_code='SIGNATURE_PROVENANCE_FAILURE',proof_refs=[ref],authority_ref=dict(kind='LOCAL_ARTIFACT',source_id='synthetic-local-audit',source_epoch='benchmark-epoch',id='audit-'+str(n),sha256=digest(dict(qualification_id=q['qualification_id'],reason_code='SIGNATURE_PROVENANCE_FAILURE'))),superseded_by=None,qualification_policy_version=POLICY['qualification_policy_version'])
                        e['event_id']=identity('dqe1',e);encoded=canonical(e).decode();events.append((e['event_id'],q['qualification_id'],1,encoded));event_bytes+=len(encoded.encode())
            last=msg
        with conn:
            conn.executemany('INSERT INTO messages VALUES('+','.join('?' for _ in range(17))+')',messages)
            conn.executemany('INSERT INTO source_provenance VALUES(?,?,?,?,?,?,?,?)',provenance)
            conn.executemany('INSERT INTO selection_membership VALUES(?,?,?,?,?,?)',membership)
            conn.executemany('INSERT INTO durable_qualifications VALUES(?,?)',qualifications)
            conn.executemany('INSERT INTO qualification_events VALUES(?,?,?,?)',events)
        if start%100000==1:print(json.dumps(dict(progress_rows=start,elapsed_seconds=round(time.perf_counter()-started,2))),flush=True)
    with conn:
        conn.execute('INSERT INTO watermarks SELECT room,generation,count(*),min(seq),max(seq) FROM messages GROUP BY room,generation')
        conn.row_factory=sqlite3.Row
        for row in conn.execute('SELECT m.* FROM messages m JOIN watermarks w ON w.room=m.room AND w.generation=m.generation AND w.max_seq=m.seq'):
            conn.execute('INSERT INTO coverage_history VALUES(?,?,?,?,?)',(row['room'],row['generation'],row['seq'],'benchmark-'+str(row['seq']),digest(dict(row))))
    elapsed=time.perf_counter()-started
    index_bytes=conn.execute("SELECT coalesce(sum(pgsize),0) FROM dbstat WHERE name IN (SELECT name FROM sqlite_master WHERE type='index')").fetchone()[0]
    audit_pages={r[0]:r[1] for r in conn.execute("SELECT name,sum(pgsize) FROM dbstat WHERE name IN ('durable_qualifications','qualification_events') GROUP BY name")}
    conn.close();return dict(materialization_seconds=elapsed,materialized_rows_per_second=count/elapsed,index_bytes=index_bytes,audit_table_bytes=audit_pages,qualification_json_bytes=audit_bytes,event_json_bytes=event_bytes)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--root',type=Path,required=True);parser.add_argument('--rows',type=int,required=True);args=parser.parse_args()
    root=args.root.resolve();require(str(root).startswith('/private/tmp/'),'Benchmark requires /private/tmp temporary state');root.mkdir(parents=True,exist_ok=True)
    path=root/f'projection-{args.rows}.sqlite';require(not path.exists(),'Benchmark refuses overwrite')
    results=materialize(path,args.rows);results.update(rows=args.rows,size_bytes=path.stat().st_size,bytes_per_row=path.stat().st_size/args.rows)
    def backup():
        src=sqlite3.connect(str(path));dest=sqlite3.connect(str(root/f'backup-{args.rows}.sqlite'))
        try:src.backup(dest,pages=256);dest.commit()
        finally:src.close();dest.close()
    _,results['online_backup_seconds']=timed(backup)
    def integrity():
        with sqlite3.connect(str(path)) as c:require(c.execute('PRAGMA integrity_check').fetchall()==[('ok',)],'Integrity failure')
    _,results['integrity_check_seconds']=timed(integrity)
    results['sha256'],results['sha256_seconds']=timed(lambda:file_hash(path))
    details,results['full_contract_validation_seconds']=timed(lambda:validate_database(path))
    results['row_counts']=details['row_counts'];results['readiness']=readiness(path.stat().st_size)
    # Actual producer update and expiry API on separate temporary state.
    state=root/f'producer-{args.rows}.sqlite'
    initialize(state,epoch='bench',router_source_id='router',router_epoch='router',router_did='did:key:z6MkRouter')
    with Projector(state) as p:
        apply(p,[])
        rows=[bundle(n,text='ordinary conversation '+str(n),sender='did:key:z6MkSender'+str(n)) for n in range(1,201)]
        _,update_time=timed(lambda:apply(p,rows,plus(NOW,1),'SOURCE_BATCH'))
        _,expiry_time=timed(lambda:apply(p,[],plus(NOW,2592001),'EXPIRY',cut='200'))
        require(p.conn.execute('SELECT count(*) FROM projection.messages').fetchone()[0]==0,'Expiry probe did not actually remove its 200 rows')
        results['incremental_update_rows_per_second']=200/update_time;results['expiry_rows_per_second']=200/expiry_time
        results['incremental_probe_rows']=200
    results['peak_rss_bytes']=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    results['assumptions']=dict(qualified_message_fraction=.10,audited_message_fraction=.01,normalized_text_fraction=1.0,all_qualifying_capabilities=True,full_text_copies_per_message=1,synthetic=True,authority_artifacts='Synthetic opaque references; not deployable audit attestations',update_probe='Actual producer API on separate 200-row complete cut; not a million-row steady-state throughput claim')
    (root/'results.json').write_bytes(canonical(results)+b'\n');print(json.dumps(results,indent=2),flush=True)


if __name__=='__main__':main()
