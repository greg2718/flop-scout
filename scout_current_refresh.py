"""Scheduled bounded-current refresh; no historical projector or live Scout writes."""
from __future__ import annotations
import argparse
from contextlib import closing
from datetime import datetime,timezone,timedelta
import fcntl
import json
from pathlib import Path
import sqlite3
import signal
import time
from scout_current_publication import Source,CLASSES,atomic,copy_records,current_bundle
from scout_projection_contract import require,utc,instant,digest,canonical

CADENCE=600
MAX_NEW=256
MAX_ENROLLED=50000
MAX_WORK_BYTES=512*1024**2
MAX_CAPTURE_AGE=600


def manifest(root):
    pointer=json.loads((root/'current.json').read_text())
    name=pointer['manifest']
    require(Path(name).name==name,'Invalid current manifest path')
    raw=(root/name).read_bytes()
    import hashlib
    require(hashlib.sha256(raw).hexdigest()==pointer['manifest_sha256'],'Current manifest hash mismatch')
    return json.loads(raw)


def refresh(source_path,work,root,*,now=None,fail=None):
    from scout_projection import Projector
    from scout_projection_publish import publish,retain
    started=time.monotonic();when=now or utc()
    require(all(p.is_absolute() and not p.is_symlink() for p in (source_path,work,root)),'Explicit nonsymlink paths required')
    plan=json.loads((work/'plan.json').read_text())
    require(plan['source_path']==str(source_path),'Changed source binding')
    projection=work/'projection.sqlite'
    with closing(sqlite3.connect(projection.with_suffix('.sqlite.ledger').as_uri()+'?mode=ro',uri=True)) as probe:
        config=json.loads(probe.execute('SELECT json FROM configuration').fetchone()[0])
    require(config['source_id']=='scout-current-bounded' and config['epoch']=='bounded-current-'+digest(plan)[:24] and config['contract_revision']=='A1','Refuse historical projection')
    with (work/'owner.lock').open('a+b') as lock:
        fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        old=manifest(root)
        pending_path=work/'refresh-pending.json'
        with Projector(projection) as p,closing(sqlite3.connect(work/'current-source.sqlite')) as local:
            local.row_factory=sqlite3.Row
            if pending_path.exists():pending=json.loads(pending_path.read_text())
            else:
                require(sum(f.stat().st_size for f in work.glob('*.sqlite*') if f.is_file())<MAX_WORK_BYTES,'Bounded current storage capacity reached; publication not freshened')
                previous=int(p.status()['source_cut']['committed_event_id'])
                src=Source(source_path)
                try:
                    cut=src.rows('SELECT coalesce(max(event_id),0) FROM observed_events')[0][0]
                    when=now or utc() # capture follows the committed source-cut read
                    require(cut>=previous,'Source event cut regressed')
                    selected={}
                    for cls in CLASSES:
                        for r in src.rows('SELECT event_id,raw_record_id FROM observed_events INDEXED BY event_class WHERE classification=? AND event_id>? AND event_id<=? ORDER BY event_id DESC LIMIT 8',(cls,previous,cut)):
                            selected[r['raw_record_id']]=r['event_id']
                    chosen=sorted(selected,key=lambda r:(-selected[r],r))
                    for r in src.rows('SELECT event_id,raw_record_id FROM observed_events WHERE event_id>? AND event_id<=? ORDER BY event_id DESC LIMIT 128',(previous,cut)):
                        if r['raw_record_id'] not in selected:chosen.append(r['raw_record_id']);selected[r['raw_record_id']]=r['event_id']
                    chosen=chosen[:MAX_NEW]
                    count=local.execute('SELECT count(*) FROM raw_network_records').fetchone()[0]
                    require(count+len(chosen)<=MAX_ENROLLED,'Bounded current record capacity reached; publication not freshened')
                    kept,excluded,byte_count=copy_records(src,local,chosen,cut)
                    # Pending plan commits before staging. Replays reuse exactly
                    # these immutable raw inputs and the original capture time.
                    pending=dict(cut=str(cut),when=when,raw_ids=kept,excluded=excluded,bytes=byte_count,
                        previous_id=old['snapshot_id'],previous_cut=str(previous))
                    atomic(pending_path,pending)
                finally:src.close()
            evaluation=p.conn.execute("SELECT number,status FROM evaluations WHERE status!='COMPLETE'").fetchone()
            # Recover the initial scheduler's pre-capture timestamp defect. An
            # empty staging evaluation has no applied inputs or qualifications;
            # seal it without publishing, then evaluate the same captured rows
            # at their actual availability time. Never edit an audit event.
            newest=max((local.execute('SELECT created_at FROM raw_network_records WHERE raw_record_id=?',(rid,)).fetchone()[0]
                for rid in pending['raw_ids']),default=pending['when'])
            available=datetime.fromisoformat(newest.replace('Z','+00:00'))
            if available>instant(pending['when']):
                if evaluation is not None:
                    require(evaluation['status']=='STAGING','Unexpected capture-time recovery state')
                    require(p.conn.execute('SELECT count(*) FROM evaluation_inputs WHERE number=?',(evaluation['number'],)).fetchone()[0]==0,'Cannot alter a partially staged evaluation')
                    p.seal(evaluation['number'])
                pending['when']=utc(available)
                atomic(pending_path,pending)
                evaluation=None
            completed=p.status()['source_cut']
            applied=(completed['committed_event_id']==pending['cut'] and p.get('evaluated_at')==pending['when'])
            if not applied:
                n=evaluation['number'] if evaluation else p.begin(pending['cut'],pending['when'],'SOURCE_BATCH')
                if evaluation is None or evaluation['status']=='STAGING':
                    batch=[]
                    for rid in pending['raw_ids']:
                        bundle=current_bundle(local,rid)
                        if bundle is not None:batch.append(bundle)
                        if len(batch)==50:p.stage(n,batch);batch=[]
                    if batch:p.stage(n,batch)
                    p.seal(n)
                else:p.resume(n)
            if fail:fail('after_apply')
            # Never replace capture time with wall time to disguise old evidence.
            age=(datetime.now(timezone.utc)-instant(pending['when'])).total_seconds()
            if age>MAX_CAPTURE_AGE:
                # The applied cut remains durable, but cannot authorize a fresh
                # timestamp. Let the next timer capture a genuinely new cut.
                pending_path.unlink()
                raise ValueError('Refresh capture exceeded 10-minute deadline; previous publication retained')
            current=manifest(root)
            already=(current['source_checkpoint']==p.status()['source_cut'] and current['selection_evaluated_at']==pending['when'])
            result=({'manifest':current} if already else publish(p,root,checked_cut=p.status()['source_cut'],evaluated_at=pending['when']))
            new=result['manifest']
            status=dict(status='READY',automatic=True,completed_at=utc(),cadence_seconds=CADENCE,
                next_due_at=utc(datetime.now(timezone.utc)+timedelta(seconds=CADENCE)),
                old_publication_id=pending['previous_id'],new_publication_id=new['snapshot_id'],
                old_expiry=utc(instant(old['produced_at'])+timedelta(seconds=3600)),
                new_expiry=utc(instant(new['produced_at'])+timedelta(seconds=3600)),
                source_cut=new['source_checkpoint'],admitted_records=len(pending['raw_ids']),
                total_records=new['row_counts']['messages'],generation_seconds=time.monotonic()-started,
                database=new['database'],size_bytes=new['size_bytes'])
            atomic(work/'refresh-status.json',status)
            pending_path.unlink()
            retain(root,keep=4)
            return status


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source','work','root'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args()
    def deadline(*_):raise TimeoutError('Bounded refresh exceeded 9-minute execution budget')
    signal.signal(signal.SIGALRM,deadline);signal.alarm(540)
    try:result=refresh(args.source,args.work,args.root)
    except BlockingIOError:return # Single owner: the current job will publish.
    except Exception as exc:
        atomic(args.work/'refresh-status.json',dict(status='DEGRADED',error=str(exc),failed_at=utc(),cadence_seconds=CADENCE))
        raise
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
