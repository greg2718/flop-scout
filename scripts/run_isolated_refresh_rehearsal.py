#!/usr/bin/env python3
"""Run an isolated Scout refresh rehearsal.

RESUME (the default) copies only current private/public state and exercises a
pending APPLYING evaluation without opening observer.sqlite.  FRESH-CUT is an
explicit later mode that takes a read-only SQLite backup of observer.sqlite.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import sqlite3
import sys
import time
import traceback

REPO=Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:sys.path.insert(0,str(REPO))
from scout_projection_contract import instant,utc
PRODUCTION=Path.home()/'.flop_scout'
OBSERVER=PRODUCTION/'observer.sqlite'
PRIVATE=PRODUCTION/'router-current'/'private'
PUBLICATION=PRODUCTION/'router-current'/'publication'
WATCHDOG_SECONDS=540
RESUME_MODES=('resume','resume-synthetic-freshness')


def under(path,parent):
    try:path.resolve().relative_to(parent.resolve());return True
    except ValueError:return False


def require(condition,message):
    if not condition:raise RuntimeError(message)


def regular(path):
    require(path.exists() and path.is_file() and not path.is_symlink(),'Expected regular file: '+str(path))


def digest_stat(path):
    regular(path);h=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):h.update(block)
    stat=path.stat()
    return dict(path=str(path),sha256=h.hexdigest(),size=stat.st_size,mtime_ns=stat.st_mtime_ns,inode=stat.st_ino)


def copy_regular(source,destination):
    regular(source);destination.parent.mkdir(mode=0o700,parents=True,exist_ok=True);shutil.copy2(source,destination)


def copy_private(destination):
    names=('current-source.sqlite','projection.sqlite','projection.sqlite.ledger','plan.json','pins.json')
    destination.mkdir(mode=0o700)
    for name in names:copy_regular(PRIVATE/name,destination/name)
    pending=PRIVATE/'refresh-pending.json'
    if pending.exists():copy_regular(pending,destination/pending.name)


def copy_publication(destination):
    destination.mkdir(mode=0o700)
    pointer_path=PUBLICATION/'current.json';pointer=json.loads(pointer_path.read_text())
    manifest=PUBLICATION/pointer['manifest'];regular(manifest)
    body=json.loads(manifest.read_text());database=PUBLICATION/body['database'];regular(database)
    copy_regular(pointer_path,destination/'current.json')
    copy_regular(manifest,destination/manifest.name)
    copy_regular(database,destination/database.name)


def checks(path):
    regular(path);conn=sqlite3.connect('file:'+str(path)+'?mode=ro',uri=True)
    try:
        return dict(quick_check=[r[0] for r in conn.execute('PRAGMA quick_check')],integrity_check=[r[0] for r in conn.execute('PRAGMA integrity_check')])
    finally:conn.close()


def counts(path,names):
    conn=sqlite3.connect('file:'+str(path)+'?mode=ro',uri=True)
    try:
        existing={row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        return {name:conn.execute('SELECT count(*) FROM '+name).fetchone()[0] for name in names if name in existing}
    finally:conn.close()


def stack():
    return [f'{Path(frame.filename).name}:{frame.lineno}:{frame.name}' for frame in traceback.extract_stack(limit=8)[:-2]]


def prepare_synthetic_freshness(work,now=None):
    """Adjust only copied pending bookkeeping; never call this on production."""
    from scout_current_publication import atomic
    path=Path(work)/'refresh-pending.json';regular(path)
    pending=json.loads(path.read_text());original=pending['when']
    pending['when']=utc(instant(now)) if now is not None else utc()
    atomic(path,pending)
    return dict(label='SYNTHETIC_FRESHNESS_REHEARSAL',field='when',original=original,adjusted=pending['when'])


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode',choices=('resume','resume-synthetic-freshness','fresh-cut'),default='resume')
    mode=parser.parse_args().mode
    stamp=time.strftime('%Y%m%dT%H%M%SZ',time.gmtime())
    root=Path('/private/tmp')/f'flop-scout-rehearsal-{stamp}-{os.getpid()}'
    root.mkdir(mode=0o700)
    log_path=root/'rehearsal.log';result_path=root/'rehearsal-result.json'
    def log(message):
        line=f'{time.strftime("%Y-%m-%dT%H:%M:%SZ",time.gmtime())} {message}'
        print(line,flush=True)
        with log_path.open('a',encoding='utf-8') as stream:stream.write(line+'\n')
    result=dict(root=str(root),mode=mode,watchdog_seconds=WATCHDOG_SECONDS,production_writes=False,pass_=False)
    exit_code=1
    protected=[];before=None;traces=[];phase_trace=[]
    try:
        for path in (OBSERVER,PRIVATE,PUBLICATION):require(path.exists(),'Missing production input: '+str(path))
        pointer=json.loads((PUBLICATION/'current.json').read_text())
        manifest=PUBLICATION/pointer['manifest'];regular(manifest)
        protected=[PUBLICATION/'current.json',manifest,PRIVATE/'projection.sqlite',PRIVATE/'projection.sqlite.ledger']
        before={str(path):digest_stat(path) for path in protected}
        source=root/'source'/'observer.sqlite';work=root/'private';public=root/'publication'
        output_paths=(root,work,public)+(source.parent,) if mode=='fresh-cut' else (root,work,public)
        for path in output_paths:
            require(not under(path,PRODUCTION),'Output path is under production: '+str(path))
        log('paths production_source='+str(OBSERVER.resolve())+' production_private='+str(PRIVATE.resolve())+' production_publication='+str(PUBLICATION.resolve()))
        log('paths isolated_work='+str(work.resolve())+' isolated_publication='+str(public.resolve()))
        began=time.monotonic();copy_private(work);copy_publication(public);result['private_publication_copy_seconds']=time.monotonic()-began
        if mode=='fresh-cut':
            log('paths isolated_source='+str(source.resolve()))
            began=time.monotonic();source.parent.mkdir(mode=0o700)
            result['observer_source_connection']='file:'+str(OBSERVER)+'?mode=ro (read-only SQLite backup source)'
            source_read=sqlite3.connect('file:'+str(OBSERVER)+'?mode=ro',uri=True);destination=sqlite3.connect(source)
            try:
                source_read.backup(destination,pages=4096,sleep=0.05);destination.execute('PRAGMA journal_mode=DELETE');destination.commit()
            finally:destination.close();source_read.close()
            result['source_backup_seconds']=time.monotonic()-began
            result['source_checks']=checks(source);result['source_counts']=counts(source,('raw_network_records','observed_events','messages','evidence_records','interactions'))
            require(result['source_checks']['quick_check']==['ok'] and result['source_checks']['integrity_check']==['ok'],'Source snapshot integrity failure')
        else:
            result['observer_source_connection']='not opened in RESUME mode'
            require((work/'refresh-pending.json').is_file(),'RESUME requires copied refresh-pending.json')
            if mode=='resume-synthetic-freshness':
                result['synthetic_freshness']=prepare_synthetic_freshness(work)
                (root/'SYNTHETIC_FRESHNESS_REHEARSAL').write_text(result['synthetic_freshness']['adjusted']+'\n')
                log('SYNTHETIC_FRESHNESS_REHEARSAL adjusted copied refresh-pending.json field=when')
            pending=json.loads((work/'refresh-pending.json').read_text())
            require(type(pending.get('raw_ids')) is list,'Invalid copied pending refresh')
            ledger=sqlite3.connect('file:'+str(work/'projection.sqlite.ledger')+'?mode=ro',uri=True)
            try:state=ledger.execute("SELECT status FROM evaluations WHERE status!='COMPLETE' ORDER BY number LIMIT 1").fetchone()
            finally:ledger.close()
            require(state and state[0]=='APPLYING','RESUME requires copied APPLYING evaluation')
            result['resume_preflight']=dict(pending_raw_ids=len(pending['raw_ids']),evaluation_status=state[0])
        for path in output_paths:require(not under(path,PRODUCTION),'Isolation guard failed: '+str(path))
        import scout_projection
        original_init=scout_projection.Projector.__init__;original_verify=scout_projection.Projector.verify_ledger;original_resume=scout_projection.Projector.resume
        sequence=[0]
        def traced_init(self,*args,**kwargs):
            entry=dict(kind='projector_init',object_id=id(self),started_monotonic=time.monotonic(),path=str(args[0] if args else kwargs['path']),caller=stack())
            try:return original_init(self,*args,**kwargs)
            finally:
                entry['ended_monotonic']=time.monotonic();entry['duration_seconds']=entry['ended_monotonic']-entry['started_monotonic'];traces.append(entry)
        def traced_verify(self,*args,**kwargs):
            sequence[0]+=1
            entry=dict(kind='verify_ledger',call_number=sequence[0],object_id=id(self),path=str(self.path),started_monotonic=time.monotonic(),caller=stack(),ledger_rows=self.conn.execute('SELECT count(*) FROM operations').fetchone()[0]+self.conn.execute('SELECT count(*) FROM evaluations').fetchone()[0]+self.conn.execute('SELECT count(*) FROM audit_history').fetchone()[0],durable_qualifications=self.conn.execute('SELECT count(*) FROM qualification_keys').fetchone()[0],counters_before=dict(self.metrics))
            try:return original_verify(self,*args,**kwargs)
            finally:
                entry['ended_monotonic']=time.monotonic();entry['duration_seconds']=entry['ended_monotonic']-entry['started_monotonic'];entry['counters_after']=dict(self.metrics)
                keys=('bundle_calls','bundle_cache_hits','bundle_cache_misses','source_ref_calls','source_ref_cache_hits','source_ref_cache_misses','bundle_sqlite_queries')
                entry['pass_metrics']={key:entry['counters_after'].get(key,0)-entry['counters_before'].get(key,0) for key in keys}
                entry['pass_metrics'].update(bundle_cache_peak_entries=entry['counters_after'].get('bundle_cache_peak_entries',0),source_ref_cache_peak_entries=entry['counters_after'].get('source_ref_cache_peak_entries',0),bundle_unique_ids=entry['counters_after'].get('bundle_unique_ids',0),source_ref_unique_ids=entry['counters_after'].get('source_ref_unique_ids',0))
                traces.append(entry)
        def traced_resume(self,*args,**kwargs):
            entry=dict(kind='per_record_projection',started_monotonic=time.monotonic(),object_id=id(self),caller=stack())
            try:return original_resume(self,*args,**kwargs)
            finally:
                entry['ended_monotonic']=time.monotonic();entry['duration_seconds']=entry['ended_monotonic']-entry['started_monotonic'];phase_trace.append(entry)
        scout_projection.Projector.__init__=traced_init;scout_projection.Projector.verify_ledger=traced_verify;scout_projection.Projector.resume=traced_resume
        def deadline(*_):raise TimeoutError('Bounded refresh exceeded 9-minute execution budget')
        signal.signal(signal.SIGALRM,deadline);signal.alarm(WATCHDOG_SECONDS)
        refresh_started=time.monotonic()
        try:
            import scout_current_refresh
            import scout_projection_publish
            original_source=scout_current_refresh.Source
            original_publish=scout_projection_publish.publish
            def traced_publish(*args,**kwargs):
                entry=dict(kind='publication_finalization',started_monotonic=time.monotonic(),caller=stack())
                try:return original_publish(*args,**kwargs)
                finally:
                    entry['ended_monotonic']=time.monotonic();entry['duration_seconds']=entry['ended_monotonic']-entry['started_monotonic'];phase_trace.append(entry)
            scout_projection_publish.publish=traced_publish
            if mode in RESUME_MODES:
                def source_forbidden(*_args,**_kwargs):raise RuntimeError('RESUME must not open observer.sqlite')
                scout_current_refresh.Source=source_forbidden
            # source_binding_path preserves the immutable plan identity while
            # source_path is only opened in FRESH-CUT mode.
            status=scout_current_refresh.refresh(source if mode=='fresh-cut' else OBSERVER,work,public,source_binding_path=OBSERVER)
        finally:
            if 'original_source' in locals():scout_current_refresh.Source=original_source
            if 'original_publish' in locals():scout_projection_publish.publish=original_publish
            signal.alarm(0)
        result['refresh_wall_seconds']=time.monotonic()-refresh_started
        result['refresh_status']=status;result['verify_trace']=traces;result['phase_trace']=phase_trace
        pointer=json.loads((public/'current.json').read_text());out_manifest=json.loads((public/pointer['manifest']).read_text())
        result['isolated_publication']=dict(snapshot_id=out_manifest['snapshot_id'],content_id=out_manifest['database_content_id'],kind=out_manifest['publication_kind'],manifest=pointer['manifest'])
        result['projection_checks']=checks(work/'projection.sqlite');result['ledger_checks']=checks(work/'projection.sqlite.ledger');result['current_source_checks']=checks(work/'current-source.sqlite')
        result['projection_counts']=counts(work/'projection.sqlite',('messages','durable_qualifications','source_provenance','qualification_events'))
        result['ledger_counts']=counts(work/'projection.sqlite.ledger',('operations','evaluations','qualification_keys','audit_history','current_inputs'))
        require(len([item for item in traces if item['kind']=='verify_ledger'])==2,'Expected exactly two verify_ledger invocations')
        require(result['refresh_wall_seconds']<WATCHDOG_SECONDS,'Refresh exceeded watchdog')
        require(all(check['quick_check']==['ok'] and check['integrity_check']==['ok'] for check in (result['projection_checks'],result['ledger_checks'],result['current_source_checks'])),'Isolated SQLite integrity failure')
        result['history_continuity_provenance']='passed by both fail-closed verify_ledger passes and publication validation'
        result['pass_']=True;exit_code=0
    except BaseException as exc:
        result.update(error_type=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
    finally:
        result['verify_trace']=traces;result['phase_trace']=phase_trace
        if before is not None:
            try:
                after={str(path):digest_stat(path) for path in protected}
                result['production_artifacts_unchanged']=before==after
                if not result['production_artifacts_unchanged']:
                    result['pass_']=False;exit_code=1
            except BaseException as exc:
                result['production_artifact_check_error']=str(exc);result['pass_']=False;exit_code=1
        result['exit_code']=exit_code;result['cpu_user_seconds']=resource.getrusage(resource.RUSAGE_SELF).ru_utime;result['cpu_system_seconds']=resource.getrusage(resource.RUSAGE_SELF).ru_stime
        result_path.write_text(json.dumps(result,indent=2,sort_keys=True))
        log(('PASS' if exit_code==0 else 'FAIL')+' root='+str(root)+' result='+str(result_path))
    return exit_code


if __name__=='__main__':raise SystemExit(main())
