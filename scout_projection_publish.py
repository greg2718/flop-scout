"""Crash-safe immutable V2 publication from the projection database only."""
from __future__ import annotations
from pathlib import Path
import hashlib
import fcntl
import os
import re
import sqlite3
import stat
import uuid
from scout_projection_contract import *
from scout_projection_model import validate_qualification, validate_event, first_key

DB_PATTERN=re.compile(r'router-projection-v2-(0|[1-9][0-9]{0,19})-([0-9a-f]{64})\.sqlite\Z')
MANIFEST_PATTERN=re.compile(r'manifest-v2-(0|[1-9][0-9]{0,19})-([0-9a-f]{64})\.json\Z')


def manifest_revision(manifest):
    revision=revision_binding(manifest)
    required={'schema','contract_revision','snapshot_id','publication_kind','database_content_id','database','sha256','size_bytes','database_schema_version','selection_policy','selection_policy_sha256','content_created_at','selection_evaluated_at','produced_at','source_checkpoint','next_expiry_at','row_counts','watermarks','coverage_history'}
    keys(manifest,required | set(revision_metadata(revision)))
    require(manifest['selection_policy'] == policy_for(revision) and manifest['selection_policy_sha256'] == digest(policy_for(revision)), 'Manifest selection policy mismatch')
    if revision == TL1_REVISION:
        from scout_projection_tclk import validate_cohort
        checkpoint = manifest['source_checkpoint']
        validate_cohort(manifest['legacy_tclk_cohort'], source_id=checkpoint['source_id'], epoch=checkpoint['epoch'], cut=checkpoint['committed_event_id'])
    keys(manifest['row_counts'],tables_for(revision))
    require(all(type(v) is int and v>=0 for v in manifest['row_counts'].values()),'Invalid manifest row counts')
    return revision


def file_hash(path, stop=None):
    h=hashlib.sha256()
    fd=os.open(str(path),os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode),'Artifact is not regular')
        while True:
            if stop and stop.is_set():raise InterruptedError('Hash cancelled')
            block=stream.read(1024*1024)
            if not block:break
            h.update(block)
    return h.hexdigest()


def fsync_directory(root):
    fd=os.open(str(root),os.O_RDONLY)
    try:os.fsync(fd)
    finally:os.close(fd)


def safe_file(root,name,pattern=None):
    require(type(name) is str and Path(name).name==name and name not in {'.','..'} and (pattern is None or pattern.fullmatch(name)),'Unsafe artifact name')
    path=root/name
    info=path.lstat()
    require(stat.S_ISREG(info.st_mode),'Symlink or non-regular artifact rejected')
    return path


def read_artifact(root,name,pattern=None,limit=4*1024*1024):
    path=safe_file(root,name,pattern)
    fd=os.open(str(path),os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        raw=stream.read(limit+1)
    require(len(raw)<=limit,'Artifact exceeds size limit')
    return raw


def atomic_json(root,name,value,immutable=True):
    data=canonical(value)
    staging=root/('.scout-v2-'+uuid.uuid4().hex+'.tmp')
    fd=os.open(str(staging),os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    try:
        with os.fdopen(fd,'wb') as stream:stream.write(data);stream.flush();os.fsync(stream.fileno())
        if immutable:
            # Hard-link publication is atomic and fails rather than overwrites.
            os.link(str(staging),str(root/name));staging.unlink()
        else:
            if (root/name).exists() or (root/name).is_symlink():safe_file(root,name)
            os.replace(str(staging),str(root/name))
        fsync_directory(root)
    finally:
        if staging.exists():staging.unlink()


def validate_database(path, stop=None, *, contract_revision=REVISION, tl1_binding=None):
    require(contract_revision in REVISIONS,'Unsupported database validation revision')
    conn=connect(path,True)
    try:
        require(conn.execute('PRAGMA user_version').fetchone()[0]==2,'Wrong database user_version')
        reference_db=sqlite3.connect(':memory:');reference_db.executescript(sql_for(contract_revision))
        expected=[tuple(r) for r in reference_db.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")]
        actual=[tuple(r) for r in conn.execute("SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")]
        # SQLite strips attached schema qualifiers from stored CREATE statements.
        require(actual==expected,'Database schema differs from exact A1 contract')
        for table in tables_for(contract_revision):
            require([tuple(r) for r in conn.execute('PRAGMA table_xinfo('+table+')')]==[tuple(r) for r in reference_db.execute('PRAGMA table_xinfo('+table+')')],'Contract table_xinfo mismatch')
        reference_db.close()
        require([r[0] for r in conn.execute('PRAGMA integrity_check')]==['ok'],'SQLite integrity failure')
        require(not conn.execute('PRAGMA foreign_key_check').fetchone(),'Foreign key failure')
        with open(path,'rb') as stream:
            header=stream.read(100)
        require(header[:16]==b'SQLite format 3\x00' and header[18:20]==b'\x01\x01','Standalone rollback database required')
        metas=conn.execute('SELECT * FROM snapshot_meta').fetchall();require(len(metas)==1,'Invalid content metadata count');meta=dict(metas[0])
        require(meta['singleton']==1 and meta['schema']==SCHEMA and meta['selection_policy_sha256']==digest(policy_for(contract_revision)),'Invalid content metadata')
        decimal(meta['database_content_id']);instant(meta['content_created_at'])
        for table,entity in [('messages','message'),('interactions','interaction')]:
            require(not conn.execute(f'''SELECT 1 FROM {table} m LEFT JOIN source_provenance p ON p.entity_type=? AND p.projection_row_id=m.projection_row_id LEFT JOIN selection_membership s ON s.entity_type=? AND s.projection_row_id=m.projection_row_id WHERE p.projection_row_id IS NULL OR s.projection_row_id IS NULL LIMIT 1''',(entity,entity)).fetchone(),'Missing one-to-one provenance/membership')
        for table in ('source_provenance','selection_membership'):
            require(not conn.execute(f'''SELECT 1 FROM {table} p LEFT JOIN messages m ON p.entity_type='message' AND m.projection_row_id=p.projection_row_id LEFT JOIN interactions i ON p.entity_type='interaction' AND i.projection_row_id=p.projection_row_id WHERE m.projection_row_id IS NULL AND i.projection_row_id IS NULL LIMIT 1''').fetchone(),'Orphan provenance/membership')
        require(not conn.execute('SELECT 1 FROM messages GROUP BY room,generation,seq HAVING count(DISTINCT text)>1 OR count(DISTINCT sender)>1 OR count(DISTINCT timestamp)>1 OR count(DISTINCT nonce)>1 OR count(DISTINCT sig)>1 LIMIT 1').fetchone(),'Conflicting source position')
        for row in conn.execute('SELECT * FROM messages'):
            if stop and stop.is_set():raise InterruptedError('Validation cancelled')
            for key in ('projection_row_id','room','generation','sender'):string(row[key])
            require(type(row['seq']) is int and row['seq']>=0 and type(row['signed']) is int and row['signed'] in (0,1),'Invalid message SQLite type')
            require(type(row['text']) is str,'Invalid message text');canonical(row['text'])
            for key in ('timestamp','normalized_text','nonce','sig','source_export_path','evidence_id','verification_status'):
                require(row[key] is None or type(row[key]) is str,'Invalid nullable message type')
            for key in ('message_hash','template_normalized_hash','source_export_hash'):sha(row[key],True)
            require(row['message_hash'] is None or row['message_hash']==text_hash(row['text']),'Message content hash mismatch')
        for row in conn.execute('SELECT * FROM interactions'):
            for key in ('projection_row_id','source_did','target_did','relationship_type'):string(row[key])
            require(type(row['confidence']) in (float,int) and math.isfinite(row['confidence']),'Invalid confidence')
        for row in conn.execute('SELECT * FROM source_provenance'):
            for key in ('projection_row_id','source_namespace','source_record_locator'):string(row[key])
            for key in ('raw_record_id',):string(row[key],True)
            if row['scout_event_id'] is not None:decimal(row['scout_event_id'])
            sha(row['raw_record_sha256'],True);ann=annotations(loads(row['annotations_json'],65536),contract_revision)
            if ann.get('legacy_generation') is not None:
                message=conn.execute('SELECT * FROM messages WHERE projection_row_id=?',(row['projection_row_id'],)).fetchone()
                require(message is not None,'LG1 annotation on non-message')
                validate_legacy_annotation(ann['legacy_generation'],dict(message),dict(row))
        if contract_revision in (LG2_REVISION, TL1_REVISION):
            from scout_projection_compact import validate_all
            validate_all(conn)
        for row in conn.execute('SELECT * FROM selection_membership'):
            require(row['retention_class'] in CLASSES | ({'TCLK_LEGACY_AUDIT'} if contract_revision == TL1_REVISION else set()),'Unknown retention class')
            first=instant(row['first_observed_at'])
            if row['retain_until'] is not None:require(instant(row['retain_until'])>=first,'Expiry before first availability')
            roots(loads(row['pin_roots_json'],65536))
        watermarks=[dict(r) for r in conn.execute('SELECT * FROM watermarks ORDER BY room,generation')]
        derived=[dict(r) for r in conn.execute('SELECT room,generation,count(*) AS record_count,min(seq) AS min_seq,max(seq) AS max_seq FROM messages GROUP BY room,generation ORDER BY room,generation')]
        require(watermarks==derived,'Incorrect projection-scoped watermarks')
        history=[dict(r) for r in conn.execute('SELECT * FROM coverage_history ORDER BY room,generation')]
        require(len(watermarks)<=10000 and len(history)<=10000,'Coverage domain capacity exceeded')
        by_domain={(r['room'],r['generation']):r for r in history}
        for row in history:
            string(row['room']);string(row['generation']);string(row['witness_source_locator']);sha(row['witness_record_sha256'])
            require(type(row['max_ever_projected_seq']) is int and row['max_ever_projected_seq']>=0,'Invalid historical watermark')
        for row in watermarks:require((row['room'],row['generation']) in by_domain and by_domain[row['room'],row['generation']]['max_ever_projected_seq']>=row['max_seq'],'Historical coverage regression')
        class Qualifications:
            def __contains__(self,key):return conn.execute('SELECT 1 FROM durable_qualifications WHERE qualification_id=?',(key,)).fetchone() is not None
            def __getitem__(self,key):
                row=conn.execute('SELECT record_json FROM durable_qualifications WHERE qualification_id=?',(key,)).fetchone()
                require(row,'Missing qualification');return loads(row[0],65536)
        qualifications=Qualifications();firsts=set()
        for row in conn.execute('SELECT * FROM durable_qualifications'):
            record=validate_qualification(loads(row['record_json'],65536), policy_versions(contract_revision));require(record['qualification_id']==row['qualification_id'],'Qualification row ID mismatch')
            require(first_key(record) not in firsts,'Duplicate first-qualification tuple');firsts.add(first_key(record))
            for ref in record['provenance_refs']:
                if ref['kind']=='PROJECTED_MESSAGE':
                    witness=conn.execute("SELECT m.text,s.retain_until FROM messages m JOIN selection_membership s ON s.entity_type='message' AND s.projection_row_id=m.projection_row_id WHERE m.projection_row_id=?",(ref['id'],)).fetchone()
                    require(witness and text_hash(witness['text'])==ref['sha256'] and witness['retain_until'] is None,'Missing or expired durable witness')
        prior=[];prior_qid=None;graph={}
        for row in conn.execute('SELECT * FROM qualification_events ORDER BY qualification_id,sequence'):
            event=loads(row['event_json'],65536);qid=row['qualification_id']
            if qid!=prior_qid:prior=[];prior_qid=qid
            chain=prior
            validate_event(event,chain,qualifications)
            for ref in event['proof_refs']+[event['authority_ref']]:
                if ref['kind']=='PROJECTED_MESSAGE':
                    witness=conn.execute("SELECT m.text,s.retain_until FROM messages m JOIN selection_membership s ON s.entity_type='message' AND s.projection_row_id=m.projection_row_id WHERE m.projection_row_id=?",(ref['id'],)).fetchone()
                    require(witness and text_hash(witness['text'])==ref['sha256'] and witness['retain_until'] is None,'Missing or expirable qualification-event proof')
            require((row['event_id'],row['sequence'])==(event['event_id'],event['sequence']),'Audit row mismatch');chain.append(event)
            if event['event_type']=='SUPERSEDED':graph.setdefault(qid,set()).add(event['superseded_by'])
        for start in graph:
            frontier=list(graph[start]);seen=set()
            while frontier:
                node=frontier.pop();require(node!=start,'Supersession cycle')
                if node not in seen:seen.add(node);frontier.extend(graph.get(node,()))
        if contract_revision == TL1_REVISION:
            from scout_projection_tclk import validate_public, validate_binding
            require(tl1_binding is not None, 'TL1 explicit validation binding required')
            validate_binding(tl1_binding)
            checkpoint = tl1_binding['source_checkpoint']
            validate_public(conn, tl1_binding['legacy_tclk_cohort'], checkpoint['source_id'], checkpoint['epoch'], checkpoint['committed_event_id'], check=lambda: require(not stop or not stop.is_set(), 'TL1_VALIDATION_CANCELLED'))
        return dict(meta=meta,row_counts={t:conn.execute('SELECT count(*) FROM '+t).fetchone()[0] for t in tables_for(contract_revision)},watermarks=watermarks,coverage_history=history,next_expiry_at=conn.execute('SELECT min(retain_until) FROM selection_membership').fetchone()[0])
    finally:conn.close()


def validate_history_extension(previous_path,candidate_path,stop=None,*,previous_revision=REVISION,current_revision=REVISION):
    """Previously accepted audit bytes and permanent witnesses cannot disappear."""
    require(previous_revision in REVISIONS and current_revision in REVISIONS,'Unsupported history revision')
    require(previous_revision==current_revision or (previous_revision,current_revision) in (('A1',REVISION),(REVISION,LG2_REVISION),(LG2_REVISION,TL1_REVISION)),'Unsupported history transition; downgrade forbidden')
    old=connect(previous_path,True);new=connect(candidate_path,True)
    try:
        from scout_projection_legacy import continuity
        for row in old.execute('SELECT * FROM source_provenance'):
            found=new.execute('SELECT * FROM source_provenance WHERE entity_type=? AND projection_row_id=?',(row['entity_type'],row['projection_row_id'])).fetchone()
            if found is None:continue  # Ordinary expiry is checked by the retention rules.
            before=annotations(loads(row['annotations_json']),previous_revision)
            after=annotations(loads(found['annotations_json']),current_revision)
            if current_revision in (LG2_REVISION, TL1_REVISION):
                from scout_projection_compact import read_audit
                old_audit=read_audit(old,row) if previous_revision in (LG2_REVISION, TL1_REVISION) else before.get('legacy_generation')
                new_audit=read_audit(new,found)
                continuity(old_audit,new_audit)
                if previous_revision not in (LG2_REVISION, TL1_REVISION):
                    require(previous_revision==REVISION and old_audit==new_audit and {k:v for k,v in before.items() if k!='legacy_generation'}==after,'LG2 migration changed logical annotations')
            elif previous_revision==LG2_REVISION:raise ProjectionError('LG2 downgrade forbidden')
            elif previous_revision==REVISION:continuity(before['legacy_generation'],after.get('legacy_generation'))
            elif current_revision==REVISION:
                require(before=={k:v for k,v in after.items() if k!='legacy_generation'},'LG1 transition changed substantive annotations')
                require(after['legacy_generation'] is None,'Existing A1 row cannot acquire an unvalidated legacy class')
        for table,key,payload in [('durable_qualifications','qualification_id','record_json'),('qualification_events','event_id','event_json')]:
            for row in old.execute('SELECT '+key+','+payload+' FROM '+table):
                if stop and stop.is_set():raise InterruptedError('History validation cancelled')
                found=new.execute('SELECT '+payload+' FROM '+table+' WHERE '+key+'=?',(row[0],)).fetchone()
                require(found and found[0]==row[1],'Previously accepted audit history was lost or rewritten')
        permanent={'TCLK_LEGACY_AUDIT','NEGATIVE_EVIDENCE','PINNED','IDENTITY_OPERATOR','BENCH_VERIFICATION','CAPABILITY_SUPPORT','CAPABILITY_CONTRADICTION'}
        for row in old.execute('SELECT * FROM selection_membership'):
            if stop and stop.is_set():raise InterruptedError('Retention validation cancelled')
            pin_roots=loads(row['pin_roots_json'])
            if row['retention_class'] not in permanent and not pin_roots:continue
            found=new.execute('SELECT * FROM selection_membership WHERE entity_type=? AND projection_row_id=?',(row['entity_type'],row['projection_row_id'])).fetchone()
            require(found and found['retain_until'] is None,'Previously retained permanent proof was lost or made expirable')
            require({canonical(r) for r in pin_roots}<={canonical(r) for r in loads(found['pin_roots_json'])},'Previously published pin root was lost')
            table='messages' if row['entity_type']=='message' else 'interactions'
            fields=('room','generation','seq','timestamp','sender','text','nonce','sig') if table=='messages' else ('source_did','target_did','relationship_type')
            before=old.execute('SELECT '+','.join(fields)+' FROM '+table+' WHERE projection_row_id=?',(row['projection_row_id'],)).fetchone()
            after=new.execute('SELECT '+','.join(fields)+' FROM '+table+' WHERE projection_row_id=?',(row['projection_row_id'],)).fetchone()
            require(before and after and tuple(before)==tuple(after),'Previously protected source content changed')
        for row in old.execute('SELECT * FROM coverage_history'):
            found=new.execute('SELECT * FROM coverage_history WHERE room=? AND generation=?',(row['room'],row['generation'])).fetchone()
            require(found and found['max_ever_projected_seq']>=row['max_ever_projected_seq'],'Projection coverage history regressed')
            if found['max_ever_projected_seq']==row['max_ever_projected_seq']:require(tuple(found)==tuple(row),'Coverage witness changed without a higher sequence')
    finally:old.close();new.close()


def archive_lg1_publication(root, pointer, manifest, stop=None):
    """Preserve accepted LG1 bytes outside ordinary publication retention."""
    import shutil
    archive=root/(('lg2-publication-archive-' if manifest['contract_revision'] == LG2_REVISION else 'lg1-publication-archive-')+uuid.uuid4().hex)
    archive.mkdir(mode=0o700)
    source=safe_file(root,manifest['database'],DB_PATTERN)
    require(file_hash(source,stop)==manifest['sha256'],'LG1 archive source hash mismatch')
    target=archive/manifest['database']
    with open(source,'rb') as src,open(target,'xb') as dst:
        shutil.copyfileobj(src,dst,1024*1024);dst.flush();os.fsync(dst.fileno())
    require(file_hash(target,stop)==manifest['sha256'],'LG1 archive copy hash mismatch')
    target.chmod(0o400)
    raw=read_artifact(root,pointer['manifest'],MANIFEST_PATTERN)
    require(hashlib.sha256(raw).hexdigest()==pointer['manifest_sha256'],'LG1 archive manifest mismatch')
    with open(archive/pointer['manifest'],'xb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
    (archive/pointer['manifest']).chmod(0o400)
    atomic_json(archive,'current.json',pointer)
    (archive/'current.json').chmod(0o400)
    fsync_directory(archive);fsync_directory(root)
    return str(archive)


def _publish(projector,root,*,checked_cut,evaluated_at=None,fail=None):
    """Explicit fresh source cut check is mandatory even for heartbeat reuse."""
    projector.check();root=Path(root)
    require(root.is_absolute() and not root.is_symlink(),'Explicit absolute non-symlink publication root required')
    require(root.resolve()!=projector.path.parent.resolve(),'Publication root must be separate from working state')
    root.mkdir(parents=True,exist_ok=True);root=root.resolve()
    require(not projector.conn.execute("SELECT 1 FROM evaluations WHERE status!='COMPLETE'").fetchone(),'Incomplete source evaluation')
    require(projector.get('tl1_activation_pending', '0') == '0', 'TL1 complete source enrollment required before publication')
    require(projector.conn.execute('SELECT 1 FROM pin_exports').fetchone() and not projector.get('pin_error'),'Missing or rejected pin interchange')
    require(loads(projector.get('source_cut','null'))==checked_cut,'Source cut was not checked/caught up')
    when=utc(instant(evaluated_at or utc()));require(instant(when)>=instant(projector.get('evaluated_at')),'Regressed publication evaluation')
    due=projector.conn.execute('SELECT min(due) FROM expiry').fetchone()[0]
    if due and instant(due)<=instant(when):
        number=projector.begin(checked_cut['committed_event_id'],when,'EXPIRY');projector.seal(number)
    projector.verify_ledger()
    previous=None;revision_changed=False;lg1_archive=None
    revision=revision_binding(projector.config)
    if revision == TL1_REVISION:
        from scout_projection_tclk import validate_public
        diagnostics = validate_public(projector.conn, projector.config['legacy_tclk_cohort'], checked_cut['source_id'], checked_cut['epoch'], checked_cut['committed_event_id'], 'projection.', projector.check)
        with projector.conn: projector.set('tl1_status', canonical(diagnostics).decode())
    if (root/'current.json').exists() or (root/'current.json').is_symlink():
        pointer=loads(read_artifact(root,'current.json',limit=16384));keys(pointer,{'schema','manifest','manifest_sha256','published_at'})
        require(pointer['schema']=='flop-scout-router-current/v2','Publication root is not V2')
        raw=read_artifact(root,pointer['manifest'],MANIFEST_PATTERN)
        require(hashlib.sha256(raw).hexdigest()==pointer['manifest_sha256'],'Current manifest corrupted')
        previous=loads(raw)
        previous_revision=manifest_revision(previous)
        revision_changed=previous_revision!=revision
        if revision == TL1_REVISION and previous_revision == TL1_REVISION:
            require({k:previous[k] for k in revision_metadata(revision)} == revision_metadata(revision, projector.config['legacy_tclk_cohort']), 'TL1_HEARTBEAT_BINDING_CHANGED')
        require(not revision_changed or previous_revision=='A1' and revision==REVISION and projector.get('lg1_transition')=='1' or previous_revision==REVISION and revision==LG2_REVISION and projector.get('lg2_transition')=='1' or previous_revision==LG2_REVISION and revision==TL1_REVISION and projector.get('tl1_transition')=='1','Explicit contract migration required; downgrade forbidden')
        require(previous['source_checkpoint']['source_id']==checked_cut['source_id'] and previous['source_checkpoint']['epoch']==checked_cut['epoch'],'Publication source namespace changed')
        require(int(previous['source_checkpoint']['committed_event_id'])<=int(checked_cut['committed_event_id']),'Source checkpoint regression')
        require(instant(when)>=instant(previous['selection_evaluated_at']),'Publication time regression')
        last=projector.conn.execute('SELECT id,manifest,hash FROM publication_log ORDER BY length(id) DESC,id DESC LIMIT 1').fetchone()
        if last:
            require(int(previous['snapshot_id'])>=int(last['id']),'Current pointer publication rollback')
            if previous['snapshot_id']==last['id']:require(pointer['manifest']==last['manifest'] and pointer['manifest_sha256']==last['hash'],'Conflicting repeated publication ID')
        if projector.get('dirty','1')=='0' and not revision_changed:
            require(previous['database_content_id']==projector.get('content_id'),'Reusable database content rollback')
            require(previous['sha256']==projector.get('published_database_sha256'),'Reusable database identity changed')
        if revision_changed and revision==LG2_REVISION:
            lg1_archive=archive_lg1_publication(root,pointer,previous,projector.stop)
        if revision_changed and revision==TL1_REVISION:
            lg1_archive=archive_lg1_publication(root,pointer,previous,projector.stop)
    with projector.conn:
        pub_id=max(int(projector.get('publication_id','0')),int(previous['snapshot_id']) if previous else 0)+1
        decimal(str(pub_id));projector.set('publication_id',pub_id)
    changed=projector.get('dirty','1')=='1' or previous is None or revision_changed
    temp=None
    try:
        if changed:
            with projector.conn:
                content_id=max(int(projector.get('content_id','0')),int(previous['database_content_id']) if previous else 0)+1
                decimal(str(content_id));projector.set('content_id',content_id)
                projector.conn.execute('UPDATE projection.snapshot_meta SET database_content_id=?,content_created_at=? WHERE singleton=1',(str(content_id),when))
            temp=root/('.scout-v2-'+uuid.uuid4().hex+'.sqlite.tmp')
            fd=os.open(str(temp),os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600);os.close(fd)
            destination=sqlite3.connect(str(temp))
            try:
                def progress(status,remaining,total):projector.check()
                projector.conn.backup(destination,name='projection',pages=256,progress=progress,sleep=0.01)
                destination.execute('PRAGMA journal_mode=DELETE');destination.commit()
            finally:destination.close()
            size=temp.stat().st_size
            require(readiness(size)!='OVERSIZE','OVERSIZE: retain current pointer; do not truncate')
            details=validate_database(temp,projector.stop,contract_revision=revision,tl1_binding=dict(projector.config,source_checkpoint=checked_cut) if revision == TL1_REVISION else None)
            if previous:
                previous_path=safe_file(root,previous['database'],DB_PATTERN)
                require(file_hash(previous_path,projector.stop)==previous['sha256'],'Previously accepted database was corrupted')
                validate_history_extension(previous_path,temp,projector.stop,previous_revision=previous['contract_revision'],current_revision=revision)
            with open(temp,'rb') as stream:os.fsync(stream.fileno())
            h=file_hash(temp,projector.stop);name=f'router-projection-v2-{content_id}-{h}.sqlite'
            os.link(str(temp),str(root/name));temp.unlink();temp=None;fsync_directory(root)
        else:
            name=previous['database'];path=safe_file(root,name,DB_PATTERN)
            require(file_hash(path,projector.stop)==previous['sha256'],'Reusable content artifact corrupted')
            h=previous['sha256'];size=path.stat().st_size;content_id=previous['database_content_id']
            details=dict(meta=dict(content_created_at=previous['content_created_at']),row_counts=previous['row_counts'],watermarks=previous['watermarks'],coverage_history=previous['coverage_history'],next_expiry_at=previous['next_expiry_at'])
        require(details['next_expiry_at'] is None or instant(details['next_expiry_at'])>instant(when),'Unprocessed due expiry')
        require(readiness(size)!='OVERSIZE','OVERSIZE reusable artifact')
        if fail:fail('database')
        manifest=dict(schema='flop-scout-router-snapshot/v2',contract_revision=revision,snapshot_id=str(pub_id),publication_kind='CONTENT' if changed else 'HEARTBEAT',database_content_id=str(content_id),database=name,sha256=h,size_bytes=size,database_schema_version=SCHEMA,selection_policy=projector.policy,selection_policy_sha256=projector.policy_sha,content_created_at=details['meta']['content_created_at'],selection_evaluated_at=when,produced_at=when,source_checkpoint=checked_cut,next_expiry_at=details['next_expiry_at'],row_counts=details['row_counts'],watermarks=details['watermarks'],coverage_history=details['coverage_history'])
        manifest.update(revision_metadata(revision, projector.config.get('legacy_tclk_cohort')))
        manifest_revision(manifest)
        revision_binding(manifest)
        require(len(canonical(manifest))<=4*1024*1024,'Manifest exceeds limit')
        mh=digest(manifest);mn=f'manifest-v2-{pub_id}-{mh}.json';atomic_json(root,mn,manifest)
        if fail:fail('manifest')
        pointer=dict(schema='flop-scout-router-current/v2',manifest=mn,manifest_sha256=mh,published_at=when)
        projector.check();atomic_json(root,'current.json',pointer,False)
        with projector.conn:
            projector.conn.execute('INSERT INTO publication_log VALUES(?,?,?,?)',(str(pub_id),mn,mh,name))
            projector.set('lg1_transition','0');projector.set('lg2_transition','0');projector.set('dirty','0');projector.set('last_publication',when);projector.set('publication_error','');projector.set('publication_failures','0');projector.set('publication_readiness',readiness(size));projector.set('publication_size_bytes',size);projector.set('published_database_sha256',h)
        return dict(manifest=manifest,pointer=pointer,readiness=readiness(size),preferred=size<512*1024**2,**({('lg2_publication_archive' if revision == TL1_REVISION else 'lg1_publication_archive'):lg1_archive} if lg1_archive else {}))
    except BaseException as exc:
        with projector.conn:
            projector.set('publication_error',str(exc));failures=int(projector.get('publication_failures','0'))+1;projector.set('publication_failures',failures)
            projector.set('publication_retry_seconds',min(900,15*2**min(failures,6)))
        raise
    finally:
        if temp and temp.exists():temp.unlink()


def _retain(root,keep=4,in_flight=()):
    root=Path(root);require(root.is_absolute() and not root.is_symlink(),'Invalid retention root');require(type(keep) is int and keep>=1,'Keep at least current publication')
    root=root.resolve();pointer=loads(read_artifact(root,'current.json',limit=16384));keys(pointer,{'schema','manifest','manifest_sha256','published_at'});require(pointer['schema']=='flop-scout-router-current/v2','Invalid retention pointer');current=pointer['manifest']
    require(hashlib.sha256(read_artifact(root,current,MANIFEST_PATTERN)).hexdigest()==pointer['manifest_sha256'],'Current pointer hash mismatch')
    manifests=[]
    for path in root.iterdir():
        match=MANIFEST_PATTERN.fullmatch(path.name)
        if match:
            raw=read_artifact(root,path.name,MANIFEST_PATTERN);require(hashlib.sha256(raw).hexdigest()==match[2],'Retention manifest hash mismatch')
            obj=loads(raw);require(obj['snapshot_id']==match[1] and DB_PATTERN.fullmatch(obj['database']),'Invalid retention manifest')
            safe_file(root,obj['database'],DB_PATTERN);manifests.append((int(match[1]),path.name,obj['database']))
        elif DB_PATTERN.fullmatch(path.name):safe_file(root,path.name,DB_PATTERN)
    require(any(name==current for _,name,_ in manifests),'Missing current manifest')
    retained={name for _,name,_ in sorted(manifests,reverse=True)[:keep]}|{current}
    referenced={db for _,name,db in manifests if name in retained}|set(in_flight)
    for name in in_flight:require(DB_PATTERN.fullmatch(name),'Invalid in-flight reference')
    removed=[]
    for _,name,_ in manifests:
        if name not in retained:safe_file(root,name,MANIFEST_PATTERN).unlink();removed.append(name)
    # Only matching owned filenames are candidates; shared heartbeat DB survives.
    for path in root.iterdir():
        if DB_PATTERN.fullmatch(path.name) and path.name not in referenced:safe_file(root,path.name,DB_PATTERN).unlink();removed.append(path.name)
    fsync_directory(root);return removed


class PublicationLock:
    def __init__(self,root):self.root=Path(root);self.fd=None
    def __enter__(self):
        require(self.root.is_absolute() and not self.root.is_symlink(),'Explicit regular publication root required')
        self.root.mkdir(parents=True,exist_ok=True)
        self.fd=os.open(str(self.root/'.scout-v2-publication.lock'),os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        try:fcntl.flock(self.fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(self.fd);self.fd=None;raise ProjectionError('Publication/retention already has an owner')
        return self
    def __exit__(self,*args):
        if self.fd is not None:os.close(self.fd)


def publish(projector,root,*,checked_cut,evaluated_at=None,fail=None):
    try:
        with PublicationLock(root):return _publish(projector,root,checked_cut=checked_cut,evaluated_at=evaluated_at,fail=fail)
    except (ProjectionError, InterruptedError) as exc:
        if projector.config['contract_revision'] in (LG2_REVISION, TL1_REVISION):projector.legacy_error(exc)
        raise


def retain(root,keep=4,in_flight=()):
    with PublicationLock(root):return _retain(root,keep,in_flight)
