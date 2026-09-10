"""Exact Scout source mapping and opt-in committed outbox.

No implicit source path. Source reads use existing immutable raw IDs; compatibility
rows are optional only when their exact raw link and location match.
"""
from __future__ import annotations
from scout_projection_contract import *
from scout_projection_model import classify, BENCH, KIBBLE


def observed_time(value):
    require(type(value) is str,'Missing immutable first-observed time')
    try:
        parsed=datetime.fromisoformat(value.replace('Z','+00:00'))
        require(parsed.tzinfo is not None,'Naive first-observed time')
        return utc(parsed.astimezone(timezone.utc))
    except ValueError as exc:raise ProjectionError('Invalid first-observed source time') from exc


def generation(value):
    if value is None:return 'UNKNOWN_LEGACY'
    if type(value) is int and value>=0:return str(value)
    return string(value)


def exact_cache(conn,table,raw,revision=REVISION,legacy=None,prepared=None):
    require(table in {'messages','evidence_records','tclk_frames','kibble_events'},'Unsupported compatibility cache')
    text_column={'messages':'text','evidence_records':'text','tclk_frames':'raw_text','kibble_events':'exact_text'}[table]
    rows=prepared.joined_cache(raw['raw_record_id'],table) if prepared is not None else conn.execute(f'SELECT c.*,l.raw_text_sha256 AS projection_link_hash FROM {table} c JOIN compatibility_evidence_links l ON l.cache_table=? AND l.cache_rowid=c.rowid WHERE l.raw_record_id=? ',(table,raw['raw_record_id'])).fetchall()
    matches=[]
    for row in rows:
        item=dict(row)
        require(item.pop('projection_link_hash')==raw['raw_text_sha256'],'Compatibility link hash mismatch')
        require(item['room']==raw['room'] and item['seq']==raw['seq'] and item[text_column]==raw['raw_text'],'Conflicting compatibility source link')
        if 'generation' in item and generation(item['generation'])!=generation(raw['generation']):
            if revision in (REVISION,LG2_REVISION,TL1_REVISION) and generation(raw['generation'])=='UNKNOWN_LEGACY':
                from scout_projection_legacy import source_proof
                if legacy is None: legacy,_=source_proof(conn,raw)
                require(item['generation']==legacy['reported_generation'],'Compatibility generation mismatch')
            else:
                from scout_projection_legacy import LegacyGenerationError
                raise LegacyGenerationError('LG1_GENERATION_CONFLICT')
        sender=item.get('sender',item.get('did',item.get('sender_did',item.get('transport_did'))))
        if sender is not None:require(sender==raw['sender_did'],'Compatibility sender mismatch')
        if table=='evidence_records':
            require(item.get('sig')==raw['signature'],'Compatibility signature mismatch')
            if item.get('nonce') is not None and raw['nonce'] is not None:
                require(type(item['nonce']) is int and re.fullmatch('[0-9]+',raw['nonce']) and item['nonce']==int(raw['nonce']),'Compatibility nonce mismatch')
        matches.append(item)
    require(len(matches)<=1,'Ambiguous compatibility evidence link')
    return matches[0] if matches else None


def map_raw(conn,raw_id,local_dids=(),revision=REVISION,*,_prepared=None):
    row=_prepared.raws.get(raw_id) if _prepared is not None else conn.execute('SELECT * FROM raw_network_records WHERE raw_record_id=?',(raw_id,)).fetchone();require(row,'Missing immutable raw input');raw=dict(row)
    event=_prepared.events.get(raw_id) if _prepared is not None else conn.execute('SELECT * FROM observed_events WHERE raw_record_id=?',(raw_id,)).fetchone()
    require(event and event['raw_text_sha256']==raw['raw_text_sha256'],'Missing or inconsistent committed derived evidence')
    if generation(raw['generation'])!='UNKNOWN_LEGACY' and raw.get('reported_generation') not in (None,raw['generation']):
        from scout_projection_legacy import LegacyGenerationError
        raise LegacyGenerationError('LG1_GENERATION_CONFLICT')
    legacy=originals=None
    if revision in (REVISION,LG2_REVISION,TL1_REVISION) and generation(raw['generation'])=='UNKNOWN_LEGACY' and raw.get('reported_generation') not in (None,'UNKNOWN_LEGACY','GENERATION_MISSING',''):
        from scout_projection_legacy import source_proof
        legacy,originals=source_proof(conn,raw,_prepared)
    primary,obj=classify(raw['raw_text']) if isinstance(raw['raw_text'],str) else ('MALFORMED_UNVERIFIABLE_EVENT',{})
    signed_candidate=isinstance(raw['sender_did'],str) and raw['sender_did'].startswith('did:key:z6Mk')
    structural=primary in {'TCLK_TRANSCRIPT_EVENT','VERIFICATION_REQUEST','VERIFICATION_RESULT','KIBBLE_JOB','KIBBLE_CLAIM','KIBBLE_RESULT','KIBBLE_ATTESTATION','WORK_REQUEST','WORK_ACCEPTANCE','WORK_RESULT'}
    if not signed_candidate and raw['signature_status']!='FAILED' and not raw['did_mismatch'] and not structural:return None
    require(text_hash(raw['raw_text'])==raw['raw_text_sha256'],'Raw source text corruption')
    cache=exact_cache(conn,'messages',raw,revision,legacy,_prepared);verified=exact_cache(conn,'evidence_records',raw,revision,legacy,_prepared)
    for table in ('tclk_frames','kibble_events'):exact_cache(conn,table,raw,revision,legacy,_prepared)
    msg=dict(projection_row_id='sm1:'+raw_id,room=raw['room'],generation=generation(raw['generation']),seq=raw['seq'],timestamp=raw['network_timestamp'],sender=raw['sender_did'],signed=cache['signed'] if cache else int(isinstance(raw['sender_did'],str) and raw['sender_did'].startswith('did:key:z6Mk')),text=raw['raw_text'],normalized_text=cache['normalized_text'] if cache else None,template_normalized_hash=cache['template_normalized_hash'] if cache else None,nonce=raw['nonce'],sig=raw['signature'],message_hash=verified['message_hash'] if verified else text_hash(raw['raw_text']),verification_status=verified['verification_status'] if verified else None,source_export_hash=None,source_export_path=None,evidence_id=verified['evidence_id'] if verified else None)
    meta=loads(raw['transport_metadata_json'])
    # Only the exact supplying export is an export provenance witness.
    if meta.get('snapshot_id'):
        snapshot=conn.execute('SELECT * FROM evidence_export_snapshots WHERE snapshot_id=?',(meta['snapshot_id'],)).fetchone()
        if snapshot:
            snapshot=dict(snapshot)
            require(snapshot['room']==msg['room'] and generation(snapshot['generation'])==msg['generation'],'Export provenance mismatch')
            msg['source_export_hash']=snapshot.get('content_sha256',snapshot.get('sha256'))
            msg['source_export_path']=snapshot.get('file_path',snapshot.get('path'))
    ann=annotation_template(revision)
    if revision==REVISION:ann['legacy_generation']=legacy
    if msg['sender'] in local_dids:ann.update(operator_group=FAMILY,same_operator=True,independent_reputation=False)
    primary,obj=classify(msg['text']);ann['classification']=primary
    if obj.get('schema_version',obj.get('schema')) in BENCH:
        link={k:obj.get(k) for k in ('request_id','result_hash','bench_did','validation_id','correctness','reproducibility','authenticity','evidence_classification')}
        if any(link[k] is not None for k in ('request_id','result_hash','bench_did','validation_id')):ann['verification_links']=[link]
    task={k:obj.get(k) for k in ('job_proto','job_id','task_hash','routing_decision_id','routing_decision_hash')}
    if any(v is not None for v in task.values()):ann['task_routing_links']=[task]
    facts=dict(signature_failure=raw['signature_status']=='FAILED' or bool(verified and verified['verification_status']=='INVALID_SIGNATURE'),did_mismatch=bool(raw['did_mismatch']),identity_binding=False,official=False,operator_local=msg['sender'] in local_dids,workflow=None)
    # Structured workflow authority is derived separately from exact cache proof;
    # unsupported linkage remains explicitly unresolved, never guessed closed.
    if msg['text'].startswith('tclk1 '):
        frame=exact_cache(conn,'tclk_frames',raw,revision)
        if frame and frame.get('transport_binding_status')=='TCLK_DID_MISMATCH':facts['did_mismatch']=True
        job=obj.get('job')
        if isinstance(job,dict) and any(job.get(k) is not None for k in ('proto','id')):
            ann['task_routing_links']=[dict(job_proto=job.get('proto'),job_id=job.get('id'),task_hash=None,routing_decision_id=None,routing_decision_hash=None)]
    tclk_original = None
    legacy_candidate = False
    if revision == TL1_REVISION and msg['text'].startswith('tclk1 '):
        from scout_projection_tclk import structural as tclk_structure, authenticated_original
        tclk_original = dict(raw=raw, event=dict(event))
        legacy_candidate = bool(tclk_structure(msg['text'])[1] and authenticated_original(tclk_original))
        if legacy_candidate:
            ann['classification'] = 'TCLK_LEGACY_NONCONFORMING'
            ann['capability_support'] = []
            msg['verification_status'] = 'VERIFIED_OFFLINE'
            # The compatibility parser labels missing/unparseable frame.from as
            # a mismatch. TL1 has independently verified transport authorship;
            # absence/parse failure is not contradictory authorship evidence.
            facts['did_mismatch'] = False
    workflow=None if legacy_candidate else workflow_from_source(conn,raw,msg,obj,revision)
    facts['workflow']=workflow
    provenance=dict(entity_type='message',projection_row_id=msg['projection_row_id'],source_namespace=raw['source'],source_record_locator=raw_id,scout_event_id=str(event['event_id']),raw_record_id=raw_id,raw_record_sha256=None,annotations_json=canonical(annotations(ann,revision)).decode())
    bundle=dict(message=msg,provenance=provenance,first_observed_at=observed_time(raw['created_at']),facts=facts,dependencies=[])
    if revision in (LG2_REVISION,TL1_REVISION):
        from scout_projection_compact import encode
        bundle['legacy_generation_compact']=encode(legacy)
    if originals is not None:bundle['legacy_generation_originals']=originals
    if revision == TL1_REVISION: bundle['tclk_original'] = tclk_original
    return bundle


def map_batch(conn,raw_ids,local_dids=(),revision=REVISION):
    require(type(raw_ids) is list and len(raw_ids)<=200,'Map at most 200 raw inputs')
    if revision not in (LG2_REVISION,TL1_REVISION):
        return [b for b in (map_raw(conn,r,local_dids,revision) for r in raw_ids) if b is not None]
    from scout_projection_batch import SourceInputs,SOURCE_BATCH_ROWS
    owned=not conn.in_transaction
    if owned:conn.execute('SAVEPOINT router_projection_source_read')
    try:
        result=[]
        for start in range(0,len(raw_ids),SOURCE_BATCH_ROWS):
            ids=raw_ids[start:start+SOURCE_BATCH_ROWS];prepared=SourceInputs(conn,ids)
            for rid in ids:
                b=map_raw(conn,rid,local_dids,revision,_prepared=prepared)
                if b is not None:result.append(b)
            prepared=None  # Release lookup maps before constructing the next batch.
        return result
    finally:
        # Mapping only reads. Release never commits a caller-owned transaction.
        if owned:conn.execute('RELEASE router_projection_source_read')


def workflow_from_source(conn,raw,msg,obj,revision=REVISION):
    """Only unique authenticated roots establish scoped workflow identity."""
    if msg['text'].startswith('tclk1 '):return tclk_workflow(conn,raw,msg,obj,revision)
    schema=obj.get('schema_version',obj.get('schema'));kind=obj.get('type');version=obj.get('version',obj.get('v'))
    is_kibble=isinstance(kind,str) and kind in KIBBLE and (type(version) in (str,int) and version in ('1','v1',1) or isinstance(schema,str) and schema.endswith('.v1'))
    if not is_kibble or not isinstance(obj.get('job_id'),str):
        primary,_=classify(msg['text'])
        if raw['signature_status']=='VERIFIED_OFFLINE' and primary in {'WORK_REQUEST','WORK_ACCEPTANCE','WORK_RESULT'}:
            wid,ident=workflow_identity('scout-unresolved/v1',msg['sender'],msg['room'],msg['generation'],'raw_record_id',raw['raw_record_id'],namespace=raw['source'])
            return dict(id=wid,identity=ident,role='ROOT',root_id=msg['projection_row_id'],result_id=None,authenticated=True,deadline_ms=None,terminal=None)
        return None
    job_id=obj['job_id'];candidates=[]
    for row in conn.execute("SELECT r.* FROM kibble_events k JOIN compatibility_evidence_links l ON l.cache_table='kibble_events' AND l.cache_rowid=k.rowid JOIN raw_network_records r ON r.raw_record_id=l.raw_record_id WHERE k.job_id=? AND k.event_type='JOB' AND r.room=? AND r.generation IS ?",(job_id,raw['room'],raw['generation'])):
        item=dict(row)
        exact_cache(conn,'kibble_events',item,revision)
        try:body=loads(item['raw_text'])
        except ProjectionError:continue
        if isinstance(body,dict) and body.get('job_id')==job_id and item['signature_status']=='VERIFIED_OFFLINE':candidates.append(item)
    if kind=='JOB' and raw['signature_status']=='VERIFIED_OFFLINE' and not any(r['raw_record_id']==raw['raw_record_id'] for r in candidates):candidates.append(raw)
    issuers={r['sender_did'] for r in candidates}
    if not candidates:return None
    require(len(issuers)==1,'Ambiguous workflow root issuer')
    issuer=next(iter(issuers));wid,ident=workflow_identity('kibble/v1',issuer,msg['room'],msg['generation'],'job_id',job_id)
    root_id='sm1:'+candidates[0]['raw_record_id'] if len(candidates)==1 else None
    result_id=obj.get('result_raw_record_id')
    if result_id is not None:result_id='sm1:'+string(result_id)
    return dict(id=wid,identity=ident,role='ROOT' if kind=='JOB' else 'RESULT' if kind in {'RESULT','DELIVER'} else 'TERMINAL' if kind=='ACCEPT' else kind,root_id=root_id,result_id=result_id,authenticated=raw['signature_status']=='VERIFIED_OFFLINE',deadline_ms=None,terminal='ACCEPT' if kind=='ACCEPT' else None)


def migrate_tl1(projector, source_path, cohort, raw_ids, evaluated_at):
    """Enumerate the whole quiescent source snapshot before one-way activation."""
    from scout_projection_tclk import validate_cohort
    resuming = projector.config['contract_revision'] == TL1_REVISION and projector.get('tl1_activation_pending') == '1'
    require(projector.config['contract_revision'] == LG2_REVISION or resuming, 'TL1 migration requires LG2 or its pending activation')
    if resuming:
        require(projector.config['legacy_tclk_cohort'] == cohort and projector.config['legacy_tclk_raw_ids'] == sorted(raw_ids), 'TL1 pending enrollment changed')
    with connect(Path(source_path), True) as source:
        source.execute('BEGIN')
        binding = source.execute('SELECT source_id,epoch FROM router_projection_source WHERE singleton=1').fetchone()
        require(binding and tuple(binding) == (projector.config['source_id'], projector.config['epoch']), 'TL1_SOURCE_BINDING_MISMATCH')
        require(not source.execute("SELECT 1 FROM router_projection_outbox WHERE status!='COMPLETE'").fetchone() and not source.execute('SELECT 1 FROM router_projection_pending').fetchone() and not source.execute('SELECT 1 FROM router_projection_pending_edges').fetchone(), 'TL1_INCOMPLETE_SOURCE_BATCH')
        require(not source.execute('SELECT 1 FROM raw_network_records r LEFT JOIN observed_events e ON e.raw_record_id=r.raw_record_id WHERE e.event_id IS NULL LIMIT 1').fetchone(), 'TL1_SOURCE_ORIGINAL_UNCOMMITTED')
        cut = str(source.execute('SELECT coalesce(max(event_id),0) FROM observed_events').fetchone()[0])
        prior_cut = loads(projector.get('source_cut', 'null'))
        require(prior_cut is None or int(cut) >= int(prior_cut['committed_event_id']), 'TL1_SOURCE_CUT_REGRESSED')
        previous = projector.conn.execute('SELECT id FROM current_inputs ORDER BY id')
        while True:
            rows = previous.fetchmany(200)
            if not rows: break
            projector.check()
            old_ids = [row[0][4:] for row in rows]
            available = source.execute('SELECT count(*) FROM raw_network_records WHERE raw_record_id IN (' + ','.join('?' for _ in old_ids) + ')', old_ids).fetchone()[0]
            require(available == len(old_ids), 'TL1_HISTORICAL_SOURCE_ORIGINAL_MISSING')
        validate_cohort(cohort, source_id=projector.config['source_id'], epoch=projector.config['epoch'], cut=cut, raw_ids=raw_ids)
        discovered = []
        cursor = source.execute('SELECT raw_record_id FROM observed_events ORDER BY event_id')
        while True:
            batch = cursor.fetchmany(200)
            if not batch: break
            projector.check()
            for bundle in map_batch(source, [row[0] for row in batch], projector.config['local_dids'], TL1_REVISION):
                if loads(bundle['provenance']['annotations_json'])['classification'] == 'TCLK_LEGACY_NONCONFORMING':
                    require(int(bundle['provenance']['scout_event_id']) <= int(cohort['through_event_id']), 'TL1_AFTER_HISTORICAL_CUT')
                    discovered.append(bundle['provenance']['raw_record_id'])
                    require(len(discovered) <= 4096, 'TL1_COHORT_CAPACITY')
        validate_cohort(cohort, source_id=projector.config['source_id'], epoch=projector.config['epoch'], cut=cut, raw_ids=discovered)
        if not resuming: projector.activate_tl1(cohort, raw_ids)
        pending = projector.conn.execute("SELECT number,body,status FROM evaluations WHERE status!='COMPLETE'").fetchone()
        if pending:
            require(loads(pending['body'])['source_cut']['committed_event_id'] == cut, 'TL1 pending source cut changed')
            number = pending['number']
        else:
            number = projector.begin(cut, evaluated_at, 'SOURCE_BATCH')
        if pending is None or pending['status'] == 'STAGING':
            cursor = source.execute('SELECT raw_record_id FROM observed_events ORDER BY event_id')
            while True:
                batch = cursor.fetchmany(200)
                if not batch: break
                projector.stage(number, map_batch(source, [row[0] for row in batch], projector.config['local_dids'], TL1_REVISION))
            edges = []
            for row in source.execute('SELECT * FROM interactions ORDER BY room,source_seq,response_seq,relationship_type'):
                edges.append(resolve_interaction(source, dict(row)))
                if len(edges) == 200: projector.stage_edges(number, edges); edges = []
            if edges: projector.stage_edges(number, edges)
            result = projector.seal(number)
        else:
            result = projector.resume(number)
        with projector.conn:
            projector.set('tl1_activation_pending', '0')
            projector.record_operation('TL1_ENUMERATION', dict(source_cut=cut))
            projector.set('outbox_position', source.execute('SELECT coalesce(max(id),0) FROM router_projection_outbox').fetchone()[0])
        return result


def tclk_workflow(conn,raw,msg,obj,revision=REVISION):
    if revision == TL1_REVISION:
        from scout_projection_tclk import structural
        if structural(msg['text'])[1]: return None
    frame=exact_cache(conn,'tclk_frames',raw,revision)
    if not frame:return None
    authenticated=frame['parse_status']=='TCLK_PARSEABLE' and frame['transport_binding_status']=='SIGNED_TCLK_FRAME' and frame['transport_verification_status']=='VERIFIED_OFFLINE'
    kind=obj.get('type');initial=obj.get('id') if kind=='offer' else obj.get('ref') or obj.get('contract')
    if not isinstance(initial,str):
        require(not authenticated or kind=='offer','Authenticated TCLK transition lacks resolvable linkage')
        return None
    frontier=[initial];seen=set();candidates={}
    while frontier:
        key=frontier.pop(0)
        if key in seen:continue
        seen.add(key);require(len(seen)<=200,'TCLK source linkage exceeds bounded lookup capacity')
        rows=conn.execute("SELECT r.* FROM tclk_frames t JOIN compatibility_evidence_links l ON l.cache_table='tclk_frames' AND l.cache_rowid=t.rowid JOIN raw_network_records r ON r.raw_record_id=l.raw_record_id WHERE (t.offer_id=? OR t.contract_id=?) AND r.room=? AND r.generation IS ? LIMIT 201",(key,key,raw['room'],raw['generation'])).fetchall()
        require(len(rows)<=200,'TCLK reference fanout exceeds bounded lookup capacity')
        for row in rows:
            candidate=dict(row);cache=exact_cache(conn,'tclk_frames',candidate,revision)
            if not cache or cache['transport_binding_status']!='SIGNED_TCLK_FRAME' or cache['transport_verification_status']!='VERIFIED_OFFLINE' or cache['parse_status']!='TCLK_PARSEABLE':continue
            if revision == TL1_REVISION and structural(candidate['raw_text'])[1]: continue
            body=loads(candidate['raw_text'][6:])
            if body.get('type')=='offer':candidates[candidate['raw_record_id']]=(candidate,body)
            else:
                for value in (body.get('ref'),body.get('contract')):
                    if isinstance(value,str) and value not in seen:frontier.append(value)
        frontier=sorted(set(frontier))
    if kind=='offer' and authenticated:candidates[raw['raw_record_id']]=(raw,obj)
    if not candidates:
        require(not authenticated,'Authenticated TCLK transition has no authoritative offer root')
        return None
    identities={(r['sender_did'],b.get('id')) for r,b in candidates.values()};require(len(identities)==1,'Ambiguous TCLK maker/offer root')
    issuer,offer_id=next(iter(identities));string(offer_id)
    wid,ident=workflow_identity('tclk/1',issuer,msg['room'],msg['generation'],'offer_id',offer_id)
    deadline=obj.get('expiresMs') if kind=='offer' else None
    if type(deadline) is not int or deadline<0:deadline=None
    root_ids=sorted(candidates)
    return dict(id=wid,identity=ident,role='ROOT' if kind=='offer' else str(kind).upper(),root_id='sm1:'+root_ids[0] if len(root_ids)==1 else None,result_id=None,authenticated=authenticated,deadline_ms=deadline,terminal=None)


def _bootstrap(projector,source_path,cut,evaluated_at):
    """Explicit quiescent committed cut; never used for each publication."""
    source_path=Path(source_path)
    require(source_path.resolve()!=projector.path.resolve(),'Source cannot be projection')
    decimal(cut)
    with connect(source_path,True) as source:
        source.execute('BEGIN')
        indexes={r[0] for r in source.execute("SELECT name FROM sqlite_master WHERE type='index'")}
        require('router_projection_raw_links' in indexes,'Prepare the opt-in indexed source outbox before bootstrap')
        require(not source.execute("SELECT 1 FROM router_projection_outbox WHERE status!='COMPLETE'").fetchone() and not source.execute('SELECT 1 FROM router_projection_pending').fetchone() and not source.execute('SELECT 1 FROM router_projection_pending_edges').fetchone(),'Bootstrap source has an incomplete logical batch')
        binding=source.execute('SELECT source_id,epoch FROM router_projection_source WHERE singleton=1').fetchone();require(binding and tuple(binding)==(projector.config['source_id'],projector.config['epoch']),'Bootstrap source binding mismatch')
        require(source.execute('SELECT coalesce(max(event_id),0) FROM observed_events').fetchone()[0]==int(cut),'Bootstrap cut must equal the complete source snapshot')
        require(not source.execute('SELECT 1 FROM raw_network_records r LEFT JOIN observed_events e ON e.raw_record_id=r.raw_record_id WHERE e.event_id IS NULL LIMIT 1').fetchone(),'Raw-first source has incomplete derived records')
        number=projector.begin(cut,evaluated_at,'BOOTSTRAP');batch=[]
        for row in source.execute('SELECT raw_record_id FROM observed_events WHERE event_id<=? ORDER BY event_id',(int(cut),)):
            batch.append(row[0])
            if len(batch)==200:
                projector.stage(number,map_batch(source,batch,projector.config['local_dids'],projector.config['contract_revision']));batch=[]
        if batch:projector.stage(number,map_batch(source,batch,projector.config['local_dids'],projector.config['contract_revision']))
        edges=[]
        for row in source.execute('SELECT * FROM interactions ORDER BY room,source_seq,response_seq,relationship_type'):
            edges.append(resolve_interaction(source,dict(row)))
            if len(edges)==200:projector.stage_edges(number,edges);edges=[]
        if edges:projector.stage_edges(number,edges)
        result=projector.seal(number)
        with projector.conn:projector.set('outbox_position',source.execute('SELECT coalesce(max(id),0) FROM router_projection_outbox').fetchone()[0])
        return result


def resolve_interaction(conn,row):
    pairs=[]
    for sequence,did in [(row['source_seq'],row['source_did']),(row['response_seq'],row['target_did'])]:
        values=[dict(r) for r in conn.execute('SELECT raw_record_id,generation FROM raw_network_records WHERE room=? AND seq=? AND sender_did=?',(row['room'],sequence,did))]
        pairs.append(values)
    consistent=[(a,b) for a in pairs[0] for b in pairs[1] if generation(a['generation'])==generation(b['generation'])]
    require(len(consistent)==1,'INTERACTION_SOURCE_AMBIGUOUS')
    a,b=consistent[0]
    return dict(source_id='sm1:'+a['raw_record_id'],target_id='sm1:'+b['raw_record_id'],relationship_type=row['relationship_type'],confidence=row['confidence'])


OUTBOX_SQL="""
CREATE TABLE IF NOT EXISTS router_projection_source(singleton INTEGER PRIMARY KEY CHECK(singleton=1),source_id TEXT NOT NULL,epoch TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS router_projection_retrieval_raw ON evidence_retrievals(raw_record_id);
CREATE TRIGGER IF NOT EXISTS router_projection_retrieval AFTER INSERT ON evidence_retrievals BEGIN INSERT OR IGNORE INTO router_projection_pending VALUES(NEW.raw_record_id); END;
CREATE TRIGGER IF NOT EXISTS router_projection_alternate_raw AFTER INSERT ON raw_network_records BEGIN INSERT OR IGNORE INTO router_projection_pending SELECT raw_record_id FROM raw_network_records WHERE room=NEW.room AND seq=NEW.seq AND raw_text_sha256=NEW.raw_text_sha256 AND (generation IS NULL OR generation='UNKNOWN_LEGACY'); END;
CREATE INDEX IF NOT EXISTS router_projection_raw_links ON compatibility_evidence_links(raw_record_id,raw_text_sha256,cache_table,cache_rowid);
CREATE INDEX IF NOT EXISTS router_projection_tclk_offer ON tclk_frames(offer_id,frame_type,room,generation);
CREATE INDEX IF NOT EXISTS router_projection_tclk_contract ON tclk_frames(contract_id,room,generation);
CREATE TABLE IF NOT EXISTS router_projection_outbox(id INTEGER PRIMARY KEY AUTOINCREMENT,cut TEXT,evaluated_at TEXT,status TEXT NOT NULL,parts_sha256 TEXT);
CREATE TABLE IF NOT EXISTS router_projection_outbox_parts(batch_id INTEGER NOT NULL,part INTEGER NOT NULL,payload TEXT NOT NULL,payload_sha256 TEXT NOT NULL,PRIMARY KEY(batch_id,part));
CREATE TABLE IF NOT EXISTS router_projection_pending(raw_record_id TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS router_projection_pending_edges(room TEXT NOT NULL,source_seq INTEGER NOT NULL,response_seq INTEGER NOT NULL,source_did TEXT NOT NULL,target_did TEXT NOT NULL,relationship_type TEXT NOT NULL,confidence REAL NOT NULL,PRIMARY KEY(room,source_seq,response_seq,relationship_type));
CREATE TABLE IF NOT EXISTS router_projection_outbox_edges(batch_id INTEGER NOT NULL,edge_key TEXT NOT NULL,payload TEXT NOT NULL,payload_sha256 TEXT NOT NULL,PRIMARY KEY(batch_id,edge_key));
CREATE TRIGGER IF NOT EXISTS router_projection_edge AFTER INSERT ON interactions BEGIN INSERT OR REPLACE INTO router_projection_pending_edges VALUES(NEW.room,NEW.source_seq,NEW.response_seq,NEW.source_did,NEW.target_did,NEW.relationship_type,NEW.confidence); END;
CREATE TRIGGER IF NOT EXISTS router_projection_raw AFTER INSERT ON raw_network_records BEGIN INSERT OR IGNORE INTO router_projection_pending VALUES(NEW.raw_record_id); END;
CREATE TRIGGER IF NOT EXISTS router_projection_new_event AFTER INSERT ON observed_events BEGIN INSERT OR IGNORE INTO router_projection_pending VALUES(NEW.raw_record_id); END;
CREATE TRIGGER IF NOT EXISTS router_projection_removed_event AFTER DELETE ON observed_events BEGIN INSERT OR IGNORE INTO router_projection_pending VALUES(OLD.raw_record_id); END;
CREATE TRIGGER IF NOT EXISTS router_projection_derived AFTER UPDATE ON observed_events BEGIN INSERT OR IGNORE INTO router_projection_pending VALUES(NEW.raw_record_id); END;
CREATE TRIGGER IF NOT EXISTS router_projection_link AFTER INSERT ON compatibility_evidence_links BEGIN INSERT OR IGNORE INTO router_projection_pending VALUES(NEW.raw_record_id); END;
CREATE TRIGGER IF NOT EXISTS router_projection_relink AFTER UPDATE ON compatibility_evidence_links BEGIN INSERT OR IGNORE INTO router_projection_pending VALUES(OLD.raw_record_id); INSERT OR IGNORE INTO router_projection_pending VALUES(NEW.raw_record_id); END;
CREATE TRIGGER IF NOT EXISTS router_projection_unlink AFTER DELETE ON compatibility_evidence_links BEGIN INSERT OR IGNORE INTO router_projection_pending VALUES(OLD.raw_record_id); END;
"""


class Outbox:
    """Bounded staging on Scout's existing writer; only complete logical cuts seal."""
    def __init__(self,conn,local_dids=(),*,epoch,source_id='scout-observer',install=False,revision=REVISION,cohort=None):
        self.cohort=cohort
        if revision == TL1_REVISION: require(cohort is not None, 'TL1 explicit outbox cohort required')
        if revision == TL1_REVISION:
            from scout_projection_tclk import validate_cohort
            validate_cohort(cohort,source_id=source_id,epoch=epoch,cut=cohort['through_event_id'])
        self.conn=conn;self.local_dids=local_dids;self.revision=revision
        require(revision in REVISIONS,'Unsupported outbox revision')
        if install:
            if conn.execute("SELECT 1 FROM sqlite_master WHERE name='router_projection_source' AND type='table'").fetchone() and conn.execute('SELECT 1 FROM router_projection_source').fetchone():
                import scout_schema
                existing=scout_schema.structure(conn);expected=scout_schema.projection_outbox_contract()
                require(all(name in existing for name,obj in expected.items() if obj['kind']=='table'),'Lost source outbox history must be restored, not recreated empty')
            conn.executescript(OUTBOX_SQL)
            for table in ('messages','evidence_records','kibble_events','tclk_frames'):
                conn.execute(update_trigger_sql(table))
            with conn:conn.execute('INSERT OR IGNORE INTO router_projection_source VALUES(1,?,?)',(source_id,epoch))
        row=conn.execute('SELECT source_id,epoch FROM router_projection_source WHERE singleton=1').fetchone()
        require(row and tuple(row)==(source_id,epoch),'Outbox source binding missing or mismatched; prepare it explicitly before worker startup')

    def capture(self,complete=False):
        rows=self.conn.execute('SELECT raw_record_id FROM router_projection_pending ORDER BY raw_record_id LIMIT 200').fetchall()
        bundles=map_batch(self.conn,[r[0] for r in rows],self.local_dids,self.revision)
        edge_rows=self.conn.execute('SELECT * FROM router_projection_pending_edges ORDER BY room,source_seq,response_seq,relationship_type LIMIT 200').fetchall()
        edges=[resolve_interaction(self.conn,dict(row)) for row in edge_rows]
        with self.conn:
            header=self.conn.execute("SELECT id FROM router_projection_outbox WHERE status='OPEN'").fetchone()
            if not header and not rows and not edges:return None
            if not header:
                batch_id=self.conn.execute("INSERT INTO router_projection_outbox(status) VALUES('OPEN')").lastrowid
            else:batch_id=header[0]
            if rows or (not header and self.revision in (REVISION,LG2_REVISION,TL1_REVISION)):
                part=self.conn.execute('SELECT coalesce(max(part),0)+1 FROM router_projection_outbox_parts WHERE batch_id=?',(batch_id,)).fetchone()[0]
                self.conn.execute('INSERT INTO router_projection_outbox_parts VALUES(?,?,?,?)',(batch_id,part,canonical(pack(bundles,self.revision,self.cohort)).decode(),digest(pack(bundles,self.revision,self.cohort))))
                self.conn.executemany('DELETE FROM router_projection_pending WHERE raw_record_id=?',[(r[0],) for r in rows])
            for edge,row in zip(edges,edge_rows):
                self.conn.execute('INSERT OR REPLACE INTO router_projection_outbox_edges VALUES(?,?,?,?)',(batch_id,digest({k:v for k,v in edge.items() if k!='confidence'}),canonical(edge).decode(),digest(edge)))
                self.conn.execute('DELETE FROM router_projection_pending_edges WHERE room=? AND source_seq=? AND response_seq=? AND relationship_type=?',(row['room'],row['source_seq'],row['response_seq'],row['relationship_type']))
            if complete and not self.conn.execute('SELECT 1 FROM router_projection_pending').fetchone() and not self.conn.execute('SELECT 1 FROM router_projection_pending_edges').fetchone():
                cut=str(self.conn.execute('SELECT coalesce(max(event_id),0) FROM observed_events').fetchone()[0])
                self.conn.execute("UPDATE router_projection_outbox SET status='COMPLETE',cut=?,evaluated_at=?,parts_sha256=? WHERE id=?",(cut,utc(),outbox_manifest(self.conn,batch_id),batch_id))
                return cut
        return None


def _consume(projector,source_path,limit=1):
    require(type(limit) is int and 1<=limit<=200,'Invalid outbox turn limit')
    with connect(Path(source_path),True) as source:
        binding=source.execute('SELECT source_id,epoch FROM router_projection_source WHERE singleton=1').fetchone()
        require(binding and tuple(binding)==(projector.config['source_id'],projector.config['epoch']),'Outbox source namespace mismatch')
        position=int(projector.get('outbox_position','0'))
        require(source.execute('SELECT coalesce(max(id),0) FROM router_projection_outbox').fetchone()[0]>=position,'Source outbox history was reset or lost')
        rows=source.execute('SELECT * FROM router_projection_outbox WHERE id>? ORDER BY id LIMIT ?',(position,limit)).fetchall()
        for row in rows:
            require(row['id']==position+1,'Outbox gap')
            if row['status']!='COMPLETE':break
            require(row['parts_sha256']==outbox_manifest(source,row['id']),'Outbox complete-cut manifest mismatch')
            if projector.config['contract_revision'] in (REVISION,LG2_REVISION):
                require(source.execute('SELECT 1 FROM router_projection_outbox_parts WHERE batch_id=? LIMIT 1',(row['id'],)).fetchone(),'LG1 outbox cut lacks revision/policy binding')
            saved=projector.get('outbox_evaluation:'+str(row['id']))
            if not saved:
                pending_row=projector.conn.execute("SELECT number,body FROM evaluations WHERE status!='COMPLETE'").fetchone()
                if pending_row:
                    body=loads(pending_row['body'])
                    require(body['source_cut']['committed_event_id']==row['cut'] and body['evaluated_at']==row['evaluated_at'],'Pending cut does not match outbox')
                    saved=str(pending_row['number'])
            if saved:
                pending=projector.conn.execute('SELECT status FROM evaluations WHERE number=?',(int(saved),)).fetchone()
                if pending['status']=='STAGING':
                    for part in source.execute('SELECT * FROM router_projection_outbox_parts WHERE batch_id=? ORDER BY part',(row['id'],)):
                        payload=loads(part['payload']);require(digest(payload)==part['payload_sha256'],'Outbox corruption');bundles=unpack(payload,projector.config['contract_revision'],projector.config.get('legacy_tclk_cohort'));projector.stage(int(saved),bundles)
                        payload=None;bundles=None;part=None
                    stage_outbox_edges(projector,source,row['id'],int(saved))
                    projector.seal(int(saved))
                elif pending['status']!='COMPLETE':projector.resume(int(saved))
            else:
                number=projector.begin(row['cut'],row['evaluated_at'])
                part_number=0
                for part in source.execute('SELECT * FROM router_projection_outbox_parts WHERE batch_id=? ORDER BY part',(row['id'],)):
                    part_number+=1;require(part['part']==part_number,'Outbox part gap')
                    payload=loads(part['payload']);require(digest(payload)==part['payload_sha256'],'Outbox corruption');bundles=unpack(payload,projector.config['contract_revision'],projector.config.get('legacy_tclk_cohort'))
                    projector.stage(number,bundles)
                    # Sealing reloads its verified inputs from the ledger. Do
                    # not retain the previous source part across the next decode
                    # or the complete sender evaluation.
                    payload=None;bundles=None;part=None
                with projector.conn:projector.set('outbox_evaluation:'+str(row['id']),number)
                stage_outbox_edges(projector,source,row['id'],number)
                projector.seal(number)
            with projector.conn:projector.set('outbox_position',row['id'])
            position=row['id']
        caught_up=not source.execute('SELECT 1 FROM router_projection_pending').fetchone() and not source.execute('SELECT 1 FROM router_projection_pending_edges').fetchone() and not source.execute('SELECT 1 FROM router_projection_outbox WHERE id>?',(position,)).fetchone()
        if caught_up:
            actual=source.execute('SELECT coalesce(max(event_id),0) FROM observed_events').fetchone()[0]
            require(projector.get('source_cut') is not None and int(loads(projector.get('source_cut'))['committed_event_id'])==actual,'Committed source events are ahead of the checked outbox cut')
    result=projector.status();result['source_caught_up']=caught_up;return result


def stage_outbox_edges(projector,source,batch_id,number):
    edges=[]
    for row in source.execute('SELECT * FROM router_projection_outbox_edges WHERE batch_id=? ORDER BY edge_key',(batch_id,)):
        edge=loads(row['payload']);require(digest(edge)==row['payload_sha256'],'Corrupt outbox interaction')
        edges.append(edge)
        if len(edges)==200:projector.stage_edges(number,edges);edges=[]
    if edges:projector.stage_edges(number,edges)


def outbox_manifest(conn,batch_id):
    h=hashlib.sha256()
    for row in conn.execute('SELECT part,payload_sha256 FROM router_projection_outbox_parts WHERE batch_id=? ORDER BY part',(batch_id,)):h.update(canonical(['messages',*tuple(row)]))
    for row in conn.execute('SELECT edge_key,payload_sha256 FROM router_projection_outbox_edges WHERE batch_id=? ORDER BY edge_key',(batch_id,)):h.update(canonical(['interaction',*tuple(row)]))
    return h.hexdigest()


def update_trigger_sql(table):
    require(table in {'messages','evidence_records','kibble_events','tclk_frames'},'Unknown source cache trigger')
    return f"CREATE TRIGGER IF NOT EXISTS router_projection_changed_{table} AFTER UPDATE ON {table} BEGIN INSERT OR IGNORE INTO router_projection_pending SELECT raw_record_id FROM compatibility_evidence_links WHERE cache_table='{table}' AND cache_rowid=NEW.rowid; END"


def pack(bundles,revision,cohort=None):
    if revision=='A1':return bundles
    if revision==TL1_REVISION:require(cohort is not None,'TL1 explicit outbox cohort required')
    return dict(revision_metadata(revision,cohort),bundles=bundles)


def unpack(payload,revision,cohort=None):
    if revision=='A1':
        require(type(payload) is list,'Mixed A1/LG1 source outbox');return payload
    keys(payload,set(revision_metadata(revision)) | {'bundles'})
    require(revision_binding(payload)==revision,'Mixed A1/LG1 source outbox')
    if revision == TL1_REVISION: require(cohort is not None and payload['legacy_tclk_cohort'] == cohort, 'TL1_OUTBOX_COHORT_MISMATCH')
    require(type(payload['bundles']) is list,'Invalid outbox records');return payload['bundles']


def bootstrap(projector,source_path,cut,evaluated_at):
    try:return _bootstrap(projector,source_path,cut,evaluated_at)
    except ProjectionError as exc:
        projector.legacy_error(exc);raise


def consume(projector,source_path,limit=1):
    try:return _consume(projector,source_path,limit)
    except ProjectionError as exc:
        projector.legacy_error(exc);raise
