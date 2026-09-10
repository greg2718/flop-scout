"""Local-only CLI; status paths are read-only and never initialize state."""
from pathlib import Path
from scout_projection_contract import *


def add_parser(sub):
    root=sub.add_parser('projection',help='Opt-in local Router V2/A1-LG2 projection')
    root.add_argument('--db',type=Path,required=True,help='Absolute dedicated projection DB (never observer.sqlite)')
    commands=root.add_subparsers(dest='projection_cmd',required=True)
    init=commands.add_parser('init')
    for name in ('epoch','router-source-id','router-epoch','router-did'):init.add_argument('--'+name,required=True)
    init.add_argument('--contract-revision',choices=REVISIONS,default=LG2_REVISION)
    init.add_argument('--tl1-enrollment',type=Path,help='Explicit JSON with cohort and raw_ids; mandatory for TL1')
    commands.add_parser('migrate-lg1')
    commands.add_parser('migrate-lg2')
    tl1=commands.add_parser('migrate-tl1')
    tl1.add_argument('--source-db',type=Path,required=True)
    tl1.add_argument('--tl1-enrollment',type=Path,required=True)
    tl1.add_argument('--evaluated-at')
    init.add_argument('--local-did',action='append',default=[])
    for name in ('status','pin-status','expiry-status','publication-status'):commands.add_parser(name)
    commands.add_parser('tl1-status')
    hints=commands.add_parser('tl1-hints');hints.add_argument('--offset',type=int,default=0);hints.add_argument('--limit',type=int,default=100)
    record=commands.add_parser('tl1-record');record.add_argument('--raw-id',required=True)
    replay=commands.add_parser('replay');replay.add_argument('--destination',type=Path)
    source_init=commands.add_parser('source-init');source_init.add_argument('--source-db',type=Path,required=True)
    update=commands.add_parser('update');update.add_argument('--source-db',type=Path,required=True);update.add_argument('--bootstrap',action='store_true');update.add_argument('--complete-cut');update.add_argument('--evaluated-at')
    pin=commands.add_parser('pin-import');pin.add_argument('artifact',type=Path)
    expiry=commands.add_parser('expiry-run');expiry.add_argument('--evaluated-at')
    publication=commands.add_parser('publish');publication.add_argument('--root',type=Path,required=True);publication.add_argument('--source-db',type=Path,required=True);publication.add_argument('--pins',type=Path,required=True)
    artifact=commands.add_parser('artifact-import');artifact.add_argument('artifact',type=Path);artifact.add_argument('--id',required=True);artifact.add_argument('--source-id',required=True);artifact.add_argument('--epoch',required=True);artifact.add_argument('--authority',choices=['AUDIT_DIRECTIVE','CONTROLLED_BENCH','OBJECTIVE_VALIDATION'],required=True)
    qualify=commands.add_parser('qualify-local');qualify.add_argument('--request-id',required=True);qualify.add_argument('--result-id',required=True);qualify.add_argument('--kind',choices=['CONTROLLED_BENCH','OBJECTIVE_VALIDATION','CAPABILITY_CONTRADICTION'],required=True)
    event=commands.add_parser('qualification-event');event.add_argument('artifact',type=Path)
    retention=commands.add_parser('retention-run');retention.add_argument('--root',type=Path,required=True);retention.add_argument('--keep',type=int,default=4)
    return root


def run(args):
    from scout_projection import Projector,initialize,read_status
    from scout_projection_source import bootstrap,consume
    from scout_projection_pins import import_pins
    from scout_projection_publish import publish
    require(args.db.is_absolute(),'Explicit absolute projection DB required')
    command=args.projection_cmd
    if command in {'status','pin-status','expiry-status','publication-status','tl1-status'}:return read_status(args.db)
    if command=='tl1-hints':
        from scout_projection_tclk import audit_hints
        require(read_status(args.db)['contract_revision']==TL1_REVISION, 'TL1 revision required')
        with connect(args.db,True) as conn:return audit_hints(conn,offset=args.offset,limit=args.limit)
    if command=='tl1-record':
        from scout_projection_tclk import claims, reason_names, POLICY as TL1_POLICY
        sha(args.raw_id)
        require(read_status(args.db)['contract_revision']==TL1_REVISION, 'TL1 revision required')
        with connect(args.db,True) as conn:
            row=conn.execute('SELECT l.*,m.text,m.room,m.generation,p.source_record_locator,p.scout_event_id FROM legacy_tclk_records l JOIN messages m ON m.projection_row_id=l.message_id JOIN source_provenance p ON p.entity_type=\'message\' AND p.projection_row_id=l.message_id WHERE l.raw_ref=?',(bytes.fromhex(args.raw_id),)).fetchone()
            require(row is not None, 'TL1 record not found')
            return dict(legacy_tclk_record_id='lt1:'+args.raw_id,message_id=row['message_id'],claimed_type_code=row['claimed_type_code'],reasons=reason_names(row['nonconformance_mask']),claims=claims(row['text']),dialect=TL1_POLICY['dialect'],authentication='AUTHENTICATED_BUT_NONCONFORMING',room=row['room'],generation=row['generation'],source_record_locator=row['source_record_locator'],scout_event_id=row['scout_event_id'])
    enrollment=None
    if getattr(args,'tl1_enrollment',None):
        require(args.tl1_enrollment.is_absolute() and not args.tl1_enrollment.is_symlink(), 'Explicit local TL1 enrollment required')
        with open(args.tl1_enrollment,'rb') as stream:enrollment=loads(stream.read(4*1024*1024+1))
        keys(enrollment,{'cohort','raw_ids'})
    if command=='init':return initialize(args.db,epoch=args.epoch,router_source_id=args.router_source_id,router_epoch=args.router_epoch,router_did=args.router_did,local_dids=args.local_did,contract_revision=args.contract_revision,legacy_tclk_cohort=enrollment['cohort'] if enrollment else None,legacy_tclk_raw_ids=enrollment['raw_ids'] if enrollment else None)
    with Projector(args.db) as p:
        if command=='migrate-lg1':return p.enable_lg1()
        if command=='migrate-lg2':return p.enable_lg2()
        if command=='migrate-tl1':
            from scout_projection_source import migrate_tl1
            return migrate_tl1(p,args.source_db,enrollment['cohort'],enrollment['raw_ids'],args.evaluated_at or utc())
        if command=='source-init':
            from scout_projection_source import Outbox
            import flop_scout
            require(args.source_db.is_absolute() and args.source_db.resolve()!=args.db.resolve(),'Explicit distinct observer source required')
            with flop_scout.poll_lock(args.source_db.parent) as acquired:
                require(acquired,'Source writer must be fenced for outbox preparation')
                with connect(args.source_db) as source:Outbox(source,p.config['local_dids'],epoch=p.config['epoch'],source_id=p.config['source_id'],install=True,revision=p.config['contract_revision'],cohort=p.config.get('legacy_tclk_cohort'))
            return {'source_outbox_prepared':True,'source_id':p.config['source_id'],'epoch':p.config['epoch']}
        if command in {'artifact-import','qualification-event'}:
            require(args.artifact.is_absolute() and not args.artifact.is_symlink(),'Explicit regular local artifact required')
            with open(args.artifact,'rb') as stream:raw=stream.read(4*1024*1024+1)
            if command=='artifact-import':return p.import_artifact(args.id,raw,source_id=args.source_id,epoch=args.epoch,authority=args.authority)
            return {'event_id':p.append_event(loads(raw,65536))}
        if command=='qualify-local':
            refs=[]
            for identifier in (args.request_id,args.result_id):
                row=p.conn.execute('SELECT * FROM local_artifacts WHERE id=?',(identifier,)).fetchone();require(row,'Missing explicit local artifact import')
                refs.append(dict(kind='LOCAL_ARTIFACT',source_id=row['source_id'],source_epoch=row['epoch'],id=row['id'],sha256=row['hash']))
            qid=p.qualify_objective_contradiction(*refs) if args.kind=='CAPABILITY_CONTRADICTION' else p.qualify_local_bench(*refs,kind=args.kind)
            return {'qualification_id':qid}
        if command=='retention-run':
            from scout_projection_publish import retain
            return {'removed':retain(args.root,args.keep)}
        if command=='replay':return p.replay_to(args.destination) if args.destination else p.resume()
        if command=='update':
            if args.bootstrap:
                require(args.complete_cut is not None,'Bootstrap requires explicit --complete-cut for a quiescent committed source')
                return bootstrap(p,args.source_db,args.complete_cut,args.evaluated_at or utc())
            return consume(p,args.source_db)
        if command=='pin-import':
            try:
                require(args.artifact.is_absolute() and not args.artifact.is_symlink(),'Explicit regular local pin artifact required')
                with open(args.artifact,'rb') as stream:return import_pins(p,stream.read(4*1024*1024+1))
            except Exception as exc:
                with p.conn:p.set('pin_error',str(exc))
                raise
        if command=='expiry-run':
            cut=loads(p.get('source_cut','null'));require(cut,'Bootstrap required')
            n=p.begin(cut['committed_event_id'],args.evaluated_at or utc(),'EXPIRY');return p.seal(n)
        if command=='publish':
            result=consume(p,args.source_db)
            require(result['source_caught_up'],'Source is not caught up')
            require(args.pins.is_absolute() and not args.pins.is_symlink(),'Explicit regular pin artifact required')
            with open(args.pins,'rb') as stream:import_pins(p,stream.read(4*1024*1024+1))
            return publish(p,args.root,checked_cut=result['source_cut'])
        raise ProjectionError('Unknown projection command')
