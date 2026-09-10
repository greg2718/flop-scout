"""Responsive scheduler; bounded reader work; exactly one SQLite owner thread."""
from concurrent.futures import ThreadPoolExecutor
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
import threading
import time
import json
import os

import scout_diagnostics as diagnostics
import scout_preparation as preparation
import scout_coverage as coverage
import scout_evidence as evidence
import scout_checkpoint as checkpoint


class BatchBudget:
    """Conservative first turn; adapt towards 25ms, never exceed 200 records."""
    def __init__(self,target=0.025):self.size=1;self.target=target
    def observe(self,records,seconds,commit_ms=0,checkpoint_ms=0,tail_age=0):
        if records:
            desired=max(1,min(200,int(records*self.target/max(seconds,0.000001))))
            if commit_ms>250 or checkpoint_ms>1000:
                self.size=max(1,min(desired,self.size//4))
                return
            self.size=min(max(1,self.size*2),desired)


class Storage:
    """All methods, connections and iterators belong to the sqlite-owner thread."""
    def __init__(self,path,settings,config,diag,clock,wall,projection=None):
        import flop_scout as scout
        import scout_worker as worker
        self.owner=threading.get_ident();self.diag=diag
        with diagnostics.operation('schema_verification'):
            self.conn=scout.observer_connect_write(path,connection_factory=diagnostics.TimedConnection)
        # FULL retains each committed WAL transaction through a power failure;
        # deferred checkpoints must not extend NORMAL's unsynced-data window.
        self.conn.execute('PRAGMA synchronous=FULL')
        self.conn.execute('PRAGMA wal_autocheckpoint=0')
        # Only SQLite's safe post-checkpoint WAL reset may trim allocation.
        # This is not a blocking TRUNCATE checkpoint or manual WAL deletion.
        self.conn.execute('PRAGMA journal_size_limit=4194304')
        self.conn.diagnostic_path=Path(path)
        with diag.lock:
            diag.values['sqlite_settings']={k:self.conn.execute('PRAGMA '+k).fetchone()[0]
                for k in ('journal_mode','synchronous','wal_autocheckpoint','page_size','cache_size',
                          'mmap_size','temp_store','locking_mode','busy_timeout','fullfsync','checkpoint_fullfsync','journal_size_limit')}
        self.settings=settings if settings is not None else worker.configuration(
            scout.validation_watch_rooms(self.conn),config or scout.HOME/'polling.json',
            evidence.load_collections(scout.HOME/'watch_collections.json'))
        self.co=worker.Coordinator(self.conn,self.settings,clock=clock,wall_clock=wall)
        self.exports={}
        self.tail_budgets={}
        self.tail_coverage_work={}
        self.export_coverage_work={}
        self.projection_outbox=None;self.projection_active=set();self.projection_error=None;self.projection_retry_at=0
        if projection:
            from scout_projection_source import Outbox
            from scout_projection_contract import connect,loads
            with connect(Path(projection['path']).with_suffix(Path(projection['path']).suffix+'.ledger'),True) as ledger:
                binding=loads(ledger.execute('SELECT json FROM configuration').fetchone()[0])
            self.projection_outbox=Outbox(self.conn,binding['local_dids'],epoch=binding['epoch'],source_id=binding['source_id'],revision=binding['contract_revision'],cohort=binding.get('legacy_tclk_cohort'))

    def projection_capture(self,complete=False):
        if self.projection_outbox and time.monotonic()>=self.projection_retry_at:
            try:
                self.projection_outbox.capture(complete=complete and not self.projection_active)
                self.projection_error=None
            except Exception as exc:
                self.projection_error=str(exc);self.projection_retry_at=time.monotonic()+30
                from scout_projection_legacy import LegacyGenerationError
                from scout_projection_contract import LEGACY_POLICY,REVISION,LG2_REVISION,LG2_ENCODING
                with self.diag.lock:
                    status=dict(self.diag.values.get('router_projection_source',{}),readiness='NOT_READY',error=str(exc))
                    if isinstance(exc,LegacyGenerationError):
                        key='true_generation_conflicts_rejected' if exc.code=='LG1_GENERATION_CONFLICT' else 'unsupported_legacy_records'
                        status[key]=status.get(key,0)+1
                        status['last_lg1_error']=exc.code
                        status['legacy_generation_policy']=LEGACY_POLICY if self.projection_outbox.revision in (REVISION,LG2_REVISION) else None
                        if self.projection_outbox.revision==LG2_REVISION:status['legacy_generation_encoding']=LG2_ENCODING
                        status['rejection_count_scope']='source capture attempts in this worker process'
                    self.diag.values['router_projection_source']=status

    def projection_drain(self):
        self.projection_capture(complete=True)
        return {}

    def metadata(self):
        import flop_scout as scout
        assert threading.get_ident()==self.owner
        result={}
        for room in self.settings:
            cursor=scout.room_cursor(self.conn,room)
            row=self.conn.execute('SELECT * FROM source_coverage_state WHERE room=? AND generation=?',(room,cursor['generation'])).fetchone()
            saved=self.conn.execute('SELECT * FROM evidence_export_snapshots WHERE room=? AND generation=? ORDER BY retrieved_at DESC LIMIT 1',(room,cursor['generation'])).fetchone()
            result[room]=dict(cursor=cursor,coverage=dict(row) if row else None,snapshot=dict(saved) if saved else None,
                              poll=dict(self.co.polls[room]),due=self.co.due[room],failures=self.co.failures[room],
                              backfill_due=self.co.backfill_due.get(room,0),backfill_failures=self.co.backfill_failures[room])
        return result

    def tail(self,room,job,size):
        # A single small committed chunk per ownership turn. Feedback cannot
        # bound an unexpectedly expensive record; never accumulate page work.
        return self._tail_batch(room,job,min(size,8))

    def _tail_batch(self,room,job,size):
        import flop_scout as scout
        assert threading.get_ident()==self.owner
        obj,generation=job['response'];records=job['records'];start=job['offset']
        batch=records[start:start+size]
        if self.projection_outbox:self.projection_active.add(('tail',room))
        plan=job['prepared']
        token=scout._VERIFICATION_CACHE.set(plan['verifications'])
        try:
            with diagnostics.operation('tail_persist',room):
                meta=obj.get('_scout_transport',{})
                endpoint=meta.get('endpoint',scout.room_read_endpoint(room,200,job['cursor']))
                summary=scout.ingest_messages(self.conn,room,batch,
                    generation=generation,
                    source='service-poll',source_endpoint=endpoint,transport_metadata=meta,
                    retrieved_at=plan['retrieved_at'],prepared=plan['items'][start:start+len(batch)])
                inserted=job['inserted']+summary['inserted']
                offset=start+len(batch)
                if offset<len(records):
                    self.projection_capture()
                    return dict(offset=offset,inserted=inserted,records=len(batch))
                summary=dict(received=len(records),inserted=inserted,
                             signed_writers=len({scout.message_sender(r) for r in records if isinstance(r,dict) and scout.is_signed_sender(scout.message_sender(r))}),
                             unsigned_writers=len({scout.message_sender(r) for r in records if isinstance(r,dict) and not scout.is_signed_sender(scout.message_sender(r))}))
                with diagnostics.operation('tail_coverage_finalize',room):
                    coverage_token=coverage.COVERAGE_WORK.set(self.tail_coverage_work)
                    try:
                        cursor=scout.room_cursor(self.conn,room)
                        changed=generation is not None and cursor['generation'] not in (
                            None,scout.UNKNOWN_LEGACY_GENERATION,scout.GENERATION_MISSING,str(generation))
                        current=coverage.state(self.conn,room,generation,0 if changed else cursor['last_seq'])
                        # Resolve resumable coverage before opening the accounted
                        # poll cycle; a cooperative yield is not a read failure.
                        coverage.contiguous(self.conn,room,generation,current['coverage_cursor'])
                        result=scout.service_poll_room(self.conn,room,response=job['response'],pre_ingested_summary=summary,
                            prepared_raw_ids=[item['raw'][0] for item in plan['items']])
                    except coverage.CoveragePending:
                        return dict(offset=offset,inserted=inserted,records=len(batch))
                    except BaseException as error:
                        error.scout_poll_accounted=True
                        raise
                    finally:coverage.COVERAGE_WORK.reset(coverage_token)
                self.tail_coverage_work={k:v for k,v in self.tail_coverage_work.items() if k[0]!=room}
                if result['continuity']=='READ_FAILED':
                    error=RuntimeError(result['last_read_error']);error.scout_poll_accounted=True
                    raise error
                self.co.polls[room]['last_poll_started']=job['started_wall']
                self.co.health(room,job['started'],high=result['observed_high_water'])
                self.co.needs_tail_refresh.discard(room)
                self.projection_active.discard(('tail',room));self.projection_capture(complete=True)
                return dict(done=True,records=len(batch),metadata=self.metadata())
        finally:scout._VERIFICATION_CACHE.reset(token)

    def tail_failed(self,room,job,error):
        self.tail_coverage_work={k:v for k,v in self.tail_coverage_work.items() if k[0]!=room}
        if not getattr(error,'scout_poll_accounted',False):
            with self.conn:
                evidence.bump(self.conn,'read_failures')
                if isinstance(error,__import__('sqlite3').Error):evidence.bump(self.conn,'database_errors')
        self.co.health(room,job['started'],error=error)
        return dict(done=True,metadata=self.metadata())

    def export_batch(self,room,snapshot,batch,prepared,position,done):
        import flop_scout as scout
        assert threading.get_ident()==self.owner
        with diagnostics.operation('export_persist',room):
            if self.projection_outbox:self.projection_active.add(('export',room))
            if room not in self.exports:
                if scout.room_cursor(self.conn,room)['generation']!=snapshot['generation']:
                    raise ValueError('Generation changed during export download')
                self.exports[room]=coverage.begin_export(self.conn,snapshot,scout.room_cursor(self.conn,room)['last_seq'])
            saved=self.exports[room]
            token=scout._VERIFICATION_CACHE.set(prepared['verifications'])
            try:
                if batch:
                    def ingest(records,s):
                        scout.ingest_messages(self.conn,room,records,generation=s['generation'],source='export-backfill',
                            source_endpoint=s['source_endpoint'],transport_metadata={**json.loads(s['metadata_json']),'snapshot_id':s['snapshot_id']},retrieved_at=s['retrieved_at'],prepared=prepared['items'])
                    coverage.persist_batch(self.conn,saved,batch,position,ingest)
                if not done:
                    self.projection_capture()
                    return dict(records=len(batch))
                with diagnostics.operation('export_coverage_finalize',room):
                    coverage_token=coverage.COVERAGE_WORK.set(self.export_coverage_work)
                    try:result=coverage.finish_export(self.conn,saved)
                    except coverage.CoveragePending:return dict(records=len(batch),finalizing=True)
                    finally:coverage.COVERAGE_WORK.reset(coverage_token)
                self.export_coverage_work={k:v for k,v in self.export_coverage_work.items() if k[0]!=room}
                if scout.room_cursor(self.conn,room)['generation']==saved['generation']:
                    scout.update_room_cursor(self.conn,room,saved['generation'],result['coverage_cursor'])
                    scout.set_state(self.conn,f'cursor:{room}:continuity',result['coverage_status'])
                error=RuntimeError('Export coverage unresolved') if result['backfill_required'] else None
                self.co.export_finished(room,error)
                self.exports.pop(room,None)
                self.projection_active.discard(('export',room));self.projection_capture(complete=True)
                return dict(done=True,records=len(batch),error=error,metadata=self.metadata())
            finally:scout._VERIFICATION_CACHE.reset(token)

    def export_failed(self,room,generation,error):
        self.export_coverage_work={k:v for k,v in self.export_coverage_work.items() if k[0]!=room}
        coverage.failed(self.conn,room,generation,error)
        self.exports.pop(room,None);self.co.export_finished(room,error)
        return dict(done=True,metadata=self.metadata())

    def save_status(self,snapshot):
        with self.conn:
            self.conn.execute("INSERT INTO evidence_settings VALUES ('worker_scheduler_v1',?) ON CONFLICT(name) DO UPDATE SET value=excluded.value",(json.dumps(snapshot),))
        return {}

    def close(self):self.conn.close()


class Runtime:
    def __init__(self,path,settings=None,config=None,concurrency=4,reader=None,clock=time.monotonic,wall=time.time,stop=None,projection=None):
        if not 1<=concurrency<=8:raise ValueError('Concurrency must be 1..8')
        self.projection=projection;self.last_projection_drain=0
        self.path=Path(path);self.settings=settings;self.config=config;self.concurrency=concurrency
        self.reader=reader;self.clock=clock;self.wall=wall;self.stop=stop or threading.Event()
        self.diag=diagnostics.Diagnostics(self.path.parent/'run'/'worker-diagnostics.json',clock,wall)
        self.started=wall();self.data={};self.reads={};self.tails={};self.active=set();self.backfills={}
        self.export=None;self.cleanup=None;self.writer_job=None;self.tail_budget=BatchBudget();self.export_budget=BatchBudget()
        self.room_budgets={}
        self.turns=0;self.last_status=clock();self.once=False;self.tail_done=set();self.export_done=set()
        self.critical=[];self.export_blocked=set()
        self.wakeup=threading.Event()
        self.last_budget_checkpoint=0
        self.last_export_turn=clock()
        self.work_intervals=deque(maxlen=4096)

    def call(self,name,room,fn,*args):
        with diagnostics.use(self.diag),self.diag.operation(name,room):return fn(*args)

    def read_tail(self,room,cursor):
        import flop_scout as scout
        fetched=self.clock()
        with diagnostics.operation('tail_fetch',room):
            result=self.reader(room,'tail',cursor['generation'],cursor['last_seq']) if self.reader else scout.observation_only(scout.fetch_room_view)(room,200,since=cursor['last_seq'],allow_missing=True)
        fetch_seconds=self.clock()-fetched
        records=scout.raw_room_messages(result[0])
        if len(records)>200:raise ValueError('Tail response exceeds bounded record count')
        started=self.clock()
        with diagnostics.operation('tail_batch_preparation',room):
            meta=result[0].get('_scout_transport',{})
            prepared=preparation.prepare_page(room,records,generation=result[1],
                endpoint=meta.get('endpoint',scout.room_read_endpoint(room,200,cursor['last_seq'])),metadata=meta)
        return result,records,prepared,self.clock()-started,fetch_seconds

    def open_export(self,room,cursor,snapshot):
        import flop_scout as scout
        if snapshot is None:
            with diagnostics.operation('export_fetch',room):
                snapshot=self.reader(room,'export',cursor['generation'],cursor['last_seq']) if self.reader else scout.fetch_room_export(room,cursor['generation'],stop_event=self.stop)
        if snapshot['room']!=room or snapshot['generation']!=cursor['generation']:raise ValueError('Export generation/room mismatch')
        stream=preparation.ExportStream(snapshot,snapshot.get('processed_records',0))
        return stream

    def update(self,result):
        if 'metadata' in result:self.data=result['metadata']

    def discover(self):
        for room,info in self.data.items():
            row=info['coverage'];gen=info['cursor']['generation']
            eligible=(row and row['backfill_required'] and self.settings[room]['export_backfill_enabled']
                      and gen not in (None,'GENERATION_MISSING','UNKNOWN_LEGACY')
                      and not (self.once and (room in self.export_done or (room in self.tail_done and info['failures']))))
            if eligible:self.backfills.setdefault(room,self.clock())
            elif not self.export or self.export['room']!=room:self.backfills.pop(room,None)

    def schedule_reads(self):
        maintenance=getattr(self,'checkpointer',None)
        due=sorted((r for r,v in self.data.items() if r not in self.active and v['due']<=self.clock()
                    and not(self.once and r in self.tail_done)),key=lambda r:(self.data[r]['due'],self.settings[r]['priority'],r))
        for room in due:
            if maintenance and maintenance.drain_tail_admission:break
            if len(self.reads)>=self.concurrency or len(self.active)>=self.concurrency:break
            info=self.data[room];started=self.clock();stamp=datetime.fromtimestamp(self.wall(),timezone.utc).isoformat()
            job=dict(room=room,started=started,started_wall=stamp,cursor=info['cursor']['last_seq'])
            future=self.tail_pool.submit(self.call,'tail_read_prepare',room,self.read_tail,room,info['cursor'])
            self.reads[future]=job;self.active.add(room)
            future.add_done_callback(lambda _:self.wakeup.set())
            info['poll']['last_poll_started']=stamp
        self.discover()
        if maintenance and maintenance.pressure:return
        if self.export is None and self.cleanup is None:
            for room in self.backfills:
                info=self.data[room]
                if room in self.export_blocked or info['backfill_due']>self.clock():continue
                if info['failures']:continue
                row=info['coverage'];saved=info['snapshot']
                resumable=saved and (saved['processed_records']<saved['record_count'] or saved['status']=='VALIDATED'
                    or (row['coverage_status']=='BACKFILLING' and (saved['last_seq'] or 0)>=row['observed_high_water']))
                future=self.export_pool.submit(self.call,'export_open',room,self.open_export,room,info['cursor'],saved if resumable else None)
                self.export=dict(room=room,generation=info['cursor']['generation'],future=future,stream=None,ready=None,queued=self.backfills[room])
                self.export_done.add(room);break

    def finish_export(self,error=None):
        job=self.export
        if error:self.diag.failed(job['room'],error)
        self.backfills.pop(job['room'],None)
        if job['stream']:
            # Close is reader-side; queued behind any current reader operation.
            self.cleanup=self.export_pool.submit(self.call,'snapshot_close',job['room'],job['stream'].close)
        self.export=None

    def harvest_reads(self):
        if self.cleanup and self.cleanup.done():
            self.cleanup.result();self.cleanup=None
        for future in list(self.reads):
            if not future.done():continue
            job=self.reads.pop(future);room=job['room']
            try:
                parts=future.result();response,records,prepared=parts[:3]
                job['preparation_seconds']=parts[3] if len(parts)>3 else 0
                job['fetch_seconds']=parts[4] if len(parts)>4 else 0
                job.update(response=response,records=records,prepared=prepared,offset=0,inserted=0,queued=self.clock(),turn_ready=self.clock())
                self.tails[room]=job
            except BaseException as error:
                self.critical.append(('tail_failed',room,(room,job,error)))
        job=self.export
        if job and job['future'] and job['future'].done():
            try:
                result=job['future'].result();job['future']=None
                if job['stream'] is None:job['stream']=result
                else:job['ready']=result;job['ready_at']=self.clock()
            except BaseException as error:
                self.export_blocked.add(job['room'])
                self.critical.append(('export_failed',job['room'],(job['room'],job['generation'],error)))
                self.finish_export(error)
        job=self.export
        if job and job['stream'] and not job['future'] and job['ready'] is None and not (self.writer_job and self.writer_job['kind']=='export_batch'):
            job['future']=self.export_pool.submit(self.call,'export_prepare_batch',job['room'],job['stream'].batch,min(self.export_budget.size,4))

    def submit_write(self,kind,room,args,queued=None):
        queued=self.clock() if queued is None else queued
        submitted=self.clock()
        if kind=='tail':
            page=args[1];delay=max(0,submitted-queued)
            page['queue_seconds']=page.get('queue_seconds',0)+delay
            accounted=0
            for start,end,category in self.work_intervals:
                overlap=max(0,min(end,submitted)-max(start,queued))
                page['wait_'+category]=page.get('wait_'+category,0)+overlap
                accounted+=overlap
            page['wait_scheduler']=page.get('wait_scheduler',0)+max(0,delay-accounted)
            with self.diag.lock:
                self.diag.values['tail_max_queue_wait_ms']=max(delay*1000,self.diag.values.get('tail_max_queue_wait_ms',0))
        def write():
            wait=(self.clock()-queued)*1000
            with self.diag.lock:
                self.diag.values['sqlite_queue_wait_ms']=wait
                self.diag.values['sqlite_max_queue_wait_ms']=max(wait,self.diag.values.get('sqlite_max_queue_wait_ms',0))
            began=self.clock()
            sql_keys=('sqlite_select_total_duration_ms','sqlite_insert_total_duration_ms','sqlite_update_total_duration_ms','sqlite_delete_total_duration_ms','sqlite_statement_total_duration_ms','sqlite_commit_total_duration_ms')
            with self.diag.lock:sql_before=sum(self.diag.values.get(k,0) for k in sql_keys)
            connection=getattr(self.storage,'conn',None)
            if connection is not None:connection.turn_commit_max_ms=0
            result=self.call('sqlite_write',room,getattr(self.storage,kind),*args)
            result['_write_seconds']=self.clock()-began
            result['_dispatch_seconds']=began-submitted
            result['_completed_at']=self.clock()
            result['_began_at']=began
            with self.diag.lock:result['_sql_ms']=sum(self.diag.values.get(k,0) for k in sql_keys)-sql_before
            result['_commit_ms']=getattr(connection,'turn_commit_max_ms',0)
            return result
        write.task_kind=kind;write.task_args=args
        future=self.write_pool.submit(write)
        future.add_done_callback(lambda _:self.wakeup.set())
        self.writer_job=dict(future=future,kind=kind,room=room,started=self.clock(),args=args)

    def harvest_write(self):
        job=self.writer_job
        if not job or not job['future'].done():return
        self.writer_job=None;room=job['room'];kind=job['kind']
        try:result=job['future'].result()
        except BaseException as error:
            if kind in ('tail','tail_failed'):
                if kind=='tail_failed':raise
                self.tails.pop(room,None)
                self.critical.append(('tail_failed',room,(room,job['args'][1],error)))
            elif kind=='export_batch':
                self.export_blocked.add(room)
                self.critical.append(('export_failed',room,(room,self.export['generation'],error)))
                self.finish_export(error)
            else:raise
            return
        self.update(result)
        self.work_intervals.append((result.get('_began_at',job['started']),result.get('_completed_at',self.clock()),'tail' if kind=='tail' else 'backfill' if kind=='export_batch' else 'metadata'))
        cp=getattr(self,'checkpointer',None)
        if cp:cp.changed()
        checkpoint_count=self.diag.values.get('sqlite_checkpoint_count',0)
        pressure=dict(commit_ms=result.get('_commit_ms',0),
                      checkpoint_ms=cp.last_ms if cp and checkpoint_count!=self.last_budget_checkpoint else 0,
                      tail_age=max((self.clock()-j['queued'] for j in self.tails.values()),default=0))
        if kind in ('tail','export_batch'):self.last_budget_checkpoint=checkpoint_count
        if kind=='tail':
            page=self.tails[room]
            page['write_seconds']=page.get('write_seconds',0)+result.get('_write_seconds',0)
            page['dispatch_seconds']=page.get('dispatch_seconds',0)+result.get('_dispatch_seconds',0)
            page['completion_wait_seconds']=page.get('completion_wait_seconds',0)+max(0,self.clock()-result.get('_completed_at',self.clock()))
            page['write_turns']=page.get('write_turns',0)+1
            page['sql_ms']=page.get('sql_ms',0)+result.get('_sql_ms',0)
            self.room_budgets.setdefault(room,BatchBudget()).observe(result.get('records',0),result.get('_write_seconds',self.clock()-job['started']),**pressure)
            if result.get('done'):
                page_ms=(self.clock()-self.tails[room]['queued'])*1000
                with self.diag.lock:
                    self.diag.values['tail_page_persist_duration_ms']=page_ms
                    self.diag.values['tail_page_persist_max_duration_ms']=max(page_ms,self.diag.values.get('tail_page_persist_max_duration_ms',0))
                    timing=dict(room=room,records=len(page['records']),turns=page['write_turns'],elapsed_ms=page_ms,
                                writer_ms=page['write_seconds']*1000,dispatch_ms=page['dispatch_seconds']*1000,
                                completion_wait_ms=page['completion_wait_seconds']*1000)
                    timing['other_wait_ms']=max(0,page_ms-timing['writer_ms']-timing['dispatch_ms']-timing['completion_wait_ms'])
                    timing.update(queue_ms=page.get('queue_seconds',0)*1000,preparation_ms=page.get('preparation_seconds',0)*1000,sqlite_ms=page['sql_ms'],
                                  queue_breakdown_ms={k:page.get('wait_'+k,0)*1000 for k in ('tail','backfill','metadata','maintenance','scheduler')})
                    timing.update(upstream_get_ms=page.get('fetch_seconds',0)*1000,
                                  internal_ms=page_ms+timing['preparation_ms'],
                                  completed_at=self.wall(),
                                  sequence=self.diag.values.get('tail_page_timing_sequence',0)+1)
                    self.diag.values['tail_page_timing_sequence']=timing['sequence']
                    self.diag.values['tail_page_execution_max_ms']=max(timing['writer_ms'],self.diag.values.get('tail_page_execution_max_ms',0))
                    self.diag.values['tail_page_timing_history']=(self.diag.values.get('tail_page_timing_history',[])+[timing])[-64:]
                    self.diag.values['tail_page_max_queue_wait_ms']=max(timing['queue_ms'],self.diag.values.get('tail_page_max_queue_wait_ms',0))
                    self.diag.values['tail_page_timing']=timing
                    if page_ms>=self.diag.values.get('tail_page_slowest_timing',{}).get('elapsed_ms',0):
                        self.diag.values['tail_page_slowest_timing']=timing
                self.tails.pop(room,None);self.active.discard(room);self.tail_done.add(room)
            else:self.tails[room].update(offset=result['offset'],inserted=result['inserted'],turn_ready=self.clock())
        elif kind=='tail_failed':self.active.discard(room);self.tail_done.add(room)
        elif kind=='export_failed':self.export_blocked.discard(room)
        elif kind=='export_batch':
            self.export_budget.observe(result.get('records',0),result.get('_write_seconds',self.clock()-job['started']),**pressure)
            if result.get('done'):self.finish_export(result.get('error'))
            elif result.get('finalizing'):
                _,prepared,position,_=self.export['ready']
                self.export['ready']=([],dict(prepared,items=[]),position,True)
                self.export['ready_at']=self.clock()
            else:self.export['ready']=None

    def choose_write(self):
        if self.writer_job:return
        cp=getattr(self,'checkpointer',None)
        if cp and cp.blocks_writes:
            if cp.future is not None and getattr(cp,'serial_turn',not cp.concurrent):return
            # At the high watermark, drain only the finite work already
            # admitted. Otherwise urgent pages and maintenance would deadlock.
            # New reads/exports are paused; no status/export writes can grow WAL
            # indefinitely behind a pinned reader.
            if not (self.tails or self.critical):return
        if self.critical:
            kind,room,args=self.critical.pop(0);self.submit_write(kind,room,args);return
        ready=self.export and self.export['ready'] is not None and not (cp and getattr(cp,'pressure',False))
        if self.tails and (not ready or self.clock()-self.last_export_turn<2):
            # Oldest runnable chunk first; rotate after each durable chunk. One bounded backfill turn at least
            # every two seconds of runnable contention prevents starvation.
            room=min(self.tails,key=lambda r:self.tails[r]['turn_ready']);job=self.tails[room]
            budget=self.room_budgets.setdefault(room,BatchBudget())
            with self.diag.lock:self.diag.values['sqlite_batch_size']=min(budget.size,8)
            self.submit_write('tail',room,(room,job,budget.size),job['turn_ready']);self.turns+=1
        elif ready:
            job=self.export;records,prepared,position,done=job['ready']
            with self.diag.lock:self.diag.values['sqlite_batch_size']=len(records)
            self.submit_write('export_batch',job['room'],(job['room'],job['stream'].snapshot,records,prepared,position,done),job['ready_at']);self.turns=0
            self.last_export_turn=self.clock()
        elif self.clock()-self.last_status>=1:
            self.submit_write('save_status',None,(self.scheduler_snapshot(),));self.last_status=self.clock()
        elif self.projection and self.clock()-self.last_projection_drain>=0.25:
            self.submit_write('projection_drain',None,());self.last_projection_drain=self.clock()

    def scheduler_snapshot(self):
        stamp=lambda t:datetime.fromtimestamp(self.wall()+t-self.clock(),timezone.utc).isoformat()
        return dict(started_at=datetime.fromtimestamp(self.started,timezone.utc).isoformat(),updated_at=stamp(self.clock()),
                    rooms={r:dict(v['poll'],next_due=stamp(v['due']),backfill_failures=v['backfill_failures'],backfill_next_due=stamp(v['backfill_due'])) for r,v in self.data.items()},
                    pending_backfills={r:stamp(t) for r,t in self.backfills.items()},
                    pending_tails={r:stamp(v['due']) for r,v in self.data.items() if v['due']<=self.clock()},
                    tail_inflight=len(self.reads),export_inflight=int(self.export is not None))

    def step(self):
        began=self.clock()
        try:
            with diagnostics.use(self.diag),self.diag.operation('scheduler_tick'):
                self._step()
        finally:
            with self.diag.lock:self.diag.tick_duration=self.clock()-began

    def _step(self):
        self.diag.tick()
        self.harvest_write();self.harvest_reads();self.schedule_reads()
        cp=getattr(self,'checkpointer',None)
        if cp:
            previous=cp.future
            cp.step(urgent=bool(self.tails or self.critical),writer_busy=self.writer_job is not None)
            if previous is not None and previous.done() and cp.future is not previous and getattr(cp,'serial_turn',False):
                interval=getattr(cp,'last_interval',None)
                if interval:self.work_intervals.append((*interval,'maintenance'))
        self.choose_write()
        with self.diag.lock:
            self.diag.queues=dict(tail_read_queue=len(self.reads),tail_persist_queue=len(self.tails),backfill_queue=len(self.backfills),
                                  sqlite_queue=len(self.tails)+len(self.critical)+int(bool(self.export and self.export['ready'] is not None)),
                                  oldest_tail_queue_age=max((self.clock()-j['queued'] for j in self.tails.values()),default=0),
                                  oldest_backfill_queue_age=max((self.clock()-t for t in self.backfills.values()),default=0))
            self.diag.scheduler=self.scheduler_snapshot()

    def loop(self):
        while not self.stop.is_set():
            self.wakeup.clear()
            self.step()
            if self.once and len(self.tail_done)==len(self.settings) and not self.reads and not self.tails and not self.writer_job and not self.export and not self.cleanup and not self.backfills and not self.critical:break
            with self.diag.operation('scheduler_sleep'):
                self.wakeup.wait(0.01)

    def run(self,once=False):
        self.once=once;self.diag.start()
        with ThreadPoolExecutor(max_workers=1,thread_name_prefix='scout-sqlite') as self.write_pool, ThreadPoolExecutor(max_workers=self.concurrency,thread_name_prefix='scout-tail') as self.tail_pool, ThreadPoolExecutor(max_workers=1,thread_name_prefix='scout-export') as self.export_pool:
            opened=self.write_pool.submit(self.call,'writer_startup',None,Storage,self.path,self.settings,self.config,self.diag,self.clock,self.wall,self.projection)
            try:
                while not opened.done():self.diag.tick();self.stop.wait(0.01)
                self.storage=opened.result();self.settings=self.storage.settings
                self.checkpointer=checkpoint.Checkpoints(self.path,self.diag,self.clock)
                initial=self.write_pool.submit(self.storage.metadata)
                while not initial.done():self.diag.tick();self.stop.wait(0.01)
                self.data=initial.result()
                if self.projection:
                    from scout_projection_service import ProjectionService
                    self.projection_service=ProjectionService(self.path,self.projection['path'],self.projection['root'],self.projection['pins'],self.diag,self.stop,self.projection.get('cadence',900))
                    self.projection_service.start()
                self.diag.lifecycle='RUNNING'
                self.loop()
            finally:
                self.diag.lifecycle='STOPPING'
                if hasattr(self,'projection_service'):
                    self.stop.set();self.projection_service.close()
                # No new admission. Wait for bounded in-flight read/preparation and
                # the one writer turn; no connection crosses thread ownership.
                for f in self.reads:f.cancel()
                if self.export and self.export['future']:self.export['future'].cancel()
                self.tail_pool.shutdown(wait=True,cancel_futures=True)
                self.export_pool.shutdown(wait=True,cancel_futures=True)
                if self.export:
                    stream=self.export['stream']
                    if stream:stream.close()
                    elif self.export['future'] and not self.export['future'].cancelled():
                        try:self.export['future'].result().close()
                        except BaseException:pass
                if hasattr(self,'storage'):
                    try:
                        if self.writer_job:self.writer_job['future'].result()
                    finally:
                        try:
                            if hasattr(self,'checkpointer'):self.checkpointer.close()
                            self.write_pool.submit(self.storage.save_status,self.scheduler_snapshot()).result()
                        finally:
                            # Join checkpoint work before last-writer close to
                            # avoid an implicit close checkpoint racing it.
                            self.write_pool.submit(self.storage.close).result()
                self.diag.lifecycle='STOPPED'
                self.diag.close()
