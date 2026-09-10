"""Opt-in local V2/A1 projection owner and durable replay ledger.

The private ledger is the main database. The nine-table projection is attached
in DELETE journal mode: SQLite's super-journal commits both files atomically.
Only this owner writes either file. Incomplete evaluations block publication.
"""
from __future__ import annotations
from collections import Counter, defaultdict
from dataclasses import asdict
from pathlib import Path
import fcntl
import json
import os
import sqlite3
import threading
import time
from scout_projection_contract import *
from scout_projection_model import *
import scout_projection_rules as rules

LEDGER_SQL = '''
CREATE TABLE operations(number INTEGER PRIMARY KEY,hash TEXT UNIQUE NOT NULL,body TEXT NOT NULL);
CREATE TABLE configuration(singleton INTEGER PRIMARY KEY CHECK(singleton=1),json TEXT NOT NULL);
CREATE TABLE state(key TEXT PRIMARY KEY,value TEXT NOT NULL);
CREATE TABLE input_versions(hash TEXT PRIMARY KEY,id TEXT NOT NULL,body TEXT NOT NULL);
CREATE TABLE source_aliases(kind TEXT NOT NULL,alias TEXT NOT NULL,id TEXT NOT NULL,PRIMARY KEY(kind,alias,id));
CREATE TABLE current_inputs(id TEXT PRIMARY KEY,hash TEXT NOT NULL REFERENCES input_versions(hash),sender TEXT,room TEXT,generation TEXT,seq INTEGER,template TEXT,first_observed_at TEXT NOT NULL,workflow_id TEXT);
CREATE INDEX input_workflow ON current_inputs(workflow_id);
CREATE TABLE evaluation_groups(number INTEGER NOT NULL,sender TEXT NOT NULL,PRIMARY KEY(number,sender));
CREATE INDEX input_sender ON current_inputs(sender,room,generation,seq,id);
CREATE INDEX input_template ON current_inputs(room,generation,template,sender);
CREATE INDEX input_template_global ON current_inputs(template,sender);
CREATE TABLE evaluations(number INTEGER PRIMARY KEY,event_id TEXT UNIQUE NOT NULL,body TEXT NOT NULL,previous_sha256 TEXT,status TEXT NOT NULL);
CREATE INDEX pending_evaluations ON evaluations(number) WHERE status!='COMPLETE';
CREATE TABLE evaluation_edges(number INTEGER NOT NULL REFERENCES evaluations(number),key TEXT NOT NULL,body TEXT NOT NULL,PRIMARY KEY(number,key));
CREATE TABLE evaluation_inputs(number INTEGER NOT NULL REFERENCES evaluations(number),id TEXT NOT NULL,hash TEXT NOT NULL REFERENCES input_versions(hash),PRIMARY KEY(number,id));
CREATE TABLE rule_manifests(hash TEXT PRIMARY KEY,body TEXT NOT NULL);
CREATE TABLE qualification_keys(first_key TEXT PRIMARY KEY,qualification_id TEXT UNIQUE NOT NULL,record_json TEXT NOT NULL);
CREATE TABLE audit_history(event_id TEXT PRIMARY KEY,event_json TEXT NOT NULL);
CREATE TABLE dependency_jobs(id TEXT PRIMARY KEY,status TEXT NOT NULL);
CREATE TABLE dependency_frontier(job_id TEXT NOT NULL,node TEXT NOT NULL,done INTEGER NOT NULL,PRIMARY KEY(job_id,node));
CREATE INDEX dependency_due ON dependency_frontier(job_id,done,node);
CREATE TABLE dependencies(parent TEXT NOT NULL,child TEXT NOT NULL,PRIMARY KEY(parent,child));
CREATE TABLE permanent(id TEXT PRIMARY KEY,reason TEXT NOT NULL);
CREATE TABLE expiry(id TEXT PRIMARY KEY,entity_type TEXT NOT NULL,due TEXT NOT NULL);
CREATE INDEX expiry_due ON expiry(due,id);
CREATE TABLE workflows(id TEXT PRIMARY KEY,identity_json TEXT NOT NULL,state TEXT NOT NULL,closed_at TEXT,closure_evidence_id TEXT,closure_reason TEXT,proofs_json TEXT NOT NULL);
CREATE TABLE pins(id TEXT PRIMARY KEY,body TEXT NOT NULL);
CREATE TABLE pin_exports(revision INTEGER PRIMARY KEY,hash TEXT UNIQUE NOT NULL,body TEXT NOT NULL);
CREATE TABLE pin_members(id TEXT NOT NULL,root_json TEXT NOT NULL,PRIMARY KEY(id,root_json));
CREATE TABLE local_artifacts(id TEXT PRIMARY KEY,source_id TEXT NOT NULL,epoch TEXT NOT NULL,hash TEXT NOT NULL,body BLOB NOT NULL,authority TEXT NOT NULL,first_observed_at TEXT NOT NULL);
CREATE TABLE publication_log(id TEXT PRIMARY KEY,manifest TEXT NOT NULL,hash TEXT NOT NULL,database_name TEXT NOT NULL);
'''
MESSAGE_COLUMNS = ('projection_row_id room generation seq timestamp sender signed text normalized_text template_normalized_hash nonce sig message_hash verification_status source_export_hash source_export_path evidence_id').split()
PROVENANCE_COLUMNS = 'entity_type projection_row_id source_namespace source_record_locator scout_event_id raw_record_id raw_record_sha256 annotations_json'.split()
BUNDLE_KEYS = {'message', 'provenance', 'first_observed_at', 'facts', 'dependencies'}
FACT_KEYS = {'signature_failure', 'did_mismatch', 'identity_binding', 'official', 'operator_local', 'workflow'}


def initialize(path, *, epoch, router_source_id, router_epoch, router_did, local_dids=(), source_id='scout-observer', contract_revision=REVISION, legacy_tclk_cohort=None, legacy_tclk_raw_ids=None):
    path = Path(path)
    require(path.is_absolute(), 'Absolute projection path required')
    ledger = path.with_suffix(path.suffix + '.ledger')
    require(not path.exists() and not ledger.exists(), 'Existing projection or ledger: never reset history')
    require(path.name != 'observer.sqlite', 'Projection must be distinct from observer')
    for value in (epoch, router_source_id, router_epoch, router_did, source_id): string(value)
    for value in local_dids: string(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    policy = policy_for(contract_revision)
    if contract_revision == TL1_REVISION:
        from scout_projection_tclk import validate_cohort
        require(legacy_tclk_raw_ids is not None, 'TL1 explicit cohort identities required')
        validate_cohort(legacy_tclk_cohort, source_id=source_id, epoch=epoch, cut=legacy_tclk_cohort['through_event_id'], raw_ids=legacy_tclk_raw_ids)
    else:
        require(legacy_tclk_cohort is None and legacy_tclk_raw_ids is None, 'Mixed TL1 enrollment under older revision')
    config = dict(epoch=epoch, source_id=source_id, router_source_id=router_source_id,
                  router_epoch=router_epoch, router_did=router_did, local_dids=sorted(set(local_dids)),
                  policy=policy, policy_sha256=digest(policy), schema=SCHEMA, contract_revision=contract_revision,ledger_schema_sha256=text_hash(LEDGER_SQL))
    config.update(revision_metadata(contract_revision, legacy_tclk_cohort))
    if contract_revision == TL1_REVISION: config['legacy_tclk_raw_ids'] = sorted(legacy_tclk_raw_ids)
    revision_binding(config)
    # O_EXCL prevents accidentally replacing either member of the durable pair.
    for target in (path, ledger):
        fd = os.open(str(target), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600); os.close(fd)
    conn = sqlite3.connect(str(ledger))
    try:
        conn.executescript(LEDGER_SQL)
        conn.execute('INSERT INTO configuration VALUES(1,?)', (canonical(config).decode(),))
        conn.execute("INSERT INTO state VALUES('initialized','0')")
        if contract_revision == TL1_REVISION:
            anchor = dict(kind='TL1_INITIAL_ENROLLMENT', payload=dict(revision_metadata(TL1_REVISION, legacy_tclk_cohort), legacy_tclk_raw_ids=sorted(legacy_tclk_raw_ids)), previous_sha256=None)
            conn.execute('INSERT INTO operations VALUES(1,?,?)', (digest(anchor), canonical(anchor).decode()))
            conn.execute('INSERT INTO state VALUES(?,?)', ('operation_head', digest(anchor)))
        conn.commit()
        conn.execute('ATTACH DATABASE ? AS projection', (str(path),))
        conn.execute('PRAGMA projection.auto_vacuum=INCREMENTAL')
        # DDL is fixed and reviewed; create in the attached database.
        ddl = '\n'.join(line for line in sql_for(contract_revision).splitlines() if not line.lstrip().startswith('--'))
        for statement in ddl.split(';'):
            statement = statement.strip()
            if not statement: continue
            if 'PRAGMA user_version' in statement:
                conn.execute('PRAGMA projection.user_version=2'); continue
            statement = statement.replace('CREATE TABLE ', 'CREATE TABLE projection.', 1)
            statement = statement.replace('CREATE INDEX messages_coverage', 'CREATE INDEX projection.messages_coverage', 1)
            conn.execute(statement)
        with conn:
            conn.execute('INSERT INTO projection.snapshot_meta VALUES(1,?,?,?,?)', (SCHEMA, '0', utc(), digest(policy)))
            conn.execute("UPDATE state SET value='1' WHERE key='initialized'")
    finally: conn.close()
    return config


class Projector:
    def __init__(self, path, stop=None, *, write_batch_size=50):
        require(type(write_batch_size) is int and write_batch_size in (50,100,200,500),
                'Unsupported bounded projection batch size')
        self.write_batch_size=write_batch_size
        self.retention_revision=0
        self.path = Path(path); self.owner = threading.get_ident(); self.stop = stop or threading.Event()
        self.ledger = self.path.with_suffix(self.path.suffix + '.ledger')
        require(not self.path.is_symlink() and not self.ledger.is_symlink(),'Symlink working state rejected')
        require(self.path.exists() and self.ledger.exists(), 'Missing projection/replay ledger; restore, never bootstrap over history')
        with connect(self.ledger,True) as config_probe:
            probe_revision=revision_binding(loads(config_probe.execute('SELECT json FROM configuration').fetchone()[0]))
        with connect(self.path,True) as probe:
            require(probe.execute('PRAGMA user_version').fetchone()[0]==2 and {r[0] for r in probe.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}==set(tables_for(probe_revision))|{'snapshot_meta'},'Working projection schema is not V2/A1')
        fd=os.open(str(self.path)+'.lock',os.O_RDWR|os.O_CREAT|os.O_NOFOLLOW,0o600)
        self.lock=os.fdopen(fd,'a+b')
        try: fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.lock.close(); raise ProjectionError('Projection already has an owner')
        try:
            self.conn = connect(self.ledger)
            self.conn.execute('ATTACH DATABASE ? AS projection', (str(self.path),))
            for db in ('main', 'projection'):
                require(self.conn.execute(f'PRAGMA {db}.journal_mode=DELETE').fetchone()[0] == 'delete', 'Rollback journal required for atomic ledger/projection commit')
                self.conn.execute(f'PRAGMA {db}.synchronous=FULL')
                # LG2's larger private proofs otherwise fill both 8 MiB caches
                # during publication verification. Bound native memory as well
                # as Python batches; this does not change durability or schema.
                cache_kib = 4096 if probe_revision in (LG2_REVISION, TL1_REVISION) else 8192
                self.conn.execute(f'PRAGMA {db}.cache_size=-{cache_kib}')
            require(self.get('initialized') == '1', 'Incomplete initialization; explicit recovery required')
            self.config = loads(self.conn.execute('SELECT json FROM configuration').fetchone()[0])
            require(self.config.get('ledger_schema_sha256')==text_hash(LEDGER_SQL),'Unsupported private replay ledger schema; restore the matching producer')
            self.policy = policy_for(self.config['contract_revision'])
            self.policy_sha = digest(self.policy)
            require(self.config['policy_sha256'] == self.policy_sha and self.config['policy'] == self.policy, 'Unreviewed policy migration')
            revision_binding(self.config)
            if self.config['contract_revision'] == TL1_REVISION:
                from scout_projection_tclk import validate_cohort
                cohort = self.config['legacy_tclk_cohort']
                validate_cohort(cohort, source_id=self.config['source_id'], epoch=self.config['epoch'], cut=cohort['through_event_id'], raw_ids=self.config['legacy_tclk_raw_ids'])
            if self.config['contract_revision'] in (LG2_REVISION, TL1_REVISION):
                from scout_projection_compact import validate_schema
                validate_schema(self.conn,'projection.',self.config['contract_revision'])
            self.verify_ledger()
            with self.conn:
                self.set('qualification_count',self.conn.execute('SELECT count(*) FROM projection.durable_qualifications').fetchone()[0])
                self.set('qualification_event_count',self.conn.execute('SELECT count(*) FROM projection.qualification_events').fetchone()[0])
        except BaseException:
            self.close(); raise

    def __enter__(self): return self
    def __exit__(self, *args): self.close()
    def close(self):
        if getattr(self, 'conn', None): self.conn.close(); self.conn = None
        if getattr(self, 'lock', None): self.lock.close(); self.lock = None

    def check(self):
        require(threading.get_ident() == self.owner, 'Projection writer ownership violation')
        if self.stop.is_set(): raise InterruptedError('Projection cancelled; pending cut remains replayable')

    def get(self, key, default=None):
        row = self.conn.execute('SELECT value FROM state WHERE key=?', (key,)).fetchone()
        return row[0] if row else default

    def set(self, key, value):
        self.conn.execute('INSERT INTO state VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (key, str(value)))

    def record_operation(self,kind,payload):
        previous=self.conn.execute('SELECT number,hash FROM operations ORDER BY number DESC LIMIT 1').fetchone()
        number=previous[0]+1 if previous else 1
        body=dict(kind=kind,payload=payload,previous_sha256=previous[1] if previous else None)
        self.conn.execute('INSERT INTO operations VALUES(?,?,?)',(number,digest(body),canonical(body).decode()))
        self.set('operation_head',digest(body))

    def verify_ledger(self):
        previous=None
        replay_revision=self.config.get('initial_contract_revision',self.config['contract_revision'])
        if replay_revision == TL1_REVISION:
            anchor = self.conn.execute('SELECT body FROM operations WHERE number=1').fetchone()
            require(anchor and loads(anchor[0])['kind'] == 'TL1_INITIAL_ENROLLMENT', 'TL1 initial enrollment anchor missing')
        for operation in self.conn.execute('SELECT * FROM operations ORDER BY number'):
            body=loads(operation['body']);require(digest(body)==operation['hash'] and body['previous_sha256']==previous,'Corrupt replay operation chain');previous=operation['hash']
            if body['kind'] == 'TL1_INITIAL_ENROLLMENT':
                require(operation['number'] == 1 and replay_revision == TL1_REVISION and revision_binding(body['payload']) == TL1_REVISION, 'TL1 invalid initial enrollment')
                require(body['payload']['legacy_tclk_cohort'] == self.config['legacy_tclk_cohort'] and body['payload']['legacy_tclk_raw_ids'] == self.config['legacy_tclk_raw_ids'], 'TL1 initial cohort changed')
            if body['kind']=='LG1_MIGRATION':
                require(replay_revision=='A1' and revision_binding(body['payload'])==REVISION,'Invalid LG1 migration history')
                replay_revision=REVISION
            if body['kind']=='LG2_MIGRATION':
                require(replay_revision==REVISION and revision_binding(body['payload'])==LG2_REVISION,'Invalid LG2 migration history')
                replay_revision=LG2_REVISION
            if body['kind']=='TL1_MIGRATION':
                require(replay_revision == LG2_REVISION and revision_binding(body['payload']) == TL1_REVISION, 'Invalid TL1 migration history')
                require(body['payload']['legacy_tclk_cohort'] == self.config['legacy_tclk_cohort'] and body['payload']['legacy_tclk_raw_ids'] == self.config['legacy_tclk_raw_ids'], 'TL1 cohort history changed')
                replay_revision = TL1_REVISION
            if body['kind']=='EVALUATION':
                event=self.conn.execute('SELECT body FROM evaluations WHERE number=?',(body['payload']['number'],)).fetchone()
                require(event and loads(event[0]).get('contract_revision','A1')==replay_revision,'Replay revision/history mismatch')
        require(replay_revision==self.config['contract_revision'],'Missing explicit contract migration history')
        require(previous==self.get('operation_head'),'Replay operation history was truncated')
        previous = None;last_evaluation=None;first_evaluation=None;last_complete=None
        for row in self.conn.execute('SELECT * FROM evaluations ORDER BY number'):
            body = loads(row['body'])
            require(row['event_id'] == identity('pe1', body) and row['previous_sha256'] == previous and body['previous_sha256'] == previous, 'Corrupt evaluation chain')
            revision_binding(body if 'contract_revision' in body else dict(body,contract_revision='A1'))
            require(body.get('contract_revision','A1')=='A1' or self.config['contract_revision'] in (REVISION,LG2_REVISION,TL1_REVISION),'Legacy evaluation under A1 state')
            historical_policy = policy_for(body.get('contract_revision', 'A1'))
            require(body['policy'] == historical_policy and body['policy_sha256'] == digest(historical_policy) and body['classifier_version'] == historical_policy['classifier_version'], 'Unreviewed replay semantics')
            if body.get('contract_revision') == TL1_REVISION:
                require(body['legacy_tclk_cohort'] == self.config['legacy_tclk_cohort'], 'TL1 evaluation cohort changed')
            if row['status']!='STAGING':
                require(body['input_manifest_sha256']==self.input_manifest_hash(row['number']),'Corrupt complete input manifest')
                require(body['edge_manifest_sha256']==self.edge_manifest_hash(row['number']),'Corrupt complete edge manifest')
            previous = row['event_id'][4:];last_evaluation=row['event_id'];first_evaluation=first_evaluation or row['event_id']
            if row['status']=='COMPLETE':last_complete=body
        require(last_evaluation==self.get('evaluation_head'),'Evaluation history was truncated')
        if last_complete:
            require(loads(self.get('source_cut','null'))==last_complete['source_cut'] and self.get('evaluated_at')==last_complete['evaluated_at'],'Checkpoint differs from completed evaluation history')
        # Retained LG1 rows must still have their exact private audit originals.
        if self.config['contract_revision']==REVISION:
            for retained in self.conn.execute("SELECT projection_row_id,annotations_json FROM projection.source_provenance WHERE entity_type='message' AND json_extract(annotations_json,'$.legacy_generation') IS NOT NULL"):
                original=self.bundle(retained['projection_row_id'])
                self.validate_bundle(original)
                require(loads(original['provenance']['annotations_json'])['legacy_generation']==loads(retained['annotations_json'])['legacy_generation'],'LG1 retained audit differs from replay input')
        if self.config['contract_revision'] in (LG2_REVISION, TL1_REVISION):
            from scout_projection_compact import verify_private
            verify_private(self)
        checked_manifests=set()
        # Ledger witnesses are compared with projection bytes, never reconstructed from current scores.
        for row in self.conn.execute('SELECT * FROM qualification_keys'):
            record = validate_qualification(loads(row['record_json']), policy_versions(self.config['contract_revision']))
            evaluation=self.conn.execute('SELECT body FROM evaluations WHERE event_id=?',(record['evaluation_id'],)).fetchone()
            require(evaluation is not None and record['bootstrap_id']==first_evaluation,'Qualification lost its evaluation/bootstrap provenance')
            evaluation=loads(evaluation[0]);require(record['qualified_at']==evaluation['evaluated_at'] and record['source_cut']==evaluation['source_cut'],'Qualification evaluation binding changed')
            require(record['policy_sha256'] == evaluation['policy_sha256'] and record['classifier_version'] == evaluation['classifier_version'], 'Qualification policy/evaluation mismatch')
            require(first_key(record) == row['first_key'] and record['qualification_id'] == row['qualification_id'], 'Conflicting first qualification')
            for h in (record['rule_input_sha256'],record['rule_group_sha256']):
                if h in checked_manifests:continue
                manifest=self.conn.execute('SELECT body FROM rule_manifests WHERE hash=?',(h,)).fetchone()
                require(manifest and digest(loads(manifest[0],max(4*1024*1024,len(manifest[0].encode()))))==h,'Missing/corrupt historical rule inputs')
                checked_manifests.add(h)
            for ref in record['provenance_refs']:self.resolve_audit_ref(ref)
            projected = self.conn.execute('SELECT record_json FROM projection.durable_qualifications WHERE qualification_id=?', (row['qualification_id'],)).fetchone()
            require(projected and projected[0] == row['record_json'], 'Lost or rewritten historical qualification')
        require(self.conn.execute('SELECT count(*) FROM qualification_keys').fetchone()[0] == self.conn.execute('SELECT count(*) FROM projection.durable_qualifications').fetchone()[0], 'Unledgered qualification')
        for row in self.conn.execute('SELECT * FROM audit_history'):
            event=loads(row['event_json'],65536)
            for ref in event['proof_refs']+[event['authority_ref']]:self.resolve_audit_ref(ref)
            projected = self.conn.execute('SELECT event_json FROM projection.qualification_events WHERE event_id=?', (row['event_id'],)).fetchone()
            require(projected and projected[0] == row['event_json'], 'Lost or rewritten qualification event')
        require(self.conn.execute('SELECT count(*) FROM audit_history').fetchone()[0] == self.conn.execute('SELECT count(*) FROM projection.qualification_events').fetchone()[0], 'Unledgered audit event')

    def validate_bundle(self, bundle):
        keys(bundle, BUNDLE_KEYS | ({'tclk_original'} if self.config['contract_revision'] == TL1_REVISION else set()) | ({'legacy_generation_compact'} if self.config['contract_revision'] in (LG2_REVISION, TL1_REVISION) else set()) | ({'legacy_generation_originals'} if 'legacy_generation_originals' in bundle else set())); message = bundle['message']; provenance = bundle['provenance']
        keys(message, MESSAGE_COLUMNS); keys(provenance, PROVENANCE_COLUMNS)
        for key in ('projection_row_id', 'room', 'generation', 'sender'): string(message[key])
        require(type(message['seq']) is int and message['seq'] >= 0, 'Malformed source sequence')
        require(type(message['signed']) is int and message['signed'] in (0, 1), 'Malformed source signing flag')
        require(type(message['text']) is str, 'Malformed source text'); canonical(message['text'])
        for key in set(MESSAGE_COLUMNS) - {'seq', 'signed', 'text', 'projection_row_id', 'room', 'generation', 'sender'}:
            require(message[key] is None or type(message[key]) is str, 'Malformed optional message field')
        for key in ('template_normalized_hash', 'message_hash', 'source_export_hash'): sha(message[key], True)
        require(message['message_hash'] is None or message['message_hash'] == text_hash(message['text']), 'Message hash differs from exact text')
        require(provenance['entity_type'] == 'message' and provenance['projection_row_id'] == message['projection_row_id'], 'Mismatched provenance')
        require(message['projection_row_id'] == 'sm1:' + string(provenance['raw_record_id']), 'Unstable message identity')
        for k in ('source_namespace', 'source_record_locator'): string(provenance[k])
        sha(provenance['raw_record_sha256'], True)
        if provenance['scout_event_id'] is not None: decimal(provenance['scout_event_id'])
        annotations(loads(provenance['annotations_json'], 65536),self.config['contract_revision'])
        from scout_projection_legacy import validate_bundle_proof
        validate_bundle_proof(bundle)
        instant(bundle['first_observed_at']); keys(bundle['facts'], FACT_KEYS)
        for k in FACT_KEYS - {'workflow'}: require(type(bundle['facts'][k]) is bool, 'Untrusted fact type')
        require(type(bundle['dependencies']) is list and len(bundle['dependencies']) <= 256, 'Invalid dependencies')
        for dep in bundle['dependencies']: string(dep)
        require(bundle['dependencies'] == sorted(set(bundle['dependencies'])), 'Unsorted dependencies')
        if self.config['contract_revision'] == TL1_REVISION:
            from scout_projection_tclk import validate_bundle as validate_tclk
            member = validate_tclk(bundle)
            if member:
                require(member[0] in self.config['legacy_tclk_raw_ids'], 'TL1_UNENROLLED_NONCONFORMING')
                require(int(provenance['scout_event_id']) <= int(self.config['legacy_tclk_cohort']['through_event_id']), 'TL1_AFTER_HISTORICAL_CUT')
            else:
                require(provenance['raw_record_id'] not in self.config['legacy_tclk_raw_ids'], 'TL1_ENROLLED_RECORD_NOT_ELIGIBLE')
        return bundle

    def begin(self, cut, evaluated_at, kind='SOURCE_BATCH'):
        require(not self.get('pending_pin_sha256'),'Resume interrupted pin import before source evaluation')
        self.check(); decimal(cut); evaluated_at=utc(instant(evaluated_at))
        if self.config['contract_revision'] == TL1_REVISION:
            from scout_projection_tclk import validate_cohort
            validate_cohort(self.config['legacy_tclk_cohort'], source_id=self.config['source_id'], epoch=self.config['epoch'], cut=cut, raw_ids=self.config['legacy_tclk_raw_ids'])
        require(kind in {'BOOTSTRAP', 'SOURCE_BATCH', 'EXPIRY'}, 'Unknown evaluation kind')
        pending = self.conn.execute("SELECT * FROM evaluations WHERE status!='COMPLETE'").fetchone()
        require(not pending, 'Pending evaluation must be resumed before another cut')
        last = self.conn.execute('SELECT * FROM evaluations ORDER BY number DESC LIMIT 1').fetchone()
        if last:
            old = loads(last['body'])
            require(int(cut) >= int(old['source_cut']['committed_event_id']) and instant(evaluated_at) >= instant(old['evaluated_at']), 'Regressed cut/time')
            require(kind != 'BOOTSTRAP', 'Bootstrap may run only once')
        else: require(kind == 'BOOTSTRAP', 'First complete evaluation must be explicit bootstrap')
        body = dict(kind=kind, source_cut=dict(source_id=self.config['source_id'], epoch=self.config['epoch'], committed_event_id=cut),
                    evaluated_at=evaluated_at, policy=self.policy, policy_sha256=self.policy_sha,
                    classifier_version=self.policy['classifier_version'], qualification_policy_version=self.policy['qualification_policy_version'],
                    previous_sha256=last['event_id'][4:] if last else None)
        if self.config['contract_revision']!='A1':body.update(revision_metadata(self.config['contract_revision'], self.config.get('legacy_tclk_cohort')))
        number = last['number'] + 1 if last else 1
        with self.conn:
            self.conn.execute('INSERT INTO evaluations VALUES(?,?,?,?,?)', (number, identity('pe1', body), canonical(body).decode(), body['previous_sha256'], 'STAGING'))
            self.set('evaluation_head',identity('pe1',body))
        return number

    def stage(self, number, bundles):
        self.check(); require(len(bundles) <= 200, 'Stage at most 200 records per transaction')
        row = self.conn.execute('SELECT * FROM evaluations WHERE number=?', (number,)).fetchone()
        require(row and row['status'] == 'STAGING', 'Evaluation is not accepting inputs')
        when = instant(loads(row['body'])['evaluated_at'])
        # Validate complete supplied inputs before opening the write transaction.
        # Keep hashes and caller-owned references, not 200 serialized originals.
        # Re-encode at most 50 at a time and recheck the hash before storage.
        prepared={}
        for bundle in bundles:
            self.check();self.validate_bundle(bundle)
            require(instant(bundle['first_observed_at']) <= when, 'Evaluation predates source availability')
            body=canonical(bundle);h=hashlib.sha256(body).hexdigest();rid=bundle['message']['projection_row_id']
            require(rid not in prepared or prepared[rid][0]==h,'Conflicting source in complete cut')
            prepared[rid]=(h,bundle)
        with self.conn:
            existing={r['id']:r['hash'] for r in self.conn.execute('SELECT id,hash FROM evaluation_inputs WHERE number=? AND id IN ('+','.join('?' for _ in prepared)+')',(number,*prepared))} if prepared else {}
            for rid,h in existing.items():require(prepared[rid][0]==h,'Conflicting source in complete cut')
            added=[(rid,h,bundle) for rid,(h,bundle) in prepared.items() if rid not in existing]
            for start in range(0,len(added),50):
                encoded=[]
                for rid,h,bundle in added[start:start+50]:
                    body=canonical(bundle)
                    require(hashlib.sha256(body).hexdigest()==h,'Source input changed during staging')
                    encoded.append((h,rid,body.decode()))
                self.conn.executemany('INSERT OR IGNORE INTO input_versions VALUES(?,?,?)',encoded)
                self.conn.executemany('INSERT INTO evaluation_inputs VALUES(?,?,?)',[(number,rid,h) for h,rid,_ in encoded])

    def stage_edges(self,number,edges):
        self.check();status=self.conn.execute('SELECT status FROM evaluations WHERE number=?',(number,)).fetchone()
        require(status and status[0]=='STAGING','Edges require a staging evaluation')
        require(type(edges) is list and len(edges)<=200,'Stage at most 200 edges')
        with self.conn:
            for edge in edges:
                keys(edge,{'source_id','target_id','relationship_type','confidence'})
                key=digest({k:v for k,v in edge.items() if k!='confidence'})
                old=self.conn.execute('SELECT body FROM evaluation_edges WHERE number=? AND key=?',(number,key)).fetchone()
                require(not old or old[0]==canonical(edge).decode(),'Conflicting edge within source cut')
                self.conn.execute('INSERT OR IGNORE INTO evaluation_edges VALUES(?,?,?)',(number,key,canonical(edge).decode()))

    def edge_manifest_hash(self,number):
        return digest([loads(r[0]) for r in self.conn.execute('SELECT body FROM evaluation_edges WHERE number=? ORDER BY key',(number,))])

    def input_manifest_hash(self, number):
        h=hashlib.sha256();h.update(b'[');first=True
        for row in self.conn.execute('SELECT id,hash FROM evaluation_inputs WHERE number=? ORDER BY id',(number,)):
            if not first:h.update(b',')
            first=False;h.update(canonical(dict(row)))
        h.update(b']');return h.hexdigest()

    def seal(self, number):
        self.check()
        row=self.conn.execute('SELECT body,status FROM evaluations WHERE number=?',(number,)).fetchone()
        require(row and row['status']=='STAGING','Evaluation cannot be sealed')
        body=loads(row['body']);body['input_manifest_sha256']=self.input_manifest_hash(number);body['edge_manifest_sha256']=self.edge_manifest_hash(number)
        with self.conn:
            self.conn.execute('UPDATE evaluations SET body=?,event_id=? WHERE number=?',(canonical(body).decode(),identity('pe1',body),number))
            self.set('evaluation_head',identity('pe1',body))
            self.record_operation('EVALUATION',dict(number=number))
            require(self.conn.execute("UPDATE evaluations SET status='SEALED' WHERE number=? AND status='STAGING'", (number,)).rowcount == 1, 'Evaluation cannot be sealed')
        return self.resume(number)

    def bundle(self, rid):
        row = self.conn.execute('SELECT v.hash,v.body FROM current_inputs c JOIN input_versions v ON v.hash=c.hash WHERE c.id=?', (rid,)).fetchone()
        require(row is not None, 'Missing local dependency: ' + rid)
        body = loads(row['body'], max(4*1024*1024, len(row['body'].encode())))
        require(digest(body) == row['hash'], 'Corrupt replay input')
        return body

    def source_ref(self, rid):
        msg = self.bundle(rid)['message']
        return dict(kind='PROJECTED_MESSAGE', source_id=self.config['source_id'], source_epoch=self.config['epoch'], id=rid, sha256=text_hash(msg['text']))

    def save_manifest(self, body):
        h = digest(body)
        self.conn.execute('INSERT OR IGNORE INTO rule_manifests VALUES(?,?)', (h, canonical(body).decode()))
        return h

    def mark_permanent(self, rid, reason):
        old=self.conn.execute('SELECT reason FROM permanent WHERE id=?',(rid,)).fetchone()
        if not old:
            self.conn.execute('INSERT INTO permanent VALUES(?,?)',(rid,reason));self.retention_revision+=1
        elif PRIORITY.index(reason)<PRIORITY.index(old[0]):
            self.conn.execute('UPDATE permanent SET reason=? WHERE id=?',(reason,rid));self.retention_revision+=1
        self.conn.execute('DELETE FROM expiry WHERE id=?', (rid,))
        changed=self.conn.execute('UPDATE projection.selection_membership SET retain_until=NULL WHERE projection_row_id=? AND retain_until IS NOT NULL', (rid,)).rowcount
        if changed:self.set('dirty','1')

    def apply_pin_member(self,rid,when):
        if self.conn.execute('SELECT 1 FROM current_inputs WHERE id=?',(rid,)).fetchone():
            self._upsert_message(self.bundle(rid),when)
        elif self.conn.execute('SELECT 1 FROM projection.interactions WHERE projection_row_id=?',(rid,)).fetchone():
            values=[loads(r[0]) for r in self.conn.execute('SELECT root_json FROM pin_members WHERE id=?',(rid,))]
            values.sort(key=lambda r:(r['kind'],r['id']));roots(values);encoded=canonical(values).decode()
            current=self.conn.execute("SELECT retain_until,pin_roots_json FROM projection.selection_membership WHERE entity_type='interaction' AND projection_row_id=?",(rid,)).fetchone()
            require(current,'Missing interaction membership')
            if current['retain_until'] is not None or current['pin_roots_json']!=encoded:
                self.conn.execute("UPDATE projection.selection_membership SET retention_class='PINNED',retain_until=NULL,pin_roots_json=? WHERE entity_type='interaction' AND projection_row_id=?",(encoded,rid));self.set('dirty','1')
            self.conn.execute('DELETE FROM expiry WHERE id=?',(rid,))

    def closure(self, starts):
        """Persisted deterministic frontier, committed in at most 200-node turns."""
        starts=sorted(set(starts))
        latest=self.conn.execute('SELECT event_id FROM evaluations ORDER BY number DESC LIMIT 1').fetchone()
        job=digest(dict(starts=starts,evaluation=latest[0] if latest else None))
        with self.conn:
            self.conn.execute("INSERT OR IGNORE INTO dependency_jobs VALUES(?,'PENDING')",(job,))
            self.conn.executemany('INSERT OR IGNORE INTO dependency_frontier VALUES(?,?,0)',[(job,node) for node in starts])
        while True:
            self.check()
            batch=self.conn.execute('SELECT node FROM dependency_frontier WHERE job_id=? AND done=0 ORDER BY node LIMIT 200',(job,)).fetchall()
            if not batch:break
            with self.conn:
                for row in batch:
                    rid=row[0]
                    require(self.conn.execute('SELECT 1 FROM current_inputs WHERE id=? UNION SELECT 1 FROM workflows WHERE id=? UNION SELECT 1 FROM projection.interactions WHERE projection_row_id=?',(rid,rid,rid)).fetchone(),'Missing local dependency: '+rid)
                    self.conn.execute('INSERT OR IGNORE INTO dependency_frontier SELECT ?,child,0 FROM dependencies WHERE parent=?',(job,rid))
                    self.conn.execute('UPDATE dependency_frontier SET done=1 WHERE job_id=? AND node=?',(job,rid))
                require(self.conn.execute('SELECT count(*) FROM dependency_frontier WHERE job_id=?',(job,)).fetchone()[0]<=100000,'Dependency capacity exceeded; no truncation')
        with self.conn:self.conn.execute("UPDATE dependency_jobs SET status='COMPLETE' WHERE id=?",(job,))
        return [r[0] for r in self.conn.execute('SELECT node FROM dependency_frontier WHERE job_id=? ORDER BY node',(job,))]

    def qualify(self, rid, claim, kind, outcome, evaluation, inputs, group, refs=None, authenticity=None, correctness=None, reproducibility=None, subject=None):
        bundle = self.bundle(rid); msg = bundle['message']; ann = loads(bundle['provenance']['annotations_json'])
        source = self.source_ref(rid)
        if self.config['contract_revision'] == TL1_REVISION:
            from scout_projection_tclk import positive_eligible
            if kind != 'NEGATIVE_FACT':
                require(positive_eligible(self, rid, evaluation['evaluated_at']), 'TL1_POSITIVE_QUALIFICATION_FORBIDDEN')
            old_key = digest([source, subject or msg['sender'], claim, kind, POLICY_SHA, POLICY['classifier_version'], POLICY['qualification_policy_version']])
            historical = self.conn.execute('SELECT qualification_id FROM qualification_keys WHERE first_key=?', (old_key,)).fetchone()
            if historical: return historical[0]
        early_key=digest([source,subject or msg['sender'],claim,kind,self.policy_sha,self.policy['classifier_version'],self.policy['qualification_policy_version']])
        existing=self.conn.execute('SELECT qualification_id FROM qualification_keys WHERE first_key=?',(early_key,)).fetchone()
        if existing:return existing[0]
        if msg['sender'] in self.config['local_dids']:ann.update(operator_group=FAMILY,same_operator=True,independent_reputation=False)
        record = dict(schema='router-durable-qualification/v1', source_ref=source,
            scout_event_id=bundle['provenance']['scout_event_id'], evidence_id=msg['evidence_id'], subject_did=subject or msg['sender'],
            claim=claim, qualification_type=kind, qualification_outcome=outcome, qualified_at=evaluation['evaluated_at'],
            policy_version=self.policy['version'], policy_sha256=self.policy_sha, classifier_version=self.policy['classifier_version'],
            qualification_policy_version=self.policy['qualification_policy_version'], bootstrap_id=self.get('bootstrap_id'),
            evaluation_id=evaluation['event_id'], source_cut=evaluation['source_cut'], rule_id=inputs['rule_id'],
            rule_input_sha256=self.save_manifest(inputs), rule_group_sha256=group() if callable(group) else group if isinstance(group,str) else self.save_manifest(group),
            provenance_refs=sorted(refs or [source], key=canonical), operator_group=ann['operator_group'],
            same_operator=ann['same_operator'], independent_reputation=ann['independent_reputation'],
            authenticity=authenticity if authenticity is not None else msg['verification_status'], correctness=correctness,
            reproducibility=reproducibility, initial_status='VALID')
        record['qualification_id'] = identity('dq1', record); validate_qualification(record, policy_versions(self.config['contract_revision']))
        key = first_key(record)
        old = self.conn.execute('SELECT qualification_id FROM qualification_keys WHERE first_key=?', (key,)).fetchone()
        if old: return old[0]
        closures=[]
        for ref in record['provenance_refs']:
            self.resolve_audit_ref(ref)
            if ref['kind']=='PROJECTED_MESSAGE':closures.append(self.closure([ref['id']]))
        encoded = canonical(record).decode()
        self.conn.execute('INSERT INTO qualification_keys VALUES(?,?,?)', (key, record['qualification_id'], encoded))
        self.set('dirty','1')
        self.conn.execute('INSERT INTO projection.durable_qualifications VALUES(?,?)', (record['qualification_id'], encoded))
        self.set('qualification_count',int(self.get('qualification_count','0'))+1)
        for members in closures:
            for dep in members:
                self.mark_permanent(dep, 'CAPABILITY_SUPPORT' if kind == 'CAPABILITY_USE' else 'NEGATIVE_EVIDENCE' if kind == 'NEGATIVE_FACT' else 'BENCH_VERIFICATION')
                if self.conn.execute('SELECT 1 FROM current_inputs WHERE id=?',(dep,)).fetchone():self._upsert_message(self.bundle(dep),evaluation['evaluated_at'])
        return record['qualification_id']

    def resolve_audit_ref(self, ref):
        reference(ref, {'PROJECTED_MESSAGE', 'LOCAL_ARTIFACT'})
        if ref['kind'] == 'PROJECTED_MESSAGE':
            require(ref == self.source_ref(ref['id']), 'Audit source hash or namespace mismatch')
        else:
            row = self.conn.execute('SELECT * FROM local_artifacts WHERE id=?', (ref['id'],)).fetchone()
            require(row and (row['source_id'], row['epoch'], row['hash']) == (ref['source_id'], ref['source_epoch'], ref['sha256']), 'Missing authoritative local artifact')
            require(hashlib.sha256(row['body']).hexdigest() == row['hash'], 'Corrupt local artifact')

    def _upsert_message(self, bundle, evaluated_at, legacy_writes=None):
        msg = bundle['message']; rid = msg['projection_row_id']; facts = bundle['facts']; p = dict(bundle['provenance'])
        primary, obj = classify(msg['text'], facts['official'], facts['identity_binding'])
        tl1 = self.config['contract_revision'] == TL1_REVISION
        held = legacy = False
        if tl1:
            from scout_projection_tclk import is_held, is_legacy
            held, legacy = is_held(self, rid), is_legacy(self, rid)
            if legacy: primary = 'TCLK_LEGACY_NONCONFORMING'
        ann = loads(p['annotations_json']); ann['classification'] = primary
        if msg['sender'] in self.config['local_dids']:
            require(ann['independent_reputation'] is not True, 'Conflicting known local independence')
            ann.update(operator_group=FAMILY, same_operator=True, independent_reputation=False)
        else:
            require(not facts['operator_local'], 'Unconfigured local operator fact')
        # Current capability outputs are recomputed as a complete group below.
        existing_ann=self.conn.execute("SELECT annotations_json FROM projection.source_provenance WHERE entity_type='message' AND projection_row_id=?",(rid,)).fetchone()
        ann['capability_support'] = loads(existing_ann[0])['capability_support'] if existing_ann else []
        if legacy: ann['capability_support'] = []
        workflow_facts=facts['workflow']
        if workflow_facts:
            links=list(ann['evidence_links'])
            state=self.conn.execute('SELECT closure_evidence_id FROM workflows WHERE id=?',(workflow_facts['id'],)).fetchone()
            required={workflow_facts['root_id'],workflow_facts['result_id'],state[0] if state else None}-{None,rid}
            for dep in sorted(required):
                source=self.bundle(dep)['message'];links.append(dict(room=source['room'],generation=source['generation'],seq=source['seq'],evidence_id=source['evidence_id']))
            ann['evidence_links']=[loads(v) for v in sorted(set(canonical(v) for v in links))]
        p['annotations_json'] = canonical(annotations(ann,self.config['contract_revision'])).decode()
        reasons = {'CONTEXT'}
        if facts['signature_failure'] or facts['did_mismatch']: reasons.add('NEGATIVE_EVIDENCE')
        if facts['identity_binding']: reasons.add('IDENTITY_OPERATOR')
        if obj.get('schema_version', obj.get('schema')) in BENCH: reasons.add('BENCH_VERIFICATION')
        if primary in {'CAPABILITY_CLAIM', 'PROMOTIONAL_CLAIM'} or primary=='UNCLASSIFIED' and any(rules.pattern_matches(msg['text'],pattern) for rule in rules.CAPABILITY_RULES for pattern in rule.strong_patterns+rule.weak_patterns): reasons.add('CAPABILITY_SIGNAL')
        permanent = self.conn.execute('SELECT reason FROM permanent WHERE id=?', (rid,)).fetchone()
        if permanent: reasons.add(permanent[0])
        pin_roots = [loads(r[0]) for r in self.conn.execute('SELECT root_json FROM pin_members WHERE id=? ORDER BY root_json', (rid,))]
        pin_roots.sort(key=lambda r:(r['kind'],r['id'])); roots(pin_roots)
        if pin_roots: reasons.add('PINNED')
        expiry = plus(bundle['first_observed_at'], 7776000 if 'CAPABILITY_SIGNAL' in reasons else 2592000)
        if reasons & {'NEGATIVE_EVIDENCE','IDENTITY_OPERATOR','BENCH_VERIFICATION','CAPABILITY_SUPPORT','CAPABILITY_CONTRADICTION','PINNED'}: expiry = None
        workflow = facts['workflow']
        if workflow:
            state = self.conn.execute('SELECT * FROM workflows WHERE id=?', (workflow['id'],)).fetchone()
            require(state is not None, 'Workflow state missing')
            reasons.add('TCLK_LIFECYCLE' if workflow['identity']['protocol'] == 'tclk/1' else 'WORK_LIFECYCLE')
            if not state['closed_at']: expiry = None
            elif expiry is not None: expiry = plus(state['closed_at'], 7776000)
        retention = next(k for k in PRIORITY if k in reasons)
        if held:
            ordinary_expiry = expiry
            if workflow and workflow['id'] in getattr(self, 'tclk_ordinary_closed', {}):
                closed = self.tclk_ordinary_closed[workflow['id']]
                if closed and not reasons & {'NEGATIVE_EVIDENCE','IDENTITY_OPERATOR','BENCH_VERIFICATION','CAPABILITY_SUPPORT','CAPABILITY_CONTRADICTION','PINNED'}:
                    ordinary_expiry = plus(closed, 7776000)
            self.conn.execute('UPDATE temp.tl1_hold SET ordinary_due=? WHERE id=?', (ordinary_expiry, rid))
            expiry = None
            if retention not in {'NEGATIVE_EVIDENCE','PINNED','IDENTITY_OPERATOR','BENCH_VERIFICATION','CAPABILITY_CONTRADICTION','CAPABILITY_SUPPORT'}:
                retention = 'TCLK_LEGACY_AUDIT'
        selected = bool(msg['signed'] or reasons - {'CONTEXT', 'CAPABILITY_SIGNAL'} or bundle['dependencies'])
        if held: selected = True
        if not selected or expiry is not None and instant(expiry) <= instant(evaluated_at):
            self._remove(rid); return
        existing = self.conn.execute('SELECT * FROM projection.messages WHERE room=? AND generation=? AND seq=?', (msg['room'],msg['generation'],msg['seq'])).fetchall()
        for old in existing:
            require(old['text'] == msg['text'] and old['sender'] == msg['sender'], 'Conflicting message contents at same source position')
            for field in ('timestamp','nonce','sig'):
                require(old[field] is None or msg[field] is None or old[field]==msg[field],'Conflicting known network fields at same source position')
        old_msg=self.conn.execute('SELECT * FROM projection.messages WHERE projection_row_id=?',(rid,)).fetchone()
        old_p=self.conn.execute("SELECT * FROM projection.source_provenance WHERE entity_type='message' AND projection_row_id=?",(rid,)).fetchone()
        old_m=self.conn.execute("SELECT * FROM projection.selection_membership WHERE entity_type='message' AND projection_row_id=?",(rid,)).fetchone()
        membership=('message',rid,retention,bundle['first_observed_at'],expiry,canonical(pin_roots).decode())
        if self.config['contract_revision'] in (LG2_REVISION, TL1_REVISION):
            from scout_projection_compact import sync
            compact_bundle=dict(bundle,provenance=dict(p,annotations_json=canonical(ann).decode()))
            if sync(self.conn,compact_bundle,batch=legacy_writes):self.set('dirty','1')
        if legacy:
            from scout_projection_tclk import sync_record
            sync_record(self, bundle)
        if old_msg and dict(old_msg)==msg and old_p and dict(old_p)==p and old_m and tuple(old_m)==membership:return
        self.set('dirty','1')
        if not old_msg:
            self.conn.execute('INSERT INTO projection.watermarks VALUES(?,?,1,?,?) ON CONFLICT(room,generation) DO UPDATE SET record_count=record_count+1,min_seq=min(min_seq,excluded.min_seq),max_seq=max(max_seq,excluded.max_seq)',(msg['room'],msg['generation'],msg['seq'],msg['seq']))
        self.conn.execute('INSERT INTO projection.messages VALUES('+','.join('?' for _ in MESSAGE_COLUMNS)+') ON CONFLICT(projection_row_id) DO UPDATE SET '+','.join(k+'=excluded.'+k for k in MESSAGE_COLUMNS[1:]), tuple(msg[k] for k in MESSAGE_COLUMNS))
        self.conn.execute('INSERT INTO projection.source_provenance VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(entity_type,projection_row_id) DO UPDATE SET '+','.join(k+'=excluded.'+k for k in PROVENANCE_COLUMNS[2:]), tuple(p[k] for k in PROVENANCE_COLUMNS))
        self.conn.execute('INSERT INTO projection.selection_membership VALUES(?,?,?,?,?,?) ON CONFLICT(entity_type,projection_row_id) DO UPDATE SET retention_class=excluded.retention_class,retain_until=excluded.retain_until,pin_roots_json=excluded.pin_roots_json', ('message',rid,retention,bundle['first_observed_at'],expiry,canonical(pin_roots).decode()))
        if expiry: self.conn.execute('INSERT INTO expiry VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET due=excluded.due', (rid,'message',expiry))
        else: self.conn.execute('DELETE FROM expiry WHERE id=?', (rid,))
        self.conn.execute('INSERT INTO projection.coverage_history VALUES(?,?,?,?,?) ON CONFLICT(room,generation) DO UPDATE SET max_ever_projected_seq=excluded.max_ever_projected_seq,witness_source_locator=excluded.witness_source_locator,witness_record_sha256=excluded.witness_record_sha256 WHERE excluded.max_ever_projected_seq>coverage_history.max_ever_projected_seq', (msg['room'],msg['generation'],msg['seq'],p['source_record_locator'],digest(msg)))

    def _remove(self, rid):
        if self.config['contract_revision'] == TL1_REVISION:
            from scout_projection_tclk import is_held
            require(not is_held(self, rid), 'TL1_HELD_DEPENDENCY_REMOVAL_FORBIDDEN')
        require(not self.conn.execute('SELECT 1 FROM permanent WHERE id=? UNION SELECT 1 FROM pin_members WHERE id=?', (rid,rid)).fetchone(), 'Attempted removal of permanent evidence')
        # Enumerate the complete schema-allowed type domain so SQLite can use
        # the leading column of each composite PK instead of scanning every
        # retained row for each expiry. This still removes either entity type.
        if self.conn.execute("SELECT 1 FROM projection.selection_membership WHERE entity_type IN ('message','interaction') AND projection_row_id=?",(rid,)).fetchone():self.set('dirty','1')
        old_message=self.conn.execute('SELECT room,generation FROM projection.messages WHERE projection_row_id=?',(rid,)).fetchone()
        if self.config['contract_revision'] in (LG2_REVISION, TL1_REVISION):
            from scout_projection_compact import remove
            remove(self.conn,rid)
        self.conn.execute('DELETE FROM projection.messages WHERE projection_row_id=?', (rid,))
        if old_message:
            domain=tuple(old_message)
            low=self.conn.execute('SELECT seq FROM projection.messages WHERE room=? AND generation=? ORDER BY seq LIMIT 1',domain).fetchone()
            if low:
                high=self.conn.execute('SELECT seq FROM projection.messages WHERE room=? AND generation=? ORDER BY seq DESC LIMIT 1',domain).fetchone()[0]
                self.conn.execute('UPDATE projection.watermarks SET record_count=record_count-1,min_seq=?,max_seq=? WHERE room=? AND generation=?',(low[0],high,*domain))
            else:self.conn.execute('DELETE FROM projection.watermarks WHERE room=? AND generation=?',domain)
        self.conn.execute('DELETE FROM projection.interactions WHERE projection_row_id=?', (rid,))
        self.conn.execute("DELETE FROM projection.source_provenance WHERE entity_type IN ('message','interaction') AND projection_row_id=?", (rid,))
        self.conn.execute("DELETE FROM projection.selection_membership WHERE entity_type IN ('message','interaction') AND projection_row_id=?", (rid,))
        self.conn.execute('DELETE FROM expiry WHERE id=?', (rid,))

    def resume(self, number=None):
        self.check()
        row = self.conn.execute("SELECT * FROM evaluations WHERE status!='COMPLETE' ORDER BY number LIMIT 1").fetchone()
        if row is None: return self.status()
        require(number is None or number == row['number'], 'Wrong pending evaluation')
        require(row['status'] != 'STAGING', 'Incomplete source cut cannot be evaluated')
        number = row['number']; evaluation = loads(row['body']); evaluation['event_id'] = row['event_id']
        when = evaluation['evaluated_at']
        with self.conn:
            if not self.get('bootstrap_id'): self.set('bootstrap_id', row['event_id'])
            self.conn.execute("UPDATE evaluations SET status='APPLYING' WHERE number=?", (number,))
        cursor = self.conn.execute('SELECT i.id,i.hash,v.body FROM evaluation_inputs i JOIN input_versions v ON v.hash=i.hash WHERE i.number=? ORDER BY i.id', (number,))
        while True:
            self.check(); batch = cursor.fetchmany(200)
            if not batch: break
            with self.conn:
                for item in batch:
                    bundle = loads(item['body'], max(4*1024*1024,len(item['body'].encode()))); require(digest(bundle) == item['hash'], 'Corrupt staged input')
                    self.validate_bundle(bundle)
                    msg = bundle['message']; rid = msg['projection_row_id']
                    old = self.conn.execute('SELECT first_observed_at FROM current_inputs WHERE id=?', (rid,)).fetchone()
                    require(not old or old[0] == bundle['first_observed_at'], 'First-observed time changed')
                    if old:
                        prior_bundle=self.bundle(rid)
                        from scout_projection_legacy import continuity
                        from scout_projection_compact import logical_audit
                        continuity(logical_audit(prior_bundle),logical_audit(bundle))
                        prior=prior_bundle['message']
                        require(all(prior[k]==msg[k] for k in ('room','generation','seq','sender','text','timestamp','nonce','sig')),'Immutable source fields changed under the same raw identity')
                    self.conn.execute('INSERT INTO current_inputs VALUES(?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET hash=excluded.hash,sender=excluded.sender,room=excluded.room,generation=excluded.generation,seq=excluded.seq,template=excluded.template,workflow_id=excluded.workflow_id WHERE current_inputs.hash IS NOT excluded.hash OR current_inputs.sender IS NOT excluded.sender OR current_inputs.room IS NOT excluded.room OR current_inputs.generation IS NOT excluded.generation OR current_inputs.seq IS NOT excluded.seq OR current_inputs.template IS NOT excluded.template OR current_inputs.workflow_id IS NOT excluded.workflow_id', (rid,item['hash'],msg['sender'],msg['room'],msg['generation'],msg['seq'],msg['template_normalized_hash'] or '',bundle['first_observed_at'],bundle['facts']['workflow']['id'] if bundle['facts']['workflow'] else None))
                    self.conn.execute('INSERT OR IGNORE INTO evaluation_groups VALUES(?,?)',(number,msg['sender']))
                    for alias_kind,alias in [('SCOUT_EVENT',bundle['provenance']['scout_event_id']),('EVIDENCE_RECORD',msg['evidence_id'])]:
                        if alias is not None:self.conn.execute('INSERT OR IGNORE INTO source_aliases VALUES(?,?,?)',(alias_kind,alias,rid))
                    for dep in bundle['dependencies']: self.conn.execute('INSERT OR IGNORE INTO dependencies VALUES(?,?)', (rid,dep))
        if self.config['contract_revision'] == TL1_REVISION:
            from scout_projection_tclk import prepare_holds
            prepare_holds(self)
            self.include_groups(number, 'SELECT DISTINCT c.sender FROM current_inputs c JOIN temp.tl1_hold h ON h.id=c.id', ())
        # Discover each changed template once, then persist affected senders in
        # bounded turns even when one template has very large peer fanout.
        self.include_groups(number,'SELECT DISTINCT peer.sender FROM (SELECT DISTINCT c.template FROM evaluation_inputs e JOIN current_inputs c ON c.id=e.id WHERE e.number=?) changed JOIN current_inputs peer ON peer.template=changed.template',(number,))
        self.include_groups(number,'SELECT DISTINCT c.sender FROM expiry e JOIN current_inputs c ON c.id=e.id WHERE e.due<=?',(when,))
        self.include_groups(number,'SELECT DISTINCT peer.sender FROM (SELECT DISTINCT c.template FROM expiry e JOIN current_inputs c ON c.id=e.id WHERE e.due<=?) expired JOIN current_inputs peer ON peer.template=expired.template',(when,))
        for edge in self.conn.execute('SELECT body FROM evaluation_edges WHERE number=? ORDER BY key',(number,)):
            self.add_interaction(**loads(edge[0]))
        if self.config['contract_revision'] == TL1_REVISION:
            prepare_holds(self)
            with self.conn:
                self.conn.execute("UPDATE projection.selection_membership SET retain_until=NULL,retention_class='TCLK_LEGACY_AUDIT' WHERE entity_type='interaction' AND projection_row_id IN (SELECT id FROM temp.tl1_hold)")
                self.conn.execute("DELETE FROM expiry WHERE entity_type='interaction' AND id IN (SELECT id FROM temp.tl1_hold)")
            self.include_groups(number, 'SELECT DISTINCT c.sender FROM current_inputs c JOIN temp.tl1_hold h ON h.id=c.id', ())
        self.evaluate_workflows(when)
        from scout_projection_pins import refresh_pins
        refresh_pins(self,number)
        # Reclassification includes expiry-affected groups and selected-scope counts.
        # Streaming source rows bounds staging memory; per-sender rule groups remain whole.
        cursor=self.conn.execute('SELECT c.id FROM current_inputs c JOIN evaluation_groups g ON g.sender=c.sender WHERE g.number=? ORDER BY c.id',(number,))
        limit=self.write_batch_size if self.config['contract_revision'] in (LG2_REVISION, TL1_REVISION) else 1
        while True:
            batch=cursor.fetchmany(limit)
            if not batch:break
            # Decode/hash bounded private inputs before taking a write lock.
            bundles=[self.bundle(item[0]) for item in batch]
            with self.conn:
                legacy_writes=None
                if self.config['contract_revision'] in (LG2_REVISION, TL1_REVISION):
                    from scout_projection_compact import WriteBatch
                    if not self.conn.in_transaction:self.conn.execute('BEGIN')
                    legacy_writes=WriteBatch(self.conn,bundles)
                started=time.monotonic()
                for bundle in bundles:
                    self.check();self._upsert_message(bundle,when,legacy_writes)
                    if time.monotonic()-started>=0.020:
                        if legacy_writes is not None:legacy_writes.flush()
                        self.conn.commit();self.check();started=time.monotonic()
                if legacy_writes is not None:legacy_writes.flush()
            # Release private originals before building a whole sender rule group.
            bundles=None;legacy_writes=None;bundle=None
        prepared_retention_revision=self.retention_revision if self.config['contract_revision'] in (LG2_REVISION, TL1_REVISION) else None
        senders = [r[0] for r in self.conn.execute('SELECT sender FROM evaluation_groups WHERE number=? ORDER BY sender',(number,))]
        for sender in senders:
            self.check()
            self.evaluate_sender(sender, evaluation, prepared_retention_revision=prepared_retention_revision)
        while True:
            expired=self.conn.execute("SELECT id FROM expiry WHERE entity_type='interaction' AND due<=? ORDER BY due,id LIMIT 200",(when,)).fetchall()
            if not expired:break
            self.check()
            with self.conn:
                for item in expired:self._remove(item[0])
        if self.config['contract_revision'] in (LG2_REVISION, TL1_REVISION):
            from scout_projection_compact import validate_relations
            validate_relations(self.conn,'projection.')
        if self.config['contract_revision'] == TL1_REVISION:
            from scout_projection_tclk import validate_public
            details = validate_public(self.conn, self.config['legacy_tclk_cohort'], self.config['source_id'], self.config['epoch'], evaluation['source_cut']['committed_event_id'], 'projection.', self.check)
            with self.conn: self.set('tl1_status', canonical(details).decode())
        with self.conn:
            self.conn.execute("UPDATE evaluations SET status='COMPLETE' WHERE number=?", (number,))
            self.set('source_cut', canonical(evaluation['source_cut']).decode()); self.set('evaluated_at', when)
        self.conn.execute('PRAGMA projection.incremental_vacuum(200)')
        return self.status()

    def include_groups(self, number, query, args):
        cursor=self.conn.execute(query,args)
        while True:
            rows=cursor.fetchmany(200)
            if not rows:return
            self.check()
            with self.conn:
                self.conn.executemany('INSERT OR IGNORE INTO evaluation_groups VALUES(?,?)',[(number,row[0]) for row in rows])

    def evaluate_sender(self, sender, evaluation, *, prepared_retention_revision=None):
        require(self.conn.execute('SELECT count(*) FROM current_inputs WHERE sender=?',(sender,)).fetchone()[0]<=100000,'Complete sender group exceeds operational capacity; no truncation')
        observations = []; ids = []; all_ids = []
        for row in self.conn.execute('SELECT m.* FROM current_inputs c JOIN projection.messages m ON m.projection_row_id=c.id WHERE c.sender=? ORDER BY c.room,c.generation,c.seq,c.id', (sender,)):
            m = dict(row); all_ids.append(m['projection_row_id'])
            if self.config['contract_revision'] == TL1_REVISION:
                from scout_projection_tclk import positive_eligible
                if not positive_eligible(self, m['projection_row_id'], evaluation['evaluated_at']): continue
            ids.append(m['projection_row_id'])
            count = self.conn.execute('SELECT count(DISTINCT c.sender) FROM current_inputs c JOIN projection.messages m ON m.projection_row_id=c.id WHERE c.template=?',(m['template_normalized_hash'],)).fetchone()[0] if m['template_normalized_hash'] is not None else 1
            if self.config['contract_revision'] == TL1_REVISION and m['template_normalized_hash'] is not None:
                count = len({peer['sender'] for peer in self.conn.execute('SELECT c.id,c.sender FROM current_inputs c JOIN projection.messages m ON m.projection_row_id=c.id WHERE c.template=?', (m['template_normalized_hash'],)) if positive_eligible(self, peer['id'], evaluation['evaluated_at'])})
            observations.append(rules.AgentObservation(identity=rules.AgentIdentity(sender), room=m['room'], sequence_id=m['seq'], timestamp=m['timestamp'], text=m['text'], normalized_text=m['normalized_text'] or rules.normalize_text(m['text']), template_hash=m['template_normalized_hash'] or '', is_signed=bool(m['signed']), template_dids=count, generation=m['generation'], nonce=m['nonce'], sig=m['sig'], message_hash=m['message_hash'], verification_status=m['verification_status'] or 'PROVENANCE_INCOMPLETE', source_export_hash=m['source_export_hash'], source_export_path=m['source_export_path'], evidence_id=m['evidence_id']))
        counts = Counter(rules.template_count_key(obs) for obs in observations)
        group_sha=None
        def group_hash():
            nonlocal group_sha
            if group_sha is None:
                group=[dict(source_ref=self.source_ref(rid),duplicate_count=counts[rules.template_count_key(obs)],template_dids=obs.template_dids) for rid,obs in zip(ids,observations)]
                group_sha=self.save_manifest(group)
            return group_sha
        support = defaultdict(list)
        with self.conn:
            for rule in rules.CAPABILITY_RULES:
                decisions = rules.capability_evidence_decisions(observations, rule.capability_id, counts)
                for index,(rid, obs, decision) in enumerate(zip(ids, observations, decisions)):
                    if index and index%200==0:self.conn.commit();self.check()
                    if not decision.relevant: continue
                    if self.config['contract_revision'] == TL1_REVISION:
                        from scout_projection_tclk import positive_eligible
                        if not positive_eligible(self, rid, evaluation['evaluated_at']): continue
                    # Do not fabricate an absent source evidence ID for annotation slots.
                    if obs.evidence_id:
                        support[rid].append(dict(capability_id=rule.capability_id, classification=decision.support_contribution, evidence_id=obs.evidence_id))
                    facts = self.bundle(rid)['facts']
                    if decision.passed_threshold and decision.support_contribution in {'LIMITED','STRONG'} and obs.is_signed and re.fullmatch(r'did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+',sender) and not facts['signature_failure'] and not facts['did_mismatch']:
                        self.qualify(rid, dict(kind='CAPABILITY',id=rule.capability_id), 'CAPABILITY_USE', decision.support_contribution, evaluation,
                                     dict(rule_id='capability_evidence_decisions:'+rule.capability_id, observation={k:v for k,v in asdict(obs).items() if k!='text'}, text_ref=self.source_ref(rid), output=asdict(decision)), group_hash)
            for index,rid in enumerate(all_ids):
                if index and index%200==0:self.conn.commit();self.check()
                b = self.bundle(rid); facts=b['facts']
                if facts['signature_failure'] or facts['did_mismatch']:
                    claim = 'envelope:'+rid+(':signature_failure' if facts['signature_failure'] else ':did_mismatch')
                    self.qualify(rid,dict(kind='NEGATIVE_FACT',id=claim),'NEGATIVE_FACT','ESTABLISHED_NEGATIVE_FACT',evaluation,
                                 dict(rule_id='scout-envelope-adverse/v1',facts={k:facts[k] for k in ('signature_failure','did_mismatch')}),[self.source_ref(rid)], subject='envelope:'+rid)
                # The complete-cut first pass already checked/upserted every row.
                # Rules only change retention via mark_permanent; refresh when any
                # such change occurred, including dependency changes in prior groups.
                if prepared_retention_revision is None or self.retention_revision!=prepared_retention_revision:
                    self._upsert_message(b, evaluation['evaluated_at'])
                row=self.conn.execute("SELECT annotations_json FROM projection.source_provenance WHERE entity_type='message' AND projection_row_id=?",(rid,)).fetchone()
                if row:
                    ann=loads(row[0]); ann['capability_support']=sorted(support[rid],key=canonical)
                    updated=canonical(annotations(ann,self.config['contract_revision'])).decode()
                    if self.config['contract_revision'] in (LG2_REVISION, TL1_REVISION):
                        from scout_projection_compact import logical_audit
                        logical_audit(dict(b,provenance=dict(b['provenance'],annotations_json=updated)))
                    if updated!=row[0]:
                        self.set('dirty','1')
                        self.conn.execute("UPDATE projection.source_provenance SET annotations_json=? WHERE entity_type='message' AND projection_row_id=?",(updated,rid))

    def evaluate_workflows(self, when):
        self.tclk_ordinary_closed = {}
        groups = defaultdict(list)
        for row in self.conn.execute('SELECT id FROM current_inputs WHERE workflow_id IS NOT NULL ORDER BY workflow_id,id'):
            bundle=self.bundle(row[0]); workflow=bundle['facts']['workflow']
            if workflow:
                keys(workflow, {'id','identity','role','root_id','result_id','authenticated','deadline_ms','terminal'})
                require(workflow['id']==identity('sw1',workflow['identity']), 'Workflow identity mismatch')
                require(type(workflow['authenticated']) is bool,'Invalid workflow authority')
                groups[workflow['id']].append((row[0],bundle,workflow))
        for wid, members in groups.items():
            self.check(); state='UNRESOLVED'; closed=None; proof=None; reason=None
            identities={canonical(w['identity']) for _,_,w in members}; require(len(identities)==1,'Conflicting workflow scope')
            ident=members[0][2]['identity']; roots_found=[x for x in members if x[2]['role']=='ROOT' and x[2]['authenticated']]
            # A root must be bound to its immutable issuer; two distinct payload roots conflict.
            valid_roots=[x for x in roots_found if x[1]['message']['sender']==ident['scope']['issuer']]
            if len({text_hash(b['message']['text']) for _,b,_ in valid_roots})>1: state='CONFLICT'
            elif valid_roots:
                state='OPEN'; root_ids={r for r,_,_ in valid_roots}; protocol=ident['protocol']
                if protocol=='kibble/v1':
                    results={r:b for r,b,w in members if w['role']=='RESULT' and w['authenticated'] and w['root_id'] in root_ids}
                    if results: state='RESULT_POSTED'
                    elif any(w['role']=='CLAIM' and w['authenticated'] and w['root_id'] in root_ids for _,_,w in members): state='CLAIMED'
                    terminal_outcomes=set()
                    for rid,b,w in members:
                        if w['role']=='TERMINAL' and w['authenticated'] and w['root_id'] in root_ids and b['message']['sender']==ident['scope']['issuer'] and w['result_id'] in results:
                            terminal_outcomes.add((w['terminal'],w['result_id']))
                            if w['terminal']=='ACCEPT':
                                candidate=max(instant(b['first_observed_at']),instant(results[w['result_id']]['first_observed_at']),*(instant(rb['first_observed_at']) for _,rb,_ in valid_roots))
                                if closed is None or candidate<instant(closed): state='CLOSED';closed=utc(candidate);proof=rid;reason='KIBBLE_POSTER_ACCEPTED_RESULT'
                            elif w['terminal']=='REJECT':
                                state='REJECTED';proof=rid;reason='KIBBLE_POSTER_REJECTED_RESULT'
                                with self.conn:
                                    for member,_,_ in members:self.mark_permanent(member,'NEGATIVE_EVIDENCE')
                    if len(terminal_outcomes)>1:state='CONFLICT';closed=None;proof=None;reason='CONFLICTING_TERMINAL_PROOF'
                elif protocol=='tclk/1':
                    deadlines={w['deadline_ms'] for _,_,w in valid_roots}
                    active=any(w['role']!='ROOT' for _,_,w in members)
                    if not active and len(deadlines)==1:
                        deadline=next(iter(deadlines))
                        if type(deadline) is int and deadline>=0:
                            try:dt=datetime(1970,1,1,tzinfo=timezone.utc)+timedelta(milliseconds=deadline)
                            except (OverflowError,ValueError):dt=None
                            if dt is not None and dt<=instant(when):state='EXPIRED';closed=utc(dt);proof=valid_roots[0][0];reason='TCLK_OFFER_DEADLINE'
            if self.config['contract_revision'] == TL1_REVISION and ident['protocol'] == 'tclk/1' and any((b['message']['room'], b['message']['generation']) in self.tclk_domains for _, b, _ in members):
                self.tclk_ordinary_closed[wid] = closed
                state, closed, proof, reason = 'UNRESOLVED', None, None, 'TCLK_LEGACY_AUDIT'
            with self.conn:
                self.conn.execute('INSERT INTO workflows VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,closed_at=excluded.closed_at,closure_evidence_id=excluded.closure_evidence_id,closure_reason=excluded.closure_reason,proofs_json=excluded.proofs_json',(wid,canonical(ident).decode(),state,closed,proof,reason,canonical(sorted(r for r,_,_ in members)).decode()))
                for rid,_,_ in members:self.conn.execute('INSERT OR IGNORE INTO dependencies VALUES(?,?)',(wid,rid))
                pending=self.conn.execute("SELECT number FROM evaluations WHERE status='APPLYING' ORDER BY number DESC LIMIT 1").fetchone()
                if pending:self.conn.execute('INSERT OR IGNORE INTO evaluation_groups SELECT ?,sender FROM current_inputs WHERE workflow_id=?',(pending[0],wid))

    def status(self):
        pending=self.conn.execute("SELECT count(*) FROM evaluations WHERE status!='COMPLETE'").fetchone()[0]
        ready=self.get('publication_readiness','NOT_READY') if not pending and self.get('dirty','0')=='0' and not self.get('pin_error') and not self.get('publication_error') else 'NOT_READY'
        return dict(tl1=loads(self.get('tl1_status','null')) if self.config['contract_revision'] == TL1_REVISION else None,schema=SCHEMA,contract_revision=self.config['contract_revision'],legacy_generation=self.legacy_status(),readiness=ready,publication_error=self.get('publication_error'),last_publication=self.get('last_publication'),source_cut=loads(self.get('source_cut','null')),
                    selection_evaluated_at=self.get('evaluated_at'),pending_evaluations=pending,
                    pins_initialized=self.conn.execute('SELECT count(*) FROM pin_exports').fetchone()[0]>0,
                    qualifications=int(self.get('qualification_count','0')),
                    qualification_events=int(self.get('qualification_event_count','0')),
                    next_expiry_at=self.conn.execute('SELECT min(due) FROM expiry').fetchone()[0],
                    dirty=self.get('dirty','0')=='1')

    def import_artifact(self, identifier, raw, *, source_id, epoch, authority, observed_at=None):
        """Import explicitly selected local bytes; IDs never resolve to filesystem paths.

        authority is a configured local input purpose, not a field trusted from a
        room message. CLI requires an explicit --authority choice.
        """
        self.check(); string(identifier); string(source_id); string(epoch)
        require(authority in {'AUDIT_DIRECTIVE','CONTROLLED_BENCH','OBJECTIVE_VALIDATION'},'Unsupported local authority purpose')
        require(type(raw) is bytes and len(raw)<=4*1024*1024,'Invalid local artifact bytes')
        artifact=loads(raw)
        require(type(artifact) is dict,'Local authority artifact must be an object')
        allowed={'flop-scout-qualification-directive/v1'} if authority=='AUDIT_DIRECTIVE' else {'flop-verification-request/v1','flop-verification-result/v1'}
        require(artifact.get('schema',artifact.get('schema_version')) in allowed,'Unsupported local authority artifact schema')
        h=hashlib.sha256(raw).hexdigest()
        old=self.conn.execute('SELECT * FROM local_artifacts WHERE id=?',(identifier,)).fetchone()
        require(not old or (old['source_id'],old['epoch'],old['hash'],old['body'],old['authority'])==(source_id,epoch,h,raw,authority),'Immutable local artifact conflict')
        with self.conn:
            self.conn.execute('INSERT OR IGNORE INTO local_artifacts VALUES(?,?,?,?,?,?,?)',(identifier,source_id,epoch,h,raw,authority,observed_at or utc()))
            if not old:self.record_operation('ARTIFACT',dict(id=identifier))
        return dict(kind='LOCAL_ARTIFACT',source_id=source_id,source_epoch=epoch,id=identifier,sha256=h)

    def append_event(self, event):
        self.check()
        old=self.conn.execute('SELECT event_json FROM audit_history WHERE event_id=?',(event.get('event_id'),)).fetchone()
        if old:
            require(old[0]==canonical(event).decode(),'Conflicting immutable event');return event['event_id']
        qualifications={r[0]:loads(r[1]) for r in self.conn.execute('SELECT * FROM projection.durable_qualifications')}
        prior=[loads(r[0]) for r in self.conn.execute('SELECT event_json FROM projection.qualification_events WHERE qualification_id=? ORDER BY sequence',(event.get('qualification_id'),))]
        validate_event(event,prior,qualifications)
        self.resolve_audit_ref(event['authority_ref'])
        require(event['authority_ref']['kind']=='LOCAL_ARTIFACT','This producer only accepts explicitly imported local audit directives')
        artifact=self.conn.execute('SELECT * FROM local_artifacts WHERE id=?',(event['authority_ref']['id'],)).fetchone()
        require(artifact['authority']=='AUDIT_DIRECTIVE','Wrong audit authority purpose')
        require(instant(event['recorded_at'])>=instant(artifact['first_observed_at']),'Audit predates authority availability')
        directive=loads(artifact['body'])
        keys(directive,{'schema','verifier_version','qualification_id','event_type','reason_code','proof_refs','superseded_by'})
        require(directive['schema']=='flop-scout-qualification-directive/v1','Unknown audit directive')
        string(directive['verifier_version'])
        require(all(directive[k]==event[k] for k in ('qualification_id','event_type','reason_code','proof_refs','superseded_by')),'Authority does not bind exact audit event')
        audit_closures=[]
        for ref in event['proof_refs']:
            self.resolve_audit_ref(ref)
            if ref['kind']=='PROJECTED_MESSAGE':audit_closures.append(self.closure([ref['id']]))
        if event['event_type']=='SUPERSEDED':
            graph=defaultdict(set)
            for row in self.conn.execute('SELECT event_json FROM projection.qualification_events'):
                item=loads(row[0])
                if item['event_type']=='SUPERSEDED':graph[item['qualification_id']].add(item['superseded_by'])
            frontier=[event['superseded_by']];seen=set()
            while frontier:
                target=frontier.pop();require(target!=event['qualification_id'],'Supersession cycle')
                if target not in seen:seen.add(target);frontier.extend(graph[target])
        with self.conn:
            encoded=canonical(event).decode()
            self.conn.execute('INSERT INTO audit_history VALUES(?,?)',(event['event_id'],encoded))
            self.record_operation('AUDIT',dict(event_id=event['event_id']))
            self.conn.execute('INSERT INTO projection.qualification_events VALUES(?,?,?,?)',(event['event_id'],event['qualification_id'],event['sequence'],encoded))
            self.set('qualification_event_count',int(self.get('qualification_event_count','0'))+1)
            for members in audit_closures:
                for rid in members:
                    reason='NEGATIVE_EVIDENCE' if event['event_type']=='INVALIDATED' else 'BENCH_VERIFICATION' if qualifications[event['qualification_id']]['qualification_type'] in {'CONTROLLED_BENCH','OBJECTIVE_VALIDATION'} else 'CAPABILITY_SUPPORT'
                    self.mark_permanent(rid,reason)
                    if self.conn.execute('SELECT 1 FROM current_inputs WHERE id=?',(rid,)).fetchone():self._upsert_message(self.bundle(rid),event['recorded_at'])
            self.set('dirty','1')
        return event['event_id']


    def qualify_local_bench(self, request_ref, result_ref, evaluated_at=None, kind='CONTROLLED_BENCH'):
        """A configured local Bench result is an audit, never independent credit."""
        self.check();self.resolve_audit_ref(request_ref);self.resolve_audit_ref(result_ref)
        require(request_ref['kind']==result_ref['kind']=='LOCAL_ARTIFACT','Local audit originals required')
        request_row=self.conn.execute('SELECT * FROM local_artifacts WHERE id=?',(request_ref['id'],)).fetchone()
        result_row=self.conn.execute('SELECT * FROM local_artifacts WHERE id=?',(result_ref['id'],)).fetchone()
        require(kind in {'CONTROLLED_BENCH','OBJECTIVE_VALIDATION'} and request_row['authority']==result_row['authority']==kind,'Unconfigured validation authority')
        request=loads(request_row['body']);result=loads(result_row['body'])
        require(request.get('schema_version')=='flop-verification-request/v1' and result.get('schema_version')=='flop-verification-result/v1','Unsupported Bench artifact schema')
        require(result.get('request_id')==request.get('request_id') and result.get('artifact_hashes',{}).get('request_sha256')==digest(request),'Broken Bench request/result linkage')
        for key in ('request_id','target_agent_did','requester_did','routing_decision_id'):string(request.get(key))
        for key in ('task_hash','routing_decision_hash'):sha(request.get(key))
        require(result.get('bench_did') in self.config['local_dids'] and request['requester_did'] in self.config['local_dids'],'Bench/requester not in configured local family')
        require(result.get('status') in {'PASS','FAIL'},'Unknown Bench outcome')
        require(result.get('independent_reputation') is not True and request.get('independent_reputation') is not True,'Conflicting controlled independence')
        when=utc(instant(evaluated_at or utc()))
        require(instant(when)>=max(instant(request_row['first_observed_at']),instant(result_row['first_observed_at'])),'Qualification predates complete local proof')
        cut=loads(self.get('source_cut','null'));require(cut,'Bootstrap required before local qualification')
        number=self.begin(cut['committed_event_id'],when,'SOURCE_BATCH');self.seal(number)
        event=self.conn.execute('SELECT event_id FROM evaluations WHERE number=?',(number,)).fetchone()[0]
        refs=sorted([request_ref,result_ref],key=canonical)
        with self.conn:
            record=dict(schema='router-durable-qualification/v1',source_ref=result_ref,scout_event_id=None,evidence_id=None,subject_did=request['target_agent_did'],claim=dict(kind='VERIFICATION',id=request['request_id']),qualification_type=kind,qualification_outcome=result['status'],qualified_at=when,policy_version=self.policy['version'],policy_sha256=self.policy_sha,classifier_version=self.policy['classifier_version'],qualification_policy_version=self.policy['qualification_policy_version'],bootstrap_id=self.get('bootstrap_id'),evaluation_id=event,source_cut=cut,rule_id='scout-controlled-bench-linkage/v1' if kind=='CONTROLLED_BENCH' else 'scout-objective-validation-linkage/v1',rule_input_sha256=self.save_manifest(dict(request_ref=request_ref,result_ref=result_ref,request_sha256=digest(request),outcome=result['status'],rule_id='scout-controlled-bench-linkage/v1')),rule_group_sha256=self.save_manifest(refs),provenance_refs=refs,operator_group=FAMILY,same_operator=True,independent_reputation=False,authenticity='UNSIGNED_LOCAL',correctness=result['status'],reproducibility=result.get('reproducibility'),initial_status='VALID')
            record['qualification_id']=identity('dq1',record);validate_qualification(record, policy_versions(self.config['contract_revision']));key=first_key(record)
            old=self.conn.execute('SELECT qualification_id FROM qualification_keys WHERE first_key=?',(key,)).fetchone()
            if old:return old[0]
            encoded=canonical(record).decode()
            self.conn.execute('INSERT INTO qualification_keys VALUES(?,?,?)',(key,record['qualification_id'],encoded))
            self.conn.execute('INSERT INTO projection.durable_qualifications VALUES(?,?)',(record['qualification_id'],encoded));self.set('dirty','1');self.set('qualification_count',int(self.get('qualification_count','0'))+1)
            self.record_operation('LOCAL_QUALIFICATION',dict(qualification_id=record['qualification_id']))
            self.local_workflow(request_row,result_row,refs)
        return record['qualification_id']


    def local_workflow(self,request_row,result_row,refs):
        # Called in the qualification transaction and deterministic replay.
        request=loads(request_row['body']);result=loads(result_row['body'])
        wid,ident=workflow_identity('flop-verification-request/v1',request['requester_did'],None,None,'request_id',request['request_id'],namespace='scout-verification')
        state='CLOSED' if result['status']=='PASS' else 'REJECTED'
        closed=utc(max(instant(request_row['first_observed_at']),instant(result_row['first_observed_at'])))
        proof=result_row['id'];reason='BENCH_LINKED_RESULT' if state=='CLOSED' else 'BENCH_OBJECTIVE_FAIL'
        old=self.conn.execute('SELECT * FROM workflows WHERE id=?',(wid,)).fetchone()
        if old:
            refs=sorted({canonical(ref):ref for ref in refs+loads(old['proofs_json'])}.values(),key=canonical)
            if old['state']!=state:
                state='CONFLICT';closed=None;proof=None;reason='CONFLICTING_TERMINAL_PROOF'
            elif old['closed_at'] and instant(old['closed_at'])<instant(closed):
                closed=old['closed_at'];proof=old['closure_evidence_id']
        self.conn.execute('INSERT INTO workflows VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET state=excluded.state,closed_at=excluded.closed_at,closure_evidence_id=excluded.closure_evidence_id,closure_reason=excluded.closure_reason,proofs_json=excluded.proofs_json',(wid,canonical(ident).decode(),state,closed,proof,reason,canonical(refs).decode()))


    def qualify_objective_contradiction(self,request_ref,result_ref,evaluated_at=None):
        """Versioned proof rule: linked deterministic objective FAIL with failed checks.

        This qualifies the scoped failed capability test. It never invalidates a
        prior positive witness or labels an arbitrary room allegation as fact.
        """
        self.resolve_audit_ref(request_ref);self.resolve_audit_ref(result_ref)
        request=loads(self.conn.execute('SELECT body FROM local_artifacts WHERE id=?',(request_ref['id'],)).fetchone()[0])
        result=loads(self.conn.execute('SELECT body FROM local_artifacts WHERE id=?',(result_ref['id'],)).fetchone()[0])
        capability=request.get('capability_id');require(capability in {r.capability_id for r in rules.CAPABILITY_RULES},'Missing exact tested capability')
        checks=result.get('checks');require(result.get('status')=='FAIL' and result.get('reproducibility')=='DETERMINISTIC' and type(checks) is dict and bool(checks) and all(type(v) is bool for v in checks.values()) and not all(checks.values()),'No reproducible failed objective proof')
        parent=self.qualify_local_bench(request_ref,result_ref,evaluated_at,kind='OBJECTIVE_VALIDATION')
        base=loads(self.conn.execute('SELECT record_json FROM projection.durable_qualifications WHERE qualification_id=?',(parent,)).fetchone()[0])
        base.pop('qualification_id');base.update(claim=dict(kind='CAPABILITY',id=capability),qualification_type='CAPABILITY_CONTRADICTION',qualification_outcome='CONTRADICTED',rule_id='scout-objective-capability-contradiction/v1')
        with self.conn:
            base['rule_input_sha256']=self.save_manifest(dict(rule_id=base['rule_id'],request_ref=request_ref,result_ref=result_ref,request_sha256=digest(request),checks=checks,reproducibility='DETERMINISTIC',qualification_outcome='CONTRADICTED'))
            base['qualification_id']=identity('dq1',base);validate_qualification(base, policy_versions(self.config['contract_revision']));key=first_key(base)
            old=self.conn.execute('SELECT qualification_id FROM qualification_keys WHERE first_key=?',(key,)).fetchone()
            if old:return old[0]
            encoded=canonical(base).decode();self.conn.execute('INSERT INTO qualification_keys VALUES(?,?,?)',(key,base['qualification_id'],encoded));self.conn.execute('INSERT INTO projection.durable_qualifications VALUES(?,?)',(base['qualification_id'],encoded))
            self.record_operation('LOCAL_QUALIFICATION',dict(qualification_id=base['qualification_id']));self.set('dirty','1');self.set('qualification_count',int(self.get('qualification_count','0'))+1)
        return base['qualification_id']

    def add_interaction(self, source_id, target_id, relationship_type, confidence):
        self.check();require(type(confidence) in (int,float) and math.isfinite(confidence),'Invalid interaction confidence')
        source=self.bundle(source_id);target=self.bundle(target_id)
        endpoints=[]
        for bundle in (source,target):
            m=bundle['message'];endpoints.append(dict(raw_record_id=bundle['provenance']['raw_record_id'],room=m['room'],generation=m['generation'],seq=m['seq'],sender_did=m['sender']))
        require(endpoints[0]['room']==endpoints[1]['room'] and endpoints[0]['generation']==endpoints[1]['generation'],'Interaction source generation mismatch')
        rid,obj=interaction_identity(relationship_type,*endpoints)
        first=max(source['first_observed_at'],target['first_observed_at'],key=instant)
        ann=annotation_template(self.config['contract_revision']);ann['evidence_links']=sorted([dict(room=m['room'],generation=m['generation'],seq=m['seq'],evidence_id=m['evidence_id']) for m in (source['message'],target['message'])],key=canonical)
        ann['evidence_links']=[loads(v) for v in sorted(set(canonical(v) for v in ann['evidence_links']))]
        with self.conn:
            prior=self.conn.execute('SELECT * FROM projection.interactions WHERE projection_row_id=?',(rid,)).fetchone()
            values=(rid,source['message']['sender'],target['message']['sender'],relationship_type,float(confidence))
            if prior:
                require(tuple(prior)[:4]==values[:4],'Conflicting stable interaction identity')
                if tuple(prior)!=values:
                    self.conn.execute('UPDATE projection.interactions SET confidence=? WHERE projection_row_id=?',(float(confidence),rid));self.set('dirty','1')
                    self.record_operation('INTERACTION',dict(source_id=source_id,target_id=target_id,relationship_type=relationship_type,confidence=confidence))
                return rid
            self.conn.execute('INSERT INTO projection.interactions VALUES(?,?,?,?,?)',values)
            self.conn.execute('INSERT INTO projection.source_provenance VALUES(?,?,?,?,?,?,?,?)',('interaction',rid,'scout-interaction-inference',rid,None,None,None,canonical(annotations(ann,self.config['contract_revision'])).decode()))
            due=plus(first,2592000)
            self.conn.execute('INSERT INTO projection.selection_membership VALUES(?,?,?,?,?,?)',('interaction',rid,'CONTEXT',first,due,'[]'))
            self.conn.execute('INSERT INTO expiry VALUES(?,?,?)',(rid,'interaction',due))
            for dep in (source_id,target_id):self.conn.execute('INSERT OR IGNORE INTO dependencies VALUES(?,?)',(rid,dep))
            self.set('interaction:'+rid,canonical(obj).decode());self.set('dirty','1')
            self.record_operation('INTERACTION',dict(source_id=source_id,target_id=target_id,relationship_type=relationship_type,confidence=confidence))
        return rid


    def legacy_status(self):
        if self.config['contract_revision'] in (LG2_REVISION, TL1_REVISION):
            from scout_projection_compact import statistics
            return dict(statistics(self.conn,'projection.'),policy=LEGACY_POLICY,authority='LEGACY_REPORTED_ONLY',
                true_generation_conflicts_rejected=int(self.get('lg1_conflicts','0')),unsupported_legacy_records=int(self.get('lg1_unsupported','0')),last_error=self.get('lg2_error',self.get('lg1_error')))
        counts={'0':0,'1':0}
        for row in self.conn.execute("SELECT json_extract(annotations_json,'$.legacy_generation.reported_generation'),count(*) FROM projection.source_provenance WHERE json_extract(annotations_json,'$.legacy_generation') IS NOT NULL GROUP BY 1"):
            counts[row[0]]=row[1]
        return dict(policy=self.config.get('legacy_generation_policy'),authority='LEGACY_REPORTED_ONLY',rejection_count_scope='persisted bootstrap/consume rejection attempts',non_authoritative_report_counts=counts,
                    rows=sum(counts.values()),true_generation_conflicts_rejected=int(self.get('lg1_conflicts','0')),
                    unsupported_legacy_records=int(self.get('lg1_unsupported','0')),last_error=self.get('lg1_error'))

    def legacy_error(self,exc):
        from scout_projection_legacy import LegacyGenerationError
        if self.config['contract_revision'] == TL1_REVISION:
            with self.conn:
                code = str(exc) if str(exc).startswith('TL1_') else 'TL1_PROJECTION_REJECTED'
                self.set('tl1_error', code)
                prior = loads(self.get('tl1_status', '{}'))
                prior.update(last_tl1_error=code, overflow='CAPACITY' in code, counts_scope='LAST_VALID_EVALUATION', current_evaluation_valid=False)
                self.set('tl1_status', canonical(prior).decode())
                self.set('publication_readiness', 'NOT_READY')
        if self.config['contract_revision'] in (LG2_REVISION, TL1_REVISION):
            with self.conn:self.set('lg2_error',exc.code if isinstance(exc,LegacyGenerationError) else 'LG2_PROJECTION_REJECTED')
        if isinstance(exc,LegacyGenerationError):
            with self.conn:
                key='lg1_conflicts' if exc.code=='LG1_GENERATION_CONFLICT' else 'lg1_unsupported'
                self.set(key,int(self.get(key,'0'))+1);self.set('lg1_error',exc.code)

    def enable_lg1(self):
        """Explicit A1 transition: audit shape only; old qualifications remain bytes."""
        require(self.config['contract_revision']=='A1','Only explicit A1 to LG1 transition is supported')
        require(not self.conn.execute("SELECT 1 FROM evaluations WHERE status!='COMPLETE'").fetchone() and not self.get('pending_pin_sha256'),'Finish pending work before LG1 migration')
        self.verify_ledger()
        # Preserve a separately inspectable A1 pair before changing derived state.
        # Unique, exclusive directory creation never replaces a prior archive.
        import uuid
        from scout_projection_publish import file_hash,fsync_directory
        archive=self.path.parent/(self.path.name+'.a1-archive-'+uuid.uuid4().hex)
        archive.mkdir(mode=0o700)
        archived={}
        for name,database in ((self.path.name,'projection'),(self.ledger.name,'main')):
            target=archive/name
            with sqlite3.connect(str(target)) as destination:
                self.conn.backup(destination,pages=200,name=database,progress=lambda *args:self.check())
            with open(target,'rb') as stream:os.fsync(stream.fileno())
            archived[name]=file_hash(target)
            target.chmod(0o400)
        marker=archive/'archive.json'
        marker.write_bytes(canonical(dict(schema='scout-a1-private-archive/v1',contract_revision='A1',files=archived))+b'\n')
        with open(marker,'rb') as stream:os.fsync(stream.fileno())
        marker.chmod(0o400);fsync_directory(archive);fsync_directory(archive.parent)
        config=dict(self.config,initial_contract_revision='A1',contract_revision=REVISION,legacy_generation_policy=LEGACY_POLICY)
        with self.conn:
            for row in self.conn.execute('SELECT c.id,v.body FROM current_inputs c JOIN input_versions v ON v.hash=c.hash'):
                b=loads(row['body'],max(4*1024*1024,len(row['body'].encode())))
                ann=annotations(loads(b['provenance']['annotations_json']),'A1');ann['legacy_generation']=None
                b['provenance']['annotations_json']=canonical(ann).decode();h=digest(b)
                self.conn.execute('INSERT OR IGNORE INTO input_versions VALUES(?,?,?)',(h,row['id'],canonical(b).decode()))
                self.conn.execute('UPDATE current_inputs SET hash=? WHERE id=?',(h,row['id']))
            for row in self.conn.execute('SELECT entity_type,projection_row_id,annotations_json FROM projection.source_provenance'):
                ann=annotations(loads(row['annotations_json']),'A1');ann['legacy_generation']=None
                self.conn.execute('UPDATE projection.source_provenance SET annotations_json=? WHERE entity_type=? AND projection_row_id=?',(canonical(ann).decode(),row['entity_type'],row['projection_row_id']))
            self.conn.execute('UPDATE configuration SET json=?',(canonical(config).decode(),))
            self.record_operation('LG1_MIGRATION',dict(contract_revision=REVISION,legacy_generation_policy=LEGACY_POLICY))
            self.set('dirty','1');self.set('lg1_transition','1')
        self.config=config
        return dict(self.status(),a1_private_archive=str(archive))

    def enable_lg2(self):
        """Archived, replayable representation migration; immutable history stays LG1."""
        require(self.config['contract_revision']==REVISION,'Only explicit LG1 to LG2 migration is supported; downgrade forbidden')
        require(not self.conn.execute("SELECT 1 FROM evaluations WHERE status!='COMPLETE'").fetchone() and not self.get('pending_pin_sha256'),'Finish pending work before LG2 migration')
        self.check();self.verify_ledger()
        import uuid
        from scout_projection_publish import file_hash,fsync_directory
        archive=self.path.parent/(self.path.name+'.lg1-archive-'+uuid.uuid4().hex)
        archive.mkdir(mode=0o700)
        archived={}
        for name,database in ((self.path.name,'projection'),(self.ledger.name,'main')):
            target=archive/name
            with sqlite3.connect(str(target)) as destination:
                self.conn.backup(destination,pages=200,name=database,progress=lambda *args:self.check())
            with open(target,'rb') as stream:os.fsync(stream.fileno())
            archived[name]=file_hash(target)
            target.chmod(0o400)
        marker=archive/'archive.json'
        marker.write_bytes(canonical(dict(schema='scout-lg1-private-archive/v1',contract_revision=REVISION,files=archived))+b'\n')
        with open(marker,'rb') as stream:os.fsync(stream.fileno())
        marker.chmod(0o400);fsync_directory(archive);fsync_directory(archive.parent)
        from scout_projection_compact import convert_bundle, sync, logical_audit, read_audit
        config=dict(self.config,initial_contract_revision=self.config.get('initial_contract_revision',REVISION),**revision_metadata(LG2_REVISION))
        # Explicit BEGIN keeps attached DDL, input pointers, and configuration atomic.
        self.conn.execute('BEGIN IMMEDIATE')
        try:
            ddl=Path(__file__).with_name('docs').joinpath('router-legacy-generation-lg2-schema.sql').read_text()
            for statement in ddl.split(';'):
                if statement.strip():self.conn.execute(statement.replace('CREATE TABLE ','CREATE TABLE projection.',1))
            for row in self.conn.execute('SELECT c.id,v.body FROM current_inputs c JOIN input_versions v ON v.hash=c.hash'):
                self.check()
                old=loads(row['body'],max(4*1024*1024,len(row['body'].encode())))
                self.validate_bundle(old)
                b=convert_bundle(old);h=digest(b)
                require(logical_audit(old)==logical_audit(b),'LG2 migration changed logical audit')
                self.conn.execute('INSERT OR IGNORE INTO input_versions VALUES(?,?,?)',(h,row['id'],canonical(b).decode()))
                self.conn.execute('UPDATE current_inputs SET hash=? WHERE id=?',(h,row['id']))
            for row in self.conn.execute('SELECT * FROM projection.source_provenance'):
                ann=annotations(loads(row['annotations_json']),REVISION)
                audit=ann.pop('legacy_generation')
                self.conn.execute('UPDATE projection.source_provenance SET annotations_json=? WHERE entity_type=? AND projection_row_id=?',(canonical(ann).decode(),row['entity_type'],row['projection_row_id']))
                if row['entity_type']=='message':
                    b=self.bundle(row['projection_row_id'])
                    require(logical_audit(b)==audit,'LG2 migration lacks exact original input')
                    sync(self.conn,b)
                    projected=dict(row,annotations_json=canonical(ann).decode())
                    require(read_audit(self.conn,projected,'projection.')==audit,'LG2 migration did not preserve public audit')
                else:require(audit is None,'Legacy report on non-message')
            self.conn.execute('UPDATE configuration SET json=?',(canonical(config).decode(),))
            self.record_operation('LG2_MIGRATION',revision_metadata(LG2_REVISION))
            self.set('dirty','1');self.set('lg2_transition','1')
            self.conn.commit()
        except BaseException:
            self.conn.rollback();raise
        self.config=config
        self.verify_ledger()
        return dict(self.status(),lg1_private_archive=str(archive))

    def activate_tl1(self, cohort, raw_ids):
        """Explicit one-way local activation; a full source evaluation must follow."""
        from scout_projection_tclk import validate_cohort
        self.check()
        require(self.config['contract_revision'] == LG2_REVISION, 'TL1 requires explicit LG2 migration; no reset or downgrade')
        require(not self.conn.execute("SELECT 1 FROM evaluations WHERE status!='COMPLETE'").fetchone(), 'Finish pending evaluation before TL1 migration')
        validate_cohort(cohort, source_id=self.config['source_id'], epoch=self.config['epoch'], cut=cohort['through_event_id'], raw_ids=raw_ids)
        self.verify_ledger()
        policy = policy_for(TL1_REVISION)
        config = dict(self.config, initial_contract_revision=self.config.get('initial_contract_revision', LG2_REVISION),
                      **revision_metadata(TL1_REVISION, cohort))
        config.update(policy=policy, policy_sha256=digest(policy), legacy_tclk_raw_ids=sorted(raw_ids))
        ddl = Path(__file__).with_name('docs').joinpath('router-tclk-legacy-tl1-schema.sql').read_text()
        ddl = '\n'.join(line for line in ddl.splitlines() if not line.lstrip().startswith('--'))
        with self.conn:
            self.conn.execute(ddl.replace('CREATE TABLE ', 'CREATE TABLE projection.', 1))
            self.conn.execute('UPDATE configuration SET json=?', (canonical(config).decode(),))
            self.conn.execute('UPDATE projection.snapshot_meta SET selection_policy_sha256=?', (digest(policy),))
            self.record_operation('TL1_MIGRATION', dict(revision_metadata(TL1_REVISION, cohort), legacy_tclk_raw_ids=sorted(raw_ids)))
            self.set('tl1_transition', '1'); self.set('tl1_activation_pending', '1'); self.set('dirty', '1')
        self.config, self.policy, self.policy_sha = config, policy, digest(policy)

    def replay_to(self,destination):
        """Deterministically reconstruct a NEW development pair from retained inputs.

        Never resets or repairs missing history in place. Version or byte divergence
        fails closed and leaves the reconstruction available for diagnosis.
        """
        self.check();self.verify_ledger()
        require(not self.get('pending_pin_sha256'),'Resume interrupted pin import before reconstruction')
        require(not self.conn.execute("SELECT 1 FROM evaluations WHERE status!='COMPLETE'").fetchone(),'Finish pending source cut before full reconstruction')
        config=self.config
        initial_revision = config.get('initial_contract_revision', config['contract_revision'])
        initialize(destination,epoch=config['epoch'],router_source_id=config['router_source_id'],router_epoch=config['router_epoch'],router_did=config['router_did'],local_dids=config['local_dids'],source_id=config['source_id'],contract_revision=initial_revision,
                   legacy_tclk_cohort=config.get('legacy_tclk_cohort') if initial_revision == TL1_REVISION else None,
                   legacy_tclk_raw_ids=config.get('legacy_tclk_raw_ids') if initial_revision == TL1_REVISION else None)
        from scout_projection_pins import import_pins
        with Projector(destination,self.stop) as target:
            for operation in self.conn.execute('SELECT body FROM operations ORDER BY number'):
                self.check();op=loads(operation[0]);payload=op['payload'];kind=op['kind']
                if kind=='EVALUATION':
                    original=self.conn.execute('SELECT * FROM evaluations WHERE number=?',(payload['number'],)).fetchone();body=loads(original['body'])
                    n=target.begin(body['source_cut']['committed_event_id'],body['evaluated_at'],body['kind']);rows=[]
                    for row in self.conn.execute('SELECT v.body FROM evaluation_inputs i JOIN input_versions v ON v.hash=i.hash WHERE i.number=? ORDER BY i.id',(payload['number'],)):
                        rows.append(loads(row[0],max(4*1024*1024,len(row[0].encode()))))
                        if len(rows)==200:target.stage(n,rows);rows=[]
                    if rows:target.stage(n,rows)
                    edges=[]
                    for row in self.conn.execute('SELECT body FROM evaluation_edges WHERE number=? ORDER BY key',(payload['number'],)):
                        edges.append(loads(row[0]))
                        if len(edges)==200:target.stage_edges(n,edges);edges=[]
                    if edges:target.stage_edges(n,edges)
                    target.seal(n)
                    require(target.conn.execute('SELECT event_id FROM evaluations WHERE number=?',(n,)).fetchone()[0]==original['event_id'],'Evaluation replay divergence')
                elif kind=='LG1_MIGRATION':target.enable_lg1()
                elif kind=='LG2_MIGRATION':target.enable_lg2()
                elif kind=='TL1_MIGRATION':target.activate_tl1(payload['legacy_tclk_cohort'], payload['legacy_tclk_raw_ids'])
                elif kind=='TL1_ENUMERATION':
                    with target.conn:
                        target.set('tl1_activation_pending', '0'); target.record_operation(kind, payload)
                elif kind=='TL1_INITIAL_ENROLLMENT':
                    require(target.conn.execute('SELECT body FROM operations WHERE number=1').fetchone()[0] == operation[0], 'TL1 replay enrollment changed')
                elif kind=='ARTIFACT':
                    row=self.conn.execute('SELECT * FROM local_artifacts WHERE id=?',(payload['id'],)).fetchone()
                    target.import_artifact(row['id'],row['body'],source_id=row['source_id'],epoch=row['epoch'],authority=row['authority'],observed_at=row['first_observed_at'])
                elif kind=='PIN':
                    row=self.conn.execute('SELECT body FROM pin_exports WHERE revision=?',(payload['revision'],)).fetchone();doc=loads(row[0]);import_pins(target,row[0],now=doc['produced_at'],evaluate=False)
                elif kind=='LOCAL_QUALIFICATION':
                    row=self.conn.execute('SELECT * FROM qualification_keys WHERE qualification_id=?',(payload['qualification_id'],)).fetchone();record=validate_qualification(loads(row['record_json']), policy_versions(self.config['contract_revision']))
                    for ref in record['provenance_refs']:target.resolve_audit_ref(ref)
                    with target.conn:
                        for h in (record['rule_input_sha256'],record['rule_group_sha256']):
                            manifest=self.conn.execute('SELECT body FROM rule_manifests WHERE hash=?',(h,)).fetchone();require(manifest,'Missing historical local rule input');target.save_manifest(loads(manifest[0]))
                        if record['qualification_type'] in {'CONTROLLED_BENCH','OBJECTIVE_VALIDATION'}:
                            originals=[target.conn.execute('SELECT * FROM local_artifacts WHERE id=?',(ref['id'],)).fetchone() for ref in record['provenance_refs']]
                            request_row=next(r for r in originals if loads(r['body']).get('schema_version')=='flop-verification-request/v1')
                            result_row=next(r for r in originals if r['id']==record['source_ref']['id'])
                            target.local_workflow(request_row,result_row,record['provenance_refs'])
                        target.conn.execute('INSERT INTO qualification_keys VALUES(?,?,?)',tuple(row));target.conn.execute('INSERT INTO projection.durable_qualifications VALUES(?,?)',(record['qualification_id'],row['record_json']));target.record_operation(kind,payload);target.set('dirty','1')
                elif kind=='AUDIT':
                    row=self.conn.execute('SELECT event_json FROM audit_history WHERE event_id=?',(payload['event_id'],)).fetchone();target.append_event(loads(row[0]))
                elif kind=='INTERACTION':target.add_interaction(**payload)
                else:raise ProjectionError('Unsupported replay operation')
            # Compare all named published facts; content/publication identities are
            # allocator state, not a new historical qualification evaluation.
            for table in tables_for(config['contract_revision']):
                columns=[r[1] for r in self.conn.execute('PRAGMA projection.table_info('+table+')')]
                order=','.join(columns)
                left=self.conn.execute('SELECT * FROM projection.'+table+' ORDER BY '+order)
                right=target.conn.execute('SELECT * FROM projection.'+table+' ORDER BY '+order)
                while True:
                    a=[tuple(r) for r in left.fetchmany(200)];b=[tuple(r) for r in right.fetchmany(200)]
                    require(a==b,'Reconstruction differs in '+table)
                    if not a:break
            with target.conn:
                target.conn.execute('DELETE FROM projection.snapshot_meta')
                meta=self.conn.execute('SELECT * FROM projection.snapshot_meta').fetchone();target.conn.execute('INSERT INTO projection.snapshot_meta VALUES(?,?,?,?,?)',tuple(meta))
                for row in self.conn.execute('SELECT key,value FROM state'):target.set(row['key'],row['value'])
                for row in self.conn.execute('SELECT * FROM publication_log'):target.conn.execute('INSERT INTO publication_log VALUES(?,?,?,?)',tuple(row))
            target.verify_ledger()
        return dict(destination=str(destination),replayed=True,history_verified=True)


def read_status(path):
    """Read-only status: does not create a lock, journal, schema, or database."""
    path=Path(path);ledger=path.with_suffix(path.suffix+'.ledger')
    with connect(ledger,True) as conn:
        allowed=('initialized','source_cut','evaluated_at','bootstrap_id','outbox_position','dirty','pin_error','publication_id','content_id','last_publication','publication_error','publication_failures','publication_retry_seconds','publication_readiness','publication_size_bytes','published_database_sha256','lg1_error','lg1_conflicts','lg1_unsupported','lg2_error','tl1_status','tl1_error','tl1_activation_pending')
        values={r[0]:r[1] for r in conn.execute('SELECT key,value FROM state WHERE key IN ('+','.join('?' for _ in allowed)+')',allowed)}
        if 'source_cut' in values:values['source_cut']=loads(values['source_cut'])
        config=loads(conn.execute('SELECT json FROM configuration').fetchone()[0]);revision_binding(config)
        values['contract_revision']=config['contract_revision'];values['legacy_generation_policy']=config.get('legacy_generation_policy')
        with connect(path,True) as projection:
            if config['contract_revision'] not in (LG2_REVISION,TL1_REVISION):
                values['non_authoritative_report_counts']=dict({'0':0,'1':0},**{str(r[0]):r[1] for r in projection.execute("SELECT json_extract(annotations_json,'$.legacy_generation.reported_generation'),count(*) FROM source_provenance WHERE json_extract(annotations_json,'$.legacy_generation') IS NOT NULL GROUP BY 1")})
            if config['contract_revision'] in (LG2_REVISION,TL1_REVISION):
                from scout_projection_compact import statistics
                values.update(statistics(projection))
                values.update(true_generation_conflicts_rejected=int(values.get('lg1_conflicts',0)),unsupported_legacy_records=int(values.get('lg1_unsupported',0)),last_error=values.get('lg2_error',values.get('lg1_error')))
        if config['contract_revision'] == TL1_REVISION:
            from scout_projection_tclk import metadata
            values.update(metadata(config['legacy_tclk_cohort']))
            values['contract_revision'] = TL1_REVISION
            values['tl1_status'] = loads(values.get('tl1_status','null'))
        values['legacy_reported_only_rows']=sum(values['non_authoritative_report_counts'].values())
        values['lg1_rejection_count_scope']='persisted bootstrap/consume rejection attempts'
        values['pending_evaluations']=conn.execute("SELECT count(*) FROM evaluations WHERE status!='COMPLETE'").fetchone()[0]
        values['expiry_rows']=conn.execute('SELECT count(*) FROM expiry').fetchone()[0]
        values['pin_count']=conn.execute('SELECT count(*) FROM pins').fetchone()[0]
        values['last_pin_revision']=conn.execute('SELECT max(revision) FROM pin_exports').fetchone()[0]
        values['next_expiry_at']=conn.execute('SELECT min(due) FROM expiry').fetchone()[0]
        values['size_bytes']=path.stat().st_size
        values['readiness']=values.get('publication_readiness','NOT_READY') if not values['pending_evaluations'] and values.get('dirty','0')=='0' and not values.get('pin_error') else 'NOT_READY'
        values['expiry_backlog']=conn.execute('SELECT count(*) FROM expiry WHERE due<=?',(utc(),)).fetchone()[0]
        return values
