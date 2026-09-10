"""Strict, local-only Scout Router V2/A1 wire contract primitives."""
from __future__ import annotations
import hashlib
import json
import math
import re
import sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path

POLICY = {
    'schema': 'flop-router-projection-selection/v1',
    'version': 'router-evidence-horizons/2',
    'classifier_version': 'router-evidence-classes/2',
    'qualification_policy_version': 'router-durable-qualification/v1',
    'parameters': {'context_seconds': 2592000, 'capability_signal_seconds': 7776000,
                   'closed_work_seconds': 7776000, 'closed_tclk_seconds': 7776000},
    'cutoff_semantics': 'trusted-first-observed-strict-before-expiry/v1',
    'pinned_record_rules': 'transitive-local-evidence-dependencies-no-implicit-unpin/v1',
}
SCHEMA = 'scout-router-projection/v2'
FAMILY = 'local-flop-agent-family'
TABLES = ('messages', 'interactions', 'source_provenance', 'selection_membership',
          'watermarks', 'coverage_history', 'durable_qualifications', 'qualification_events')
CLASSES = {'IDENTITY_OPERATOR', 'BENCH_VERIFICATION', 'CAPABILITY_SUPPORT',
           'CAPABILITY_CONTRADICTION', 'NEGATIVE_EVIDENCE', 'CONTEXT',
           'CAPABILITY_SIGNAL', 'WORK_LIFECYCLE', 'TCLK_LIFECYCLE', 'PINNED'}
REF_KEYS = {'kind', 'source_id', 'source_epoch', 'id', 'sha256'}
A1_ANNOTATIONS = {'classification': None, 'same_operator': None, 'independent_reputation': None,
               'operator_group': None, 'capability_support': [], 'verification_links': [],
               'task_routing_links': [], 'evidence_links': []}
REVISION = 'A1-LG1'  # Frozen compatibility API default; LG2 is explicit.
LG2_REVISION = 'A1-LG2'
TL1_REVISION = 'A1-LG2-TL1'
LG2_ENCODING = 'router-legacy-generation-storage/v2'
REVISIONS = ('A1', REVISION, LG2_REVISION, TL1_REVISION)
LG2_TABLES = ('legacy_generation_reports', 'legacy_generation_witnesses')
LEGACY_POLICY = {'schema':'router-legacy-generation-authority/v1',
                 'migration_class':'scout-legacy-evidence-v1-service-poll',
                 'allowed_reported_generations':['0','1'], 'authority':'LEGACY_REPORTED_ONLY',
                 'match_status':'UNRESOLVED_LEGACY', 'watermark_domain':'CAPTURED'}
LEGACY_FIXED = dict(generation_authority='LEGACY_REPORTED_ONLY',
    generation_match_status='UNRESOLVED_LEGACY', migration_class=LEGACY_POLICY['migration_class'],
    raw_source='legacy_evidence', ingestion_schema='flop-scout-evidence/v1', ingestion_version='1',
    legacy_record=True, raw_completeness='PARTIAL', cache_source='service-poll',
    transport_lineage='UNAVAILABLE_IN_LEGACY_CAPTURE')
ANNOTATIONS = dict(A1_ANNOTATIONS, legacy_generation=None)
SQL = Path(__file__).with_name('docs').joinpath('router-projection-v2-schema.sql').read_text()


class ProjectionError(ValueError):
    """Fail-closed producer error; never authorizes discarding evidence."""


def require(ok, message):
    if not ok:
        raise ProjectionError(message)


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False,
                          allow_nan=False).encode('utf-8')
    except (ValueError, TypeError, UnicodeError) as exc:
        raise ProjectionError('Non-canonical JSON value') from exc


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def text_hash(value):
    require(type(value) is str, 'Text must be a string')
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def loads(raw, limit=4*1024*1024):
    require(not (isinstance(raw,bytes) and raw.startswith(b'\xef\xbb\xbf') or isinstance(raw,str) and raw.startswith('\ufeff')), 'JSON BOM rejected')
    require(len(raw.encode('utf-8') if isinstance(raw, str) else raw) <= limit, 'JSON exceeds limit')
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'Duplicate JSON key: ' + key)
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda v: require(False, 'Nonfinite JSON'))
        canonical(value)
        return value
    except (ValueError, UnicodeError) as exc:
        raise ProjectionError('Invalid strict JSON: ' + str(exc)) from exc


def keys(value, expected):
    require(type(value) is dict and set(value) == set(expected), 'Unexpected object fields')


def string(value, nullable=False):
    if nullable and value is None:
        return value
    require(type(value) is str and bool(value.strip()) and len(value) <= 256, 'Invalid bounded string')
    canonical(value)
    return value


def sha(value, nullable=False):
    require(nullable and value is None or type(value) is str and re.fullmatch('[0-9a-f]{64}', value), 'Invalid SHA-256')
    return value


def decimal(value):
    require(type(value) is str and re.fullmatch('0|[1-9][0-9]{0,19}', value), 'Invalid decimal ID')
    return value


def instant(value):
    require(type(value) is str and re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?Z', value), 'Invalid UTC timestamp')
    try:
        return datetime.fromisoformat(value[:-1] + '+00:00')
    except ValueError as exc:
        raise ProjectionError('Invalid UTC date') from exc


def utc(value=None):
    return (value or datetime.now(timezone.utc)).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def plus(value, seconds):
    return utc(instant(value) + timedelta(seconds=seconds))


def reference(value, kinds=None, nullable_hash=False):
    keys(value, REF_KEYS)
    for key in REF_KEYS - {'sha256'}:
        string(value[key])
    if kinds is not None:
        require(value['kind'] in kinds, 'Unsupported reference kind')
    sha(value['sha256'], nullable_hash)
    return value


def ordered_refs(values, nonempty=False):
    require(type(values) is list and len(values) <= 256 and (values or not nonempty), 'Invalid reference list')
    for value in values:
        reference(value)
    require([canonical(v) for v in values] == sorted(set(canonical(v) for v in values)), 'References must be sorted and unique')


def revision_binding(value):
    revision = value.get('contract_revision')
    require(revision in REVISIONS, 'Unsupported projection contract revision')
    if revision in (REVISION, LG2_REVISION, TL1_REVISION):
        require(canonical(value.get('legacy_generation_policy')) == canonical(LEGACY_POLICY), 'Unsupported legacy generation policy')
    else:
        require('legacy_generation_policy' not in value, 'LG1 policy under A1')
    if revision in (LG2_REVISION, TL1_REVISION):
        require(value.get('legacy_generation_encoding') == LG2_ENCODING, 'Unsupported legacy generation encoding')
    else:
        require('legacy_generation_encoding' not in value, 'Mixed legacy generation encoding')
    from scout_projection_tclk import PIN, validate_binding
    tl1_fields = set(PIN) | {'tclk_legacy_policy', 'tclk_legacy_policy_sha256', 'legacy_tclk_cohort'}
    if revision == TL1_REVISION:
        validate_binding(value)
        require('legacy_tclk_cohort' in value, 'TL1 explicit cohort required')
    else:
        require(not tl1_fields.intersection(value), 'Mixed TL1 metadata')
    return revision


def revision_metadata(revision, cohort=None):
    require(revision in REVISIONS, 'Unsupported projection revision')
    result = dict(contract_revision=revision)
    if revision != 'A1': result['legacy_generation_policy'] = LEGACY_POLICY
    if revision in (LG2_REVISION, TL1_REVISION): result['legacy_generation_encoding'] = LG2_ENCODING
    if revision == TL1_REVISION:
        from scout_projection_tclk import metadata
        result.update(metadata(cohort))
    return result


def tables_for(revision):
    require(revision in REVISIONS, 'Unsupported projection revision')
    return TABLES + (LG2_TABLES if revision in (LG2_REVISION, TL1_REVISION) else ()) + (('legacy_tclk_records',) if revision == TL1_REVISION else ())


def sql_for(revision):
    tables_for(revision)
    return SQL + ('\n' + Path(__file__).with_name('docs').joinpath('router-legacy-generation-lg2-schema.sql').read_text() if revision in (LG2_REVISION, TL1_REVISION) else '') + ('\n' + Path(__file__).with_name('docs').joinpath('router-tclk-legacy-tl1-schema.sql').read_text() if revision == TL1_REVISION else '')


def policy_for(revision):
    require(revision in REVISIONS, 'Unsupported policy revision')
    result = loads(canonical(POLICY))
    if revision == TL1_REVISION:
        result.update(version='router-evidence-horizons/3', classifier_version='router-evidence-classes/3')
    return result


def policy_versions(revision):
    policy = policy_for(revision)
    return {(policy['version'], digest(policy), policy['classifier_version'], policy['qualification_policy_version'])}


def annotation_template(revision=REVISION):
    require(revision in REVISIONS, 'Unsupported annotation revision')
    return loads(canonical(ANNOTATIONS if revision == REVISION else A1_ANNOTATIONS))


def validate_legacy_annotation(value, message=None, provenance=None):
    if value is None: return
    keys(value, set(LEGACY_FIXED) | {'captured_generation','reported_generation','raw_record_id','raw_text_sha256','linked_cache_records'})
    for key, expected in LEGACY_FIXED.items():
        require(type(value[key]) is type(expected) and value[key] == expected, 'Invalid LG1 class metadata')
    require(value['captured_generation']=='UNKNOWN_LEGACY' and value['reported_generation'] in ('0','1'), 'Invalid LG1 generation metadata')
    sha(value['raw_record_id']); sha(value['raw_text_sha256'])
    refs=value['linked_cache_records']
    require(type(refs) is list and 1 <= len(refs) <= 256, 'Invalid LG1 cache references')
    seen={}; tables=set()
    for ref in refs:
        keys(ref, {'cache_table','source_record_locator','record_sha256','reported_generation'})
        require(ref['cache_table'] in {'evidence_records','tclk_frames','kibble_events'}, 'Unsupported LG1 cache table')
        string(ref['source_record_locator']); sha(ref['record_sha256'])
        require(ref['reported_generation']==value['reported_generation'], 'Competing LG1 reports')
        key=(ref['cache_table'],ref['source_record_locator'])
        require(key not in seen, 'Duplicate/conflicting LG1 locator'); seen[key]=ref; tables.add(ref['cache_table'])
    require('evidence_records' in tables, 'LG1 requires evidence cache original')
    require([canonical(r) for r in refs] == sorted(set(canonical(r) for r in refs)), 'Unsorted LG1 references')
    if provenance is not None:
        require(provenance['entity_type']=='message' and provenance['raw_record_id']==value['raw_record_id'] and provenance['source_namespace']=='legacy_evidence', 'Invalid projected LG1 raw binding')
    if message is not None:
        require(message['projection_row_id']=='sm1:'+value['raw_record_id'] and message['generation']=='UNKNOWN_LEGACY' and text_hash(message['text'])==value['raw_text_sha256'], 'Invalid projected LG1 message binding')


def annotations(value, revision=REVISION):
    keys(value, ANNOTATIONS if revision == REVISION else A1_ANNOTATIONS)
    require(revision in REVISIONS, 'Unsupported annotation revision')
    if value.get('classification') == 'TCLK_LEGACY_NONCONFORMING':
        require(revision == TL1_REVISION and value['capability_support'] == [], 'Mixed/positive TL1 annotation')
    if revision == REVISION: validate_legacy_annotation(value['legacy_generation'])
    require(len(canonical(value)) <= 65536, 'Annotations exceed limit')
    string(value['classification'], True); string(value['operator_group'], True)
    for key in ('same_operator', 'independent_reputation'):
        require(value[key] is None or type(value[key]) is bool, 'Invalid operator boolean')
    if value['operator_group'] == FAMILY or value['same_operator'] is True:
        require(value['independent_reputation'] is not True, 'Same operator cannot be independent')
    shapes = {
        'capability_support': {'capability_id', 'classification', 'evidence_id'},
        'verification_links': {'request_id', 'result_hash', 'bench_did', 'validation_id', 'correctness', 'reproducibility', 'authenticity', 'evidence_classification'},
        'task_routing_links': {'job_proto', 'job_id', 'task_hash', 'routing_decision_id', 'routing_decision_hash'},
        'evidence_links': {'room', 'generation', 'seq', 'evidence_id'},
    }
    for name, shape in shapes.items():
        rows = value[name]
        require(type(rows) is list and len(rows) <= 256, 'Invalid annotations array')
        require([canonical(r) for r in rows] == sorted(set(canonical(r) for r in rows)), 'Unsorted annotations')
        for row in rows:
            keys(row, shape)
            for key, item in row.items():
                if key == 'seq':
                    require(item is None or type(item) is int and item >= 0, 'Invalid link sequence')
                else:
                    string(item, name != 'capability_support')
                    if key in {'task_hash', 'result_hash', 'routing_decision_hash'}:
                        sha(item, True)
            if name == 'verification_links':
                require(any(row[k] is not None for k in ('request_id', 'result_hash', 'bench_did', 'validation_id')), 'Unidentified verification')
            if name == 'task_routing_links':
                require(any(v is not None for v in row.values()), 'Unidentified task')
            if name == 'evidence_links':
                location = [row[k] is not None for k in ('room', 'generation', 'seq')]
                require(all(location) or not any(location) and row['evidence_id'] is not None, 'Incomplete evidence location')
    return value


def roots(value):
    require(type(value) is list and len(value) <= 256 and len(canonical(value)) <= 65536, 'Invalid pin roots')
    for root in value:
        keys(root, {'kind', 'id'}); string(root['id'])
        require(root['kind'] in {'ROUTING_DECISION', 'TASK', 'VALIDATION', 'VERIFICATION'}, 'Invalid pin root kind')
    require(value == sorted(value, key=lambda r: (r['kind'], r['id'])) and len({canonical(v) for v in value}) == len(value), 'Unsorted pin roots')


def identity(prefix, value):
    return prefix + ':' + digest(value)


def interaction_identity(relationship_type, source, target):
    endpoints = []
    for role, endpoint in [('source', source), ('target', target)]:
        keys(endpoint, {'raw_record_id', 'room', 'generation', 'seq', 'sender_did'})
        require(type(endpoint['seq']) is int and endpoint['seq'] >= 0, 'Invalid endpoint sequence')
        for k in ('raw_record_id', 'room', 'generation', 'sender_did'):
            string(endpoint[k])
        endpoints.append(dict(role=role, **endpoint))
    obj = dict(schema='flop-scout-interaction-identity/v1', source_namespace='scout-observer',
               relationship_type=string(relationship_type), endpoints=endpoints)
    return identity('si1', obj), obj


def workflow_identity(protocol, issuer, room, generation, key_type, value, namespace='scout-observer'):
    obj = {'schema': 'flop-scout-workflow-identity/v1', 'protocol': string(protocol),
           'scope': {'source_namespace': string(namespace), 'issuer': string(issuer),
                     'room': string(room, True), 'generation': string(generation, True)},
           'key': {'type': string(key_type), 'value': string(value)}}
    return identity('sw1', obj), obj


def readiness(size, ready=True, hard_ceiling=4*1024**3):
    require(type(size) is int and size >= 0, 'Invalid byte count')
    require(hard_ceiling == 4*1024**3, 'Larger hard ceiling requires a future reviewed operator override')
    if not ready: return 'NOT_READY'
    if size > hard_ceiling: return 'OVERSIZE'
    if size >= 1024**3: return 'WARNING_LARGE'
    return 'QUALIFIED'


POLICY_SHA = digest(POLICY)


def connect(path, readonly=False):
    path = Path(path)
    require(path.is_absolute(), 'Projection paths must be absolute')
    require(not path.is_symlink(), 'Symlink database rejected')
    conn = sqlite3.connect(path.as_uri() + ('?mode=ro' if readonly else '?mode=rw'), uri=True)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys=ON')
    conn.execute('PRAGMA busy_timeout=1000')
    if readonly: conn.execute('PRAGMA query_only=ON')
    return conn
