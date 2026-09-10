"""Versioned classification and immutable A1 audit objects. No I/O."""
from __future__ import annotations
import re
from scout_projection_contract import *

KIBBLE = {'JOB': 'KIBBLE_JOB', 'CLAIM': 'KIBBLE_CLAIM', 'RESULT': 'KIBBLE_RESULT',
          'DELIVER': 'KIBBLE_RESULT', 'ATTEST': 'KIBBLE_ATTESTATION', 'ACCEPT': 'WORK_ACCEPTANCE',
          'WITNESS': 'VERIFICATION_RESULT', 'BRIEF': 'WORK_REQUEST'}
BENCH = {'flop-verification-request/v1': 'VERIFICATION_REQUEST',
         'flop-verification-result/v1': 'VERIFICATION_RESULT',
         'flop-bench.verification-result-delivery.v1': 'VERIFICATION_RESULT'}
GENERIC = {'WORK_REQUEST', 'WORK_ACCEPTANCE', 'WORK_RESULT', 'VERIFICATION_REQUEST', 'VERIFICATION_RESULT'}
PRIORITY = ['NEGATIVE_EVIDENCE', 'PINNED', 'IDENTITY_OPERATOR', 'BENCH_VERIFICATION',
            'CAPABILITY_CONTRADICTION', 'CAPABILITY_SUPPORT', 'TCLK_LIFECYCLE',
            'WORK_LIFECYCLE', 'CAPABILITY_SIGNAL', 'CONTEXT']


def classify(text, official=False, identity_binding=False):
    require(type(text) is str, 'Unrepresentable source text')
    candidates = []
    malformed = False
    obj = None
    try:
        obj = loads(text[6:] if text.startswith('tclk1 ') else text, max(65536, len(text.encode('utf8'))))
    except ProjectionError:
        malformed = text.lstrip().startswith(('{', '[')) or text.startswith('tclk1 ')
    if not isinstance(obj, dict): obj = {}
    if text.startswith('tclk1 '):
        candidates.append((10, 'TCLK_TRANSCRIPT_EVENT'))
    schema = obj.get('schema_version', obj.get('schema'))
    if isinstance(schema, str) and schema in BENCH:
        candidates.append((20, BENCH[schema]))
    kind = obj.get('type')
    version = obj.get('version', obj.get('v'))
    if isinstance(kind, str) and kind in KIBBLE and (type(version) in (int, str) and version in ('1', 'v1', 1) or isinstance(schema, str) and schema.endswith('.v1')):
        candidates.append((30, KIBBLE[kind]))
    if official: candidates.append((40, 'OFFICIAL_NETWORK_ANNOUNCEMENT'))
    if identity_binding or re.search(r'^(?:presence:|hello[,! ]|online\b)', text, re.I):
        candidates.append((50, 'IDENTITY_PRESENCE'))
    if schema == 'flop-work-event/v1' and isinstance(kind, str) and kind in GENERIC:
        candidates.append((60, kind))
    for offset, (label, pattern) in enumerate([
        ('VERIFICATION_RESULT', r'^(?:verification result|bench result)\b'),
        ('WORK_RESULT', r'^(?:work result|result:)'),
        ('WORK_ACCEPTANCE', r'^(?:work acceptance|accepted job|i accept the task)\b'),
        ('WORK_REQUEST', r'^(?:work request|request:|help needed|looking for an agent)\b'),
        ('EXTERNAL_RAIL_CLAIM', r'^(?:payment sent|settlement claim|funds transferred)\b'),
    ]):
        if re.search(pattern, text, re.I): candidates.append((70 + offset / 10, label))
    if re.search(r'^(?:capabilities:|i can |we offer |available for )', text, re.I):
        candidates.append((80, 'CAPABILITY_CLAIM' if text.lower().startswith('capabilities:') else 'PROMOTIONAL_CLAIM'))
    if malformed: candidates.append((90, 'MALFORMED_UNVERIFIABLE_EVENT'))
    candidates.append((100, 'UNCLASSIFIED'))
    return min(candidates)[1], obj


QUAL_KEYS = set('schema qualification_id source_ref scout_event_id evidence_id subject_did claim qualification_type qualification_outcome qualified_at policy_version policy_sha256 classifier_version qualification_policy_version bootstrap_id evaluation_id source_cut rule_id rule_input_sha256 rule_group_sha256 provenance_refs operator_group same_operator independent_reputation authenticity correctness reproducibility initial_status'.split())
EVENT_KEYS = set('schema event_id qualification_id sequence previous_event_sha256 event_type recorded_at reason_code proof_refs authority_ref superseded_by qualification_policy_version'.split())
OUTCOMES = {'CAPABILITY_USE': {'LIMITED', 'STRONG'}, 'CONTROLLED_BENCH': {'PASS', 'FAIL'},
            'OBJECTIVE_VALIDATION': {'PASS', 'FAIL'}, 'CAPABILITY_CONTRADICTION': {'CONTRADICTED'},
            'NEGATIVE_FACT': {'ESTABLISHED_NEGATIVE_FACT'}}
REASONS = {'SIGNATURE_PROVENANCE_FAILURE', 'WRONG_IDENTITY_BINDING', 'BROKEN_TASK_LINKAGE',
           'CORRUPTED_EVIDENCE', 'COORDINATED_CLASSIFIER_RECLASSIFICATION', 'PROVEN_FRAUD_SPOOFING'}


def validate_qualification(record, historical_policies=None):
    keys(record, QUAL_KEYS)
    require(len(canonical(record)) <= 65536, 'Qualification too large')
    require(record['schema'] == 'router-durable-qualification/v1', 'Unsupported qualification schema')
    require(record['qualification_id'] == identity('dq1', {k:v for k,v in record.items() if k != 'qualification_id'}), 'Qualification ID hash mismatch')
    reference(record['source_ref'], {'PROJECTED_MESSAGE', 'LOCAL_ARTIFACT'})
    ordered_refs(record['provenance_refs'], True)
    require(record['source_ref'] in record['provenance_refs'], 'Qualification missing source proof')
    keys(record['claim'], {'kind', 'id'}); string(record['claim']['id'])
    require(record['claim']['kind'] in {'CAPABILITY', 'VERIFICATION', 'NEGATIVE_FACT'}, 'Invalid claim kind')
    require(record['qualification_type'] in OUTCOMES and record['qualification_outcome'] in OUTCOMES[record['qualification_type']], 'Invalid qualification outcome')
    require(record['initial_status'] == 'VALID', 'Initial qualification must be VALID')
    instant(record['qualified_at'])
    versions = (record['policy_version'], record['policy_sha256'], record['classifier_version'], record['qualification_policy_version'])
    allowed = {(POLICY['version'], POLICY_SHA, POLICY['classifier_version'], POLICY['qualification_policy_version'])}
    allowed.update(historical_policies or ())
    require(versions in allowed, 'Unreviewed qualification policy versions')
    for k in ('policy_sha256', 'rule_input_sha256', 'rule_group_sha256'): sha(record[k])
    for k in ('subject_did', 'bootstrap_id', 'evaluation_id', 'rule_id'): string(record[k])
    for k in ('evidence_id', 'operator_group', 'authenticity', 'correctness', 'reproducibility'): string(record[k], True)
    if record['scout_event_id'] is not None: decimal(record['scout_event_id'])
    keys(record['source_cut'], {'source_id', 'epoch', 'committed_event_id'})
    string(record['source_cut']['source_id']); string(record['source_cut']['epoch']); decimal(record['source_cut']['committed_event_id'])
    for k in ('same_operator', 'independent_reputation'):
        require(record[k] is None or type(record[k]) is bool, 'Invalid operator boolean')
    if record['operator_group'] == FAMILY or record['same_operator'] is True:
        require(record['operator_group'] == FAMILY and record['same_operator'] is True and record['independent_reputation'] is False, 'Invalid family qualification')
    return record


def first_key(record):
    return digest([record[k] for k in ('source_ref', 'subject_did', 'claim', 'qualification_type', 'policy_sha256', 'classifier_version', 'qualification_policy_version')])


def validate_event(event, prior, qualifications):
    keys(event, EVENT_KEYS)
    require(len(canonical(event)) <= 65536, 'Audit event too large')
    require(event['schema'] == 'router-qualification-event/v1' and event['qualification_policy_version'] == POLICY['qualification_policy_version'], 'Unsupported audit policy')
    require(event['event_id'] == identity('dqe1', {k:v for k,v in event.items() if k != 'event_id'}), 'Event ID hash mismatch')
    qid = event['qualification_id']
    require(qid in qualifications, 'Missing qualification target')
    require(type(event['sequence']) is int and event['sequence'] == len(prior)+1, 'Audit sequence fork or gap')
    require(event['previous_event_sha256'] == (prior[-1]['event_id'][5:] if prior else None), 'Audit chain mismatch')
    when = instant(event['recorded_at'])
    require(when >= instant(prior[-1]['recorded_at'] if prior else qualifications[qid]['qualified_at']), 'Regressed audit time')
    ordered_refs(event['proof_refs'], True); reference(event['authority_ref'], {'LOCAL_ARTIFACT', 'PROJECTED_MESSAGE'})
    if event['event_type'] == 'INVALIDATED':
        require(event['reason_code'] in REASONS and event['superseded_by'] is None, 'Invalid invalidation reason')
    elif event['event_type'] == 'SUPERSEDED':
        target = event['superseded_by']
        require(event['reason_code'] == 'NEW_QUALIFICATION' and target in qualifications and target != qid, 'Invalid supersession target')
        require(all(qualifications[qid][k] == qualifications[target][k] for k in ('subject_did', 'claim')), 'Supersession domain mismatch')
    else: raise ProjectionError('Unsupported audit transition (downgrade is not an event)')
    return event


def effective_status(events):
    return 'INVALIDATED' if any(e['event_type'] == 'INVALIDATED' for e in events) else 'VALID'
