"""Pinned TL1 structural audit primitives. No network, decoder or workflow effects.

The schema interpreter implements only the vocabulary present in the immutable
approved artifact. Changing that artifact requires an explicit policy revision.
"""
from __future__ import annotations
import hashlib
import json
import math
import re
from functools import lru_cache
from pathlib import Path
from scout_projection_contract import canonical, decimal, digest, keys, require, sha, string, ProjectionError

REVISION = 'A1-LG2-TL1'
PIN = {
    'tclk_frame_schema_repository': 'flop-labs/tclk',
    'tclk_frame_schema_revision': '5cc4ab93efbc8999a3a7e1471b639deca25998ea',
    'tclk_frame_schema_path': 'schema/tclk1-frames.schema.json',
    'tclk_frame_schema_sha256': '17071a2b3b21e8484cac9da7976088f3700e6fb6c1372268d4756b61ddd60c70',
    'tclk_frame_structural_boundary': 'tclk1-tl1-structural-schema/v1',
    'tclk_frame_validator_version': 'router-tclk1-structure/1',
}
POLICY = {
    'schema': 'router-tclk-legacy-audit-policy/v1',
    'dialect': 'router-tclk-legacy-audit/v1',
    'retention': 'unresolved-domain-hold-no-auto-release/v1',
    'hint_authority': 'AUDIT_ONLY_NO_WORKFLOW_ID',
    'max_cohort_records': 4096,
    'max_hold_messages': 100000,
    'max_hold_serialized_bytes': 268435456,
}
REASONS = {
    1: 'MISSING_REQUIRED_REF', 2: 'MISSING_REQUIRED_CONTRACT',
    4: 'UNSUPPORTED_OFFER_ID', 8: 'MISSING_LINKAGE', 16: 'MALFORMED_RECEIPT',
    32: 'CONFLICTING_CLAIMED_OFFER_HINTS', 64: 'OTHER_SCHEMA_FAILURE',
    128: 'UNPARSEABLE_OR_AMBIGUOUS_JSON', 256: 'INVALID_FIELD_TYPE_OR_VALUE',
    512: 'UNSUPPORTED_FRAME_TYPE',
}
CONTRACT_TYPES = frozenset(('accept', 'lock', 'reveal', 'refund', 'cancel', 'receipt', 'heartbeat'))
SCHEMA_PATH = Path(__file__).with_name('docs') / 'tclk-tl1-validator-review/tclk1-frames.schema.candidate.json'


def verify_pin(value):
    for key, expected in PIN.items():
        require(value.get(key) == expected, 'TL1_SCHEMA_PIN_MISMATCH: ' + key)
    raw = SCHEMA_PATH.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == PIN['tclk_frame_schema_sha256'], 'TL1_SCHEMA_BYTES_MISMATCH')
    return raw


@lru_cache(maxsize=1)
def schema():
    return json.loads(verify_pin(PIN))


def _errors(value, rule, path=()):
    """Yield (keyword, path); never expose hostile field values in diagnostics."""
    if '$ref' in rule:
        ref = rule['$ref']
        require(ref.startswith('#/$defs/') and ref.count('/') == 2, 'TL1_SCHEMA_REFERENCE_UNSUPPORTED')
        yield from _errors(value, schema()['$defs'][ref.split('/')[-1]], path)
        return
    if 'oneOf' in rule:
        if sum(not list(_errors(value, branch, path)) for branch in rule['oneOf']) != 1:
            yield 'oneOf', path
        return
    kind = rule.get('type')
    matches = {'object': type(value) is dict, 'array': type(value) is list,
               'string': type(value) is str,
               'integer': type(value) is int or type(value) is float and math.isfinite(value) and value.is_integer()}
    if kind is not None and not matches[kind]:
        yield 'type', path
        return
    if 'const' in rule and (type(value) is not type(rule['const']) or value != rule['const']):
        yield 'const', path
    if 'enum' in rule and not any(type(value) is type(item) and value == item for item in rule['enum']):
        yield 'enum', path
    if type(value) is dict:
        properties = rule.get('properties', {})
        for key in rule.get('required', []):
            if key not in value:
                yield 'required', path + (key,)
        for key, item in value.items():
            if key in properties:
                yield from _errors(item, properties[key], path + (key,))
            elif rule.get('additionalProperties') is False:
                yield 'additionalProperties', path + (key,)
    if type(value) is list:
        if len(value) < rule.get('minItems', 0):
            yield 'minItems', path
        if 'items' in rule:
            for index, item in enumerate(value):
                yield from _errors(item, rule['items'], path + (index,))
    if type(value) is str:
        if len(value) < rule.get('minLength', 0):
            yield 'minLength', path
        if 'pattern' in rule:
            # Every approved pattern is anchored. ECMAScript's non-multiline $
            # means true end-of-input; Python's $ also accepts a final newline.
            pattern = rule['pattern']
            if pattern.endswith('$'): pattern = pattern[:-1] + r'\Z'
            if re.search(pattern, value) is None:
                yield 'pattern', path
    if type(value) in (int, float) and 'minimum' in rule and value < rule['minimum']:
        yield 'minimum', path


class DuplicateKey(ValueError):
    pass


def parse(text):
    require(type(text) is str and text.startswith('tclk1 '), 'TL1_NOT_TCLK_TEXT')
    # The transport cap is 4096 characters; legacy audit may preserve longer
    # source records, bounded by the existing 4 MiB canonical source limit.
    require(len(text.encode('utf8')) <= 4 * 1024 * 1024, 'TL1_TEXT_CAPACITY')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise DuplicateKey()
            result[key] = value
        return result
    def invalid_constant(value):
        raise ValueError()
    try:
        obj = json.loads(text[6:], object_pairs_hook=pairs, parse_constant=invalid_constant)
        canonical(obj)
        if type(obj) is not dict:
            return None, 'UNAVAILABLE_PARSE'
        return obj, None
    except DuplicateKey:
        return None, 'AMBIGUOUS_DUPLICATE_KEY'
    except (ValueError, UnicodeError, RecursionError):
        return None, 'UNAVAILABLE_PARSE'


def structural(text):
    """Return exact type/mask. No reference-decoder result is an input."""
    obj, unavailable = parse(text)
    if unavailable:
        return 0, 128
    kind = obj.get('type')
    code = 1 if kind == 'accept' else 2 if kind == 'receipt' else 3 if type(kind) is str else 0
    defs = schema()['$defs']
    supported = type(kind) is str and kind in ('offer',) + tuple(CONTRACT_TYPES)
    if supported:
        errors = list(_errors(obj, defs[kind]))
        if not errors:
            return code, 0
    else:
        # A missing type does not authorize guessing per-type required fields.
        errors = []
        common = {'from': defs['did']}
        for key, rule in common.items():
            if key in obj:
                errors.extend(_errors(obj[key], rule, (key,)))
    mask = 0 if supported else 512
    if 'offer_id' in obj:
        mask |= 4
    if kind == 'accept' and 'ref' not in obj:
        mask |= 1
    if supported and kind in CONTRACT_TYPES and 'contract' not in obj:
        mask |= 2
    usable = lambda key: key in obj and not list(_errors(obj[key], defs['hex32']))
    if kind == 'accept' and not (usable('ref') or usable('contract')):
        mask |= 8
    elif supported and kind in CONTRACT_TYPES and kind != 'accept' and not usable('contract'):
        mask |= 8
    if kind == 'accept' and all(type(obj.get(k)) is str and obj[k] for k in ('offer_id', 'ref')) and obj['offer_id'] != obj['ref']:
        mask |= 32
    for keyword, path in errors:
        if keyword == 'required':
            if path == ('ref',) and kind == 'accept' or path == ('contract',) and kind in CONTRACT_TYPES:
                continue
            mask |= 64
        elif keyword == 'additionalProperties':
            if path != ('offer_id',):
                mask |= 64
        else:
            mask |= 256
    if kind == 'receipt' and mask:
        mask |= 16
    require(mask != 0, 'TL1_UNMAPPED_SCHEMA_FAILURE')
    return code, mask


def reason_names(mask):
    require(type(mask) is int and 0 < mask <= 1023, 'TL1_UNKNOWN_REASON')
    return [name for bit, name in REASONS.items() if mask & bit]


def claims(text):
    obj, unavailable = parse(text)
    result = {}
    for key in ('offer_id', 'ref', 'contract'):
        if unavailable:
            result[key] = {'state': unavailable}
        elif key not in obj:
            result[key] = {'state': 'ABSENT'}
        elif obj[key] is None:
            result[key] = {'state': 'PRESENT_NULL', 'value': None}
        else:
            result[key] = {'state': 'PRESENT_TYPED_VALUE', 'value': obj[key]}
    return result


def cohort_digest(raw_ids):
    ordered = sorted(raw_ids)
    require(len(ordered) == len(set(ordered)), 'TL1_DUPLICATE_COHORT_ID')
    require(len(ordered) <= POLICY['max_cohort_records'], 'TL1_COHORT_CAPACITY')
    for raw_id in ordered:
        sha(raw_id)
    return hashlib.sha256(b''.join(bytes.fromhex(raw_id) for raw_id in ordered)).hexdigest()


def validate_cohort(cohort, *, source_id, epoch, cut, raw_ids=None):
    keys(cohort, {'source_id', 'epoch', 'through_event_id', 'record_count', 'records_sha256'})
    string(cohort['source_id']); string(cohort['epoch']); decimal(cohort['through_event_id']); decimal(cut)
    require(cohort['source_id'] == source_id and cohort['epoch'] == epoch, 'TL1_COHORT_DOMAIN_MISMATCH')
    require(int(cohort['through_event_id']) <= int(cut), 'TL1_COHORT_FUTURE_CUT')
    require(type(cohort['record_count']) is int and 0 <= cohort['record_count'] <= 4096, 'TL1_COHORT_CAPACITY')
    sha(cohort['records_sha256'])
    if raw_ids is not None:
        require(cohort_digest(raw_ids) == cohort['records_sha256'] and len(raw_ids) == cohort['record_count'], 'TL1_COHORT_CONTENT_MISMATCH')
    return cohort


def metadata(cohort):
    return dict(PIN, tclk_legacy_policy=POLICY, tclk_legacy_policy_sha256=digest(POLICY), legacy_tclk_cohort=cohort)


def validate_binding(value):
    verify_pin(value)
    require(canonical(value.get('tclk_legacy_policy')) == canonical(POLICY), 'TL1_POLICY_MISMATCH')
    require(value.get('tclk_legacy_policy_sha256') == digest(POLICY), 'TL1_POLICY_HASH_MISMATCH')


def serialized_row_bytes(table, row):
    obj = {key: value.hex() if isinstance(value, bytes) else value for key, value in dict(row).items()}
    return len(canonical([table, obj])) + 1


def capacity(*, enrolled, held_messages, dependency_bytes):
    values = {'max_cohort_records': enrolled, 'max_hold_messages': held_messages,
              'max_hold_serialized_bytes': dependency_bytes}
    require(all(type(v) is int and v >= 0 for v in values.values()), 'TL1_CAPACITY_INVALID_COUNT')
    overflow = [name for name, value in values.items() if value > POLICY[name]]
    return {'counts': values, 'utilization_percent': {name: value * 100 / POLICY[name] for name, value in values.items()},
            'overflow': bool(overflow), 'overflow_limits': overflow}


def require_capacity(**counts):
    result = capacity(**counts)
    require(not result['overflow'], 'TL1_CAPACITY_EXCEEDED: ' + ','.join(result['overflow_limits']))
    return result


def authenticated_original(original):
    """Reverify an immutable transport envelope, independent of frame parsing."""
    from scout_projection_contract import loads, text_hash
    import scout_evidence
    from flop_scout import verify_signed_record_offline
    keys(original, {'raw', 'event'})
    raw, event = original['raw'], original['event']
    envelope = loads(raw['raw_record_json'])
    require(type(envelope) is dict and envelope.get('text') == raw['raw_text'], 'TL1_RAW_ENVELOPE_MISMATCH')
    require(text_hash(raw['raw_text']) == raw['raw_text_sha256'], 'TL1_RAW_HASH_MISMATCH')
    require(scout_evidence.raw_identity(raw['source'], raw['room'], raw['generation'], raw.get('reported_generation'), envelope) == raw['raw_record_id'], 'TL1_RAW_ID_MISMATCH')
    require(event['raw_record_id'] == raw['raw_record_id'] and event['raw_text_sha256'] == raw['raw_text_sha256'], 'TL1_EVENT_MISMATCH')
    require(type(event['event_id']) is int and event['event_id'] >= 0, 'TL1_EVENT_ID_INVALID')
    require(type(envelope.get('seq')) is int and envelope['seq'] == raw['seq'], 'TL1_RAW_POSITION_MISMATCH')
    require(envelope.get('did', envelope.get('from')) == raw['sender_did'] and envelope.get('sig') == raw['signature'], 'TL1_RAW_AUTHOR_MISMATCH')
    nonce = envelope.get('nonce')
    require(nonce is None and raw['nonce'] is None or type(nonce) in (int, str) and str(nonce) == raw['nonce'], 'TL1_RAW_NONCE_MISMATCH')
    status = verify_signed_record_offline(raw['room'], envelope)
    obj, unavailable = parse(raw['raw_text'])
    contradictory = bool(raw['did_mismatch']) or (obj is not None and 'from' in obj and obj['from'] != raw['sender_did'])
    return status == 'VERIFIED_OFFLINE' and raw['signature_status'] == 'VERIFIED_OFFLINE' and not contradictory


def validate_bundle(bundle):
    """Validate source-bound TL1 candidacy; explicit cohort is checked by owner."""
    from scout_projection_contract import loads, text_hash
    message = bundle['message']
    if not message['text'].startswith('tclk1 '):
        require(bundle.get('tclk_original') is None, 'TL1_ORIGINAL_ON_NON_TCLK')
        return None
    original = bundle.get('tclk_original')
    require(type(original) is dict, 'TL1_MISSING_ORIGINAL')
    raw = original['raw']
    provenance = bundle['provenance']
    require(message['projection_row_id'] == 'sm1:' + raw['raw_record_id'] and provenance['raw_record_id'] == raw['raw_record_id'], 'TL1_MESSAGE_RAW_MISMATCH')
    require(provenance['scout_event_id'] == str(original['event']['event_id']) and provenance['source_namespace'] == raw['source'], 'TL1_SOURCE_MISMATCH')
    for message_key, raw_key in [('text','raw_text'), ('room','room'), ('seq','seq'), ('sender','sender_did'), ('nonce','nonce'), ('sig','signature')]:
        require(message[message_key] == raw[raw_key], 'TL1_PROJECTED_ORIGINAL_MISMATCH')
    from scout_projection_source import generation, observed_time
    require(message['generation'] == generation(raw['generation']) and bundle['first_observed_at'] == observed_time(raw['created_at']), 'TL1_ORIGINAL_DOMAIN_MISMATCH')
    code, mask = structural(message['text'])
    authenticated = authenticated_original(original)
    candidate = bool(mask and authenticated)
    annotation = loads(provenance['annotations_json'])
    require((annotation['classification'] == 'TCLK_LEGACY_NONCONFORMING') == candidate, 'TL1_CLASSIFICATION_MISMATCH')
    if candidate:
        require(bundle['facts']['workflow'] is None and annotation['capability_support'] == [], 'TL1_AUTHORITATIVE_LINK_FORBIDDEN')
        require(message['signed'] == 1 and message['verification_status'] == 'VERIFIED_OFFLINE', 'TL1_AUTHENTICATION_MISMATCH')
        return (raw['raw_record_id'], code, mask)
    return None


def prepare_holds(owner):
    """Rebuild from complete private originals before projection horizon pruning."""
    conn = owner.conn
    conn.execute('CREATE TEMP TABLE IF NOT EXISTS tl1_hold(id TEXT PRIMARY KEY, ordinary_due TEXT) WITHOUT ROWID')
    conn.execute('DELETE FROM tl1_hold')
    conn.execute('CREATE TEMP TABLE IF NOT EXISTS tl1_reverse(child TEXT NOT NULL,parent TEXT NOT NULL,PRIMARY KEY(child,parent)) WITHOUT ROWID')
    conn.execute('CREATE INDEX IF NOT EXISTS temp.tl1_reverse_parent ON tl1_reverse(parent,child)')
    conn.execute('DELETE FROM tl1_reverse')
    conn.execute("INSERT INTO tl1_reverse SELECT child,parent FROM dependencies WHERE parent LIKE 'si1:%'")
    from scout_projection_contract import loads
    for qualification in conn.execute('SELECT qualification_id,record_json FROM projection.durable_qualifications'):
        owner.check(); record = loads(qualification['record_json'])
        refs = list(record['provenance_refs'])
        for event in conn.execute('SELECT event_json FROM projection.qualification_events WHERE qualification_id=?', (qualification['qualification_id'],)):
            body = loads(event[0]); refs.extend(body['proof_refs'] + [body['authority_ref']])
        conn.executemany('INSERT OR IGNORE INTO tl1_reverse VALUES(?,?)', [(ref['id'], qualification['qualification_id']) for ref in refs if ref['kind'] == 'PROJECTED_MESSAGE'])
    domains = set()
    for raw_id in owner.config['legacy_tclk_raw_ids']:
        owner.check()
        bundle = owner.bundle('sm1:' + raw_id)
        require(validate_bundle(bundle) is not None, 'TL1_COHORT_ORIGINAL_MISSING')
        domains.add((bundle['message']['room'], bundle['message']['generation']))
    owner.tclk_domains = domains
    found = set()
    frontier = []
    message_count = 0
    def add(identifier):
        nonlocal message_count
        if identifier in found:
            return
        found.add(identifier)
        if identifier.startswith('sm1:'):
            message_count += 1
            require(message_count <= 100000, 'TL1_HOLD_MESSAGE_CAPACITY')
        frontier.append(identifier)
    for room, generation in sorted(domains):
        for row in conn.execute("SELECT c.id FROM current_inputs c JOIN input_versions v ON v.hash=c.hash WHERE c.room=? AND c.generation=? AND substr(json_extract(v.body,'$.message.text'),1,6)='tclk1 '", (room, generation)):
            owner.check(); add(row[0])
    index = 0
    while index < len(frontier):
        owner.check()
        identifier = frontier[index]; index += 1
        for row in conn.execute('SELECT child FROM dependencies WHERE parent=?', (identifier,)):
            add(row[0])
        for row in conn.execute('SELECT child FROM temp.tl1_reverse WHERE parent=?', (identifier,)):
            add(row[0])
        # Public interaction closure must retain both ends, even across held domains.
        for row in conn.execute('SELECT parent FROM temp.tl1_reverse WHERE child=?', (identifier,)):
            add(row[0])
    messages = [identifier for identifier in found if identifier.startswith('sm1:')]
    require(len(messages) <= 100000, 'TL1_HOLD_MESSAGE_CAPACITY')
    with conn:
        conn.executemany('INSERT INTO tl1_hold VALUES(?,NULL)', [(identifier,) for identifier in sorted(found)])
    # A missing original is a publication failure, never an exclusion proof.
    for identifier in messages:
        owner.check()
        require(conn.execute('SELECT 1 FROM current_inputs WHERE id=?', (identifier,)).fetchone(), 'TL1_HELD_ORIGINAL_MISSING')
    owner.tclk_held_messages = len(messages)
    owner.tclk_holds_initialized = True
    return found


def is_held(owner, identifier):
    if not getattr(owner, 'tclk_holds_initialized', False):
        prepare_holds(owner)
    return owner.conn.execute('SELECT 1 FROM temp.tl1_hold WHERE id=?', (identifier,)).fetchone() is not None


def is_legacy(owner, identifier):
    return identifier.startswith('sm1:') and identifier[4:] in owner.config['legacy_tclk_raw_ids']


def positive_eligible(owner, identifier, when):
    from scout_projection_contract import instant
    if is_legacy(owner, identifier):
        return False
    row = owner.conn.execute('SELECT ordinary_due FROM temp.tl1_hold WHERE id=?', (identifier,)).fetchone()
    return row is None or row[0] is None or instant(row[0]) > instant(when)


def sync_record(owner, bundle):
    raw_id = bundle['provenance']['raw_record_id']
    if raw_id not in owner.config['legacy_tclk_raw_ids']:
        return
    code, mask = structural(bundle['message']['text'])
    row = (bytes.fromhex(raw_id), code, mask)
    existing = owner.conn.execute('SELECT raw_ref,claimed_type_code,nonconformance_mask FROM projection.legacy_tclk_records WHERE raw_ref=?', (row[0],)).fetchone()
    require(existing is None or tuple(existing) == row, 'TL1_IMMUTABLE_RECORD_CHANGED')
    if existing is None:
        owner.conn.execute('INSERT INTO projection.legacy_tclk_records(raw_ref,claimed_type_code,nonconformance_mask) VALUES(?,?,?)', row)
        owner.set('dirty', '1')


def valid_offer(message):
    """Independent OFFER identity validation for diagnostics, never an alias."""
    obj, unavailable = parse(message['text'])
    if unavailable or obj.get('type') != 'offer' or structural(message['text'])[1]:
        return None
    if obj['from'] != message['sender'] or message['verification_status'] != 'VERIFIED_OFFLINE':
        return None
    from flop_scout import verify_signed_record_offline
    if verify_signed_record_offline(message['room'], dict(did=message['sender'], nonce=message['nonce'], sig=message['sig'], text=message['text'])) != 'VERIFIED_OFFLINE':
        return None
    for field in ('claimByMs', 'refundAfterMs', 'expiresMs'):
        if type(obj[field]) not in (int, float) or not 0 < obj[field] <= 9007199254740991 or int(obj[field]) != obj[field]:
            return None
    if obj['claimByMs'] >= obj['refundAfterMs'] or obj['lock'] == 'point' and 'paymentKey' not in obj:
        return None
    if 'paymentKey' in obj:
        from cryptography.hazmat.primitives.asymmetric import ec
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), bytes.fromhex(obj['paymentKey'][2:]))
        except ValueError:
            return None
    # All numbers allowed in OFFER are already bounded integer milliseconds.
    # JSON's ASCII escaping matches the reference domain-hash serialization.
    fields = {key: value for key, value in obj.items() if key != 'id'}
    for key in ('claimByMs', 'refundAfterMs', 'expiresMs'): fields[key] = int(fields[key])
    payload = json.dumps(fields, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False)
    expected = '0x' + hashlib.sha256(('FLOP::tclk::v1|offer|' + payload).encode('ascii')).hexdigest()
    return obj['id'] if obj['id'] == expected else None


def decoder_diagnostic(text):
    """Pinned reference checks for telemetry only; never called by structural()."""
    if len(text.encode('utf-16-le')) // 2 > 4096:
        return False
    try:
        obj = json.loads(text[6:])
    except (ValueError, RecursionError):
        return False
    if type(obj) is not dict:
        return False
    kind = obj.get('type')
    if type(kind) is not str or kind not in ('offer',) + tuple(CONTRACT_TYPES):
        return False
    probe = dict(obj)
    # This deliberately remains diagnostic: TL1 NEVER copies this coercion.
    if kind == 'receipt' and isinstance(probe.get('outcome'), list):
        def js_string(value):
            if value is None: return ''
            if type(value) is list: return ','.join(js_string(item) for item in value)
            if type(value) is str: return value
            if value is True: return 'true'
            if value is False: return 'false'
            return str(value) if type(value) in (int, float) else '[object Object]'
        probe['outcome'] = js_string(probe['outcome'])
    if list(_errors(probe, schema()['$defs'][kind])):
        return False
    if 'paymentKey' in obj:
        from cryptography.hazmat.primitives.asymmetric import ec
        try:
            ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), bytes.fromhex(obj['paymentKey'][2:]))
        except ValueError:
            return False
    if kind == 'offer':
        if any(not 0 < obj[key] <= 9007199254740991 for key in ('claimByMs','refundAfterMs','expiresMs')):
            return False
        if obj['claimByMs'] >= obj['refundAfterMs'] or obj['lock'] == 'point' and 'paymentKey' not in obj:
            return False
        fields = {key: value for key, value in obj.items() if key != 'id'}
        for key in ('claimByMs', 'refundAfterMs', 'expiresMs'): fields[key] = int(fields[key])
        payload = json.dumps(fields, sort_keys=True, ensure_ascii=True, separators=(',', ':'))
        if obj['id'] != '0x' + hashlib.sha256(('FLOP::tclk::v1|offer|' + payload).encode()).hexdigest():
            return False
    return True


def audit_hints(conn, prefix='', check=lambda: None, offset=0, limit=100):
    require(prefix in ('', 'projection.') and type(offset) is int and offset >= 0 and type(limit) is int and 0 <= limit <= 1000, 'TL1_HINT_PAGE_INVALID')
    offers = {}
    # A bounded derived index. It is not serialized into public evidence.
    count = 0
    domains = conn.execute('SELECT DISTINCT m.room,m.generation FROM ' + prefix + 'legacy_tclk_records l JOIN ' + prefix + 'messages m ON m.projection_row_id=l.message_id').fetchall()
    for room, generation in domains:
        for row in conn.execute('SELECT * FROM ' + prefix + "messages WHERE room=? AND generation=? AND substr(text,1,6)='tclk1 '", (room, generation)):
            check(); count += 1
            require(count <= 100000, 'TL1_HINT_SCAN_CAPACITY')
            offer_id = valid_offer(row)
            if offer_id:
                offers.setdefault((room, generation, offer_id), set()).add(row['projection_row_id'])
    page = []; total = ambiguous = 0; seen = 0; matched_keys = set()
    for row in conn.execute('SELECT m.* FROM ' + prefix + 'legacy_tclk_records l JOIN ' + prefix + 'messages m ON m.projection_row_id=l.message_id ORDER BY l.raw_ref'):
        check(); obj, unavailable = parse(row['text']); candidate_keys = set()
        if not unavailable:
            fields = ['offer_id'] + (['ref'] if obj.get('type') == 'accept' else [])
            for field in fields:
                value = obj.get(field)
                if type(value) is str and value:
                    key = (row['room'], row['generation'], value)
                    if key in offers: candidate_keys.add(key)
        matched_keys.update(candidate_keys)
        # Distinct validated OFFER.id groups are disjoint. Count them without
        # expanding up to 4096 x 100000 diagnostic edges during publication.
        size = sum(len(offers[key]) for key in candidate_keys)
        total += size; ambiguous += int(size > 1)
        if limit and seen < offset + limit and seen + size > offset:
            import heapq
            from itertools import islice
            ordered = heapq.merge(*(sorted(offers[key]) for key in candidate_keys))
            start = max(0, offset-seen); end = min(size, offset+limit-seen)
            for candidate in islice(ordered, start, end):
                check()
                page.append(dict(legacy_tclk_record_id='lt1:' + row['projection_row_id'][4:], candidate_message_id=candidate, authority='AUDIT_ONLY_NO_WORKFLOW_ID', ambiguous=size > 1))
        seen += size
    return dict(audit_hint_count=total, ambiguous_hint_count=ambiguous, candidate_dependency_count=sum(len(offers[key]) for key in matched_keys), offset=offset, limit=limit, hints=page)


def validate_public(conn, cohort, source_id, epoch, cut, prefix='', check=lambda: None):
    """Independently recompute compact rows, holds and canonical public bytes."""
    from scout_projection_contract import loads, text_hash
    require(prefix in ('', 'projection.'), 'TL1_SQL_NAMESPACE')
    table = lambda name: prefix + name
    records = conn.execute('SELECT * FROM ' + table('legacy_tclk_records') + ' ORDER BY raw_ref').fetchmany(4097)
    require(len(records) <= 4096, 'TL1_COHORT_CAPACITY')
    require(all(type(row['raw_ref']) is bytes and len(row['raw_ref']) == 32 for row in records), 'TL1_PUBLIC_RAW_REF_TYPE')
    raw_ids = [row['raw_ref'].hex() for row in records]
    validate_cohort(cohort, source_id=source_id, epoch=epoch, cut=cut, raw_ids=raw_ids)
    held = set(); domains = set(); reasons = {name: 0 for name in REASONS.values()}
    decoder_pass = 0
    type_counts = {0: 0, 1: 0, 2: 0, 3: 0}
    for row in records:
        check()
        require(type(row['raw_ref']) is bytes and len(row['raw_ref']) == 32 and type(row['claimed_type_code']) is int and row['claimed_type_code'] in type_counts, 'TL1_PUBLIC_ROW_TYPE')
        reason_names(row['nonconformance_mask'])
        identifier = 'sm1:' + row['raw_ref'].hex()
        require(row['message_id'] == identifier, 'TL1_PUBLIC_ID_MISMATCH')
        message = conn.execute('SELECT * FROM ' + table('messages') + ' WHERE projection_row_id=?', (identifier,)).fetchone()
        provenance = conn.execute("SELECT * FROM " + table('source_provenance') + " WHERE entity_type='message' AND projection_row_id=?", (identifier,)).fetchone()
        require(message is not None and provenance is not None and provenance['raw_record_id'] == row['raw_ref'].hex(), 'TL1_PUBLIC_PROVENANCE_MISSING')
        require(structural(message['text']) == (row['claimed_type_code'], row['nonconformance_mask']), 'TL1_PUBLIC_REASON_MISMATCH')
        require(int(provenance['scout_event_id']) <= int(cohort['through_event_id']), 'TL1_PUBLIC_AFTER_COHORT_CUT')
        ann = loads(provenance['annotations_json'])
        require(ann['classification'] == 'TCLK_LEGACY_NONCONFORMING' and ann['capability_support'] == [], 'TL1_PUBLIC_CLASSIFICATION_MISMATCH')
        require(message['signed'] == 1 and message['verification_status'] == 'VERIFIED_OFFLINE', 'TL1_PUBLIC_AUTHENTICATION')
        from flop_scout import verify_signed_record_offline
        envelope = dict(text=message['text'], did=message['sender'], nonce=message['nonce'], sig=message['sig'])
        require(verify_signed_record_offline(message['room'], envelope) == 'VERIFIED_OFFLINE', 'TL1_PUBLIC_INVALID_SIGNATURE')
        obj, _ = parse(message['text'])
        require(obj is None or 'from' not in obj or obj['from'] == message['sender'], 'TL1_PUBLIC_DID_CONFLICT')
        held.add(identifier); domains.add((message['room'], message['generation']))
        type_counts[row['claimed_type_code']] += 1
        decoder_pass += int(decoder_diagnostic(message['text']))
        for name in reason_names(row['nonconformance_mask']): reasons[name] += 1
    for room, generation in sorted(domains):
        for row in conn.execute('SELECT projection_row_id FROM ' + table('messages') + " WHERE room=? AND generation=? AND substr(text,1,6)='tclk1 '", (room, generation)):
            check(); held.add(row[0])
            require(len(held) <= 100000, 'TL1_HOLD_MESSAGE_CAPACITY')
    enrolled_ids = {'sm1:' + raw_id for raw_id in raw_ids}
    for row in conn.execute('SELECT m.*,p.annotations_json FROM ' + table('messages') + ' m JOIN ' + table('source_provenance') + " p ON p.entity_type='message' AND p.projection_row_id=m.projection_row_id WHERE substr(m.text,1,6)='tclk1 '"):
        check()
        classification = loads(row['annotations_json'])['classification']
        require(classification != 'TCLK_LEGACY_NONCONFORMING' or row['projection_row_id'] in enrolled_ids, 'TL1_UNREGISTERED_PUBLIC_CLASSIFICATION')
        if row['projection_row_id'] not in enrolled_ids and structural(row['text'])[1] and row['verification_status'] == 'VERIFIED_OFFLINE':
            from flop_scout import verify_signed_record_offline
            obj, _ = parse(row['text'])
            if obj is None or 'from' not in obj or obj['from'] == row['sender']:
                verified = verify_signed_record_offline(row['room'], dict(did=row['sender'], nonce=row['nonce'], sig=row['sig'], text=row['text']))
                require(verified != 'VERIFIED_OFFLINE', 'TL1_UNENROLLED_NONCONFORMING')
    # Derive interaction dependencies from the existing exact source references.
    edges = []
    for row in conn.execute("SELECT projection_row_id,annotations_json FROM " + table('source_provenance') + " WHERE entity_type='interaction'"):
        check(); refs = set(); unresolved = False
        for link in loads(row['annotations_json'])['evidence_links']:
            if link.get('room') is not None:
                found = [item[0] for item in conn.execute('SELECT projection_row_id FROM ' + table('messages') + ' WHERE room=? AND generation=? AND seq=?', (link['room'], link['generation'], link['seq']))]
                refs.update(found); unresolved |= not found
            else:
                found = [item[0] for item in conn.execute('SELECT projection_row_id FROM ' + table('messages') + ' WHERE evidence_id=?', (link['evidence_id'],))]
                refs.update(found); unresolved |= not found
        edges.append((row['projection_row_id'], refs, unresolved))
    qualifications = []
    for row in conn.execute('SELECT * FROM ' + table('durable_qualifications')):
        check(); record = loads(row['record_json'])
        refs = {ref['id'] for ref in record['provenance_refs'] if ref['kind'] == 'PROJECTED_MESSAGE'}
        if record['policy_version'] == 'router-evidence-horizons/3' and record['qualification_type'] != 'NEGATIVE_FACT':
            require(not refs.intersection('sm1:' + raw_id for raw_id in raw_ids), 'TL1_POSITIVE_QUALIFICATION_FORBIDDEN')
        for event in conn.execute('SELECT event_json FROM ' + table('qualification_events') + ' WHERE qualification_id=?', (row['qualification_id'],)):
            body = loads(event[0]); refs.update(ref['id'] for ref in body['proof_refs'] + [body['authority_ref']] if ref['kind'] == 'PROJECTED_MESSAGE')
        qualifications.append((row['qualification_id'], refs))
    selected_interactions = set(); selected_qualifications = set()
    while True:
        check(); before = len(held)
        for identifier, refs, unresolved in edges:
            if refs & held:
                require(not unresolved, 'TL1_INTERACTION_DEPENDENCY_MISSING')
                selected_interactions.add(identifier); held.update(refs)
        for identifier, refs in qualifications:
            if refs & held:
                selected_qualifications.add(identifier); held.update(refs)
        require(len(held) <= 100000, 'TL1_HOLD_MESSAGE_CAPACITY')
        if len(held) == before: break
    total = 0; rows_counted = 0
    def count(name, row):
        nonlocal total, rows_counted
        require(row is not None, 'TL1_DEPENDENCY_MISSING')
        total += serialized_row_bytes(name, row); rows_counted += 1
        require(total <= 268435456, 'TL1_HOLD_BYTE_CAPACITY')
    for identifier in sorted(held):
        check()
        message = conn.execute('SELECT * FROM ' + table('messages') + ' WHERE projection_row_id=?', (identifier,)).fetchone()
        count('messages', message)
        for name in ('source_provenance', 'selection_membership'):
            row = conn.execute('SELECT * FROM ' + table(name) + " WHERE entity_type='message' AND projection_row_id=?", (identifier,)).fetchone()
            count(name, row)
            if name == 'selection_membership':
                require(row['retain_until'] is None, 'TL1_FINITE_HOLD')
        raw_ref = bytes.fromhex(identifier[4:])
        for name in ('legacy_tclk_records', 'legacy_generation_reports', 'legacy_generation_witnesses'):
            for row in conn.execute('SELECT * FROM ' + table(name) + ' WHERE raw_ref=?', (raw_ref,)):
                count(name, row)
    for identifier in sorted(selected_interactions):
        check(); count('interactions', conn.execute('SELECT * FROM ' + table('interactions') + ' WHERE projection_row_id=?', (identifier,)).fetchone())
        for name in ('source_provenance', 'selection_membership'):
            row = conn.execute('SELECT * FROM ' + table(name) + " WHERE entity_type='interaction' AND projection_row_id=?", (identifier,)).fetchone()
            count(name, row)
            if name == 'selection_membership': require(row['retain_until'] is None, 'TL1_FINITE_INTERACTION_HOLD')
    for identifier in sorted(selected_qualifications):
        count('durable_qualifications', conn.execute('SELECT * FROM ' + table('durable_qualifications') + ' WHERE qualification_id=?', (identifier,)).fetchone())
        for row in conn.execute('SELECT * FROM ' + table('qualification_events') + ' WHERE qualification_id=?', (identifier,)):
            count('qualification_events', row)
    result = require_capacity(enrolled=len(records), held_messages=len(held), dependency_bytes=total)
    result.update(revision=REVISION, policy=POLICY, **PIN, enrolled_count=len(records), accept_like_count=type_counts[1], receipt_like_count=type_counts[2], reason_counts=reasons,
                  held_message_count=len(held), dependency_bytes=total, dependency_rows=rows_counted,
                  schema_fail_count=len(records), decoder_pass_count=decoder_pass, decoder_fail_count=len(records)-decoder_pass,
                  decoder_diagnostic_status='PINNED_REFERENCE_RULES_DIAGNOSTIC_NOT_A_COHORT_INPUT')
    hints = audit_hints(conn, prefix, check, limit=0)
    result.update(audit_hint_count=hints['audit_hint_count'], ambiguous_hint_count=hints['ambiguous_hint_count'], candidate_dependency_count=hints['candidate_dependency_count'])
    return result
