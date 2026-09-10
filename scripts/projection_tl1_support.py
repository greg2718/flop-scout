"""Synthetic signed TL1 source fixtures. Never reads a local identity or production DB."""
import json
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import flop_scout as scout
import scout_evidence as evidence
from scout_projection_contract import TL1_REVISION
from scout_projection_source import map_raw
from scripts.projection_lg1_support import source, NOW

# A single deterministic, public test secret. Not an operator identity or wallet.
TEST_KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
DID = scout.public_did(TEST_KEY)
HEX = '0x' + '1' * 64


def offer(n=1, expires_ms=1):
    import hashlib
    obj = dict(type='offer', **{'from': DID}, role='payer', amount='1', asset='TEST', lock='hash', rails=['memory'],
               claimByMs=1, refundAfterMs=2, expiresMs=expires_ms, nonce=f'{n:08x}')
    payload = json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(',', ':'))
    obj['id'] = '0x' + hashlib.sha256(('FLOP::tclk::v1|offer|' + payload).encode()).hexdigest()
    return obj


def add(conn, n=1, obj=None, text=None, room='tclk-offers', generation=None, invalid_signature=False, key=TEST_KEY):
    if text is None:
        obj = obj or dict(type='accept', **{'from': DID}, offer_id=HEX, statement=HEX, nonce='12345678')
        text = 'tclk1 ' + json.dumps(obj, sort_keys=True, separators=(',', ':'))
    nonce = 1000+n
    raw = dict(seq=n, did=scout.public_did(key), nonce=nonce, ts=NOW, text=text)
    raw['sig'] = scout.b64u(key.sign(f'{room}|{nonce}|{text}'.encode()))
    if invalid_signature: raw['sig'] = scout.b64u(bytes(64))
    report = '0' if generation is None else generation
    with patch.object(evidence, 'now', lambda: NOW), conn:
        rid = evidence.ingest(conn, room, raw, scout.verify_signed_record_offline, generation=generation, reported_generation=report, source='legacy_evidence', legacy=True, retrieved_at=NOW)
        record = scout.evidence_record_from_message(room, report, raw, source='service-poll', retrieved_at=NOW)
        scout.store_evidence_record(conn, record)
        cache = scout.tclk_record_from_message(room, report, raw, record, observed_at=NOW)
        if cache is not None: scout.store_tclk_frame(conn, cache)
    return rid


def mapped(**kwargs):
    conn = source()
    try:
        rid = add(conn, **kwargs)
        return map_raw(conn, rid, [DID], TL1_REVISION)
    finally:
        conn.close()


def cohort(bundles, cut=None):
    from scout_projection_tclk import cohort_digest
    ids = [b['provenance']['raw_record_id'] for b in bundles if json.loads(b['provenance']['annotations_json'])['classification'] == 'TCLK_LEGACY_NONCONFORMING']
    return dict(source_id='scout-observer', epoch='source-epoch', through_event_id=cut or str(max((int(b['provenance']['scout_event_id']) for b in bundles), default=0)), record_count=len(ids), records_sha256=cohort_digest(ids)), ids
