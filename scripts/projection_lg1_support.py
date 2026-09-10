"""Synthetic legacy migration fixtures; explicit SQLite targets only."""
import sqlite3
from unittest.mock import patch
import flop_scout as scout
import scout_evidence as evidence
from scout_projection_contract import *

NOW='2026-09-08T12:00:00.000000Z'
# Public bytes only: no private key is generated or used.
DID='did:key:z'+scout.b58encode(scout.ED25519_MULTICODEC+bytes(range(32)))
TEXT='I diagnosed the Technocore API HTTP 400 failure when the signed post used the wrong endpoint. After switching to /r/technocore?format=json, I reproduced the regression with a fixture and verified the request returned HTTP 200.'


def source(path=':memory:'):
    conn=sqlite3.connect(str(path));conn.row_factory=sqlite3.Row;scout.init_observer_db(conn)
    return conn


def add_legacy(conn,n=1,report='0',text=TEXT,room='technocore',sender=DID,negative=False,protocol_cache=False,verified=False,cache_only=False):
    raw=dict(seq=n,did=sender,nonce=123+n,ts=NOW,text=text)
    if negative or verified:raw['sig']='synthetic-invalid-signature'
    verify=(lambda room,raw:'VERIFIED_OFFLINE') if verified else scout.verify_signed_record_offline
    # verified=True is an explicit unit-test authority premise, never a cryptographic claim.
    with patch.object(evidence,'now',lambda:NOW),patch.object(scout,'verify_signed_record_offline',verify),conn:
        rid=evidence.raw_identity('legacy_evidence',room,None,report,raw) if cache_only else evidence.ingest(conn,room,raw,scout.verify_signed_record_offline,generation=None,reported_generation=report,source='legacy_evidence',legacy=True,retrieved_at=NOW)
        record=scout.evidence_record_from_message(room,report,raw,source='service-poll',retrieved_at=NOW)
        scout.store_evidence_record(conn,record)
        if protocol_cache:
            other=scout.kibble_record_from_message(room,report,raw,observed_at=NOW)
            if other is None:
                # An explicitly synthetic compatibility row for linkage tests.
                other=dict(room=room,generation=report,seq=n,server_timestamp=NOW,sender_did=sender,nonce=raw['nonce'],signature=raw.get('sig'),signature_verification=record['verification_status'],exact_text=text,message_hash=text_hash(text),event_type=None,event_version=None,job_id=None,observed_at=NOW,parse_status='MALFORMED',parse_error=None,payload_json=None)
            scout.store_kibble_event(conn,other)
    return rid
