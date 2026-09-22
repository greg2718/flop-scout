import hashlib
import json
import os
import sqlite3
from pathlib import Path

import pytest

from scout_epoch_source_evidence import (SCHEMA, SourceEvidenceError, _DDL,
                                         _cache_validate, build, validate,
                                         validate_schema)
from scout_legacy_a1_recovery import canonical, raw_record_id


FIXTURE = Path(__file__).parent / "docs/fixtures/scout-router-epoch-rollover-v2-conformance.json"


def _sha(text): return hashlib.sha256(text.encode()).hexdigest()


def _descriptor():
    return {"content_id": "42", "manifest_sha256": "a" * 64, "artifact_sha256": "b" * 64,
            "artifact_size": 9, "source_kind": "bounded-current", "source_id": "source-a",
            "source_epoch": "epoch-a", "source_cut": 9}


def _context():
    return {"accepted_anchor": {"content_id": "41"}, "bridge_predecessor": {"content_id": "42"},
            "source_checkpoint": {"source_id": "source-a", "source_epoch": "epoch-a", "source_cut": 9},
            "previous_bridge_binding_sha256": "c" * 64}


def _inputs(tmp_path):
    projection, source = tmp_path / "projection.sqlite", tmp_path / "source.sqlite"
    text = "fixture source text"; envelope = {"text": text, "seq": 4, "nonce": 7, "from": "did:key:z"}
    rid = raw_record_id("technocore_room", "room", "1", None, envelope); digest = _sha(text); pid = "sm1:" + rid
    with sqlite3.connect(source) as c:
        c.executescript("""
        CREATE TABLE raw_network_records(raw_record_id TEXT PRIMARY KEY,source TEXT,room TEXT,generation TEXT,reported_generation TEXT,seq INTEGER,sender_did TEXT,signature TEXT,nonce INTEGER,raw_text TEXT,raw_text_sha256 TEXT,raw_record_json TEXT);
        CREATE TABLE observed_events(event_id INTEGER PRIMARY KEY,raw_record_id TEXT,raw_text_sha256 TEXT);
        CREATE TABLE compatibility_evidence_links(cache_table TEXT,cache_rowid INTEGER,raw_record_id TEXT,raw_text_sha256 TEXT);
        CREATE TABLE messages(room TEXT,generation TEXT,seq INTEGER,text TEXT,sender TEXT);
        CREATE TABLE evidence_records(room TEXT,generation TEXT,seq INTEGER,text TEXT,sender TEXT,sig TEXT,nonce INTEGER);
        CREATE TABLE tclk_frames(room TEXT,generation TEXT,seq INTEGER,raw_text TEXT,sender TEXT);
        CREATE TABLE kibble_events(room TEXT,generation TEXT,seq INTEGER,exact_text TEXT,sender TEXT);
        """)
        c.execute("INSERT INTO raw_network_records VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (rid,"technocore_room","room","1",None,4,"did:key:z","signature",7,text,digest,json.dumps(envelope,separators=(",",":"))))
        c.execute("INSERT INTO observed_events VALUES(?,?,?)", (9,rid,digest))
        c.execute("INSERT INTO messages(rowid,room,generation,seq,text,sender) VALUES(?,?,?,?,?,?)", (101,"room","1",4,text,"did:key:z"))
        c.execute("INSERT INTO compatibility_evidence_links VALUES(?,?,?,?)", ("messages",101,rid,digest))
    witness = {"projection_row_id":pid,"room":"room","generation":"1","seq":4,"text":text}
    with sqlite3.connect(projection) as c:
        c.executescript("""
        CREATE TABLE source_provenance(entity_type TEXT,projection_row_id TEXT,source_namespace TEXT,source_record_locator TEXT,scout_event_id TEXT,raw_record_id TEXT,raw_record_sha256 TEXT,annotations_json TEXT);
        CREATE TABLE selection_membership(entity_type TEXT,projection_row_id TEXT,retain_until TEXT,pin_roots_json TEXT,retention_class TEXT);
        CREATE TABLE durable_qualifications(qualification_id INTEGER PRIMARY KEY,record_json TEXT);
        CREATE TABLE coverage_history(room TEXT,generation TEXT,max_ever_projected_seq INTEGER,witness_source_locator TEXT,witness_record_sha256 TEXT);
        CREATE TABLE messages(projection_row_id TEXT PRIMARY KEY,room TEXT,generation TEXT,seq INTEGER,text TEXT);
        """)
        c.execute("INSERT INTO source_provenance VALUES(?,?,?,?,?,?,?,?)", ("message",pid,"technocore_room",rid,"9",rid,None,"{}"))
        c.execute("INSERT INTO selection_membership VALUES(?,?,?,?,?)", ("message",pid,None,"[]","TCLK_LIFECYCLE"))
        c.execute("INSERT INTO durable_qualifications VALUES(?,?)", (1,json.dumps({"source_ref":{"kind":"PROJECTED_MESSAGE","id":pid}})))
        c.execute("INSERT INTO messages VALUES(?,?,?,?,?)", (pid,"room","1",4,text))
        c.execute("INSERT INTO coverage_history VALUES(?,?,?,?,?)", ("room","1",4,rid,hashlib.sha256(canonical(witness)).hexdigest()))
    return projection, source


def _built(tmp_path):
    projection, source = _inputs(tmp_path); out = tmp_path / "member.sqlite"; stage = tmp_path / "stage.sqlite"; d = _descriptor()
    d["artifact_size"] = projection.stat().st_size
    d["artifact_sha256"] = hashlib.sha256(projection.read_bytes()).hexdigest()
    result = build(projection.resolve(), source.resolve(), stage.resolve(), out.resolve(), d, dict(d), _context())
    return projection, source, out, d, result


def test_build_and_independent_validation_are_bounded_and_read_only(tmp_path):
    projection, source = _inputs(tmp_path)
    before = {path: (path.stat().st_size, path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest()) for path in (projection, source)}
    out = tmp_path / "member.sqlite"; stage = tmp_path / "stage.sqlite"; descriptor = _descriptor()
    descriptor["artifact_size"] = projection.stat().st_size; descriptor["artifact_sha256"] = hashlib.sha256(projection.read_bytes()).hexdigest()
    result = build(projection.resolve(), source.resolve(), stage.resolve(), out.resolve(), descriptor, dict(descriptor), _context())
    assert result["records"] == result["events"] == 1 and result["schema"] == SCHEMA
    assert os.stat(out).st_mode & 0o777 == 0o600
    again = validate(out.resolve(), projection.resolve(), descriptor, dict(descriptor), _context(), {"schema": SCHEMA, "size_bytes": out.stat().st_size, "sha256": result["sha256"]})
    assert again["recovery"]["closure_count"] == 1
    with sqlite3.connect(out) as conn:
        assert conn.execute("SELECT cache_rowid FROM messages").fetchone()[0] == 101
        assert conn.execute("SELECT cache_rowid FROM compatibility_links").fetchone()[0] == 101
    assert before == {path: (path.stat().st_size, path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest()) for path in (projection, source)}


@pytest.mark.parametrize("sql,code", [
    ("UPDATE source_evidence_metadata SET canonical_ddl_sha256='0'||substr(canonical_ddl_sha256,2)", "SOURCE_EVIDENCE_DDL"),
    ("DELETE FROM raw_records", "SOURCE_EVIDENCE_REFERENCES"),
    ("INSERT INTO raw_records SELECT '0'||substr(raw_record_id,2),source,room,generation,reported_generation,seq,sender_did,signature,nonce,raw_text,raw_text_sha256,raw_record_json FROM raw_records", "SOURCE_EVIDENCE_RAW_SET"),
    ("PRAGMA ignore_check_constraints=ON; UPDATE compatibility_links SET cache_table='bad'", "SOURCE_EVIDENCE_CACHE_TABLE"),
])
def test_validator_rejects_metadata_rows_and_link_mutations(tmp_path, sql, code):
    projection, _source, out, descriptor, _result = _built(tmp_path)
    with sqlite3.connect(out) as c:
        for statement in sql.split("; "):
            c.execute(statement)
    with pytest.raises(SourceEvidenceError) as caught:
        validate(out.resolve(), projection.resolve(), descriptor, dict(descriptor), _context())
    assert caught.value.code == code


def test_schema_drift_and_preexisting_or_symlink_output_fail_closed(tmp_path):
    projection, source = _inputs(tmp_path); d = _descriptor(); out = tmp_path / "out.sqlite"; out.write_bytes(b"old")
    with pytest.raises(SourceEvidenceError): build(projection.resolve(), source.resolve(), (tmp_path / "stage.sqlite").resolve(), out.resolve(), d, dict(d), _context())
    member = tmp_path / "bad.sqlite"; member.write_bytes(b"x")
    with pytest.raises(SourceEvidenceError): validate(member.resolve(), projection.resolve(), d, dict(d), _context())


def test_real_cache_shapes_preserve_exact_cache_sender_and_nonce_semantics(tmp_path):
    path = tmp_path / "shapes.sqlite"; text = "shape text"; digest = _sha(text)
    envelope = {"text": text, "seq": 4, "nonce": 7, "from": "did:key:z"}
    rid = raw_record_id("technocore_room", "room", "1", None, envelope)
    with sqlite3.connect(path) as conn:
        for sql in _DDL.values(): conn.execute(sql)
        conn.execute("INSERT INTO raw_records VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", (rid,"technocore_room","room","1",None,4,"did:key:z","sig","7",text,digest,json.dumps(envelope,separators=(",",":"))))
        conn.execute("INSERT INTO messages VALUES(?,?,?,?,?)", (101,"room",4,text,"did:key:z"))
        conn.execute("INSERT INTO evidence_records VALUES(?,?,?,?,?,?,?,?)", (102,"room","1",4,text,"did:key:z","sig",7))
        conn.execute("INSERT INTO tclk_frames VALUES(?,?,?,?,?,?)", (103,"room","1",4,text,"did:key:z"))
        conn.execute("INSERT INTO kibble_events VALUES(?,?,?,?,?,?)", (104,"room","1",4,text,"did:key:z"))
        for table, rowid in (("messages",101),("evidence_records",102),("tclk_frames",103),("kibble_events",104)):
            conn.execute("INSERT INTO compatibility_links VALUES(?,?,?,?)", (table,rowid,rid,digest))
        conn.row_factory = sqlite3.Row
        result = _cache_validate(conn, {"raw_record_id":rid,"raw_text_sha256":digest,"room":"room","seq":4,"raw_text":text,"generation":"1","sender_did":"did:key:z","signature":"sig","nonce":"7"})
    assert {key: len(value) for key, value in result.items()} == {"messages":1,"evidence_records":1,"tclk_frames":1,"kibble_events":1}


def test_implementation_ddl_hash_matches_frozen_valid_archive_vector(tmp_path):
    vector = next(case for case in json.loads(FIXTURE.read_text())["archive_format_cases"] if case["name"] == "archive-manifest-valid")
    path = tmp_path / "schema.sqlite"
    with sqlite3.connect(path) as conn:
        for sql in _DDL.values(): conn.execute(sql)
        assert validate_schema(conn) == vector["source_evidence"]["canonical_ddl_sha256"]
